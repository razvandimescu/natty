use std::io;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::AlwaysResolvesClientRawPublicKeys;
use tokio_rustls::rustls::crypto::{
    ring, verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms,
};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::server::AlwaysResolvesServerRawPublicKeys;
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{
    version, CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error,
    ServerConfig, SignatureScheme,
};

use crate::{PublicKey, SecretKey};

// RFC 8410 encodings: SubjectPublicKeyInfo and PKCS#8 v1 for Ed25519.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Peers authenticate with RFC 7250 raw public keys: the Ed25519 key is the
/// whole identity, so there is no certificate to build or chain to check.
pub(crate) struct PeerTls {
    provider: Arc<CryptoProvider>,
    key: Arc<CertifiedKey>,
    alpn: Vec<Vec<u8>>,
}

impl PeerTls {
    pub(crate) fn new(secret: &SecretKey, alpn: &[&[u8]]) -> io::Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let pkcs8 = [&PKCS8_PREFIX[..], secret.seed()].concat();
        let signer = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(pkcs8.into()))
            .map_err(io::Error::other)?;
        let spki = CertificateDer::from([&SPKI_PREFIX[..], &secret.public().0].concat());
        Ok(Self {
            key: Arc::new(CertifiedKey::new(vec![spki], signer)),
            provider,
            alpn: alpn.iter().map(|p| p.to_vec()).collect(),
        })
    }

    pub(crate) fn server_config(&self) -> io::Result<quinn::ServerConfig> {
        let mut tls = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(self.verifier(None)))
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
                self.key.clone(),
            )));
        tls.alpn_protocols = self.alpn.clone();
        let quic = QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
    }

    pub(crate) fn client_config(&self, peer: PublicKey) -> io::Result<quinn::ClientConfig> {
        let mut tls = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(self.verifier(Some(peer))))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                self.key.clone(),
            )));
        tls.alpn_protocols = self.alpn.clone();
        let quic = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        Ok(quinn::ClientConfig::new(Arc::new(quic)))
    }

    fn verifier(&self, expected: Option<PublicKey>) -> PeerVerifier {
        PeerVerifier {
            expected,
            algorithms: self.provider.signature_verification_algorithms,
        }
    }
}

/// The key a connection's peer proved during the handshake.
pub fn peer_key(connection: &quinn::Connection) -> Option<PublicKey> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    key_from_spki(certs.first()?)
}

fn key_from_spki(der: &[u8]) -> Option<PublicKey> {
    der.strip_prefix(&SPKI_PREFIX)?
        .try_into()
        .ok()
        .map(PublicKey)
}

/// Dialing checks the presented key against the one dialed; accepting takes
/// any valid key and leaves authorization to the application.
#[derive(Debug)]
struct PeerVerifier {
    expected: Option<PublicKey>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PeerVerifier {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        match key_from_spki(end_entity) {
            Some(key) if intermediates.is_empty() && self.expected.is_none_or(|e| e == key) => {
                Ok(())
            }
            _ => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        verify_tls13_signature_with_raw_key(message, &spki, dss, &self.algorithms)
    }
}

fn tls12_unsupported() -> Result<HandshakeSignatureValid, Error> {
    Err(Error::General("natty peers require TLS 1.3".into()))
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity, intermediates)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12_unsupported()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(end_entity, intermediates)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12_unsupported()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spki(key: &PublicKey) -> CertificateDer<'static> {
        CertificateDer::from([&SPKI_PREFIX[..], &key.0].concat())
    }

    #[test]
    fn dialer_rejects_any_key_but_the_dialed_one() {
        let tls = PeerTls::new(&SecretKey::generate(), &[]).unwrap();
        let (dialed, other) = (
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        );
        let verifier = tls.verifier(Some(dialed));
        assert!(verifier.check(&spki(&dialed), &[]).is_ok());
        assert!(verifier.check(&spki(&other), &[]).is_err());
        assert!(verifier.check(&spki(&dialed), &[spki(&other)]).is_err());
        assert!(verifier
            .check(&CertificateDer::from(vec![0; 44]), &[])
            .is_err());
    }

    #[test]
    fn acceptor_takes_any_well_formed_key() {
        let tls = PeerTls::new(&SecretKey::generate(), &[]).unwrap();
        let verifier = tls.verifier(None);
        assert!(verifier
            .check(&spki(&SecretKey::generate().public()), &[])
            .is_ok());
        assert_eq!(key_from_spki(&[0; 44]), None);
    }
}
