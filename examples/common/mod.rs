use std::io;
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{version, ClientConfig, RootCertStore};

/// Mozilla's roots, plus NATTY_CA=<pem> for relays with self-signed certs.
pub fn relay_tls() -> io::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Ok(path) = std::env::var("NATTY_CA") {
        for cert in CertificateDer::pem_file_iter(&path).map_err(io::Error::other)? {
            roots
                .add(cert.map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
