use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::sync::Arc;

use natty::SecretKey;
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

/// A new key per run, or with NATTY_KEY=<file> the same key every run. The
/// file holds the 32-byte seed and is created on first use.
pub fn secret_key() -> io::Result<SecretKey> {
    let Ok(path) = std::env::var("NATTY_KEY") else {
        return Ok(SecretKey::generate());
    };
    match fs::read(&path) {
        Ok(bytes) => {
            let seed = <[u8; 32]>::try_from(bytes)
                .map_err(|_| io::Error::other(format!("{path}: not a 32-byte key")))?;
            Ok(SecretKey::from_seed(seed))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.open(&path)?.write_all(key.seed())?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}
