use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use natty_relay::{Config, Relay};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{version, ServerConfig};

const USAGE: &str = "usage: natty-relay --cert PEM --key PEM [--listen [::]:443] [--stun [::]:3478] [--cap BYTES_PER_SEC] [--per-ip N]";

struct Args {
    cert: PathBuf,
    key: PathBuf,
    listen: SocketAddr,
    stun: SocketAddr,
    cap: u32,
    per_ip: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut cert = None;
    let mut key = None;
    let mut listen = "[::]:443".parse().unwrap();
    let mut stun = "[::]:3478".parse().unwrap();
    let mut cap = 1 << 20;
    let mut per_ip = 16;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--cert" => cert = Some(PathBuf::from(&value)),
            "--key" => key = Some(PathBuf::from(&value)),
            "--listen" => listen = parse(&flag, &value)?,
            "--stun" => stun = parse(&flag, &value)?,
            "--cap" => cap = parse(&flag, &value)?,
            "--per-ip" => per_ip = parse(&flag, &value)?,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(Args {
        cert: cert.ok_or("--cert is required")?,
        key: key.ok_or("--key is required")?,
        listen,
        stun,
        cap,
        per_ip,
    })
}

fn parse<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn tls_config(args: &Args) -> io::Result<ServerConfig> {
    let certs = CertificateDer::pem_file_iter(&args.cert)
        .and_then(Iterator::collect)
        .map_err(|e| io::Error::other(format!("{}: {e}", args.cert.display())))?;
    let key = PrivateKeyDer::from_pem_file(&args.key)
        .map_err(|e| io::Error::other(format!("{}: {e}", args.key.display())))?;
    ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&version::TLS13])
        .and_then(|b| b.with_no_client_auth().with_single_cert(certs, key))
        .map_err(io::Error::other)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2);
    });
    let listener = TcpListener::bind(args.listen).await?;
    let stun = UdpSocket::bind(args.stun).await?;
    let relay = Relay::new(Config {
        tls: Arc::new(tls_config(&args)?),
        cap: args.cap,
        max_conns_per_ip: args.per_ip,
        stun_port: stun.local_addr()?.port(),
    });
    eprintln!(
        "natty-relay listening on {} (stun {})",
        args.listen, args.stun
    );
    tokio::join!(relay.serve_tcp(listener), relay.serve_stun(stun));
    Ok(())
}
