//! TCP services by name between two keys, through a natty relay.
//! `natty serve` runs beside the services and needs no inbound port. `natty
//! connect` gives one of them a local port on another machine.

mod env;
mod grants;

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use log::{debug, info, warn};
use natty::quinn::Connection;
use natty::tunnel::{self, OpenError, Policy};
use natty::{Endpoint, PublicKey, SecretKey, Welcome};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};

const USAGE: &str = "usage:
  natty key
  natty serve <relay> --grants <file> --service <name>=<host:port> ...
  natty connect <key>@<relay> <service> --port <port>
  natty list <key>@<relay>
environment:
  NATTY_KEY=<file>  the key of this side, made on first use (required)
  NATTY_CA=<pem>    one more trusted root for the certificate of the relay
  NATTY_LOG=debug   more log lines";

#[tokio::main]
async fn main() -> ExitCode {
    let debug = std::env::var("NATTY_LOG").is_ok_and(|level| level == "debug");
    log::set_max_level(if debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });
    let _ = log::set_logger(&Stderr);
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("natty: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Stderr;

impl log::Log for Stderr {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("natty")
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        match record.level() {
            log::Level::Info => eprintln!("{}", record.args()),
            level => eprintln!("{level}: {}", record.args()),
        }
    }

    fn flush(&self) {}
}

async fn run(args: &[String]) -> io::Result<()> {
    let (words, options) = split(args)?;
    match (words.as_slice(), options.as_slice()) {
        ([] | ["help"], _) => println!("{USAGE}"),
        (["key"], []) => println!("{}", key()?.public()),
        (["serve", relay], _) => serve(relay, &options).await?,
        (["connect", address, service], [("port", port)]) => {
            connect(address, service, port).await?
        }
        (["list", address], []) => list(address).await?,
        _ => return Err(io::Error::other(USAGE)),
    }
    Ok(())
}

type Options<'a> = Vec<(&'a str, &'a str)>;

/// Words, and options given as `--name value` or `--name=value`.
fn split(args: &[String]) -> io::Result<(Vec<&str>, Options<'_>)> {
    let (mut words, mut options) = (Vec::new(), Vec::new());
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        let Some(option) = arg.strip_prefix("--") else {
            words.push(arg);
            continue;
        };
        options.push(match option.split_once('=') {
            Some(pair) => pair,
            None => (option, args.next().ok_or_else(|| io::Error::other(USAGE))?),
        });
    }
    Ok((words, options))
}

fn key() -> io::Result<SecretKey> {
    if std::env::var_os("NATTY_KEY").is_none() {
        return Err(io::Error::other(
            "set NATTY_KEY=<file>; natty makes the file on first use",
        ));
    }
    env::secret_key()
}

fn bind(relay: &str) -> io::Result<Endpoint> {
    Endpoint::bind(key()?, relay, env::relay_tls()?, &[tunnel::ALPN])
}

fn peer_address(address: &str) -> io::Result<(PublicKey, &str)> {
    let (key, relay) = address
        .split_once('@')
        .ok_or_else(|| io::Error::other(format!("{address}: expected <key>@<relay>")))?;
    Ok((key.parse().map_err(io::Error::other)?, relay))
}

async fn serve(relay: &str, options: &[(&str, &str)]) -> io::Result<()> {
    let mut path = None;
    let mut upstreams = HashMap::new();
    for &(option, value) in options {
        match option {
            "grants" if path.is_none() => path = Some(PathBuf::from(value)),
            "service" => {
                let (name, upstream) = service(value)?;
                if upstreams.insert(name, upstream).is_some() {
                    return Err(io::Error::other(format!(
                        "{value}: the name is given twice"
                    )));
                }
            }
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    let (Some(path), false) = (path, upstreams.is_empty()) else {
        return Err(io::Error::other(USAGE));
    };
    let grants = grants::load(&path, &upstreams)?;
    let endpoint = bind(relay)?;
    let (policy, changes) = watch::channel(Policy { grants, upstreams });
    tokio::spawn(grants::follow(path, policy));
    let address = format!("{}@{relay}", endpoint.public_key());
    tokio::spawn(report_relay(endpoint.relay_state(), address));
    let stopped = tokio::select! {
        () = tunnel::serve(&endpoint, changes) => Ok(()),
        stopped = stop() => stopped,
    };
    endpoint.close().await;
    stopped
}

/// `name=host:port`. The host stays a name, so each stream resolves it again.
fn service(value: &str) -> io::Result<(String, String)> {
    let parsed = value.split_once('=').filter(|(name, upstream)| {
        tunnel::valid_name(name)
            && upstream
                .rsplit_once(':')
                .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    });
    match parsed {
        Some((name, upstream)) => Ok((name.to_lowercase(), upstream.to_owned())),
        None => Err(io::Error::other(format!(
            "{value}: expected <name>=<host:port>, the name from letters, digits and hyphens"
        ))),
    }
}

async fn report_relay(mut state: watch::Receiver<Option<Welcome>>, address: String) {
    loop {
        if state.borrow_and_update().is_some() {
            info!("serving as {address}");
        } else {
            info!("connecting to the relay as {address}");
        }
        if state.changed().await.is_err() {
            return;
        }
    }
}

/// Ctrl-C, or the SIGTERM that stops a container. As process 1 of a
/// container, natty gets SIGTERM only because a handler exists.
async fn stop() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            interrupted = tokio::signal::ctrl_c() => interrupted,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

struct Tunnel {
    endpoint: Endpoint,
    peer: PublicKey,
    conn: Mutex<Option<Connection>>,
}

impl Tunnel {
    /// One connection, shared by every stream and dialed again once closed.
    async fn connection(&self) -> Result<Connection, OpenError> {
        let mut conn = self.conn.lock().await;
        if let Some(open) = conn.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(open.clone());
        }
        let dialed = tunnel::dial(&self.endpoint, self.peer).await?;
        *conn = Some(dialed.clone());
        Ok(dialed)
    }
}

async fn connect(address: &str, service: &str, port: &str) -> io::Result<()> {
    let (peer, relay) = peer_address(address)?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::other(format!("{port}: not a port")))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let tunnel = Arc::new(Tunnel {
        endpoint: bind(relay)?,
        peer,
        conn: Mutex::default(),
    });
    let stopped = tokio::select! {
        failed = forward(listener, Arc::clone(&tunnel), service.to_lowercase()) => failed,
        stopped = stop() => stopped,
    };
    tunnel.endpoint.close().await;
    stopped
}

async fn forward(listener: TcpListener, tunnel: Arc<Tunnel>, service: String) -> io::Result<()> {
    let conn = tunnel.connection().await.map_err(io::Error::other)?;
    let granted = tunnel::list(&conn).await.map_err(io::Error::other)?;
    if !granted.contains(&service) {
        return Err(io::Error::other(format!(
            "the host offers no service `{service}` to this key: {}",
            tunnel.endpoint.public_key()
        )));
    }
    info!("{} -> {service}", listener.local_addr()?);
    loop {
        let (tcp, _) = listener.accept().await?;
        let tunnel = Arc::clone(&tunnel);
        let service = service.clone();
        tokio::spawn(async move {
            let opened = async {
                let conn = tunnel.connection().await?;
                tunnel::open(&conn, &service).await
            };
            match opened.await {
                Ok((send, recv)) => {
                    if let Err(e) = tunnel::pipe(send, recv, tcp).await {
                        debug!("{service}: {e}");
                    }
                }
                Err(e) => warn!("{service}: {e}"),
            }
        });
    }
}

async fn list(address: &str) -> io::Result<()> {
    let (peer, relay) = peer_address(address)?;
    let endpoint = bind(relay)?;
    let listed = async {
        let conn = tunnel::dial(&endpoint, peer).await?;
        tunnel::list(&conn).await
    };
    let listed = listed.await;
    endpoint.close().await;
    for name in listed.map_err(io::Error::other)? {
        println!("{name}");
    }
    Ok(())
}
