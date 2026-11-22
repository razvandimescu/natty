//! TCP services by name between two keys. Each bidirectional stream carries
//! one request line, one status byte back, then raw bytes both ways. The
//! request line names a service on the host, or is `?` to list the services
//! granted to the caller. Wire format: docs/design.md, "Tunnel".

mod pipe;
mod proto;
mod serve;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub use pipe::pipe;
#[cfg(fuzzing)]
pub use proto::fuzz_tunnel;
pub use proto::{valid_name, Status, ALPN};
pub use serve::serve;

use crate::{Endpoint, PublicKey};
use proto::{parse_listing, LIST, MAX_LISTING_LEN};

const RELAY_WAIT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Who may open what on a host. Service names are in lower case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The services each key may open. A key with an entry is known to the
    /// host, even when the entry is empty.
    pub grants: HashMap<PublicKey, BTreeSet<String>>,
    /// The address of each service, as `host:port`.
    pub upstreams: HashMap<String, String>,
}

impl Policy {
    fn knows(&self, peer: &PublicKey) -> bool {
        self.grants.contains_key(peer)
    }

    fn permits(&self, peer: &PublicKey, service: &str) -> bool {
        self.grants
            .get(peer)
            .is_some_and(|granted| granted.contains(service))
    }

    /// The grant is checked before the service, so a key without a grant
    /// learns nothing about which services the host has.
    fn resolve(&self, peer: &PublicKey, service: &str) -> Result<&str, Status> {
        if !self.permits(peer, service) {
            return Err(Status::Denied);
        }
        self.upstreams
            .get(service)
            .map(String::as_str)
            .ok_or(Status::Unknown)
    }

    /// Granted services that exist, so a listing offers only names that open.
    fn listing(&self, peer: &PublicKey) -> Vec<&str> {
        self.grants
            .get(peer)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .filter(|service| self.upstreams.contains_key(*service))
            .collect()
    }
}

#[derive(Debug)]
pub enum OpenError {
    RelayDown,
    Unreachable(String),
    Refused(Status),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RelayDown => f.write_str("the relay is not reachable"),
            Self::Unreachable(reason) => f.write_str(reason),
            Self::Refused(status) => status.fmt(f),
        }
    }
}

impl std::error::Error for OpenError {}

fn lost(e: impl fmt::Display) -> OpenError {
    let text = e.to_string();
    let printable = text.chars().filter(|c| *c == ' ' || c.is_ascii_graphic());
    OpenError::Unreachable(printable.collect())
}

/// Dials `peer` once the relay session of `endpoint` is up. The endpoint
/// must be bound with [`ALPN`].
pub async fn dial(endpoint: &Endpoint, peer: PublicKey) -> Result<Connection, OpenError> {
    let mut relay = endpoint.relay_state();
    if !matches!(
        timeout(RELAY_WAIT, relay.wait_for(Option::is_some)).await,
        Ok(Ok(_))
    ) {
        return Err(OpenError::RelayDown);
    }
    within(DIAL_TIMEOUT, async {
        endpoint.connect(peer).await.map_err(lost)
    })
    .await
}

/// Opens a stream to `service` on the host. After `Ok`, the stream carries
/// the bytes of the service.
pub async fn open(conn: &Connection, service: &str) -> Result<(SendStream, RecvStream), OpenError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(lost)?;
    within(REQUEST_TIMEOUT, request(&mut send, &mut recv, service)).await?;
    Ok((send, recv))
}

/// The services the host grants to this key.
pub async fn list(conn: &Connection) -> Result<Vec<String>, OpenError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(lost)?;
    let body = within(REQUEST_TIMEOUT, async {
        request(&mut send, &mut recv, LIST).await?;
        recv.read_to_end(MAX_LISTING_LEN).await.map_err(lost)
    })
    .await?;
    Ok(parse_listing(&body))
}

async fn within<T>(
    limit: Duration,
    work: impl Future<Output = Result<T, OpenError>>,
) -> Result<T, OpenError> {
    timeout(limit, work).await.unwrap_or_else(|_| {
        Err(OpenError::Unreachable(format!(
            "no answer within {} s",
            limit.as_secs()
        )))
    })
}

async fn request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    line: &str,
) -> Result<(), OpenError> {
    send.write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(lost)?;
    match Status::from_byte(recv.read_u8().await.map_err(lost)?) {
        Status::Ok => Ok(()),
        status => Err(OpenError::Refused(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    fn policy(peer: PublicKey) -> Policy {
        Policy {
            grants: HashMap::from([(peer, BTreeSet::from(["web".into(), "gone".into()]))]),
            upstreams: HashMap::from([
                ("web".into(), "127.0.0.1:8080".into()),
                ("db".into(), "127.0.0.1:5432".into()),
            ]),
        }
    }

    #[test]
    fn a_grant_is_checked_before_the_service() {
        let peer = SecretKey::generate().public();
        let stranger = SecretKey::generate().public();
        let policy = policy(peer);
        assert_eq!(policy.resolve(&peer, "web"), Ok("127.0.0.1:8080"));
        assert_eq!(policy.resolve(&peer, "gone"), Err(Status::Unknown));
        assert_eq!(policy.resolve(&peer, "db"), Err(Status::Denied));
        assert_eq!(policy.resolve(&stranger, "web"), Err(Status::Denied));
        assert_eq!(policy.resolve(&stranger, "nope"), Err(Status::Denied));
    }

    #[test]
    fn a_lost_connection_reads_as_printable_text() {
        let closed = "closed by peer: \x1b]52;c;aGk=\x07<b>busy</b>\r\n (code 9)";
        let printable = "closed by peer: ]52;c;aGk=<b>busy</b> (code 9)";
        assert_eq!(lost(closed).to_string(), printable);
        let own = "closed by peer: busy (code 2)";
        assert_eq!(lost(own).to_string(), own);
    }

    #[test]
    fn a_listing_offers_granted_services_that_exist() {
        let peer = SecretKey::generate().public();
        let policy = policy(peer);
        assert_eq!(policy.listing(&peer), ["web"]);
        assert!(policy.listing(&SecretKey::generate().public()).is_empty());
    }
}
