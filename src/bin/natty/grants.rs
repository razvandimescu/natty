//! The grants file. Each line holds one key and then its services, with
//! spaces between them. `#` starts a comment.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use log::{info, warn};
use natty::tunnel::{valid_name, Policy};
use natty::PublicKey;
use tokio::sync::watch;

pub type Grants = HashMap<PublicKey, BTreeSet<String>>;

const POLL: Duration = Duration::from_millis(if cfg!(test) { 20 } else { 5000 });

pub fn load(path: &Path, upstreams: &HashMap<String, String>) -> io::Result<Grants> {
    let text = fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let (grants, warnings) = parse(&text, upstreams);
    report(path, &grants, &warnings);
    Ok(grants)
}

/// Reads the file again at each poll and publishes a change. While the file
/// cannot be read, the last grants stay.
pub async fn follow(path: PathBuf, policy: watch::Sender<Policy>) {
    let mut unreadable = false;
    loop {
        tokio::time::sleep(POLL).await;
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                if !unreadable {
                    warn!("{}: {e}; the last grants stay", path.display());
                }
                unreadable = true;
                continue;
            }
        };
        unreadable = false;
        let (grants, warnings) = parse(&text, &policy.borrow().upstreams);
        let changed = policy.send_if_modified(|policy| {
            let changed = policy.grants != grants;
            if changed {
                policy.grants = grants;
            }
            changed
        });
        if changed {
            report(&path, &policy.borrow().grants, &warnings);
        }
    }
}

fn report(path: &Path, grants: &Grants, warnings: &[String]) {
    for warning in warnings {
        warn!("{}: {warning}", path.display());
    }
    info!("grants from {}: {} keys", path.display(), grants.len());
}

/// A line that does not start with a key grants nothing. A name that is not
/// a service of this agent stays in the grants when it is a valid name, so
/// its key gets `unknown` and not `denied`.
fn parse(text: &str, upstreams: &HashMap<String, String>) -> (Grants, Vec<String>) {
    let mut grants = Grants::new();
    let mut warnings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let mut words = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let Some(key) = words.next() else {
            continue;
        };
        let Ok(key) = key.parse::<PublicKey>() else {
            warnings.push(format!("line {number}: no key at the start, ignored"));
            continue;
        };
        let services = grants.entry(key).or_default();
        for word in words {
            let name = word.to_lowercase();
            if !upstreams.contains_key(&name) {
                warnings.push(format!(
                    "line {number}: `{name}` is not a service of this agent"
                ));
            }
            if valid_name(&name) {
                services.insert(name);
            }
        }
    }
    (grants, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use natty::SecretKey;

    fn upstreams() -> HashMap<String, String> {
        HashMap::from([("web".into(), "127.0.0.1:80".into())])
    }

    #[test]
    fn each_line_grants_its_key_the_listed_services() {
        let (alice, bob) = (
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        );
        let text = format!("# team\n{alice} Web db  # two\n\n{bob}\n{alice} web\n");
        let (grants, warnings) = parse(&text, &upstreams());
        assert_eq!(grants[&alice], BTreeSet::from(["db".into(), "web".into()]));
        assert!(grants[&bob].is_empty());
        assert_eq!(grants.len(), 2);
        assert_eq!(warnings, ["line 2: `db` is not a service of this agent"]);
    }

    #[test]
    fn a_bad_line_grants_nothing_and_the_other_lines_stay() {
        let alice = SecretKey::generate().public();
        let text = format!("web {alice}\n{alice} web a/b\n");
        let (grants, warnings) = parse(&text, &upstreams());
        assert_eq!(grants[&alice], BTreeSet::from(["web".into()]));
        assert_eq!(grants.len(), 1);
        assert_eq!(
            warnings,
            [
                "line 1: no key at the start, ignored",
                "line 2: `a/b` is not a service of this agent"
            ]
        );
    }

    #[tokio::test]
    async fn a_changed_file_is_published_and_an_unreadable_file_keeps_the_grants() {
        let alice = SecretKey::generate().public();
        let path = std::env::temp_dir().join(format!("natty-grants-{alice}"));
        fs::write(&path, format!("{alice} web\n")).unwrap();
        let policy = Policy {
            grants: load(&path, &upstreams()).unwrap(),
            upstreams: upstreams(),
        };
        let (tx, mut rx) = watch::channel(policy);
        let following = tokio::spawn(follow(path.clone(), tx));

        fs::write(&path, format!("{alice}\n")).unwrap();
        rx.changed().await.unwrap();
        assert!(rx.borrow_and_update().grants[&alice].is_empty());

        fs::remove_file(&path).unwrap();
        tokio::time::sleep(POLL * 3).await;
        assert!(!rx.has_changed().unwrap());
        assert!(rx.borrow().grants.contains_key(&alice));
        following.abort();
    }
}
