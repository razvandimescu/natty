use std::fmt;
use std::io;

pub const ALPN: &[u8] = b"natty-tunnel/1";
pub(super) const LIST: &str = "?";
pub(super) const MAX_REQUEST_LEN: usize = 64;
pub(super) const MAX_LISTING_LEN: usize = 64 * 1024;
const MAX_NAME_LEN: usize = 63;
const MAX_LISTED: usize = 256;

/// The byte a host answers a request line with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ok,
    Denied,
    Unknown,
    Unavailable,
    /// A value this version does not name. It is a refusal.
    Other(u8),
}

impl Status {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Ok,
            1 => Self::Denied,
            2 => Self::Unknown,
            3 => Self::Unavailable,
            other => Self::Other(other),
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Denied => 1,
            Self::Unknown => 2,
            Self::Unavailable => 3,
            Self::Other(other) => other,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Denied => f.write_str("the host has not granted this key the service"),
            Self::Unknown => f.write_str("the host has no such service"),
            Self::Unavailable => f.write_str("the service is not answering on the host"),
            Self::Other(other) => write!(f, "the host refused the request (status {other})"),
        }
    }
}

/// 1 to 63 letters, digits and hyphens. Names compare in lower case.
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A request line without its newline. The result is `?` or a candidate name
/// in lower case; the policy decides whether the name exists.
pub(super) fn parse_request(line: &[u8]) -> io::Result<String> {
    let name = std::str::from_utf8(line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .trim()
        .to_lowercase();
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty request line",
        ));
    }
    Ok(name)
}

/// A listing comes from the other side and is untrusted: only valid, distinct
/// names are kept, so a caller can print or link them as they are.
pub(super) fn parse_listing(body: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(body).lines() {
        let name = line.trim().to_lowercase();
        if valid_name(&name) && !names.contains(&name) {
            names.push(name);
            if names.len() == MAX_LISTED {
                break;
            }
        }
    }
    names
}

/// A listing holds only valid, distinct names, whatever the host sent.
#[cfg(fuzzing)]
pub fn fuzz_tunnel(data: &[u8]) {
    if let Ok(request) = parse_request(data) {
        assert!(!request.is_empty());
    }
    let names = parse_listing(data);
    assert!(names.len() <= MAX_LISTED);
    for (i, name) in names.iter().enumerate() {
        assert!(valid_name(name));
        assert!(!names[..i].contains(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lines_are_lowercased_and_trimmed() {
        assert_eq!(parse_request(b" Web\r").unwrap(), "web");
        assert_eq!(parse_request(b"?").unwrap(), LIST);
        assert!(parse_request(b"").is_err());
        assert!(parse_request(b" \r").is_err());
        assert!(parse_request(&[0xff]).is_err());
    }

    #[test]
    fn every_byte_is_a_status_and_only_zero_is_ok() {
        for byte in 0..=u8::MAX {
            let status = Status::from_byte(byte);
            assert_eq!(status.byte(), byte);
            assert_eq!(status == Status::Ok, byte == 0);
        }
        assert_eq!(Status::from_byte(9), Status::Other(9));
    }

    #[test]
    fn names_are_letters_digits_and_hyphens() {
        assert!(valid_name("web-2"));
        assert!(valid_name(&"a".repeat(63)));
        assert!(!valid_name(&"a".repeat(64)));
        assert!(!valid_name(""));
        assert!(!valid_name("?"));
        assert!(!valid_name("a b"));
        assert!(!valid_name("a.b"));
    }

    #[test]
    fn listings_keep_valid_unique_names_only() {
        let body = b"web\n<img src=x onerror=alert(1)>\nWeb\n\x1b[31mred\n\ngit\r\n";
        assert_eq!(parse_listing(body), ["web", "git"]);
        let many: String = (0..1000).map(|i| format!("s{i}\n")).collect();
        assert_eq!(parse_listing(many.as_bytes()).len(), MAX_LISTED);
    }
}
