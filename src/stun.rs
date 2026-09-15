//! RFC 5389 subset: binding request, success response, XOR-MAPPED-ADDRESS.

use std::net::{IpAddr, SocketAddr};

const MAGIC: [u8; 4] = 0x2112_A442u32.to_be_bytes();
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const XOR_MAPPED_ADDRESS: [u8; 2] = [0x00, 0x20];

/// RFC 5389 binding request in, success response with XOR-MAPPED-ADDRESS out.
/// Attributes in the request are not parsed.
pub fn binding_response(req: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < 20
        || req[0..2] != BINDING_REQUEST
        || req[4..8] != MAGIC
        || usize::from(u16::from_be_bytes([req[2], req[3]])) != req.len() - 20
    {
        return None;
    }
    let txid = &req[8..20];
    let (family, addr): (u8, Vec<u8>) = match src.ip().to_canonical() {
        IpAddr::V4(ip) => (1, xor(&ip.octets(), txid)),
        IpAddr::V6(ip) => (2, xor(&ip.octets(), txid)),
    };
    let attr_len = 4 + addr.len() as u16;

    let mut out = Vec::with_capacity(24 + addr.len());
    out.extend_from_slice(&BINDING_SUCCESS);
    out.extend_from_slice(&(4 + attr_len).to_be_bytes());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(txid);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS);
    out.extend_from_slice(&attr_len.to_be_bytes());
    out.extend_from_slice(&[0, family]);
    out.extend_from_slice(&(src.port() ^ 0x2112).to_be_bytes());
    out.extend_from_slice(&addr);
    Some(out)
}

pub fn binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST);
    req[4..8].copy_from_slice(&MAGIC);
    req[8..20].copy_from_slice(txid);
    req
}

/// Cheap classification; no UDP payload QUIC sends starts this way.
pub fn is_binding_response(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0..2] == BINDING_SUCCESS && packet[4..8] == MAGIC
}

/// The XOR-MAPPED-ADDRESS of a success response to the request `txid`.
pub fn mapped_address(resp: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if !is_binding_response(resp) || resp[8..20] != *txid {
        return None;
    }
    let mut attrs = resp.get(20..20 + usize::from(u16::from_be_bytes([resp[2], resp[3]])))?;
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_be_bytes([attrs[2], attrs[3]]));
        let value = attrs.get(4..4 + len)?;
        if attrs[0..2] == XOR_MAPPED_ADDRESS && len >= 4 {
            let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
            let octets = xor(&value[4..], txid);
            let ip = match value[1] {
                1 => IpAddr::from(<[u8; 4]>::try_from(octets).ok()?),
                2 => IpAddr::from(<[u8; 16]>::try_from(octets).ok()?),
                _ => return None,
            };
            return Some(SocketAddr::new(ip, port));
        }
        attrs = attrs
            .get((4 + len).next_multiple_of(4)..)
            .unwrap_or_default();
    }
    None
}

/// XOR with the magic cookie then the transaction ID, as far as `ip` goes.
fn xor(ip: &[u8], txid: &[u8]) -> Vec<u8> {
    let key = MAGIC.iter().chain(txid);
    ip.iter().zip(key).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    fn request() -> Vec<u8> {
        [&BINDING_REQUEST[..], &[0, 0], &MAGIC, &TXID].concat()
    }

    // RFC 5769 section 2.2 and 2.3 test vectors.
    #[test]
    fn xor_mapped_address_ipv4() {
        let resp = binding_response(&request(), "192.0.2.1:32853".parse().unwrap()).unwrap();
        assert_eq!(&resp[..2], &BINDING_SUCCESS);
        assert_eq!(&resp[8..20], &TXID);
        assert_eq!(
            &resp[20..],
            &[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]
        );
    }

    #[test]
    fn xor_mapped_address_ipv6() {
        let src = "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
            .parse()
            .unwrap();
        let resp = binding_response(&request(), src).unwrap();
        assert_eq!(
            &resp[20..],
            &[
                0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3,
                0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9
            ]
        );
    }

    #[test]
    fn mapped_address_roundtrips_through_the_responder() {
        for src in ["192.0.2.1:32853", "[2001:db8::7]:443"] {
            let src: SocketAddr = src.parse().unwrap();
            let resp = binding_response(&binding_request(&TXID), src).unwrap();
            assert_eq!(mapped_address(&resp, &TXID), Some(src));
            assert_eq!(mapped_address(&resp, &[0; 12]), None);
        }
    }

    #[test]
    fn ignores_non_binding_requests() {
        let src = "192.0.2.1:1".parse().unwrap();
        let mut bad_type = request();
        bad_type[1] = 0x02;
        let mut bad_len = request();
        bad_len[3] = 4;
        assert!(binding_response(&bad_type, src).is_none());
        assert!(binding_response(&bad_len, src).is_none());
        assert!(binding_response(&request()[..19], src).is_none());
    }
}
