#![no_main]
//! Binding requests to the relay's STUN responder, from any UDP source. A
//! response must carry the source address back, IPv4-mapped IPv6 as IPv4.

use std::net::{Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use natty::stun::{binding_response, mapped_address};
use natty::wire::canonical;

fuzz_target!(|data: &[u8]| {
    let Some((head, req)) = data.split_first_chunk::<18>() else {
        return;
    };
    let ip: [u8; 16] = head[..16].try_into().unwrap();
    let src = SocketAddr::from((Ipv6Addr::from(ip), u16::from_be_bytes([head[16], head[17]])));
    let Some(resp) = binding_response(req, src) else {
        return;
    };
    let txid = req[8..20].try_into().unwrap();
    assert_eq!(mapped_address(&resp, txid), Some(canonical(src)));
});
