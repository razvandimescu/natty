#![no_main]
//! STUN responses to an endpoint. Any host can send them to its UDP port. The
//! transaction ID comes from the input, so the attribute parser is reached.

use libfuzzer_sys::fuzz_target;
use natty::stun::mapped_address;

fuzz_target!(|data: &[u8]| {
    if let Some(txid) = data.get(8..20) {
        let _ = mapped_address(data, txid.try_into().unwrap());
    }
});
