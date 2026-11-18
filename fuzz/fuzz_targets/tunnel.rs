#![no_main]
//! Tunnel request lines, which a host reads from any dialer, and listings,
//! which a dialer reads from a host. See `natty::tunnel::fuzz_tunnel`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| natty::tunnel::fuzz_tunnel(data));
