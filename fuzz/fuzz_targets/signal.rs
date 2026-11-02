#![no_main]
//! Signals between peers: CANDIDATES through the relay, PROBE and PROBE_ACK
//! over UDP. See `natty::fuzz_signal`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| natty::fuzz_signal(data));
