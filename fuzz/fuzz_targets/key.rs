#![no_main]
//! Keys as text, from the `<key>@<relay>` addresses that users and peers pass
//! around. A key has one text form: every accepted string is its encoding.

use libfuzzer_sys::fuzz_target;
use natty::PublicKey;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = text.parse::<PublicKey>() {
        assert_eq!(key.to_string(), text);
    }
});
