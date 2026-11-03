#![no_main]
//! Keys as text, from the `<key>@<relay>` addresses that users and peers pass
//! around. A key has one text form: every accepted string is its encoding.

use libfuzzer_sys::fuzz_target;
use natty::PublicKey;

fuzz_target!(|text: &str| {
    if let Ok(key) = text.parse::<PublicKey>() {
        assert_eq!(key.to_string(), text);
    }
});
