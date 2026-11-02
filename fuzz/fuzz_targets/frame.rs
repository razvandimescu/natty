#![no_main]
//! Relay frames as one byte stream: what a relay reads from any client, and a
//! client from its relay. Every frame that decodes must survive a re-encode.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;
use natty::wire::read_frame;

fuzz_target!(|data: &[u8]| {
    let mut stream = data;
    while let Some(Ok(frame)) = now(read_frame(&mut stream)) {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let again = now(read_frame(&mut &buf[..])).and_then(Result::ok);
        assert_eq!(again, Some(frame));
    }
});

/// Reads from a byte slice never wait, so one poll completes the future.
fn now<F: Future>(f: F) -> Option<F::Output> {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => Some(out),
        Poll::Pending => None,
    }
}
