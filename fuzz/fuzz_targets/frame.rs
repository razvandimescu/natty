#![no_main]
//! Relay frames as one byte stream: what a relay reads from any client, and a
//! client from its relay.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;
use natty::wire::read_frame;

fuzz_target!(|data: &[u8]| {
    let mut stream = data;
    while let Ok(frame) = now(read_frame(&mut stream)) {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(now(read_frame(&mut &buf[..])).ok(), Some(frame));
    }
});

/// Reads from a byte slice never wait, so one poll completes the future.
fn now<F: Future>(f: F) -> F::Output {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => unreachable!(),
    }
}
