//! Fuzz the frozen frame codec (INFRA_SPEC.md §6, M0 item 7).
//!
//! Properties:
//! 1. `Frame::decode` never panics on arbitrary bytes.
//! 2. If decode succeeds, re-encoding reproduces the input byte-for-byte
//!    (the header layout is frozen; there is no lossy normalization).

#![no_main]

use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;
use proto::framing::{Frame, HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = Frame::decode(Bytes::copy_from_slice(data)) else {
        return; // errors are fine; panics are not
    };
    // Decode succeeded: the input must have been a full header + payload,
    // and re-encoding must reproduce it exactly.
    assert!(data.len() >= HEADER_LEN);
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    assert_eq!(&buf[..], data, "re-encode differs from input");

    // Decoding the re-encoded bytes yields the same frame (idempotence).
    let again = Frame::decode(buf.freeze()).expect("re-encoded frame must decode");
    assert_eq!(again, frame);
});
