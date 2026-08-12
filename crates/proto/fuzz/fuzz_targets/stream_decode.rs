//! Fuzz the length-prefixed stream decoder under arbitrary chunkings
//! (INFRA_SPEC.md §6, M0 item 7).
//!
//! Properties:
//! 1. `Frame::decode_stream` never panics, whatever bytes and chunk
//!    boundaries the transport delivers.
//! 2. Chunking is invisible: feeding the same bytes in fuzzer-chosen chunks
//!    yields exactly the frames (or the error) that feeding them all at once
//!    yields.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use proto::framing::Frame;

fuzz_target!(|data: &[u8]| {
    // First byte selects how many chunk boundaries to derive; the following
    // bytes are boundary seeds; the rest is the stream itself.
    let (n_splits, rest) = match data.split_first() {
        Some((n, rest)) => ((*n as usize).min(16), rest),
        None => return,
    };
    if rest.len() < n_splits {
        return;
    }
    let (seeds, stream) = rest.split_at(n_splits);

    // Reference: decode the whole stream in one shot.
    let mut whole = BytesMut::from(stream);
    let mut expected = Vec::new();
    let reference: Result<(), _> = loop {
        match Frame::decode_stream(&mut whole) {
            Ok(Some(f)) => expected.push(f),
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };

    // Chunked: same bytes, boundaries derived from the seeds.
    let mut points: Vec<usize> = seeds
        .iter()
        .map(|s| (*s as usize * 257) % (stream.len() + 1))
        .collect();
    points.sort_unstable();
    points.push(stream.len());

    let mut acc = BytesMut::new();
    let mut got = Vec::new();
    let mut prev = 0usize;
    let mut chunked: Result<(), _> = Ok(());
    'outer: for p in points {
        acc.extend_from_slice(&stream[prev..p]);
        prev = p;
        loop {
            match Frame::decode_stream(&mut acc) {
                Ok(Some(f)) => got.push(f),
                Ok(None) => break,
                Err(e) => {
                    chunked = Err(e);
                    break 'outer;
                }
            }
        }
    }

    assert_eq!(got, expected, "chunking changed the decoded frames");
    assert_eq!(
        chunked.err(),
        reference.err(),
        "chunking changed the error outcome"
    );
});
