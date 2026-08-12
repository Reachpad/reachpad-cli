//! Round-trip property tests for the frozen formats (INFRA_SPEC.md §4.2,
//! §6). These pin the wire-level invariants downstream crates rely on:
//! encode∘decode is the identity on frames, stream reassembly is chunking-
//! independent, and the event envelope survives a prost round trip.

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use prost::Message;
use proto::framing::{Frame, FrameError, HEADER_LEN};
use proto::wire;

/// Arbitrary frame: random version/seq/ack/channel and payload up to 64 KiB.
fn arb_frame() -> impl Strategy<Value = Frame> {
    (
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u16>(),
        proptest::collection::vec(any::<u8>(), 0..=64 * 1024),
    )
        .prop_map(|(version, seq, ack, channel, payload)| Frame {
            version,
            seq,
            ack,
            channel,
            payload: Bytes::from(payload),
        })
}

fn arb_event() -> impl Strategy<Value = wire::Event> {
    (
        any::<u32>(),
        proptest::collection::vec(any::<u8>(), 0..64),
        any::<u64>(),
        proptest::collection::vec(any::<u8>(), 0..64),
        any::<u32>(),
        any::<u64>(),
        proptest::collection::vec(any::<u8>(), 0..4096),
    )
        .prop_map(
            |(v, workspace, seq, principal, r#type, ts_ms, payload)| wire::Event {
                v,
                workspace,
                seq,
                principal,
                r#type,
                ts_ms,
                payload,
            },
        )
}

proptest! {
    /// §6: encode → decode is the identity for any frame.
    #[test]
    fn frame_encode_decode_identity(frame in arb_frame()) {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        prop_assert_eq!(buf.len(), HEADER_LEN + frame.payload.len());
        let decoded = Frame::decode(buf.freeze()).unwrap();
        prop_assert_eq!(decoded, frame);
    }

    /// Stream encoding reassembles identically regardless of where the byte
    /// stream is split (transport chunking must be invisible).
    #[test]
    fn stream_reassembles_under_random_splits(
        frames in proptest::collection::vec(arb_frame(), 1..8),
        splits in proptest::collection::vec(any::<u16>(), 0..32),
    ) {
        let mut stream = BytesMut::new();
        for f in &frames {
            f.encode_stream(&mut stream);
        }
        let stream = stream.freeze();

        // Derive split points inside the stream from the random u16s.
        let mut points: Vec<usize> = splits
            .iter()
            .map(|s| usize::from(*s) % (stream.len() + 1))
            .collect();
        points.sort_unstable();
        points.dedup();
        points.push(stream.len());

        let mut acc = BytesMut::new();
        let mut out = Vec::new();
        let mut prev = 0usize;
        for p in points {
            acc.extend_from_slice(&stream[prev..p]);
            prev = p;
            while let Some(f) = Frame::decode_stream(&mut acc).unwrap() {
                out.push(f);
            }
        }
        prop_assert!(acc.is_empty(), "no leftover bytes after full stream");
        prop_assert_eq!(out, frames);
    }

    /// Decoding arbitrary bytes never panics; success implies the input was
    /// at least a full header.
    #[test]
    fn frame_decode_arbitrary_bytes_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..=1024)
    ) {
        let len = bytes.len();
        match Frame::decode(Bytes::from(bytes)) {
            Ok(f) => {
                prop_assert!(len >= HEADER_LEN);
                prop_assert_eq!(f.payload.len(), len - HEADER_LEN);
            }
            Err(FrameError::Truncated { .. }) => prop_assert!(len < HEADER_LEN),
            Err(FrameError::TooLarge(_)) => {
                // unreachable at <=1 KiB inputs, but not a panic either way
                prop_assert!(false, "TooLarge on small input");
            }
        }
    }

    /// §4.2 frozen envelope: prost round trip is the identity.
    #[test]
    fn event_envelope_prost_roundtrip(event in arb_event()) {
        let bytes = event.encode_to_vec();
        let back = wire::Event::decode(bytes.as_slice()).unwrap();
        prop_assert_eq!(back, event);
    }
}
