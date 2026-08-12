//! Property tests for [`proto::quic::FrameAccumulator`] — the EXACT decoder
//! both hub's and reach's QUIC stream readers run
//! (ADR-0026). Complements the libfuzzer targets in `fuzz/` (which cover
//! `Frame::decode`/`decode_stream` directly) with the accumulator's
//! chunked-push shape:
//!
//! - arbitrary byte soup, arbitrarily chunked, never panics and yields
//!   only typed errors ([`FrameError::TooLarge`]/[`FrameError::Truncated`]);
//! - well-formed frames decode identically under EVERY chunking, so QUIC's
//!   read sizes cannot matter;
//! - a stream dying mid-frame is always visible (`buffered() > 0`);
//! - garbage after valid frames still yields the valid prefix first.

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use proto::framing::{Frame, FrameError, HEADER_LEN, MAX_PAYLOAD};
use proto::quic::FrameAccumulator;

fn arb_frame() -> impl Strategy<Value = Frame> {
    (
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u16>(),
        proptest::collection::vec(any::<u8>(), 0..600),
    )
        .prop_map(|(version, seq, ack, channel, payload)| Frame {
            version,
            seq,
            ack,
            channel,
            payload: Bytes::from(payload),
        })
}

/// Split `data` at the given fractions — an arbitrary chunking.
fn chunks(data: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let mut cuts: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
    cuts.sort_unstable();
    let mut out = Vec::new();
    let mut prev = 0;
    for cut in cuts {
        out.push(data[prev..cut].to_vec());
        prev = cut;
    }
    out.push(data[prev..].to_vec());
    out
}

/// Drive an accumulator over chunks; collect frames until error/end.
fn drive(chunks: &[Vec<u8>]) -> (Vec<Frame>, Option<FrameError>, usize) {
    let mut acc = FrameAccumulator::new();
    let mut frames = Vec::new();
    for chunk in chunks {
        acc.push(chunk);
        loop {
            match acc.next_frame() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(e) => return (frames, Some(e), acc.buffered()),
            }
        }
    }
    (frames, None, acc.buffered())
}

proptest! {
    /// Garbage in, typed errors out — NEVER a panic. (This function body
    /// completing at all is the no-panic proof; the match is exhaustive
    /// over the decoder's whole error surface.)
    #[test]
    fn arbitrary_bytes_never_panic_the_decoder(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
    ) {
        let (frames, error, _buffered) = drive(&chunks(&data, &cuts));
        if let Some(e) = error {
            let typed = matches!(e, FrameError::TooLarge(_) | FrameError::Truncated { .. });
            prop_assert!(typed, "untyped decoder error: {}", e);
        }
        // Any frames decoded before an error must round-trip.
        for frame in frames {
            let mut buf = BytesMut::new();
            frame.encode_stream(&mut buf);
            let mut acc = FrameAccumulator::new();
            acc.push(&buf);
            prop_assert_eq!(acc.next_frame().unwrap().unwrap(), frame);
        }
    }

    /// Chunk boundaries are invisible: every chunking of a valid frame
    /// sequence decodes to exactly that sequence, with nothing buffered.
    #[test]
    fn valid_frames_survive_every_chunking(
        frames in proptest::collection::vec(arb_frame(), 1..6),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
    ) {
        let mut wire = BytesMut::new();
        for frame in &frames {
            frame.encode_stream(&mut wire);
        }
        let (decoded, error, buffered) = drive(&chunks(&wire, &cuts));
        prop_assert!(error.is_none(), "spurious error: {error:?}");
        prop_assert_eq!(decoded, frames);
        prop_assert_eq!(buffered, 0);
    }

    /// A stream that dies mid-frame is LOUD: the truncation is visible as
    /// buffered-but-undecodable bytes, never silently swallowed.
    #[test]
    fn mid_frame_death_is_always_visible(
        frame in arb_frame(),
        keep_fraction in 0.0f64..1.0,
    ) {
        let mut wire = BytesMut::new();
        frame.encode_stream(&mut wire);
        let keep = ((wire.len() as f64) * keep_fraction) as usize;
        let keep = keep.min(wire.len().saturating_sub(1)); // strictly truncated
        let mut acc = FrameAccumulator::new();
        acc.push(&wire[..keep]);
        prop_assert_eq!(acc.next_frame().unwrap(), None);
        if keep > 0 {
            prop_assert!(acc.buffered() > 0);
        }
    }

    /// Valid frames followed by garbage: the valid prefix decodes, then the
    /// error is typed — the poison is positional, not retroactive.
    #[test]
    fn garbage_after_valid_frames_yields_the_prefix_then_a_typed_error(
        frames in proptest::collection::vec(arb_frame(), 1..4),
        garbage_len in 4usize..64,
    ) {
        let mut wire = BytesMut::new();
        for frame in &frames {
            frame.encode_stream(&mut wire);
        }
        // A length prefix that is structurally impossible (< HEADER_LEN).
        wire.extend_from_slice(&(HEADER_LEN as u32 - 1).to_be_bytes());
        wire.extend_from_slice(&vec![0xAA; garbage_len]);
        let (decoded, error, _) = drive(&[wire.to_vec()]);
        prop_assert_eq!(decoded, frames);
        let truncated = matches!(error, Some(FrameError::Truncated { .. }));
        prop_assert!(truncated, "expected Truncated, got {:?}", error);
    }

    /// Oversized length prefixes are rejected from the prefix alone —
    /// before any payload is buffered.
    #[test]
    fn oversized_prefix_is_rejected_immediately(
        excess in 1usize..1_000_000,
    ) {
        let len = (HEADER_LEN + MAX_PAYLOAD + excess) as u32;
        let mut acc = FrameAccumulator::new();
        acc.push(&len.to_be_bytes());
        let err = acc.next_frame().unwrap_err();
        let too_large = matches!(err, FrameError::TooLarge(_));
        prop_assert!(too_large, "expected TooLarge, got {:?}", err);
    }
}
