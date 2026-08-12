//! §6 QUIC transport mapping (ADR-0026). Additive: the FROZEN frame layout
//! ([`crate::framing`]) and handshake ([`crate::handshake`]) are untouched —
//! this module only fixes how the frozen frames are carried over QUIC
//! streams, exactly as ADR-0007 fixed how they are carried over WebSocket
//! binary messages.
//!
//! ## The mapping (normative for both ends)
//!
//! - **ALPN**: [`ALPN`] (`reachpad/1`). This is the raw-QUIC dialect of the
//!   protocol; it is deliberately NOT `h3`, so a future WebTransport
//!   listener can share the UDP port and dispatch on ALPN.
//! - **Streams**: every stream is a client-initiated bidirectional stream
//!   beginning with a 2-byte big-endian **channel-binding preamble**
//!   ([`preamble`]): the §6 channel id the stream is dedicated to.
//!   Length-prefixed frames ([`crate::framing::Frame::encode_stream`])
//!   follow, back to back.
//! - The **first** stream a client opens MUST be bound to channel 0
//!   (`ctl`); the handshake happens there.
//! - The frame header's `channel` field stays **authoritative** for
//!   dispatch on both ends. A stream binding is an *ordering/priority
//!   domain*, not an addressing mechanism: each side sends a frame on the
//!   stream bound to the frame's channel when one exists and on the ctl
//!   stream otherwise, and each side dispatches every received frame by its
//!   header, whatever stream it arrived on. This is what gives §6 its
//!   "dedicated QUIC streams for pty channels" property: a client that
//!   opens a stream per pty keeps its interactive bytes out of the
//!   retransmission shadow of a bulk `fs` transfer.
//! - `seq`/`ack` remain **session-scoped**, exactly as over WebSocket.
//!   Delivery is ordered per stream, not across streams; `seq` was never an
//!   ordering promise across channels (§6 gives it to client-side predicted
//!   echo), so nothing changes.
//!
//! ## Malformed input posture
//!
//! [`FrameAccumulator`] is the shared incremental read path: bytes in,
//! frames out, all errors typed. A decode error poisons only the stream it
//! happened on — the transport closes the offending stream (or the
//! connection, when the stream is ctl) and never panics.

use bytes::BytesMut;

use crate::framing::{Frame, FrameError};

/// ALPN protocol id for the raw-QUIC dialect of the §6 protocol.
pub const ALPN: &[u8] = b"reachpad/1";

/// Length of the channel-binding preamble opening every stream.
pub const PREAMBLE_LEN: usize = 2;

/// The 2-byte big-endian channel-binding preamble for `channel`.
#[must_use]
pub fn preamble(channel: u16) -> [u8; PREAMBLE_LEN] {
    channel.to_be_bytes()
}

/// Read a channel-binding preamble back.
#[must_use]
pub fn parse_preamble(bytes: [u8; PREAMBLE_LEN]) -> u16 {
    u16::from_be_bytes(bytes)
}

/// Incremental frame reader for one stream: push received chunks in, pull
/// complete frames out. Wraps the frozen
/// [`Frame::decode_stream`] so the QUIC read path and its tests exercise
/// the exact same decoder as every other stream transport.
///
/// After [`next_frame`](Self::next_frame) returns an error the stream's
/// framing is lost for good — the caller must stop reading the stream.
#[derive(Debug, Default)]
pub struct FrameAccumulator {
    buf: BytesMut,
}

impl FrameAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a received chunk. Chunk boundaries are meaningless — any
    /// split of the byte stream decodes to the same frames.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Decode the next complete frame, `Ok(None)` if more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        Frame::decode_stream(&mut self.buf)
    }

    /// Bytes buffered but not yet decoded. Non-zero at end-of-stream means
    /// the peer died mid-frame.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{channel, HEADER_LEN, MAX_PAYLOAD};
    use bytes::Bytes;

    #[test]
    fn preamble_round_trips() {
        assert_eq!(parse_preamble(preamble(0)), 0);
        assert_eq!(parse_preamble(preamble(channel::PTY_BASE + 3)), 19);
        assert_eq!(parse_preamble(preamble(u16::MAX)), u16::MAX);
        assert_eq!(preamble(0x0102), [1, 2], "big-endian on the wire");
    }

    #[test]
    fn accumulator_decodes_across_arbitrary_chunk_boundaries() {
        let frames: Vec<Frame> = (0..3)
            .map(|i| Frame::new(channel::EVENTS, i + 1, i, Bytes::from(vec![i as u8; 5])))
            .collect();
        let mut wire = BytesMut::new();
        for f in &frames {
            f.encode_stream(&mut wire);
        }
        let mut acc = FrameAccumulator::new();
        let mut out = Vec::new();
        for byte in wire.iter() {
            acc.push(&[*byte]);
            while let Some(f) = acc.next_frame().unwrap() {
                out.push(f);
            }
        }
        assert_eq!(out, frames);
        assert_eq!(acc.buffered(), 0);
    }

    #[test]
    fn accumulator_reports_oversized_and_undersized_prefixes() {
        // Prefix promising more than MAX_PAYLOAD: rejected before buffering.
        let mut acc = FrameAccumulator::new();
        let huge = ((HEADER_LEN + MAX_PAYLOAD + 1) as u32).to_be_bytes();
        acc.push(&huge);
        assert!(matches!(acc.next_frame(), Err(FrameError::TooLarge(_))));

        // Prefix smaller than the frozen header: structurally impossible.
        let mut acc = FrameAccumulator::new();
        acc.push(&(HEADER_LEN as u32 - 1).to_be_bytes());
        assert!(matches!(
            acc.next_frame(),
            Err(FrameError::Truncated { .. })
        ));
    }

    #[test]
    fn mid_frame_death_is_visible_as_buffered_bytes() {
        let frame = Frame::new(channel::FS, 1, 0, Bytes::from_static(b"payload"));
        let mut wire = BytesMut::new();
        frame.encode_stream(&mut wire);
        let mut acc = FrameAccumulator::new();
        acc.push(&wire[..wire.len() - 1]);
        assert_eq!(acc.next_frame().unwrap(), None);
        assert!(acc.buffered() > 0, "a dead-mid-frame stream must be loud");
    }
}
