//! §6 frozen framing. Every frame = `{u32 version, u64 seq, u64 ack,
//! u16 channel, bytes payload}`. FROZEN — changes require human approval.
//!
//! Wire encoding (big-endian), transport-independent. Stream transports
//! (TCP/WebSocket binary/QUIC stream) carry frames with a u32 length prefix
//! covering the header + payload; datagram transports carry one frame per
//! datagram without the prefix.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Current protocol version. Frames with other versions are still *parsed*
/// (header layout is frozen); acceptance is a handshake concern.
pub const PROTOCOL_VERSION: u32 = 1;

/// Fixed header size: version(4) + seq(8) + ack(8) + channel(2).
pub const HEADER_LEN: usize = 22;

/// Hard cap on payload size; a frame larger than this is a protocol error.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Well-known channel ids. `ctl` is always 0; other channels are negotiated
/// via `ChannelOpen` on ctl. Unknown channels are skipped, never fatal (§6).
pub mod channel {
    pub const CTL: u16 = 0;
    pub const EVENTS: u16 = 1;
    pub const FS: u16 = 2;
    pub const PRESENCE: u16 = 3;
    /// PTY channels are `PTY_BASE + n` for pty *n*.
    pub const PTY_BASE: u16 = 16;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u32,
    pub seq: u64,
    pub ack: u64,
    pub channel: u16,
    pub payload: Bytes,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("payload length {0} exceeds MAX_PAYLOAD")]
    TooLarge(usize),
}

impl Frame {
    pub fn new(channel: u16, seq: u64, ack: u64, payload: impl Into<Bytes>) -> Self {
        Frame {
            version: PROTOCOL_VERSION,
            seq,
            ack,
            channel,
            payload: payload.into(),
        }
    }

    /// Encode header + payload (no length prefix).
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(HEADER_LEN + self.payload.len());
        dst.put_u32(self.version);
        dst.put_u64(self.seq);
        dst.put_u64(self.ack);
        dst.put_u16(self.channel);
        dst.put_slice(&self.payload);
    }

    /// Decode a complete frame from `buf` (header + payload, no prefix).
    /// Consumes the entire buffer.
    pub fn decode(mut buf: Bytes) -> Result<Frame, FrameError> {
        if buf.len() < HEADER_LEN {
            return Err(FrameError::Truncated {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let version = buf.get_u32();
        let seq = buf.get_u64();
        let ack = buf.get_u64();
        let channel = buf.get_u16();
        if buf.len() > MAX_PAYLOAD {
            return Err(FrameError::TooLarge(buf.len()));
        }
        Ok(Frame {
            version,
            seq,
            ack,
            channel,
            payload: buf,
        })
    }

    /// Encode with the u32 length prefix used by stream transports.
    pub fn encode_stream(&self, dst: &mut BytesMut) {
        dst.reserve(4 + HEADER_LEN + self.payload.len());
        dst.put_u32((HEADER_LEN + self.payload.len()) as u32);
        self.encode(dst);
    }

    /// Try to decode one length-prefixed frame from the front of `buf`.
    /// Returns `Ok(None)` if more bytes are needed; consumes on success.
    pub fn decode_stream(buf: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len < HEADER_LEN {
            return Err(FrameError::Truncated {
                need: HEADER_LEN,
                have: len,
            });
        }
        if len - HEADER_LEN > MAX_PAYLOAD {
            return Err(FrameError::TooLarge(len - HEADER_LEN));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        buf.advance(4);
        let frame = buf.split_to(len).freeze();
        Frame::decode(frame).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let f = Frame::new(channel::EVENTS, 7, 3, Bytes::from_static(b"hello"));
        let mut buf = BytesMut::new();
        f.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN + 5);
        let g = Frame::decode(buf.freeze()).unwrap();
        assert_eq!(f, g);
    }

    #[test]
    fn stream_roundtrip_partial() {
        let f = Frame::new(channel::CTL, 1, 0, Bytes::from_static(b"x"));
        let mut buf = BytesMut::new();
        f.encode_stream(&mut buf);
        // feed byte by byte
        let full = buf.clone();
        let mut acc = BytesMut::new();
        let mut out = None;
        for b in full.iter() {
            acc.put_u8(*b);
            if let Some(fr) = Frame::decode_stream(&mut acc).unwrap() {
                out = Some(fr);
            }
        }
        assert_eq!(out.unwrap(), f);
        assert!(acc.is_empty());
    }

    #[test]
    fn truncated_header() {
        let e = Frame::decode(Bytes::from_static(&[0u8; 10])).unwrap_err();
        assert!(matches!(e, FrameError::Truncated { .. }));
    }
}
