//! Typed payload helpers over the frozen frame (§6) and event-envelope
//! validation (§4.2).
//!
//! The frame payload is opaque bytes on the wire; by convention it is a
//! protobuf message (`prost` on the backend, `protobuf-es` in the web
//! client). These helpers put a prost message into a [`Frame`] and parse one
//! back out without either side touching the frozen header layout.

use bytes::{Bytes, BytesMut};
use prost::Message;

use crate::framing::{Frame, MAX_PAYLOAD};
use crate::wire;

/// Errors from typed payload encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The encoded message would exceed the frame payload cap
    /// ([`MAX_PAYLOAD`]).
    #[error("encoded message is {0} bytes, exceeds MAX_PAYLOAD")]
    TooLarge(usize),
    /// The payload is not a valid encoding of the requested message type.
    #[error("payload does not decode as the requested message: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Encode `msg` as the payload of a new [`Frame`] on `channel` with the
/// given `seq`/`ack` (§6: sequence/ack exist from day one for client-side
/// predicted echo).
pub fn frame_message<M: Message>(
    channel: u16,
    seq: u64,
    ack: u64,
    msg: &M,
) -> Result<Frame, CodecError> {
    let len = msg.encoded_len();
    if len > MAX_PAYLOAD {
        return Err(CodecError::TooLarge(len));
    }
    let mut buf = BytesMut::with_capacity(len);
    msg.encode(&mut buf)
        .expect("BytesMut grows on demand; encode cannot fail");
    Ok(Frame::new(channel, seq, ack, buf.freeze()))
}

/// Parse a typed message out of a frame payload.
pub fn decode_message<M: Message + Default>(frame: &Frame) -> Result<M, CodecError> {
    decode_payload(frame.payload.clone())
}

/// Parse a typed message from raw payload bytes (e.g. an [`wire::Event`]
/// `payload` field, whose inner type is selected by `Event.type`).
pub fn decode_payload<M: Message + Default>(payload: impl Into<Bytes>) -> Result<M, CodecError> {
    Ok(M::decode(payload.into())?)
}

/// Event-envelope validation failures (§4.2 frozen envelope, I5, I11).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventValidationError {
    /// `v == 0`: every persisted artifact carries an explicit non-zero
    /// format version (I11).
    #[error("event envelope version is 0 (I11: versions are explicit)")]
    ZeroVersion,
    /// Empty principal violates I5 — no anonymous writes anywhere.
    #[error("event has empty principal (I5: every event is attributed)")]
    EmptyPrincipal,
    /// Events are meaningless outside a workspace's totally ordered log (I3).
    #[error("event has empty workspace id")]
    EmptyWorkspace,
    /// `type == 0` is unassigned in the append-only registry
    /// ([`crate::events`]). Types *above* the highest known value are
    /// accepted: the registry is append-only and peers may be newer (§6:
    /// unknown types are skipped, never fatal — but type 0 is malformed,
    /// not future).
    #[error("event type is 0 (unassigned in the registry)")]
    ZeroType,
}

/// Validate the invariant-bearing fields of an event envelope (§4.2):
/// non-zero format version (I11), non-empty principal (I5), non-empty
/// workspace, and a non-zero type. Unknown-but-future types pass — the
/// registry is append-only and consumers must tolerate types they do not
/// know (§6).
pub fn validate_event(event: &wire::Event) -> Result<(), EventValidationError> {
    if event.v == 0 {
        return Err(EventValidationError::ZeroVersion);
    }
    if event.principal.is_empty() {
        return Err(EventValidationError::EmptyPrincipal);
    }
    if event.workspace.is_empty() {
        return Err(EventValidationError::EmptyWorkspace);
    }
    if event.r#type == 0 {
        return Err(EventValidationError::ZeroType);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::channel;
    use crate::{events, EVENT_ENVELOPE_V};

    fn valid_event() -> wire::Event {
        wire::Event {
            v: EVENT_ENVELOPE_V,
            workspace: b"ws-1".to_vec(),
            seq: 42,
            principal: b"principal-1".to_vec(),
            r#type: events::PTY_OUT,
            ts_ms: 1_000,
            payload: Vec::new(),
        }
    }

    #[test]
    fn frame_message_roundtrip() {
        let hello = wire::ClientHello {
            min_version: 1,
            max_version: 3,
            capabilities: vec!["zstd".into()],
            token: b"tok".to_vec(),
            workspace: b"ws".to_vec(),
        };
        let frame = frame_message(channel::CTL, 1, 0, &hello).unwrap();
        assert_eq!(frame.channel, channel::CTL);
        let back: wire::ClientHello = decode_message(&frame).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn decode_message_wrong_bytes_errors() {
        // A payload that is not a valid ChannelAck varint stream.
        let frame = Frame::new(channel::CTL, 1, 0, Bytes::from_static(&[0xFF, 0xFF, 0xFF]));
        let r: Result<wire::ChannelAck, _> = decode_message(&frame);
        assert!(matches!(r, Err(CodecError::Decode(_))));
    }

    #[test]
    fn frame_message_rejects_oversized() {
        let big = wire::PtyData {
            data: vec![0u8; MAX_PAYLOAD + 1],
            pty: 0,
        };
        assert!(matches!(
            frame_message(channel::PTY_BASE, 1, 0, &big),
            Err(CodecError::TooLarge(_))
        ));
    }

    #[test]
    fn validate_event_accepts_valid_and_future_types() {
        validate_event(&valid_event()).unwrap();
        // Future type far beyond the registry: ok (append-only registry, §6).
        let mut future = valid_event();
        future.r#type = 10_000;
        validate_event(&future).unwrap();
    }

    #[test]
    fn validate_event_rejects_invariant_violations() {
        let mut e = valid_event();
        e.v = 0;
        assert_eq!(validate_event(&e), Err(EventValidationError::ZeroVersion));

        let mut e = valid_event();
        e.principal.clear();
        assert_eq!(
            validate_event(&e),
            Err(EventValidationError::EmptyPrincipal)
        );

        let mut e = valid_event();
        e.workspace.clear();
        assert_eq!(
            validate_event(&e),
            Err(EventValidationError::EmptyWorkspace)
        );

        let mut e = valid_event();
        e.r#type = 0;
        assert_eq!(validate_event(&e), Err(EventValidationError::ZeroType));
    }
}
