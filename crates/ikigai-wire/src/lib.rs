//! The IPC wire protocol: length-prefixed [postcard](https://postcard.jamesmunns.com)
//! messages between a REPL client and a kernel server.
//!
//! [`Call`] and [`Reply`] mirror the [`Resolver`](ikigai_resolve::Resolver) surface,
//! and the framing ([`write_message`] / [`read_message`]) is a `u32` big-endian length
//! followed by the postcard payload. The codec is non-self-describing — client
//! and server ship together at the same version — and the core types already
//! derive `Serialize`/`Deserialize`, so nothing here re-describes them.

use std::io::{self, Read, Write};

use ikigai_core::{Capability, Representation, Request, SpaceEntry};
use ikigai_resolve::CacheStatus;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Bumped when the on-wire shape changes incompatibly. Not negotiated yet
/// (client and server ship together) — it's here to fail loudly when that
/// changes. v2 adds [`Call::IssueAs`] (capability-on-the-wire).
pub const PROTOCOL_VERSION: u32 = 2;

/// The largest framed message accepted. Guards [`read_message`] against a bogus
/// length header demanding a huge allocation; 64 MiB is far above any
/// representation a REPL round-trips.
const MAX_FRAME: usize = 64 * 1024 * 1024;

/// A client → server call, mirroring the [`Resolver`](ikigai_resolve::Resolver) methods.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Call {
    Issue(Request),
    IsCached(Request),
    Entries,
    /// Resolve `Request` under an explicit `Capability` (capability-on-the-wire).
    /// Appended after the existing variants so the postcard discriminants of
    /// `Issue`/`IsCached`/`Entries` are unchanged. A server clamps the carried
    /// capability to the principal the channel authenticated.
    IssueAs(Request, Capability),
}

/// A server → client reply. [`Error`](Reply::Error) can answer any call — a
/// failed resolution, or a server/transport error.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Reply {
    Resolved(Representation, CacheStatus),
    Cached(bool),
    Entries(Option<Vec<SpaceEntry>>),
    Error(String),
}

/// Serialize `message` and write it length-prefixed (`u32` big-endian length,
/// then the postcard payload), flushing the writer.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    let bytes = postcard::to_allocvec(message).map_err(codec_error)?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large to frame"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Read one length-prefixed message and deserialize it. Rejects a frame larger
/// than [`MAX_FRAME`] before allocating for it.
pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framed message exceeds the size limit",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    postcard::from_bytes(&buf).map_err(codec_error)
}

/// Serialize a message to postcard bytes, with no length prefix — for transports
/// that frame messages themselves (e.g. one QUIC stream per call).
pub fn encode<T: Serialize>(message: &T) -> io::Result<Vec<u8>> {
    postcard::to_allocvec(message).map_err(codec_error)
}

/// Deserialize a postcard message from a complete, self-framed byte slice (the
/// counterpart to [`encode`]).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    postcard::from_bytes(bytes).map_err(codec_error)
}

fn codec_error(error: postcard::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgRef, Iri, ReprType, Verb};

    fn request() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:fn:toUpper").unwrap())
            .with_arg("in", ArgRef::Inline(b"hi".to_vec()))
    }

    #[test]
    fn calls_and_replies_round_trip_through_a_pipe() {
        // A buffer plays both ends: write each message, then read it back.
        let messages = [
            Reply::Resolved(
                Representation::new(ReprType::new("text/plain"), b"HI".to_vec()),
                CacheStatus::Miss,
            ),
            Reply::Cached(true),
            Reply::Entries(None),
            Reply::Error("boom".to_string()),
        ];
        let mut buf: Vec<u8> = Vec::new();
        for message in &messages {
            write_message(&mut buf, message).unwrap();
        }
        let mut cursor = std::io::Cursor::new(buf);
        for expected in &messages {
            let got: Reply = read_message(&mut cursor).unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn a_call_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Call::Issue(request())).unwrap();
        write_message(&mut buf, &Call::Entries).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_message::<_, Call>(&mut cursor).unwrap(),
            Call::Issue(request())
        );
        assert_eq!(read_message::<_, Call>(&mut cursor).unwrap(), Call::Entries);
    }

    #[test]
    fn framing_is_length_prefixed() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Call::Entries).unwrap();
        let declared = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, buf.len() - 4, "header counts the payload bytes");
    }

    #[test]
    fn an_oversized_length_header_is_rejected_before_allocating() {
        // A frame claiming > MAX_FRAME bytes must error, not try to allocate it.
        let mut framed = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        framed.push(0); // a single body byte; read should fail on the length first
        let err = read_message::<_, Call>(&mut std::io::Cursor::new(framed)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_truncated_frame_errors() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Call::Entries).unwrap();
        buf.truncate(buf.len() - 1); // lose the last payload byte
        let err = read_message::<_, Call>(&mut std::io::Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
