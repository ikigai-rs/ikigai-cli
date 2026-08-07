//! The IPC wire protocol: length-prefixed [postcard](https://postcard.jamesmunns.com)
//! messages between a REPL client and a kernel server.
//!
//! [`Call`] and [`Reply`] mirror the [`Resolver`](ikigai_resolve::Resolver) surface,
//! and the framing ([`write_message`] / [`read_message`]) is a `u32` big-endian length
//! followed by the postcard payload. The codec is non-self-describing — client
//! and server ship together at the same version — and the core types already
//! derive `Serialize`/`Deserialize`, so nothing here re-describes them.

use std::io::{self, Read, Write};

use ikigai_core::{Capability, Representation, Request, SpaceEntry, TraceEvent};
use ikigai_resolve::CacheStatus;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Bumped when the on-wire shape changes incompatibly. v2 adds [`Call::IssueAs`]
/// (capability-on-the-wire); v3 adds [`Call::IssueTraced`] /
/// [`Reply::ResolvedTraced`] (trace-over-the-wire); v5 changes `TraceEvent`'s
/// postcard layout (core 0.1.48 adds `notes` — endpoint span annotations);
/// **v6 adds the [`Hello`] exchange**, so version (and mount mode) finally
/// CROSS the wire instead of being assumed — see `docs/wire-hello-design.md`.
pub const PROTOCOL_VERSION: u32 = 6;

/// The ALPN protocol id for QUIC — `ikigai/{PROTOCOL_VERSION}`, so the TLS
/// handshake itself is the version gate on that transport. [`ALPN_LEGACY`] is
/// the pre-v6 id, still offered/accepted for one version so a mixed fleet
/// degrades to a warning instead of a broken drain; v7 removes it.
pub fn alpn() -> Vec<u8> {
    format!("ikigai/{PROTOCOL_VERSION}").into_bytes()
}

/// The version-blind pre-v6 ALPN id (tolerated through v6, removed at v7).
pub const ALPN_LEGACY: &[u8] = b"ikigai/0";

/// The magic prefix of a hello payload. A first frame that does NOT start with
/// it is a legacy (≤v5) [`Call`] — that contrast is what makes the hello
/// detectable without the postcard codec whose version it negotiates.
pub const HELLO_MAGIC: [u8; 4] = *b"IKWH";

/// How the dialing side will address this connection — a HINT for peers whose
/// canonical IRIs carry a namespace prefix (ikigai-python's `urn:py:hello`),
/// which otherwise cannot know what form `Entries` should list. The Rust
/// server ignores it: a served kernel speaks canonical IRIs, and alias
/// rewriting happens client-side in `MountedRemote`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HelloMode {
    /// A plain client, `--connect`, or an `--override`/`--prefer` mount:
    /// IRIs arrive canonical, entries wanted canonical.
    #[default]
    Verbatim,
    /// An alias `--mount`: IRIs arrive prefix-stripped, entries wanted
    /// prefix-stripped (the mount re-prefixes them).
    Alias,
}

/// One side's hello. The payload is deliberately NOT postcard — the codec
/// whose version is being negotiated must not be needed to negotiate it:
/// `"IKWH" + u32 BE version + u8 mode`, and readers IGNORE trailing bytes
/// (that is the extension mechanism). The server's answer omits the mode
/// byte; [`decode_hello`] defaults it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hello {
    pub version: u32,
    pub mode: HelloMode,
}

/// Encode a hello payload (frame it with [`write_message`]'s framing via
/// [`write_hello`], or your own on self-framing transports).
pub fn encode_hello(hello: &Hello) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9);
    bytes.extend_from_slice(&HELLO_MAGIC);
    bytes.extend_from_slice(&hello.version.to_be_bytes());
    bytes.push(match hello.mode {
        HelloMode::Verbatim => 0,
        HelloMode::Alias => 1,
    });
    bytes
}

/// Decode a hello payload: `None` if the magic is absent (a legacy first
/// frame — treat it as a ≤v5 [`Call`]). A missing mode byte defaults to
/// [`HelloMode::Verbatim`] (the server's answer carries none); an unknown
/// mode value also falls back to verbatim rather than failing — the mode is
/// a hint, and a NEWER peer's new mode must not break an older reader.
/// Trailing bytes beyond the known prefix are ignored, by design.
pub fn decode_hello(payload: &[u8]) -> Option<Hello> {
    if payload.len() < 8 || payload[..4] != HELLO_MAGIC {
        return None;
    }
    let version = u32::from_be_bytes(payload[4..8].try_into().expect("4 bytes"));
    let mode = match payload.get(8) {
        Some(1) => HelloMode::Alias,
        _ => HelloMode::Verbatim,
    };
    Some(Hello { version, mode })
}

/// Write a length-framed hello.
pub fn write_hello<W: Write>(writer: &mut W, hello: &Hello) -> io::Result<()> {
    let payload = encode_hello(hello);
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

/// Read one length-framed payload WITHOUT decoding it — the server's first
/// read, which must distinguish a hello from a legacy [`Call`] before it
/// knows which decoder applies. Pair with [`decode_hello`] / [`decode`].
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
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
    Ok(buf)
}

/// The largest framed message accepted. Guards [`read_message`] against a bogus
/// length header demanding a huge allocation; 64 MiB is far above any
/// representation a REPL round-trips.
const MAX_FRAME: usize = 64 * 1024 * 1024;

/// A trace context carried on a traced call, so a remote kernel can record into
/// the caller's trace. `parent_span` is `None` for a whole-session `--connect`
/// trace (the remote root *is* the trace root); a future mount-stitch sets it to
/// the local span that issued the call, to re-parent the returned subtree.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TraceContext {
    /// Identifies the overall trace this call belongs to.
    pub trace_id: u64,
    /// The caller's span to parent the returned subtree under, or `None` for a
    /// whole-session trace (the returned root has no parent).
    pub parent_span: Option<u64>,
}

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
    /// Resolve under `Capability` **and record the resolution**, answered with
    /// [`Reply::ResolvedTraced`] carrying the recorded spans. The [`TraceContext`]
    /// lets a future mount stitch the remote subtree under a local span. Appended
    /// so existing discriminants are unchanged.
    IssueTraced(Request, Capability, TraceContext),
}

/// A server → client reply. [`Error`](Reply::Error) can answer any call — a
/// failed resolution, or a server/transport error.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Reply {
    Resolved(Representation, CacheStatus),
    Cached(bool),
    Entries(Option<Vec<SpaceEntry>>),
    Error(String),
    /// A resolved representation plus the [`TraceEvent`]s the server recorded for
    /// the call — the answer to [`Call::IssueTraced`]. Appended so existing
    /// discriminants are unchanged.
    ResolvedTraced(Representation, CacheStatus, Vec<TraceEvent>),
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
            Reply::ResolvedTraced(
                Representation::new(ReprType::new("text/plain"), b"HI".to_vec()),
                CacheStatus::Miss,
                vec![TraceEvent {
                    target: "urn:fn:toUpper".to_string(),
                    thread: "ikigai-sched-0".to_string(),
                    started: None,
                    ended: None,
                    cache_hit: false,
                    span: 0,
                    parent: None,
                    capability: Some(vec!["urn:cap:demo".to_string()]),
                    notes: vec![("model".to_string(), "llama3.2:3b".to_string())],
                }],
            ),
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
        let traced = Call::IssueTraced(
            request(),
            Capability::root(),
            TraceContext {
                trace_id: 7,
                parent_span: None,
            },
        );
        write_message(&mut buf, &traced).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_message::<_, Call>(&mut cursor).unwrap(),
            Call::Issue(request())
        );
        assert_eq!(read_message::<_, Call>(&mut cursor).unwrap(), Call::Entries);
        assert_eq!(read_message::<_, Call>(&mut cursor).unwrap(), traced);
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
    fn a_hello_round_trips_and_names_its_version() {
        let hello = Hello {
            version: PROTOCOL_VERSION,
            mode: HelloMode::Alias,
        };
        let mut buf = Vec::new();
        write_hello(&mut buf, &hello).unwrap();
        let payload = read_frame(&mut std::io::Cursor::new(buf)).unwrap();
        assert_eq!(decode_hello(&payload), Some(hello));
    }

    /// The golden bytes: the hello layout is a PUBLIC contract (ikigai-python
    /// mirrors it byte-for-byte), so lock it against accidental drift.
    #[test]
    fn the_hello_payload_bytes_are_the_documented_layout() {
        let payload = encode_hello(&Hello {
            version: 6,
            mode: HelloMode::Alias,
        });
        assert_eq!(payload, b"IKWH\x00\x00\x00\x06\x01");
    }

    #[test]
    fn a_legacy_first_frame_is_not_a_hello() {
        // A ≤v5 client's first frame is a Call; the magic must not match it.
        let mut buf = Vec::new();
        write_message(&mut buf, &Call::Entries).unwrap();
        let payload = read_frame(&mut std::io::Cursor::new(buf)).unwrap();
        assert_eq!(decode_hello(&payload), None);
    }

    /// Trailing bytes are the extension mechanism: a future hello with more
    /// fields must decode on THIS reader, prefix-only.
    #[test]
    fn a_longer_future_hello_still_decodes() {
        let mut payload = encode_hello(&Hello {
            version: 9,
            mode: HelloMode::Verbatim,
        });
        payload.extend_from_slice(b"future-extension-bytes");
        let hello = decode_hello(&payload).expect("prefix decodes");
        assert_eq!(hello.version, 9);
        // An unknown future MODE byte falls back to verbatim, never errors.
        let mut odd = encode_hello(&Hello {
            version: 9,
            mode: HelloMode::Verbatim,
        });
        odd[8] = 7;
        assert_eq!(decode_hello(&odd).unwrap().mode, HelloMode::Verbatim);
    }

    #[test]
    fn the_alpn_id_tracks_the_protocol_version() {
        assert_eq!(alpn(), format!("ikigai/{PROTOCOL_VERSION}").into_bytes());
        assert_ne!(alpn(), ALPN_LEGACY.to_vec());
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
