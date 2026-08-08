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
/// CROSS the wire instead of being assumed — see `docs/wire-hello-design.md`;
/// **v7 adds [`Reply::ErrorTyped`]** (the error TAXONOMY crosses, not a flat
/// string — a remote denial is a denial, a remote timeout is transient) and
/// **removes the v6 tolerances**: the hello is REQUIRED and the legacy ALPN is
/// gone. A v6 peer still fails CLEANLY (the hello exchange itself reports the
/// mismatch naming both versions); only pre-v6 peers fail without explanation.
pub const PROTOCOL_VERSION: u32 = 7;

/// The ALPN protocol id for QUIC — `ikigai/{PROTOCOL_VERSION}`, the TLS
/// handshake itself as the version gate. Since v7 it is the ONLY id offered
/// and accepted: the v6 transition (offer/accept the version-blind `ikigai/0`
/// beside it, warn on negotiation) is over.
pub fn alpn() -> Vec<u8> {
    format!("ikigai/{PROTOCOL_VERSION}").into_bytes()
}

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

/// A server → client reply. [`ErrorTyped`](Reply::ErrorTyped) is how a v7+
/// server answers failures; the flat [`Error`](Reply::Error) variant remains
/// decodable (discriminants are append-only) but is no longer sent.
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
    /// A failure with its TAXONOMY intact (v7): the client rebuilds the same
    /// `ikigai_core::Error` variant the server saw, so a remote denial stays a
    /// permanent `Denied` (a Failover must NOT paper over it with a weaker
    /// local answer), a remote timeout stays TRANSIENT (a Failover MAY act),
    /// and an HTTP face can say 403/404/400 instead of a blanket 502.
    ErrorTyped(WireError),
}

/// The error taxonomy on the wire — a field-for-field mirror of
/// `ikigai_core::Error`, kept wire-local so a taxonomy addition is a WIRE
/// version event (this codec is a public ABI with independent
/// implementations), not a silent core cascade. Variant order is the postcard
/// contract: append only.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WireError {
    /// Kernel found no binding for the target (the IRI, as text).
    Unresolved(String),
    MissingArgument(String),
    InvalidArgument {
        name: String,
        detail: String,
    },
    Endpoint(String),
    /// Permanent: the capability did not authorize it.
    Denied(String),
    /// Permanent: a bound endpoint reports the fronted thing absent.
    NotFound(String),
    /// Transient.
    Timeout(String),
    /// Transient.
    Unavailable(String),
}

impl From<&ikigai_core::Error> for WireError {
    fn from(error: &ikigai_core::Error) -> Self {
        use ikigai_core::Error as E;
        match error {
            E::Unresolved(iri) => WireError::Unresolved(iri.as_str().to_string()),
            E::MissingArgument(name) => WireError::MissingArgument(name.clone()),
            E::InvalidArgument { name, detail } => WireError::InvalidArgument {
                name: name.clone(),
                detail: detail.clone(),
            },
            E::Endpoint(message) => WireError::Endpoint(message.clone()),
            E::Denied(message) => WireError::Denied(message.clone()),
            E::NotFound(message) => WireError::NotFound(message.clone()),
            E::Timeout(message) => WireError::Timeout(message.clone()),
            E::Unavailable(message) => WireError::Unavailable(message.clone()),
            // Core's Error is non_exhaustive: a variant newer than this wire
            // revision degrades to Endpoint (message preserved) until the wire
            // catches up — a taxonomy addition is a wire-version event, and an
            // old peer meanwhile sees a correct-if-untyped failure.
            other => WireError::Endpoint(other.to_string()),
        }
    }
}

impl From<WireError> for ikigai_core::Error {
    fn from(error: WireError) -> Self {
        use ikigai_core::Error as E;
        match error {
            // An IRI that crossed the wire came FROM an Iri, so a parse failure
            // here means corruption; degrade to Endpoint rather than panic.
            WireError::Unresolved(iri) => match ikigai_core::Iri::parse(&iri) {
                Ok(iri) => E::Unresolved(iri),
                Err(_) => E::Endpoint(format!("no endpoint resolved for {iri}")),
            },
            WireError::MissingArgument(name) => E::MissingArgument(name),
            WireError::InvalidArgument { name, detail } => E::InvalidArgument { name, detail },
            WireError::Endpoint(message) => E::Endpoint(message),
            WireError::Denied(message) => E::Denied(message),
            WireError::NotFound(message) => E::NotFound(message),
            WireError::Timeout(message) => E::Timeout(message),
            WireError::Unavailable(message) => E::Unavailable(message),
        }
    }
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
    }

    /// Every taxonomy variant crosses and comes back as the SAME core variant,
    /// with transience preserved — the property the reliability overlays and
    /// the HTTP faces depend on.
    #[test]
    fn typed_errors_round_trip_with_taxonomy_intact() {
        use ikigai_core::Error as E;
        let cases: Vec<ikigai_core::Error> = vec![
            E::Unresolved(Iri::parse("urn:x:y").unwrap()),
            E::MissingArgument("in".into()),
            E::InvalidArgument {
                name: "n".into(),
                detail: "not a number".into(),
            },
            E::Endpoint("boom".into()),
            E::Denied("needs urn:cap:x".into()),
            E::NotFound("no such row".into()),
            E::Timeout("5s elapsed".into()),
            E::Unavailable("connection refused".into()),
        ];
        for original in cases {
            let mut buf = Vec::new();
            write_message(&mut buf, &Reply::ErrorTyped(WireError::from(&original))).unwrap();
            let got: Reply = read_message(&mut std::io::Cursor::new(buf)).unwrap();
            let Reply::ErrorTyped(wire_error) = got else {
                panic!("expected ErrorTyped");
            };
            let rebuilt: ikigai_core::Error = wire_error.into();
            assert_eq!(
                rebuilt.is_transient(),
                original.is_transient(),
                "transience must survive the wire: {original:?}"
            );
            assert_eq!(
                std::mem::discriminant(&rebuilt),
                std::mem::discriminant(&original),
                "variant must survive the wire: {original:?}"
            );
        }
    }

    /// ErrorTyped's postcard discriminant is part of the public ABI — lock it.
    #[test]
    fn error_typed_wire_discriminant_is_five() {
        let bytes = encode(&Reply::ErrorTyped(WireError::Endpoint("x".into()))).unwrap();
        assert_eq!(bytes[0], 5, "Reply::ErrorTyped is variant 5");
        let inner = encode(&Reply::ErrorTyped(WireError::Denied("x".into()))).unwrap();
        assert_eq!(inner[1], 4, "WireError::Denied is variant 4");
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
