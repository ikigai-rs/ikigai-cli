//! **Wire v10: streamed bodies** (ledger #2242, stage 6 of the binary streams design, ledger
//! #2228).
//!
//! A streamed exchange is a HEAD frame, then bounded CHUNK frames, then END or a typed
//! ABORT. A bare end of stream (EOF, a reset, a FIN) is never a clean end: a reader that
//! has not seen END reports the body as failed, so a body is whole or refused, never a
//! well-formed shorter one.
//!
//! The frames are an APPEND to the [`Call`] and [`Reply`] discriminant spaces, the same
//! numbers in both directions, and each one encodes byte for byte as the matching
//! variant would if it were appended to the enum:
//!
//! | tag | call direction | reply direction | payload after the tag |
//! |----:|----------------|-----------------|-----------------------|
//! | 0–5 | [`Call`] | [`Reply`] | the variant's fields, unchanged |
//! | 6 | [`CallHead`] | [`ReplyHead`] | the head's fields, postcard |
//! | 7 | chunk | chunk | a varint length, then that many bytes (at most [`MAX_CHUNK`]) |
//! | 8 | end | end | nothing |
//! | 9 | abort | abort | a [`WireError`] |
//!
//! The Rust enums stay exactly as they were (adding a variant to an exhaustive public enum
//! is a breaking change): the frames are the new types [`CallFrame`], [`ReplyFrame`] and
//! [`BodyFrame`]. A later breaking release can fold them into `Call` and `Reply` as
//! variants 6 to 9 without changing one byte on the wire.
//!
//! **Who sends what.** A client asks for a streamed answer by sending a [`CallHead`]
//! (tag 6), only to a peer that negotiated v10 ([`streams`]); with a body of its own
//! ([`CallHead::body`]) it follows the head with chunks and END or ABORT. The answer to a
//! head is EITHER one ordinary [`Reply`] frame (a failure before any byte, or a traced
//! run, which is collected) OR a [`ReplyHead`] followed by chunks and END or ABORT. Every
//! existing call keeps its existing reply, so a v7 to v9 peer never meets a frame: it
//! sends no head, and gets the collected answer, or `OverBudget` once that answer is past
//! what one frame carries ([`encode_reply_for_peer`]).
//!
//! **Framing.** On the IPC socket every message is already a frame (`u32` big-endian
//! length, then the payload), and the frames above are simply more of them. On QUIC, where
//! a plain call is one unframed message ended by FIN, a stream that carries frames opens
//! with the four bytes [`STREAM_MAGIC`] and then carries the same length-prefixed frames
//! as the socket; a plain call starts with its tag (0 to 5), so the two never collide.
//! The codec here names no transport type, so WebTransport can reuse it.

use std::io::{self, Read, Write};

use ikigai_core::{Body, Bytes, Capability, ReprType, Representation, Request};
use ikigai_resolve::CacheStatus;
use serde::{Deserialize, Serialize};

use crate::{codec_error, Call, IssueWith, Reply, WireError, MAX_FRAME};

/// The first wire version whose peers understand the stream frames.
pub const STREAMS_SINCE: u32 = 10;

/// Whether a peer that negotiated `version` understands the stream frames: whether a
/// [`CallHead`] may be sent to it (a client) or accepted from it (a server).
///
/// ```
/// assert!(ikigai_wire::streams(10));
/// assert!(!ikigai_wire::streams(9) && !ikigai_wire::streams(7));
/// ```
pub fn streams(version: u32) -> bool {
    version >= STREAMS_SINCE
}

/// The most bytes one chunk frame carries: 256 KiB. A sender splits a larger buffer; a
/// reader refuses a chunk that declares more before it allocates for it.
pub const MAX_CHUNK: usize = 256 * 1024;

/// The four bytes a QUIC (or WebTransport) stream of frames opens with. A plain call on
/// such a stream is one unframed message whose first byte is its tag, 0 to 5, so it can
/// never begin with `I` (0x49). The IPC socket, where every message is a frame already,
/// sends no magic.
pub const STREAM_MAGIC: [u8; 4] = *b"IKWS";

/// The frame tags, the first byte of a frame's payload. The same numbers in both
/// directions; 0 to 5 are the existing [`Call`] and [`Reply`] variants.
pub mod tag {
    /// A [`CallHead`](super::CallHead) or a [`ReplyHead`](super::ReplyHead).
    pub const HEAD: u8 = 6;
    /// A chunk of the body.
    pub const CHUNK: u8 = 7;
    /// The body is whole.
    pub const END: u8 = 8;
    /// The body failed, with a typed [`WireError`](crate::WireError).
    pub const ABORT: u8 = 9;
}

/// The largest frame payload a reader accepts for a frame whose tag is `tag`: a chunk is
/// its tag, a varint of at most three bytes and [`MAX_CHUNK`] bytes; every other frame is
/// bounded by [`MAX_FRAME`], the cap on any one frame.
///
/// ```
/// use ikigai_wire::{frame_limit, tag, MAX_CHUNK, MAX_FRAME};
/// assert_eq!(frame_limit(tag::CHUNK), MAX_CHUNK + 4);
/// assert_eq!(frame_limit(tag::HEAD), MAX_FRAME);
/// ```
pub fn frame_limit(tag: u8) -> usize {
    if tag == tag::CHUNK {
        MAX_CHUNK + 4
    } else {
        MAX_FRAME
    }
}

/// A streamed call's head (tag 6): what to resolve, under what, as part of which run, and
/// whether a body of the caller's own follows it.
///
/// `with` is [`IssueWith`], the v9 run context, with one difference in meaning: a TRACED
/// streamed call (`with.trace` set) is answered collected, as one
/// [`Reply::ResolvedTraced`] frame, because core records no trace for a streamed issue.
///
/// ```
/// use ikigai_core::{Capability, Iri, Request, Verb};
/// use ikigai_wire::{decode_call_frame, encode_call_frame, BodyHead, CallFrame, CallHead, IssueWith};
///
/// let head = CallHead {
///     request: Request::new(Verb::Sink, Iri::parse("urn:x").unwrap()),
///     capability: Capability::root(),
///     with: IssueWith::default(),
///     body: Some(BodyHead { arg: "content".into(), len: Some(3) }),
/// };
/// let bytes = encode_call_frame(&CallFrame::Head(head.clone())).unwrap();
/// assert_eq!(bytes[0], 6, "a head is tag 6");
/// assert!(bytes.ends_with(&[0x00, 0x00, 0x00, 0x01, 0x07, b'c', b'o', b'n', b't', b'e', b'n', b't', 0x01, 0x03]));
/// assert_eq!(decode_call_frame(&bytes).unwrap(), CallFrame::Head(head));
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CallHead {
    /// The request. It must not already carry the argument the body fills.
    pub request: Request,
    /// The capability the caller resolves under; a server clamps it as it clamps
    /// [`Call::IssueAs`]'s.
    pub capability: Capability,
    /// The run context, as [`Call::IssueWith`] carries it.
    pub with: IssueWith,
    /// The caller's own body, when chunks follow this head: `None` asks only for a
    /// streamed answer.
    pub body: Option<BodyHead>,
}

/// The body a [`CallHead`] announces: the argument it fills (the value of `arg`, as an
/// inline argument would be) and its length when the caller knows it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BodyHead {
    /// The argument the body is the value of; `content` for a Sink.
    pub arg: String,
    /// The body's length in bytes, when known. A reader holds the sender to it: more or
    /// fewer bytes before END is a failed body, not a different one.
    pub len: Option<u64>,
}

/// A streamed answer's head (tag 6): the representation without its bytes, how the cache
/// served it, and the body's length when the producer knows it.
///
/// `representation` is a [`Representation<()>`], so it encodes as the type and the expiry
/// with no bytes between them, and [`into_representation`](Self::into_representation)
/// puts a body back.
///
/// ```
/// use ikigai_core::{Body, ReprType, Representation};
/// use ikigai_resolve::CacheStatus;
/// use ikigai_wire::ReplyHead;
///
/// let answer = Representation::new(ReprType::new("text/plain"), b"hi".to_vec()).into_body();
/// let (head, body) = ReplyHead::of(answer, false);
/// assert_eq!(head.status, CacheStatus::Uncacheable);
/// assert_eq!(head.len, Some(2));
/// assert_eq!(head.into_representation(body).bytes.as_bytes().unwrap(), &b"hi"[..]);
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReplyHead {
    /// The representation's type and expiry; its body follows as chunks.
    pub representation: Representation<()>,
    /// How the cache served the answer. A one-shot body is never stored, so it is
    /// [`Uncacheable`](CacheStatus::Uncacheable) whatever its expiry says.
    pub status: CacheStatus,
    /// The body's length in bytes, when known before reading it.
    pub len: Option<u64>,
}

impl ReplyHead {
    /// Split a streamed answer into its head and its body. `was_cached` is whether the
    /// kernel held the answer before this issue (the probe `ikigai_resolve` makes for a
    /// collected answer), from which the status is derived the same way.
    pub fn of(answer: Representation<Body>, was_cached: bool) -> (ReplyHead, Body) {
        let one_shot = answer.bytes.is_one_shot();
        let len = answer.bytes.len_hint();
        let uncacheable = one_shot || answer.expiry == ikigai_core::Expiry::Always;
        let mut body = None;
        let representation = answer.map_body(|b| body = Some(b));
        let status = if uncacheable {
            CacheStatus::Uncacheable
        } else if was_cached {
            CacheStatus::Hit
        } else {
            CacheStatus::Miss
        };
        let head = ReplyHead {
            representation,
            status,
            len,
        };
        (head, body.expect("map_body calls its closure"))
    }

    /// The head as a representation over `body`.
    pub fn into_representation<B>(self, body: B) -> Representation<B> {
        self.representation.map_body(|()| body)
    }

    /// The representation's type.
    pub fn repr_type(&self) -> &ReprType {
        &self.representation.repr_type
    }
}

/// A frame that follows a head, in either direction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum BodyFrame {
    /// Bytes of the body (tag 7), at most [`MAX_CHUNK`].
    Chunk(Bytes),
    /// The body is whole (tag 8).
    End,
    /// The body failed (tag 9); what it carried before is not a body.
    Abort(WireError),
}

/// One frame in the call direction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CallFrame {
    /// A plain call (tags 0 to 5), exactly as [`encode`](crate::encode) writes it.
    Call(Call),
    /// A streamed call's head (tag 6).
    Head(CallHead),
    /// A frame of the caller's body (tags 7 to 9).
    Body(BodyFrame),
}

/// One frame in the reply direction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ReplyFrame {
    /// A plain reply (tags 0 to 5), exactly as [`encode`](crate::encode) writes it.
    Reply(Reply),
    /// A streamed answer's head (tag 6).
    Head(ReplyHead),
    /// A frame of the answer's body (tags 7 to 9).
    Body(BodyFrame),
}

/// Encode a call-direction frame's payload (frame it with [`write_frame`]).
pub fn encode_call_frame(frame: &CallFrame) -> io::Result<Vec<u8>> {
    match frame {
        CallFrame::Call(call) => crate::encode(call),
        CallFrame::Head(head) => tagged(tag::HEAD, head),
        CallFrame::Body(body) => Ok(encode_body_frame(body)),
    }
}

/// Encode a reply-direction frame's payload (frame it with [`write_frame`]).
pub fn encode_reply_frame(frame: &ReplyFrame) -> io::Result<Vec<u8>> {
    match frame {
        ReplyFrame::Reply(reply) => crate::encode(reply),
        ReplyFrame::Head(head) => tagged(tag::HEAD, head),
        ReplyFrame::Body(body) => Ok(encode_body_frame(body)),
    }
}

/// Decode a call-direction frame's payload. A plain call decodes exactly as
/// [`decode`](crate::decode) decodes it.
pub fn decode_call_frame(payload: &[u8]) -> io::Result<CallFrame> {
    match payload.first() {
        Some(&tag::HEAD) => Ok(CallFrame::Head(untag(payload)?)),
        Some(&t) if t > tag::HEAD => Ok(CallFrame::Body(decode_body_frame(payload)?)),
        _ => Ok(CallFrame::Call(crate::decode(payload)?)),
    }
}

/// Decode a reply-direction frame's payload. A plain reply decodes exactly as
/// [`decode`](crate::decode) decodes it.
pub fn decode_reply_frame(payload: &[u8]) -> io::Result<ReplyFrame> {
    match payload.first() {
        Some(&tag::HEAD) => Ok(ReplyFrame::Head(untag(payload)?)),
        Some(&t) if t > tag::HEAD => Ok(ReplyFrame::Body(decode_body_frame(payload)?)),
        _ => Ok(ReplyFrame::Reply(crate::decode(payload)?)),
    }
}

/// Encode a body frame's payload: `07 len bytes`, `08`, or `09` and the error.
///
/// ```
/// use ikigai_wire::{encode_body_frame, BodyFrame, WireError};
/// assert_eq!(encode_body_frame(&BodyFrame::Chunk(b"ab"[..].into())), [0x07, 0x02, b'a', b'b']);
/// assert_eq!(encode_body_frame(&BodyFrame::End), [0x08]);
/// assert_eq!(
///     encode_body_frame(&BodyFrame::Abort(WireError::OverBudget("x".into()))),
///     [0x09, 0x0b, 0x01, b'x']
/// );
/// ```
pub fn encode_body_frame(frame: &BodyFrame) -> Vec<u8> {
    match frame {
        BodyFrame::Chunk(bytes) => {
            let mut out = chunk_header(bytes.len());
            out.extend_from_slice(bytes);
            out
        }
        BodyFrame::End => vec![tag::END],
        BodyFrame::Abort(error) => {
            // A WireError always encodes: its fields are strings and integers.
            tagged(tag::ABORT, error).expect("a WireError encodes")
        }
    }
}

/// Decode a body frame's payload (tags 7 to 9); anything else is a protocol error. A chunk
/// must carry exactly the bytes its length declares, and at most [`MAX_CHUNK`]; an END
/// carries nothing after its tag.
pub fn decode_body_frame(payload: &[u8]) -> io::Result<BodyFrame> {
    decode_body_owned(Bytes::copy_from_slice(payload))
}

/// [`decode_body_frame`] over an owned payload, so a chunk is a view of it and not a copy.
fn decode_body_owned(payload: Bytes) -> io::Result<BodyFrame> {
    match payload.first() {
        Some(&tag::CHUNK) => {
            let (len, rest) =
                postcard::take_from_bytes::<u64>(&payload[1..]).map_err(codec_error)?;
            let start = payload.len() - rest.len();
            if len > MAX_CHUNK as u64 {
                return Err(protocol(format!(
                    "a chunk declared {len} bytes, more than the {MAX_CHUNK} one chunk carries"
                )));
            }
            if rest.len() as u64 != len {
                return Err(protocol(format!(
                    "a chunk declared {len} bytes and carried {}",
                    rest.len()
                )));
            }
            Ok(BodyFrame::Chunk(payload.slice(start..)))
        }
        Some(&tag::END) if payload.len() == 1 => Ok(BodyFrame::End),
        Some(&tag::END) => Err(protocol("an END frame carried bytes after its tag".into())),
        Some(&tag::ABORT) => Ok(BodyFrame::Abort(
            postcard::from_bytes(&payload[1..]).map_err(codec_error)?,
        )),
        Some(other) => Err(protocol(format!(
            "frame tag {other} where a body frame (7, 8 or 9) was due"
        ))),
        None => Err(protocol("an empty frame".into())),
    }
}

/// Write one frame: a `u32` big-endian length, then `payload`. What
/// [`write_message`](crate::write_message) does after it encodes, for a payload already
/// encoded. Refuses a payload past [`MAX_FRAME`], which no reader would accept.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds the size limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)
}

/// Write `bytes` as chunk frames of at most [`MAX_CHUNK`] each, without copying them
/// into a frame first. An empty buffer writes nothing. The writer is not flushed.
pub fn write_chunks<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    for piece in bytes.chunks(MAX_CHUNK) {
        let header = chunk_header(piece.len());
        writer.write_all(&((header.len() + piece.len()) as u32).to_be_bytes())?;
        writer.write_all(&header)?;
        writer.write_all(piece)?;
    }
    Ok(())
}

/// Write one body frame, length-prefixed.
pub fn write_body_frame<W: Write>(writer: &mut W, frame: &BodyFrame) -> io::Result<()> {
    match frame {
        BodyFrame::Chunk(bytes) => write_chunks(writer, bytes),
        other => write_frame(writer, &encode_body_frame(other)),
    }
}

/// Read one length-prefixed frame whose payload may be at most what its tag allows
/// ([`frame_limit`]), refusing a larger one before allocating for it. `Ok(None)` is a clean
/// end of stream BEFORE the frame began (what ends a connection between calls); an end
/// part-way through a frame is `UnexpectedEof`.
pub fn read_tagged_frame<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match reader.read(&mut len[..1])? {
        0 => return Ok(None),
        _ => reader.read_exact(&mut len[1..])?,
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(protocol("an empty frame".into()));
    }
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    if len > frame_limit(first[0]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framed message exceeds the size limit",
        ));
    }
    let mut payload = vec![0u8; len];
    payload[0] = first[0];
    reader.read_exact(&mut payload[1..])?;
    Ok(Some(payload))
}

/// A typed refusal carried by an [`io::Error`]: the peer's ABORT, or a bound the reader
/// holds. [`refusal`] finds it again, so a transport surfaces the typed error rather
/// than its own reading of the I/O failure.
#[derive(Debug)]
pub struct Refusal(pub WireError);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error: ikigai_core::Error = self.0.clone().into();
        write!(f, "{error}")
    }
}

impl std::error::Error for Refusal {}

/// The typed refusal `error` carries, when it carries one ([`Refusal`]).
///
/// ```
/// use ikigai_wire::{refusal, Refusal, WireError};
/// let error = std::io::Error::other(Refusal(WireError::OverBudget("x".into())));
/// assert_eq!(refusal(&error), Some(&WireError::OverBudget("x".into())));
/// assert_eq!(refusal(&std::io::Error::other("plain")), None);
/// ```
pub fn refusal(error: &io::Error) -> Option<&WireError> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refusal>())
        .map(|refusal| &refusal.0)
}

/// The receiving half of a body as a state machine with no I/O of its own: feed it each
/// frame's payload, in order, and it hands back the chunks, holds the sender to the length
/// it declared, and says when the body is whole. The sync [`BodyReader`] and an async
/// transport drive the same rules through it.
#[derive(Debug)]
pub struct BodyState {
    expected: Option<u64>,
    seen: u64,
    ended: bool,
    failed: bool,
}

impl BodyState {
    /// A body that declared `len` bytes (or none).
    pub fn new(len: Option<u64>) -> Self {
        BodyState {
            expected: len,
            seen: 0,
            ended: false,
            failed: false,
        }
    }

    /// Take one frame's payload: `Ok(Some(chunk))` for bytes, `Ok(None)` once the body is
    /// whole (and for every call after), `Err` for an ABORT (a [`Refusal`]) or a protocol
    /// violation, after which the body is failed for good.
    pub fn feed(&mut self, payload: Vec<u8>) -> io::Result<Option<Bytes>> {
        if self.ended {
            return Ok(None);
        }
        if self.failed {
            return Err(protocol("a frame after the body had already failed".into()));
        }
        let step = self.step(payload);
        if step.is_err() {
            self.failed = true;
        }
        step
    }

    fn step(&mut self, payload: Vec<u8>) -> io::Result<Option<Bytes>> {
        match decode_body_owned(Bytes::from(payload))? {
            BodyFrame::Chunk(bytes) => {
                self.seen += bytes.len() as u64;
                match self.expected {
                    Some(expected) if self.seen > expected => Err(protocol(format!(
                        "the body declared {expected} bytes and carried more"
                    ))),
                    _ => Ok(Some(bytes)),
                }
            }
            BodyFrame::End => match self.expected {
                Some(expected) if expected != self.seen => Err(protocol(format!(
                    "the body declared {expected} bytes and ended after {}",
                    self.seen
                ))),
                _ => {
                    self.ended = true;
                    Ok(None)
                }
            },
            BodyFrame::Abort(error) => Err(io::Error::other(Refusal(error))),
        }
    }

    /// The stream ended (EOF, a reset, a FIN) where a frame was due: the error that says
    /// so. Never a clean end, so it fails the body.
    pub fn ended_early(&mut self) -> io::Error {
        self.failed = true;
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "the stream ended after {} body bytes without its END frame; a body is never \
                 whole without one",
                self.seen
            ),
        )
    }

    /// Whether END has been read.
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// The body bytes read so far.
    pub fn seen(&self) -> u64 {
        self.seen
    }
}

/// A body read off a sync stream of frames, as an [`io::Read`]: the bytes of its chunks,
/// then a clean end at END. An ABORT, a stream that ends before END, and a length other
/// than the declared one are errors, never a short read that looks whole.
///
/// ```
/// use std::io::Read;
/// use ikigai_wire::{write_body_frame, write_chunks, BodyFrame, BodyReader, WireError};
///
/// let mut wire = Vec::new();
/// write_chunks(&mut wire, b"hello").unwrap();
/// write_body_frame(&mut wire, &BodyFrame::End).unwrap();
/// let mut body = String::new();
/// BodyReader::new(&wire[..], Some(5)).read_to_string(&mut body).unwrap();
/// assert_eq!(body, "hello");
///
/// // The same chunk without its END is a failed body, not a shorter one.
/// let cut = &wire[..wire.len() - 5];
/// let mut sink = Vec::new();
/// assert!(BodyReader::new(cut, None).read_to_end(&mut sink).is_err());
///
/// // An ABORT carries its typed error.
/// let mut aborted = Vec::new();
/// write_body_frame(&mut aborted, &BodyFrame::Abort(WireError::OverBudget("x".into()))).unwrap();
/// let error = BodyReader::new(&aborted[..], None).read_to_end(&mut sink).unwrap_err();
/// assert_eq!(ikigai_wire::refusal(&error), Some(&WireError::OverBudget("x".into())));
/// ```
pub struct BodyReader<R> {
    inner: R,
    state: BodyState,
    pending: Bytes,
}

impl<R: Read> BodyReader<R> {
    /// Read a body that declared `len` bytes (or none) off `inner`, which is positioned
    /// just after the head.
    pub fn new(inner: R, len: Option<u64>) -> Self {
        BodyReader {
            inner,
            state: BodyState::new(len),
            pending: Bytes::new(),
        }
    }

    /// The next chunk, `Ok(None)` once the body is whole.
    pub fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        if !self.pending.is_empty() {
            return Ok(Some(std::mem::take(&mut self.pending)));
        }
        loop {
            if self.state.is_ended() {
                return Ok(None);
            }
            let payload = match read_tagged_frame(&mut self.inner) {
                Ok(Some(payload)) => payload,
                Ok(None) => return Err(self.state.ended_early()),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(self.state.ended_early())
                }
                Err(error) => return Err(error),
            };
            match self.state.feed(payload)? {
                // An empty chunk carries nothing; read on rather than report a zero read,
                // which `Read` callers take as the end.
                Some(chunk) if chunk.is_empty() => continue,
                other => return Ok(other),
            }
        }
    }

    /// Read the whole body into memory, refusing with `OverBudget` (a [`Refusal`]) at the
    /// first chunk that would take it past `max_bytes`, never truncating it. The body's
    /// declared length is checked against the bound before anything is read.
    ///
    /// On a refusal the stream is left wherever reading stopped; a receiver that keeps the
    /// connection uses [`collect_or_refuse`](Self::collect_or_refuse) instead.
    pub fn collect(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let over = |seen: u64| {
            io::Error::other(Refusal(WireError::OverBudget(format!(
                "the body is larger than the {max_bytes}-byte bound that collects it (at least \
                 {seen} bytes)"
            ))))
        };
        if let Some(len) = self.state.expected {
            if len > max_bytes as u64 {
                return Err(over(len));
            }
        }
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk()? {
            if out.len() + chunk.len() > max_bytes {
                return Err(over((out.len() + chunk.len()) as u64));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// [`collect`](Self::collect), leaving the stream ALIGNED after the body whatever the
    /// outcome: `Ok(Ok(bytes))` for the whole body; `Ok(Err(refusal))` when the sender
    /// aborted it or it was past `max_bytes` (the rest is then read and thrown away, a chunk
    /// at a time); `Err` when the stream itself failed (an I/O error, a protocol violation,
    /// an end before END), after which nothing more can be read from it.
    pub fn collect_or_refuse(
        &mut self,
        max_bytes: usize,
    ) -> io::Result<Result<Vec<u8>, WireError>> {
        match self.collect(max_bytes) {
            Ok(bytes) => Ok(Ok(bytes)),
            Err(error) => match refusal(&error).cloned() {
                // The sender's ABORT ends the body: nothing follows it to drain.
                Some(refused) if self.state.failed => Ok(Err(refused)),
                // Our own bound: the sender is still sending; read past the rest.
                Some(refused) => {
                    self.pending = Bytes::new();
                    match self.drain() {
                        Ok(()) => Ok(Err(refused)),
                        // The sender aborted while we drained: its error is the answer.
                        Err(error) => match refusal(&error).cloned() {
                            Some(aborted) => Ok(Err(aborted)),
                            None => Err(error),
                        },
                    }
                }
                None => Err(error),
            },
        }
    }

    /// Read the rest of the body and throw it away: what keeps a connection usable after a
    /// receiver refused the body part-way. Holds nothing but one chunk at a time.
    pub fn drain(&mut self) -> io::Result<()> {
        while self.next_chunk()?.is_some() {}
        Ok(())
    }

    /// Whether END has been read.
    pub fn is_ended(&self) -> bool {
        self.state.is_ended() && self.pending.is_empty()
    }

    /// The stream, after the body (or wherever reading stopped).
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            match self.next_chunk()? {
                Some(chunk) => self.pending = chunk,
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        let _ = self.pending.split_to(n);
        Ok(n)
    }
}

/// Encode `reply` as a peer speaking wire `peer_version` must receive it
/// ([`Reply::for_peer`]), refusing an answer one frame cannot carry: past [`MAX_FRAME`] the
/// reply becomes a typed `OverBudget` (downgraded for the peer like any other error),
/// never a frame the peer's reader would refuse as malformed. That is the collected answer
/// a v7 to v9 peer gets for a body a v10 peer would stream.
///
/// ```
/// use ikigai_core::{ReprType, Representation};
/// use ikigai_resolve::CacheStatus;
/// use ikigai_wire::{decode, encode_reply_for_peer, Reply, WireError, MAX_FRAME};
///
/// let small = Reply::Resolved(Representation::new(ReprType::new("text/plain"), b"x".to_vec()), CacheStatus::Miss);
/// assert_eq!(decode::<Reply>(&encode_reply_for_peer(small.clone(), 9).unwrap()).unwrap(), small);
///
/// let huge = Reply::Resolved(
///     Representation::new(ReprType::new("application/octet-stream"), vec![0u8; MAX_FRAME]),
///     CacheStatus::Miss,
/// );
/// let refused = decode::<Reply>(&encode_reply_for_peer(huge.clone(), 9).unwrap()).unwrap();
/// assert!(matches!(refused, Reply::ErrorTyped(WireError::OverBudget(_))));
/// // A v8 peer gets the same refusal as the Endpoint text it has always received.
/// let for_v8 = decode::<Reply>(&encode_reply_for_peer(huge, 8).unwrap()).unwrap();
/// assert!(matches!(for_v8, Reply::ErrorTyped(WireError::Endpoint(m)) if m.starts_with("over budget: ")));
/// ```
pub fn encode_reply_for_peer(reply: Reply, peer_version: u32) -> io::Result<Vec<u8>> {
    let over = |size: String| {
        let refused = Reply::ErrorTyped(WireError::OverBudget(format!(
            "the answer is {size}, past the {MAX_FRAME}-byte frame a collected answer travels \
             in; a wire v{STREAMS_SINCE} client streams it"
        )));
        crate::encode(&refused.for_peer(peer_version))
    };
    // Bytes alone past the bound: refused without encoding a copy of them first.
    if let Reply::Resolved(representation, _) | Reply::ResolvedTraced(representation, _, _) = &reply
    {
        if representation.bytes.len() > MAX_FRAME {
            return over(format!("{} bytes", representation.bytes.len()));
        }
    }
    let bytes = crate::encode(&reply.for_peer(peer_version))?;
    if bytes.len() <= MAX_FRAME {
        return Ok(bytes);
    }
    over(format!("{} bytes encoded", bytes.len()))
}

/// `request` with `body` as the value of its argument `arg`: what a server does with a
/// streamed call's collected body before it resolves. A request that already carries
/// `arg` is refused, as a repeated argument is everywhere else ([`GIVEN_TWICE`]).
///
/// [`GIVEN_TWICE`]: ikigai_core::GIVEN_TWICE
///
/// ```
/// use ikigai_core::{ArgRef, Iri, Request, Verb};
/// let sink = Request::new(Verb::Sink, Iri::parse("urn:x").unwrap());
/// let with = ikigai_wire::with_body_arg(sink.clone(), "content", b"hi".to_vec()).unwrap();
/// assert_eq!(with.args.get("content"), Some(&ArgRef::Inline(b"hi".to_vec())));
/// assert!(ikigai_wire::with_body_arg(with, "content", b"again".to_vec()).is_err());
/// ```
pub fn with_body_arg(
    request: Request,
    arg: &str,
    body: Vec<u8>,
) -> Result<Request, ikigai_core::Error> {
    if request.args.contains_key(arg) {
        return Err(ikigai_core::Error::InvalidArgument {
            name: arg.to_string(),
            detail: ikigai_core::GIVEN_TWICE.to_string(),
        });
    }
    Ok(request.with_arg(arg, ikigai_core::ArgRef::Inline(body)))
}

/// A caller's own body for a streamed call: the argument it is the value of, where its
/// bytes come from, and its length when the caller knows it (the reader is held to it).
pub struct Upload<'a> {
    /// The argument the body fills; `content` for a Sink.
    pub arg: String,
    /// The bytes, read to their end.
    pub body: &'a mut dyn Read,
    /// The length, when known: announced in the head, and checked as it is sent.
    pub len: Option<u64>,
}

impl<'a> Upload<'a> {
    /// The `content` of a Sink, of unknown length.
    pub fn content(body: &'a mut dyn Read) -> Self {
        Upload {
            arg: "content".to_string(),
            body,
            len: None,
        }
    }

    /// The [`BodyHead`] a [`CallHead`] announces this body with.
    pub fn head(&self) -> BodyHead {
        BodyHead {
            arg: self.arg.clone(),
            len: self.len,
        }
    }

    /// Read the whole body into memory, refusing with `OverBudget` (a [`Refusal`]) past
    /// `max_bytes`, never truncating: what a client does for a peer older than v10, which
    /// takes a body only as an inline argument inside one frame. A body shorter or longer
    /// than its declared length is refused too.
    ///
    /// ```
    /// use ikigai_wire::Upload;
    /// let mut bytes = &b"hello"[..];
    /// assert_eq!(Upload::content(&mut bytes).read_bounded(5).unwrap(), b"hello");
    /// let mut bytes = &b"hello"[..];
    /// assert!(Upload::content(&mut bytes).read_bounded(4).is_err());
    /// ```
    pub fn read_bounded(self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let read = self
            .body
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut out)?;
        if read > max_bytes {
            return Err(io::Error::other(Refusal(WireError::OverBudget(format!(
                "the body is larger than the {max_bytes} bytes this peer takes inline (a wire \
                 v{STREAMS_SINCE} peer streams it)"
            )))));
        }
        check_declared(self.len, out.len() as u64)?;
        Ok(out)
    }
}

/// A body's declared length against what was actually read.
pub(crate) fn check_declared(declared: Option<u64>, actual: u64) -> io::Result<()> {
    match declared {
        Some(declared) if declared != actual => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the body declared {declared} bytes and its reader gave {actual}"),
        )),
        _ => Ok(()),
    }
}

/// `07` and the length as a postcard varint: a chunk frame's payload before its bytes.
fn chunk_header(len: usize) -> Vec<u8> {
    let mut varint = [0u8; 10];
    let encoded =
        postcard::to_slice(&(len as u64), &mut varint).expect("a u64 varint fits 10 bytes");
    let mut out = Vec::with_capacity(1 + encoded.len() + len);
    out.push(tag::CHUNK);
    out.extend_from_slice(encoded);
    out
}

/// A tag byte, then `value` in postcard.
fn tagged<T: Serialize>(tag: u8, value: &T) -> io::Result<Vec<u8>> {
    let mut out = vec![tag];
    out.extend_from_slice(&crate::encode(value)?);
    Ok(out)
}

/// The value after a tag byte.
fn untag<T: serde::de::DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    crate::decode(&payload[1..])
}

fn protocol(detail: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("wire stream: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgRef, Iri, ReprType, Verb};

    #[test]
    fn a_reply_head_round_trips_and_is_the_bytes_an_appended_variant_would_be() {
        let answer = Representation::new(ReprType::new("text/plain"), b"hello".to_vec())
            .cacheable()
            .into_body();
        let (head, _) = ReplyHead::of(answer, true);
        assert_eq!(head.status, CacheStatus::Hit);
        let bytes = encode_reply_frame(&ReplyFrame::Head(head.clone())).unwrap();
        assert_eq!(
            decode_reply_frame(&bytes).unwrap(),
            ReplyFrame::Head(head.clone())
        );
        // `Reply::Resolved` is the representation then the status; a head is the same with no
        // bytes in the middle, then the length hint.
        let resolved = crate::encode(&Reply::Resolved(
            Representation::new(ReprType::new("text/plain"), Vec::new()).cacheable(),
            CacheStatus::Hit,
        ))
        .unwrap();
        let type_len = 1 + "text/plain".len() + 1; // varint len + the string + an empty params map
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[1..=type_len], &resolved[1..=type_len]);
        assert_eq!(
            &bytes[bytes.len() - 2..],
            &[0x01, 0x05],
            "the length hint, Some(5)"
        );
    }

    fn chunk_payload(bytes: &[u8]) -> Vec<u8> {
        encode_body_frame(&BodyFrame::Chunk(Bytes::copy_from_slice(bytes)))
    }

    #[test]
    fn a_body_is_held_to_its_declared_length_both_ways() {
        let mut short = BodyState::new(Some(3));
        assert_eq!(
            short.feed(chunk_payload(b"ab")).unwrap().unwrap(),
            &b"ab"[..]
        );
        assert!(
            short.feed(vec![tag::END]).is_err(),
            "two bytes is not three"
        );
        assert!(
            short.feed(vec![tag::END]).is_err(),
            "a failed body stays failed"
        );

        let mut long = BodyState::new(Some(1));
        assert!(
            long.feed(chunk_payload(b"ab")).is_err(),
            "more than declared"
        );

        let mut exact = BodyState::new(Some(2));
        exact.feed(chunk_payload(b"ab")).unwrap();
        assert_eq!(exact.feed(vec![tag::END]).unwrap(), None);
        assert!(exact.is_ended());
        assert_eq!(
            exact.feed(chunk_payload(b"late")).unwrap(),
            None,
            "nothing after END"
        );
    }

    #[test]
    fn a_chunk_past_max_chunk_or_with_the_wrong_byte_count_is_refused() {
        let mut big = chunk_header(MAX_CHUNK + 1);
        big.extend(std::iter::repeat_n(0u8, MAX_CHUNK + 1));
        assert!(decode_body_frame(&big).is_err());
        let mut lying = chunk_header(4);
        lying.extend_from_slice(b"abc");
        assert!(decode_body_frame(&lying).is_err());
        assert!(decode_body_frame(&[tag::END, 0]).is_err());
        assert!(
            decode_body_frame(&[tag::HEAD]).is_err(),
            "a head is not a body frame"
        );
        assert!(decode_body_frame(&[]).is_err());
        let full = chunk_payload(&vec![1u8; MAX_CHUNK]);
        assert_eq!(
            full.len(),
            frame_limit(tag::CHUNK),
            "a full chunk fits its frame limit"
        );
        assert!(decode_body_frame(&full).is_ok());
    }

    #[test]
    fn a_chunk_frame_declaring_more_than_its_limit_is_refused_before_allocating() {
        let mut wire = ((frame_limit(tag::CHUNK) + 1) as u32)
            .to_be_bytes()
            .to_vec();
        wire.push(tag::CHUNK);
        let error = read_tagged_frame(&mut &wire[..]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // A clean end before a frame is `None`; part-way through one is an error.
        assert!(read_tagged_frame(&mut &[][..]).unwrap().is_none());
        assert!(read_tagged_frame(&mut &[0u8, 0][..]).is_err());
    }

    #[test]
    fn write_chunks_splits_at_max_chunk_and_reads_back_whole() {
        let data: Vec<u8> = (0..(2 * MAX_CHUNK + 10)).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        write_chunks(&mut wire, &data).unwrap();
        write_body_frame(&mut wire, &BodyFrame::End).unwrap();
        let mut reader = BodyReader::new(&wire[..], Some(data.len() as u64));
        let mut sizes = Vec::new();
        let mut back = Vec::new();
        while let Some(chunk) = reader.next_chunk().unwrap() {
            sizes.push(chunk.len());
            back.extend_from_slice(&chunk);
        }
        assert_eq!(sizes, [MAX_CHUNK, MAX_CHUNK, 10]);
        assert_eq!(back, data);
        assert!(reader.is_ended());
    }

    #[test]
    fn collect_refuses_past_its_bound_and_drain_keeps_the_stream_aligned() {
        let mut wire = Vec::new();
        write_chunks(&mut wire, b"abcdef").unwrap();
        write_body_frame(&mut wire, &BodyFrame::End).unwrap();
        write_frame(&mut wire, &crate::encode(&Reply::Cached(true)).unwrap()).unwrap();
        // Declared too long: refused before reading.
        let mut reader = BodyReader::new(&wire[..], Some(6));
        let error = reader.collect(5).unwrap_err();
        assert!(matches!(refusal(&error), Some(WireError::OverBudget(_))));
        // Undeclared: refused at the chunk that crosses it; the rest drains, and the next
        // message on the stream is intact.
        let mut reader = BodyReader::new(&wire[..], None);
        assert!(reader.collect(5).is_err());
        reader.drain().unwrap();
        let mut rest = reader.into_inner();
        let next: Reply = crate::read_message(&mut rest).unwrap();
        assert_eq!(next, Reply::Cached(true));
    }

    #[test]
    fn a_plain_message_decodes_through_the_frame_decoders_unchanged() {
        let call = Call::IssueAs(
            Request::new(Verb::Source, Iri::parse("urn:x").unwrap())
                .with_arg("in", ArgRef::Inline(b"hi".to_vec())),
            Capability::root(),
        );
        let bytes = crate::encode(&call).unwrap();
        assert_eq!(
            decode_call_frame(&bytes).unwrap(),
            CallFrame::Call(call.clone())
        );
        assert_eq!(encode_call_frame(&CallFrame::Call(call)).unwrap(), bytes);
        let reply = Reply::Cached(false);
        let bytes = crate::encode(&reply).unwrap();
        assert_eq!(
            decode_reply_frame(&bytes).unwrap(),
            ReplyFrame::Reply(reply)
        );
    }

    #[test]
    fn a_one_shot_body_is_reported_uncacheable_whatever_its_expiry() {
        let answer = Representation::from_body(
            ReprType::new("text/plain"),
            Body::once(futures::stream::iter([Ok(Bytes::from_static(b"a"))])),
        )
        .cacheable();
        let (head, _) = ReplyHead::of(answer, true);
        assert_eq!(head.status, CacheStatus::Uncacheable);
        assert_eq!(head.len, None);
    }
}
