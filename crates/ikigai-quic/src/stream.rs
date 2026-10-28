//! Wire v10 on QUIC (ledger #2242): a streamed answer and a streamed call on ONE
//! bidirectional stream, as the same frames the IPC socket carries ([`ikigai_wire::stream`]).
//!
//! A plain call is still one unframed message ended by FIN. A stream of frames opens with
//! [`STREAM_MAGIC`], then carries length-prefixed frames both ways: the caller's head (and
//! its body's chunks and END or ABORT), then the answer's one plain reply frame, or its
//! head, chunks and END or ABORT. QUIC's own flow control is the backpressure. Canceling
//! is the existing [`CANCELED`] STOP_SENDING (and RESET of a half-written request), so a
//! reader that drops an answer part-way stops the producer, whose Drop releases what it
//! holds.

use std::io::{self, Read};
use std::sync::Arc;

use futures::StreamExt;
use ikigai_core::{Body, Bytes, Capability, Clock, Error, Kernel, Representation, Request};
use ikigai_resolve::{CacheStatus, Resolver, RunContext, SpanCollector};
use ikigai_wire::{
    decode_call_frame, decode_reply_frame, encode_call_frame, encode_reply_for_peer,
    encode_reply_frame, frame_limit, refusal, streams, with_body_arg, write_body_frame,
    write_chunks, write_frame, BodyFrame, BodyState, CallFrame, CallHead, IssueWith, Reply,
    ReplyFrame, ReplyHead, TraceContext, Upload, WireError, MAX_CHUNK, MAX_FRAME, STREAM_MAGIC,
};

use crate::{admit, drive, other, quic_error, QuicResolver, Session, CANCELED};

/// The most of a caller's streamed body a QUIC door takes: 64 MiB, what one message
/// carried before v10, so no call that crossed before is refused now. The door collects
/// the body before it resolves (core gives a door no way to hand a body to a request but an
/// inline value or a content store it holds).
pub const MAX_UPLOAD: usize = ikigai_core::DEFAULT_STREAM_MEMORY as usize;

/// How much of a body a peer older than v10 takes, inline in one message: the message's
/// bound, less room for the request around it.
const INLINE_BODY_BOUND: usize = MAX_FRAME - 64 * 1024;

// --- reading frames off a QUIC stream -----------------------------------------------------

/// Read one length-prefixed frame off `recv`, at most what its tag allows
/// ([`frame_limit`]), refused before allocating for more. `Ok(None)` is a clean FIN before
/// the frame began; a FIN part-way through one is `UnexpectedEof`.
pub(crate) async fn read_frame(recv: &mut quinn::RecvStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match recv.read(&mut len[..1]).await.map_err(other)? {
        None => return Ok(None),
        Some(_) => read_exact(recv, &mut len[1..]).await?,
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "an empty frame"));
    }
    let mut tag = [0u8; 1];
    read_exact(recv, &mut tag).await?;
    if len > frame_limit(tag[0]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framed message exceeds the size limit",
        ));
    }
    let mut payload = vec![0u8; len];
    payload[0] = tag[0];
    read_exact(recv, &mut payload[1..]).await?;
    Ok(Some(payload))
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf).await.map_err(|error| match error {
        quinn::ReadExactError::FinishedEarly(_) => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the stream finished part-way through a frame",
        ),
        quinn::ReadExactError::ReadError(error) => other(error),
    })
}

/// Read up to the first four bytes of a call stream: the magic, or the start of a plain
/// call (which may be shorter than four bytes: `Entries` is one).
pub(crate) async fn read_prefix(recv: &mut quinn::RecvStream) -> io::Result<Vec<u8>> {
    let mut prefix = vec![0u8; STREAM_MAGIC.len()];
    let mut filled = 0;
    while filled < prefix.len() {
        match recv.read(&mut prefix[filled..]).await.map_err(other)? {
            None => break,
            Some(n) => filled += n,
        }
    }
    prefix.truncate(filled);
    Ok(prefix)
}

/// `payload` framed: its `u32` big-endian length, then it.
fn framed(payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + payload.len());
    write_frame(&mut out, payload)?;
    Ok(out)
}

// --- the server half ----------------------------------------------------------------------

/// Answer one stream of frames from a v10 peer (it opened with [`STREAM_MAGIC`], already
/// read): its head, its body when it announces one (collected under [`MAX_UPLOAD`]), then
/// the answer, streamed. A failure before the answer's first byte, and a TRACED call (core
/// records no trace for a streamed issue), is one plain reply frame.
///
/// Returns the send half once the answer is written and finished, so the door can let it
/// land before an age bound closes the connection; `None` when the stream broke.
pub(crate) async fn answer_streamed(
    kernel: &Kernel,
    session: &Session,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    version: u32,
) -> Option<quinn::SendStream> {
    let head = match read_frame(&mut recv).await {
        Ok(Some(payload)) => match decode_call_frame(&payload) {
            Ok(CallFrame::Head(head)) => head,
            _ => {
                let malformed = Error::Endpoint(
                    "malformed call: a stream of frames must open with a head".into(),
                );
                return reply(send, recv, failed(&malformed), version).await;
            }
        },
        _ => return None,
    };
    let CallHead {
        mut request,
        capability,
        with,
        body,
    } = head;
    admit(&mut request, session);
    let capability = session.authority().clamp(&capability);
    if let Some(body) = body {
        let collected = match collect_upload(&mut recv, body.len, MAX_UPLOAD).await {
            Ok(Ok(bytes)) => with_body_arg(request, &body.arg, bytes),
            Ok(Err(refused)) => Err(refused.into()),
            // The stream broke while the body arrived: nobody is left to answer.
            Err(_) => return None,
        };
        request = match collected {
            Ok(request) => request,
            Err(error) => return reply(send, recv, failed(&error), version).await,
        };
    }
    let context = with.issue_context(ikigai_core::SystemClock.now());
    if with.trace.is_some() {
        let answer = off_worker(|| {
            let collector = Arc::new(SpanCollector::default());
            match ikigai_resolve::issue_traced_as_with_context(
                kernel,
                request,
                &capability,
                collector.clone(),
                context,
            ) {
                Ok((representation, status)) => {
                    Reply::ResolvedTraced(representation, status, collector.take())
                }
                Err(error) => failed(&error),
            }
        });
        let answer = answer.unwrap_or_else(|panic| failed(&panic));
        return reply(send, recv, answer, version).await;
    }
    let resolved = off_worker(|| {
        let was_cached = Kernel::is_cached(kernel, &request, &capability);
        futures::executor::block_on(kernel.issue_body_with_context(request, &capability, context))
            .map(|answer| ReplyHead::of(answer, was_cached))
    });
    let (head, body) = match resolved.and_then(|answer| answer) {
        Ok(split) => split,
        Err(error) => return reply(send, recv, failed(&error), version).await,
    };
    let head = encode_reply_frame(&ReplyFrame::Head(head))
        .and_then(|p| framed(&p))
        .ok()?;
    send.write_all(&head).await.ok()?;
    pump(body, &mut send, version).await.ok()?;
    send.finish().ok()?;
    Some(send)
}

/// Write `body` as chunk frames, then END, or an ABORT carrying the producer's error the
/// moment it fails; a producer that yields more or fewer bytes than its length hint ends in
/// an ABORT too. `Err` when the peer stopped reading (CANCELED): the body is dropped here,
/// and with it whatever the producer holds.
async fn pump(body: Body, send: &mut quinn::SendStream, version: u32) -> io::Result<()> {
    let declared = body.len_hint();
    let mut chunks = body.into_stream();
    let mut sent: u64 = 0;
    let mut frames = Vec::new();
    while let Some(item) = chunks.next().await {
        let bytes = match item {
            Ok(bytes) => bytes,
            Err(error) => return abort(send, &error, version).await,
        };
        sent += bytes.len() as u64;
        if declared.is_some_and(|declared| sent > declared) {
            return abort(send, &miscounted(declared, sent), version).await;
        }
        frames.clear();
        write_chunks(&mut frames, &bytes)?;
        send.write_all(&frames).await.map_err(other)?;
    }
    if declared.is_some_and(|declared| sent != declared) {
        return abort(send, &miscounted(declared, sent), version).await;
    }
    frames.clear();
    write_body_frame(&mut frames, &BodyFrame::End)?;
    send.write_all(&frames).await.map_err(other)
}

fn miscounted(declared: Option<u64>, sent: u64) -> Error {
    Error::Endpoint(format!(
        "the body's producer declared {} bytes and produced {sent}",
        declared.unwrap_or_default()
    ))
}

async fn abort(send: &mut quinn::SendStream, error: &Error, version: u32) -> io::Result<()> {
    let mut frame = Vec::new();
    let error = WireError::from(error).for_peer(version);
    write_body_frame(&mut frame, &BodyFrame::Abort(error))?;
    send.write_all(&frame).await.map_err(other)
}

/// The caller's body, collected under `max_bytes`: `Ok(Err(refusal))` when the caller
/// aborted it or it ran past the bound (the rest is not read: the stream's receive half is
/// stopped instead), `Err` when the stream broke.
async fn collect_upload(
    recv: &mut quinn::RecvStream,
    len: Option<u64>,
    max_bytes: usize,
) -> io::Result<Result<Vec<u8>, WireError>> {
    let over = |seen: u64| {
        WireError::OverBudget(format!(
            "the body is larger than the {max_bytes}-byte bound this door collects (at least \
             {seen} bytes)"
        ))
    };
    if let Some(len) = len.filter(|len| *len > max_bytes as u64) {
        let _ = recv.stop(0u32.into());
        return Ok(Err(over(len)));
    }
    let mut state = BodyState::new(len);
    let mut out = Vec::new();
    loop {
        let payload = match read_frame(recv).await {
            Ok(Some(payload)) => payload,
            Ok(None) => return Err(state.ended_early()),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(state.ended_early())
            }
            Err(error) => return Err(error),
        };
        match state.feed(payload) {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > max_bytes {
                    let _ = recv.stop(0u32.into());
                    return Ok(Err(over((out.len() + chunk.len()) as u64)));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(Ok(out)),
            Err(error) => {
                return match refusal(&error) {
                    Some(aborted) => Ok(Err(aborted.clone())),
                    None => Err(error),
                }
            }
        }
    }
}

/// Run a resolution off the runtime's workers (see `dispatch_off_worker`), a panic in it
/// costing this call only: it arrives as a typed error, never as a dead stream.
fn off_worker<T>(work: impl FnOnce() -> T) -> Result<T, Error> {
    let caught = || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).map_err(|payload| {
            Error::Endpoint(format!(
                "the server panicked handling this call: {}",
                crate::panic_message(payload)
            ))
        })
    };
    let multi_thread = tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi_thread {
        tokio::task::block_in_place(caught)
    } else {
        caught()
    }
}

fn failed(error: &Error) -> Reply {
    Reply::ErrorTyped(WireError::from(error))
}

/// Write one plain reply as a frame (within one frame's bound, at the peer's version),
/// finish, and stop reading whatever the caller is still sending.
async fn reply(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    reply: Reply,
    version: u32,
) -> Option<quinn::SendStream> {
    let _ = recv.stop(0u32.into());
    let frame = encode_reply_for_peer(reply, version)
        .and_then(|p| framed(&p))
        .ok()?;
    send.write_all(&frame).await.ok()?;
    send.finish().ok()?;
    Some(send)
}

/// Turn away a stream of frames because the connection is full: the typed refusal as one
/// reply frame, without reading the caller's body.
pub(crate) async fn refuse_streamed(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    refusal: Reply,
    version: u32,
) {
    let _ = reply(send, recv, refusal, version).await;
}

// --- the client half ----------------------------------------------------------------------

/// A streamed answer from [`QuicResolver::issue_streamed`]: its [`head`](Self::head), and
/// its body as an [`io::Read`], frame by frame off the call's own QUIC stream, so a body of
/// any size crosses in the memory of one chunk ([`MAX_CHUNK`]).
///
/// Dropped before END, it stops the stream with [`CANCELED`], and the server drops the
/// producer. Each frame is waited for under the resolver's call deadline, which here bounds
/// the silence between frames, not the whole body. A read fails, never ends short, on the
/// producer's ABORT (its typed error is [`ikigai_wire::refusal`]'s), on a stream that ends
/// before END, and on a body other than its declared length.
pub struct QuicStreamed<'a> {
    resolver: &'a QuicResolver,
    head: ReplyHead,
    source: Source,
}

enum Source {
    Stream {
        recv: Option<quinn::RecvStream>,
        state: BodyState,
        pending: Bytes,
    },
    Buffered(io::Cursor<Vec<u8>>),
}

impl QuicStreamed<'_> {
    /// The answer's head: the representation without its bytes, its cache status, and its
    /// length when the producer knew it.
    pub fn head(&self) -> &ReplyHead {
        &self.head
    }

    /// Read the body to its end into `out`; a failure is typed.
    pub fn copy_to<W: io::Write + ?Sized>(&mut self, out: &mut W) -> Result<u64, Error> {
        io::copy(self, out).map_err(read_error)
    }

    /// Collect the body into a representation, refusing with `OverBudget` past `max_bytes`,
    /// never truncating.
    pub fn collect(mut self, max_bytes: usize) -> Result<(Representation, CacheStatus), Error> {
        let mut bytes = Vec::new();
        let read = (&mut self)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
        if read > max_bytes {
            return Err(Error::OverBudget {
                detail: format!("the streamed answer is larger than the {max_bytes}-byte bound"),
            });
        }
        let status = self.head.status;
        Ok((self.head.clone().into_representation(bytes), status))
    }

    fn buffered(
        resolver: &QuicResolver,
        representation: Representation,
        status: CacheStatus,
    ) -> QuicStreamed<'_> {
        let len = representation.bytes.len() as u64;
        let mut bytes = None;
        let representation = representation.map_body(|b| bytes = Some(b));
        QuicStreamed {
            resolver,
            head: ReplyHead {
                representation,
                status,
                len: Some(len),
            },
            source: Source::Buffered(io::Cursor::new(bytes.expect("map_body calls it"))),
        }
    }
}

impl Read for QuicStreamed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.resolver.call_timeout;
        let runtime = self.resolver.runtime();
        match &mut self.source {
            Source::Buffered(cursor) => cursor.read(buf),
            Source::Stream {
                recv,
                state,
                pending,
            } => {
                if buf.is_empty() {
                    return Ok(0);
                }
                while pending.is_empty() {
                    if state.is_ended() {
                        return Ok(0);
                    }
                    let Some(mut stream) = recv.take() else {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "the streamed answer's stream was already spent",
                        ));
                    };
                    let wire = Arc::clone(&self.resolver.wire);
                    let (stream, next) = drive(runtime, async move {
                        let next = match deadline {
                            Some(deadline) => {
                                match tokio::time::timeout(deadline, read_frame(&mut stream)).await
                                {
                                    Ok(next) => next,
                                    // Silent for a whole deadline: the next call redials
                                    // rather than trusting this connection (ledger #1092).
                                    Err(_) => Err(stale(
                                        &wire,
                                        io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            format!(
                                            "the peer sent no frame of the streamed answer within \
                                             {deadline:?}; the stream was canceled"
                                        ),
                                        ),
                                    )),
                                }
                            }
                            None => read_frame(&mut stream).await,
                        };
                        (stream, next)
                    })?;
                    *recv = Some(stream);
                    let step = match next {
                        Ok(Some(payload)) => state.feed(payload),
                        Ok(None) => Err(state.ended_early()),
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                            Err(state.ended_early())
                        }
                        Err(error) => Err(error),
                    };
                    match step {
                        Ok(Some(chunk)) => *pending = chunk,
                        Ok(None) => return Ok(0),
                        Err(error) => return Err(error),
                    }
                }
                let n = buf.len().min(pending.len());
                buf[..n].copy_from_slice(&pending[..n]);
                let _ = pending.split_to(n);
                Ok(n)
            }
        }
    }
}

impl Drop for QuicStreamed<'_> {
    fn drop(&mut self) {
        if let Source::Stream { recv, state, .. } = &mut self.source {
            if let Some(recv) = recv.as_mut() {
                if !state.is_ended() {
                    let _ = recv.stop(quinn::VarInt::from_u32(CANCELED));
                }
            }
        }
    }
}

/// Mark the resolver's connection stale (the next call redials) and pass `error` on: what a
/// missed deadline does, as it does for a plain call.
fn stale(wire: &crate::Wire, error: io::Error) -> io::Error {
    wire.stale.store(true, std::sync::atomic::Ordering::SeqCst);
    error
}

/// A failure reading a streamed body, typed: the producer's own error after an ABORT,
/// otherwise the transport's.
fn read_error(error: io::Error) -> Error {
    match refusal(&error) {
        Some(refused) => refused.clone().into(),
        None if error.kind() == io::ErrorKind::InvalidData => Error::Endpoint(error.to_string()),
        None => quic_error(error),
    }
}

/// The two halves of a call's stream while the call is being written, CANCELED on the
/// wire if dropped before the request was finished (a reset, never a truncated body).
struct CallStream {
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl Drop for CallStream {
    fn drop(&mut self) {
        let code = quinn::VarInt::from_u32(CANCELED);
        if let Some(send) = self.send.as_mut() {
            let _ = send.reset(code);
        }
        if let Some(recv) = self.recv.as_mut() {
            let _ = recv.stop(code);
        }
    }
}

impl QuicResolver {
    /// Resolve `request` under `capability` as part of `run`, with the answer STREAMED (wire
    /// v10, ledger #2242) on the call's own QUIC stream: its head now, its body frame by
    /// frame ([`QuicStreamed`]). With an `upload`, the caller's own body is sent the same way
    /// as the value of its argument (`content` for a Sink); the server collects it, under its
    /// upload bound ([`MAX_UPLOAD`]), before it resolves.
    ///
    /// Against a peer older than v10 this is the collected exchange that peer has always
    /// served, presented as a body: the upload goes inline (refused with `OverBudget` past
    /// one message), and the answer is the peer's `Resolved` (or its `OverBudget`).
    ///
    /// A streamed exchange is not replayed after a failure: the body may be one-shot on
    /// either side. When a tracer is installed the call is recorded, and a traced call is
    /// answered collected (core records no trace for a streamed issue).
    ///
    /// # Errors
    ///
    /// A typed [`Error`]: the server's refusal, the transport's failure, or `OverBudget`
    /// for a body past a bound.
    pub fn issue_streamed(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
        upload: Option<Upload<'_>>,
    ) -> Result<QuicStreamed<'_>, Error> {
        if !streams(self.wire.version()) {
            let request = match upload {
                Some(upload) => {
                    let arg = upload.arg.clone();
                    let bytes = upload.read_bounded(INLINE_BODY_BOUND).map_err(read_error)?;
                    with_body_arg(request, &arg, bytes)?
                }
                None => request,
            };
            let (representation, status) =
                Resolver::issue_as_in_run(self, request, capability, run)?;
            return Ok(QuicStreamed::buffered(self, representation, status));
        }
        let tracer = self.tracer().clone();
        let trace = tracer.as_ref().map(|_| TraceContext {
            trace_id: 1,
            parent_span: None,
        });
        let head = CallHead {
            request,
            capability: capability.clone(),
            with: IssueWith {
                trace,
                retries: run.retries,
                time_left_ms: run.time_left_millis(),
            },
            body: upload.as_ref().map(Upload::head),
        };
        let mut opening = STREAM_MAGIC.to_vec();
        let head_frame = encode_call_frame(&CallFrame::Head(head)).map_err(quic_error)?;
        write_frame(&mut opening, &head_frame).map_err(quic_error)?;
        let first = self.exchange_head(opening, upload).map_err(read_error)?;
        let (payload, recv) = first;
        match decode_reply_frame(&payload) {
            Ok(ReplyFrame::Head(head)) => {
                let len = head.len;
                Ok(QuicStreamed {
                    resolver: self,
                    head,
                    source: Source::Stream {
                        recv: Some(recv),
                        state: BodyState::new(len),
                        pending: Bytes::new(),
                    },
                })
            }
            Ok(ReplyFrame::Reply(Reply::Resolved(representation, status))) => {
                Ok(QuicStreamed::buffered(self, representation, status))
            }
            Ok(ReplyFrame::Reply(Reply::ResolvedTraced(representation, status, events))) => {
                if let Some(tracer) = &tracer {
                    for event in events {
                        tracer.record(event);
                    }
                }
                Ok(QuicStreamed::buffered(self, representation, status))
            }
            Ok(ReplyFrame::Reply(Reply::ErrorTyped(error))) => Err(error.into()),
            Ok(ReplyFrame::Reply(Reply::Error(message))) => Err(Error::Endpoint(message)),
            other => Err(Error::Endpoint(format!(
                "unexpected answer to a streamed call: {other:?}"
            ))),
        }
    }

    /// Open the call's stream (redialing once when the connection is dead: nothing was sent),
    /// write `opening` (the magic and the head), the caller's body as chunks and END (an
    /// ABORT when it fails to read or reads to the wrong length), finish, and read the first
    /// frame of the answer. When a write fails because the door refused the call and
    /// stopped reading, the answer it wrote is still read, so its typed refusal reaches the
    /// caller rather than a stopped stream.
    fn exchange_head(
        &self,
        opening: Vec<u8>,
        upload: Option<Upload<'_>>,
    ) -> io::Result<(Vec<u8>, quinn::RecvStream)> {
        let wire = Arc::clone(&self.wire);
        let (send, recv) = drive(self.runtime(), async move {
            use std::sync::atomic::Ordering;
            if wire.stale.swap(false, Ordering::SeqCst) {
                wire.reconnect().await?;
            }
            // The connection is cloned out of its lock in a statement of its own, so the
            // guard is not held across the await.
            let connection = wire.connection().clone();
            let (mut send, recv) = match connection.open_bi().await {
                Ok(halves) => halves,
                Err(_) => {
                    wire.reconnect().await?;
                    let connection = wire.connection().clone();
                    connection.open_bi().await.map_err(other)?
                }
            };
            send.write_all(&opening).await.map_err(other)?;
            Ok::<_, io::Error>((send, recv))
        })??;
        let mut call = CallStream {
            send: Some(send),
            recv: Some(recv),
        };
        let sent = match upload {
            Some(upload) => self.send_body(&mut call, upload),
            None => Ok(()),
        };
        let sent = sent.and_then(|()| {
            let mut send = call.send.take().expect("the send half is held");
            send.finish().map_err(other)
        });
        let mut recv = call.recv.take().expect("the receive half is held");
        let deadline = self.call_timeout;
        let wire = Arc::clone(&self.wire);
        let (recv, first) = drive(self.runtime(), async move {
            let first = match deadline {
                Some(deadline) => tokio::time::timeout(deadline, read_frame(&mut recv))
                    .await
                    .unwrap_or_else(|_| {
                        Err(stale(
                            &wire,
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "the peer did not answer within {deadline:?}; the call was \
                                     canceled"
                                ),
                            ),
                        ))
                    }),
                None => read_frame(&mut recv).await,
            };
            (recv, first)
        })?;
        let mut guard = CallStream {
            send: None,
            recv: Some(recv),
        };
        match first {
            Ok(Some(payload)) => {
                let recv = guard.recv.take().expect("held");
                Ok((payload, recv))
            }
            Ok(None) => Err(sent.err().unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer finished without an answer",
                )
            })),
            Err(read) => Err(sent.err().unwrap_or(read)),
        }
    }

    /// Send `upload` on `call`'s stream as chunks of at most [`MAX_CHUNK`], then END; or
    /// ABORT when it fails to read or reads to the wrong length.
    fn send_body(&self, call: &mut CallStream, upload: Upload<'_>) -> io::Result<()> {
        let Upload { arg, body, len } = upload;
        let mut buf = vec![0u8; MAX_CHUNK];
        let mut sent: u64 = 0;
        let ending = loop {
            let n = match body.read(&mut buf) {
                Ok(0) => break None,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    break Some(Error::Endpoint(format!(
                        "the caller's body failed to read: {error}"
                    )))
                }
            };
            sent += n as u64;
            if len.is_some_and(|len| sent > len) {
                break None;
            }
            let mut frame = Vec::with_capacity(n + 8);
            write_chunks(&mut frame, &buf[..n])?;
            self.write(call, frame)?;
        };
        let ending = ending.or_else(|| match len {
            Some(len) if len != sent => Some(Error::InvalidArgument {
                name: arg,
                detail: format!("the body announced {len} bytes and its reader gave {sent}"),
            }),
            _ => None,
        });
        let mut frame = Vec::new();
        match ending {
            Some(error) => {
                write_body_frame(&mut frame, &BodyFrame::Abort(WireError::from(&error)))?
            }
            None => write_body_frame(&mut frame, &BodyFrame::End)?,
        }
        self.write(call, frame)
    }

    /// Write `bytes` on `call`'s send half, on the resolver's runtime.
    fn write(&self, call: &mut CallStream, bytes: Vec<u8>) -> io::Result<()> {
        let mut send = call.send.take().expect("the send half is held");
        let (send, written) = drive(self.runtime(), async move {
            let written = send.write_all(&bytes).await.map_err(other);
            (send, written)
        })?;
        call.send = Some(send);
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use async_trait::async_trait;
    use ikigai_core::{
        ArgRef, Endpoint, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, ReprType, Verb,
    };
    use ikigai_wire::{decode, encode, Call, PROTOCOL_VERSION};
    use tokio::runtime::Runtime;

    use crate::{
        alpn_protocols, client_config_offering, connect, generate, negotiated_version,
        serve_connection, server_config_accepting, Identity, DEFAULT_IDLE_TIMEOUT, MAX_MESSAGE,
    };

    const BIG: usize = 1_000_010;

    fn pattern(total: usize) -> Vec<u8> {
        (0..total).map(|i| i as u8).collect()
    }

    /// Answers `total` bytes in 100 000-byte pieces as a one-shot body, failing with
    /// `OverBudget` from `fail_after` on; `total: None` never ends, and sets `dropped` when
    /// its stream is dropped (what canceling must reach).
    struct Generate {
        total: Option<usize>,
        fail_after: Option<usize>,
        dropped: Arc<AtomicBool>,
    }

    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Endpoint for Generate {
        async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
            let body = self.invoke_body(inv).await?;
            let bytes = inv.collect(body.bytes).await?;
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                bytes.to_vec(),
            ))
        }

        async fn invoke_body(
            &self,
            _inv: &Invocation<'_>,
        ) -> ikigai_core::Result<Representation<Body>> {
            let body = match self.total {
                Some(total) => {
                    let data = Bytes::from(pattern(total));
                    let fail_after = self.fail_after;
                    let pieces: Vec<ikigai_core::Result<Bytes>> = (0..total)
                        .step_by(100_000)
                        .map(|at| {
                            if fail_after.is_some_and(|f| at >= f) {
                                Err(Error::OverBudget {
                                    detail: "the producer ran past its bound".into(),
                                })
                            } else {
                                Ok(data.slice(at..(at + 100_000).min(data.len())))
                            }
                        })
                        .collect();
                    Body::once(futures::stream::iter(pieces))
                }
                None => {
                    let guard = SetOnDrop(Arc::clone(&self.dropped));
                    Body::once(futures::stream::unfold(guard, |guard| async move {
                        Some((Ok(Bytes::from_static(&[1u8; 65_536])), guard))
                    }))
                }
            };
            Ok(Representation::from_body(
                ReprType::new("application/octet-stream"),
                body,
            ))
        }
    }

    fn kernel(dropped: Arc<AtomicBool>) -> Kernel {
        let echo = FnEndpoint::new("echo", |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                inv.inline_arg("content")?.to_vec(),
            ))
        });
        let huge = FnEndpoint::new("huge", |_: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                vec![7u8; MAX_FRAME + 1],
            ))
        });
        let generate = |total, fail_after| Generate {
            total,
            fail_after,
            dropped: Arc::clone(&dropped),
        };
        Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:big"), generate(Some(BIG), None))
                .bind(
                    Exact::new("urn:test:broken"),
                    generate(Some(BIG), Some(300_000)),
                )
                .bind(Exact::new("urn:test:endless"), generate(None, None))
                .bind(Exact::new("urn:test:echo"), echo)
                .bind(Exact::new("urn:test:huge"), huge),
        ))
    }

    fn read(target: &str) -> Request {
        Request::new(Verb::Source, Iri::parse(target).unwrap())
    }

    fn sink(target: &str) -> Request {
        Request::new(Verb::Sink, Iri::parse(target).unwrap())
    }

    /// Serve ONE connection of [`kernel`] on a server accepting `alpns` (port 0, read back),
    /// returning its address and a handle that yields the version it negotiated.
    fn serve(
        server_id: &Identity,
        client_id: &Identity,
        alpns: Vec<Vec<u8>>,
        dropped: Arc<AtomicBool>,
    ) -> (SocketAddr, thread::JoinHandle<Option<u32>>) {
        let cfg = server_config_accepting(
            server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
            alpns,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await?;
                let connection = incoming.await.ok()?;
                let version = negotiated_version(&connection);
                let session = Session {
                    capability: Capability::root(),
                    file_segment: String::new(),
                    principal: None,
                };
                serve_connection(&Arc::new(kernel(dropped)), connection, session).await;
                endpoint.wait_idle().await;
                version
            })
        });
        (addr, server)
    }

    fn pair() -> (Identity, Identity) {
        (generate(), generate())
    }

    #[test]
    fn a_streamed_answer_crosses_on_one_stream_and_is_whole_at_end() {
        let (server_id, client_id) = pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (addr, server) = serve(&server_id, &client_id, alpn_protocols(), dropped);
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let mut answer = client
            .issue_streamed(
                read("urn:test:big"),
                &Capability::root(),
                &RunContext::default(),
                None,
            )
            .unwrap();
        assert_eq!(answer.head().status, CacheStatus::Uncacheable);
        let mut body = Vec::new();
        assert_eq!(answer.copy_to(&mut body).unwrap(), BIG as u64);
        assert_eq!(body, pattern(BIG));
        drop(answer);
        let (plain, _) = client
            .issue_as(
                sink("urn:test:echo").with_arg("content", ArgRef::Inline(b"ok".to_vec())),
                &Capability::root(),
            )
            .unwrap();
        assert_eq!(plain.bytes, b"ok");
        drop(client);
        assert_eq!(server.join().unwrap(), Some(PROTOCOL_VERSION));
    }

    #[test]
    fn a_producer_failure_ends_the_quic_stream_in_a_typed_abort() {
        let (server_id, client_id) = pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (addr, server) = serve(&server_id, &client_id, alpn_protocols(), dropped);
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let answer = client
            .issue_streamed(
                read("urn:test:broken"),
                &Capability::root(),
                &RunContext::default(),
                None,
            )
            .unwrap();
        let error = answer.collect(usize::MAX).unwrap_err();
        assert!(
            matches!(error, Error::OverBudget { ref detail } if detail.contains("its bound")),
            "{error:?}"
        );
        drop(client);
        server.join().unwrap();
    }

    /// The caller's body crosses as chunks and is the Sink's `content`; a body that announces
    /// more than the door's bound is refused at once, its bytes never read.
    #[test]
    fn a_streamed_call_carries_the_body_and_an_announced_overrun_is_refused() {
        let (server_id, client_id) = pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (addr, server) = serve(&server_id, &client_id, alpn_protocols(), dropped);
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let data = pattern(700_000);
        let mut reader = &data[..];
        let upload = Upload {
            arg: "content".into(),
            body: &mut reader,
            len: Some(data.len() as u64),
        };
        let (echoed, _) = client
            .issue_streamed(
                sink("urn:test:echo"),
                &Capability::root(),
                &RunContext::default(),
                Some(upload),
            )
            .unwrap()
            .collect(usize::MAX)
            .unwrap();
        assert_eq!(echoed.bytes, data);

        let mut endless = io::repeat(0).take(MAX_UPLOAD as u64 + 1);
        let upload = Upload {
            arg: "content".into(),
            body: &mut endless,
            len: Some(MAX_UPLOAD as u64 + 1),
        };
        let error = client
            .issue_streamed(
                sink("urn:test:echo"),
                &Capability::root(),
                &RunContext::default(),
                Some(upload),
            )
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, Error::OverBudget { .. }), "{error:?}");
        drop(client);
        server.join().unwrap();
    }

    /// ★ Canceling is the existing STOP_SENDING: a reader that drops an endless answer
    /// part-way stops the server's pump, and the producer is dropped (its Drop is what
    /// releases a spill or a wasm instance). The connection serves the next call.
    #[test]
    fn dropping_an_answer_cancels_the_producer() {
        let (server_id, client_id) = pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (addr, server) = serve(
            &server_id,
            &client_id,
            alpn_protocols(),
            Arc::clone(&dropped),
        );
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let mut answer = client
            .issue_streamed(
                read("urn:test:endless"),
                &Capability::root(),
                &RunContext::default(),
                None,
            )
            .unwrap();
        let mut some = vec![0u8; 300_000];
        answer.read_exact(&mut some).unwrap();
        drop(answer);
        let mut waited = Duration::ZERO;
        while !dropped.load(Ordering::SeqCst) && waited < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(20));
            waited += Duration::from_millis(20);
        }
        assert!(dropped.load(Ordering::SeqCst), "the producer was dropped");
        let (plain, _) = client
            .issue_as(
                sink("urn:test:echo").with_arg("content", ArgRef::Inline(b"next".to_vec())),
                &Capability::root(),
            )
            .unwrap();
        assert_eq!(plain.bytes, b"next");
        drop(client);
        server.join().unwrap();
    }

    // ---- the downgrade, both directions ----

    /// This build's client against a v9-only server (accepting just `ikigai/9`): the call
    /// goes plain, the upload inline, and the collected answer is read as a body.
    #[test]
    fn against_a_v9_server_the_client_sends_the_plain_call_with_the_body_inline() {
        let (server_id, client_id) = pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (addr, server) = serve(&server_id, &client_id, vec![b"ikigai/9".to_vec()], dropped);
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let mut bytes = &b"inline for v9"[..];
        let mut answer = client
            .issue_streamed(
                sink("urn:test:echo"),
                &Capability::root(),
                &RunContext::default(),
                Some(Upload::content(&mut bytes)),
            )
            .unwrap();
        let mut body = String::new();
        answer.read_to_string(&mut body).unwrap();
        assert_eq!(body, "inline for v9");
        drop(answer);
        drop(client);
        assert_eq!(server.join().unwrap(), Some(9));
    }

    /// A v9 (and a v8) client — raw quinn, offering only its own id — sends a plain call and
    /// gets the collected answer; past one message, a typed `OverBudget` (for v8 the Endpoint
    /// text it has always received), never a message its reader refuses.
    #[test]
    fn a_v9_client_gets_the_collected_answer_or_over_budget() {
        for (version, typed) in [(9u32, true), (8, false)] {
            let (server_id, client_id) = pair();
            let dropped = Arc::new(AtomicBool::new(false));
            let (addr, server) = serve(&server_id, &client_id, alpn_protocols(), dropped);
            let rt = Runtime::new().unwrap();
            let reply = rt.block_on(async {
                let cfg = client_config_offering(
                    &client_id,
                    &server_id.cert_pem,
                    DEFAULT_IDLE_TIMEOUT,
                    vec![format!("ikigai/{version}").into_bytes()],
                )
                .unwrap();
                let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                endpoint.set_default_client_config(cfg);
                let connection = endpoint.connect(addr, "ikigai").unwrap().await.unwrap();
                assert_eq!(negotiated_version(&connection), Some(version));
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                let call = Call::IssueAs(read("urn:test:huge"), Capability::root());
                send.write_all(&encode(&call).unwrap()).await.unwrap();
                send.finish().unwrap();
                let bytes = recv.read_to_end(MAX_MESSAGE).await.unwrap();
                connection.close(0u32.into(), b"done");
                decode::<Reply>(&bytes).unwrap()
            });
            match reply {
                Reply::ErrorTyped(WireError::OverBudget(detail)) if typed => {
                    assert!(detail.contains("streams it"), "{detail}")
                }
                Reply::ErrorTyped(WireError::Endpoint(text)) if !typed => {
                    assert!(text.starts_with("over budget: "), "{text}")
                }
                other => panic!("v{version}: {other:?}"),
            }
            assert_eq!(server.join().unwrap(), Some(version));
        }
    }
}
