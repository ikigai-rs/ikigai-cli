//! Wire v10 on the socket (ledger #2242): a streamed answer and a streamed call, as frames
//! after the ones the socket already carries ([`ikigai_wire::stream`]).
//!
//! The server half answers a [`CallHead`] from a v10 peer; the client half is
//! [`IpcResolver::issue_streamed`]. Calls on one connection stay sequential, so a streamed
//! exchange simply holds the connection until its END or ABORT; one abandoned part-way
//! spends the connection, and the next call redials.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, MutexGuard};

use futures::executor::block_on;
use futures::StreamExt;
use ikigai_core::{Body, Bytes, Capability, Clock, Error, Kernel, Representation, Request};
use ikigai_resolve::{CacheStatus, Resolver, RunContext, SpanCollector};
use ikigai_wire::{
    decode_reply_frame, encode_call_frame, encode_reply_for_peer, encode_reply_frame, read_frame,
    read_tagged_frame, refusal, streams, with_body_arg, write_body_frame, write_chunks,
    write_frame, BodyFrame, BodyReader, BodyState, CallFrame, CallHead, IssueWith, Reply,
    ReplyFrame, ReplyHead, TraceContext, Upload, WireError, MAX_CHUNK, MAX_FRAME,
};

use crate::{wire_error, Admission, IpcResolver, Limits, Link};

// --- the server half ----------------------------------------------------------------------

/// Answer one streamed call from a v10 peer: read the caller's body (when the head announces
/// one) under the door's upload bound, resolve, and write the answer as a head, chunks and
/// END or ABORT, or as one plain [`Reply`] frame when it fails before its first byte or the
/// caller is recording a trace (core records no trace for a streamed issue, so a traced
/// call is answered collected).
///
/// `Err` means the connection can carry nothing more (the peer is gone, or broke the
/// protocol); every failure of the CALL itself is written to the peer as a typed error.
pub(crate) fn answer_streamed(
    kernel: &Kernel,
    head: CallHead,
    admission: &Admission,
    stream: &mut &UnixStream,
    peer_version: u32,
    limits: &Limits,
) -> io::Result<()> {
    let CallHead {
        request,
        capability,
        with,
        body,
    } = head;
    let mut request = admission.admit_request(request);
    let capability = admission.admit_capability(&capability);
    if let Some(body) = body {
        // The body is the argument's value, so it is read whole before anything resolves.
        // Past the bound the rest is read and thrown away, so the connection stays aligned
        // for the next call, and the refusal is the answer.
        let mut reader = BodyReader::new(&mut *stream, body.len);
        let collected = match reader.collect_or_refuse(limits.max_upload()) {
            Ok(Ok(bytes)) => with_body_arg(request, &body.arg, bytes),
            Ok(Err(refused)) => Err(refused.into()),
            Err(error) => return Err(error),
        };
        match collected {
            Ok(with_body) => request = with_body,
            Err(error) => return write_reply(stream, failed(&error), peer_version),
        }
    }
    let context = with.issue_context(ikigai_core::SystemClock.now());
    if with.trace.is_some() {
        let collector = Arc::new(SpanCollector::default());
        let reply = match ikigai_resolve::issue_traced_as_with_context(
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
        };
        return write_reply(stream, reply, peer_version);
    }
    let was_cached = Kernel::is_cached(kernel, &request, &capability);
    let answer = match block_on(kernel.issue_body_with_context(request, &capability, context)) {
        Ok(answer) => answer,
        Err(error) => return write_reply(stream, failed(&error), peer_version),
    };
    let (head, body) = ReplyHead::of(answer, was_cached);
    write_frame(stream, &encode_reply_frame(&ReplyFrame::Head(head))?)?;
    pump(body, stream, peer_version)
}

/// Write `body` as chunk frames, then END, or an ABORT carrying the producer's error the
/// moment it fails. A producer that yields more or fewer bytes than its length hint ends in
/// an ABORT too: the reader holds the head to that hint, and an END after the wrong count
/// would read as a protocol error rather than the producer's.
fn pump<W: Write>(body: Body, out: &mut W, peer_version: u32) -> io::Result<()> {
    let declared = body.len_hint();
    let mut chunks = body.into_stream();
    let mut sent: u64 = 0;
    while let Some(item) = block_on(chunks.next()) {
        match item {
            Ok(bytes) => {
                sent += bytes.len() as u64;
                if declared.is_some_and(|declared| sent > declared) {
                    return abort(out, &miscounted(declared, sent), peer_version);
                }
                write_chunks(out, &bytes)?;
            }
            Err(error) => return abort(out, &error, peer_version),
        }
    }
    if declared.is_some_and(|declared| sent != declared) {
        return abort(out, &miscounted(declared, sent), peer_version);
    }
    write_body_frame(out, &BodyFrame::End)?;
    out.flush()
}

fn miscounted(declared: Option<u64>, sent: u64) -> Error {
    Error::Endpoint(format!(
        "the body's producer declared {} bytes and produced {sent}",
        declared.unwrap_or_default()
    ))
}

fn abort<W: Write>(out: &mut W, error: &Error, peer_version: u32) -> io::Result<()> {
    let error = WireError::from(error).for_peer(peer_version);
    write_body_frame(out, &BodyFrame::Abort(error))?;
    out.flush()
}

fn failed(error: &Error) -> Reply {
    Reply::ErrorTyped(WireError::from(error))
}

/// Write one plain reply frame, at the peer's version and within one frame's bound.
pub(crate) fn write_reply<W: Write>(
    out: &mut W,
    reply: Reply,
    peer_version: u32,
) -> io::Result<()> {
    write_frame(out, &encode_reply_for_peer(reply, peer_version)?)?;
    out.flush()
}

// --- the client half ----------------------------------------------------------------------

/// A streamed answer from [`IpcResolver::issue_streamed`]: its [`head`](Self::head), and its
/// body as an [`io::Read`], chunk by chunk off the socket, so a body of any size crosses in
/// the memory of one chunk ([`MAX_CHUNK`]).
///
/// It HOLDS the connection until the body is read to its END: calls on a socket are
/// sequential, so nothing else can use it meanwhile. Dropped before END, it spends the
/// connection (the server's next write fails and it drops the producer), and the
/// resolver's next call redials.
///
/// A read fails, never ends short, on the producer's ABORT (its typed error is
/// [`ikigai_wire::refusal`]'s), on a stream that stops before END, and on a body other than
/// its declared length.
pub struct Streamed<'a> {
    head: ReplyHead,
    source: Source<'a>,
}

enum Source<'a> {
    /// Chunks still to come off the socket.
    Socket {
        guard: MutexGuard<'a, Option<Link>>,
        state: BodyState,
        pending: Bytes,
    },
    /// The whole body is already here: a collected answer (a peer older than v10, or a
    /// traced call), served as a body all the same.
    Buffered(io::Cursor<Vec<u8>>),
}

impl Streamed<'_> {
    /// The answer's head: the representation without its bytes, its cache status, and its
    /// length when the producer knew it.
    pub fn head(&self) -> &ReplyHead {
        &self.head
    }

    /// Read the body to its end into `out`, the bytes copied as they arrive. Returns how
    /// many were written; a failure is typed (the producer's own error after an ABORT).
    pub fn copy_to<W: Write + ?Sized>(&mut self, out: &mut W) -> Result<u64, Error> {
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
        let head = self.head.clone();
        Ok((head.into_representation(bytes), status))
    }

    fn buffered(representation: Representation, status: CacheStatus) -> Streamed<'static> {
        let len = representation.bytes.len() as u64;
        let mut bytes = None;
        let representation = representation.map_body(|b| bytes = Some(b));
        Streamed {
            head: ReplyHead {
                representation,
                status,
                len: Some(len),
            },
            source: Source::Buffered(io::Cursor::new(bytes.expect("map_body calls it"))),
        }
    }
}

impl Read for Streamed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.source {
            Source::Buffered(cursor) => cursor.read(buf),
            Source::Socket {
                guard,
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
                    let Some(link) = guard.as_ref() else {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "the streamed answer's connection was already spent",
                        ));
                    };
                    let next = match read_tagged_frame(&mut &link.stream) {
                        Ok(Some(payload)) => state.feed(payload),
                        Ok(None) => Err(state.ended_early()),
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                            Err(state.ended_early())
                        }
                        Err(error) => Err(error),
                    };
                    match next {
                        Ok(Some(chunk)) => *pending = chunk,
                        Ok(None) => return Ok(0),
                        Err(error) => {
                            // An ABORT leaves the connection aligned, but a failed body
                            // is rare enough that a fresh connection is the simple rule.
                            **guard = None;
                            return Err(error);
                        }
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

impl Drop for Streamed<'_> {
    fn drop(&mut self) {
        if let Source::Socket { guard, state, .. } = &mut self.source {
            if !state.is_ended() {
                // Abandoned part-way: the rest of the body is still coming, and calls are
                // matched to replies positionally, so the connection is spent.
                **guard = None;
            }
        }
    }
}

/// A failure reading a streamed body, typed: the producer's own error after an ABORT,
/// otherwise the transport's reading of the I/O failure.
fn read_error(error: io::Error) -> Error {
    match refusal(&error) {
        Some(refused) => refused.clone().into(),
        None if error.kind() == io::ErrorKind::InvalidData => Error::Endpoint(error.to_string()),
        None => wire_error(error),
    }
}

/// How much of a body a peer older than v10 takes, inline in one frame: the frame's bound,
/// less room for the request around it.
const INLINE_BODY_BOUND: usize = MAX_FRAME - 64 * 1024;

impl IpcResolver {
    /// Resolve `request` under `capability` as part of `run`, with the answer STREAMED (wire
    /// v10, ledger #2242): its head now, its body read chunk by chunk ([`Streamed`]), so an
    /// answer of any size crosses in the memory of one chunk. With an `upload`, the
    /// caller's own body is sent the same way as the value of its argument (`content` for a
    /// Sink); the server collects it, under its upload bound, before it resolves.
    ///
    /// Against a peer older than v10 this is the collected exchange that peer has always
    /// served, presented as a body: the upload goes inline in one frame (refused with
    /// `OverBudget` past it), and the answer is the peer's `Resolved` (or its `OverBudget`
    /// for one past a frame).
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
    ) -> Result<Streamed<'_>, Error> {
        let tracer = self.tracer.lock().expect("tracer lock").clone();
        let trace = tracer.as_ref().map(|_| TraceContext {
            trace_id: 1,
            parent_span: None,
        });
        let mut guard = self.stream.lock().expect("ipc stream lock");
        let dialed_this_call = guard.is_none();
        if dialed_this_call {
            *guard = Some(self.redial(None).map_err(wire_error)?);
        }
        let version = guard.as_ref().expect("just ensured").version;
        if !streams(version) {
            drop(guard);
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
            return Ok(Streamed::buffered(representation, status));
        }
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
        let head_frame = encode_call_frame(&CallFrame::Head(head.clone())).map_err(read_error)?;
        let mut written = write_head(&guard.as_ref().expect("just ensured").stream, &head_frame);
        if !dialed_this_call && written.as_ref().is_err_and(crate::is_dead_connection) {
            // Heal on use: the established connection died (the server bounced) before the
            // head reached it, so nothing ran and nothing of the body was read. Redial once.
            *guard = None;
            let link = self.redial(None).map_err(wire_error)?;
            if !streams(link.version) {
                // It came back speaking an older version: the collected exchange it serves.
                *guard = Some(link);
                drop(guard);
                return self.issue_streamed(head.request, capability, run, upload);
            }
            written = write_head(&link.stream, &head_frame);
            *guard = Some(link);
        }
        if let Err(error) = written {
            *guard = None;
            return Err(read_error(error));
        }
        let first = {
            let link = guard.as_ref().expect("just ensured");
            exchange_body(&link.stream, upload)
        };
        let payload = match first {
            Ok(payload) => payload,
            Err(error) => {
                *guard = None;
                return Err(read_error(error));
            }
        };
        match decode_reply_frame(&payload) {
            Ok(ReplyFrame::Head(head)) => {
                let len = head.len;
                Ok(Streamed {
                    head,
                    source: Source::Socket {
                        guard,
                        state: BodyState::new(len),
                        pending: Bytes::new(),
                    },
                })
            }
            Ok(ReplyFrame::Reply(Reply::Resolved(representation, status))) => {
                Ok(Streamed::buffered(representation, status))
            }
            Ok(ReplyFrame::Reply(Reply::ResolvedTraced(representation, status, events))) => {
                if let Some(tracer) = &tracer {
                    for event in events {
                        tracer.record(event);
                    }
                }
                Ok(Streamed::buffered(representation, status))
            }
            Ok(ReplyFrame::Reply(Reply::ErrorTyped(error))) => Err(error.into()),
            Ok(ReplyFrame::Reply(Reply::Error(message))) => Err(Error::Endpoint(message)),
            other => {
                *guard = None;
                Err(Error::Endpoint(format!(
                    "unexpected answer to a streamed call: {other:?}"
                )))
            }
        }
    }
}

/// Write a streamed call's head frame.
fn write_head(stream: &UnixStream, head_frame: &[u8]) -> io::Result<()> {
    let mut out = stream;
    write_frame(&mut out, head_frame).and_then(|()| out.flush())
}

/// After the head: write the caller's body, then read the first frame of the answer. A
/// body that fails to read, or reads to a length other than the one announced, is ABORTED,
/// never ended short. When the write fails part-way (a door that refused the call and
/// closed), the answer it wrote before closing is still read, so its typed refusal reaches
/// the caller rather than a broken pipe.
fn exchange_body(stream: &UnixStream, upload: Option<Upload<'_>>) -> io::Result<Vec<u8>> {
    let mut out = stream;
    let sent = match upload {
        Some(upload) => send_body(&mut out, upload).and_then(|()| out.flush()),
        None => Ok(()),
    };
    match read_frame(&mut &*stream) {
        Ok(payload) => Ok(payload),
        Err(read) => Err(sent.err().unwrap_or(read)),
    }
}

/// Send `upload` as chunks of at most [`MAX_CHUNK`], then END; or ABORT when it fails to
/// read or reads to the wrong length.
fn send_body<W: Write>(out: &mut W, upload: Upload<'_>) -> io::Result<()> {
    let Upload { arg, body, len } = upload;
    let mut buf = vec![0u8; MAX_CHUNK];
    let mut sent: u64 = 0;
    loop {
        let n = match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let failed = Error::Endpoint(format!("the caller's body failed to read: {error}"));
                return write_body_frame(out, &BodyFrame::Abort(WireError::from(&failed)));
            }
        };
        sent += n as u64;
        if len.is_some_and(|len| sent > len) {
            break;
        }
        write_chunks(out, &buf[..n])?;
    }
    match len {
        Some(len) if len != sent => {
            let wrong = Error::InvalidArgument {
                name: arg,
                detail: format!("the body announced {len} bytes and its reader gave {sent}"),
            };
            write_body_frame(out, &BodyFrame::Abort(WireError::from(&wrong)))
        }
        _ => write_body_frame(out, &BodyFrame::End),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::thread;

    use async_trait::async_trait;
    use ikigai_core::{
        ArgRef, Endpoint, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, ReprType, Verb,
    };
    use ikigai_wire::{
        decode, encode, read_message, write_hello, write_message, Call, Hello, HelloMode,
        PROTOCOL_VERSION,
    };

    use crate::{connect, serve_connection, Admission};

    /// Answers `total` bytes (`0, 1, …, 255, 0, …`) in 100 000-byte pieces as a one-shot
    /// body, failing with `OverBudget` once `fail_after` bytes are out when that is set.
    struct Generate {
        total: usize,
        fail_after: Option<usize>,
    }

    fn pattern(total: usize) -> Vec<u8> {
        (0..total).map(|i| i as u8).collect()
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
            let data = Bytes::from(pattern(self.total));
            let fail_after = self.fail_after;
            let pieces: Vec<ikigai_core::Result<Bytes>> = (0..self.total)
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
            Ok(Representation::from_body(
                ReprType::new("application/octet-stream"),
                Body::once(futures::stream::iter(pieces)),
            ))
        }
    }

    const BIG: usize = 1_000_010;

    fn kernel() -> Kernel {
        let size = FnEndpoint::new("size", |inv: &ikigai_core::Invocation<'_>| {
            let n = inv.inline_arg("content")?.len();
            Ok(Representation::new(
                ReprType::new("text/plain"),
                n.to_string().into_bytes(),
            ))
        });
        let echo = FnEndpoint::new("echo", |inv: &ikigai_core::Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                inv.inline_arg("content")?.to_vec(),
            ))
        });
        Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    Exact::new("urn:test:big"),
                    Generate {
                        total: BIG,
                        fail_after: None,
                    },
                )
                .bind(
                    Exact::new("urn:test:broken"),
                    Generate {
                        total: BIG,
                        fail_after: Some(300_000),
                    },
                )
                .bind(Exact::new("urn:test:size"), size)
                .bind(Exact::new("urn:test:echo"), echo),
        ))
    }

    fn read(target: &str) -> Request {
        Request::new(Verb::Source, Iri::parse(target).unwrap())
    }

    fn sink(target: &str) -> Request {
        Request::new(Verb::Sink, Iri::parse(target).unwrap())
    }

    /// A short socket path: the scratch directory may be too long for `sun_path`.
    fn socket_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/iks{}{name}", std::process::id()))
    }

    /// Serve ONE connection on `path` under `limits`, returning the handle to join.
    fn serve_one(path: &Path, limits: Limits) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&kernel(), stream, &limits, &Admission::owner());
        })
    }

    #[test]
    fn a_streamed_answer_crosses_in_chunks_and_is_whole_at_end() {
        let path = socket_path("sa");
        let server = serve_one(&path, Limits::default());
        let client = connect(&path).unwrap();
        let mut answer = client
            .issue_streamed(
                read("urn:test:big"),
                &Capability::root(),
                &RunContext::default(),
                None,
            )
            .unwrap();
        assert_eq!(
            answer.head().repr_type(),
            &ReprType::new("application/octet-stream")
        );
        assert_eq!(
            answer.head().status,
            CacheStatus::Uncacheable,
            "a one-shot body"
        );
        assert_eq!(answer.head().len, None);
        let mut body = Vec::new();
        assert_eq!(answer.copy_to(&mut body).unwrap(), BIG as u64);
        assert_eq!(body, pattern(BIG));
        drop(answer);
        // The connection is still good for a plain call after a whole body.
        let (plain, _) = client
            .issue_as(
                sink("urn:test:size").with_arg("content", ArgRef::Inline(b"abc".to_vec())),
                &Capability::root(),
            )
            .unwrap();
        assert_eq!(plain.bytes, b"3");
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// The producer fails part-way: the reader gets the producer's typed error, never the
    /// 300 000 bytes before it as if they were the body.
    #[test]
    fn a_producer_failure_ends_the_stream_in_a_typed_abort() {
        let path = socket_path("ab");
        let server = serve_one(&path, Limits::default());
        let client = connect(&path).unwrap();
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
        let _ = std::fs::remove_file(&path);
    }

    /// The caller's body crosses as chunks and becomes the Sink's `content`, larger than one
    /// chunk; past the door's upload bound it is refused, the connection kept aligned for
    /// the next call.
    #[test]
    fn a_streamed_call_carries_the_body_and_the_door_bounds_it() {
        let path = socket_path("up");
        let server = serve_one(&path, Limits::default().with_max_upload(600_000));
        let client = connect(&path).unwrap();
        let data = pattern(500_000);
        let mut reader = &data[..];
        let upload = Upload {
            arg: "content".into(),
            body: &mut reader,
            len: Some(data.len() as u64),
        };
        let answer = client
            .issue_streamed(
                sink("urn:test:echo"),
                &Capability::root(),
                &RunContext::default(),
                Some(upload),
            )
            .unwrap();
        let (echoed, _) = answer.collect(usize::MAX).unwrap();
        assert_eq!(echoed.bytes, data);

        let too_big = pattern(700_000);
        let mut reader = &too_big[..];
        let error = client
            .issue_streamed(
                sink("urn:test:size"),
                &Capability::root(),
                &RunContext::default(),
                Some(Upload::content(&mut reader)),
            )
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, Error::OverBudget { .. }), "{error:?}");
        // The same connection serves the next call.
        let mut small = &b"four"[..];
        let answer = client
            .issue_streamed(
                sink("urn:test:size"),
                &Capability::root(),
                &RunContext::default(),
                Some(Upload::content(&mut small)),
            )
            .unwrap();
        assert_eq!(answer.collect(16).unwrap().0.bytes, b"4");
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A reader that announces one length and gives another is aborted, never ended short:
    /// the door answers with the typed error and runs nothing.
    #[test]
    fn an_upload_shorter_than_it_announced_is_refused() {
        let path = socket_path("sh");
        let server = serve_one(&path, Limits::default());
        let client = connect(&path).unwrap();
        let mut reader = &b"abc"[..];
        let upload = Upload {
            arg: "content".into(),
            body: &mut reader,
            len: Some(10),
        };
        let error = client
            .issue_streamed(
                sink("urn:test:size"),
                &Capability::root(),
                &RunContext::default(),
                Some(upload),
            )
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidArgument { ref name, .. } if name == "content"),
            "{error:?}"
        );
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Dropping a streamed answer part-way spends the connection, and the next call redials
    /// onto a fresh one rather than reading the rest of the abandoned body as its answer.
    #[test]
    fn an_abandoned_stream_spends_the_connection_and_the_next_call_redials() {
        let path = socket_path("dr");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(&kernel(), stream, &Limits::default(), &Admission::owner());
            }
        });
        let client = connect(&path).unwrap();
        let mut answer = client
            .issue_streamed(
                read("urn:test:big"),
                &Capability::root(),
                &RunContext::default(),
                None,
            )
            .unwrap();
        let mut first = [0u8; 10];
        answer.read_exact(&mut first).unwrap();
        drop(answer);
        let (plain, _) = client
            .issue_as(
                sink("urn:test:size").with_arg("content", ArgRef::Inline(b"ab".to_vec())),
                &Capability::root(),
            )
            .unwrap();
        assert_eq!(plain.bytes, b"2");
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Heal on use, as a plain call does: the server closed the established connection (an
    /// idle bound here; a bounce in life), so the head's write fails before anything ran,
    /// and the streamed call redials once and is served.
    #[test]
    fn a_streamed_call_heals_a_connection_the_server_closed() {
        let path = socket_path("he");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let limits = Limits::default().with_idle_timeout(std::time::Duration::from_millis(100));
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(&kernel(), stream, &limits, &Admission::owner());
            }
        });
        let client = connect(&path).unwrap();
        let (plain, _) = client
            .issue_as(
                sink("urn:test:size").with_arg("content", ArgRef::Inline(b"a".to_vec())),
                &Capability::root(),
            )
            .unwrap();
        assert_eq!(plain.bytes, b"1");
        thread::sleep(std::time::Duration::from_millis(400));
        let mut bytes = &b"after the close"[..];
        let answer = client
            .issue_streamed(
                sink("urn:test:size"),
                &Capability::root(),
                &RunContext::default(),
                Some(Upload::content(&mut bytes)),
            )
            .unwrap();
        assert_eq!(answer.collect(16).unwrap().0.bytes, b"15");
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // ---- the downgrade, both directions ----

    /// A v9 peer (raw bytes, not this build's client) is answered at 9 and never meets a
    /// frame: its plain call gets the collected answer, and an answer past one frame is a
    /// typed `OverBudget`, never a frame its reader refuses. A v8 peer gets the same refusal
    /// as the Endpoint text it has always received.
    #[test]
    fn a_v9_peer_gets_the_collected_answer_or_over_budget() {
        let huge = Kernel::new(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:test:huge"),
            FnEndpoint::new("huge", |_: &ikigai_core::Invocation<'_>| {
                Ok(Representation::new(
                    ReprType::new("application/octet-stream"),
                    vec![7u8; MAX_FRAME + 1],
                ))
            }),
        )));
        let huge = Arc::new(huge);
        for (version, expect_typed) in [(9u32, true), (8, false)] {
            let path = socket_path(&format!("v{version}"));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let kernel = Arc::clone(&huge);
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(&kernel, stream, &Limits::default(), &Admission::owner());
            });
            let stream = UnixStream::connect(&path).unwrap();
            let mut s = &stream;
            write_hello(
                &mut s,
                &Hello {
                    version,
                    mode: HelloMode::Verbatim,
                },
            )
            .unwrap();
            let answer = ikigai_wire::decode_hello(&read_frame(&mut s).unwrap()).unwrap();
            assert_eq!(answer.version, version);
            write_message(
                &mut s,
                &Call::IssueAs(read("urn:test:huge"), Capability::root()),
            )
            .unwrap();
            let reply: Reply = read_message(&mut s).unwrap();
            match reply {
                Reply::ErrorTyped(WireError::OverBudget(detail)) if expect_typed => {
                    assert!(detail.contains("streams it"), "{detail}")
                }
                Reply::ErrorTyped(WireError::Endpoint(text)) if !expect_typed => {
                    assert!(text.starts_with("over budget: "), "{text}")
                }
                other => panic!("v{version}: {other:?}"),
            }
            // And a plain answer that fits is the plain `Resolved` it always was.
            drop(stream);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }
    }

    /// A v9 peer that sends a head anyway is refused as malformed: the door closes rather
    /// than read frames the peer never negotiated.
    #[test]
    fn a_head_from_a_v9_peer_is_not_served() {
        let path = socket_path("h9");
        let server = serve_one(&path, Limits::default());
        let stream = UnixStream::connect(&path).unwrap();
        let mut s = &stream;
        write_hello(
            &mut s,
            &Hello {
                version: 9,
                mode: HelloMode::Verbatim,
            },
        )
        .unwrap();
        let _ = read_frame(&mut s).unwrap();
        let head = CallHead {
            request: read("urn:test:big"),
            capability: Capability::root(),
            with: IssueWith::default(),
            body: None,
        };
        write_frame(&mut s, &encode_call_frame(&CallFrame::Head(head)).unwrap()).unwrap();
        assert!(read_frame(&mut s).is_err(), "the door closes");
        drop(stream);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// The client's side of the downgrade: against a v9 server (one that answers 9 to the
    /// hello, as a v9 build does), `issue_streamed` sends the plain call with the upload
    /// INLINE, and presents the collected answer as a body.
    #[test]
    fn against_a_v9_server_the_client_sends_the_plain_call_and_reads_a_collected_answer() {
        let path = socket_path("s9");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let mut offered = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut s = &stream;
                let hello = ikigai_wire::decode_hello(&read_frame(&mut s).unwrap()).unwrap();
                offered.push(hello.version);
                write_hello(
                    &mut s,
                    &Hello {
                        version: 9,
                        mode: HelloMode::Verbatim,
                    },
                )
                .unwrap();
                if hello.version != 9 {
                    continue; // a v9 server closes on a mismatch
                }
                // A v9 server decodes only plain calls; a head here would fail this decode.
                let payload = read_frame(&mut s).unwrap();
                let call: Call = decode(&payload).expect("a v9 server is sent a plain call");
                let Call::IssueAs(request, _) = call else {
                    panic!("expected IssueAs, got {call:?}");
                };
                let content = request.args.get("content").cloned();
                let reply = Reply::Resolved(
                    Representation::new(
                        ReprType::new("text/plain"),
                        match content {
                            Some(ArgRef::Inline(bytes)) => bytes,
                            other => format!("{other:?}").into_bytes(),
                        },
                    ),
                    CacheStatus::Miss,
                );
                write_frame(&mut s, &encode(&reply).unwrap()).unwrap();
            }
            offered
        });
        let client = connect(&path).unwrap();
        let mut bytes = &b"inline for v9"[..];
        let mut answer = client
            .issue_streamed(
                sink("urn:test:echo"),
                &Capability::root(),
                &RunContext::default(),
                Some(Upload::content(&mut bytes)),
            )
            .unwrap();
        assert_eq!(answer.head().len, Some(13));
        let mut body = String::new();
        answer.read_to_string(&mut body).unwrap();
        assert_eq!(body, "inline for v9");
        drop(answer);
        drop(client);
        assert_eq!(server.join().unwrap(), vec![PROTOCOL_VERSION, 9]);
        let _ = std::fs::remove_file(&path);
    }
}
