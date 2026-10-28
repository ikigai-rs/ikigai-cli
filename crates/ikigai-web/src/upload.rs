//! Uploads larger than memory (ledger #2244, stage 8 of the streams design, ledger #2228):
//! **spill, then dispatch.** An upload route ([`Uploads::route`]) does not read its body into
//! memory. The door writes it through the kernel's spill facility
//! ([`Kernel::with_spill`](ikigai_core::Kernel::with_spill)) as it arrives, the facility
//! hashing it while it writes, holds the result in a content store under its content id,
//! and issues the Sink with `content=b3:…` ([`ArgRef::Content`](ikigai_core::ArgRef::Content)).
//! The Sink reads it with [`Invocation::content_body`](ikigai_core::Invocation::content_body),
//! as a body that can be read again: request identity stays a pure value and a retried Sink
//! reads its content again. The spill is released when the request is answered, and the
//! file goes when the last holder of it lets go.
//!
//! The bounds, each a refusal and never a truncation:
//!
//! - **The route's own `max_body_bytes`**, checked against `Content-Length` before a byte is
//!   read: past it, `413`.
//! - **The caller's disk grant**, `urn:cap:stream:spill:<bytes>`
//!   ([`cap_stream_spill`](ikigai_core::cap_stream_spill)) clamped to the kernel's ceiling
//!   ([`Kernel::with_stream_spill`](ikigai_core::Kernel::with_stream_spill)): past it, `413`
//!   naming the grant. A caller holding NO grant in that family does not spill at all: its
//!   request is taken into memory under [`EdgeConfig::max_body_bytes`](crate::EdgeConfig)
//!   like any other, so a door's behavior is unchanged for every caller it grants nothing.
//! - **A minimum rate** ([`Uploads::min_rate`]): the body must keep arriving at
//!   `bytes_per_second`, after a `grace` at the start. The deadline is `grace` plus one second
//!   for every `bytes_per_second` received so far, so a client may pause as long as it is
//!   ahead; one that falls behind is cut with `408` and its spill removed. The same rule as
//!   Apache's `mod_reqtimeout` `MinRate`.
//! - **The content store's own bound** (the total held by uploads in flight): past it, `503`
//!   with `Retry-After`.
//!
//! A request that will not be spilled is refused before its spill begins: admission
//! ([`EdgeConfig::admit_fn`](crate::EdgeConfig)) runs first, as it runs first everywhere.
//! An upload route takes its body BY `Content-Length` only: `Transfer-Encoding` on one is
//! `501`, since request-side chunked parsing is where request smuggling lives and a length
//! known up front is what lets the bounds above refuse before reading.
//!
//! What a Sink behind an upload route must do: read `content` with `content_body` (a Sink
//! that reads it with `inline_arg` is handed a content id it cannot read, and refuses).

use crate::door::{refusal, render, reply, unread, DoorBody};
use crate::{
    answer_admitted, apply_edge_policy, error_resp, finish, path_segments, refuse_admission,
    request_capability, route_table, shape_binds, HttpRequest, Matched, Resp, Shared,
    DEFAULT_BODY_TIMEOUT,
};
use bytes::Buf;
use futures_core::Stream;
use http_body::Body;
use ikigai_core::{
    ByteStream, Bytes, Capability, ContentId, Error, Issuer, Kernel, MemoryContentStore, Replay,
    Spill, CAP_STREAM_SPILL,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

/// The rate an upload must keep up after its grace, by default: 16 KiB a second (about 128
/// kbit/s), well under a phone on a poor connection, and enough that a client holding a
/// connection open with a trickle is cut within seconds of falling behind.
pub const DEFAULT_UPLOAD_MIN_RATE: u64 = 16 * 1024;

/// How long an upload may take before the rate applies, by default: the door's body deadline
/// ([`DEFAULT_BODY_TIMEOUT`]), so a body the in-memory path would have taken is taken here too.
pub const DEFAULT_UPLOAD_GRACE: Duration = DEFAULT_BODY_TIMEOUT;

/// The upload routes of a door, and the content store their spills are held in. Served with
/// [`serve_with_uploads`](crate::serve_with_uploads).
///
/// A `POST` or `PUT` to an upload route, from a caller whose capability holds
/// `urn:cap:stream:spill:<bytes>` ([`cap_stream_spill`](ikigai_core::cap_stream_spill)), is
/// written through the kernel's spill facility as it arrives (hashed while written), held in
/// `store` under its content id, and the Sink is issued with `content=b3:…`; it reads it with
/// [`Invocation::content_body`](ikigai_core::Invocation::content_body). Each bound refuses and
/// never truncates:
///
/// - the route's own `max_body_bytes` and the caller's grant (clamped to the kernel's ceiling,
///   [`Kernel::with_stream_spill`](ikigai_core::Kernel::with_stream_spill)), both checked on
///   `Content-Length` before a byte is read: `413`;
/// - the minimum rate ([`min_rate`](Self::min_rate)): `408`, the spill removed;
/// - `store`'s own bound, on everything held at once: `503` with `Retry-After`.
///
/// Admission runs before any of it. An upload route takes its body by `Content-Length`:
/// `Transfer-Encoding` on one is `501`. A caller holding no grant in the family does not spill:
/// its body is read into memory under `EdgeConfig::max_body_bytes`, as on any route.
///
/// `store` must be the store the kernel resolves content ids through
/// ([`Kernel::with_content_store`](ikigai_core::Kernel::with_content_store)): the door puts each
/// spill there, and the Sink reads it from there. Its byte bound is the most disk the door's
/// uploads in flight may hold at once.
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use ikigai_core::MemoryContentStore;
/// use ikigai_web::Uploads;
///
/// let store = Arc::new(MemoryContentStore::new(8 << 30)); // 8 GiB held at once, at most
/// let uploads = Uploads::new(store)
///     .route("/media/{name}", 4 << 30) // up to 4 GiB each
///     .min_rate(64 * 1024, Duration::from_secs(10));
/// assert_eq!(uploads.max_body_bytes("/media/film.mp4"), Some(4 << 30));
/// assert_eq!(uploads.max_body_bytes("/notes/x"), None);
/// ```
#[derive(Clone)]
pub struct Uploads {
    store: Arc<MemoryContentStore>,
    routes: Vec<(String, u64)>,
    min_rate: u64,
    grace: Duration,
}

impl std::fmt::Debug for Uploads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Uploads")
            .field("routes", &self.routes)
            .field("min_rate", &self.min_rate)
            .field("grace", &self.grace)
            .finish_non_exhaustive()
    }
}

impl Uploads {
    /// No upload routes yet, holding spills in `store`, at [`DEFAULT_UPLOAD_MIN_RATE`] after
    /// [`DEFAULT_UPLOAD_GRACE`].
    pub fn new(store: Arc<MemoryContentStore>) -> Uploads {
        Uploads {
            store,
            routes: Vec::new(),
            min_rate: DEFAULT_UPLOAD_MIN_RATE,
            grace: DEFAULT_UPLOAD_GRACE,
        }
    }

    /// One more upload route: a `POST` or `PUT` whose path fits `pattern` (the path grammar
    /// of [`Route::pattern`](crate::Route::pattern), `{var}` matching one segment) takes a
    /// body of up to `max_body_bytes` by spilling it. The target is whatever the route table
    /// (or the mechanical default) makes of the path. The first matching pattern wins.
    pub fn route(mut self, pattern: impl Into<String>, max_body_bytes: u64) -> Uploads {
        self.routes.push((pattern.into(), max_body_bytes));
        self
    }

    /// The minimum rate an upload must keep, in bytes a second, once `grace` has passed. The
    /// deadline is `grace` plus one second for every `bytes_per_second` received so far (the
    /// rule of Apache's `mod_reqtimeout` `MinRate`), so a client may pause while it is ahead;
    /// one that falls behind is cut with `408`. A rate of `0` is taken as `1`: there is always
    /// a rate.
    pub fn min_rate(mut self, bytes_per_second: u64, grace: Duration) -> Uploads {
        self.min_rate = bytes_per_second.max(1);
        self.grace = grace;
        self
    }

    /// The largest body the upload route for `path` takes, or `None` when no upload route
    /// fits `path`.
    pub fn max_body_bytes(&self, path: &str) -> Option<u64> {
        let segs = path_segments(path);
        self.routes
            .iter()
            .find(|(pattern, _)| shape_binds(pattern, &segs).is_some())
            .map(|(_, max)| *max)
    }

    /// Whether `kernel` can carry these uploads: it has a spill facility, and it resolves a
    /// content id through this very store. Checked once, when the door starts.
    pub(crate) fn check(&self, kernel: &Kernel) -> std::io::Result<()> {
        let refuse = |why: String| Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, why));
        if let Err(e) = Issuer::spill(kernel, &Capability::root()) {
            return refuse(format!(
                "upload routes need the kernel's spill facility (`Kernel::with_spill`): {e}"
            ));
        }
        let probe = match self
            .store
            .put(Bytes::from_static(b"ikigai-web: upload store probe"))
        {
            Ok(probe) => probe,
            Err(e) => return refuse(format!("the upload content store refused a probe: {e}")),
        };
        if Issuer::content(kernel, &probe.id()).is_err() {
            return refuse(
                "the kernel does not resolve content ids through the uploads' store: install \
                 the same store with `Kernel::with_content_store`"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// An upload the door will spill: the route's bound, the caller's grant, and the facility.
pub(crate) struct Plan {
    max: u64,
    granted: u64,
    spill: Arc<dyn Spill>,
    matched: Option<Matched>,
}

/// The plan for `head`, when it is an upload to spill: a `POST` or `PUT` to an upload route,
/// with a body, from a caller holding a disk grant. `None` takes the request the ordinary way.
pub(crate) fn plan(shared: &Shared, head: &HttpRequest) -> Option<Plan> {
    let uploads = shared.uploads.as_ref()?;
    if !matches!(head.method.as_str(), "POST" | "PUT") {
        return None;
    }
    let max = uploads.max_body_bytes(&head.path)?;
    // No length and no chunking is no body: nothing to spill.
    if head.header("content-length").is_none() && head.header("transfer-encoding").is_none() {
        return None;
    }
    let matched = route_table(shared).match_path(&head.path);
    // A route that refuses the path (a strict `{var}`) answers `400` the ordinary way, without
    // a byte of the body written to disk first.
    if matched.as_ref().is_some_and(|m| m.iri.is_err()) {
        return None;
    }
    let cap = request_capability(shared, head, matched.as_ref());
    if !cap.satisfies(CAP_STREAM_SPILL) {
        return None;
    }
    let (spill, granted) = Issuer::spill(&*shared.kernel, &cap).ok()?;
    Some(Plan {
        max,
        granted,
        spill,
        matched,
    })
}

/// Spill `body`, then answer `head` with the Sink issued over its content id. Every refusal
/// is a finished answer (an error page for a browser, the edge policy applied) given before
/// the body was read to its end, so the connection closes after it.
pub(crate) async fn exchange<B>(
    shared: &Shared,
    head: HttpRequest,
    body: B,
    plan: Plan,
) -> http::Response<DoorBody>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let refuse = |resp: Resp| refused(shared, &head, plan.matched.as_ref(), resp);
    if let Some(admission) = refuse_admission(shared, &head) {
        return unread(render(admission));
    }
    let Some(uploads) = shared.uploads.as_ref() else {
        return refuse(Resp::text(500, "Internal Server Error", "no upload routes"));
    };
    if head.header("transfer-encoding").is_some() {
        return refuse(Resp::text(
            501,
            "Not Implemented",
            "an upload takes its body by Content-Length, not Transfer-Encoding",
        ));
    }
    let Some(declared) = head
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return refuse(*refusal(
            false,
            400,
            "Bad Request",
            "malformed Content-Length",
        ));
    };
    if declared > plan.max {
        let why = format!(
            "request body too large: this route takes at most {} bytes",
            plan.max
        );
        return refuse(Resp::text(413, "Payload Too Large", &why));
    }
    if declared > plan.granted {
        let why = format!(
            "request body too large: this request may spill at most {} bytes (a \
             `urn:cap:stream:spill:<bytes>` grant)",
            plan.granted
        );
        return refuse(Resp::text(413, "Payload Too Large", &why));
    }
    let cut = Arc::new(Mutex::new(None));
    let paced: ByteStream = Box::pin(Paced::new(
        body,
        uploads.min_rate,
        uploads.grace,
        Arc::clone(&cut),
    ));
    let spilled = plan.spill.spill(paced, declared).await;
    let replay = match spilled {
        Ok(replay) => replay,
        Err(error) => {
            let why = cut.lock().ok().and_then(|mut cut| cut.take());
            return refuse(match why {
                Some(Cut::Slow { rate }) => {
                    let why = format!("the request body arrived slower than {rate} bytes a second");
                    Resp::text(408, "Request Timeout", &why)
                }
                Some(Cut::Broken) => Resp::text(400, "Bad Request", "incomplete request body"),
                None if matches!(error, Error::OverBudget { .. }) => {
                    Resp::text(413, "Payload Too Large", "request body too large")
                }
                None => error_resp(&shared.config, &error),
            });
        }
    };
    let held = match uploads.store.put_replay(Held(replay)) {
        Ok(held) => held,
        Err(_) => {
            let mut busy = Resp::text(
                503,
                "Service Unavailable",
                "the door is holding as many uploads as it may; try again shortly",
            );
            busy.headers
                .push(("Retry-After".to_string(), "5".to_string()));
            return refuse(busy);
        }
    };
    let id: ContentId = held.id();
    let out = reply(answer_admitted(shared, head, Some(id)).await);
    // The answer is built: let the spill go. A body the answer still reads holds its own
    // handle on it.
    drop(held);
    out
}

/// A refusal of an upload, finished as every answer to a parsed request is.
fn refused(
    shared: &Shared,
    head: &HttpRequest,
    matched: Option<&Matched>,
    resp: Resp,
) -> http::Response<DoorBody> {
    let mut resp = finish(resp, head, &shared.config);
    apply_edge_policy(&mut resp, &shared.config, head, matched);
    unread(render(resp))
}

/// A spill's answer, as the store takes it (by value).
struct Held(Arc<dyn Replay>);

impl Replay for Held {
    fn open(&self) -> ByteStream {
        self.0.open()
    }
    fn open_at(&self, offset: u64) -> Option<ByteStream> {
        self.0.open_at(offset)
    }
    fn len_hint(&self) -> Option<u64> {
        self.0.len_hint()
    }
    fn validator(&self) -> Option<ContentId> {
        self.0.validator()
    }
}

/// Why [`Paced`] ended a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// It fell behind the minimum rate.
    Slow { rate: u64 },
    /// The client hung up part-way, or broke the framing.
    Broken,
}

/// A request body as a [`ByteStream`], held to a minimum rate: the deadline is `grace` plus
/// one second per `rate` bytes received, from the first poll. Why it ended a body is left in
/// `cut` for the door to answer with.
struct Paced<B> {
    body: Pin<Box<B>>,
    started: tokio::time::Instant,
    grace: Duration,
    rate: u64,
    received: u64,
    deadline: Pin<Box<tokio::time::Sleep>>,
    cut: Arc<Mutex<Option<Cut>>>,
}

impl<B> Paced<B> {
    fn new(body: B, rate: u64, grace: Duration, cut: Arc<Mutex<Option<Cut>>>) -> Self {
        let started = tokio::time::Instant::now();
        Paced {
            body: Box::pin(body),
            started,
            grace,
            rate: rate.max(1),
            received: 0,
            deadline: Box::pin(tokio::time::sleep_until(started + grace)),
            cut,
        }
    }

    /// The deadline once `received` bytes are in.
    fn due(&self) -> tokio::time::Instant {
        let earned_ms = u128::from(self.received) * 1000 / u128::from(self.rate);
        let earned = Duration::from_millis(u64::try_from(earned_ms).unwrap_or(u64::MAX));
        self.started + self.grace.saturating_add(earned)
    }

    fn end(&self, why: Cut) {
        if let Ok(mut cut) = self.cut.lock() {
            *cut = Some(why);
        }
    }
}

impl<B> Stream for Paced<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Item = ikigai_core::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // `Paced` holds its body and its timer pinned in boxes, so it is `Unpin` itself.
        let this = unsafe_free_mut(self);
        loop {
            match this.body.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers carry no content.
                    let Ok(mut data) = frame.into_data() else {
                        continue;
                    };
                    let chunk = data.copy_to_bytes(data.remaining());
                    if chunk.is_empty() {
                        continue;
                    }
                    this.received += chunk.len() as u64;
                    let due = this.due();
                    this.deadline.as_mut().reset(due);
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(_))) => {
                    this.end(Cut::Broken);
                    return Poll::Ready(Some(Err(Error::InvalidArgument {
                        name: "content".to_string(),
                        detail: "the request body ended before its Content-Length".to_string(),
                    })));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => break,
            }
        }
        match this.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => {
                let rate = this.rate;
                this.end(Cut::Slow { rate });
                Poll::Ready(Some(Err(Error::Timeout(format!(
                    "the request body fell below {rate} bytes a second"
                )))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `Paced` is `Unpin` (its body and timer are boxed), so its pin is a plain `&mut`.
fn unsafe_free_mut<B>(paced: Pin<&mut Paced<B>>) -> &mut Paced<B> {
    Pin::into_inner(paced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use http_body_util::StreamBody;

    type Frames = StreamBody<
        futures::channel::mpsc::Receiver<Result<http_body::Frame<Bytes>, std::io::Error>>,
    >;

    fn channel() -> (
        futures::channel::mpsc::Sender<Result<http_body::Frame<Bytes>, std::io::Error>>,
        Frames,
    ) {
        let (tx, rx) = futures::channel::mpsc::channel(4);
        (tx, StreamBody::new(rx))
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_keeps_ahead_of_the_rate_is_taken_and_one_that_falls_behind_is_cut() {
        // 1000 bytes a second after a one-second grace.
        let (mut tx, body) = channel();
        let cut = Arc::new(Mutex::new(None));
        let mut paced = Paced::new(body, 1000, Duration::from_secs(1), Arc::clone(&cut));
        // 2000 bytes in: the deadline is 1 s + 2 s from the start.
        use futures::SinkExt;
        tx.send(Ok(http_body::Frame::data(Bytes::from(vec![0u8; 2000]))))
            .await
            .unwrap();
        assert_eq!(paced.next().await.unwrap().unwrap().len(), 2000);
        tokio::time::advance(Duration::from_millis(2900)).await;
        tx.send(Ok(http_body::Frame::data(Bytes::from_static(b"x"))))
            .await
            .unwrap();
        assert_eq!(paced.next().await.unwrap().unwrap().len(), 1, "still ahead");
        // Nothing more: the deadline (1 s + 2.001 s) passes and the body is cut.
        let ended = paced.next().await.unwrap();
        assert!(matches!(ended, Err(Error::Timeout(_))), "{ended:?}");
        assert_eq!(*cut.lock().unwrap(), Some(Cut::Slow { rate: 1000 }));
        assert!(tokio::time::Instant::now() >= paced.started + Duration::from_millis(3001));
    }

    #[tokio::test]
    async fn a_body_that_breaks_is_named_broken() {
        let (mut tx, body) = channel();
        let cut = Arc::new(Mutex::new(None));
        let mut paced = Paced::new(body, 1000, Duration::from_secs(60), Arc::clone(&cut));
        use futures::SinkExt;
        tx.send(Err(std::io::Error::other("hung up")))
            .await
            .unwrap();
        assert!(matches!(
            paced.next().await,
            Some(Err(Error::InvalidArgument { .. }))
        ));
        assert_eq!(*cut.lock().unwrap(), Some(Cut::Broken));
    }
}
