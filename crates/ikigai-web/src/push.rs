//! **Server push**: an event stream that tells a page when something it shows was
//! invalidated, so it re-fetches instead of polling (ledger #618).
//!
//! One `GET` of [`PushConfig::path`] answers `text/event-stream` and stays open. Behind it
//! sits exactly one core cut listener ([`Kernel::listen`](ikigai_core::Kernel::listen)),
//! registered under **the capability the host's [`CapFn`](crate::CapFn) grants this very
//! request** — the same capability its reads resolve under, so the listener sits in the same
//! cache partition as the page's own reads and hears the cuts those reads rest on, and nothing
//! else. Every cut it hears becomes one `cut` event; the page re-fetches what the event names,
//! and those re-fetches are cheap because an unchanged fragment revalidates to a bodyless
//! `304` against its `ETag`.
//!
//! # Authority
//!
//! - The capability must hold [`CAP_LISTEN`] (`urn:cap:kernel:listen`), or the stream is
//!   answered **`403`**. The edge never adds it: a capability with it added is a DIFFERENT
//!   capability, keyed to a different cache partition, and would hear nothing the page read.
//!   A host that wants its pages pushed to grants `urn:cap:kernel:listen` in its `CapFn`, to
//!   anonymous callers too if anonymous pages should be pushed.
//! - A non-root capability hears a cut only when an entry **it** cached depends on the thread,
//!   and an event names only entries it cached (core's rule, see `ikigai_core::listen`). So an
//!   anonymous stream hears exactly what anonymous reads rest on: a thread only a signed-in
//!   session has read is never heard by it, and neither are that session's entries.
//! - A route that pins its own capability (`Route::cap`) resolves its reads in THAT
//!   capability's partition, which the stream (under `CapFn`) does not share, so reads through
//!   such a route are not heard.
//! - ⚠ Only CACHED reads are heard. The kernel learns that a result depends on a thread when it
//!   stores the result, so a fragment answered `no-store` (`Expiry::Always`) hangs from nothing
//!   and must be polled.
//!
//! # Subscribing
//!
//! The query string says what the page wants to hear, and every parameter repeats:
//!
//! | parameter | hears |
//! |---|---|
//! | `path=/l/default/item/5` | cuts that invalidate the resource this edge serves at that path (through the route table, else the mechanical mapping); the event lists it in `paths` |
//! | `thread=urn:x:y` | cuts of that thread, by exact name |
//! | `prefix=urn:x:` | cuts of every thread under the prefix |
//! | *(none)* | every cut this capability may hear |
//!
//! `path=` is the spelling a page wants: it names what the page SHOWS, and the event hands
//! the same paths back, so a fragment finds itself by the URL it was fetched from. It matches
//! by what a cut INVALIDATED, not by the thread's name, so a composite (a board, a list)
//! hanging from a store's thread is heard when the store is written. Any other parameter is
//! a `400`, and more than [`PushConfig::max_subscriptions`] is a `400`, never a silent
//! trim: a stream that dropped a subscription would look subscribed and stay quiet.
//!
//! # Events
//!
//! ```text
//! retry: 2000                      (the reconnect delay, once, on open)
//!
//! event: ready                     (once, on open: the listener is registered)
//! id: 0
//! data: {}
//!
//! event: cut                       (one per cut heard)
//! id: 17                           (the cut's sequence in the kernel's single cut order)
//! data: {"thread":"urn:…","sequence":17,"invalidated":["urn:…"],"more":0,"paths":["/…"]}
//!
//! event: resync                    (history was lost: refresh everything shown)
//! data: {"reason":"dropped","dropped":12}
//!
//! : keepalive                      (a comment, every heartbeat)
//! ```
//!
//! - `invalidated` names at most 64 cached targets, sorted, and `more` counts the rest. When
//!   `more > 0` the edge cannot tell whether a subscribed path was among the unnamed, so it
//!   lists EVERY subscribed path in `paths`. The page's rule is one line: refresh `paths`.
//! - `resync` is sent when the listener's bounded queue overflowed (`"reason":"dropped"`) and
//!   when a client reconnects carrying `Last-Event-ID` (`"reason":"reconnect"`), because cuts
//!   in the gap were heard by nobody. `ready` carries `id: 0` so that EVERY reconnect carries
//!   one; a fresh page load carries none and is not told to resync.
//!
//! # Expiry is not a cut, and the stream does not pretend it is
//!
//! An answer whose validity is a deadline (`Expiry::At`) goes stale when time passes, and no
//! thread is cut, so no event fires. **Revalidating on a deadline stays the page's job.** The
//! stream knows the page's subscriptions, not its answers: to learn a deadline it would have
//! to read every subscribed path itself — a read per path per stream, beside the page's own,
//! and possibly under different arguments than the page used. The answer already carries it:
//! a deadline nothing can cut is `Cache-Control: max-age=<seconds>`, which a page timer can
//! count down. ⚠ The gap, stated: an answer that has a deadline AND hangs from a thread is
//! projected as `no-cache` (see `cache_control_of`), which does not carry the deadline, so a
//! page cannot learn it today. Pushing it needs the kernel to report a deadline passing the
//! way it reports a cut — a scheduled cut — which is a core question, not an edge one.
//!
//! # Bounds
//!
//! - A stream is one connection and holds its slot under
//!   [`EdgeConfig::max_connections`](crate::EdgeConfig::max_connections) for as long as it is
//!   open.
//! - Every write (an event batch, a heartbeat) is bounded by
//!   [`EdgeConfig::write_timeout`](crate::EdgeConfig::write_timeout); a client that stops
//!   reading is dropped at it and its slot comes back.
//! - A heartbeat comment every [`PushConfig::heartbeat`] keeps a proxy from closing an idle
//!   connection and notices a client that has gone.
//! - After [`PushConfig::idle_timeout`] with no event sent, the stream closes. `EventSource`
//!   reconnects on its own and is told to `resync`, so a page left open in a background tab
//!   gives its slot back periodically at the cost of a round of `304`s.
//! - A slow reader cannot grow memory: the listener's queue holds at most
//!   [`PushConfig::queue`] events, a cut arriving at a full queue is counted rather than
//!   kept, and the count is sent as a `resync`. What the edge holds per stream is that queue
//!   and one batch being written.
//!
//! # The page side
//!
//! Plain `EventSource`, a few lines, with htmx doing the re-fetch (the htmx SSE extension is not
//! vendored anywhere in the ecosystem, and does not need to be). A fragment says where it came
//! from; the script triggers `push` on it; htmx re-issues its `hx-get`:
//!
//! ```html
//! <div hx-get="/l/default/item/5/card" hx-trigger="push" data-push="/l/default/item/5/card">…</div>
//! ```
//!
//! ```js
//! const shown = [...document.querySelectorAll('[data-push]')];
//! const query = shown.map(el => 'path=' + encodeURIComponent(el.dataset.push)).join('&');
//! const events = new EventSource('/_ikigai/push?' + query);
//! events.addEventListener('cut', e => {
//!   for (const path of JSON.parse(e.data).paths)
//!     shown.filter(el => el.dataset.push === path).forEach(el => htmx.trigger(el, 'push'));
//! });
//! events.addEventListener('resync', () => shown.forEach(el => htmx.trigger(el, 'push')));
//! ```
//!
//! Served as a file rather than inline, so the default `script-src 'self'` holds.
//!
//! # The shape, pinned
//!
//! ```
//! use ikigai_core::{
//!     Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType,
//!     Representation, Verb,
//! };
//! use ikigai_web::{EdgeConfig, HttpRequest, PushConfig};
//! use std::sync::Arc;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # #[tokio::main]
//! # async fn main() {
//! // A cell: a cacheable read, and a write (which the kernel follows with a cut).
//! let cell = FnEndpoint::new("cell", |_inv: &Invocation<'_>| {
//!     Ok(Representation::new(ReprType::new("text/plain"), b"5".to_vec()).cacheable())
//! })
//! .with_description(Description::new("cell").verb(Verb::Source).verb(Verb::Sink));
//! let kernel = Arc::new(Kernel::new(Arc::new(
//!     EndpointSpace::new().bind(Exact::new("urn:sheet:cell:a1"), cell),
//! )));
//! // Every caller may read and may listen.
//! let door = Arc::new(|_req: &HttpRequest| Capability::scoped(["urn:cap:kernel:listen"]));
//! let config = EdgeConfig { push: Some(PushConfig::default()), ..EdgeConfig::default() };
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
//! let addr = listener.local_addr().unwrap();
//! tokio::spawn(ikigai_web::serve_with_listener(kernel, door, listener, config));
//!
//! async fn send(addr: std::net::SocketAddr, raw: &str) -> String {
//!     let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
//!     c.write_all(raw.as_bytes()).await.unwrap();
//!     let mut out = Vec::new();
//!     c.read_to_end(&mut out).await.unwrap();
//!     String::from_utf8_lossy(&out).into_owned()
//! }
//!
//! // The page opens its stream for what it shows, and waits for `ready`.
//! let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
//! stream
//!     .write_all(b"GET /_ikigai/push?path=/sheet/cell/a1 HTTP/1.1\r\nHost: x\r\n\r\n")
//!     .await
//!     .unwrap();
//! let mut seen = String::new();
//! let mut buf = [0u8; 4096];
//! while !seen.contains("event: ready\n") {
//!     let n = stream.read(&mut buf).await.unwrap();
//!     seen.push_str(&String::from_utf8_lossy(&buf[..n]));
//! }
//! assert!(seen.starts_with("HTTP/1.1 200 OK\r\n"), "{seen}");
//! assert!(seen.contains("Content-Type: text/event-stream\r\n"), "{seen}");
//!
//! // The page reads the cell (and the kernel caches it), then someone writes it.
//! send(addr, "GET /sheet/cell/a1 HTTP/1.1\r\nHost: x\r\n\r\n").await;
//! send(addr, "PUT /sheet/cell/a1 HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n6").await;
//!
//! // The stream says so, naming the thread, what it invalidated, and the page's own path.
//! while !seen.contains("event: cut\n") || !seen.ends_with("\n\n") {
//!     let n = stream.read(&mut buf).await.unwrap();
//!     seen.push_str(&String::from_utf8_lossy(&buf[..n]));
//! }
//! let cut = &seen[seen.find("event: cut\n").unwrap()..];
//! let data = cut.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
//! let event: serde_json::Value = serde_json::from_str(data).unwrap();
//! assert_eq!(event["thread"], "urn:sheet:cell:a1");
//! assert_eq!(event["invalidated"], serde_json::json!(["urn:sheet:cell:a1"]));
//! assert_eq!(event["more"], 0);
//! assert_eq!(event["paths"], serde_json::json!(["/sheet/cell/a1"]));
//! assert_eq!(cut.lines().nth(1), Some(format!("id: {}", event["sequence"]).as_str()));
//! # }
//! ```

use crate::{
    apply_edge_policy, error_resp, head_of, iri_from_path, write_within, EdgeConfig, HttpRequest,
    Resp, RouteTable, Shared,
};
use ikigai_core::{CutBatch, CutEvent, Iri, ListenSpec, CAP_LISTEN, LISTEN_CAPACITY};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where the event stream is served when [`PushConfig::path`] is not set otherwise. Under a
/// leading `_` so the mechanical `/noun/partition/key` mapping never wants it for a resource.
pub const DEFAULT_PUSH_PATH: &str = "/_ikigai/push";

/// How often a heartbeat comment is written to an open stream. Well inside the 60 s idle
/// timeout of the usual proxies (nginx `proxy_read_timeout`, Apache `ProxyTimeout` defaults).
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(15);

/// How long a stream may go without sending an event before it is closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The reconnect delay the stream advertises (`retry:`), which `EventSource` honors.
pub const DEFAULT_RETRY: Duration = Duration::from_secs(2);

/// How many subscriptions one stream may carry. A page names the fragments it shows; sixty-four
/// is several full pages of them.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 64;

/// Server push at the edge: where the stream is served and its bounds. Set
/// [`EdgeConfig::push`](crate::EdgeConfig::push) to serve one. See the [module docs](self).
#[derive(Clone, Debug)]
pub struct PushConfig {
    /// The path the stream is served at. Default [`DEFAULT_PUSH_PATH`]. It is matched before
    /// the route table, so it shadows a route of the same path.
    pub path: String,
    /// Interval between heartbeat comments. Default [`DEFAULT_HEARTBEAT`].
    pub heartbeat: Duration,
    /// A stream that has sent no event for this long is closed. Default
    /// [`DEFAULT_IDLE_TIMEOUT`].
    pub idle_timeout: Duration,
    /// The reconnect delay sent as `retry:`. Default [`DEFAULT_RETRY`].
    pub retry: Duration,
    /// The listener's queue bound, in events; a cut arriving at a full queue is counted and
    /// sent as a `resync`. Default core's `LISTEN_CAPACITY`.
    pub queue: usize,
    /// The most subscriptions one stream may carry; more is a `400`. Default
    /// [`DEFAULT_MAX_SUBSCRIPTIONS`].
    pub max_subscriptions: usize,
}

impl Default for PushConfig {
    fn default() -> Self {
        PushConfig {
            path: DEFAULT_PUSH_PATH.to_string(),
            heartbeat: DEFAULT_HEARTBEAT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            retry: DEFAULT_RETRY,
            queue: LISTEN_CAPACITY,
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
        }
    }
}

/// What one stream asked to hear.
struct Subscriptions {
    /// `thread=` and `prefix=`, kept apart from the spec handed to the kernel (which widens to
    /// every thread whenever a path is subscribed) so an event can be matched against them.
    named: ListenSpec,
    named_any: bool,
    /// `path=`: the path as the page wrote it, and the IRI this edge serves there.
    paths: Vec<(String, String)>,
}

impl Subscriptions {
    /// Read the query string. A refusal is the `400` body.
    fn parse(
        req: &HttpRequest,
        config: &EdgeConfig,
        table: &RouteTable,
        push: &PushConfig,
    ) -> Result<Self, String> {
        if req.query.len() > push.max_subscriptions {
            return Err(format!(
                "{} subscriptions; a stream carries at most {}",
                req.query.len(),
                push.max_subscriptions
            ));
        }
        let mut subs = Subscriptions {
            named: ListenSpec::new(),
            named_any: false,
            paths: Vec::new(),
        };
        for (key, value) in &req.query {
            match key.as_str() {
                "thread" if !value.is_empty() => {
                    subs.named = subs.named.exact(value.clone());
                    subs.named_any = true;
                }
                "prefix" => {
                    subs.named = subs.named.prefix(value.clone());
                    subs.named_any = true;
                }
                "path" => {
                    let iri = match table.match_path(value) {
                        Some(matched) => matched.iri,
                        None if config.routes_only => {
                            return Err(format!("no route serves `{value}`"))
                        }
                        None => iri_from_path(value),
                    };
                    if Iri::parse(&iri).is_err() {
                        return Err(format!("`{value}` is not a resource path"));
                    }
                    subs.paths.push((value.clone(), iri));
                }
                "thread" => return Err("`thread=` needs a thread name".to_string()),
                other => {
                    return Err(format!(
                        "unknown subscription parameter `{other}` (path=, thread=, prefix=)"
                    ))
                }
            }
        }
        Ok(subs)
    }

    /// The spec handed to the kernel. A path subscription matches by what a cut invalidated,
    /// which no thread name predicts, so it widens the listener to every thread (what is
    /// actually HEARD stays bounded by the capability); no subscription at all means the same.
    fn listen_spec(&self, queue: usize) -> ListenSpec {
        let spec = if self.named_any && self.paths.is_empty() {
            self.named.clone()
        } else {
            ListenSpec::new().prefix("")
        };
        spec.capacity(queue)
    }

    /// Whether `event` is one this stream asked for, and if so the subscribed paths it
    /// touches. `None` → not sent.
    fn matches(&self, event: &CutEvent) -> Option<Vec<&str>> {
        if !self.named_any && self.paths.is_empty() {
            return Some(Vec::new());
        }
        let thread = event.thread.as_str();
        let paths: Vec<&str> = self
            .paths
            .iter()
            .filter(|(_, iri)| {
                // Unnamed invalidations could be any of them: list every path rather than
                // guess, so the page refreshes too much and never too little.
                event.invalidated_more > 0
                    || iri == thread
                    || event.invalidated.iter().any(|t| t == iri)
            })
            .map(|(path, _)| path.as_str())
            .collect();
        let named = self.named_any && self.named.matches(thread);
        (named || !paths.is_empty()).then_some(paths)
    }
}

/// One `resync` event.
fn resync(reason: &str, dropped: Option<u64>) -> String {
    let mut data = serde_json::json!({ "reason": reason });
    if let Some(dropped) = dropped {
        data["dropped"] = dropped.into();
    }
    format!("event: resync\ndata: {data}\n\n")
}

/// The wire text for one drained batch: a `cut` per event this stream asked for, in cut
/// order, then a `resync` when the queue overflowed. Empty when nothing is to be sent.
fn render(batch: &CutBatch, subs: &Subscriptions) -> String {
    let mut out = String::new();
    for event in &batch.events {
        let Some(paths) = subs.matches(event) else {
            continue;
        };
        let data = serde_json::json!({
            "thread": event.thread.as_str(),
            "sequence": event.sequence,
            "invalidated": event.invalidated,
            "more": event.invalidated_more,
            "paths": paths,
        });
        // Compact JSON escapes every newline, so `data` is one line, as SSE needs.
        out.push_str(&format!(
            "event: cut\nid: {}\ndata: {data}\n\n",
            event.sequence
        ));
    }
    if batch.dropped > 0 {
        out.push_str(&resync("dropped", Some(batch.dropped)));
    }
    out
}

/// Write `bytes` within the write deadline, or fail.
async fn send(
    sock: &mut (impl AsyncWriteExt + Unpin),
    bytes: &[u8],
    limit: Duration,
) -> std::io::Result<()> {
    let write = async {
        sock.write_all(bytes).await?;
        sock.flush().await
    };
    match tokio::time::timeout(limit, write).await {
        Ok(done) => done,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "event write took too long",
        )),
    }
}

/// Serve one event stream on `sock` until the client goes, a write misses its deadline, or
/// the stream sits idle past [`PushConfig::idle_timeout`].
pub(crate) async fn stream(
    mut sock: TcpStream,
    req: HttpRequest,
    shared: &Shared,
    table: &RouteTable,
    push: &PushConfig,
) -> std::io::Result<()> {
    let config = &shared.config;
    let wt = config.write_timeout;
    let refuse = |mut resp: Resp| {
        apply_edge_policy(&mut resp, config, &req, None);
        resp
    };
    match req.method.as_str() {
        "GET" => {}
        "OPTIONS" => {
            let resp = Resp {
                allow: Some("GET, OPTIONS".to_string()),
                ..Resp::status(204, "No Content")
            };
            return write_within(&mut sock, refuse(resp), wt).await;
        }
        _ => {
            let resp = Resp {
                allow: Some("GET, OPTIONS".to_string()),
                ..Resp::text(405, "Method Not Allowed", "method not allowed")
            };
            return write_within(&mut sock, refuse(resp), wt).await;
        }
    }
    let subs = match Subscriptions::parse(&req, config, table, push) {
        Ok(subs) => subs,
        Err(why) => {
            let resp = Resp::text(400, "Bad Request", &why);
            return write_within(&mut sock, refuse(resp), wt).await;
        }
    };
    // The capability this request's reads resolve under — never widened here (see the module
    // docs: adding `CAP_LISTEN` would move the listener into another cache partition).
    let cap = (shared.cap_fn)(&req);
    let listener = match shared.kernel.listen(subs.listen_spec(push.queue), &cap) {
        Ok(listener) => listener,
        Err(e) => {
            let mut resp = error_resp(&e);
            if matches!(e, ikigai_core::Error::Denied(_)) {
                resp.body = format!("an event stream needs `{CAP_LISTEN}`").into_bytes();
            }
            return write_within(&mut sock, refuse(resp), wt).await;
        }
    };

    let mut head = Resp {
        content_type: "text/event-stream".to_string(),
        cache_control: Some("no-store".to_string()),
        // What is heard follows the capability, which `CapFn` reads from these.
        vary: vec!["Authorization", "Cookie"],
        ..Resp::status(200, "OK")
    };
    // nginx buffers a proxied response unless told otherwise, which would hold every event.
    head.headers
        .push(("X-Accel-Buffering".to_string(), "no".to_string()));
    apply_edge_policy(&mut head, config, &req, None);
    let mut opening = head_of(&head, None);
    opening.push_str(&format!(
        "retry: {}\n\nevent: ready\nid: 0\ndata: {{}}\n\n",
        push.retry.as_millis()
    ));
    // A reconnect: whatever was cut between the old stream and this one was heard by nobody.
    if req.header("last-event-id").is_some() {
        opening.push_str(&resync("reconnect", None));
    }
    let (mut rd, mut wr) = sock.split();
    send(&mut wr, opening.as_bytes(), wt).await?;

    let mut heartbeat =
        tokio::time::interval_at(tokio::time::Instant::now() + push.heartbeat, push.heartbeat);
    let idle = tokio::time::sleep(push.idle_timeout);
    tokio::pin!(idle);
    let mut scratch = [0u8; 256];
    loop {
        tokio::select! {
            batch = listener.wait() => {
                let text = render(&batch, &subs);
                if !text.is_empty() {
                    send(&mut wr, text.as_bytes(), wt).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + push.idle_timeout);
                }
            }
            _ = heartbeat.tick() => send(&mut wr, b": keepalive\n\n", wt).await?,
            _ = &mut idle => break,
            // A client sends nothing on a stream; a read returning is it hanging up (or
            // sending bytes that mean nothing here, which are discarded).
            read = rd.read(&mut scratch) => {
                if matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    }
    let _ = wr.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{serve_with_listener, CapFn, EdgeConfig, HttpRequest, PushConfig};
    use ikigai_core::{
        ArgRef, Capability, Description, EndpointSpace, FnEndpoint, Invocation, Iri, Kernel,
        ReprType, Representation, Request, UriTemplate, Verb,
    };
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const LISTEN: &str = "urn:cap:kernel:listen";
    const SECRET: &str = "urn:cap:test:secret";

    fn text(body: &[u8]) -> Representation {
        Representation::new(ReprType::new("text/plain"), body.to_vec())
    }

    /// Cells that store what is written to them; a board that hangs from every cell's
    /// thread (a composite the page shows); a secret only a signed-in session may read.
    fn kernel() -> Arc<Kernel> {
        let cells: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let store = Arc::clone(&cells);
        let cell = FnEndpoint::new("cell", move |inv: &Invocation<'_>| {
            let key = inv.request.target.as_str().to_string();
            let mut cells = store.lock().unwrap();
            if inv.request.verb == Verb::Sink {
                let body = inv.inline_arg("content").unwrap_or(b"").to_vec();
                cells.insert(key, body);
                return Ok(text(b""));
            }
            Ok(text(cells.get(&key).map(Vec::as_slice).unwrap_or(b"-")).cacheable())
        })
        .with_description(Description::new("cell").verb(Verb::Source).verb(Verb::Sink));
        let board = FnEndpoint::new("board", |_inv: &Invocation<'_>| {
            Ok(text(b"board")
                .cacheable()
                .depends_on("urn:test:cell:a")
                .depends_on("urn:test:cell:b"))
        })
        .with_description(Description::new("board").verb(Verb::Source));
        let secret = FnEndpoint::new("secret", |inv: &Invocation<'_>| {
            if !inv.capability.allows(SECRET) {
                return Err(ikigai_core::Error::Denied(format!("needs {SECRET}")));
            }
            Ok(text(b"secret").cacheable())
        })
        .with_description(
            Description::new("secret")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
        let space = EndpointSpace::new()
            .bind(UriTemplate::parse("urn:test:cell:{name}").unwrap(), cell)
            .bind(ikigai_core::Exact::new("urn:test:board"), board)
            .bind(ikigai_core::Exact::new("urn:test:secret"), secret);
        Arc::new(Kernel::new(Arc::new(space)))
    }

    /// The door: a `session=admin` cookie may read the secret, `session=root` is root,
    /// `session=mute` may read but not listen, and anyone else is anonymous — who may listen.
    fn door() -> CapFn {
        Arc::new(|req: &HttpRequest| match req.header("cookie") {
            Some("session=root") => Capability::root(),
            Some("session=admin") => Capability::scoped([LISTEN, SECRET]),
            Some("session=mute") => Capability::scoped(Vec::<String>::new()),
            _ => Capability::scoped([LISTEN]),
        })
    }

    fn anonymous() -> Capability {
        Capability::scoped([LISTEN])
    }

    fn short(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    async fn serve(config: EdgeConfig) -> (SocketAddr, Arc<Kernel>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let kernel = kernel();
        let served = Arc::clone(&kernel);
        tokio::spawn(async move {
            let _ = serve_with_listener(served, door(), listener, config).await;
        });
        (addr, kernel)
    }

    fn pushing(push: PushConfig) -> EdgeConfig {
        EdgeConfig {
            push: Some(push),
            ..EdgeConfig::default()
        }
    }

    async fn roundtrip(addr: SocketAddr, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// A GET or PUT through the edge, with an optional cookie.
    async fn http(addr: SocketAddr, method: &str, path: &str, cookie: &str, body: &str) -> String {
        let cookie = if cookie.is_empty() {
            String::new()
        } else {
            format!("Cookie: {cookie}\r\n")
        };
        roundtrip(
            addr,
            &format!(
                "{method} {path} HTTP/1.1\r\nHost: x\r\n{cookie}Content-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await
    }

    /// An open event stream and everything read from it so far.
    struct Stream {
        sock: TcpStream,
        seen: String,
    }

    impl Stream {
        /// Open a stream; returns once `ready` (or the refusal) has arrived.
        async fn open(addr: SocketAddr, query: &str, extra: &str) -> Stream {
            let mut sock = TcpStream::connect(addr).await.unwrap();
            let raw = format!("GET /_ikigai/push{query} HTTP/1.1\r\nHost: x\r\n{extra}\r\n");
            sock.write_all(raw.as_bytes()).await.unwrap();
            let mut stream = Stream {
                sock,
                seen: String::new(),
            };
            stream.read_while(|seen| !seen.contains("\r\n\r\n")).await;
            if stream.seen.starts_with("HTTP/1.1 200 ") {
                stream.until("event: ready\n").await;
            }
            stream
        }

        /// Read until `needle` has been seen and the event it starts has ended.
        async fn until(&mut self, needle: &str) -> &str {
            let ended = |seen: &str| {
                seen.find(needle)
                    .is_some_and(|at| seen[at..].contains("\n\n"))
            };
            self.read_while(|seen| !ended(seen)).await;
            let at = self.seen.find(needle).unwrap();
            &self.seen[at..]
        }

        /// Read while `more` holds of what has been seen, failing the test (rather than
        /// hanging it) when the server goes quiet or hangs up first.
        async fn read_while(&mut self, more: impl Fn(&str) -> bool) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let mut buf = [0u8; 8192];
            while more(&self.seen) {
                let n = tokio::time::timeout_at(deadline, self.sock.read(&mut buf))
                    .await
                    .unwrap_or_else(|_| panic!("the stream went quiet: {:?}", self.seen))
                    .unwrap();
                assert!(n > 0, "the stream closed early: {:?}", self.seen);
                self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        }

        /// The data of every `cut` event seen so far.
        fn cuts(&self) -> Vec<serde_json::Value> {
            self.seen
                .split("\n\n")
                .filter(|e| e.contains("event: cut\n"))
                .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
                .map(|d| serde_json::from_str(d).unwrap())
                .collect()
        }

        /// Read until the server hangs up.
        async fn closed(&mut self) {
            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), self.sock.read_to_end(&mut rest))
                .await
                .expect("the server must close the stream")
                .unwrap();
            self.seen.push_str(&String::from_utf8_lossy(&rest));
        }
    }

    /// Read and write a cell directly on the kernel, under `cap`, with no await in between —
    /// so on this single-threaded test runtime the stream's task cannot drain in between.
    fn read_now(kernel: &Kernel, iri: &str, cap: &Capability) {
        let req = Request::new(Verb::Source, Iri::parse(iri).unwrap());
        futures::executor::block_on(kernel.issue(req, cap)).unwrap();
    }

    fn write_now(kernel: &Kernel, iri: &str, cap: &Capability) {
        let req = Request::new(Verb::Sink, Iri::parse(iri).unwrap())
            .with_arg("content", ArgRef::Inline(b"x".to_vec()));
        futures::executor::block_on(kernel.issue(req, cap)).unwrap();
    }

    #[tokio::test]
    async fn a_write_through_the_edge_reaches_an_open_stream_as_a_cut_naming_the_thread() {
        let (addr, _kernel) = serve(pushing(PushConfig::default())).await;
        let mut stream = Stream::open(addr, "?path=/test/cell/a", "").await;
        assert!(stream.seen.contains("Content-Type: text/event-stream\r\n"));
        assert!(stream.seen.contains("Cache-Control: no-store\r\n"));
        assert!(!stream.seen.contains("Content-Length"), "{}", stream.seen);
        assert!(stream.seen.contains("retry: 2000\n"), "{}", stream.seen);

        let read = http(addr, "GET", "/test/cell/a", "", "").await;
        assert!(read.ends_with("\r\n-"), "{read}");
        let write = http(addr, "PUT", "/test/cell/a", "", "7").await;
        assert!(write.starts_with("HTTP/1.1 204 "), "{write}");

        stream.until("event: cut\n").await;
        let cuts = stream.cuts();
        assert_eq!(cuts.len(), 1, "{}", stream.seen);
        assert_eq!(cuts[0]["thread"], "urn:test:cell:a");
        assert_eq!(
            cuts[0]["invalidated"],
            serde_json::json!(["urn:test:cell:a"])
        );
        assert_eq!(cuts[0]["paths"], serde_json::json!(["/test/cell/a"]));
    }

    #[tokio::test]
    async fn a_path_hears_a_cut_of_any_thread_its_resource_hangs_from() {
        let (addr, _kernel) = serve(pushing(PushConfig::default())).await;
        // The page shows the board, which hangs from the cells' threads, not its own name.
        let mut stream = Stream::open(addr, "?path=/test/board&path=/test/cell/z", "").await;
        http(addr, "GET", "/test/board", "", "").await;
        http(addr, "PUT", "/test/cell/b", "", "o").await;
        stream.until("event: cut\n").await;
        let cuts = stream.cuts();
        assert_eq!(cuts[0]["thread"], "urn:test:cell:b");
        assert_eq!(
            cuts[0]["invalidated"],
            serde_json::json!(["urn:test:board"])
        );
        // Only the path the cut touched, not every subscribed one.
        assert_eq!(cuts[0]["paths"], serde_json::json!(["/test/board"]));
    }

    #[tokio::test]
    async fn a_stream_without_the_listen_capability_is_403() {
        let (addr, _kernel) = serve(pushing(PushConfig::default())).await;
        let stream = Stream::open(addr, "", "Cookie: session=mute\r\n").await;
        assert!(stream.seen.starts_with("HTTP/1.1 403 "), "{}", stream.seen);
        assert!(
            !stream.seen.contains("text/event-stream"),
            "{}",
            stream.seen
        );
    }

    #[tokio::test]
    async fn an_anonymous_stream_hears_only_what_anonymous_reads_rest_on() {
        let (addr, kernel) = serve(pushing(PushConfig::default())).await;
        let mut anon = Stream::open(addr, "", "").await;
        let mut admin = Stream::open(addr, "", "Cookie: session=admin\r\n").await;
        // Only the signed-in session reads the secret; then it is written.
        let secret = http(addr, "GET", "/test/secret", "session=admin", "").await;
        assert!(secret.ends_with("secret"), "{secret}");
        kernel.cut("urn:test:secret");
        // The anonymous page reads a cell, which is then written.
        http(addr, "GET", "/test/cell/a", "", "").await;
        write_now(&kernel, "urn:test:cell:a", &Capability::root());

        admin.until("urn:test:secret").await;
        anon.until("event: cut\n").await;
        let cuts = anon.cuts();
        // Cuts arrive in sequence order, so had the secret's cut been heard it would be first.
        assert_eq!(cuts.len(), 1, "{}", anon.seen);
        assert_eq!(cuts[0]["thread"], "urn:test:cell:a");
        assert!(!anon.seen.contains("secret"), "{}", anon.seen);
        // And the admin stream hears the cell only if the admin read it — it did not.
        assert_eq!(admin.cuts().len(), 1, "{}", admin.seen);
    }

    #[tokio::test]
    async fn an_overflowing_queue_is_bounded_and_sent_as_a_resync() {
        let (addr, kernel) = serve(pushing(PushConfig {
            queue: 2,
            ..PushConfig::default()
        }))
        .await;
        let mut stream = Stream::open(addr, "?prefix=urn:test:cell:", "").await;
        // Ten cuts land while the stream's task cannot run: two are queued, eight counted.
        for _ in 0..10 {
            read_now(&kernel, "urn:test:cell:a", &anonymous());
            write_now(&kernel, "urn:test:cell:a", &anonymous());
        }
        let resync = stream.until("event: resync\n").await.to_string();
        assert!(resync.contains(r#""dropped":8"#), "{resync}");
        assert!(resync.contains(r#""reason":"dropped""#), "{resync}");
        assert_eq!(stream.cuts().len(), 2, "{}", stream.seen);
    }

    #[tokio::test]
    async fn a_reconnect_is_told_to_resync() {
        let (addr, _kernel) = serve(pushing(PushConfig::default())).await;
        let fresh = Stream::open(addr, "", "").await;
        assert!(!fresh.seen.contains("resync"), "{}", fresh.seen);
        assert!(fresh.seen.contains("id: 0\n"), "{}", fresh.seen);
        let mut again = Stream::open(addr, "", "Last-Event-ID: 0\r\n").await;
        let resync = again.until("event: resync\n").await;
        assert!(resync.contains(r#""reason":"reconnect""#), "{resync}");
    }

    #[tokio::test]
    async fn an_idle_stream_sends_heartbeats_and_closes_at_the_idle_limit() {
        let (addr, _kernel) = serve(pushing(PushConfig {
            heartbeat: short(50),
            idle_timeout: short(400),
            ..PushConfig::default()
        }))
        .await;
        let mut stream = Stream::open(addr, "", "").await;
        stream.until(": keepalive\n").await;
        stream.closed().await;
        assert!(
            stream.seen.matches(": keepalive\n").count() >= 2,
            "{}",
            stream.seen
        );
    }

    #[tokio::test]
    async fn a_stream_counts_against_the_connection_cap() {
        let (addr, _kernel) = serve(EdgeConfig {
            max_connections: 1,
            ..pushing(PushConfig::default())
        })
        .await;
        let stream = Stream::open(addr, "", "").await;
        let busy = http(addr, "GET", "/test/cell/a", "", "").await;
        assert!(busy.starts_with("HTTP/1.1 503 "), "{busy}");
        drop(stream);
        for _ in 0..250 {
            let answer = http(addr, "GET", "/test/cell/a", "", "").await;
            if answer.starts_with("HTTP/1.1 200 ") {
                return;
            }
            tokio::time::sleep(short(20)).await;
        }
        panic!("the stream's slot never came back");
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_is_dropped_at_the_write_deadline() {
        let (addr, kernel) = serve(EdgeConfig {
            max_connections: 1,
            write_timeout: short(300),
            ..pushing(PushConfig {
                queue: 8,
                ..PushConfig::default()
            })
        })
        .await;
        // Root hears every cut; a long thread name makes each event large enough that the
        // socket buffers fill while the client reads nothing.
        let stalled = Stream::open(addr, "", "Cookie: session=root\r\n").await;
        let long = format!("urn:test:cell:{}", "x".repeat(64 * 1024));
        let root = Capability::root();
        for _ in 0..2000 {
            write_now(&kernel, &long, &root);
            tokio::task::yield_now().await;
            if let Ok(answer) =
                tokio::time::timeout(short(5), http(addr, "GET", "/test/cell/a", "", "")).await
            {
                if answer.starts_with("HTTP/1.1 200 ") {
                    drop(stalled);
                    return;
                }
            }
        }
        panic!("a stalled stream kept its slot");
    }

    #[tokio::test]
    async fn bad_subscriptions_are_refused_not_trimmed() {
        let (addr, _kernel) = serve(pushing(PushConfig {
            max_subscriptions: 2,
            ..PushConfig::default()
        }))
        .await;
        let unknown = Stream::open(addr, "?topic=x", "").await;
        assert!(
            unknown.seen.starts_with("HTTP/1.1 400 "),
            "{}",
            unknown.seen
        );
        let many = Stream::open(addr, "?path=/a/b&path=/a/c&path=/a/d", "").await;
        assert!(many.seen.starts_with("HTTP/1.1 400 "), "{}", many.seen);
        let post = roundtrip(
            addr,
            "POST /_ikigai/push HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
        assert!(post.contains("Allow: GET, OPTIONS\r\n"), "{post}");
    }

    #[tokio::test]
    async fn without_push_configured_the_path_is_an_ordinary_route() {
        let (addr, _kernel) = serve(EdgeConfig::default()).await;
        let answer = roundtrip(addr, "GET /_ikigai/push HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(answer.starts_with("HTTP/1.1 404 "), "{answer}");
    }
}
