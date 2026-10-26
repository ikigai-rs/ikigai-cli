//! The door's HTTP/1.1 listener: one accepted connection served by hyper's HTTP/1.1 server
//! (ledger #2236), around the version-independent [`door::exchange`].
//!
//! hyper owns the framing: the request line and headers, `Content-Length` and chunked bodies,
//! `Expect: 100-continue`, keep-alive, and the answers to a request it cannot parse (`400`, `431`
//! when its read buffer passes [`MAX_HEAD`], `414`). This module owns what HTTP/1.1 means by a
//! connection here:
//!
//! - **Keep-alive is the client's to ask for.** A request whose `Connection` header names
//!   `keep-alive` leaves its connection open for the next request; any other is answered
//!   `Connection: close`, one request per connection, which is what every client of the door saw
//!   before the move. So no existing client waits on a connection it expected to close, and a
//!   browser (which names it) reuses its connections. An answer given before the request body
//!   was read to its end ([`door::Unread`]) always closes.
//! - **The header read deadline** is hyper's ([`EdgeConfig::header_timeout`]), which also bounds
//!   how long a kept connection idles. hyper closes a timed-out connection without a word; the
//!   door then answers `408` itself when a request had been started (or when the connection
//!   never carried one, as the hand-written door always did), and closes in silence when a kept
//!   connection merely went idle.
//! - **The write deadline** ([`EdgeConfig::write_timeout`]) bounds each stall: a write that
//!   makes no progress for that long fails the connection, so a client that stops reading gives
//!   its slot back. hyper has no write deadline of its own.

use crate::door::{self, DoorBody, Unread, MAX_HEAD};
use crate::{refused, EdgeConfig, Resp, Shared};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How many bytes of a request still arriving are kept to decide whether it is a `HEAD`.
const KEPT: usize = 16;

/// Serve one connection until the client closes it, the door closes it, or a deadline passes.
pub(crate) async fn serve_connection<S>(
    mut sock: S,
    peer: IpAddr,
    shared: Arc<Shared>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let config: &EdgeConfig = &shared.config;
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_timeout)
        .max_buf_size(MAX_HEAD)
        .keep_alive(true)
        // The door's own answers name their headers in their usual case (`Content-Type`); hyper
        // would lowercase them. `ETag` is the one name this writes differently (`Etag`): a header
        // name is case-insensitive (RFC 9110 §5.1), and hyper offers no way to keep it.
        .title_case_headers(true)
        // No `Date`, as before the move.
        .auto_date_header(false);
    let tracker = Tracker::default();
    let served = {
        let door = Arc::clone(&shared);
        let service = hyper::service::service_fn(move |req: http::Request<Incoming>| {
            let door = Arc::clone(&door);
            async move {
                let keep = asks_keep_alive(req.headers());
                let mut resp = door::exchange(&door, req, Some(peer)).await;
                let unread = resp.extensions_mut().remove::<Unread>().is_some();
                if unread || !keep {
                    resp.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                Ok::<http::Response<DoorBody>, Infallible>(resp)
            }
        });
        let io = TokioIo::new(Guarded {
            io: &mut sock,
            tracker: &tracker,
            write_timeout: config.write_timeout,
            stall: None,
        });
        builder.serve_connection(io, service).await
    };
    match served {
        Err(e) if e.is_timeout() => match tracker.owed() {
            // A request was under way, or none ever came: say why the door is hanging up.
            Some(started) => {
                let resp = Resp::text(408, "Request Timeout", "request headers took too long");
                refused(&mut sock, resp, &started, config.write_timeout)
                    .await
                    .map(|_| ())
            }
            // A kept connection went idle between requests: close it without a word.
            None => Ok(()),
        },
        // Every other end (the client went, a framing error hyper answered, a write that
        // stalled) leaves no one to tell.
        _ => Ok(()),
    }
}

/// Whether the request's `Connection` header names `keep-alive`, in any case.
fn asks_keep_alive(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("keep-alive"))
}

/// What the connection has carried, for the `408` decision after hyper gives up on a head.
#[derive(Default)]
struct Tracker {
    state: Mutex<Seen>,
}

#[derive(Default)]
struct Seen {
    /// Some answer has been written on this connection.
    answered: bool,
    /// Bytes read since the last write: how many, and the first [`KEPT`] of them.
    since_answer: usize,
    first: Vec<u8>,
}

impl Tracker {
    fn read(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Ok(mut seen) = self.state.lock() {
            seen.since_answer += bytes.len();
            let room = KEPT.saturating_sub(seen.first.len());
            seen.first
                .extend_from_slice(&bytes[..room.min(bytes.len())]);
        }
    }

    fn wrote(&self) {
        if let Ok(mut seen) = self.state.lock() {
            seen.answered = true;
            seen.since_answer = 0;
            seen.first.clear();
        }
    }

    /// When the head deadline passed: `Some(what arrived of the request)` when the client is
    /// owed a `408` (a request was started, or none was ever answered on this connection),
    /// `None` when a kept connection only went idle.
    fn owed(&self) -> Option<Vec<u8>> {
        let seen = self.state.lock().ok()?;
        (!seen.answered || seen.since_answer > 0).then(|| seen.first.clone())
    }
}

/// The socket as hyper sees it: every read and write noted for the [`Tracker`], and a write that
/// makes no progress for `write_timeout` failed with `TimedOut`.
struct Guarded<'a, S> {
    io: &'a mut S,
    tracker: &'a Tracker,
    write_timeout: Duration,
    stall: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> Guarded<'_, S> {
    /// The socket would not take bytes: start the stall deadline if it is not running, and fail
    /// once it has passed.
    fn stalled(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let limit = self.write_timeout;
        let deadline = self
            .stall
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        match deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response write took too long",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut *this.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            this.tracker.read(&buf.filled()[before..]);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.io).poll_write(cx, bytes) {
            Poll::Ready(written) => {
                this.stall = None;
                if matches!(written, Ok(n) if n > 0) {
                    this.tracker.wrote();
                }
                Poll::Ready(written)
            }
            Poll::Pending => this.stalled(cx).map(|failed| failed.map(|()| 0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.io).poll_flush(cx) {
            Poll::Ready(flushed) => {
                this.stall = None;
                Poll::Ready(flushed)
            }
            Poll::Pending => this.stalled(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.io).poll_shutdown(cx) {
            Poll::Ready(done) => {
                this.stall = None;
                Poll::Ready(done)
            }
            Poll::Pending => this.stalled(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_head;

    #[test]
    fn keep_alive_is_read_from_any_connection_token_in_any_case() {
        let mut headers = http::HeaderMap::new();
        assert!(!asks_keep_alive(&headers));
        headers.insert(
            http::header::CONNECTION,
            "Upgrade, Keep-Alive".parse().unwrap(),
        );
        assert!(asks_keep_alive(&headers));
        headers.insert(http::header::CONNECTION, "close".parse().unwrap());
        assert!(!asks_keep_alive(&headers));
    }

    #[test]
    fn a_408_is_owed_to_a_started_request_or_a_connection_never_answered() {
        let tracker = Tracker::default();
        assert_eq!(tracker.owed(), Some(Vec::new()), "nothing ever came");
        let line = b"HEAD /a-long-path HTTP/1.1\r\n";
        tracker.read(line);
        assert_eq!(tracker.owed().as_deref(), Some(&line[..KEPT]));
        assert!(is_head(&tracker.owed().unwrap()));
        tracker.wrote();
        assert_eq!(tracker.owed(), None, "a kept connection went idle");
        tracker.read(b"GE");
        assert_eq!(tracker.owed().as_deref(), Some(&b"GE"[..]));
    }
}
