//! The door's seam, independent of the HTTP version and of hyper's connection types (ledger
//! #2236, and the hub's addition for ledger #2301).
//!
//! [`exchange`] takes one `http::Request` whose body is any [`http_body::Body`], and gives back
//! one `http::Response` whose body is a [`DoorBody`]. Everything the door decides happens here or
//! below: the head bound (`431`), the body bound (`413`, never a truncation), the body deadline
//! (`408`), the request target's decoding (`400`), then [`crate::answer`], which holds admission, the push stream,
//! routing, dispatch, content negotiation, the error pages and the edge policy.
//!
//! What a listener owns is only what its HTTP version means by a connection. The HTTP/1.1
//! listener ([`crate::h1`]) owns keep-alive (`Connection`), the header read deadline and its
//! `408`, and the write-stall deadline. A later listener (HTTP/2 through hyper, HTTP/3 through
//! a QUIC server such as h3-quinn) adapts its request stream into an `http::Request<impl Body>`,
//! calls [`exchange`], and frames the answer its own way: no second door.
//!
//! An answer that streams (ledger #2244, the private `stream` module) is framed by
//! `Content-Length` when its length is known and chunked when it is not, and a producer that
//! fails part-way ends it short: hyper then closes the connection without the final chunk, so
//! a client sees the failure. An upload route (the private `upload` module) spills its body
//! instead of reading it into memory.
//!
//! Two things in an answer are HTTP/1.1's, and harmless elsewhere: the status's reason phrase
//! rides as hyper's `ReasonPhrase` extension (HTTP/2 and HTTP/3 send no reason phrase), and an
//! answer that leaves the request body unread carries the [`Unread`] extension, which tells an
//! HTTP/1.1 listener the connection cannot be reused.

use crate::stream::{Sending, StreamFailed};
use crate::{
    answer, header_fields, parse_target, upload, EdgeConfig, HttpRequest, Reply, Resp, Shared,
};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The largest request head the door takes: the target and every header field, counted as
/// they would be written (`name: value` and a line break each). Past it the answer is `431`,
/// the hand-written reader's bound. hyper's own bound (`max_buf_size`, set to the same number by
/// [`crate::h1`]) is a read-buffer limit, not a head limit: a head that arrives in one read can
/// pass it, so the door counts too.
pub(crate) const MAX_HEAD: usize = 64 * 1024;

/// Marks an answer given before the request body was read to its end (a refusal decided on the
/// head, a body past the bound or its deadline). The connection that carried it cannot carry
/// another request, since what is left of the body would be read as one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unread;

/// The content of a door's answer.
pub(crate) enum DoorBody {
    /// The whole content, or `None` for none (a `HEAD`, a `204`, a `304`). Its length is known,
    /// so HTTP/1.1 frames it with `Content-Length`.
    Full(Option<Bytes>),
    /// The push stream: each item as it arrives, until the sender is dropped. Its length is not
    /// known, so HTTP/1.1 frames it chunked.
    Stream(tokio::sync::mpsc::Receiver<Bytes>),
    /// An endpoint's answer as it is read (ledger #2244): framed by its length when known,
    /// chunked otherwise. A failure part-way is this body's error, and hyper ends the answer
    /// short and closes the connection.
    Streamed(Sending),
}

impl Body for DoorBody {
    type Data = Bytes;
    type Error = StreamFailed;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, StreamFailed>>> {
        match self.get_mut() {
            DoorBody::Full(content) => Poll::Ready(content.take().map(|b| Ok(Frame::data(b)))),
            DoorBody::Stream(events) => events
                .poll_recv(cx)
                .map(|event| event.map(|b| Ok(Frame::data(b)))),
            DoorBody::Streamed(sending) => sending
                .poll_chunk(cx)
                .map(|chunk| chunk.map(|c| c.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, DoorBody::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            DoorBody::Full(None) => SizeHint::with_exact(0),
            DoorBody::Full(Some(content)) => SizeHint::with_exact(content.len() as u64),
            DoorBody::Stream(_) => SizeHint::default(),
            DoorBody::Streamed(sending) => match sending.length() {
                Some(length) => SizeHint::with_exact(length),
                None => SizeHint::default(),
            },
        }
    }
}

/// One request through the door: intake under the body bound and deadline, then
/// [`crate::answer`], rendered as an `http::Response`. See the [module docs](self).
pub(crate) async fn exchange<B>(
    shared: &Shared,
    req: http::Request<B>,
    peer: Option<IpAddr>,
) -> http::Response<DoorBody>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();
    let head = match head_of(&parts, peer) {
        Ok(head) => head,
        Err(refused) => return unread(render(*refused)),
    };
    // An upload route, for a caller that may spill: the body goes to disk as it arrives.
    if let Some(plan) = upload::plan(shared, &head) {
        return upload::exchange(shared, head, body, plan).await;
    }
    match read_body(&shared.config, head, body).await {
        Ok(req) => reply(answer(shared, req).await),
        Err(refused) => unread(render(*refused)),
    }
}

/// A door's answer as an `http::Response`.
pub(crate) fn reply(reply: Reply) -> http::Response<DoorBody> {
    match reply {
        Reply::Whole(resp) => render(resp),
        Reply::Stream { head, events } => framed(&head, None, DoorBody::Stream(events)),
    }
}

/// `out`, marked as given before the request body was read to its end ([`Unread`]).
pub(crate) fn unread(mut out: http::Response<DoorBody>) -> http::Response<DoorBody> {
    out.extensions_mut().insert(Unread);
    out
}

/// A refusal decided on the request's head: `text/plain`, the head alone for `HEAD`.
pub(crate) fn refusal(head: bool, status: u16, reason: &'static str, why: &str) -> Box<Resp> {
    let resp = Resp::text(status, reason, why);
    Box::new(if head { resp.into_head() } else { resp })
}

/// The request's head as an [`HttpRequest`] with no body yet, under the head bound, exactly
/// as the hand-written [`crate::read_request`] reads it, with the framing already settled by
/// the listener. A refusal is the answer to send: `text/plain`, the head alone for `HEAD`, and
/// no edge policy, since `read_request`'s refusals never carried one.
fn head_of(parts: &http::request::Parts, peer: Option<IpAddr>) -> Result<HttpRequest, Box<Resp>> {
    let head = parts.method == http::Method::HEAD;
    let refuse = |status, reason, why: &str| refusal(head, status, reason, why);
    let target = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let (path, query) =
        parse_target(target.as_bytes()).map_err(|why| refuse(400, "Bad Request", why))?;
    let head_size = target.len()
        + parts
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum::<usize>();
    if head_size > MAX_HEAD {
        return Err(refuse(431, "Request Header Fields Too Large", ""));
    }
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).trim().to_string();
            (name.as_str().to_string(), value)
        })
        .collect();
    Ok(HttpRequest {
        method: parts.method.as_str().to_string(),
        path,
        query,
        headers,
        body: Vec::new(),
        peer,
    })
}

/// Read the body of `req` into it, under the door's body bound and deadline.
async fn read_body<B>(
    config: &EdgeConfig,
    mut req: HttpRequest,
    body: B,
) -> Result<HttpRequest, Box<Resp>>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let head = req.method == "HEAD";
    let refuse = |status, reason, why: &str| refusal(head, status, reason, why);
    let max = config.max_body_bytes;
    // REFUSE, DO NOT TRUNCATE, and decide on the declared length before reading a byte, so the
    // refusal costs nothing and a client holding its body back for `100 Continue` is never
    // invited (HTTP/1.1 sends the `100` only when the body is first read, below). A listener
    // that has already checked the framing (hyper refuses an unreadable `Content-Length` with
    // `400` itself) will never send an unparseable one here; another listener might.
    if let Some(declared) = req.header("content-length") {
        match declared.trim().parse::<u64>().ok() {
            None => return Err(refuse(400, "Bad Request", "malformed Content-Length")),
            Some(n) if n > max as u64 => {
                return Err(refuse(413, "Payload Too Large", "request body too large"))
            }
            Some(_) => {}
        }
    }
    // A chunked body carries its length inside it, so the same bound is held as it arrives:
    // `Limited` fails the read the moment the body passes `max`, and that failure is a `413`,
    // never the first `max` bytes handed on. The whole body is read under its own deadline, for
    // the reason the head is: a client that trickles it would otherwise hold the connection.
    let read = tokio::time::timeout(config.body_timeout, Limited::new(body, max).collect()).await;
    let body = match read {
        Err(_) => return Err(refuse(408, "Request Timeout", "request body took too long")),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Err(refuse(413, "Payload Too Large", "request body too large"))
        }
        // The client hung up part-way, or broke the framing: a PARTIAL submission, which the
        // endpoint must never be handed as if it were whole.
        Ok(Err(_)) => return Err(refuse(400, "Bad Request", "incomplete request body")),
        Ok(Ok(collected)) => collected.to_bytes().to_vec(),
    };
    req.body = body;
    Ok(req)
}

/// An answer as an `http::Response`: its content framed by length (or chunked, for a stream
/// of unknown length), or none for `HEAD`.
pub(crate) fn render(mut resp: Resp) -> http::Response<DoorBody> {
    if let Some(sending) = resp.stream.take() {
        let length = sending.length();
        let body = if resp.head_only {
            DoorBody::Full(None)
        } else {
            DoorBody::Streamed(sending)
        };
        return framed(&resp, length, body);
    }
    let length = resp.body.len() as u64;
    let body = if resp.head_only || resp.body.is_empty() {
        DoorBody::Full(None)
    } else {
        DoorBody::Full(Some(Bytes::from(std::mem::take(&mut resp.body))))
    };
    framed(&resp, Some(length), body)
}

/// `resp`'s status, reason and [`header_fields`] around `body`. `content_length` is `None` only
/// for the push stream. A header field that cannot be framed (a byte HTTP forbids) is the
/// door's own bug, answered `500` naming it rather than dropped from the answer in silence.
fn framed(resp: &Resp, content_length: Option<u64>, body: DoorBody) -> http::Response<DoorBody> {
    let mut out = http::Response::new(body);
    *out.status_mut() =
        http::StatusCode::from_u16(resp.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in header_fields(resp, content_length) {
        let name = http::HeaderName::from_bytes(name.as_bytes());
        let value = http::HeaderValue::from_bytes(value.as_bytes());
        match (name, value) {
            (Ok(name), Ok(value)) => {
                out.headers_mut().append(name, value);
            }
            _ => {
                let why = "the door built a header field HTTP cannot carry";
                let mut refusal = Resp::text(500, "Internal Server Error", why);
                refusal.head_only = resp.head_only;
                return render(refusal);
            }
        }
    }
    out.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            resp.reason.as_bytes(),
        ));
    out
}
