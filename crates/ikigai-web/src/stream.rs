//! Answers that stream (ledger #2244, stage 8 of the streams design, ledger #2228): the door
//! reads an endpoint's answer through the body path ([`Kernel::issue_body`]) and writes it as
//! it is read, so a 1 GiB download holds about one chunk in memory, not a gibibyte.
//!
//! **Which answers stream.** [`settle`] decides, from the body's shape alone:
//!
//! | body | served |
//! |---|---|
//! | a buffer ([`Body::Bytes`]) | whole, exactly as before |
//! | an [`HTTP_ENTITY`](crate::HTTP_ENTITY) envelope, any shape | whole: its headers ride inside it |
//! | a [`Replay`] of known length up to [`BUFFER_BELOW`], read as a write's answer or with no content id | whole |
//! | any other [`Replay`], or a one-shot [`Body::Once`] | streamed |
//!
//! A whole answer is the path every answer took before, with its strong `ETag`, its `304`
//! and its `Content-Length`. A streamed one is framed by `Content-Length` when its length is
//! known and chunked when it is not, and a failure part-way is VISIBLE to the client: a
//! chunked answer ends without its final zero-length chunk and a measured one ends short,
//! and either way the connection closes. Never a well-formed shorter body.
//!
//! **Validators.** A streamed body has a strong `ETag` only when its producer knows its
//! content id ([`Replay::validator`], what a spill computes while it writes): the same tag a
//! buffer of those bytes would carry ([`crate::etag_from`]). Without one it has no `ETag`,
//! since a tag cannot be computed without reading the body first.
//!
//! **Ranges** (RFC 9110 §14). A `GET` over a [`Replay`] that is seekable
//! ([`Replay::open_at`]), knows its length and has a strong validator says
//! `Accept-Ranges: bytes` and honors a `Range` of ONE byte range: `206 Partial Content` with
//! `Content-Range`, or `416 Range Not Satisfiable` (with `Content-Range: bytes */<length>`) when
//! it lies past the end. `If-Range` is compared strongly against the `ETag`; a mismatch, a date
//! (the door sends no `Last-Modified`, so no date is a strong validator here) or a value that
//! does not parse answers the whole body with `200`. A request for SEVERAL ranges is answered
//! with the whole body and `200`, which RFC 9110 allows (a server may ignore `Range`):
//! `multipart/byteranges` is not served. An unparseable `Range`, or one in a unit other than
//! `bytes`, is ignored the same way. Every other body (a buffer, a one-shot stream, a replay
//! with no validator or that cannot seek) answers `200` with the whole body and no
//! `Accept-Ranges`. The grammar is ikigai-http's ([`ikigai_http::range`]), never a parser of
//! the door's own.

use crate::{
    cache_control_of, etag_from, if_none_match_hit, media_type_of, wall_clock_ms, Freshness,
    HttpRequest, Resp, HTTP_ENTITY,
};
use futures_core::Stream;
use ikigai_core::{Body, ByteStream, Bytes, Representation};
use ikigai_http::range::{ContentRange, IfRange, Range};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A body of known length up to this many bytes, whose content id its producer does not
/// state, is collected and served whole: holding a mebibyte costs little, and it keeps the
/// strong `ETag` (and so the `304`) every such answer had before ledger #2244. A file read is
/// the common case (ikigai-fs answers a seekable [`Replay`] with no validator). Past it the
/// body streams with no validator, because computing one would mean reading it twice.
///
/// The same mebibyte as [`DEFAULT_MAX_BODY_BYTES`](crate::DEFAULT_MAX_BODY_BYTES), the bound
/// the door already holds a request body to.
pub(crate) const BUFFER_BELOW: u64 = 1024 * 1024;

/// The most a body that settles whole may hold when it arrives as a stream (an envelope, or a
/// replay whose length hint was wrong): the kernel's own default byte budget for one run
/// ([`ikigai_core::DEFAULT_STREAM_MEMORY`]). Past it the answer is refused with `OverBudget`,
/// never truncated.
const MAX_WHOLE: usize = ikigai_core::DEFAULT_STREAM_MEMORY as usize;

/// How an answer is served: held whole, or streamed.
pub(crate) enum Settled {
    /// The answer's content, in memory: the path every answer took before ledger #2244.
    Whole(Representation),
    /// The answer as the endpoint produced it, to be written as it is read.
    Streamed(Representation<Body>),
}

/// Settle `repr` as the [module docs](self) describe. `ranged` is whether the answer may be
/// asked for by range (a read): a small replay that states its content id then streams, so
/// it keeps its `Accept-Ranges`.
pub(crate) async fn settle(
    repr: Representation<Body>,
    ranged: bool,
) -> ikigai_core::Result<Settled> {
    let envelope = repr.repr_type.media_type.eq_ignore_ascii_case(HTTP_ENTITY);
    let whole = match &repr.bytes {
        Body::Bytes(_) => true,
        _ if envelope => true,
        Body::Replay(replay) => match replay.len_hint() {
            Some(len) if len <= BUFFER_BELOW => !(ranged && replay.validator().is_some()),
            _ => false,
        },
        Body::Once(_) => false,
    };
    if !whole {
        return Ok(Settled::Streamed(repr));
    }
    let bound = if repr.bytes.as_bytes().is_some() {
        usize::MAX // already in memory: handed over as it is
    } else {
        MAX_WHOLE
    };
    Ok(Settled::Whole(repr.collect(bound).await?))
}

/// The strong `ETag` of a body, when one can be had without reading it: a buffer's, from its
/// bytes, or a replay's, from the content id its producer states. `None` otherwise.
pub(crate) fn validator_etag(repr: &Representation<Body>) -> Option<String> {
    match &repr.bytes {
        Body::Bytes(bytes) => Some(etag_from(
            &repr.repr_type,
            &ikigai_core::ContentId::of(bytes),
        )),
        Body::Replay(replay) => replay.validator().map(|id| etag_from(&repr.repr_type, &id)),
        Body::Once(_) => None,
    }
}

/// A read whose answer streams: `200` with the body, `206` with one range of it, `304` when
/// `If-None-Match` names its validator, or `416` for a range past its end. The same
/// `Cache-Control` and `Vary` a whole read carries ([`crate::read_resp`]'s rules).
pub(crate) fn read(
    req: &HttpRequest,
    repr: Representation<Body>,
    freshness: Freshness,
    vary: Vec<String>,
) -> Resp {
    let etag = validator_etag(&repr);
    let cache_control = Some(cache_control_of(repr.expiry, freshness, wall_clock_ms()));
    if let (Some(inm), Some(tag)) = (req.header("if-none-match"), etag.as_deref()) {
        if if_none_match_hit(inm, tag) {
            return Resp {
                etag,
                cache_control,
                vary,
                ..Resp::status(304, "Not Modified")
            };
        }
    }
    let mut resp = Resp {
        content_type: media_type_of(&repr),
        etag: etag.clone(),
        cache_control,
        vary,
        ..Resp::status(200, "OK")
    };
    // Ranges only over a body that is seekable, knows its length and has a strong validator.
    // Opening at 0 is how seekability is learned, and that reader serves a whole answer.
    let seekable = match (&repr.bytes, etag) {
        (Body::Replay(replay), Some(tag)) => replay
            .len_hint()
            .and_then(|len| Some((std::sync::Arc::clone(replay), len, replay.open_at(0)?, tag))),
        _ => None,
    };
    let Some((replay, len, whole, tag)) = seekable else {
        let length = repr.bytes.len_hint();
        resp.stream = Some(Sending::whole(repr.bytes.into_stream(), length));
        return resp;
    };
    resp.headers
        .push(("Accept-Ranges".to_string(), "bytes".to_string()));
    match asked_range(req, &tag, len) {
        Asked::Whole => resp.stream = Some(Sending::whole(whole, Some(len))),
        Asked::Part(first, last) => {
            let part = replay.open_at(first);
            let range = ContentRange::satisfied(first, last, Some(len));
            match (part, range) {
                (Some(part), Ok(range)) => {
                    resp.status = 206;
                    resp.reason = "Partial Content";
                    resp.headers
                        .push(("Content-Range".to_string(), range.to_string()));
                    resp.stream = Some(Sending::part(part, last - first + 1));
                }
                // The replay would not open at the offset it opened at 0 for, or the interval
                // is not one: serve the whole body rather than guess.
                _ => resp.stream = Some(Sending::whole(whole, Some(len))),
            }
        }
        Asked::Unsatisfiable => {
            let why = format!("the range asks for bytes this {len}-byte body does not have");
            let mut refused = Resp::text(416, "Range Not Satisfiable", &why);
            refused.headers.push((
                "Content-Range".to_string(),
                ContentRange::unsatisfied(len).to_string(),
            ));
            refused
                .headers
                .push(("Accept-Ranges".to_string(), "bytes".to_string()));
            return refused;
        }
    }
    resp
}

/// A write whose answer streams: `200` with it.
pub(crate) fn write(repr: Representation<Body>) -> Resp {
    let length = repr.bytes.len_hint();
    Resp {
        content_type: media_type_of(&repr),
        stream: Some(Sending::whole(repr.bytes.into_stream(), length)),
        ..Resp::status(200, "OK")
    }
}

/// What a `GET` asked for of a body of `len` bytes whose strong `ETag` is `tag`.
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    /// The whole body: no `Range`, one that is ignored, or an `If-Range` that does not match.
    Whole,
    /// Bytes `first..=last`, within the body.
    Part(u64, u64),
    /// A single range that lies wholly past the end.
    Unsatisfiable,
}

fn asked_range(req: &HttpRequest, tag: &str, len: u64) -> Asked {
    if req.method != "GET" {
        return Asked::Whole;
    }
    let Some(range) = req.header("range") else {
        return Asked::Whole;
    };
    // An unparseable Range, or one in another unit, is ignored (RFC 9110 §14.2).
    let Ok(range) = range.parse::<Range>() else {
        return Asked::Whole;
    };
    if let Some(condition) = req.header("if-range") {
        // Strong comparison (RFC 9110 §13.1.5). A date never matches: the door sends no
        // `Last-Modified`, so no date it could be sent back is a strong validator.
        let matched = condition
            .parse::<IfRange>()
            .ok()
            .and_then(|v| v.entity_tag().map(|t| t == tag))
            .unwrap_or(false);
        if !matched {
            return Asked::Whole;
        }
    }
    // Several ranges: the whole body, no `multipart/byteranges` (see the module docs).
    let [one] = range.ranges() else {
        return Asked::Whole;
    };
    match one.resolve(len) {
        Some((first, last)) => Asked::Part(first, last),
        None => Asked::Unsatisfiable,
    }
}

/// A streamed answer's content as the door writes it: the chunks of `stream`, held to
/// `length` when it is known.
///
/// A body that ends short of its length, or runs past it, fails rather than be framed as
/// whole; so does a producer's own error. A RANGE takes exactly its `length` and stops,
/// since a replay opened at an offset reads to the end.
pub(crate) struct Sending {
    stream: ByteStream,
    length: Option<u64>,
    take: bool,
    sent: u64,
}

impl Sending {
    /// The whole body, of `length` bytes when it is known.
    fn whole(stream: ByteStream, length: Option<u64>) -> Sending {
        Sending {
            stream,
            length,
            take: false,
            sent: 0,
        }
    }

    /// The first `count` bytes of `stream`.
    fn part(stream: ByteStream, count: u64) -> Sending {
        Sending {
            stream,
            length: Some(count),
            take: true,
            sent: 0,
        }
    }

    /// The number of bytes this sends, when it is known: its `Content-Length`.
    pub(crate) fn length(&self) -> Option<u64> {
        self.length
    }

    /// The next chunk to write, `None` at a whole end, or the failure that ends it short.
    pub(crate) fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, StreamFailed>>> {
        loop {
            if self.take && self.length.is_some_and(|len| self.sent >= len) {
                return Poll::Ready(None);
            }
            let polled = Pin::new(&mut self.stream).poll_next(cx);
            let chunk = match polled {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => chunk,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(failed(error)))),
                Poll::Ready(None) => {
                    return match self.length {
                        Some(len) if self.sent < len => {
                            Poll::Ready(Some(Err(failed(ikigai_core::Error::Conflict(format!(
                                "the body ended after {} of its {len} bytes",
                                self.sent
                            ))))))
                        }
                        _ => Poll::Ready(None),
                    };
                }
            };
            let mut chunk = chunk;
            if let Some(len) = self.length {
                let left = len - self.sent;
                if chunk.len() as u64 > left {
                    if !self.take {
                        return Poll::Ready(Some(Err(failed(ikigai_core::Error::Conflict(
                            format!("the body ran past its {len} bytes"),
                        )))));
                    }
                    chunk.truncate(left as usize);
                }
            }
            // An empty chunk would read as the end of a chunked answer: skip it.
            if chunk.is_empty() {
                continue;
            }
            self.sent += chunk.len() as u64;
            return Poll::Ready(Some(Ok(chunk)));
        }
    }
}

/// A streamed answer that failed part-way: the producer's error, or a body that did not hold
/// to its length. Logged once, here, because the client only sees the connection close.
#[derive(Debug)]
pub(crate) struct StreamFailed(ikigai_core::Error);

fn failed(error: ikigai_core::Error) -> StreamFailed {
    eprintln!("ikigai-web: a streamed answer ended part-way: {error}");
    StreamFailed(error)
}

impl std::fmt::Display for StreamFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the streamed answer ended part-way: {}", self.0)
    }
}

impl std::error::Error for StreamFailed {}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            path: "/x".to_string(),
            query: Vec::new(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
            peer: None,
        }
    }

    #[test]
    fn one_range_is_a_part_and_anything_else_is_the_whole_body() {
        let tag = "\"t\"";
        let asked = |headers: &[(&str, &str)]| asked_range(&get(headers), tag, 10);
        assert_eq!(asked(&[]), Asked::Whole);
        assert_eq!(asked(&[("range", "bytes=2-4")]), Asked::Part(2, 4));
        assert_eq!(asked(&[("range", "bytes=-3")]), Asked::Part(7, 9));
        assert_eq!(asked(&[("range", "bytes=8-")]), Asked::Part(8, 9));
        assert_eq!(asked(&[("range", "bytes=5-99")]), Asked::Part(5, 9));
        assert_eq!(asked(&[("range", "bytes=10-")]), Asked::Unsatisfiable);
        // Several ranges, another unit, and nonsense: the whole body.
        assert_eq!(asked(&[("range", "bytes=0-1, 4-5")]), Asked::Whole);
        assert_eq!(asked(&[("range", "pages=1-2")]), Asked::Whole);
        assert_eq!(asked(&[("range", "bytes=x")]), Asked::Whole);
        // If-Range: the tag, strongly; anything else is the whole body.
        let ranged = ("range", "bytes=2-4");
        assert_eq!(asked(&[ranged, ("if-range", "\"t\"")]), Asked::Part(2, 4));
        assert_eq!(asked(&[ranged, ("if-range", "\"u\"")]), Asked::Whole);
        assert_eq!(asked(&[ranged, ("if-range", "W/\"t\"")]), Asked::Whole);
        let date = ("if-range", "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(asked(&[ranged, date]), Asked::Whole);
        // Only a GET is answered by range.
        let mut head = get(&[ranged]);
        head.method = "HEAD".to_string();
        assert_eq!(asked_range(&head, tag, 10), Asked::Whole);
    }

    fn chunks(parts: &[&'static [u8]]) -> ByteStream {
        let parts: Vec<_> = parts.iter().map(|p| Ok(Bytes::from_static(p))).collect();
        Box::pin(futures::stream::iter(parts))
    }

    fn drain(mut sending: Sending) -> Result<Vec<u8>, String> {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();
        loop {
            match sending.poll_chunk(&mut cx) {
                Poll::Ready(Some(Ok(chunk))) => out.extend_from_slice(&chunk),
                Poll::Ready(Some(Err(e))) => return Err(e.to_string()),
                Poll::Ready(None) => return Ok(out),
                Poll::Pending => unreachable!("an iterator stream is always ready"),
            }
        }
    }

    #[test]
    fn a_body_is_held_to_its_length_and_a_part_takes_exactly_its_count() {
        assert_eq!(
            drain(Sending::whole(chunks(&[b"ab", b"cd"]), Some(4))).unwrap(),
            b"abcd"
        );
        assert_eq!(
            drain(Sending::whole(chunks(&[b"ab", b"", b"cd"]), None)).unwrap(),
            b"abcd"
        );
        let short = drain(Sending::whole(chunks(&[b"ab"]), Some(4))).unwrap_err();
        assert!(short.contains("after 2 of its 4 bytes"), "{short}");
        let long = drain(Sending::whole(chunks(&[b"ab", b"cde"]), Some(4))).unwrap_err();
        assert!(long.contains("ran past its 4 bytes"), "{long}");
        assert_eq!(
            drain(Sending::part(chunks(&[b"ab", b"cde"]), 3)).unwrap(),
            b"abc"
        );
        let cut = drain(Sending::part(chunks(&[b"ab"]), 3)).unwrap_err();
        assert!(cut.contains("after 2 of its 3 bytes"), "{cut}");
    }
}
