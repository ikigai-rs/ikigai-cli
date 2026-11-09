//! Core's two resolution outcomes on the HTTP face (ledger #3151): `Error::Gone` answers `410`,
//! and a Source answering core's typed redirect answers its status with `Location`. Raw HTTP
//! over a socket, the way a client meets them. No browser or assistive technology is involved.
mod common;

use async_trait::async_trait;
use common::{header, send, split, start};
use ikigai_core::{
    Body, Bytes, Description, Endpoint, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
    Kernel, Redirect, RedirectStatus, ReprType, Representation, Verb, REDIRECT_MEDIA_TYPE,
};
use ikigai_web::{public_cap, EdgeConfig, ErrorBody, HTTP_ENTITY};
use std::net::SocketAddr;
use std::sync::Arc;

const BROWSER: &str = "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n";

fn redirect(status: RedirectStatus, location: &str) -> Representation {
    Representation::redirect(Redirect::new(status, location).unwrap())
}

/// A door over one read at `/t/x`, answering whatever `answer` builds.
async fn door_answering(
    answer: impl Fn() -> ikigai_core::Result<Representation> + Send + Sync + 'static,
) -> SocketAddr {
    let endpoint = FnEndpoint::new("x", move |_inv: &Invocation<'_>| answer())
        .with_description(Description::new("x").verb(Verb::Source));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:t:x"), endpoint),
    ));
    start(Arc::new(kernel), EdgeConfig::default(), public_cap()).await
}

async fn request(addr: SocketAddr, method: &str, extra: &str) -> String {
    send(
        addr,
        format!("{method} /t/x HTTP/1.1\r\nHost: h\r\n{extra}\r\n").as_bytes(),
    )
    .await
}

fn status_line(resp: &str) -> &str {
    split(resp).0[0]
}

#[tokio::test]
async fn every_redirect_status_answers_that_code_and_the_exact_location() {
    let expected = [
        (RedirectStatus::MovedPermanently, "301 Moved Permanently"),
        (RedirectStatus::Found, "302 Found"),
        (RedirectStatus::SeeOther, "303 See Other"),
        (RedirectStatus::TemporaryRedirect, "307 Temporary Redirect"),
        (RedirectStatus::PermanentRedirect, "308 Permanent Redirect"),
    ];
    assert_eq!(expected.len(), RedirectStatus::ALL.len());
    for (status, line) in expected {
        let location = "https://example.org/about?x=1&y=%2F#top";
        let addr = door_answering(move || Ok(redirect(status, location))).await;
        let resp = request(addr, "GET", "").await;
        assert_eq!(status_line(&resp), format!("HTTP/1.1 {line}"), "{resp}");
        assert_eq!(header(&resp, "Location"), Some(location), "{resp}");
    }
}

#[tokio::test]
async fn an_off_site_location_is_kept() {
    let addr = door_answering(|| {
        Ok(redirect(
            RedirectStatus::Found,
            "https://elsewhere.example/x",
        ))
    })
    .await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(status_line(&resp), "HTTP/1.1 302 Found", "{resp}");
    assert_eq!(
        header(&resp, "Location"),
        Some("https://elsewhere.example/x"),
        "{resp}"
    );
}

/// Core allows what an IRI allows; a header carries what a URI allows.
#[tokio::test]
async fn a_location_is_percent_encoded_only_where_a_uri_needs_it() {
    let addr = door_answering(|| {
        Ok(redirect(
            RedirectStatus::SeeOther,
            "https://example.org/caf\u{e9}?a=%2F",
        ))
    })
    .await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(
        header(&resp, "Location"),
        Some("https://example.org/caf%C3%A9?a=%2F"),
        "{resp}"
    );
    // The page's link goes where the header goes, and its text is what the endpoint wrote.
    let page = request(addr, "GET", BROWSER).await;
    let body = split(&page).1;
    assert!(
        body.contains("href=\"https://example.org/caf%C3%A9?a=%2F\""),
        "{body}"
    );
    assert!(
        body.contains(">https://example.org/caf\u{e9}?a=%2F<"),
        "{body}"
    );
}

#[tokio::test]
async fn head_has_the_head_of_get_and_no_body() {
    let addr = door_answering(|| {
        Ok(redirect(
            RedirectStatus::PermanentRedirect,
            "https://example.org/moved",
        ))
    })
    .await;
    for accept in ["", BROWSER] {
        let get = request(addr, "GET", accept).await;
        let head = request(addr, "HEAD", accept).await;
        assert_eq!(
            status_line(&head),
            "HTTP/1.1 308 Permanent Redirect",
            "{head}"
        );
        assert_eq!(header(&head, "Location"), Some("https://example.org/moved"));
        assert!(split(&head).1.is_empty(), "{head}");
        assert!(!split(&get).1.is_empty(), "{get}");
        assert_eq!(
            header(&head, "Content-Length"),
            header(&get, "Content-Length")
        );
        assert_eq!(header(&head, "Content-Type"), header(&get, "Content-Type"));
    }
}

#[tokio::test]
async fn a_browser_gets_the_accessible_page_and_any_other_client_text() {
    let location = "https://example.org/a?x=1&y='2'";
    let addr = door_answering(move || Ok(redirect(RedirectStatus::SeeOther, location))).await;

    let page = request(addr, "GET", BROWSER).await;
    assert_eq!(
        header(&page, "Content-Type"),
        Some("text/html; charset=utf-8"),
        "{page}"
    );
    let body = split(&page).1;
    assert!(body.starts_with("<!DOCTYPE html>"), "{body}");
    assert!(body.contains("<html lang=\"en\">"), "{body}");
    assert!(body.contains("<title>303 See Other</title>"), "{body}");
    assert!(body.contains("<main><h1>303 See Other</h1>"), "{body}");
    assert_eq!(body.matches("<main>").count(), 1, "{body}");
    assert!(
        body.contains("<a href=\"https://example.org/a?x=1&amp;y=&#39;2&#39;\">"),
        "{body}"
    );
    assert!(
        !body.contains("<script") && !body.contains("style"),
        "{body}"
    );

    for accept in ["", "Accept: */*\r\n", "Accept: application/json\r\n"] {
        let text = request(addr, "GET", accept).await;
        assert_eq!(
            header(&text, "Content-Type"),
            Some("text/plain; charset=utf-8"),
            "{text}"
        );
        assert!(split(&text).1.contains(location), "{text}");
        assert!(!split(&text).1.contains('<'), "{text}");
    }
}

/// A location is any absolute IRI, so `javascript:` reads. The header carries it as the endpoint
/// said, for the client to judge; the page never makes it something to click.
#[tokio::test]
async fn a_location_that_is_not_http_is_never_a_link() {
    for location in ["javascript:alert(1)", "urn:name:moved"] {
        let addr = door_answering(move || Ok(redirect(RedirectStatus::Found, location))).await;
        let page = request(addr, "GET", BROWSER).await;
        assert_eq!(status_line(&page), "HTTP/1.1 302 Found", "{page}");
        assert_eq!(header(&page, "Location"), Some(location), "{page}");
        let body = split(&page).1;
        assert!(!body.contains("href"), "{body}");
        assert!(body.contains(location), "{body}");
    }
}

#[tokio::test]
async fn caching_follows_the_representations_expiry_as_for_any_answer() {
    let text = || Representation::new(ReprType::new("text/plain"), b"hi".to_vec());
    let found = || redirect(RedirectStatus::Found, "https://example.org/x");
    for (redirected, plain) in [
        (found(), text()),
        (found().cacheable(), text().cacheable()),
        (
            found().cacheable_until(ikigai_core::Time::from_millis(u64::MAX / 2)),
            text().cacheable_until(ikigai_core::Time::from_millis(u64::MAX / 2)),
        ),
    ] {
        let redirected = request(
            door_answering(move || Ok(redirected.clone())).await,
            "GET",
            "",
        )
        .await;
        let plain = request(door_answering(move || Ok(plain.clone())).await, "GET", "").await;
        assert_eq!(
            header(&redirected, "Cache-Control").map(without_max_age),
            header(&plain, "Cache-Control").map(without_max_age),
            "{redirected}\n{plain}"
        );
        assert!(
            header(&redirected, "Cache-Control").is_some(),
            "{redirected}"
        );
    }
}

/// `max-age` counts down between the two answers; only its presence is compared.
fn without_max_age(value: &str) -> String {
    value
        .split(',')
        .map(|d| d.trim().split('=').next().unwrap())
        .collect::<Vec<_>>()
        .join(",")
}

/// The body depends on `Accept`, so a shared cache must key on it, and the validator is of the
/// bytes sent, so a tag never stands for a page and a sentence at once.
#[tokio::test]
async fn the_answer_varies_on_accept_and_revalidates_per_body() {
    let addr = door_answering(|| {
        Ok(redirect(RedirectStatus::MovedPermanently, "https://example.org/x").cacheable())
    })
    .await;
    let text = request(addr, "GET", "").await;
    let page = request(addr, "GET", BROWSER).await;
    assert!(
        header(&text, "Vary").is_some_and(|v| v.contains("Accept")),
        "{text}"
    );
    let (text_tag, page_tag) = (
        header(&text, "ETag").unwrap(),
        header(&page, "ETag").unwrap(),
    );
    assert_ne!(text_tag, page_tag);

    let matched = request(addr, "GET", &format!("If-None-Match: {text_tag}\r\n")).await;
    assert_eq!(
        status_line(&matched),
        "HTTP/1.1 304 Not Modified",
        "{matched}"
    );
    let other = request(addr, "GET", "If-None-Match: \"something-else\"\r\n").await;
    assert_eq!(
        status_line(&other),
        "HTTP/1.1 301 Moved Permanently",
        "{other}"
    );
}

/// A location longer than a header may carry is refused by name, not sent over the limit.
#[tokio::test]
async fn a_location_too_long_for_a_header_is_refused_by_name() {
    let location = format!("https://example.org/{}", "a".repeat(5000));
    let addr = door_answering(move || Ok(redirect(RedirectStatus::Found, &location))).await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(
        status_line(&resp),
        "HTTP/1.1 500 Internal Server Error",
        "{resp}"
    );
    assert_eq!(header(&resp, "Location"), None, "{resp}");
    assert!(split(&resp).1.contains("Location"), "{resp}");
}

/// Core's reader settles what the type's bytes mean: a body it cannot read is no redirect.
#[tokio::test]
async fn the_reserved_type_over_a_body_core_cannot_read_is_an_ordinary_answer() {
    let addr = door_answering(|| {
        Ok(Representation::new(
            ReprType::new(REDIRECT_MEDIA_TYPE),
            br#"{"status":404,"location":"https://example.org/x"}"#.to_vec(),
        ))
    })
    .await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(header(&resp, "Location"), None, "{resp}");
    assert_eq!(header(&resp, "Content-Type"), Some(REDIRECT_MEDIA_TYPE));
}

/// A redirect delivered as a one-shot stream, through the body entry point.
struct StreamedRedirect;

#[async_trait]
impl Endpoint for StreamedRedirect {
    async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
        self.invoke_body(inv).await?.collect(1 << 20).await
    }

    async fn invoke_body(
        &self,
        _inv: &Invocation<'_>,
    ) -> ikigai_core::Result<Representation<Body>> {
        Ok(Representation::from_body(
            ReprType::new(REDIRECT_MEDIA_TYPE),
            Body::once(futures::stream::iter([Ok(Bytes::from_static(
                br#"{"status":307,"location":"https://example.org/streamed"}"#,
            ))])),
        ))
    }
}

/// Core's reader reads no stream, so the door collects this type first, as it does an envelope.
#[tokio::test]
async fn a_streamed_redirect_answers_like_a_buffered_one() {
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:t:x"), StreamedRedirect),
    ));
    let addr = start(Arc::new(kernel), EdgeConfig::default(), public_cap()).await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(
        status_line(&resp),
        "HTTP/1.1 307 Temporary Redirect",
        "{resp}"
    );
    assert_eq!(
        header(&resp, "Location"),
        Some("https://example.org/streamed")
    );
}

/// A door over a write at `/t/w`, answering whatever `answer` builds.
async fn door_writing(answer: impl Fn() -> Representation + Send + Sync + 'static) -> SocketAddr {
    let endpoint = FnEndpoint::new("w", move |_inv: &Invocation<'_>| Ok(answer()))
        .with_description(Description::new("w").verb(Verb::Sink));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:t:w"), endpoint),
    ));
    start(Arc::new(kernel), EdgeConfig::default(), public_cap()).await
}

const POST: &[u8] = b"POST /t/w HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n";

/// The typed answer is for reads: a write's answer of that type is served as it came.
#[tokio::test]
async fn a_write_answering_the_reserved_type_is_not_a_redirect() {
    let addr =
        door_writing(|| redirect(RedirectStatus::SeeOther, "https://elsewhere.example/")).await;
    let resp = send(addr, POST).await;
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(header(&resp, "Location"), None, "{resp}");
}

/// The envelope's `Location` keeps its own rule: same-origin, or refused.
#[tokio::test]
async fn a_writes_off_site_location_is_still_refused() {
    fn envelope(location: &str) -> Representation {
        Representation::new(
            ReprType::new(HTTP_ENTITY),
            format!("Content-Type: text/plain\r\nLocation: {location}\r\n\r\ndone"),
        )
    }

    let addr = door_writing(|| envelope("https://evil.example/")).await;
    let refused = send(addr, POST).await;
    assert_eq!(
        status_line(&refused),
        "HTTP/1.1 500 Internal Server Error",
        "{refused}"
    );
    assert_eq!(header(&refused, "Location"), None, "{refused}");
    assert!(split(&refused).1.contains("Location"), "{refused}");

    let addr = door_writing(|| envelope("/thanks")).await;
    let kept = send(addr, POST).await;
    assert_eq!(status_line(&kept), "HTTP/1.1 303 See Other", "{kept}");
    assert_eq!(header(&kept, "Location"), Some("/thanks"), "{kept}");
}

#[tokio::test]
async fn gone_answers_410_with_its_sentence() {
    let gone = || Err(Error::Gone("urn:t:x was retired in 2024".into()));
    let addr = door_answering(gone).await;
    let text = request(addr, "GET", "").await;
    assert_eq!(status_line(&text), "HTTP/1.1 410 Gone", "{text}");
    assert_eq!(
        split(&text).1,
        "gone: urn:t:x was retired in 2024",
        "{text}"
    );

    let head = request(addr, "HEAD", "").await;
    assert_eq!(status_line(&head), "HTTP/1.1 410 Gone", "{head}");
    assert!(split(&head).1.is_empty(), "{head}");

    let page = request(addr, "GET", BROWSER).await;
    assert_eq!(status_line(&page), "HTTP/1.1 410 Gone", "{page}");
    let body = split(&page).1;
    assert!(body.contains("<main><h1>410 Gone</h1>"), "{body}");
    assert!(
        body.contains("<p>gone: urn:t:x was retired in 2024</p>"),
        "{body}"
    );
}

#[tokio::test]
async fn gone_keeps_its_word_on_a_json_door() {
    let endpoint = FnEndpoint::new(
        "x",
        |_inv: &Invocation<'_>| -> ikigai_core::Result<Representation> {
            Err(Error::Gone("retired".into()))
        },
    )
    .with_description(Description::new("x").verb(Verb::Source));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:t:x"), endpoint),
    ));
    let config = EdgeConfig {
        error_body: ErrorBody::Json,
        ..EdgeConfig::default()
    };
    let addr = start(Arc::new(kernel), config, public_cap()).await;
    let resp = request(addr, "GET", "").await;
    assert_eq!(status_line(&resp), "HTTP/1.1 410 Gone", "{resp}");
    let json: serde_json::Value = serde_json::from_str(split(&resp).1).unwrap();
    assert_eq!(json["kind"], "gone", "{resp}");
    assert_eq!(json["class"], "permanent", "{resp}");
}
