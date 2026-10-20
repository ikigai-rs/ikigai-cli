//! A door writes its own error page (ledger #2025).
//!
//! `EdgeConfig::error_page` is asked for the body of an error a BROWSER asked for as a page,
//! and only the body: the status and every header stay the ones the answer was built with,
//! the door's CSP governs the page, and a JSON client, curl and an htmx fragment request never
//! see the door's HTML. `None` from the hook keeps the minimal page of ledger #117.
mod common;

use common::{header, headers, send, split, start};
use ikigai_core::{
    Description, EndpointSpace, Error, Exact, FailureClass, FnEndpoint, Invocation, Kernel, Verb,
};
use ikigai_web::{
    public_cap, AdmitFn, EdgeConfig, ErrorBody, ErrorPageFn, ErrorView, HttpRequest, Refusal,
    SecurityHeaders, HTML_DOOR_CSP,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const DOOR_PAGE: &str = "<!DOCTYPE html><title>the door's own page</title>";

fn kernel() -> Arc<Kernel> {
    let denied = FnEndpoint::new(
        "denied",
        |_inv: &Invocation<'_>| -> ikigai_core::Result<_> {
            Err(Error::Denied("sign in to read <this>".into()))
        },
    )
    .with_description(Description::new("denied").verb(Verb::Source));
    let limited = FnEndpoint::new(
        "limited",
        |_inv: &Invocation<'_>| -> ikigai_core::Result<_> {
            Err(Error::RetryAfter {
                delay: Some(Duration::from_secs(30)),
                detail: "5 per minute".into(),
            })
        },
    )
    .with_description(Description::new("limited").verb(Verb::Source));
    Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:t:denied"), denied)
            .bind(Exact::new("urn:t:limited"), limited),
    )))
}

/// What the hook was shown, one row per call.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    status: u16,
    reason: String,
    message: String,
    error_kind: Option<&'static str>,
    refusal: Option<Refusal>,
    class: Option<FailureClass>,
    navigation: bool,
}

/// A hook that records each view and answers `page` (`None` keeps the default page).
fn recording(page: Option<&'static str>) -> (ErrorPageFn, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let hook: ErrorPageFn = Arc::new(move |_req: &HttpRequest, view: &ErrorView<'_>| {
        log.lock().unwrap().push(Seen {
            status: view.status,
            reason: view.reason.to_string(),
            message: view.message.to_string(),
            error_kind: view.error.map(Error::kind),
            refusal: view.refusal.cloned(),
            class: view.class,
            navigation: view.navigation,
        });
        page.map(str::to_string)
    });
    (hook, seen)
}

fn door(hook: ErrorPageFn) -> EdgeConfig {
    EdgeConfig {
        error_page: Some(hook),
        ..EdgeConfig::default()
    }
}

/// A request with the given extra header lines (each ending `\r\n`).
fn get(path: &str, extra: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").into_bytes()
}

fn navigate(path: &str) -> Vec<u8> {
    get(
        path,
        &format!("Accept: {BROWSER}\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n"),
    )
}

/// The head lines of `resp` that are not about the body (its type, length and `Vary`), so an
/// answer with the door's page can be compared to one without.
fn other_headers(resp: &str) -> Vec<String> {
    split(resp)
        .0
        .into_iter()
        .map(str::to_ascii_lowercase)
        .filter(|l| {
            !(l.starts_with("content-type:")
                || l.starts_with("content-length:")
                || l.starts_with("vary:")
                || l.starts_with("date:"))
        })
        .collect()
}

#[tokio::test]
async fn a_door_that_supplies_a_page_gets_it_with_the_status_and_headers_unchanged() {
    let (hook, seen) = recording(Some(DOOR_PAGE));
    let with = start(kernel(), door(hook), public_cap()).await;
    let without = start(kernel(), EdgeConfig::default(), public_cap()).await;
    for (path, status) in [
        ("/t/denied", "403 Forbidden"),
        ("/t/limited", "429 Too Many Requests"),
    ] {
        let page = send(with, &navigate(path)).await;
        let plain = send(without, &navigate(path)).await;
        assert!(page.starts_with(&format!("HTTP/1.1 {status}")), "{page}");
        assert_eq!(split(&page).1, DOOR_PAGE, "{page}");
        assert_eq!(
            header(&page, "content-type"),
            Some("text/html; charset=utf-8"),
            "{page}"
        );
        assert_eq!(
            other_headers(&page),
            other_headers(&plain),
            "{page}\n---\n{plain}"
        );
    }
    let page = send(with, &navigate("/t/limited")).await;
    assert_eq!(header(&page, "retry-after"), Some("30"), "{page}");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen[0],
        Seen {
            status: 403,
            reason: "Forbidden".into(),
            message: "denied: sign in to read <this>".into(),
            error_kind: Some("denied"),
            refusal: None,
            class: Some(FailureClass::Denied),
            navigation: true,
        }
    );
    assert_eq!(seen[1].class, Some(FailureClass::RetryAfter));
    assert_eq!(seen[1].error_kind, Some("retry-after"));
}

#[tokio::test]
async fn none_from_the_hook_keeps_the_default_page() {
    let (hook, seen) = recording(None);
    let with = start(kernel(), door(hook), public_cap()).await;
    let without = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let page = send(with, &navigate("/t/denied")).await;
    let plain = send(without, &navigate("/t/denied")).await;
    assert!(page.starts_with("HTTP/1.1 403 Forbidden"), "{page}");
    assert_eq!(split(&page).1, split(&plain).1);
    assert!(
        split(&page).1.contains("<main><h1>403 Forbidden</h1>"),
        "{page}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1, "the hook was asked");
}

#[tokio::test]
async fn a_json_client_curl_and_htmx_never_get_the_door_page() {
    let (hook, seen) = recording(Some(DOOR_PAGE));
    let addr = start(kernel(), door(hook), public_cap()).await;
    for (who, extra) in [
        (
            "a JSON client",
            "Accept: application/json\r\nSec-Fetch-Mode: cors\r\n".to_string(),
        ),
        ("curl", "Accept: */*\r\n".to_string()),
        ("curl naming html", "Accept: text/html\r\n".to_string()),
        (
            "htmx",
            format!("Accept: {BROWSER}\r\nSec-Fetch-Mode: cors\r\nHX-Request: true\r\n"),
        ),
        (
            "htmx default accept",
            "Accept: */*\r\nSec-Fetch-Mode: cors\r\nHX-Request: true\r\n".to_string(),
        ),
    ] {
        let resp = send(addr, &get("/t/denied", &extra)).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{who}: {resp}");
        assert!(!resp.contains(DOOR_PAGE), "{who}: {resp}");
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
}

/// A door that answers JSON errors keeps them for a browser too, hook or not.
#[tokio::test]
async fn a_json_door_never_asks_the_hook() {
    let (hook, seen) = recording(Some(DOOR_PAGE));
    let config = EdgeConfig {
        error_body: ErrorBody::Json,
        ..door(hook)
    };
    let addr = start(kernel(), config, public_cap()).await;
    let resp = send(addr, &navigate("/t/denied")).await;
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/json"),
        "{resp}"
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_door_page_is_served_under_the_door_csp() {
    let (hook, _) = recording(Some(DOOR_PAGE));
    let config = EdgeConfig {
        security: Some(SecurityHeaders::html_door()),
        ..door(hook)
    };
    let addr = start(kernel(), config, public_cap()).await;
    let resp = send(addr, &navigate("/t/denied")).await;
    assert_eq!(split(&resp).1, DOOR_PAGE, "{resp}");
    assert_eq!(
        header(&resp, "content-security-policy"),
        Some(HTML_DOOR_CSP),
        "{resp}"
    );
    assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));
}

/// A script's fetch that asks for HTML is asked about too, told it is not a navigation, so
/// the door can decline it.
#[tokio::test]
async fn a_fetch_from_script_is_not_a_navigation() {
    let (hook, seen) = recording(None);
    let addr = start(kernel(), door(hook), public_cap()).await;
    let resp = send(
        addr,
        &get(
            "/t/denied",
            "Accept: text/html\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n",
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].navigation);
}

/// An admission refusal is shown as a refusal, with the class its status is decided as.
#[tokio::test]
async fn an_admission_refusal_reaches_the_hook() {
    let admit: AdmitFn = Arc::new(|_req: &HttpRequest| {
        Some(Refusal {
            status: 403,
            reason: "not from here".to_string(),
        })
    });
    let (hook, seen) = recording(Some(DOOR_PAGE));
    let config = EdgeConfig {
        admit_fn: Some(admit),
        ..door(hook)
    };
    let addr = start(kernel(), config, public_cap()).await;
    let resp = send(addr, &navigate("/t/denied")).await;
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "{resp}");
    assert_eq!(split(&resp).1, DOOR_PAGE);
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[0].refusal,
        Some(Refusal {
            status: 403,
            reason: "not from here".to_string()
        })
    );
    assert_eq!(seen[0].error_kind, None);
    assert_eq!(seen[0].class, Some(FailureClass::Denied));
    assert_eq!(seen[0].message, "not from here");
}

/// With a hook, the body also depends on `Sec-Fetch-Mode` and `HX-Request`, so a cache is
/// told; without one, `Vary` is what it was.
#[tokio::test]
async fn vary_names_what_selects_the_door_page() {
    let (hook, _) = recording(None);
    let with = start(kernel(), door(hook), public_cap()).await;
    let without = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let vary = |resp: &str| headers(resp, "vary").join(", ");
    let resp = send(with, &get("/t/denied", "Accept: */*\r\n")).await;
    for name in ["Accept", "Sec-Fetch-Mode", "HX-Request"] {
        assert!(vary(&resp).contains(name), "{name}: {resp}");
    }
    let resp = send(without, &get("/t/denied", "Accept: */*\r\n")).await;
    assert!(!vary(&resp).contains("Sec-Fetch-Mode"), "{resp}");
}

/// HEAD carries the head of the door's page: its length, no content.
#[tokio::test]
async fn head_carries_the_door_page_length() {
    let (hook, _) = recording(Some(DOOR_PAGE));
    let addr = start(kernel(), door(hook), public_cap()).await;
    let raw = String::from_utf8(navigate("/t/denied"))
        .unwrap()
        .replacen("GET", "HEAD", 1);
    let resp = send(addr, raw.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(
        header(&resp, "content-length"),
        Some(DOOR_PAGE.len().to_string().as_str())
    );
    assert_eq!(split(&resp).1, "");
}
