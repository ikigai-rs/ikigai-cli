//! A door that serves HTML adopts the Origin check and the page CSP in one call (ledger
//! #1813).
//!
//! Before `EdgeConfig::html_door` a door had to hand-roll both, and the doors that serve HTML
//! (the standalone ikigai-web, web-demo) did neither: the default edge admitted a write from
//! any origin, and sent neither `object-src 'none'` nor an opener policy. Each test names
//! whether it fails without the change or guards behavior the change must keep.
mod common;

use common::{header, send, split, start};
use ikigai_core::{
    Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType, Representation,
    Verb,
};
use ikigai_web::{public_cap, EdgeConfig, OriginCheck, Route, RouteTable, HTML_DOOR_CSP};
use std::sync::Arc;

const DOOR: &str = "https://door.example";

/// A note a page reads and writes, and a second page served under its own route.
fn kernel() -> Arc<Kernel> {
    let note = FnEndpoint::new("note", |inv: &Invocation<'_>| {
        let body = if inv.request.verb == Verb::Sink {
            "saved"
        } else {
            "<p>a note</p>"
        };
        Ok(Representation::new(
            ReprType::new("text/html"),
            body.as_bytes().to_vec(),
        ))
    })
    .with_description(
        Description::new("note")
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Delete),
    );
    Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:note"), note),
    )))
}

async fn door() -> std::net::SocketAddr {
    start(
        kernel(),
        EdgeConfig::html_door([DOOR]).unwrap(),
        public_cap(),
    )
    .await
}

/// A write to the note carrying `headers` (each a whole `Name: value` line).
fn write(method: &str, headers: &[&str]) -> Vec<u8> {
    let mut raw = format!("{method} /test/note HTTP/1.1\r\nHost: door.example\r\n");
    for h in headers {
        raw.push_str(h);
        raw.push_str("\r\n");
    }
    raw.push_str("Content-Length: 2\r\n\r\nhi");
    raw.into_bytes()
}

fn status(resp: &str) -> &str {
    split(resp).0[0]
}

/// FAILS WITHOUT THE CHANGE: the default edge admitted these (200).
#[tokio::test]
async fn a_cross_origin_write_is_refused() {
    let addr = door().await;
    for (method, origin) in [
        ("POST", "Origin: https://evil.example"),
        ("PUT", "Origin: https://evil.example"),
        ("PATCH", "Origin: https://evil.example"),
        ("DELETE", "Origin: https://evil.example"),
        // Another port and another scheme are other origins; the same site is not enough.
        ("POST", "Origin: https://door.example:8443"),
        ("POST", "Origin: http://door.example"),
        ("POST", "Origin: null"),
        ("POST", "Sec-Fetch-Site: cross-site"),
        ("POST", "Sec-Fetch-Site: same-site"),
    ] {
        let resp = send(addr, &write(method, &[origin, "Cookie: s=1"])).await;
        assert_eq!(
            status(&resp),
            "HTTP/1.1 403 Forbidden",
            "{method} {origin}\n{resp}"
        );
        assert!(!resp.ends_with("saved"), "{method} {origin}\n{resp}");
        // The refusal still carries the page headers.
        assert_eq!(
            header(&resp, "Content-Security-Policy"),
            Some(HTML_DOOR_CSP),
            "{resp}"
        );
    }
}

/// GUARDS: the door's own page keeps writing, by Origin or, without one, Sec-Fetch-Site.
#[tokio::test]
async fn a_same_origin_write_is_admitted() {
    let addr = door().await;
    for headers in [
        &["Origin: https://door.example", "Cookie: s=1"][..],
        &["Origin: https://DOOR.example:443", "Cookie: s=1"],
        &[
            "Origin: https://door.example",
            "Sec-Fetch-Site: same-origin",
        ],
        &["Sec-Fetch-Site: same-origin", "Cookie: s=1"],
        &["Sec-Fetch-Site: none", "Cookie: s=1"],
    ] {
        let resp = send(addr, &write("POST", headers)).await;
        assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{headers:?}\n{resp}");
        assert!(resp.ends_with("saved"), "{headers:?}\n{resp}");
    }
    // A read is never checked: a link from another site still opens the page.
    let read = send(
        addr,
        b"GET /test/note HTTP/1.1\r\nHost: door.example\r\nOrigin: https://evil.example\r\n\
          Sec-Fetch-Site: cross-site\r\nCookie: s=1\r\n\r\n",
    )
    .await;
    assert_eq!(status(&read), "HTTP/1.1 200 OK", "{read}");
}

/// The decided case: no Origin and no Sec-Fetch-Site is not a current browser. Admitted with
/// no ambient credential (curl, an API client with a bearer token); refused with a cookie or a
/// credential a browser replays on its own. FAILS WITHOUT THE CHANGE for the refused half.
#[tokio::test]
async fn an_origin_less_write_is_admitted_only_without_ambient_credentials() {
    let addr = door().await;
    for headers in [&[][..], &["Authorization: Bearer tok"]] {
        let resp = send(addr, &write("POST", headers)).await;
        assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{headers:?}\n{resp}");
    }
    for headers in [
        &["Cookie: s=1"][..],
        &["Authorization: Basic dTpw"],
        &["Authorization: Negotiate abc"],
    ] {
        let resp = send(addr, &write("POST", headers)).await;
        assert_eq!(
            status(&resp),
            "HTTP/1.1 403 Forbidden",
            "{headers:?}\n{resp}"
        );
        assert!(resp.contains("no Origin or Sec-Fetch-Site"), "{resp}");
    }
}

/// FAILS WITHOUT THE CHANGE: the default sent no `object-src` and no opener policy.
#[tokio::test]
async fn the_preset_sends_its_exact_header_lines() {
    let addr = door().await;
    let resp = send(
        addr,
        b"GET /test/note HTTP/1.1\r\nHost: door.example\r\n\r\n",
    )
    .await;
    let (head, _) = split(&resp);
    for line in [
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: no-referrer",
        "Cross-Origin-Opener-Policy: same-origin",
    ] {
        assert!(head.contains(&line), "{line}\n{resp}");
    }
    // HSTS only on HTTPS; this request was plain HTTP and no proxy is trusted.
    assert_eq!(header(&resp, "Strict-Transport-Security"), None, "{resp}");
}

/// GUARDS: the default edge is unchanged by the new field, so no existing door loosens or
/// gains an opener policy it did not ask for.
#[tokio::test]
async fn the_default_edge_is_unchanged() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, b"GET /test/note HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(
        header(&resp, "Content-Security-Policy"),
        Some("default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
        "{resp}"
    );
    assert_eq!(header(&resp, "Cross-Origin-Opener-Policy"), None, "{resp}");
}

/// GUARDS: a door that opts in still sets a CSP per route, and only that route changes.
#[tokio::test]
async fn an_html_door_can_still_set_a_per_route_csp() {
    let route_csp = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'";
    let config = EdgeConfig {
        routes: RouteTable::new(vec![Route {
            pattern: "/gallery".into(),
            iri_template: "urn:test:note".into(),
            redirect: None,
            cap: None,
            cors: None,
            csp: Some(route_csp.into()),
        }]),
        ..EdgeConfig::html_door([DOOR]).unwrap()
    };
    let addr = start(kernel(), config, public_cap()).await;
    let routed = send(addr, b"GET /gallery HTTP/1.1\r\nHost: door.example\r\n\r\n").await;
    assert_eq!(status(&routed), "HTTP/1.1 200 OK", "{routed}");
    assert_eq!(
        header(&routed, "Content-Security-Policy"),
        Some(route_csp),
        "{routed}"
    );
    // The rest of the preset still rides on the routed page.
    assert_eq!(
        header(&routed, "Cross-Origin-Opener-Policy"),
        Some("same-origin"),
        "{routed}"
    );
    let other = send(
        addr,
        b"GET /test/note HTTP/1.1\r\nHost: door.example\r\n\r\n",
    )
    .await;
    assert_eq!(
        header(&other, "Content-Security-Policy"),
        Some(HTML_DOOR_CSP),
        "{other}"
    );
    // And the Origin check still guards the routed path.
    let raw = b"POST /gallery HTTP/1.1\r\nHost: door.example\r\nOrigin: https://evil.example\r\n\
                Content-Length: 2\r\n\r\nhi";
    assert_eq!(status(&send(addr, raw).await), "HTTP/1.1 403 Forbidden");
}

/// A door with an admission rule of its own composes the check inside its own hook.
#[tokio::test]
async fn a_door_composes_the_check_with_its_own_admission() {
    let check = OriginCheck::new([DOOR]).unwrap();
    let admit: ikigai_web::AdmitFn = Arc::new(move |req: &ikigai_web::HttpRequest| {
        if req.header("host") != Some("door.example") {
            return Some(ikigai_web::Refusal {
                status: 421,
                reason: "wrong host".into(),
            });
        }
        check.check(req)
    });
    let config = EdgeConfig {
        admit_fn: Some(admit),
        ..EdgeConfig::html_door([DOOR]).unwrap()
    };
    let addr = start(kernel(), config, public_cap()).await;
    let foreign = send(addr, &write("POST", &["Origin: https://evil.example"])).await;
    assert_eq!(status(&foreign), "HTTP/1.1 403 Forbidden", "{foreign}");
    let ours = send(addr, &write("POST", &["Origin: https://door.example"])).await;
    assert_eq!(status(&ours), "HTTP/1.1 200 OK", "{ours}");
}
