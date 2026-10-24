//! Route-owned Post/Redirect/Get, with the htmx answer kept in place.
mod common;

use common::{header, send, split, start};
use ikigai_core::{
    Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Kernel, ReprType,
    Representation, Verb,
};
use ikigai_web::{public_cap, EdgeConfig, Route, RouteTable};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn route(pattern: &str, target: &str, redirect: Option<&str>) -> Route {
    Route {
        pattern: pattern.into(),
        iri_template: target.into(),
        redirect: redirect.map(str::to_owned),
        cap: None,
        cors: None,
        csp: None,
    }
}

async fn door(routes: Vec<Route>, routes_only: bool) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let writes = Arc::new(AtomicUsize::new(0));
    let counted = writes.clone();
    let note = FnEndpoint::new("note", move |inv: &Invocation<'_>| {
        counted.fetch_add(1, Ordering::SeqCst);
        if matches!(
            inv.request.args.get("fail"),
            Some(ikigai_core::ArgRef::Inline(_))
        ) {
            return Err(Error::Conflict("note refused".into()));
        }
        let repr = Representation::new(
            ReprType::new("text/plain"),
            if inv.request.args.contains_key("empty") {
                Vec::new()
            } else {
                b"written".to_vec()
            },
        );
        if inv.request.args.contains_key("outcome") {
            return Ok(
                ikigai_web::with_headers(repr, &[("Location", "?outcome=recorded")]).unwrap(),
            );
        }
        Ok(repr)
    })
    .with_description(Description::new("note").verb(Verb::Sink));
    let page = FnEndpoint::new("page", |_inv: &Invocation<'_>| {
        Ok(Representation::new(ReprType::new("text/html"), b"<!doctype html><html lang=\"en\"><title>Note</title><main><h1>Note</h1><p>Saved</p></main></html>".to_vec()))
    }).with_description(Description::new("page").verb(Verb::Source));
    let kernel = Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:test:note"), note)
            .bind(Exact::new("urn:test:page"), page),
    )));
    let config = EdgeConfig {
        routes: RouteTable::new(routes),
        routes_only,
        ..EdgeConfig::html_door(["https://door.example"]).unwrap()
    };
    (start(kernel, config, public_cap()).await, writes)
}

async fn post(addr: std::net::SocketAddr, path: &str, headers: &str) -> String {
    send(addr, format!("POST {path} HTTP/1.1\r\nHost: door.example\r\nOrigin: https://door.example\r\nAccept: text/html\r\nContent-Type: application/x-www-form-urlencoded\r\n{headers}Content-Length: 6\r\n\r\nnote=x").as_bytes()).await
}

#[tokio::test]
async fn a_plain_form_post_redirects_to_the_page_after_writing() {
    let (addr, writes) = door(
        vec![route("/note", "urn:test:note", Some("urn:test:page"))],
        false,
    )
    .await;
    let resp = post(addr, "/note", "").await;
    assert_eq!(split(&resp).0[0], "HTTP/1.1 303 See Other", "{resp}");
    assert_eq!(header(&resp, "Location"), Some("/test/page"));
    assert_eq!(header(&resp, "Vary"), Some("HX-Request"));
    assert!(split(&resp).1.is_empty());
    assert!(header(&resp, "Content-Security-Policy").is_some());
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    // Follow Location as a GET, then reload: neither repeats the Sink.
    for _ in 0..2 {
        let page = send(
            addr,
            b"GET /test/page HTTP/1.1\r\nHost: door.example\r\n\r\n",
        )
        .await;
        assert_eq!(split(&page).0[0], "HTTP/1.1 200 OK", "{page}");
        assert!(split(&page).1.contains("<p>Saved</p>"));
    }
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn htmx_keeps_the_in_place_answer_and_false_is_a_plain_post() {
    let (addr, writes) = door(
        vec![route("/note", "urn:test:note", Some("urn:test:page"))],
        false,
    )
    .await;
    for value in ["true", "TRUE"] {
        let resp = post(addr, "/note", &format!("HX-Request: {value}\r\n")).await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 200 OK", "{resp}");
        assert_eq!(split(&resp).1, "written");
        assert_eq!(header(&resp, "Location"), None);
        assert_eq!(header(&resp, "Vary"), Some("HX-Request"));
    }
    assert_eq!(
        split(&post(addr, "/note", "HX-Request: false\r\n").await).0[0],
        "HTTP/1.1 303 See Other"
    );
    assert_eq!(writes.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_page_alias_is_used_even_on_a_routes_only_door() {
    let (addr, _) = door(
        vec![
            route("/note", "urn:test:note", Some("urn:test:page")),
            route("/inspector", "urn:test:page", None),
        ],
        true,
    )
    .await;
    let resp = post(addr, "/note", "").await;
    assert_eq!(split(&resp).0[0], "HTTP/1.1 303 See Other", "{resp}");
    assert_eq!(header(&resp, "Location"), Some("/inspector"));
}

#[tokio::test]
async fn captures_in_the_page_iri_are_encoded_in_the_location() {
    let (addr, _) = door(
        vec![
            route("/note/{+name}", "urn:test:note", Some("urn:page:{+name}")),
            route("/inspect/{+name}", "urn:page:{+name}", None),
        ],
        true,
    )
    .await;
    for (name, location) in [
        ("alice", "/inspect/alice"),
        ("a%2Fb%3Fc%23d", "/inspect/a%2Fb%3Fc%23d"),
        ("%C3%A9", "/inspect/%C3%A9"),
        ("a%2520b", "/inspect/a%2520b"),
    ] {
        let resp = post(addr, &format!("/note/{name}"), "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 303 See Other", "{resp}");
        assert_eq!(header(&resp, "Location"), Some(location), "{resp}");
    }
}

#[tokio::test]
async fn errors_and_admission_refusals_do_not_redirect() {
    let (addr, writes) = door(
        vec![route("/note", "urn:test:note", Some("urn:test:page"))],
        false,
    )
    .await;
    let failed = post(addr, "/note?fail=yes", "").await;
    assert_eq!(split(&failed).0[0], "HTTP/1.1 409 Conflict", "{failed}");
    assert_eq!(header(&failed, "Location"), None);
    let refused = send(addr, b"POST /note HTTP/1.1\r\nHost: door.example\r\nOrigin: https://other.example\r\nContent-Length: 0\r\n\r\n").await;
    assert_eq!(split(&refused).0[0], "HTTP/1.1 403 Forbidden", "{refused}");
    assert_eq!(header(&refused, "Location"), None);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unaddressable_page_is_refused_before_the_sink() {
    for (destination, only) in [
        ("https://other.example/page", false),
        ("urn:test:page", true),
        ("urn:test:..", false),
        ("not an iri", false),
    ] {
        let (addr, writes) = door(
            vec![route("/note", "urn:test:note", Some(destination))],
            only,
        )
        .await;
        let resp = post(addr, "/note", "").await;
        assert_eq!(
            split(&resp).0[0],
            "HTTP/1.1 500 Internal Server Error",
            "{resp}"
        );
        assert_eq!(header(&resp, "Location"), None);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn routes_without_a_redirect_and_other_methods_keep_their_answers() {
    let (addr, writes) = door(vec![route("/note", "urn:test:note", None)], false).await;
    assert_eq!(split(&post(addr, "/note", "").await).1, "written");
    let (addr, _) = door(
        vec![route("/note", "urn:test:note", Some("urn:test:page"))],
        false,
    )
    .await;
    let put = send(addr, b"PUT /note HTTP/1.1\r\nHost: door.example\r\nOrigin: https://door.example\r\nContent-Length: 0\r\n\r\n").await;
    assert_eq!(split(&put).0[0], "HTTP/1.1 200 OK", "{put}");
    assert_eq!(split(&put).1, "written");
    assert_eq!(header(&put, "Location"), None);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_empty_success_redirects_and_an_endpoint_location_keeps_its_outcome() {
    let (addr, writes) = door(
        vec![route("/note", "urn:test:note", Some("urn:test:page"))],
        false,
    )
    .await;
    for (query, expected) in [
        ("empty=yes", "/test/page"),
        ("outcome=yes", "?outcome=recorded"),
    ] {
        let resp = post(addr, &format!("/note?{query}"), "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 303 See Other", "{resp}");
        assert_eq!(header(&resp, "Location"), Some(expected));
    }
    assert_eq!(writes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_shadowed_page_path_cannot_redirect_to_another_resource() {
    let (addr, writes) = door(
        vec![
            route("/note", "urn:test:note", Some("urn:test:page")),
            route("/inspector", "urn:test:other", None),
            route("/inspector", "urn:test:page", None),
            route("/test/page", "urn:test:other", None),
        ],
        false,
    )
    .await;
    let resp = post(addr, "/note", "").await;
    assert_eq!(
        split(&resp).0[0],
        "HTTP/1.1 500 Internal Server Error",
        "{resp}"
    );
    assert_eq!(header(&resp, "Location"), None);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_write_uses_one_route_snapshot_when_the_table_changes_during_the_sink() {
    let table = |page_path| {
        RouteTable::new(vec![
            route("/note", "urn:test:note", Some("urn:test:page")),
            route(page_path, "urn:test:page", None),
        ])
    };
    let live = ikigai_web::live_routes(table("/before"));
    let changed = live.clone();
    let replacement = table("/after");
    let note = FnEndpoint::new("note", move |_inv: &Invocation<'_>| {
        ikigai_web::swap_routes(&changed, replacement.clone());
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"written".to_vec(),
        ))
    })
    .with_description(Description::new("note").verb(Verb::Sink));
    let kernel = Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:note"), note),
    )));
    let addr = start(
        kernel,
        EdgeConfig {
            live_routes: Some(live),
            routes_only: true,
            ..EdgeConfig::default()
        },
        public_cap(),
    )
    .await;
    let first = post(addr, "/note", "").await;
    assert_eq!(header(&first, "Location"), Some("/before"), "{first}");
    let next = post(addr, "/note", "").await;
    assert_eq!(header(&next, "Location"), Some("/after"), "{next}");
}
