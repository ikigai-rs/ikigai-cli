//! Read redirects pass through the ordinary HTTP intake and edge policy.
mod common;
use common::{header, send, split, start};
use ikigai_core::{EndpointSpace, Kernel};
use ikigai_web::{public_cap, EdgeConfig, ReadRedirect};
use std::sync::Arc;

#[tokio::test]
async fn get_and_head_keep_the_raw_query() {
    let addr = start(
        Arc::new(Kernel::new(Arc::new(EndpointSpace::new()))),
        config(),
        public_cap(),
    )
    .await;
    for method in ["GET", "HEAD"] {
        let resp = send(
            addr,
            format!("{method} /face/name/alice?x=%2f+%20&empty=&bare HTTP/1.1\r\nHost: x\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert_eq!(
            split(&resp).0[0],
            "HTTP/1.1 308 Permanent Redirect",
            "{resp}"
        );
        assert_eq!(
            header(&resp, "Location"),
            Some("/face/name/alice/?x=%2f+%20&empty=&bare")
        );
        assert!(split(&resp).1.is_empty());
    }
}

fn config() -> EdgeConfig {
    EdgeConfig {
        read_redirects: vec![
            ReadRedirect::exact("/old", "/new/").unwrap(),
            ReadRedirect::trailing_slash("/face/name/").unwrap(),
        ],
        routes_only: true,
        ..EdgeConfig::default()
    }
}

async fn request(config: EdgeConfig, method: &str, path: &str, extra: &str) -> String {
    let addr = start(
        Arc::new(Kernel::new(Arc::new(EndpointSpace::new()))),
        config,
        public_cap(),
    )
    .await;
    send(
        addr,
        format!("{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n{extra}\r\n")
            .as_bytes(),
    )
    .await
}

#[tokio::test]
async fn exact_paths_and_prefix_boundaries_keep_encoded_paths_and_empty_queries() {
    for (path, expected) in [
        ("/old?", "/new/?"),
        ("/old?a=1&a=2", "/new/?a=1&a=2"),
        ("/face/name", "/face/name/"),
        ("/face/name/a%2fb?x=%26%3f", "/face/name/a%2fb/?x=%26%3f"),
        ("/face/name/%C3%A9", "/face/name/%C3%A9/"),
    ] {
        let resp = request(config(), "GET", path, "").await;
        assert_eq!(
            split(&resp).0[0],
            "HTTP/1.1 308 Permanent Redirect",
            "{resp}"
        );
        assert_eq!(header(&resp, "Location"), Some(expected));
    }
    for path in [
        "/other",
        "/older",
        "/face/names/alice",
        "/face/name/alice/",
        "/new/",
    ] {
        let resp = request(config(), "GET", path, "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 404 Not Found", "{resp}");
        assert_eq!(header(&resp, "Location"), None);
    }
}

#[tokio::test]
async fn writes_options_and_default_configuration_are_unchanged() {
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let resp = request(config(), method, "/old", "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 404 Not Found", "{resp}");
        assert_eq!(header(&resp, "Location"), None);
    }
    let resp = request(EdgeConfig::default(), "GET", "/face/name/alice", "").await;
    assert_eq!(split(&resp).0[0], "HTTP/1.1 404 Not Found", "{resp}");
    assert_eq!(header(&resp, "Location"), None);
}

#[tokio::test]
async fn admission_and_bounded_intake_refuse_before_redirecting() {
    let mut refused = config();
    refused.admit_fn = Some(Arc::new(|_| {
        Some(ikigai_web::Refusal {
            status: 403,
            reason: "admission refused".into(),
        })
    }));
    for method in ["GET", "HEAD"] {
        let resp = request(refused.clone(), method, "/old", "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 403 Forbidden", "{resp}");
        assert_eq!(header(&resp, "Location"), None);
    }
    let mut bounded = config();
    bounded.max_body_bytes = 0;
    bounded.admit_fn = Some(Arc::new(|_| {
        panic!("oversize intake must precede admission")
    }));
    let addr = start(
        Arc::new(Kernel::new(Arc::new(EndpointSpace::new()))),
        bounded,
        public_cap(),
    )
    .await;
    let resp = send(
        addr,
        b"GET /old HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx",
    )
    .await;
    assert_eq!(
        split(&resp).0[0],
        "HTTP/1.1 413 Payload Too Large",
        "{resp}"
    );
    assert_eq!(header(&resp, "Location"), None);
}

#[tokio::test]
async fn redirects_carry_security_and_route_cors_policy() {
    let mut config = config();
    config.routes = ikigai_web::RouteTable::new(vec![ikigai_web::Route {
        pattern: "/old".into(),
        iri_template: "urn:old".into(),
        redirect: None,
        cap: None,
        cors: Some(ikigai_web::CorsPolicy {
            allowed_origins: vec!["*".into()],
            ..Default::default()
        }),
        csp: Some("default-src 'none'".into()),
    }]);
    for method in ["GET", "HEAD"] {
        let resp = request(
            config.clone(),
            method,
            "/old",
            "Origin: https://other.example\r\n",
        )
        .await;
        assert_eq!(
            split(&resp).0[0],
            "HTTP/1.1 308 Permanent Redirect",
            "{resp}"
        );
        assert_eq!(
            header(&resp, "Content-Security-Policy"),
            Some("default-src 'none'")
        );
        assert_eq!(header(&resp, "X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(header(&resp, "Access-Control-Allow-Origin"), Some("*"));
        assert!(split(&resp).1.is_empty());
    }
}

#[test]
fn rules_refuse_unsafe_or_ambiguous_destinations() {
    for path in [
        "//other.example/x",
        "https://other.example/x",
        "/x?y",
        "/x#y",
        "/x\\y",
        "/x\r\nLocation: x",
        "/x y",
        "?x",
    ] {
        assert!(ReadRedirect::exact("/old", path).is_err(), "{path:?}");
        assert!(ReadRedirect::exact(path, "/new").is_err(), "{path:?}");
    }
    assert!(ReadRedirect::trailing_slash("/face/name").is_err());
}

#[tokio::test]
async fn a_post_to_a_redirect_path_still_invokes_the_endpoint() {
    use ikigai_core::{Description, Exact, FnEndpoint, Invocation, ReprType, Representation, Verb};
    let endpoint = FnEndpoint::new("note", |inv: &Invocation<'_>| {
        assert_eq!(inv.request.verb, Verb::Sink);
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"written".to_vec(),
        ))
    })
    .with_description(Description::new("note").verb(Verb::Sink));
    let kernel = Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:old"), endpoint),
    )));
    let mut config = config();
    config.routes_only = false;
    let addr = start(kernel, config, public_cap()).await;
    let resp = send(
        addr,
        b"POST /old HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(split(&resp).0[0], "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(split(&resp).1, "written");
    assert_eq!(header(&resp, "Location"), None);
}

#[tokio::test]
async fn first_matching_rule_wins_and_malformed_targets_still_fail_intake() {
    let mut config = config();
    config.read_redirects.insert(
        0,
        ReadRedirect::exact("/face/name/alice", "/preferred/").unwrap(),
    );
    let resp = request(config, "GET", "/face/name/alice", "").await;
    assert_eq!(header(&resp, "Location"), Some("/preferred/"));
    for path in ["/old?bad=%", "/face/name/%FF"] {
        let resp = request(self::config(), "GET", path, "").await;
        assert_eq!(split(&resp).0[0], "HTTP/1.1 400 Bad Request", "{resp}");
        assert_eq!(header(&resp, "Location"), None);
    }
}
