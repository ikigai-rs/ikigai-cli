// Test at the invocation boundary so the kernel cannot resolve a reference or inject a default
// before the endpoint reads it.
use super::*;
use futures::executor::block_on;
use ikigai_core::{Bindings, Capability, ContentId};

fn request(iri: &str) -> Request {
    Request::new(Verb::Source, Iri::parse(iri).unwrap())
}

fn inline(value: &str) -> ArgRef {
    ArgRef::Inline(value.as_bytes().to_vec())
}

pub(super) fn rejects_unreadable(
    base: &Request,
    names: &[&str],
    issue: impl Fn(&Request) -> Result<Representation>,
) {
    for &name in names {
        for (arg, reason) in [
            (ArgRef::Inline(vec![0xff]), "not valid UTF-8"),
            (
                ArgRef::Reference(Iri::parse("urn:test:argument").unwrap()),
                "expected an inline value",
            ),
            (
                ArgRef::Content(ContentId::of(b"body")),
                "expected an inline value",
            ),
        ] {
            let err = issue(&base.clone().with_arg(name, arg)).expect_err(name);
            assert!(
                matches!(&err, Error::InvalidArgument { name: actual, detail }
                    if actual == name && detail.contains(reason)),
                "{err:?}"
            );
            let line = err.to_string();
            assert!(line.contains(name) && line.contains(reason), "{line}");
        }
    }
}

fn detached(endpoint: &(impl Endpoint + ?Sized), req: &Request) -> Result<Representation> {
    block_on(endpoint.invoke(&Invocation::detached(
        req,
        &Bindings::new(),
        &Capability::root(),
    )))
}

#[test]
fn clock_does_not_choose_plain_text_for_unreadable_html() {
    let clock = clock_now();
    let base = request("urn:time:now");
    let issue = |req: &Request| detached(&clock, req);
    assert!(issue(&base)
        .unwrap()
        .repr_type
        .to_string()
        .starts_with("text/plain"));
    let html = issue(&base.clone().with_arg("html", inline("true"))).unwrap();
    assert!(String::from_utf8_lossy(&html.bytes).contains("ik-clock-colon"));
    rejects_unreadable(&base, &["html"], issue);
    let err = issue(&base.with_arg("html", inline("on"))).unwrap_err();
    assert!(matches!(err, Error::InvalidArgument { name, .. } if name == "html"));
}

#[test]
fn health_and_posture_refuse_unreadable_faces() {
    let health = |req: &Request| detached(&KernelHealth, req);
    let posture = posture::host_posture();
    let posture = |req: &Request| detached(&posture, req);
    for (iri, issue) in [
        (
            "urn:host:health",
            &health as &dyn Fn(&Request) -> Result<Representation>,
        ),
        ("urn:host:posture", &posture),
    ] {
        let base = request(iri);
        assert_eq!(issue(&base).unwrap().repr_type.to_string(), "text/plain");
        let valid = base.clone().with_arg("as", inline("text/turtle"));
        assert_eq!(issue(&valid).unwrap().repr_type.to_string(), "text/turtle");
        rejects_unreadable(&base, &["as"], issue);
        let err = issue(&base.with_arg("as", inline("image/png"))).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument { name, .. } if name == "as"));
    }
}

#[test]
fn peer_list_does_not_drop_an_unreadable_filter_or_face() {
    let base = request("urn:peer:list");
    let cap = Capability::root();
    let bindings = Bindings::new();
    let issue = |req: &Request| {
        list_peers(&Invocation::detached(req, &bindings, &cap), || {
            Ok(vec![ikigai_discovery::Peer {
                name: "test-peer".to_string(),
                addrs: Vec::new(),
                port: 1234,
                surface: None,
                ceiling: None,
                version: None,
                trusted: false,
            }])
        })
    };
    let default = issue(&base).unwrap();
    assert_eq!(default.repr_type.to_string(), "text/plain");
    assert!(String::from_utf8_lossy(&default.bytes).contains("test-peer"));
    let valid = base
        .clone()
        .with_arg("trusted", inline("yes"))
        .with_arg("as", inline("text/turtle"));
    let turtle = issue(&valid).unwrap();
    assert_eq!(turtle.repr_type.to_string(), "text/turtle");
    assert!(!String::from_utf8_lossy(&turtle.bytes).contains("test-peer"));
    rejects_unreadable(&base, &["trusted", "as"], issue);
}

#[test]
fn agent_selection_and_aliases_refuse_unreadable_options() {
    #[allow(clippy::disallowed_methods)] // internal: an empty, in-process test fixture
    let kernel = Kernel::with_meta_renderer(Arc::new(EndpointSpace::new()), Arc::new(CliRenderer));
    let cap = Capability::root();
    let bindings = Bindings::new();
    let select = |req: &Request| {
        block_on(
            AgentSelectEndpoint.invoke(&Invocation::with_issuer(req, &bindings, &cap, &kernel)),
        )
    };
    let base = request("urn:agent:select");
    assert!(select(&base).is_ok());
    let valid = base
        .clone()
        .with_arg("verb", inline("source"))
        .with_arg("types", inline("urn:test:class"))
        .with_arg("want", inline("text/plain"))
        .with_arg("goal", inline("find a matching action"));
    assert!(String::from_utf8_lossy(&select(&valid).unwrap().bytes)
        .contains("no authorized action fits"));
    rejects_unreadable(&base, &["goal", "verb", "types", "want"], select);
    let err = select(&base.with_arg("verb", inline("bogus"))).unwrap_err();
    assert!(matches!(err, Error::InvalidArgument { name, .. } if name == "verb"));

    let aliases = |req: &Request| {
        block_on(LispAliases.invoke(&Invocation::with_issuer(req, &bindings, &cap, &kernel)))
    };
    let base = request("urn:lisp:aliases");
    assert_eq!(
        aliases(&base).unwrap().repr_type.to_string(),
        "text/x-scheme"
    );
    let valid = base
        .clone()
        .with_arg("prefix", inline("urn:test:"))
        .with_arg("as", inline("text/x-emacs-lisp"));
    assert_eq!(
        aliases(&valid).unwrap().repr_type.to_string(),
        "text/x-emacs-lisp"
    );
    rejects_unreadable(&base, &["prefix", "as"], aliases);
}

#[test]
fn unreadable_ledger_filters_do_not_return_the_whole_ledger() {
    let base = request("urn:people");
    let people = people::PeopleLedger {
        path: PathBuf::new(),
    };
    let issue = |req: &Request| detached(&people, req);
    assert!(issue(&base).is_ok());
    assert!(issue(
        &base
            .clone()
            .with_arg("email", inline("person@example.test"))
    )
    .is_ok());
    rejects_unreadable(&base, &["email"], issue);

    let decisions = decisions::DecisionLog {
        path: PathBuf::new(),
    };
    let issue = |req: &Request| detached(&decisions, req);
    let base = request("urn:decisions");
    assert!(issue(&base).is_ok());
    assert!(issue(&base.clone().with_arg("action", inline("block"))).is_ok());
    let membership = base
        .clone()
        .with_arg("blocked", inline("person@example.test"));
    assert_eq!(issue(&membership).unwrap().bytes, b"no");
    rejects_unreadable(&base, &["blocked", "action"], issue);
}

#[test]
fn signed_link_pages_do_not_treat_unreadable_query_or_body_values_as_missing() {
    // A valid outcome page bypasses the key read. With no outcome, the existing confirm
    // path tries to load the key. Unreadable input must not take either route.
    let pages: [(&str, Box<dyn Endpoint>); 3] = [
        (
            "urn:calendar-request:approve",
            Box::new(decide::CalendarRequest {
                key_path: PathBuf::new(),
            }),
        ),
        (
            "urn:contact-block",
            Box::new(contactblock::ContactBlock {
                key_path: PathBuf::new(),
            }),
        ),
        (
            "urn:contact-label",
            Box::new(contactblock::ContactLabel {
                key_path: PathBuf::new(),
            }),
        ),
    ];
    for (iri, page) in pages {
        let base = request(iri);
        let issue = |req: &Request| detached(page.as_ref(), req);
        assert!(matches!(issue(&base), Err(Error::Endpoint(_))));
        let valid = base.clone().with_arg("outcome", inline("recorded"));
        assert!(issue(&valid)
            .unwrap()
            .repr_type
            .to_string()
            .starts_with("text/html"));
        rejects_unreadable(&base, &["outcome", "content"], issue);
    }
}

#[test]
fn a_form_body_is_used_only_after_a_readable_query_lookup() {
    let bindings = Bindings::new();
    let cap = Capability::root();
    let base = Request::new(Verb::Sink, Iri::parse("urn:test:form").unwrap());
    let issue = |req: &Request| decide::param(&Invocation::detached(req, &bindings, &cap), "email");

    assert_eq!(issue(&base).unwrap(), "");
    let form = base.with_arg("content", inline("email=form%40example.test"));
    assert_eq!(issue(&form).unwrap(), "form@example.test");
    let query = form.clone().with_arg("email", inline("query@example.test"));
    assert_eq!(issue(&query).unwrap(), "query@example.test");
    let unreadable_body = query.with_arg("content", ArgRef::Inline(vec![0xff]));
    let err = issue(&unreadable_body).unwrap_err();
    assert!(matches!(err, Error::InvalidArgument { name, .. } if name == "content"));

    let unreadable = form.with_arg("email", ArgRef::Inline(vec![0xff]));
    let err = issue(&unreadable).unwrap_err();
    assert!(matches!(err, Error::InvalidArgument { name, .. } if name == "email"));
}
