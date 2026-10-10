//! Audit round 5, root cause 1 (ledger #877): a `match=` ASK carrying `SERVICE <http://…>`
//! made the host open an outbound connection under nothing but `urn:cap:space:read` (rd) or
//! `urn:cap:space:take` (take). oxigraph's HTTP client is on in the host build by feature
//! unification (rudof enables it), and this crate's dev-dependency turns it on here too, so
//! these tests guard the shipping configuration, not a quieter one.

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Kernel, Request, Verb};
use ikigai_intray::{space, CAP_OUT, CAP_READ, CAP_TAKE};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A local SPARQL "endpoint" that counts the connections it is offered (answering each with
/// an empty result set, so a request that does arrive completes rather than hangs).
struct Listener {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Listener {
    fn start() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        l.set_nonblocking(true).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (h, s) = (Arc::clone(&hits), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((mut conn, _)) => {
                        h.fetch_add(1, Ordering::SeqCst);
                        let _ = conn.set_nonblocking(false);
                        let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut buf = [0u8; 4096];
                        let _ = conn.read(&mut buf);
                        let body = r#"{"head":{"vars":["s","p","o"]},"results":{"bindings":[]}}"#;
                        let _ = write!(
                            conn,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/sparql-results+json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Listener {
            port,
            hits,
            stop,
            thread: Some(thread),
        }
    }

    /// The connections seen, after giving a late one time to arrive.
    fn hits_after_settling(mut self) -> usize {
        std::thread::sleep(Duration::from_millis(300));
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
        self.hits.load(Ordering::SeqCst)
    }
}

/// The refusal names `match`, says `SERVICE`, gives the intray's own remedy and never the
/// store's (`urn:iki:store:load` means nothing to a match; ledger #1108).
fn is_match_refusal(r: &Result<ikigai_core::Representation, Error>) -> bool {
    matches!(r, Err(Error::InvalidArgument { name, detail })
        if name == "match"
            && detail.contains("SERVICE")
            && detail.contains("never leaves this host")
            && !detail.contains("urn:iki:store:load"))
}

#[test]
fn rd_refuses_a_match_with_service_and_opens_no_connection() {
    let k = Kernel::new(Arc::new(space(scratch("svc-rd"))));
    let listener = Listener::start();
    let ask = format!(
        "ASK {{ SERVICE <http://127.0.0.1:{}/sparql> {{ ?s ?p ?o }} }}",
        listener.port
    );
    let r = block_on(
        k.issue(
            Request::new(Verb::Source, iri("urn:space:empty"))
                .with_arg("match", ArgRef::Inline(ask.into_bytes())),
            &Capability::scoped([CAP_READ]),
        ),
    );
    let hits = listener.hits_after_settling();
    assert_eq!(
        hits, 0,
        "rd under only {CAP_READ} opened a connection ({r:?})"
    );
    assert!(
        is_match_refusal(&r),
        "a SERVICE match is refused as such: {r:?}"
    );
}

#[test]
fn take_refuses_a_match_with_service_and_keeps_the_tuple() {
    let root = scratch("svc-take");
    let k = Kernel::new(Arc::new(space(root)));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:q",
        b"<urn:a> <urn:secret> \"hunter2\" .",
    )
    .unwrap();
    let listener = Listener::start();
    let ask = format!(
        "ASK {{ ?s <urn:secret> ?o . SERVICE <http://127.0.0.1:{}/sparql> {{ ?x ?y ?o }} }}",
        listener.port
    );
    let r = block_on(
        k.issue(
            Request::new(Verb::Delete, iri("urn:space:q"))
                .with_arg("match", ArgRef::Inline(ask.into_bytes())),
            &Capability::scoped([CAP_TAKE]),
        ),
    );
    let hits = listener.hits_after_settling();
    assert_eq!(
        hits, 0,
        "take under only {CAP_TAKE} opened a connection ({r:?})"
    );
    assert!(
        is_match_refusal(&r),
        "a SERVICE match is refused as such: {r:?}"
    );
    let left = block_on(k.issue(
        Request::new(Verb::Source, iri("urn:space:q")),
        &Capability::scoped([CAP_READ]),
    ))
    .unwrap();
    assert_eq!(
        String::from_utf8(left.bytes).unwrap(),
        id,
        "nothing was taken"
    );
}

/// The check walks the ALGEBRA: a SERVICE hidden in a `FILTER EXISTS`, under an `OPTIONAL`,
/// in a `MINUS`, or in a sub-select is refused like a top-level one.
#[test]
fn a_nested_service_is_refused_wherever_it_hides() {
    let k = Kernel::new(Arc::new(space(scratch("svc-nested"))));
    let cap = Capability::scoped([CAP_READ]);
    let listener = Listener::start();
    let svc = format!(
        "SERVICE <http://127.0.0.1:{}/sparql> {{ ?a ?b ?c }}",
        listener.port
    );
    let queries = [
        format!("ASK {{ ?s ?p ?o FILTER EXISTS {{ {svc} }} }}"),
        format!("ASK {{ ?s ?p ?o FILTER (?o = 1 || NOT EXISTS {{ {svc} }}) }}"),
        format!("ASK {{ ?s ?p ?o OPTIONAL {{ {svc} }} }}"),
        format!("ASK {{ ?s ?p ?o MINUS {{ {svc} }} }}"),
        format!("ASK {{ {{ SELECT ?s WHERE {{ {svc} }} }} }}"),
        format!("ASK {{ {{ ?s ?p ?o }} UNION {{ GRAPH <urn:g> {{ {svc} }} }} }}"),
        format!("ASK {{ ?s ?p ?o BIND (EXISTS {{ {svc} }} AS ?x) }}"),
        "ASK { SERVICE SILENT ?endpoint { ?s ?p ?o } }".to_string(),
    ];
    for q in queries {
        let r = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:empty"))
                    .with_arg("match", ArgRef::Inline(q.clone().into_bytes())),
                &cap,
            ),
        );
        assert!(is_match_refusal(&r), "{q}\n  was not refused: {r:?}");
    }
    assert_eq!(listener.hits_after_settling(), 0);
}

/// And it walks the algebra rather than the TEXT: the word in a string literal, an IRI, or a
/// comment is not a SERVICE clause and must not be refused.
#[test]
fn the_word_service_outside_a_service_clause_is_not_refused() {
    let k = Kernel::new(Arc::new(space(scratch("svc-text"))));
    let both = Capability::scoped([CAP_OUT, CAP_READ]);
    let id = drop_tuple(
        &k,
        &both,
        "urn:space:t",
        b"<urn:a> <urn:says> \"SERVICE <http://x/>\" .",
    )
    .unwrap();
    for q in [
        "ASK { ?s <urn:says> \"SERVICE <http://x/>\" }",
        "ASK { ?s <urn:says> ?o } # SERVICE <http://x/> { }",
    ] {
        let r = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:t"))
                    .with_arg("match", ArgRef::Inline(q.as_bytes().to_vec())),
                &both,
            ),
        )
        .unwrap_or_else(|e| panic!("{q} was refused: {e:?}"));
        assert_eq!(
            String::from_utf8(r.bytes).unwrap(),
            id,
            "{q} matches the tuple"
        );
    }
}
