//! ★ **SPARQL in THIS host never leaves the process** — `SERVICE` and `LOAD` refused at every
//! door that evaluates caller text, with nothing reaching the network (ledger #1083).
//!
//! # Why it has to be tested HERE and not only in the module crates
//!
//! oxigraph's `SparqlEvaluator` installs an HTTP service handler whenever `oxigraph/http-client`
//! is on, and this workspace turns it on without asking for it: `ikigai-shacl` → `shacl` →
//! `rudof_rdf`, which enables oxigraph's `http-client-rustls-native` on every native target,
//! and Cargo unifies features across the whole graph. So in THIS build — not in
//! `ikigai-sparql`'s or `ikigai-store`'s own default builds, where the feature is off and
//! the hole cannot be seen — `SERVICE <http://…>` in a caller's query was an outbound
//! request with no `urn:cap:net:*` anywhere near it. `just … egress-drift` reports the
//! feature as ON for this repo, and it stays on after the fix: what changed is that every
//! evaluator this host reaches refuses.
//!
//! The instrument is a loopback stub that counts connections ([`support::egress_stub`]); the
//! assertion is ZERO connections and a typed `InvalidArgument` naming the input, at each
//! door, for each shape (`SILENT`, inside `EXISTS`, in an update's `WHERE`, `LOAD`).
//!
//! ★ Measured before the fix: against ikigai-sparql 0.1.11 / ikigai-store 0.2.7 (the pins
//! cli 0.1.44 shipped) every `SERVICE` and `LOAD` case at `urn:sparql:*` and `urn:iki:store:*`
//! REACHED the stub, and most of them answered with its rows. That includes `LOAD` at
//! `urn:iki:store:update`, which an earlier note said 0.2.7 already refused at the door: in this
//! build it did not.
//! ikigai-sparql 0.2.1 and ikigai-store 0.2.10 are the floors that make this file pass.
//!
//! The tuple space's `match=` (`ikigai-intray`, which builds its own evaluator) is walked here
//! too; since ledger #1085 it evaluates through `ikigai_store::service`, the store's own helpers.
//! So is `urn:shacl:validate`, whose SHACL-SPARQL rudof evaluates with the same client (ledger
//! #1099): ikigai-shacl 0.3.2 is its floor, and every case there reached the stub on 0.3.1.
//!
//! This binary is the DEFAULT regime: no `browse.root`, so `urn:sparql:*` is
//! `ikigai_sparql::space()` (a private per-query store, no update door). With the `store`
//! feature on (CI runs `--all-features`) it also walks the durable store's doors. The
//! shared-store regime, where `urn:sparql:update` exists, is `tests/egress_shared.rs`.
//!
//! ⚠ `cfg(test)` does not reach a `tests/` binary, so the hermetic redirect is a CALL —
//! `HOME`, `XDG_CONFIG_HOME` and `set_file_root` before the first kernel is built.

#[path = "support/egress_stub.rs"]
mod egress_stub;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use egress_stub::{Stub, LEAK_MARKER};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};

fn fixture_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("ikigai-embedded-egress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
        #[cfg(feature = "store")]
        ikigai_embedded::store::set_store_path(dir.join("store"));
        dir
    })
    .as_path()
}

fn kernel() -> &'static Kernel {
    static KERNEL: OnceLock<Kernel> = OnceLock::new();
    KERNEL.get_or_init(|| {
        fixture_home();
        ikigai_embedded::kernel()
    })
}

/// One door, one shape: the verb, the IRI, the input that carries the text, and the text.
struct Case {
    verb: Verb,
    iri: &'static str,
    input: &'static str,
    text: String,
}

/// Issue every case under ROOT (the strongest caller: if root cannot reach the network,
/// no grant can) and return one line per case that leaked or did not refuse as expected.
fn walk(stub: &Stub, cases: Vec<Case>) -> Vec<String> {
    let mut failures = Vec::new();
    for case in cases {
        let before = stub.hits();
        let request = Request::new(case.verb, Iri::parse(case.iri).expect("a door IRI"))
            .with_arg(case.input, ArgRef::Inline(case.text.clone().into_bytes()));
        let answer = block_on(kernel().issue(request, &Capability::root()));
        let reached = stub.hits() - before;
        let what = format!("{:?} {} {}", case.verb, case.iri, case.text);
        if reached != 0 {
            failures.push(format!("{what}: REACHED the stub {reached} time(s)"));
        }
        match answer {
            Err(Error::InvalidArgument { name, .. }) if name == case.input => {}
            Err(other) => failures.push(format!(
                "{what}: refused, but not as InvalidArgument naming `{}`: {other:?}",
                case.input
            )),
            Ok(repr) => {
                let body = String::from_utf8_lossy(&repr.bytes);
                let leaked = if body.contains(LEAK_MARKER) {
                    " — and the answer carries the stub's rows"
                } else {
                    ""
                };
                failures.push(format!("{what}: ANSWERED instead of refusing{leaked}"));
            }
        }
    }
    failures
}

/// The four query forms with `SERVICE` in each shape oxigraph would federate.
fn service_queries(stub: &Stub, iri_of: fn(&str) -> &'static str) -> Vec<Case> {
    let svc = stub.url("/sparql");
    [
        ("select", format!("SELECT * WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}")),
        ("select", format!("SELECT * WHERE {{ SERVICE SILENT <{svc}> {{ ?s ?p ?o }} }}")),
        (
            "select",
            format!("SELECT ?x WHERE {{ BIND(1 AS ?x) FILTER EXISTS {{ SERVICE <{svc}> {{ ?s ?p ?o }} }} }}"),
        ),
        ("ask", format!("ASK {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}")),
        (
            "construct",
            format!("CONSTRUCT {{ ?s ?p ?o }} WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}"),
        ),
        ("describe", format!("DESCRIBE ?s WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}")),
    ]
    .into_iter()
    .map(|(form, text)| Case {
        verb: Verb::Source,
        iri: iri_of(form),
        input: "query",
        text,
    })
    .collect()
}

/// `urn:sparql:*`, as this host binds it with no browse store: `ikigai_sparql::space()`.
#[test]
fn the_sparql_doors_refuse_service_and_nothing_reaches_the_network() {
    let stub = Stub::start();
    let cases = service_queries(&stub, |form| match form {
        "select" => "urn:sparql:select",
        "ask" => "urn:sparql:ask",
        "construct" => "urn:sparql:construct",
        _ => "urn:sparql:describe",
    });
    let failures = walk(&stub, cases);
    assert!(
        failures.is_empty() && stub.hits() == 0,
        "SPARQL egress through urn:sparql:* ({} connection(s) reached the stub):\n{}",
        stub.hits(),
        failures.join("\n")
    );
}

/// `urn:iki:store:*`, the durable store this host binds behind the `store` feature: the
/// query forms, an update whose `WHERE` federates, and `LOAD` in both spellings.
#[cfg(feature = "store")]
#[test]
fn the_store_doors_refuse_service_and_load_and_nothing_reaches_the_network() {
    let stub = Stub::start();
    let mut cases = service_queries(&stub, |form| match form {
        "select" => "urn:iki:store:select",
        "ask" => "urn:iki:store:ask",
        "construct" => "urn:iki:store:construct",
        _ => "urn:iki:store:describe",
    });
    let svc = stub.url("/sparql");
    let doc = stub.url("/data.ttl");
    for text in [
        format!("INSERT {{ GRAPH <urn:test:g> {{ ?s ?p ?o }} }} WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}"),
        format!("LOAD <{doc}>"),
        format!("LOAD SILENT <{doc}> INTO GRAPH <urn:test:g>"),
    ] {
        cases.push(Case {
            verb: Verb::Sink,
            iri: "urn:iki:store:update",
            input: "content",
            text,
        });
    }
    let failures = walk(&stub, cases);
    assert!(
        failures.is_empty() && stub.hits() == 0,
        "SPARQL egress through urn:iki:store:* ({} connection(s) reached the stub):\n{}",
        stub.hits(),
        failures.join("\n")
    );
}

/// `urn:space:{name}`, the tuple space (`ikigai-intray`): a `match=` template is the one
/// SPARQL in that crate, evaluated against each tuple's graph. Read (`Source`) and take
/// (`Delete`) both evaluate it, so both are walked, over a space holding one RDF tuple so the
/// template really is evaluated rather than skipped for want of a tuple. ★ Measured before the
/// move to `ikigai_store::service` (ledger #1085): this already passed, because intray carried
/// its own copy of the walk and the refusing handler since ledger #877; the test pins that the
/// move kept it.
#[test]
fn the_tuple_space_refuses_service_in_a_match_and_nothing_reaches_the_network() {
    let stub = Stub::start();
    let drop = Request::new(
        Verb::Sink,
        Iri::parse("urn:space:egress").expect("a space IRI"),
    )
    .with_arg(
        "content",
        ArgRef::Inline(b"<urn:t:a> <urn:t:b> \"c\" .".to_vec()),
    );
    block_on(kernel().issue(drop, &Capability::root())).expect("a tuple drops");
    let svc = stub.url("/sparql");
    let mut cases = Vec::new();
    for verb in [Verb::Source, Verb::Delete] {
        for text in [
            format!("ASK {{ ?s ?p ?o . SERVICE <{svc}> {{ ?x ?y ?o }} }}"),
            format!("ASK {{ FILTER EXISTS {{ SERVICE SILENT <{svc}> {{ ?s ?p ?o }} }} }}"),
        ] {
            cases.push(Case {
                verb,
                iri: "urn:space:egress",
                input: "match",
                text,
            });
        }
    }
    let failures = walk(&stub, cases);
    assert!(
        failures.is_empty() && stub.hits() == 0,
        "SPARQL egress through urn:space:* ({} connection(s) reached the stub):\n{}",
        stub.hits(),
        failures.join("\n")
    );
}

/// The shapes-graph prelude every `urn:shacl:validate` case below shares.
const SHACL_HEAD: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n\
                          @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\
                          @prefix ex: <http://example.org/> .\n";

/// A data graph with one `ex:Person`, so a shape targeting the class has a focus node and rudof
/// really evaluates its `sh:select` (once per focus node).
const SHACL_DATA: &str = "@prefix ex: <http://example.org/> .\nex:a a ex:Person ; ex:p ex:b .\n";

/// A node shape on `ex:Person` with one `sh:sparql` whose `sh:select` is `select`.
fn shacl_select_shape(select: &str) -> String {
    format!(
        "{SHACL_HEAD}ex:S a sh:NodeShape ; sh:targetClass ex:Person ;\n  \
         sh:sparql [ sh:select \"\"\"{select}\"\"\" ] .\n"
    )
}

/// `text` with every character a SPARQL `IRIREF` forbids written as a Turtle `\uXXXX` escape,
/// so it survives rudof's lenient Turtle reader into an IRI term (as in ikigai-shacl's own test).
fn shacl_escaped_iri(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\' | '\0'..=' ' => {
                format!("\\u{:04X}", c as u32)
            }
            c => c.to_string(),
        })
        .collect()
}

/// `urn:shacl:validate`, as this host binds it (`ikigai_shacl::space()` in the embedded root,
/// no `requires`): a SHACL-SPARQL `sh:select` that federates, and an IRI that breaks out of the
/// `VALUES ?this { … }` rudof splices a focus node into. Each must make ZERO connections to the
/// stub and be refused as a typed `InvalidArgument` naming the graph that carried it
/// (ledger #1099).
///
/// ★ Measured before the fix: on ikigai-shacl 0.3.1 (the pin cli 0.1.45 merged with) every case
/// here REACHED the stub. ikigai-shacl 0.3.2 is the floor that makes this pass: it parses every
/// query rudof will run and refuses `SERVICE` before rudof sees it, and refuses any IRI no
/// SPARQL query can hold. rudof builds its evaluator privately, so that pre-check is the only
/// guard there is; this host cannot install a refusing service handler of its own.
#[test]
fn the_shacl_door_refuses_sparql_service_and_nothing_reaches_the_network() {
    let stub = Stub::start();
    let svc = stub.url("/sparql");
    let service = format!("SERVICE <{svc}> {{ ?s ?p ?o }}");
    let breakout = shacl_escaped_iri(&format!(
        "http://example.org/x> }} {service} VALUES ?q {{ <http://example.org/y"
    ));
    // (what, data, shapes, the input the refusal must name)
    let cases: Vec<(&str, String, String, &str)> = vec![
        (
            "sh:select with SERVICE",
            SHACL_DATA.to_string(),
            shacl_select_shape(&format!(
                "SELECT $this WHERE {{ $this a ?t . {service} }}"
            )),
            "shapes",
        ),
        (
            "sh:select with SERVICE SILENT",
            SHACL_DATA.to_string(),
            shacl_select_shape(&format!(
                "SELECT $this WHERE {{ $this a ?t . SERVICE SILENT <{svc}> {{ ?s ?p ?o }} }}"
            )),
            "shapes",
        ),
        (
            "SERVICE hidden in an sh:declare prefix name",
            SHACL_DATA.to_string(),
            format!(
                "{SHACL_HEAD}ex:S a sh:NodeShape ; sh:targetClass ex:Person ;\n  \
                 sh:sparql [ sh:prefixes ex:decls ; sh:select \"# nothing\" ] .\n\
                 ex:decls sh:declare [ sh:prefix \"\"\"a: <http://example.org/a/> SELECT $this WHERE {{ {service} }} #\"\"\" ;\n  \
                 sh:namespace \"http://example.org/b/\"^^xsd:anyURI ] .\n"
            ),
            "shapes",
        ),
        (
            "a data literal whose datatype IRI breaks out of VALUES",
            format!("@prefix ex: <http://example.org/> .\nex:a ex:p \"v\"^^<{breakout}> .\n"),
            format!(
                "{SHACL_HEAD}ex:S a sh:NodeShape ; sh:targetObjectsOf ex:p ;\n  \
                 sh:sparql [ sh:select \"\"\"SELECT $this WHERE {{ OPTIONAL {{ ?s ?p $this }} }}\"\"\" ] .\n"
            ),
            "data",
        ),
    ];
    let mut failures = Vec::new();
    for (what, data, shapes, input) in cases {
        let before = stub.hits();
        let request = Request::new(
            Verb::Source,
            Iri::parse("urn:shacl:validate").expect("the door IRI"),
        )
        .with_arg("data", ArgRef::Inline(data.into_bytes()))
        .with_arg("shapes", ArgRef::Inline(shapes.into_bytes()));
        let answer = block_on(kernel().issue(request, &Capability::root()));
        let reached = stub.hits() - before;
        if reached != 0 {
            failures.push(format!("{what}: REACHED the stub {reached} time(s)"));
        }
        match answer {
            Err(Error::InvalidArgument { name, .. }) if name == input => {}
            Err(other) => failures.push(format!(
                "{what}: refused, but not as InvalidArgument naming `{input}`: {other:?}"
            )),
            Ok(_) => failures.push(format!("{what}: ANSWERED a report instead of refusing")),
        }
    }
    assert!(
        failures.is_empty() && stub.hits() == 0,
        "SHACL-SPARQL egress through urn:shacl:validate ({} connection(s) reached the stub):\n{}",
        stub.hits(),
        failures.join("\n")
    );
}

/// ★ The instrument works: the stub really answers an HTTP client, so a zero count above
/// means nothing called, not that the stub was unreachable.
#[test]
fn the_stub_counts_a_real_request() {
    use std::io::{Read, Write};
    let stub = Stub::start();
    let mut stream =
        std::net::TcpStream::connect(stub.url("").trim_start_matches("http://")).expect("connect");
    write!(stream, "GET /data.ttl HTTP/1.1\r\nHost: x\r\n\r\n").expect("a request");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("an answer");
    assert!(answer.contains(LEAK_MARKER), "{answer}");
    assert_eq!(stub.hits(), 1);
}
