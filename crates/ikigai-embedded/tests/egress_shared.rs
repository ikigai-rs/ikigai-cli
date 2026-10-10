//! ★ The shared-store regime of `tests/egress.rs`: with a `browse.root` configured this host
//! binds `ikigai_sparql::space_with_store` over browse's `Arc<Store>`, which is the regime
//! where `urn:sparql:update` exists — so it is the one place `LOAD <http://…>` and an update
//! whose `WHERE` federates can be sent through `urn:sparql:*` (ledger #1083).
//!
//! Same instrument, same assertion: a loopback stub that counts connections, zero
//! connections, and a typed `InvalidArgument` naming the input. See `tests/egress.rs` for
//! why this must be measured in the host build rather than in the module crate.
//!
//! ★ Measured before the fix (ikigai-sparql 0.1.11): every case below reached the stub.
//!
//! ⚠ `cfg(test)` does not reach a `tests/` binary, so the hermetic redirect is a CALL, and
//! the browse store is opened once per PROCESS, hence the `OnceLock` kernel.

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
        let dir = std::env::temp_dir().join(format!(
            "ikigai-embedded-egress-shared-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::fs::create_dir_all(dir.join("demo")).expect("the browse root");
        std::fs::write(dir.join("demo/a.rs"), "fn one() {}\n").expect("a file");
        std::fs::write(
            dir.join("config/ikigai/config.toml"),
            format!(
                "browse.root = \"{}\"\nbrowse.store = \"{}\"\n",
                dir.join("demo").display(),
                dir.join("browse-store").display()
            ),
        )
        .expect("the browse config");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
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

/// The regime really is the shared one: `urn:sparql:update` is bound only by
/// `space_with_store`. Without this the test below could pass against the default regime,
/// where the update door does not exist and every update case is `Unresolved`.
#[test]
fn this_binary_runs_the_shared_store_regime() {
    assert!(
        kernel()
            .entries()
            .expect("an enumerable root")
            .iter()
            .any(|e| e.pattern == "urn:sparql:update"),
        "urn:sparql:update is not bound: browse.root did not take, so this is not the \
         shared-store regime"
    );
}

#[test]
fn the_shared_sparql_doors_refuse_service_and_load_and_nothing_reaches_the_network() {
    let stub = Stub::start();
    let svc = stub.url("/sparql");
    let doc = stub.url("/data.ttl");
    let cases: Vec<(Verb, &str, &str, String)> = vec![
        (
            Verb::Source,
            "urn:sparql:select",
            "query",
            format!("SELECT * WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}"),
        ),
        (
            Verb::Source,
            "urn:sparql:select",
            "query",
            format!("SELECT * WHERE {{ SERVICE SILENT <{svc}> {{ ?s ?p ?o }} }}"),
        ),
        (
            Verb::Source,
            "urn:sparql:ask",
            "query",
            format!("ASK {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}"),
        ),
        (
            Verb::Sink,
            "urn:sparql:update",
            "content",
            format!("INSERT {{ GRAPH <urn:test:g> {{ ?s ?p ?o }} }} WHERE {{ SERVICE <{svc}> {{ ?s ?p ?o }} }}"),
        ),
        (Verb::Sink, "urn:sparql:update", "content", format!("LOAD <{doc}>")),
        (
            Verb::Sink,
            "urn:sparql:update",
            "content",
            format!("LOAD SILENT <{doc}> INTO GRAPH <urn:test:g>"),
        ),
    ];
    let mut failures = Vec::new();
    for (verb, iri, input, text) in cases {
        let before = stub.hits();
        let request = Request::new(verb, Iri::parse(iri).expect("a door IRI"))
            .with_arg(input, ArgRef::Inline(text.clone().into_bytes()));
        let answer = block_on(kernel().issue(request, &Capability::root()));
        let reached = stub.hits() - before;
        let what = format!("{verb:?} {iri} {text}");
        if reached != 0 {
            failures.push(format!("{what}: REACHED the stub {reached} time(s)"));
        }
        match answer {
            Err(Error::InvalidArgument { name, .. }) if name == input => {}
            Err(other) => failures.push(format!(
                "{what}: refused, but not as InvalidArgument naming `{input}`: {other:?}"
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
    // A LOAD that got through wrote the stub's triple into browse's store: say so too.
    let planted = block_on(kernel().issue(
        Request::new(Verb::Source, Iri::parse("urn:sparql:ask").expect("ask")).with_arg(
            "query",
            ArgRef::Inline(
                // A query's default graph is the union of every graph in the shared store.
                format!("ASK {{ ?s ?p \"{LEAK_MARKER}\" }}").into_bytes(),
            ),
        ),
        &Capability::root(),
    ))
    .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
    .unwrap_or_default();
    if planted.contains("true") {
        failures.push("the stub's triple is now IN this host's shared store".into());
    }
    assert!(
        failures.is_empty() && stub.hits() == 0,
        "SPARQL egress through the shared urn:sparql:* ({} connection(s) reached the stub):\n{}",
        stub.hits(),
        failures.join("\n")
    );
}
