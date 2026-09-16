//! Browse reads are confined to the graph browse writes — stated over THIS host's
//! composition, not over a private store.
//!
//! The confinement itself belongs to `ikigai-browse` 0.4.0 and is tested there. What is
//! only visible from here is the condition that makes it matter: this host hands ONE
//! `Arc<Store>` to browse and to `urn:sparql:*` alike, and before browse ever writes a
//! quad `browse::setup` loads the bundled vocabulary into the NAMED graph
//! `urn:ikigai:vocab` in that same store (`ikigai_sparql::load_vocabulary`). Through
//! 0.3.2 every browse read passed `None` for the graph — which in `quads_for_pattern`
//! means EVERY graph — so browse's annotation reads have been scanning another writer's
//! graph in production. Nothing matched, because no vocabulary subject is an
//! `oa:Annotation`; that is luck about the data, not a property of the code.
//!
//! So the test plants a decoy that IS shaped like an annotation, in exactly the graph
//! this host really writes, and asserts browse does not answer out of it. The decoy has
//! to be planted before the kernel exists: RocksDB admits one writer per directory, and
//! the host holds it for the life of the process.
//!
//! ★ Measured against 0.3.2 before the bump (this file, run on the pre-bump tree): all
//! three assertions fail, and the third failure is the one worth writing down. The
//! cross-graph exposure was not only a read — a plain `Source` of
//! `urn:repo:demo:annotations` re-anchored the decoy and PERSISTED it, so the quads left
//! `urn:ikigai:vocab` and landed in browse's default graph. A `GRAPH <urn:ikigai:vocab>`
//! ASK went true → false across one read, with the default graph true afterwards. Under
//! 0.3.2 a read of this host's annotations was a write into another writer's graph; under
//! 0.4.0 it cannot see that graph to begin with.
//!
//! ⚠ `cfg(test)` does not reach a `tests/` binary, so the hermetic redirect is a CALL —
//! `HOME`, `XDG_CONFIG_HOME` and `set_file_root` before the first kernel is built.
//! Without it this would open the developer's own `~/.ikigai/browse-store` and fail for a
//! reason that has nothing to do with the code.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_sparql::Store;
use oxigraph::model::{Literal, NamedNode, Quad, Term};

/// The graph the decoy sits in: the one this host's `browse::setup` really writes, on
/// every start. Named from the vocab crate rather than spelled out, so a rename of the
/// vocabulary graph moves this test with it instead of quietly making it a test about
/// nothing.
fn vocab_graph() -> NamedNode {
    NamedNode::new(ikigai_vocab::VOCAB_IRI).expect("the vocabulary graph IRI")
}

fn oa(term: &str) -> NamedNode {
    NamedNode::new(format!("http://www.w3.org/ns/oa#{term}")).expect("an oa term")
}

fn ik(term: &str) -> NamedNode {
    NamedNode::new(format!("https://ikigai-rs.dev/ns#{term}")).expect("an ik term")
}

/// The scratch home, the browse config, and the one root the family serves. Returns the
/// scratch root.
fn fixture_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("ikigai-embedded-browse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::fs::create_dir_all(dir.join("demo")).expect("the browse root");
        std::fs::write(dir.join("demo/a.rs"), "fn one() {}\nfn two() {}\n").expect("a file");
        // Unscoped lines: this binary is one process and the default instance ("repl").
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

/// The one kernel this binary builds — `OnceLock` because the browse store is opened once
/// per PROCESS and held.
fn kernel() -> &'static Kernel {
    static KERNEL: OnceLock<Kernel> = OnceLock::new();
    KERNEL.get_or_init(|| {
        plant_the_decoy();
        ikigai_embedded::kernel()
    })
}

/// A quad set shaped exactly like one of browse's own annotations — same type, same
/// predicates, same repo and path — written into the vocabulary graph while nobody holds
/// the store. Anything that reads across graphs finds it.
fn plant_the_decoy() {
    let dir = fixture_home().join("browse-store");
    let store = Store::open(&dir).expect("the scratch browse store");
    let decoy = NamedNode::new("urn:iki:annotation:theirs").expect("the decoy IRI");
    for (predicate, object) in [
        (
            NamedNode::new("http://www.w3.org/1999/02/22-rdf-syntax-ns#type").unwrap(),
            Term::NamedNode(oa("Annotation")),
        ),
        (
            oa("bodyValue"),
            Term::Literal(Literal::new_simple_literal("not ours")),
        ),
        (
            ik("repo"),
            Term::Literal(Literal::new_simple_literal("demo")),
        ),
        (
            ik("path"),
            Term::Literal(Literal::new_simple_literal("a.rs")),
        ),
        (
            ik("annotates"),
            Term::NamedNode(NamedNode::new("urn:repo:demo:file:a.rs").unwrap()),
        ),
    ] {
        store
            .insert(Quad::new(decoy.clone(), predicate, object, vocab_graph()).as_ref())
            .expect("planting the decoy");
    }
    store.flush().expect("flush before the host takes the lock");
    drop(store); // release the directory: the host opens it next.
}

fn issue(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Result<String, Error> {
    let request = args.iter().fold(
        Request::new(verb, Iri::parse(iri).expect("a test IRI")),
        |request, (name, value)| request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec())),
    );
    block_on(kernel().issue(request, &Capability::root()))
        .map(|repr| String::from_utf8_lossy(&repr.bytes).into_owned())
}

fn root(verb: Verb, iri: &str, args: &[(&str, &str)]) -> String {
    issue(verb, iri, args).unwrap_or_else(|e| panic!("{verb:?} {iri} failed: {e}"))
}

/// ★ The decoy is really there, and this host can see it — through SPARQL, over the same
/// `Arc<Store>` browse holds. Without this the confinement assertions below would pass
/// just as happily against an empty store, which is the shape a negative test fails in.
#[test]
fn the_decoy_is_in_this_hosts_shared_dataset() {
    let answer = root(
        Verb::Source,
        "urn:sparql:ask",
        &[(
            "query",
            &format!(
                "ASK {{ GRAPH <{}> {{ <urn:iki:annotation:theirs> a <http://www.w3.org/ns/oa#Annotation> }} }}",
                ikigai_vocab::VOCAB_IRI
            ),
        )],
    );
    assert!(
        answer.contains("true"),
        "the planted decoy is not in the dataset, so the confinement tests below prove \
         nothing: {answer}"
    );
}

/// The file-scoped listing answers out of browse's own graph only. Both halves matter:
/// the host's own annotation is listed (so the read path works and the assertion is not
/// vacuous), and the decoy in the vocabulary graph is not.
#[test]
fn an_annotation_listing_does_not_reach_into_the_vocabulary_graph() {
    root(
        Verb::Sink,
        "urn:iki:annotation:mine",
        &[
            ("target", "urn:repo:demo:file:a.rs"),
            ("exact", "fn one()"),
            ("body", "the default graph's own"),
            ("as", "application/json"),
        ],
    );
    let listed = root(Verb::Source, "urn:repo:demo:annotations", &[]);
    assert!(
        listed.contains("urn:iki:annotation:mine"),
        "this host's own annotation is missing from its own listing: {listed}"
    );
    assert!(
        !listed.contains("urn:iki:annotation:theirs"),
        "a browse read reached into <{}>, the graph this host loads the vocabulary into: \
         {listed}",
        ikigai_vocab::VOCAB_IRI
    );
}

/// And by id: the decoy does not resolve, because browse never looks in that graph. Not
/// `Denied` and not a body — `NotFound`, the same answer an id nobody ever minted gets.
#[test]
fn reading_the_decoy_by_id_is_not_found() {
    let error = issue(Verb::Source, "urn:iki:annotation:theirs", &[])
        .expect_err("an annotation in another graph does not resolve");
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");
}
