//! The durable store as this host binds it: one dataset, held by this process, reachable
//! through the composed kernel — and refused to anybody else while we hold it.
//!
//! ⚠ `cfg(test)` does not reach a `tests/` binary, so the hermetic redirect here is a
//! CALL: [`ikigai_embedded::store::set_store_path`] before the first kernel is built.
//! Without it these tests would open the developer's own `~/.ikigai/store` — and on a
//! machine where an `ikigai` is already running, fail for a reason that has nothing to do
//! with the code.
//!
//! ⚠ **`tests/conformance.rs` does NOT walk these resources, and that is not an
//! oversight.** Its fixture home carries no `store` line, so the composed kernel it walks
//! binds no dataset and its catalog is unchanged by this feature — which is also why
//! adding the feature needed no opt-out there. The seven store resources are walked by
//! `ikigai-store`'s own conformance suite, over the same `space()` this host binds; what
//! is left for THIS crate to state is the composition, and that is what this file is.
#![cfg(feature = "store")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};

/// Redirect every ambient path this crate reads, once for the whole binary, and name the
/// dataset directory. Returns the scratch root.
fn fixture_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("ikigai-embedded-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
        // The switch and the path in one call: `set_store_path` implies "configured", so
        // this binary needs no `store = true` line in its scratch config.
        ikigai_embedded::store::set_store_path(dir.join("store"));
        dir
    })
    .as_path()
}

/// The one kernel this binary builds. ⚠ `OnceLock`, not a fresh kernel per test: the
/// dataset is opened once per PROCESS (RocksDB refuses a second open on a path even from
/// the same process), and while `ikigai_embedded::store` memoises that open, keeping the
/// kernel here too makes the constraint visible at the point somebody would otherwise add
/// a second `kernel()` call.
fn kernel() -> &'static Kernel {
    static KERNEL: OnceLock<Kernel> = OnceLock::new();
    KERNEL.get_or_init(|| {
        fixture_home();
        ikigai_embedded::kernel()
    })
}

fn issue(
    capability: &Capability,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
) -> Result<String, Error> {
    let request = args.iter().fold(
        Request::new(verb, Iri::parse(iri).expect("a test IRI")),
        |request, (name, value)| request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec())),
    );
    block_on(kernel().issue(request, capability))
        .map(|repr| String::from_utf8_lossy(&repr.bytes).into_owned())
}

fn root(verb: Verb, iri: &str, args: &[(&str, &str)]) -> String {
    issue(&Capability::root(), verb, iri, args)
        .unwrap_or_else(|e| panic!("{verb:?} {iri} failed: {e}"))
}

/// The composition, end to end: a write through `urn:iki:store:update` is readable through
/// `urn:iki:store:select` in the same kernel. This is the whole point of the binding — a
/// dataset that is not rebuilt from its sources — and it is what the ledger will ride on.
#[test]
fn a_write_through_the_kernel_is_readable_through_the_kernel() {
    root(
        Verb::Sink,
        "urn:iki:store:update",
        &[(
            "content",
            "INSERT DATA { GRAPH <urn:test:g> { <urn:test:s> <urn:test:p> \"durable\" } }",
        )],
    );
    let answer = root(
        Verb::Source,
        "urn:iki:store:select",
        &[(
            "query",
            "SELECT ?o WHERE { GRAPH <urn:test:g> { <urn:test:s> <urn:test:p> ?o } }",
        )],
    );
    assert!(answer.contains("durable"), "{answer}");
}

/// ★ **This process holds the directory, and holding it is observable.** A second
/// `DurableStore::open` on the same path is refused — from this very process, because
/// RocksDB keeps its own registry and POSIX advisory locks would not have caught it.
///
/// The test is the reason `ikigai_embedded::store` memoises its open instead of opening
/// per kernel, and the reason the host's answer to a held directory is the wire rather
/// than a retry.
#[test]
fn the_dataset_is_held_and_a_second_open_is_refused_as_transient() {
    let dir = fixture_home().join("store");
    kernel(); // take the lock first, whatever order the harness runs tests in
    let error = ikigai_store::DurableStore::open(&dir)
        .expect_err("a second open of a held dataset is refused");
    assert!(
        error.is_transient(),
        "a held directory is Unavailable — the typed, transient shape the host prints \
         one line for rather than panicking over: {error}"
    );
    assert!(
        error.to_string().contains(&dir.display().to_string()),
        "the refusal names the path: {error}"
    );
}

/// What a grant has to contain. The everyday REPL session is root, so this is the answer
/// for a `cap`-narrowed session, a served connection, or an agent: the store's own
/// `urn:cap:store:read` — and **nothing narrower works**, because the store's scopes are
/// per-verb and not per-graph.
#[test]
fn reading_the_store_needs_the_stores_own_read_scope() {
    let query = "SELECT ?s WHERE { GRAPH ?g { ?s ?p ?o } } LIMIT 1";
    let denied = issue(
        &Capability::scoped(["urn:cap:ledger:read"]),
        Verb::Source,
        "urn:iki:store:select",
        &[("query", query)],
    )
    .expect_err("a ledger grant is not a store grant");
    assert!(matches!(denied, Error::Denied(_)), "{denied}");

    issue(
        &Capability::scoped([ikigai_store::CAP_READ]),
        Verb::Source,
        "urn:iki:store:select",
        &[("query", query)],
    )
    .expect("urn:cap:store:read reads");
}

/// The seven store resources are in the composed catalog, under the names the manifold
/// advertises — so `urn:kernel:actions` offers them and the engine can route named
/// arguments to them.
#[test]
fn the_store_resources_join_the_composed_catalog() {
    let patterns: Vec<String> = kernel()
        .entries()
        .expect("an enumerable root")
        .iter()
        .map(|e| e.pattern.clone())
        .collect();
    for iri in [
        "urn:iki:store:select",
        "urn:iki:store:ask",
        "urn:iki:store:construct",
        "urn:iki:store:describe",
        "urn:iki:store:info",
        "urn:iki:store:update",
        "urn:iki:store:load",
    ] {
        assert!(
            patterns.iter().any(|p| p == iri),
            "{iri} is missing from the composed catalog"
        );
        assert!(
            kernel().describe_pattern(iri).is_some(),
            "{iri} describes itself, so the manifold can offer it"
        );
    }
}
