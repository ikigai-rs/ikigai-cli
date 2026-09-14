//! The work ledger as an operator actually reaches it: **through the REPL grammar**,
//! over the composed embedded kernel, against a real RocksDB dataset.
//!
//! ⚠ This file lives in `ikigai-cli` and not beside `tests/store.rs` in `ikigai-embedded`
//! on purpose. `ikigai-engine` and `ikigai-embedded` do not depend on each other — the
//! binary crate is the only place both exist — and a test that issued `Request`s at the
//! kernel would prove the binding while saying nothing about the thing Brian types. The
//! field guide's pipeline-citizenship row is the reason that distinction is not pedantry:
//! the engine routes a positional value by the endpoint's *contract*, and an endpoint can
//! be perfectly correct at the kernel and unreachable from a command line.
//!
//! Two properties this file exists for, neither visible from either crate alone:
//!
//! 1. **The five verbs work as typed lines**, with the argument spellings an operator
//!    would use — including the trailing-value form on `append`, which is the pipeline
//!    path.
//! 2. **The grant list in `ikigai_embedded::store::grants_for` is the one that works** —
//!    the narrow per-graph store tokens, never `urn:cap:store:write`.
//!
//! Each test uses its **own named ledger**, so the harness may run them in parallel over
//! the one process-wide dataset without racing on a shared `#N` counter.
#![cfg(feature = "store")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use futures::executor::block_on;
use ikigai_engine::{Action, Engine};

/// Redirect every ambient path this binary reads, once, and name the dataset directory.
///
/// ⚠ `cfg(test)` does not reach a `tests/` binary, so the hermetic redirect is a CALL —
/// the same seam `tests/store.rs` next door uses. Without it these tests would open the
/// operator's own `~/.ikigai/store` and, on a machine already running an `ikigai`, fail
/// for a reason that has nothing to do with this code.
fn fixture_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ikigai-cli-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
        // `set_store_path` implies "configured", so this binary needs no `store = true`
        // line in its scratch config.
        ikigai_embedded::store::set_store_path(dir.join("store"));
        dir
    })
    .as_path()
}

/// A REPL engine over the composed embedded kernel — the same pair `ikigai -c '…'` builds.
///
/// A fresh `Engine` per test and a fresh `Kernel` behind it: the DATASET is opened once
/// per process and memoised in `ikigai_embedded::store`, so every kernel here shares the
/// one open. That is the constraint `tests/store.rs` documents, working.
fn engine() -> Engine {
    fixture_home();
    Engine::new(ikigai_embedded::kernel())
}

/// Evaluate one typed line, expecting it to succeed, and return what the REPL printed.
fn line(engine: &Engine, input: &str) -> String {
    match block_on(engine.eval_async(input)) {
        Action::Output(entry) => entry
            .result
            .unwrap_or_else(|e| panic!("`{input}` failed: {e}")),
        // ⚠ `Action` carries no `Debug`, so the diagnostic names the input rather than
        // the variant. Everything a typed line can produce that is not `Output` is a REPL
        // control action (`quit`, `help`, `clear`, an empty line) and cannot come from
        // `source`/`sink`/`cap` — so the fact of it is the whole finding.
        _ => panic!("`{input}` produced a REPL control action rather than output"),
    }
}

/// Evaluate one typed line, expecting it to FAIL, and return the message.
fn refused(engine: &Engine, input: &str) -> String {
    match block_on(engine.eval_async(input)) {
        Action::Output(entry) => match entry.result {
            Err(e) => e,
            Ok(out) => panic!("`{input}` was expected to fail and printed:\n{out}"),
        },
        // ⚠ `Action` carries no `Debug`, so the diagnostic names the input rather than
        // the variant. Everything a typed line can produce that is not `Output` is a REPL
        // control action (`quit`, `help`, `clear`, an empty line) and cannot come from
        // `source`/`sink`/`cap` — so the fact of it is the whole finding.
        _ => panic!("`{input}` produced a REPL control action rather than output"),
    }
}

/// ★ **The arc's deliverable, as a test.** Append, list, comment, rank and close — the
/// five verbs, typed the way the docs tell an operator to type them.
///
/// The `append` line deliberately uses the **trailing-value** form rather than
/// `content="…"`: that is the same routing path a pipe takes (`engine.rs` fills the sole
/// unnamed argument, and a mutating verb's value always lands in `content`), so this one
/// line is the evidence that `… | sink urn:iki:ledger:append` works too. Naming the body
/// would have proved only that a named argument arrives.
#[test]
fn the_five_verbs_work_as_typed_lines() {
    let engine = engine();

    // ── append ───────────────────────────────────────────────────────────────────
    // First line is the title, the rest is the body. The number comes back with the IRI
    // it was minted at, qualified by the ledger's name because this is not `default`.
    let filed = line(
        &engine,
        "sink urn:iki:ledger:smoke:append Bind the ledger into the embedded host",
    );
    assert!(filed.starts_with("smoke#1 "), "{filed}");
    assert!(
        filed.contains("urn:iki:ledger:smoke:item:"),
        "an item is minted at its canonical IRI: {filed}"
    );

    let second = line(
        &engine,
        "sink urn:iki:ledger:smoke:append priority=0 labels=cli Say what to type",
    );
    assert!(second.starts_with("smoke#2 "), "{second}");

    // ── items ────────────────────────────────────────────────────────────────────
    let list = line(&engine, "source urn:iki:ledger:smoke:items");
    assert!(
        list.contains("Bind the ledger into the embedded host"),
        "{list}"
    );
    assert!(list.contains("Say what to type"), "{list}");
    assert!(list.contains("2 item(s)"), "{list}");

    // ── comment ──────────────────────────────────────────────────────────────────
    // `item=` names which, and the remainder is the note — the same `content` slot the
    // pipe fills.
    let commented = line(
        &engine,
        "sink urn:iki:ledger:smoke:comment item=#1 author=brian It resolves from a one-shot",
    );
    assert!(commented.starts_with("commented on smoke#1"), "{commented}");
    let item = line(&engine, "source urn:iki:ledger:smoke:item:1");
    assert!(
        item.contains("It resolves from a one-shot"),
        "the comment is on the item: {item}"
    );

    // ── next ─────────────────────────────────────────────────────────────────────
    // Both are ready, so the policy decides — and p0 beats no priority.
    let next = line(&engine, "source urn:iki:ledger:smoke:next");
    assert!(next.contains("Say what to type"), "{next}");
    assert!(
        next.contains("policy:"),
        "the ranking says what ranked it: {next}"
    );

    // ── close ────────────────────────────────────────────────────────────────────
    let closed = line(
        &engine,
        "sink urn:iki:ledger:smoke:close item=#2 reason=done author=brian Shipped",
    );
    assert!(closed.contains("closed smoke#2"), "{closed}");

    // ⚠ **`items` lists OPEN items by default** — `status=` is `open`, `closed` or `all`.
    // Worth pinning rather than assuming: "it vanished from `items`" is exactly what a
    // close looks like from the default listing, and an operator who reads that as "a
    // close deletes" has learned the opposite of what a ledger is for.
    let default_listing = line(&engine, "source urn:iki:ledger:smoke:items");
    assert!(
        !default_listing.contains("Say what to type"),
        "the default listing is the OPEN items: {default_listing}"
    );
    assert!(default_listing.contains("1 item(s)"), "{default_listing}");

    // A close is not a delete: ask for it and it is still there, whole.
    let all = line(&engine, "source urn:iki:ledger:smoke:items status=all");
    assert!(
        all.contains("Say what to type"),
        "still in the graph: {all}"
    );
    assert!(all.contains("2 item(s)"), "{all}");

    // …and out of the ready set, which is the operational half of closing.
    let ready = line(&engine, "source urn:iki:ledger:smoke:next");
    assert!(
        !ready.contains("Say what to type"),
        "a closed item is not ready: {ready}"
    );
}

/// ★ **The grant list, exercised rather than asserted.**
///
/// `grants_for` builds the tokens; this proves a session narrowed to exactly them can
/// file and read an item — and that the broad `urn:cap:store:write` cannot, which is the
/// failure the brief singled out as the most likely hour lost. `urn:iki:store:graph-update`
/// declares and enforces `urn:cap:store:write:graph:*`, and the powerful key is not under
/// that prefix, so a grant list built around it produces a ledger that cannot write and a
/// `Denied` that reads like a bug in the ledger.
#[test]
fn the_narrow_per_graph_grants_work_and_the_broad_store_key_does_not() {
    use ikigai_embedded::store::{grants_for, Authority};

    // The broad key first, on its own session, because `cap` only ever narrows.
    let broad = engine();
    line(
        &broad,
        "cap urn:cap:ledger:write:grants urn:cap:ledger:read:grants \
         urn:cap:store:read urn:cap:store:write",
    );
    let denied = refused(
        &broad,
        "sink urn:iki:ledger:grants:append Filed with the keys to the whole dataset",
    );
    assert!(
        denied.to_lowercase().contains("denied") || denied.contains("urn:cap:store:"),
        "the broad store key is refused by the narrow door: {denied}"
    );

    // And now the list a host should actually issue.
    let narrow = engine();
    let grants = grants_for("grants", Authority::Write).expect("a valid ledger name");
    line(&narrow, &format!("cap {}", grants.join(" ")));
    let filed = line(
        &narrow,
        "sink urn:iki:ledger:grants:append Filed under the narrow per-graph tokens",
    );
    assert!(filed.starts_with("grants#1 "), "{filed}");
    let list = line(&narrow, "source urn:iki:ledger:grants:items");
    assert!(
        list.contains("Filed under the narrow per-graph tokens"),
        "{list}"
    );

    // ★ …and READING ONE ITEM, which is the assertion this test exists for as much as the
    // listing. Through `ikigai-ledger` 0.2.0 this line was DENIED:
    // `urn:iki:ledger:{ledger}:item:{id}` declared the broad `urn:cap:store:read` on its
    // `Source`/`Exists` where the sibling `read_scopes` correctly used the per-graph
    // family, so a caller holding exactly the list `grants_for` issues could file an item
    // and list the ledger and then fail to read back the single item behind the line it
    // had just listed. Core's pre-check requires every declared scope and `allows` is exact
    // set membership for a scope with no trailing `*`, so nothing narrower satisfied it —
    // the only cure was handing over `urn:cap:store:read`, every graph in the dataset,
    // which is the precise tenancy hole 0.2.0 existed to close.
    //
    // 0.2.1 declares the per-graph family here too, and the workspace floor is pinned there
    // (`ikigai-ledger = "0.2.1"`). This line is what makes that floor a checked claim rather
    // than a comment: resolve against 0.2.0 and it goes red.
    let item = line(&narrow, "source urn:iki:ledger:grants:item:1");
    assert!(
        item.contains("Filed under the narrow per-graph tokens"),
        "one item reads under the narrow grants, without `urn:cap:store:read`: {item}"
    );
}

/// The ledger's resources are in the composed catalog under the names the manifold
/// advertises, so `urn:kernel:actions` offers them and the engine can route named
/// arguments to them — which is what every line in the first test depends on.
#[test]
fn the_ledger_resources_join_the_composed_catalog() {
    let kernel = {
        fixture_home();
        ikigai_embedded::kernel()
    };
    let patterns: Vec<String> = kernel
        .entries()
        .expect("an enumerable root")
        .iter()
        .map(|e| e.pattern.clone())
        .collect();
    // ★ The per-ledger resources list as TEMPLATES, not as the bare sugar: the catalog
    // carries `urn:iki:ledger:{ledger}:append`, and `urn:iki:ledger:append` appears
    // nowhere in it. That is the short form being an alias rather than a second binding —
    // one row, one capability — and it is what a reader of the catalog has to expand with
    // the `ledger` argument's declared default. Asserting the bare spelling here would
    // have been asserting a second door this design deliberately does not have.
    for pattern in [
        "urn:iki:ledger:{ledger}:append",
        "urn:iki:ledger:{ledger}:items",
        "urn:iki:ledger:{ledger}:item:{id}",
        "urn:iki:ledger:{ledger}:next",
        // The two that carry no ledger segment, because neither is a ledger's own state.
        "urn:iki:ledger:ledgers",
        "urn:iki:ledger:policy:{name}",
    ] {
        assert!(
            patterns.iter().any(|p| p == pattern),
            "{pattern} is missing from the composed catalog: {patterns:?}"
        );
        assert!(
            kernel.describe_pattern(pattern).is_some(),
            "{pattern} describes itself, so the manifold can offer it and the engine can \
             route named arguments to it"
        );
    }
    // And the store is still there beside it — the pair is bound together or not at all,
    // including the narrow doors every ledger read and write actually goes through.
    for pattern in ["urn:iki:store:graph-select", "urn:iki:store:graph-update"] {
        assert!(
            patterns.iter().any(|p| p == pattern),
            "{pattern} is missing from the composed catalog"
        );
    }
}
