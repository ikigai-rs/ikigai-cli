//! `urn:reason:closure` and `urn:reason:inferred` (ikigai-reason) through the REAL binary. The
//! runbook's OWL 2 RL pages (ledger #2641) run on them, and the host did not bind the module:
//! the runbook links ikigai-reason only for its own tests, as it did ikigai-compress
//! (`compress_space.rs`).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `json_space.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(feature = "embedded")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-reason-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the binary under test runs")
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const ALIGNMENT: &str = "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
     <http://example.org/Customer> rdfs:subClassOf <http://example.org/Person> .\n\
     <http://example.org/bob> a <http://example.org/Customer> .\n";

/// The reasoner answers from the local root: Bob is a Customer, and Customer is a subclass of
/// Person, so `urn:reason:inferred` entails that Bob is a Person.
#[test]
fn the_reasoner_entails_a_subclass_typing_from_a_file() {
    let home = scratch("entails");
    std::fs::write(home.join("files").join("a.ttl"), ALIGNMENT).expect("write the graph");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "source urn:reason:inferred graph=urn:file:a.ttl as=application/n-triples",
        ],
    );
    let (stdout, stderr) = text(&out);
    assert!(
        !stderr.contains("no endpoint resolved"),
        "the reasoner is not bound on this host: {stderr}"
    );
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains(
            "<http://example.org/bob> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> \
             <http://example.org/Person>"
        ),
        "the entailed typing is missing: {stdout}"
    );
}

/// The Thread page's point, in one process: a write through the kernel cuts the file's thread,
/// and the next read of the same closure follows the edit.
#[test]
fn an_edit_through_the_kernel_is_followed_by_the_next_closure() {
    let home = scratch("edit");
    let files = home.join("files");
    std::fs::write(files.join("a.ttl"), ALIGNMENT).expect("write the graph");
    // The edited alignment, written beside it; the edit is piped through the kernel below, so
    // the Sink (not the disk) cuts `urn:file:a.ttl`'s thread.
    let edited = format!(
        "{ALIGNMENT}<http://example.org/Person> \
         <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://example.org/Agent> .\n"
    );
    std::fs::write(files.join("edited.ttl"), edited).expect("write the edit");
    let read = "source urn:reason:inferred graph=urn:file:a.ttl as=application/n-triples";
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            read,
            "-c",
            "source urn:file:edited.ttl | sink urn:file:a.ttl",
            "-c",
            read,
        ],
    );
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    let agent = "<http://example.org/bob> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> \
                 <http://example.org/Agent>";
    assert_eq!(
        stdout.matches(agent).count(),
        1,
        "only the read after the edit entails Agent: {stdout}"
    );
}

/// One OWL 2 RL page's steps run in order in ONE process (`-c` per step), as the TUI's demo
/// tab runs them, so a file one step writes is read by the next and the engine's cache tally
/// is the page's. The steps are read from the page's own JSON face, so a step the runbook adds
/// later runs here too. Returns stdout, stderr (each step's tally and any error, in order) and
/// whether the batch succeeded.
fn run_page(home: &Path, page: &str) -> (String, String, bool) {
    let json = run(
        home,
        &[
            "--quiet",
            "--demo",
            "-c",
            &format!("source urn:runbook:{page} as=application/json"),
        ],
    );
    let (stdout, stderr) = text(&json);
    assert!(json.status.success(), "the {page} page: {stdout}\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("the page's JSON");
    let steps = json["steps"].as_array().expect("the page lists steps");
    assert!(!steps.is_empty(), "the {page} page lists no steps");
    let mut args = vec!["--quiet".to_string(), "--demo".to_string()];
    for step in steps {
        args.push("-c".to_string());
        args.push(
            step["cmd"]
                .as_str()
                .expect("a step has a command")
                .to_string(),
        );
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(home, &args);
    let (stdout, stderr) = text(&out);
    assert!(
        !stderr.contains("no endpoint resolved"),
        "a step of the {page} page did not resolve on this host: {stderr}"
    );
    (stdout, stderr, out.status.success())
}

/// Every step of the five OWL 2 RL pages that should answer does, on this host: the runbook
/// pages a demo on bug shows (ledger #2641). Their answers are checked in the runbook's own
/// `tests/reasoning_demos.rs` over the engine; this checks that the binary binds everything
/// they name and that none of them errs.
#[test]
fn every_step_of_the_answering_owl_pages_answers() {
    for page in ["selection", "vocabularies", "typing", "topics", "thread"] {
        let home = scratch(page);
        let (stdout, stderr, ok) = run_page(&home, page);
        assert!(
            ok && !stderr.contains("error"),
            "the {page} page: stdout: {stdout}\nstderr: {stderr}"
        );
    }
}

/// The Thread page's point, as the page runs: reasoning over each of two graphs again is all
/// cached, and after an edit to ONE of them only that one recomputes.
#[test]
fn the_thread_page_recomputes_only_what_the_edit_cut() {
    let home = scratch("thread-page");
    let (stdout, stderr, ok) = run_page(&home, "thread");
    assert!(ok, "stdout: {stdout}\nstderr: {stderr}");
    let again = stderr
        .find("[3 cached]")
        .unwrap_or_else(|| panic!("the second read over both graphs was not all cached: {stderr}"));
    assert!(
        stderr[again..].contains("[2 cached · 1 computed]"),
        "after the edit, more or less than the edited graph recomputed: {stderr}"
    );
}

/// The Reasoner bounds page: its two bounded steps are refused as over budget, each naming its
/// bound, and nothing else on the page errs.
#[test]
fn the_bounds_page_refuses_at_both_bounds() {
    let home = scratch("bounds-page");
    let (stdout, stderr, ok) = run_page(&home, "bounds");
    assert!(!ok, "the bounds page reasoned past a bound: {stdout}");
    let errors: Vec<&str> = stderr.lines().filter(|l| l.contains("error")).collect();
    assert_eq!(
        errors,
        [
            "error: over budget: OWL RL closure exceeds 100000 triples",
            "error: over budget: OWL RL input exceeds 1000 triples",
        ],
        "stderr: {stderr}"
    );
}

/// Past the input bound (1,000 triples by default) the reasoner refuses as OverBudget before it
/// reasons, and never truncates.
#[test]
fn a_graph_past_the_input_bound_is_refused() {
    let home = scratch("bound");
    let mut big = String::new();
    for n in 0..1_001 {
        big.push_str(&format!(
            "<http://example.org/s{n}> <http://example.org/p> <http://example.org/o> .\n"
        ));
    }
    std::fs::write(home.join("files").join("big.nt"), big).expect("write the graph");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "source urn:reason:closure graph=urn:file:big.nt",
        ],
    );
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "a 1,001-triple input was reasoned: {stdout}"
    );
    assert!(
        !stderr.contains("no endpoint resolved"),
        "the reasoner is not bound on this host: {stderr}"
    );
    assert!(
        stderr.contains("OWL RL input exceeds 1000 triples"),
        "not refused by its input bound: {stderr}"
    );
}
