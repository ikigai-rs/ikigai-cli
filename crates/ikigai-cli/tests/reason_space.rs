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
