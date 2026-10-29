//! The names layer through the REAL binary (named requests C1, ledger #2515): the config home's
//! `names` file (or `names.ttl`, or `--names <file>`) binds named requests LAST in the REPL's
//! root, `bind` persists into it, an edit to a file a binding reads recomputes, and a binding
//! a served name shadows is reported by the status door.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `json_space.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const QUAKES: &str = r#"{"type":"FeatureCollection","features":[
  {"type":"Feature","properties":{"mag":4.5,"place":"north"}},
  {"type":"Feature","properties":{"mag":2.1,"place":"south"}},
  {"type":"Feature","properties":{"mag":5.2,"place":"east"}}
]}"#;

/// The named request: a jq program in a FILE, over the quakes, both fixed by reference. Its
/// fixed arguments in the order a names file prints them, so `bind` writes exactly this line.
const COUNT: &str =
    "urn:quakes:count = source urn:json:query q=<urn:file:count.jq> src=<urn:file:quakes.json>\n";

const STATUS: &str = "urn:iki:space:dynamic:names:status";

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-names-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config(&dir)).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(dir.join("files").join("quakes.json"), QUAKES).expect("a GeoJSON file");
    std::fs::write(dir.join("files").join("count.jq"), ".features|length\n").expect("a jq file");
    dir
}

fn config(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn ikigai(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"));
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    ikigai(home, args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test runs")
}

/// stdout, after asserting the run succeeded.
fn answer(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    stdout
}

/// The item's transcript: `ikigai -c 'source urn:quakes:count'` with a names file answers the
/// count. Before the layer, the name answered "no endpoint resolved".
#[test]
fn a_names_file_in_the_config_home_answers_the_count() {
    let home = scratch("count");
    std::fs::write(config(&home).join("names"), COUNT).expect("a names file");
    let out = run(&home, &["--quiet", "-c", "source urn:quakes:count"]);
    assert_eq!(answer(&out).trim(), "3");
}

/// `names.ttl` is the same table as Turtle (what `urn:names:to-rdf` writes, made here by the
/// same library call), and `--names`
/// names a file anywhere instead of the config home's.
#[test]
fn names_ttl_and_the_flag_name_the_same_table() {
    let home = scratch("ttl");
    let turtle = ikigai_engine::names::names_to_turtle(COUNT).expect("the table as Turtle");
    std::fs::write(config(&home).join("names.ttl"), &turtle).expect("a Turtle names file");
    let out = run(&home, &["--quiet", "-c", "source urn:quakes:count"]);
    assert_eq!(answer(&out).trim(), "3", "names.ttl:\n{turtle}");

    std::fs::remove_file(config(&home).join("names.ttl")).expect("remove names.ttl");
    std::fs::write(home.join("elsewhere.names"), COUNT).expect("a names file elsewhere");
    let out = run(
        &home,
        &[
            "--names",
            "elsewhere.names",
            "--quiet",
            "-c",
            "source urn:quakes:count",
        ],
    );
    assert_eq!(answer(&out).trim(), "3");
}

/// Two names files in one config home could only mean two tables: the start is refused,
/// naming both, rather than one of them silently winning.
#[test]
fn both_names_files_stop_the_start() {
    let home = scratch("both");
    std::fs::write(config(&home).join("names"), COUNT).expect("names");
    std::fs::write(config(&home).join("names.ttl"), "").expect("names.ttl");
    let out = run(&home, &["--quiet", "-c", "source urn:quakes:count"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.starts_with("ikigai: ") && stderr.contains("names.ttl") && stderr.contains("both"),
        "{stderr}"
    );
}

/// A REPL binding persists into the config home's `names` by default (creating it), and a
/// later process answers it.
#[test]
fn bind_persists_into_the_names_file() {
    let home = scratch("bind");
    let file = config(&home).join("names");
    assert!(!file.exists());
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "bind urn:quakes:count = source urn:json:query src=<urn:file:quakes.json> \
             q=<urn:file:count.jq>",
            "-c",
            "source urn:quakes:count",
        ],
    );
    let stdout = answer(&out);
    assert_eq!(stdout.lines().last(), Some("3"), "{stdout}");
    let written = std::fs::read_to_string(&file).expect("bind wrote the names file");
    assert_eq!(written, COUNT);

    let out = run(&home, &["--quiet", "-c", "unbind urn:quakes:count"]);
    answer(&out);
    assert_eq!(std::fs::read_to_string(&file).expect("still a file"), "");
    let out = run(&home, &["--quiet", "-c", "source urn:quakes:count"]);
    assert!(!out.status.success(), "unbound, the name answers nothing");
}

/// A binding whose name the host already serves never answers, because the layer is LAST:
/// the status door reports it, and the host's own answer is unchanged.
#[test]
fn a_shadowing_binding_is_reported_by_the_status_door() {
    let home = scratch("shadow");
    std::fs::write(
        config(&home).join("names"),
        format!("{COUNT}urn:iki:host:arrangement = source urn:quakes:count\n"),
    )
    .expect("a names file");
    let out = run(&home, &["--quiet", "-c", &format!("source {STATUS}")]);
    let status = answer(&out);
    assert!(
        status.contains("shadowed: urn:iki:host:arrangement"),
        "{status}"
    );
    assert!(!status.contains("shadowed: urn:quakes:count"), "{status}");

    // The host's own answer wins.
    let out = run(&home, &["--quiet", "-c", "source urn:iki:host:arrangement"]);
    assert_ne!(answer(&out).trim(), "3");

    // A shadowing binding made in the REPL is reported the same way.
    let home = scratch("shadow-bind");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "bind urn:host:heartbeat = source urn:json:query src=<urn:file:quakes.json> \
             q=<urn:file:count.jq>",
            "-c",
            &format!("source {STATUS}"),
        ],
    );
    let status = answer(&out);
    assert!(status.contains("shadowed: urn:host:heartbeat"), "{status}");
}

/// In one running REPL: editing the query file the binding references recomputes the named
/// request, and editing the NAMES file rebinds it, both out of band (an editor), heard by the
/// watches. Polls rather than sleeping once: the watcher's latency is the platform's.
#[test]
// A native test of a native binary: the deadline is the test's own wall clock.
#[allow(clippy::disallowed_methods)]
fn edits_to_the_query_file_and_the_names_file_recompute() {
    let home = scratch("edit");
    std::fs::write(config(&home).join("names"), COUNT).expect("a names file");
    let mut child = ikigai(&home, &["--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ikigai");
    let mut stdin = child.stdin.take().expect("piped stdin");
    // Answers are read on a thread, so a line that never comes (a name that does not resolve
    // writes its error to stderr) fails the test at its deadline instead of hanging it.
    let (answers, answer) = std::sync::mpsc::channel();
    let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    std::thread::spawn(move || {
        for line in stdout.lines() {
            let Ok(line) = line else { return };
            if answers.send(line.trim().to_string()).is_err() {
                return;
            }
        }
    });
    let mut until = |line: &str, want: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            writeln!(stdin, "{line}").expect("write a line");
            stdin.flush().expect("flush");
            let got = answer
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| "<no answer>".to_string());
            if got == want {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "`{line}` answers {got}, not {want}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    until("source urn:quakes:count", "3");

    // The query file changes on disk: the named request recomputes.
    std::fs::write(
        home.join("files").join("count.jq"),
        "[.features[]|select(.properties.mag>4)]|length\n",
    )
    .expect("edit the query");
    until("source urn:quakes:count", "2");

    // The names file changes on disk: the binding is rebound.
    std::fs::write(
        config(&home).join("names"),
        "urn:quakes:count = source urn:json:query src=<urn:file:quakes.json> q=\".type\"\n",
    )
    .expect("edit the names");
    until("source urn:quakes:count", "\"FeatureCollection\"");

    drop(stdin);
    let _ = child.wait();
}
