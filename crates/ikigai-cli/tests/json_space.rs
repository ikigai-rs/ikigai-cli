//! `urn:json:*` (ikigai-json) through the REAL binary (ledger #2481): the local root binds
//! jq and the CSV transreptors, so `-c`, the REPL and replays reach them, and compose's
//! `$j{…}` marker (sugar for `urn:json:query`) works. Until 0.2.3 the binary bound none of
//! them and answered `no endpoint resolved for urn:json:query`.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `version_verbose.rs`: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned process only.
#![cfg(feature = "embedded")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const QUAKES: &str = r#"{"type":"FeatureCollection","features":[
  {"type":"Feature","properties":{"mag":4.5,"place":"north"}},
  {"type":"Feature","properties":{"mag":2.1,"place":"south"}},
  {"type":"Feature","properties":{"mag":5.2,"place":"east"}}
]}"#;

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-json-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(dir.join("files").join("quakes.json"), QUAKES).expect("a GeoJSON file");
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

/// The command from the report, but over `quakes.json`: ikigai-fs types a file by its
/// extension and has no entry for `.geojson`, so that file reads as no JSON type and the query
/// refuses `src` by name. That table is ikigai-fs's, not this host's.
#[test]
fn a_jq_query_over_a_file_answers_from_the_cli() {
    let home = scratch("query");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            r#"source urn:json:query src=urn:file:quakes.json q=".features|length""#,
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout.trim(), "3", "stderr: {stderr}");
}

/// Compose's `$j{<src> <program>}` is sugar for `urn:json:query`, so it resolves too.
#[test]
fn compose_splices_a_jq_marker() {
    let home = scratch("compose");
    std::fs::write(
        home.join("files").join("count.txt"),
        "quakes: $j{urn:file:quakes.json .features|length}\n",
    )
    .expect("a template");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "source urn:iki:fn:compose src=urn:file:count.txt",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout.trim(), "quakes: 3", "stderr: {stderr}");
}

/// The CSV pair the book's in-browser kernel binds: `from-csv` and `to-csv`, piped.
#[test]
fn csv_reads_as_json_and_back() {
    let home = scratch("csv");
    std::fs::write(
        home.join("files").join("people.csv"),
        "name,age\nada,36\nlin,29\n",
    )
    .expect("a CSV file");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "source urn:file:people.csv | urn:json:from-csv | urn:json:to-csv",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout.trim().replace("\r\n", "\n"),
        "name,age\nada,36\nlin,29",
        "stderr: {stderr}"
    );
}
