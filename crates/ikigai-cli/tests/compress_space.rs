//! `urn:compress:*` and `urn:decompress:*` (ikigai-compress) through the REAL binary. The
//! runbook's Bytes tab runs on them, and until this host bound the module every step of that
//! tab answered `no endpoint resolved for urn:compress:gzip` (found on bug, 2026-10-30): the
//! runbook links ikigai-compress for its own tests, and the host did not.
//!
//! The steps are read from the runbook's own page (`urn:runbook:bytes`, JSON face), so a step
//! the runbook adds later is checked here too.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `json_space.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(feature = "embedded")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-compress-{}-{case}", std::process::id()));
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

#[test]
fn gzip_then_gunzip_round_trips_from_the_cli() {
    let home = scratch("round-trip");
    let out = run(
        &home,
        &[
            "--quiet",
            "-c",
            "source urn:compress:gzip hello hello hello | urn:decompress:gzip as=text/plain",
        ],
    );
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout.trim(), "hello hello hello", "stderr: {stderr}");
}

/// What each step of the Bytes tab must show, by label, as its note says. These mirror the
/// runbook's own `tests/bytes_demo.rs`, which runs the same steps over the engine; this runs
/// them through the binary. A step the runbook adds without a case here fails, on purpose.
fn as_its_note_says(label: &str, out: &Result<String, String>) -> bool {
    match label {
        // The page's first step: gzip output is not UTF-8, so it is refused with its size.
        "gzip → not text" => matches!(out, Err(e) if e.contains("not UTF-8")),
        "what are these bytes?" => matches!(out, Ok(t) if t.trim() == "application/gzip"),
        "gzip, then gunzip" | "gunzip, unnamed" | "at the bound → ok" => {
            matches!(out, Ok(t) if t.trim_end() == "hello hello hello")
        }
        // `hello hello hello` is 17 bytes: a limit of 17 passes and 16 refuses.
        "past the bound → refused" => {
            matches!(out, Err(e) if e.contains("16-byte limit") && e.contains("max-bytes"))
        }
        _ => false,
    }
}

/// Every step of the runbook's Bytes tab, as the page lists it, runs on this host and shows
/// what its note says, and none of them is unresolved.
#[test]
fn every_step_of_the_runbooks_bytes_tab_resolves() {
    let home = scratch("bytes-tab");
    let page = run(
        &home,
        &[
            "--quiet",
            "--demo",
            "-c",
            "source urn:runbook:bytes as=application/json",
        ],
    );
    let (stdout, stderr) = text(&page);
    assert!(page.status.success(), "the Bytes page: {stdout}\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("the page's JSON");
    let steps = json["steps"].as_array().expect("the page lists steps");
    assert!(!steps.is_empty(), "the Bytes page lists no steps");
    for step in steps {
        let label = step["label"].as_str().expect("a step has a label");
        let cmd = step["cmd"].as_str().expect("a step has a command");
        let out = run(&home, &["--quiet", "-c", cmd]);
        let (stdout, stderr) = text(&out);
        assert!(
            !stderr.contains("no endpoint resolved"),
            "`{cmd}` did not resolve on this host: {stderr}"
        );
        let result = if out.status.success() {
            Ok(stdout)
        } else {
            Err(stderr)
        };
        assert!(
            as_its_note_says(label, &result),
            "step `{label}`: `{cmd}` gave {result:?}"
        );
    }
}
