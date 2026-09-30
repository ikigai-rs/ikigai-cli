//! `--arrangement` through the REAL binary (ledger #637): the local root built from a declared
//! arrangement, named by the flag or by the config home, and every way that must STOP the start
//! instead of falling back to the built-in root.
//!
//! The unit tests in `ikigai-embedded` pin the round trip against constructed roots. This file
//! pins what an operator types: a file on disk, a flag or a config key, and a process that either
//! runs that arrangement or exits saying why — never one that quietly runs the default, which an
//! operator who asked for a declaration could not tell from the one they asked for.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `host_posture.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only, so the developer's config home is never
//! read.
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ikigai_core::{Door, MatchKind, SpaceKind, Topology};

/// A scratch home for one case, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-arr-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

/// Run `ikigai <args…>` against `home` and wait for it (`output` waits, so the exit status
/// is the reaped one).
fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A declaration with ONE door, `urn:host:demo`, bound to the host's own `host-demo` endpoint
/// — so every other name the built-in root answers is gone, which is the observable proof the
/// declaration and not the default is running.
fn one_door() -> String {
    Topology::new(SpaceKind::EndpointSpace {
        doors: vec![Door::new("urn:host:demo", MatchKind::Exact, "host-demo")],
    })
    .to_turtle()
}

/// The flag runs the declaration: its one door answers, a name the built-in root binds does
/// not, and the process says, once, which arrangement it is running.
#[test]
fn the_flag_runs_the_declared_arrangement() {
    let home = scratch("flag");
    std::fs::write(home.join("root.ttl"), one_door()).unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "root.ttl",
            "-c",
            "source urn:host:demo",
            "-c",
            "source urn:host:info",
        ],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(
        stdout.contains("demo off"),
        "the declared door answers: {stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("no endpoint resolved for urn:host:info"),
        "a door the declaration dropped is not answered: {stderr}"
    );
    assert!(
        stderr.contains("local root arranged from") && stderr.contains("(from the flag)"),
        "{stderr}"
    );
}

/// The config home names it too — relative to the config home — and the host's own resource
/// answers the arrangement it is running, header and all.
#[test]
fn the_config_home_names_it_and_the_host_answers_it() {
    let home = scratch("config");
    let config = home.join("config").join("ikigai");
    std::fs::write(config.join("root.ttl"), one_door()).unwrap();
    std::fs::write(config.join("config.toml"), "arrangement = \"root.ttl\"\n").unwrap();
    let out = run(&home, &["-c", "source urn:iki:host:arrangement"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(stderr.contains("(from the config)"), "{stderr}");
    assert!(
        stdout.contains("# The arrangement this host built its local root from"),
        "{stdout}"
    );
    assert!(stdout.contains("ik:endpointName \"host-demo\""), "{stdout}");
    assert!(
        !stdout.contains("urn:host:info"),
        "only the declared door: {stdout}"
    );
}

/// A declaration that is named and missing stops the start. Exit 2, and the message names
/// the file.
#[test]
fn a_missing_declaration_stops_the_start() {
    let home = scratch("missing");
    let out = run(
        &home,
        &["--arrangement", "absent.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("absent.ttl") && stderr.contains("cannot be read"),
        "{stderr}"
    );
    assert!(!text(&out.stdout).contains("demo off"), "nothing ran");
}

/// A document that is not a declaration stops the start with core's message.
#[test]
fn a_malformed_declaration_stops_the_start() {
    let home = scratch("malformed");
    let odd = one_door().replace("ik:EndpointSpace", "ik:Tunnel");
    std::fs::write(home.join("root.ttl"), odd).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("not a declaration") && stderr.contains("ik:Tunnel"),
        "{stderr}"
    );
}

/// A declaration that parses and does not BUILD stops the start too, with core's message
/// naming the node: here, an endpoint the host never registered.
#[test]
fn an_unbuildable_declaration_stops_the_start() {
    let home = scratch("unbuildable");
    let conjured = Topology::new(SpaceKind::EndpointSpace {
        doors: vec![Door::new("urn:x:y", MatchKind::Exact, "no-such-endpoint")],
    })
    .to_turtle();
    std::fs::write(home.join("root.ttl"), conjured).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:x:y"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("`no-such-endpoint`") && stderr.contains("<urn:ikigai:space:_:1:door:1>"),
        "{stderr}"
    );
}

/// ★ The built-in root dumped and fed back is REFUSED on this host, and says why: `file` names
/// two different endpoints (the org-file jail and the workspace jail), so a door naming it cannot
/// say which. Pinned end to end so the day a module gives each its own name, this test is what
/// changes.
#[test]
fn the_dumped_default_is_refused_on_an_ambiguous_name() {
    let home = scratch("dump");
    let dump = run(&home, &["-c", "source urn:iki:host:arrangement"]);
    let turtle = text(&dump.stdout);
    assert!(
        turtle.contains("⚠ Not declarable as it stands: `file`"),
        "{turtle}"
    );
    std::fs::write(home.join("root.ttl"), &turtle).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("binds `file`, which names 2 different endpoints in this host"),
        "{stderr}"
    );
}

/// `--connect` resolves on another kernel, so it builds no local root to arrange: the flag is
/// refused there rather than ignored.
#[test]
fn the_flag_is_refused_where_no_local_root_is_built() {
    let home = scratch("connect");
    std::fs::write(home.join("root.ttl"), one_door()).unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "root.ttl",
            "--connect",
            "/tmp/iki-arr-nobody.sock",
            "-c",
            "source urn:host:demo",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("does not build one"), "{stderr}");
}
