//! `--no-config-mounts` end to end, through the real binary and a real config home.
//!
//! The unit tests in `main.rs` pin the posture algebra and the parse refusals. This file
//! pins the thing an operator actually sees: a server started with a `config.toml` on disk,
//! and what its startup banner says it composed. That is the deliverable half of ledger
//! #410 — the peer that inherited the machine's whole topology had a banner reporting only a
//! mount COUNT, so "this server mounted its own caller" was invisible from the outside.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, not by `set_var`. `XDG_CONFIG_HOME` points
//! `config_home()` at a scratch directory, and it is set on the SPAWNED PROCESS only —
//! the test process never mutates its own environment, which is process-global and would
//! race the harness's other threads. The developer's `~/.config/ikigai` is never read and
//! never written.
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner (or die) before the test kills it. Generous:
/// this is a watchdog against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A scratch config home carrying `lines` as `mount` keys, plus the directory the socket
/// will live in. Named per test so the cases cannot see each other's files.
fn scratch(case: &str, lines: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-np-{}-{case}", std::process::id()));
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    let body: String = lines
        .iter()
        .map(|line| format!("mount = \"{line}\"\n"))
        .collect();
    std::fs::write(config.join("config.toml"), body).expect("scratch config.toml");
    dir
}

/// Start `ikigai serve <sock>` with the scratch home, and return everything it wrote to
/// stderr up to and including its banner — or up to its exit, for the cases that refuse to
/// start. The child is killed either way: it is a server, and it would otherwise outlive
/// the test.
fn serve(home: &Path, args: &[&str]) -> (String, Option<i32>) {
    let sock = home.join("s.sock");
    let _ = std::fs::remove_file(&sock);
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("serve")
        .arg(&sock)
        .args(args)
        // The three variables that decide where a host reads and writes. All three point
        // INTO the scratch tree, so a failure cannot touch the developer's own state.
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let stderr = child.stderr.take().expect("piped stderr");
    // Read on a worker so the MAIN thread keeps a timeout: a blocking read against a door
    // that neither prints nor exits would otherwise hang the whole test binary.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut serving = false;
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            serving = line.contains("serving on");
            seen.push_str(&line);
            seen.push('\n');
            if serving {
                break;
            }
        }
        let _ = tx.send((seen, serving));
    });
    let (seen, serving) = rx.recv_timeout(PATIENCE).unwrap_or_else(|e| {
        let _ = child.kill();
        panic!("`serve {args:?}` said nothing in {PATIENCE:?}: {e}")
    });
    // ⚠ `wait`, NOT `try_wait`: stderr reaching EOF says the child is EXITING, not that it
    // has been reaped, so a `try_wait` here returns `None` on a process that is about to
    // report exit 2 — a race that reads as "the refusal did not refuse". It showed up once
    // under the hermetic sandbox and would otherwise have been an intermittent CI red.
    // Only a door that printed its banner is still running, and that one gets killed.
    let status = if serving {
        let _ = child.kill();
        let _ = child.wait();
        None
    } else {
        child.wait().ok().and_then(|s| s.code())
    };
    (seen, status)
}

/// Unchanged behaviour, and the reason the flag is needed: with no mount flags a server
/// composes the MACHINE's topology, whatever that machine's `config.toml` happens to say.
#[test]
fn no_flags_compose_the_config_homes_mount_lines() {
    let home = scratch(
        "inherit",
        &[
            "prefer urn:iki:store:=/tmp/iki-np-absent-a.sock",
            "prefer urn:iki:ledger:=/tmp/iki-np-absent-b.sock",
        ],
    );
    let (seen, _) = serve(&home, &[]);
    assert!(
        seen.contains("; 2 mount(s)"),
        "the config home's two mount lines must compose: {seen}"
    );
}

/// The flag: the same config home, declined. Zero mounts, and a banner that SAYS SO — the
/// difference between "nothing was configured" and "this process refused what was" is the
/// whole diagnostic that #410 lacked.
#[test]
fn declining_composes_nothing_and_the_banner_says_so() {
    let home = scratch(
        "decline",
        &[
            "prefer urn:iki:store:=/tmp/iki-np-absent-a.sock",
            "prefer urn:iki:ledger:=/tmp/iki-np-absent-b.sock",
        ],
    );
    let (seen, _) = serve(&home, &["--no-config-mounts"]);
    assert!(
        seen.contains("mounts declined (--no-config-mounts)"),
        "the banner must name the declined posture: {seen}"
    );
    assert!(
        !seen.contains("mount(s)"),
        "nothing composed, so there is no count to print: {seen}"
    );
}

/// Both postures at once refuses to START — no precedence rule, no silent winner, and the
/// refusal names both flags so the operator does not have to guess which one would have won.
#[test]
fn declining_beside_a_mount_flag_refuses_to_start() {
    let home = scratch(
        "conflict",
        &["prefer urn:iki:store:=/tmp/iki-np-absent-a.sock"],
    );
    let (seen, status) = serve(
        &home,
        &["--no-config-mounts", "--prefer", "urn:x:=/tmp/x.sock"],
    );
    assert_eq!(status, Some(2), "a usage refusal exits 2: {seen}");
    assert!(
        seen.contains("--no-config-mounts") && seen.contains("--prefer"),
        "the refusal must name both flags: {seen}"
    );
    assert!(
        !seen.contains("serving on"),
        "it must not serve at all: {seen}"
    );
}

/// The other half of "wholesale": a mount flag still REPLACES the config home rather than
/// adding to it. Two lines on disk, one flag on the command line, one mount composed.
#[test]
fn a_mount_flag_still_wins_wholesale_over_the_config_home() {
    let home = scratch(
        "wholesale",
        &[
            "prefer urn:iki:store:=/tmp/iki-np-absent-a.sock",
            "prefer urn:iki:ledger:=/tmp/iki-np-absent-b.sock",
        ],
    );
    let (seen, _) = serve(&home, &["--prefer", "urn:x:=/tmp/iki-np-absent-c.sock"]);
    assert!(
        seen.contains("; 1 mount(s)"),
        "the flag is the WHOLE topology, not an addition to the file's two: {seen}"
    );
}
