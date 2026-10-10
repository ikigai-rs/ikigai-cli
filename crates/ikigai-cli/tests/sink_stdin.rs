//! A content-less `sink` and the stdin it inherits, through the REAL binary (ledger #1088).
//!
//! `ikigai -c 'sink …'` with no content reads stdin for it, so a secret can be piped in and
//! never sit on the command line. The defect: the read waited for stdin to END, and an
//! inherited pipe that nobody writes never ends. An agent's backgrounded shell is exactly that,
//! so `sink urn:iki:ledger:close item=N` hung forever unless every caller remembered
//! `</dev/null`. Now the read waits a grace period for the first byte; a stdin silent that long
//! is idle, and the sink goes without `content`.
//!
//! Each case spawns the binary with `Stdio::piped()` and KEEPS the write end, which is the
//! idle descriptor. The child is reaped with `wait()` on a helper thread (never `try_wait()`:
//! stderr EOF says a child is exiting, not that it has been reaped), and a deadline on that
//! thread turns the old hang into a failure instead of a stuck test.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `why_views.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Far above the binary's 2 s grace plus a debug start, far below "forever".
const DEADLINE: Duration = Duration::from_secs(60);

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ss-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

/// What the child did: its status, its stderr, and how long it took.
struct Ran {
    status: ExitStatus,
    stderr: String,
    took: Duration,
}

/// Run `ikigai -c <command>` with a piped stdin, hand the write end to `feed`, and reap the
/// child on a thread so a hang becomes a failed deadline rather than a stuck test.
fn run(home: &Path, command: &str, feed: impl FnOnce(std::process::ChildStdin)) -> Ran {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["-c", command])
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ikigai");
    let stdin = child.stdin.take().expect("piped stdin");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let output = child.wait_with_output();
        let _ = tx.send(output);
    });
    feed(stdin);
    match rx.recv_timeout(DEADLINE) {
        Ok(output) => {
            let output = output.expect("reap ikigai");
            Ran {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                took: started.elapsed(),
            }
        }
        Err(_) => {
            // Stop exactly the child this test spawned, by its pid.
            let _ = Command::new("kill").arg(pid.to_string()).status();
            panic!(
                "`ikigai -c '{command}'` did not finish within {DEADLINE:?}: the idle-stdin hang"
            );
        }
    }
}

/// The hub's shape: a content-less sink whose stdin is open and silent. It finishes, says on
/// stderr that nothing arrived, and — since `urn:file:` requires `content` — writes nothing,
/// where an empty body would have truncated the file.
#[test]
fn a_content_less_sink_does_not_wait_on_an_idle_stdin() {
    let home = scratch("idle");
    std::fs::write(home.join("files").join("note.txt"), "kept").unwrap();
    let mut held = None;
    let ran = run(&home, "sink urn:file:note.txt", |stdin| held = Some(stdin));
    drop(held);
    assert!(
        ran.took < Duration::from_secs(30),
        "it finished, but only after {:?}",
        ran.took
    );
    assert!(
        ran.stderr.contains("nothing arrived on stdin"),
        "the idle stdin is named: {}",
        ran.stderr
    );
    assert!(
        !ran.status.success(),
        "a required content was missing: {}",
        ran.stderr
    );
    assert_eq!(
        std::fs::read_to_string(home.join("files").join("note.txt")).unwrap(),
        "kept",
        "an idle stdin must not overwrite the file with an empty body"
    );
}

/// The case the stdin read exists for is unchanged: piped bytes are the content.
#[test]
fn a_piped_value_is_still_the_content() {
    let home = scratch("piped");
    let ran = run(&home, "sink urn:file:secret.txt", |mut stdin| {
        stdin.write_all(b"s3cr3t").unwrap();
    });
    assert!(ran.status.success(), "{}", ran.stderr);
    assert_eq!(
        std::fs::read_to_string(home.join("files").join("secret.txt")).unwrap(),
        "s3cr3t"
    );
}

/// A producer that is slow to START, but inside the grace, still delivers.
#[test]
fn a_producer_inside_the_grace_still_delivers() {
    let home = scratch("slow");
    let ran = run(&home, "sink urn:file:late.txt", |mut stdin| {
        std::thread::sleep(Duration::from_millis(300));
        stdin.write_all(b"late but ").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        stdin.write_all(b"whole").unwrap();
    });
    assert!(ran.status.success(), "{}", ran.stderr);
    assert_eq!(
        std::fs::read_to_string(home.join("files").join("late.txt")).unwrap(),
        "late but whole"
    );
}
