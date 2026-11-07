//! A consumer may close stdout before the first byte or after reading a prefix.
#![cfg(all(feature = "embedded", unix))]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Held while a test creates pipes and spawns children (ledger #2725). On macOS, std makes
/// a pipe and only then marks it close-on-exec, so a child another test spawns in between
/// inherits that pipe: holding the REPL's stdout reader, it let the REPL's write succeed
/// with no broken pipe, and the REPL then waited on its open stdin until it was killed.
static SPAWNING: Mutex<()> = Mutex::new(());

fn spawning() -> MutexGuard<'static, ()> {
    SPAWNING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ikigai() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command.args([
        "--quiet",
        "--config-home",
        "/nonexistent-ikigai-broken-pipe-test",
    ]);
    command.stderr(Stdio::piped());
    command
}

#[test]
fn closed_stdout_exits_quietly() {
    let _spawning = spawning();
    let mut failures = Vec::new();
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["-c", "help"],
        vec!["-c", "source urn:host:identity"],
    ] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = ikigai()
            .args(&args)
            .stdin(Stdio::null())
            .stdout(writer)
            .output()
            .unwrap();
        if !output.status.success() || !output.stderr.is_empty() {
            failures.push(format!("{args:?}: {output:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn line_repl_stops_when_consumer_closes_stdout() {
    let _spawning = spawning();
    let expected = ikigai()
        .args(["-c", "help"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(expected.status.success(), "{expected:?}");
    assert!(!expected.stdout.is_empty());
    let mut child = ikigai()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"help\n").unwrap();
    // The first response is read on its own thread under a deadline (ledger #2725): with
    // stdin held open, a response shorter than the reference (or never flushed) would block
    // `read_exact` forever, and the macOS CI job once timed out here with nothing to show.
    let output = child.stdout.take().unwrap();
    let want = expected.stdout.len();
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = output;
        let mut first_response = Vec::with_capacity(want);
        let mut chunk = [0; 4096];
        while first_response.len() < want {
            match output.read(&mut chunk[..(want - first_response.len()).min(4096)]) {
                Ok(0) | Err(_) => break,
                Ok(n) => first_response.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = sent.send((first_response, output));
    });
    let (first_response, output) = match received.recv_timeout(Duration::from_secs(10)) {
        Ok(read) => read,
        Err(_) => {
            child.kill().unwrap();
            let stderr = child.wait_with_output().unwrap().stderr;
            panic!(
                "the first `help` response did not arrive within 10s (expected {want} bytes); \
                 stderr: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
    };
    assert_eq!(
        first_response,
        expected.stdout,
        "the REPL's first `help` response ({} bytes) differs from `-c help` ({want} bytes)",
        first_response.len()
    );
    drop(output);
    // Read the whole first response before closing its reader, so even a small
    // pipe cannot fail during that response and race the next stdin write.
    assert_repl_stops(child, input);
}

/// A process that still holds the REPL's stdout reader, as a child that inherited it
/// would, keeps the REPL's next write from failing; once it lets go, the write after
/// that must end the REPL (ledger #2725).
#[test]
fn line_repl_stops_once_a_leaked_reader_lets_go() {
    let _spawning = spawning();
    let mut child = ikigai()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.take().unwrap();
    let output = OwnedFd::from(child.stdout.take().unwrap());
    let mut holder = Command::new("sleep")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .spawn()
        .unwrap();
    drop(output);
    assert_repl_stops(child, input);
    assert!(holder.wait().unwrap().success());
}

/// With its stdout reader closed, the REPL must exit quietly at its next answer, without
/// waiting for stdin to end. `help` is sent again until it does, so a write the kernel
/// still accepted (a reader held elsewhere for a while) cannot leave it waiting on stdin.
fn assert_repl_stops(mut child: Child, mut input: ChildStdin) {
    // This Unix-only subprocess test cannot run on wasm; use a real timeout
    // to reap a native child that fails to exit.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    let mut sent: Option<Instant> = None;
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() >= Duration::from_secs(10) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("REPL did not stop after stdout closed: {output:?}");
        }
        if sent.is_none_or(|at| at.elapsed() >= Duration::from_millis(100)) {
            // The REPL may exit between the check and this write; that error is the point.
            let _ = input.write_all(b"help\n");
            #[allow(clippy::disallowed_methods)]
            let now = Instant::now();
            sent = Some(now);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn other_stdout_errors_still_fail_with_a_diagnostic() {
    let _spawning = spawning();
    let output = ikigai()
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(
            std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("ikigai: could not write stdout:"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}
