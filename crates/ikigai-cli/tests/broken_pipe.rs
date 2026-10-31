//! A consumer may close stdout before the first byte or after reading a prefix.
#![cfg(all(feature = "embedded", unix))]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
    input.write_all(b"help\n").unwrap();
    // Keep stdin open: a closed consumer must end the REPL without waiting for EOF.
    // This Unix-only subprocess test cannot run on wasm; use a real timeout
    // to reap a native child that fails to exit.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() >= Duration::from_secs(10) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("REPL did not stop after stdout closed: {output:?}");
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
