//! A consumer may close stdout before the first byte or after reading a prefix.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
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
    let mut child = ikigai()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"help\n").unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut first_line = String::new();
    assert!(output.read_line(&mut first_line).unwrap() > 0);
    drop(output);
    // The first response was small enough to fit in the pipe. Only issue the
    // next command after closing its reader, so the failed write is certain.
    input.write_all(b"help\n").unwrap();
    // Keep stdin open: a closed consumer must end the REPL without waiting for EOF.
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
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
