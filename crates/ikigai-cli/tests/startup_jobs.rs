//! Startup declarations survive process restarts and fail loudly when malformed.
#![cfg(all(feature = "embedded", unix))]

use std::path::PathBuf;
use std::process::{Command, Output};

fn home(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-startup-jobs-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config")).unwrap();
    std::fs::create_dir_all(dir.join("files")).unwrap();
    dir
}

fn run(home: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "--config-home",
            home.join("config").to_str().unwrap(),
            "--quiet",
            "-c",
            "source urn:time:jobs",
        ])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("IKIGAI_FILES", home.join("files"))
        .output()
        .unwrap()
}

#[test]
fn declared_job_is_registered_after_each_fresh_start() {
    let home = home("restart");
    std::fs::write(home.join("config/jobs"),
        "{\"instance\":\"repl\",\"target\":\"urn:startup:test\",\"method\":\"Sink\",\"every\":\"1s\",\"scopes\":[]}\n").unwrap();
    for _ in 0..2 {
        let out = run(&home);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("urn:startup:test"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn malformed_declaration_stops_start_and_names_its_line() {
    let home = home("malformed");
    std::fs::write(home.join("config/jobs"), "# operator jobs\n{broken}\n").unwrap();
    let out = run(&home);
    assert_eq!(out.status.code(), Some(2));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("jobs:2"), "{error}");
    assert!(error.contains("ikigai:"), "{error}");
}

struct Host {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
    errors: std::sync::mpsc::Receiver<String>,
}

fn lines(stream: impl std::io::Read + Send + 'static) -> std::sync::mpsc::Receiver<String> {
    use std::io::BufRead;
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stream).lines() {
            if send.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    receive
}

impl Host {
    fn start(home: &std::path::Path) -> Self {
        use std::process::Stdio;
        let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
            .args([
                "--config-home",
                home.join("config").to_str().unwrap(),
                "--name",
                "judge",
                "--plain",
                "--quiet",
            ])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("xdg"))
            .env("IKIGAI_FILES", home.join("files"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = lines(child.stdout.take().unwrap());
        let errors = lines(child.stderr.take().unwrap());
        Self {
            child,
            lines: output,
            errors,
        }
    }

    fn snapshot(&mut self) -> String {
        use std::io::Write;
        writeln!(self.child.stdin.as_mut().unwrap(), "source urn:time:jobs").unwrap();
        let mut result = String::new();
        loop {
            let line = self
                .lines
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("host answers time jobs");
            if line.is_empty() && !result.is_empty() {
                return result;
            }
            result.push_str(&line);
            result.push('\n');
        }
    }

    fn wait_for(&mut self, test: impl Fn(&str) -> bool) -> String {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let answer = self.snapshot();
            if test(&answer) {
                return answer;
            }
            assert!(std::time::Instant::now() < end, "timed out: {answer}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const CLOCK: &str =
    r#"{"instance":"judge","target":"urn:time:now","method":"Source","every":"50ms","scopes":[]}"#;

fn ran(answer: &str) -> bool {
    answer
        .lines()
        .any(|line| line.contains("every 50ms") && !line.contains("runs 0 "))
}

#[test]
fn declared_job_runs_after_each_restart() {
    let home = home("ticks");
    std::fs::write(home.join("config/jobs"), CLOCK).unwrap();
    for _ in 0..2 {
        let mut host = Host::start(&home);
        let answer = host.wait_for(ran);
        assert!(answer.contains("last:"), "{answer}");
    }
}

#[test]
fn live_creation_replacement_invalid_edit_and_removal() {
    let home = home("live");
    let mut host = Host::start(&home);
    assert!(!host.snapshot().contains("every 50ms"));
    let path = home.join("config/jobs");
    // Editor-style atomic replacement, while the host is already running.
    std::fs::write(home.join("config/new-jobs"), CLOCK).unwrap();
    std::fs::rename(home.join("config/new-jobs"), &path).unwrap();
    host.wait_for(ran);
    std::fs::write(home.join("config/new-jobs"), "# comment\n{broken}\n").unwrap();
    std::fs::rename(home.join("config/new-jobs"), &path).unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let error = host
            .errors
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        if error.contains("jobs:2:") {
            assert!(
                error.contains("keeping the previous startup jobs"),
                "{error}"
            );
            break;
        }
        assert!(std::time::Instant::now() < end, "no jobs refusal: {error}");
    }
    assert!(ran(&host.snapshot()), "invalid edit keeps the running job");
    let replacement = CLOCK.replace("50ms", "75ms");
    std::fs::write(home.join("config/new-jobs"), replacement).unwrap();
    std::fs::rename(home.join("config/new-jobs"), &path).unwrap();
    host.wait_for(|answer| answer.contains("every 75ms") && !answer.contains("every 50ms"));
    std::fs::remove_file(path).unwrap();
    host.wait_for(|answer| !answer.contains("every 75ms"));
    assert!(
        host.snapshot().contains("every 1s"),
        "the built-in clock is preserved"
    );
}
