//! The outbound HTTP transport's wait bound through the REAL binary (ledger #2692): a server
//! that accepts and never answers is refused as `Timeout` at `http.timeout`, instead of holding
//! the REPL line that asked for as long as it likes, and a bad `http.timeout` stops the host at
//! start-up.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `config_home.rs`: the config home is named by
//! `--config-home`, and `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned
//! process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A scratch tree whose `config/` is the config home, holding `config_toml`.
fn scratch(case: &str, config_toml: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-http-timeout-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config")).expect("config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(dir.join("config").join("config.toml"), config_toml).expect("config.toml");
    dir
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--config-home")
        .arg(home.join("config"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS");
    command
}

fn both(out: &Output) -> String {
    format!(
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// How long the REPL may take to give the line back under `http.timeout = 1`. Generous on
/// purpose (a debug build's start-up on a loaded machine): it bounds how long a transport with
/// NO timeout takes to fail this test, never how fast a working one must be.
const BOUND: Duration = Duration::from_secs(120);

/// A server that accepts every connection, reads nothing back and never answers. The
/// connections are held open by the thread, which outlives the test.
fn silent_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a local port");
    let url = format!("http://{}/", listener.local_addr().expect("its address"));
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    url
}

/// Ledger #2692: before the fix the transport set no timeout, so this line never came back.
// Native-only (a spawned process): the wall clock bounds only how long a hang may take to fail.
#[allow(clippy::disallowed_methods)]
#[test]
fn a_read_from_a_server_that_never_answers_is_refused_as_timeout() {
    let url = silent_server();
    let home = scratch("silent", "http.timeout = 1\n");
    let mut child = command(&home, &[])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let mut stdin = child.stdin.take().expect("piped stdin");
    writeln!(stdin, "source urn:http:get url={url}").expect("the line is sent");
    drop(stdin);
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    }
    let stdout = drain(child.stdout.take().expect("piped stdout"));
    let stderr = drain(child.stderr.take().expect("piped stderr"));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child can be polled") {
            break status;
        }
        if started.elapsed() > BOUND {
            let _ = child.kill();
            let status = child.wait().expect("the killed child is reaped");
            let out = Output {
                status,
                stdout: stdout.join().expect("stdout drained"),
                stderr: stderr.join().expect("stderr drained"),
            };
            panic!(
                "the read did not return within {BOUND:?}: the transport has no timeout\n{}",
                both(&out)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let out = Output {
        status,
        stdout: stdout.join().expect("stdout drained"),
        stderr: stderr.join().expect("stderr drained"),
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("error: timeout:"),
        "the refusal must be a Timeout\n{}",
        both(&out)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A bad `http.timeout` stops every mode at start-up, naming the key and the file, rather than
/// reading as the default.
#[test]
fn a_bad_http_timeout_stops_the_host_at_start_up() {
    for (case, line) in [
        ("words", "http.timeout = \"ten\"\n"),
        ("zero", "http.timeout = 0\n"),
        ("fraction", "http.timeout = 1.5\n"),
    ] {
        let home = scratch(case, line);
        let out = command(&home, &["-e", "(+ 1 2)"])
            .stdin(Stdio::null())
            .output()
            .expect("the binary under test runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{case}\n{}", both(&out));
        assert!(
            stderr.contains("http.timeout") && stderr.contains("config.toml"),
            "{case}\n{}",
            both(&out)
        );
        assert!(out.stdout.is_empty(), "{case}\n{}", both(&out));
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// A valid one leaves the host as it was.
#[test]
fn a_valid_http_timeout_is_accepted() {
    let home = scratch("valid", "http.timeout = 1_200\n");
    let out = command(&home, &["-e", "(+ 1 2)"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test runs");
    assert!(out.status.success(), "{}", both(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "3",
        "{}",
        both(&out)
    );
    let _ = std::fs::remove_dir_all(&home);
}
