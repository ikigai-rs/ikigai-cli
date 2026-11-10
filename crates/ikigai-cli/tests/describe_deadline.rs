//! A host's mounts describe under a SHORTER deadline than the one its clients reach it under
//! (ledger #1288), through the real binary: a `--connect` client asks a `serve <socket>` host
//! to describe a name its `--override` mount sends to a QUIC peer that never answers.
//!
//! Before, both deadlines were the same value, so the CLIENT's fired first (it started first)
//! and blamed the host: "no response from the kernel server (it may be hung or gone)" about a
//! host that was healthy and waiting on its peer. Now the host's own deadline fires first, and
//! the error the client prints names the silent peer.
//!
//! The peer never answers because it is STOPPED (`kill -STOP <pid>`, by PID): the host's
//! connection to it stays established, and every packet goes unanswered. `describe.timeout`
//! in the shared scratch config home is 3 s, so the test is bounded by seconds, not by the
//! 30 s default.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_redial.rs` is.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child killed when the test ends, whatever the test does (SIGKILL ends a stopped
/// process too).
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home with a config home that sets `describe.timeout`. Kept SHORT: the host's
/// Unix socket lives in it, and `sun_path` is 104 bytes on macOS.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("idd-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    std::fs::write(config.join("config.toml"), "describe.timeout = 3\n").expect("config.toml");
    dir
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

/// Start the binary with `args` and wait for its `serving on` banner; returns the door and
/// the address the banner names.
fn door(home: &Path, args: &[&str]) -> (Door, String) {
    let mut child = spawn(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never printed its banner: {e}"));
    let address = seen
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{seen}"))
        .to_string();
    (door, address)
}

#[test]
fn a_silent_peer_is_named_by_the_host_not_blamed_on_it() {
    let home = scratch("stop");
    let certs = home.join("certs");
    let made = spawn(
        &home,
        &["cert", "generate", "--dir", certs.to_str().unwrap()],
    )
    .stdin(Stdio::null())
    .output()
    .expect("cert generate runs");
    assert!(made.status.success(), "cert generate: {made:?}");

    let (peer, address) = door(
        &home,
        &[
            "serve",
            "quic://127.0.0.1:0",
            "--allow-unenrolled",
            "--name",
            "peer",
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
    );
    assert!(!address.ends_with(":0"), "the BOUND port: {address}");
    let socket = home.join("s.sock");
    let mount = format!("urn:host:={address}");
    let (_host, _) = door(
        &home,
        &[
            "serve",
            socket.to_str().unwrap(),
            "--override",
            &mount,
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
    );
    let ask = |command: &str| {
        spawn(
            &home,
            &[
                "--connect",
                socket.to_str().unwrap(),
                "--plain",
                "-c",
                command,
            ],
        )
        .stdin(Stdio::null())
        .output()
        .expect("the client runs")
    };
    // The socket door's accept loop may trail its banner by a moment. A READ, not the
    // describe under test: the host caches a description, and a cached one would answer
    // after the peer stops without asking it.
    let mut healthy = ask("source urn:host:identity");
    for _ in 0..40 {
        if healthy.status.success() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        healthy = ask("source urn:host:identity");
    }
    assert!(
        healthy.status.success(),
        "the mount reaches the peer while it answers: {}",
        String::from_utf8_lossy(&healthy.stderr)
    );

    let stopped = Command::new("kill")
        .args(["-STOP", &peer.0.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(stopped.success(), "the peer is stopped");

    // Native-only: a test of the host binary, never built for wasm, and elapsed wall time is
    // part of the claim. Bound to a `let` so the opt-out covers this one call.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = ask("describe urn:host:identity");
    let elapsed = start.elapsed();
    // The host answers in time, with the mount's "contract unavailable" placeholder whose
    // summary carries the transport's error; before, the client gave up first with an error
    // about the host. Both streams are read: which one carries it is not the claim.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("did not describe itself") && said.contains(&address),
        "the answer names the silent PEER ({address}), from the host's own deadline: {said}"
    );
    assert!(
        !said.contains("no response from the kernel server"),
        "the client's deadline did not fire first and blame the host: {said}"
    );
    // The client's own 3 s deadline would have failed the assertions above; this only keeps
    // a hang from passing as a slow answer.
    assert!(
        elapsed < Duration::from_secs(20),
        "answered by a deadline, not a hang: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
