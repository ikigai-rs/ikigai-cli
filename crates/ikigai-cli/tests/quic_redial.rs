//! A host that mounts a QUIC peer keeps answering when that peer RESTARTS (ledger #1262),
//! through the REAL binary: the shape of gonk's `prefer urn:llm:=quic://127.0.0.1:4433`.
//!
//! One `serve quic://` door is the peer. One `serve <socket> --prefer|--override` is the
//! host that mounts it, a long-lived process holding ONE QUIC connection, as gonk does. A
//! short client asks the host; the peer is killed (no close frame, like a launchd restart)
//! and a new one started on the SAME port; the client asks again. The second answer must come
//! from the NEW peer, promptly.
//!
//! Why this heals, so a failure here can be read: the door derives its stateless-reset key
//! from its identity (ledger #1092), so the replacement resets the connection its predecessor
//! held, the host's next round trip fails at once on it, and `QuicResolver` redials and
//! replays the read. A peer that cannot reset (one older than 0.1.46) costs the host one
//! describe deadline, which marks the connection stale so the next call redials first.
//!
//! ★ Every door binds port 0 and the test reads the bound port off its banner (field guide 9h,
//! ledger #1223), and the replacement then binds that same port by number.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_principals.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// The bound on the healed request. Generous for a loaded CI runner; what it rules out is
/// the failure the ledger item describes, a describe deadline (30 s) or the idle timeout
/// (300 s) paid because the host kept the dead connection.
const HEALED_WITHIN: Duration = Duration::from_secs(20);

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home unique to this case and process, with an empty config home. Kept SHORT:
/// the host's Unix socket lives in it, and `sun_path` is 104 bytes on macOS.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iqr-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        // The test harness may run with the developer's own overrides set; these would
        // point the child at real enrolment files.
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Start the binary with `args` and wait for its `serving on` banner. Returns the door and
/// the address the banner names, or `Err` with what it printed when it exited first (a
/// replacement that found the port still held).
fn door(home: &Path, args: &[&str]) -> Result<(Door, String), String> {
    let mut child = spawn(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    // Keep draining after the banner, so the door's log is a pipe someone reads.
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
    match seen
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
    {
        Some(address) => Ok((door, address.to_string())),
        None => Err(seen),
    }
}

/// The peer: `serve quic://<bind> --name <name>`, its address read off the banner.
fn peer(home: &Path, certs: &Path, bind: &str, name: &str) -> Result<(Door, String), String> {
    door(
        home,
        &[
            "serve",
            bind,
            "--allow-unenrolled",
            "--name",
            name,
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
    )
}

/// Ask the host `command` over its socket, retrying a refused first connect (the socket
/// door's accept loop may trail its banner by a moment).
fn ask(home: &Path, socket: &Path, command: &str) -> Output {
    let socket = socket.to_str().unwrap();
    let mut last = None;
    for _ in 0..40 {
        let out = spawn(home, &["--connect", socket, "--plain", "-c", command])
            .stdin(Stdio::null())
            .output()
            .expect("the client runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains("connect") {
            return out;
        }
        last = Some(out);
        std::thread::sleep(Duration::from_millis(100));
    }
    last.expect("at least one attempt")
}

/// Which peer answered: its `--name` is in the principal the door minted for the host's
/// certificate (`urn:iki:host:{name}:client:<fingerprint>`). A `--prefer` mount that fell
/// back to the LOCAL binding answers with no principal at all, so it cannot pass for either.
fn answered_by(identity: &str) -> Option<String> {
    identity
        .lines()
        .find_map(|line| line.strip_prefix("principal urn:iki:host:"))
        .and_then(|rest| rest.split(':').next())
        .map(str::to_string)
}

/// The scenario, under one mount flag (`--prefer` is gonk's and the incident's; `--override`
/// has no local fallback to hide behind).
fn a_restarted_peer_is_redialled(flag: &str, case: &str) {
    let home = scratch(case);
    let certs = home.join("certs");
    ok(
        spawn(
            &home,
            &["cert", "generate", "--dir", certs.to_str().unwrap()],
        )
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs"),
        "cert generate",
    );
    let (first, address) =
        peer(&home, &certs, "quic://127.0.0.1:0", "first").expect("the first peer serves");
    assert!(
        !address.ends_with(":0"),
        "the banner names the BOUND port: {address}"
    );

    let socket = home.join("s.sock");
    let mount = format!("urn:host:={address}");
    let (_host, _) = door(
        &home,
        &[
            "serve",
            socket.to_str().unwrap(),
            flag,
            &mount,
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
    )
    .expect("the host serves");

    let before = ok(
        ask(&home, &socket, "source urn:host:identity"),
        "the first ask",
    );
    assert_eq!(
        answered_by(&before).as_deref(),
        Some("first"),
        "the mount reaches the peer: {before}"
    );

    // Kill the peer outright (no close frame), then serve again on the SAME port. The kill
    // and the wait are synchronous, so the port is free; a bounded retry covers a platform
    // that releases it a beat late.
    drop(first);
    let mut tries = 0;
    let _second = loop {
        match peer(&home, &certs, &address, "second") {
            Ok((door, _)) => break door,
            Err(_) if tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(seen) => panic!("the replacement never served on {address}:\n{seen}"),
        }
    };

    // Native-only: a test of the host binary over a real QUIC door, never built for wasm, and
    // elapsed wall time is the measurement. Bound to a `let` so the opt-out covers this call.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let after = ok(
        ask(&home, &socket, "source urn:host:identity"),
        "the ask after the restart",
    );
    let elapsed = start.elapsed();
    assert_eq!(
        answered_by(&after).as_deref(),
        Some("second"),
        "the host redialled the NEW peer: {after}"
    );
    assert!(
        elapsed < HEALED_WITHIN,
        "healed by a reset and a redial, not a deadline: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_prefer_mount_redials_a_restarted_peer() {
    a_restarted_peer_is_redialled("--prefer", "p");
}

#[test]
fn an_override_mount_redials_a_restarted_peer() {
    a_restarted_peer_is_redialled("--override", "o");
}
