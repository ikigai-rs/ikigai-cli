//! A `--daemon` whose `--mount`/`--override` target does not answer at start (ledger #3847),
//! through the real binary. The daemon is a long-running host: it starts anyway, says ONE
//! warning line naming the target, and dials that target again on each use, so a peer that
//! comes back is picked up with no restart. A one-shot `-c` with the same override still
//! fails loudly, as it did before.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set
//! on each spawned process only.
#![cfg(all(unix, feature = "embedded"))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A watchdog against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// Kept SHORT: a Unix socket lives in it, and `sun_path` is 104 bytes on macOS.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("idu-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

fn ikigai(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

/// Kills the daemon when the test ends, passing or not.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `ikigai <args> --daemon` and collect its stderr until the `daemon up` banner, or
/// until the process exits (its stderr closes) — the failure this file reproduces.
fn start_daemon(home: &Path, args: &[&str]) -> (Daemon, String) {
    let mut child = ikigai(home)
        .args(args)
        .arg("--daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test runs");
    let stderr = child.stderr.take().expect("piped stderr");
    let (lines, seen) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                return;
            }
        }
    });
    let mut banner = String::new();
    while let Ok(line) = seen.recv_timeout(PATIENCE) {
        banner.push_str(&line);
        banner.push('\n');
        if line.contains("daemon up") {
            break;
        }
    }
    (Daemon(child), banner)
}

/// What the daemon must have done: started, still running, and said one warning line that
/// names the target it could not reach.
fn assert_started_with_one_warning(daemon: &mut Daemon, banner: &str, target: &str) {
    assert!(
        banner.contains("daemon up"),
        "the daemon must start without its peer: {banner}"
    );
    assert!(
        daemon.0.try_wait().expect("the daemon's status").is_none(),
        "the daemon must keep running: {banner}"
    );
    let warnings: Vec<&str> = banner
        .lines()
        .filter(|line| line.contains("not reachable at start"))
        .collect();
    assert_eq!(warnings.len(), 1, "one warning line: {banner}");
    assert!(
        warnings[0].contains(target),
        "the warning names the target: {banner}"
    );
}

#[test]
fn a_daemon_starts_when_its_override_socket_is_absent() {
    let home = scratch("ipc");
    let target = home.join("absent.sock").display().to_string();
    let spec = format!("urn:layer:={target}");
    let (mut daemon, banner) = start_daemon(&home, &["--override", &spec]);
    assert_started_with_one_warning(&mut daemon, &banner, &target);
    drop(daemon);
    let _ = std::fs::remove_dir_all(&home);
}

/// The one-shot stays loud: `-c` with an override that cannot connect still exits 1, naming
/// the flag and the target. Only a long-running host tolerates an absent peer.
#[test]
fn a_one_shot_with_an_absent_override_still_fails() {
    let home = scratch("oneshot");
    let target = home.join("absent.sock").display().to_string();
    let spec = format!("urn:layer:={target}");
    let out = ikigai(&home)
        .args(["--override", &spec, "--plain", "-c", "source urn:layer:x"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("--override: connect") && stderr.contains(&target),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The incident's own shape: `--override urn:layer:=quic://…` to a port nothing answers on.
#[cfg(feature = "quic")]
#[test]
fn a_daemon_starts_when_its_override_quic_target_does_not_answer() {
    let home = scratch("quic");
    let certs = home.join("certs");
    let generated = ikigai(&home)
        .args(["cert", "generate", "--dir", certs.to_str().unwrap()])
        .output()
        .expect("cert generate runs");
    assert!(
        generated.status.success(),
        "cert generate: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    // A UDP port bound and released: nothing is listening on it when the daemon dials.
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("a free UDP port")
        .port();
    let target = format!("quic://127.0.0.1:{port}");
    let spec = format!("urn:layer:={target}");
    let (mut daemon, banner) = start_daemon(
        &home,
        &["--override", &spec, "--cert-dir", certs.to_str().unwrap()],
    );
    assert_started_with_one_warning(&mut daemon, &banner, &target);
    drop(daemon);
    let _ = std::fs::remove_dir_all(&home);
}

/// Start `ikigai <args> --daemon` expecting it to REFUSE: it must exit, with code 2, before
/// its banner, naming `says`. Round 2 of ledger #3847: only a peer that does not answer is
/// tolerated, and every check that needs no peer stays fatal, as on main.
#[cfg(feature = "quic")]
fn assert_daemon_refuses(home: &Path, args: &[&str], says: &str) {
    let (mut daemon, banner) = start_daemon(home, args);
    assert!(
        !banner.contains("daemon up") && !banner.contains("not reachable at start"),
        "a misconfiguration must not start the daemon: {banner}"
    );
    let status = daemon.0.wait().expect("the daemon's status");
    assert_eq!(status.code(), Some(2), "{banner}");
    assert!(banner.contains(says), "names the cause ({says}): {banner}");
}

/// `--cert-dir /typo`: the client identity cannot be read, which no wait fixes.
#[cfg(feature = "quic")]
#[test]
fn a_daemon_with_a_missing_cert_dir_still_exits_2() {
    let home = scratch("nocert");
    let missing = home.join("no-such-certs");
    assert_daemon_refuses(
        &home,
        &[
            "--override",
            "urn:layer:=quic://127.0.0.1:9",
            "--cert-dir",
            missing.to_str().unwrap(),
        ],
        "client.crt",
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A `quic://` address that does not parse (no port) is a typo, not an absent peer.
#[cfg(feature = "quic")]
#[test]
fn a_daemon_with_an_unparseable_quic_address_still_exits_2() {
    let home = scratch("badaddr");
    assert_daemon_refuses(
        &home,
        &["--override", "urn:layer:=quic://no-port-here"],
        "no-port-here",
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A `peer:<name>` this machine holds no pinned certificate for is refused before any browse,
/// so it is not mistaken for a peer that is away.
#[cfg(feature = "quic")]
#[test]
fn a_daemon_with_an_unenrolled_peer_still_exits_2() {
    let home = scratch("unenrolled");
    assert_daemon_refuses(
        &home,
        &["--override", "urn:layer:=peer:nobody-enrolled"],
        "holds no pinned certificate",
    );
    let _ = std::fs::remove_dir_all(&home);
}
