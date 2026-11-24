//! The harness shared by the tests that drive the REAL binary against a real QUIC door
//! (`connect_retry.rs`, `connection_parity.rs`): a door killed on drop, a SHORT scratch home
//! (a host's Unix socket lives in it, and `sun_path` is 104 bytes on macOS), a hub served
//! on a port it binds itself, and `--connect` to it.
//!
//! Each test target uses part of it, so the parts another target does not are not dead code.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
pub const PATIENCE: Duration = Duration::from_secs(90);

/// A child killed when the test ends, whatever the test does.
pub struct Door(pub Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home unique to this case and process, with an empty config home. Kept SHORT:
/// the host's Unix socket lives in it, and `sun_path` is 104 bytes on macOS.
pub fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("irt-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

pub fn spawn(home: &Path, args: &[&str]) -> Command {
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

pub fn ok(out: Output, what: &str) -> String {
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
pub fn door(home: &Path, args: &[&str]) -> Result<(Door, String), String> {
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
pub fn peer(home: &Path, certs: &Path, bind: &str, name: &str) -> Result<(Door, String), String> {
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

pub fn generate(home: &Path) -> PathBuf {
    let certs = home.join("certs");
    ok(
        spawn(
            home,
            &["cert", "generate", "--dir", certs.to_str().unwrap()],
        )
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs"),
        "cert generate",
    );
    certs
}

pub fn text_of(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `ikigai --connect <hub> -c <command>`, the client dialing the hub itself.
pub fn connect(home: &Path, certs: &Path, address: &str, command: &str) -> Output {
    spawn(
        home,
        &[
            "--connect",
            address,
            "--cert-dir",
            certs.to_str().unwrap(),
            "--plain",
            "-c",
            command,
        ],
    )
    .stdin(Stdio::null())
    .output()
    .expect("the client runs")
}

pub const CONNECT_POLICY: &str =
    "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 1000\n";

/// Bring the hub back on `address` after `delay`, on its own thread; the door comes back on
/// the channel (and dies when the receiver drops it).
pub fn hub_back_after(
    home: &Path,
    certs: &Path,
    address: &str,
    delay: Duration,
) -> mpsc::Receiver<Door> {
    let (tx, rx) = mpsc::channel();
    let (h, c, a) = (home.to_path_buf(), certs.to_path_buf(), address.to_string());
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        for _ in 0..50 {
            if let Ok((door, _)) = peer(&h, &c, &a, "hub") {
                let _ = tx.send(door);
                return;
            }
            // The port may be a moment from free after the kill.
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the hub never came back on {a}");
    });
    rx
}
