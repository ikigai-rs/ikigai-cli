//! `--pending` on a served mount (ledger #3169), through the real binary: a host that starts
//! before its peer, answers Unavailable while the peer is absent, and reaches the peer once it
//! binds, with no restart. Without the flag the same mount still refuses to start.
#![cfg(all(unix, feature = "ipc", feature = "embedded"))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation};

/// A watchdog against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

fn home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ikmp-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

fn ikigai(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"));
    command
}

/// Kills the served host when the test ends, passing or not.
struct Host(Child);

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `ikigai serve <socket> <args>` and return it with its stderr up to the banner.
fn start(home: &Path, socket: &Path, args: &[&str]) -> (Host, String) {
    let mut child = ikigai(home)
        .arg("serve")
        .arg(socket)
        .args(args)
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
        if line.contains("serving on") {
            break;
        }
    }
    (Host(child), banner)
}

fn read_through(home: &Path, host: &Path, iri: &str) -> Output {
    ikigai(home)
        .arg("--connect")
        .arg(host)
        .args(["--plain", "-c", &format!("source {iri}")])
        .output()
        .expect("the client runs")
}

/// A real server of this user's on `socket`, answering `urn:hello`.
fn serve_peer(socket: &Path) {
    let hello = FnEndpoint::new("hello", |_inv| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"Hello, Ada".to_vec(),
        ))
    });
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:hello"), hello),
    ));
    let listener = ikigai_ipc::bind(socket).expect("the peer binds");
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_shared_on(Arc::new(kernel), listener);
    });
}

#[test]
fn a_pending_mount_starts_without_its_peer_and_reaches_it_once_it_binds() {
    let home = home("later");
    let host = home.join("h.sock");
    let peer = home.join("p.sock");
    let mount = format!("urn:peer:={}", peer.display());

    let (_host, banner) = start(&home, &host, &["--mount", &mount, "--pending"]);
    assert!(banner.contains("serving on"), "it must serve: {banner}");
    assert!(
        banner.contains("[pending"),
        "the banner must say the mount is not connected yet: {banner}"
    );

    let before = read_through(&home, &host, "urn:peer:hello");
    let stderr = String::from_utf8_lossy(&before.stderr);
    assert!(
        !before.status.success() && stderr.contains("--mount: connect"),
        "with no peer, the read fails and names the mount's dial: {stderr}"
    );

    serve_peer(&peer);

    let after = read_through(&home, &host, "urn:peer:hello");
    let stdout = String::from_utf8_lossy(&after.stdout);
    assert!(
        after.status.success() && stdout.contains("Hello, Ada"),
        "the same host reaches the peer with no restart: {stdout}\n{}",
        String::from_utf8_lossy(&after.stderr)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The default stays loud: a mount that does not say `--pending` still stops the start.
#[test]
fn a_mount_without_pending_still_refuses_to_start() {
    let home = home("refuse");
    let host = home.join("h.sock");
    let mount = format!("urn:peer:={}", home.join("absent.sock").display());

    let out = ikigai(&home)
        .arg("serve")
        .arg(&host)
        .args(["--mount", &mount])
        .output()
        .expect("the binary under test runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--mount: connect"), "{stderr}");
    let _ = std::fs::remove_dir_all(&home);
}
