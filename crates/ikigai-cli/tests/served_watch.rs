//! A SERVED kernel sees a workspace file changed on disk, through the REAL binary (ledger #246,
//! #1425).
//!
//! `urn:file:*` is bound `.cacheable().depends_on(target)` on every served surface, so the
//! first read of a file is cached under the `urn:file:<rel>` golden thread and every later
//! read is a hit until something cuts that thread. A `Sink` through the kernel cuts it; a
//! file replaced on disk by anything else (an editor, a deploy) is cut only by a filesystem
//! watcher. Until this test existed only the REPL and the daemon ran one, so the edge kept
//! rendering a replaced `foaf.xsl` until its unit restarted (2026-09-09).
//!
//! Each case starts a door, reads a file through it, rewrites the file with `std::fs` (the
//! out-of-band edit the kernel cannot see), and polls the SAME door until it answers with the
//! new bytes, bounded by [`FRESH_WITHIN`]. Without a watch the door answers the old bytes
//! forever, so the deadline is what fails.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `host_posture.rs` is: `HOME`, `XDG_CONFIG_HOME`
//! and `IKIGAI_FILES` are set on the spawned process only.
//!
//! Gated on `web` AND `ipc` together, like `host_posture.rs`: whole under `--all-features`
//! (what `ci.yml` passes, on Linux and macOS), empty otherwise, so no helper is dead code
//! under some feature combination.
#![cfg(all(feature = "embedded", feature = "ipc", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door gets to print its banner. A watchdog against a hang, not a measurement.
const PATIENCE: Duration = Duration::from_secs(90);

/// How long a changed file may take to be served fresh. FSEvents on macOS batches its
/// notifications (a fraction of a second, longer under load) and inotify is near-instant;
/// this is generous for both, and a door that never sees the change fails at it.
const FRESH_WITHIN: Duration = Duration::from_secs(20);

/// A child process that is killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home with an empty config home and a workspace holding `live.txt` = `one`.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-sw-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(dir.join("files").join("live.txt"), "one").expect("the first version");
    dir
}

/// `ikigai <args…>` against `home`, every ambient path pointing into the scratch tree.
fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"));
    command
}

/// Start a door and return it with everything it wrote to stderr up to the line containing
/// `ready` (the banner, which is the readiness signal).
fn start(home: &Path, args: &[&str], ready: &'static str) -> (Door, String) {
    let mut child = spawn(home, args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let done = line.contains(ready);
            seen.push_str(&line);
            seen.push('\n');
            if done {
                break;
            }
        }
        let _ = tx.send(seen);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never printed `{ready}` in {PATIENCE:?}: {e}"));
    (door, seen)
}

/// The port an HTTP door bound, read off its banner (`serving HTTP on 127.0.0.1:<port>`).
fn bound_port(banner: &str) -> u16 {
    banner
        .lines()
        .find_map(|line| line.split("serving HTTP on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .map(|addr| addr.port())
        .unwrap_or_else(|| panic!("no bound address on the banner: {banner}"))
}

/// `GET path` over plain HTTP/1.1, returning (status line, body).
fn get(port: u16, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("nothing accepted on {port}: {e}"));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    (
        head.lines().next().unwrap_or_default().to_string(),
        body.to_string(),
    )
}

/// Ask a serving IPC door for a resource through the binary's own client. Returns stdout.
fn ask(home: &Path, connect: &str, command: &str) -> String {
    let out = spawn(home, &["--connect", connect, "--plain", "-c", command])
        .stdin(Stdio::null())
        .output()
        .expect("the client runs");
    assert!(
        out.status.success(),
        "`{command}` failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Read through `read` until it answers `two`, or panic at [`FRESH_WITHIN`] naming the last
/// answer. Polls rather than sleeping once: the watcher's latency is the platform's, and a
/// single sleep would pass by luck on a fast machine and fail by luck on a slow one.
fn served_fresh(door: &str, mut read: impl FnMut() -> String) {
    // Native-only: a test of the host binary, never built for wasm (the workspace bans
    // `Instant::now` because it panics there). Bound to a `let` so the opt-out covers one call.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < FRESH_WITHIN {
        last = read();
        if last.trim() == "two" {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{door}: a file rewritten on disk was still served stale after {FRESH_WITHIN:?} \
         (last answer: {last:?}); nothing cut its `urn:file:` thread"
    );
}

/// The HTTP door, the one the edge runs: `/file/live.txt` is `urn:file:live.txt`, read under
/// an operator ceiling that grants the workspace.
#[test]
fn the_http_door_serves_a_file_changed_on_disk_without_a_restart() {
    let home = scratch("http");
    let files = home.join("files");
    let cap = format!("urn:cap:fs:read:{}", files.display());
    let (_door, banner) = start(
        &home,
        &["serve", "--http", "0", "--cap", &cap],
        "serving HTTP on",
    );
    assert!(
        banner.contains("ikigai: watching "),
        "the door must say it watches the workspace: {banner}"
    );
    let port = bound_port(&banner);

    let (status, body) = get(port, "/file/live.txt");
    assert!(status.contains("200"), "{status} {body}");
    assert_eq!(body, "one", "the first read, now cached");

    // std::fs on purpose: this IS the out-of-band edit (a deploy replacing a stylesheet).
    std::fs::write(files.join("live.txt"), "two").expect("the out-of-band edit");
    served_fresh("the HTTP door", || get(port, "/file/live.txt").1);
    let _ = std::fs::remove_dir_all(&home);
}

/// The IPC door (`ikigai serve <socket>`), the same-user surface Emacs and the MCP server
/// connect to. Its kernel is the full trusted root, a different composer from the HTTP door's,
/// so it is its own case.
#[test]
fn the_ipc_door_serves_a_file_changed_on_disk_without_a_restart() {
    let home = scratch("ipc");
    let files = home.join("files");
    // ⚠ A SHORT socket path: `sockaddr_un` fits 104 bytes on macOS and a temp dir there is
    // most of that on its own.
    // In a private 0700 directory: the door refuses to serve straight in a shared `/tmp`
    // (ledger #3634).
    let sock_dir = format!("/tmp/iki-sw{}", std::process::id());
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
        .create(&sock_dir)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .expect("the socket directory");
    let sock = format!("{sock_dir}/s.sock");
    let _ = std::fs::remove_file(&sock);
    let (_door, banner) = start(&home, &["serve", &sock], "serving on");
    assert!(
        banner.contains("ikigai: watching "),
        "the door must say it watches the workspace: {banner}"
    );

    assert_eq!(
        ask(&home, &sock, "source urn:file:live.txt").trim(),
        "one",
        "the first read, now cached"
    );
    std::fs::write(files.join("live.txt"), "two").expect("the out-of-band edit");
    served_fresh("the IPC door", || {
        ask(&home, &sock, "source urn:file:live.txt")
    });
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&home);
}
