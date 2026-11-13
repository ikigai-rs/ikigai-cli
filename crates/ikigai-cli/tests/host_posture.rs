//! `urn:host:posture` through the REAL binary, over the doors an operator actually uses.
//!
//! The unit tests in `ikigai-embedded` pin the two faces and the capability gate against a
//! constructed value. This file pins the thing the resource exists for: **a SERVING process,
//! asked from outside, about a composition nobody watched happen.** That is the whole
//! argument of ledger #428 — the peer that cost plasma a ~120s `urn:kernel:actions` (#408)
//! had composed two mounts back at its own caller, and the only way to learn it was to have
//! been present at its startup, to grep a log, or to restart it.
//!
//! Three properties, one test each:
//!
//! 1. **The serving process answers about ITSELF.** A door started with a `config.toml` on
//!    disk reports the mounts it composed, named, over its own socket.
//! 2. **The banner and the resource cannot disagree**, because they render from one recorded
//!    value through one renderer. Asserted by comparing the door's own stderr against the
//!    resource's bytes — which is the only place that claim is observable end to end.
//! 3. ★ **It is off the public door.** `GET /host/posture` on a public HTTP edge is a 403,
//!    and the same door with `--cap urn:cap:host:posture` serves it. The paths are the
//!    sensitive part (a mount target names another machine, a cert path describes this
//!    disk); a fingerprint is a hash of a public certificate and discloses nothing.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, not by `set_var`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the SPAWNED process only, so the developer's `~/.config/ikigai`
//! is never read and never written, and this test process never mutates an environment it
//! shares with the harness's other threads.
//!
//! ⚠ Gated on `web` AND `ipc` together, so this file is empty under default features and
//! whole under `--all-features` (which is what `ci.yml` passes, on Linux and macOS). Split
//! per-feature the helpers would be dead code under some combination, and `-D warnings`
//! turns that into a red build somewhere nobody looks.
#![cfg(all(feature = "embedded", feature = "ipc", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner before the test gives up. Generous: a watchdog
/// against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child process that is killed when the test ends, whatever the test does. A server
/// outliving its test would hold a port or a socket for the rest of the run.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch config home carrying `lines` as `mount` keys. Named per case so the tests
/// cannot see each other's files.
fn scratch(case: &str, lines: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-hp-{}-{case}", std::process::id()));
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    let body: String = lines
        .iter()
        .map(|line| format!("mount = \"{line}\"\n"))
        .collect();
    std::fs::write(config.join("config.toml"), body).expect("scratch config.toml");
    dir
}

/// `ikigai <args…>` against `home`, with every ambient path pointing into the scratch tree.
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
/// `ready`. The banner IS the readiness signal, so this is also how the test knows the door
/// is up without polling for a socket that is bound last.
fn start(home: &Path, args: &[&str], ready: &'static str) -> (Door, String) {
    let mut child = spawn(home, args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let stderr = child.stderr.take().expect("piped stderr");
    // Read on a worker so the MAIN thread keeps a timeout: a blocking read against a door
    // that neither prints nor exits would hang the whole test binary.
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

/// Assert that an IPC door's socket is BOUND the moment its banner has printed (ledger #430).
///
/// ★ The banner is the readiness signal. `serve_ipc` used to print `serving on <path>` and
/// only then call `ikigai_ipc::serve`, which is what bound, so a client that dialed on the
/// banner got `No such file or directory` roughly half the time, and this file carried a
/// poller for the socket. The door now binds first (`ikigai_ipc::bind`, then `serve_on`), as
/// the HTTP and QUIC doors do (ledger #1223, see [`bound_port`]), so this checks once and
/// never waits: a regression fails here instead of being absorbed by a retry.
fn assert_bound(path: &str) {
    assert!(
        Path::new(path).exists(),
        "`{path}` must be bound when the banner prints: the banner is the readiness signal"
    );
}

/// Ask a serving door for a resource, through the binary's own client. Returns stdout.
fn ask(home: &Path, connect: &str, command: &str) -> String {
    let out = spawn(home, &["--connect", connect, "--plain", "-c", command])
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

/// The port an HTTP door BOUND, read off its banner (`serving HTTP on 127.0.0.1:<port>`).
///
/// ★ The door is started with `--http 0` and the KERNEL picks the port (ledger #1223). What
/// stood here chose one itself — bind `127.0.0.1:0`, read the port, release it — and on
/// macOS a released port is not reliably free: `socket()` and `FD_CLOEXEC` are two calls
/// there, so a child spawned by one of this binary's other tests in that window inherits
/// the listener and keeps the port LISTENING after this test dropped it. The door then
/// failed to bind (EADDRINUSE, exit 1) while `get` connected into the inheritor's backlog
/// and read `ECONNRESET` when the inheritor exited: ~2% of runs under load, and the CI
/// failure the item names. A banner that printed before the bind could not carry the
/// bound port, which is why the harness had to guess; the door now binds first.
fn bound_port(banner: &str) -> u16 {
    let port = banner
        .lines()
        .find_map(|line| line.split("serving HTTP on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .map(|addr| addr.port())
        .unwrap_or_else(|| panic!("no bound address on the banner: {banner}"));
    assert_ne!(
        port, 0,
        "the banner must name the port the door BOUND, not the one it was asked for: {banner}"
    );
    port
}

/// `GET path` over plain HTTP/1.1, returning (status line, body). Written by hand rather
/// than with a client crate: the assertion is about the STATUS a public door answers with,
/// and adding a dependency to read one line of it would be the larger change.
///
/// One connect, no retry: the door binds before it prints the banner [`start`] waits for,
/// so a refused connect here is a real failure, not a race to paper over.
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
    let status = head.lines().next().unwrap_or_default().to_string();
    (status, body.to_string())
}

/// ★ A SERVING process, asked from outside, about a composition nobody watched. The two
/// mounts are named — which is the fact #408 turned on and #418's count could not carry.
#[test]
fn a_serving_door_reports_the_mounts_it_composed() {
    let home = scratch(
        "ipc",
        // ⚠ Both `prefer`, and that is forced rather than chosen: an `alias`/`override`
        // mount dials EAGERLY and a door whose peer is absent refuses to start (by design —
        // #410). A prefer-mount connects on demand, so an absent peer is normal. The mode
        // WORD is pinned by the unit tests in `ikigai-embedded`, which need no peer at all.
        &[
            "prefer urn:iki:store:=/tmp/iki-hp-absent-a.sock",
            "prefer urn:cal:=/tmp/iki-hp-absent-b.sock",
        ],
    );
    // ⚠ A SHORT socket path, not one under the scratch home: `sockaddr_un` fits 103 bytes
    // on macOS and a temp dir there is most of that on its own.
    // In a private 0700 directory: the door refuses to serve straight in a shared `/tmp`
    // (ledger #3634).
    let sock_dir = format!("/tmp/iki-hp-{}", std::process::id());
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
    assert_bound(&sock);
    let text = ask(&home, &sock, "source urn:host:posture");

    assert!(text.contains(&format!("door       {sock}")), "{text}");
    assert!(
        text.contains("mount   prefer urn:iki:store: -> /tmp/iki-hp-absent-a.sock"),
        "the first config line must be named: {text}"
    );
    assert!(
        text.contains("mount   prefer urn:cal: -> /tmp/iki-hp-absent-b.sock"),
        "the second config line, with its own prefix and target: {text}"
    );
    // The freshness half. Both halves: what is frozen, and that nothing here is live.
    assert!(text.contains("as of      STARTUP"), "{text}");
    assert!(
        text.contains("re-read of the config home"),
        "the report must say it is the PROCESS's composition, not the file's: {text}"
    );
    assert!(text.contains("reloads    nothing"), "{text}");

    // ★ The banner and the resource render from ONE value through ONE renderer, so the
    // mount lines are the same BYTES. Two renderers over the same facts is how a diagnostic
    // and a resource drift into two spellings of one thing (#418/#426), and this is the only
    // place that claim is observable from outside the process.
    for line in banner.lines().filter_map(|l| l.strip_prefix("ikigai: ")) {
        if line.starts_with("mount   ") {
            assert!(
                text.contains(line),
                "the banner said `{line}` and the resource does not: {text}"
            );
        }
    }

    // The graph face, skolemized: one stable IRI per mount, no blank nodes.
    let turtle = ask(&home, &sock, "source urn:host:posture as=text/turtle");
    assert!(
        turtle.contains("<urn:host:posture> a ik:Posture"),
        "{turtle}"
    );
    assert!(
        turtle.contains("ik:mountPrefix \"urn:iki:store:\""),
        "{turtle}"
    );
    assert!(
        turtle.contains("ik:mountTarget \"/tmp/iki-hp-absent-b.sock\""),
        "{turtle}"
    );
    assert!(turtle.contains("ik:asOf \"startup\""), "{turtle}");
    assert!(!turtle.contains("_:"), "no blank nodes: {turtle}");
}

/// A door told to compose nothing says THAT, over the wire as well as on the banner. The
/// three mount postures stay three facts wherever they are read (#418).
#[test]
fn a_declined_topology_is_reported_as_a_decline_not_as_emptiness() {
    let home = scratch(
        "declined",
        &["prefer urn:iki:store:=/tmp/iki-hp-absent-c.sock"],
    );
    // In a private 0700 directory: the door refuses to serve straight in a shared `/tmp`
    // (ledger #3634).
    let sock_dir = format!("/tmp/iki-hp-d{}", std::process::id());
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
    let (_door, _) = start(&home, &["serve", &sock, "--no-config-mounts"], "serving on");
    assert_bound(&sock);
    let text = ask(&home, &sock, "source urn:host:posture");
    assert!(
        text.contains("mount   declined (--no-config-mounts)"),
        "{text}"
    );
    assert!(
        !text.contains("urn:iki:store:"),
        "a declined door composed NOTHING and must name no mount: {text}"
    );
    let turtle = ask(&home, &sock, "source urn:host:posture as=text/turtle");
    assert!(turtle.contains("ik:mountPosture \"declined\""), "{turtle}");
    assert!(
        !turtle.contains("ik:mount <"),
        "nothing to point at: {turtle}"
    );
}

/// ★ **Off the public door, with a test proving it** — and gated by AUTHORITY rather than
/// withheld by composition, so the same door serves it to an operator who grants the scope.
///
/// `urn:cap:host:posture` and not `urn:cap:kernel:inspect`: inspect is the grant every agent
/// holds in order to have a tool list at all, and the paths in this report are a strictly
/// bigger disclosure than the tool list.
#[test]
fn the_public_http_door_refuses_posture_and_a_granted_one_serves_it() {
    let home = scratch("http", &["prefer urn:iki:store:=/tmp/iki-hp-absent-d.sock"]);

    let (_door, banner) = start(&home, &["serve", "--http", "0"], "serving HTTP on");
    let public = bound_port(&banner);
    let (status, body) = get(public, "/host/posture");
    assert!(
        status.contains("403"),
        "a public edge must not hand a stranger its topology: {status} {body}"
    );
    assert!(
        body.contains("urn:cap:host:posture"),
        "the refusal names the scope that would open it: {body}"
    );
    assert!(
        !body.contains("iki-hp-absent-d.sock"),
        "and it leaks no path while refusing: {body}"
    );

    let (_door, banner) = start(
        &home,
        &["serve", "--http", "0", "--cap", "urn:cap:host:posture"],
        "serving HTTP on",
    );
    let granted = bound_port(&banner);
    let (status, body) = get(granted, "/host/posture");
    assert!(status.contains("200"), "{status} {body}");
    assert!(
        body.contains(&format!("door       http://127.0.0.1:{granted}")),
        "{body}"
    );
    assert!(
        body.contains("mount   prefer urn:iki:store: -> /tmp/iki-hp-absent-d.sock"),
        "{body}"
    );
}

/// ★ `urn:host:info` names the door that ANSWERED (ledger #430). A `--connect`ed client is
/// answered by the serving kernel, so it reads `Remote (IPC)`; the same binary resolving in
/// process reads `Embedded (Native)`; the HTTP door reads `Remote (HTTP)`. Until ledger #430
/// the socket door discarded the label `serve_ipc` passes and said `Embedded (Native)`, so
/// this pins `serve_ipc`'s label through the real binary, beside the composer's unit tests in
/// `ikigai-embedded`.
#[test]
fn each_door_names_its_own_nature_in_host_info() {
    let home = scratch("nature", &[]);

    // In a private 0700 directory: the door refuses to serve straight in a shared `/tmp`

    // (ledger #3634).

    let sock_dir = format!("/tmp/iki-hn{}", std::process::id());

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
    let (_door, _) = start(&home, &["serve", &sock], "serving on");
    assert_bound(&sock);
    let remote = ask(&home, &sock, "source urn:host:info");
    assert!(remote.contains("nature    Remote (IPC)"), "{remote}");
    assert!(!remote.contains("Embedded"), "{remote}");

    let out = spawn(&home, &["--plain", "-c", "source urn:host:info"])
        .output()
        .expect("the binary runs in process");
    let local = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{local}");
    assert!(local.contains("nature    Embedded (Native)"), "{local}");

    let (_http, banner) = start(&home, &["serve", "--http", "0"], "serving HTTP on");
    let (status, body) = get(bound_port(&banner), "/host/info");
    assert!(status.contains("200"), "{status} {body}");
    assert!(body.contains("nature    Remote (HTTP)"), "{body}");
    let _ = std::fs::remove_file(&sock);
}
