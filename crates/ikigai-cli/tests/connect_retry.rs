//! The `connect.retry.*` policy over a host's mounts (ledger #3383), through the REAL binary
//! and a real QUIC door on a port it binds itself (the harness of `quic_redial.rs`).
//!
//! The same policy over `--connect quic://…` itself: a hub restarted mid-session, a hub
//! that is down when the client starts and comes up within the limit, and one that stays
//! down. And what the policy must NOT do: resend a Sink whose contract declares nothing
//! (it fails back after one attempt), and keep hammering a hub whose shared breaker has
//! opened (it fails fast, then lets a later call through after the cool-off).
//!
//! A host serves a socket with `--mount urn:hub:=quic://…`; the hub is killed; a client
//! reads through the host while the hub is down. With the policy configured the host rides
//! the outage out when the hub comes back within the limit, and answers the typed
//! `GaveUp` (attempts and elapsed time) when it does not.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

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
    let dir = std::env::temp_dir().join(format!("irt-{}-{case}", std::process::id()));
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
        // Only the client's own connect to the socket is retried here: a hub's dial
        // failure also reads `connect …`, and is what a test measures.
        if out.status.success() || !stderr.contains(&format!("connect {socket}:")) {
            return out;
        }
        last = Some(out);
        std::thread::sleep(Duration::from_millis(100));
    }
    last.expect("at least one attempt")
}

fn generate(home: &Path) -> PathBuf {
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

/// A host mounting a killed hub, under `config` in its config home.
fn host_of_a_dead_hub(case: &str, config: &str) -> (PathBuf, PathBuf, String, Door) {
    let home = scratch(case);
    std::fs::write(
        home.join("config").join("ikigai").join("config.toml"),
        config,
    )
    .expect("config.toml");
    let certs = generate(&home);
    let (hub, address) = peer(&home, &certs, "quic://127.0.0.1:0", "hub").expect("the hub serves");
    let socket = home.join("s.sock");
    let mount = format!("urn:hub:={address}");
    let (host, _) = door(
        &home,
        &[
            "serve",
            socket.to_str().unwrap(),
            "--mount",
            &mount,
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
    )
    .expect("the host serves");
    let before = ask(&home, &socket, "source urn:hub:host:identity");
    ok(before, "the read while the hub is up");
    drop(hub);
    (home, socket, address, host)
}

#[test]
fn a_hub_back_within_the_limit_answers_the_read() {
    let (home, socket, address, _host) = host_of_a_dead_hub(
        "back",
        "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 1000\n",
    );
    let certs = home.join("certs");
    let (tx, rx) = mpsc::channel();
    let (h, a) = (home.clone(), address.clone());
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        let mut tries = 0;
        loop {
            match peer(&h, &certs, &a, "hub") {
                Ok((door, _)) => {
                    let _ = tx.send(door);
                    return;
                }
                Err(_) if tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(seen) => panic!("the hub never came back on {a}:\n{seen}"),
            }
        }
    });
    let out = ask(&home, &socket, "source urn:hub:host:identity");
    let _back = rx.recv_timeout(PATIENCE).expect("the hub came back");
    let text = ok(out, "the read across the outage");
    assert!(
        text.contains("urn:iki:host:hub"),
        "the hub answered: {text}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_hub_that_stays_down_is_a_typed_gave_up() {
    let (home, socket, _address, _host) = host_of_a_dead_hub(
        "down",
        "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 2000\n",
    );
    // Native-only: elapsed wall time is the measurement.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = ask(&home, &socket, "source urn:hub:host:identity");
    let elapsed = start.elapsed();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the read fails: {all}");
    assert!(
        all.contains("gave up after"),
        "the typed final failure: {all}"
    );
    assert!(
        elapsed >= Duration::from_secs(50),
        "it kept trying within the limit: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

fn text_of(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A scratch home with `config`, its certs, and the address of a hub that served on a port
/// it bound itself and was then killed (so the port is known, and nothing listens on it).
fn a_dead_hub(case: &str, config: &str) -> (PathBuf, PathBuf, String) {
    let home = scratch(case);
    std::fs::write(
        home.join("config").join("ikigai").join("config.toml"),
        config,
    )
    .expect("config.toml");
    let certs = generate(&home);
    let (hub, address) = peer(&home, &certs, "quic://127.0.0.1:0", "hub").expect("the hub serves");
    drop(hub);
    (home, certs, address)
}

/// Bring the hub back on `address` after `delay`, on its own thread; the door comes back on
/// the channel (and dies when the receiver drops it).
fn hub_back_after(
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

/// `ikigai --connect <hub> -c <command>`, the client dialing the hub itself.
fn connect(home: &Path, certs: &Path, address: &str, command: &str) -> Output {
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

const CONNECT_POLICY: &str =
    "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 1000\n";

#[test]
fn connect_waits_for_a_hub_down_at_startup() {
    let (home, certs, address) = a_dead_hub("cstart", CONNECT_POLICY);
    let back = hub_back_after(&home, &certs, &address, Duration::from_secs(3));
    let out = connect(&home, &certs, &address, "source urn:host:identity");
    let _hub = back.recv_timeout(PATIENCE).expect("the hub came back");
    let text = ok(out, "the read from a client started while its hub was down");
    assert!(
        text.contains("urn:iki:host:hub"),
        "the hub answered: {text}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn connect_to_a_hub_that_stays_down_is_a_typed_gave_up() {
    let (home, certs, address) = a_dead_hub("cdown", CONNECT_POLICY);
    // Native-only: elapsed wall time is the measurement.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = connect(&home, &certs, &address, "source urn:host:identity");
    let elapsed = start.elapsed();
    let all = text_of(&out);
    assert!(!out.status.success(), "the client fails: {all}");
    assert!(
        all.contains("gave up after"),
        "the typed final failure: {all}"
    );
    assert!(
        elapsed >= Duration::from_secs(50),
        "it kept dialing within the limit: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn connect_without_a_policy_still_fails_at_once() {
    let (home, certs, address) = a_dead_hub("cnone", "");
    // Native-only: elapsed wall time is the measurement.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = connect(&home, &certs, &address, "source urn:host:identity");
    let elapsed = start.elapsed();
    let all = text_of(&out);
    assert!(!out.status.success(), "the client fails: {all}");
    assert!(!all.contains("gave up after"), "no policy, no retry: {all}");
    assert!(elapsed < Duration::from_secs(30), "one dial: {elapsed:?}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn connect_rides_out_a_hub_restarted_mid_session() {
    let (home, certs, address) = a_dead_hub("cmid", CONNECT_POLICY);
    let first = hub_back_after(&home, &certs, &address, Duration::ZERO);
    let hub = first.recv_timeout(PATIENCE).expect("the hub serves");
    // One session: a `--quiet` REPL on a piped stdin, fed a read, then (with the hub
    // killed) a second read, while the hub comes back a few seconds later.
    let mut client = spawn(
        &home,
        &[
            "--connect",
            &address,
            "--cert-dir",
            certs.to_str().unwrap(),
            "--quiet",
        ],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("the client starts");
    let mut stdin = client.stdin.take().expect("piped stdin");
    let stdout = client.stdout.take().expect("piped stdout");
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    // Killed when the test ends, a panic included.
    let _client = Door(client);
    let answered = |what: &str| loop {
        match lines.recv_timeout(PATIENCE) {
            Ok(line) if line.contains("urn:iki:host:hub") => return,
            Ok(_) => continue,
            Err(e) => panic!("{what}: no answer from the hub ({e})"),
        }
    };
    writeln!(stdin, "source urn:host:identity").expect("the first read");
    answered("the read before the restart");
    drop(hub);
    let back = hub_back_after(&home, &certs, &address, Duration::from_secs(3));
    writeln!(stdin, "source urn:host:identity").expect("the second read");
    answered("the read across the restart");
    let _hub = back.recv_timeout(PATIENCE).expect("the hub came back");
    drop(stdin);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_keyless_sink_is_not_resent() {
    let (home, socket, _address, _host) = host_of_a_dead_hub(
        "sink",
        "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 1000\n",
    );
    // Native-only: elapsed wall time is the measurement.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = ask(&home, &socket, "sink urn:hub:kernel:actions a-body");
    let elapsed = start.elapsed();
    let all = text_of(&out);
    assert!(!out.status.success(), "the Sink fails back: {all}");
    assert!(
        !all.contains("gave up after"),
        "a Sink with no declared resend safety is not retried: {all}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "it failed back after one attempt, not at the limit: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn the_shared_breaker_opens_and_recovers_after_its_cooloff() {
    // A cool-off longer than the limit: an open circuit is a delay the retry cannot wait
    // out, so it answers at once instead of spending the limit on it.
    let cooloff = Duration::from_secs(70);
    let (home, socket, address, _host) = host_of_a_dead_hub(
        "breaker",
        "connect.retry.limit_minutes = 1\nconnect.retry.initial_backoff_ms = 200\nconnect.retry.max_backoff_ms = 1000\nconnect.retry.breaker_threshold = 2\nconnect.retry.breaker_cooloff_seconds = 70\n",
    );
    // Native-only: elapsed wall time is the measurement.
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let out = ask(&home, &socket, "source urn:hub:host:identity");
    let elapsed = start.elapsed();
    let all = text_of(&out);
    assert!(!out.status.success(), "the read fails: {all}");
    assert!(all.contains("circuit open"), "the breaker opened: {all}");
    assert!(
        elapsed < Duration::from_secs(40),
        "the open circuit cut the retry short of its limit: {elapsed:?}"
    );
    // The hub is back, but the circuit is the host's, shared by every client: a second
    // tool is refused at once while it cools.
    let certs = home.join("certs");
    let back = hub_back_after(&home, &certs, &address, Duration::ZERO);
    let _hub = back.recv_timeout(PATIENCE).expect("the hub came back");
    let out = ask(&home, &socket, "source urn:hub:host:identity");
    let all = text_of(&out);
    assert!(!out.status.success(), "still open: {all}");
    assert!(all.contains("circuit open"), "the shared circuit: {all}");
    // After the cool-off a probe goes through, and the read is answered.
    let left = (cooloff + Duration::from_secs(2)).saturating_sub(start.elapsed());
    std::thread::sleep(left);
    let text = ok(
        ask(&home, &socket, "source urn:hub:host:identity"),
        "the read after the cool-off",
    );
    assert!(
        text.contains("urn:iki:host:hub"),
        "the hub answered: {text}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
