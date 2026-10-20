//! A v9 client's RUN reaches a peer that `ikigai serve` mounts with `--prefer` (ledger #1942),
//! through the real binary: a client sends `Call::IssueWith` to a `serve <socket> --prefer
//! urn:rec:=<peer>` door, and an in-process peer kernel records the run its endpoint sees.
//!
//! Before, the deadline stopped at the door. The door's kernel has a clock and rebuilt the run
//! (`Invocation::time_left` is measured there), and the mount's forwarding endpoint asked its
//! resolver to carry it with `issue_as_in_run`. But a `--prefer` mount's resolver is the CLI's
//! `LazyResolver` (it dials on first use, so an asleep peer can wake), and that wrapper did not
//! forward `issue_as_in_run`: the trait's default drops the run and resolves as `issue_as`, so
//! the peer was sent a plain `IssueAs`. Both faces pinned it as observed (ikigai-python PR 46,
//! ikigai-deno PR 39): retries None and deadline None on the peer.
//!
//! What stays as it was, by design, and is pinned here so a change is deliberate:
//! - **The retry COUNT stops at the door.** `serve` configures no retry budget
//!   (`Kernel::with_retry_budget`), and a kernel without one drops a carried count, so the run
//!   at the door has no pool and none crosses. The peer mints its own: root's ceiling, 3 here.
//! - **A spent deadline is answered, not refused.** The kernel reads a deadline and does not
//!   enforce it (`Kernel::issue_with_context`), and the door adds nothing: a run with no time
//!   left resolves, and the peer sees zero left. A budgeted endpoint bounds itself by that.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: the door's HOME and config home are a scratch
//! directory, so it reads none of this machine's mounts and takes no lock a live host holds.
//! The sockets live under `temp_dir()` with a short name (`sun_path` is 104 bytes on macOS).
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use ikigai_core::{
    Capability, EndpointSpace, Exact, FnEndpoint, Iri, Kernel, ReprType, Representation, Request,
    SystemClock, Verb,
};
use ikigai_resolve::{Resolver, RunContext};

/// How long the door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// The door, killed when the test ends whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home, kept SHORT because both sockets live in it.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iprc-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

/// The peer: one endpoint that reports the run it serves as `{retries},{time_left_ms}`, `-`
/// for a half the run does not carry. It has a retry budget (ceiling 3), so a carried count
/// would narrow the pool and an absent one shows as root's 3, and a clock, so a deadline can
/// be measured.
fn peer(socket: &Path) {
    let probe = FnEndpoint::new("probe", |inv: &ikigai_core::Invocation<'_>| {
        let retries = inv
            .retry_budget()
            .map(|pool| pool.remaining().to_string())
            .unwrap_or_else(|| "-".to_string());
        let left = inv
            .time_left()
            .map(|left| left.as_millis().to_string())
            .unwrap_or_else(|| "-".to_string());
        Ok(Representation::new(
            ReprType::new("text/plain"),
            format!("{retries},{left}").into_bytes(),
        ))
    });
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:rec:probe"), probe),
    ))
    .with_retry_budget(0, 3)
    .with_clock(Arc::new(SystemClock));
    let listener = ikigai_ipc::bind(socket).expect("the peer binds");
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_shared_on(Arc::new(kernel), listener);
    });
}

/// `ikigai serve <door> --prefer urn:rec:=<peer>`, waited for by its `serving on` banner.
fn door(home: &Path, door: &Path, peer: &Path) -> Door {
    let mount = format!("urn:rec:={}", peer.display());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["serve", door.to_str().unwrap(), "--prefer", &mount])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS")
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
                let _ = tx.send(Ok(seen.clone()));
                lines.for_each(drop);
                return;
            }
        }
        let _ = tx.send(Err(seen));
    });
    let door = Door(child);
    match rx.recv_timeout(PATIENCE) {
        Ok(Ok(_)) => door,
        Ok(Err(seen)) => panic!("the door exited before its banner:\n{seen}"),
        Err(e) => panic!("the door never printed its banner: {e}"),
    }
}

fn probe() -> Request {
    Request::new(Verb::Source, Iri::parse("urn:rec:probe").unwrap())
}

/// What the peer saw: its retries and the ms it had left (`None` for `-`).
fn seen(answer: &Representation) -> (String, Option<u64>) {
    let text = String::from_utf8_lossy(&answer.bytes);
    let (retries, left) = text.split_once(',').expect("retries,time_left");
    (retries.to_string(), left.parse().ok())
}

#[test]
fn a_prefer_mount_carries_the_runs_deadline_to_its_peer() {
    let home = scratch("run");
    let peer_socket = home.join("p.sock");
    let door_socket = home.join("d.sock");
    peer(&peer_socket);
    let _door = door(&home, &door_socket, &peer_socket);
    let client = ikigai_ipc::connect(&door_socket).expect("the client reaches the door");

    // A run with a pool of 2 and 30 s left.
    let run = RunContext {
        retries: Some(2),
        time_left: Some(Duration::from_secs(30)),
    };
    let (answer, _) = client
        .issue_as_in_run(probe(), &Capability::root(), &run)
        .expect("the peer answers through the door");
    let (retries, left) = seen(&answer);
    let left = left.unwrap_or_else(|| {
        panic!("the deadline stopped at the door: the peer saw no time left ({retries},-)")
    });
    assert!(
        (20_000..=30_000).contains(&left),
        "about the carried 30 s, on the peer's clock: {left} ms"
    );
    assert_eq!(
        retries, "3",
        "the count stops at the door (serve has no retry budget); the peer mints its own"
    );

    // A plain call carries nothing, and the peer runs under its own policy, as before v9.
    let (answer, _) = client
        .issue_as(probe(), &Capability::root())
        .expect("a plain read");
    assert_eq!(seen(&answer), ("3".to_string(), None));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_spent_deadline_is_answered_and_reaches_the_peer_as_zero_left() {
    let home = scratch("spent");
    let peer_socket = home.join("p.sock");
    let door_socket = home.join("d.sock");
    peer(&peer_socket);
    let _door = door(&home, &door_socket, &peer_socket);
    let client = ikigai_ipc::connect(&door_socket).expect("the client reaches the door");

    let spent = RunContext {
        retries: Some(0),
        time_left: Some(Duration::ZERO),
    };
    let (answer, _) = client
        .issue_as_in_run(probe(), &Capability::root(), &spent)
        .expect("a spent deadline is answered, not refused at the door");
    assert_eq!(seen(&answer), ("3".to_string(), Some(0)));
    // The door's own resources answer under it too.
    let own = Request::new(Verb::Source, Iri::parse("urn:host:info").unwrap());
    client
        .issue_as_in_run(own, &Capability::root(), &spent)
        .expect("the door's own resource answers a spent run");
    let _ = std::fs::remove_dir_all(&home);
}
