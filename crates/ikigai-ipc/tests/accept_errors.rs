//! ★ One accept error must not end the socket door (ledger #720).
//!
//! `serve` used to be `for stream in listener.incoming() { let stream = stream?; … }`, so a
//! single `EMFILE` returned from it and a host built on it exited. This drives the door into
//! REAL file-descriptor exhaustion and checks that it backs off, logs the episode once, and
//! serves the next connection.
//!
//! ⚠ The limit is lowered in a CHILD process — this test binary re-executed with one test
//! selected — never in the process running the suite, and never in the developer's shell.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{builtins, ArgRef, EndpointSpace, Exact, Iri, Kernel, Request, Verb};
use ikigai_resolve::Resolver;

/// Set in the child: run the scenario instead of spawning it.
const CHILD: &str = "IKIGAI_IPC_ACCEPT_ERRORS_CHILD";
const TEST: &str = "the_socket_door_survives_fd_exhaustion_and_serves_the_next_connection";

#[test]
fn the_socket_door_survives_fd_exhaustion_and_serves_the_next_connection() {
    if std::env::var_os(CHILD).is_some() {
        return exhaust_and_recover();
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the child failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status
    );
    assert_eq!(
        stderr.matches("accept failing").count(),
        1,
        "the episode was not logged exactly once:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("accept recovered").count(),
        1,
        "the recovery was not logged exactly once:\n{stderr}"
    );
}

fn upper(text: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
        .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
}

/// Resolve one request over a fresh connection and require the right answer.
fn assert_serves(path: &Path, what: &str) {
    let client = ikigai_ipc::connect(path).unwrap_or_else(|e| panic!("{what}: connect: {e}"));
    let (representation, _) = client
        .issue(upper(what))
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(
        representation.bytes,
        what.to_uppercase().as_bytes(),
        "{what}"
    );
}

/// The child: lower the soft fd limit, serve, exhaust, recover.
fn exhaust_and_recover() {
    lower_soft_fd_limit(64);
    // Short: a Unix socket path must fit `sun_path` (104 bytes on macOS).
    // A private directory: the door refuses to serve straight in a shared `/tmp` (ledger #3634).
    let dir = std::env::temp_dir().join(format!("iki-acc-{}", std::process::id()));
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    }
    let path = dir.join("d.sock");
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
    ));
    // Everything this process holds before the door exists; the door adds its listener.
    let baseline = open_fds();
    // Bound here, so the door is listening before its thread starts and needs no poll
    // (ledger #1051).
    let listener = ikigai_ipc::bind(&path).expect("bind the door");
    let door = std::thread::spawn(move || ikigai_ipc::serve_on(kernel, listener));
    assert_serves(&path, "control");

    // ★ Wait for the door to let go of every connection made so far (ledger #803, #870). The
    // client hangs up FIRST here, and the door's per-connection thread closes its end only
    // when it notices — later, on its own schedule. A server-side descriptor still open when
    // the table is filled below is one more slot freed DURING the exhaustion, and the door's
    // accept takes that slot instead of failing: no episode, no log line, a red test with
    // nothing wrong in the door. Measured under load on macOS: every failing run had one such
    // descriptor open at this point (5 of 5), and no run without one failed (0 of 62).
    settle_fds(baseline + 1);

    // Exhaust the table, then free exactly one slot and spend it on a client socket: the door's
    // accept has no descriptor to give the server side of it — EMFILE.
    let mut held = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => held.push(f),
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e}");
                break;
            }
        }
        assert!(held.len() < 4096, "the lowered limit did not take");
    }
    held.pop();
    let waiting = UnixStream::connect(&path).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    if door.is_finished() {
        panic!(
            "one EMFILE ended the socket door: {:?}",
            door.join().unwrap()
        );
    }

    drop(held);
    // macOS drops a connection accept could not give a descriptor to; Linux keeps it queued
    // and the door takes it once the exhaustion clears. Either way it carries no request, so
    // it is only hung up here; what must hold is that the NEXT connection is served.
    drop(waiting);
    assert_serves(&path, "next");
    assert!(
        !door.is_finished(),
        "the socket door ended after recovering"
    );
    let _ = std::fs::remove_file(&path);
}

/// How many descriptors this process has open, the directory handle that counts them
/// included (so two readings compare exactly). `/dev/fd` lists them on macOS and Linux.
fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd")
        .expect("/dev/fd lists this process's descriptors")
        .count()
}

/// Wait, boundedly, until this process holds exactly `expected` descriptors.
fn settle_fds(expected: usize) {
    let mut now = open_fds();
    for _ in 0..500 {
        if now == expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
        now = open_fds();
    }
    panic!(
        "expected {expected} open descriptors (the baseline and the door's listener), found \
         {now} 5s after the test closed its connections: the door is holding (or lost) one"
    );
}

/// Lower THIS process's soft `RLIMIT_NOFILE` (the child's only), keeping the hard limit.
fn lower_soft_fd_limit(soft: libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid resource id and a valid out-param.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = soft.min(limit.rlim_max);
    // SAFETY: a valid resource id and a fully initialized limit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}
