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
    let path = std::env::temp_dir().join(format!("iki-acc-{}.sock", std::process::id()));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
    ));
    let door = {
        let path = path.clone();
        std::thread::spawn(move || ikigai_ipc::serve(kernel, &path))
    };
    // The bind happens on the door's thread; wait for it to answer.
    for _ in 0..200 {
        if ikigai_ipc::connect(&path).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_serves(&path, "control");

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
