//! ★ One accept error must not end the HTTP door (ledger #720).
//!
//! The loop used to be `listener.accept().await?`, so a single `EMFILE` returned from
//! `serve_with_listener` and a host built on it (gonk) exited. This drives the door into REAL
//! file-descriptor exhaustion and checks that it backs off, logs the episode once, and serves
//! the next connection (and, on Linux, the one that waited out the exhaustion).
//!
//! ⚠ The limit is lowered in a CHILD process — this test binary re-executed with one test
//! selected — never in the process running the suite: other tests in the same binary would
//! start failing to open files, and the developer's shell must never be touched at all.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// Set in the child: run the scenario instead of spawning it.
const CHILD: &str = "IKIGAI_WEB_ACCEPT_ERRORS_CHILD";
const TEST: &str = "the_door_survives_fd_exhaustion_and_serves_the_next_connection";

#[test]
fn the_door_survives_fd_exhaustion_and_serves_the_next_connection() {
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
    // Logged ONCE per episode — a door under exhaustion that logs every retry floods the very
    // log an operator would read to find out why.
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

/// The child: lower the soft fd limit, serve, exhaust, recover.
fn exhaust_and_recover() {
    lower_soft_fd_limit(64);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let kernel = Arc::new(ikigai_core::Kernel::new(Arc::new(
        ikigai_core::EndpointSpace::new(),
    )));
    let cap: ikigai_web::CapFn =
        Arc::new(|_| ikigai_core::Capability::scoped(Vec::<String>::new()));
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let door = rt.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
        ikigai_web::serve_with_listener(kernel, cap, listener, ikigai_web::EdgeConfig::default())
            .await
    });

    // Control: the door answers before anything goes wrong.
    assert_answers(&mut TcpStream::connect(addr).unwrap(), "control");

    // Exhaust the table, then free exactly one slot and spend it on a client socket: the
    // handshake completes in the kernel, and the door's accept has no descriptor to give the
    // server side of it — EMFILE.
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
    let waiting = TcpStream::connect(addr).unwrap();
    // Long enough for several backoff rounds (10ms, 20ms, 40ms, …).
    std::thread::sleep(Duration::from_millis(500));
    if door.is_finished() {
        panic!(
            "one EMFILE ended the door: {:?}",
            rt.block_on(door).unwrap()
        );
    }

    drop(held);
    // Linux leaves the connection in the backlog when accept has no descriptor for it, so it
    // is served once the exhaustion clears (the backoff is capped at one second). macOS does
    // NOT: XNU drops a connection it could not give a descriptor to (the client sees a reset),
    // so there is nothing to wait for — measured, not assumed: the first version of this test
    // asserted it on macOS and read back an empty answer.
    #[cfg(target_os = "linux")]
    {
        let mut waiting = waiting;
        assert_answers(&mut waiting, "the connection that waited");
    }
    #[cfg(not(target_os = "linux"))]
    drop(waiting);
    // Either way, the next connection is served.
    assert_answers(
        &mut TcpStream::connect(addr).unwrap(),
        "the next connection",
    );
    assert!(!door.is_finished(), "the door ended after recovering");
}

/// Send a request and require an HTTP status line back.
fn assert_answers(sock: &mut TcpStream, what: &str) {
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.write_all(
        b"GET /urn:test:nothing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut answer = Vec::new();
    let _ = sock.read_to_end(&mut answer);
    assert!(
        answer.starts_with(b"HTTP/1.1 "),
        "{what}: no HTTP answer: {:?}",
        String::from_utf8_lossy(&answer)
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
