//! A door drains without losing the calls it is answering (ledger #3325).
//!
//! A process that stops used to end every call in flight, so a write in progress failed with a
//! transport error and its client could not tell whether it applied. These tests drive a real
//! door over real QUIC through its [`Drain`]: a call in progress finishes, a Sink turned away
//! is sent again and applies once, a handshake during the drain reaches the next server on
//! the port, the serve function returns within its cap, and a door nobody drains is unchanged.
//! That a Sink whose reply is lost for any other reason is NOT sent again is pinned beside the
//! client (`turned_away` in `src/lib.rs`), against a door scripted to lose it each way.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_quic::{
    bind, connect_with, generate, serve_draining_on, serve_with, Admission, Drain, Identity,
    Minter, QuicResolver, Served, Session,
};
use ikigai_resolve::Resolver;

/// A cap no test here should reach unless it means to.
const LONG_CAP: Duration = Duration::from_secs(60);

fn root_minter() -> Minter {
    Arc::new(|_| {
        Some(Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    })
}

fn text(body: &[u8]) -> Representation {
    Representation::new(ReprType::new("text/plain"), body.to_vec())
}

/// What a door's kernel has run.
#[derive(Default)]
struct Runs {
    sinks: AtomicUsize,
    holds: AtomicUsize,
}

/// A kernel named `name`: `urn:test:who` answers the name, the Sink `urn:test:append` counts
/// its runs, and the Source `urn:test:hold` counts its runs and takes `hold` to answer.
fn kernel(name: &'static str, runs: &Arc<Runs>, hold: Duration) -> Kernel {
    let who = FnEndpoint::new("who", move |_: &Invocation<'_>| Ok(text(name.as_bytes())))
        .with_description(Description::new("who").verb(Verb::Source));
    let counter = Arc::clone(runs);
    let append = FnEndpoint::new("append", move |_: &Invocation<'_>| {
        counter.sinks.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(hold);
        Ok(text(name.as_bytes()))
    })
    .with_description(Description::new("append").verb(Verb::Sink));
    let counter = Arc::clone(runs);
    let held = FnEndpoint::new("hold", move |_: &Invocation<'_>| {
        counter.holds.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(hold);
        Ok(text(name.as_bytes()))
    })
    .with_description(Description::new("hold").verb(Verb::Source));
    Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:test:who"), who)
            .bind(Exact::new("urn:test:append"), append)
            .bind(Exact::new("urn:test:hold"), held),
    ))
}

/// The two identities a door and its client pin.
struct Pair {
    server: Identity,
    client: Identity,
}

fn pair() -> Pair {
    Pair {
        server: generate(),
        client: generate(),
    }
}

/// A served door and the handle that triggers its drain.
struct Door {
    addr: SocketAddr,
    drain: Drain,
    thread: JoinHandle<std::io::Result<Served>>,
}

/// Serve `kernel` on `addr` (port 0 picks one) under a drain. The bind is retried, boundedly:
/// the door being replaced has returned, but its socket closes on its runtime's schedule.
fn serve_door(addr: SocketAddr, pair: &Pair, kernel: Kernel) -> Door {
    let mut tries = 0;
    let socket = loop {
        match bind(addr) {
            Ok(socket) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 100 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("bind {addr}: {e}"),
        }
    };
    let addr = socket.local_addr().expect("the bound address");
    let drain = Drain::new();
    let identity = Identity {
        cert_pem: pair.server.cert_pem.clone(),
        key_pem: pair.server.key_pem.clone(),
    };
    let pins = vec![pair.client.cert_pem.clone()];
    let handle = drain.clone();
    let thread = std::thread::spawn(move || {
        serve_draining_on(
            Arc::new(kernel),
            socket,
            &identity,
            Admission::Pinned(&pins),
            root_minter(),
            Duration::from_secs(300),
            None,
            &handle,
        )
    });
    Door {
        addr,
        drain,
        thread,
    }
}

impl Door {
    /// The serve function's result, which it must give within `limit`.
    fn returns_within(self, limit: Duration) -> std::io::Result<Served> {
        wait_until(limit, "the serve function to return", || {
            self.thread.is_finished()
        });
        self.thread.join().expect("the serve thread did not panic")
    }
}

fn client(addr: SocketAddr, pair: &Pair) -> QuicResolver {
    connect_with(
        addr,
        &pair.client,
        &pair.server.cert_pem,
        Duration::from_secs(300),
    )
    .expect("the client connects")
}

fn wait_until(limit: Duration, what: &str, done: impl Fn() -> bool) {
    let step = Duration::from_millis(10);
    let mut waited = Duration::ZERO;
    while !done() {
        assert!(waited < limit, "waited {limit:?} for {what}");
        std::thread::sleep(step);
        waited += step;
    }
}

fn sink() -> Request {
    Request::new(Verb::Sink, Iri::parse("urn:test:append").unwrap())
        .with_arg("content", ArgRef::Inline(b"one line".to_vec()))
}

fn source(iri: &str) -> Request {
    Request::new(Verb::Source, Iri::parse(iri).unwrap())
}

fn body(
    result: Result<(Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>,
) -> String {
    let (representation, _) = result.expect("the call is answered");
    String::from_utf8(representation.bytes).unwrap()
}

/// Start `urn:test:hold` on `client`, on its own thread, and return once the door has run it:
/// from then on the door's drain is waiting for this call.
fn hold_the_door(client: &Arc<QuicResolver>, runs: &Arc<Runs>) -> JoinHandle<String> {
    let caller = Arc::clone(client);
    let held = std::thread::spawn(move || body(caller.issue(source("urn:test:hold"))));
    wait_until(Duration::from_secs(10), "the held call to start", || {
        runs.holds.load(Ordering::SeqCst) == 1
    });
    held
}

/// A call in progress when the drain fires finishes, and its reply arrives.
#[test]
fn a_call_in_progress_when_the_drain_fires_finishes_and_its_reply_arrives() {
    let pair = pair();
    let runs = Arc::new(Runs::default());
    let hold = Duration::from_millis(1200);
    let door = serve_door(
        "127.0.0.1:0".parse().unwrap(),
        &pair,
        kernel("first", &runs, hold),
    );
    let client = Arc::new(client(door.addr, &pair));
    let caller = Arc::clone(&client);
    let write = std::thread::spawn(move || caller.issue(sink()));
    wait_until(Duration::from_secs(10), "the Sink to start", || {
        runs.sinks.load(Ordering::SeqCst) == 1
    });

    door.drain.trigger(LONG_CAP);

    assert_eq!(
        body(write.join().unwrap()),
        "first",
        "the reply to the call in progress is delivered"
    );
    assert_eq!(runs.sinks.load(Ordering::SeqCst), 1, "the Sink ran once");
    assert_eq!(
        door.returns_within(Duration::from_secs(10)).unwrap(),
        Served::Drained { cut_off: 0 },
        "the door tells its caller this was a drain, and that nothing was cut off"
    );
}

/// A Sink the drain turns away is sent again, reaches the next server, and applies exactly
/// once across both.
#[test]
fn a_sink_turned_away_by_the_drain_is_re_sent_and_applies_exactly_once() {
    let pair = pair();
    let first = Arc::new(Runs::default());
    let next = Arc::new(Runs::default());
    let door = serve_door(
        "127.0.0.1:0".parse().unwrap(),
        &pair,
        kernel("first", &first, Duration::from_millis(1200)),
    );
    let addr = door.addr;
    let client = Arc::new(client(addr, &pair));
    let held = hold_the_door(&client, &first);

    door.drain.trigger(LONG_CAP);
    // The connection is draining but open: the held call is still running on it.
    std::thread::sleep(Duration::from_millis(200));
    let caller = Arc::clone(&client);
    let write = std::thread::spawn(move || caller.issue(sink()));

    assert_eq!(held.join().unwrap(), "first");
    door.returns_within(Duration::from_secs(10)).unwrap();
    let _next = serve_door(addr, &pair, kernel("next", &next, Duration::ZERO));

    assert_eq!(
        body(write.join().unwrap()),
        "next",
        "the turned-away Sink is answered by the next server"
    );
    assert_eq!(
        first.sinks.load(Ordering::SeqCst),
        0,
        "the draining door never ran the Sink it turned away"
    );
    assert_eq!(next.sinks.load(Ordering::SeqCst), 1, "it applied once");
}

/// A handshake that arrives during the drain is not refused: the client keeps trying, and
/// connects to the next server on the port.
#[test]
fn a_handshake_during_the_drain_is_not_refused_and_connects_to_the_next_server() {
    let pair = Arc::new(pair());
    let first = Arc::new(Runs::default());
    let door = serve_door(
        "127.0.0.1:0".parse().unwrap(),
        &pair,
        kernel("first", &first, Duration::from_millis(1200)),
    );
    let addr = door.addr;
    let client = Arc::new(client(addr, &pair));
    let held = hold_the_door(&client, &first);

    door.drain.trigger(LONG_CAP);
    std::thread::sleep(Duration::from_millis(100));
    let dialer = Arc::clone(&pair);
    let arriving = std::thread::spawn(move || {
        let resolver = self::client(addr, &dialer);
        body(resolver.issue(source("urn:test:who")))
    });
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !arriving.is_finished(),
        "a refused handshake fails at once; an ignored one is still retransmitting"
    );

    assert_eq!(held.join().unwrap(), "first");
    door.returns_within(Duration::from_secs(10)).unwrap();
    let _next = serve_door(
        addr,
        &pair,
        kernel("next", &Arc::new(Runs::default()), Duration::ZERO),
    );

    assert_eq!(
        arriving.join().unwrap(),
        "next",
        "the handshake held through the drain reached the next server"
    );
}

/// A call that never finishes cannot hold the serve function past its cap, and the caller is
/// told the drain cut it off.
#[test]
fn the_serve_function_returns_within_the_cap_when_a_call_never_finishes() {
    let pair = pair();
    let runs = Arc::new(Runs::default());
    let (release, stuck) = mpsc::channel::<()>();
    let stuck = Mutex::new(stuck);
    let counter = Arc::clone(&runs);
    let wedged = FnEndpoint::new("append", move |_: &Invocation<'_>| {
        counter.sinks.fetch_add(1, Ordering::SeqCst);
        // Until the test is over: `recv` returns only once `release` has gone.
        let _ = stuck.lock().unwrap().recv();
        Ok(text(b"late"))
    })
    .with_description(Description::new("append").verb(Verb::Sink));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:append"), wedged),
    ));
    let door = serve_door("127.0.0.1:0".parse().unwrap(), &pair, kernel);
    let client = Arc::new(client(door.addr, &pair));
    let caller = Arc::clone(&client);
    let write = std::thread::spawn(move || caller.issue(sink()));
    wait_until(Duration::from_secs(10), "the Sink to start", || {
        runs.sinks.load(Ordering::SeqCst) == 1
    });

    door.drain.trigger(Duration::from_secs(1));
    // Only the first trigger counts.
    door.drain.trigger(LONG_CAP);

    assert_eq!(
        door.returns_within(Duration::from_secs(3)).unwrap(),
        Served::Drained { cut_off: 1 },
        "the door returns at its cap and says it cut a connection off"
    );
    wait_until(
        Duration::from_secs(3),
        "the client to hear its connection closed",
        || write.is_finished(),
    );
    assert!(
        write.join().unwrap().is_err(),
        "the cut-off call surfaces as a transient"
    );
    assert_eq!(
        runs.sinks.load(Ordering::SeqCst),
        1,
        "a call that may have run is not sent again"
    );
    drop(release);
}

/// Without a drain nothing changes: a door behind a plain serve function, and a door whose drain
/// is never triggered, keep serving, and a client that connects late is admitted.
#[test]
fn without_a_drain_nothing_changes() {
    let pair = pair();
    let runs = Arc::new(Runs::default());

    let untriggered = serve_door(
        "127.0.0.1:0".parse().unwrap(),
        &pair,
        kernel("untriggered", &runs, Duration::ZERO),
    );
    let client_of_untriggered = client(untriggered.addr, &pair);
    assert_eq!(
        body(client_of_untriggered.issue(sink())),
        "untriggered",
        "a Sink is answered under a drain nobody triggered"
    );
    assert_eq!(runs.sinks.load(Ordering::SeqCst), 1);

    let plain = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("a free UDP port");
    let plain_runs = Arc::new(Runs::default());
    let plain_kernel = kernel("plain", &plain_runs, Duration::ZERO);
    let (server, pins) = (
        Identity {
            cert_pem: pair.server.cert_pem.clone(),
            key_pem: pair.server.key_pem.clone(),
        },
        vec![pair.client.cert_pem.clone()],
    );
    let plain_thread = std::thread::spawn(move || {
        serve_with(
            plain_kernel,
            plain,
            &server,
            &pins,
            root_minter(),
            Duration::from_secs(300),
        )
    });
    std::thread::sleep(Duration::from_millis(300));
    let plain_client = client(plain, &pair);
    assert_eq!(body(plain_client.issue(sink())), "plain");
    assert_eq!(
        body(plain_client.issue(source("urn:test:who"))),
        "plain",
        "the same connection carries the next call"
    );
    assert_eq!(plain_runs.sinks.load(Ordering::SeqCst), 1);

    assert!(!untriggered.thread.is_finished(), "the door keeps serving");
    assert!(!plain_thread.is_finished(), "the plain door keeps serving");
    let late = self::client(untriggered.addr, &pair);
    assert_eq!(body(late.issue(source("urn:test:who"))), "untriggered");
}
