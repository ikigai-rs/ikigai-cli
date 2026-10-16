//! A door answers a connection's calls CONCURRENTLY, up to a stated bound, and refuses past
//! it (ledger #1692).
//!
//! Every call on a QUIC connection is its own bidirectional stream, and a mount holds one
//! connection to its peer. A door that answered those streams one at a time made every call
//! on a shared mount wait behind the slowest: a long poll (`urn:layers:feed … wait=50`)
//! starved the other calls past their deadlines, and gonk's Layers page had to give its
//! follower a connection of its own. These tests pin the two halves: a slow call does not
//! hold up a quick one on the SAME connection, and a connection with
//! [`MAX_CALLS_PER_CONNECTION`] calls in flight refuses the next at once, typed and
//! transient, rather than stalling it.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ikigai_core::{
    Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_quic::{
    bind, connect_with, generate, serve_bounded_on, Identity, Minter, QuicResolver, Session,
    MAX_CALLS_PER_CONNECTION,
};
use ikigai_resolve::Resolver;

/// The wall clock, for this test's own waits and timings.
#[allow(clippy::disallowed_methods)] // native-only test: the ban is for code that runs on wasm
fn now() -> Instant {
    Instant::now()
}

/// What the door's endpoints have seen: how many `urn:test:hold` calls are running now, and
/// whether they may return yet.
#[derive(Default)]
struct Held {
    running: AtomicUsize,
    released: AtomicBool,
}

impl Held {
    /// Wait until `n` hold calls are running at once, or fail after a generous bound.
    fn until_running(&self, n: usize) {
        let start = now();
        while self.running.load(Ordering::SeqCst) < n {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "only {} of {n} calls are running: the door is not serving them concurrently",
                self.running.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A kernel whose `urn:test:hold` runs until the test releases it (a stand-in for a long
/// poll) and whose `urn:test:quick` answers at once.
fn kernel(held: Arc<Held>) -> Kernel {
    let hold = FnEndpoint::new("hold", move |_inv: &Invocation<'_>| {
        held.running.fetch_add(1, Ordering::SeqCst);
        let start = now();
        while !held.released.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(10));
        }
        held.running.fetch_sub(1, Ordering::SeqCst);
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"held".to_vec(),
        ))
    })
    .with_description(Description::new("hold").verb(Verb::Source));
    let quick = FnEndpoint::new("quick", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"quick".to_vec(),
        ))
    })
    .with_description(Description::new("quick").verb(Verb::Source));
    Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:test:hold"), hold)
            .bind(Exact::new("urn:test:quick"), quick),
    ))
}

/// Serve `kernel` (closing connections `max_age` old), counting the connections minted, and
/// connect ONE client (one connection).
fn door(kernel: Kernel, mints: &Arc<AtomicUsize>, max_age: Option<Duration>) -> Arc<QuicResolver> {
    let server_id = generate();
    let client_id = generate();
    // Bound here, port 0 in the door itself: no port picked by bind-and-release (ledger #1223).
    let socket = bind("127.0.0.1:0".parse().unwrap()).expect("a UDP socket");
    let addr = socket.local_addr().expect("its address");
    let client_cert = client_id.cert_pem.clone();
    let (cert_pem, key_pem) = (server_id.cert_pem.clone(), server_id.key_pem.clone());
    let counter = Arc::clone(mints);
    let minter: Minter = Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Some(Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    });
    std::thread::spawn(move || {
        let identity = Identity { cert_pem, key_pem };
        let _ = serve_bounded_on(
            kernel,
            socket,
            &identity,
            &[client_cert],
            minter,
            Duration::from_secs(300),
            max_age,
        );
    });
    Arc::new(
        connect_with(
            addr,
            &client_id,
            &server_id.cert_pem,
            Duration::from_secs(300),
        )
        .expect("the client connects"),
    )
}

fn source(target: &str) -> Request {
    Request::new(Verb::Source, Iri::parse(target).unwrap())
}

/// Issue `urn:test:quick` under `deadline`, reporting the answer and how long it took.
fn quick(client: &QuicResolver, deadline: Duration) -> (Result<String, Error>, Duration) {
    let start = now();
    let answer = client
        .issue_as_within(source("urn:test:quick"), &Capability::root(), deadline)
        .map(|(representation, _)| String::from_utf8(representation.bytes).unwrap());
    (answer, start.elapsed())
}

/// Start `n` hold calls on `client`, each on its own thread.
fn hold(client: &Arc<QuicResolver>, n: usize) -> Vec<std::thread::JoinHandle<Result<(), Error>>> {
    (0..n)
        .map(|_| {
            let client = Arc::clone(client);
            std::thread::spawn(move || client.issue(source("urn:test:hold")).map(|_| ()))
        })
        .collect()
}

/// The defect, reproduced: a call that is still running (a long poll) must not hold up a
/// second call on the same connection past that call's deadline.
#[test]
fn a_running_call_does_not_hold_up_a_second_call_on_the_same_connection() {
    let held = Arc::new(Held::default());
    let mints = Arc::new(AtomicUsize::new(0));
    let client = door(kernel(Arc::clone(&held)), &mints, None);
    let long_poll = hold(&client, 1);
    held.until_running(1);

    let (answer, took) = quick(&client, Duration::from_secs(3));
    held.released.store(true, Ordering::SeqCst);
    assert_eq!(
        answer.expect("the second call is answered while the first still runs"),
        "quick"
    );
    assert!(took < Duration::from_secs(3), "took {took:?}");
    for call in long_poll {
        call.join().unwrap().expect("the long call is answered too");
    }
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "both calls rode ONE connection"
    );
}

/// The bound: with [`MAX_CALLS_PER_CONNECTION`] calls in flight, the next call on that
/// connection is refused at once as a transient `Unavailable` naming the bound, never queued
/// behind them; and once they finish, the connection serves again.
#[test]
fn past_the_bound_a_call_is_refused_at_once_typed_and_transient() {
    let held = Arc::new(Held::default());
    let mints = Arc::new(AtomicUsize::new(0));
    let client = door(kernel(Arc::clone(&held)), &mints, None);
    let in_flight = hold(&client, MAX_CALLS_PER_CONNECTION);
    held.until_running(MAX_CALLS_PER_CONNECTION);

    let (refused, took) = quick(&client, Duration::from_secs(10));
    match &refused {
        Err(error @ Error::Unavailable(message)) => {
            assert!(error.is_transient(), "{error:?}");
            assert!(
                message.contains(&MAX_CALLS_PER_CONNECTION.to_string()),
                "the refusal names the bound: {message}"
            );
        }
        other => panic!("expected a typed Unavailable refusal, got {other:?}"),
    }
    assert!(
        took < Duration::from_secs(5),
        "refused at once, not stalled: {took:?}"
    );

    held.released.store(true, Ordering::SeqCst);
    for call in in_flight {
        call.join()
            .unwrap()
            .expect("every call within the bound is answered");
    }
    let (answer, _) = quick(&client, Duration::from_secs(10));
    assert_eq!(answer.expect("served again once the calls finish"), "quick");
    assert_eq!(mints.load(Ordering::SeqCst), 1, "all on ONE connection");
}

/// The age bound with a long call in flight: the door waits for that call before it closes
/// the connection, and a call opened on it meanwhile is turned away at once, so the client
/// heals onto a new connection (a read is replayed there) instead of waiting unanswered
/// behind the long call past its deadline.
#[test]
fn past_the_age_bound_a_new_call_does_not_wait_behind_a_long_one() {
    let held = Arc::new(Held::default());
    let mints = Arc::new(AtomicUsize::new(0));
    let client = door(
        kernel(Arc::clone(&held)),
        &mints,
        Some(Duration::from_millis(800)),
    );
    let long_poll = hold(&client, 1);
    held.until_running(1);
    std::thread::sleep(Duration::from_millis(1600));

    let (answer, took) = quick(&client, Duration::from_secs(3));
    held.released.store(true, Ordering::SeqCst);
    assert_eq!(
        answer.expect("the call opened past the bound is answered, on a new connection"),
        "quick"
    );
    assert!(took < Duration::from_secs(3), "took {took:?}");
    for call in long_poll {
        call.join()
            .unwrap()
            .expect("the long call in flight at the bound still gets its reply");
    }
    assert_eq!(mints.load(Ordering::SeqCst), 2, "the client redialed once");
}
