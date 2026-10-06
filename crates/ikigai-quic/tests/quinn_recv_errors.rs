//! A TRIPWIRE on the one quinn behavior `serve_with`'s accept loop rests on (ledger #752).
//!
//! `serve_with` ends with `while let Some(incoming) = endpoint.accept().await { … } Ok(())`.
//! quinn's `accept()` yields `None` in two cases: the endpoint was `close`d, which
//! `serve_with` never does, or its DRIVER task ended. The driver ends on any receive error
//! its socket reports except `ECONNRESET` (quinn 0.11.11, `src/endpoint.rs`,
//! `RecvState::poll_socket`: `Poll::Ready(Err(e)) => return Err(e)`), and the spawned task
//! that runs it only logs the error through `tracing` (`new_with_abstract_socket`:
//! `tracing::error!("I/O error: {}", e)`). If that path were reachable, the QUIC door would
//! stop and `serve_with` would report SUCCESS.
//!
//! It is not reachable on quinn 0.11.x, because the socket quinn builds for tokio never
//! reports a receive error: `src/runtime/tokio.rs`'s `poll_recv` is
//! `if let Ok(res) = self.io.try_io(…) { return Poll::Ready(Ok(res)) }` inside a `loop`,
//! which discards every error and polls again. The only error that escapes is tokio's own
//! "runtime is shutting down", and `serve_with` owns its runtime for as long as it loops.
//!
//! ⚠ **That changes upstream.** quinn commit 57ea8a5 ("Surface non-`WouldBlock` recv errors
//! from `poll_recv`", 2026-07-10) returns the error instead, and is on quinn's `main`
//! (0.12.0), not on the 0.11.x branch. Our `quinn = "0.11"` pin cannot resolve 0.12, so it
//! arrives either by a deliberate manifest bump or by a backport to 0.11.x through a lock
//! update. Either way, `a_receive_error_on_the_production_socket_does_not_end_the_driver`
//! goes red, and then `serve_with` must stop treating `accept() == None` as success:
//! rebind the endpoint (bounded backoff) or return an `Err` naming the cause, so the host
//! exits non-zero with a reason. The second test is the seam that fix would be tested with.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

/// A loopback UDP socket CONNECTED to a port nobody listens on, and a second handle to
/// the same socket. Sending through either makes the kernel queue an ICMP
/// port-unreachable as the socket's pending error, so its next receive fails with
/// `ECONNREFUSED` — a real receive error, provoked without touching any network
/// configuration. Also returns the dead address, for a test that needs to re-bind it.
fn refused_socket() -> (UdpSocket, UdpSocket, SocketAddr) {
    let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(dead_addr).unwrap();
    let twin = socket.try_clone().unwrap();
    (socket, twin, dead_addr)
}

/// Receive on a nonblocking socket until it reports something other than `WouldBlock`,
/// polling every 10ms up to `polls` more times.
fn first_receive_error(socket: &UdpSocket, mut polls: u32) -> io::Error {
    socket.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    loop {
        match socket.recv(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && polls > 0 => {
                polls -= 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return e,
            Ok(n) => panic!("received {n} bytes on a socket connected to a dead port"),
        }
    }
}

/// The control: without it, the tripwire could pass because no error was ever raised.
#[test]
fn the_os_reports_a_receive_error_on_a_socket_connected_to_a_dead_port() {
    let (socket, twin, _) = refused_socket();
    twin.send(b"x").unwrap();
    let error = first_receive_error(&socket, 200);
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused, "{error:?}");
}

/// The tripwire. quinn's tokio socket must CONSUME a real receive error (so the driver
/// saw it) and the endpoint must still be accepting afterwards. Red means quinn now
/// surfaces receive errors, and `serve_with`'s `Ok(())` after its accept loop has become
/// a door that stops silently — read this file's header before changing anything else.
#[test]
fn a_receive_error_on_the_production_socket_does_not_end_the_driver() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (socket, twin, dead_addr) = refused_socket();
        socket.set_nonblocking(true).unwrap();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        // Raise the error only once the driver is polling the socket.
        tokio::time::sleep(Duration::from_millis(100)).await;
        twin.send(b"x").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // A pending socket error wakes a READABLE waiter on macOS (kqueue) but not on Linux
        // (epoll reports EPOLLERR, which tokio keeps apart from READABLE). So follow the
        // error with a datagram from the dead port, now re-bound: the socket turns
        // readable on both, and Linux's recvmsg reports the pending error BEFORE the data.
        let wake = UdpSocket::bind(dead_addr).expect("re-bind the dead port");
        wake.send_to(b"wake", twin.local_addr().unwrap()).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let accepted = tokio::time::timeout(Duration::from_secs(1), endpoint.accept()).await;
        assert!(
            accepted.is_err(),
            "accept() returned {:?} after a receive error: quinn's driver ENDED on it, so \
             ikigai_quic::serve_with now reports Ok(()) for a door that stopped (ledger #752)",
            accepted.map(|incoming| incoming.is_some()),
        );
        // The error was raised AND read: the socket's pending error is gone, so the
        // driver met it and carried on. Without this, a driver that never polled the
        // socket would pass the assertion above.
        let after = first_receive_error(&twin, 0);
        assert_eq!(
            after.kind(),
            io::ErrorKind::WouldBlock,
            "the socket's pending error is still there ({after:?}), so quinn never read \
             it and this test proved nothing",
        );
    });
}

/// quinn's tokio socket, except that its FIRST receive reports an error — what every
/// receive error looks like to the driver once quinn surfaces them.
struct FailsOnce {
    inner: Arc<dyn AsyncUdpSocket>,
    failed: AtomicBool,
}

impl fmt::Debug for FailsOnce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FailsOnce")
    }
}

impl AsyncUdpSocket for FailsOnce {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()));
        }
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// The mechanism the tripwire guards against, shown directly: one surfaced receive error
/// ends the driver, and `accept()` then yields `None` exactly as it would after `close`.
#[test]
fn a_surfaced_receive_error_ends_the_driver_and_accept_yields_none() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let tokio_runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
        let socket = Arc::new(FailsOnce {
            inner: tokio_runtime.wrap_udp_socket(socket).unwrap(),
            failed: AtomicBool::new(false),
        });
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            tokio_runtime,
        )
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(1), endpoint.accept()).await;
        assert!(
            matches!(accepted, Ok(None)),
            "expected accept() to yield None once the driver ended, got {:?}",
            accepted.map(|incoming| incoming.is_some()),
        );
    });
}
