//! Unix-domain-socket IPC between the `ikigai` REPL and a local kernel server.
//!
//! [`serve`] runs a kernel behind a socket; [`connect`] returns an
//! [`IpcResolver`] that drives that server through the same [`Resolver`] surface
//! the embedded kernel uses, so the engine can't tell the difference. Messages
//! are the framed [`wire`](ikigai_wire) protocol.
//!
//! Security is the operating system's, not a certificate's (see the crate
//! README): the socket lives in a `0700` per-user directory ([`default_socket_path`])
//! and is itself `0600`, so other users can't reach it; and [`serve`] checks each
//! peer's kernel-verified UID and refuses anyone but the server's own user.
//!
//! **Who a connection is, and what it may do, is an [`Admission`]** (ledger #1830). Every
//! door admits only its own UID, and the plain [`serve`] family admits that peer as
//! [`Admission::owner`]: root authority and NO principal, because a UID is the owner, not a
//! party the door can name. Under it a name the client supplies (a `principal` argument, or a
//! carried capability's `urn:cap:principal:<iri>`) is removed before the kernel sees the
//! request. [`serve_shared_on_admitted`] serves under a bounded admission instead: a scoped
//! ceiling every carried capability is clamped to, and optionally a principal the door mints.
//!
//! Unix only — the module is empty elsewhere.
#![cfg(unix)]

mod accept;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ikigai_core::{
    Capability, Clock, Error, Kernel, Representation, Request, SpaceEntry, SystemClock, Tracer,
};
use ikigai_resolve::{scoped_entries, CacheStatus, Resolver, RunContext, SpanCollector};
use ikigai_wire::{
    answer_to, decode_hello, read_frame, read_message, speaks, write_hello, write_message, Call,
    Hello, Reply, TraceContext, WireError, PROTOCOL_VERSION,
};
// Re-exported so consumers (the CLI's mount plumbing) can pass a mode without
// depending on ikigai-wire directly.
pub use ikigai_wire::HelloMode;

/// Run `kernel` as a server on `path` until the listener itself fails: [`bind`] the socket
/// (replacing a stale one, refusing a live one, restricted to `0600`), then [`serve_on`] it,
/// each same-user connection on its own thread, under the default [`Limits`]. Connections from
/// another UID are refused — defense in depth over the `0700` directory.
///
/// Returns only on a dead listener (`EBADF`, `EINVAL`, …). One connection's accept
/// error is skipped, and running out of descriptors or threads is backed off and
/// retried with the episode logged once (ledger #720; see the private `accept`
/// module) — so a host's socket door does not exit on a transient `EMFILE`.
///
/// ⚠ This call does not return while it serves, so it gives no readiness signal: the socket
/// is bound somewhere inside it. A host that announces the door, or a test that dials it,
/// binds first with [`bind`] and serves the listener with [`serve_on`] (ledger #1051).
pub fn serve(kernel: Kernel, path: &Path) -> io::Result<()> {
    serve_on(kernel, bind(path)?)
}

/// [`serve`] for a kernel the caller SHARES: one kernel, so one cache and one set of golden
/// threads, behind this door and whatever else holds the `Arc` (an HTTP face, a file watcher,
/// another door). A write through one face cuts the threads every other face's readers hang
/// from, and a read cached through one is a hit through the others (ledger #593). The QUIC
/// door's counterpart is `ikigai_quic::serve_shared_on`.
pub fn serve_shared(kernel: Arc<Kernel>, path: &Path) -> io::Result<()> {
    serve_shared_on(kernel, bind(path)?)
}

/// Bind the server socket at `path`: remove a STALE socket file, bind, and restrict the socket
/// to `0600`. The listener is LISTENING when this returns, so a client that connects from then
/// on waits in its backlog until [`serve_on`] accepts it rather than being refused: a host can
/// announce the door the moment this returns, and a test can dial it without polling
/// (ledger #1051, #430).
///
/// ★ **A live server's socket is never replaced** (ledger #1665). The path is dialed first: a
/// server that answers is still serving, and this refuses with [`AddrInUse`](io::ErrorKind::AddrInUse),
/// naming the path and the server's process id. Only a socket nobody listens on (the dial is
/// refused) is removed. Before this, a second server on the same path unlinked the first one's
/// socket and bound its own, and the first went on running with no error and no way to be
/// reached. Anything at `path` that is not a socket (or a link to one) is refused too, never
/// removed.
///
/// The dial, the removal and the bind run under an exclusive lock on `<path>.lock` (an `flock`,
/// held only for those three steps and released when this returns), so two servers starting at
/// once cannot both find the old socket dead and remove each other's: the second waits, then
/// finds the first one listening. The lock file stays beside the socket; removing it would
/// reopen that race. ⚠ It orders only binders that take it: this function, in any version
/// since ledger #1665. An older ikigai, or another program, still replaces the socket blindly.
///
/// ```no_run
/// use std::sync::Arc;
/// use ikigai_core::{EndpointSpace, Kernel};
///
/// let path = std::path::Path::new("/tmp/ikigai-doc.sock");
/// let listener = ikigai_ipc::bind(path)?;
/// eprintln!("serving on {}", path.display()); // true when it prints: the socket is bound
/// let kernel = Kernel::new(Arc::new(EndpointSpace::new()));
/// ikigai_ipc::serve_on(kernel, listener)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    let _held = bind_lock(path)?;
    clear_stale(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Take the exclusive lock that orders binders of `path` (see [`bind`]): `<path>.lock`, created
/// `0600` if absent. The lock is released when the returned file drops.
fn bind_lock(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = PathBuf::from(name);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("could not open the bind lock {}: {e}", lock_path.display()),
            )
        })?;
    file.lock().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("could not lock {}: {e}", lock_path.display()),
        )
    })?;
    Ok(file)
}

/// Make `path` free for a bind without taking it from anyone: nothing there is fine; a socket
/// (or a link) nobody answers on is removed; a live server, or a file that is not a socket, is
/// an error. Called under [`bind_lock`].
fn clear_stale(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let kind = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !(kind.is_socket() || kind.is_symlink()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to replace it",
                path.display()
            ),
        ));
    }
    match UnixStream::connect(path) {
        Ok(probe) => {
            let who = peer_pid(&probe).map_or_else(
                || "a process whose id could not be read".to_string(),
                |pid| format!("process {pid}"),
            );
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "a kernel server is already listening on {} ({who}); stop it, or serve on \
                     another path",
                    path.display()
                ),
            ))
        }
        // Nobody listens: a socket left by a server that exited (or a dangling link).
        // ⚠ On macOS a LIVE listener whose accept backlog is full also refuses a dial, so a
        // server stuck that far behind reads as dead here. The door's accept loop takes every
        // connection it can (past the cap it answers and closes them), so its backlog stays
        // short unless the loop itself is stalled.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io::Error::new(
                    e.kind(),
                    format!("could not remove the stale socket {}: {e}", path.display()),
                )),
            }
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "could not tell whether a server is listening on {}: {e}",
                path.display()
            ),
        )),
    }
}

/// The most connections one socket door serves at once: [`Limits::default`]'s cap.
///
/// ★ **128, and why.** Each connection is one OS thread and one file descriptor, and a process
/// launchd starts gets a soft limit of **256** descriptors unless its plist raises it
/// (`launchctl limit maxfiles`, measured on plasma 2026-10-16), so 128 leaves half of that for
/// the rest of the host: its own files, its watcher, its other doors. It is far above any
/// legitimate fan-in seen: on 2026-10-16 gonk's door held 2 connections and plasma's
/// `ikigai serve` 1. And a connection is one resolution at a time, so 128 concurrent
/// resolutions is already several times what an 18-core machine can run usefully. Past it a
/// client gets a typed [`Unavailable`](Error::Unavailable) (see [`serve_shared_on_with`]).
pub const MAX_CONNECTIONS: usize = 128;

/// How long a connection may stay silent BETWEEN calls before the door closes it:
/// [`Limits::default`]'s idle timeout. It also bounds each write of a reply to a client that
/// stopped reading.
///
/// ★ **Ten minutes, and why.** It is the same bound the QUIC door already puts on a whole
/// connection (`quic.max_connection_age`, 600 s), so a client of either door already has to
/// expect a standing connection to end. [`IpcResolver`] heals on use: its next call meets the
/// closed socket on its WRITE, which proves nothing ran, so it redials and replays any verb.
/// The one window that costs a call is a request written in the instant the door closes the
/// connection: that reads as a hang-up after the write, so a `Sink` or `Delete` is not replayed
/// and its caller gets a typed transient to retry. ⚠ A client that does not redial (a hand-held
/// socket) sees its next call fail after ten idle minutes.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// How long a new connection has to send its version hello: [`Limits::default`]'s hello
/// timeout. Every client sends the hello the moment it connects, so this only ends a connection
/// that sends NOTHING, which used to hold its thread for as long as it stayed open.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the door waits on each step of turning away a connection past the cap (its hello,
/// then its first call). This runs on the accept loop itself, so it is short: a refusal must
/// not hold up the door.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);

/// The bounds a socket door serves under ([`serve_shared_on_with`]). [`Limits::default`] is
/// [`MAX_CONNECTIONS`], [`IDLE_TIMEOUT`] and [`HELLO_TIMEOUT`], and it is what [`serve`] and
/// the other `serve_*` functions use.
///
/// ```
/// use std::time::Duration;
///
/// let limits = ikigai_ipc::Limits::default();
/// assert_eq!(limits.max_connections(), 128);
/// assert_eq!(limits.idle_timeout(), Duration::from_secs(600));
/// assert_eq!(limits.hello_timeout(), Duration::from_secs(10));
///
/// let tight = limits.with_max_connections(4).with_idle_timeout(Duration::from_secs(30));
/// assert_eq!((tight.max_connections(), tight.idle_timeout()), (4, Duration::from_secs(30)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    max_connections: usize,
    idle_timeout: Duration,
    hello_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: MAX_CONNECTIONS,
            idle_timeout: IDLE_TIMEOUT,
            hello_timeout: HELLO_TIMEOUT,
        }
    }
}

impl Limits {
    /// Serve at most `n` connections at once. Panics on zero, which would refuse everyone.
    pub fn with_max_connections(mut self, n: usize) -> Self {
        assert!(n > 0, "a socket door must serve at least one connection");
        self.max_connections = n;
        self
    }

    /// Close a connection silent for `timeout` between calls. Panics on zero, which a socket
    /// cannot take as a timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        assert!(
            !timeout.is_zero(),
            "an idle timeout must be longer than zero"
        );
        self.idle_timeout = timeout;
        self
    }

    /// Close a new connection that has not sent its hello within `timeout`. Panics on zero.
    pub fn with_hello_timeout(mut self, timeout: Duration) -> Self {
        assert!(
            !timeout.is_zero(),
            "a hello timeout must be longer than zero"
        );
        self.hello_timeout = timeout;
        self
    }

    /// The connection cap.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The idle timeout between calls.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// The timeout for a new connection's hello.
    pub fn hello_timeout(&self) -> Duration {
        self.hello_timeout
    }
}

/// [`serve`] on a listener the caller already bound — with [`bind`], which sets the socket's
/// mode; a listener bound any other way is served with whatever mode its socket has.
pub fn serve_on(kernel: Kernel, listener: UnixListener) -> io::Result<()> {
    serve_shared_on(Arc::new(kernel), listener)
}

/// [`serve_shared`] on a listener the caller already bound (see [`serve_on`]), under the
/// default [`Limits`].
pub fn serve_shared_on(kernel: Arc<Kernel>, listener: UnixListener) -> io::Result<()> {
    serve_shared_on_with(kernel, listener, Limits::default())
}

/// [`serve_shared_on`] under explicit [`Limits`] (ledger #1665).
///
/// - **A connection cap.** At most `limits.max_connections()` connections are served at once.
///   One past it is answered, not dropped: the door reads its hello and its first call, each
///   within a second, and answers that call with a typed
///   [`Unavailable`](Error::Unavailable) naming the cap, a transient a Retry overlay acts on.
///   (A connection closed without a word reads to the client as a server that predates wire
///   v6, which would misreport a busy door.) That exchange runs on the accept loop, so while
///   the door is full it takes at most about two seconds per refused connection, and it spawns
///   no thread.
/// - **A hello timeout.** A connection that has not sent its hello within
///   `limits.hello_timeout()` is closed.
/// - **An idle timeout.** A connection silent between calls for `limits.idle_timeout()` is
///   closed, and so is one whose reply cannot be written for that long.
///
/// Every per-message bound is unchanged: a frame is still refused past the wire's size limit.
pub fn serve_shared_on_with(
    kernel: Arc<Kernel>,
    listener: UnixListener,
    limits: Limits,
) -> io::Result<()> {
    serve_shared_on_admitted(kernel, listener, limits, Admission::owner())
}

/// [`serve_shared_on_with`] under an explicit [`Admission`] (ledger #1830): every connection
/// the door accepts (still its own UID only) resolves under `admission`, so a socket can be
/// served bounded by a grant, and naming a principal, rather than as the owner's root.
pub fn serve_shared_on_admitted(
    kernel: Arc<Kernel>,
    listener: UnixListener,
    limits: Limits,
    admission: Admission,
) -> io::Result<()> {
    let admission = Arc::new(admission);
    let me = own_uid();
    let mut backoff = accept::Backoff::default();
    // The connections being served. Only this loop adds to it, so reading it and then adding
    // cannot overshoot; a finishing connection subtracts (its `Slot` drops).
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => match accept::classify(&e) {
                accept::Fault::Skip => continue,
                accept::Fault::BackOff => {
                    std::thread::sleep(backoff.failed(&e));
                    continue;
                }
                accept::Fault::Fatal => return Err(e),
            },
        };
        if peer_uid(&stream) != Some(me) {
            continue; // not our user — drop it
        }
        if live.load(Ordering::SeqCst) >= limits.max_connections {
            refuse_over_capacity(stream, limits.max_connections);
            continue;
        }
        let slot = Slot::take(&live);
        let kernel = Arc::clone(&kernel);
        let admission = Arc::clone(&admission);
        let spawned = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            serve_connection(&kernel, stream, &limits, &admission)
        });
        match spawned {
            Ok(_) => backoff.succeeded(),
            // Out of threads (`EAGAIN`). The stream went down with the closure, so the client
            // sees a hang-up and redials; `thread::spawn` would have PANICKED here instead,
            // taking the whole accept loop with it.
            // The slot went down with the closure too, so it is free again.
            Err(e) => std::thread::sleep(backoff.failed(&e)),
        }
    }
}

/// One served connection's place under the cap: counted when taken, given back on drop, so a
/// connection that ends any way at all (a hang-up, a panic, a failed spawn) frees its place.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>) -> Slot {
        live.fetch_add(1, Ordering::SeqCst);
        Slot(Arc::clone(live))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Turn away a connection that arrived with the door full: answer its hello, then answer its
/// first call with a typed [`Unavailable`](Error::Unavailable), then close. Each step waits at
/// most [`REFUSAL_TIMEOUT`], since this runs on the accept loop. A client that sends no call in
/// that time finds the socket closed when it does, and a healing [`IpcResolver`] redials and
/// replays straight into this refusal, so it still reads the typed answer.
fn refuse_over_capacity(stream: UnixStream, cap: usize) {
    let _ = stream.set_read_timeout(Some(REFUSAL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REFUSAL_TIMEOUT));
    let mut stream = &stream;
    let Some(version) = answer_hello(&mut stream) else {
        return;
    };
    if read_message::<_, Call>(&mut stream).is_err() {
        return;
    }
    let refusal = Error::Unavailable(format!(
        "the kernel server is at its limit of {cap} connections; try again shortly"
    ));
    let reply = Reply::ErrorTyped(WireError::from(&refusal)).for_peer(version);
    let _ = write_message(&mut stream, &reply);
}

/// The default socket read/write deadline. Without it, a hung or vanished server
/// would block a `--connect` client's blocking read **forever** (a synchronous
/// read never yields, so no async `Timeout` overlay can save it). On elapse the
/// call returns a `timeout` error — which the reliability overlays can then act on.
///
/// FIVE MINUTES, not thirty seconds. What this bounds is SILENCE from the server, and the
/// server says nothing until a resolution finishes — so for a long resolution the silence
/// IS the work. A 70B model loads ~40GB before it emits its first token, and at 30s every
/// such call failed with "no response from the kernel server (it may be hung or gone)"
/// while the server was working perfectly. A deadline that cannot tell "hung" from "busy"
/// reports the wrong thing confidently, which is worse than reporting late.
///
/// A genuinely gone server usually fails FAST anyway — connection refused, or EOF — so
/// little detection is lost by being patient about silence.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// The deadline for a peer's **self-description** — an `Entries` enumeration, or a `Meta`
/// issue — as opposed to [`DEFAULT_TIMEOUT`], which bounds a *resolution*.
///
/// ★ The two deadlines exist because they bound different things, and conflating them is
/// what let one slow peer take out a whole federation (ledger #404). [`DEFAULT_TIMEOUT`] is
/// five minutes because what it bounds is SILENCE during work, and a 70B model loading
/// ~40GB is silent while it works — for a resolution, the silence IS the work. **Nothing is
/// ever working during a self-description.** `Entries` reads a binding table the peer
/// already holds; `Meta` returns a `Description` the endpoint already holds. Neither
/// computes, neither calls out — except transitively, which is the whole problem:
/// enumeration fans out across the mount graph, so a peer's answer includes its own peers'.
/// That is why this is thirty seconds and not one: it must cover a healthy peer that is
/// itself federating (~10s measured through `ikigai-gonk` on plasma, 2026-09-17), while
/// staying far enough below five minutes that a human reads a miss as a failure rather than
/// as a hang.
///
/// ⚠ **A fixed per-hop deadline does not compose.** Three kernels deep, every hop bounds at
/// the same value, so the outer hop cuts off at exactly the moment the inner hop would have
/// answered with its own degraded catalog. The real answer is a *budget* carried on the
/// wire and decremented per hop; that is a protocol change and is not this. Until then, a
/// deep federation raises `describe.timeout` at the outermost kernel.
pub const DEFAULT_DESCRIBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to a kernel server listening on `path`, with the default I/O timeout.
pub fn connect(path: &Path) -> io::Result<IpcResolver> {
    connect_as(path, HelloMode::Verbatim)
}

/// Connect declaring how this side will address the peer — an alias mount
/// passes [`HelloMode::Alias`] so a prefix-canonical peer (ikigai-python) can
/// list its entries in the form the mount expects.
pub fn connect_as(path: &Path, mode: HelloMode) -> io::Result<IpcResolver> {
    connect_with(path, Some(DEFAULT_TIMEOUT), mode)
}

/// Connect with an explicit socket I/O `timeout` (`None` blocks indefinitely).
pub fn connect_with_timeout(path: &Path, timeout: Option<Duration>) -> io::Result<IpcResolver> {
    connect_with(path, timeout, HelloMode::Verbatim)
}

/// The full connect: dial, then exchange the version [`Hello`] — REQUIRED
/// since v7 (the v6 legacy-reconnect tolerance is gone). A v7 server is met by
/// redialing at 7 (see the private `handshake`). A peer outside the spoken
/// range errors naming BOTH versions; a peer that hangs up on the hello
/// predates v6 entirely and is refused with that diagnosis.
pub fn connect_with(
    path: &Path,
    timeout: Option<Duration>,
    mode: HelloMode,
) -> io::Result<IpcResolver> {
    let link = handshake(path, timeout, mode)?;
    Ok(IpcResolver {
        path: path.to_path_buf(),
        timeout,
        describe_timeout: Some(DEFAULT_DESCRIBE_TIMEOUT),
        call_timeout: timeout,
        mode,
        stream: Mutex::new(Some(link)),
        tracer: Mutex::new(None),
    })
}

/// Dial `path` and run the version-hello exchange, returning the established
/// stream. This is the whole cost of a (re)connect, so a resolver that redials
/// a broken connection renegotiates the hello too — the peer may have been
/// upgraded across its bounce, and a redial that now speaks a different wire
/// version must surface the normal version error, not a desynced hang.
///
/// ★ Since v8 the client may REDIAL once. A v7 server answers a v8 hello with 7 and
/// then CLOSES (it cannot serve a version it does not speak, and says so by answering
/// its own), so the downgrade cannot happen inside that connection. An answer LOWER
/// than the offer that this build still [speaks] is therefore a request to come back
/// at that version: dial again, offer it, and serve at it. That is per-connection
/// negotiation, not a flag day — nothing on the next connection remembers it.
fn handshake(path: &Path, timeout: Option<Duration>, mode: HelloMode) -> io::Result<Link> {
    match hello_at(path, timeout, mode, PROTOCOL_VERSION)? {
        (stream, answer) if answer == PROTOCOL_VERSION => Ok(Link {
            stream,
            version: answer,
        }),
        (_, answer) if answer < PROTOCOL_VERSION && speaks(answer) => {
            match hello_at(path, timeout, mode, answer)? {
                (stream, again) if again == answer => Ok(Link {
                    stream,
                    version: again,
                }),
                (_, again) => Err(version_mismatch(again, answer)),
            }
        }
        (_, answer) => Err(version_mismatch(answer, PROTOCOL_VERSION)),
    }
}

/// The error for a server that answered `theirs` to our offer of `ours`.
fn version_mismatch(theirs: u32, ours: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the kernel server speaks wire v{theirs}, this client speaks v{ours} — update the older side"
        ),
    )
}

/// Dial `path`, offer wire `version`, and return the stream with the version the
/// server answered. Whether that answer is acceptable is the caller's decision.
fn hello_at(
    path: &Path,
    timeout: Option<Duration>,
    mode: HelloMode,
    version: u32,
) -> io::Result<(UnixStream, u32)> {
    let stream = dial(path, timeout)?;
    let mut writer = &stream;
    write_hello(&mut writer, &Hello { version, mode })?;
    match read_frame(&mut &stream) {
        Ok(payload) => match decode_hello(&payload) {
            Some(hello) => Ok((stream, hello.version)),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel server answered the version hello with something else entirely",
            )),
        },
        // Silence is a HANG (the server may be overloaded — do not misdiagnose
        // it as ancient); a hang-up (EOF/reset) is the pre-v6 signature.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no answer to the version hello within the deadline (server hung or overloaded)",
            ))
        }
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the kernel server at {} hung up on the version hello — it predates wire v6 \
                 and cannot speak v{PROTOCOL_VERSION}; update the server",
                path.display()
            ),
        )),
    }
}

fn dial(path: &Path, timeout: Option<Duration>) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    Ok(stream)
}

/// A [`Resolver`] backed by a kernel server over a Unix socket.
///
/// The connection **heals on use**: an ESTABLISHED connection that breaks —
/// the server bounced under a long-running client (a daemon's standing mount,
/// an interactive `--connect` session) — is dropped and redialed instead of
/// failing every subsequent call forever (the 2026-08-09 incident: one dev-server
/// restart turned every `urn:repo:*` forward into "unavailable: Broken pipe"
/// until the daemon itself was restarted). The redial runs the full
/// the private `handshake`, hello included. What may be *replayed* on the fresh
/// connection follows the Retry/Failover discipline — see the private `replay_may_follow`.
///
/// A connection that MISSED A DEADLINE is dropped too, and for a different reason: the
/// reply the call gave up on is still coming, and replies are matched to calls
/// positionally, so keeping the stream would answer the next call with the abandoned
/// one's payload (ledger #479/#487). That drop carries no replay — see the private
/// `missed_a_deadline`.
/// One dialed connection and the wire version its hello negotiated. The version is kept
/// because a call is shaped for the PEER: a [`Call::IssueWith`] (v9) goes to a v7 or v8
/// peer as the `IssueAs`/`IssueTraced` it can decode ([`Call::for_peer`]), and before v9
/// nothing on the client side needed to remember what the handshake agreed.
struct Link {
    stream: UnixStream,
    version: u32,
}

pub struct IpcResolver {
    /// The server's socket path, kept so a broken connection can be redialed.
    path: PathBuf,
    /// The I/O deadline every (re)dial installs on its stream.
    timeout: Option<Duration>,
    /// The shorter deadline a SELF-DESCRIPTION call runs under (see
    /// [`DEFAULT_DESCRIBE_TIMEOUT`]); `None` means describe like everything else.
    describe_timeout: Option<Duration>,
    /// The deadline every other call runs under, start to finish (see
    /// [`IpcResolver::with_call_timeout`]); `None` leaves only the standing I/O timeout.
    call_timeout: Option<Duration>,
    /// The hello mode every (re)dial declares — a redialed alias mount must
    /// re-present itself as one.
    mode: HelloMode,
    /// The live connection, or `None` after a failure that spent it — the peer gone
    /// ([`is_dead_connection`]) or a deadline missed mid-exchange
    /// ([`missed_a_deadline`]) — in which case the next call redials. The mutex also
    /// serializes whole round-trips: the protocol is strict request/reply on one stream,
    /// so two concurrent calls interleaving frames would desync it.
    stream: Mutex<Option<Link>>,
    /// The tracer the `trace` command installs. When set, a resolution is sent as
    /// [`Call::IssueTraced`] and the server's returned spans are forwarded here —
    /// so a `--connect` trace shows the *remote* kernel's execution tree.
    tracer: Mutex<Option<Arc<dyn Tracer>>>,
}

/// Which half of a request/reply exchange failed. The distinction carries replay
/// safety: a WRITE failure means the length-framed request was never fully
/// written — the server reads frames with `read_exact` and cannot dispatch a
/// partial one — so the request provably never executed. A READ failure is
/// ambiguous: the request was fully written, and the server may have executed
/// it with the reply lost in the break.
enum Phase {
    Write,
    Read,
}

/// An [`exchange`] failure: the error, tagged with the [`Phase`] it struck.
struct ExchangeFailed {
    phase: Phase,
    error: io::Error,
}

/// Whether `call` asks the peer to DESCRIBE ITSELF rather than to do work — the calls that
/// run under [`DEFAULT_DESCRIBE_TIMEOUT`] instead of [`DEFAULT_TIMEOUT`].
///
/// `Entries` is the enumeration; a `Meta` issue is one endpoint's contract (it is what
/// `ForwardingEndpoint::describe` sends, so every row of a mounted manifold is one of
/// these). `IsCached` is deliberately NOT here: it is a probe about a *resolution*, and
/// answering it may require the peer to look at work in flight.
fn is_describe(call: &Call) -> bool {
    match call {
        Call::Entries => true,
        Call::Issue(request)
        | Call::IssueAs(request, _)
        | Call::IssueTraced(request, _, _)
        | Call::IssueWith(request, _, _) => request.verb == ikigai_core::Verb::Meta,
        Call::IsCached(_) => false,
    }
}

/// A deadline over a WHOLE exchange: every read, every write and any redial of one call
/// (ledger [#1335](http://localhost:1060/l/default/item/1335)).
///
/// ★ Why a socket timeout alone was not one. `SO_RCVTIMEO` bounds ONE read, so it bounds
/// silence and nothing else: a peer that trickles its reply a byte at a time, each inside the
/// timeout, held the caller for as long as it liked (a 100 KB frame at a byte per 300 ms is
/// eight hours). Here each read and write is armed with the smaller of the connection's
/// standing timeout and the time LEFT, so the sum is bounded too.
struct Deadline {
    /// When the exchange must be over.
    until: std::time::Instant,
    /// The bound it was given, for the error.
    bound: Duration,
    /// Whether the call was a self-description, for the error's wording.
    describing: bool,
    /// Whether the last arming was cut short by THIS deadline rather than the standing
    /// timeout, so a timeout that fires a hair early still reads as this deadline's miss.
    capped: std::cell::Cell<bool>,
}

/// Elapsed time, for the deadline. Native-only: this crate is `#![cfg(unix)]`, so it is
/// never built for `wasm32-unknown-unknown`, where `Instant::now` panics.
#[allow(clippy::disallowed_methods)]
fn now() -> std::time::Instant {
    std::time::Instant::now()
}

impl Deadline {
    fn new(bound: Duration, describing: bool) -> Self {
        Deadline {
            until: now() + bound,
            bound,
            describing,
            capped: std::cell::Cell::new(false),
        }
    }

    /// The timeout the next blocking operation runs under: the smaller of `standing` and the
    /// time left. A deadline already passed is a `TimedOut` here, before any syscall.
    fn arm(&self, standing: Option<Duration>) -> io::Result<Duration> {
        let left = self.until.saturating_duration_since(now());
        if left.is_zero() {
            self.capped.set(true);
            return Err(io::ErrorKind::TimedOut.into());
        }
        let capped = standing.is_none_or(|standing| left < standing);
        self.capped.set(capped);
        Ok(if capped {
            left
        } else {
            standing.unwrap_or(left)
        })
    }

    /// Whether `error` is THIS deadline's miss (and not the standing timeout's).
    fn missed_by(&self, error: &io::Error) -> bool {
        missed_a_deadline(error) && (self.capped.get() || now() >= self.until)
    }

    /// The error a miss surfaces as: a `TimedOut` carrying [`Missed`], which [`wire_error`]
    /// turns into a [`Timeout`](Error::Timeout) naming the peer and the bound.
    fn missed(&self, peer: &Path) -> io::Error {
        // `Debug` keeps the unit (`300ms`, `30s`); `as_secs()` reports `300ms` as `0s`.
        let (peer, bound) = (peer.display(), self.bound);
        io::Error::new(
            io::ErrorKind::TimedOut,
            Missed(if self.describing {
                format!("the peer at {peer} did not describe itself within {bound:?}")
            } else {
                format!(
                    "the peer at {peer} did not answer within {bound:?}; the call was canceled \
                     (its connection is dropped)"
                )
            }),
        )
    }
}

/// The payload of a missed [`Deadline`], so [`wire_error`] can tell it from the standing
/// timeout's anonymous one.
#[derive(Debug)]
struct Missed(String);

impl std::fmt::Display for Missed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Missed {}

/// One exchange's view of a stream: each read and write armed by the [`Deadline`] if there
/// is one, and the stream's standing timeouts put back on drop, so a deadline's arming
/// cannot leak onto the next call, which shares the connection. Restoring on DROP is
/// deliberate: the exchange returns early on every error path.
struct Bounded<'a> {
    stream: &'a UnixStream,
    standing: Option<Duration>,
    deadline: Option<&'a Deadline>,
}

impl Bounded<'_> {
    /// Arm the next read with what is left of the deadline.
    ///
    /// ⚠ A failed `setsockopt` is IGNORED, not returned: macOS answers it with `EINVAL` on a
    /// socket whose peer has already closed, and returning that would hide the death the
    /// read itself is about to report (`UnexpectedEof`, `BrokenPipe`), which is what decides
    /// the redial and the replay. The read then runs under the previous arming, and a dead
    /// socket answers at once.
    fn arm_read(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            let _ = self
                .stream
                .set_read_timeout(Some(deadline.arm(self.standing)?));
        }
        Ok(())
    }

    /// Arm the next write with what is left of the deadline (see [`Bounded::arm_read`]).
    fn arm_write(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            let _ = self
                .stream
                .set_write_timeout(Some(deadline.arm(self.standing)?));
        }
        Ok(())
    }
}

impl io::Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm_read()?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

impl io::Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm_write()?;
        let mut stream = self.stream;
        stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

impl Drop for Bounded<'_> {
    fn drop(&mut self) {
        if self.deadline.is_some() {
            let _ = self.stream.set_read_timeout(self.standing);
            let _ = self.stream.set_write_timeout(self.standing);
        }
    }
}

/// One request/reply exchange on an established stream, under `deadline` if there is one.
fn exchange(
    stream: &UnixStream,
    call: &Call,
    standing: Option<Duration>,
    deadline: Option<&Deadline>,
) -> Result<Reply, ExchangeFailed> {
    let mut io = Bounded {
        stream,
        standing,
        deadline,
    };
    write_message(&mut io, call).map_err(|error| ExchangeFailed {
        phase: Phase::Write,
        error,
    })?;
    read_message(&mut io).map_err(|error| ExchangeFailed {
        phase: Phase::Read,
        error,
    })
}

/// Whether `error` means the established connection is DEAD (peer gone), as
/// opposed to busy or misbehaving:
///
/// - `BrokenPipe` — a write on a socket whose peer closed (EPIPE; what the
///   long-running daemon saw forever after the dev server bounced).
/// - `ConnectionReset` — the peer died with data in flight (ECONNRESET).
/// - `UnexpectedEof` — a `read_exact` hit end-of-stream mid-conversation (the
///   peer closed cleanly between our write and its reply).
/// - `NotConnected` / `ConnectionAborted` — platform spellings of the same death.
///
/// Deliberately NOT `TimedOut`/`WouldBlock`: silence is a busy server, not a dead one
/// (see [`DEFAULT_TIMEOUT`]), so a deadline miss must not trigger the redial-and-REPLAY
/// path below — replaying would spend a second deadline on a peer that just missed one.
///
/// ⚠ That is the whole of what this predicate decides, and it used to decide more. A
/// missed deadline still leaves the connection unusable, for a different reason and with
/// a different remedy — see [`missed_a_deadline`], which drops the stream without
/// replaying anything.
fn is_dead_connection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
            | io::ErrorKind::ConnectionAborted
    )
}

/// Whether `error` is a MISSED DEADLINE — a read or write bound elapsed with the
/// exchange incomplete.
///
/// ★ Such a connection is SPENT, and the reason is the protocol, not the peer. Replies
/// are matched to calls POSITIONALLY — strict request/reply on one stream, no correlation
/// id on the wire — so the stream's meaning depends on every reply being read in order.
/// A read that misses its deadline abandons a reply the server is still going to write; a
/// write that misses one leaves a partial frame the server's `read_exact` will never
/// complete. Either way the next call on that stream reads the wrong thing: a well-formed
/// representation of a resource nobody asked for, with no error, for the life of the
/// connection (ledger #479, diagnosed in #487).
///
/// ⚠ That is a capability failure, not only a correctness one. The shifted reply was
/// computed for a DIFFERENT request, so a host multiplexing identities over one standing
/// [`IpcResolver`] hands one principal's answer to another with no grant consulted — the
/// check already passed, for someone else. A Retry overlay makes it worse: the retry
/// consumes the abandoned reply, reports a clean success, and leaves the shift in place.
///
/// ★ `ikigai-quic` is immune, and the asymmetry states exactly what this transport lacks:
/// its `Wire::attempt` opens a fresh bidirectional stream per call, so an abandoned reply
/// dies with its stream instead of queueing behind the next one.
///
/// The remedy is to drop the stream (the next call redials) and NOT to replay — see
/// [`IpcResolver::round_trip`].
fn missed_a_deadline(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Whether `call` may be REPLAYED on a fresh connection after `phase` failed on
/// a dead one. This follows the documented Retry/Failover replay discipline
/// (ikigai-throttle): a mutating verb is never blindly re-sent — a replayed
/// `Sink` could double-write, and a replayed `Delete` that already ran would
/// misreport a success as not-found — with one addition the transport can
/// prove: a WRITE-phase failure means the frame never fully reached the server
/// (see [`Phase`]), so nothing executed and replaying any verb is safe. After a
/// READ-phase failure only the read-only calls replay — `Source`/`Exists`/`Meta`
/// issues and the `IsCached`/`Entries` probes; `Sink`/`Delete` surface the typed
/// transient for the CALLER to retry (the connection still heals for the next
/// request).
fn replay_may_follow(phase: &Phase, call: &Call) -> bool {
    if matches!(phase, Phase::Write) {
        return true;
    }
    match call {
        Call::IsCached(_) | Call::Entries => true,
        Call::Issue(request)
        | Call::IssueAs(request, _)
        | Call::IssueTraced(request, _, _)
        | Call::IssueWith(request, _, _) => {
            matches!(
                request.verb,
                ikigai_core::Verb::Source | ikigai_core::Verb::Exists | ikigai_core::Verb::Meta
            )
        }
    }
}

impl IpcResolver {
    /// Set the deadline a SELF-DESCRIPTION call runs under (builder) — see
    /// [`DEFAULT_DESCRIBE_TIMEOUT`], which is what a plain [`connect`] installs.
    /// `None` takes the bound off, leaving describe calls on the connection's
    /// standing I/O deadline.
    pub fn with_describe_timeout(mut self, describe_timeout: Option<Duration>) -> Self {
        self.describe_timeout = describe_timeout;
        self
    }

    /// Set the deadline every call that is NOT a self-description runs under, from the first
    /// byte written to the last byte read, a redial and replay included (builder). `None`
    /// leaves only the standing I/O timeout, which bounds each read and write alone. A plain
    /// [`connect_with`] starts it at that same standing timeout.
    ///
    /// ★ Why this exists (ledger [#1335](http://localhost:1060/l/default/item/1335)): the
    /// standing timeout bounds SILENCE, one read at a time, so a peer that accepted a call and
    /// then trickled its reply held the caller for as long as it liked, and a caller could not
    /// ask for less than the connection's patience for one call. On expiry the connection is
    /// DROPPED, which is how a request is canceled on a socket with no stream of its own
    /// (the peer's write of the abandoned reply fails), the next call redials, and the caller
    /// gets a typed [`Timeout`](Error::Timeout) naming the peer and the deadline. No thread
    /// is involved: the bound is armed on the socket for each read and write.
    ///
    /// ★ **Why the default is the standing timeout** ([`DEFAULT_TIMEOUT`], `ipc.timeout`).
    /// The server writes nothing until a resolution finishes, so against an honest peer the
    /// silence before a reply already WAS the whole call, and that was already bounded by the
    /// standing timeout. Starting the deadline there removes the unbounded case and changes
    /// nothing that used to succeed; an operator who raised `ipc.timeout` for long model
    /// calls keeps them. A caller that knows its calls are short sets a short one here, or
    /// per call with [`issue_as_within`](Self::issue_as_within).
    pub fn with_call_timeout(mut self, call_timeout: Option<Duration>) -> Self {
        self.call_timeout = call_timeout;
        self
    }

    /// The per-call deadline ([`with_call_timeout`](Self::with_call_timeout)).
    pub fn call_timeout(&self) -> Option<Duration> {
        self.call_timeout
    }

    /// [`Resolver::issue_as`], under `deadline` for THIS call instead of the resolver's
    /// standing one ([`with_call_timeout`](Self::with_call_timeout), or the describe deadline
    /// for a `Meta` request). What a host with its own idea of how long one call may take
    /// passes, without a resolver per deadline.
    ///
    /// # Errors
    ///
    /// As [`Resolver::issue_as`]; a missed deadline is [`Error::Timeout`], naming the peer
    /// and the deadline.
    pub fn issue_as_within(
        &self,
        request: Request,
        capability: &Capability,
        deadline: Duration,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, Some(deadline), &RunContext::default())
    }

    /// [`Resolver::issue_as`] under `explicit` if given, else the standing deadline.
    fn issue_as_under(
        &self,
        request: Request,
        capability: &Capability,
        explicit: Option<Duration>,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        // When a tracer is installed (the `trace` command), ask the server to record
        // the resolution and ship its spans back, then forward them to the tracer —
        // so the tree shows the *remote* kernel's execution. `parent_span` is None:
        // the whole session runs remotely, so the remote root is the trace root.
        let tracer = self.tracer.lock().expect("tracer lock").clone();
        let trace = tracer.as_ref().map(|_| TraceContext {
            trace_id: 1,
            parent_span: None,
        });
        // A run that carries a pool or a deadline goes as `IssueWith` (wire v9); the
        // exchange downgrades it for a peer that negotiated an older version.
        let call = Call::issue_in_run(request, capability, trace, run);
        match self.round_trip_within(call, explicit).map_err(wire_error)? {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            Reply::ResolvedTraced(representation, status, events) => {
                if let Some(tracer) = &tracer {
                    for event in events {
                        tracer.record(event);
                    }
                }
                Ok((representation, status))
            }
            // v7: the taxonomy crosses intact — a remote Denied IS a Denied here.
            Reply::ErrorTyped(wire_error) => Err(wire_error.into()),
            // The flat string form is still decodable though a v7 server never sends it.
            Reply::Error(message) => Err(Error::Endpoint(
                message
                    .strip_prefix("endpoint error: ")
                    .map(str::to_string)
                    .unwrap_or(message),
            )),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to IssueAs: {other:?}"
            ))),
        }
    }

    /// Dial afresh (the full handshake) inside `deadline`, then put the connection's standing
    /// timeouts back: a hello cut short by the deadline must not shorten later calls.
    fn redial(&self, deadline: Option<&Deadline>) -> io::Result<Link> {
        let Some(deadline) = deadline else {
            return handshake(&self.path, self.timeout, self.mode);
        };
        let link = handshake(&self.path, Some(deadline.arm(self.timeout)?), self.mode)?;
        // Ignored for the reason in `Bounded::arm_read`: a peer that hung up right after the
        // hello makes these fail, and the exchange is about to say so properly.
        let _ = link.stream.set_read_timeout(self.timeout);
        let _ = link.stream.set_write_timeout(self.timeout);
        Ok(link)
    }

    /// Send a call and read its reply, healing a dead connection on use.
    ///
    /// A broken established connection is dropped and redialed (full
    /// the private `handshake`, fresh hello) — at most ONE redial per call. Whether this
    /// call is then replayed on the fresh connection is the private `replay_may_follow`'s
    /// verdict; when it must not replay, the dead connection is still cleared so
    /// the NEXT call redials, and this one surfaces its error (a typed transient
    /// via [`wire_error`]) for the caller to retry.
    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        self.round_trip_within(call, None)
    }

    /// [`round_trip`](Self::round_trip) under `explicit` if given, else the deadline its kind
    /// of call runs under: the describe deadline for a self-description, the call deadline
    /// otherwise. A miss of THAT deadline is reported as one ([`Deadline::missed`]), naming
    /// the peer; the standing timeout's own miss keeps its anonymous form.
    fn round_trip_within(&self, call: Call, explicit: Option<Duration>) -> io::Result<Reply> {
        let describing = is_describe(&call);
        let deadline = explicit
            .or(if describing {
                self.describe_timeout
            } else {
                self.call_timeout
            })
            .map(|bound| Deadline::new(bound, describing));
        self.round_trip_under(&call, deadline.as_ref())
            .map_err(|error| match &deadline {
                Some(deadline) if deadline.missed_by(&error) => deadline.missed(&self.path),
                _ => error,
            })
    }

    fn round_trip_under(&self, call: &Call, deadline: Option<&Deadline>) -> io::Result<Reply> {
        let mut guard = self.stream.lock().expect("ipc stream lock");
        let dialed_this_call = guard.is_none();
        if guard.is_none() {
            // A previous call found the connection dead: heal on use.
            *guard = Some(self.redial(deadline)?);
        }
        // The deadline arms every read and write of this exchange; the connection's standing
        // timeouts come back however the exchange leaves (`Bounded`'s drop). Scoped so the
        // stream borrow ends before the dead-connection path clears it.
        let failed = {
            let link = guard.as_ref().expect("stream just ensured");
            match exchange(
                &link.stream,
                &call.as_sent_to(link.version),
                self.timeout,
                deadline,
            ) {
                Ok(reply) => return Ok(reply),
                Err(failed) => failed,
            }
        };
        if !is_dead_connection(&failed.error) {
            // ★ A missed deadline is not death, but it SPENDS the connection: the reply
            // this call gave up on is still coming, and positional matching would hand it
            // to the next call (see `missed_a_deadline` for why that is a capability
            // failure and not merely a wrong answer). Drop the stream so the next call
            // redials onto a clean one.
            //
            // ⚠ The objection this code used to carry — "redialing would abandon a
            // resolution that is still running" — is already void at this point. The
            // resolution IS abandoned: we are about to return the deadline error and the
            // caller moves on. All that is left to decide is whether its reply also
            // corrupts the next call, and the answer is no.
            //
            // Deliberately NO replay here, which is why this is not the dead-connection
            // path below. Replaying would spend a second deadline against a peer that
            // just missed one — doubling the wait a bound exists to cap, and doubling
            // what a silent mount costs a manifold walk. The caller (or a Retry overlay)
            // still owns that decision, and now retries onto a fresh connection.
            if missed_a_deadline(&failed.error) {
                *guard = None;
            }
            return Err(failed.error);
        }
        // The established connection is dead. Drop it FIRST, unconditionally,
        // so the next call redials even when this one must not replay.
        *guard = None;
        if dialed_this_call || !replay_may_follow(&failed.phase, call) {
            return Err(failed.error);
        }
        // One redial + one replay; a second failure surfaces as-is. Both run inside what is
        // LEFT of the same deadline: a redial must not quietly restore patience.
        let fresh = self.redial(deadline)?;
        let second_attempt = exchange(
            &fresh.stream,
            &call.as_sent_to(fresh.version),
            self.timeout,
            deadline,
        );
        match second_attempt {
            Ok(reply) => {
                *guard = Some(fresh);
                Ok(reply)
            }
            Err(second) => {
                // Keep the fresh connection unless it too is dead — or spent by a missed
                // deadline, which leaves it just as unusable for the next call.
                if !is_dead_connection(&second.error) && !missed_a_deadline(&second.error) {
                    *guard = Some(fresh);
                }
                Err(second.error)
            }
        }
    }
}

/// Classify a socket I/O error as a typed [`Error`] so the reliability overlays can
/// act on it: a read/write deadline is a **transient** [`Timeout`](Error::Timeout),
/// a refused/reset/broken/EOF-mid-conversation connection a **transient**
/// [`Unavailable`](Error::Unavailable) (the server is hung or gone — a Retry or
/// Failover should move on); anything else is a generic endpoint error.
/// `UnexpectedEof` belongs in the unavailable set: a server that closes between
/// our write and its reply IS gone, and surfacing it as a generic endpoint error
/// ("failed to fill whole buffer") would hide the one retryable failure a
/// non-replayable Sink needs its caller to see.
fn wire_error(e: io::Error) -> Error {
    // A missed per-call or describe deadline names the peer and the bound it missed.
    if let Some(missed) = e.get_ref().and_then(|inner| inner.downcast_ref::<Missed>()) {
        return Error::Timeout(missed.0.clone());
    }
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout(
            "no response from the kernel server (it may be hung or gone)".to_string(),
        ),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::NotConnected => {
            Error::Unavailable(format!("the kernel server is unreachable: {e}"))
        }
        _ => Error::Endpoint(e.to_string()),
    }
}

impl Resolver for IpcResolver {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        match self.round_trip(Call::Issue(request)).map_err(wire_error)? {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            // v7: the taxonomy crosses intact — a remote Denied IS a Denied here.
            Reply::ErrorTyped(wire_error) => Err(wire_error.into()),
            // The flat string form is still decodable (append-only discriminants)
            // though a v7 server never sends it.
            Reply::Error(message) => Err(Error::Endpoint(
                message
                    .strip_prefix("endpoint error: ")
                    .map(str::to_string)
                    .unwrap_or(message),
            )),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to Issue: {other:?}"
            ))),
        }
    }

    /// Resolve under the session capability — carried to the server, which clamps
    /// it to the peercred-verified principal. This is what makes a `cap`-attenuated
    /// `--connect` session behave over IPC exactly like the embedded kernel.
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, None, &RunContext::default())
    }

    /// Resolve carrying the caller's run (wire v9): what is left of its retry pool and its
    /// deadline cross as `Call::IssueWith` to a v9 server, which bounds the resolution by
    /// them; a v7 or v8 server is sent the plain `IssueAs` it has always served.
    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, None, run)
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        *self.tracer.lock().expect("tracer lock") = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer.lock().expect("tracer lock") = None;
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        // ⚠ NOT CARRIED, and it cannot be without a wire change: `Call::IsCached` has no
        // capability field (resolutions do — `Call::IssueAs`), so the server answers for
        // its peercred-verified owner, root. That cannot LEAK: the owner may already
        // resolve anything as root over this socket, so a probe tells it nothing its own
        // authority does not. What it can be is WRONG for a narrowed caller — the cache
        // is namespaced by capability, so "cached" means cached for root, and the same
        // read under the narrowed capability may still miss. Carrying it is a new
        // appended `Call` variant, a wire version event (ledger #849).
        let _ = capability;
        matches!(
            self.round_trip(Call::IsCached(request.clone())),
            Ok(Reply::Cached(true))
        )
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.try_entries().ok().flatten()
    }

    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        match self.round_trip(Call::Entries).map_err(wire_error)? {
            Reply::Entries(entries) => Ok(entries),
            Reply::ErrorTyped(wire) => Err(wire.into()),
            Reply::Error(message) => Err(Error::Endpoint(message)),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to Entries: {other:?}"
            ))),
        }
    }

    fn transport(&self) -> String {
        "ipc · unix domain socket (peercred-verified, same user)".to_string()
    }
}

/// Serve one connection under the default [`Limits`] (the tests' entry point).
#[cfg(test)]
fn handle_connection(kernel: &Kernel, stream: UnixStream) {
    serve_connection(kernel, stream, &Limits::default(), &Admission::owner())
}

/// Serve one connection: the version hello first, then calls until the peer
/// hangs up, falls silent past `limits` (see [`serve_shared_on_with`]), or sends a wire error.
fn serve_connection(kernel: &Kernel, stream: UnixStream, limits: &Limits, admission: &Admission) {
    // Ignored on failure: a socket the peer already closed refuses `setsockopt` on macOS, and
    // the read below reports that death properly.
    let _ = stream.set_read_timeout(Some(limits.hello_timeout));
    let _ = stream.set_write_timeout(Some(limits.idle_timeout));
    let mut stream = &stream;
    let Some(peer_version) = answer_hello(&mut stream) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(limits.idle_timeout));
    loop {
        let call: Call = match read_message(&mut stream) {
            Ok(call) => call,
            // EOF, a malformed frame, or silence past the idle timeout ends the session.
            Err(_) => return,
        };
        let reply = dispatch(kernel, call, admission).for_peer(peer_version);
        if write_message(&mut stream, &reply).is_err() {
            return;
        }
    }
}

/// Read and answer a connection's version hello, returning the version to serve it at, or
/// `None` when the connection ends here.
///
/// The FIRST frame decides the connection's era. A hello (magic-prefixed) in the
/// spoken range is answered with the CLIENT's version and served AT it — every
/// reply passes through [`Reply::for_peer`], so a v7 client never meets a v8-only
/// variant. A hello outside the range gets our own version (so the CLIENT can
/// name both in its error) and a close. A frame WITHOUT the magic is a ≤v5
/// client and is refused.
fn answer_hello(stream: &mut &UnixStream) -> Option<u32> {
    let first = read_frame(stream).ok()?;
    match decode_hello(&first) {
        Some(hello) => {
            // The mode is a hint for prefix-canonical peers; this server's
            // kernel speaks canonical IRIs either way, so it is read and
            // deliberately unused here.
            let answer = Hello {
                version: answer_to(hello.version),
                mode: HelloMode::Verbatim,
            };
            write_hello(stream, &answer).ok()?;
            // Out of range: the client renders the mismatch; nothing more to say.
            speaks(hello.version).then_some(hello.version)
        }
        None => {
            // v7: the hello is REQUIRED. A first frame without the magic is a
            // pre-v6 client; refuse it (the v6 serve-it-anyway tolerance is
            // over — this fleet updates together).
            eprintln!(
                "ikigai: refused a client that connected without the version hello \
                 (wire ≤v5; v{PROTOCOL_VERSION} requires it). Update the client."
            );
            None
        }
    }
}

/// Who a socket door admits, and what each admitted connection may do (ledger #1830).
///
/// A Unix socket door authenticates a UID (its own: every other is refused), never a party,
/// so the honest default is [`Admission::owner`]: the owner's root authority, naming nobody.
/// A [`bounded`](Admission::bounded) admission serves the same peers under a scoped ceiling and,
/// when given one, a principal the door MINTS into every call's capability and stamps as the
/// `principal` argument.
///
/// Either way a name the CLIENT supplies never reaches an endpoint: its `principal` argument is
/// replaced ([`ikigai_resolve::stamp_principal`]), and a carried capability's principal is
/// dropped under the owner's root ([`ikigai_resolve::without_principals`]; core's `clamp` keeps
/// a carried name under a root ceiling, because root may act as anyone) or replaced by the
/// ceiling's under a bounded one (core's `clamp` keeps the CEILING's principal).
///
/// ⚠ A bound here is as strong as the peer's inability to reach a door that admits it as the
/// owner. Every door admits its own UID, so a client running as the owner can always dial an
/// owner door instead: a bounded socket constrains a cooperating client, or one confined
/// (a sandbox, a container) to this socket, and not a same-user process that chooses another.
///
/// ```
/// use ikigai_core::Capability;
/// use ikigai_ipc::Admission;
///
/// let owner = Admission::owner();
/// assert!(owner.ceiling().is_root() && owner.principal().is_none());
///
/// let agent = Admission::bounded(
///     Capability::scoped(["urn:cap:demo:read"]),
///     Some("urn:example:agent".to_string()),
/// )
/// .unwrap();
/// assert_eq!(agent.principal(), Some("urn:example:agent"));
/// // A principal needs a scoped ceiling: root names nobody.
/// assert!(Admission::bounded(Capability::root(), Some("urn:example:agent".into())).is_err());
/// ```
#[derive(Clone, Debug)]
pub struct Admission {
    ceiling: Capability,
    principal: Option<String>,
}

impl Admission {
    /// The owner of the socket: root authority, no principal. What [`serve`] and every other
    /// door without an explicit admission serves.
    pub fn owner() -> Admission {
        Admission {
            ceiling: Capability::root(),
            principal: None,
        }
    }

    /// Serve under `ceiling`, naming `principal` when given.
    ///
    /// # Errors
    ///
    /// A principal core cannot carry ([`ikigai_core::PrincipalError`]), and a principal on a
    /// root ceiling, which names nobody.
    pub fn bounded(
        ceiling: Capability,
        principal: Option<String>,
    ) -> Result<Admission, ikigai_core::PrincipalError> {
        if let Some(principal) = &principal {
            ceiling.with_principal(principal)?;
        }
        Ok(Admission { ceiling, principal })
    }

    /// The ceiling every call is resolved under (or clamped to).
    pub fn ceiling(&self) -> &Capability {
        &self.ceiling
    }

    /// The principal the door mints, if any.
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// The door's own authority: the ceiling with the principal minted.
    fn authority(&self) -> Capability {
        match &self.principal {
            Some(principal) => self
                .ceiling
                .with_principal(principal)
                .unwrap_or_else(|_| self.ceiling.clone()),
            None => self.ceiling.clone(),
        }
    }

    /// The capability a call carrying `carried` resolves under.
    fn admit_capability(&self, carried: &Capability) -> Capability {
        let authority = self.authority();
        if authority.is_root() {
            ikigai_resolve::without_principals(carried)
        } else {
            authority.clamp(carried)
        }
    }

    /// The request as the kernel sees it: the client's `principal` argument replaced by the
    /// door's.
    fn admit_request(&self, mut request: Request) -> Request {
        ikigai_resolve::stamp_principal(&mut request, self.principal.as_deref());
        request
    }
}

/// Answer one [`Call`] against the local kernel under `admission`, reusing its [`Resolver`]
/// impl so the server computes cache status exactly as the embedded path does.
fn dispatch(kernel: &Kernel, call: Call, admission: &Admission) -> Reply {
    match call {
        Call::Issue(request) => {
            let request = admission.admit_request(request);
            match Resolver::issue_as(kernel, request, &admission.authority()) {
                Ok((representation, status)) => Reply::Resolved(representation, status),
                Err(error) => Reply::ErrorTyped(WireError::from(&error)),
            }
        }
        Call::IssueAs(request, capability) => {
            let request = admission.admit_request(request);
            let capability = admission.admit_capability(&capability);
            match Resolver::issue_as(kernel, request, &capability) {
                Ok((representation, status)) => Reply::Resolved(representation, status),
                Err(error) => Reply::ErrorTyped(WireError::from(&error)),
            }
        }
        Call::IsCached(request) => {
            let request = admission.admit_request(request);
            Reply::Cached(Resolver::is_cached(
                kernel,
                &request,
                &admission.authority(),
            ))
        }
        // The manifold under the door's own authority, through the same cap filter as QUIC,
        // not the raw catalog, so the two transports agree.
        Call::Entries => Reply::Entries(Some(scoped_entries(kernel, &admission.authority()))),
        // Trace-over-the-wire: resolve with a PER-CALL collector
        // (`issue_traced_as`), ship the recorded spans back. Each connection's
        // trace records into its own scope, so concurrent traced calls no longer
        // interleave through the process-global tracer. `_ctx.parent_span` is for
        // a future mount-stitch (re-parenting the subtree); a whole-session
        // `--connect` trace ignores it.
        Call::IssueTraced(request, capability, _ctx) => {
            let request = admission.admit_request(request);
            let capability = admission.admit_capability(&capability);
            let collector = Arc::new(SpanCollector::default());
            match ikigai_resolve::issue_traced_as(kernel, request, &capability, collector.clone()) {
                Ok((representation, status)) => {
                    Reply::ResolvedTraced(representation, status, collector.take())
                }
                Err(error) => Reply::ErrorTyped(WireError::from(&error)),
            }
        }
        // Wire v9: the caller's run context. The time left is added to THIS door's now
        // (the system clock the kernel reads by default; the deadline is on the kernel
        // clock, and a kernel pinned to another clock would need that clock here, which
        // core does not expose). The kernel narrows the retries to what the capability is
        // entitled to and drops them on a kernel with no retry budget.
        Call::IssueWith(request, capability, with) => {
            let request = admission.admit_request(request);
            let capability = admission.admit_capability(&capability);
            let context = with.issue_context(SystemClock.now());
            match with.trace {
                Some(_ctx) => {
                    let collector = Arc::new(SpanCollector::default());
                    match ikigai_resolve::issue_traced_as_with_context(
                        kernel,
                        request,
                        &capability,
                        collector.clone(),
                        context,
                    ) {
                        Ok((representation, status)) => {
                            Reply::ResolvedTraced(representation, status, collector.take())
                        }
                        Err(error) => Reply::ErrorTyped(WireError::from(&error)),
                    }
                }
                None => match ikigai_resolve::issue_as_with_context(
                    kernel,
                    request,
                    &capability,
                    context,
                ) {
                    Ok((representation, status)) => Reply::Resolved(representation, status),
                    Err(error) => Reply::ErrorTyped(WireError::from(&error)),
                },
            }
        }
    }
}

/// The default per-user socket path: `<runtime-dir>/ikigai/kernel.sock`, with the
/// `ikigai` directory created `0700` so only this user can reach the socket.
/// `<runtime-dir>` is `$XDG_RUNTIME_DIR` when set, else `$TMPDIR`/`/tmp` plus the
/// uid. `None` if the directory can't be created.
pub fn default_socket_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let tmp =
                std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            tmp.join(format!("ikigai-{}", own_uid()))
        });
    let dir = base.join("ikigai");
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    Some(dir.join("kernel.sock"))
}

/// This process's real user id.
fn own_uid() -> u32 {
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    unsafe { libc::getuid() }
}

/// The connected peer's user id, kernel-verified — `None` if it can't be read.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid fd and correctly-sized out-params for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

/// The connected peer's user id (macOS/BSD use `getpeereid`).
#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: a valid fd and two valid out-params.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

/// The connected peer's process id, for naming a live server [`bind`] will not replace —
/// `None` where it cannot be read.
#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid fd and correctly-sized out-params for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

/// The connected peer's process id (macOS: `LOCAL_PEERPID`).
#[cfg(target_vendor = "apple")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: a valid fd and a correctly-sized out-param for LOCAL_PEERPID.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid)
}

/// Elsewhere the peer's process id is not read; the refusal says so.
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn peer_pid(_stream: &UnixStream) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use ikigai_core::{
        builtins, ArgRef, Capability, EndpointSpace, Exact, FnEndpoint, Iri, ReprType, Verb,
    };

    fn kernel() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        ))
    }

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ikigai-ipc-{}-{}.sock", std::process::id(), name))
    }

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
            .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
    }

    /// Accept one connection on `path` and serve it on a thread, returning the
    /// handle so the test can join after dropping the client.
    fn serve_one(path: &Path, kernel: Kernel) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(&kernel, stream);
        })
    }

    #[test]
    fn issue_round_trips_over_a_socket() {
        let path = socket_path("issue");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        let (representation, first) = client.issue(upper("hi")).unwrap();
        assert_eq!(representation.bytes, b"HI");
        assert_eq!(first, CacheStatus::Miss);
        // Same request again: the server's cache reports a hit.
        let (_, second) = client.issue(upper("hi")).unwrap();
        assert_eq!(second, CacheStatus::Hit);

        drop(client); // hang up → the handler returns
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// ledger #1051: [`bind`] is the readiness signal. The socket is bound, `0600` and
    /// listening when it returns, so a client dials at once, BEFORE the accept loop starts,
    /// and is served once it does: no poll, no retry.
    #[test]
    fn a_bound_listener_takes_a_connection_before_the_server_runs() {
        let path = socket_path("bind-first");
        let listener = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the socket is private as soon as it exists");

        // The connection is queued in the backlog; nothing is accepting yet.
        let dialed = UnixStream::connect(&path).expect("a bound socket takes a connection");
        drop(dialed);

        thread::spawn(move || {
            let _ = serve_on(kernel(), listener);
        });
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("ready")).unwrap().0.bytes, b"READY");
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// Remove a test socket and the bind lock beside it.
    fn remove_socket(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }

    /// Serve `kernel` on `path` under `limits`, bound before this returns.
    fn serve_limited(path: &Path, limits: Limits) {
        remove_socket(path);
        let listener = bind(path).unwrap();
        thread::spawn(move || {
            let _ = serve_shared_on_with(Arc::new(kernel()), listener, limits);
        });
    }

    /// ledger #1665: a second server on a live server's path is REFUSED, naming the path and
    /// the live server's process, and the first server keeps its socket. Before, the second
    /// bind unlinked the first one's socket and took the path, and the first went on running
    /// with no error and no way to be reached.
    #[test]
    fn a_second_bind_refuses_a_live_server_and_names_it() {
        let path = socket_path("live-twice");
        remove_socket(&path);
        let first = bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve_on(kernel(), first);
        });

        let refused = bind(&path).expect_err("a live server's socket is not replaced");
        assert_eq!(refused.kind(), io::ErrorKind::AddrInUse, "{refused}");
        let message = refused.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(
            message.contains(&format!("process {}", std::process::id())),
            "the refusal names the live server's process: {message}"
        );

        // The first server still answers on the path.
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("still")).unwrap().0.bytes, b"STILL");
        drop(client);
        remove_socket(&path);
    }

    /// A socket nobody listens on (its server exited) is still replaced.
    #[test]
    fn a_stale_socket_is_replaced() {
        let path = socket_path("stale");
        remove_socket(&path);
        drop(UnixListener::bind(&path).unwrap()); // the file stays; nobody listens
        assert!(path.exists(), "the stale socket file is there");

        let listener = bind(&path).expect("a dead socket is replaced");
        thread::spawn(move || {
            let _ = serve_on(kernel(), listener);
        });
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("fresh")).unwrap().0.bytes, b"FRESH");
        drop(client);
        remove_socket(&path);
    }

    /// ledger #1665: a file at the path that is not a socket is refused and left alone; the
    /// old bind removed whatever was there.
    #[test]
    fn a_file_that_is_not_a_socket_is_not_removed() {
        let path = socket_path("not-a-socket");
        remove_socket(&path);
        std::fs::write(&path, b"keep me").unwrap();

        let refused = bind(&path).expect_err("a regular file is not a socket to replace");
        assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"keep me",
            "the file is untouched"
        );
        remove_socket(&path);
    }

    /// ledger #1665: [`bind`] waits for the bind lock and probes AFTER taking it, so two
    /// servers starting at once cannot both find the old socket dead and remove each other's.
    /// Here another binder holds the lock and binds while this one waits; when the lock is
    /// released, this one finds that server listening and refuses.
    #[test]
    fn bind_waits_for_the_lock_then_finds_the_other_server() {
        let path = socket_path("lock-race");
        remove_socket(&path);
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(lock_name))
            .unwrap();
        held.lock().unwrap();

        let racer = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(bind(&racer).map(|_| ()));
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "bind does not touch the path while another binder holds the lock"
        );

        // The other binder, still holding the lock, binds and serves.
        let other = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve_on(kernel(), other);
        });
        drop(held);

        let raced = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("bind returns once the lock is free");
        let refused = raced.expect_err("the server bound under the lock is live");
        assert_eq!(refused.kind(), io::ErrorKind::AddrInUse, "{refused}");
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("kept")).unwrap().0.bytes, b"KEPT");
        drop(client);
        remove_socket(&path);
    }

    /// ledger #1665: past the connection cap a client gets a TYPED `Unavailable` naming the
    /// cap, and once a served connection ends its place is free again.
    #[test]
    fn a_connection_past_the_cap_is_refused_typed_and_the_place_comes_back() {
        let path = socket_path("cap");
        serve_limited(&path, Limits::default().with_max_connections(1));

        let holder = connect(&path).unwrap();
        assert_eq!(holder.issue(upper("one")).unwrap().0.bytes, b"ONE");

        let turned_away = connect(&path).expect("the hello is answered past the cap");
        match turned_away.issue(upper("two")) {
            Err(Error::Unavailable(message)) => {
                assert!(message.contains("limit of 1 connections"), "{message}")
            }
            other => panic!("expected a typed Unavailable past the cap, got {other:?}"),
        }

        drop(holder); // its thread reads EOF and gives the place back
        let mut served = None;
        for _ in 0..100 {
            match turned_away.issue(upper("two")) {
                Ok((representation, _)) => {
                    served = Some(representation.bytes);
                    break;
                }
                Err(Error::Unavailable(_)) => thread::sleep(Duration::from_millis(20)),
                Err(other) => panic!("unexpected error while the place frees: {other:?}"),
            }
        }
        assert_eq!(
            served.as_deref(),
            Some(&b"TWO"[..]),
            "the freed place is served"
        );
        drop(turned_away);
        remove_socket(&path);
    }

    /// ledger #1665: a connection that never sends its hello is closed after the hello
    /// timeout. Before, it held its thread for as long as it stayed open.
    #[test]
    fn a_connection_that_sends_nothing_is_closed() {
        let path = socket_path("silent");
        serve_limited(
            &path,
            Limits::default().with_hello_timeout(Duration::from_millis(200)),
        );
        let silent = UnixStream::connect(&path).unwrap();
        silent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        let read = io::Read::read(&mut &silent, &mut byte);
        assert!(
            matches!(read, Ok(0)),
            "the door hangs up on a connection that says nothing: {read:?}"
        );
        remove_socket(&path);
    }

    /// ledger #1665: a connection idle between calls past the idle timeout is closed, and an
    /// [`IpcResolver`] heals across it: its next call redials and is served.
    #[test]
    fn an_idle_connection_is_closed_and_the_resolver_heals() {
        let path = socket_path("idle");
        serve_limited(
            &path,
            Limits::default().with_idle_timeout(Duration::from_millis(200)),
        );

        // A raw client: hello, then silence. The door hangs up after the idle timeout.
        let raw = UnixStream::connect(&path).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_hello(
            &mut &raw,
            &Hello {
                version: PROTOCOL_VERSION,
                mode: HelloMode::Verbatim,
            },
        )
        .unwrap();
        read_frame(&mut &raw).expect("the hello is answered");
        let mut byte = [0u8; 1];
        let read = io::Read::read(&mut &raw, &mut byte);
        assert!(
            matches!(read, Ok(0)),
            "the door hangs up on an idle connection: {read:?}"
        );

        // A resolver idle past the timeout redials on its next call.
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("before")).unwrap().0.bytes, b"BEFORE");
        thread::sleep(Duration::from_millis(500));
        assert_eq!(client.issue(upper("after")).unwrap().0.bytes, b"AFTER");
        drop(client);
        remove_socket(&path);
    }

    /// ledger #593: [`serve_shared`] puts the CALLER's kernel behind the door, so the door and
    /// the host share one cache. A read through the door is cached on the host's kernel, a cut
    /// on the host's kernel is a recompute through the door, and the host still holds it.
    #[test]
    fn serve_shared_puts_one_kernel_and_one_cache_behind_the_door() {
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let counter = FnEndpoint::new("counter", move |_| {
            let n = counted.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(
                Representation::new(ReprType::new("text/plain"), n.to_string().into_bytes())
                    .cacheable(),
            )
        });
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:counter"), counter),
        )));
        let read = || Request::new(Verb::Source, Iri::parse("urn:test:counter").unwrap());

        let path = socket_path("shared");
        let listener = bind(&path).unwrap();
        thread::spawn({
            let kernel = Arc::clone(&kernel);
            move || {
                let _ = serve_shared_on(kernel, listener);
            }
        });
        let client = connect(&path).unwrap();

        assert_eq!(client.issue(read()).unwrap().0.bytes, b"1");
        assert!(
            kernel.is_cached(&read(), &Capability::root()),
            "the door's read is in the host's cache"
        );
        let (again, status) = client.issue(read()).unwrap();
        assert_eq!(
            (again.bytes.as_slice(), status),
            (&b"1"[..], CacheStatus::Hit)
        );
        kernel.cut("urn:test:counter");
        assert_eq!(client.issue(read()).unwrap().0.bytes, b"2");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// ★ A LIMITED name crosses the wire exactly as an unbound one does (ledger #536). The
    /// served surface carves `urn:personal:` out with a `Limit` (`ikigai-embedded`'s
    /// `served_root`), and a boundary that reveals nothing in-process must reveal nothing on
    /// the far side of a transport either: the same typed `Unresolved`, the same words — never
    /// a `Denied`, never a different message a client could tell apart. The family is BOUND
    /// just behind the limiter here, which is the case the indistinguishability is for.
    #[test]
    fn a_limited_name_is_unresolved_over_the_wire_byte_for_byte() {
        use ikigai_core::{Fallback, Limit, Space};

        let path = socket_path("limited");
        let kernel = Kernel::new(Arc::new(Fallback::new(vec![
            Arc::new(Limit::new("urn:personal:")) as Arc<dyn Space>,
            Arc::new(
                EndpointSpace::new()
                    .bind(Exact::new("urn:test:upper"), builtins::to_upper())
                    .bind(Exact::new("urn:personal:calendar"), builtins::to_upper()),
            ),
        ])));
        let server = serve_one(&path, kernel);
        let client = connect(&path).unwrap();
        let source = |iri: &str| Request::new(Verb::Source, Iri::parse(iri).unwrap());

        let limited = client
            .issue(source("urn:personal:calendar"))
            .expect_err("limited");
        let unbound = client
            .issue(source("urn:nowhere:calendar"))
            .expect_err("unbound");
        assert!(
            matches!(limited, ikigai_core::Error::Unresolved(_)),
            "{limited:?}"
        );
        assert_eq!(
            limited
                .to_string()
                .replace("urn:personal:calendar", "urn:nowhere:calendar"),
            unbound.to_string()
        );
        // The connection is healthy afterwards: the public door answers on it.
        let (representation, _) = client.issue(upper("hi")).unwrap();
        assert_eq!(representation.bytes, b"HI");

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_traced_resolution_returns_the_remote_spans() {
        let path = socket_path("traced");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        // Install a tracer, as the `trace` command does. The client sends
        // Call::IssueTraced, the server records its own execution and ships the
        // spans back, and the client forwards them here — so a --connect trace
        // shows the *remote* kernel's tree.
        let collector = Arc::new(SpanCollector::default());
        client.set_tracer(collector.clone());
        let (representation, _status) = client.issue_as(upper("hi"), &Capability::root()).unwrap();
        client.clear_tracer();
        assert_eq!(representation.bytes, b"HI");

        let events = collector.take();
        assert!(
            events.iter().any(|e| e.target == "urn:test:upper"),
            "the remote span crossed the wire: {events:?}"
        );

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_local_kernel_composes_a_remote_one_via_remotespace() {
        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::RemoteSpace;

        // Remote server: has urn:test:upper.
        let path = socket_path("remote-mount");
        let server = serve_one(&path, kernel());

        // Local kernel: an empty local space, then the remote as a fallback. A
        // resource the local kernel lacks resolves by forwarding to the remote —
        // one composed resolution graph across two kernels.
        let client = connect(&path).unwrap();
        let local = Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(RemoteSpace::new(Arc::new(client))) as Arc<dyn Space>,
        ]);
        let local_kernel = Kernel::new(Arc::new(local));

        let (representation, _status) =
            Resolver::issue_as(&local_kernel, upper("hi"), &Capability::root()).unwrap();
        assert_eq!(
            representation.bytes, b"HI",
            "the local kernel resolved a remote-only resource by forwarding"
        );

        drop(local_kernel); // drops the client → the server sees EOF and returns
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_trace_through_a_mount_stitches_the_remote_subtree() {
        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::{RemoteSpace, SpanCollector};

        let path = socket_path("mount-trace");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        let local = Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(RemoteSpace::new(Arc::new(client))) as Arc<dyn Space>,
        ]);
        let local_kernel = Kernel::new(Arc::new(local));

        // Trace the LOCAL kernel resolving a remote-only resource. The forward is
        // traced too, and its span is re-based under the mount node.
        let collector = Arc::new(SpanCollector::default());
        local_kernel.set_tracer(collector.clone());
        let (representation, _status) =
            Resolver::issue_as(&local_kernel, upper("hi"), &Capability::root()).unwrap();
        local_kernel.clear_tracer();
        assert_eq!(representation.bytes, b"HI");

        // Two nodes: the local mount node (the trace root) and the remote resolution
        // stitched beneath it — not collapsed into one.
        let events = collector.take();
        assert_eq!(
            events.len(),
            2,
            "mount node + stitched remote node: {events:?}"
        );
        let root = events.iter().find(|e| e.parent.is_none()).expect("a root");
        let child = events
            .iter()
            .find(|e| e.parent == Some(root.span))
            .expect("a node stitched under the mount");
        assert_eq!(
            child.target, "urn:test:upper",
            "the remote node under the mount"
        );

        drop(local_kernel);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// ★ Ledger #92: a cut on the PEER must reach a read made THROUGH a mount. The peer's
    /// endpoint is cacheable and hangs from a thread of its own (`depends_on`), which is the
    /// case that matters: a pure endpoint has no state to go stale, so it would pass either way.
    /// Before the fix the mounting kernel cached the first answer and served it after the
    /// peer's state changed and its thread was cut, because threads do not cross the wire and
    /// nothing on the mounting side could cut the entry.
    #[test]
    fn a_cut_on_the_peer_reaches_a_read_through_the_mount() {
        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::MountedRemote;

        const STATE: &str = "urn:test:state";
        let value = Arc::new(Mutex::new(b"v1".to_vec()));
        let cell = {
            let value = Arc::clone(&value);
            FnEndpoint::new("cell", move |_inv| {
                Ok(
                    Representation::new(ReprType::new("text/plain"), value.lock().unwrap().clone())
                        .cacheable()
                        .depends_on(STATE),
                )
            })
        };
        let peer = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:cell"), cell),
        )));

        let path = socket_path("peer-cut");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let served = Arc::clone(&peer);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(&served, stream);
        });

        let client = connect(&path).unwrap();
        let mounting = Kernel::new(Arc::new(Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(MountedRemote::overriding(
                Arc::new(client),
                "urn:test:",
                format!("ipc:{}", path.display()),
            )) as Arc<dyn Space>,
        ])));
        let read = |kernel: &Kernel| {
            let cell = Request::new(Verb::Source, Iri::parse("urn:test:cell").unwrap());
            Resolver::issue_as(kernel, cell, &Capability::root())
                .unwrap()
                .0
                .bytes
        };

        assert_eq!(read(&mounting), b"v1");
        *value.lock().unwrap() = b"v2".to_vec();
        peer.cut(STATE);
        // Control: the peer itself recomputes after its own cut.
        assert_eq!(read(&peer), b"v2", "the peer serves the new state");
        assert_eq!(
            read(&mounting),
            b"v2",
            "the mounting kernel must not serve a peer answer whose thread the peer has cut"
        );

        drop(mounting);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    // Native-only test: the IPC transport is Unix-domain sockets, unavailable on
    // wasm. The test measures elapsed time to prove the read timeout fires.
    #[allow(clippy::disallowed_methods)]
    fn a_hung_server_times_out_instead_of_hanging() {
        let path = socket_path("hang");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        // A "server" that accepts the connection but never replies.
        let server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut s = &stream;
                let _ = read_frame(&mut s);
                let _ = write_hello(
                    &mut s,
                    &Hello {
                        version: PROTOCOL_VERSION,
                        mode: HelloMode::Verbatim,
                    },
                );
                std::thread::sleep(Duration::from_millis(400)); // hold it, write nothing
                drop(stream);
            }
        });

        let client = connect_with_timeout(&path, Some(Duration::from_millis(100))).unwrap();
        let start = std::time::Instant::now();
        let result = client.issue(upper("hi"));
        assert!(result.is_err(), "a hung server errors instead of hanging");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "returned promptly on the read timeout, not blocked forever"
        );
        // The hang is a *transient* Timeout — so a Retry/Failover above a mount to
        // this server would act on it, not treat it as a permanent failure.
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        assert!(err.is_transient());

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_mount_to_a_hung_server_forwards_a_transient_error() {
        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::RemoteSpace;

        let path = socket_path("mount-hang");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut s = &stream;
                let _ = read_frame(&mut s);
                let _ = write_hello(
                    &mut s,
                    &Hello {
                        version: PROTOCOL_VERSION,
                        mode: HelloMode::Verbatim,
                    },
                );
                std::thread::sleep(Duration::from_millis(400));
                drop(stream);
            }
        });

        // A local kernel that mounts the (hung) remote as a fallback.
        let client = connect_with_timeout(&path, Some(Duration::from_millis(100))).unwrap();
        let local = Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(RemoteSpace::new(Arc::new(client))) as Arc<dyn Space>,
        ]);
        let kernel = Kernel::new(Arc::new(local));

        // Resolving a remote-only resource against the hung server yields a TRANSIENT
        // error — so a Retry/Failover overlay above this kernel would act on it, the
        // whole point of the structured Resolver boundary.
        let err = Resolver::issue_as(&kernel, upper("hi"), &Capability::root()).unwrap_err();
        assert!(
            err.is_transient(),
            "the mount forwards the hang as transient: {err:?}"
        );

        drop(kernel);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn is_cached_and_entries_round_trip() {
        let path = socket_path("probe");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        assert!(!client.is_cached(&upper("hey"), &Capability::root())); // not resolved yet
        client.issue(upper("hey")).unwrap();
        assert!(client.is_cached(&upper("hey"), &Capability::root()));

        let entries = client.entries().expect("space enumerates");
        assert!(entries.iter().any(|e| e.endpoint == "to-upper"));

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unresolved_iri_comes_back_as_an_error() {
        let path = socket_path("err");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        let request = Request::new(Verb::Source, Iri::parse("urn:test:nope").unwrap());
        assert!(client.issue(request).is_err());

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// v7: a ≤v5 client (a Call first, no hello) is REFUSED — the tolerance
    /// era is over. The connection closes without an answer.
    #[test]
    fn a_pre_hello_client_is_refused() {
        let path = socket_path("legacy-client");
        let server = serve_one(&path, kernel());

        let stream = UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut s = &stream;
        write_message(&mut s, &Call::Issue(upper("hi"))).unwrap();
        assert!(
            read_message::<_, Reply>(&mut s).is_err(),
            "the server must hang up, not serve a pre-hello client"
        );

        drop(stream);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// v7: a client dialing a pre-hello server gets a CLEAR refusal naming the
    /// diagnosis — no silent legacy reconnect.
    #[test]
    fn a_pre_hello_server_is_diagnosed_not_tolerated() {
        let path = socket_path("legacy-server");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        // A ≤v5 server: cannot decode the hello, hangs up silently.
        let server = thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut s = &stream;
            let _ = read_frame(&mut s);
        });

        let message = match connect(&path) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("a pre-hello server must be refused"),
        };
        assert!(message.contains("predates wire v6"), "{message}");

        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A version MISMATCH against a hello-speaking server errors immediately,
    /// naming both versions — the failure mode this whole design buys.
    #[test]
    fn a_version_mismatch_names_both_versions() {
        let path = socket_path("mismatch");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        // A future v9 server: answers the hello with its own version, closes.
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = &stream;
            let _ = read_frame(&mut s).unwrap();
            write_hello(
                &mut s,
                &Hello {
                    version: 10,
                    mode: HelloMode::Verbatim,
                },
            )
            .unwrap();
        });

        let message = match connect(&path) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("a version mismatch must refuse the connection"),
        };
        assert!(message.contains("v10"), "{message}");
        assert!(
            message.contains(&format!("v{PROTOCOL_VERSION}")),
            "{message}"
        );

        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // ---- wire v8: backward-compatible negotiation (ledger #583) ----

    /// A kernel whose one endpoint refuses by STATE — core's `Error::Conflict`.
    fn conflict_kernel() -> Kernel {
        let taken = FnEndpoint::new("taken", |_inv: &ikigai_core::Invocation<'_>| {
            Err(Error::Conflict("x".into()))
        });
        Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:upper"), builtins::to_upper())
                .bind(Exact::new("urn:test:taken"), taken),
        ))
    }

    fn taken() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:taken").unwrap())
    }

    /// Open a raw connection, offer `version`, and return the stream with the answer.
    fn raw_hello(path: &Path, version: u32) -> (UnixStream, u32) {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut s = &stream;
        write_hello(
            &mut s,
            &Hello {
                version,
                mode: HelloMode::Verbatim,
            },
        )
        .unwrap();
        let answer = decode_hello(&read_frame(&mut s).unwrap()).expect("a hello");
        (stream, answer.version)
    }

    /// ★ A v7 client — pinned here as raw bytes, not as this build's client — is
    /// answered 7 (the v7 client refuses any other answer) and SERVED.
    #[test]
    fn a_v7_hello_is_answered_7_and_served() {
        let path = socket_path("v7-hello");
        let server = serve_one(&path, kernel());
        let (stream, answer) = raw_hello(&path, 7);
        assert_eq!(
            answer, 7,
            "an accepted hello is answered with the peer's version"
        );
        let mut s = &stream;
        write_message(&mut s, &Call::Issue(upper("hi"))).unwrap();
        match read_message::<_, Reply>(&mut s).unwrap() {
            Reply::Resolved(representation, _) => assert_eq!(representation.bytes, b"HI"),
            other => panic!("a v7 peer must be served: {other:?}"),
        }
        drop(stream);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A hello outside the spoken range (6 below, 10 above) gets OUR version, so the
    /// client can name both, and the connection closes without serving.
    #[test]
    fn a_hello_outside_7_to_9_is_answered_9_and_refused() {
        for (n, offered) in [6u32, 10].into_iter().enumerate() {
            let path = socket_path(&format!("v-out-{n}"));
            let server = serve_one(&path, kernel());
            let (stream, answer) = raw_hello(&path, offered);
            assert_eq!(answer, PROTOCOL_VERSION, "offered v{offered}");
            let mut s = &stream;
            let _ = write_message(&mut s, &Call::Issue(upper("hi")));
            assert!(
                read_message::<_, Reply>(&mut s).is_err(),
                "a v{offered} peer must not be served"
            );
            drop(stream);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }
    }

    /// The downgrade: a Conflict reaches a v7 peer as EXACTLY the untyped Endpoint
    /// error a v7 server always sent, and a v8 peer typed.
    #[test]
    fn a_conflict_is_downgraded_for_a_v7_peer_and_typed_for_a_v8_one() {
        for (version, expected) in [
            (7, WireError::Endpoint("conflict: x".into())),
            (8, WireError::Conflict("x".into())),
        ] {
            let path = socket_path(&format!("conflict-v{version}"));
            let server = serve_one(&path, conflict_kernel());
            let (stream, answer) = raw_hello(&path, version);
            assert_eq!(answer, version);
            let mut s = &stream;
            write_message(&mut s, &Call::Issue(taken())).unwrap();
            assert_eq!(
                read_message::<_, Reply>(&mut s).unwrap(),
                Reply::ErrorTyped(expected),
                "a v{version} peer"
            );
            drop(stream);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Through this build's own client the Conflict arrives typed and PERMANENT.
    #[test]
    fn a_conflict_crosses_to_a_v8_client_as_a_permanent_conflict() {
        let path = socket_path("conflict-client");
        let server = serve_one(&path, conflict_kernel());
        let client = connect(&path).unwrap();
        let err = client.issue(taken()).unwrap_err();
        assert!(matches!(err, Error::Conflict(ref m) if m == "x"), "{err:?}");
        assert!(!err.is_transient());
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// ★ A v7-only server answers a v8 hello with 7 and CLOSES — so the client
    /// cannot downgrade inside that connection. It redials offering 7 and is served.
    /// The fake server is exactly the v7 `handle_connection`: answer its own version,
    /// close on a mismatch, serve on a match.
    #[test]
    fn a_v8_client_redials_a_v7_only_server_at_7() {
        let path = socket_path("v7-server");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let mut offered = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut s = &stream;
                let hello = decode_hello(&read_frame(&mut s).unwrap()).expect("a hello");
                offered.push(hello.version);
                write_hello(
                    &mut s,
                    &Hello {
                        version: 7,
                        mode: HelloMode::Verbatim,
                    },
                )
                .unwrap();
                if hello.version != 7 {
                    continue; // the v7 server closes on a mismatch
                }
                let call: Call = read_message(&mut s).unwrap();
                assert!(
                    matches!(call, Call::IssueAs(..) | Call::Issue(..)),
                    "{call:?}"
                );
                let reply = Reply::Resolved(
                    Representation::new(ReprType::new("text/plain"), b"from v7".to_vec()),
                    CacheStatus::Miss,
                );
                write_message(&mut s, &reply).unwrap();
            }
            offered
        });

        let client = connect(&path).unwrap();
        let (representation, _) = client.issue(upper("hi")).unwrap();
        assert_eq!(representation.bytes, b"from v7");
        drop(client);
        assert_eq!(server.join().unwrap(), vec![PROTOCOL_VERSION, 7]);
        let _ = std::fs::remove_file(&path);
    }

    // ---- wire v9: the run's context crosses (ledger #1546) ----

    /// A kernel whose one endpoint reports the run it sees: `{retries},{time_left_ms}`,
    /// `-` for a half the run does not carry. It has a retry budget (ceiling 3), so a pool
    /// exists for the carried count to narrow.
    fn run_kernel() -> Kernel {
        let left = FnEndpoint::new("left", |inv: &ikigai_core::Invocation<'_>| {
            let retries = inv
                .retry_budget()
                .map(|pool| pool.remaining().to_string())
                .unwrap_or_else(|| "-".to_string());
            let time_left = inv
                .time_left()
                .map(|left| left.as_millis().to_string())
                .unwrap_or_else(|| "-".to_string());
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{retries},{time_left}").into_bytes(),
            ))
        });
        // A clock, so `time_left` can be measured against the deadline the door sets.
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:left"), left),
        ))
        .with_retry_budget(0, 3)
        .with_clock(Arc::new(SystemClock))
    }

    fn left() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:left").unwrap())
    }

    /// The carried answer, split: the retries the peer saw and the ms it had left.
    fn carried(bytes: &[u8]) -> (String, Option<u64>) {
        let text = String::from_utf8_lossy(bytes);
        let (retries, left) = text.split_once(',').expect("retries,time_left");
        (retries.to_string(), left.parse().ok())
    }

    /// A v9 client's run context reaches a v9 server: the peer's endpoint sees the
    /// carried retries (the pool minted at the limit, under root's ceiling of 3) and a
    /// deadline about the carried time left away, on the PEER's clock. A plain `issue_as`
    /// from the same client carries nothing, and the peer runs under its own policy:
    /// root's ceiling and no deadline, today's behavior.
    #[test]
    fn a_run_context_crosses_to_a_v9_server_and_bounds_the_resolution() {
        let path = socket_path("run-context");
        let server = serve_one(&path, run_kernel());
        let client = connect(&path).unwrap();
        let run = RunContext {
            retries: Some(1),
            time_left: Some(Duration::from_secs(30)),
        };
        let (answer, _) = client
            .issue_as_in_run(left(), &Capability::root(), &run)
            .unwrap();
        let (retries, time_left) = carried(&answer.bytes);
        assert_eq!(retries, "1", "the carried count narrows the pool");
        let time_left = time_left.expect("a deadline crossed");
        assert!(
            (25_000..=30_000).contains(&time_left),
            "about the carried 30 s left, on the peer's clock: {time_left} ms"
        );
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);

        let path = socket_path("run-context-none");
        let server = serve_one(&path, run_kernel());
        let client = connect(&path).unwrap();
        let (answer, _) = client.issue_as(left(), &Capability::root()).unwrap();
        assert_eq!(carried(&answer.bytes), ("3".to_string(), None));
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// The downgrade on the CLIENT's side: a v8 server (one answering 8 to the hello)
    /// cannot decode `IssueWith`, so a run that carries a context is sent as the `IssueAs`
    /// the server has always served, and the run is served under the server's own policy.
    #[test]
    fn a_run_context_is_dropped_for_a_v8_server() {
        let path = socket_path("v8-server-run");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let mut offered = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut s = &stream;
                let hello = decode_hello(&read_frame(&mut s).unwrap()).expect("a hello");
                offered.push(hello.version);
                write_hello(
                    &mut s,
                    &Hello {
                        version: 8,
                        mode: HelloMode::Verbatim,
                    },
                )
                .unwrap();
                if hello.version != 8 {
                    continue; // a v8 server closes on a mismatch
                }
                let call: Call = read_message(&mut s).unwrap();
                assert!(
                    matches!(call, Call::IssueAs(..)),
                    "a v8 server must see IssueAs, got {call:?}"
                );
                let reply = Reply::Resolved(
                    Representation::new(ReprType::new("text/plain"), b"from v8".to_vec()),
                    CacheStatus::Miss,
                );
                write_message(&mut s, &reply).unwrap();
            }
            offered
        });

        let client = connect(&path).unwrap();
        let run = RunContext {
            retries: Some(1),
            time_left: Some(Duration::from_secs(30)),
        };
        let (representation, _) = client
            .issue_as_in_run(left(), &Capability::root(), &run)
            .unwrap();
        assert_eq!(representation.bytes, b"from v8");
        drop(client);
        assert_eq!(server.join().unwrap(), vec![PROTOCOL_VERSION, 8]);
        let _ = std::fs::remove_file(&path);
    }

    /// The alias mode crosses in the client hello — the byte a
    /// prefix-canonical peer (ikigai-python) reads to pick its entries form.
    #[test]
    fn the_client_hello_carries_the_mount_mode() {
        let path = socket_path("mode");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = &stream;
            let payload = read_frame(&mut s).unwrap();
            let hello = decode_hello(&payload).expect("a hello");
            write_hello(
                &mut s,
                &Hello {
                    version: PROTOCOL_VERSION,
                    mode: HelloMode::Verbatim,
                },
            )
            .unwrap();
            hello.mode
        });

        let _client = connect_as(&path, HelloMode::Alias).unwrap();
        assert_eq!(server.join().unwrap(), HelloMode::Alias);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_remote_denial_stays_a_permanent_denial() {
        let space = EndpointSpace::new().bind(
            Exact::new("urn:demo:gated"),
            ikigai_core::FnEndpoint::new("gated", |_inv| {
                Err(Error::Denied("needs urn:cap:x".to_string()))
            }),
        );
        let path = socket_path("typed-denied");
        let server = serve_one(&path, Kernel::new(Arc::new(space)));
        let client = connect(&path).unwrap();
        let err = client
            .issue(Request::new(Verb::Source, iri_of("urn:demo:gated")))
            .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!err.is_transient());
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_remote_timeout_stays_transient_across_the_wire() {
        let space = EndpointSpace::new().bind(
            Exact::new("urn:demo:slow"),
            ikigai_core::FnEndpoint::new("slow", |_inv| {
                Err(Error::Timeout("5s elapsed".to_string()))
            }),
        );
        let path = socket_path("typed-timeout");
        let server = serve_one(&path, Kernel::new(Arc::new(space)));
        let client = connect(&path).unwrap();
        let err = client
            .issue(Request::new(Verb::Source, iri_of("urn:demo:slow")))
            .unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        assert!(
            err.is_transient(),
            "a remote transient must remain actionable by Failover/Retry"
        );
        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    fn iri_of(s: &str) -> Iri {
        Iri::parse(s).unwrap()
    }

    // --- reconnect-on-broken-connection (heal on use) -----------------------

    /// Accept one connection, verify + count its hello, then serve until
    /// `resolutions` REAL resolutions (non-Meta Issue calls) are answered and
    /// hang up — a server instance whose LIFETIME the test controls, so a
    /// bounce (serve some, die) is deterministic. Meta probes (a mount's
    /// `describe()` forwards one per resolve) and the IsCached/Entries
    /// bookkeeping ride free, so the bounce lands between the first answered
    /// resolution and the next regardless of how many probes surround them.
    fn serve_counting_hellos(
        path: &Path,
        kernel: Kernel,
        hellos: Arc<AtomicUsize>,
        resolutions: usize,
    ) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = &stream;
            let payload = read_frame(&mut s).unwrap();
            assert!(
                decode_hello(&payload).is_some(),
                "every (re)dial must open with a version hello"
            );
            hellos.fetch_add(1, Ordering::SeqCst);
            write_hello(
                &mut s,
                &Hello {
                    version: PROTOCOL_VERSION,
                    mode: HelloMode::Verbatim,
                },
            )
            .unwrap();
            let mut served = 0;
            while served < resolutions {
                let call: Call = match read_message(&mut s) {
                    Ok(call) => call,
                    Err(_) => return, // EOF: the client hung up
                };
                let real = match &call {
                    Call::Issue(request)
                    | Call::IssueAs(request, _)
                    | Call::IssueTraced(request, _, _)
                    | Call::IssueWith(request, _, _) => request.verb != Verb::Meta,
                    Call::IsCached(_) | Call::Entries => false,
                };
                if write_message(&mut s, &dispatch(&kernel, call, &Admission::owner())).is_err() {
                    return;
                }
                if real {
                    served += 1;
                }
            }
            // Served its budget — hang up mid-session (the bounce).
        })
    }

    /// A kernel whose `urn:demo:box` Sink counts its executions — shared memory
    /// with the test (server threads are in-process), so the test can assert
    /// exactly how many times a mutation actually ran across a break.
    fn counting_sink_kernel(executed: Arc<AtomicUsize>) -> Kernel {
        let sink = FnEndpoint::new("box", move |_inv| {
            executed.fetch_add(1, Ordering::SeqCst);
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"stored".to_vec(),
            ))
        });
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:demo:box"), sink),
        ))
    }

    fn sink_box() -> Request {
        Request::new(Verb::Sink, Iri::parse("urn:demo:box").unwrap())
            .with_arg("content", ArgRef::Inline(b"x".to_vec()))
    }

    /// The incident (2026-08-09): an ESTABLISHED connection breaks under a
    /// long-running client — the server bounced — and before this fix every
    /// subsequent call failed with "Broken pipe" forever; a process restart was
    /// the only cure. A Source must transparently heal: one redial, correct
    /// answer, and the redial renegotiates the version hello (the peer may have
    /// been upgraded across the bounce).
    #[test]
    fn a_source_heals_across_a_server_bounce_with_a_fresh_hello() {
        let path = socket_path("heal-source");
        let first_hellos = Arc::new(AtomicUsize::new(0));
        let first = serve_counting_hellos(&path, kernel(), Arc::clone(&first_hellos), 1);

        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("one")).unwrap().0.bytes, b"ONE");
        // The server bounces: its one-resolution budget is spent and it hangs
        // up, leaving the client holding a dead established connection.
        first.join().unwrap();

        let second_hellos = Arc::new(AtomicUsize::new(0));
        let second = serve_counting_hellos(&path, kernel(), Arc::clone(&second_hellos), usize::MAX);
        let (representation, _) = client
            .issue(upper("two"))
            .expect("a broken established connection heals on use");
        assert_eq!(representation.bytes, b"TWO");
        assert_eq!(
            second_hellos.load(Ordering::SeqCst),
            1,
            "the redial renegotiated the hello with the restarted server"
        );
        assert_eq!(first_hellos.load(Ordering::SeqCst), 1);

        drop(client);
        second.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// The daemon's shape: a mounted remote (`MountedRemote` forwarding over
    /// IPC) whose peer bounces. The next forwarded resolution must heal instead
    /// of returning "unavailable: Broken pipe" forever.
    #[test]
    fn a_mounted_remote_heals_across_a_server_bounce() {
        use ikigai_resolve::MountedRemote;

        let path = socket_path("heal-mount");
        let hellos = Arc::new(AtomicUsize::new(0));
        let first = serve_counting_hellos(&path, kernel(), Arc::clone(&hellos), 1);

        let client = connect(&path).unwrap();
        // An override-style mount: IRIs forwarded unchanged (the prefer/override
        // mount the personal daemon runs).
        let mounted = MountedRemote::overriding(Arc::new(client), "urn:test:", "test://dev.sock");
        let local = Kernel::new(Arc::new(mounted));
        let (representation, _) =
            Resolver::issue_as(&local, upper("one"), &Capability::root()).unwrap();
        assert_eq!(representation.bytes, b"ONE");
        first.join().unwrap(); // the peer bounces

        let second = serve_counting_hellos(&path, kernel(), Arc::clone(&hellos), usize::MAX);
        let (representation, _) = Resolver::issue_as(&local, upper("two"), &Capability::root())
            .expect("the standing mount heals on use after the peer bounced");
        assert_eq!(representation.bytes, b"TWO");

        drop(local);
        second.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A Sink whose reply is lost is AMBIGUOUS — the server read the full
    /// request and may have executed it — so it must NOT be silently replayed
    /// (a replay could double-write): the caller gets a typed transient to
    /// retry, and the connection still heals for the following request.
    ///
    /// The replacement server instance is listening BEFORE the break surfaces,
    /// so a buggy silent replay would reach it and be caught — the assertion is
    /// sharp, not saved by an accidental connect failure.
    #[test]
    fn a_sink_across_a_break_is_a_typed_transient_never_a_silent_replay() {
        let path = socket_path("heal-sink");
        let executed = Arc::new(AtomicUsize::new(0));
        let kernel = counting_sink_kernel(Arc::clone(&executed));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = {
            let path = path.clone();
            thread::spawn(move || {
                // First instance: hello, read ONE full call, die without replying.
                let (stream, _) = listener.accept().unwrap();
                let mut s = &stream;
                let payload = read_frame(&mut s).unwrap();
                assert!(decode_hello(&payload).is_some());
                write_hello(
                    &mut s,
                    &Hello {
                        version: PROTOCOL_VERSION,
                        mode: HelloMode::Verbatim,
                    },
                )
                .unwrap();
                let _swallowed: Call = read_message(&mut s).unwrap();
                // The restarted instance binds BEFORE the old connection drops,
                // closing the window where a buggy replay would merely fail to
                // connect and masquerade as discipline.
                let _ = std::fs::remove_file(&path);
                let reborn = UnixListener::bind(&path).unwrap();
                drop(stream); // NOW the client sees the break
                let (stream, _) = reborn.accept().unwrap();
                handle_connection(&kernel, stream);
            })
        };

        let client = connect(&path).unwrap();
        let err = client
            .issue(sink_box())
            .expect_err("a Sink whose reply was lost must surface, not silently replay");
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
        assert!(err.is_transient(), "typed transient: the caller may retry");
        // The caller's EXPLICIT retry heals the connection and runs the Sink —
        // once. (A silent replay would have made it two, or answered the failed
        // call with Ok.)
        let (representation, _) = client
            .issue(sink_box())
            .expect("the following request heals the connection");
        assert_eq!(representation.bytes, b"stored");
        assert_eq!(
            executed.load(Ordering::SeqCst),
            1,
            "the mutation ran exactly once — the explicit retry, no silent replay"
        );

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// The one case a mutation MAY replay: the request frame was never fully
    /// written (the write itself failed), so the server provably never
    /// dispatched it — replaying cannot double-apply. The client is held back
    /// until the first instance's socket is fully closed, making the write-phase
    /// failure deterministic.
    #[test]
    fn a_sink_whose_frame_never_left_replays_once_and_applies_once() {
        let path = socket_path("heal-sink-unwritten");
        let executed = Arc::new(AtomicUsize::new(0));
        let kernel = counting_sink_kernel(Arc::clone(&executed));
        let (dead, dead_signal) = std::sync::mpsc::channel::<()>();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = {
            let path = path.clone();
            thread::spawn(move || {
                // First instance: hello only, then die BEFORE reading any call.
                let (stream, _) = listener.accept().unwrap();
                let mut s = &stream;
                let payload = read_frame(&mut s).unwrap();
                assert!(decode_hello(&payload).is_some());
                write_hello(
                    &mut s,
                    &Hello {
                        version: PROTOCOL_VERSION,
                        mode: HelloMode::Verbatim,
                    },
                )
                .unwrap();
                let _ = std::fs::remove_file(&path);
                let reborn = UnixListener::bind(&path).unwrap();
                drop(stream);
                dead.send(()).unwrap(); // the client may now write — into EPIPE
                let (stream, _) = reborn.accept().unwrap();
                handle_connection(&kernel, stream);
            })
        };

        let client = connect(&path).unwrap();
        dead_signal.recv().unwrap();
        let (representation, _) = client
            .issue(sink_box())
            .expect("a provably-unwritten Sink replays on the fresh connection");
        assert_eq!(representation.bytes, b"stored");
        assert_eq!(
            executed.load(Ordering::SeqCst),
            1,
            "applied exactly once — the replay, with nothing before it"
        );

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A break whose server never returns: the healing attempt's redial fails,
    /// and the call surfaces the same typed transient a connect failure always
    /// was — promptly, with the next call retrying the dial (no wedged state).
    #[test]
    fn a_break_with_no_server_back_stays_a_typed_transient() {
        let path = socket_path("heal-nobody");
        let hellos = Arc::new(AtomicUsize::new(0));
        let server = serve_counting_hellos(&path, kernel(), Arc::clone(&hellos), 1);
        let client = connect(&path).unwrap();
        assert_eq!(client.issue(upper("one")).unwrap().0.bytes, b"ONE");
        server.join().unwrap(); // gone, and staying gone

        for _ in 0..2 {
            let err = client.issue(upper("two")).unwrap_err();
            assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
            assert!(
                err.is_transient(),
                "an absent peer stays the transient a Failover falls through on"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_self_connection_reports_our_own_uid() {
        let path = socket_path("uid");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        // Both ends are this process, so the peer UID is our own.
        assert_eq!(peer_uid(&server_side), Some(own_uid()));
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// ★ The case with NO COVERAGE before ledger #404, and the reason it shipped: a peer
    /// that ACCEPTS the connection, completes the version hello, and then answers nothing
    /// at all. A refused connect fails fast and a dead socket fails fast; only *accepted
    /// and silent* reaches a blocking read with nobody on the other end.
    mod a_peer_that_accepts_and_never_answers {
        use super::*;
        use ikigai_core::{ActionQuery, Fallback, Space};
        use ikigai_resolve::MountedRemote;

        /// The deadline under test. Short enough that a wall-clock assertion is honest
        /// about what it proves, and long enough that a loopback round trip (~50µs) is
        /// never mistaken for a miss.
        const BOUND: Duration = Duration::from_millis(200);

        /// A peer that accepts, says hello, and then answers NOTHING — counting the calls
        /// that reached it, so a test can prove a mount stopped asking. The loop ends when
        /// the client hangs up, which is what makes `join()` a valid end-of-test barrier.
        fn silent_peer(path: &Path, received: Arc<AtomicUsize>) -> thread::JoinHandle<()> {
            silent_peer_for(path, received, 1)
        }

        /// The same double, serving `connections` clients — one mount dials one
        /// connection, so a test with two mounts of one peer needs two.
        fn silent_peer_for(
            path: &Path,
            received: Arc<AtomicUsize>,
            connections: usize,
        ) -> thread::JoinHandle<()> {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).unwrap();
            thread::spawn(move || {
                let mut served = Vec::new();
                for _ in 0..connections {
                    let Ok((stream, _)) = listener.accept() else {
                        break;
                    };
                    let received = Arc::clone(&received);
                    served.push(thread::spawn(move || {
                        let mut s = &stream;
                        let _ = read_frame(&mut s); // the client's hello
                        let _ = write_hello(
                            &mut s,
                            &Hello {
                                version: PROTOCOL_VERSION,
                                mode: HelloMode::Verbatim,
                            },
                        );
                        while read_frame(&mut s).is_ok() {
                            received.fetch_add(1, Ordering::SeqCst);
                        }
                    }));
                }
                for handle in served {
                    let _ = handle.join();
                }
            })
        }

        /// A mount whose peer is silent, beside a local endpoint. `BOUND` is the DESCRIBE
        /// deadline; the connection's own I/O deadline is left long, so a test that passes
        /// proves the new bound fired and not the old one.
        /// One peer per socket: the label a mount carries, and the key a `PeerHealth`
        /// shares its verdict under.
        fn origin_of(path: &Path) -> String {
            format!("ipc:{}", path.display())
        }

        fn kernel_with_a_silent_mount(path: &Path) -> Kernel {
            let client = connect_with_timeout(path, Some(Duration::from_secs(30)))
                .unwrap()
                .with_describe_timeout(Some(BOUND));
            Kernel::new(Arc::new(Fallback::new(vec![
                Arc::new(
                    EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
                ) as Arc<dyn Space>,
                Arc::new(MountedRemote::new(
                    Arc::new(client),
                    "urn:edge:",
                    origin_of(path),
                )) as Arc<dyn Space>,
            ])))
        }

        /// Isolation probe kept as a test in its own right: the MOUNT, with no kernel
        /// around it, answers a silent peer with exactly one row.
        #[test]
        fn the_mount_itself_contributes_one_naming_row() {
            let path = socket_path("silent-mount-only");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&path, Arc::clone(&received));
            let client = connect_with_timeout(&path, Some(Duration::from_secs(30)))
                .unwrap()
                .with_describe_timeout(Some(BOUND));
            assert!(
                matches!(Resolver::try_entries(&client), Err(Error::Timeout(_))),
                "the transport reports the silence as a deadline"
            );
            let mounted = MountedRemote::new(Arc::new(client), "urn:edge:", origin_of(&path));
            let entries = Space::entries(&mounted).expect("a failed enumeration still SAYS so");
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(entries[0].pattern, "urn:edge:ikigai:mount-unavailable");
            assert_eq!(entries[0].origin, Some(origin_of(&path)));

            drop(mounted);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// The headline: the manifold RETURNS, within a bound, and it SAYS which peer did
        /// not answer. A timeout that silently dropped the peer would pass the first half
        /// and fail the second — and that is the defect this arc exists not to ship, since
        /// a caller would then conclude the peer's capabilities do not exist.
        #[test]
        // Native-only: the IPC transport is Unix sockets. The test measures elapsed time,
        // which is the only way to prove a bound fired rather than a hang being lucky.
        #[allow(clippy::disallowed_methods)]
        fn the_manifold_returns_bounded_and_names_the_peer() {
            let path = socket_path("silent-manifold");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&path, Arc::clone(&received));
            let kernel = kernel_with_a_silent_mount(&path);

            let start = std::time::Instant::now();
            let matches = kernel.select_actions(&ActionQuery::default());
            let elapsed = start.elapsed();

            assert!(
                elapsed < Duration::from_secs(5),
                "the manifold returned on the bound, not on a hang: {elapsed:?}"
            );
            let named: Vec<&str> = matches.iter().map(|m| m.endpoint.as_str()).collect();
            assert!(
                named.contains(&"urn:edge:ikigai:mount-unavailable"),
                "the degraded manifold NAMES the peer that did not answer: {named:?}"
            );
            // …and the rest of the kernel is intact. A bound that dropped the silent peer
            // AND the local bindings would be a worse lie than the hang.
            assert!(
                named.contains(&"urn:test:upper"),
                "every other action is still offered: {named:?}"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// The row is not decoration: it RESOLVES, and what it resolves to is the whole
        /// diagnosis — which namespace is missing, from which peer, and why. That is what
        /// "in a form a caller can act on" has to mean for something an agent reads.
        #[test]
        fn the_row_resolves_to_which_peer_and_why() {
            let path = socket_path("silent-row");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&path, Arc::clone(&received));
            let kernel = kernel_with_a_silent_mount(&path);

            // The enumeration is what discovers the silence; the row is its record.
            let _ = Resolver::entries(&kernel);
            let request = Request::new(
                Verb::Source,
                Iri::parse("urn:edge:ikigai:mount-unavailable").unwrap(),
            );
            let (representation, _) =
                Resolver::issue_as(&kernel, request, &Capability::root()).unwrap();
            let said = String::from_utf8(representation.bytes).unwrap();
            assert!(said.contains(&origin_of(&path)), "names the peer: {said}");
            assert!(said.contains("urn:edge:"), "names the namespace: {said}");
            assert!(
                said.contains("not absent") || said.contains("unknown"),
                "says the resources are UNKNOWN, not absent: {said}"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// ★ The failure mode this arc must not introduce: a bound that silently DROPS the
        /// slow peer would pass "the manifold returns" and quietly under-offer. The other
        /// direction matters just as much — one silent peer must not cost a healthy peer's
        /// rows, which is what a whole-enumeration failure would have done.
        #[test]
        fn a_silent_mount_costs_the_healthy_mount_nothing() {
            use ikigai_core::Space;

            let silent_path = socket_path("mixed-silent");
            let live_path = socket_path("mixed-live");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&silent_path, Arc::clone(&received));
            // Bound before the server thread starts, so the connect below needs no retry.
            let listener = bind(&live_path).unwrap();
            let live = thread::spawn(move || {
                let _ = serve_on(kernel(), listener);
            });
            let healthy = connect(&live_path).unwrap();
            let silent = connect_with_timeout(&silent_path, Some(Duration::from_secs(30)))
                .unwrap()
                .with_describe_timeout(Some(BOUND));

            let kernel = Kernel::new(Arc::new(Fallback::new(vec![
                Arc::new(MountedRemote::new(
                    Arc::new(silent),
                    "urn:edge:",
                    origin_of(&silent_path),
                )) as Arc<dyn Space>,
                Arc::new(MountedRemote::new(
                    Arc::new(healthy),
                    "urn:live:",
                    origin_of(&live_path),
                )) as Arc<dyn Space>,
            ])));

            // The catalog carries the healthy peer's bindings, complete and re-prefixed…
            let catalog = Resolver::entries(&kernel).expect("the kernel enumerates");
            assert!(
                catalog.iter().any(|e| e.pattern == "urn:live:test:upper"),
                "the healthy peer's bindings are COMPLETE beside a silent one: {catalog:?}"
            );
            // …and the manifold, which is the resource an agent reads, names the silent one.
            // (The healthy peer's kernel here has no JSON Meta renderer, so its rows carry
            // no actions — a pre-existing, separately-diagnosed condition, and the reason
            // this half asserts over the catalog rather than over the manifold.)
            let named: Vec<String> = kernel
                .select_actions(&ActionQuery::default())
                .into_iter()
                .map(|m| m.endpoint)
                .collect();
            assert!(
                named
                    .iter()
                    .any(|e| e == "urn:edge:ikigai:mount-unavailable"),
                "the silent mount is named in the manifold: {named:?}"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&silent_path);
            let _ = std::fs::remove_file(&live_path);
            drop(live);
        }

        /// ★ Silence is a property of the PEER, not of the local name a mount gave it.
        /// plasma mounts one `ikigai-gonk` under two prefixes; with a record per mount that
        /// one silent process cost TWO deadlines on every manifold read (measured at 60s
        /// where one deadline is 30s), and five mounts would have cost five.
        ///
        /// Both namespaces still get their own row — what they share is the verdict, not
        /// the statement. One row for two silenced namespaces would under-report exactly
        /// the case this exists for.
        #[test]
        fn two_mounts_of_one_silent_peer_cost_one_deadline_and_still_name_both() {
            use ikigai_core::Space;

            let path = socket_path("silent-shared");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer_for(&path, Arc::clone(&received), 2);
            let origin = origin_of(&path);
            // One `PeerHealth` for this kernel's mounts — what a composer hands every
            // mount it builds. Two mounts, one peer, one verdict.
            let peers = ikigai_resolve::PeerHealth::default();
            let mut mounts: Vec<Arc<dyn Space>> = Vec::new();
            for prefix in ["urn:one:", "urn:two:"] {
                let client = connect_with_timeout(&path, Some(Duration::from_secs(30)))
                    .unwrap()
                    .with_describe_timeout(Some(BOUND));
                mounts.push(Arc::new(
                    MountedRemote::new(Arc::new(client), prefix, origin.clone()).sharing(&peers),
                ));
            }
            let kernel = Kernel::new(Arc::new(Fallback::new(mounts)));

            let named: Vec<String> = kernel
                .select_actions(&ActionQuery::default())
                .into_iter()
                .map(|m| m.endpoint)
                .collect();
            assert!(
                named
                    .iter()
                    .any(|e| e == "urn:one:ikigai:mount-unavailable")
                    && named
                        .iter()
                        .any(|e| e == "urn:two:ikigai:mount-unavailable"),
                "both silenced namespaces say so: {named:?}"
            );
            assert_eq!(
                received.load(Ordering::SeqCst),
                1,
                "…and the peer was asked once, not once per mount"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// ⚠ The row is reachable in a process where nothing has failed — a one-shot
        /// `ikigai -c` reading an IRI out of a manifold an earlier process printed. It must
        /// not claim a failure it cannot support. (It said "it has answered since; this row
        /// is stale" for a peer that had never been asked, which is a contradiction in one
        /// sentence and was exactly the first thing a live run printed.)
        #[test]
        fn with_no_failure_recorded_the_row_does_not_claim_one() {
            let path = socket_path("silent-unasked");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&path, Arc::clone(&received));
            let kernel = kernel_with_a_silent_mount(&path);

            // Deliberately NO enumeration first.
            let request = Request::new(
                Verb::Source,
                Iri::parse("urn:edge:ikigai:mount-unavailable").unwrap(),
            );
            let (representation, _) =
                Resolver::issue_as(&kernel, request, &Capability::root()).unwrap();
            let said = String::from_utf8(representation.bytes).unwrap();
            assert!(
                said.contains("no current record"),
                "it says what it knows, which is nothing: {said}"
            );
            assert!(
                said.contains(&origin_of(&path)),
                "and still names the peer: {said}"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// ★ The deadline bounds a CALL; this bounds the WALK. A manifold read is one
        /// enumeration plus one `describe()` per catalog row, so a per-call deadline over a
        /// silent peer would cost `rows × deadline` — bounded arithmetic that is still a
        /// hang to a human. The mount asks ONCE and believes the answer for a cooldown.
        #[test]
        fn a_silent_peer_is_asked_once_per_walk_not_once_per_row() {
            let path = socket_path("silent-once");
            let received = Arc::new(AtomicUsize::new(0));
            let server = silent_peer(&path, Arc::clone(&received));
            let kernel = kernel_with_a_silent_mount(&path);

            // Three full manifold walks, each of which would re-ask an unguarded mount.
            for _ in 0..3 {
                let _ = kernel.select_actions(&ActionQuery::default());
            }
            assert_eq!(
                received.load(Ordering::SeqCst),
                1,
                "the peer was asked once and believed; every later describe failed instantly"
            );

            drop(kernel);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }
    }

    /// The other half of the bound: a healthy peer must not pay for it, and a RESOLUTION
    /// must not inherit it. A deadline implemented as "wait, then check" would trade a hang
    /// for a tax on every call, which is not a fix.
    mod the_bound_costs_a_healthy_peer_nothing {
        use super::*;
        use ikigai_core::Space;
        use ikigai_resolve::MountedRemote;

        /// A peer that answers everything, but only after `delay`. One delay, two
        /// outcomes: it is under the connection's I/O deadline and over the describe one,
        /// so the SAME server on the SAME connection serves a resolution and misses a
        /// self-description. Nothing else in the test distinguishes the two calls.
        ///
        /// Serves exactly `connections` clients and then stops accepting, so `join()` is a
        /// valid end-of-test barrier — a test that dials fewer would hang in `accept`. Two
        /// is the interesting number: a call that misses its deadline now SPENDS its
        /// connection, so the call after it redials.
        fn slow_peer(path: &Path, delay: Duration, connections: usize) -> thread::JoinHandle<()> {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).unwrap();
            thread::spawn(move || {
                let mut served = Vec::new();
                for _ in 0..connections {
                    let Ok((stream, _)) = listener.accept() else {
                        break;
                    };
                    served.push(thread::spawn(move || {
                        let mut s = &stream;
                        let _ = read_frame(&mut s); // the client's hello
                        let _ = write_hello(
                            &mut s,
                            &Hello {
                                version: PROTOCOL_VERSION,
                                mode: HelloMode::Verbatim,
                            },
                        );
                        while let Ok(call) = read_message::<_, Call>(&mut s) {
                            std::thread::sleep(delay);
                            let reply = match call {
                                Call::Entries => Reply::Entries(Some(Vec::new())),
                                _ => Reply::Resolved(
                                    Representation::new(
                                        ikigai_core::ReprType::new("text/plain"),
                                        "slow",
                                    ),
                                    ikigai_resolve::CacheStatus::Uncacheable,
                                ),
                            };
                            if write_message(&mut s, &reply).is_err() {
                                return;
                            }
                        }
                    }));
                }
                for handle in served {
                    let _ = handle.join();
                }
            })
        }

        #[test]
        fn a_resolution_keeps_the_patient_deadline_a_describe_does_not() {
            let path = socket_path("slow-peer");
            let server = slow_peer(&path, Duration::from_millis(300), 2);
            let client = connect_with_timeout(&path, Some(Duration::from_secs(30)))
                .unwrap()
                .with_describe_timeout(Some(Duration::from_millis(100)));

            // A resolution takes 300ms and succeeds: its deadline is 30s, untouched.
            let (representation, _) = client
                .issue(Request::new(
                    Verb::Source,
                    Iri::parse("urn:test:slow").unwrap(),
                ))
                .expect("a slow resolution is still a resolution");
            assert_eq!(representation.bytes, b"slow");

            // The same peer, the same 300ms, an enumeration: bounded at 100ms, refused.
            let error = Resolver::try_entries(&client)
                .expect_err("a self-description that misses its deadline is an ERROR");
            assert!(matches!(error, Error::Timeout(_)), "{error:?}");
            assert!(error.is_transient(), "a deadline is transient: {error:?}");

            // ★ ONE MORE CALL — the line this test stopped short of, and the whole of
            // ledger #479. The enumeration above gave up on a reply the peer is still
            // going to write; replies match calls POSITIONALLY, so a kept connection
            // would answer this resolution with that abandoned `Entries`. It must not:
            // the missed deadline spent the connection, and this call redials.
            let (after, _) = client
                .issue(Request::new(
                    Verb::Source,
                    Iri::parse("urn:test:slow").unwrap(),
                ))
                .expect("the call after a deadline miss gets its OWN reply, not the last one's");
            assert_eq!(
                after.bytes, b"slow",
                "a resolution answered with the abandoned enumeration's reply"
            );

            drop(client);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }

        /// A healthy mount's enumeration costs a round trip, not a deadline. The assertion
        /// is deliberately far below the bound: what it rules out is an implementation that
        /// waits out the deadline before looking.
        #[test]
        // Native-only, and elapsed time is the measurement — see the module above.
        #[allow(clippy::disallowed_methods)]
        fn a_healthy_enumeration_does_not_pay_a_deadline() {
            let path = socket_path("healthy-enum");
            let listener = bind(&path).unwrap();
            let server = thread::spawn(move || {
                let _ = serve_on(kernel(), listener);
            });
            let client = connect(&path)
                .unwrap()
                .with_describe_timeout(Some(Duration::from_secs(30)));
            let mounted = MountedRemote::new(Arc::new(client), "urn:edge:", "ipc:healthy.sock");

            let start = std::time::Instant::now();
            let entries = Space::entries(&mounted).expect("a healthy peer enumerates");
            let elapsed = start.elapsed();

            assert!(
                entries.iter().any(|e| e.pattern == "urn:edge:test:upper"),
                "the peer's real bindings, re-prefixed: {entries:?}"
            );
            assert!(
                !entries.iter().any(|e| e.endpoint == "mount-unavailable"),
                "no degraded row on a healthy mount: {entries:?}"
            );
            assert!(
                elapsed < Duration::from_millis(500),
                "a round trip, not a deadline: {elapsed:?}"
            );

            drop(mounted);
            let _ = std::fs::remove_file(&path);
            drop(server);
        }
    }
    /// ★ Ledger #479 as a test: a call that misses its deadline must not hand its reply to
    /// the NEXT call. The peer here labels every reply with the IRI it was asked for, so a
    /// shifted reply is visible as a shifted reply and not merely as an error — which is
    /// the point, because in the field this failure produced a well-formed, internally
    /// consistent, completely wrong answer with no error anywhere.
    mod a_missed_deadline_does_not_poison_the_connection {
        use super::*;

        /// A peer that answers every resolution with the IRI it was ASKED for, so each
        /// reply can be traced to its call — and that sleeps `delay` on the FIRST call it
        /// ever receives and answers everything after it promptly. One slow call is all
        /// the defect needs; making the rest prompt keeps the test measuring the desync
        /// rather than the delay.
        ///
        /// The call counter is shared ACROSS connections deliberately: the redial must not
        /// buy a second slow call, or the test could pass by timing out twice.
        fn identifying_peer(
            path: &Path,
            connections: usize,
            delay: Duration,
        ) -> thread::JoinHandle<()> {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            thread::spawn(move || {
                let mut served = Vec::new();
                for _ in 0..connections {
                    let Ok((stream, _)) = listener.accept() else {
                        break;
                    };
                    let calls = Arc::clone(&calls);
                    served.push(thread::spawn(move || {
                        let mut s = &stream;
                        let _ = read_frame(&mut s); // the client's hello
                        let _ = write_hello(
                            &mut s,
                            &Hello {
                                version: PROTOCOL_VERSION,
                                mode: HelloMode::Verbatim,
                            },
                        );
                        while let Ok(call) = read_message::<_, Call>(&mut s) {
                            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                                std::thread::sleep(delay);
                            }
                            let asked = match &call {
                                Call::Issue(request)
                                | Call::IssueAs(request, _)
                                | Call::IssueTraced(request, _, _) => {
                                    request.target.as_str().to_string()
                                }
                                other => format!("{other:?}"),
                            };
                            let reply = Reply::Resolved(
                                Representation::new(
                                    ikigai_core::ReprType::new("text/plain"),
                                    asked,
                                ),
                                ikigai_resolve::CacheStatus::Uncacheable,
                            );
                            if write_message(&mut s, &reply).is_err() {
                                return;
                            }
                        }
                    }));
                }
                for handle in served {
                    let _ = handle.join();
                }
            })
        }

        fn source(iri: &str) -> Request {
            Request::new(Verb::Source, Iri::parse(iri).unwrap())
        }

        #[test]
        fn a_timed_out_call_cannot_hand_its_reply_to_the_next_one() {
            let path = socket_path("desync");
            // Two connections: the first is spent by the deadline miss, the second is the
            // redial. A third would mean we are redialing more than the defect requires.
            //
            // ⚠ The two numbers are chosen against EACH OTHER, and both directions matter.
            // The delay must exceed the bound (or the first call never misses) AND fall
            // short of twice it (or the abandoned reply arrives after the SECOND call's
            // deadline too, and the defect hides behind a second timeout instead of
            // showing itself as a wrong answer). 200/300 leaves 100ms of slack each way.
            let server = identifying_peer(&path, 2, Duration::from_millis(300));
            let client = connect_with_timeout(&path, Some(Duration::from_millis(200))).unwrap();

            let missed = client
                .issue(source("urn:test:a"))
                .expect_err("300ms of silence against a 200ms bound is a miss");
            assert!(matches!(missed, Error::Timeout(_)), "{missed:?}");

            // The peer writes `a`'s reply 100ms into THIS call's own deadline. With
            // positional matching and a kept connection, this call reads it — and reads
            // it successfully, which is the whole horror of ledger #479: not an error, a
            // well-formed representation of a resource nobody asked for.
            let (b, _) = client
                .issue(source("urn:test:b"))
                .expect("the call after a deadline miss resolves");
            assert_eq!(
                String::from_utf8_lossy(&b.bytes),
                "urn:test:b",
                "b was answered with another request's reply"
            );

            // And the shift, once taken, never went away — so a second clean call is the
            // difference between a one-off and a poisoned connection.
            let (c, _) = client
                .issue(source("urn:test:c"))
                .expect("and the one after that");
            assert_eq!(
                String::from_utf8_lossy(&c.bytes),
                "urn:test:c",
                "the connection stayed shifted by one reply"
            );

            drop(client);
            server.join().unwrap();
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// ledger #1335: a peer that ACCEPTS a call and never answers it (or answers a byte at a
/// time) must cost the caller its deadline and no more, and the call must be canceled.
#[cfg(test)]
mod call_deadline {
    use super::*;
    use ikigai_core::{Iri, Verb};
    use std::io::{Read as _, Write as _};
    use std::sync::mpsc;
    use std::time::Instant;

    /// Far above every deadline under test: a test that passes proves the CALL deadline
    /// fired, not the connection's standing timeout.
    const STANDING: Duration = Duration::from_secs(30);

    fn socket(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ik-cd-{}-{name}.sock", std::process::id()))
    }

    /// How a scratch peer behaves once it has read a call.
    #[derive(Clone, Copy)]
    enum Peer {
        /// Says nothing at all.
        Silent,
        /// Starts a 100 KB reply and sends one byte of it every `0`: each inside any
        /// standing timeout, the whole never.
        Trickle(Duration),
        /// Answers `slow` after `0`.
        Slow(Duration),
    }

    /// A peer that accepts any number of connections, says hello, and treats each call as
    /// `behavior` says. When a client hangs up on a call it never finished answering, the
    /// peer reports it: that is the call canceled.
    fn peer(path: &Path, behavior: Peer) -> mpsc::Receiver<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let (hung_up, canceled) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let hung_up = hung_up.clone();
                std::thread::spawn(move || {
                    let mut s = &stream;
                    let _ = read_frame(&mut s); // the client's hello
                    let _ = write_hello(
                        &mut s,
                        &Hello {
                            version: PROTOCOL_VERSION,
                            mode: HelloMode::Verbatim,
                        },
                    );
                    while read_frame(&mut s).is_ok() {
                        match behavior {
                            Peer::Silent => {
                                // Wait for the client to give up: its hang-up ends the read.
                                let mut rest = Vec::new();
                                let _ = s.read_to_end(&mut rest);
                                let _ = hung_up.send(());
                                return;
                            }
                            Peer::Trickle(every) => {
                                let _ = s.write_all(&100_000u32.to_be_bytes());
                                loop {
                                    std::thread::sleep(every);
                                    if s.write_all(&[0]).is_err() {
                                        let _ = hung_up.send(());
                                        return;
                                    }
                                }
                            }
                            Peer::Slow(delay) => {
                                std::thread::sleep(delay);
                                let reply = Reply::Resolved(
                                    Representation::new(
                                        ikigai_core::ReprType::new("text/plain"),
                                        "slow",
                                    ),
                                    CacheStatus::Uncacheable,
                                );
                                if write_message(&mut s, &reply).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        canceled
    }

    fn source() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:slow").unwrap())
    }

    /// The call returns on the CALLER's thread within the deadline: no thread is spawned
    /// for it, so none can be left behind.
    #[test]
    // Unix-only, never wasm; elapsed time is the measurement.
    #[allow(clippy::disallowed_methods)]
    fn a_peer_that_never_answers_costs_the_call_deadline_and_the_call_is_canceled() {
        let path = socket("silent");
        let canceled = peer(&path, Peer::Silent);
        let client = connect_with_timeout(&path, Some(STANDING))
            .unwrap()
            .with_call_timeout(Some(Duration::from_millis(300)));

        let start = Instant::now();
        let error = client
            .issue(source())
            .expect_err("a peer that never answers is an ERROR, not a wait");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(300) && elapsed < Duration::from_secs(2),
            "bounded by the call deadline, not the {STANDING:?} standing timeout: {elapsed:?}"
        );
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(error.is_transient(), "{error:?}");
        let said = error.to_string();
        assert!(
            said.contains(&path.display().to_string()) && said.contains("within 300ms"),
            "the deadline names the peer and the bound: {said}"
        );
        // Canceled: the connection the call rode is dropped, and the peer sees the hang-up.
        assert_eq!(canceled.recv_timeout(Duration::from_secs(5)), Ok(()));
        assert!(
            client.stream.lock().unwrap().is_none(),
            "the spent connection is not kept"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The case a socket timeout alone never bounded: every byte arrives inside the
    /// standing timeout, so before the deadline this call ran for as long as the peer liked.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_peer_that_trickles_its_reply_is_bounded_by_the_whole_call() {
        let path = socket("trickle");
        let canceled = peer(&path, Peer::Trickle(Duration::from_millis(50)));
        let client = connect_with_timeout(&path, Some(Duration::from_secs(1)))
            .unwrap()
            .with_call_timeout(Some(Duration::from_millis(600)));

        let start = Instant::now();
        let error = client
            .issue(source())
            .expect_err("a reply that never completes is an ERROR");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(error.to_string().contains("within 600ms"), "{error}");
        assert_eq!(canceled.recv_timeout(Duration::from_secs(5)), Ok(()));
        let _ = std::fs::remove_file(&path);
    }

    /// A deadline passed for ONE call, on a resolver with no standing call deadline.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_deadline_passed_for_one_call_bounds_that_call() {
        let path = socket("percall");
        let _canceled = peer(&path, Peer::Silent);
        let client = connect_with_timeout(&path, Some(STANDING))
            .unwrap()
            .with_call_timeout(None);
        assert_eq!(client.call_timeout(), None);

        let start = Instant::now();
        let error = client
            .issue_as_within(source(), &Capability::root(), Duration::from_millis(300))
            .expect_err("bounded by the deadline this call was given");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(error.to_string().contains("within 300ms"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// The bound costs an honest peer nothing, and leaves no trace on the connection: a
    /// call answered inside its deadline is answered, and the connection's standing timeouts
    /// are back afterwards, so the next call is not cut short by what is left of this one.
    #[test]
    fn a_slow_peer_that_answers_inside_the_deadline_still_succeeds() {
        let path = socket("slow");
        let _canceled = peer(&path, Peer::Slow(Duration::from_millis(200)));
        let client = connect_with_timeout(&path, Some(STANDING))
            .unwrap()
            .with_call_timeout(Some(Duration::from_secs(5)));
        for _ in 0..2 {
            let (answer, _) = client
                .issue(source())
                .expect("answered inside the deadline");
            assert_eq!(answer.bytes, b"slow");
        }
        let (answer, _) = client
            .issue_as_within(source(), &Capability::root(), Duration::from_secs(5))
            .expect("and per call");
        assert_eq!(answer.bytes, b"slow");
        let guard = client.stream.lock().unwrap();
        let stream = &guard.as_ref().expect("the connection is kept").stream;
        assert_eq!(stream.read_timeout().unwrap(), Some(STANDING));
        assert_eq!(stream.write_timeout().unwrap(), Some(STANDING));
        drop(guard);
        let _ = std::fs::remove_file(&path);
    }

    /// A self-description that misses ITS deadline says so, naming the peer.
    #[test]
    fn a_missed_describe_deadline_names_the_peer() {
        let path = socket("describe");
        let _canceled = peer(&path, Peer::Silent);
        let client = connect_with_timeout(&path, Some(STANDING))
            .unwrap()
            .with_describe_timeout(Some(Duration::from_millis(200)));
        let error = Resolver::try_entries(&client).expect_err("a silent peer");
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("did not describe itself within 200ms")
                && error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The default follows the standing timeout, so an operator who raised `ipc.timeout`
    /// for long calls keeps them.
    #[test]
    fn the_default_call_deadline_is_the_standing_timeout() {
        let path = socket("default");
        let _canceled = peer(&path, Peer::Silent);
        let client = connect_with_timeout(&path, Some(STANDING)).unwrap();
        assert_eq!(client.call_timeout(), Some(STANDING));
        let _ = std::fs::remove_file(&path);
    }
}

/// D4 and D12 of the principal model (ledger #1830): what the owner socket does with a name
/// the client supplies. Each test was written to FAIL on the door before this change.
#[cfg(test)]
mod principal_tests {
    use super::*;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Exact, FnEndpoint, Iri, ReprType, Verb};
    use std::thread;

    /// An endpoint that answers `<capability principal>|<principal argument>`, `-` for none.
    fn whoami_kernel() -> Kernel {
        let whoami = FnEndpoint::new("whoami", |inv: &ikigai_core::Invocation<'_>| {
            let held = inv.capability.principal().unwrap_or("-").to_string();
            let arg = inv.inline_str("principal").unwrap_or("-").to_string();
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{held}|{arg}").into_bytes(),
            ))
        });
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:whoami"), whoami),
        ))
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ikp-{}-{name}.sock", std::process::id()))
    }

    fn serve(path: &Path) {
        let listener = bind(path).unwrap();
        thread::spawn(move || {
            let _ = serve_on(whoami_kernel(), listener);
        });
    }

    fn whoami() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:whoami").unwrap())
    }

    fn serve_admitted(path: &Path, admission: Admission) {
        let listener = bind(path).unwrap();
        thread::spawn(move || {
            let _ = serve_shared_on_admitted(
                Arc::new(whoami_kernel()),
                listener,
                Limits::default(),
                admission,
            );
        });
    }

    /// A bounded admission MINTS its principal into every call, whatever the client carried
    /// or sent, and the carried capability is clamped to its ceiling.
    #[test]
    fn a_bounded_admission_names_its_own_principal_on_every_call() {
        let path = path("bounded");
        serve_admitted(
            &path,
            Admission::bounded(
                Capability::scoped(["urn:cap:demo:read"]),
                Some("urn:example:agent".to_string()),
            )
            .unwrap(),
        );
        let client = connect(&path).unwrap();
        let forged =
            whoami().with_arg("principal", ArgRef::Inline(b"urn:example:mallory".to_vec()));
        let named = "urn:example:agent|urn:example:agent";
        let (plain, _) = client.issue(forged.clone()).unwrap();
        assert_eq!(String::from_utf8_lossy(&plain.bytes), named);
        let mallory = Capability::scoped(["urn:cap:demo:read"])
            .with_principal("urn:example:mallory")
            .unwrap();
        let (carried, _) = client.issue_as(forged.clone(), &mallory).unwrap();
        assert_eq!(String::from_utf8_lossy(&carried.bytes), named);
        let (rooted, _) = client.issue_as(forged, &Capability::root()).unwrap();
        assert_eq!(String::from_utf8_lossy(&rooted.bytes), named);
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// A bounded ceiling is a ceiling: a carried root, or a carried scope the ceiling does not
    /// hold, cannot reach what the ceiling does not grant.
    #[test]
    fn a_bounded_admission_refuses_what_its_ceiling_does_not_grant() {
        let guarded = FnEndpoint::new("guarded", |_inv: &ikigai_core::Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"ok".to_vec(),
            ))
        })
        .with_description(
            ikigai_core::Description::new("guarded")
                .verb(Verb::Source)
                .requires("urn:cap:demo:write"),
        );
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:guarded"), guarded),
        )));
        let path = path("ceiling");
        let listener = bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve_shared_on_admitted(
                kernel,
                listener,
                Limits::default(),
                Admission::bounded(Capability::scoped(["urn:cap:demo:read"]), None).unwrap(),
            );
        });
        let client = connect(&path).unwrap();
        let guarded = || Request::new(Verb::Source, Iri::parse("urn:test:guarded").unwrap());
        assert!(
            client.issue(guarded()).is_err(),
            "the ceiling lacks the scope"
        );
        let widened = Capability::scoped(["urn:cap:demo:write"]);
        assert!(client.issue_as(guarded(), &widened).is_err());
        assert!(client.issue_as(guarded(), &Capability::root()).is_err());
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// D4: a carried capability naming a principal must not name it at the owner door. The
    /// door authenticated a UID, not a principal, so a name it did not mint never enters.
    #[test]
    fn a_carried_principal_never_reaches_an_endpoint_through_the_owner_socket() {
        let path = path("carried");
        serve(&path);
        let client = connect(&path).unwrap();
        let forged = Capability::scoped(["urn:cap:demo:read"])
            .with_principal("urn:example:mallory")
            .unwrap();
        let (answer, _) = client.issue_as(whoami(), &forged).unwrap();
        assert_eq!(String::from_utf8_lossy(&answer.bytes), "-|-");
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    /// D12: a `principal` ARGUMENT the client sends is removed, as the QUIC door removes it.
    #[test]
    fn a_client_principal_argument_is_removed_at_the_owner_socket() {
        let path = path("arg");
        serve(&path);
        let client = connect(&path).unwrap();
        let forged =
            whoami().with_arg("principal", ArgRef::Inline(b"urn:example:mallory".to_vec()));
        let (plain, _) = client.issue(forged.clone()).unwrap();
        assert_eq!(String::from_utf8_lossy(&plain.bytes), "-|-");
        let (carried, _) = client
            .issue_as(forged, &Capability::scoped(["urn:cap:demo:read"]))
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&carried.bytes), "-|-");
        drop(client);
        let _ = std::fs::remove_file(&path);
    }
}
