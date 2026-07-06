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
//! Capability-based authorization (finer than per-user) layers on later.
//!
//! Unix only — the module is empty elsewhere.
#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ikigai_core::{Capability, Kernel, Representation, Request, SpaceEntry, Tracer};
use ikigai_resolve::{CacheStatus, Resolver, SpanCollector};
use ikigai_wire::{read_message, write_message, Call, Reply, TraceContext};

/// Run `kernel` as a server on `path` until an unrecoverable accept error: bind
/// the socket (replacing a stale one), restrict it to `0600`, and serve each
/// same-user connection on its own thread. Connections from another UID are
/// refused — defense in depth over the `0700` directory.
pub fn serve(kernel: Kernel, path: &Path) -> io::Result<()> {
    let kernel = Arc::new(kernel);
    let _ = std::fs::remove_file(path); // a leftover socket would fail the bind
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let me = own_uid();
    for stream in listener.incoming() {
        let stream = stream?;
        if peer_uid(&stream) != Some(me) {
            continue; // not our user — drop it
        }
        let kernel = Arc::clone(&kernel);
        std::thread::spawn(move || handle_connection(&kernel, stream));
    }
    Ok(())
}

/// Connect to a kernel server listening on `path`.
pub fn connect(path: &Path) -> io::Result<IpcResolver> {
    Ok(IpcResolver {
        stream: UnixStream::connect(path)?,
        tracer: Mutex::new(None),
    })
}

/// A [`Resolver`] backed by a kernel server over a Unix socket.
pub struct IpcResolver {
    stream: UnixStream,
    /// The tracer the `trace` command installs. When set, a resolution is sent as
    /// [`Call::IssueTraced`] and the server's returned spans are forwarded here —
    /// so a `--connect` trace shows the *remote* kernel's execution tree.
    tracer: Mutex<Option<Arc<dyn Tracer>>>,
}

impl IpcResolver {
    /// Send a call and read its reply. `&UnixStream` is `Read + Write`, so the
    /// shared `&self` can drive the socket without interior mutability.
    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        let mut stream = &self.stream;
        write_message(&mut stream, &call)?;
        read_message(&mut stream)
    }
}

impl Resolver for IpcResolver {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String> {
        match self
            .round_trip(Call::Issue(request))
            .map_err(|e| e.to_string())?
        {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            Reply::Error(message) => Err(message),
            other => Err(format!("unexpected reply to Issue: {other:?}")),
        }
    }

    /// Resolve under the session capability — carried to the server, which clamps
    /// it to the peercred-verified principal. This is what makes a `cap`-attenuated
    /// `--connect` session behave over IPC exactly like the embedded kernel.
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), String> {
        // When a tracer is installed (the `trace` command), ask the server to record
        // the resolution and ship its spans back, then forward them to the tracer —
        // so the tree shows the *remote* kernel's execution. `parent_span` is None:
        // the whole session runs remotely, so the remote root is the trace root.
        let tracer = self.tracer.lock().expect("tracer lock").clone();
        let call = if tracer.is_some() {
            Call::IssueTraced(
                request,
                capability.clone(),
                TraceContext {
                    trace_id: 1,
                    parent_span: None,
                },
            )
        } else {
            Call::IssueAs(request, capability.clone())
        };
        match self.round_trip(call).map_err(|e| e.to_string())? {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            Reply::ResolvedTraced(representation, status, events) => {
                if let Some(tracer) = &tracer {
                    for event in events {
                        tracer.record(event);
                    }
                }
                Ok((representation, status))
            }
            Reply::Error(message) => Err(message),
            other => Err(format!("unexpected reply to IssueAs: {other:?}")),
        }
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        *self.tracer.lock().expect("tracer lock") = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer.lock().expect("tracer lock") = None;
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        // The probe resolves under the server's own authority; the wire protocol
        // doesn't carry the caller's capability yet (capability-on-the-wire is a TODO),
        // so it's accepted but not forwarded.
        let _ = capability;
        matches!(
            self.round_trip(Call::IsCached(request.clone())),
            Ok(Reply::Cached(true))
        )
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        match self.round_trip(Call::Entries) {
            Ok(Reply::Entries(entries)) => entries,
            _ => None,
        }
    }

    fn transport(&self) -> String {
        "ipc · unix domain socket (peercred-verified, same user)".to_string()
    }
}

/// Serve one connection: answer calls until the peer hangs up (or a wire error).
fn handle_connection(kernel: &Kernel, stream: UnixStream) {
    let mut stream = &stream;
    loop {
        let call: Call = match read_message(&mut stream) {
            Ok(call) => call,
            Err(_) => return, // EOF or a malformed frame ends the session
        };
        if write_message(&mut stream, &dispatch(kernel, call)).is_err() {
            return;
        }
    }
}

/// Answer one [`Call`] against the local kernel, reusing its [`Resolver`] impl so
/// the server computes cache status exactly as the embedded path does.
fn dispatch(kernel: &Kernel, call: Call) -> Reply {
    match call {
        Call::Issue(request) => match Resolver::issue(kernel, request) {
            Ok((representation, status)) => Reply::Resolved(representation, status),
            Err(message) => Reply::Error(message),
        },
        // The peer is the owner (peercred-verified in `serve`), so the principal's
        // entitlement is root and the carried capability is already ≤ root —
        // resolving under it *is* the clamp. A future non-root IPC principal would
        // intersect the carried capability with its entitlement here.
        Call::IssueAs(request, capability) => {
            match Resolver::issue_as(kernel, request, &capability) {
                Ok((representation, status)) => Reply::Resolved(representation, status),
                Err(message) => Reply::Error(message),
            }
        }
        Call::IsCached(request) => {
            Reply::Cached(Resolver::is_cached(kernel, &request, &Capability::root()))
        }
        Call::Entries => Reply::Entries(Resolver::entries(kernel)),
        // Trace-over-the-wire: install a collector, resolve, ship the recorded spans
        // back. `_ctx.parent_span` is for a future mount-stitch (re-parenting the
        // subtree); a whole-session `--connect` trace ignores it. The kernel's tracer
        // is process-global, so concurrent traced calls would interleave — fine for
        // the one-shot interactive `trace`.
        Call::IssueTraced(request, capability, _ctx) => {
            let collector = Arc::new(SpanCollector::default());
            Kernel::set_tracer(kernel, collector.clone());
            let reply = match Resolver::issue_as(kernel, request, &capability) {
                Ok((representation, status)) => {
                    Reply::ResolvedTraced(representation, status, collector.take())
                }
                Err(message) => Reply::Error(message),
            };
            Kernel::clear_tracer(kernel);
            reply
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    use ikigai_core::{builtins, ArgRef, Capability, EndpointSpace, Exact, Iri, Verb};

    fn kernel() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:fn:toUpper"), builtins::to_upper()),
        ))
    }

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ikigai-ipc-{}-{}.sock", std::process::id(), name))
    }

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:fn:toUpper").unwrap())
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
            events.iter().any(|e| e.target == "urn:fn:toUpper"),
            "the remote span crossed the wire: {events:?}"
        );

        drop(client);
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
        assert!(entries.iter().any(|e| e.endpoint == "toUpper"));

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unresolved_iri_comes_back_as_an_error() {
        let path = socket_path("err");
        let server = serve_one(&path, kernel());

        let client = connect(&path).unwrap();
        let request = Request::new(Verb::Source, Iri::parse("urn:fn:nope").unwrap());
        assert!(client.issue(request).is_err());

        drop(client);
        server.join().unwrap();
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
}
