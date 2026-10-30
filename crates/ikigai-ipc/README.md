# ikigai-ipc

The **IPC transport** for [ikigai](https://crates.io/crates/ikigai-core): a
`Resolver` over a Unix domain socket, so the `ikigai` REPL can drive a kernel
running in another local process exactly as it drives an in-process one. It
implements the [ikigai-resolve](https://crates.io/crates/ikigai-resolve) `Resolver`
seam and speaks the framed [ikigai-wire](https://crates.io/crates/ikigai-wire)
`Call`/`Reply` protocol, so the engine can't tell a socket-attached kernel from the
embedded one.

```rust
// server
ikigai_ipc::serve(kernel, &path)?;        // runs until the listener itself dies (EMFILE is waited out)

// …or bind first, so the door is ready (listening, 0600) before anything announces it
let listener = ikigai_ipc::bind(&path)?;
eprintln!("serving on {}", path.display());
ikigai_ipc::serve_on(kernel, listener)?;  // serve_shared / serve_shared_on take an Arc<Kernel>

// client — an IpcResolver the engine drives like any other Resolver
let resolver = ikigai_ipc::connect(&path)?;
let (representation, status) = resolver.issue(request)?;
```

## Security is the OS's, not a certificate's

No CA, no TLS — the operating system already authenticates a local peer:

- **`default_socket_path()`** places the socket in a `0700` per-user directory
  (`$XDG_RUNTIME_DIR`, else `$TMPDIR`/`/tmp` plus the uid), and the socket itself is
  `0600`, so no other user can reach it.
- **`serve`** additionally checks each peer's **kernel-verified UID** (`SO_PEERCRED`
  on Linux, `getpeereid` on macOS/BSD, read through the `nix` crate) and refuses any
  connection that isn't the server's own user — defense in depth over the directory mode.

Because the peer is the owner, a `cap`-attenuated `--connect` session carries its
capability over `Call::IssueAs`; the server resolves under it (already ≤ root), so
attenuation behaves over IPC exactly as it does for the embedded kernel.

**A UID names the owner, not a party.** The plain `serve` family admits its peer as
`Admission::owner()`: root, and NO principal. A name the client supplies never reaches an
endpoint: a `principal` argument is removed, and so is a carried capability's
`urn:cap:principal:<iri>` (under a root ceiling core's `clamp` would keep it, since root may
act as anyone). `serve_shared_on_admitted` serves under `Admission::bounded(ceiling,
principal)` instead: every call is clamped to the ceiling, and the principal, if given, is
minted into every call and stamped as the argument. ⚠ A door that admits only its own UID
constrains a cooperating or confined client this way, never a same-user process that dials an
owner socket instead: for a real bound, run the client as another account (below).

## Admitting another account, bounded (ledger #2139)

`serve_shared_on_admissions` admits each connection by its peer's kernel-verified UID, through
an `Admissions` table:

- **the door's own UID** is the owner (`Admission::owner()`), as before, unless the table
  names that UID too;
- **a UID the table names** gets its admission, typically `Admission::bounded(grant,
  principal)`: every call is clamped to the grant and names the principal;
- **any other UID**, and a peer whose UID cannot be read, is closed at accept, before its hello
  is read, and the door logs the UID (at the 1st, 2nd, 4th, 8th, … refusal of that UID, so a
  client dialing in a loop cannot flood the log). Nothing the peer sent is read, so nothing it
  sent is logged.

Such a door binds with **`bind_shared(path, gid)`**, which sets exactly this: the socket's
group is `gid` and its mode is `0660`. It does not change the directory. It checks the
socket's parent directory first and refuses to bind unless the directory is owned by the
door's user, has group `gid`, is searchable by that group, is not writable by it, and grants
other users nothing (`0710` or `0750` with group `gid`). So even on a system that ignored a
socket file's mode on `connect`, nobody outside the group could reach the socket: the door
refuses to start in a directory that would make the socket connectable by every user. The
per-user default directories (`$XDG_RUNTIME_DIR`, macOS's per-user `$TMPDIR`) are `0700` and
cannot be shared, so a shared door names its own socket path, for example:

```sh
sudo mkdir /var/run/ikigai && sudo chown brian:ikigai /var/run/ikigai && sudo chmod 0710 /var/run/ikigai
```

Every directory above it must let the group's members search it as well.

### The trust model, plainly

- **Another account is bounded.** The operating system reports its UID,
  the door maps that UID to a grant and a principal, and it holds no way to reach an owner
  door: the owner's sockets are `0600` in `0700` directories, and every owner door refuses its
  UID. This is what makes "a node on the same machine" boundable: run the node as its own
  account, name that account in the table, and it gets its grant and nothing more.
- **The door's own user is the owner, and that cannot change.** To the
  operating system it IS the same principal: it can read the owner's files, dial the owner's
  other sockets, ptrace the door, or edit the table that bounds it. A table entry naming the
  door's own UID bounds only the clients that dial THIS socket, which is a cooperative bound,
  not a security one. The `ikigai` host refuses to configure it for that reason.
- **The table must be one the bounded account cannot write.** The `ikigai` host checks the
  grants file, every directory above it and every link on the way, and refuses to start if the
  account could rewrite or replace any of them.
- **Root is never bounded** (it can do all of the above), and a UID of 0 is refused as an
  account.

Each accepted connection is served on its own thread, answering calls against the
kernel's own `Resolver` impl until the peer hangs up — so cache status is computed
exactly as the embedded path computes it, and two clients sharing a server see each
other's cached results.

## One server per socket, and bounded connections

`bind` never takes a socket from a live server. It dials the path first: a server that
answers is still serving, and `bind` refuses with `AddrInUse`, naming the path and that
server's process id. Only a socket nobody listens on is removed, and a file that is not a
socket is never removed. The dial, the removal and the bind run under an `flock` on
`<path>.lock` (held only for those steps), so two servers starting at once cannot each
remove the other's socket. Before this, a second `ikigai serve` on the same path unlinked
the first one's socket, and the first kept running with no error and no way to reach it.

A door also bounds its connections (`Limits`, `serve_shared_on_with`; the other `serve_*`
functions use the defaults):

| bound | default | past it |
| --- | --- | --- |
| connections at once | 128 (`MAX_CONNECTIONS`) | the first call is answered with a typed `Unavailable` naming the cap |
| a new connection's hello | 10 s (`HELLO_TIMEOUT`) | the connection is closed |
| silence between calls, or a stalled reply write | 10 min (`IDLE_TIMEOUT`) | the connection is closed |

128 leaves half of launchd's default 256-descriptor soft limit for the rest of the host,
and is far above any fan-in seen in use. Ten minutes matches the QUIC door's
`quic.max_connection_age`. An `IpcResolver` heals across an idle close: its next call meets
the closed socket on its write, redials, and replays. A client that does not redial sees
its next call fail.

`serve` gives no readiness signal: it does not return while it serves, and the socket is
bound somewhere inside it. A host that prints a banner, or a test that dials the door, calls
`bind` (which returns a listening socket) and then `serve_on`; a connection made in between
waits in the backlog. `serve_shared` and `serve_shared_on` take the kernel as an
`Arc<Kernel>`, so one kernel, and one cache, can sit behind this door and another face (an
HTTP door, a file watcher) at once, as `ikigai_quic::serve_shared_on` does for QUIC.

## Two deadlines: patience for work, a bound for self-description

`DEFAULT_TIMEOUT` is **five minutes**, because what a socket deadline bounds is SILENCE
from the server and a resolution is silent while it works — a 70B model loads ~40GB
before its first token, and a bound that cannot tell *hung* from *busy* reports the
wrong thing confidently.

Nothing is ever working during a **self-description**, so those calls run under
`DEFAULT_DESCRIBE_TIMEOUT` (**30s**, `describe.timeout` in the config home) instead: a
`Call::Entries`, and a `Meta` issue — the one `MountedRemote`'s forwarding endpoint
sends to read a peer's contract. Without that split, one silent peer took out
`urn:kernel:catalog` and `urn:kernel:actions` for every kernel that could reach it,
and the manifold is the resource an agent must read before it can do anything at all.

⚠ Enumeration is **transitive**, so the bound is per hop and per-hop bounds do not
compose: three kernels deep, the outer hop cuts off at exactly the moment the inner hop
would have answered with its own degraded catalog. A deep federation raises
`describe.timeout` at the outermost kernel. Carrying a decrementing *budget* on the wire
is the real answer and is a protocol change. Until then the `ikigai` binary orders the
common two-hop case by role: a process that SERVES a door gives its own mounts two thirds of
`describe.timeout` (20 s by default), so when a client asks a host about a silent peer, the
host's deadline fires inside the client's and its answer names the peer
(`the peer at quic://… did not describe itself within 20s`) instead of the client blaming
the host (ledger #1288).

**Unix only** — the crate is empty on other targets (the `ipc` feature is gated out).

## License

MIT OR Apache-2.0.
