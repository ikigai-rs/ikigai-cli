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
ikigai_ipc::serve(kernel, &path)?;        // runs until an unrecoverable accept error

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
  on Linux, `getpeereid` on macOS/BSD) and refuses any connection that isn't the
  server's own user — defense in depth over the directory mode.

Because the peer is the owner, a `cap`-attenuated `--connect` session carries its
capability over `Call::IssueAs`; the server resolves under it (already ≤ root), so
attenuation behaves over IPC exactly as it does for the embedded kernel.

Each accepted connection is served on its own thread, answering calls against the
kernel's own `Resolver` impl until the peer hangs up — so cache status is computed
exactly as the embedded path computes it, and two clients sharing a server see each
other's cached results.

**Unix only** — the crate is empty on other targets (the `ipc` feature is gated out).

## License

MIT OR Apache-2.0.
