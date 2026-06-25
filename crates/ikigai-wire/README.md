# ikigai-wire

The **on-wire protocol** shared by the [ikigai](https://crates.io/crates/ikigai-core)
remote transports. `Call`/`Reply` messages mirror the
[ikigai-resolve](https://crates.io/crates/ikigai-resolve) `Resolver` surface and are
serialized with [postcard](https://postcard.jamesmunns.com), so a REPL client and a
kernel server speak the same compact protocol whether they meet over a Unix socket
([ikigai-ipc](https://crates.io/crates/ikigai-ipc)), QUIC
([ikigai-quic](https://crates.io/crates/ikigai-quic)), or a browser network demo.

The codec is **non-self-describing** — client and server ship together at the same
version — and the `ikigai-core` types already derive `Serialize`/`Deserialize`, so
nothing here re-describes them. `PROTOCOL_VERSION` is bumped when the on-wire shape
changes incompatibly (v2 added `Call::IssueAs` for capability-on-the-wire).

## Messages

```rust
pub enum Call {
    Issue(Request),
    IsCached(Request),
    Entries,
    IssueAs(Request, Capability), // resolve under an explicit capability
}

pub enum Reply {
    Resolved(Representation, CacheStatus),
    Cached(bool),
    Entries(Option<Vec<SpaceEntry>>),
    Error(String), // answers any call: a failed resolution or a transport error
}
```

`IssueAs` is appended after the original variants so the postcard discriminants of
`Issue`/`IsCached`/`Entries` are unchanged; a server clamps the carried capability
to the principal the channel authenticated.

## Framing

Two framing strategies share one postcard codec:

| function | for transports that… |
|----------|----------------------|
| `write_message` / `read_message` | need length prefixing — `u32` big-endian length, then the payload (the IPC socket) |
| `encode` / `decode` | frame messages themselves — one self-contained byte slice per call (one QUIC stream per call) |

`read_message` rejects a frame larger than a 64 MiB cap before allocating for it,
guarding against a bogus length header.

## License

MIT OR Apache-2.0.
