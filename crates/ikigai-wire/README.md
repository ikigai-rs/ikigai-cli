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
changes (v2 added `Call::IssueAs` for capability-on-the-wire; v7 made the error taxonomy
cross as `Reply::ErrorTyped(WireError)`).

## Versions

`PROTOCOL_VERSION` is **10** and `MIN_PROTOCOL_VERSION` is **7**: a v10 peer speaks 7 to 10,
and each connection is served at the version it negotiated. A server answers an accepted
hello with the PEER's version (`answer_to`); QUIC negotiates by ALPN (`alpns()`, newest
first). Each revision since v7 is backward compatible, downgraded per peer:

- **v8** appended `WireError::Conflict` (variant 8; `Reply::ErrorTyped(WireError::Conflict("x"))`
  encodes as `05 08 01 78`); a v7 peer gets the `Endpoint("conflict: …")` it always received
  (`Reply::for_peer`).
- **v9** appended the failure classes (`DepthExceeded` … `Unsupported`, variants 9 to 13) and
  `Call::IssueWith`, the run's context; an older peer gets `Endpoint(display)` and the plain
  call (`Call::for_peer`).
- **v10** streams a body (ledger #2242): see below. An older peer never sends a head, so it
  never meets a frame, and gets the collected answer, or a typed `OverBudget` for one past
  a frame (`encode_reply_for_peer`).

The full hello design is `docs/wire-hello-design.md` in the ikigai-cli repository.

## Messages

```rust
pub enum Call {
    Issue(Request),
    IsCached(Request),
    Entries,
    IssueAs(Request, Capability), // resolve under an explicit capability
    IssueTraced(Request, Capability, TraceContext),
    IssueWith(Request, Capability, IssueWith), // v9: the run's context
}

pub enum Reply {
    Resolved(Representation, CacheStatus),
    Cached(bool),
    Entries(Option<Vec<SpaceEntry>>),
    Error(String), // decodable, no longer sent: ErrorTyped replaced it in v7
    ResolvedTraced(Representation, CacheStatus, Vec<TraceEvent>),
    ErrorTyped(WireError), // the error taxonomy, variant for variant
}
```

Every enum is append-only: the variant ORDER is the postcard contract.

## Streamed bodies (v10)

A streamed exchange is a HEAD frame, then CHUNK frames of at most 256 KiB, then END or a
typed ABORT. A stream that stops without END (EOF, a reset, a FIN) is a failed body, never a
shorter one; past a bound the stream ends in an ABORT carrying `OverBudget`.

The frames are appended to the `Call` and `Reply` discriminant spaces, the same tags both
ways, and each encodes byte for byte as the matching enum variant would:

| tag | call direction | reply direction | payload after the tag |
|----:|----------------|-----------------|-----------------------|
| 0–5 | `Call` | `Reply` | unchanged |
| 6 | `CallHead` (request, capability, run context, optional body head) | `ReplyHead` (the representation without its bytes, cache status, length hint) | postcard |
| 7 | chunk | chunk | varint length, then the bytes |
| 8 | end | end | nothing |
| 9 | abort | abort | a `WireError` |

The Rust enums are untouched (adding a variant to an exhaustive public enum breaks every
`match` on it); the frames are the new types `CallFrame`, `ReplyFrame` and `BodyFrame`, with
`BodyReader` (a sync `Read` over a body), `BodyState` (the same rules with no I/O, for an
async transport) and `encode_reply_for_peer`.

The answer to a head is one plain `Reply` frame (a failure before the first byte, or a
traced call, which is collected) or a `ReplyHead`, chunks and END or ABORT. With a body of
its own (`CallHead::body`), the caller sends its chunks and END or ABORT after the head.

`tests/vectors/stream_frames.json` holds the bytes of every frame (an ABORT per failure
class) and whole exchanges, including the collected answer a v9 and a v8 peer get. A test
fails if the file differs from what the codec writes; the faces pin it verbatim.

## Framing

| function | for transports that… |
|----------|----------------------|
| `write_message` / `read_message` | need length prefixing: `u32` big-endian length, then the payload (the IPC socket) |
| `encode` / `decode` | frame messages themselves: one self-contained byte slice per call (one QUIC stream per call) |
| `write_frame` / `read_tagged_frame` | carry stream frames: the IPC socket's framing, and on QUIC a stream that opens with the magic `IKWS` |

`MAX_FRAME` (64 MiB) caps one frame, refused before allocating; a chunk frame is capped at
`MAX_CHUNK` (256 KiB). Since v10 the cap is per frame, and a run's byte budget governs a
streamed body's total.

## License

MIT OR Apache-2.0.
