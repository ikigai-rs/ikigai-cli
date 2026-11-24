# Retry exhaustion across host boundaries (ledger #3424)

On 2026-11-11, regression tests added before the implementation change reproduced both
claims on the worker branch's original main revision:

- `cargo test -p ikigai-wire gave_up_round_trip -- --nocapture`: the assertion of
  `Error::class() == FailureClass::Transient` failed with left `Unknown`.
- `cargo test -p ikigai-web gave_up_is_service -- --nocapture`: the assertion of
  `error_status(GaveUp { attempts: 9, elapsed: 120s, detail: "down" }) == 503`
  failed with left `500`.

The wire test also requires the attempt count, exact elapsed Duration (including
nanoseconds), and detail to survive encode/decode and conversion back to core.

Wire v11 appends GaveUp at tag 14. Negotiated v7–v10 replies and stream aborts use the
existing per-peer downgrade: Endpoint(core display), retaining the older Unknown class.
No crate version changes. The HTTP door returns 503. GaveUp has no retry delay, so the
existing delay-based header logic emits no Retry-After; elapsed time is not a delay.

## Other error matches checked

A source search across this workspace for Error variants, Timeout/Unavailable matches,
class and transience helpers found no other classification fallthrough needing a change:

- The CLI's front.rs delegates HTTP status and JSON error fields to ikigai-web and
  reconstructs typed wire errors through core's conversion.
- main.rs's dial_error maps std::io::ErrorKind, not core errors. The CLI's other
  Error variant matches are test assertions.
- Embedded connect retries delegate to ikigai-throttle's Retry, which uses core's
  failure class. Its retry documentation now includes GaveUp among transient errors.
- Embedded store.rs handles a specific store-lock Unavailable refusal, not a general
  transient classification. The HTTP body-reader error match preserves errors that
  its bounded reader can produce (OverBudget, Timeout); that reader cannot emit GaveUp.
- IPC, QUIC and P2P typed replies use per-peer downgrade before encoding. IPC and QUIC
  server stream aborts also downgrade; client upload aborts construct only Endpoint or
  InvalidArgument, so cannot leak the new tag to an older peer. P2P remains capped at
  v9 because it cannot carry stream frames, and therefore receives the old behavior.

Regression coverage includes real QUIC negotiation at v10 and v11, wire downgrade
checks for every supported older version, wire and stream byte vectors, and the HTTP
503/no-Retry-After response over a socket. These are protocol and socket tests;
no browser or assistive technology evaluation was performed.
