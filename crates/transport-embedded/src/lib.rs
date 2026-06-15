//! In-process transport: composes a kernel directly in the host process.
//!
//! This is the simplest "attach to a kernel instance" binding — no network, no
//! IPC. The kernel, its endpoints, and its cache all live in the calling process.
//! Other transports (IPC, QUIC) front the same `Issuer` interface over a wire.

use std::sync::Arc;

use ikigai_core::{builtins, EndpointSpace, Exact, Kernel, UriTemplate};
use ikigai_vocab::TurtleRenderer;

/// Build an embedded kernel pre-bound with the built-in pure endpoints and an
/// RDF self-description renderer (so `Meta` requests resolve to Turtle/text).
///
/// `toUpper` / `reverseList` take their input from the `in` argument; `echo` is
/// bound to a URI template and returns the `{message}` segment captured during
/// resolution — so the space exercises both inline args and grammar bindings.
///
/// This is the demo space; a real host would compose its own endpoints here.
pub fn kernel() -> Kernel {
    let echo = UriTemplate::parse("urn:demo:echo/{message}").expect("valid template");
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
        .bind(Exact::new("urn:fn:reverseList"), builtins::reverse_list())
        .bind(echo, builtins::echo());
    Kernel::with_meta_renderer(Arc::new(space), Arc::new(TurtleRenderer))
}
