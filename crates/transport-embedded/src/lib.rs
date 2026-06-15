//! In-process transport: composes a kernel directly in the host process.
//!
//! This is the simplest "attach to a kernel instance" binding — no network, no
//! IPC. The kernel, its endpoints, and its cache all live in the calling process.
//! Other transports (IPC, QUIC) front the same `Issuer` interface over a wire.

use std::sync::Arc;

use ikigai_core::{
    builtins, Description, EndpointSpace, Error, Exact, Kernel, MetaRenderer, ReprType,
    Representation, Result, UriTemplate,
};
use ikigai_vocab::TurtleRenderer;

/// The `Meta` renderer used by the CLI kernel.
///
/// Adds an `application/json` projection of the [`Description`] — which the REPL
/// reads to learn an endpoint's parameter contract — on top of the Turtle and
/// plain-text rendering provided by [`TurtleRenderer`]. Going through `Meta` (a
/// resource request) rather than a direct call keeps the lookup transport-agnostic:
/// a future remote frontend learns the contract the same way.
struct CliRenderer;

impl MetaRenderer for CliRenderer {
    fn render(&self, description: &Description, target: &ReprType) -> Result<Representation> {
        if target.media_type == "application/json" {
            let json = serde_json::to_vec(description)
                .map_err(|e| Error::Endpoint(format!("describe as json: {e}")))?;
            return Ok(Representation::new(ReprType::new("application/json"), json));
        }
        TurtleRenderer.render(description, target)
    }
}

/// Build an embedded kernel pre-bound with the built-in pure endpoints and a
/// self-description renderer (Turtle / plain text / JSON).
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
    Kernel::with_meta_renderer(Arc::new(space), Arc::new(CliRenderer))
}
