//! In-process transport: composes a kernel directly in the host process.
//!
//! This is the simplest "attach to a kernel instance" binding — no network, no
//! IPC. The kernel, its endpoints, and its cache all live in the calling process.
//! Other transports (IPC, QUIC) front the same `Issuer` interface over a wire.

use std::sync::Arc;

use ikigai_core::{
    builtins, ArgSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Kernel,
    MetaRenderer, ReprType, Representation, Result, UriTemplate, Verb,
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

/// `wrap`: surrounds the `text` argument with square brackets. Its argument is
/// deliberately named `text`, not `in`, so the REPL's self-description-driven
/// routing is visible — `source urn:demo:wrap hi` works only because the contract
/// says the input goes to `text`, and it makes pipelines show their work
/// (`source urn:fn:toUpper hi | urn:demo:wrap` → `[HI]`).
fn wrap_impl(inv: &Invocation<'_>) -> Result<Representation> {
    let text = inv.inline_str("text")?;
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        format!("[{text}]").into_bytes(),
    )
    .cacheable())
}

fn wrap() -> FnEndpoint {
    FnEndpoint::new("wrap", wrap_impl).with_description(
        Description::new("wrap")
            .title("Wrap")
            .summary("Surrounds the `text` argument with square brackets.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(ArgSpec::new("text").summary("the text to wrap"))
            .output("text/plain;charset=utf-8"),
    )
}

/// `split`: splits the `in` argument on commas (trimming each) into
/// newline-separated items. It exists so the demo space has a *list producer*
/// for the `..` map operator to iterate — `source urn:demo:split "a, b, c" ..
/// urn:fn:toUpper` runs `toUpper` per item and rejoins (`A`/`B`/`C`). The
/// newline-separated list is the same convention `reverseList` reads.
fn split_impl(inv: &Invocation<'_>) -> Result<Representation> {
    let input = inv.inline_str("in")?;
    let items = input
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        items.into_bytes(),
    )
    .cacheable())
}

fn split() -> FnEndpoint {
    FnEndpoint::new("split", split_impl).with_description(
        Description::new("split")
            .title("Split")
            .summary("Splits the `in` argument on commas into newline-separated items.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(ArgSpec::new("in").summary("comma-separated items"))
            .output("text/plain;charset=utf-8"),
    )
}

/// `greet`: combines two arguments, `greeting` and `name`, into `"{greeting},
/// {name}"`. It's the demo space's *multi-argument* endpoint — `source
/// urn:demo:greet greeting=Hello name=World` names both; with one named, the
/// positional text or a piped value fills the other (`source urn:demo:greet
/// Hello name=World`, or `… | urn:demo:greet name=World`).
fn greet_impl(inv: &Invocation<'_>) -> Result<Representation> {
    let greeting = inv.inline_str("greeting")?;
    let name = inv.inline_str("name")?;
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        format!("{greeting}, {name}").into_bytes(),
    )
    .cacheable())
}

fn greet() -> FnEndpoint {
    FnEndpoint::new("greet", greet_impl).with_description(
        Description::new("greet")
            .title("Greet")
            .summary("Combines `greeting` and `name` into a greeting.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(ArgSpec::new("greeting").summary("the salutation, e.g. Hello"))
            .input(ArgSpec::new("name").summary("who to greet"))
            .output("text/plain;charset=utf-8"),
    )
}

/// Build an embedded kernel pre-bound with the demo endpoints and a
/// self-description renderer (Turtle / plain text / JSON).
///
/// The space deliberately exercises every input style: `toUpper` / `reverseList`
/// read the `in` argument; `wrap` reads a differently-named `text` argument (so
/// the contract-driven routing is visible); `echo` reads a `{message}` binding
/// captured from the IRI; `split` produces a newline list, giving the `..` map
/// operator something to iterate (`split … .. toUpper`); `greet` takes two
/// arguments, exercising `name=value` routing.
///
/// This is the demo space; a real host would compose its own endpoints here.
pub fn kernel() -> Kernel {
    let echo = UriTemplate::parse("urn:demo:echo/{message}").expect("valid template");
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
        .bind(Exact::new("urn:fn:reverseList"), builtins::reverse_list())
        .bind(Exact::new("urn:demo:wrap"), wrap())
        .bind(Exact::new("urn:demo:split"), split())
        .bind(Exact::new("urn:demo:greet"), greet())
        .bind(echo, builtins::echo());
    Kernel::with_meta_renderer(Arc::new(space), Arc::new(CliRenderer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Request};

    #[test]
    fn wrap_routes_the_text_argument() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:wrap").unwrap())
            .with_arg("text", ArgRef::Inline(b"hi".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"[hi]");
    }

    #[test]
    fn split_makes_a_newline_list_for_map() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:split").unwrap())
            .with_arg("in", ArgRef::Inline(b"a, b ,c".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"a\nb\nc");
    }

    #[test]
    fn greet_combines_two_arguments() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:greet").unwrap())
            .with_arg("greeting", ArgRef::Inline(b"Hello".to_vec()))
            .with_arg("name", ArgRef::Inline(b"World".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"Hello, World");
    }
}
