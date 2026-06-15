//! Renderer-agnostic REPL engine.
//!
//! Parses a command line, issues it against the kernel, and reports the result.
//! It knows nothing about terminals or rendering — the plain line REPL, the
//! `ratatui` TUI, and a future `ratzilla` browser frontend all drive this same
//! engine and present the [`Action`] it returns however suits their medium.
//!
//! `source` is self-description-driven: rather than assuming an `in` argument, it
//! asks the target endpoint for its parameter contract (a `Meta` request rendered
//! as `application/json`) and routes the input to the declared argument — so an
//! endpoint that reads a differently-named argument, or only a grammar binding,
//! is handled correctly. The contract is fetched through `issue`, so this works
//! the same against a remote kernel.

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Description, InputSource, Iri, Kernel, Request, Verb};

/// Help text shown by the `help` command (and the TUI's hint line links to it).
pub const HELP: &str = "\
commands:
  source <iri> [input]       SOURCE a resource; `input` is routed to its declared argument
  describe <iri> [type]      META a resource; `type` defaults to text/turtle
  help                       show this help
  quit                       exit

try:
  source urn:fn:toUpper resource-oriented computing
  source urn:demo:echo/hello
  describe urn:fn:toUpper text/turtle";

/// One evaluated request: the line the user typed and what came back.
pub struct Entry {
    pub input: String,
    pub result: Result<String, String>,
}

/// What the frontend should do with an evaluated line.
pub enum Action {
    /// Display this request/response.
    Output(Entry),
    /// Show [`HELP`].
    Help,
    /// Leave the REPL.
    Quit,
    /// Empty line — do nothing.
    Noop,
}

/// Where a `source` input should go, decided from the target's self-description.
enum ArgChoice {
    /// Route the input to this declared argument name.
    Named(String),
    /// The endpoint's only parameter is a grammar binding — input belongs in the IRI.
    BindingOnly,
    /// Several arguments declared; the REPL can't pick one yet.
    Ambiguous(Vec<String>),
    /// No contract available — assume the conventional `in` argument.
    Fallback,
}

/// Holds the kernel and turns input lines into [`Action`]s.
pub struct Engine {
    kernel: Kernel,
}

impl Engine {
    pub fn new(kernel: Kernel) -> Self {
        Self { kernel }
    }

    /// Evaluate one input line.
    pub fn eval(&self, line: &str) -> Action {
        let line = line.trim();
        if line.is_empty() {
            return Action::Noop;
        }
        let (cmd, rest) = split_first_word(line);
        match cmd {
            "quit" | "exit" => Action::Quit,
            "help" | "?" => Action::Help,
            "source" | "src" => {
                let (target, input) = split_first_word(rest);
                Action::Output(Entry {
                    input: line.to_string(),
                    result: self.run_source(target, input),
                })
            }
            "describe" | "desc" => {
                let (target, ty) = split_first_word(rest);
                let ty = if ty.is_empty() { "text/turtle" } else { ty };
                Action::Output(Entry {
                    input: line.to_string(),
                    result: self.run_meta(target, ty),
                })
            }
            other => Action::Output(Entry {
                input: line.to_string(),
                result: Err(format!("unknown command `{other}` (try `help`)")),
            }),
        }
    }

    /// `SOURCE` a resource, routing `input` to the endpoint's declared argument.
    fn run_source(&self, target: &str, input: &str) -> Result<String, String> {
        let iri = parse_target(target)?;
        let mut request = Request::new(Verb::Source, iri.clone());
        if !input.is_empty() {
            let value = ArgRef::Inline(input.as_bytes().to_vec());
            match self.argument_choice(&iri) {
                ArgChoice::Named(name) => request = request.with_arg(name, value),
                ArgChoice::Fallback => request = request.with_arg("in", value),
                ArgChoice::BindingOnly => {
                    return Err(format!(
                        "`{}` takes no by-value argument — its parameter is captured from the \
                         identifier, so put the value in the IRI",
                        iri.as_str()
                    ));
                }
                ArgChoice::Ambiguous(names) => {
                    return Err(format!(
                        "`{}` accepts multiple arguments ({}); the REPL can't pick one yet",
                        iri.as_str(),
                        names.join(", ")
                    ));
                }
            }
        }
        self.run(request)
    }

    /// `META` a resource, rendered to `ty`.
    fn run_meta(&self, target: &str, ty: &str) -> Result<String, String> {
        let iri = parse_target(target)?;
        let request =
            Request::new(Verb::Meta, iri).with_arg("as", ArgRef::Inline(ty.as_bytes().to_vec()));
        self.run(request)
    }

    /// Decide where a `source` input should go from the target's contract.
    fn argument_choice(&self, iri: &Iri) -> ArgChoice {
        match self.describe_struct(iri) {
            Some(description) => argument_for(&description),
            None => ArgChoice::Fallback,
        }
    }

    /// Fetch a target's structured self-description via a `Meta` request rendered
    /// as `application/json`. `None` if it doesn't resolve or isn't JSON-renderable.
    fn describe_struct(&self, iri: &Iri) -> Option<Description> {
        let request = Request::new(Verb::Meta, iri.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
        let representation = block_on(self.kernel.issue(request, &Capability::root())).ok()?;
        serde_json::from_slice(&representation.bytes).ok()
    }

    /// Issue a request and decode the representation as UTF-8 text.
    fn run(&self, request: Request) -> Result<String, String> {
        let representation =
            block_on(self.kernel.issue(request, &Capability::root())).map_err(|e| e.to_string())?;
        String::from_utf8(representation.bytes).map_err(|e| e.to_string())
    }
}

/// Choose the argument to route input to, given a target's declared inputs.
fn argument_for(description: &Description) -> ArgChoice {
    if description.inputs.is_empty() {
        // Nothing declared — assume the conventional `in`, never worse than before.
        return ArgChoice::Fallback;
    }
    let arguments: Vec<String> = description
        .inputs
        .iter()
        .filter(|input| input.source == InputSource::Argument)
        .map(|input| input.name.clone())
        .collect();
    match arguments.len() {
        0 => ArgChoice::BindingOnly,
        1 => ArgChoice::Named(arguments.into_iter().next().expect("len == 1")),
        _ => ArgChoice::Ambiguous(arguments),
    }
}

fn parse_target(target: &str) -> Result<Iri, String> {
    if target.is_empty() {
        return Err("expected an IRI".to_string());
    }
    Iri::parse(target).map_err(|e| e.to_string())
}

/// Split off the first whitespace-delimited token; trim the remainder.
fn split_first_word(s: &str) -> (&str, &str) {
    match s.split_once(char::is_whitespace) {
        Some((head, tail)) => (head, tail.trim()),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ikigai_core::{
        builtins, ArgSpec, EndpointSpace, Exact, FnEndpoint, Invocation, MetaRenderer, ReprType,
        Representation, UriTemplate,
    };

    /// A minimal renderer that emits the description as JSON — what the embedded
    /// transport's renderer does, isolated here so engine tests don't depend on it.
    struct JsonRenderer;
    impl MetaRenderer for JsonRenderer {
        fn render(
            &self,
            description: &Description,
            _target: &ReprType,
        ) -> ikigai_core::Result<Representation> {
            Ok(Representation::new(
                ReprType::new("application/json"),
                serde_json::to_vec(description).expect("serialize description"),
            ))
        }
    }

    fn builtin_engine() -> Engine {
        let echo = UriTemplate::parse("urn:demo:echo/{message}").expect("valid template");
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(echo, builtins::echo());
        Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ))
    }

    fn output(action: Action) -> Result<String, String> {
        match action {
            Action::Output(entry) => entry.result,
            _ => panic!("expected Action::Output"),
        }
    }

    #[test]
    fn sources_an_inline_arg() {
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper hi")).unwrap(),
            "HI"
        );
    }

    #[test]
    fn resolves_a_template_binding() {
        assert_eq!(
            output(builtin_engine().eval("source urn:demo:echo/hello")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn passing_a_value_to_a_binding_endpoint_is_a_helpful_error() {
        let err = output(builtin_engine().eval("source urn:demo:echo/hi extra")).unwrap_err();
        assert!(err.contains("identifier"), "got: {err}");
    }

    #[test]
    fn routes_input_to_the_declared_argument_name() {
        // `shout` reads a `text` argument, not `in`. Contract-driven routing must
        // send the input there; a hardcoded `in` would make this fail.
        let shout = FnEndpoint::new("shout", |inv: &Invocation<'_>| {
            let text = inv.inline_str("text")?;
            Ok(Representation::new(
                ReprType::new("text/plain"),
                text.to_uppercase().into_bytes(),
            )
            .cacheable())
        })
        .with_description(
            Description::new("shout")
                .verb(Verb::Source)
                .verb(Verb::Meta)
                .input(ArgSpec::new("text").summary("the text to shout"))
                .output("text/plain"),
        );
        let space = EndpointSpace::new().bind(Exact::new("urn:fn:shout"), shout);
        let engine = Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ));
        assert_eq!(output(engine.eval("source urn:fn:shout hi")).unwrap(), "HI");
    }

    #[test]
    fn unknown_command_is_an_error() {
        assert!(output(builtin_engine().eval("frobnicate x")).is_err());
    }

    #[test]
    fn unresolved_iri_is_an_error() {
        assert!(output(builtin_engine().eval("source urn:fn:nope x")).is_err());
    }

    #[test]
    fn control_words_map_to_actions() {
        assert!(matches!(builtin_engine().eval("quit"), Action::Quit));
        assert!(matches!(builtin_engine().eval("help"), Action::Help));
        assert!(matches!(builtin_engine().eval("   "), Action::Noop));
    }

    #[test]
    fn argument_for_distinguishes_the_cases() {
        let arg = Description::new("toUpper").input(ArgSpec::new("in"));
        assert!(matches!(argument_for(&arg), ArgChoice::Named(n) if n == "in"));

        let binding = Description::new("echo").input(ArgSpec::new("message").binding());
        assert!(matches!(argument_for(&binding), ArgChoice::BindingOnly));

        let many = Description::new("x")
            .input(ArgSpec::new("a"))
            .input(ArgSpec::new("b"));
        assert!(matches!(argument_for(&many), ArgChoice::Ambiguous(_)));

        let undeclared = Description::new("x");
        assert!(matches!(argument_for(&undeclared), ArgChoice::Fallback));
    }
}
