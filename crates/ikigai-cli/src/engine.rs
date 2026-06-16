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
  source a [input] | b | c   pipeline: feed each stage's output into the next
  describe <iri> [type]      META a resource; `type` defaults to text/turtle
  list                       list the resources bound in the current space
  help                       show this help
  quit                       exit

quoting:
  wrap a word in \"…\" to keep `|` or spaces literal inside an IRI or input;
  \\\" is a literal quote and \\\\ a literal backslash.

try:
  source urn:fn:toUpper resource-oriented computing
  source urn:demo:echo/hello
  source urn:fn:toUpper hello | urn:fn:toUpper
  source urn:fn:toUpper \"a | b\"
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
            "list" | "ls" => Action::Output(Entry {
                input: line.to_string(),
                result: self.run_list(),
            }),
            "source" | "src" => Action::Output(Entry {
                input: line.to_string(),
                result: self.run_pipeline(rest),
            }),
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

    /// Run a `|`-separated pipeline: source the first stage, then feed each
    /// stage's output into the next as its input. The first stage is
    /// `<iri> [input]`; later stages are bare IRIs (their input is the pipe).
    /// A single stage with no `|` is just a plain `source`.
    ///
    /// The spec is split by [`lex_stages`], which honours `"…"` quoting so a
    /// literal `|` (or whitespace) can appear inside an IRI or input. Each stage
    /// is then just a `source`, so routing, the binding-only error, and caching
    /// all come from [`run_source`](Self::run_source). (`..` map and fork/join
    /// build on this same tokenizer.)
    fn run_pipeline(&self, spec: &str) -> Result<String, String> {
        let mut stages = lex_stages(spec)?.into_iter();
        let first = stages.next().expect("lex_stages yields at least one stage");
        let (target, input) = stage_target_input(&first)?;
        let mut value = self.run_source(target, &input)?;
        for words in stages {
            value = self.run_source(piped_stage_target(&words)?, &value)?;
        }
        Ok(value)
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

    /// List the bindings of the kernel's root space (pattern → endpoint), or an
    /// error if the space doesn't support enumeration.
    fn run_list(&self) -> Result<String, String> {
        let entries = self
            .kernel
            .entries()
            .ok_or_else(|| "the current space does not support listing".to_string())?;
        if entries.is_empty() {
            return Ok("(no bindings)".to_string());
        }
        let width = entries
            .iter()
            .map(|entry| entry.pattern.chars().count())
            .max()
            .unwrap_or(0);
        let lines: Vec<String> = entries
            .iter()
            .map(|entry| format!("{:<width$}  → {}", entry.pattern, entry.endpoint))
            .collect();
        Ok(lines.join("\n"))
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

/// Split a pipeline spec into stages, each a list of words.
///
/// Stages are separated by top-level `|`; within a stage, words are split on
/// whitespace. A `"…"` span keeps `|`, whitespace, and anything else literal
/// (and is removed from the resulting word), so an IRI or input can contain
/// them — `"a | b"` is one word holding a literal pipe. Inside a quote, `\"` is
/// a literal quote and `\\` a literal backslash; any other `\x` is left as-is.
///
/// Always yields at least one stage (possibly with zero words, e.g. an empty
/// line or a trailing `|`), so callers can treat the first stage as present and
/// report empty stages themselves.
fn lex_stages(spec: &str) -> Result<Vec<Vec<String>>, String> {
    let mut stages = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false; // started a word? distinguishes "" (a quoted empty) from no word
    let mut chars = spec.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => word.push(e),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err("unterminated `\\` escape in quoted text".into()),
                        },
                        Some('"') => break,
                        Some(ch) => word.push(ch),
                        None => return Err("unterminated `\"` quote".into()),
                    }
                }
            }
            '|' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
                stages.push(std::mem::take(&mut words));
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    stages.push(words);
    Ok(stages)
}

/// The first stage of a pipeline: `<iri> [input]`. The target is the first word;
/// the input is the remaining words rejoined with single spaces (quote a word to
/// keep its own spacing). Empty when no IRI was given.
fn stage_target_input(words: &[String]) -> Result<(&str, String), String> {
    match words.split_first() {
        Some((target, rest)) => Ok((target, rest.join(" "))),
        None => Err("expected an IRI".to_string()),
    }
}

/// A non-first ("piped") stage: its input comes from the pipe, so it must be a
/// bare `<iri>` — exactly one word. Empty (`a | | b`) or carrying a literal input
/// (`a | b extra`) is an error, since that input would have nowhere to go.
fn piped_stage_target(words: &[String]) -> Result<&str, String> {
    match words {
        [] => Err("empty pipeline stage (a stray `|`?)".to_string()),
        [target] => Ok(target),
        [target, ..] => Err(format!(
            "piped stage `{target}` takes its input from the pipe — drop the literal input"
        )),
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
        Representation, Rewrite, UriTemplate,
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
    fn pipeline_chains_output_into_the_next_stage() {
        // `wrap` returns "[input]"; piping toUpper into it proves the value flows
        // and is routed to wrap's argument.
        let wrap = FnEndpoint::new("wrap", |inv: &Invocation<'_>| {
            let s = inv.inline_str("in")?;
            Ok(
                Representation::new(ReprType::new("text/plain"), format!("[{s}]").into_bytes())
                    .cacheable(),
            )
        });
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(Exact::new("urn:test:wrap"), wrap);
        let engine = Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ));
        assert_eq!(
            output(engine.eval("source urn:fn:toUpper hi | urn:test:wrap")).unwrap(),
            "[HI]"
        );
    }

    #[test]
    fn quotes_keep_a_pipe_literal_in_the_input() {
        // Without quoting this would split into two stages; the quotes make
        // `a | b` a single literal input to toUpper.
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper \"a | b\"")).unwrap(),
            "A | B"
        );
    }

    #[test]
    fn quoted_input_preserves_internal_spacing() {
        // Bare words rejoin with single spaces; a quoted word keeps its own.
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper \"a   b\"")).unwrap(),
            "A   B"
        );
    }

    #[test]
    fn piped_stage_with_a_literal_input_is_an_error() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | urn:fn:toUpper x"))
            .unwrap_err();
        assert!(err.contains("from the pipe"), "got: {err}");
    }

    #[test]
    fn a_stray_pipe_is_an_error() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | | urn:fn:toUpper"))
            .unwrap_err();
        assert!(err.contains("empty pipeline stage"), "got: {err}");
    }

    #[test]
    fn lex_stages_splits_and_unquotes() {
        // Two stages; the quoted span holds a literal pipe and collapses to one word.
        let stages = lex_stages("urn:fn:toUpper \"a | b\" | urn:demo:wrap").unwrap();
        assert_eq!(
            stages,
            vec![
                vec!["urn:fn:toUpper".to_string(), "a | b".to_string()],
                vec!["urn:demo:wrap".to_string()],
            ]
        );
    }

    #[test]
    fn lex_stages_processes_escapes() {
        let stages = lex_stages(r#"x "say \"hi\" \\ ok""#).unwrap();
        assert_eq!(
            stages,
            vec![vec!["x".to_string(), r#"say "hi" \ ok"#.to_string()]]
        );
    }

    #[test]
    fn lex_stages_rejects_an_unterminated_quote() {
        assert!(lex_stages("x \"unclosed").is_err());
    }

    #[test]
    fn pipeline_propagates_a_stage_error() {
        assert!(output(builtin_engine().eval("source urn:fn:toUpper hi | urn:fn:nope")).is_err());
    }

    #[test]
    fn pipeline_into_binding_only_endpoint_errors() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | urn:demo:echo/x"))
            .unwrap_err();
        assert!(err.contains("identifier"), "got: {err}");
    }

    #[test]
    fn lists_the_bound_resources() {
        let listing = output(builtin_engine().eval("list")).unwrap();
        assert!(listing.contains("urn:fn:toUpper"));
        assert!(listing.contains("toUpper"));
        assert!(listing.contains("urn:demo:echo/{message}"));
        assert!(listing.contains("echo"));
    }

    #[test]
    fn list_on_a_non_enumerable_space_errors() {
        let inner = Arc::new(EndpointSpace::new().bind(Exact::new("urn:x"), builtins::to_upper()));
        let engine = Engine::new(Kernel::new(Arc::new(Rewrite::new(inner, |_iri| None))));
        assert!(output(engine.eval("list")).is_err());
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
