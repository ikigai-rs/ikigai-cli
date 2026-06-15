//! Renderer-agnostic REPL engine.
//!
//! Parses a command line, issues it against the kernel, and reports the result.
//! It knows nothing about terminals or rendering — the plain line REPL, the
//! `ratatui` TUI, and a future `ratzilla` browser frontend all drive this same
//! engine and present the [`Action`] it returns however suits their medium.

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

/// Help text shown by the `help` command (and the TUI's hint line links to it).
pub const HELP: &str = "\
commands:
  source <iri> [input]       SOURCE a resource; `input` is passed as the `in` arg
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
                    result: self.issue(Verb::Source, target, "in", input),
                })
            }
            "describe" | "desc" => {
                let (target, ty) = split_first_word(rest);
                let ty = if ty.is_empty() { "text/turtle" } else { ty };
                Action::Output(Entry {
                    input: line.to_string(),
                    result: self.issue(Verb::Meta, target, "as", ty),
                })
            }
            other => Action::Output(Entry {
                input: line.to_string(),
                result: Err(format!("unknown command `{other}` (try `help`)")),
            }),
        }
    }

    /// Issue one request and decode the representation as UTF-8 text.
    fn issue(&self, verb: Verb, target: &str, arg: &str, value: &str) -> Result<String, String> {
        if target.is_empty() {
            return Err("expected an IRI".to_string());
        }
        let iri = Iri::parse(target).map_err(|e| e.to_string())?;
        let mut request = Request::new(verb, iri);
        if !value.is_empty() {
            request = request.with_arg(arg, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        let representation =
            block_on(self.kernel.issue(request, &Capability::root())).map_err(|e| e.to_string())?;
        String::from_utf8(representation.bytes).map_err(|e| e.to_string())
    }
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

    use ikigai_core::{builtins, EndpointSpace, Exact, UriTemplate};

    fn engine() -> Engine {
        let echo = UriTemplate::parse("urn:demo:echo/{message}").expect("valid template");
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(echo, builtins::echo());
        Engine::new(Kernel::new(Arc::new(space)))
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
            output(engine().eval("source urn:fn:toUpper hi")).unwrap(),
            "HI"
        );
    }

    #[test]
    fn resolves_a_template_binding() {
        assert_eq!(
            output(engine().eval("source urn:demo:echo/hello")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn unknown_command_is_an_error() {
        assert!(output(engine().eval("frobnicate x")).is_err());
    }

    #[test]
    fn unresolved_iri_is_an_error() {
        assert!(output(engine().eval("source urn:fn:nope x")).is_err());
    }

    #[test]
    fn control_words_map_to_actions() {
        assert!(matches!(engine().eval("quit"), Action::Quit));
        assert!(matches!(engine().eval("help"), Action::Help));
        assert!(matches!(engine().eval("   "), Action::Noop));
    }
}
