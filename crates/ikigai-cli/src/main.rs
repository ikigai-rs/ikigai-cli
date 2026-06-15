//! ikigai — resource-resolution REPL.
//!
//! Attaches to a kernel instance over a pluggable transport. Today the only wired
//! transport is `embedded` (the kernel runs in this process); IPC and QUIC will
//! front the same interface over a wire. Each line you type is a request issued
//! against the kernel's address space; the response is its representation's bytes.

#[cfg(feature = "embedded")]
fn main() {
    repl::run(transport_embedded::kernel());
}

#[cfg(not(feature = "embedded"))]
fn main() {
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}

#[cfg(feature = "embedded")]
mod repl {
    use std::io::{self, Write};

    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

    const HELP: &str = "\
commands:
  source <iri> [input]       SOURCE a resource; `input` is passed as the `in` arg
  describe <iri> [type]      META a resource; `type` defaults to text/turtle
  help                       show this help
  quit                       exit

try:
  source urn:fn:toUpper resource-oriented computing
  source urn:demo:echo/hello
  describe urn:fn:toUpper text/turtle";

    /// Read-eval-print loop over the kernel until EOF or `quit`.
    pub fn run(kernel: Kernel) {
        println!(
            "ikigai {} — embedded REPL. Type `help`, or `quit` to exit.",
            env!("CARGO_PKG_VERSION")
        );
        let stdin = io::stdin();
        let mut line = String::new();
        loop {
            print!("ikigai> ");
            io::stdout().flush().ok();
            line.clear();
            if stdin.read_line(&mut line).unwrap_or(0) == 0 {
                println!();
                break; // EOF (Ctrl-D)
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match dispatch(&kernel, trimmed) {
                Ok(Some(out)) => println!("{out}"),
                Ok(None) => break, // quit
                Err(e) => eprintln!("error: {e}"),
            }
        }
    }

    /// Returns `Ok(Some(output))` to print, `Ok(None)` to quit, `Err` to report.
    fn dispatch(kernel: &Kernel, line: &str) -> Result<Option<String>, String> {
        let (cmd, rest) = split_first_word(line);
        match cmd {
            "quit" | "exit" => Ok(None),
            "help" | "?" => Ok(Some(HELP.to_string())),
            "source" | "src" => {
                let (target, input) = split_first_word(rest);
                issue(kernel, Verb::Source, target, "in", input).map(Some)
            }
            "describe" | "desc" => {
                let (target, ty) = split_first_word(rest);
                let ty = if ty.is_empty() { "text/turtle" } else { ty };
                issue(kernel, Verb::Meta, target, "as", ty).map(Some)
            }
            other => Err(format!("unknown command `{other}` (try `help`)")),
        }
    }

    /// Issue one request and decode the representation as UTF-8 text.
    fn issue(
        kernel: &Kernel,
        verb: Verb,
        target: &str,
        arg: &str,
        value: &str,
    ) -> Result<String, String> {
        if target.is_empty() {
            return Err("expected an IRI".to_string());
        }
        let iri = Iri::parse(target).map_err(|e| e.to_string())?;
        let mut request = Request::new(verb, iri);
        if !value.is_empty() {
            request = request.with_arg(arg, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        let representation =
            block_on(kernel.issue(request, &Capability::root())).map_err(|e| e.to_string())?;
        String::from_utf8(representation.bytes).map_err(|e| e.to_string())
    }

    /// Split off the first whitespace-delimited token; trim the remainder.
    fn split_first_word(s: &str) -> (&str, &str) {
        match s.split_once(char::is_whitespace) {
            Some((head, tail)) => (head, tail.trim()),
            None => (s, ""),
        }
    }
}
