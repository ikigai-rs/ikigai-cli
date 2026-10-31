//! Running a `.iki` script (ledger #2649): from the shell, `ikigai <file>.iki [key=value …]`
//! or `--script <file>` (the shebang form), and from either REPL, `script <iri> [key=value …]`.
//!
//! The script format is the engine's ([`ikigai_engine::script`], ledger #2485): REPL lines in
//! file order, `#` comments (so a `#!` shebang is one), `# @param <name> [= <default>]`
//! declarations used as `{name}`, and stop at the first failing line. [`run`] parses and binds
//! with the engine's [`Script`] and then evaluates each line itself rather than calling
//! [`ikigai_engine::Engine::run_script`], so each answer is shown as its line finishes,
//! with that line's fan-out and contract notes, instead of all at once at the end. It stops where
//! `run_script` stops: at the first line whose answer is an error, or at `quit`.
//!
//! The REPL command is `script`, not `run`: the engine still reads `run` as the old name of
//! `execute` (ledger #104), so `run urn:file:plan.ttl` keeps running a stored plan.

use std::collections::BTreeMap;

use ikigai_engine::{Action, Script, ScriptError};

use crate::session::Session;

/// The REPL command that runs a stored script.
pub const COMMAND: &str = "script";

/// What the REPL's `script` command does, for its usage line.
pub const USAGE: &str = "usage: `script <iri> [key=value …]` runs the `.iki` script stored at \
                         <iri>, one line at a time, stopping at the first that fails";

/// A REPL `script` line: the script's IRI and the parameters it was given.
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub iri: String,
    pub params: BTreeMap<String, String>,
}

/// Whether `line` is the REPL's `script` command: `None` when it is not (the engine answers
/// it), else the invocation or why it is malformed.
pub fn command(line: &str) -> Option<Result<Invocation, String>> {
    let line = line.trim();
    let rest = match line.split_once(char::is_whitespace) {
        Some((COMMAND, rest)) => rest,
        None if line == COMMAND => "",
        _ => return None,
    };
    Some(invocation(rest))
}

fn invocation(rest: &str) -> Result<Invocation, String> {
    let mut words = words(rest)?.into_iter();
    let iri = words.next().ok_or_else(|| USAGE.to_string())?;
    if iri.contains('=') && !iri.contains(':') {
        return Err(format!(
            "`{iri}` is a parameter; the script's IRI comes first. {USAGE}"
        ));
    }
    if iri.chars().any(|c| c.is_whitespace() || c == '"') {
        return Err(format!("`{iri}` is not an IRI. {USAGE}"));
    }
    Ok(Invocation {
        iri,
        params: params(words)?,
    })
}

/// The words of a REPL `script` line: split at whitespace, where `"…"` keeps a span together
/// and `\"` and `\\` inside it are a quote and a backslash, as the engine reads them. So
/// `who="two words"` gives `who` the value `two words`.
fn words(text: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => words.extend(word.take()),
            '"' => {
                let word = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => word.push(e),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err("an unterminated `\\` escape".to_string()),
                        },
                        Some(c) => word.push(c),
                        None => return Err("an unterminated `\"`".to_string()),
                    }
                }
            }
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    Ok(words)
}

/// `key=value` arguments as a script's parameters. A word with no `=` and a name given twice
/// are refused; whether the script declares each name is the script's to say ([`run`]).
pub fn params(args: impl IntoIterator<Item = String>) -> Result<BTreeMap<String, String>, String> {
    let mut params = BTreeMap::new();
    for arg in args {
        let Some((name, value)) = arg.split_once('=') else {
            return Err(format!(
                "`{arg}` is not a parameter: give a script's parameters as `name=value`"
            ));
        };
        if name.is_empty() {
            return Err(format!("`{arg}` names no parameter: write `name=value`"));
        }
        if params.insert(name.to_string(), value.to_string()).is_some() {
            return Err(format!("the parameter `{name}` is given twice"));
        }
    }
    Ok(params)
}

/// Run `text` as a script with `supplied` for its parameters. A script that does not parse,
/// or that refuses `supplied`, runs no line. Otherwise each line is evaluated in file order and
/// handed to `each` with its line number and the line as it ran (parameters substituted); the
/// run stops after the first line whose answer is an error, which is the `Err`, or at `quit`.
pub fn run(
    engine: &Session,
    text: &str,
    supplied: &BTreeMap<String, String>,
    mut each: impl FnMut(usize, &str, Action),
) -> Result<(), ScriptError> {
    let lines = Script::parse(text)?.bind(supplied)?;
    for (number, line) in lines {
        let action = engine.eval(&line);
        let failed = match &action {
            Action::Output(entry) => entry.result.as_ref().err().cloned(),
            _ => None,
        };
        let quit = matches!(action, Action::Quit);
        each(number, &line, action);
        if let Some(message) = failed {
            return Err(ScriptError {
                line: Some(number),
                message,
            });
        }
        if quit {
            break;
        }
    }
    Ok(())
}

/// Read the script stored at `iri` through the engine (`source <iri>`), under the session's
/// capability, as any other read from the REPL is.
pub fn read(engine: &Session, iri: &str) -> Result<String, String> {
    match engine.eval(&format!("source {iri}")) {
        Action::Output(entry) => entry
            .result
            .map_err(|e| format!("cannot read the script {iri}: {e}")),
        _ => Err(format!("cannot read the script {iri}")),
    }
}

/// The REPL's `script <iri> [key=value …]`: read the script and [`run`] it. The refusal of a
/// malformed command or an unreadable script belongs to no line (`line: None`).
pub fn run_command(
    engine: &Session,
    invocation: Result<Invocation, String>,
    each: impl FnMut(usize, &str, Action),
) -> Result<(), ScriptError> {
    let refused = |message| ScriptError {
        line: None,
        message,
    };
    let invocation = invocation.map_err(refused)?;
    let text = read(engine, &invocation.iri).map_err(refused)?;
    run(engine, &text, &invocation.params, each)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoked(line: &str) -> Option<Result<Invocation, String>> {
        command(line)
    }

    #[test]
    fn only_the_script_command_is_taken() {
        assert!(invoked("source urn:file:a.iki").is_none());
        assert!(invoked("scripts urn:file:a.iki").is_none());
        assert!(invoked("run urn:file:plan.ttl").is_none());
        assert_eq!(invoked("script"), Some(Err(USAGE.to_string())));
        assert_eq!(invoked("  script  "), Some(Err(USAGE.to_string())));
    }

    #[test]
    fn parameters_follow_the_iri() {
        let Some(Ok(invocation)) =
            invoked(r#"script urn:file:refresh.iki since=2026-10-01 who="two words" q="a \"b\"""#)
        else {
            panic!("a script command");
        };
        assert_eq!(invocation.iri, "urn:file:refresh.iki");
        assert_eq!(invocation.params["since"], "2026-10-01");
        assert_eq!(invocation.params["who"], "two words");
        assert_eq!(invocation.params["q"], r#"a "b""#);
    }

    #[test]
    fn a_malformed_command_is_refused() {
        for line in [
            "script who=brian",
            "script urn:file:a.iki brian",
            "script urn:file:a.iki who=a who=b",
            "script urn:file:a.iki =x",
            r#"script urn:file:a.iki who="open"#,
        ] {
            assert!(
                matches!(invoked(line), Some(Err(_))),
                "{line} should be refused"
            );
        }
    }
}
