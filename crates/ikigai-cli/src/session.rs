//! CLI evaluation policy shared by batches, scripts, and both REPLs.
//!
//! The engine leaves the previous capability intact when `cap` is refused. At the host
//! boundary that refusal must also block subsequent evaluation until the operator explicitly
//! recovers, including evaluation through the TUI's scratch buffer or a stored script.

use std::cell::Cell;

use ikigai_engine::{Action, CacheStats, ContractNote, Engine, Entry, FanOut};

pub struct Session {
    engine: Engine,
    refusing: Cell<bool>,
}

impl Session {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            refusing: Cell::new(false),
        }
    }

    pub fn is_refusing(&self) -> bool {
        self.refusing.get()
    }

    pub fn eval(&self, line: &str) -> Action {
        let line = line.trim();
        let (command, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        let cap = command == "cap";
        // A query or a seal without scopes does not supply a replacement narrowing.
        let recovery = cap && !rest.is_empty() && rest != "seal";
        if self.is_refusing() && !recovery {
            return match command {
                "quit" | "exit" => Action::Quit,
                "help" | "?" => Action::Help,
                "clear" | "cls" => Action::Clear,
                "" | "#" => Action::Noop,
                _ if line.trim_start().starts_with('#') => Action::Noop,
                _ => Self::refusal(line),
            };
        }
        let action = self.engine.eval(line);
        if cap {
            match &action {
                Action::Output(entry) if entry.result.is_err() => self.refusing.set(true),
                Action::Output(entry) if recovery && entry.result.is_ok() => {
                    self.refusing.set(false);
                }
                _ => {}
            }
        }
        action
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn eval_lisp(&self, src: &str) -> Action {
        if self.is_refusing() {
            Self::refusal(src)
        } else {
            self.engine.eval_lisp(src)
        }
    }

    // Expose only the metadata the frontends need, rather than the underlying engine's
    // unguarded evaluation entry points. A refusal has no resolution notes of its own.
    pub fn last_fan_out(&self) -> Option<FanOut> {
        if self.is_refusing() {
            None
        } else {
            self.engine.last_fan_out()
        }
    }

    pub fn last_contract_notes(&self) -> Vec<ContractNote> {
        if self.is_refusing() {
            Vec::new()
        } else {
            self.engine.last_contract_notes()
        }
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
        if self.is_refusing() {
            None
        } else {
            self.engine.entries()
        }
    }

    fn refusal(input: &str) -> Action {
        Action::Output(Entry {
            input: input.to_string(),
            result: Err("session is refusing after a failed `cap`; enter a valid `cap <scope or profile>` or `cap reset` to resume".to_string()),
            cache: CacheStats::default(),
        })
    }
}
