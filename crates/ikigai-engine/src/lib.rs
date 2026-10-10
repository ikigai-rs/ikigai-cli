//! The renderer-agnostic ikigai REPL engine.
//!
//! [`Engine`] parses a request line, issues it against a kernel through a
//! [`Resolver`](ikigai_resolve::Resolver), and returns an [`Action`] describing
//! what to display — knowing nothing about terminals or rendering. The plain
//! line REPL, the `ratatui` TUI, and a browser frontend all drive this same
//! engine and present its [`Action`] however suits their medium.
//!
//! Pulled out of the CLI binary into its own crate so the browser frontend can
//! reuse it unchanged. [`config`] is the small user-settings reader the engine's
//! `config` command and the TUI's keybindings use; on a target with no config
//! directory (e.g. WebAssembly) it simply reports defaults.

pub mod config;
pub mod engine;
pub mod fanout;
mod plan;
/// `urn:plan:eval`, `urn:plan:validate` and `urn:plan:requires` — plan execution as a
/// resource. Reading a plan needs the Turtle parser, so this is the `plan-reader` feature's.
#[cfg(feature = "plan-reader")]
pub mod plan_space;
pub mod suggest;

pub use engine::{Action, CacheStats, Engine, Entry, Viewer, COMMANDS, HELP};
pub use fanout::FanOut;
