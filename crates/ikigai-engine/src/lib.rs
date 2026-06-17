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

pub use engine::{Action, CacheStats, Engine, Entry, HELP};
