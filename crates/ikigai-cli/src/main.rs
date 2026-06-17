//! ikigai — resource-resolution REPL.
//!
//! Attaches to a kernel instance over a pluggable transport: `embedded` (the
//! kernel runs in this process) or `ipc` (a kernel server over a Unix socket —
//! `ikigai serve` runs one, `--connect` attaches to it); QUIC will front the same
//! interface over a network. Each line is a request issued against the kernel's
//! address space; the response is its representation's bytes.
//!
//! With `-c '<command>'` (repeatable) it runs the command(s) and exits — handy
//! for scripting. Otherwise, on an interactive terminal it launches a full-screen
//! [`tui`] REPL; piped or with `--plain` it falls back to the line-oriented
//! [`repl`]. All drive the same renderer-agnostic [`engine`] over the chosen
//! [`Backend`](transport_core::Backend), local or remote.

#[cfg(not(target_family = "wasm"))]
mod clipboard;
mod config;
mod engine;
mod repl;
#[cfg(not(target_family = "wasm"))]
mod tui;

const USAGE: &str = "\
ikigai — resource-resolution REPL

usage:
  ikigai                       start the interactive REPL (full-screen on a terminal)
  ikigai --plain               force the line REPL (also used automatically when piped)
  ikigai --connect [<path>]    attach the REPL to a kernel server over IPC (default socket if omitted)
  ikigai serve [<path>]        run a kernel server on a Unix socket (default socket if omitted)
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit
  ikigai -h | --help           show this help

inside the REPL: source, describe, help, quit (type `help` for details)";

use crate::engine::Engine;

/// What the CLI was asked to do.
enum Mode {
    /// Run the REPL (interactive, piped, or one-shot).
    Repl(ReplArgs),
    /// Run a kernel server; the optional path overrides the default socket.
    Serve(Option<String>),
}

/// Options for the REPL mode.
#[derive(Default)]
struct ReplArgs {
    plain: bool,
    /// `-c` / `--command` values, in order; non-empty means one-shot mode.
    commands: Vec<String>,
    /// `None` = the embedded in-process kernel; `Some` = attach over IPC, with
    /// `Some(None)` meaning the default socket.
    connect: Option<Option<String>>,
}

/// Parse argv. `Ok(None)` means a usage request was handled and we should exit 0.
fn parse_args() -> Result<Option<Mode>, String> {
    let mut argv = std::env::args().skip(1).peekable();

    if argv.peek().map(String::as_str) == Some("serve") {
        argv.next();
        let path = argv.next();
        if let Some(extra) = argv.next() {
            return Err(format!("unexpected argument after `serve`: {extra}"));
        }
        return Ok(Some(Mode::Serve(path)));
    }

    let mut repl = ReplArgs::default();
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--plain" => repl.plain = true,
            "--connect" => {
                // Optional path: take the next token unless it looks like a flag.
                let path = match argv.peek() {
                    Some(next) if !next.starts_with('-') => argv.next(),
                    _ => None,
                };
                repl.connect = Some(path);
            }
            "-c" | "--command" => {
                let command = argv
                    .next()
                    .ok_or_else(|| format!("{arg} requires a command argument"))?;
                repl.commands.push(command);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Some(Mode::Repl(repl)))
}

#[cfg(feature = "embedded")]
fn main() {
    let mode = match parse_args() {
        Ok(Some(mode)) => mode,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("ikigai: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    match mode {
        Mode::Serve(path) => serve(path),
        Mode::Repl(args) => {
            let engine = build_engine(args.connect).unwrap_or_else(|e| {
                eprintln!("ikigai: {e}");
                std::process::exit(1);
            });
            run_repl(engine, args.plain, &args.commands);
        }
    }
}

/// Build the engine over the chosen backend: the embedded kernel, or — with
/// `--connect` — an IPC client to a kernel server.
#[cfg(feature = "embedded")]
fn build_engine(connect: Option<Option<String>>) -> Result<Engine, String> {
    match connect {
        None => Ok(Engine::new(transport_embedded::kernel())),
        Some(path) => connect_over_ipc(path),
    }
}

/// Drive the engine: one-shot `-c`, else the full-screen TUI on a terminal, else
/// the line REPL.
#[cfg(feature = "embedded")]
fn run_repl(engine: Engine, plain: bool, commands: &[String]) {
    if !commands.is_empty() {
        std::process::exit(repl::run_commands(engine, commands));
    }
    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        if !plain && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            // The keybinding scheme is read before entering the alternate screen
            // so an unsupported-value notice is visible.
            if let Err(e) = tui::run(engine, config::keybindings()) {
                eprintln!("ikigai: tui error: {e}");
                std::process::exit(1);
            }
            return;
        }
        repl::run(engine);
    }
    #[cfg(target_family = "wasm")]
    repl::run(engine);
}

/// Run a kernel server (IPC). On a non-Unix or non-`ipc` build this just reports
/// that the feature is unavailable.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn serve(path: Option<String>) -> ! {
    let socket = ipc_socket(path);
    eprintln!("ikigai: serving on {}  (Ctrl-C to stop)", socket.display());
    match transport_ipc::serve(transport_embedded::kernel(), &socket) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: serve error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn connect_over_ipc(path: Option<String>) -> Result<Engine, String> {
    let socket = ipc_socket(path);
    let backend = transport_ipc::connect(&socket)
        .map_err(|e| format!("connect {}: {e}", socket.display()))?;
    Ok(Engine::new(backend))
}

/// Resolve an explicit socket path, or the secure default, exiting if neither is
/// available.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn ipc_socket(path: Option<String>) -> std::path::PathBuf {
    path.map(std::path::PathBuf::from)
        .or_else(transport_ipc::default_socket_path)
        .unwrap_or_else(|| {
            eprintln!("ikigai: no socket path given and no runtime directory to default to");
            std::process::exit(2);
        })
}

#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn serve(_path: Option<String>) -> ! {
    eprintln!("ikigai: `serve` needs the `ipc` feature on a Unix platform");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn connect_over_ipc(_path: Option<String>) -> Result<Engine, String> {
    Err("`--connect` needs the `ipc` feature on a Unix platform".to_string())
}

#[cfg(not(feature = "embedded"))]
fn main() {
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}
