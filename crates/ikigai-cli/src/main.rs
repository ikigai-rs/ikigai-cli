//! ikigai — resource-resolution REPL.
//!
//! Attaches to a kernel instance over a pluggable transport. Today the only wired
//! transport is `embedded` (the kernel runs in this process); IPC and QUIC will
//! front the same interface over a wire. Each line is a request issued against
//! the kernel's address space; the response is its representation's bytes.
//!
//! With `-c '<command>'` (repeatable) it runs the command(s) and exits — handy
//! for scripting and the foundation for attaching to a remote kernel later.
//! Otherwise, on an interactive terminal it launches a full-screen [`tui`] REPL;
//! piped or with `--plain` it falls back to the line-oriented [`repl`]. All three
//! drive the same renderer-agnostic [`engine`].

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
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit
  ikigai -h | --help           show this help

inside the REPL: source, describe, help, quit (type `help` for details)";

/// Parsed command-line options.
#[derive(Default)]
struct Args {
    plain: bool,
    /// `-c` / `--command` values, in order; non-empty means one-shot mode.
    commands: Vec<String>,
}

/// Parse argv. `Ok(None)` means a usage request was handled and we should exit 0.
fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--plain" => args.plain = true,
            "-c" | "--command" => {
                let command = argv
                    .next()
                    .ok_or_else(|| format!("{arg} requires a command argument"))?;
                args.commands.push(command);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Some(args))
}

#[cfg(feature = "embedded")]
fn main() {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("ikigai: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    let kernel = transport_embedded::kernel();

    // One-shot: run the -c commands and exit with their status.
    if !args.commands.is_empty() {
        std::process::exit(repl::run_commands(kernel, &args.commands));
    }

    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        if !args.plain && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            // The keybinding scheme is read before entering the alternate screen
            // so an unsupported-value notice is visible.
            if let Err(e) = tui::run(kernel, config::keybindings()) {
                eprintln!("ikigai: tui error: {e}");
                std::process::exit(1);
            }
            return;
        }
        repl::run(kernel);
    }

    #[cfg(target_family = "wasm")]
    repl::run(kernel);
}

#[cfg(not(feature = "embedded"))]
fn main() {
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}
