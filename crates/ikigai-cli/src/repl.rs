//! Plain line REPL — one request per line, no full-screen UI.
//!
//! Used when stdout is not a terminal (piping, scripts, CI) or with `--plain`.

use std::io::{self, Write};

use ikigai_engine::{Action, CacheStats, Engine, HELP};

/// Execute each command non-interactively, then return a process exit code
/// (`1` if any command errored, else `0`). Output goes to stdout, errors to
/// stderr — so `ikigai -c '…'` composes in a shell. A `quit` ends the batch.
///
/// Across a multi-command batch, the cache outcomes are tallied and a one-line
/// summary is printed at the end (to stderr) — so `ikigai -c … -c …`, especially
/// `--connect`'d to a server with a warm cache, shows how much of the batch was
/// served from cache rather than recomputed.
pub fn run_commands(engine: Engine, commands: &[String]) -> i32 {
    let mut code = 0;
    let mut total = CacheStats::default();
    let mut ran = 0u32;
    for command in commands {
        match engine.eval(command) {
            Action::Output(entry) => {
                match &entry.result {
                    Ok(output) => println!("{output}"),
                    Err(err) => {
                        eprintln!("error: {err}");
                        code = 1;
                    }
                }
                // Cache outcome goes to stderr so stdout stays clean for pipes.
                if let Some(label) = entry.cache.label() {
                    eprintln!("[{label}]");
                }
                total.merge(entry.cache);
                ran += 1;
            }
            Action::Help => println!("{HELP}"),
            // No screen to clear in a non-interactive batch.
            Action::Clear => {}
            Action::Quit => break,
            Action::Noop => {}
        }
    }
    // Batch caching summary — only when a batch resolved more than one command.
    if ran > 1 {
        if let Some(label) = total.label() {
            eprintln!("— batch: {ran} commands · {label}");
        }
    }
    code
}

/// Read-eval-print loop over the kernel until EOF or `quit`.
pub fn run(engine: Engine) {
    println!(
        "ikigai {} — REPL. Type `help`, or `quit` to exit.",
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
        match engine.eval(&line) {
            Action::Quit => break,
            Action::Help => println!("{HELP}"),
            // Clear the terminal screen and home the cursor (ANSI). The shell's
            // scrollback and the kernel's state are untouched.
            Action::Clear => {
                print!("\x1b[2J\x1b[H");
                io::stdout().flush().ok();
            }
            Action::Output(entry) => {
                match &entry.result {
                    Ok(out) => println!("{out}"),
                    Err(err) => eprintln!("error: {err}"),
                }
                // Cache outcome goes to stderr so stdout stays clean for pipes.
                if let Some(label) = entry.cache.label() {
                    eprintln!("[{label}]");
                }
            }
            Action::Noop => {}
        }
    }
}
