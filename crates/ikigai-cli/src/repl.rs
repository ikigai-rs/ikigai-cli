//! Plain line REPL — one request per line, no full-screen UI.
//!
//! Used when stdout is not a terminal (piping, scripts, CI) or with `--plain`.

use std::io::{self, Write};

use ikigai_core::Kernel;

use crate::engine::{Action, Engine, HELP};

/// Read-eval-print loop over the kernel until EOF or `quit`.
pub fn run(kernel: Kernel) {
    let engine = Engine::new(kernel);
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
            Action::Output(entry) => match entry.result {
                Ok(out) => println!("{out}"),
                Err(err) => eprintln!("error: {err}"),
            },
            Action::Noop => {}
        }
    }
}
