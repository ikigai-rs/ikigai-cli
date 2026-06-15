//! ikigai — resource-resolution REPL.
//!
//! Attaches to a kernel instance over a pluggable transport. Today the only wired
//! transport is `embedded` (the kernel runs in this process); IPC and QUIC will
//! front the same interface over a wire. Each line is a request issued against
//! the kernel's address space; the response is its representation's bytes.
//!
//! On an interactive terminal it launches a full-screen [`tui`] REPL; piped or
//! with `--plain` it falls back to the line-oriented [`repl`]. Both drive the
//! same renderer-agnostic [`engine`].

mod engine;
mod repl;
#[cfg(not(target_family = "wasm"))]
mod tui;

#[cfg(feature = "embedded")]
fn main() {
    let kernel = transport_embedded::kernel();
    let plain = std::env::args().skip(1).any(|arg| arg == "--plain");

    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        if !plain && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            if let Err(e) = tui::run(kernel) {
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
