//! Best-effort system-clipboard access via the platform's command-line tools.
//!
//! No clipboard *library* is linked: this shells out to the small utilities each
//! OS ships (or that are conventional), the same ones you'd use in a shell pipe.
//! When none is present — a stripped container, a Linux box without `xclip`, an
//! unsupported platform — both functions report failure and the caller falls
//! back to its in-process buffer. Over SSH these talk to the *remote* clipboard.

use std::io::Write;
use std::process::{Command, Stdio};

/// Candidate `(program, args)` clipboard writers for the current platform, tried
/// in order (text is piped to the program's stdin).
#[cfg(target_os = "macos")]
const WRITERS: &[(&str, &[&str])] = &[("pbcopy", &[])];
#[cfg(target_os = "macos")]
const READERS: &[(&str, &[&str])] = &[("pbpaste", &[])];

#[cfg(target_os = "linux")]
const WRITERS: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard"]),
    ("xsel", &["--clipboard", "--input"]),
];
#[cfg(target_os = "linux")]
const READERS: &[(&str, &[&str])] = &[
    ("wl-paste", &["--no-newline"]),
    ("xclip", &["-selection", "clipboard", "-o"]),
    ("xsel", &["--clipboard", "--output"]),
];

#[cfg(target_os = "windows")]
const WRITERS: &[(&str, &[&str])] = &[("clip", &[])];
#[cfg(target_os = "windows")]
const READERS: &[(&str, &[&str])] = &[("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])];

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const WRITERS: &[(&str, &[&str])] = &[];
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const READERS: &[(&str, &[&str])] = &[];

/// Copy `text` to the system clipboard. Returns whether a platform tool
/// accepted it; either way the caller keeps its in-process buffer as a fallback.
///
/// Also emits an OSC-52 escape sequence when over SSH or when no tool succeeded:
/// OSC-52 asks the *terminal* to set its clipboard, which is the local one even
/// across SSH (where `pbcopy`/`xclip` would set the unreachable remote clipboard)
/// and works when no clipboard tool is installed. Locally, with a tool present,
/// it's skipped so no escape sequence is written for the common case.
pub fn copy(text: &str) -> bool {
    let via_tool = WRITERS
        .iter()
        .any(|&(program, args)| write_to(program, args, text));
    if !via_tool || is_ssh() {
        emit_osc52(text);
    }
    via_tool
}

/// Whether this looks like an SSH session (so the local clipboard is only
/// reachable through the terminal, via OSC-52).
fn is_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}

/// Write the OSC-52 "set clipboard" sequence for `text` to the terminal.
fn emit_osc52(text: &str) {
    let mut out = std::io::stdout();
    let _ = out.write_all(osc52_sequence(text).as_bytes());
    let _ = out.flush();
}

/// The OSC-52 sequence that sets the terminal's clipboard (`c`) to `text`:
/// `ESC ] 52 ; c ; <base64> BEL`.
fn osc52_sequence(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", base64(text.as_bytes()))
}

/// Standard (RFC 4648) base64 with padding — hand-rolled to keep the crate free
/// of a base64 dependency for this one use.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Read the system clipboard, or `None` if no reader is available or it fails.
/// A trailing newline (an artifact of some tools) is trimmed.
pub fn paste() -> Option<String> {
    READERS.iter().find_map(|&(program, args)| {
        let output = Command::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        Some(text.trim_end_matches(['\n', '\r']).to_string())
    })
}

/// Spawn `program args`, pipe `text` to its stdin, and report success.
fn write_to(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    // Drop the stdin handle after writing so the child sees EOF, then wait.
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|status| status.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        // RFC 4648 examples, including the padding cases.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn osc52_sequence_wraps_the_base64_payload() {
        assert_eq!(osc52_sequence("foo"), "\x1b]52;c;Zm9v\x07");
    }

    /// Round-trips the real system clipboard, saving and restoring its prior
    /// contents. `#[ignore]`d so normal test runs and CI never touch the
    /// clipboard (and it needs a clipboard tool present); run it with
    /// `cargo test -- --ignored` on a machine that has one.
    #[test]
    #[ignore = "touches the real system clipboard"]
    fn round_trips_the_clipboard() {
        let saved = paste();
        assert!(
            copy("ikigai clipboard test ✓"),
            "no clipboard writer available"
        );
        assert_eq!(paste().as_deref(), Some("ikigai clipboard test ✓"));
        if let Some(previous) = saved {
            copy(&previous); // restore what was there before
        }
    }
}
