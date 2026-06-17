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

/// Copy `text` to the system clipboard. Returns `false` if no writer is
/// available, so the caller can keep using its in-process buffer.
pub fn copy(text: &str) -> bool {
    WRITERS
        .iter()
        .any(|&(program, args)| write_to(program, args, text))
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
