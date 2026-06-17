//! User configuration, read from `$XDG_CONFIG_HOME/ikigai-cli/config.toml`
//! (falling back to `$HOME/.config/ikigai-cli/config.toml`).
//!
//! Only one property exists today — `keybindings` — so the reader is a minimal
//! `key = value` scanner rather than a full TOML parser; it grows a real parser
//! if and when the config does.

use std::path::PathBuf;

/// Which keybinding scheme the TUI input line uses.
///
/// Only [`Emacs`](Keybindings::Emacs) is implemented for now; other values
/// (`vi`, …) are recognised in the config but fall back to Emacs with a notice,
/// so the scheme can grow without changing the config surface.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum Keybindings {
    /// Readline / Emacs-style editing: `Ctrl-A`/`Ctrl-E`, `Ctrl-F`/`Ctrl-B`,
    /// `Ctrl-P`/`Ctrl-N`, `Alt-F`/`Alt-B`, `Ctrl-K`/`Ctrl-U`/`Ctrl-W`. The default.
    #[default]
    Emacs,
}

impl Keybindings {
    /// Parse a config value into a scheme, or `None` if it isn't one we implement.
    fn parse(value: &str) -> Option<Keybindings> {
        match value.to_ascii_lowercase().as_str() {
            "emacs" => Some(Keybindings::Emacs),
            _ => None,
        }
    }
}

/// Load the configured keybinding scheme, defaulting to [`Keybindings::Emacs`]
/// when the config file, the `keybindings` key, or the value is absent. A value
/// we don't implement yet warns and falls back to the default.
pub fn keybindings() -> Keybindings {
    let value = config_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| value_for(&text, "keybindings"));
    match value {
        None => Keybindings::default(),
        Some(value) => Keybindings::parse(&value).unwrap_or_else(|| {
            eprintln!("ikigai: keybindings `{value}` not supported yet; using emacs");
            Keybindings::default()
        }),
    }
}

/// `$XDG_CONFIG_HOME/ikigai-cli/config.toml`, or `$HOME/.config/...` when
/// `XDG_CONFIG_HOME` is unset. `None` if neither base directory is known.
fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("ikigai-cli").join("config.toml"))
}

/// The value of the first `key = value` line for `key`, trimmed and unquoted.
/// Blank lines and `#` comments are skipped. Not a full TOML parser — just the
/// flat `key = value` shape the config uses today.
fn value_for(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == key {
                let value = value.trim().trim_matches(['"', '\'']).trim();
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_keybindings_value() {
        assert_eq!(
            value_for("keybindings = emacs", "keybindings").as_deref(),
            Some("emacs")
        );
        // Quotes, surrounding whitespace, comments, and other keys are handled.
        let text = "# my config\n\n  keybindings  =  \"vi\"  \ntheme = dark\n";
        assert_eq!(value_for(text, "keybindings").as_deref(), Some("vi"));
        assert_eq!(value_for(text, "theme").as_deref(), Some("dark"));
        assert_eq!(value_for("theme = dark", "keybindings"), None);
    }

    #[test]
    fn parses_known_schemes_only() {
        assert_eq!(Keybindings::parse("emacs"), Some(Keybindings::Emacs));
        assert_eq!(Keybindings::parse("EMACS"), Some(Keybindings::Emacs));
        assert_eq!(Keybindings::parse("vi"), None);
        assert_eq!(Keybindings::parse("dvorak"), None);
    }
}
