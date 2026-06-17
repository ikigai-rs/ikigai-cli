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
    match get("keybindings") {
        None => Keybindings::default(),
        Some(value) => Keybindings::parse(&value).unwrap_or_else(|| {
            eprintln!("ikigai: keybindings `{value}` not supported yet; using emacs");
            Keybindings::default()
        }),
    }
}

/// Whether `value` names a keybinding scheme that is actually implemented (so a
/// caller can warn when storing one that isn't yet).
pub fn keybindings_supported(value: &str) -> bool {
    Keybindings::parse(value).is_some()
}

/// `$XDG_CONFIG_HOME/ikigai-cli/config.toml`, or `$HOME/.config/...` when
/// `XDG_CONFIG_HOME` is unset. `None` if neither base directory is known.
pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("ikigai-cli").join("config.toml"))
}

/// The stored value of `key`, or `None` if the file or key is absent.
pub fn get(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path()?).ok()?;
    value_for(&text, key)
}

/// Persist `key = value`, creating the config directory and file as needed and
/// preserving any other lines. Returns the path written.
pub fn set(key: &str, value: &str) -> std::io::Result<PathBuf> {
    let path = path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no config directory (set $XDG_CONFIG_HOME or $HOME)",
        )
    })?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, upsert(&existing, key, value))?;
    Ok(path)
}

/// Replace the first `key = …` line in `text` (skipping comments) with
/// `key = "value"`, or append it if absent. Other lines are kept verbatim.
fn upsert(text: &str, key: &str, value: &str) -> String {
    let assignment = format!("{key} = \"{value}\"");
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let matches_key = !replaced
            && !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(name, _)| name.trim() == key);
        if matches_key {
            lines.push(assignment.clone());
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(assignment);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
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

    #[test]
    fn upsert_appends_a_missing_key() {
        assert_eq!(
            upsert("", "keybindings", "emacs"),
            "keybindings = \"emacs\"\n"
        );
        assert_eq!(
            upsert("theme = dark\n", "keybindings", "emacs"),
            "theme = dark\nkeybindings = \"emacs\"\n"
        );
    }

    #[test]
    fn upsert_replaces_in_place_and_keeps_other_lines() {
        let before = "# header\nkeybindings = emacs\ntheme = dark\n";
        let after = "# header\nkeybindings = \"vi\"\ntheme = dark\n";
        assert_eq!(upsert(before, "keybindings", "vi"), after);
        // A commented-out key is not treated as the key.
        assert_eq!(
            upsert("# keybindings = vi\n", "keybindings", "emacs"),
            "# keybindings = vi\nkeybindings = \"emacs\"\n"
        );
    }

    #[test]
    fn upsert_round_trips_through_value_for() {
        let text = upsert("", "keybindings", "emacs");
        assert_eq!(value_for(&text, "keybindings").as_deref(), Some("emacs"));
    }
}
