//! Host configuration, read from `$XDG_CONFIG_HOME/ikigai/config.toml` (falling back to
//! `~/.config/ikigai/config.toml`).
//!
//! The one place the daemon and the CLI both read — so they cannot diverge the way a shell
//! env var and a launchd plist just did (the mail `from` that was set for one process and not
//! the other). A minimal `key = "value"` scanner; dotted keys like `mail.from` are ordinary
//! keys to it. It grows a real TOML parser if and when the config outgrows a flat map.
//!
//! Deliberately in the CONFIG dir, NOT `file_root()`: `IKIGAI_FILES` repoints the workspace
//! *data* dir, but a *setting* like the mail sender shouldn't move with it. This is the shared
//! ikigai config home — `grants.json` already lives beside it, and the CLI's own settings
//! (keybindings) read the same `config.toml`.
//!
//! Settings that already had environment variables keep them as an override — the file is the
//! home, the env is an escape hatch for CI and containers. [`email_config`](crate::email_config)
//! reads `mail.from` / `mail.host` / `mail.port` this way.

/// `$XDG_CONFIG_HOME/ikigai/config.toml`, or `~/.config/ikigai/config.toml` when
/// `XDG_CONFIG_HOME` is unset. Independent of `IKIGAI_FILES` (see the module note).
pub fn config_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from);
            home.join(".config")
        });
    base.join("ikigai").join("config.toml")
}

/// The value of `key` in the host config, or `None` if the file or the key is absent.
pub fn get(key: &str) -> Option<String> {
    value_for(&std::fs::read_to_string(config_path()).ok()?, key)
}

/// The first `key = value` line for `key`, trimmed and unquoted. Blank lines and `#` comments
/// are skipped. Not a full TOML parser — the flat `key = "value"` shape the config uses today.
fn value_for(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == key {
                return Some(value.trim().trim_matches(['"', '\'']).trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::value_for;

    #[test]
    fn reads_a_dotted_key_unquoted() {
        let text = "# host config\n\nmail.from = \"brian@bosatsu.net\"\nmail.port = 587\n";
        assert_eq!(
            value_for(text, "mail.from").as_deref(),
            Some("brian@bosatsu.net")
        );
        assert_eq!(value_for(text, "mail.port").as_deref(), Some("587"));
    }

    #[test]
    fn an_absent_or_commented_key_is_none() {
        assert_eq!(value_for("mail.host = localhost", "mail.from"), None);
        // A commented line is not the key.
        assert_eq!(value_for("# mail.from = x@y.example", "mail.from"), None);
    }
}
