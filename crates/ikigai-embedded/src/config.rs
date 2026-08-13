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

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The ikigai config home: `$XDG_CONFIG_HOME/ikigai`, or `$HOME/.config/ikigai` when
/// `XDG_CONFIG_HOME` is unset. `None` when neither base directory is known.
///
/// THE spelling of the config home — every file the host reads from it resolves through
/// here. It used to be written twice: this module honoured `XDG_CONFIG_HOME` while nine
/// other call sites joined `$HOME/.config/ikigai` directly. The two AGREE in the default
/// case, which is precisely why the divergence survived: it appears only on a machine that
/// sets the variable, and there it split the config home in half — `grants.json`,
/// `clients.json`, `calendar.json`, `llm.json` and the code-signers directory read from
/// `$HOME` while `config.toml` read from `$XDG_CONFIG_HOME`. The QUIC certificate directory
/// managed to disagree with *itself*: `ikigai-cli`'s `quic::dir` resolved it through the
/// XDG-honouring spelling and `peer_cert_dir` through the other, so `holds_cert_for` could
/// report no certificate for a peer whose certificate had just been written.
///
/// `ikigai_engine::config::path` is a deliberate TWIN of this rule, not a third spelling:
/// neither crate depends on the other, so one shared function would have to be pushed down
/// into `ikigai-core`. Keep the two in step.
pub fn config_home() -> Option<PathBuf> {
    config_home_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// [`config_home`] with the environment passed in, so the resolution rule is testable
/// without `set_var`: the environment is process-global, and mutating it races the test
/// harness's own threads.
///
/// A set-but-EMPTY `XDG_CONFIG_HOME` counts as unset, per the XDG base directory spec. The
/// old spellings took it literally and resolved a relative `ikigai/…` against the working
/// directory — a config home that moved with `cd`.
fn config_home_from(xdg: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    xdg.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("ikigai"))
}

/// `$XDG_CONFIG_HOME/ikigai/config.toml`, or `~/.config/ikigai/config.toml` when
/// `XDG_CONFIG_HOME` is unset. Independent of `IKIGAI_FILES` (see the module note).
///
/// Falls back to a RELATIVE `./.config/ikigai/config.toml` where [`config_home`] gives up:
/// a process with no `HOME` still reads *a* file. The JSON siblings return `None` instead —
/// each caller keeps the failure semantics it already had, only the directory is unified.
pub fn config_path() -> PathBuf {
    config_home()
        .unwrap_or_else(|| Path::new(".").join(".config").join("ikigai"))
        .join("config.toml")
}

/// The value of `key` in the host config, or `None` if the file or the key is absent.
pub fn get(key: &str) -> Option<String> {
    value_for(&std::fs::read_to_string(config_path()).ok()?, key)
}

/// Every value for `key`, in file order — for settings that legitimately repeat.
///
/// A machine's TOPOLOGY is the motivating case: it has as many mounts as it has peers, and
/// they belong in the config home rather than in a launchd plist, so `git pull` cannot
/// overwrite one machine's identity with another's.
pub fn all(key: &str) -> Vec<String> {
    std::fs::read_to_string(config_path())
        .map(|text| values_for(&text, key))
        .unwrap_or_default()
}

/// The instance names that SCOPE `key` in the file — the `<instance>` of every
/// `<instance>.<key> = …` line, in file order, deduped.
///
/// Instance-scoped properties (`serve.derive_every`, `serve.browse.root`) attach behavior to a
/// NAMED process instead of to every process reading the shared config. A reader that falls
/// back from `<instance>.<key>` to plain `<key>` needs to know whether ANYONE scopes the key:
/// for a resource only one process may hold (the browse store), a scoped line for instance A
/// plus an unscoped line that instance B still honours re-creates exactly the collision the
/// scoping exists to prevent.
pub fn scoping_instances(key: &str) -> Vec<String> {
    std::fs::read_to_string(config_path())
        .map(|text| scoping_instances_in(&text, key))
        .unwrap_or_default()
}

/// The `<instance>` prefixes of every `<instance>.<key>` line in `text`. See
/// [`scoping_instances`].
fn scoping_instances_in(text: &str, key: &str) -> Vec<String> {
    let suffix = format!(".{key}");
    let mut instances: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            if let Some(instance) = name.trim().strip_suffix(&suffix) {
                if !instance.is_empty() && !instances.iter().any(|i| i == instance) {
                    instances.push(instance.to_string());
                }
            }
        }
    }
    instances
}

/// Every `key = value` line for `key`. See [`value_for`] for the parsing rules.
fn values_for(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim().trim_matches(['"', '\'']).trim().to_string())
        .collect()
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
    use super::{
        config_home, config_home_from, config_path, scoping_instances_in, value_for, values_for,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// `XDG_CONFIG_HOME` decides the config home when it is set. The second spelling this
    /// replaced ignored it, and the two agreed everywhere except on the machines that set
    /// it — a divergence the default case cannot show.
    #[test]
    fn xdg_config_home_decides_the_config_home_when_set() {
        assert_eq!(
            config_home_from(Some("/xdg".into()), Some("/home/b".into())),
            Some(PathBuf::from("/xdg/ikigai"))
        );
        // With no HOME to fall back to, XDG alone still resolves.
        assert_eq!(
            config_home_from(Some("/xdg".into()), None),
            Some(PathBuf::from("/xdg/ikigai"))
        );
    }

    /// Unset — and set-but-empty, which the spec says to read as unset — fall back to
    /// `$HOME/.config`. Empty used to resolve a RELATIVE `ikigai/…`, a config home that
    /// moved with the working directory.
    #[test]
    fn an_unset_or_empty_xdg_falls_back_to_home_config() {
        assert_eq!(
            config_home_from(None, Some("/home/b".into())),
            Some(PathBuf::from("/home/b/.config/ikigai"))
        );
        assert_eq!(
            config_home_from(Some(OsString::new()), Some("/home/b".into())),
            Some(PathBuf::from("/home/b/.config/ikigai"))
        );
    }

    /// Neither base directory known: `None`, so each caller applies its OWN fallback
    /// rather than inheriting one it did not choose.
    #[test]
    fn no_base_directory_at_all_is_none() {
        assert_eq!(config_home_from(None, None), None);
        assert_eq!(
            config_path(),
            config_home()
                .unwrap_or_else(|| Path::new(".").join(".config").join("ikigai"))
                .join("config.toml")
        );
    }

    /// The invariant that actually broke: `config.toml`, `grants.json` and `clients.json`
    /// are SIBLINGS in one directory. Whatever the ambient environment resolves to, a
    /// served kernel must not read its grants from one config home and its settings from
    /// another.
    #[test]
    fn the_config_home_files_are_siblings() {
        // An explicit override relocates its file BY DESIGN — the escape hatch for CI and
        // containers is not a divergence.
        if std::env::var_os("IKIGAI_GRANTS").is_some()
            || std::env::var_os("IKIGAI_CLIENTS").is_some()
        {
            return;
        }
        let Some(home) = config_home() else {
            return; // no HOME and no XDG_CONFIG_HOME: nothing to be a sibling of.
        };
        let grants = crate::grants_path();
        let clients = crate::clients::clients_path();
        assert_eq!(config_path().parent(), Some(home.as_path()));
        assert_eq!(
            grants.as_deref().and_then(Path::parent),
            Some(home.as_path())
        );
        assert_eq!(
            clients.as_deref().and_then(Path::parent),
            Some(home.as_path())
        );
    }

    /// `serve.browse.root` scopes `browse.root` to the "serve" instance; the plain key, a
    /// commented line, and an unrelated dotted key must not read as scoping instances.
    #[test]
    fn scoped_spellings_surface_their_instances() {
        let text = "browse.root = \"~/a\"\n\
                    serve.browse.root = \"~/b\"\n\
                    serve.browse.root = \"~/c\"\n\
                    daemon.browse.root = \"~/d\"\n\
                    # repl.browse.root = \"~/e\"\n\
                    mail.from = \"x@y.example\"\n";
        assert_eq!(
            scoping_instances_in(text, "browse.root"),
            vec!["serve".to_string(), "daemon".to_string()]
        );
        assert!(scoping_instances_in(text, "browse.store").is_empty());
    }

    /// A machine has as many mounts as it has peers, so `mount` must be repeatable — the
    /// single-value reader would silently take the first and drop the rest.
    #[test]
    fn repeated_keys_all_come_back_in_order() {
        let text = "# topology\n\
                    mount = \"prefer urn:llm:=peer:plasma\"\n\
                    other = 1\n\
                    mount = \"alias urn:cal:=quic://bug.local:4433\"\n";
        assert_eq!(
            values_for(text, "mount"),
            vec![
                "prefer urn:llm:=peer:plasma".to_string(),
                "alias urn:cal:=quic://bug.local:4433".to_string()
            ]
        );
        assert!(values_for(text, "absent").is_empty());
    }

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
