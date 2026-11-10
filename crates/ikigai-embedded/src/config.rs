//! Host configuration, read from `$XDG_CONFIG_HOME/ikigai/config.toml` (falling back to
//! `~/.config/ikigai/config.toml`).
//!
//! The one place the daemon and the CLI both read — so they cannot diverge the way a shell
//! env var and a launchd plist just did (the mail `from` that was set for one process and not
//! the other). A strict reader of flat `key = value` lines; dotted keys like `mail.from` are
//! ordinary keys to it. See [`check`] for the grammar.
//!
//! Not a TOML parser, on purpose: `mount` (and `browse.root`, `bayes.models`) repeat, one line
//! per mount, which TOML forbids as a duplicate key, and `ikigai_engine::config` reads and
//! rewrites the same file line by line. Each line is read the way TOML reads a `key = value`
//! line, and anything outside that shape stops the host ([`check`]) rather than being skipped.
//!
//! Deliberately in the CONFIG dir, NOT `file_root()`: `IKIGAI_FILES` repoints the workspace
//! *data* dir, but a *setting* like the mail sender shouldn't move with it. This is the shared
//! ikigai config home — `grants.json` already lives beside it, and the CLI's own settings
//! (keybindings) read the same `config.toml`.
//!
//! Settings that already had environment variables keep them as an override — the file is the
//! home, the env is an escape hatch for CI and containers. `email_config`
//! reads `mail.from` / `mail.host` / `mail.port` this way.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The config home a `--config-home` FLAG named for this process, if one did. Set once, by the
/// binary, before anything reads the config home; see [`set_config_home`].
static FLAG_HOME: OnceLock<PathBuf> = OnceLock::new();

/// Name this process's config home outright, as the `--config-home` flag does (ledger #919):
/// from here on [`config_home`], [`config_path`] and every file under them resolve inside
/// `dir`, and `XDG_CONFIG_HOME` and `HOME` are not consulted for it. **An explicit flag wins
/// over the environment** — the rule is config home plus flags, so the flag is the channel and
/// the environment the fallback, never the other way round.
///
/// `dir` IS the config home (it holds `config.toml`, `grants.json`, …), not an XDG base with an
/// `ikigai/` beneath it: gonk's `--config-home` means the same. It must be ABSOLUTE — the
/// binary absolutizes what was typed — because a relative config home is one that moves with
/// the working directory, which `config_home` exists to refuse. Setting it twice to the same
/// directory is a no-op; to a different one is refused, since a process has one config home.
///
/// `ikigai_engine::config::set_config_home` is this function's TWIN (the engine reads the same
/// `config.toml` and depends on nothing here); the binary sets both.
pub fn set_config_home(dir: PathBuf) -> Result<(), String> {
    if !dir.is_absolute() {
        return Err(format!(
            "the config home must be an absolute path, and `{}` is not",
            dir.display()
        ));
    }
    match FLAG_HOME.get() {
        Some(prior) if *prior == dir => Ok(()),
        Some(prior) => Err(format!(
            "the config home is already `{}`; a process has one",
            prior.display()
        )),
        None => FLAG_HOME
            .set(dir)
            .map_err(|_| "the config home was set concurrently".into()),
    }
}

/// The config home a `--config-home` flag named, if any — for a caller that must hand a home
/// to a module that would otherwise read the environment itself (the durable store's
/// `store.toml`, browse's `a11y.toml` layers).
pub fn config_home_flag() -> Option<&'static Path> {
    FLAG_HOME.get().map(PathBuf::as_path)
}

/// The ikigai config home: the `--config-home` flag's directory when one was given
/// ([`set_config_home`]), else `$XDG_CONFIG_HOME/ikigai`, or `$HOME/.config/ikigai` when
/// `XDG_CONFIG_HOME` is unset, or `%USERPROFILE%\.config\ikigai` when `HOME` is unset too
/// (Windows). A variable that is unset, empty or not an absolute path is passed over, so the
/// answer is always absolute, and `None` when none of them is usable.
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
    if let Some(flag) = config_home_flag() {
        return Some(flag.to_path_buf());
    }
    config_home_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
        std::env::var_os("USERPROFILE"),
    )
}

/// [`config_home`] with the environment passed in, so the resolution rule is testable
/// without `set_var`: the environment is process-global, and mutating it races the test
/// harness's own threads.
///
/// An empty or relative `XDG_CONFIG_HOME` counts as unset, per the XDG base directory spec,
/// and `HOME` and `USERPROFILE` are held to the same rule: the config home never moves with
/// the working directory.
///
/// `USERPROFILE` is read only when `HOME` is not usable: plain PowerShell and cmd on Windows
/// set it instead of `HOME`. Where `HOME` is usable, the result is unchanged.
fn config_home_from(
    xdg: Option<OsString>,
    home: Option<OsString>,
    userprofile: Option<OsString>,
) -> Option<PathBuf> {
    absolute(xdg)
        .or_else(|| user_home_from(home, userprofile).map(|home| home.join(".config")))
        .map(|base| base.join("ikigai"))
}

/// `value` as a path when it is set and absolute. The empty path is not absolute, so an
/// empty variable is an unset one.
fn absolute(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

/// The user's home: `$HOME`, else `%USERPROFILE%`, each only when absolute. `None` when
/// neither is usable, so that no path is ever built from a home that is not one.
pub fn user_home() -> Option<PathBuf> {
    user_home_from(std::env::var_os("HOME"), std::env::var_os("USERPROFILE"))
}

/// [`user_home`] with the environment passed in.
fn user_home_from(home: Option<OsString>, userprofile: Option<OsString>) -> Option<PathBuf> {
    absolute(home).or_else(|| absolute(userprofile))
}

/// The config home, or the sentence that stops a host which needs one and has none.
pub fn require_config_home() -> Result<PathBuf, String> {
    config_home().ok_or_else(|| {
        "no config home: XDG_CONFIG_HOME, HOME and USERPROFILE are each unset, empty or not an \
         absolute path; set one to an absolute path, or name the directory with \
         --config-home <dir>"
            .to_string()
    })
}

/// `$XDG_CONFIG_HOME/ikigai/config.toml`, or `~/.config/ikigai/config.toml` when
/// `XDG_CONFIG_HOME` is unset. Independent of `IKIGAI_FILES` (see the module note).
///
/// `None` where [`config_home`] gives up: with no config home there is no file to read.
pub fn config_path() -> Option<PathBuf> {
    Some(config_home()?.join("config.toml"))
}

/// [`config_path`] for a diagnostic that names the file: its bare name with no config home.
pub fn config_path_shown() -> String {
    config_path().map_or_else(|| "config.toml".to_string(), |p| p.display().to_string())
}

/// The text of `config.toml`, when there is a config home and the file reads.
fn config_text() -> Option<String> {
    std::fs::read_to_string(config_path()?).ok()
}

/// The per-peer certificate directory `<config home>/quic-<name>/` (plasma holds
/// `quic-bug`, bug holds `quic-plasma`), or `None` when there is no config home or `name`
/// cannot name one directory. See [`peer_cert_dir_in`].
pub fn peer_cert_dir(name: &str) -> Option<PathBuf> {
    peer_cert_dir_in(&config_home()?, name)
}

/// `<home>/quic-<name>/`, or `None` when `name` is not a single path segment.
///
/// THE spelling of the per-peer directory: the peer listing's "do I hold a pinned
/// certificate?" oracle and the CLI's `peer:<name>` dialer both resolve through here, so
/// they cannot disagree about where a peer's certificate lives.
///
/// ⚠ `name` is usually what the LAN ANNOUNCED over mDNS, and a DNS-SD instance name may
/// carry any byte. Joined raw, `plasma/../quic-plasma` resolved to the real `quic-plasma`
/// directory, so a stranger's announcement was listed as trusted with `ik:pinnedHere true`
/// (ledger #741). A name with a path separator (`/` or `\`), a NUL, or nothing at all
/// names no directory; it is refused here, before any path is built, rather than
/// normalized, because a normalized name would be a DIFFERENT peer's name. So is a name
/// Windows would rewrite (ledger #1307): `quic-plasma.` opens `quic-plasma` there, which is
/// the same borrow by another spelling, and a `:` names a stream, not a directory.
///
/// ```
/// use std::path::{Path, PathBuf};
/// use ikigai_embedded::config::peer_cert_dir_in;
///
/// let home = Path::new("/home/b/.config/ikigai");
/// assert_eq!(peer_cert_dir_in(home, "plasma"), Some(PathBuf::from("/home/b/.config/ikigai/quic-plasma")));
/// assert_eq!(peer_cert_dir_in(home, "plasma/../quic-bug"), None);
/// assert_eq!(peer_cert_dir_in(home, ""), None);
/// assert_eq!(peer_cert_dir_in(home, "plasma."), None);
/// ```
pub fn peer_cert_dir_in(home: &Path, name: &str) -> Option<PathBuf> {
    is_single_segment(name).then(|| home.join(format!("quic-{name}")))
}

/// Whether `name` stays ONE directory entry once prefixed with `quic-`, by the workspace's
/// one rule for a joined name ([`ikigai_resolve::is_plain_file_name`]): separators of either
/// platform, a `:`, and a trailing `.` or space are refused on every platform, because a
/// name that is one entry on macOS and a different one on Windows is not a name to build a
/// path from. The rule is applied to the ENTRY (`quic-<name>`), which is what is joined.
fn is_single_segment(name: &str) -> bool {
    !name.is_empty() && ikigai_resolve::is_plain_file_name(&format!("quic-{name}"))
}

/// Every key the host reads from `config.toml`. A key is also known with an instance name
/// in front of it (`serve.files`, `daemon.browse.root`), the way the scoped readers look
/// it up, so an instance minted by `--name` needs no entry here.
const KNOWN_KEYS: &[&str] = &[
    "files",
    "store",
    "mount",
    "scheduler",
    "width-routing",
    "arrangement",
    "keybindings",
    "show.opener",
    "describe.timeout",
    "call.timeout",
    "quic.timeout",
    "quic.max_connection_age",
    "ipc.timeout",
    "ipc.group",
    "ipc.server_user",
    "layers.https",
    "layers.state",
    "layers.key",
    "bayes.state",
    "bayes.models",
    "passkey.max_challenges",
    "http.max_response_bytes",
    "http.user_agent",
    "http.timeout",
    "mail.host",
    "mail.port",
    "mail.from",
    "browse.root",
    "browse.store",
    "browse.file_model",
    "browse.dir_model",
    "browse.file_max_tokens",
    "browse.dir_max_tokens",
    "cache.max_entries",
    "cache.max_bytes",
];

/// Key families whose own readers validate every member and name a misspelled one
/// (`lisp.*`, the upload, spill and rate-limit rules), so any key under them is let through.
const KNOWN_PREFIXES: &[&str] = &["lisp.", "http.upload", "http.spill", "http.rate_limit"];

/// Whether `key` is one the host reads: a [`KNOWN_KEYS`] entry, a member of a
/// [`KNOWN_PREFIXES`] family, or either of those after an instance name.
fn is_known_key(key: &str) -> bool {
    let known =
        |key: &str| KNOWN_KEYS.contains(&key) || KNOWN_PREFIXES.iter().any(|p| key.starts_with(p));
    known(key)
        || key
            .char_indices()
            .filter(|&(_, c)| c == '.')
            .any(|(at, _)| at > 0 && known(&key[at + 1..]))
}

/// Read `config.toml` through, before the host acts on any of it: `Ok` when there is no
/// config home or no file, or when every line reads and names a key the host knows; else the
/// sentence that stops the host, naming the file and the line.
///
/// A line is blank, a `#` comment, or `key = value`. The key is bare: letters, digits, `_`,
/// `-` and `.`, with no empty segment. The value is a `"basic"` string (with TOML's escapes),
/// a `'literal'` string, or a bare word or number running to the end of the line. A `#` after
/// the value starts a comment. A `[table]` header, a line with no `=`, an unterminated string
/// or anything after a string's closing quote is an unreadable line.
pub fn check() -> Result<(), String> {
    let Some(path) = config_path() else {
        return Ok(());
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    check_text(&text).map_err(|e| format!("{} {e}", path.display()))
}

/// [`check`] over text already read; the error begins with the line it is about.
pub(crate) fn check_text(text: &str) -> Result<(), String> {
    for (index, line) in text.lines().enumerate() {
        let at = || format!("line {}", index + 1);
        match parse_line(line) {
            Err(e) => return Err(format!("{}: {e}", at())),
            Ok(Some((key, _))) if !is_known_key(&key) => {
                return Err(format!(
                    "{}: `{key}` is not a setting this host reads; check its spelling, or \
                     remove the line",
                    at()
                ))
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

/// One line of `config.toml`: `None` for a blank or comment line, the key and its unquoted
/// value for an assignment, or why the line cannot be read. See [`check`] for the grammar.
fn parse_line(line: &str) -> Result<Option<(String, String)>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if line.starts_with('[') {
        return Err(format!(
            "`{line}`: table headers are not read here; write each setting as one \
             `dotted.key = value` line"
        ));
    }
    let (key, value) = line
        .split_once('=')
        .ok_or_else(|| format!("`{line}`: expected `key = value`"))?;
    let key = key.trim();
    let bare_key = !key.is_empty()
        && key.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
    if !bare_key {
        return Err(format!(
            "`{line}`: expected a key of letters, digits, `_`, `-` and `.` before the `=`"
        ));
    }
    let value = value.trim_start();
    let (value, rest) = match value.chars().next() {
        Some('"') => basic_string(&value[1..]).ok_or_else(|| {
            format!("`{line}`: the string after `{key} =` is not closed, or has a bad escape")
        })?,
        Some('\'') => {
            let body = &value[1..];
            let end = body
                .find('\'')
                .ok_or_else(|| format!("`{line}`: the string after `{key} =` is not closed"))?;
            (body[..end].to_string(), &body[end + 1..])
        }
        _ => {
            let bare = value.split('#').next().unwrap_or_default().trim();
            if bare.is_empty() {
                return Err(format!("`{line}`: `{key}` has no value"));
            }
            if bare.contains(['"', '\'']) {
                return Err(format!(
                    "`{line}`: a quote inside a bare value; quote the whole value instead"
                ));
            }
            (bare.to_string(), "")
        }
    };
    let rest = rest.trim_start();
    if !(rest.is_empty() || rest.starts_with('#')) {
        return Err(format!(
            "`{line}`: unexpected `{rest}` after the value; a comment starts with `#`"
        ));
    }
    Ok(Some((key.to_string(), value)))
}

/// A TOML basic string's body, `text` being what follows the opening `"`: the unescaped
/// value and what follows the closing quote, or `None` if it is unclosed or a bad escape.
fn basic_string(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &text[at + 1..])),
            '\\' => {
                let (_, escaped) = chars.next()?;
                match escaped {
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    'n' => value.push('\n'),
                    't' => value.push('\t'),
                    'r' => value.push('\r'),
                    'b' => value.push('\u{8}'),
                    'f' => value.push('\u{c}'),
                    'e' => value.push('\u{1b}'),
                    'u' | 'U' => {
                        let width = if escaped == 'u' { 4 } else { 8 };
                        let digits: String = (0..width)
                            .filter_map(|_| chars.next().map(|(_, c)| c))
                            .collect();
                        if digits.len() != width {
                            return None;
                        }
                        value.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
                    }
                    _ => return None,
                }
            }
            _ => value.push(c),
        }
    }
    None
}

/// Every readable assignment in `text`, in file order. A line [`check`] would refuse is
/// passed over here; the host has already stopped on it before any setting is read.
fn entries(text: &str) -> impl Iterator<Item = (String, String)> + '_ {
    text.lines()
        .filter_map(|line| parse_line(line).ok().flatten())
}

/// The value of `key` in the host config, or `None` if the file or the key is absent.
pub fn get(key: &str) -> Option<String> {
    value_for(&config_text()?, key)
}

/// Every value for `key`, in file order — for settings that legitimately repeat.
///
/// A machine's TOPOLOGY is the motivating case: it has as many mounts as it has peers, and
/// they belong in the config home rather than in a launchd plist, so `git pull` cannot
/// overwrite one machine's identity with another's.
pub fn all(key: &str) -> Vec<String> {
    config_text()
        .map(|text| values_for(&text, key))
        .unwrap_or_default()
}

/// Every `key = value` line whose key begins with `prefix`, in file order, as
/// `(key, value)` — for a family of settings that is validated as a whole, so a misspelled
/// key is reported rather than silently ignored (the `lisp.*` bounds read it).
pub fn entries_under(prefix: &str) -> Vec<(String, String)> {
    config_text()
        .map(|text| entries_under_in(&text, prefix))
        .unwrap_or_default()
}

/// The `(key, value)` lines of `text` whose key begins with `prefix`. See [`value_for`] for
/// the parsing rules.
pub(crate) fn entries_under_in(text: &str, prefix: &str) -> Vec<(String, String)> {
    entries(text)
        .filter(|(name, _)| name.starts_with(prefix))
        .collect()
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
    config_text()
        .map(|text| scoping_instances_in(&text, key))
        .unwrap_or_default()
}

/// The `<instance>` prefixes of every `<instance>.<key>` line in `text`. See
/// [`scoping_instances`].
fn scoping_instances_in(text: &str, key: &str) -> Vec<String> {
    let suffix = format!(".{key}");
    let mut instances: Vec<String> = Vec::new();
    for (name, _) in entries(text) {
        if let Some(instance) = name.strip_suffix(&suffix) {
            if !instance.is_empty() && !instances.iter().any(|i| i == instance) {
                instances.push(instance.to_string());
            }
        }
    }
    instances
}

/// Every `key = value` line for `key`. See [`value_for`] for the parsing rules.
fn values_for(text: &str, key: &str) -> Vec<String> {
    entries(text)
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value)
        .collect()
}

/// The value of the first `key = value` line for `key`, unquoted, with any trailing comment
/// dropped. See [`check`] for the line grammar.
fn value_for(text: &str, key: &str) -> Option<String> {
    entries(text)
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::{
        check_text, config_home, config_home_from, config_path, is_known_key, parse_line,
        peer_cert_dir_in, scoping_instances_in, value_for, values_for,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// `path` as an absolute path on this platform, for the rules that test `is_absolute`.
    fn abs(path: &str) -> OsString {
        if cfg!(windows) {
            format!("C:{path}").into()
        } else {
            path.into()
        }
    }

    /// `XDG_CONFIG_HOME` decides the config home when it is set. The second spelling this
    /// replaced ignored it, and the two agreed everywhere except on the machines that set
    /// it — a divergence the default case cannot show.
    #[test]
    fn xdg_config_home_decides_the_config_home_when_set() {
        assert_eq!(
            config_home_from(Some(abs("/xdg")), Some(abs("/home/b")), None),
            Some(PathBuf::from(abs("/xdg/ikigai")))
        );
        // With no HOME to fall back to, XDG alone still resolves.
        assert_eq!(
            config_home_from(Some(abs("/xdg")), None, None),
            Some(PathBuf::from(abs("/xdg/ikigai")))
        );
    }

    /// Unset — and set-but-empty, which the spec says to read as unset — fall back to
    /// `$HOME/.config`. Empty used to resolve a RELATIVE `ikigai/…`, a config home that
    /// moved with the working directory.
    #[test]
    fn an_unset_or_empty_xdg_falls_back_to_home_config() {
        assert_eq!(
            config_home_from(None, Some(abs("/home/b")), None),
            Some(PathBuf::from(abs("/home/b/.config/ikigai")))
        );
        assert_eq!(
            config_home_from(Some(OsString::new()), Some(abs("/home/b")), None),
            Some(PathBuf::from(abs("/home/b/.config/ikigai")))
        );
    }

    /// `USERPROFILE` is the last resort, consulted only when `HOME` is unset or empty (plain
    /// PowerShell sets it and not `HOME`); `XDG_CONFIG_HOME` and `HOME` both beat it.
    #[test]
    fn userprofile_is_the_last_resort() {
        let profile = || Some(abs("/Users/b"));
        assert_eq!(
            config_home_from(None, None, profile()),
            Some(PathBuf::from(abs("/Users/b/.config/ikigai")))
        );
        assert_eq!(
            config_home_from(None, Some(OsString::new()), profile()),
            Some(PathBuf::from(abs("/Users/b/.config/ikigai")))
        );
        assert_eq!(
            config_home_from(None, Some(abs("/home/b")), profile()),
            Some(PathBuf::from(abs("/home/b/.config/ikigai")))
        );
        assert_eq!(
            config_home_from(Some(abs("/xdg")), None, profile()),
            Some(PathBuf::from(abs("/xdg/ikigai")))
        );
    }

    /// An empty or relative value counts as unset, wherever it appears, so the answer is
    /// absolute or `None` and never moves with the working directory.
    #[test]
    fn an_empty_or_relative_variable_counts_as_unset() {
        for unusable in ["", "rel", "./rel", "../rel"] {
            let bad = || Some(OsString::from(unusable));
            assert_eq!(config_home_from(bad(), None, None), None);
            assert_eq!(config_home_from(None, bad(), None), None);
            assert_eq!(config_home_from(None, None, bad()), None);
            assert_eq!(config_home_from(bad(), bad(), bad()), None);
            assert_eq!(
                config_home_from(bad(), Some(abs("/home/b")), None),
                Some(PathBuf::from(abs("/home/b/.config/ikigai")))
            );
            assert_eq!(
                config_home_from(None, bad(), Some(abs("/Users/b"))),
                Some(PathBuf::from(abs("/Users/b/.config/ikigai")))
            );
        }
    }

    /// Neither base directory known: `None`, so each caller applies its OWN fallback
    /// rather than inheriting one it did not choose.
    #[test]
    fn no_base_directory_at_all_is_none() {
        assert_eq!(config_home_from(None, None, None), None);
        assert_eq!(
            config_path(),
            config_home().map(|home| home.join("config.toml"))
        );
    }

    /// The invariant that actually broke: `config.toml`, `grants.json` and `clients.json`
    /// are SIBLINGS in one directory. Whatever the ambient environment resolves to, a
    /// served kernel must not read its grants from one config home and its settings from
    /// another.
    #[test]
    fn the_config_home_files_are_siblings() {
        // Both retired variables make these lookups refuse, so there is nothing to compare.
        if std::env::var_os("IKIGAI_GRANTS").is_some()
            || std::env::var_os("IKIGAI_CLIENTS").is_some()
        {
            return;
        }
        let Some(home) = config_home() else {
            return; // no HOME and no XDG_CONFIG_HOME: nothing to be a sibling of.
        };
        let grants = crate::grants_path().unwrap();
        let clients = crate::clients::clients_path().unwrap();
        assert_eq!(
            config_path().as_deref().and_then(Path::parent),
            Some(home.as_path())
        );
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

    /// A value reads the way TOML reads it: quotes removed, escapes applied in a basic string
    /// and not in a literal one, and a `#` after the value is a comment, not part of it.
    #[test]
    fn a_line_reads_as_toml_reads_it() {
        let read = |line: &str| parse_line(line).unwrap().unwrap().1;
        assert_eq!(read(r#"files = "/r" # the root"#), "/r");
        assert_eq!(read("files = '/r'# the root"), "/r");
        assert_eq!(read(r#"mail.from = "a#b@c.example""#), "a#b@c.example");
        assert_eq!(
            read(r#"x.y = "say \"hi\" \\ \u00e9""#),
            "say \"hi\" \\ \u{e9}"
        );
        assert_eq!(read(r"x.y = 'C:\Users\b'"), r"C:\Users\b");
        assert_eq!(read("mail.port = 587 # submission"), "587");
        assert_eq!(
            read(r#"mount = "prefer urn:llm:=peer:plasma""#),
            "prefer urn:llm:=peer:plasma"
        );
        assert_eq!(read(r#"x = """#), "");
        for skipped in ["", "   ", "# a comment", "  # indented"] {
            assert_eq!(parse_line(skipped), Ok(None), "{skipped:?}");
        }
        for unreadable in [
            "[mail]",
            "[ipc",
            "just words",
            "= \"x\"",
            "two words = 1",
            "a..b = 1",
            "files =",
            "files = # nothing",
            r#"files = "/r"#,
            r#"files = "/r" trailing"#,
            r#"files = "/r" "/s""#,
            "files = '/r",
            r#"files = "bad \q escape""#,
            r#"files = /r"x"#,
        ] {
            assert!(
                parse_line(unreadable).is_err(),
                "{unreadable:?} must not read"
            );
        }
    }

    /// A key is known as itself, as a member of a validated family, or after an instance
    /// name; anything else is refused by name, on the line it is on.
    #[test]
    fn unknown_keys_are_refused_by_name() {
        for known in [
            "files",
            "serve.files",
            "mount",
            "serve.browse.root",
            "my-box.scheduler",
            "lisp.timeout",
            "lisp.anything",
            "http.upload_grace",
            "http.rate_limit_sources",
            "cache.max_bytes",
        ] {
            assert!(is_known_key(known), "{known}");
        }
        for unknown in [
            "mounts",
            "serve.filez",
            "mail.form",
            "files.x",
            ".files",
            "http.timout",
        ] {
            assert!(!is_known_key(unknown), "{unknown}");
        }
        let err = check_text("# ok\nfiles = \"/r\"\nmounts = \"x\"\n").unwrap_err();
        assert!(err.starts_with("line 3: `mounts`"), "{err}");
        let err = check_text("files = \"/r\"\n[ipc\n").unwrap_err();
        assert!(err.starts_with("line 2: "), "{err}");
        assert_eq!(
            check_text("# only comments\n\nmount = \"a\"\nmount = \"b\"\n"),
            Ok(())
        );
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

    /// The per-peer directory is one entry under the config home, or nothing (ledger #741):
    /// a name that would add segments is refused, never normalized into another peer's.
    #[test]
    fn a_peer_cert_dir_is_one_segment_or_none() {
        let home = Path::new("/c/ikigai");
        assert_eq!(
            peer_cert_dir_in(home, "plasma"),
            Some(PathBuf::from("/c/ikigai/quic-plasma"))
        );
        // Names an announcement may legitimately carry are kept as they are.
        for ok in ["bug-2", "plasma (2)", "..bug", "plasma.local"] {
            let dir = peer_cert_dir_in(home, ok).unwrap_or_else(|| panic!("{ok:?} is one segment"));
            assert_eq!(
                dir.parent(),
                Some(home),
                "{ok:?} stays directly under the home"
            );
        }
        // `.`, `..` and `plasma.` end in a dot, which Windows strips: `quic-plasma.` would
        // open `quic-plasma` there (ledger #1307), and `quic-..` would open `quic-`.
        for bad in [
            "",
            "plasma/../quic-bug",
            "/etc",
            "a/b",
            "a\\b",
            "a\0b",
            "C:x",
            "plasma.",
            "plasma ",
            "..",
            ".",
        ] {
            assert_eq!(
                peer_cert_dir_in(home, bad),
                None,
                "{bad:?} must name no directory"
            );
        }
    }
}
