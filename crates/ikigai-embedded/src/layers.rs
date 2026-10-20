//! The layer host a served QUIC door links (`ikigai-layers`, ledger #1188).
//!
//! **The switch is a directory.** When the config home holds `layers/`, `serve quic://` opens
//! an [`ikigai_layers::Host`] over the config home (the layer definitions under `layers/`,
//! `participants.ttl`, `collabs/*.toml`) and a STATE directory, and binds
//! [`ikigai_layers::space`], alone, on a kernel with a clock. Without `layers/` nothing here
//! runs, and the served kernel is built exactly as before.
//!
//! **Where the state lives** — config home for the setting, data home for the bytes, and no
//! environment variable names either (the store's rule, `store.rs`):
//!
//! 1. `--layers-state <dir>` on `serve` ([`StateSource::Flag`]), relative to the working
//!    directory;
//! 2. `<instance>.layers.state` in the config home's `config.toml`, else `layers.state`
//!    ([`StateSource::Config`]), relative to the config home;
//! 3. `<data home>/layers/<instance>`, i.e. `~/.ikigai/layers/<instance>`
//!    ([`StateSource::Default`]).
//!
//! **The state is sealed at rest** (ikigai-layers 0.3.0, ledger #2011): every file the host
//! writes is age ciphertext sealed to the host's key, an age identity FILE (`age-keygen -o`)
//! whose path comes from
//!
//! 1. `--layers-key <path>` on `serve` ([`KeySource::Flag`]), relative to the working directory;
//! 2. `<instance>.layers.key` in the config home's `config.toml`, else `layers.key`
//!    ([`KeySource::Config`]), relative to the config home.
//!
//! There is no default and no environment variable: a door that hosts layers and is given no
//! key refuses to start, naming the flag, and never serves its state unsealed. A path, not the
//! key itself, so a deployment can hand the file over from an in-memory credential store
//! (systemd's `LoadCredentialEncrypted`). A wrong key is refused at open, before anything is
//! read. A state directory written before 0.3.0 holds plaintext, and the host refuses it until
//! ONE start with `--layers-reseal` ([`ikigai_layers::Migration::Reseal`]) seals it in place;
//! that start then serves normally, and running it again is safe (it resumes an interrupted
//! run, and over a sealed directory it changes nothing). The same flag rotates the key: put
//! the new identity FIRST in the file, keep the old one after it, start once with
//! `--layers-reseal`, then drop the old line.
//!
//! The default is per INSTANCE because a layer host is one host per state directory, and the
//! host enforces it: [`ikigai_layers::Host::open`] holds `<state>/host.lock` exclusively while
//! the host lives and refuses a second host over the same directory, in this process or
//! another, naming the holder's pid. So two doors with different `--name`s reading one config
//! home get two directories, and anything that reopens a host (a test, a reload) drops the old
//! one first. The operating system releases the lock when the holder exits, however it exits.
//!
//! **Admission is the host's own call, so the door binds no validator** (ledger #1295,
//! ikigai-layers 0.2.1). The host links ikigai-shacl and validates every `say` and `out`
//! itself; a layer whose shapes the validator cannot compile stops the host at [`open`]. Until
//! 0.2.1 admission composed `urn:shacl:validate`, so this door bound it beside the layers, and
//! that endpoint declares no capability: every participant was offered a validator. It is not
//! bound here any more, and `tests/layers_serve.rs` holds every participant's manifold to that.
//!
//! **Who writes is the door's business.** Participants are the config home's `clients.json` /
//! `grants.json`, as `ikigai-layers grants <config home>` generates them: each certificate's
//! entry names its grant (`urn:cap:layer:{verb}:{layer}` scopes) and its `principal` (the
//! participant's IRI), which the door mints into the connection's capability exactly as it
//! does for every other client ([`crate::clients`]). Nothing here reads either file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_core::{EndpointSpace, Iri, Space, SystemClock};

/// The directory under the config home whose presence switches the layer host on.
pub const DIR: &str = "layers";

/// The config-home key naming the state directory, instance-scoped as
/// `<instance>.layers.state`. A relative path is resolved against the config home; `~/`
/// against `$HOME`.
pub const STATE_KEY: &str = "layers.state";

/// The flag naming the state directory, on `serve quic://`.
pub const STATE_FLAG: &str = "--layers-state";

/// The config-home key naming the host's age identity file, instance-scoped as
/// `<instance>.layers.key`. A relative path is resolved against the config home; `~/` against
/// `$HOME`.
pub const KEY_KEY: &str = "layers.key";

/// The flag naming the host's age identity file, on `serve quic://`.
pub const KEY_FLAG: &str = "--layers-key";

/// The one-time flag that seals a state directory written before ikigai-layers 0.3.0 in place
/// (and rotates the key), on `serve quic://`: [`ikigai_layers::Migration::Reseal`].
pub const RESEAL_FLAG: &str = "--layers-reseal";

/// The name the served root gives the layer space: the space answers what its host was
/// handed, so it claims no name of its own and the host names it (core's `SPACE-NAME` rule).
pub const SPACE: &str = "urn:ikigai:space:served:layers";

/// Which channel named the state directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateSource {
    /// `--layers-state <dir>`.
    Flag,
    /// `layers.state` (or `<instance>.layers.state`) in the config home.
    Config,
    /// Neither: `<data home>/layers/<instance>`.
    Default,
}

impl StateSource {
    /// `flag` / `config` / `default`, as the banner says it.
    pub fn as_str(self) -> &'static str {
        match self {
            StateSource::Flag => "flag",
            StateSource::Config => "config",
            StateSource::Default => "default",
        }
    }
}

/// Which channel named the host's key file. There is no default: see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// `--layers-key <path>`.
    Flag,
    /// `layers.key` (or `<instance>.layers.key`) in the config home.
    Config,
}

impl KeySource {
    /// `flag` / `config`, as the banner says it.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Flag => "flag",
            KeySource::Config => "config",
        }
    }
}

/// What `serve quic://` was told about the layer host, every flag already absolute.
#[derive(Clone, Copy, Debug, Default)]
pub struct Flags<'a> {
    /// `--layers-state <dir>`.
    pub state: Option<&'a Path>,
    /// `--layers-key <path>`.
    pub key: Option<&'a Path>,
    /// `--layers-reseal`.
    pub reseal: bool,
}

impl Flags<'_> {
    /// The flags given, by name, for a refusal that says which ones do nothing.
    fn given(&self) -> Vec<&'static str> {
        let mut given = Vec::new();
        if self.state.is_some() {
            given.push(STATE_FLAG);
        }
        if self.key.is_some() {
            given.push(KEY_FLAG);
        }
        if self.reseal {
            given.push(RESEAL_FLAG);
        }
        given
    }
}

/// An opened layer host and where it came from.
pub struct Hosted {
    /// The host [`ikigai_layers::space`] binds.
    pub host: Arc<ikigai_layers::Host>,
    /// The config home it was opened over (its `layers/` holds the definitions).
    pub config: PathBuf,
    /// The state directory it writes.
    pub state: PathBuf,
    /// Which channel named [`state`](Self::state).
    pub source: StateSource,
    /// The age identity file the state is sealed with.
    pub key: PathBuf,
    /// Which channel named [`key`](Self::key).
    pub key_source: KeySource,
    /// The recipient (`age1…`, public) every state file is sealed to now.
    pub recipient: String,
    /// Whether this open sealed the state in place (`--layers-reseal`).
    pub resealed: bool,
}

impl Hosted {
    /// One banner line per layer: `talk (channel)`, `tasks-bobby (tuplespace)`.
    pub fn layer_lines(&self) -> Vec<String> {
        self.host
            .layers()
            .iter()
            .map(|(name, state)| format!("{name} ({})", state.def.model.as_str()))
            .collect()
    }
}

/// `<config home>/layers/` when it is a directory: the switch.
pub fn configured() -> Option<PathBuf> {
    configured_in(&crate::config::config_home()?)
}

/// [`configured`] for an explicit config home.
pub fn configured_in(home: &Path) -> Option<PathBuf> {
    let dir = home.join(DIR);
    dir.is_dir().then_some(dir)
}

/// Where the state lives, by the precedence in the module docs. `flag` is `--layers-state`,
/// already absolute (the binary absolutizes what was typed).
pub fn state_dir(flag: Option<&Path>) -> Result<(PathBuf, StateSource), String> {
    let instance = crate::instance_name();
    let configured = crate::config::get(&format!("{instance}.{STATE_KEY}"))
        .or_else(|| crate::config::get(STATE_KEY));
    state_dir_from(
        flag,
        configured.as_deref(),
        crate::config::config_home().as_deref(),
        std::env::var_os("HOME").as_deref().map(Path::new),
        instance,
    )
}

/// [`state_dir`] with every input passed in, so the precedence is testable without touching
/// the process environment.
pub fn state_dir_from(
    flag: Option<&Path>,
    configured: Option<&str>,
    config_home: Option<&Path>,
    home: Option<&Path>,
    instance: &str,
) -> Result<(PathBuf, StateSource), String> {
    if let Some(dir) = flag {
        return Ok((dir.to_path_buf(), StateSource::Flag));
    }
    if let Some(value) = configured.map(str::trim).filter(|v| !v.is_empty()) {
        // The workspace's one `~` rule (ledger #1379): a `~` it cannot expand is refused
        // here, by key, rather than resolved against the config home as a directory named `~`.
        let path = ikigai_resolve::expand_home(value, home)
            .map_err(|e| format!("`{STATE_KEY}` in the config home: {e}"))?;
        let path = match config_home {
            Some(base) if path.is_relative() => base.join(path),
            _ => path,
        };
        return Ok((path, StateSource::Config));
    }
    let home = home.filter(|h| !h.as_os_str().is_empty()).ok_or_else(|| {
        format!(
            "layers are configured but no state directory is: pass {STATE_FLAG} <dir>, set \
             `{STATE_KEY}` in the config home, or set HOME so the default \
             (~/.ikigai/layers/{instance}) has somewhere to be"
        )
    })?;
    Ok((
        ikigai_core::config::data_home_in(home)
            .join("layers")
            .join(instance),
        StateSource::Default,
    ))
}

/// Where the host's age identity file is, by the precedence in the module docs. `flag` is
/// `--layers-key`, already absolute (the binary absolutizes what was typed).
pub fn key_path(flag: Option<&Path>) -> Result<(PathBuf, KeySource), String> {
    let instance = crate::instance_name();
    let configured = crate::config::get(&format!("{instance}.{KEY_KEY}"))
        .or_else(|| crate::config::get(KEY_KEY));
    key_path_from(
        flag,
        configured.as_deref(),
        crate::config::config_home().as_deref(),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
}

/// [`key_path`] with every input passed in, so the precedence is testable without touching
/// the process environment. Neither channel naming a key is refused, naming both: a door
/// that hosts layers never serves their state unsealed.
pub fn key_path_from(
    flag: Option<&Path>,
    configured: Option<&str>,
    config_home: Option<&Path>,
    home: Option<&Path>,
) -> Result<(PathBuf, KeySource), String> {
    if let Some(path) = flag {
        return Ok((path.to_path_buf(), KeySource::Flag));
    }
    if let Some(value) = configured.map(str::trim).filter(|v| !v.is_empty()) {
        let path = ikigai_resolve::expand_home(value, home)
            .map_err(|e| format!("`{KEY_KEY}` in the config home: {e}"))?;
        let path = match config_home {
            Some(base) if path.is_relative() => base.join(path),
            _ => path,
        };
        return Ok((path, KeySource::Config));
    }
    Err(format!(
        "layers are configured, and their state is sealed at rest with the host's key, but no \
         key is named: pass {KEY_FLAG} <file> or set `{KEY_KEY}` in the config home. The file \
         is an age identity, as `age-keygen -o <file>` writes one; no environment variable \
         names it, and the host does not serve its state unsealed"
    ))
}

/// Open the layer host when the config home configures one: `Ok(None)` without `layers/`
/// (and then no flag may be given: a state directory, a key or a reseal for layers nobody
/// configured is a flag that does nothing, and is refused rather than ignored).
pub fn open(flags: Flags<'_>) -> Result<Option<Hosted>, String> {
    let given = flags.given();
    let Some(home) = crate::config::config_home() else {
        return match given.is_empty() {
            false => Err(format!(
                "{} need{} a config home holding `{DIR}/`",
                given.join(" and "),
                if given.len() == 1 { "s" } else { "" }
            )),
            true => Ok(None),
        };
    };
    if configured_in(&home).is_none() {
        return match given.is_empty() {
            false => Err(format!(
                "{} appl{} to a door that hosts layers, but {} does not exist, so no layer is \
                 configured",
                given.join(" and "),
                if given.len() == 1 { "ies" } else { "y" },
                home.join(DIR).display()
            )),
            true => Ok(None),
        };
    }
    let (state, source) = state_dir(flags.state)?;
    let (key, key_source) = key_path(flags.key)?;
    let opened = ikigai_layers::StateKey::load(&key).map_err(|e| e.to_string())?;
    let migration = if flags.reseal {
        ikigai_layers::Migration::Reseal
    } else {
        ikigai_layers::Migration::None
    };
    let host = ikigai_layers::Host::open_with(&home, &state, &opened, migration).map_err(|e| {
        // The library names its option; this door's operator holds a flag.
        let e = e.to_string();
        let hint = if !flags.reseal && e.contains("Migration::Reseal") {
            format!(
                ". For this door: start it ONCE with {RESEAL_FLAG} beside the same key, which \
                 seals them in place and then serves"
            )
        } else {
            String::new()
        };
        format!(
            "layers are configured in {} but the host cannot open: {e}{hint}",
            home.join(DIR).display()
        )
    })?;
    Ok(Some(Hosted {
        host,
        config: home,
        state,
        source,
        recipient: opened.recipient(),
        key,
        key_source,
        resealed: flags.reseal,
    }))
}

/// The spaces a hosting kernel binds: the layer space, alone. Admission validates inside the
/// host, so no validator is bound beside it (see the module docs).
pub fn spaces(host: &Arc<ikigai_layers::Host>) -> Vec<Arc<dyn Space>> {
    let layers: EndpointSpace = ikigai_layers::space(host)
        .named(Iri::parse(SPACE).expect("the layer space's name is an IRI"));
    vec![Arc::new(layers) as Arc<dyn Space>]
}

/// The clock a hosting kernel carries: every entry, tuple and receipt is stamped with the
/// kernel's time, and a layer refuses a write when it has none.
pub fn clock() -> Arc<dyn ikigai_core::Clock> {
    Arc::new(SystemClock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_wins_then_the_config_home_then_the_data_home() {
        let flag = Path::new("/srv/flagged");
        let home = Path::new("/home/b");
        let config = Path::new("/home/b/.config/ikigai");
        assert_eq!(
            state_dir_from(
                Some(flag),
                Some("ignored"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((flag.to_path_buf(), StateSource::Flag))
        );
        // Relative to the config home, `~/` to HOME, absolute as written.
        assert_eq!(
            state_dir_from(None, Some("state"), Some(config), Some(home), "layers"),
            Ok((config.join("state"), StateSource::Config))
        );
        assert_eq!(
            state_dir_from(
                None,
                Some("~/layer-state"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((home.join("layer-state"), StateSource::Config))
        );
        assert_eq!(
            state_dir_from(
                None,
                Some("/var/layers"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((PathBuf::from("/var/layers"), StateSource::Config))
        );
        // The default is per instance, under the data home.
        assert_eq!(
            state_dir_from(None, None, Some(config), Some(home), "layers"),
            Ok((home.join(".ikigai/layers/layers"), StateSource::Default))
        );
        assert_eq!(
            state_dir_from(None, Some("  "), Some(config), Some(home), "edge"),
            Ok((home.join(".ikigai/layers/edge"), StateSource::Default)),
            "a blank setting is no setting"
        );
        let err = state_dir_from(None, None, Some(config), None, "layers").unwrap_err();
        assert!(err.contains(STATE_FLAG) && err.contains(STATE_KEY), "{err}");
    }

    /// ledger #1379: the state key takes the workspace's one `~` rule. A bare `~` is the
    /// home; another user's `~name` and a `~` with no home are refused naming the key,
    /// where before they became a directory named `~…` under the config home.
    #[test]
    fn the_state_key_takes_the_shared_tilde_rule() {
        let home = Path::new("/home/b");
        let config = Path::new("/home/b/.config/ikigai");
        assert_eq!(
            state_dir_from(None, Some("~"), Some(config), Some(home), "layers"),
            Ok((home.to_path_buf(), StateSource::Config))
        );
        let err =
            state_dir_from(None, Some("~bob/s"), Some(config), Some(home), "layers").unwrap_err();
        assert!(
            err.contains(STATE_KEY) && err.contains("another user's home"),
            "{err}"
        );
        let err = state_dir_from(None, Some("~/s"), Some(config), None, "layers").unwrap_err();
        assert!(
            err.contains(STATE_KEY) && err.contains("HOME is not set"),
            "{err}"
        );
    }

    /// ledger #2011: the key comes from the flag, then the config home, and from nowhere else.
    /// No channel naming one is a refusal that names both, never a host that serves unsealed.
    #[test]
    fn the_key_is_the_flag_then_the_config_home_and_never_a_default() {
        let flag = Path::new("/run/credentials/edge/layers.key");
        let home = Path::new("/home/b");
        let config = Path::new("/home/b/.config/ikigai");
        assert_eq!(
            key_path_from(Some(flag), Some("ignored"), Some(config), Some(home)),
            Ok((flag.to_path_buf(), KeySource::Flag))
        );
        assert_eq!(
            key_path_from(None, Some("layers.key"), Some(config), Some(home)),
            Ok((config.join("layers.key"), KeySource::Config))
        );
        assert_eq!(
            key_path_from(None, Some("~/keys/l.key"), Some(config), Some(home)),
            Ok((home.join("keys/l.key"), KeySource::Config))
        );
        assert_eq!(
            key_path_from(None, Some("/etc/l.key"), Some(config), Some(home)),
            Ok((PathBuf::from("/etc/l.key"), KeySource::Config))
        );
        for configured in [None, Some(""), Some("   ")] {
            let err = key_path_from(None, configured, Some(config), Some(home)).unwrap_err();
            assert!(
                err.contains(KEY_FLAG) && err.contains(KEY_KEY) && err.contains("age-keygen"),
                "{configured:?}: {err}"
            );
        }
        let err = key_path_from(None, Some("~bob/k"), Some(config), Some(home)).unwrap_err();
        assert!(err.contains(KEY_KEY), "{err}");
    }

    #[test]
    fn only_a_directory_switches_the_host_on() {
        let dir = std::env::temp_dir().join(format!("iki-layers-switch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(configured_in(&dir), None);
        std::fs::write(dir.join(DIR), "not a directory").unwrap();
        assert_eq!(
            configured_in(&dir),
            None,
            "a FILE named layers is not a configuration"
        );
        std::fs::remove_file(dir.join(DIR)).unwrap();
        std::fs::create_dir(dir.join(DIR)).unwrap();
        assert_eq!(configured_in(&dir), Some(dir.join(DIR)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
