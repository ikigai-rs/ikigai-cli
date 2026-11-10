//! The spam filter the local root binds (`ikigai-bayes`, ledger #1512): `urn:bayes:{model}:score`,
//! `…:train`, `…:untrain`, `…:stats` and `urn:bayes:models`, over a state directory this host
//! names.
//!
//! **The switch is a state directory AND at least one model.** Both come from flags or the config
//! home, and no environment variable names either:
//!
//! 1. `--bayes-state <dir>` (made absolute against the working directory), else
//!    `<instance>.bayes.state`, else `bayes.state` in `config.toml` (relative to the config home,
//!    a leading `~` to `$HOME`);
//! 2. `--bayes-model <name>` (repeatable), else every `<instance>.bayes.models` line, else every
//!    `bayes.models` line. A line may name several models, separated by commas or spaces.
//!
//! With neither half nothing is opened and nothing is bound: the host is exactly what it was. One
//! half without the other is REFUSED at startup rather than ignored, because a state directory
//! with no model (or a model with nowhere to live) is a setting that does nothing, and an
//! operator who wrote it believes otherwise.
//!
//! **One writer per state directory, and so one process.** [`ikigai_bayes::Bayes::open`] holds
//! `<state>/LOCK` exclusively for the life of the process and refuses a second writer, in this
//! process or another, naming the holder's pid. So the model is opened ONCE per process
//! ([`arm`], memoized in `OPENED`) and every kernel the process builds gets an `Arc` of the one
//! space; and a second process over the same directory stops at startup with the holder's pid
//! ([`arm`] returns the refusal, and the binary exits 2). ⚠ The config home is shared by every
//! process on the machine: an unscoped `bayes.state` + `bayes.models` pair makes EVERY local-root
//! process (a REPL, a `-c`, an MCP server) open the model, and the second one refuses to start.
//! Name the holder: the `--bayes-*` flags on its unit, or the `<instance>.` keys.
//!
//! **Only the local root binds it, and only when the binary arms it.** [`arm`] is called by the
//! modes that build the local root (the REPL and `-c`, `--daemon`, `mcp`, `serve <socket>`); a
//! served door (`serve quic://…`, `serve --http`) never calls it, so even its route loader's
//! `kernel()` binds nothing here, and the binary refuses the flags beside such a door by name.
//! The public HTTP face must never hold the model: a training click there becomes a dropped
//! tuple the daemon applies.
//!
//! **Authority is the model's own.** Each model's doors declare `urn:cap:bayes:read:{model}`
//! (score, stats) and `urn:cap:bayes:train:{model}` (train, untrain); `urn:bayes:models` needs
//! none. Nothing here grants them: the REPL's root session holds them as it holds everything,
//! and a reactive space's handler holds them when the host's
//! `<config home>/space-authority/<space>` file lists them.
//!
//! **The state directory is as sensitive as the messages** (it keeps every trained message's
//! token set, which is what makes untraining exact), so a missing one is CREATED at mode 0700,
//! and an existing one that group or others can read is reported on stderr.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ikigai_core::{ArgRef, EndpointSpace, Iri, Kernel, Request, Space, Verb};

/// The flag naming the state directory.
pub const STATE_FLAG: &str = "--bayes-state";

/// The flag naming one model (repeatable).
pub const MODEL_FLAG: &str = "--bayes-model";

/// The config-home key naming the state directory, instance-scoped as `<instance>.bayes.state`.
pub const STATE_KEY: &str = "bayes.state";

/// The config-home key naming the models, instance-scoped as `<instance>.bayes.models`.
pub const MODELS_KEY: &str = "bayes.models";

/// The name the local root gives the bayes space. The space answers for the models its host
/// opened, so it claims no name of its own and the host names it (core's `SPACE-NAME` rule), as
/// [`crate::layers::SPACE`] is named for the layer host.
pub const SPACE: &str = "urn:ikigai:space:bayes";

/// What the flags said, set by the binary before any mode arms. See [`set_flags`].
static FLAGS: Mutex<Option<Flags>> = Mutex::new(None);

/// The one open, memoized for the life of the process: `None` inside = not configured.
static OPENED: OnceLock<Option<Opened>> = OnceLock::new();

#[derive(Clone, Debug, Default)]
struct Flags {
    state: Option<PathBuf>,
    models: Vec<String>,
}

/// Which channel named a half of the setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--bayes-state` / `--bayes-model`.
    Flag,
    /// The config home's `bayes.*` keys (scoped or not).
    Config,
}

impl Source {
    /// `flag` / `config`, as the startup line says it.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Config => "config",
        }
    }
}

/// Where the model lives and which models are offered, once both halves are known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The state directory, absolute when it came from the flag.
    pub state: PathBuf,
    /// Which channel named [`state`](Self::state).
    pub state_source: Source,
    /// The model names, in the order given.
    pub models: Vec<String>,
    /// Which channel named [`models`](Self::models).
    pub models_source: Source,
}

/// An opened model set, its space, and the startup line.
struct Opened {
    space: Arc<dyn Space>,
    line: String,
}

/// Record the `--bayes-state` and `--bayes-model` flags for this process. Read by [`arm`]; a
/// later call replaces the earlier one (the binary calls it once, while parsing argv).
pub fn set_flags(state: Option<PathBuf>, models: Vec<String>) {
    *FLAGS.lock().expect("bayes flags lock") = Some(Flags { state, models });
}

/// Were either of the flags given? For a door that builds no local root, which refuses them
/// rather than ignoring them.
pub fn flags_given() -> bool {
    FLAGS
        .lock()
        .expect("bayes flags lock")
        .as_ref()
        .is_some_and(|f| f.state.is_some() || !f.models.is_empty())
}

/// Open the models this process is configured for, once, and return the startup line (`None`
/// when nothing is configured). Every later call answers the first call's outcome without
/// reopening anything; a refusal (half a setting, a held directory, a model file that will not
/// load) is returned as the message the binary prints before it exits.
pub fn arm() -> Result<Option<String>, String> {
    // A failed open is not memoized: the binary exits on it, and a test that wants to see it
    // again sees the same refusal rather than a stale "nothing configured".
    if let Some(opened) = OPENED.get() {
        return Ok(opened.as_ref().map(|o| o.line.clone()));
    }
    let flags = FLAGS
        .lock()
        .expect("bayes flags lock")
        .clone()
        .unwrap_or_default();
    let instance = crate::instance_name();
    let config_state = crate::config::get(&format!("{instance}.{STATE_KEY}"))
        .or_else(|| crate::config::get(STATE_KEY));
    let mut config_models = crate::config::all(&format!("{instance}.{MODELS_KEY}"));
    if config_models.is_empty() {
        config_models = crate::config::all(MODELS_KEY);
    }
    let setting = setting_from(
        flags.state.as_deref(),
        &flags.models,
        config_state.as_deref(),
        &config_models,
        crate::config::config_home().as_deref(),
        crate::config::user_home().as_deref(),
    )?;
    let opened = match setting {
        None => None,
        Some(setting) => Some(open(&setting)?),
    };
    let line = opened.as_ref().map(|o| o.line.clone());
    // Two threads arming at once would both open, and the second open refuses on the lock; the
    // binary arms once, on its main thread, before any kernel exists.
    let _ = OPENED.set(opened);
    Ok(line)
}

/// The bayes space, when this process armed one. `None` otherwise, and always `None` in a
/// process that never called [`arm`] (a served door, a test binary that did not arm).
pub(crate) fn space() -> Option<Arc<dyn Space>> {
    OPENED
        .get()
        .and_then(|opened| opened.as_ref().map(|o| Arc::clone(&o.space)))
}

/// [`arm`]'s precedence with every input passed in, so it is testable without the process
/// environment. `Ok(None)` = neither half is set anywhere.
pub fn setting_from(
    flag_state: Option<&Path>,
    flag_models: &[String],
    config_state: Option<&str>,
    config_models: &[String],
    config_home: Option<&Path>,
    home: Option<&Path>,
) -> Result<Option<Setting>, String> {
    let state = match (
        flag_state,
        config_state.map(str::trim).filter(|v| !v.is_empty()),
    ) {
        (Some(dir), _) => Some((dir.to_path_buf(), Source::Flag)),
        (None, Some(value)) => {
            // The workspace's one `~` rule (ledger #1379), refused by key when it cannot expand.
            let path = ikigai_resolve::expand_home(value, home)
                .map_err(|e| format!("`{STATE_KEY}` in the config home: {e}"))?;
            let path = match config_home {
                Some(base) if path.is_relative() => base.join(path),
                _ => path,
            };
            Some((path, Source::Config))
        }
        (None, None) => None,
    };
    let models = if !flag_models.is_empty() {
        Some((flag_models.to_vec(), Source::Flag))
    } else {
        let named: Vec<String> = config_models
            .iter()
            .flat_map(|line| line.split([',', ' ', '\t']))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(String::from)
            .collect();
        (!named.is_empty()).then_some((named, Source::Config))
    };
    match (state, models) {
        (None, None) => Ok(None),
        (Some((state, state_source)), Some((models, models_source))) => Ok(Some(Setting {
            state,
            state_source,
            models,
            models_source,
        })),
        (Some((state, _)), None) => Err(format!(
            "bayes: a state directory is named ({}) but no model is: pass {MODEL_FLAG} <name> \
             (repeatable) or set `{MODELS_KEY}` in the config home. With no model named, \
             nothing is opened",
            state.display()
        )),
        (None, Some((models, _))) => Err(format!(
            "bayes: model{} {} named but no state directory is: pass {STATE_FLAG} <dir> or set \
             `{STATE_KEY}` in the config home",
            if models.len() == 1 { " is" } else { "s are" },
            models.join(", ")
        )),
    }
}

/// Open the state directory (creating it at 0700 when it is missing), bind the space, and build
/// the startup line from each model's own stats.
fn open(setting: &Setting) -> Result<Opened, String> {
    prepare_dir(&setting.state)?;
    let bayes = ikigai_bayes::Bayes::open(
        &setting.state,
        setting
            .models
            .iter()
            .map(|name| ikigai_bayes::ModelConfig::new(name.as_str())),
    )
    .map_err(|e| format!("bayes: {e}"))?;
    let space: EndpointSpace = ikigai_bayes::space(&bayes)
        .named(Iri::parse(SPACE).expect("the bayes space's name is an IRI"));
    let space: Arc<dyn Space> = Arc::new(space);
    let counts = setting
        .models
        .iter()
        .map(|name| model_counts(&space, name).map(|(spam, ham)| (name.as_str(), spam, ham)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Opened {
        line: startup_line(&counts, &setting.state, setting.state_source),
        space,
    })
}

/// `ikigai: bayes: contact (3 messages: 2 spam, 1 ham) — state in <dir> (flag)`: one line,
/// every model in the order named.
pub fn startup_line(counts: &[(&str, u64, u64)], state: &Path, source: Source) -> String {
    let models: Vec<String> = counts
        .iter()
        .map(|(name, spam, ham)| {
            format!("{name} ({} messages: {spam} spam, {ham} ham)", spam + ham)
        })
        .collect();
    format!(
        "ikigai: bayes: {} — state in {} ({})",
        models.join(", "),
        state.display(),
        source.as_str()
    )
}

/// One model's (spam, ham) message counts, read through its own `stats` door as root: the
/// counts are the module's to derive, never this host's to recompute from its file.
fn model_counts(space: &Arc<dyn Space>, model: &str) -> Result<(u64, u64), String> {
    let kernel = Kernel::new(Arc::clone(space));
    let iri = Iri::parse(ikigai_bayes::model_iri(model, "stats"))
        .map_err(|e| format!("bayes: model `{model}`: {e}"))?;
    let request = Request::new(Verb::Source, iri)
        .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
    let (rep, _) = ikigai_resolve::Resolver::issue(&kernel, request)
        .map_err(|e| format!("bayes: model `{model}`: its stats did not resolve: {e}"))?;
    let stats: serde_json::Value = serde_json::from_slice(&rep.bytes)
        .map_err(|e| format!("bayes: model `{model}`: its stats are not JSON: {e}"))?;
    let count = |label: &str| {
        stats["messages"][label]
            .as_u64()
            .ok_or_else(|| format!("bayes: model `{model}`: its stats carry no {label} count"))
    };
    Ok((count("spam")?, count("ham")?))
}

/// Create a missing state directory at mode 0700 (and any missing parents with it); report an
/// existing one whose mode lets group or others in. Never loosens or tightens an existing mode:
/// that is the operator's.
fn prepare_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(dir)
            .map_err(|e| format!("bayes: create the state directory {}: {e}", dir.display()))?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "ikigai: bayes: the state directory {} is mode {mode:o}; it holds the token \
                     set of every trained message, so 700 is what it wants (chmod 700 {})",
                    dir.display(),
                    dir.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn nothing_named_is_nothing_bound() {
        assert_eq!(setting_from(None, &[], None, &[], None, None), Ok(None));
        assert_eq!(
            setting_from(None, &[], Some("  "), &s(&["", " "]), None, None),
            Ok(None),
            "a blank setting is no setting"
        );
    }

    #[test]
    fn the_flags_win_then_the_config_home() {
        let config = Path::new("/home/b/.config/ikigai");
        let home = Path::new("/home/b");
        let got = setting_from(
            Some(Path::new("/srv/bayes")),
            &s(&["contact"]),
            Some("ignored"),
            &s(&["other"]),
            Some(config),
            Some(home),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.state, PathBuf::from("/srv/bayes"));
        assert_eq!(got.state_source, Source::Flag);
        assert_eq!(got.models, s(&["contact"]));
        assert_eq!(got.models_source, Source::Flag);

        // Relative to the config home, `~/` to HOME; a line may name several models.
        let got = setting_from(
            None,
            &[],
            Some("bayes"),
            &s(&["contact, other", "third"]),
            Some(config),
            Some(home),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.state, config.join("bayes"));
        assert_eq!(got.state_source, Source::Config);
        assert_eq!(got.models, s(&["contact", "other", "third"]));
        assert_eq!(got.models_source, Source::Config);
        let got = setting_from(
            None,
            &[],
            Some("~/.ikigai/bayes"),
            &s(&["contact"]),
            Some(config),
            Some(home),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.state, home.join(".ikigai/bayes"));

        // Each half is taken from its own channel.
        let got = setting_from(
            Some(Path::new("/srv/bayes")),
            &[],
            None,
            &s(&["contact"]),
            Some(config),
            Some(home),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (got.state_source, got.models_source),
            (Source::Flag, Source::Config)
        );
    }

    #[test]
    fn half_a_setting_is_refused_by_name() {
        let err =
            setting_from(Some(Path::new("/srv/bayes")), &[], None, &[], None, None).unwrap_err();
        assert!(
            err.contains(MODEL_FLAG) && err.contains(MODELS_KEY),
            "{err}"
        );
        let err = setting_from(None, &s(&["contact"]), None, &[], None, None).unwrap_err();
        assert!(
            err.contains(STATE_FLAG) && err.contains(STATE_KEY) && err.contains("contact"),
            "{err}"
        );
        let err =
            setting_from(None, &[], Some("~bob/x"), &s(&["contact"]), None, None).unwrap_err();
        assert!(err.contains(STATE_KEY), "{err}");
    }

    #[test]
    fn the_startup_line_names_every_model_and_the_state() {
        assert_eq!(
            startup_line(
                &[("contact", 2, 1), ("other", 0, 0)],
                Path::new("/srv/bayes"),
                Source::Flag
            ),
            "ikigai: bayes: contact (3 messages: 2 spam, 1 ham), other (0 messages: 0 spam, 0 \
             ham) — state in /srv/bayes (flag)"
        );
    }
}
