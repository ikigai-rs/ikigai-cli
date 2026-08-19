//! How the process scheduler is CONFIGURED — the channel ladder, and what it reports.
//!
//! The scheduler decides how wide the host's fan-out actually is, and it used to be
//! settable only through `IKIGAI_SCHEDULER`: an environment variable, the third channel
//! this ecosystem rules out (settings live in the config home and on flags, where they
//! can be read, diffed and version-controlled — an env var is visible only in the
//! environment of an already-running process).
//!
//! That mattered more than tidiness. The default is `single`, and a `Single` scheduler
//! does not spawn: [`Scheduler::spawn`](ikigai_scheduler::Scheduler::spawn) hands back an
//! inline future polled cooperatively on ONE thread. The native HTTP transport is
//! *blocking* `ureq`, so blocking I/O inside a cooperatively-polled future holds that
//! thread to completion — every fan-out (`( a ; b )` forks and `..` maps) runs
//! SEQUENTIALLY at the default width, however wide it looks in the request. Ten
//! concurrent LLM calls measured 17.9s against one backend and 49.3s against another
//! (2026-08-18) — and from outside the process a serialized run and a slow server look
//! identical, which is why the width has to be legible rather than merely settable.
//!
//! So: a `--scheduler` flag, a `scheduler` key in the config home, the environment kept
//! working but deprecated, and — the part an operator actually needs — a `source` row in
//! `urn:kernel:scheduler` naming the channel that decided it.
//!
//! Precedence: **flag > config > env > `single`**.

use std::sync::OnceLock;

use ikigai_scheduler::{Scheduler, SchedulerSpec};

/// The config-home key: `scheduler = "pool:8"` in `config.toml`, instance-scoped as
/// `<instance>.scheduler` (a served kernel and a REPL want different widths, and they
/// read the same file).
pub const CONFIG_KEY: &str = "scheduler";

/// The deprecated environment channel. Still honoured — services in the field may set it
/// — but it warns when it is the channel that decided the value.
pub const ENV_VAR: &str = "IKIGAI_SCHEDULER";

/// Which channel set the scheduler. Reported as the `source` row of
/// `urn:kernel:scheduler`, so "why is this host single-threaded?" is a question the host
/// answers about itself instead of one an operator answers by reading a process's
/// environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerSource {
    /// `--scheduler <spec>` on the command line.
    Flag,
    /// `scheduler` (or `<instance>.scheduler`) in the config home.
    Config,
    /// The deprecated `IKIGAI_SCHEDULER` environment variable.
    Env,
    /// Nothing said anything: the built-in `single`.
    Default,
}

impl SchedulerSource {
    /// The row value: `flag` / `config` / `env` / `default`.
    pub fn as_str(self) -> &'static str {
        match self {
            SchedulerSource::Flag => "flag",
            SchedulerSource::Config => "config",
            SchedulerSource::Env => "env",
            SchedulerSource::Default => "default",
        }
    }
}

/// The `--scheduler` value, declared while argv is being read (first write wins, like
/// [`set_instance_name`](crate::set_instance_name)).
static FLAG_SPEC: OnceLock<String> = OnceLock::new();

/// Declare `--scheduler <single|pool|pool:N>` for this process.
///
/// **Validated here, and an invalid spec is an error rather than a fallback.** A typo'd
/// `--scheduler pool:xyz` silently becoming `single` is the worst outcome available: the
/// operator believes the host is eight-wide and it is one-wide, and nothing in the
/// process contradicts them. The environment channel keeps its lenient warn-and-continue
/// behaviour for compatibility with services already setting it; a flag typed just now
/// does not need that mercy.
///
/// Call before the scheduler is first built (it is built lazily, at the first
/// [`scheduler`] call); a later call is ignored.
pub fn set_scheduler_spec(spec: impl Into<String>) -> Result<(), String> {
    let spec = spec.into();
    spec.parse::<SchedulerSpec>()?;
    let _ = FLAG_SPEC.set(spec);
    Ok(())
}

/// The process scheduler that drives kernel work, and the channel that chose it. Built
/// once and shared — a clone shares the pool — so the kernel's injected spawner, the
/// engine's fan-out and the `urn:kernel:scheduler` reporter are all the same scheduler.
fn resolved() -> &'static (Scheduler, SchedulerSource) {
    static RESOLVED: OnceLock<(Scheduler, SchedulerSource)> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        let decision = decide(
            FLAG_SPEC.get().map(String::as_str),
            config_spec().as_deref(),
            std::env::var(ENV_VAR).ok().as_deref(),
        );
        for warning in &decision.warnings {
            eprintln!("ikigai: {warning}");
        }
        (decision.spec.build(), decision.source)
    })
}

/// The process scheduler (see [`resolved`]). Cheap to clone.
pub fn scheduler() -> Scheduler {
    resolved().0.clone()
}

/// The channel that decided this process's scheduler.
pub fn scheduler_source() -> SchedulerSource {
    resolved().1
}

/// The scheduler setting from the config home: the instance-scoped spelling
/// (`serve.scheduler`) wins over the plain one, the same rule the browse settings use.
/// A daemon and a served kernel are different processes with different fan-out needs
/// reading one file.
fn config_spec() -> Option<String> {
    crate::config::get(&format!("{}.{CONFIG_KEY}", crate::instance_name()))
        .or_else(|| crate::config::get(CONFIG_KEY))
}

/// What the ladder decided, plus anything the operator should be told about it.
struct Decision {
    spec: SchedulerSpec,
    source: SchedulerSource,
    warnings: Vec<String>,
}

/// The channel ladder as a PURE function of the three channels — flag > config > env >
/// `single` — so the precedence is testable without a process, a config file, or
/// `set_var` (which races the test harness's own threads).
///
/// An unparseable value warns and the ladder continues to the next channel: that is the
/// environment's long-standing behaviour, which running services depend on, and applying
/// it uniformly means a broken line in a shared config file degrades rather than bricks
/// a launchd-supervised daemon. The flag never reaches here unparsed — [`set_scheduler_spec`]
/// rejects it at argv time.
fn decide(flag: Option<&str>, config: Option<&str>, env: Option<&str>) -> Decision {
    let mut warnings = Vec::new();
    let channels = [
        (SchedulerSource::Flag, flag, "--scheduler"),
        (SchedulerSource::Config, config, CONFIG_KEY),
        (SchedulerSource::Env, env, ENV_VAR),
    ];
    for (source, value, label) in channels {
        let Some(value) = value else { continue };
        match value.parse::<SchedulerSpec>() {
            Ok(spec) => {
                if source == SchedulerSource::Env {
                    warnings.push(format!(
                        "{ENV_VAR} is deprecated; write `{CONFIG_KEY} = \"{spec}\"` in \
                         {} or pass `--scheduler {spec}`",
                        crate::config::config_path().display()
                    ));
                }
                return Decision {
                    spec,
                    source,
                    warnings,
                };
            }
            Err(e) => warnings.push(format!("{e} (from {label}); ignoring it")),
        }
    }
    Decision {
        spec: SchedulerSpec::Single,
        source: SchedulerSource::Default,
        warnings,
    }
}

/// The `urn:kernel:scheduler` reporter: the scheduler's own live rows plus the `source`
/// row naming the channel that set the backend.
///
/// The kernel renders reporter rows verbatim, so the host adds this without a core
/// change — and the width becomes readable through the same control-plane resource the
/// Control tab already composes.
pub struct ConfiguredScheduler {
    scheduler: Scheduler,
    source: SchedulerSource,
}

impl ikigai_core::SchedulerReporter for ConfiguredScheduler {
    fn rows(&self) -> Vec<(String, String)> {
        let mut rows = ikigai_core::SchedulerReporter::rows(&self.scheduler);
        rows.push(("source".to_string(), self.source.as_str().to_string()));
        rows
    }
}

/// The reporter to inject into the kernel (see [`ConfiguredScheduler`]).
pub fn reporter() -> ConfiguredScheduler {
    let (scheduler, source) = resolved();
    ConfiguredScheduler {
        scheduler: scheduler.clone(),
        source: *source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::SchedulerReporter;

    /// The whole precedence, in one test: each channel beats the ones below it, and the
    /// channel that won says so.
    #[test]
    fn flag_beats_config_beats_env_beats_default() {
        let all = decide(Some("pool:2"), Some("pool:3"), Some("pool:4"));
        assert_eq!(all.spec, SchedulerSpec::Pool(2));
        assert_eq!(all.source, SchedulerSource::Flag);

        let no_flag = decide(None, Some("pool:3"), Some("pool:4"));
        assert_eq!(no_flag.spec, SchedulerSpec::Pool(3));
        assert_eq!(no_flag.source, SchedulerSource::Config);

        let env_only = decide(None, None, Some("pool:4"));
        assert_eq!(env_only.spec, SchedulerSpec::Pool(4));
        assert_eq!(env_only.source, SchedulerSource::Env);

        let nothing = decide(None, None, None);
        assert_eq!(nothing.spec, SchedulerSpec::Single);
        assert_eq!(nothing.source, SchedulerSource::Default);
        assert!(nothing.warnings.is_empty(), "silence when nothing is set");
    }

    /// The environment still works — that is the compatibility promise — but it says it
    /// is deprecated, and ONLY when it is the channel that decided the value: a service
    /// that sets it while a flag or the config overrides it is not nagged about a
    /// setting that had no effect on the width.
    #[test]
    fn the_env_channel_warns_only_when_it_decides() {
        let decided = decide(None, None, Some("pool:4"));
        assert_eq!(decided.warnings.len(), 1);
        assert!(
            decided.warnings[0].contains(ENV_VAR) && decided.warnings[0].contains("deprecated"),
            "{:?}",
            decided.warnings
        );
        // The advice is actionable: it spells the replacement setting.
        assert!(
            decided.warnings[0].contains("pool:4"),
            "{:?}",
            decided.warnings
        );

        let overridden = decide(Some("single"), None, Some("pool:4"));
        assert!(overridden.warnings.is_empty(), "{:?}", overridden.warnings);
    }

    /// An invalid env value warns and falls through, exactly as it did when the variable
    /// was the only channel — a live service with a typo keeps running single-threaded
    /// rather than failing to start.
    #[test]
    fn an_invalid_env_value_warns_and_falls_back() {
        let decision = decide(None, None, Some("pool:xyz"));
        assert_eq!(decision.spec, SchedulerSpec::Single);
        assert_eq!(decision.source, SchedulerSource::Default);
        assert_eq!(decision.warnings.len(), 1);
        assert!(
            decision.warnings[0].contains("pool:xyz"),
            "{:?}",
            decision.warnings
        );
    }

    /// A broken config line degrades to the next channel rather than bricking a
    /// supervised daemon — and the channel that actually decided is reported, not the
    /// one that was ignored.
    #[test]
    fn an_invalid_config_value_falls_through_to_the_env() {
        let decision = decide(None, Some("nonsense"), Some("pool:4"));
        assert_eq!(decision.spec, SchedulerSpec::Pool(4));
        assert_eq!(decision.source, SchedulerSource::Env);
        assert_eq!(decision.warnings.len(), 2, "{:?}", decision.warnings);
    }

    /// The flag is the one channel that must NOT fall back: `--scheduler pool:xyz` is a
    /// user error typed seconds ago, and silently running one-wide while the operator
    /// believes it is eight-wide is invisible from outside the process.
    #[test]
    fn an_invalid_flag_value_is_an_error() {
        let e = set_scheduler_spec("pool:xyz").expect_err("a typo'd flag must not be accepted");
        assert!(e.contains("pool:xyz"), "{e}");
        assert!(set_scheduler_spec("nonsense").is_err());
        // Deliberately NOT asserting that a valid spec is accepted here: a successful
        // call arms a process-global OnceLock, which would reach into every other test
        // in this binary. The accepted spellings are pinned in `ikigai-scheduler`.
    }

    /// The reporter carries the deciding channel into `urn:kernel:scheduler` alongside
    /// the backend and width — the row an operator reads to see the fan-out.
    #[test]
    fn the_reporter_adds_the_deciding_channel_as_a_row() {
        let reporter = ConfiguredScheduler {
            scheduler: SchedulerSpec::Pool(3).build(),
            source: SchedulerSource::Config,
        };
        let rows = reporter.rows();
        assert!(rows.contains(&("backend".to_string(), "pool:3".to_string())));
        assert!(rows.contains(&("threads".to_string(), "3".to_string())));
        assert_eq!(
            rows.last(),
            Some(&("source".to_string(), "config".to_string()))
        );
    }
}
