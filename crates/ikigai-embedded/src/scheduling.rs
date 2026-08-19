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
//!
//! The width the scheduler permits is also what a fan-out may *route* on: at two or more
//! effectively-concurrent requests, the engine can append `needs=batchAt<=W` so a backend
//! is chosen by the load shape rather than by a caller's guess (see
//! `ikigai_engine::fanout`). That is a second setting, [`width_routing`], and it lives
//! here because it is the same question — how wide is this host, really — read for a
//! different purpose. It is **off by default and has no environment channel**: it is new,
//! so nothing in the field sets it, and the env var was only ever kept for compatibility.

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

/// The config-home key: `width-routing = "on"` in `config.toml`, instance-scoped as
/// `<instance>.width-routing`.
pub const WIDTH_ROUTING_CONFIG_KEY: &str = "width-routing";

/// Which channel set automatic width routing.
///
/// Deliberately *not* [`SchedulerSource`]: there is no environment channel here. The
/// scheduler keeps one only because services in the field already set `IKIGAI_SCHEDULER`;
/// a setting introduced today has no such debt, and an env var is the third channel this
/// ecosystem rules out — visible only inside an already-running process, so it can be
/// neither diffed nor version-controlled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingSource {
    /// `--width-routing <on|off>` on the command line.
    Flag,
    /// `width-routing` (or `<instance>.width-routing`) in the config home.
    Config,
    /// Nothing said anything: off.
    Default,
}

impl RoutingSource {
    /// The row value: `flag` / `config` / `default`.
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingSource::Flag => "flag",
            RoutingSource::Config => "config",
            RoutingSource::Default => "default",
        }
    }
}

/// The `--width-routing` value, declared while argv is being read (first write wins).
static WIDTH_ROUTING_FLAG: OnceLock<bool> = OnceLock::new();

/// Declare `--width-routing <on|off>` for this process.
///
/// Rejects anything else, for the same reason `--scheduler` does: a typo silently
/// meaning "off" leaves the operator believing the host routes by load shape when it does
/// not, and nothing in the process contradicts them.
pub fn set_width_routing(value: &str) -> Result<(), String> {
    let on = parse_switch(value)?;
    let _ = WIDTH_ROUTING_FLAG.set(on);
    Ok(())
}

/// Whether this process routes fan-outs by their measured width. **Off unless something
/// says otherwise** — it changes which backend answers, and `ikigai-browse` keys its
/// durable explanation archive on model identity, so turning it on without meaning to
/// would write "which backend answered depends on how many siblings the request happened
/// to have" permanently into a store.
pub fn width_routing() -> bool {
    resolved_routing().0
}

/// The channel that decided [`width_routing`].
pub fn width_routing_source() -> RoutingSource {
    resolved_routing().1
}

fn resolved_routing() -> &'static (bool, RoutingSource) {
    static RESOLVED: OnceLock<(bool, RoutingSource)> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        let (on, source, warnings) = decide_routing(
            WIDTH_ROUTING_FLAG.get().copied(),
            routing_config_spec().as_deref(),
        );
        for warning in &warnings {
            eprintln!("ikigai: {warning}");
        }
        (on, source)
    })
}

/// The width-routing setting from the config home, instance-scoped spelling first — the
/// same rule the scheduler key uses, because a served kernel and a REPL read one file and
/// want different answers.
fn routing_config_spec() -> Option<String> {
    crate::config::get(&format!(
        "{}.{WIDTH_ROUTING_CONFIG_KEY}",
        crate::instance_name()
    ))
    .or_else(|| crate::config::get(WIDTH_ROUTING_CONFIG_KEY))
}

/// `on`/`off` (and the `true`/`false` spelling a TOML-minded operator will try).
fn parse_switch(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" => Ok(true),
        "off" | "false" => Ok(false),
        other => Err(format!("`{other}` is not a width-routing setting (on|off)")),
    }
}

/// The width-routing ladder as a PURE function of its two channels — flag > config > off
/// — so the precedence is testable without a process or a config file.
///
/// A broken config line warns and leaves the switch OFF rather than bricking a supervised
/// daemon, and off is the safe direction: it declines an optimization instead of silently
/// changing which backend answers.
fn decide_routing(flag: Option<bool>, config: Option<&str>) -> (bool, RoutingSource, Vec<String>) {
    let mut warnings = Vec::new();
    if let Some(on) = flag {
        return (on, RoutingSource::Flag, warnings);
    }
    if let Some(value) = config {
        match parse_switch(value) {
            Ok(on) => return (on, RoutingSource::Config, warnings),
            Err(e) => warnings.push(format!(
                "{e} (from {WIDTH_ROUTING_CONFIG_KEY}); ignoring it"
            )),
        }
    }
    (false, RoutingSource::Default, warnings)
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
    width_routing: bool,
    routing_source: RoutingSource,
}

impl ikigai_core::SchedulerReporter for ConfiguredScheduler {
    fn rows(&self) -> Vec<(String, String)> {
        let mut rows = ikigai_core::SchedulerReporter::rows(&self.scheduler);
        rows.push(("source".to_string(), self.source.as_str().to_string()));
        // Whether fan-outs route on their measured width, and who said so. A routing
        // decision nobody can observe is one nobody can debug — and the answer an
        // operator needs first is "is this even on?", which lives beside the width it
        // routes on rather than in a second resource.
        //
        // The labels are short on purpose: the kernel renders these rows as
        // `{label:<10} {value}`, so anything longer breaks the column for every row
        // beside it. The VALUE carries the meaning instead — `routing by-width` says what
        // `routing on` would have left the reader to guess.
        rows.push((
            "routing".to_string(),
            if self.width_routing {
                "by-width"
            } else {
                "off"
            }
            .to_string(),
        ));
        rows.push((
            "routing.by".to_string(),
            self.routing_source.as_str().to_string(),
        ));
        rows
    }
}

/// The reporter to inject into the kernel (see [`ConfiguredScheduler`]).
pub fn reporter() -> ConfiguredScheduler {
    let (scheduler, source) = resolved();
    ConfiguredScheduler {
        scheduler: scheduler.clone(),
        source: *source,
        width_routing: width_routing(),
        routing_source: width_routing_source(),
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
            width_routing: false,
            routing_source: RoutingSource::Default,
        };
        let rows = reporter.rows();
        assert!(rows.contains(&("backend".to_string(), "pool:3".to_string())));
        assert!(rows.contains(&("threads".to_string(), "3".to_string())));
        assert!(rows.contains(&("source".to_string(), "config".to_string())));
    }

    /// The fan-out routing switch is readable from the same resource as the width it
    /// routes on, and it says which channel set it — so "why did this host pick that
    /// backend?" is a question the host answers about itself.
    #[test]
    fn the_reporter_states_whether_width_routing_is_on_and_who_said_so() {
        let off = ConfiguredScheduler {
            scheduler: SchedulerSpec::Single.build(),
            source: SchedulerSource::Default,
            width_routing: false,
            routing_source: RoutingSource::Default,
        };
        assert!(off
            .rows()
            .contains(&("routing".to_string(), "off".to_string())));
        assert!(off
            .rows()
            .contains(&("routing.by".to_string(), "default".to_string())));

        let on = ConfiguredScheduler {
            scheduler: SchedulerSpec::Pool(8).build(),
            source: SchedulerSource::Flag,
            width_routing: true,
            routing_source: RoutingSource::Config,
        };
        assert!(on
            .rows()
            .contains(&("routing".to_string(), "by-width".to_string())));
        assert!(on
            .rows()
            .contains(&("routing.by".to_string(), "config".to_string())));
        // The kernel renders `{label:<10} {value}`: a longer label breaks the column.
        for (label, _) in on.rows() {
            assert!(label.len() <= 10, "`{label}` overflows the row column");
        }
    }

    /// Width routing is OFF unless something says otherwise, the flag beats the config,
    /// and each channel names itself. Off is the default because turning it on changes
    /// which backend answers, and browse keys a durable archive on that.
    #[test]
    fn width_routing_is_off_by_default_and_the_flag_beats_the_config() {
        assert!(
            !decide_routing(None, None).0,
            "off unless something says so"
        );
        assert_eq!(decide_routing(None, None).1, RoutingSource::Default);

        let from_config = decide_routing(None, Some("on"));
        assert!(from_config.0);
        assert_eq!(from_config.1, RoutingSource::Config);

        let flag_wins = decide_routing(Some(false), Some("on"));
        assert!(!flag_wins.0);
        assert_eq!(flag_wins.1, RoutingSource::Flag);
    }

    /// A typo in a shared config file degrades to OFF and says so, rather than bricking a
    /// launchd-supervised daemon — and off is the direction that declines an optimization
    /// instead of silently rerouting work.
    #[test]
    fn an_invalid_width_routing_config_value_warns_and_stays_off() {
        let (on, source, warnings) = decide_routing(None, Some("maybe"));
        assert!(!on);
        assert_eq!(source, RoutingSource::Default);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("maybe"), "{warnings:?}");
    }

    /// Both spellings an operator will reach for, and nothing else. `--width-routing yes`
    /// is a typo, not a synonym: silently reading it as "off" is the failure this rejects.
    #[test]
    fn the_switch_accepts_on_off_and_the_toml_booleans() {
        assert_eq!(parse_switch("on"), Ok(true));
        assert_eq!(parse_switch("ON"), Ok(true));
        assert_eq!(parse_switch("true"), Ok(true));
        assert_eq!(parse_switch("off"), Ok(false));
        assert_eq!(parse_switch("false"), Ok(false));
        assert!(parse_switch("yes").is_err());
        assert!(set_width_routing("yes").is_err());
    }
}
