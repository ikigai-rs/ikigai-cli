//! Host-owned recurring jobs from the config home's `jobs` file (JSON Lines).
//!
//! Each declaration names an instance and an explicit scope list. Only watched local
//! kernels run these jobs; served surfaces and remote clients do not enlist as workers.
//! Startup refuses the entire file on an error. Live edits keep the last valid table on
//! error and report the refusal on stderr, like the names layer.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ikigai_core::{Capability, Iri, Verb};
use ikigai_time::{parse_schedule, JobRegistry, Schedule};
use notify::{RecursiveMode, Watcher};
use serde::Deserialize;

type Result<T> = std::result::Result<T, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    instance: String,
    target: String,
    method: String,
    every: String,
    scopes: Vec<String>,
}

struct Job {
    line: usize,
    instance: String,
    target: String,
    verb: Verb,
    schedule: Schedule,
    capability: Capability,
}

fn parse(path: &Path, text: &str) -> Result<Vec<Job>> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|(index, text)| {
            let line = index + 1;
            let refuse = |why| format!("{}:{line}: {why}", path.display());
            let declaration: Declaration =
                serde_json::from_str(text).map_err(|e| refuse(e.to_string()))?;
            if declaration.instance.is_empty()
                || declaration.instance.chars().any(char::is_whitespace)
            {
                return Err(refuse(
                    "instance must be a nonempty name without whitespace".into(),
                ));
            }
            Iri::parse(&declaration.target).map_err(|e| refuse(format!("invalid target: {e}")))?;
            let verb = match declaration.method.as_str() {
                "Source" => Verb::Source,
                "Sink" => Verb::Sink,
                "Delete" => Verb::Delete,
                "Exists" => Verb::Exists,
                "Meta" => Verb::Meta,
                _ => {
                    return Err(refuse(
                        "method must be Source, Sink, Delete, Exists, or Meta".into(),
                    ))
                }
            };
            let schedule = parse_schedule(&declaration.every).map_err(refuse)?;
            // Scopes are the host's grants, never an ambient root fallback. Require IRIs
            // so a typo such as "root" cannot look like an accepted authority choice.
            for scope in &declaration.scopes {
                Iri::parse(scope).map_err(|e| refuse(format!("invalid scope `{scope}`: {e}")))?;
            }
            Ok(Job {
                line,
                instance: declaration.instance,
                target: declaration.target,
                verb,
                schedule,
                capability: Capability::scoped(declaration.scopes),
            })
        })
        .collect()
}

#[derive(Default)]
struct State {
    text: Option<String>,
    ids: Vec<u64>,
}

struct StartupJobs {
    path: PathBuf,
    instance: String,
    registry: JobRegistry,
    state: Mutex<State>,
    watch: OnceLock<notify::RecommendedWatcher>,
}

impl StartupJobs {
    fn new(path: PathBuf, instance: String, registry: JobRegistry) -> Self {
        Self {
            path,
            instance,
            registry,
            state: Mutex::new(State::default()),
            watch: OnceLock::new(),
        }
    }

    fn reload(&self) -> Result<()> {
        // Serialize the read as well as installation: overlapping editor events must not
        // restore an older reading after a newer one, or register the same table twice.
        let mut state = self.state.lock().expect("startup jobs lock");
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: cannot read jobs: {e}", self.path.display())),
        };
        if state.text.as_ref() == Some(&text) {
            return Ok(());
        }
        // Validate ALL lines, even those for other instances, before changing any jobs.
        let jobs = parse(&self.path, &text)?;
        let mut ids = Vec::new();
        for job in jobs.into_iter().filter(|job| job.instance == self.instance) {
            match self.registry.schedule_persistent(
                job.target,
                job.verb,
                job.schedule,
                true,
                job.capability,
            ) {
                Ok(id) => ids.push(id),
                Err(e) => {
                    for id in ids {
                        self.registry.cancel(id);
                    }
                    return Err(format!("{}:{}: {e}", self.path.display(), job.line));
                }
            }
        }
        for id in state.ids.drain(..) {
            self.registry.cancel(id);
        }
        state.ids = ids;
        state.text = Some(text);
        Ok(())
    }

    fn watch(self: &Arc<Self>) -> Result<()> {
        let dir = self.path.parent().expect("jobs file has a parent");
        // No config directory is normal on an unconfigured host. An existing directory
        // is watched even without a jobs file, so creating it live works too.
        if !dir.exists() {
            return Ok(());
        }
        let shared = Arc::downgrade(self);
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                match event {
                    Ok(event)
                        if !matches!(event.kind, notify::EventKind::Access(_))
                            && (event.need_rescan()
                                || event
                                    .paths
                                    .iter()
                                    .any(|p| p.file_name() == shared.path.file_name())) =>
                    {
                        if let Err(e) = shared.reload() {
                            eprintln!("ikigai: {e}; keeping the previous startup jobs");
                        }
                    }
                    Err(e) => {
                        eprintln!("ikigai: {}: jobs watch failed: {e}", shared.path.display())
                    }
                    _ => {}
                }
            })
            .map_err(|e| format!("{}: cannot watch jobs: {e}", self.path.display()))?;
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .map_err(|e| format!("{}: cannot watch jobs: {e}", self.path.display()))?;
        let _ = self.watch.set(watcher);
        // Cover an edit between the initial read and watch installation.
        self.reload()
    }
}

/// Register the config home's jobs once per process, after installing the resolver.
/// Held for the process lifetime, as are the host's other persistent timers.
pub(crate) fn start(registry: JobRegistry) -> Result<()> {
    static ACTIVE: OnceLock<Result<Option<Arc<StartupJobs>>>> = OnceLock::new();
    match ACTIVE.get_or_init(|| {
        let Some(home) = crate::config::config_home() else {
            return Ok(None);
        };
        let jobs = Arc::new(StartupJobs::new(
            home.join("jobs"),
            crate::instance_name().into(),
            registry,
        ));
        jobs.reload()?;
        jobs.watch()?;
        Ok(Some(jobs))
    }) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{
        Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType,
        Representation, SystemClock,
    };
    use ikigai_time::{TimerBackend, TimerHandle};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    type Tick = Arc<dyn Fn() + Send + Sync>;
    #[derive(Default)]
    struct Manual(Mutex<Vec<Tick>>);
    impl TimerBackend for Manual {
        fn start(&self, _: Duration, recurring: bool, tick: Tick) -> TimerHandle {
            assert!(recurring);
            let canceled = Arc::new(AtomicBool::new(false));
            let flag = canceled.clone();
            self.0.lock().unwrap().push(Arc::new(move || {
                if !flag.load(Ordering::SeqCst) {
                    tick();
                }
            }));
            TimerHandle::new(move || canceled.store(true, Ordering::SeqCst))
        }
    }
    impl Manual {
        fn fire(&self) {
            let ticks = self.0.lock().unwrap().clone();
            for tick in ticks {
                tick();
            }
        }
    }

    fn path(case: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iki-jobs-{}-{case}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("jobs")
    }

    fn declaration(target: &str, scopes: &[&str]) -> String {
        serde_json::json!({"instance":"judge", "target":target, "method":"Sink", "every":"1s", "scopes":scopes}).to_string()
    }

    fn fixture(case: &str) -> (StartupJobs, Arc<Manual>) {
        let ticks = Arc::new(Manual::default());
        let registry = JobRegistry::new(ticks.clone(), Arc::new(SystemClock));
        let mut space = EndpointSpace::new();
        for (target, required) in [
            ("urn:test:allowed", "urn:cap:test:a"),
            ("urn:test:denied", "urn:cap:test:b"),
        ] {
            space = space.bind(
                Exact::new(target),
                FnEndpoint::new("test", |inv: &Invocation<'_>| {
                    // This assertion also catches extra authority attached on the way to a tick.
                    assert_eq!(*inv.capability, Capability::scoped(["urn:cap:test:a"]));
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"ran".to_vec(),
                    ))
                })
                .with_description(Description::new("test").verb(Verb::Sink).requires(required)),
            );
        }
        registry.set_resolver(Arc::new(Kernel::new(Arc::new(space))));
        (
            StartupJobs::new(path(case), "judge".into(), registry),
            ticks,
        )
    }

    #[test]
    fn ticks_run_under_exactly_the_declared_capability() {
        let (jobs, ticks) = fixture("authority");
        std::fs::write(
            &jobs.path,
            format!(
                "{}\n{}\n",
                declaration("urn:test:allowed", &["urn:cap:test:a"]),
                declaration("urn:test:denied", &["urn:cap:test:a"])
            ),
        )
        .unwrap();
        jobs.reload().unwrap();
        assert_eq!(
            jobs.registry.cancel_all(),
            0,
            "host declarations are persistent"
        );
        ticks.fire();
        let health = jobs.registry.health();
        assert_eq!(health.len(), 2);
        assert_eq!(health[0].runs, 1);
        assert_eq!(health[0].last_output, "ran");
        assert_eq!(health[1].runs, 1);
        assert_eq!(health[1].failures_in_a_row, 1, "scope b must be denied");
    }

    #[test]
    fn reload_replaces_only_owned_jobs_and_invalid_edits_keep_the_previous_table() {
        let (jobs, ticks) = fixture("reload");
        let valid = declaration("urn:test:allowed", &["urn:cap:test:a"]);
        std::fs::write(&jobs.path, &valid).unwrap();
        jobs.reload().unwrap();
        jobs.reload().unwrap();
        assert_eq!(
            jobs.registry.health().len(),
            1,
            "duplicate notifications do not add jobs"
        );
        std::fs::write(&jobs.path, format!("{valid}\n{{broken}}\n")).unwrap();
        assert!(jobs.reload().unwrap_err().contains("jobs:2"));
        ticks.fire();
        assert_eq!(jobs.registry.health()[0].runs, 1);

        // A valid narrowing replaces the previous timer and cannot inherit its scope.
        std::fs::write(&jobs.path, declaration("urn:test:allowed", &[])).unwrap();
        jobs.reload().unwrap();
        ticks.fire();
        let health = jobs.registry.health();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].runs, 1);
        assert_eq!(health[0].failures_in_a_row, 1);
        jobs.registry
            .schedule_persistent(
                "urn:test:external".into(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
                Capability::scoped(Vec::<String>::new()),
            )
            .unwrap();
        std::fs::remove_file(&jobs.path).unwrap();
        jobs.reload().unwrap();
        let remaining = jobs.registry.health();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].target, "urn:test:external",
            "only this file's jobs are canceled"
        );
    }

    #[test]
    fn malformed_fields_are_refused_with_the_line_number_even_for_another_instance() {
        let valid: serde_json::Value =
            serde_json::from_str(&declaration("urn:test:allowed", &[])).unwrap();
        for (key, value) in [
            ("method", serde_json::json!("Snk")),
            ("every", serde_json::json!("0s")),
            ("target", serde_json::json!("not an IRI")),
            ("scopes", serde_json::json!(["root"])),
            ("unknown", serde_json::json!(true)),
            ("instance", serde_json::json!("")),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            let err = parse(Path::new("jobs"), &format!("# comment\n{bad}"))
                .err()
                .expect("refused");
            assert!(err.starts_with("jobs:2:"), "{err}");
        }
        let mut missing = valid;
        missing.as_object_mut().unwrap().remove("scopes");
        assert!(
            parse(Path::new("jobs"), &missing.to_string()).is_err(),
            "authority is required"
        );
    }

    #[test]
    fn other_instances_do_not_enlist() {
        let (jobs, _) = fixture("instance");
        let text = declaration("urn:test:allowed", &[]).replace("judge", "another");
        std::fs::write(&jobs.path, text).unwrap();
        jobs.reload().unwrap();
        assert!(jobs.registry.health().is_empty());
    }
}
