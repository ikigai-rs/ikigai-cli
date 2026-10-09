//! The host's Lisp: the bounds `ikigai-lisp` evaluates under, and the wall-clock governor in
//! front of every Lisp door this host runs for itself (ledger #920).
//!
//! ## The bounds come from the config home
//!
//! `ikigai-lisp` 0.2 fixes its [`Limits`](ikigai_lisp::Limits) once per process, before the
//! first evaluation, and takes them from the host, never from environment variables
//! (`IKIGAI_LISP_WORKERS` is gone, ledger #214). This host reads them from `config.toml`:
//!
//! | key                         | `Limits` field       | default (ikigai-lisp's)    |
//! |-----------------------------|----------------------|----------------------------|
//! | `lisp.workers`              | `workers`            | available parallelism, ≥ 8 |
//! | `lisp.worker_stack_bytes`   | `worker_stack_bytes` | 128 MiB (reserved)         |
//! | `lisp.max_program_bytes`    | `max_program_bytes`  | 4 MiB                      |
//! | `lisp.max_input_bytes`      | `max_input_bytes`    | 16 MiB                     |
//! | `lisp.max_nesting`          | `max_nesting`        | 1,000                      |
//! | `lisp.timeout`              | (this host's governor, seconds) | 300 (see below) |
//!
//! Every value is a whole number of at least 1 (TOML's `_` separators are allowed). A value
//! that is not, a key under `lisp.` that is none of these, or a key given twice **fails at
//! start-up** ([`configure`], called by the binary before any mode runs) rather than being
//! read as the default: a misspelled bound that silently does nothing is the failure a bound
//! exists to prevent.
//!
//! ⚠ `worker_stack_bytes` and `max_nesting` travel together: a stack too small for the
//! nesting admitted overflows, and a stack overflow ABORTS the process rather than failing one
//! eval. ikigai-lisp measured the deepest program its default nesting admits at 32 MiB with
//! Steel unoptimized; lower the stack only with the nesting.
//!
//! ## The governor: why 300 seconds
//!
//! An eval is interrupted only when something DROPS it (ikigai-lisp 0.2 checks an interrupt
//! flag before every instruction, and a drop sets it). Without a wall-clock governor nothing
//! drops an eval in this host, so a runaway held its worker for the life of the process
//! (ledger #87, closed only for hosts that wrap). [`govern`] puts `ikigai-throttle`'s
//! `Timeout` in front of every door in [`DOORS`] plus the stored programs this host binds.
//!
//! The default has to clear the longest LEGITIMATE run, because a governor that fires on one
//! interrupts a booking between its mails. The evidence (2026-10-09):
//!
//! - The booking handler, measured on the host that runs it (bug): 23 settled requests, drop
//!   to settle median 1 s, the `urn:llm:ask` interpretation path 5 s, longest ordinary run
//!   37 s (two longer gaps were queue time while the daemon was down, not handler time).
//! - It and `confirm.scm` call `urn:llm:ask`, `urn:email:send` and `urn:meeting:zoom:schedule`,
//!   and `ikigai-llm` has no timeout of its own: a cold model load is the handler's time.
//! - The operator set `lisp.timeout = 300` on both live hosts (plasma and bug) after the old
//!   10 s budget cut off an Emacs call that asked a 70B model a question.
//!
//! So 300 s: eight times the longest observed legitimate run, and the value the operator
//! already chose. A stranger's program is a different threat and keeps its own, tighter
//! budget: a served kernel's eval is governed by `--eval-timeout` (default 10 s), which reads
//! `lisp.timeout` only when the flag is absent.

use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use ikigai_core::{Fallback, Request, Resolution, Scope, Space};

/// The governor's budget when `lisp.timeout` is not set. See the module note for the evidence.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// The Lisp doors that are not stored programs: the evaluator and the signed-run door. The
/// programs are listed beside their bindings (`crate::PROGRAMS`).
pub const DOORS: &[&str] = &["urn:lisp:eval", "urn:lisp:run"];

/// Every key this host reads under `lisp.`.
pub const KEYS: &[&str] = &[
    "lisp.workers",
    "lisp.worker_stack_bytes",
    "lisp.max_program_bytes",
    "lisp.max_input_bytes",
    "lisp.max_nesting",
    "lisp.timeout",
];

/// The `lisp.*` settings, validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The bounds handed to `ikigai_lisp::set_limits`: ikigai-lisp's defaults, overridden by
    /// each key present.
    pub limits: ikigai_lisp::Limits,
    /// `lisp.timeout`, when set.
    pub timeout: Option<Duration>,
}

/// Validate `entries` — the `(key, value)` lines under `lisp.` — into [`Settings`].
pub fn settings_from(entries: &[(String, String)]) -> Result<Settings, String> {
    let mut limits = ikigai_lisp::Limits::default();
    let mut timeout = None;
    let mut seen: Vec<&str> = Vec::new();
    for (key, value) in entries {
        if seen.contains(&key.as_str()) {
            return Err(format!("`{key}` is set twice; set it once"));
        }
        seen.push(key);
        let number = whole_number(key, value)?;
        let size =
            || usize::try_from(number).map_err(|_| format!("`{key} = {value}` is too large here"));
        match key.as_str() {
            "lisp.workers" => limits = limits.workers(size()?),
            "lisp.worker_stack_bytes" => limits = limits.worker_stack_bytes(size()?),
            "lisp.max_program_bytes" => limits = limits.max_program_bytes(size()?),
            "lisp.max_input_bytes" => limits = limits.max_input_bytes(size()?),
            "lisp.max_nesting" => limits = limits.max_nesting(size()?),
            "lisp.timeout" => timeout = Some(Duration::from_secs(number)),
            _ => {
                return Err(format!(
                    "`{key}` is not a Lisp setting; the keys are {}",
                    KEYS.join(", ")
                ))
            }
        }
    }
    Ok(Settings { limits, timeout })
}

/// A whole number of at least 1, with TOML's `_` separators allowed.
fn whole_number(key: &str, value: &str) -> Result<u64, String> {
    let digits: String = value.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "`{key} = {value}` is not a whole number (the value is a count of {})",
            if key == "lisp.timeout" {
                "seconds"
            } else if key.ends_with("bytes") {
                "bytes"
            } else if key == "lisp.workers" {
                "threads"
            } else {
                "levels"
            }
        ));
    }
    match digits.parse::<u64>() {
        Ok(0) => Err(format!("`{key} = {value}`: the least it can be is 1")),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("`{key} = {value}` is too large")),
    }
}

/// The settings read from this process's config home, once.
fn settings() -> &'static Result<Settings, String> {
    static SETTINGS: OnceLock<Result<Settings, String>> = OnceLock::new();
    SETTINGS.get_or_init(|| {
        settings_from(&crate::config::entries_under("lisp.")).map_err(|e| {
            format!(
                "{e} (in {}; see the `lisp.*` keys in ikigai-cli's README)",
                crate::config::config_path().display()
            )
        })
    })
}

/// **Fix ikigai-lisp's bounds from the config home**, once per process and before the first
/// evaluation. The binary calls this before any mode runs and exits on an error, so a bad
/// `lisp.*` line stops the host at start-up. Calling it again is a no-op.
///
/// Errors when a `lisp.*` line is invalid, or when the bounds were already fixed to something
/// else (an evaluation ran first, with the defaults).
pub fn configure() -> Result<(), String> {
    let settings = settings().as_ref().map_err(Clone::clone)?;
    match ikigai_lisp::set_limits(settings.limits.clone()) {
        Ok(()) => Ok(()),
        Err(fixed) if fixed == settings.limits => Ok(()),
        Err(fixed) => Err(format!(
            "the Lisp bounds were fixed before the config home was read ({fixed:?}), so the \
             `lisp.*` keys cannot take effect; configure them before the first evaluation"
        )),
    }
}

/// `lisp.timeout`, when it is set and valid.
pub fn configured_timeout() -> Option<Duration> {
    settings().as_ref().ok().and_then(|s| s.timeout)
}

/// The budget the governor in front of the host's own Lisp doors runs with: `lisp.timeout`,
/// else [`DEFAULT_TIMEOUT`].
///
/// Also fixes the bounds ([`configure`]) if nobody has: a kernel is built before anything
/// evaluates, so a host that embeds this crate without the binary's start-up still gets its
/// config home's bounds. It cannot stop that host, so an invalid `lisp.*` line is reported
/// once on stderr and the defaults stand.
pub fn host_timeout() -> Duration {
    if let Err(e) = configure() {
        static WARNED: Once = Once::new();
        WARNED.call_once(|| eprintln!("ikigai: {e}; the Lisp defaults stand"));
    }
    configured_timeout().unwrap_or(DEFAULT_TIMEOUT)
}

/// **Put a wall-clock governor in front of `doors` in `root`.** A request for one of `doors`
/// resolves through `root` as before, and the endpoint it finds runs behind
/// `ikigai_throttle::Timeout(budget)`: past the budget the eval is dropped (which interrupts
/// the program and releases its worker) and the caller gets a transient `Timeout`. Every other
/// request misses the governed layer and resolves in `root` unchanged.
///
/// It wraps the WHOLE root rather than each binding so a declared arrangement is governed too
/// (whatever it binds a door to, the door resolves through here), and so the governed doors
/// keep their place in the root's topology: `ikigai_throttle::Timeout` reports an opaque node,
/// and a binding wrapped in one would vanish from the endpoints a declaration can name.
pub fn govern(root: Arc<dyn Space>, budget: Duration, doors: Vec<String>) -> Arc<dyn Space> {
    let only = Only {
        inner: Arc::clone(&root),
        doors,
    };
    Arc::new(Fallback::new(vec![
        Arc::new(ikigai_throttle::Timeout::new(only, budget)) as Arc<dyn Space>,
        root,
    ]))
}

/// `inner`, seen only through `doors`: everything else misses. Not enumerable, so the
/// governed doors are listed once, by `inner` itself, in the layer behind.
struct Only {
    inner: Arc<dyn Space>,
    doors: Vec<String>,
}

impl Space for Only {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        let target = request.target.as_str();
        let name = target.split(['?', '#']).next().unwrap_or(target);
        if self.doors.iter().any(|door| door == name) {
            self.inner.resolve(request, scope)
        } else {
            Resolution::Miss
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Error, Exact, Iri, Kernel, Verb};

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn every_key_maps_to_its_bound() {
        let settings = settings_from(&entries(&[
            ("lisp.workers", "3"),
            ("lisp.worker_stack_bytes", "67_108_864"),
            ("lisp.max_program_bytes", "1024"),
            ("lisp.max_input_bytes", "2048"),
            ("lisp.max_nesting", "200"),
            ("lisp.timeout", "45"),
        ]))
        .expect("valid settings");
        let expected = ikigai_lisp::Limits::default()
            .workers(3)
            .worker_stack_bytes(64 * 1024 * 1024)
            .max_program_bytes(1024)
            .max_input_bytes(2048)
            .max_nesting(200);
        assert_eq!(settings.limits, expected);
        assert_eq!(settings.timeout, Some(Duration::from_secs(45)));
    }

    #[test]
    fn no_keys_means_ikigai_lisps_defaults_and_no_timeout() {
        let settings = settings_from(&[]).expect("empty is valid");
        assert_eq!(settings.limits, ikigai_lisp::Limits::default());
        assert_eq!(settings.timeout, None);
    }

    /// A bound that silently reads as its default is the failure a bound exists to prevent, so
    /// each of these is refused, naming the key.
    #[test]
    fn a_bad_line_is_refused_naming_the_key() {
        for (key, value, says) in [
            ("lisp.workers", "0", "least it can be is 1"),
            ("lisp.timeout", "0", "least it can be is 1"),
            ("lisp.timeout", "10s", "seconds"),
            ("lisp.max_nesting", "-5", "not a whole number"),
            ("lisp.max_input_bytes", "1MiB", "bytes"),
            ("lisp.worker_stack_bytes", "", "not a whole number"),
            (
                "lisp.max_program_bytes",
                "99999999999999999999999",
                "too large",
            ),
            ("lisp.worker_stack", "1024", "not a Lisp setting"),
        ] {
            let error = settings_from(&entries(&[(key, value)]))
                .expect_err(&format!("`{key} = {value}` is refused"));
            assert!(error.contains(key), "{error}");
            assert!(error.contains(says), "`{key} = {value}`: {error}");
        }
        let twice = settings_from(&entries(&[("lisp.timeout", "5"), ("lisp.timeout", "6")]))
            .expect_err("a key given twice is refused");
        assert!(twice.contains("set twice"), "{twice}");
    }

    #[test]
    fn the_config_scanner_hands_over_every_lisp_line_and_nothing_else() {
        let text = "lisp.timeout = 300\n# lisp.workers = 2\nmail.from = \"a@b\"\n\
                    lisp.max_nesting = \"500\"\nbug.lisp.timeout = 9\n";
        assert_eq!(
            crate::config::entries_under_in(text, "lisp."),
            entries(&[("lisp.timeout", "300"), ("lisp.max_nesting", "500")])
        );
    }

    fn eval(kernel: &Kernel, program: &str) -> Result<String, Error> {
        let request = Request::new(Verb::Source, Iri::parse("urn:lisp:eval").expect("an IRI"))
            .with_arg("in", ArgRef::Inline(program.as_bytes().to_vec()));
        futures::executor::block_on(kernel.issue(request, &Capability::root()))
            .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
    }

    /// ★ **The governor stops a runaway, and the evaluator survives it.** ikigai-lisp 0.2
    /// interrupts an eval whose future is dropped, and releases its worker (pinned in that
    /// crate); this is the drop. The program loops forever; the governed door answers a
    /// transient `Timeout` near the budget, and the evaluator still answers afterwards.
    #[test]
    // Native-only test: the wall clock measures how long the governor took to fire.
    #[allow(clippy::disallowed_methods)]
    fn the_governor_interrupts_a_runaway_and_the_evaluator_survives_it() {
        let root: Arc<dyn Space> =
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval()));
        // Not milliseconds: every eval builds its own engine, which an unoptimized test build
        // takes hundreds of milliseconds to do, and that is inside the budget too.
        let budget = Duration::from_secs(3);
        let kernel = Kernel::new(govern(root, budget, vec!["urn:lisp:eval".to_string()]));
        let started = std::time::Instant::now();
        let runaway = eval(&kernel, "(define (spin n) (spin (+ n 1))) (spin 0)");
        let took = started.elapsed();
        match runaway {
            Err(Error::Timeout(detail)) => assert!(detail.contains("urn:lisp:eval"), "{detail}"),
            other => panic!("a runaway is stopped with a Timeout, got {other:?}"),
        }
        assert!(
            took < Duration::from_secs(20),
            "stopped near its {budget:?} budget, not by something else: {took:?}"
        );
        // The evaluator's worker pool is process-wide, so an UNGOVERNED kernel over it shows
        // it still answers. Not through the governed one: a debug engine build on a loaded CI
        // runner alone can take longer than any budget short enough for a test (seen: past
        // 3 s), and that would time the follow-up out for a reason that is not the runaway.
        let plain = Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval()),
        ));
        for _ in 0..3 {
            assert_eq!(
                eval(&plain, "(+ 1 2)").expect("the evaluator survives"),
                "3"
            );
        }
    }

    /// The governed layer answers only its doors: anything else resolves in the root exactly
    /// as before, and a door the root does not bind is still a miss.
    #[test]
    fn only_the_named_doors_are_governed() {
        let root: Arc<dyn Space> = Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval())
                .bind(
                    Exact::new("urn:other"),
                    ikigai_lisp::program("other", "(+ 40 2)"),
                ),
        );
        let only = Only {
            inner: Arc::clone(&root),
            doors: vec!["urn:lisp:eval".to_string(), "urn:absent".to_string()],
        };
        let resolve = |iri: &str| {
            let request = Request::new(Verb::Source, Iri::parse(iri).expect("an IRI"));
            matches!(only.resolve(&request, &Scope::empty()), Resolution::Hit(_))
        };
        assert!(resolve("urn:lisp:eval"));
        assert!(!resolve("urn:other"), "not a governed door");
        assert!(
            !resolve("urn:absent"),
            "a governed door the root does not bind"
        );
        // The ungoverned door still answers through the composed space.
        let kernel = Kernel::new(govern(
            root,
            Duration::from_secs(5),
            vec!["urn:lisp:eval".to_string()],
        ));
        let request = Request::new(Verb::Source, Iri::parse("urn:other").expect("an IRI"));
        let answer = futures::executor::block_on(kernel.issue(request, &Capability::root()))
            .expect("the root still answers");
        assert_eq!(String::from_utf8_lossy(&answer.bytes), "42");
    }
}
