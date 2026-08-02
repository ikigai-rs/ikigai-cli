//! In-process transport: composes a kernel directly in the host process.
//!
//! This is the simplest "attach to a kernel instance" binding — no network, no
//! IPC. The kernel, its endpoints, and its cache all live in the calling process.
//! Other transports (IPC, QUIC) front the same `Issuer` interface over a wire.
//!
//! The reusable function endpoints (`toUpper`, `reverseList`, `wrap`, `split`,
//! `greet`, `echo`, `compose`) are not defined here — they come from the linked
//! [`ikigai_fn`] module crate, mounted via [`ikigai_fn::space`]. This host adds
//! only its own endpoints: the demo `page` shape and `urn:host:info`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Fallback,
    FnEndpoint, Invocation, Iri, Kernel, MetaRenderer, ReprType, Representation, Request,
    Resolution, Result, Scope, Space, SpaceEntry, SystemClock, Time, UriTemplate, Verb,
};
use ikigai_scheduler::Scheduler;

pub mod config;
pub mod contactblock;
pub mod decide;
pub mod decisions;
pub mod jsonl;
pub mod passkey;
pub mod people;
use ikigai_time::JobRegistry;
use ikigai_vocab::TurtleRenderer;
use notify::{RecursiveMode, Watcher};

/// The `Meta` renderer used by the CLI kernel.
///
/// Adds an `application/json` projection of the [`Description`] — which the REPL
/// reads to learn an endpoint's parameter contract — on top of the Turtle and
/// plain-text rendering provided by [`TurtleRenderer`]. Going through `Meta` (a
/// resource request) rather than a direct call keeps the lookup transport-agnostic:
/// a future remote frontend learns the contract the same way.
struct CliRenderer;

impl MetaRenderer for CliRenderer {
    fn render(&self, description: &Description, target: &ReprType) -> Result<Representation> {
        if target.media_type == "application/json" {
            let json = serde_json::to_vec(description)
                .map_err(|e| Error::Endpoint(format!("describe as json: {e}")))?;
            return Ok(Representation::new(ReprType::new("application/json"), json));
        }
        TurtleRenderer.render(description, target)
    }
}

/// `urn:data:page`: a demo *shape* for `compose`. A text template whose
/// `$a{<iri>}` markers transclude other resources in this space; resolving
/// `source urn:fn:compose src=urn:data:page` assembles the whole thing in one
/// pull. The escaped `$$a{…}` shows a literal marker surviving expansion.
fn page_impl(_inv: &Invocation<'_>) -> Result<Representation> {
    let body = "ikigai compose demo — one pull, recursively assembled\n\n  \
        toUpper : $a{urn:fn:toUpper?in=\"resource oriented computing\"}\n  \
        wrap    : $a{urn:demo:wrap?text=hello}\n  \
        greet   : $a{urn:demo:greet?greeting=Hi&name=World}\n  \
        nested  : $a{urn:data:about}\n\n\
        literal marker (escaped, not expanded): $$a{urn:fn:toUpper?in=x}\n";
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.as_bytes().to_vec(),
    )
    .cacheable())
}

/// `urn:data:alias-demo`: a Lisp program that PULLS ITS OWN PRELUDE.
///
/// The point of the transclusion marker here: each `urn:lisp:eval` is isolated, so
/// definitions never survive from one evaluation to the next — a prelude has to be IN the
/// program. `$a{urn:lisp:aliases}` splices in the generated alias definitions by REFERENCE,
/// so what is stored is a pointer to the live manifold rather than a copy that goes stale
/// the moment an endpoint changes.
fn alias_demo_impl(_inv: &Invocation<'_>) -> Result<Representation> {
    let body = "$a{urn:lisp:aliases}\n\n\
        ;; The prelude above is generated from THIS kernel's manifold, under YOUR\n\
        ;; capability. Everything below is an ordinary call to a named verb.\n\
        (fn-toUpper \"named verbs, generated from the manifold\")\n";
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.as_bytes().to_vec(),
    ))
}

fn alias_demo() -> FnEndpoint {
    FnEndpoint::new("alias-demo", alias_demo_impl).with_description(
        Description::new("alias-demo")
            .title("Alias demo program")
            .summary(
                "a Lisp program that transcludes the generated alias prelude and then calls \
                 one of its verbs — compose it, then pipe it to urn:lisp:eval",
            )
            .verb(Verb::Source)
            .output("text/plain"),
    )
}

fn page() -> FnEndpoint {
    FnEndpoint::new("page", page_impl).with_description(
        Description::new("page")
            .title("Demo page")
            .summary("A compose shape: a text template with `$a{<iri>}` transclusion markers.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:data:control`: the **Control** page as one composed resource. The three
/// `$a{}` markers are sub-requests `compose` resolves and inlines —
/// `urn:kernel:scheduler` (the host work backend + live task counts),
/// `urn:kernel:cache` (what's cached), and `urn:time:jobs` (the time transport's
/// timed jobs). So `source urn:fn:compose src=urn:data:control` is "a composite
/// resource pulling three sub-requests," its cache validity folding all three — the
/// text analog of the browser demo's Control page.
fn control_impl(_inv: &Invocation<'_>) -> Result<Representation> {
    let body = "ikigai control plane — one composed resource\n\
        three sub-requests: urn:kernel:scheduler + urn:kernel:cache + urn:time:jobs\n\n\
        $a{urn:kernel:scheduler}\n\
        $a{urn:kernel:cache}\n\
        $a{urn:time:jobs}";
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.as_bytes().to_vec(),
    )
    .cacheable())
}

fn control() -> FnEndpoint {
    FnEndpoint::new("control", control_impl).with_description(
        Description::new("control")
            .title("Control page")
            .summary("A compose shape: the kernel control plane (scheduler + cache + time jobs) as three transcluded sub-requests.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:data:about`: a nested shape the demo page transcludes — which itself
/// transcludes another resource, so `compose` (and the `trace` tree) recurses.
fn about_impl(_inv: &Invocation<'_>) -> Result<Representation> {
    let body = "a shape within a shape: \
        $a{urn:fn:toUpper?in=\"composed within a composed shape\"}";
    Ok(Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.as_bytes().to_vec(),
    )
    .cacheable())
}

fn about() -> FnEndpoint {
    FnEndpoint::new("about", about_impl).with_description(
        Description::new("about")
            .title("About (nested shape)")
            .summary("A compose shape the demo page transcludes, which itself transcludes another resource.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:host:info` — reports the host's *nature* (the `nature` label, set by
/// whoever composes the kernel: `Embedded (Native)`, `Remote (IPC)`, …) and its
/// runtime, so `source urn:host:info` shows what differs between the embedded,
/// IPC, and QUIC situations. Deliberately **uncacheable** — a live host fact, not
/// a pure function — which also demonstrates the `uncacheable` cache outcome.
fn host_info(nature: &'static str) -> FnEndpoint {
    FnEndpoint::new("host-info", move |_inv: &Invocation<'_>| {
        let runtime = if cfg!(target_family = "wasm") {
            "browser · wasm32".to_string()
        } else {
            format!(
                "native · {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        };
        let body = format!(
            "ikigai host\n  nature    {nature}\n  runtime   {runtime}\n  \
             space     ikigai-fn (toUpper · reverseList · wrap · split · greet · echo · compose)\n"
        );
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            body.into_bytes(),
        ))
    })
    .with_description(
        Description::new("host-info")
            .title("Host info")
            .summary("Reports the kernel host's nature (embedded/remote + transport) and runtime.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// The process scheduler that drives kernel work. Single-threaded by default; set
/// `IKIGAI_SCHEDULER` (`single` | `pool` | `pool:N`) to run on a threadpool. Built
/// once and shared (a clone shares the pool), so the kernel's injected spawner and
/// its `urn:kernel:scheduler` reporter reflect the same scheduler.
pub fn scheduler() -> Scheduler {
    static SCHEDULER: OnceLock<Scheduler> = OnceLock::new();
    SCHEDULER
        .get_or_init(|| match std::env::var("IKIGAI_SCHEDULER") {
            Ok(spec) => Scheduler::from_config(&spec).unwrap_or_else(|e| {
                eprintln!("ikigai: {e}; falling back to a single-threaded scheduler");
                Scheduler::single()
            }),
            Err(_) => Scheduler::single(),
        })
        .clone()
}

/// Process-global registry of time-transport jobs — the `urn:time:schedule` /
/// `urn:time:cancel` / `urn:time:jobs` control plane, driven by the native
/// [`ThreadTimer`](ikigai_time::ThreadTimer). Built once and shared (a clone shares
/// the same `Arc`-backed registry), so the `urn:time:*` endpoints bound in
/// [`root_space`] and the kernel handle installed in [`watched_kernel`] act on one
/// registry. The kernel handle is set *after* the kernel is built, since the
/// endpoints are bound into that same kernel.
pub fn time_registry() -> JobRegistry {
    static REGISTRY: OnceLock<JobRegistry> = OnceLock::new();
    REGISTRY
        .get_or_init(|| JobRegistry::new(Arc::new(ikigai_time::ThreadTimer)))
        .clone()
}

/// Process-global flag: is the interactive runbook (`urn:runbook:*`) active? OFF by
/// default — the CLI is a tool, not a demo. `--demo` sets it at startup; `sink
/// urn:host:demo on|off` (the `demo` command) flips it at runtime. One source of
/// truth, read by the [`Gated`] runbook space and (later) the TUI's tab bar.
pub fn demo_flag() -> Arc<AtomicBool> {
    static DEMO: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    DEMO.get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// A space mounted only while its flag is set. When off it resolves and enumerates
/// nothing, so the runbook is absent from `list` and `urn:runbook:*` is unresolved
/// until the demo is turned on — without rebuilding the kernel.
struct Gated {
    inner: EndpointSpace,
    on: Arc<AtomicBool>,
}

impl Space for Gated {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        if self.on.load(Ordering::Relaxed) {
            self.inner.resolve(request, scope)
        } else {
            Resolution::Miss
        }
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        if self.on.load(Ordering::Relaxed) {
            self.inner.entries()
        } else {
            Some(Vec::new())
        }
    }
}

/// `urn:host:demo` — the demo toggle as a resource. `source urn:host:demo` reports
/// `on`/`off`; `sink urn:host:demo on|off` (lenient: also true/false/enable/disable)
/// flips it, mounting/unmounting the runbook (and, in the TUI, the demo tabs). The
/// `demo` command is sugar over these.
fn host_demo() -> FnEndpoint {
    FnEndpoint::new("host-demo", move |inv: &Invocation<'_>| {
        let flag = demo_flag();
        // A Sink carries the new state as `content`; a Source just reports it.
        if let Ok(value) = inv.inline_str("content") {
            let on = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "on" | "true" | "enable" | "enabled" | "yes" | "1"
            );
            flag.store(on, Ordering::SeqCst);
        }
        let state = if flag.load(Ordering::SeqCst) {
            "on"
        } else {
            "off"
        };
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!("demo {state}\n").into_bytes(),
        ))
    })
    .with_description(
        Description::new("host-demo")
            .title("Demo toggle")
            .summary(
                "The interactive runbook on/off — source reports it, `sink … on|off` flips it.",
            )
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `$HOME/.ikigai`, created — the ikigai-owned config/state directory. ([`file_root`]
/// nests `workspace/` beneath it; command history persists here too.)
fn ikigai_home() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    let dir = home.join(".ikigai");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Process-global flag: persist command history across invocations? Mirrors
/// [`demo_flag`], but seeded from the on-disk marker so `history on` is **sticky** —
/// a session enabled in a prior run starts with persistence already on (and its
/// history loaded). `sink urn:host:history on|off` (the `history` command) flips it.
pub fn history_flag() -> Arc<AtomicBool> {
    static HISTORY: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    HISTORY
        .get_or_init(|| Arc::new(AtomicBool::new(history_marker().exists())))
        .clone()
}

/// The marker whose presence means persistence is on, so the toggle survives across
/// invocations (the flag is seeded from it). Kept separate from the history file, so
/// turning persistence off never discards the lines already recorded.
fn history_marker() -> PathBuf {
    ikigai_home().join("history.on")
}

/// The history file within a given config dir — one line per command. Split from
/// [`ikigai_home`] so the round-trip is testable without touching `$HOME`.
fn history_file(dir: &Path) -> PathBuf {
    dir.join("history")
}

/// Read the command history from `dir`, oldest first; empty if absent/unreadable.
fn read_history(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(history_file(dir))
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Append a (trimmed, non-blank) command to the history file in `dir`.
fn write_history(dir: &Path, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_file(dir))
    {
        let _ = writeln!(file, "{line}");
    }
}

/// The persisted command history, oldest first — what a fresh session preloads into
/// its line recall. Empty if nothing has been saved (or the file can't be read).
pub fn load_history() -> Vec<String> {
    read_history(&ikigai_home())
}

/// Append one command to the persisted history — a no-op when persistence is off or
/// the line is blank, so a frontend can call it unconditionally on every submit.
pub fn append_history(line: &str) {
    if !history_flag().load(Ordering::Relaxed) {
        return;
    }
    write_history(&ikigai_home(), line);
}

/// Turn history persistence on or off, updating both the live flag and the on-disk
/// marker that makes the choice stick across invocations. Turning it off leaves the
/// recorded lines in place.
pub fn set_history(on: bool) {
    history_flag().store(on, Ordering::SeqCst);
    let marker = history_marker();
    if on {
        let _ = std::fs::File::create(&marker); // presence is the signal; empty is fine
    } else {
        let _ = std::fs::remove_file(&marker);
    }
}

/// `urn:host:history` — the history-persistence toggle as a resource, the same
/// convention as [`host_demo`]. `source urn:host:history` reports `on`/`off` (with the
/// entry count when on); `sink urn:host:history on|off` (lenient) flips it. The
/// `history` command is sugar over these.
fn host_history() -> FnEndpoint {
    FnEndpoint::new("host-history", move |inv: &Invocation<'_>| {
        // A Sink carries the new state as `content`; a Source just reports it.
        if let Ok(value) = inv.inline_str("content") {
            let on = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "on" | "true" | "enable" | "enabled" | "yes" | "1"
            );
            set_history(on);
        }
        let body = if history_flag().load(Ordering::SeqCst) {
            format!("history on ({} entries)\n", load_history().len())
        } else {
            "history off\n".to_string()
        };
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            body.into_bytes(),
        ))
    })
    .with_description(
        Description::new("host-history")
            .title("History toggle")
            .summary(
                "Persist command history across runs — source reports it, `sink … on|off` flips it.",
            )
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:host:identity` — reports the identity the current session resolves under, read
/// from the invocation capability (the capability *is* the identity). Over QUIC this is
/// the principal minted from the client certificate, so a connected peer can `source
/// urn:host:identity` to see the `ws/<id>` segment its cert scoped it to — capability-on-
/// the-wire, made observable. Anonymous (root) resolves report `root`.
fn host_identity() -> FnEndpoint {
    FnEndpoint::new("host-identity", move |inv: &Invocation<'_>| {
        let who = inv
            .capability
            .scopes()
            .and_then(|s| s.iter().find_map(|sc| sc.strip_prefix("urn:cap:fs:read:")))
            .and_then(|path| path.rsplit(['/', '\\']).next())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "root (full authority)".to_string());
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!("identity {who}\n").into_bytes(),
        ))
    })
    .with_description(
        Description::new("host-identity")
            .title("Identity")
            .summary("Reports the identity the session resolves under (the session capability).")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// The base demo space: the linked [`ikigai_fn`] function library plus this host's
/// own resources (the `page`/`about` shapes, `urn:host:info`, the `urn:host:demo` /
/// `urn:host:history` toggles, and `urn:host:identity`). Used as-is for a *served*
/// kernel — it deliberately omits the personal space, which must not be exposed over the
/// wire until capability-on-the-wire lands.
/// `urn:style:catalog` — a **text-output** XSLT (a resource) that renders the catalog
/// RDF/XML into terminal-friendly text "cards", one per endpoint. The TUI Docs tab pipes
/// `urn:kernel:catalog | urn:rdf:transrept as=application/rdf+xml | urn:xslt:transform
/// stylesheet=urn:style:catalog as=text/plain` through it — the same XSLT styling the
/// browser uses for HTML cards, here producing text. The `id`-fallback + omit-empty
/// guards keep an under-described endpoint from rendering a hollow card.
// Note on the whitespace: xrust strips *whitespace-only* text nodes, but preserves
// whitespace embedded in a text node that also carries a visible character. So every
// newline here rides with the `│` card-border glyph (`&#10;│ …`) — which both keeps the
// line break and draws a tidy left border on each card. (The HTML stylesheet in the web
// demo doesn't need this — element structure carries the layout there.)
const CATALOG_CARDS_TEXT_XSL: &str = r#"<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ik="https://ikigai-rs.dev/ns#">
  <xsl:output method="text"/>
  <xsl:template match="/"><xsl:apply-templates select="//ik:Endpoint"/></xsl:template>
  <xsl:template match="ik:Endpoint"><xsl:text>&#10;│&#10;│ </xsl:text><xsl:choose><xsl:when test="ik:title"><xsl:value-of select="ik:title"/></xsl:when><xsl:otherwise><xsl:value-of select="ik:id"/></xsl:otherwise></xsl:choose><xsl:text>  ·  </xsl:text><xsl:value-of select="ik:id"/><xsl:if test="ik:summary"><xsl:text>&#10;│   </xsl:text><xsl:value-of select="ik:summary"/></xsl:if><xsl:if test="ik:verb or ik:output"><xsl:text>&#10;│   </xsl:text><xsl:for-each select="ik:verb"><xsl:text>[</xsl:text><xsl:value-of select="."/><xsl:text>] </xsl:text></xsl:for-each><xsl:if test="ik:output"><xsl:text>&#8594; </xsl:text><xsl:value-of select="ik:output"/></xsl:if></xsl:if><xsl:text>&#10;</xsl:text></xsl:template>
</xsl:stylesheet>"#;

fn catalog_cards_xsl() -> FnEndpoint {
    FnEndpoint::new("catalog-cards-xsl", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("application/xslt+xml").with_param("charset", "utf-8"),
            CATALOG_CARDS_TEXT_XSL.as_bytes().to_vec(),
        )
        .cacheable())
    })
    .with_description(
        Description::new("catalog-cards-xsl")
            .title("Catalog cards stylesheet (text)")
            .summary(
                "XSLT that renders the catalog RDF/XML into terminal text cards for the Docs tab.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("application/xslt+xml"),
    )
}

/// `urn:demo:greeter` — a tiny endpoint that returns a greeting. It's the target the
/// **Timer** runbook fires on a schedule (`source urn:time:schedule
/// target=urn:demo:greeter every=1s`), the same command the browser demo uses, so the
/// timed-job demo reads identically in the REPL and in both frontends' runbooks.
fn greeter() -> FnEndpoint {
    FnEndpoint::new("greeter", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            b"Hello from the ikigai kernel.\n".to_vec(),
        ))
    })
    .with_description(
        Description::new("greeter")
            .title("Greeter")
            .summary("Returns a greeting — the target the Timer runbook fires on a schedule.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:time:now` — the current **OS-local** time as `HH:MM`, **cacheable** until the
/// next minute boundary (`Expiry::At`, honoured by the injected `SystemClock`). The
/// REPL tab-bar clock sources it every render tick, but within the minute every request
/// is a cache HIT returning the same value — it only recomputes on the minute. Default
/// is plain `HH:MM`; `html=true` wraps the colon in a span (the browser nav's blink).
/// The same resource + demo as the web nav clock.
fn clock_now() -> FnEndpoint {
    FnEndpoint::new("clock-now", |inv: &Invocation<'_>| {
        use chrono::Timelike;
        let html = inv.inline_str("html").is_ok();
        let now = chrono::Local::now();
        let (h, m) = (now.hour(), now.minute());
        let next_minute = ((now.timestamp_millis().max(0) as u64) / 60_000 + 1) * 60_000;
        let (body, media) = if html {
            (
                format!("{h:02}<span class=\"ik-clock-colon\">:</span>{m:02}"),
                "text/html",
            )
        } else {
            (format!("{h:02}:{m:02}"), "text/plain")
        };
        Ok(Representation::new(
            ReprType::new(media).with_param("charset", "utf-8"),
            body.into_bytes(),
        )
        .cacheable_until(Time::from_millis(next_minute)))
    })
    .with_description(
        Description::new("clock-now")
            .title("Clock")
            .summary(
                "The current local time (HH:MM), cacheable until the next minute boundary — \
                 sourced every render tick but recomputes once a minute.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("html")
                    .summary("html=true wraps the colon in a span (default: plain HH:MM)")
                    .optional(),
            )
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:runbook:timer` — a **Timer** runbook tab for the TUI, mirroring the browser
/// demo's tab. Sourced `as=application/json` by the TUI's `load_demos`, it returns the
/// `{label, intro, steps}` shape the runbook renders: start a one-second job that fires
/// the greeter through the time transport, list the jobs, and stop it. The job lives in
/// the kernel's registry, so it keeps ticking when you switch to the Control tab and
/// watch it there. Each step's `cmd` is exactly what you'd type in the REPL.
fn runbook_timer_demo() -> FnEndpoint {
    FnEndpoint::new("runbook-timer", |_inv: &Invocation<'_>| {
        let json = serde_json::json!({
            "label": "Timer",
            "intro": "The time transport fires a resource-request on a timer. Start a one-second \
                      job that sources urn:demo:greeter on every tick, then switch to the Control \
                      tab and watch it tick live in the time-jobs readout — the job runs in the \
                      kernel, so it keeps firing while you're on another tab. Come back to stop it.",
            "steps": [
                {
                    "label": "start a 1-second greeter timer",
                    "cmd": "source urn:time:schedule target=urn:demo:greeter every=1s",
                    "note": "schedules urn:demo:greeter every 1s — persists across tabs"
                },
                {
                    "label": "list the timed jobs",
                    "cmd": "source urn:time:jobs",
                    "note": "id · interval · run count · last greeting"
                },
                {
                    "label": "stop the greeter timer",
                    "cmd": "source urn:time:cancel target=urn:demo:greeter",
                    "note": "cancels every greeter timer by target — leaves the clock running"
                }
            ]
        });
        Ok(Representation::new(
            ReprType::new("application/json"),
            serde_json::to_vec(&json).unwrap_or_default(),
        ))
    })
    .with_description(
        Description::new("runbook-timer")
            .title("Timer")
            .summary("A runbook tab: start/stop a recurring time job that fires the greeter every second.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("application/json"),
    )
}

fn base_space(nature: &'static str) -> EndpointSpace {
    ikigai_fn::space()
        .bind(Exact::new("urn:data:page"), page())
        .bind(Exact::new("urn:data:control"), control())
        .bind(Exact::new("urn:data:about"), about())
        .bind(Exact::new("urn:data:alias-demo"), alias_demo())
        .bind(Exact::new("urn:demo:greeter"), greeter())
        .bind(Exact::new("urn:time:now"), clock_now())
        .bind(Exact::new("urn:tz:convert"), ikigai_tz::convert())
        .bind(Exact::new("urn:tz:now"), ikigai_tz::now())
        .bind(Exact::new("urn:style:catalog"), catalog_cards_xsl())
        .bind(Exact::new("urn:host:info"), host_info(nature))
        .bind(Exact::new("urn:host:demo"), host_demo())
        .bind(Exact::new("urn:host:history"), host_history())
        .bind(Exact::new("urn:host:identity"), host_identity())
}

/// The directory the local file module is jailed to: `$IKIGAI_FILES`, else
/// `$HOME/.ikigai/workspace`. Created if missing.
///
/// Deliberately a dedicated, ikigai-owned sandbox — *not* the user's home or
/// documents — so the owner's root capability grants files only within this tree.
/// The CLI mints `read-only`/`write`/`delete` `cap` profiles against this root,
/// and the file endpoint's jail makes it the hard floor regardless of capability.
pub fn file_root() -> PathBuf {
    let root = std::env::var_os("IKIGAI_FILES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
            home.join(".ikigai").join("workspace")
        });
    let _ = std::fs::create_dir_all(&root);
    root
}

/// The base space plus the spaces a *trusted* principal drives (the local owner,
/// or an IPC peer the OS verified is the same user): the personal space
/// (`urn:personal:*`) and the local file module (`urn:file:{path}`), jailed to
/// [`file_root`]. Omitted from [`base_space`] (the QUIC-served space) until remote
/// auth + capability-on-the-wire land.
/// The consolidated-view calendar config: `IKIGAI_CALENDAR_CONFIG`, else
/// `~/.config/ikigai/calendar.json`. An absent file is normal (the config
/// resource then guides you to create it); a bad file warns and is ignored.
fn calendar_config() -> Option<ikigai_personal::CalendarConfig> {
    let path = std::env::var("IKIGAI_CALENDAR_CONFIG")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config/ikigai/calendar.json"))
        })?;
    let json = std::fs::read_to_string(&path).ok()?;
    match ikigai_personal::CalendarConfig::from_json(&json) {
        Ok(config) => Some(config),
        Err(e) => {
            eprintln!(
                "ikigai: calendar config ({}) parse error: {e:?} — ignoring",
                path.display()
            );
            None
        }
    }
}

/// The org agenda config from the same calendar.json: `org_dir` (the jail root
/// for the org-file space) and `org_files` (which files carry date-fixed
/// events). Parsed independently of CalendarConfig so the file stays ONE
/// hand-editable config.
fn org_config() -> Option<(PathBuf, Vec<String>)> {
    let path = std::env::var("IKIGAI_CALENDAR_CONFIG")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config/ikigai/calendar.json"))
        })?;
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let dir = v["org_dir"].as_str()?;
    let dir = if let Some(rest) = dir.strip_prefix("~/") {
        Path::new(&std::env::var("HOME").ok()?).join(rest)
    } else {
        PathBuf::from(dir)
    };
    let files = v["org_files"]
        .as_array()?
        .iter()
        .filter_map(|f| f.as_str().map(|f| format!("urn:orgfile:{f}")))
        .collect::<Vec<_>>();
    Some((dir, files))
}

/// The per-source detail projection from calendar.json: `"project":
/// {"Bosatsu": "busy"}` renders that source's events into the view as
/// `Busy (Bosatsu)` with the location withheld — the freebusy capability idea
/// applied at derivation time. UIDs are untouched, so flipping a source's mode
/// UPDATES its events in place (the diff sees changed titles, not new events).
/// Where MCP grants are read from: `$IKIGAI_GRANTS` else
/// `~/.config/ikigai/grants.json`. Exposed so a host can WATCH it (the live
/// grant-swap: edit the file, the connected client's tool list morphs).
pub fn grants_path() -> Option<PathBuf> {
    std::env::var("IKIGAI_GRANTS")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config/ikigai/grants.json"))
        })
}

/// The scopes of a named MCP grant, from `~/.config/ikigai/grants.json`
/// (env override `IKIGAI_GRANTS`). A grant is a NAMED UNION of capability scopes —
/// the union of affordances an MCP session may see. Two shapes are accepted, so a
/// grant can also carry a *visibility* profile (see [`grant_visibility`]): the
/// original scopes-only array `"<grant>": ["urn:cap:…", …]`, or an object
/// `"<grant>": { "scopes": ["urn:cap:…", …], "show": […], "hide": […] }`.
/// Unknown grant / no file / neither shape ⇒ empty.
pub fn grant_scopes(name: &str) -> Vec<String> {
    grant_entry(name).map(|e| scopes_of(&e)).unwrap_or_default()
}

/// The visibility profile of a named MCP grant — the `show`/`hide` glob lists from
/// the object form (empty for the scopes-only array form). Distinct from the
/// grant's *authority* ([`grant_scopes`]): visibility narrows the projected tool
/// list to what's worth showing, without changing what the session may call.
/// Returns `(show, hide)`.
pub fn grant_visibility(name: &str) -> (Vec<String>, Vec<String>) {
    grant_entry(name)
        .map(|e| visibility_of(&e))
        .unwrap_or_default()
}

/// Scopes of one grant entry: the object form nests them under `"scopes"`; the
/// array form IS the scopes.
fn scopes_of(entry: &serde_json::Value) -> Vec<String> {
    string_array(entry.get("scopes").unwrap_or(entry))
}

/// `(show, hide)` visibility globs of one grant entry (both empty for the array
/// form, which carries no visibility keys).
fn visibility_of(entry: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    (string_array(&entry["show"]), string_array(&entry["hide"]))
}

/// Read one grant's JSON value from the grants file. `None` if there is no file,
/// it doesn't parse, or the grant is absent.
fn grant_entry(name: &str) -> Option<serde_json::Value> {
    let path = grants_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    let v = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let entry = &v[name];
    if entry.is_null() {
        return None;
    }
    Some(entry.clone())
}

/// The string members of a JSON array value (non-arrays and non-strings dropped).
fn string_array(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn projection_config() -> std::collections::BTreeMap<String, String> {
    let Some(path) = std::env::var("IKIGAI_CALENDAR_CONFIG")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config/ikigai/calendar.json"))
        })
    else {
        return Default::default();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Default::default();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Default::default();
    };
    v["project"]
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(source, mode)| mode.as_str().map(|m| (source.clone(), m.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// The resolved [`ikigai_view::ViewConfig`] the view endpoints run against —
/// this host's calendar/org/projection config, merged into the plain value the
/// (personal-agnostic) ikigai-view crate consumes. `None` when calendar.json is
/// absent, so the endpoints report the missing config exactly as before. The
/// org files come from [`org_config`] (their `urn:orgfile:` IRIs; the directory
/// is used elsewhere, for the file-space jail).
fn view_config() -> Option<ikigai_view::ViewConfig> {
    let cal = calendar_config()?;
    Some(ikigai_view::ViewConfig {
        view: cal.view,
        sources: cal.sources,
        inbox: cal.inbox,
        org_files: org_config().map(|(_, files)| files).unwrap_or_default(),
        projections: projection_config(),
    })
}

/// A local-time stamp (`YYYY-MM-DD HH:MM:SS`) prefixed on every daemon-log derive
/// report, so the heartbeat in `/tmp/ikigai-daemon.log` doubles as a freshness clock —
/// you can see *when* the last sync ran, not just that one did.
fn stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// One candidate parsed back out of the `urn:kernel:actions` Turtle face.
#[derive(Debug, Clone)]
struct SelectCandidate {
    action: String,
    endpoint: String,
    verb: String,
    requires: Vec<String>,
    missing_optional: u32,
}

/// Parse the `ik:ActionMatch` nodes of a manifold graph.
fn parse_action_matches(turtle: &str) -> Vec<SelectCandidate> {
    use std::collections::BTreeMap;
    const IK: &str = "https://ikigai-rs.dev/ns#";
    let mut by_subject: BTreeMap<String, SelectCandidate> = BTreeMap::new();
    for quad in
        oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(turtle.as_bytes())
    {
        let Ok(quad) = quad else { continue };
        let oxrdf::NamedOrBlankNode::NamedNode(subject) = &quad.subject else {
            continue;
        };
        let entry = by_subject
            .entry(subject.as_str().to_string())
            .or_insert_with(|| SelectCandidate {
                action: subject.as_str().to_string(),
                endpoint: String::new(),
                verb: String::new(),
                requires: Vec::new(),
                missing_optional: 0,
            });
        let pred = quad.predicate.as_str();
        match &quad.object {
            oxrdf::Term::NamedNode(n) if pred == format!("{IK}endpoint") => {
                entry.endpoint = n.as_str().to_string();
            }
            oxrdf::Term::NamedNode(n) if pred == format!("{IK}requires") => {
                entry.requires.push(n.as_str().to_string());
            }
            oxrdf::Term::Literal(l) if pred == format!("{IK}verb") => {
                entry.verb = l.value().to_string();
            }
            oxrdf::Term::Literal(l) if pred == format!("{IK}requires") => {
                entry.requires.push(l.value().to_string());
            }
            oxrdf::Term::Literal(l) if pred == format!("{IK}missingOptional") => {
                entry.missing_optional = l.value().parse().unwrap_or(0);
            }
            _ => {}
        }
    }
    let mut candidates: Vec<SelectCandidate> = by_subject
        .into_values()
        .filter(|c| !c.verb.is_empty())
        .collect();
    candidates
        .sort_by(|a, b| (a.missing_optional, &a.action).cmp(&(b.missing_optional, &b.action)));
    candidates
}

/// Render candidates back out as the selection graph. The chosen one (if any)
/// leads and carries the rationale as `rdfs:comment`; the rest follow, marked
/// considered. (Proper ik:selected/ik:rationale terms can join the vocabulary
/// in a later window; rdfs:comment keeps this vocab-neutral for now.)
fn selection_turtle(
    candidates: &[SelectCandidate],
    chosen: Option<usize>,
    rationale: Option<&str>,
) -> String {
    let mut ttl = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n",
    );
    let escape = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
    };
    let order: Vec<usize> = match chosen {
        Some(i) => std::iter::once(i)
            .chain((0..candidates.len()).filter(|j| *j != i))
            .collect(),
        None => (0..candidates.len()).collect(),
    };
    for (rank, i) in order.iter().enumerate() {
        let c = &candidates[*i];
        ttl.push_str(&format!(
            "\n<{}> a ik:ActionMatch ;\n    ik:endpoint <{}> ;\n    ik:verb \"{}\"",
            c.action, c.endpoint, c.verb
        ));
        for r in &c.requires {
            ttl.push_str(&format!(" ;\n    ik:requires <{r}>"));
        }
        let comment = match (chosen, rank) {
            (Some(_), 0) => rationale.unwrap_or("chosen").to_string(),
            (Some(_), _) => "considered, not chosen".to_string(),
            // No pick. `rationale` distinguishes WHY: absent = no goal was given
            // (the funnel wants disambiguation); present = a goal WAS given but the
            // residual could not choose (unreachable / capability-denied / unparseable)
            // and it degraded to the deterministic list — surfaced so the reason (e.g.
            // a denied urn:llm:ask) is visible in the graph, not silently a "give goal=".
            (None, _) => rationale
                .unwrap_or("candidate — give goal= to disambiguate")
                .to_string(),
        };
        ttl.push_str(&format!(
            " ;\n    rdfs:comment \"{}\" .\n",
            escape(&comment)
        ));
    }
    ttl
}

/// `urn:agent:select` — the tool-selection funnel as one resource: the
/// deterministic narrowing (capability, verb=, want=, types=) runs first via
/// `urn:kernel:actions`; the LLM is the RESIDUAL, consulted only when several
/// authorized actions survive AND a goal= is given. Zero survivors is a clean
/// answer; one survivor never wakes the model. The decision comes back as a
/// graph — chosen action, rationale, and the also-rans — so "why did the
/// agent pick that tool" stays auditable.
struct AgentSelectEndpoint;

#[async_trait::async_trait]
impl Endpoint for AgentSelectEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let mut request = Request::new(
            Verb::Source,
            Iri::parse("urn:kernel:actions").expect("valid IRI"),
        )
        .with_arg("as", ikigai_core::ArgRef::Inline(b"text/turtle".to_vec()));
        for axis in ["types", "verb", "want"] {
            if let Ok(value) = inv.inline_str(axis) {
                request =
                    request.with_arg(axis, ikigai_core::ArgRef::Inline(value.as_bytes().to_vec()));
            }
        }
        let manifold = inv.issue(request).await?;
        let candidates = parse_action_matches(&String::from_utf8_lossy(&manifold.bytes));
        let goal = inv.inline_str("goal").ok();

        if candidates.is_empty() {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"no authorized action fits: the manifold under your capability is empty for this query
"
                    .to_vec(),
            ));
        }
        if candidates.len() == 1 {
            let ttl = selection_turtle(
                &candidates,
                Some(0),
                Some("the only authorized fit — no disambiguation needed"),
            );
            return Ok(Representation::new(
                ReprType::new("text/turtle").with_param("charset", "utf-8"),
                ttl.into_bytes(),
            ));
        }
        let Some(goal) = goal else {
            let ttl = selection_turtle(&candidates, None, None);
            return Ok(Representation::new(
                ReprType::new("text/turtle").with_param("charset", "utf-8"),
                ttl.into_bytes(),
            ));
        };

        // The residual: several authorized fits and a stated goal. The model
        // picks ONE and says why; if it is unreachable or unparseable the
        // ranked list comes back instead — the resource degrades to
        // deterministic, it never fails because inference did.
        let mut prompt = format!(
            "Goal: {goal}

Authorized candidate actions:
"
        );
        for (i, c) in candidates.iter().enumerate() {
            prompt.push_str(&format!(
                "{}. {} — {} on <{}>
",
                i + 1,
                c.action,
                c.verb,
                c.endpoint
            ));
        }
        prompt.push_str("\nRespond EXACTLY as: CHOICE: <number> — <one-sentence rationale>");
        let ask = Request::new(Verb::Source, Iri::parse("urn:llm:ask").expect("valid IRI"))
            .with_arg(
                "system",
                ikigai_core::ArgRef::Inline(
                    b"You select exactly one action from a numbered list. Terse.".to_vec(),
                ),
            )
            .with_arg("prompt", ikigai_core::ArgRef::Inline(prompt.into_bytes()));
        // A goal WAS given, so any non-pick here is a residual *failure*, not a
        // missing goal — capture WHY (unreachable / capability-denied / unparseable)
        // so the degraded graph says so instead of the misleading "give goal=".
        let outcome: std::result::Result<(usize, String), String> = match inv.issue(ask).await {
            Ok(reply) => {
                let text = String::from_utf8_lossy(&reply.bytes).to_string();
                // Parse the declared form first ("CHOICE: 5 — …"): a model that
                // ignores it and emits list formatting ("1. Action 5 …") would
                // otherwise have its FORMATTING read as its choice.
                let digits = |t: &str| -> Option<usize> {
                    t.chars()
                        .skip_while(|ch| !ch.is_ascii_digit())
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                        .parse()
                        .ok()
                };
                let number = text
                    .to_ascii_uppercase()
                    .find("CHOICE")
                    .and_then(|i| digits(&text[i..]))
                    .or_else(|| digits(&text));
                number
                    .and_then(|n| n.checked_sub(1))
                    .filter(|i| *i < candidates.len())
                    .map(|index| (index, format!("goal: {goal} — {}", text.trim())))
                    .ok_or_else(|| {
                        "goal set, but the residual returned no parseable choice — \
                         deterministic ranked list"
                            .to_string()
                    })
            }
            Err(e) => Err(format!(
                "goal set, but the residual was unavailable ({e}) — deterministic ranked list"
            )),
        };
        let ttl = match outcome {
            Ok((index, rationale)) => selection_turtle(&candidates, Some(index), Some(&rationale)),
            Err(reason) => selection_turtle(&candidates, None, Some(&reason)),
        };
        Ok(Representation::new(
            ReprType::new("text/turtle").with_param("charset", "utf-8"),
            ttl.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "agent-select"
    }

    fn describe(&self) -> Description {
        Description::new("agent-select")
            .title("Select an action for a goal")
            .summary(
                "The tool-selection funnel as one resource: deterministic narrowing first                  (your capability, verb=, want=, types= via urn:kernel:actions), the LLM as                  the RESIDUAL — consulted only when several authorized actions survive and                  a goal= is given. Returns the decision as a graph: chosen action,                  rationale, and the also-rans. One survivor never wakes the model;                  inference failure degrades to the ranked list, never to an error.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(ArgSpec::new("goal").summary("natural-language intent for the residual").optional())
            .input(ArgSpec::new("types").summary("present RDF class IRIs").optional())
            .input(
                ArgSpec::new("verb")
                    .summary("only actions answering this verb")
                    .one_of(["source", "sink", "exists", "delete"])
                    .optional(),
            )
            .input(ArgSpec::new("want").summary("only actions producing this media type").optional())
            .output("text/turtle")
            .output("text/plain;charset=utf-8")
    }
}

fn local_space(nature: &'static str) -> EndpointSpace {
    base_space(nature)
        .bind(
            Exact::new("urn:personal:contacts"),
            ikigai_personal::contacts(),
        )
        .bind(
            Exact::new("urn:personal:calendar"),
            ikigai_personal::calendar(calendar_config()),
        )
        .bind(
            Exact::new("urn:personal:availability"),
            ikigai_personal::availability(calendar_config()),
        )
        .bind(
            Exact::new("urn:personal:calendars"),
            ikigai_personal::calendars(calendar_config()),
        )
        .bind(
            Exact::new("urn:personal:calendar:config"),
            ikigai_personal::calendar_config(calendar_config()),
        )
        // The consolidated-view derivation lives in ikigai-view; this host binds
        // its endpoints, injecting the resolved calendar config (loaded here, from
        // calendar.json). The CLI daemon/timer/watcher just issue these through the
        // kernel — untouched by the extraction.
        .bind(
            Exact::new("urn:view:derive"),
            ikigai_view::DeriveEndpoint::new(view_config()),
        )
        .bind(
            Exact::new("urn:view:derive:tick"),
            ikigai_view::DeriveTickEndpoint::new(),
        )
        .bind(Exact::new("urn:agent:select"), AgentSelectEndpoint)
        // The Lisp evaluator — bound into the LOCAL (embedded/native) space only,
        // never `base_space`/`served_space`: it runs arbitrary code, so it stays off
        // served/remote transports and is gated by `urn:cap:lisp` (the embedded REPL's
        // default session is root, which covers it; a `cap`/`login`-narrowed session
        // must hold `urn:cap:lisp` explicitly).
        .bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval())
        .bind(
            Exact::new("urn:view:ingest"),
            ikigai_view::IngestEndpoint::new(view_config()),
        )
        // AFTER the exact binds: the period grammar must not shadow
        // urn:personal:calendar:config (first grammar match wins).
        .bind(
            UriTemplate::parse("urn:personal:calendar:{period}").expect("valid template"),
            ikigai_personal::calendar(calendar_config()),
        )
        .bind(
            UriTemplate::parse("urn:personal:availability:{period}").expect("valid template"),
            ikigai_personal::availability(calendar_config()),
        )
        .bind(
            // The org files, jailed to the configured org_dir and read THROUGH
            // the kernel by urn:org:agenda (capability-gated; golden-thread-ready).
            UriTemplate::parse("urn:orgfile:{path}").expect("valid template"),
            ikigai_fs::FileEndpoint::new(org_config().map(|(dir, _)| dir).unwrap_or_default()),
        )
        .bind(
            UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).expect("FILE_TEMPLATE is valid"),
            // Cacheable: reads of the workspace cache under a golden thread, and a
            // `sink`/`delete` through the kernel auto-cuts it (so a write
            // invalidates the cached read, and any compose over it). The workspace
            // is written through ikigai; out-of-band editor changes are caught by
            // the filesystem watcher behind [`watched_kernel`].
            ikigai_fs::FileEndpoint::new(file_root()).cacheable(),
        )
}

/// The space a remote (QUIC) kernel serves: the base demo space **plus** the file
/// module (`urn:file:{path}`, jailed to [`file_root`]). Files are exposed over the wire
/// now that capability-on-the-wire scopes each connection to its own `<file_root>/<id>`
/// segment (the client cert's principal), so a remote peer gets an **isolated** workspace
/// and the capability path-ACL refuses any other segment. The personal space stays OFF
/// the wire — owner-only, no per-tenant story yet.
fn served_space(nature: &'static str) -> EndpointSpace {
    base_space(nature)
        .bind(
            UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).expect("FILE_TEMPLATE is valid"),
            ikigai_fs::FileEndpoint::new(file_root()).cacheable(),
        )
        // The PUBLIC front doors: a contact enquiry and a booking request. These are the
        // only new things a stranger can name, and all they can do is drop a validated
        // tuple into a space.
        //
        // The privileged half deliberately is NOT here: the reactor that emails an enquiry
        // (and runs schedule.scm against the real calendar) lives in the DAEMON's kernel,
        // not this internet-facing one. So this process never holds `email:send` and never
        // touches EventKit — the TUPLESPACE IS THE AIRLOCK between them.
        //
        // The space binding below is what lets an intake complete its drop. It is reachable
        // only through a declared route: run the public edge with `--routes-only` so an
        // un-routed path (a direct POST to some other space) is a 404, and grant a ceiling
        // of exactly {contact:submit, booking:submit, space:out}. Route table = the surface
        // allowlist, capability = the authority ceiling; a bug in one still leaves the other.
        .bind(
            Exact::new("urn:contact:submit"),
            ikigai_intake::submit(contact_intake()),
        )
        .bind(
            Exact::new("urn:booking:submit"),
            ikigai_intake::submit(booking_intake()),
        )
        .bind(
            UriTemplate::parse(ikigai_intray::SPACE_TEMPLATE).expect("SPACE_TEMPLATE is valid"),
            ikigai_intray::SpaceEndpoint::new(file_root().join("spaces")),
        )
        // The emailed decision links: /calendar-request/{approve,decline}. Public — the
        // signed token IS the authorisation, and this host only RECORDS the decision into a
        // space. It reads a public key from a file and needs no secret authority at all.
        .bind(
            UriTemplate::parse("urn:calendar-request:{action}").expect("valid template"),
            decide::CalendarRequest {
                key_path: decide::public_key_path(),
            },
        )
        // The emailed "block this sender" link: /contact-block. Same public shape as the
        // calendar-request links — the signed token IS the authorisation, GET shows and POST
        // RECORDS into a space. It reads only the contact-block PUBLIC key from a file and, like
        // the decision links, holds no `decisions:write`: writing the blocklist is the daemon's
        // apply reactor, never this internet-facing face (Phase 1's ceiling stays read-only).
        .bind(
            Exact::new("urn:contact-block"),
            contactblock::ContactBlock {
                key_path: contactblock::public_key_path(),
            },
        )
        // The passkey second factor's PUBLIC face: `urn:passkey:challenge` mints a login
        // challenge, `urn:passkey:register` shows the enrolment page and stores a credential
        // (only while a window opened at the box is live). Both read/verify against the edge's
        // own credential + challenge stores; neither holds a signing key or `decisions:write`.
        // The gate itself (`passkey::require_passkey`) is called inside the contact-block and
        // calendar-request POSTs, and is inert until a credential is enrolled.
        .bind(
            Exact::new("urn:passkey:challenge"),
            passkey::PasskeyChallenge,
        )
        .bind(Exact::new("urn:passkey:register"), passkey::PasskeyRegister)
        // The ceremony script, served same-origin so the strict edge CSP (`default-src 'self'`,
        // which forbids inline scripts) admits it — the decision + register pages carry only a
        // `<script src="/passkey/app.js">` tag.
        .bind(Exact::new("urn:passkey:js"), passkey::PasskeyJs)
        // Attribution for handed-out links. The edge grants `urn:cap:client:read` and
        // nothing filesystem-shaped, so this can name a client and do nothing else.
        .bind(
            UriTemplate::parse(CLIENT_TEMPLATE).expect("CLIENT_TEMPLATE is valid"),
            ClientRegistry::new(file_root()),
        )
        // The blocklist, EDGE-LOCAL. The public intake reads it (`blocked=<email>`) to reject a
        // blocked sender at the door on either channel; recording a block is cap-gated
        // (`urn:cap:decisions:write` — not in the public ceiling), so a stranger can never add
        // one. Same `log_path` as the host root, so a manual `sink urn:decisions …` run on the
        // box (under root) is the same file the served intake reads.
        .bind(
            Exact::new("urn:decisions"),
            decisions::DecisionLog {
                path: decisions::log_path(),
            },
        )
}

/// A purpose-built kernel for a calendar-federation server (`ikigai serve quic://…
/// --cap urn:cap:personal:calendar:read:freebusy`): the base host resources PLUS the
/// calendar endpoints ONLY — `urn:personal:availability`, `urn:personal:calendar`,
/// and its period grammar — and deliberately NOTHING else. No contacts, no filesystem
/// (`served_space`'s `urn:file:` is omitted), no exec, no org. So the entire surface a
/// remote client can even name is the calendar, and the connection's clamped capability
/// (a free/busy ceiling → free/busy, a detail/write grant → detail/write) governs what
/// of that it may actually resolve. Defense-in-depth: authority is clamped AND the
/// manifold is minimal, so a bug in one still leaves the other. The endpoints read
/// EventKit directly through the configured calendar, so this kernel is only useful on
/// the machine holding the calendar (with its TCC grant).
pub fn calendar_server_space(nature: &'static str) -> EndpointSpace {
    base_space(nature)
        .bind(
            Exact::new("urn:personal:availability"),
            ikigai_personal::availability(calendar_config()),
        )
        .bind(
            Exact::new("urn:personal:calendar"),
            ikigai_personal::calendar(calendar_config()),
        )
        // AFTER the exact bind: the period grammar (`urn:personal:calendar:this-week`)
        // must not shadow the bare `urn:personal:calendar` (first grammar match wins).
        .bind(
            UriTemplate::parse("urn:personal:calendar:{period}").expect("valid template"),
            ikigai_personal::calendar(calendar_config()),
        )
        .bind(
            UriTemplate::parse("urn:personal:availability:{period}").expect("valid template"),
            ikigai_personal::availability(calendar_config()),
        )
}

/// The kernel a calendar-federation server runs. See [`calendar_server_space`].
pub fn calendar_server_kernel() -> Kernel {
    Kernel::with_meta_renderer(
        Arc::new(calendar_server_space("Calendar (QUIC)")),
        Arc::new(CliRenderer),
    )
}

/// The wire-eval L1 posture: `urn:lisp:eval` behind the wall-clock [`Timeout`]
/// governor, composed IN FRONT of a base surface (`Fallback` — first hit wins, so
/// the governed binding shadows any ungoverned one beneath). The governor bounds
/// how long a shipped program may hold the CALLER (typed transient `Timeout` at
/// the budget; `--eval-timeout <secs>`, default 10); the worker ceiling in
/// ikigai-lisp bounds how many runaway workers can ever exist; the kernel's
/// declared-`requires` floor enforces `urn:cap:lisp`; and on QUIC the
/// connection's minted ceiling must GRANT that cap for eval to be visible or
/// invocable at all. Together: cert-gated, cap-clamped, thread-bounded,
/// time-boxed remote evaluation — the transport for portable code.
fn with_wire_eval(base: Arc<dyn ikigai_core::Space>) -> Arc<dyn ikigai_core::Space> {
    let budget = eval_timeout_secs();
    let mut governed_space =
        EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval());
    let mut spaces: Vec<Arc<dyn ikigai_core::Space>> = Vec::new();

    // The signed-program door (wire-eval L1.5): configured by `--code-signer`
    // (repeatable) — public-key resource IRIs, conventionally `urn:codekey:<file>`
    // served from the code-signers directory below. None declared ⇒ `urn:lisp:run`
    // is NOT bound: the feature is absent, never defaulted to an empty-but-present
    // trust set. The signature gates what may run; the connection's clamped
    // capability still gates what it touches; the same Timeout governor fronts it.
    if let Some(signers) = code_signers() {
        governed_space =
            governed_space.bind(Exact::new("urn:lisp:run"), ikigai_lisp::run_signed(signers));
        // The signer public keys as resources: `urn:codekey:{file}` from the
        // code-signers directory (`--code-signers-dir`, default
        // `~/.config/ikigai/code-signers`) — via a dedicated OPEN endpoint, not
        // the fs module: public keys are public (that's the point of them), and
        // an fs-capped binding would demand an fs grant from a signed-only
        // ceiling just to VERIFY (the kernel's requires-floor rightly refused
        // exactly that in testing). Single path segment only; no traversal. The
        // sign module mounts too, so `urn:lisp:run`'s kernel-issued
        // `urn:sign:verify` resolves on served surfaces (verify is open + pure;
        // `urn:sign:sign` stays gated by `urn:cap:sign`, which no served ceiling
        // grants by default).
        spaces.push(Arc::new(EndpointSpace::new().bind(
            UriTemplate::parse("urn:codekey:{path}").expect("valid template"),
            CodeKey {
                dir: code_signers_dir(),
            },
        )));
        spaces.push(Arc::new(ikigai_sign::space()));
    }

    spaces.insert(
        0,
        Arc::new(ikigai_throttle::Timeout::new(
            governed_space,
            std::time::Duration::from_secs(budget),
        )),
    );
    spaces.push(base);
    Arc::new(ikigai_core::Fallback::new(spaces))
}

/// The code-signing trust set: public-key resource IRIs the host accepts
/// signatures from, set by the CLI's `--code-signer` flag (repeatable) via
/// [`set_code_signers`]. Empty ⇒ `None` ⇒ the signed-run door simply doesn't
/// exist (a feature is absent, never silently defaulted).
fn code_signers() -> Option<Vec<String>> {
    let signers = CODE_SIGNERS.lock().expect("code signers lock").clone();
    if signers.is_empty() {
        None
    } else {
        Some(signers)
    }
}

/// The trust set + its key directory, as configured by the host process before
/// it builds a kernel. Process-global like the demo flag and the instance name:
/// the CLI sets it while parsing `serve`'s flags, and the kernel builders read
/// it. (Configuration arrives as flags — not environment variables.)
static CODE_SIGNERS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
/// Wall-clock ceiling for a served eval, in seconds (`--eval-timeout`).
/// 0 = UNSET, so the config can be consulted. A concrete value here means `--eval-timeout`
/// was given, and an explicit flag beats a config file.
static EVAL_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(0);

/// The wall-clock budget for `urn:lisp:eval`, in seconds.
///
/// Precedence: `--eval-timeout` (posture, set per server) → `lisp.timeout` in the host
/// config → 10s.
///
/// Ten seconds is right for its original purpose — bounding a program a STRANGER shipped
/// over QUIC, where a runaway must not pin the server. It is wrong for the same-user IPC
/// host, because every `ikigai-invoke` from Emacs wraps its call in Lisp: asking a 70B model
/// a question is one `urn:lisp:eval`, and it was being cut off at 10s as though it were
/// hostile. The threat differs by transport, so the budget has to be settable rather than
/// fixed — and a wire-facing server should state its own with `--eval-timeout` (bug's peer
/// plist already does).
fn eval_timeout_secs() -> u64 {
    let flag = EVAL_TIMEOUT_SECS.load(Ordering::Relaxed);
    if flag > 0 {
        return flag;
    }
    config::get("lisp.timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(10)
}
static CODE_SIGNERS_DIR: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Declare the code-signing trust set: the public-key resource IRIs whose
/// signatures this host will run programs for (`--code-signer`, repeatable).
/// Call before building a served kernel; with none set, `urn:lisp:run` is not
/// bound at all.
pub fn set_code_signers(signers: Vec<String>) {
    *CODE_SIGNERS.lock().expect("code signers lock") = signers;
}

/// Whether a code-signing trust set was declared (`--code-signer`) — what the
/// serve banner reports as the `signed-run` surface.
pub fn code_signers_configured() -> bool {
    code_signers().is_some()
}

/// Point `urn:codekey:{file}` at a directory other than the default
/// `~/.config/ikigai/code-signers` (`--code-signers-dir`).
pub fn set_code_signers_dir(dir: std::path::PathBuf) {
    *CODE_SIGNERS_DIR.lock().expect("code signers dir lock") = Some(dir);
}

/// Set the wall-clock ceiling a served eval may run for (`--eval-timeout`,
/// seconds; minimum 1). Default 10.
pub fn set_eval_timeout_secs(secs: u64) {
    EVAL_TIMEOUT_SECS.store(secs.max(1), Ordering::Relaxed);
}

/// Where the code-signing public keys live (`urn:codekey:{file}` resolves here):
/// `--code-signers-dir` if given, else `~/.config/ikigai/code-signers`.
fn code_signers_dir() -> std::path::PathBuf {
    if let Some(dir) = CODE_SIGNERS_DIR
        .lock()
        .expect("code signers dir lock")
        .clone()
    {
        return dir;
    }
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
        .join(".config/ikigai/code-signers")
}

/// `urn:codekey:{file}` — a code-signing PUBLIC key, served openly from the
/// operator-curated signers directory. Open by design: a public key's job is to
/// be read (a signed-only ceiling must resolve it just to verify), and the
/// operator placing a file in this one directory is the act of publication.
/// Exactly one path segment — separators and traversal are refused, so nothing
/// outside the directory is nameable.
struct CodeKey {
    dir: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for CodeKey {
    async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
        let name = inv.bindings.get("path").ok_or_else(|| {
            ikigai_core::Error::MissingArgument("path (the key file name)".to_string())
        })?;
        if name.contains('/') || name.contains("\\") || name.contains("..") || name.is_empty() {
            return Err(ikigai_core::Error::Endpoint(format!(
                "urn:codekey: `{name}` is not a plain file name"
            )));
        }
        let path = self.dir.join(name);
        let bytes = std::fs::read(&path)
            .map_err(|e| ikigai_core::Error::NotFound(format!("code-signing key `{name}`: {e}")))?;
        Ok(Representation::new(
            ReprType::new("application/x-pem-file"),
            bytes,
        ))
    }

    fn name(&self) -> &str {
        "codekey"
    }

    fn describe(&self) -> Description {
        Description::new("codekey")
            .title("Code-signing public key")
            .summary(
                "A code-signing PUBLIC key from the operator's signers directory \
                 (`--code-signers-dir`). Open — a public key exists to be read; placing a \
                 file in the directory is the act of publication. One plain file name, no \
                 traversal.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("application/x-pem-file")
    }
}

/// [`calendar_server_kernel`] plus the governed wire-eval binding — the posture a
/// personal-ceiling server runs when its `--cap` ceiling ALSO grants
/// `urn:cap:lisp`: a trusted peer ships s-exprs that compose with this machine's
/// calendar resources, under the clamp, the governor, and the worker ceiling.
pub fn calendar_server_kernel_with_eval() -> Kernel {
    Kernel::with_meta_renderer(
        with_wire_eval(Arc::new(calendar_server_space("Calendar (QUIC)"))),
        Arc::new(CliRenderer),
    )
}

/// [`kernel_for`] plus the governed wire-eval binding — the default served
/// surface for an operator whose `--cap` ceiling grants `urn:cap:lisp`.
pub fn kernel_for_with_eval(nature: &'static str) -> Kernel {
    Kernel::with_meta_renderer(
        with_wire_eval(Arc::new(served_space(nature))),
        Arc::new(CliRenderer),
    )
}

/// Which optional faces a served kernel carries. Each is decided by the
/// connection ceiling the operator set (`--cap`), not by a separate switch: the
/// GRANT DECIDES THE SURFACE, so a capability that could never be exercised
/// doesn't put the endpoints on the wire in the first place.
#[derive(Clone, Copy, Default, Debug)]
pub struct ServedSurface {
    /// A `urn:cap:personal:*` ceiling ⇒ the minimal calendar-only space instead
    /// of the general served space.
    pub personal: bool,
    /// `urn:cap:lisp` / `urn:cap:lisp:run` ⇒ the governed eval + signed-run door.
    pub wire_eval: bool,
    /// A `urn:cap:net:*` ceiling ⇒ `urn:llm:*` is servable: a peer may spend THIS
    /// machine's inference. Bounded by construction — the llm module only reaches
    /// its configured providers, and `require_net` still checks the provider host
    /// against the grant, so `--cap urn:cap:net:localhost` means "use my local
    /// models, nothing else". The general HTTP client stays embedded-only, so this
    /// grants no arbitrary outbound access. (`urn:llm:config` redacts API keys.)
    pub llm: bool,
}

/// Build the served kernel for `surface`. One composer instead of a kernel
/// function per combination.
pub fn served_kernel(nature: &'static str, surface: ServedSurface) -> Kernel {
    let base: Arc<dyn Space> = if surface.personal {
        Arc::new(calendar_server_space(nature))
    } else {
        Arc::new(served_space(nature))
    };
    // The LLM face sits in front of the base surface (it binds its own namespace;
    // order only matters for a prefix collision, and there is none).
    let base: Arc<dyn Space> = if surface.llm {
        Arc::new(ikigai_core::Fallback::new(vec![
            Arc::new(llm_space()) as Arc<dyn Space>,
            base,
        ]))
    } else {
        base
    };
    let root = if surface.wire_eval {
        with_wire_eval(base)
    } else {
        base
    };
    Kernel::with_meta_renderer(root, Arc::new(CliRenderer))
}

/// The native HTTP transport backing the `urn:http*` endpoints: a blocking `ureq`
/// client. Runtime-free, so it runs under the CLI's `futures::block_on` without
/// pulling in Tokio — the executor stays chosen at the edge.
struct UreqTransport;

#[async_trait::async_trait]
impl ikigai_http::HttpTransport for UreqTransport {
    async fn send(
        &self,
        request: ikigai_http::HttpRequest,
    ) -> std::result::Result<ikigai_http::HttpResponse, String> {
        use std::io::Read;
        // The HttpTransport contract (ikigai-http ≥ 0.1.7) forbids following
        // redirects here: the ENDPOINT follows them, re-running the net-capability
        // ACL against every hop — an auto-following agent would let a granted
        // host 302 the request to an ungranted one. `redirects(0)` returns the
        // 3xx as-is.
        let agent = ureq::builder().redirects(0).build();
        let mut req = agent.request(request.method.as_str(), &request.url);
        for (name, value) in &request.headers {
            req = req.set(name, value);
        }
        let outcome = if request.body.is_empty() {
            req.call()
        } else {
            req.send_bytes(&request.body)
        };
        // A 4xx/5xx is still a response (with a body), not a transport failure.
        let resp = match outcome {
            Ok(resp) => resp,
            Err(ureq::Error::Status(_, resp)) => resp,
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        let headers = resp
            .headers_names()
            .into_iter()
            .filter_map(|name| resp.header(&name).map(|v| (name.clone(), v.to_string())))
            .collect();
        // A HEAD response carries headers only — no body to read.
        let mut body = Vec::new();
        if request.method != ikigai_http::Method::Head {
            resp.into_reader()
                .read_to_end(&mut body)
                .map_err(|e| format!("reading response body: {e}"))?;
        }
        Ok(ikigai_http::HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// The HTTP-client module space (`urn:httpGet`…`urn:httpDelete`) on the native
/// transport — mounted only on the *local* kernel for now, alongside the personal
/// space, since outbound HTTP from a wire-served kernel awaits capability-on-the-wire.
fn http_space() -> EndpointSpace {
    ikigai_http::space(Arc::new(UreqTransport))
}

/// The LLM module (`urn:llm:ask` + `urn:llm:<provider>:ask`) on the native ureq
/// transport. Slice 0: an OpenAI-compatible backend defaulting to a local Ollama.
/// (Mounted via a local path override until ikigai-llm is published.)
fn llm_space() -> EndpointSpace {
    ikigai_llm::space(Arc::new(UreqTransport), llm_registry())
}

/// The meeting module (`urn:meeting:schedule` + `urn:meeting:zoom:schedule`) on the native ureq
/// transport. Reads the Zoom Server-to-Server OAuth credentials from the keystore through a
/// [`HostSecrets`] reader (the same Keychain backend the `urn:secret:*` space uses), so the crate
/// links neither an HTTP client nor the keystore. Embedded-root only (not served over the wire),
/// alongside the secret/sign/encrypt family.
fn meeting_space() -> EndpointSpace {
    ikigai_meeting::space(
        Arc::new(UreqTransport),
        Arc::new(HostSecrets(ikigai_secret::default_backend())),
        ikigai_meeting::ZoomConfig::default(),
    )
}

/// What the catalog says about one endpoint: its summary, and each non-Meta verb with the
/// arguments that verb requires (in declaration order).
type DescribedEndpoint = (String, Vec<(String, Vec<String>)>);

/// One endpoint, as the alias generator needs it: the IRI you resolve, a name, and the
/// arguments each verb declares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AliasTarget {
    /// The RESOLVABLE IRI — from the space entry, not the catalog. The catalog names
    /// endpoints by a skolem IRI (`urn:ikigai:endpoint:toUpper`), which is a description,
    /// not an address; `urn:fn:toUpper` is what you can actually call.
    iri: String,
    summary: String,
    /// (verb, required inputs in declaration order).
    actions: Vec<(String, Vec<String>)>,
}

/// Reading the manifold IS inspection, so the alias generator needs the same grant
/// `urn:kernel:actions` and `urn:kernel:catalog` do. DECLARED, not merely enforced by the
/// inner resolutions: an action that enforces a cap it does not declare makes the manifold
/// over-offer, and the denial then surfaces from a nested call instead of the door.
const CAP_KERNEL_INSPECT: &str = "urn:cap:kernel:inspect";

/// `urn:lisp:aliases` — the manifold projected as callable Lisp.
///
/// Named verbs instead of URIs: `(fn-toUpper "hi")` rather than
/// `source urn:fn:toUpper in=hi`. GENERATED, never hand-written — every endpoint already
/// declares its ArgSpecs, and the same projection that turns the manifold into MCP tools
/// turns it into functions. So the alias surface cannot drift from what the server accepts
/// (the property that makes a booking form build itself from `?description`), and a new
/// endpoint gets a verb for free. Hand-maintained aliases would rot in a week.
struct LispAliases;

#[async_trait::async_trait]
impl Endpoint for LispAliases {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // THE MANIFOLD, not the raw catalog: `urn:kernel:actions` is already narrowed to
        // what THIS capability may invoke, already carries the RESOLVABLE IRI
        // (`ik:endpoint <urn:fn:toUpper>`, not the skolem description IRI), and already
        // omits templates. So capability filtering is not a filter bolted on here — it is
        // the surface the kernel says you have. A scoped session gets a smaller prelude,
        // not a full one that fails at call time.
        let mut request = Request::new(
            Verb::Source,
            Iri::parse("urn:kernel:actions").expect("a constant IRI"),
        );
        request = request.with_arg("as", ArgRef::Inline(b"text/turtle".to_vec()));
        let manifold = inv.issue(request).await?;
        let candidates = parse_action_matches(&String::from_utf8_lossy(&manifold.bytes));
        // The catalog supplies what the manifold does not: summaries, and which inputs are
        // REQUIRED (so they become positional parameters rather than riding in `rest`).
        let catalog = inv
            .issue(Request::new(
                Verb::Source,
                Iri::parse("urn:kernel:catalog").expect("a constant IRI"),
            ))
            .await?;
        let described = catalog_descriptions(&String::from_utf8_lossy(&catalog.bytes));
        let targets = alias_targets(&candidates, &described);
        let prefix = inv.inline_str("prefix").unwrap_or("").to_string();
        // Two REPRESENTATIONS of one resource, not two endpoints: the same projection,
        // emitted for whichever lisp is asking.
        let elisp = inv
            .inline_str("as")
            .map(|v| v.contains("emacs"))
            .unwrap_or(false);
        let (body, repr) = if elisp {
            (aliases_elisp(&targets, &prefix), "text/x-emacs-lisp")
        } else {
            (aliases_scheme(&targets, &prefix), "text/x-scheme")
        };
        Ok(Representation::new(ReprType::new(repr), body.into_bytes()))
    }

    fn name(&self) -> &str {
        "lisp-aliases"
    }

    fn describe(&self) -> Description {
        Description::new("lisp-aliases")
            .summary(
                "this kernel's resources as callable Lisp definitions, generated from the manifold",
            )
            .verb(Verb::Source)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the alias prelude — one definition per resolvable endpoint")
                    .input(
                        ArgSpec::new("as")
                            .optional()
                            .one_of(["text/x-scheme", "text/x-emacs-lisp"])
                            .summary("which lisp to emit (default Scheme, for urn:lisp:eval)"),
                    )
                    .input(ArgSpec::new("prefix").optional().summary(
                        "only endpoints whose IRI starts with this (e.g. `urn:fn:`), \
                                 for a prelude scoped to one family",
                    ))
                    .requires(CAP_KERNEL_INSPECT),
            )
    }
}

/// Join the capability-scoped manifold (which knows WHAT MAY BE CALLED and its resolvable
/// IRI) with the catalog (which knows the arguments), on the endpoint's id.
///
/// The manifold's `ik:ActionMatch` subject encodes that id:
/// `urn:ikigai:endpoint:{id}:action:{verb}`.
fn alias_targets(
    candidates: &[SelectCandidate],
    described: &std::collections::BTreeMap<String, DescribedEndpoint>,
) -> Vec<AliasTarget> {
    use std::collections::BTreeMap;
    let mut by_iri: BTreeMap<String, AliasTarget> = BTreeMap::new();
    for candidate in candidates {
        // A family is not a callable: a template IRI has nothing sensible to pass. The
        // manifold does not currently surface them; belt and braces, since one appearing
        // would otherwise emit a verb nobody can call.
        if candidate.endpoint.contains('{') || candidate.endpoint.is_empty() {
            continue;
        }
        let Some(id) = action_endpoint_id(&candidate.action) else {
            continue;
        };
        let (summary, actions) = match described.get(&id) {
            Some(described) => described.clone(),
            // Described nowhere: still callable, just undocumented and with no declared
            // inputs — emit it argument-less rather than dropping an authorized action.
            None => (String::new(), Vec::new()),
        };
        let required = actions
            .iter()
            .find(|(verb, _)| *verb == candidate.verb)
            .map(|(_, required)| required.clone())
            .unwrap_or_default();
        let entry = by_iri
            .entry(candidate.endpoint.clone())
            .or_insert_with(|| AliasTarget {
                iri: candidate.endpoint.clone(),
                summary,
                actions: Vec::new(),
            });
        entry.actions.push((candidate.verb.clone(), required));
    }
    let mut targets: Vec<AliasTarget> = by_iri.into_values().collect();
    for target in &mut targets {
        target.actions.sort();
        target.actions.dedup();
    }
    // Deterministic output: a prelude that reorders itself between runs is an unreadable
    // diff, and these get committed.
    targets.sort_by(|a, b| a.iri.cmp(&b.iri));
    targets
}

/// `urn:ikigai:endpoint:agent-select:action:source` → `agent-select`.
fn action_endpoint_id(action: &str) -> Option<String> {
    action
        .strip_prefix("urn:ikigai:endpoint:")?
        .rsplit_once(":action:")
        .map(|(id, _verb)| id.to_string())
}

/// Parse the catalog's Turtle into `endpoint id -> (summary, [(verb, required inputs)])`.
///
/// Two shapes have to survive here. Inputs may be SKOLEMIZED
/// (`<…endpoint:toUpper:input:in>`) or BLANK (`ik:input [ ik:inputName "in" ; … ]`), so
/// subjects are keyed as strings either way rather than filtering to named nodes — doing
/// the latter silently produced zero arguments for every endpoint. Per-verb `ik:Action`
/// nodes are used when present; when they are not, the endpoint's own verbs and inputs are
/// the contract, which is exactly right for the single-verb endpoints that are the 93% case.
fn catalog_descriptions(turtle: &str) -> std::collections::BTreeMap<String, DescribedEndpoint> {
    use std::collections::BTreeMap;
    const IK: &str = "https://ikigai-rs.dev/ns#";

    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut summaries: BTreeMap<String, String> = BTreeMap::new();
    let mut verbs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inputs_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut input_name: BTreeMap<String, String> = BTreeMap::new();
    let mut input_required: BTreeMap<String, bool> = BTreeMap::new();

    // Blank and named subjects alike, as a plain key.
    let key = |t: &oxrdf::NamedOrBlankNode| match t {
        oxrdf::NamedOrBlankNode::NamedNode(n) => n.as_str().to_string(),
        oxrdf::NamedOrBlankNode::BlankNode(b) => format!("_:{}", b.as_str()),
    };
    let obj_key = |t: &oxrdf::Term| match t {
        oxrdf::Term::NamedNode(n) => Some(n.as_str().to_string()),
        oxrdf::Term::BlankNode(b) => Some(format!("_:{}", b.as_str())),
        _ => None,
    };

    for quad in
        oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(turtle.as_bytes())
    {
        let Ok(quad) = quad else { continue };
        let subject = key(&quad.subject);
        let pred = quad.predicate.as_str().to_string();
        if let oxrdf::Term::Literal(l) = &quad.object {
            let value = l.value().to_string();
            match pred.strip_prefix(IK) {
                Some("id") => {
                    ids.insert(subject, value);
                }
                Some("summary") => {
                    summaries.entry(subject).or_insert(value);
                }
                Some("verb") => verbs.entry(subject).or_default().push(value),
                Some("inputName") => {
                    input_name.insert(subject, value);
                }
                Some("required") => {
                    input_required.insert(subject, value == "true");
                }
                _ => {}
            }
        } else if pred.strip_prefix(IK) == Some("input") {
            if let Some(object) = obj_key(&quad.object) {
                inputs_of.entry(subject).or_default().push(object);
            }
        }
    }

    let mut out = BTreeMap::new();
    for (endpoint, id) in ids {
        let summary = summaries.get(&endpoint).cloned().unwrap_or_default();
        // Declaration order is preserved by the parser, and it is the order a generated
        // function's positional parameters must follow.
        let mut required: Vec<String> = Vec::new();
        for input in inputs_of.get(&endpoint).into_iter().flatten() {
            if !input_required.get(input).copied().unwrap_or(false) {
                continue;
            }
            let Some(name) = input_name.get(input) else {
                continue;
            };
            // DEDUPE BY NAME, keeping declaration order. The catalog concatenates every
            // space, so a MOUNTED kernel describes the same endpoint again under the same
            // skolem subject (`urn:ikigai:endpoint:llm-ask`) — and accumulating across both
            // gave `prompt` twice, which generated
            //     (defun ikigai-llm-ask (prompt prompt &rest args) …)
            // an uncallable function. Only visible on a machine that actually has a mount,
            // which is the machine that needs this most.
            if !required.iter().any(|existing| existing == name) {
                required.push(name.clone());
            }
        }
        // Verbs dedupe for the same reason the inputs do: a mounted kernel describes the
        // same endpoint again under the same subject, so `ik:verb "Source"` arrives twice
        // and would emit the same defun twice.
        let mut seen_verbs: Vec<&String> = Vec::new();
        let mut actions: Vec<(String, Vec<String>)> = Vec::new();
        for verb in verbs.get(&endpoint).into_iter().flatten() {
            // Meta is every endpoint's self-description, not a selectable action.
            if verb == "Meta" || seen_verbs.contains(&verb) {
                continue;
            }
            seen_verbs.push(verb);
            actions.push((verb.clone(), required.clone()));
        }
        if !actions.is_empty() {
            out.insert(id, (summary, actions));
        }
    }
    out
}

/// Scheme identifiers a generated parameter must not shadow.
///
/// Two families, both of which produced real breakage: SYNTACTIC KEYWORDS — `urn:fn:conditional`
/// declares an argument literally named `if`, and `(define (fn-conditional if …) …)` fails to
/// parse — and the identifiers the generated BODY itself uses, which a parameter of the same
/// name would shadow out from under it. The wire name is unaffected: only the binder is
/// renamed, so `"if"` still travels as `"if"`.
const SCHEME_RESERVED: &[&str] = &[
    // R7RS syntactic keywords
    "and",
    "begin",
    "case",
    "cond",
    "define",
    "define-syntax",
    "delay",
    "do",
    "else",
    "if",
    "lambda",
    "let",
    "let*",
    "letrec",
    "letrec*",
    "or",
    "quasiquote",
    "quote",
    "set!",
    "syntax-rules",
    "unless",
    "unquote",
    "when",
    // used by the generated body — shadowing these breaks the call itself
    "apply",
    "invoke",
    "rest",
];

/// A parameter name that is safe to bind. `if` → `if*`.
fn safe_param(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if SCHEME_RESERVED.contains(&clean.as_str()) || clean.is_empty() {
        format!("{clean}*")
    } else {
        clean
    }
}

/// `urn:fn:toUpper` + Source → `fn-toUpper`; a Sink gets the Scheme mutation `!`.
fn alias_name(iri: &str, verb: &str) -> String {
    let stem = iri
        .strip_prefix("urn:")
        .unwrap_or(iri)
        .replace(':', "-")
        .replace(['/', '.', ' '], "-");
    match verb {
        "Sink" => format!("{stem}!"),
        "Delete" => format!("{stem}-delete!"),
        "Exists" => format!("{stem}?"),
        _ => stem,
    }
}

/// Emit the prelude. Pure, so the shape is testable without a kernel.
fn aliases_scheme(targets: &[AliasTarget], prefix: &str) -> String {
    let mut out = String::from(
        ";; GENERATED from this kernel's manifold — do not edit.\n\
         ;; Every definition here comes from an endpoint's own declared arguments, so this\n\
         ;; surface cannot drift from what the kernel accepts. Regenerate with\n\
         ;; `source urn:lisp:aliases`.\n\n",
    );
    let mut emitted = 0;
    for target in targets {
        if !prefix.is_empty() && !target.iri.starts_with(prefix) {
            continue;
        }
        for (verb, required) in &target.actions {
            let name = alias_name(&target.iri, verb);
            let binders: Vec<String> = required.iter().map(|r| safe_param(r)).collect();
            let params = binders.join(" ");
            // Build the flat name→value list as a CONS CHAIN ending in `rest`, bound with
            // `let` before the call. Three Steel constraints force this exact shape, each
            // found by running it:
            //   * `(apply invoke …)` fails — applying to a PRELUDE-defined variadic across
            //     the clone-per-eval boundary errors with `FreeIdentifier: ##rest2`.
            //   * `(append (list …) rest)` fails the same way; `cons` is fine.
            //   * passing the cons chain DIRECTLY to the native `%verb-args` fails too;
            //     binding it with `let` first materializes it and works.
            // So this calls the fixed-arity primitive with a let-bound list. Less pretty
            // than `(apply invoke …)`, and the only version that actually runs.
            let mut args = "rest".to_string();
            for (wire, binder) in required.iter().zip(&binders).rev() {
                args = format!("(cons \"{wire}\" (cons {binder} {args}))");
            }
            if !target.summary.is_empty() {
                out.push_str(&format!(";; {}\n", first_line(&target.summary)));
            }
            // The trailing `. rest` keeps OPTIONAL arguments reachable — a generated verb
            // is a shortcut for the common call, never a narrowing of the endpoint:
            // `(fn-toUpper "hi" "as" "text/plain")` still works.
            out.push_str(&format!(
                "(define ({name}{}{} . rest)\n  (let ((args {args}))\n    (%verb-args \"{}\" \"{}\" args)))\n\n",
                if params.is_empty() { "" } else { " " },
                params,
                verb.to_lowercase(),
                target.iri,
            ));
            emitted += 1;
        }
    }
    if emitted == 0 {
        out.push_str(";; (no endpoints matched)\n");
    }
    out
}

/// The header of a generated elisp file.
///
/// There is deliberately NO bundled runtime. `ikigai-emacs`'s `ikigai.el` already owns the
/// transport (`--connect` vs embedded `--mount`s), the mount-alias rewriting, the quoting,
/// and the stderr split that keeps cache tags out of stdout — and it defines
/// `ikigai-invoke`, which is exactly the primitive these need. Shipping a second runtime
/// would duplicate all of that AND collide on `ikigai-connect`/`ikigai-program`.
const ELISP_HEADER: &str = ";;; -*- lexical-binding: t -*-\n\
     ;;; Generated from an ikigai kernel's manifold — do not edit.\n\
     ;;;\n\
     ;;; One function per resource this capability may invoke, with the arguments that\n\
     ;;; resource declares. Regenerate with:\n\
     ;;;   ikigai -c 'source urn:lisp:aliases as=text/x-emacs-lisp' < /dev/null\n\
     ;;;\n\
     ;;; Transport, mounts and quoting come from ikigai.el.\n\n\
     (require 'ikigai)\n\n";

/// Emit the elisp face. Same targets, same rules — a different lisp.
fn aliases_elisp(targets: &[AliasTarget], prefix: &str) -> String {
    let mut out = String::from(ELISP_HEADER);
    let mut emitted = 0;
    for target in targets {
        if !prefix.is_empty() && !target.iri.starts_with(prefix) {
            continue;
        }
        for (verb, required) in &target.actions {
            // `ikigai-` namespaces the whole surface. Guarded against the handful of names
            // ikigai.el already owns — `urn:eval:*` would otherwise generate `ikigai-eval`
            // and redefine the function everything else here calls through.
            let name = elisp_defun_name(&alias_name(&target.iri, verb));
            let binders: Vec<String> = required.iter().map(|r| safe_elisp_param(r)).collect();
            let params = if binders.is_empty() {
                "&rest args".to_string()
            } else {
                format!("{} &rest args", binders.join(" "))
            };
            let passed: String = required
                .iter()
                .zip(&binders)
                .map(|(wire, binder)| format!(" \"{wire}\" {binder}"))
                .collect();
            let doc = if target.summary.is_empty() {
                format!("Issue {} on `{}'.", verb.to_lowercase(), target.iri)
            } else {
                // Elisp docstrings are string literals: escape quotes and backslashes.
                first_line(&target.summary)
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            };
            out.push_str(&format!(
                "(defun {name} ({params})\n  \"{doc}\"\n  (apply #'ikigai-invoke '{} \"{}\"{passed} args))\n\n",
                verb.to_lowercase(),
                target.iri,
            ));
            emitted += 1;
        }
    }
    if emitted == 0 {
        out.push_str(";; (no endpoints matched)\n");
    }
    out.push_str("(provide 'ikigai-aliases)\n");
    out
}

/// Public names `ikigai.el` already defines. A generated defun must not redefine them —
/// `ikigai-eval` in particular is what every alias calls through.
const ELISP_TAKEN: &[&str] = &[
    "ikigai-eval",
    "ikigai-invoke",
    "ikigai-repl",
    "ikigai-eval-dwim",
    "ikigai-schedule-zoom",
    "ikigai-org-schedule-zoom",
    "ikigai-org-email-invite",
];

/// `fn-toUpper` → `ikigai-fn-toUpper`, avoiding names ikigai.el owns.
fn elisp_defun_name(stem: &str) -> String {
    let name = format!("ikigai-{stem}");
    if ELISP_TAKEN.contains(&name.as_str()) {
        format!("{name}-resource")
    } else {
        name
    }
}

/// A parameter name safe to bind in elisp. Unlike Scheme, elisp is a lisp-2, so `if` is a
/// perfectly good VARIABLE name — only the constants cannot be rebound.
fn safe_elisp_param(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if matches!(clean.as_str(), "nil" | "t" | "args") || clean.is_empty() {
        format!("{clean}-value")
    } else {
        clean
    }
}

fn first_line(text: &str) -> String {
    // ESCAPE transclusion markers. An endpoint's summary can contain one literally —
    // `urn:fn:compose` documents itself with `$a{<iri>}` — and the moment that text lands
    // in a generated comment, composing the prelude tries to expand the EXAMPLE inside its
    // own documentation ("bad IRI in marker `<iri>`"). `$$a{…}` is compose's literal form.
    escape_markers(text.lines().next().unwrap_or("").trim())
}

/// Normalize any run of `$` before `a{` to exactly `$$a{` — compose's literal form.
///
/// Idempotent on purpose. A plain `.replace("$a{", "$$a{")` also rewrites the ALREADY
/// escaped `$$a{…}` that appears in the same sentence of compose's own summary, yielding
/// `$$$a{…}` — which compose reads as a literal `$` followed by a live marker, and fails on
/// again. Escaping must be a fixed point.
fn escape_markers(text: &str) -> String {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '$' {
            let mut j = i;
            while j < bytes.len() && bytes[j] == '$' {
                j += 1;
            }
            if bytes[j..].starts_with(&['a', '{']) {
                out.push_str("$$");
                i = j;
                continue;
            }
            for _ in i..j {
                out.push('$');
            }
            i = j;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// How many missed cadences before a recurring job is called STALE.
///
/// Three, not one: a single missed tick is noise (a slow resolution, a laptop that slept
/// through one), three in a row is a pattern. The threshold is a MULTIPLE of the job's own
/// declared interval, so nothing has to be configured — a 5-minute derive is stale at 15
/// minutes, a 30-second drain at 90 seconds.
const STALE_CADENCES: u32 = 3;

/// `urn:host:health` — is this HOST doing what it said it would?
///
/// Named for the host, not the kernel, for two reasons. The facts are the host's — its timed
/// jobs, its peers — and the kernel is a resolution engine that has no daemons. And
/// `urn:kernel:*` is intercepted by core as intrinsics before any space sees it, so a
/// binding there would never be reached.
///
/// SELF-STALENESS IS ALARMABLE; PEER ABSENCE IS NOT. "My derive has not run in 16 hours" is
/// wrong wherever the machine is. "plasma is not here" is a laptop that went travelling, and
/// a health check that pages about it is a health check nobody reads. So peers are REPORTED
/// with their presence and never counted against the verdict.
///
/// The one peer condition that IS a fault — announcing but not answering — is distinguishable
/// only because discovery separates Present from Withdrawn/Unknown, and is left to a caller
/// that wants to dial.
struct KernelHealth;

#[async_trait::async_trait]
impl Endpoint for KernelHealth {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_KERNEL_INSPECT) {
            return Err(Error::Denied(format!(
                "reading kernel health requires `{CAP_KERNEL_INSPECT}`"
            )));
        }
        let jobs = time_registry().health();
        // Peers only if a browse is ALREADY running: health must not start a background
        // multicast listener as a side effect, and on a machine whose peers are away the
        // honest answer is "not watching" rather than a 1.2s wait for silence.
        let peers = BROWSER
            .get()
            .and_then(|browser| browser.as_ref())
            .map(|browser| browser.peers())
            .unwrap_or_default();

        let turtle = inv
            .inline_str("as")
            .map(|v| v.contains("turtle"))
            .unwrap_or(false);
        let (body, repr) = if turtle {
            (health_turtle(&jobs, &peers), "text/turtle")
        } else {
            (health_text(&jobs, &peers), "text/plain")
        };
        Ok(Representation::new(ReprType::new(repr), body.into_bytes()))
    }

    fn name(&self) -> &str {
        "kernel-health"
    }

    fn describe(&self) -> Description {
        Description::new("kernel-health")
            .summary(
                "whether this kernel's own periodic work is running at the cadence it \
                 declared, plus the peers it can currently hear",
            )
            .verb(Verb::Source)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("ok | stale — judged against each job's OWN declared interval")
                    .input(
                        ArgSpec::new("as")
                            .optional()
                            .one_of(["text/plain", "text/turtle"])
                            .summary("the representation to return (default text/plain)"),
                    )
                    .requires(CAP_KERNEL_INSPECT),
            )
    }
}

/// Is a recurring job overdue by more than [`STALE_CADENCES`] of its own interval?
///
/// A job that has NEVER run is not yet stale — it may simply be younger than its first
/// tick; it becomes stale once more than that many intervals of process life have passed.
/// Non-recurring jobs are never stale: they were meant to fire once.
fn job_is_stale(job: &ikigai_time::JobHealth, uptime: std::time::Duration) -> bool {
    if !job.recurring {
        return false;
    }
    let limit = job.interval * STALE_CADENCES;
    match job.since_last {
        Some(age) => age > limit,
        None => uptime > limit,
    }
}

fn health_text(jobs: &[ikigai_time::JobHealth], peers: &[ikigai_discovery::Peer]) -> String {
    let uptime = process_uptime();
    let stale: Vec<&ikigai_time::JobHealth> =
        jobs.iter().filter(|j| job_is_stale(j, uptime)).collect();
    let mut out = format!(
        "{}  ·  {} up  ·  {} job(s), {} stale\n\n",
        if stale.is_empty() { "ok" } else { "STALE" },
        fmt_secs(uptime),
        jobs.len(),
        stale.len()
    );
    for job in jobs {
        let age = match job.since_last {
            Some(age) => fmt_secs(age),
            None => "never".to_string(),
        };
        out.push_str(&format!(
            "  {:<7} {:<34} every {:<7} runs {:<5} last {}\n",
            if job_is_stale(job, uptime) {
                "STALE"
            } else {
                "ok"
            },
            job.target,
            fmt_secs(job.interval),
            job.runs,
            age
        ));
        // The last thing it SAID, when it failed — a job can run on time and still be
        // doing nothing useful, which is the failure that hid for sixteen hours.
        if job.last_output.starts_with("error") {
            out.push_str(&format!("          {}\n", job.last_output));
        }
    }
    // Peers are INFORMATION. A travelling laptop is not a fault, so this section never
    // affects the verdict above.
    out.push_str("\npeers (not counted against health — an absent peer is normal):\n");
    if peers.is_empty() {
        out.push_str("  none heard (or no browse running here)\n");
    } else {
        for peer in peers {
            out.push_str(&format!(
                "  {:<12} {:<22} {}\n",
                peer.name,
                peer.socket_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "(no address)".to_string()),
                peer.surface.as_deref().unwrap_or("")
            ));
        }
    }
    out
}

fn health_turtle(jobs: &[ikigai_time::JobHealth], peers: &[ikigai_discovery::Peer]) -> String {
    let uptime = process_uptime();
    let stale = jobs.iter().filter(|j| job_is_stale(j, uptime)).count();
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n",
    );
    out.push_str(&format!(
        "<urn:host:health> a ik:Health ;\n    ik:verdict \"{}\" ;\n    ik:uptimeSeconds {} ;\n    ik:staleJobs {stale} .\n\n",
        if stale == 0 { "ok" } else { "stale" },
        uptime.as_secs()
    ));
    for job in jobs {
        out.push_str(&format!(
            "<urn:host:health:job:{}> a ik:Job ;\n    ik:target <{}> ;\n    ik:intervalSeconds {} ;\n    ik:runs {} ;\n    ik:stale \"{}\"^^xsd:boolean",
            job.id,
            job.target,
            job.interval.as_secs(),
            job.runs,
            job_is_stale(job, uptime)
        ));
        if let Some(age) = job.since_last {
            out.push_str(&format!(" ;\n    ik:sinceLastSeconds {}", age.as_secs()));
        }
        out.push_str(" .\n\n");
    }
    for peer in peers {
        out.push_str(&format!(
            "<urn:peer:{}> a ik:Peer ;\n    ik:peerName \"{}\" ;\n    ik:heard \"true\"^^xsd:boolean .\n\n",
            peer.name, peer.name
        ));
    }
    out
}

/// How long this process has been up — the denominator for "has a job that never ran had
/// time to run yet?".
///
/// The clock must be STARTED at kernel construction, not at first read: a `OnceLock`
/// initialized lazily begins when health is first asked, which reported `0s up` on a host
/// that had been running for hours, and would have called every never-run job healthy
/// forever. [`start_uptime_clock`] is called while the kernel is being built.
fn process_uptime() -> std::time::Duration {
    uptime_start().elapsed()
}

fn uptime_start() -> std::time::Instant {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *START.get_or_init(std::time::Instant::now)
}

/// Start the uptime clock. Idempotent; called from every kernel constructor.
fn start_uptime_clock() {
    let _ = uptime_start();
}

fn fmt_secs(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 90 {
        format!("{s}s")
    } else if s < 5400 {
        format!("{}m", s / 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

/// The capability a peer listing needs. Discovery is local-network reconnaissance — who is
/// out there, and what they claim to serve — so it is gated, not free.
const CAP_NET_DISCOVER: &str = "urn:cap:net:discover";

/// The process's mDNS browse, started ON FIRST USE and then kept.
///
/// Explicitly lazy: a background multicast listener is a daemon-ish thing, and "every
/// process that builds a kernel silently starts one" is the pattern removed from the
/// reactor. Resolving `urn:peer:*` IS the request for it, so starting it there is the
/// honest trigger.
static BROWSER: std::sync::OnceLock<Option<ikigai_discovery::Browser>> = std::sync::OnceLock::new();

/// How long the FIRST listing waits for announcements to arrive. Multicast replies are not
/// instant, so a browse started microseconds ago legitimately knows nothing; without this a
/// first call would report an empty network and look like a broken feature. Later calls read
/// the warm cache and return immediately.
const FIRST_LISTEN: std::time::Duration = std::time::Duration::from_millis(1200);

/// `urn:peer:list` — the ikigai kernels announcing themselves on this network.
///
/// Uncacheable: it is live platform state, and the answer changes when a laptop closes.
struct PeerList;

/// Does this machine hold a pinned server certificate for `name`?
///
/// The deployed convention is one directory per peer — `<config>/ikigai/quic-<name>/` holds
/// that peer's `server.crt` plus our client identity (plasma has `quic-bug`, bug has
/// `quic-plasma`). Holding one means "I could try": the peer must ALSO trust our client
/// cert, and only a dial proves that. The narrower claim is the one worth reporting.
fn holds_cert_for(name: &str) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };
    std::path::PathBuf::from(home)
        .join(".config/ikigai")
        .join(format!("quic-{name}"))
        .join("server.crt")
        .exists()
}

#[async_trait::async_trait]
impl Endpoint for PeerList {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_NET_DISCOVER) {
            return Err(Error::Denied(format!(
                "listing peers requires `{CAP_NET_DISCOVER}`"
            )));
        }
        let mut fresh = false;
        let browser = BROWSER
            .get_or_init(|| {
                fresh = true;
                ikigai_discovery::Browser::start().ok()
            })
            .as_ref()
            .ok_or_else(|| {
                Error::Endpoint("could not start an mDNS browse on this machine".to_string())
            })?;
        if fresh {
            std::thread::sleep(FIRST_LISTEN);
        }

        let mut peers = browser.peers();
        for peer in &mut peers {
            peer.trusted = holds_cert_for(&peer.name);
        }
        // `trusted=yes` narrows to peers this machine could actually dial. Deliberately NOT
        // the default: seeing an unenrolled peer is how you know there is something to
        // enrol. What must never happen is CONNECTING to one, and that is the mount's
        // business, not the listing's.
        if inv
            .inline_str("trusted")
            .map(|v| v == "yes")
            .unwrap_or(false)
        {
            peers.retain(|p| p.trusted);
        }

        let turtle = inv
            .inline_str("as")
            .map(|v| v.contains("turtle"))
            .unwrap_or(false);
        let body = if turtle {
            peers_turtle(&peers)
        } else {
            peers_text(&peers)
        };
        let repr_type = if turtle { "text/turtle" } else { "text/plain" };
        // Uncacheable by default (no .cacheable()) — live platform state: the answer
        // changes when a laptop closes.
        Ok(Representation::new(
            ReprType::new(repr_type),
            body.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "peer-list"
    }

    fn describe(&self) -> Description {
        Description::new("peer-list")
            .summary("the ikigai kernels announcing themselves on this local network")
            .verb(Verb::Source)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("list — who is out there, and what they claim to serve")
                    .input(
                        ArgSpec::new("trusted")
                            .optional()
                            .one_of(["yes", "no"])
                            .summary(
                                "yes = only peers this machine holds a pinned certificate \
                                 for (i.e. could dial)",
                            ),
                    )
                    .input(
                        ArgSpec::new("as")
                            .optional()
                            .one_of(["text/plain", "text/turtle"])
                            .summary("the representation to return (default text/plain)"),
                    )
                    .requires(CAP_NET_DISCOVER),
            )
    }
}

fn peers_text(peers: &[ikigai_discovery::Peer]) -> String {
    if peers.is_empty() {
        // An empty network and a browse that has heard nothing YET look identical, and
        // saying so is more honest than an empty list that reads as "nobody is there".
        return "no peers heard announcing on this network\n".to_string();
    }
    peers
        .iter()
        .map(|p| {
            let addr = p
                .socket_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "(no address)".to_string());
            format!(
                "{}  {}  {}  {}\n",
                p.name,
                addr,
                if p.trusted { "trusted" } else { "unenrolled" },
                p.surface.as_deref().unwrap_or("(surface not advertised)")
            )
        })
        .collect()
}

fn peers_turtle(peers: &[ikigai_discovery::Peer]) -> String {
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n",
    );
    for p in peers {
        // Skolemized, per the house rule: a stable IRI per peer name, never a blank node.
        out.push_str(&format!("<urn:peer:{}> a ik:Peer ;\n", p.name));
        out.push_str(&format!("    ik:peerName \"{}\" ;\n", p.name));
        if let Some(addr) = p.socket_addr() {
            out.push_str(&format!("    ik:peerAddress \"{addr}\" ;\n"));
        }
        if let Some(surface) = &p.surface {
            out.push_str(&format!("    ik:peerSurface \"{surface}\" ;\n"));
        }
        if let Some(ceiling) = &p.ceiling {
            out.push_str(&format!("    ik:peerCeiling \"{ceiling}\" ;\n"));
        }
        // `trusted` is OURS, not the peer's: whether this machine holds a cert for it. An
        // announcement can claim anything; only the pinned cert decides who it is.
        out.push_str(&format!(
            "    ik:pinnedHere \"{}\"^^xsd:boolean .\n\n",
            p.trusted
        ));
    }
    out
}

/// Bridges the keystore to `ikigai_meeting::SecretReader`: resolve a secret by name from the same
/// backend the `urn:secret:*` space reads. (Per-invocation secret-cap gating is a later refinement;
/// today the embedded-only reachability of the meeting endpoint plus its net-cap check are the
/// authority boundary.)
struct HostSecrets(Arc<dyn ikigai_secret::Backend>);

impl ikigai_meeting::SecretReader for HostSecrets {
    fn read(&self, name: &str) -> ikigai_core::Result<Vec<u8>> {
        self.0.get(name)?.ok_or_else(|| {
            ikigai_core::Error::Endpoint(format!("secret `{name}` is not in the keystore"))
        })
    }
}

/// The LLM provider registry: a hand-editable JSON file pointed at by
/// `IKIGAI_LLM_CONFIG` (see ikigai-llm's `Registry::from_json`), else a local
/// Ollama default. Load-time — a config edit needs a restart; live-reload (the
/// config as a golden-thread resource) is a follow-up. A bad path/JSON warns and
/// falls back rather than failing the kernel build.
fn llm_registry() -> ikigai_llm::Registry {
    let mut registry = llm_declared_registry();
    // The annotation graph (IKIGAI_LLM_ANNOTATIONS, Turtle) completes or CORRECTS
    // the declared descriptions — annotations are authoritative, but an override
    // is never silent: every conflict is logged.
    for c in registry.apply_annotations(&llm_annotation_facts()) {
        eprintln!(
            "ikigai: llm annotation overrides {}.{}: {} -> {}",
            c.provider, c.trait_name, c.declared, c.annotated
        );
    }
    registry
}

/// Where the LLM registry may be declared, in precedence order: the env var (an override
/// for CI and containers), then the config home — the same place `calendar.json` and
/// `config.toml` live, so a machine's LLM setup is configured like everything else.
fn llm_config_candidates() -> Vec<(String, &'static str)> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("IKIGAI_LLM_CONFIG") {
        candidates.push((path, "IKIGAI_LLM_CONFIG"));
    }
    if let Ok(home) = std::env::var("HOME") {
        let path = std::path::PathBuf::from(home).join(".config/ikigai/llm.json");
        candidates.push((path.display().to_string(), "llm.json"));
    }
    candidates
}

/// The declared registry: the config-home `llm.json` (or `IKIGAI_LLM_CONFIG`), else the
/// Ollama default.
fn llm_declared_registry() -> ikigai_llm::Registry {
    // The CONFIG HOME first, the environment variable only as an override.
    //
    // This used to be env-var ONLY, with no default path — so `~/.config/ikigai/llm.json`
    // sat there being ignored, and a daemon (whose plist sets no environment) silently ran
    // the built-in single-provider default. The failure was invisible until a `provider=`
    // that plainly existed in the file resolved to nothing: `no endpoint resolved for
    // urn:llm:big:ask`. `calendar.json` has always loaded from the config home; llm.json
    // was the odd one out.
    for (path, source) in llm_config_candidates() {
        let Ok(json) = std::fs::read_to_string(&path) else {
            continue;
        };
        match ikigai_llm::Registry::from_json(&json) {
            Ok(registry) => return registry,
            // LOUD: a config that exists but does not parse must never look like a config
            // that is not there. Silently falling back to the default is how you end up
            // debugging a provider you can see in the file.
            Err(e) => eprintln!("ikigai: {source} ({path}) parse error: {e:?} — using the default"),
        }
    }
    let mut ollama = ikigai_llm::OpenAiConfig::ollama("llama3.2:3b");
    // The declared trait profile urn:llm:models reports (and selection reasons
    // over): a 3B text model with a 128k window. vendor "ollama" (set by the
    // constructor) opts into /api/show discovery, which fills what's left.
    ollama.caps.context = Some(131_072);
    ollama.caps.modalities = vec!["text".to_string()];
    ollama.caps.params = Some("3B".to_string());
    ikigai_llm::Registry::single(ollama)
}

/// Facts from the `IKIGAI_LLM_ANNOTATIONS` Turtle file, as `(subject, predicate,
/// object)` strings — literal objects lose their datatype here;
/// `Registry::apply_annotations` re-parses values per trait. Missing env is
/// normal (no annotations); an unreadable/unparseable file warns and yields
/// nothing rather than failing the kernel build.
fn llm_annotation_facts() -> Vec<(String, String, String)> {
    let Ok(path) = std::env::var("IKIGAI_LLM_ANNOTATIONS") else {
        return Vec::new();
    };
    let ttl = match std::fs::read_to_string(&path) {
        Ok(ttl) => ttl,
        Err(e) => {
            eprintln!("ikigai: cannot read IKIGAI_LLM_ANNOTATIONS ({path}): {e} — ignoring");
            return Vec::new();
        }
    };
    let mut facts = Vec::new();
    for quad in
        oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(ttl.as_bytes())
    {
        let Ok(quad) = quad else { continue };
        let oxrdf::NamedOrBlankNode::NamedNode(subject) = &quad.subject else {
            continue;
        };
        let object = match &quad.object {
            oxrdf::Term::NamedNode(n) => n.as_str().to_string(),
            oxrdf::Term::Literal(l) => l.value().to_string(),
            _ => continue,
        };
        facts.push((
            subject.as_str().to_string(),
            quad.predicate.as_str().to_string(),
            object,
        ));
    }
    facts
}

/// The `urn:fn:compose` shape behind the Jury runbook tab: one question, two
/// `urn:llm:ask` markers — built against what's ACTUALLY installed. Sources
/// `urn:llm:ollama:installed` with `supports=completion` (an embedder is often
/// the smallest model installed, and a juror must be able to chat) and forks to
/// the first two distinct models (two personas of one model when only one is
/// pulled), so the demo is portable: no hardcoded model name. If the list can't
/// be read the markers carry no `model=` and the backend's own
/// default-resolution (and the gated conditional's offline note) take over.
struct JuryShape;

/// Total physical memory, best-effort — the machine attribute the jury's
/// co-load budget is computed from. None on platforms we don't know how to ask.
fn total_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb: u64 = meminfo
            .lines()
            .find(|line| line.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Pick the jurors under a co-load budget. `installed` is smallest-first with
/// sizes where known. Juror A = the smallest model that fits alone (≤ ~50% of
/// RAM); juror B = the next distinct model ONLY if both together fit the pair
/// budget (≤ ~60% of RAM) — otherwise A again (two personas), with a note
/// explaining the decision. Unknown sizes or unknown RAM are assumed to fit
/// (no machine facts = no machine policy).
fn empanel(
    installed: &[(String, Option<u64>)],
    ram: Option<u64>,
) -> (Option<String>, Option<String>, Option<String>) {
    let gb = |bytes: u64| format!("{:.1} GB", bytes as f64 / 1e9);
    let Some((first, first_size)) = installed.first() else {
        return (None, None, None);
    };
    let Some(ram) = ram else {
        let b = installed.get(1).map(|(m, _)| m.clone());
        return (Some(first.clone()), b.or_else(|| Some(first.clone())), None);
    };
    let solo_budget = ram / 2;
    let pair_budget = ram / 5 * 3;
    let ram_display = format!("{} GB", ram >> 30);

    // Juror A: smallest that fits alone (the list is smallest-first).
    let Some((a, a_size)) = installed
        .iter()
        .find(|(_, size)| size.unwrap_or(0) <= solo_budget)
    else {
        // Nothing fits comfortably; use the smallest anyway rather than refuse.
        return (
            Some(first.clone()),
            Some(first.clone()),
            Some(format!(
                "jury note: no installed model fits comfortably on a {ram_display} machine; \
                 using {first} ({}) twice",
                first_size.map(gb).unwrap_or_else(|| "size unknown".into())
            )),
        );
    };

    // Juror B: the next distinct model that CO-LOADS with A.
    let b = installed
        .iter()
        .find(|(m, size)| m != a && a_size.unwrap_or(0) + size.unwrap_or(0) <= pair_budget);
    if let Some((b, _)) = b {
        return (Some(a.clone()), Some(b.clone()), None);
    }

    // A second model exists but won't co-load: two personas, and say why.
    let note = installed.iter().find(|(m, _)| m != a).map(|(m, size)| {
        format!(
            "jury note: {m} ({}) not empaneled — won't co-load with {a} within a \
             {} budget on a {ram_display} machine; using two personas of {a} instead",
            size.map(gb).unwrap_or_else(|| "size unknown".into()),
            gb(pair_budget),
        )
    });
    (Some(a.clone()), Some(a.clone()), note)
}

#[async_trait::async_trait]
impl Endpoint for JuryShape {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // The installed list, smallest-first, with sizes where the provider
        // reports them (the as=json face of urn:llm:ollama:installed).
        let installed: Vec<(String, Option<u64>)> = match inv
            .issue(
                Request::new(
                    Verb::Source,
                    Iri::parse("urn:llm:ollama:installed").expect("valid IRI"),
                )
                .with_arg(
                    "as",
                    ikigai_core::ArgRef::Inline(b"application/json".to_vec()),
                )
                .with_arg(
                    "supports",
                    ikigai_core::ArgRef::Inline(b"completion".to_vec()),
                ),
            )
            .await
        {
            Ok(repr) => serde_json::from_slice::<serde_json::Value>(&repr.bytes)
                .ok()
                .and_then(|v| {
                    v.as_array().map(|models| {
                        models
                            .iter()
                            .filter_map(|m| {
                                m["model"]
                                    .as_str()
                                    .map(|name| (name.to_string(), m["size"].as_u64()))
                            })
                            .collect()
                    })
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let (juror_a, juror_b, jury_note) = empanel(&installed, total_memory_bytes());
        let marker = |system: &str, model: &Option<String>| {
            let model_arg = model
                .as_ref()
                .map(|m| format!("&model={m}"))
                .unwrap_or_default();
            format!(
                "$a{{urn:llm:ask?system={system}&prompt=What is resource-oriented computing, \
                 in plain terms{model_arg}}}"
            )
        };
        let label = |model: &Option<String>| {
            model
                .as_ref()
                .map(|m| format!(" · {m}"))
                .unwrap_or_default()
        };
        let mut shape = format!(
            "QUESTION: What is resource-oriented computing, in plain terms?\n\n\
             --- Candidate A (concise{}) ---\n{}\n\n\
             --- Candidate B (analogy{}) ---\n{}\n",
            label(&juror_a),
            marker("Answer in exactly one concise sentence.", &juror_a),
            label(&juror_b),
            marker(
                "Answer with one vivid everyday analogy, at most two sentences.",
                &juror_b
            ),
        );
        if let Some(note) = jury_note {
            shape.push_str(&format!("\n({note})\n"));
        }
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            shape.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "jury-shape"
    }

    fn describe(&self) -> Description {
        Description::new("jury-shape")
            .title("Jury shape")
            .summary(
                "The best-of-two compose shape, built against what's actually installed: \
                 forks to the first two distinct models the provider serves (two personas \
                 of one model if only one is pulled).",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8")
    }
}

fn jury_shape() -> JuryShape {
    JuryShape
}

/// The friendly degraded branch for LLM demos: what `urn:fn:conditional` returns
/// when `urn:llm:ollama:up` says the model server is down.
fn ollama_offline() -> FnEndpoint {
    const NOTE: &str = "\
(the model server is not running)

This demo forks a question to a local LLM, but urn:llm:ollama:up reports it
down. To bring it up:

    ollama serve                 # or launch the Ollama app
    ollama pull llama3.2:3b      # once, to fetch the model

then re-run this step — no restart needed, liveness is a live fact.
";
    FnEndpoint::new("ollama-offline", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            NOTE.as_bytes().to_vec(),
        ))
    })
}

/// The gracefully-degrading Jury: ONE compose marker invoking `urn:fn:conditional`
/// on the liveness resource. When Ollama is up the conditional returns the jury
/// shape and compose recursively expands its two `urn:llm:ask` markers (the fork);
/// when it's down the offline note is spliced in instead — the LLM branch is never
/// invoked, so nothing errors. compose + conditional + up + ask, zero glue code.
fn jury_gated_shape() -> FnEndpoint {
    const GATED: &str = "\
$a{urn:fn:conditional?if=urn:llm:ollama:up&then=urn:demo:jury&else=urn:data:ollama-offline}";
    FnEndpoint::new("jury-gated-shape", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            GATED.as_bytes().to_vec(),
        ))
    })
}

/// A native-only runbook tab (like [`runbook_timer_demo`]): best-of-two-models as
/// pure composition. Forks one question to two `urn:llm:ask` personas concurrently
/// via `urn:fn:compose` fan-out, then pipes both candidates into a third `urn:llm:ask`
/// that judges. Needs a local Ollama (LLM is mounted natively). Cross-frontend
/// promotion into the shared runbook awaits the browser LLM face.
fn runbook_jury_demo() -> FnEndpoint {
    FnEndpoint::new("runbook-jury", |_inv: &Invocation<'_>| {
        let json = serde_json::json!({
            "label": "Jury",
            "intro": "Best-of-two, as pure composition. urn:demo:jury is a urn:fn:compose shape \
                      with two urn:llm:ask markers — two personas of your local model. Sourcing \
                      it forks both concurrently (fan-out) and inlines both answers; pipe that \
                      into a third urn:llm:ask and it judges which is better. Watch the \
                      [N uncacheable] tag: the verdict depends on both upstream generations, so \
                      the cache-dependency graph propagates across compose AND the pipe. The \
                      gated form degrades gracefully: urn:fn:conditional branches on the \
                      urn:llm:ollama:up liveness resource, so if Ollama is down you get a \
                      friendly note instead of an error.",
            "steps": [
                {
                    "label": "is the model server up?",
                    "cmd": "source urn:llm:ollama:up",
                    "note": "a boolean liveness resource — a cheap ping, uncacheable (a live fact)"
                },
                {
                    "label": "who are the jurors? (whatever is installed)",
                    "cmd": "source urn:llm:ollama:installed",
                    "note": "the models this machine can actually serve — the jury forks to the \
                             first two distinct ones (two personas of one model if only one is \
                             pulled). No hardcoded model names."
                },
                {
                    "label": "fork the question to two jurors (gracefully)",
                    "cmd": "source urn:fn:compose src=urn:demo:jury-gated",
                    "note": "ONE marker: conditional branches on :up — Ollama up = the jury shape \
                             (built against the installed list, whose markers then fork), down = a \
                             friendly note. The LLM branch is never touched when down."
                },
                {
                    "label": "let a third model pick the winner",
                    "cmd": "source urn:fn:compose src=urn:demo:jury | urn:llm:ask system=\"You are judging two candidate answers, A and B, to the question shown. Reply with the winner (A or B) and one short sentence why.\"",
                    "note": "pipes both candidates into a judge; [2 uncacheable] = the verdict's two upstream deps (needs Ollama up)"
                },
                {
                    "label": "what models do I have, as data?",
                    "cmd": "source urn:llm:models as=text/turtle",
                    "note": "the annotated inventory as a queryable trait graph (context/modalities/cost/vendor) — selection's substrate"
                },
                {
                    "label": "pick a backend by capability, not by name",
                    "cmd": "source urn:llm:select needs=\"cost<=local, ctx>=32k, vendor!=openai\"",
                    "note": "resolves requirements over the trait profiles: cheapest-that-fits wins; vendor!= is a \
                             governance exclusion (an undeclared vendor fails it — it might BE that vendor). The \
                             facade takes the same needs= directly: urn:llm:ask needs=\"…\" prompt=\"…\""
                }
            ]
        });
        Ok(Representation::new(
            ReprType::new("application/json"),
            serde_json::to_vec(&json).unwrap_or_default(),
        ))
    })
    .with_description(
        Description::new("runbook-jury")
            .title("Jury")
            .summary(
                "A runbook tab: fork a question to two LLM personas and let a third judge \
                 — compose fan-out + pipe.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("application/json"),
    )
}

/// Build the **local** embedded kernel (nature `Embedded (Native)`), including
/// the personal space and the HTTP-client module. The running user *is* the owner,
/// so it resolves under their identity — the engine's default root capability — and
/// the REPL's `cap` command lets them voluntarily attenuate it before handing work
/// to an agent.
///
/// A [`SystemClock`] is injected so the HTTP module's `Cache-Control: max-age`
/// deadlines (`Expiry::At`) are honoured; without a clock those reads would stay
/// uncacheable. The root is a [`Fallback`] over the local space then the HTTP space.
/// The embedded kernel's root space: the local space, the HTTP module, and the
/// interactive runbook (`urn:runbook:*`) — the last **gated** by [`demo_flag`], so it
/// only resolves while the demo is on (OFF by default; `--demo` or `demo on` turns it
/// on at runtime, no kernel rebuild). The CLI thus reads as a tool by default.
fn root_space() -> Arc<dyn Space> {
    root_space_with_mounts(Vec::new())
}

/// The embedded root space, plus a `MountedRemote` per `(prefix, origin, resolver)`
/// — each tried after every local space, so a resource the local kernel lacks under
/// `prefix` forwards to the remote, and the remote's catalog appears re-prefixed and
/// tagged with `origin`.
fn root_space_with_mounts(mounts: Vec<MountSpec>) -> Arc<dyn Space> {
    let mut spaces: Vec<Arc<dyn Space>> = vec![
        Arc::new(local_space("Embedded (Native)")) as Arc<dyn Space>,
        Arc::new(http_space()) as Arc<dyn Space>,
        Arc::new(llm_space()) as Arc<dyn Space>,
        // Video-conference scheduling (urn:meeting:schedule + urn:meeting:zoom:schedule). Reads
        // the Zoom creds from the keystore; embedded-root only (not served over the wire).
        Arc::new(meeting_space()) as Arc<dyn Space>,
        // Who else is on this network (urn:peer:list). Embedded-root only, like the
        // meeting endpoints: telling a remote caller what else is reachable from here is
        // reconnaissance, and a served kernel has no business answering it.
        Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:peer:list"), PeerList)
                // The manifold as callable Lisp. Embedded-only: it describes THIS kernel's
                // reachable surface, which is the local operator's business.
                .bind(Exact::new("urn:lisp:aliases"), LispAliases)
                // Is this kernel doing what it said it would? Embedded-only, like its
                // neighbours: a served kernel reporting its own liveness to a remote
                // caller is a different question, with a different answer.
                .bind(Exact::new("urn:host:health"), KernelHealth),
        ) as Arc<dyn Space>,
        // The org agenda (urn:org:agenda[:{period}]) over the configured org
        // files, which it reads through the kernel via urn:orgfile:*.
        Arc::new(ikigai_org::space(
            org_config().map(|(_, files)| files).unwrap_or_default(),
        )) as Arc<dyn Space>,
        // The Linked Data toolkit: RDF transreption (urn:rdf:*) + SPARQL (urn:sparql:*)
        // + XSLT styling (urn:xslt:*). Linked natively — no module-loading machinery in
        // the native binary (that's a browser/WASI concern).
        Arc::new(ikigai_rdf::space()) as Arc<dyn Space>,
        // Unix-like text endpoints (urn:text:*) — pure, cacheable pipeline citizens;
        // compose with | and .. over the newline-list convention. First module built
        // by a satellite session.
        Arc::new(ikigai_text::space()) as Arc<dyn Space>,
        // Semantic-CMS transreptors (urn:cms:*): personal content (org bookmarks/
        // notes, library metadata) into one RDF graph on the dc:subject tag axis.
        Arc::new(ikigai_cms::space()) as Arc<dyn Space>,
        // Dev-tooling platform seam (urn:system:exec + urn:repo:*) — git/gh/cargo
        // as capability-gated resources. Native subprocess seam; ikigai using the
        // tools that build ikigai.
        Arc::new(ikigai_repo::space()) as Arc<dyn Space>,
        Arc::new(ikigai_sparql::space()) as Arc<dyn Space>,
        // The intray / tuplespace (urn:space:{name}: out=Sink, rd=Source) — a dir-backed
        // space under file_root/spaces/. The scheduling booking-inbox drops into it; the
        // reactive/sealed slices land on top. Cap-gated (urn:cap:space:out / :read).
        Arc::new(ikigai_intray::space(file_root().join("spaces"))) as Arc<dyn Space>,
        // Outbound mail (urn:email:send) — a cap-gated Sink submitting to the LOCAL MTA,
        // which relays onward through a transactional service (so DKIM/SPF and relay
        // credentials stay in the MTA, not here). The contact-request handler and the
        // scheduling confirm-link both reach you through this.
        Arc::new({
            let config = email_config();
            let transport = Arc::new(ikigai_email::SmtpSubmission::new(
                config.host.clone(),
                config.port,
            ));
            ikigai_email::space(config, transport)
        }) as Arc<dyn Space>,
        // The public contact form's front door (urn:contact:submit): parses an untrusted
        // urlencoded/JSON body, keeps only these declared fields, escapes them into a
        // tuple, and drops it into the reactive `contact` space — where the handler emails
        // it on. Field names match the form on bosatsu.net, `_honey` included.
        Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:contact:submit"),
            ikigai_intake::submit(contact_intake()),
        )) as Arc<dyn Space>,
        // The booking front door (urn:booking:submit): the visitor offers THEIR hours and
        // zone; the reactive `bookings` space fires schedule.scm, which finds a mutually
        // free slot. Brian's freebusy never leaves the machine — the visitor never sees a
        // calendar, only proposes availability. These field summaries are what a generated
        // form renders as labels, so the UI and the validation cannot drift apart.
        Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:booking:submit"),
            ikigai_intake::submit(booking_intake()),
        )) as Arc<dyn Space>,
        // Neutral s-expr → SPARQL transreptor (urn:sparql:from-sexpr, text/x-sexpr →
        // application/sparql-query): pipe an s-expr query in, feed the emitted SPARQL to
        // urn:sparql:select. A pure transreptor (no lisp engine); safe in the shared space.
        Arc::new(ikigai_sexpr::space()) as Arc<dyn Space>,
        // Signing + verification (urn:sign:sign — cap-gated `urn:cap:sign` — and
        // urn:sign:verify): sign any representation, verify it later; a signature is
        // an RDF graph, keys are kernel-resolved resources (urn:file:*, urn:secret:*).
        Arc::new(ikigai_sign::space()) as Arc<dyn Space>,
        // Public-key encryption (urn:encrypt:encrypt — open — and urn:encrypt:decrypt —
        // cap `urn:cap:decrypt`): the dual of sign, age/X25519. Keys are kernel-resolved
        // resources (urn:secret:<id>.enc / .enc.pub). Embedded-only, with the crypto family.
        Arc::new(ikigai_encrypt::space()) as Arc<dyn Space>,
        // Secrets custody (urn:secret:{name} cap-gated read + urn:secret:generate/unlock
        // — Ed25519 keygen behind `urn:cap:secret:generate` + Touch ID, macOS Keychain
        // backend). Mounted in the embedded root only (this list is not in `served_space`),
        // so keys are owner-only and never reachable over the wire. `key=urn:secret:<name>`
        // then feeds `urn:sign:sign`.
        Arc::new(ikigai_secret::space(ikigai_secret::default_backend())) as Arc<dyn Space>,
        Arc::new(ikigai_xslt::space()) as Arc<dyn Space>,
        // JSON-LD operators (urn:jsonld:expand/compact/flatten) — linked natively (the heavy
        // json-ld tree is a browser-wasm concern, lazy-loaded there; native links it).
        Arc::new(ikigai_jsonld::space()) as Arc<dyn Space>,
        // SHACL validation (urn:shacl:validate) — rudof's validator, native-only (wasm-gated
        // upstream); the browser serves the same resource via shacl-engine (JS).
        Arc::new(ikigai_shacl::space()) as Arc<dyn Space>,
        // Content sniffing + sniff-and-dispatch: `urn:sniff` classifies opaque bytes,
        // `urn:transrept:auto` sniffs then routes them to the matching transreptor — so a
        // mislabeled fetch or a file read transrepts without asserting its input type.
        Arc::new(ikigai_sniff::space()) as Arc<dyn Space>,
        // The ikigai vocabulary as a resolvable resource (urn:ikigai:vocab): the ns#
        // ontology Turtle (ik:Transreptor rdfs:subClassOf ik:Endpoint + property defs),
        // the same bytes served at https://ikigai-rs.dev/ns. Lists in the catalog.
        Arc::new(ikigai_vocab::space()) as Arc<dyn Space>,
        // The time transport's control plane: urn:time:schedule (target=/every=/after=/
        // method=) registers a job that fires a kernel request on a timer, urn:time:cancel
        // (id=) stops one, urn:time:jobs is the live readout (also the Control composite's
        // third marker). The registry's kernel handle is installed in watched_kernel().
        Arc::new(ikigai_time::space(time_registry())) as Arc<dyn Space>,
        Arc::new(Gated {
            // The shared runbook demos, plus a local Timer tab (urn:runbook:timer) — the
            // native mirror of the browser demo's tab. The TUI's load_demos enumerates
            // every urn:runbook:* here, so binding it locally is all it takes.
            inner: ikigai_runbook::space()
                .bind(Exact::new("urn:runbook:timer"), runbook_timer_demo())
                .bind(Exact::new("urn:runbook:jury"), runbook_jury_demo())
                .bind(Exact::new("urn:demo:jury"), jury_shape())
                .bind(Exact::new("urn:demo:jury-gated"), jury_gated_shape())
                .bind(Exact::new("urn:data:ollama-offline"), ollama_offline()),
            on: demo_flag(),
        }) as Arc<dyn Space>,
    ];
    // The booking handler: `schedule.scm` bound as an endpoint (`ikigai_lisp::program` — the
    // program IS the endpoint), IF the workspace provides `booking-handler.scm`. The reactive
    // `bookings` space fires `urn:booking:handle` on each dropped request, under that space's
    // own scoped `cap` file. The request reaches the program as DATA via `(input)`, never as
    // code. Absent the file, the endpoint simply isn't bound.
    if let Ok(program) = std::fs::read_to_string(file_root().join("booking-handler.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:booking:handle"),
            ikigai_lisp::program("booking", program),
        )) as Arc<dyn Space>);
    }
    // Likewise the contact handler: the reactive `contact` space fires urn:contact:handle
    // on each dropped enquiry, and the program emails it on via urn:email:send. Same
    // "the program IS the endpoint" shape — a public enquiry is DATA read with `(input)`.
    if let Ok(program) = std::fs::read_to_string(file_root().join("contact-handler.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:contact:handle"),
            ikigai_lisp::program("contact", program),
        )) as Arc<dyn Space>);
    }
    // The block-apply reactor: the public `urn:contact-block` link RECORDS a verified block
    // into `urn:space:contact-blocks`; the reactive `contact-blocks` space fires this program
    // on each drop, under that space's own `cap` file (`urn:cap:decisions:write`), and it
    // writes the block into the edge-local `urn:decisions`. Keeping the write here — off the
    // internet-facing HTTP ceiling — is the whole point of the airlock. Same "the program IS
    // the endpoint" shape; the drop reaches it as DATA via `(input)`.
    if let Ok(program) = std::fs::read_to_string(file_root().join("contactblock-apply.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:contactblock:apply"),
            ikigai_lisp::program("contactblock-apply", program),
        )) as Arc<dyn Space>);
    }
    // The human step. `confirm.scm` reads the confirmations space, and on approval writes
    // the calendar and emails the requester. Unlike the two handlers above, NO space fires
    // it — it is invoked by hand (`sink urn:booking:confirm (approve …)`), because deciding
    // to give someone your time is the one step that is meant to wait for a person. Bound in
    // the host kernel only: it reaches the calendar, which never leaves this machine.
    if let Ok(program) = std::fs::read_to_string(file_root().join("confirm.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:booking:confirm"),
            ikigai_lisp::program("confirm", program),
        )) as Arc<dyn Space>);
    }
    // Recording a drained contact. `contact-record.scm` takes a person tuple the edge dropped
    // (the contact handler runs on the edge, which has no people ledger) and sinks it into
    // `urn:people`. The drain delivers to it (see drain.scm's people leg). Host-only, beside
    // confirm — it reaches the ledger, which never leaves this machine.
    if let Ok(program) = std::fs::read_to_string(file_root().join("contact-record.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:contact:record"),
            ikigai_lisp::program("contact-record", program),
        )) as Arc<dyn Space>);
    }
    // The drain. `drain.scm` reads the EDGE's bookings space (mounted here at `urn:edge:` —
    // see `--mount`) and delivers each tuple into the LOCAL bookings space, where dropping it
    // fires `urn:booking:handle`. It is bound here and scheduled below; the edge itself never
    // runs it (the edge is the airlock — it only accepts and holds). No mount → the drain
    // simply finds nothing to read and reports zero.
    if let Ok(program) = std::fs::read_to_string(file_root().join("drain.scm")) {
        spaces.push(Arc::new(ikigai_core::EndpointSpace::new().bind(
            Exact::new("urn:booking:drain"),
            ikigai_lisp::program("drain", program),
        )) as Arc<dyn Space>);
    }
    // The two halves of the decision loop that must stay on this machine: minting a link
    // (it signs, so it touches the private key) and acting on a decision that came back
    // (it re-verifies, then writes the calendar). Never in `served_space`.
    spaces.push(Arc::new(
        ikigai_core::EndpointSpace::new()
            .bind(Exact::new("urn:decide:link"), decide::DecideLink)
            // Minting a block link signs with the edge-local `contact-block.key`, so like the
            // decision links above it is bound HERE (the daemon) and never in `served_space` —
            // the internet-facing face gets the verify-only public half, never the signing one.
            .bind(
                Exact::new("urn:contactblock:link"),
                contactblock::ContactBlockLink::default(),
            )
            // Opening a passkey enrollment window is a deliberate act at the box: cap-gated
            // (`urn:cap:passkey:enroll`) and bound here, off the public face, so only
            // `ikigai -c` on the machine can start the few-minute window in which a device
            // may register. The register endpoint itself is public (it needs a browser), but
            // it accepts a credential only while this window is open.
            .bind(
                Exact::new("urn:passkey:enroll-open"),
                passkey::PasskeyEnrollOpen,
            )
            .bind(
                Exact::new("urn:decide:accept"),
                decide::DecideAccept {
                    key_path: decide::public_key_path(),
                },
            )
            .bind(
                Exact::new("urn:decisions"),
                decisions::DecisionLog {
                    path: decisions::log_path(),
                },
            )
            // The people ledger: a durable roster captured at ingestion. Host-only, like the
            // decision log beside it — a private contact list never belongs on the served edge.
            .bind(
                Exact::new("urn:people"),
                people::PeopleLedger {
                    path: people::ledger_path(),
                },
            ),
    ) as Arc<dyn Space>);
    // Issuing a client link is a HOST action, so it is bound here and deliberately NOT in
    // `served_space`: the public edge may name a client (`urn:cap:client:read`), but only
    // this side may mint one. The registry is bound here too, so an issued link can be
    // read back locally without going through the edge.
    spaces.push(Arc::new(
        ikigai_core::EndpointSpace::new()
            .bind(
                Exact::new("urn:client:issue"),
                ClientIssue { root: file_root() },
            )
            .bind(
                UriTemplate::parse(CLIENT_TEMPLATE).expect("CLIENT_TEMPLATE is valid"),
                ClientRegistry::new(file_root()),
            ),
    ) as Arc<dyn Space>);
    // Guardrail for a real footgun: mounts are tried AFTER every local space, so a
    // mount prefix that a local space already serves is silently shadowed — requests
    // under it resolve locally and never reach the remote (e.g. `--mount urn:personal:=…`
    // on a machine that has its own `urn:personal:*`). Warn and point at the fix: an
    // alias prefix the local kernel doesn't serve (`urn:cal:…`) forces the remote.
    let local_patterns: Vec<String> = spaces
        .iter()
        .filter_map(|s| s.entries())
        .flatten()
        .map(|e| e.pattern)
        .collect();
    // Only ALIAS mounts can be silently shadowed by a local binding; an override
    // is *supposed* to claim a locally-served namespace, so warning would be noise.
    for mount in mounts.iter().filter(|m| m.kind == MountKind::Alias) {
        let prefix = &mount.prefix;
        if local_patterns
            .iter()
            .any(|p| p.starts_with(prefix.as_str()))
        {
            eprintln!(
                "ikigai: warning: --mount prefix `{prefix}` is also served locally, so requests under it resolve LOCALLY, not via the mount; use an alias prefix the local kernel does not serve (e.g. `urn:cal:`), or `--override {prefix}=<target>` (remote wins) / `--prefer {prefix}=<target>` (remote when reachable, else local)."
            );
        }
    }
    // ALIAS mounts are tried after every local space. `MountedRemote` rewrites
    // `<prefix>rest` → `urn:rest` before forwarding (so the remote, which serves
    // `urn:*`, resolves it and a `trace` stitches its execution under this mount
    // node) AND surfaces the remote's catalog back re-prefixed + tagged with its
    // origin, so a federated `list` shows where each mounted resource resolves.
    //
    // OVERRIDE mounts are the other half of the story: they forward the IRI
    // unchanged and are composed BEFORE the local spaces, so `urn:llm:` really can
    // live on a peer even though this kernel binds it too. Precedence is what makes
    // the override an override — the rewrite mode alone would still lose to a local
    // binding (`Fallback` = first hit wins).
    // Alias mounts join the local list; overrides/prefers go in FRONT of it, so
    // the local spaces must be sealed into one space first — that sealed space is
    // also what a `--prefer` mount falls back TO.
    let mut fronting: Vec<MountSpec> = Vec::new();
    for mount in mounts {
        if mount.kind == MountKind::Alias {
            spaces.push(Arc::new(ikigai_resolve::MountedRemote::new(
                mount.resolver,
                mount.prefix,
                mount.origin,
            )));
        } else {
            fronting.push(mount);
        }
    }
    if fronting.is_empty() {
        return Arc::new(Fallback::new(spaces));
    }
    // Ordered by prefix LENGTH, so the most specific mount wins regardless of
    // declaration order: `--override urn:llm:=peerA --override urn:llm:ask=peerB`
    // sends `urn:llm:ask` to peerB and the rest of `urn:llm:*` to peerA. A whole
    // IRI is simply the most specific prefix there is, which is what makes
    // single-RESOURCE overrides work.
    fronting.sort_by_key(|mount| std::cmp::Reverse(mount.prefix.len()));
    let local: Arc<dyn Space> = Arc::new(Fallback::new(spaces));
    let mut ordered: Vec<Arc<dyn Space>> = Vec::new();
    for MountSpec {
        prefix,
        origin,
        resolver,
        kind,
    } in fronting
    {
        let remote = Arc::new(ikigai_resolve::MountedRemote::overriding(
            resolver,
            prefix.clone(),
            origin,
        )) as Arc<dyn Space>;
        ordered.push(match kind {
            // The failover pair must stay INSIDE the prefix. `Failover` resolves
            // every target, so an unguarded `[remote, local]` would also answer
            // for IRIs the local spaces bind but this mount never claimed —
            // hitting before a less-specific override behind it and defeating it.
            MountKind::Prefer => Arc::new(PrefixGuard {
                prefix,
                inner: Arc::new(ikigai_throttle::Failover::new(vec![
                    Arc::clone(&remote),
                    Arc::clone(&local),
                ])),
                catalog: remote,
            }) as Arc<dyn Space>,
            _ => remote,
        });
    }
    ordered.push(local);
    Arc::new(Fallback::new(ordered))
}

/// One remote mount: where it binds, a label for the catalog, the connected
/// resolver, and whether it OVERRIDES the local namespace.
pub struct MountSpec {
    /// The IRI prefix this mount claims.
    pub prefix: String,
    /// A human label for the catalog (`origin`), usually the target string.
    pub origin: String,
    pub resolver: Arc<dyn ikigai_resolve::Resolver>,
    pub kind: MountKind,
}

/// Confines a composed space to one IRI prefix.
///
/// Used for `--prefer`, whose inner space pairs a remote with the WHOLE local
/// space; without this, that pair would claim every IRI the local kernel binds.
/// The catalog comes from `catalog` alone, so a prefer-mount lists the remote's
/// bindings rather than re-listing all of local under the mount's origin.
struct PrefixGuard {
    prefix: String,
    inner: Arc<dyn Space>,
    catalog: Arc<dyn Space>,
}

impl Space for PrefixGuard {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        if !request.target.as_str().starts_with(&self.prefix) {
            return Resolution::Miss;
        }
        self.inner.resolve(request, scope)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.catalog.entries()
    }
}

/// The three relationships a mount can have with the local namespace.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountKind {
    /// `--mount`: the prefix is a LOCAL ALIAS for a remote namespace. IRIs are
    /// rewritten (`<prefix>rest` → `urn:rest`) and the mount is tried AFTER the
    /// local spaces, so it only ever catches what this kernel lacks.
    Alias,
    /// `--override`: the SAME namespace, served remotely. IRIs forward unchanged
    /// and the mount is composed BEFORE the local spaces. If the remote is down,
    /// the resolution FAILS — that is the point: you asked for that machine.
    Override,
    /// `--prefer`: like an override, but wrapped in a [`Failover`] over the local
    /// spaces — the remote when it answers, this machine when it doesn't. Only
    /// TRANSIENT failures fall through (a capability denial still propagates, and
    /// a mutating verb is never replayed), so "graceful" never means "silently
    /// ignored the answer the peer actually gave".
    Prefer,
}

/// `rdfs:subClassOf` axioms for type-aware action selection — parsed from the runbook's RDFS
/// alignment graph (`foaf:Person ⊑ schema:Person`) so `urn:kernel:actions` reasons over the
/// hierarchy (a `foaf:Person` entity satisfies a `schema:Person` action). See
/// [`ikigai_runbook::ALIGNMENT_TTL`].
fn subclass_axioms() -> Vec<(String, String)> {
    ikigai_rdf::subclass_axioms(ikigai_runbook::ALIGNMENT_TTL)
}

/// The embedded kernel.
pub fn kernel() -> Kernel {
    Kernel::with_meta_renderer(root_space(), Arc::new(CliRenderer))
        .with_clock(Arc::new(SystemClock))
        .with_subclass_axioms(subclass_axioms())
}

/// The local embedded kernel as a shared `Arc`, with a filesystem **watcher** over
/// [`file_root`] running behind it.
///
/// The watcher is the first *external* golden-thread freshness source: when a
/// workspace file changes out of band (an editor, `git checkout`, another
/// process), it cuts that file's thread, so the kernel's cached `Source` — and any
/// composite over it — recompute, exactly as a `Sink` through the kernel already
/// does. The returned `Arc` is what the engine drives, so the watcher and the
/// engine share one kernel and one cache.
pub fn watched_kernel() -> Arc<Kernel> {
    watched_kernel_with_mounts(Vec::new())
}

/// A watched kernel that ALSO runs the space reactor — the writer's kernel.
///
/// Reacting is a privilege, not a side effect of building a kernel. A reactive process
/// CLAIMS tuples from the shared workspace (atomic rename, exactly-once) and executes
/// them, so every reactive process is a worker competing for the same production queue.
/// That must be a deliberate role — `--daemon`, or `--react` for a session that means it —
/// never the incidental consequence of starting a REPL.
pub fn reactive_kernel_with_mounts(mounts: Vec<MountSpec>) -> Arc<Kernel> {
    build_watched(mounts, true)
}

/// Like [`watched_kernel`], but composing one or more **remote kernels** into the
/// local resolution graph. Each `(prefix, resolver)` mounts a `RemoteSpace` at
/// `prefix` (rewriting `<prefix>rest` → `urn:rest` before forwarding), so a resource
/// under the mount resolves on the remote kernel — and a `trace` stitches the
/// remote execution under the mount node. Drives the `--mount` flag.
pub fn watched_kernel_with_mounts(mounts: Vec<MountSpec>) -> Arc<Kernel> {
    build_watched(mounts, false)
}

/// The shared constructor. `reactive` decides whether this process claims and runs the
/// workspace's tuples; everything else (file/org/store watchers, scheduler, timed jobs)
/// is the same either way.
fn build_watched(mounts: Vec<MountSpec>, reactive: bool) -> Arc<Kernel> {
    start_uptime_clock();
    // Inject the process scheduler so re-entrant fan-out (e.g. `compose`'s `$a{}`
    // markers) runs concurrently on it; single-threaded by default, a pool under
    // `IKIGAI_SCHEDULER=pool[:N]`. The same scheduler is injected as a read-only
    // reporter so `urn:kernel:scheduler` surfaces its live state intrinsically. The
    // runbook is mounted but gated by `demo_flag()` (off by default).
    let sched = Arc::new(scheduler());
    let kernel = Kernel::with_meta_renderer(root_space_with_mounts(mounts), Arc::new(CliRenderer))
        .with_clock(Arc::new(SystemClock))
        .with_subclass_axioms(subclass_axioms())
        .with_scheduler_reporter(sched.clone())
        .into_scheduled(sched);
    watch_root(Arc::clone(&kernel), file_root());
    watch_org(Arc::clone(&kernel));
    watch_store(Arc::clone(&kernel));
    // Install the kernel handle the time transport fires its timed requests on, now
    // that the kernel exists (its urn:time:* endpoints are bound into this same
    // kernel). A scheduled job re-enters here under the registry's capability.
    // Path-qualify the trait rather than `use` it: ikigai_resolve::Resolver has a
    // 1-arg `issue` that would collide with the inherent async `Kernel::issue` in this
    // module's tests if brought into scope.
    let registry = time_registry();
    registry.set_resolver(Arc::clone(&kernel) as Arc<dyn ikigai_resolve::Resolver>);
    // The reactive tuplespace: watch file_root/spaces and fire each reactive space's handler
    // on a drop (inbox → outbox/error). Like the scheduler, it holds the kernel as a Resolver
    // installed now that the kernel exists. Handlers run under a SCOPED processing authority —
    // the tuplespace verbs only, so a handler can compose within the fabric (drop results,
    // read/take from spaces) but not touch fs/net/exec — NEVER root, NEVER the dropper's cap.
    // A space with no `handler` file is left alone, so this is safe over the whole tree.
    //
    // ONLY when this process is the designated worker. Before that was true, EVERY entry
    // point that built a local kernel — a one-shot `ikigai -c`, an open REPL, an MCP
    // server — silently enlisted as a worker on the writer's queue. On 2026-07-31 an idle
    // REPL claimed a real booking out from under the daemon, ran the handler under the
    // TERMINAL's TCC identity (where the calendar grant belongs to the terminal app, not
    // the signed daemon), failed the freebusy read, and dead-lettered it. Exactly-once
    // claiming meant the daemon — the one process that could have handled it — never saw
    // it. A read-only query destroyed a booking.
    if reactive {
        let reactor = Arc::new(ikigai_intray::SpaceReactor::new(
            file_root().join("spaces"),
            Arc::clone(&kernel) as Arc<dyn ikigai_resolve::Resolver>,
            ikigai_core::Capability::scoped(vec![
                ikigai_intray::CAP_OUT.to_string(),
                ikigai_intray::CAP_READ.to_string(),
                ikigai_intray::CAP_TAKE.to_string(),
            ]),
        ));
        reactor.watch();
    }
    // Register the tab-bar clock's 1s timer as a PERSISTENT time-transport job, so it
    // shows on the Control tab's Time-jobs readout (the cache demo, live) and a demo
    // cancel-all leaves it running. Mirrors the browser nav clock.
    let _ = registry.schedule_persistent(
        "urn:time:now".to_string(),
        Verb::Source,
        ikigai_time::Schedule::Every(std::time::Duration::from_secs(1)),
        true,
    );
    // The standing sync: when calendar.json sets `derive_every` (e.g. "300s",
    // "5m"), register the consolidated-view derivation as a PERSISTENT job —
    // the clock pattern. Any long-running session (REPL, --daemon) then keeps
    // Brian-Busy fresh; it shows on the Control tab's Time-jobs readout.
    if let Some(every) = derive_every() {
        let _ = registry.schedule_persistent(
            "urn:view:derive:tick".to_string(),
            Verb::Source,
            ikigai_time::Schedule::Every(every),
            true,
        );
    }
    // The standing drain: when `IKIGAI_DRAIN_EVERY` is set (e.g. "30s"), pull bookings from
    // the mounted edge on that cadence. Same clock pattern as the derive tick, and it shows
    // on the Control tab's Time-jobs readout. Only meaningful with the edge mounted at
    // `urn:edge:` and `drain.scm` in the workspace; absent either, the job is harmless.
    if let Some(every) = drain_every() {
        let _ = registry.schedule_persistent(
            "urn:booking:drain".to_string(),
            Verb::Source,
            ikigai_time::Schedule::Every(every),
            true,
        );
    }
    kernel
}

/// How often to drain the edge, from `IKIGAI_DRAIN_EVERY` (`30s`, `5m`, `1h`). `None`
/// disables it — the drain still runs on demand, just not on a timer. A floor of 15s keeps
/// a fat-fingered `1s` from hammering the wire.
fn drain_every() -> Option<std::time::Duration> {
    let spec = std::env::var("IKIGAI_DRAIN_EVERY").ok()?;
    let spec = spec.trim();
    let (digits, unit) = spec.split_at(spec.len().saturating_sub(1));
    let n: u64 = digits.parse().ok()?;
    let seconds = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return None,
    };
    (seconds >= 15).then(|| std::time::Duration::from_secs(seconds))
}

/// Where a handed-out link's token is looked up. See [`ClientRegistry`].
const CLIENT_TEMPLATE: &str = "urn:client:{token}";

/// The capability to look up a client record — deliberately its OWN grant, not filesystem
/// authority. See [`ClientRegistry`].
pub const CAP_CLIENT_READ: &str = "urn:cap:client:read";

/// Who a handed-out booking link belongs to: `urn:client:{token}` → the JSON record at
/// `<workspace>/clients/<token>.json`.
///
/// Bound on the public edge so a submission carrying a link token can say WHO it came
/// from. The point of it being an endpoint rather than a plain file read is the capability:
/// the edge grants `urn:cap:client:read`, which buys exactly one thing — "given a token,
/// tell me the client" — and not the filesystem authority that reading the file directly
/// would need. A door that can attribute a booking still cannot read anything else.
///
/// Administration is the file system, on purpose: issue a client by writing the file,
/// revoke by deleting it. There is no registry format to keep, and nothing to restart.
struct ClientRegistry {
    root: PathBuf,
}

impl ClientRegistry {
    fn new(root: PathBuf) -> Self {
        ClientRegistry { root }
    }
}

#[async_trait::async_trait]
impl Endpoint for ClientRegistry {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_CLIENT_READ) {
            return Err(Error::Denied(format!(
                "reading a client record requires `{CAP_CLIENT_READ}`"
            )));
        }
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "a client record is read with Source, not {:?}",
                inv.request.verb
            )));
        }
        // The token becomes a FILENAME, so it is re-checked here rather than trusted from
        // whoever built the IRI — this is the last place before it touches a path.
        let token = inv
            .request
            .target
            .as_str()
            .rsplit(':')
            .next()
            .unwrap_or_default();
        if !ikigai_intake::token_shaped(token) {
            return Err(Error::NotFound(format!("no client `{token}`")));
        }
        let path = self.root.join("clients").join(format!("{token}.json"));
        let bytes = std::fs::read(&path)
            .map_err(|_| Error::NotFound("no client for that token".to_string()))?;
        Ok(Representation::new(
            ReprType::new("application/json"),
            bytes,
        ))
    }

    fn name(&self) -> &str {
        "client"
    }

    fn describe(&self) -> Description {
        Description::new("client")
            .title("Client record")
            .summary(
                "Who a handed-out link belongs to. Issue a client by writing \
                 clients/<token>.json in the workspace; revoke by deleting it.",
            )
            .verb(Verb::Source)
            .requires(CAP_CLIENT_READ)
            .output("application/json")
    }
}

/// The capability to ISSUE a client link. Deliberately distinct from reading one, and
/// never granted to the public edge: the door may name a client, only the host may mint one.
pub const CAP_CLIENT_ISSUE: &str = "urn:cap:client:issue";

/// Where an issued link points. Override with `IKIGAI_BOOKING_URL`.
fn booking_url() -> String {
    std::env::var("IKIGAI_BOOKING_URL")
        .unwrap_or_else(|_| "https://www.bosatsu.net/book.html".to_string())
}

/// Percent-encode a query VALUE (RFC 3986 unreserved set kept, everything else escaped).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A URL-safe opaque token. 16 bytes of OS randomness, hex — inside the alphabet and
/// length `ikigai_intake::token_shaped` will accept.
fn mint_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| Error::Endpoint(format!("no randomness available: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A human name reduced to an id: `"Jane Doe"` → `"jane-doe"`.
fn slug(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// Issue a booking link for a client: `urn:client:issue`.
///
/// Mints a token, writes `<workspace>/clients/<token>.json`, and answers with the link to
/// send. The whole administration surface is two file operations — this writes the record,
/// and revoking is `rm` — so there is no registry to keep consistent and nothing to restart.
///
/// The optional `earliest`/`latest` are the reason this exists rather than a shell script:
/// they ride in the record, get attested into the submission as `via-earliest` (never
/// confusable with a field the visitor typed), and let one client book outside the hours
/// everyone else sees. Policy travels with identity.
struct ClientIssue {
    root: PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for ClientIssue {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_CLIENT_ISSUE) {
            return Err(Error::Denied(format!(
                "issuing a client link requires `{CAP_CLIENT_ISSUE}`"
            )));
        }
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "issue a client with Sink, not {:?}",
                inv.request.verb
            )));
        }

        let arg = |name: &str| {
            inv.inline_str(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let name = arg("name").ok_or_else(|| Error::MissingArgument("name".to_string()))?;
        let id = arg("id").unwrap_or_else(|| slug(&name));
        if id.is_empty() {
            return Err(Error::InvalidArgument {
                name: "id".to_string(),
                detail: "a client needs an id (or a name to derive one from)".to_string(),
            });
        }

        let mut record = serde_json::Map::new();
        record.insert("id".to_string(), serde_json::Value::String(id.clone()));
        record.insert("name".to_string(), serde_json::Value::String(name.clone()));
        for field in ["email", "organisation", "note"] {
            if let Some(value) = arg(field) {
                record.insert(field.to_string(), serde_json::Value::String(value));
            }
        }
        // An hour outside 0..=23 would silently produce a window nobody can book in.
        for field in ["earliest", "latest"] {
            if let Some(value) = arg(field) {
                let hour: u8 = value.parse().ok().filter(|h| *h <= 23).ok_or_else(|| {
                    Error::InvalidArgument {
                        name: field.to_string(),
                        detail: format!("`{value}` is not an hour 0..23"),
                    }
                })?;
                record.insert(field.to_string(), serde_json::Value::from(hour));
            }
        }

        let token = mint_token()?;
        let dir = self.root.join("clients");
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Endpoint(format!("cannot create {}: {e}", dir.display())))?;
        let path = dir.join(format!("{token}.json"));
        let body = serde_json::to_vec_pretty(&serde_json::Value::Object(record))
            .map_err(|e| Error::Endpoint(format!("cannot serialise the record: {e}")))?;
        std::fs::write(&path, &body)
            .map_err(|e| Error::Endpoint(format!("cannot write {}: {e}", path.display())))?;

        let mut link = format!("{}?k={}", booking_url(), token);
        // Pre-fill what we already know, so the client types as little as possible. These
        // are convenience only — they are editable, unlike the token.
        for (param, value) in [("name", Some(name.clone())), ("email", arg("email"))] {
            if let Some(value) = value {
                link.push_str(&format!("&{param}={}", urlencode(&value)));
            }
        }

        // Sending is opt-in and never the default: minting a link is local and reversible,
        // putting it in someone's inbox is neither.
        let mut sent = String::new();
        if arg("send").is_some_and(|v| matches!(v.as_str(), "yes" | "true" | "1")) {
            let to = arg("email").ok_or_else(|| Error::InvalidArgument {
                name: "send".to_string(),
                detail: "nothing to send to — this client has no `email`".to_string(),
            })?;
            let text = format!(
                "Hello {name},\n\nHere is your personal link for scheduling time with me. \
                 It stays valid, so keep it somewhere you'll find it again:\n\n{link}\n\n\
                 Offer whichever hours suit you and I'll confirm one.\n\nBrian\n"
            );
            inv.issue(
                Request::new(
                    Verb::Sink,
                    Iri::parse("urn:email:send").expect("literal IRI"),
                )
                .with_arg("to", ArgRef::Inline(to.clone().into_bytes()))
                .with_arg("subject", ArgRef::Inline(b"Your scheduling link".to_vec()))
                .with_arg("content", ArgRef::Inline(text.into_bytes())),
            )
            .await?;
            sent = format!("sent to {to}\n");
        }

        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!("{link}\nclient: {id}\nrecord: {}\n{sent}", path.display()).into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "client-issue"
    }

    fn describe(&self) -> Description {
        Description::new("client-issue")
            .title("Issue a client booking link")
            .summary(
                "Mints a token, writes the client record, and answers with the link to \
                 send. Revoke by deleting the record. `earliest`/`latest` widen the \
                 booking window for this client alone.",
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("issue — mint a durable booking link for one client")
                    .requires(CAP_CLIENT_ISSUE)
                    .input(ArgSpec::new("name").summary("the client's name"))
                    .input(
                        ArgSpec::new("id")
                            .optional()
                            .summary("short id recorded on their bookings (default: from name)"),
                    )
                    .input(
                        ArgSpec::new("email")
                            .optional()
                            .summary("pre-filled in the link, and where `send=yes` posts it"),
                    )
                    .input(ArgSpec::new("organisation").optional().summary("their org"))
                    .input(
                        ArgSpec::new("note")
                            .optional()
                            .summary("a note to yourself"),
                    )
                    .input(
                        ArgSpec::new("earliest")
                            .optional()
                            .summary("earliest bookable hour for THIS client, host-local 0..23"),
                    )
                    .input(
                        ArgSpec::new("latest")
                            .optional()
                            .summary("latest bookable hour for THIS client, host-local 0..23"),
                    )
                    .input(
                        ArgSpec::new("send")
                            .optional()
                            .one_of(["yes", "no"])
                            .summary("email the link to them (default no)"),
                    ),
            )
            .output("text/plain; charset=utf-8")
    }
}

/// The public contact form's accepted fields. Each `summary` is human-facing on purpose:
/// it is what `?description` projects and a generated form renders as the field's LABEL,
/// so the validation and the UI come from ONE declaration and cannot drift.
fn contact_intake() -> ikigai_intake::IntakeConfig {
    use ikigai_intake::IntakeField as F;
    ikigai_intake::IntakeConfig {
        id: "contact".to_string(),
        space: "urn:space:contact".to_string(),
        fields: vec![
            F::required("name", "Your name"),
            F::required("email", "Your email address"),
            F::optional("organisation", "Organisation"),
            F::required("message", "Your message"),
        ],
        email_field: Some("email".to_string()),
        honeypot: Some("_honey".to_string()),
        requires: "urn:cap:contact:submit".to_string(),
        clients: Some(CLIENT_TEMPLATE.to_string()),
        attests: Vec::new(),
        // A plain form POST (JS off) lands the browser on the response, so send it to the
        // site's own styled confirmation page rather than dead-ending on a bare "received".
        // The confirmation lives in bosatsu.net's own template (header, footer, fonts), so
        // there is no interstitial CSS here to keep in sync with the site.
        redirect: Some("https://www.bosatsu.net/thanks.html".to_string()),
        check_blocked: true,
    }
}

/// The public booking request's accepted fields. The visitor offers THEIR hours and zone;
/// the handler finds a mutually free slot. The host's freebusy never leaves the machine —
/// a visitor never sees a calendar, they only propose availability.
fn booking_intake() -> ikigai_intake::IntakeConfig {
    use ikigai_intake::IntakeField as F;
    ikigai_intake::IntakeConfig {
        id: "booking".to_string(),
        space: "urn:space:bookings".to_string(),
        fields: vec![
            F::required("name", "Your name"),
            F::required("email", "Your email address"),
            F::required("period", "When would you like to meet?").one_of([
                "week",
                "next-week",
                "month",
                "today",
                "tomorrow",
            ]),
            // The specific-date picker, optional: a chosen date overrides the period above.
            // The handler validates the shape and the availability endpoint the substance —
            // this is the convenience half. A generated form renders it as an HTML5 date input
            // (keyed on the field name, the same way the zone field becomes a picker).
            F::optional("date", "Or pick a specific date"),
            // Optional: absence is "I'm flexible," not a malformed request. Blank defaults to
            // business hours (the handler's `visitor-hours-for`); a preference still only ranks
            // within them, never widens them. A non-blank value that isn't clock-hours is still
            // rejected by the handler. The generated form drops the required marker from the
            // ?description automatically — bosatsu-www needs no change.
            F::optional(
                "hours",
                "Hours that suit you, in YOUR timezone (24-hour, space separated — e.g. 9 10 14); leave blank for any business hour",
            ),
            // No "e.g. Europe/London" hint: a generated form offers a zone picker, and the
            // label is what it renders. The server still checks the name against tzdata.
            F::required("zone", "Your timezone").iana_zone(),
            F::optional(
                "preference",
                "Anything to note? (e.g. nothing before 10, not right after lunch)",
            ),
        ],
        email_field: Some("email".to_string()),
        honeypot: Some("_honey".to_string()),
        requires: "urn:cap:booking:submit".to_string(),
        clients: Some(CLIENT_TEMPLATE.to_string()),
        // A client's own booking window rides in as `via-earliest`/`via-latest`, which the
        // handler may widen on — and which the visitor cannot type, because the submitted
        // field would be `earliest`, not `via-earliest`.
        attests: vec!["earliest".to_string(), "latest".to_string()],
        // A booking is scheduled asynchronously; the plain `received` acknowledgement is right
        // (there is no slot to show yet). Left un-redirected deliberately.
        redirect: None,
        // Reject a blocked scheduler at the edge, before the request drains to bug (bug's
        // booking-handler `blocked?` stays as backstop).
        check_blocked: true,
    }
}

/// Where outbound mail is submitted and who it says it is from. Read from the host config
/// file (`~/.config/ikigai/config.toml`: `mail.host` / `mail.port` / `mail.from`) — the one
/// place the daemon and the CLI both read, so they cannot diverge. The matching environment
/// variables remain as an override for CI and containers.
///
/// The host and port default to a local MTA on the standard port (the deliverable path, since
/// that MTA owns the onward relay and its credentials). `from` has NO usable default: unset
/// means unconfigured, and `urn:email:send` refuses to send with an empty sender rather than
/// ship a placeholder (`ikigai@localhost`) that a sender-aligned relay silently rejects.
fn email_config() -> ikigai_email::EmailConfig {
    let default = ikigai_email::EmailConfig::default();
    // File first (the home), then the env var (the escape hatch).
    let setting = |key: &str, env: &str| config::get(key).or_else(|| std::env::var(env).ok());
    ikigai_email::EmailConfig {
        host: setting("mail.host", "IKIGAI_SMTP_HOST").unwrap_or(default.host),
        port: setting("mail.port", "IKIGAI_SMTP_PORT")
            .and_then(|p| p.parse().ok())
            .unwrap_or(default.port),
        from: setting("mail.from", "IKIGAI_MAIL_FROM").unwrap_or_default(),
    }
}

/// This process's INSTANCE NAME — the key config properties are scoped by
/// (`<name>.derive_every`), so behavior attaches to a named instance, never to
/// the binary: a REPL is "repl", the headless agent "daemon", a served kernel
/// "serve", and `--name` mints others. First write wins; defaults to "repl".
pub fn set_instance_name(name: impl Into<String>) {
    let _ = INSTANCE_NAME.set(name.into());
}

/// This process's instance name (see [`set_instance_name`]).
pub fn instance_name() -> &'static str {
    INSTANCE_NAME.get().map(String::as_str).unwrap_or("repl")
}

/// The standing-sync registration, for hosts that report their own startup
/// state: `Some(interval)` when `<instance>.derive_every` matched this
/// instance's name in calendar.json, `None` when this instance is idle.
pub fn standing_sync_interval() -> Option<std::time::Duration> {
    derive_every()
}

/// One immediate standing-sync pass, for a host that just came up: a daemon
/// restarting after downtime shouldn't wait a full interval to catch up on
/// what it missed. Reports under its own `startup →` label, like each watcher
/// does. No-op when the standing sync isn't registered for this instance.
pub fn startup_derive(kernel: &Arc<Kernel>) {
    if derive_every().is_none() {
        return;
    }
    let request = Request::new(
        Verb::Source,
        Iri::parse("urn:view:derive").expect("valid IRI"),
    );
    match ikigai_resolve::Resolver::issue(kernel.as_ref(), request) {
        Ok((report, _)) => eprintln!(
            "{} ikigai: startup → {}",
            stamp(),
            String::from_utf8_lossy(&report.bytes).trim()
        ),
        Err(e) => eprintln!("{} ikigai: startup → derive failed: {e}", stamp()),
    }
}

static INSTANCE_NAME: OnceLock<String> = OnceLock::new();

/// `<instance>.derive_every` from calendar.json — "300s" / "5m" / "1h". SCOPED
/// ONLY: the standing sync starts on instances explicitly named in the config
/// (a server without `serve.derive_every` never touches the calendar); an
/// unscoped `derive_every` is deliberately ignored.
fn derive_every() -> Option<std::time::Duration> {
    let path = std::env::var("IKIGAI_CALENDAR_CONFIG")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config/ikigai/calendar.json"))
        })?;
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let spec = v[format!("{}.derive_every", instance_name())].as_str()?;
    let (digits, unit) = spec.split_at(spec.len().saturating_sub(1));
    let n: u64 = digits.parse().ok()?;
    let seconds = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return None,
    };
    (seconds >= 30).then(|| std::time::Duration::from_secs(seconds))
}

/// Watch `root` recursively; on any out-of-band change, cut `urn:file:<rel>` so the
/// cached read recomputes. Runs on a detached thread for the process's lifetime; a
/// watch error disables it silently (caching then invalidates only on
/// kernel-mediated writes — still correct for files written through ikigai).
fn watch_root(kernel: Arc<Kernel>, root: PathBuf) {
    // Canonicalize so the prefix matches the paths `notify` reports — it resolves
    // symlinks (notably macOS maps `/var` → `/private/var`), and the relative path
    // is what becomes the `urn:file:<rel>` thread.
    let root = root.canonicalize().unwrap_or(root);
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(watcher) => watcher,
            Err(_) => return,
        };
        if watcher.watch(&root, RecursiveMode::Recursive).is_err() {
            return;
        }
        // `watcher` is held to the end of this scope, keeping the watch (and the
        // channel) alive; the loop blocks until the process exits.
        for event in rx.iter().flatten() {
            if event.kind.is_access() {
                continue; // a read doesn't change content
            }
            for path in &event.paths {
                if let Some(thread) = file_thread(&root, path) {
                    kernel.cut(thread);
                }
            }
        }
    });
}

/// Watch the org directory and trigger a consolidated-view derivation when an
/// agenda file changes — INSTANT freshness on top of the timer's heartbeat.
/// Debounced (Dropbox delivers edits as event bursts) and gated the same way
/// the standing sync is: only instances with a scoped `derive_every` react
/// (an unsynced instance has no business deriving). The derive itself is
/// idempotent, so a spurious extra trigger costs one no-op pass.
fn watch_org(kernel: Arc<Kernel>) {
    if derive_every().is_none() {
        return; // not a syncing instance
    }
    let Some((dir, files)) = org_config() else {
        return;
    };
    let watched: Vec<String> = files
        .iter()
        .filter_map(|iri| iri.strip_prefix("urn:orgfile:").map(str::to_string))
        .collect();
    let dir = dir.canonicalize().unwrap_or(dir);
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(watcher) => watcher,
            Err(_) => return,
        };
        if watcher.watch(&dir, RecursiveMode::NonRecursive).is_err() {
            return;
        }
        let mut last_run = std::time::Instant::now() - std::time::Duration::from_secs(60);
        for event in rx.iter().flatten() {
            if event.kind.is_access() {
                continue;
            }
            let relevant = event.paths.iter().any(|path| {
                path.file_name()
                    .map(|name| watched.iter().any(|w| w.as_str() == name.to_string_lossy()))
                    .unwrap_or(false)
            });
            if !relevant {
                continue;
            }
            // Debounce the burst, then let straggler events settle before deriving.
            if last_run.elapsed() < std::time::Duration::from_secs(3) {
                continue;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
            while rx.try_recv().is_ok() {} // drain the settled burst
            let request = Request::new(
                Verb::Source,
                Iri::parse("urn:view:derive").expect("valid IRI"),
            );
            // The same sync seam the time transport drives the kernel through.
            let outcome = ikigai_resolve::Resolver::issue(kernel.as_ref(), request);
            match outcome {
                Ok((report, _)) => eprintln!(
                    "{} ikigai: org change → {}",
                    stamp(),
                    String::from_utf8_lossy(&report.bytes).trim()
                ),
                Err(e) => eprintln!("{} ikigai: org change → derive failed: {e}", stamp()),
            }
            last_run = std::time::Instant::now();
        }
    });
}

/// React to OS calendar-store changes — an invitation landing, an edit in
/// Calendar.app, an iCloud sync from another device — by deriving the
/// consolidated view. The other half of event-driven freshness (watch_org
/// covers Brian's side; this covers the world's). The 15s window both
/// debounces iCloud bursts and suppresses the notifications our OWN derive
/// writes cause (the loop would self-terminate anyway — a re-derive is a
/// no-op — but suppression skips even that pass). Gated like the standing
/// sync: only instances with a scoped derive_every react.
fn watch_store(kernel: Arc<Kernel>) {
    if derive_every().is_none() {
        return;
    }
    // Signal source: the calendar daemon writes ~/Library/Calendars on every
    // change (local edits, invitations, iCloud syncs) — a filesystem event is a
    // reliable, documented-behavior-free change signal. (EventKit's own
    // EKEventStoreChangedNotification needs a serviced MAIN runloop this CLI
    // doesn't have — ikigai_personal::observe_calendar_changes remains for
    // hosts that do.)
    let Some(home) = std::env::var("HOME").ok() else {
        return;
    };
    // Both store locations: the classic path and the modern group container.
    let store_dirs: Vec<PathBuf> = [
        "Library/Calendars",
        "Library/Group Containers/group.com.apple.calendar",
    ]
    .iter()
    .map(|rel| Path::new(&home).join(rel))
    .filter(|dir| dir.is_dir())
    .collect();
    if store_dirs.is_empty() {
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (ftx, frx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = ftx.send(res);
        }) {
            Ok(watcher) => watcher,
            Err(_) => return,
        };
        let mut watching = 0;
        for dir in &store_dirs {
            if watcher.watch(dir, RecursiveMode::Recursive).is_ok() {
                watching += 1;
            }
        }
        if watching == 0 {
            eprintln!(
                "{} ikigai: calendar store watcher could not attach",
                stamp()
            );
            return;
        }
        eprintln!(
            "{} ikigai: calendar store watcher active ({watching} location(s))",
            stamp()
        );
        for event in frx.iter().flatten() {
            if event.kind.is_access() {
                continue;
            }
            let _ = tx.send(());
        }
    });
    std::thread::spawn(move || {
        let mut last_run = std::time::Instant::now();
        for () in rx.iter() {
            if last_run.elapsed() < std::time::Duration::from_secs(15) {
                continue;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
            while rx.try_recv().is_ok() {}
            let request = Request::new(
                Verb::Source,
                Iri::parse("urn:view:derive").expect("valid IRI"),
            );
            match ikigai_resolve::Resolver::issue(kernel.as_ref(), request) {
                Ok((report, _)) => eprintln!(
                    "{} ikigai: calendar change → {}",
                    stamp(),
                    String::from_utf8_lossy(&report.bytes).trim()
                ),
                Err(e) => eprintln!("{} ikigai: calendar change → derive failed: {e}", stamp()),
            }
            last_run = std::time::Instant::now();
        }
    });
}

/// The golden thread for a changed `path` under `root`: `urn:file:<rel>` with
/// forward-slash separators (matching the `urn:file:{path}` grammar). `None` if
/// `path` is not under `root`, or is the root itself.
fn file_thread(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let joined = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    (!joined.is_empty()).then(|| format!("urn:file:{joined}"))
}

/// Build a **trusted served** kernel (for IPC), *including* the personal space.
///
/// Safe because the IPC server peercred-verifies that the connecting peer is the
/// same OS user — the owner — so it's as trusted as the local kernel. The client
/// carries its (possibly attenuated) capability, which the server clamps to that
/// principal. Distinct from [`kernel_for`], the QUIC kernel, which omits personal
/// because a QUIC peer isn't authenticated yet.
pub fn trusted_kernel_for(nature: &'static str) -> Kernel {
    // The same-user IPC surface is the FULL embedded root — llm, rdf, meeting,
    // the demo-gated runbook, everything the terminal REPL gets. Peercred means
    // the peer IS this user: the socket is a process boundary, not a trust
    // boundary, so an emacs (or any local) client is the same principal as the
    // terminal and deserves the same manifold. (Serving only `local_space` here
    // was a pre-client-era artifact: `demo on` flipped the flag remotely while
    // the gated runbook simply wasn't mounted to wake up.) The wire-eval
    // governor still fronts it: trusted PEER ≠ trusted PROGRAM — a runaway
    // shipped over the socket times out (typed, transient) instead of pinning
    // the server.
    trusted_kernel_with_mounts(nature, Vec::new())
}

/// The trusted IPC surface, composing remote kernels into it.
///
/// THE HOST OWNS THE TOPOLOGY. A local client (Emacs, the REPL, MCP) then reaches a peer's
/// resources by talking to this socket, without knowing where that peer is or holding its
/// certificates — and without needing the platform permissions the discovery itself needs.
/// On macOS that is the difference between working and not: multicast is granted per
/// RESPONSIBLE process, so an `ikigai` spawned by Emacs.app inherits Emacs's grant rather
/// than the one you gave your terminal, and a browse that is denied simply hears nothing.
/// One daemon, granted once, removes that from every client's problem.
///
/// It is also what `ikigai.el`'s own docs already promised — "a connected host owns its own
/// mounts, so a machine's transport and topology are a property of that host" — which was
/// unachievable while only the REPL and `--daemon` could take mount flags.
pub fn trusted_kernel_with_mounts(nature: &'static str, mounts: Vec<MountSpec>) -> Kernel {
    start_uptime_clock();
    let _ = nature;
    let space = if mounts.is_empty() {
        root_space()
    } else {
        root_space_with_mounts(mounts)
    };
    Kernel::with_meta_renderer(with_wire_eval(space), Arc::new(CliRenderer))
        .with_clock(Arc::new(SystemClock))
        .with_subclass_axioms(subclass_axioms())
}

/// Build a **served** kernel for an *unauthenticated* transport (QUIC), labelled
/// `nature`. It has **no personal space**: a QUIC peer has no capability for it
/// yet and the server resolves under a default authority, so exposing
/// `urn:personal:*` would leak it — gated on remote auth + capability-on-the-wire.
pub fn kernel_for(nature: &'static str) -> Kernel {
    Kernel::with_meta_renderer(Arc::new(served_space(nature)), Arc::new(CliRenderer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Request};

    /// The prelude must be VALID STEEL, and getting there took four failed shapes — each
    /// of which produced `FreeIdentifier: ##rest2`, Steel's opaque report for a rest-arg
    /// problem. Pinning the working form so a "tidy-up" cannot silently break it:
    /// `(apply invoke …)`, `(append (list …) rest)`, and passing a cons chain straight to
    /// the native `%verb-args` all fail; a LET-BOUND cons chain into the fixed-arity
    /// primitive works.
    #[test]
    fn a_generated_alias_has_the_shape_steel_actually_accepts() {
        let targets = vec![AliasTarget {
            iri: "urn:fn:toUpper".to_string(),
            summary: "Upper-cases the text.".to_string(),
            actions: vec![("Source".to_string(), vec!["in".to_string()])],
        }];
        let out = aliases_scheme(&targets, "");
        assert!(out.contains("(define (fn-toUpper in . rest)"), "{out}");
        assert!(
            out.contains("(let ((args (cons \"in\" (cons in rest))))"),
            "{out}"
        );
        assert!(
            out.contains("(%verb-args \"source\" \"urn:fn:toUpper\" args)"),
            "the fixed-arity primitive, not `apply invoke`: {out}"
        );
    }

    /// `urn:fn:conditional` really does declare an argument named `if`, and
    /// `(define (fn-conditional if …) …)` will not parse. The BINDER is renamed; the WIRE
    /// name must not be.
    #[test]
    fn a_reserved_argument_name_is_renamed_only_in_the_binder() {
        let targets = vec![AliasTarget {
            iri: "urn:fn:conditional".to_string(),
            summary: String::new(),
            actions: vec![(
                "Source".to_string(),
                vec!["if".to_string(), "then".to_string()],
            )],
        }];
        let out = aliases_scheme(&targets, "");
        assert!(
            out.contains("(define (fn-conditional if* then . rest)"),
            "{out}"
        );
        assert!(
            out.contains("(cons \"if\" (cons if* "),
            "the wire name stays `if`: {out}"
        );
    }

    /// A verb that mutates reads as one: Scheme's `!`.
    #[test]
    fn verbs_shape_the_alias_name() {
        assert_eq!(alias_name("urn:fn:toUpper", "Source"), "fn-toUpper");
        assert_eq!(alias_name("urn:space:bookings", "Sink"), "space-bookings!");
        assert_eq!(alias_name("urn:file:x", "Delete"), "file-x-delete!");
        assert_eq!(alias_name("urn:file:x", "Exists"), "file-x?");
    }

    /// Compose documents ITSELF with a literal `$a{<iri>}` marker, so that text lands in a
    /// generated comment — and composing the prelude then tries to expand the example in
    /// its own documentation. Escaping must also be a FIXED POINT, or the already-escaped
    /// `$$a{…}` in the same sentence becomes `$$$a{…}` and fails differently.
    #[test]
    fn transclusion_markers_in_summaries_are_escaped_idempotently() {
        assert_eq!(
            escape_markers("expands $a{<iri>} markers"),
            "expands $$a{<iri>} markers"
        );
        assert_eq!(escape_markers("literal is $$a{…}"), "literal is $$a{…}");
        assert_eq!(escape_markers("$$$a{x}"), "$$a{x}");
        assert_eq!(escape_markers("a $5 cost"), "a $5 cost");
    }

    fn candidate(id: &str, iri: &str, verb: &str) -> SelectCandidate {
        SelectCandidate {
            action: format!("urn:ikigai:endpoint:{id}:action:{}", verb.to_lowercase()),
            endpoint: iri.to_string(),
            verb: verb.to_string(),
            requires: Vec::new(),
            missing_optional: 0,
        }
    }

    /// CAPABILITY FILTERING is not a filter bolted onto the generator — the prelude is
    /// projected from `urn:kernel:actions`, which the kernel has already narrowed to what
    /// this capability may invoke. An action absent from the manifold gets no verb, so a
    /// scoped session gets a SMALLER prelude rather than a full one that fails at call time.
    #[test]
    fn only_authorized_actions_get_a_verb() {
        let described = catalog_descriptions(
            r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:toUpper> a ik:Endpoint ; ik:id "toUpper" ; ik:verb "Source" ;
    ik:input [ ik:inputName "in" ; ik:required true ] .
<urn:ikigai:endpoint:client-issue> a ik:Endpoint ; ik:id "client-issue" ; ik:verb "Sink" .
"#,
        );
        // The catalog describes both; the manifold authorizes only one.
        let authorized = vec![candidate("toUpper", "urn:fn:toUpper", "Source")];
        let targets = alias_targets(&authorized, &described);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].iri, "urn:fn:toUpper");
        let out = aliases_scheme(&targets, "");
        assert!(out.contains("fn-toUpper"), "{out}");
        assert!(
            !out.contains("client-issue"),
            "an unauthorized action must not appear at all: {out}"
        );
    }

    /// The manifold carries the RESOLVABLE IRI; the catalog names endpoints by a skolem
    /// description IRI. Joining on the id is what keeps the emitted call dialable.
    #[test]
    fn the_emitted_iri_is_the_resolvable_one() {
        let described = catalog_descriptions(
            r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:toUpper> a ik:Endpoint ; ik:id "toUpper" ; ik:verb "Source" ;
    ik:input [ ik:inputName "in" ; ik:required true ] .
"#,
        );
        let targets = alias_targets(
            &[candidate("toUpper", "urn:fn:toUpper", "Source")],
            &described,
        );
        let out = aliases_scheme(&targets, "");
        assert!(out.contains("\"urn:fn:toUpper\""), "{out}");
        assert!(
            !out.contains("urn:ikigai:endpoint:toUpper\""),
            "the skolem IRI is a description, not an address: {out}"
        );
    }

    /// The elisp face is a REPRESENTATION of the same projection: same targets, same
    /// required/optional split, a different lisp.
    #[test]
    fn the_elisp_face_emits_callable_defuns() {
        let targets = vec![AliasTarget {
            iri: "urn:fn:toUpper".to_string(),
            summary: "Upper-cases the text.".to_string(),
            actions: vec![("Source".to_string(), vec!["in".to_string()])],
        }];
        let out = aliases_elisp(&targets, "");
        assert!(
            out.contains("(defun ikigai-fn-toUpper (in &rest args)"),
            "{out}"
        );
        assert!(
            out.contains("\"Upper-cases the text.\""),
            "docstring: {out}"
        );
        assert!(
            out.contains("(apply #'ikigai-invoke 'source \"urn:fn:toUpper\" \"in\" in args)"),
            "{out}"
        );
        // NO bundled runtime: ikigai.el owns transport, mounts and quoting, and defines
        // `ikigai-invoke`. A second runtime would duplicate all of that AND collide on
        // `ikigai-connect`/`ikigai-program`.
        assert!(out.contains("(require 'ikigai)"), "{out}");
        assert!(
            !out.contains("defun ikigai--call"),
            "no duplicate runtime: {out}"
        );
        assert!(out.ends_with("(provide 'ikigai-aliases)\n"), "{out}");
    }

    /// Elisp is a lisp-2, so `if` is a perfectly good VARIABLE name — unlike Scheme, where
    /// it must be renamed. Only the constants cannot be rebound.
    #[test]
    fn elisp_parameters_are_sanitized_only_where_elisp_requires_it() {
        assert_eq!(safe_elisp_param("if"), "if");
        assert_eq!(safe_elisp_param("in"), "in");
        assert_eq!(safe_elisp_param("nil"), "nil-value");
        assert_eq!(safe_elisp_param("t"), "t-value");
        // `args` is the generated rest parameter; a declared argument of that name would
        // shadow it and silently drop every optional argument.
        assert_eq!(safe_elisp_param("args"), "args-value");
    }

    /// A generated defun must never redefine something ikigai.el owns — `ikigai-eval` in
    /// particular is what every alias calls through.
    #[test]
    fn generated_names_do_not_clobber_the_package() {
        assert_eq!(elisp_defun_name("fn-toUpper"), "ikigai-fn-toUpper");
        assert_eq!(elisp_defun_name("eval"), "ikigai-eval-resource");
        assert_eq!(elisp_defun_name("invoke"), "ikigai-invoke-resource");
    }

    /// A docstring is a string literal: an embedded quote in a summary would end it early
    /// and produce a file Emacs cannot load.
    #[test]
    fn elisp_docstrings_escape_quotes() {
        let targets = vec![AliasTarget {
            iri: "urn:x:y".to_string(),
            summary: "says \"hello\" loudly".to_string(),
            actions: vec![("Source".to_string(), vec![])],
        }];
        let out = aliases_elisp(&targets, "");
        assert!(out.contains("says \\\"hello\\\" loudly"), "{out}");
    }

    /// A family is not a callable.
    #[test]
    fn templates_are_not_given_aliases() {
        let described = catalog_descriptions(
            r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:file> a ik:Endpoint ; ik:id "file" ; ik:verb "Source" .
"#,
        );
        let targets = alias_targets(
            &[candidate("file", "urn:file:{path}", "Source")],
            &described,
        );
        assert!(targets.is_empty(), "{targets:?}");
    }

    /// An authorized action the catalog says nothing about still gets a verb — undocumented
    /// and argument-less — rather than being dropped. Silence in one source must not remove
    /// an affordance the other one grants.
    #[test]
    fn an_undescribed_action_still_gets_a_verb() {
        let described = std::collections::BTreeMap::new();
        let targets = alias_targets(
            &[candidate("mystery", "urn:mystery:go", "Source")],
            &described,
        );
        let out = aliases_scheme(&targets, "");
        assert!(out.contains("(define (mystery-go . rest)"), "{out}");
    }

    /// A MOUNTED kernel describes the same endpoint again, under the same skolem subject,
    /// so the catalog carries it twice — and the required inputs were accumulated across
    /// both. That generated `(defun ikigai-llm-ask (prompt prompt &rest args) …)`, which
    /// Emacs refuses to call. Invisible without a mount; guaranteed with one.
    #[test]
    fn a_duplicated_endpoint_does_not_duplicate_its_arguments() {
        let catalog = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:llm-ask> a ik:Endpoint ; ik:id "llm-ask" ; ik:verb "Source" ;
    ik:input [ ik:inputName "prompt" ; ik:required true ] ,
             [ ik:inputName "model" ; ik:required false ] .
<urn:ikigai:endpoint:llm-ask> a ik:Endpoint ; ik:id "llm-ask" ; ik:verb "Source" ;
    ik:input [ ik:inputName "prompt" ; ik:required true ] ,
             [ ik:inputName "model" ; ik:required false ] .
"#;
        let described = catalog_descriptions(catalog);
        let (_summary, actions) = described.get("llm-ask").expect("parsed");
        assert_eq!(
            *actions,
            vec![("Source".to_string(), vec!["prompt".to_string()])],
            "one prompt, not two"
        );
    }

    /// Inputs may be BLANK nodes in the catalog's Turtle.    /// Inputs may be BLANK nodes in the catalog's Turtle. Filtering to named subjects
    /// silently produced zero arguments for every endpoint — the generator emitted
    /// parameterless functions that ignored their inputs.
    #[test]
    fn blank_node_inputs_are_read() {
        let catalog = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:toUpper> a ik:Endpoint ; ik:id "toUpper" ; ik:verb "Source", "Meta" ;
    ik:input [ ik:inputName "in" ; ik:required true ] ,
             [ ik:inputName "as" ; ik:required false ] .
"#;
        let described = catalog_descriptions(catalog);
        let (_summary, actions) = described.get("toUpper").expect("parsed");
        // Meta is self-description, never a selectable action; `as` is optional so it
        // rides in `rest` rather than becoming a positional parameter.
        assert_eq!(
            *actions,
            vec![("Source".to_string(), vec!["in".to_string()])]
        );
    }

    fn job(interval_secs: u64, since_last: Option<u64>, recurring: bool) -> ikigai_time::JobHealth {
        ikigai_time::JobHealth {
            id: 1,
            target: "urn:view:derive:tick".to_string(),
            interval: std::time::Duration::from_secs(interval_secs),
            recurring,
            persistent: true,
            runs: since_last.map(|_| 5).unwrap_or(0),
            since_last: since_last.map(std::time::Duration::from_secs),
            last_output: String::new(),
        }
    }

    /// Staleness is judged against the job's OWN declared cadence, so nothing has to be
    /// configured: a 5-minute derive is stale at 15 minutes, a 30-second drain at 90s.
    /// This is the check that would have caught a writer dead for sixteen hours within
    /// fifteen minutes.
    #[test]
    fn a_job_is_stale_after_three_of_its_own_cadences() {
        let up = std::time::Duration::from_secs(86_400);
        // 300s derive: fine at 10 minutes, stale at 20.
        assert!(!job_is_stale(&job(300, Some(600), true), up));
        assert!(job_is_stale(&job(300, Some(1200), true), up));
        // 30s drain: fine at 60s, stale at 120s.
        assert!(!job_is_stale(&job(30, Some(60), true), up));
        assert!(job_is_stale(&job(30, Some(120), true), up));
    }

    /// A job that has NEVER run is not automatically broken — it may simply be younger
    /// than its first tick. It becomes stale once the PROCESS has been up long enough that
    /// it should have fired.
    #[test]
    fn a_job_that_never_ran_is_judged_against_uptime() {
        let young = std::time::Duration::from_secs(10);
        let old = std::time::Duration::from_secs(3600);
        assert!(
            !job_is_stale(&job(300, None, true), young),
            "a fresh process has not missed anything yet"
        );
        assert!(
            job_is_stale(&job(300, None, true), old),
            "an hour up and the 5-minute job has never fired: that is broken"
        );
    }

    /// A one-shot job was meant to fire once. Calling it stale forever afterwards would
    /// make the whole report cry wolf.
    #[test]
    fn a_one_shot_job_is_never_stale() {
        let old = std::time::Duration::from_secs(86_400);
        assert!(!job_is_stale(&job(30, Some(86_000), false), old));
        assert!(!job_is_stale(&job(30, None, false), old));
    }

    /// PEER ABSENCE IS NOT A FAULT. Brian travels with plasma; a health check that pages
    /// about a laptop being elsewhere is a health check nobody reads. The verdict line
    /// must depend only on this host's own jobs.
    #[test]
    fn peers_do_not_affect_the_verdict() {
        let jobs = vec![job(300, Some(60), true)];
        let with_none = health_text(&jobs, &[]);
        let with_peer = health_text(
            &jobs,
            &[ikigai_discovery::Peer {
                name: "plasma".to_string(),
                addrs: vec![],
                port: 4433,
                surface: None,
                ceiling: None,
                version: None,
                trusted: true,
            }],
        );
        assert!(with_none.starts_with("ok"), "{with_none}");
        assert!(with_peer.starts_with("ok"), "{with_peer}");
        assert!(
            with_none.contains("none heard"),
            "an absent peer is reported, not escalated: {with_none}"
        );
    }

    /// A mount target that is always down (or always denies), so the composition's
    /// behaviour under failure can be asserted without a peer.
    struct DeadPeer {
        error: fn(String) -> ikigai_core::Error,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ikigai_resolve::Resolver for DeadPeer {
        fn issue(
            &self,
            _request: Request,
        ) -> std::result::Result<(Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err((self.error)("peer".to_string()))
        }

        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            None
        }
    }

    fn mount(
        prefix: &str,
        kind: MountKind,
        error: fn(String) -> ikigai_core::Error,
    ) -> (MountSpec, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            MountSpec {
                prefix: prefix.to_string(),
                origin: "test://peer".to_string(),
                resolver: Arc::new(DeadPeer {
                    error,
                    calls: Arc::clone(&calls),
                }),
                kind,
            },
            calls,
        )
    }

    /// `urn:fn:toUpper` is bound locally, so it is a good probe for "did the local
    /// binding get a chance to answer".
    fn probe(space: &Arc<dyn Space>, iri: &str) -> std::result::Result<String, ikigai_core::Error> {
        let kernel = Kernel::new(Arc::clone(space));
        let request = Request::new(Verb::Source, Iri::parse(iri).unwrap())
            .with_arg("in", ArgRef::Inline(b"hi".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root()))?;
        Ok(String::from_utf8_lossy(&representation.bytes).to_string())
    }

    /// The point of `--prefer`: the peer is unreachable, so THIS machine answers.
    #[test]
    fn a_prefer_mount_falls_back_to_the_local_binding_when_the_peer_is_down() {
        let (spec, calls) = mount(
            "urn:fn:",
            MountKind::Prefer,
            ikigai_core::Error::Unavailable,
        );
        let space = root_space_with_mounts(vec![spec]);
        let answer = probe(&space, "urn:fn:toUpper").expect("local must answer for a dead peer");
        assert_eq!(answer, "HI");
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the peer must be TRIED first — preferring it is the whole point"
        );
    }

    /// The same mount as an `--override` FAILS instead. You named that machine; a
    /// silent local substitution would answer a question you did not ask.
    #[test]
    fn an_override_mount_fails_when_the_peer_is_down() {
        let (spec, _) = mount(
            "urn:fn:",
            MountKind::Override,
            ikigai_core::Error::Unavailable,
        );
        let space = root_space_with_mounts(vec![spec]);
        let err = probe(&space, "urn:fn:toUpper").expect_err("an override must not fall back");
        assert!(matches!(err, ikigai_core::Error::Unavailable(_)), "{err:?}");
    }

    /// A DENIAL is not a transient failure. If the peer answered "you may not", the
    /// local binding must not quietly answer instead — that would turn a capability
    /// boundary into a suggestion.
    #[test]
    fn a_prefer_mount_does_not_swallow_a_denial() {
        let (spec, _) = mount("urn:fn:", MountKind::Prefer, ikigai_core::Error::Denied);
        let space = root_space_with_mounts(vec![spec]);
        let err = probe(&space, "urn:fn:toUpper").expect_err("a denial must propagate");
        assert!(matches!(err, ikigai_core::Error::Denied(_)), "{err:?}");
    }

    /// A prefer-mount pairs its peer with the WHOLE local space, so without a prefix
    /// guard it would answer for every IRI — hitting before a less-specific override
    /// behind it and silently defeating it.
    #[test]
    fn a_prefer_mount_does_not_claim_iris_outside_its_prefix() {
        let (prefer, prefer_calls) = mount(
            "urn:llm:",
            MountKind::Prefer,
            ikigai_core::Error::Unavailable,
        );
        let (override_mount, override_calls) = mount(
            "urn:fn:",
            MountKind::Override,
            ikigai_core::Error::Unavailable,
        );
        let space = root_space_with_mounts(vec![prefer, override_mount]);
        let err = probe(&space, "urn:fn:toUpper")
            .expect_err("the override still owns urn:fn:, despite the longer prefer prefix");
        assert!(matches!(err, ikigai_core::Error::Unavailable(_)), "{err:?}");
        assert_eq!(
            prefer_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the urn:llm: mount must not see a urn:fn: request"
        );
        assert!(override_calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
    }

    /// A kernel with just the client endpoints, rooted at a scratch directory.
    fn client_kernel(root: std::path::PathBuf) -> Kernel {
        let space = EndpointSpace::new()
            .bind(
                Exact::new("urn:client:issue"),
                ClientIssue { root: root.clone() },
            )
            .bind(
                UriTemplate::parse(CLIENT_TEMPLATE).unwrap(),
                ClientRegistry::new(root),
            );
        Kernel::new(Arc::new(space))
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ikigai-client-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn issuing_a_link_writes_a_record_the_registry_can_read_back() {
        let root = scratch("issue");
        let k = client_kernel(root.clone());
        let out = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:client:issue").unwrap())
                    .with_arg("name", ArgRef::Inline(b"Nigel Ashworth".to_vec()))
                    .with_arg("earliest", ArgRef::Inline(b"7".to_vec())),
                &Capability::scoped([CAP_CLIENT_ISSUE]),
            ),
        )
        .unwrap();
        let text = String::from_utf8(out.bytes.clone()).unwrap();
        assert!(text.contains("?k="), "answers with a link: {text}");
        // The id is derived from the name when one isn't given.
        assert!(text.contains("client: nigel-ashworth"), "{text}");

        // And the token in that link resolves through the registry to the same record.
        let token = text
            .split("?k=")
            .nth(1)
            .and_then(|s| s.split(['&', '\n']).next())
            .unwrap()
            .to_string();
        let record = block_on(k.issue(
            Request::new(
                Verb::Source,
                Iri::parse(format!("urn:client:{token}")).unwrap(),
            ),
            &Capability::scoped([CAP_CLIENT_READ]),
        ))
        .unwrap();
        let json = String::from_utf8(record.bytes.clone()).unwrap();
        assert!(json.contains("\"earliest\": 7"), "policy travels: {json}");
    }

    #[test]
    fn minting_and_reading_are_separate_authorities() {
        let root = scratch("caps");
        let k = client_kernel(root);
        // The public edge holds read, and must not be able to mint itself a client.
        let denied = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:client:issue").unwrap())
                    .with_arg("name", ArgRef::Inline(b"Sneaky".to_vec())),
                &Capability::scoped([CAP_CLIENT_READ]),
            ),
        )
        .unwrap_err();
        assert!(matches!(denied, Error::Denied(_)), "{denied:?}");
    }

    #[test]
    fn an_hour_outside_the_clock_is_refused() {
        let root = scratch("hours");
        let k = client_kernel(root);
        let err = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:client:issue").unwrap())
                    .with_arg("name", ArgRef::Inline(b"X".to_vec()))
                    .with_arg("earliest", ArgRef::Inline(b"25".to_vec())),
                &Capability::scoped([CAP_CLIENT_ISSUE]),
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not an hour"), "{err}");
    }

    #[test]
    fn a_token_shaped_like_a_path_is_not_found_rather_than_followed() {
        let root = scratch("traversal");
        std::fs::write(root.join("secret.json"), b"{}").unwrap();
        let k = client_kernel(root);
        let err = block_on(k.issue(
            Request::new(Verb::Source, Iri::parse("urn:client:../secret").unwrap()),
            &Capability::scoped([CAP_CLIENT_READ]),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    }

    #[test]
    fn calendar_server_space_exposes_only_the_calendar() {
        use ikigai_core::Space;
        let space = calendar_server_space("test");
        let patterns: Vec<String> = Space::entries(&space)
            .unwrap_or_default()
            .iter()
            .map(|e| format!("{} {}", e.pattern, e.endpoint))
            .collect();
        let has = |needle: &str| patterns.iter().any(|p| p.contains(needle));

        // The calendar surface IS present.
        assert!(has("personal:availability"), "availability: {patterns:?}");
        assert!(has("personal:calendar"), "calendar: {patterns:?}");
        // Personal data and local reach that must NOT be exposed over the wire.
        assert!(
            !has("personal:contacts"),
            "contacts must not leak: {patterns:?}"
        );
        assert!(
            !has("urn:file"),
            "the filesystem must not be served: {patterns:?}"
        );
        assert!(!has("system:exec"), "exec must not be served: {patterns:?}");
        assert!(
            !has("urn:orgfile"),
            "org files must not be served: {patterns:?}"
        );
    }

    #[test]
    fn grant_entry_parses_both_shapes() {
        // Array form: scopes only, no visibility (backward compatible).
        let arr = serde_json::json!(["urn:cap:exec:git", "urn:cap:fs:read:*"]);
        assert_eq!(
            scopes_of(&arr),
            vec![
                "urn:cap:exec:git".to_string(),
                "urn:cap:fs:read:*".to_string()
            ]
        );
        assert_eq!(visibility_of(&arr), (Vec::new(), Vec::new()));

        // Object form: scopes under "scopes", plus show/hide visibility globs.
        let obj = serde_json::json!({
            "scopes": ["urn:cap:exec:git"],
            "hide": ["wc", "greet"],
            "show": ["sparql"]
        });
        assert_eq!(scopes_of(&obj), vec!["urn:cap:exec:git".to_string()]);
        assert_eq!(
            visibility_of(&obj),
            (
                vec!["sparql".to_string()],
                vec!["wc".to_string(), "greet".to_string()]
            )
        );

        // Object form without visibility keys: scopes present, globs empty.
        let bare_obj = serde_json::json!({ "scopes": ["urn:cap:net:*"] });
        assert_eq!(scopes_of(&bare_obj), vec!["urn:cap:net:*".to_string()]);
        assert_eq!(visibility_of(&bare_obj), (Vec::new(), Vec::new()));
    }

    #[test]
    fn history_round_trips_lines() {
        // A unique dir per run so the file I/O is exercised without touching `$HOME`
        // (and without racing the env-reading tests).
        let dir = std::env::temp_dir().join(format!("ikigai-hist-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(history_file(&dir));

        assert!(read_history(&dir).is_empty(), "absent file → no history");
        write_history(&dir, "source urn:fn:toUpper hi");
        write_history(&dir, "   "); // blank → skipped
        write_history(&dir, "list");
        assert_eq!(
            read_history(&dir),
            vec!["source urn:fn:toUpper hi".to_string(), "list".to_string()],
            "appends in order, blanks dropped"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrap_routes_the_text_argument() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:wrap").unwrap())
            .with_arg("text", ArgRef::Inline(b"hi".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"[hi]");
    }

    #[test]
    fn split_makes_a_newline_list_for_map() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:split").unwrap())
            .with_arg("in", ArgRef::Inline(b"a, b ,c".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"a\nb\nc");
    }

    #[test]
    fn greet_combines_two_arguments() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:demo:greet").unwrap())
            .with_arg("greeting", ArgRef::Inline(b"Hello".to_vec()))
            .with_arg("name", ArgRef::Inline(b"World".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(representation.bytes, b"Hello, World");
    }

    #[test]
    fn page_composes_through_the_linked_module() {
        let kernel = kernel();
        let request = Request::new(Verb::Source, Iri::parse("urn:fn:compose").unwrap())
            .with_arg("src", ArgRef::Inline(b"urn:data:page".to_vec()));
        let representation = block_on(kernel.issue(request, &Capability::root())).unwrap();
        let text = String::from_utf8(representation.bytes).unwrap();
        assert!(text.contains("RESOURCE ORIENTED COMPUTING"));
        assert!(text.contains("[hello]"));
        assert!(text.contains("Hi, World"));
        // the escaped marker survives unexpanded
        assert!(text.contains("$a{urn:fn:toUpper?in=x}"));
    }

    #[test]
    fn file_thread_maps_a_changed_path_to_its_urn() {
        let root = Path::new("/ws");
        assert_eq!(
            file_thread(root, Path::new("/ws/notes.txt")).as_deref(),
            Some("urn:file:notes.txt")
        );
        assert_eq!(
            file_thread(root, Path::new("/ws/docs/a.txt")).as_deref(),
            Some("urn:file:docs/a.txt")
        );
        assert_eq!(file_thread(root, root), None); // the root itself
        assert_eq!(file_thread(root, Path::new("/elsewhere/x")), None);
    }

    #[test]
    fn agent_select_answers_deterministically_without_a_goal() {
        let kernel = kernel();
        // Zero fits is a clean text answer, not an error.
        let request = Request::new(Verb::Source, Iri::parse("urn:agent:select").unwrap())
            .with_arg("types", ArgRef::Inline(b"urn:no:Such".to_vec()));
        let repr = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert!(String::from_utf8(repr.bytes)
            .unwrap()
            .contains("no authorized action fits"));

        // Several fits, no goal: the ranked candidate graph, no LLM involved.
        let request = Request::new(Verb::Source, Iri::parse("urn:agent:select").unwrap());
        let repr = block_on(kernel.issue(request, &Capability::root())).unwrap();
        let ttl = String::from_utf8(repr.bytes).unwrap();
        assert!(repr.repr_type.media_type == "text/turtle");
        assert!(ttl.matches("a ik:ActionMatch").count() > 1, "{ttl}");
        assert!(ttl.contains("give goal= to disambiguate"), "{ttl}");
    }

    #[test]
    fn selection_turtle_distinguishes_no_goal_from_a_failed_residual() {
        let cands = vec![
            SelectCandidate {
                action: "urn:ikigai:endpoint:a:action:source".to_string(),
                endpoint: "urn:a".to_string(),
                verb: "Source".to_string(),
                requires: vec![],
                missing_optional: 0,
            },
            SelectCandidate {
                action: "urn:ikigai:endpoint:b:action:source".to_string(),
                endpoint: "urn:b".to_string(),
                verb: "Source".to_string(),
                requires: vec![],
                missing_optional: 0,
            },
        ];
        // No goal was given: the funnel invites disambiguation.
        let no_goal = selection_turtle(&cands, None, None);
        assert!(no_goal.contains("give goal= to disambiguate"), "{no_goal}");

        // A goal WAS given but the residual failed (e.g. urn:llm:ask denied on
        // localhost): the reason is surfaced in the graph, NOT the misleading
        // "give goal=" — so a capability denial can't masquerade as user error.
        let reason = "goal set, but the residual was unavailable \
                      (capability does not allow reaching localhost) — deterministic ranked list";
        let degraded = selection_turtle(&cands, None, Some(reason));
        assert!(
            !degraded.contains("give goal= to disambiguate"),
            "a failed residual must not read as a missing goal: {degraded}"
        );
        assert!(
            degraded.contains("the residual was unavailable"),
            "{degraded}"
        );
    }

    #[test]
    fn agent_select_carries_the_callers_attenuation() {
        // The funnel through the agent face: a capability without the write
        // scope gets a selection graph that simply lacks the write actions —
        // the attenuation propagates through inv.issue to urn:kernel:actions.
        let kernel = kernel();
        let scoped = Capability::scoped(["urn:cap:personal:calendar:read:freebusy"]);
        let request = Request::new(Verb::Source, Iri::parse("urn:agent:select").unwrap())
            .with_arg("verb", ArgRef::Inline(b"sink".to_vec()));
        let repr = block_on(kernel.issue(request, &scoped)).unwrap();
        let body = String::from_utf8(repr.bytes).unwrap();
        assert!(
            !body.contains("personal-calendar:action:sink"),
            "write actions must not be offered through the agent face either: {body}"
        );
    }

    #[test]
    fn the_watcher_cuts_a_thread_on_an_out_of_band_change() {
        use std::time::Duration;
        let root = std::env::temp_dir().join(format!("ikigai-watch-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("notes.txt"), b"v1").unwrap();

        // A cacheable file space over the temp root, with the watcher behind it.
        let kernel = Arc::new(Kernel::new(Arc::new(ikigai_fs::cacheable_space(&root))));
        watch_root(Arc::clone(&kernel), root.clone());
        std::thread::sleep(Duration::from_millis(400)); // let the watch start
        let cap = Capability::root();
        let source = || Request::new(Verb::Source, Iri::parse("urn:file:notes.txt").unwrap());

        // Cache the read.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v1");
        assert!(
            kernel.is_cached(&source(), &cap),
            "cached after the first read"
        );

        // Change the file OUT OF BAND — not through the kernel.
        std::fs::write(root.join("notes.txt"), b"v2").unwrap();

        // The watcher should cut the thread. Two macOS/fsevents hazards: delivery
        // latency is unbounded under load, and a write landing before the stream
        // is fully established is LOST, not delayed (streams start at
        // kFSEventStreamEventIdSinceNow). So poll with a generous ceiling,
        // early-exiting the moment the thread is cut, and re-touch the file every
        // ~2s — each touch is itself an out-of-band change, so a lost first event
        // doesn't strand the run.
        let mut cut = false;
        for tick in 0..300 {
            if !kernel.is_cached(&source(), &cap) {
                cut = true;
                break;
            }
            if tick % 20 == 19 {
                std::fs::write(root.join("notes.txt"), b"v2").unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            cut,
            "watcher should cut the thread within 30s of an out-of-band change"
        );

        // A fresh read now sees v2.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v2");
        std::fs::remove_dir_all(&root).ok();
    }
}
