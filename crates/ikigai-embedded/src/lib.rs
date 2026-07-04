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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Fallback, FnEndpoint, Invocation,
    Iri, Kernel, MetaRenderer, ReprType, Representation, Request, Resolution, Result, Scope, Space,
    SpaceEntry, SystemClock, Time, UriTemplate, Verb,
};
use ikigai_scheduler::Scheduler;
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
        .bind(Exact::new("urn:demo:greeter"), greeter())
        .bind(Exact::new("urn:time:now"), clock_now())
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

/// One event as the deriver applies it, lifted from the skolemized graph.
#[derive(Clone, Debug, PartialEq)]
struct ViewEvent {
    uid: String,
    title: String,
    start: String,
    end: String,
    all_day: bool,
    location: Option<String>,
    /// Alarms: minutes before start (ik:alert, multi-valued).
    alerts: Vec<u32>,
}

/// Parse a skolemized event graph (Turtle) into events keyed by uid.
fn events_by_uid(turtle: &str) -> std::collections::BTreeMap<String, ViewEvent> {
    const ICAL: &str = "http://www.w3.org/2002/12/cal/ical#";
    const IK: &str = "https://ikigai-rs.dev/ns#";
    let mut props: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
        Default::default();
    let mut alert_map: std::collections::BTreeMap<String, Vec<u32>> = Default::default();
    for quad in
        oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(turtle.as_bytes())
    {
        let Ok(quad) = quad else { continue };
        let oxrdf::NamedOrBlankNode::NamedNode(subject) = &quad.subject else {
            continue;
        };
        let Some(uid) = subject.as_str().strip_prefix("urn:event:") else {
            continue;
        };
        let value = match &quad.object {
            oxrdf::Term::Literal(l) => l.value().to_string(),
            oxrdf::Term::NamedNode(n) => n.as_str().to_string(),
            _ => continue,
        };
        // ik:alert is MULTI-valued — collect separately from the single-valued props.
        if quad.predicate.as_str() == "https://ikigai-rs.dev/ns#alert" {
            if let Ok(minutes) = value.parse::<u32>() {
                alert_map.entry(uid.to_string()).or_default().push(minutes);
            }
            continue;
        }
        props
            .entry(uid.to_string())
            .or_default()
            .insert(quad.predicate.as_str().to_string(), value);
    }
    props
        .into_iter()
        .filter_map(|(uid, p)| {
            let mut alerts = alert_map.get(&uid).cloned().unwrap_or_default();
            alerts.sort_unstable();
            alerts.dedup();
            Some((
                uid.clone(),
                ViewEvent {
                    // the ical:uid literal is authoritative (subjects are IRI-safe
                    // mangled); fall back to the subject-derived uid
                    uid: p.get(&format!("{ICAL}uid")).cloned().unwrap_or(uid),
                    title: p.get(&format!("{ICAL}summary")).cloned()?,
                    start: p.get(&format!("{ICAL}dtstart")).cloned()?,
                    end: p.get(&format!("{ICAL}dtend")).cloned()?,
                    all_day: p
                        .get(&format!("{IK}allDay"))
                        .map(|v| v == "true")
                        .unwrap_or(false),
                    location: p.get(&format!("{ICAL}location")).cloned(),
                    alerts,
                },
            ))
        })
        .collect()
}

/// `urn:view:ingest` — drain the phone-capture inbox (config `inbox`, e.g.
/// Brian-New) into the org system of record: each event becomes an org heading
/// (its iCal UID recorded as `:ID:`, which the org parser prefers — one
/// identity from capture to Brian-Busy), APPENDED through the kernel to the
/// first configured org file, then deleted from the inbox. Append-then-delete
/// + skip-if-ID-present make a crash between the two harmless.
struct IngestEndpoint;

#[async_trait::async_trait]
impl Endpoint for IngestEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let Some(config) = calendar_config() else {
            return Err(Error::Endpoint(
                "urn:view:ingest: no calendar config — see urn:personal:calendar:config"
                    .to_string(),
            ));
        };
        let Some(inbox) = &config.inbox else {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"no inbox configured - nothing to ingest
"
                .to_vec(),
            ));
        };
        let Some((_, files)) = org_config() else {
            return Err(Error::Endpoint(
                "urn:view:ingest: no org_files configured".to_string(),
            ));
        };
        let Some(target) = files.first() else {
            return Err(Error::Endpoint(
                "urn:view:ingest: org_files is empty".to_string(),
            ));
        };

        // The inbox's events (the rolling window), as the graph everything speaks.
        let captured = inv
            .issue(
                Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                        .expect("valid IRI"),
                )
                .with_arg(
                    "calendar",
                    ikigai_core::ArgRef::Inline(inbox.as_bytes().to_vec()),
                )
                .with_arg("as", ikigai_core::ArgRef::Inline(b"text/turtle".to_vec())),
            )
            .await?;
        let events = events_by_uid(&String::from_utf8_lossy(&captured.bytes));
        if events.is_empty() {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                format!(
                    "{inbox}: empty - nothing to ingest
"
                )
                .into_bytes(),
            ));
        }

        // Read the target org file through the kernel (same jailed space the
        // agenda reads), append a heading per event, write it back, THEN drain.
        let target_iri = Iri::parse(target.as_str())
            .map_err(|e| Error::Endpoint(format!("urn:view:ingest: bad org IRI: {e}")))?;
        let current = inv.source(&target_iri).await?;
        let mut org = String::from_utf8_lossy(&current.bytes).to_string();

        let mut ingested = 0usize;
        let mut drained = 0usize;
        for event in events.values() {
            // Idempotency: an ID already in the file was ingested by an earlier
            // (possibly crashed) pass — just drain the inbox copy.
            if !org.contains(&format!(":ID: {}", event.uid)) {
                org.push_str(&org_heading(event));
                ingested += 1;
            }
        }
        if ingested > 0 {
            inv.issue(
                Request::new(Verb::Sink, target_iri.clone())
                    .with_arg("content", ikigai_core::ArgRef::Inline(org.into_bytes())),
            )
            .await?;
        }
        // Only after the org write landed: drain the inbox.
        for event in events.values() {
            let request = Request::new(
                Verb::Delete,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg(
                "calendar",
                ikigai_core::ArgRef::Inline(inbox.as_bytes().to_vec()),
            )
            .with_arg(
                "uid",
                ikigai_core::ArgRef::Inline(event.uid.as_bytes().to_vec()),
            )
            .with_arg(
                "start",
                ikigai_core::ArgRef::Inline(event.start.as_bytes().to_vec()),
            );
            inv.issue(request).await?;
            drained += 1;
        }
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!(
                "{inbox}: ingested {ingested} into {target} · drained {drained}
"
            )
            .into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "view-ingest"
    }

    fn describe(&self) -> Description {
        Description::new("view-ingest")
            .title("Ingest the capture inbox")
            .summary(
                "Drain the phone-capture inbox calendar into the org system of record:                  each event becomes an org heading (:ID: = its iCal UID, one identity                  from capture to the consolidated view), appended through the kernel,                  then removed from the inbox. Idempotent; derive runs it first.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8")
    }
}

/// One captured event as an org heading: title, a `:PROPERTIES:` drawer carrying
/// the identity, and an active timestamp the agenda parser round-trips.
fn org_heading(event: &ViewEvent) -> String {
    let stamp = org_stamp(event);
    let alert = if event.alerts.is_empty() {
        String::new()
    } else {
        let tokens: Vec<String> = event.alerts.iter().map(|m| alert_token(*m)).collect();
        format!("  :ALERT: {}\n", tokens.join(" "))
    };
    format!(
        "\n* {}\n  :PROPERTIES:\n  :ID: {}\n  :END:\n{alert}  {stamp}\n",
        event.title, event.uid
    )
}

fn org_stamp(event: &ViewEvent) -> String {
    let date = event
        .start
        .split_once('T')
        .map(|(d, _)| d)
        .unwrap_or(&event.start);
    let day = date
        .parse::<chrono::NaiveDate>()
        .map(|d| d.format("%a").to_string())
        .unwrap_or_default();
    if event.all_day {
        return format!("<{date} {day}>");
    }
    let hhmm = |s: &str| {
        s.split_once('T')
            .map(|(_, t)| t[..5.min(t.len())].to_string())
            .unwrap_or_default()
    };
    format!("<{date} {day} {}-{}>", hhmm(&event.start), hhmm(&event.end))
}

/// The derivation window: a rolling `today-7d..today+400d` range rather than
/// the calendar year, so a late-December derive still carries January into the
/// view, and a week of just-past events survives for the diff to leave alone.
fn derive_window() -> String {
    let today = chrono::Local::now().date_naive();
    format!(
        "{}..{}",
        today - chrono::Duration::days(7),
        today + chrono::Duration::days(400)
    )
}

/// Minutes-before-start as the friendly token both the org `:ALERT:` parser
/// and the calendar `alert=` argument accept.
fn alert_token(minutes: u32) -> String {
    if minutes > 0 && minutes.is_multiple_of(1440) {
        format!("{}d", minutes / 1440)
    } else if minutes > 0 && minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// The per-source detail projection from calendar.json: `"project":
/// {"Bosatsu": "busy"}` renders that source's events into the view as
/// `Busy (Bosatsu)` with the location withheld — the freebusy capability idea
/// applied at derivation time. UIDs are untouched, so flipping a source's mode
/// UPDATES its events in place (the diff sees changed titles, not new events).
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

/// Apply a source's projection mode to its event graph (Turtle in, Turtle out).
/// `busy`: titles become "Busy (<source>)", locations and alarms are withheld.
/// Anything
/// (or no mode) passes through untouched.
fn project_source(turtle: String, source: &str, mode: Option<&str>) -> String {
    if mode != Some("busy") {
        return turtle;
    }
    let events = events_by_uid(&turtle);
    let mut out = String::from(
        "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         @prefix ik: <https://ikigai-rs.dev/ns#> .\n",
    );
    for event in events.values() {
        let mut props = vec![
            "a ical:Vevent".to_string(),
            format!("ical:uid {}", view_ttl_str(&event.uid)),
            format!("ical:summary {}", view_ttl_str(&format!("Busy ({source})"))),
            format!("ical:dtstart {}", view_ttl_str(&event.start)),
            format!("ical:dtend {}", view_ttl_str(&event.end)),
            format!("ik:calendar {}", view_ttl_str(source)),
        ];
        if event.all_day {
            props.push("ik:allDay true".to_string());
        }
        out.push_str(&format!(
            "\n<urn:event:{}> {} .\n",
            event.uid.replace(['<', '>', ' '], "-"),
            props.join(" ;\n    ")
        ));
    }
    out
}

fn view_ttl_str(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('\"', "\\\"")
            .replace('\n', " ")
    )
}

/// `urn:view:derive` — one materialization pass of the consolidated view (the
/// Brian-Busy plan's P4): desired = org agenda ∪ the allowlisted source
/// calendars (this year); current = the view calendar; the delta comes from
/// `urn:rdf:diff` THROUGH the kernel; apply = Delete the gone/changed, Sink the
/// new/changed (identity carried as urn:event:{uid} — the round-trip that makes
/// this idempotent). Drive it on a timer: `source urn:time:schedule
/// target=urn:view:derive every=300s`.
struct DeriveEndpoint;

#[async_trait::async_trait]
impl Endpoint for DeriveEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let Some(config) = calendar_config() else {
            return Err(Error::Endpoint(
                "urn:view:derive: no calendar config — see urn:personal:calendar:config"
                    .to_string(),
            ));
        };
        // Drain the capture inbox into org FIRST, so a phone capture reaches the
        // consolidated view in the same pass. Failure here must not block the
        // derivation (the inbox may be mid-sync); it reports on the next tick.
        let _ = inv
            .issue(Request::new(
                Verb::Source,
                Iri::parse("urn:view:ingest").expect("valid IRI"),
            ))
            .await;

        let turtle_of = |mut request: Request| {
            request = request.with_arg("as", ikigai_core::ArgRef::Inline(b"text/turtle".to_vec()));
            request
        };

        // DESIRED: the org agenda plus each allowlisted source calendar, over
        // the rolling window. Concatenated Turtle is legal (re-declared
        // prefixes are fine); the diff parses it with set semantics.
        let mut desired = String::new();
        if org_config()
            .map(|(_, files)| !files.is_empty())
            .unwrap_or(false)
        {
            let org = inv
                .issue(turtle_of(Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:org:agenda:{}", derive_window())).expect("valid IRI"),
                )))
                .await?;
            desired.push_str(&String::from_utf8_lossy(&org.bytes));
        }
        let projections = projection_config();
        for source in &config.sources {
            let part = inv
                .issue(
                    turtle_of(Request::new(
                        Verb::Source,
                        Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                            .expect("valid IRI"),
                    ))
                    .with_arg(
                        "calendar",
                        ikigai_core::ArgRef::Inline(source.as_bytes().to_vec()),
                    ),
                )
                .await?;
            desired.push_str(&project_source(
                String::from_utf8_lossy(&part.bytes).to_string(),
                source,
                projections.get(source).map(String::as_str),
            ));
        }

        // CURRENT: what the view calendar holds now.
        let current = inv
            .issue(
                turtle_of(Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                        .expect("valid IRI"),
                ))
                .with_arg(
                    "calendar",
                    ikigai_core::ArgRef::Inline(config.view.as_bytes().to_vec()),
                ),
            )
            .await?;
        let current = String::from_utf8_lossy(&current.bytes).to_string();

        // THE DELTA — urn:rdf:diff through the kernel, both directions.
        let diff = |mode: &'static str, a: String, b: String| {
            Request::new(Verb::Source, Iri::parse("urn:rdf:diff").expect("valid IRI"))
                .with_arg("content", ikigai_core::ArgRef::Inline(a.into_bytes()))
                .with_arg("with", ikigai_core::ArgRef::Inline(b.into_bytes()))
                .with_arg(
                    "mode",
                    ikigai_core::ArgRef::Inline(mode.as_bytes().to_vec()),
                )
        };
        let added = inv
            .issue(diff("added", desired.clone(), current.clone()))
            .await?;
        let removed = inv
            .issue(diff("removed", desired.clone(), current.clone()))
            .await?;

        // Subjects in `removed` = gone or changed -> Delete (data from CURRENT).
        // Subjects in `added` = new or changed -> Sink (data from DESIRED).
        // A changed event is in both: delete first, recreate after = an update.
        let desired_events = events_by_uid(&desired);
        let current_events = events_by_uid(&current);
        let to_delete: Vec<&ViewEvent> = events_by_uid(&String::from_utf8_lossy(&removed.bytes))
            .keys()
            .filter_map(|uid| current_events.get(uid))
            .collect();
        let to_create: Vec<&ViewEvent> = events_by_uid(&String::from_utf8_lossy(&added.bytes))
            .keys()
            .filter_map(|uid| desired_events.get(uid))
            .collect();

        let mut deleted = 0usize;
        for event in &to_delete {
            let request = Request::new(
                Verb::Delete,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg(
                "calendar",
                ikigai_core::ArgRef::Inline(config.view.as_bytes().to_vec()),
            )
            .with_arg(
                "uid",
                ikigai_core::ArgRef::Inline(event.uid.as_bytes().to_vec()),
            )
            .with_arg(
                "start",
                ikigai_core::ArgRef::Inline(event.start.as_bytes().to_vec()),
            );
            inv.issue(request).await?;
            deleted += 1;
        }
        let mut created = 0usize;
        for event in &to_create {
            let mut request = Request::new(
                Verb::Sink,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg(
                "calendar",
                ikigai_core::ArgRef::Inline(config.view.as_bytes().to_vec()),
            )
            .with_arg(
                "title",
                ikigai_core::ArgRef::Inline(event.title.as_bytes().to_vec()),
            )
            .with_arg(
                "start",
                ikigai_core::ArgRef::Inline(event.start.as_bytes().to_vec()),
            )
            .with_arg(
                "end",
                ikigai_core::ArgRef::Inline(event.end.as_bytes().to_vec()),
            )
            .with_arg(
                "uid",
                ikigai_core::ArgRef::Inline(event.uid.as_bytes().to_vec()),
            );
            if event.all_day {
                request =
                    request.with_arg("all_day", ikigai_core::ArgRef::Inline(b"true".to_vec()));
            }
            if let Some(location) = &event.location {
                request = request.with_arg(
                    "location",
                    ikigai_core::ArgRef::Inline(location.as_bytes().to_vec()),
                );
            }
            if !event.alerts.is_empty() {
                let minutes: Vec<String> = event.alerts.iter().map(u32::to_string).collect();
                request = request.with_arg(
                    "alert",
                    ikigai_core::ArgRef::Inline(minutes.join(",").into_bytes()),
                );
            }
            inv.issue(request).await?;
            created += 1;
        }

        let unchanged = current_events.len().saturating_sub(deleted);
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!(
                "{}: created {created} · removed {deleted} · unchanged {unchanged}
",
                config.view
            )
            .into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "view-derive"
    }

    fn describe(&self) -> Description {
        Description::new("view-derive")
            .title("Derive the consolidated view")
            .summary(
                "One materialization pass: desired (org agenda ∪ the configured source                  calendars, over a rolling today-7d..+400d window) minus current (the view calendar) via urn:rdf:diff —                  gone/changed events deleted, new/changed created, identity carried as                  urn:event:{uid} so the pass is idempotent. Drive it on a timer.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
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
            ikigai_personal::calendar(),
        )
        .bind(
            Exact::new("urn:personal:availability"),
            ikigai_personal::availability(),
        )
        .bind(
            Exact::new("urn:personal:calendars"),
            ikigai_personal::calendars(calendar_config()),
        )
        .bind(
            Exact::new("urn:personal:calendar:config"),
            ikigai_personal::calendar_config(calendar_config()),
        )
        .bind(Exact::new("urn:view:derive"), DeriveEndpoint)
        .bind(Exact::new("urn:view:ingest"), IngestEndpoint)
        // AFTER the exact binds: the period grammar must not shadow
        // urn:personal:calendar:config (first grammar match wins).
        .bind(
            UriTemplate::parse("urn:personal:calendar:{period}").expect("valid template"),
            ikigai_personal::calendar(),
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
    base_space(nature).bind(
        UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).expect("FILE_TEMPLATE is valid"),
        ikigai_fs::FileEndpoint::new(file_root()).cacheable(),
    )
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
        let mut req = ureq::request(request.method.as_str(), &request.url);
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

/// The declared registry: the `IKIGAI_LLM_CONFIG` file, else the Ollama default.
fn llm_declared_registry() -> ikigai_llm::Registry {
    if let Ok(path) = std::env::var("IKIGAI_LLM_CONFIG") {
        match std::fs::read_to_string(&path) {
            Ok(json) => match ikigai_llm::Registry::from_json(&json) {
                Ok(registry) => return registry,
                Err(e) => eprintln!(
                    "ikigai: IKIGAI_LLM_CONFIG ({path}) parse error: {e:?} — using the default"
                ),
            },
            Err(e) => eprintln!(
                "ikigai: cannot read IKIGAI_LLM_CONFIG ({path}): {e:?} — using the default"
            ),
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
/// `urn:llm:ollama:installed` and forks to the first two distinct models (two
/// personas of one model when only one is pulled), so the demo is portable: no
/// hardcoded model name. If the list can't be read the markers carry no
/// `model=` and the backend's own default-resolution (and the gated
/// conditional's offline note) take over.
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
    Arc::new(Fallback::new(vec![
        Arc::new(local_space("Embedded (Native)")) as Arc<dyn Space>,
        Arc::new(http_space()) as Arc<dyn Space>,
        Arc::new(llm_space()) as Arc<dyn Space>,
        // The org agenda (urn:org:agenda[:{period}]) over the configured org
        // files, which it reads through the kernel via urn:orgfile:*.
        Arc::new(ikigai_org::space(
            org_config().map(|(_, files)| files).unwrap_or_default(),
        )) as Arc<dyn Space>,
        // The Linked Data toolkit: RDF transreption (urn:rdf:*) + SPARQL (urn:sparql:*)
        // + XSLT styling (urn:xslt:*). Linked natively — no module-loading machinery in
        // the native binary (that's a browser/WASI concern).
        Arc::new(ikigai_rdf::space()) as Arc<dyn Space>,
        Arc::new(ikigai_sparql::space()) as Arc<dyn Space>,
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
    ]))
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
    // Inject the process scheduler so re-entrant fan-out (e.g. `compose`'s `$a{}`
    // markers) runs concurrently on it; single-threaded by default, a pool under
    // `IKIGAI_SCHEDULER=pool[:N]`. The same scheduler is injected as a read-only
    // reporter so `urn:kernel:scheduler` surfaces its live state intrinsically. The
    // runbook is mounted but gated by `demo_flag()` (off by default).
    let sched = Arc::new(scheduler());
    let kernel = Kernel::with_meta_renderer(root_space(), Arc::new(CliRenderer))
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
            "urn:view:derive".to_string(),
            Verb::Source,
            ikigai_time::Schedule::Every(every),
            true,
        );
    }
    kernel
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
                    "ikigai: org change → {}",
                    String::from_utf8_lossy(&report.bytes).trim()
                ),
                Err(e) => eprintln!("ikigai: org change → derive failed: {e}"),
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
            eprintln!("ikigai: calendar store watcher could not attach");
            return;
        }
        eprintln!("ikigai: calendar store watcher active ({watching} location(s))");
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
                    "ikigai: calendar change → {}",
                    String::from_utf8_lossy(&report.bytes).trim()
                ),
                Err(e) => eprintln!("ikigai: calendar change → derive failed: {e}"),
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
    Kernel::with_meta_renderer(Arc::new(local_space(nature)), Arc::new(CliRenderer))
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
    fn alerts_round_trip_from_graph_to_org_heading() {
        // Multi-valued ik:alert on one subject → sorted/deduped minutes on the
        // ViewEvent → a friendly `:ALERT:` line in the captured org heading.
        let turtle = r#"@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:event:abc> a ical:Vevent ;
    ical:uid "abc" ;
    ical:summary "Dentist" ;
    ical:dtstart "2026-07-10T09:00:00" ;
    ical:dtend "2026-07-10T10:00:00" ;
    ik:alert 1440 ;
    ik:alert 60 ;
    ik:alert 60 .
"#;
        let events = events_by_uid(turtle);
        let event = events.get("abc").expect("event parsed");
        assert_eq!(event.alerts, vec![60, 1440], "sorted and deduped");

        let heading = org_heading(event);
        assert!(heading.contains(":ID: abc"));
        assert!(
            heading.contains(":ALERT: 1h 1d"),
            "friendly tokens, not raw minutes: {heading}"
        );

        assert_eq!(alert_token(30), "30m");
        assert_eq!(alert_token(90), "90m", "not a whole hour → minutes");
        assert_eq!(alert_token(2880), "2d");
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

        // The watcher should cut the thread (filesystem-event latency: poll).
        let mut cut = false;
        for _ in 0..60 {
            if !kernel.is_cached(&source(), &cap) {
                cut = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            cut,
            "watcher should cut the thread within ~6s of the change"
        );

        // A fresh read now sees v2.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v2");
        std::fs::remove_dir_all(&root).ok();
    }
}
