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
    Description, EndpointSpace, Error, Exact, Fallback, FnEndpoint, Invocation, Kernel,
    MetaRenderer, ReprType, Representation, Request, Resolution, Result, Scope, Space, SpaceEntry,
    SystemClock, UriTemplate, Verb,
};
use ikigai_scheduler::Scheduler;
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

fn base_space(nature: &'static str) -> EndpointSpace {
    ikigai_fn::space()
        .bind(Exact::new("urn:data:page"), page())
        .bind(Exact::new("urn:data:about"), about())
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
        // The Linked Data toolkit: RDF transreption (urn:rdf:*) + SPARQL (urn:sparql:*)
        // + XSLT styling (urn:xslt:*). Linked natively — no module-loading machinery in
        // the native binary (that's a browser/WASI concern).
        Arc::new(ikigai_rdf::space()) as Arc<dyn Space>,
        Arc::new(ikigai_sparql::space()) as Arc<dyn Space>,
        Arc::new(ikigai_xslt::space()) as Arc<dyn Space>,
        // JSON-LD operators (urn:jsonld:expand/compact/flatten) — linked natively (the heavy
        // json-ld tree is a browser-wasm concern, lazy-loaded there; native links it).
        Arc::new(ikigai_jsonld::space()) as Arc<dyn Space>,
        // Content sniffing + sniff-and-dispatch: `urn:sniff` classifies opaque bytes,
        // `urn:transrept:auto` sniffs then routes them to the matching transreptor — so a
        // mislabeled fetch or a file read transrepts without asserting its input type.
        Arc::new(ikigai_sniff::space()) as Arc<dyn Space>,
        // The ikigai vocabulary as a resolvable resource (urn:ikigai:vocab): the ns#
        // ontology Turtle (ik:Transreptor rdfs:subClassOf ik:Endpoint + property defs),
        // the same bytes served at https://ikigai-rs.dev/ns. Lists in the catalog.
        Arc::new(ikigai_vocab::space()) as Arc<dyn Space>,
        Arc::new(Gated {
            inner: ikigai_runbook::space(),
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
    kernel
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
