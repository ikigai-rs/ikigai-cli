//! The seam between the REPL engine and a kernel — local or, later, remote.
//!
//! The engine drives a [`Resolver`] rather than a concrete [`Kernel`], so the
//! same engine resolves against an in-process kernel today and an IPC- or
//! QUIC-attached one tomorrow. [`Resolver`] is synchronous: the REPL runs a
//! blocking loop, so the local implementation hides `block_on` and a wire
//! implementation hides its socket round-trip behind the same surface.
//!
//! The trait is deliberately small — exactly what the engine needs: issue a
//! request, ask whether one is cached, and list the bound resources. Issue
//! reports the [`CacheStatus`] the resolution had, which a remote server knows
//! directly (no client-side cache probing across the wire). The wire protocol
//! that remote resolvers speak lives in the companion `ikigai-wire` crate.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Bindings, Capability, Description, Endpoint, Error, Expiry, Grammar, Invocation, Iri,
    Kernel, Provenance, Representation, Request, Resolution, Resolved, Scope, Space, SpaceEntry,
    TraceEvent, Tracer, UriTemplate, Verb,
};
use serde::{Deserialize, Serialize};

/// How a resolution was served by the representation cache.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CacheStatus {
    /// Served from cache without recomputing.
    Hit,
    /// Computed now, and the result was cached for next time.
    Miss,
    /// Computed now; the result is not cacheable, so it recomputes every time.
    Uncacheable,
}

/// Collects the [`TraceEvent`]s recorded during one traced resolution. A server
/// installs it on its kernel ([`Kernel::set_tracer`](ikigai_core::Kernel::set_tracer)),
/// resolves a traced call, and [`take`](SpanCollector::take)s the events to ship
/// back over the wire; the client forwards them to the tracer the `trace` command
/// installed. Shared by the IPC and QUIC transports.
#[derive(Default)]
pub struct SpanCollector(Mutex<Vec<TraceEvent>>);

impl Tracer for SpanCollector {
    fn record(&self, event: TraceEvent) {
        self.0.lock().expect("span collector").push(event);
    }
}

impl SpanCollector {
    /// Drain the events collected so far.
    pub fn take(&self) -> Vec<TraceEvent> {
        std::mem::take(&mut self.0.lock().expect("span collector"))
    }
}

/// The **capability-scoped** catalog: one [`SpaceEntry`] per endpoint that has at
/// least one action the `capability` may invoke. This is the *affordance =
/// authorization* view — the same [`Capability::allows`](ikigai_core::Capability)
/// filter the manifold (`urn:kernel:actions`) and MCP's `tools/list` apply — so a
/// scoped principal enumerating a server **over the wire** sees only what it could
/// actually call, never the full catalog. A server whose principal is root gets
/// everything. Fixes the leak where the wire `entries` bypassed capability while
/// invocation was clamped.
pub fn scoped_entries(kernel: &Kernel, capability: &Capability) -> Vec<SpaceEntry> {
    let query = ikigai_core::ActionQuery {
        capability: Some(capability),
        ..Default::default()
    };
    // Provenance comes from the space's own enumeration: `select_actions` walks the
    // same entries but an `ActionMatch` carries no origin, so a mounted binding
    // rebuilt from it alone would list indistinguishable from a local one — a
    // federated client could no longer see WHERE `urn:py:*` resolves.
    let origins: std::collections::HashMap<String, String> = kernel
        .entries()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| e.origin.map(|origin| (e.pattern, origin)))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    kernel
        .select_actions(&query)
        .into_iter()
        .filter(|m| seen.insert(m.endpoint.clone()))
        .map(|m| {
            let entry = SpaceEntry::new(&m.endpoint, m.id);
            match origins.get(&m.endpoint) {
                Some(origin) => entry.with_origin(origin),
                None => entry,
            }
        })
        .collect()
}

/// Maps an outgoing target to the *remote* endpoint's declared name, from the
/// last-enumerated remote catalog.
///
/// The name matters to exactly one caller: the kernel's `entries → Meta → describe`
/// walk probe-expands a template entry (`urn:file:{path}` → `urn:file:probe`) and
/// keeps the hit only if the resolved endpoint's name matches the entry's — the
/// shadow guard ("better invisible than misdescribed"). A forwarding endpoint
/// flatly named `"remote"` failed that guard for EVERY remote template entry, so
/// mounted template actions vanished from the local catalog, manifold, and MCP
/// projection while exact remote entries projected fine.
///
/// The cache fills from `entries()` — every catalog/manifold walk enumerates
/// before it probes — and is only ever *read* on the resolve path, so resolution
/// never pays a wire round-trip for a name. An unmatched or never-enumerated
/// target falls back to `"remote"`, which restores the old behavior (and the old
/// invisibility) rather than guessing.
struct RemoteNames {
    rows: Mutex<Vec<NameRow>>,
}

/// One remote catalog row, pre-parsed for matching and pre-scored for
/// specificity — parsing on the resolve path would be paid per resolution.
struct NameRow {
    /// The row's pattern. An exact IRI parses as a template with no variables,
    /// so one matcher covers both: its literals must equal the whole target.
    pattern: UriTemplate,
    /// The remote's declared endpoint name for that pattern.
    endpoint: String,
    /// How specifically the pattern pins an IRI — see [`literal_len`].
    specificity: usize,
}

impl RemoteNames {
    fn new() -> Self {
        RemoteNames {
            rows: Mutex::new(Vec::new()),
        }
    }

    /// Rebuild from the remote's just-fetched catalog. Entries keep the remote's
    /// own namespace (pre-aliasing): the lookup happens on the *forwarded* target,
    /// which is in that namespace in every mount mode. Unparseable patterns
    /// (display sugar like `urn:x[:{y}]`) are skipped — they can't match a probe
    /// IRI anyway.
    fn refresh(&self, entries: &[SpaceEntry]) {
        let rows = entries
            .iter()
            .filter_map(|entry| {
                let pattern = UriTemplate::parse(&entry.pattern).ok()?;
                Some(NameRow {
                    specificity: literal_len(&pattern),
                    pattern,
                    endpoint: entry.endpoint.clone(),
                })
            })
            .collect();
        *self.rows.lock().expect("remote names") = rows;
    }

    /// The remote endpoint name `target` would land on: the MOST SPECIFIC matching
    /// catalog row (see [`literal_len`]), ties broken by catalog order.
    ///
    /// Deliberately *not* first-match-wins, even though the remote's own resolution
    /// is. What crosses the wire are pattern STRINGS, and grammar semantics do not
    /// survive that trip: ikigai-browse's PR row binds `urn:repo:{repo}:pr:{n}` and
    /// then REJECTS an `n` containing a `:` — Rust logic no pattern string can
    /// express — so replaying the strings in catalog order let the shorter row
    /// swallow `…:pr:{n}:explain` and `…:pr:{n}:review` and label them `browse-pr`.
    /// Most-specific-wins is still a heuristic, but a well-founded one: a nested
    /// route is spelled by ADDING literals to its parent's pattern, so the row with
    /// more literals is the one the remote meant. It stays a guess until the wire
    /// carries the resolved name itself — the shapes that would, and which consumer
    /// each one serves, are written up in `docs/resolved-name-on-the-wire-design.md`.
    fn name_for(&self, target: &Iri) -> Option<String> {
        let rows = self.rows.lock().ok()?;
        let mut best: Option<&NameRow> = None;
        for row in rows.iter() {
            if row.pattern.match_iri(target).is_none() {
                continue;
            }
            // Strictly greater, so an equally specific row LATER in the catalog
            // does not displace the earlier one (first-wins on a true tie).
            if best.is_none_or(|top| row.specificity > top.specificity) {
                best = Some(row);
            }
        }
        best.map(|row| row.endpoint.clone())
    }
}

/// How specifically a pattern pins an IRI: the count of LITERAL (non-variable)
/// characters in it. A `{var}` matches an unbounded run, so it contributes
/// nothing; everything the pattern actually spells out counts. An exact IRI
/// therefore scores its own length, which no template matching the same string
/// can reach (a template's captures are non-empty), so exact rows outrank
/// template rows for free.
fn literal_len(pattern: &UriTemplate) -> usize {
    // `variables()` yields every occurrence in order, so a repeated variable is
    // subtracted once per appearance — `{var}` costs its name plus both braces.
    pattern.source().len() - pattern.variables().map(|var| var.len() + 2).sum::<usize>()
}

/// The catalog row that names `target`: the most specific matching pattern, ties
/// broken by catalog order — the same rule [`RemoteNames`] applies to a mount's
/// forwarded targets, over a plain slice of entries.
///
/// This is what a *renderer* wants (the REPL's `trace` labels each span's target
/// with the endpoint that served it), and the reason it can't just take the first
/// matching row is the same one: nested routes. `urn:repo:{repo}:pr:{n}` matches
/// `urn:repo:x:pr:12:explain` too, so a first-match (or, worse, a match on the
/// literal prefix before the first `{`) names the parent route for every child.
///
/// `None` when nothing matches, and for patterns that are neither IRIs nor
/// parseable templates — a caller with a looser fallback can still apply it.
pub fn naming_entry<'a>(entries: &'a [SpaceEntry], target: &Iri) -> Option<&'a SpaceEntry> {
    let mut best: Option<(usize, &SpaceEntry)> = None;
    for entry in entries {
        let Ok(pattern) = UriTemplate::parse(&entry.pattern) else {
            continue;
        };
        if pattern.match_iri(target).is_none() {
            continue;
        }
        let specificity = literal_len(&pattern);
        if best.is_none_or(|(top, _)| specificity > top) {
            best = Some((specificity, entry));
        }
    }
    best.map(|(_, entry)| entry)
}

/// A [`Space`] that resolves every request under its mount into a *remote* kernel:
/// it wraps a [`Resolver`] (an IPC or QUIC client) and, on resolve, yields a
/// forwarding endpoint that round-trips the request over the wire on invoke. This
/// is what lets a *local* kernel compose a remote one — mount it behind a prefix
/// ([`Mount`](ikigai_core::Mount)) so only that namespace goes remote. It always
/// hits (routing is the mount prefix's job); a genuinely-absent remote resource
/// comes back as an error on invoke, not a resolution miss.
pub struct RemoteSpace {
    resolver: Arc<dyn Resolver>,
    names: RemoteNames,
}

impl RemoteSpace {
    /// Wrap a connected [`Resolver`] as a mountable space.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        RemoteSpace {
            resolver,
            names: RemoteNames::new(),
        }
    }
}

impl Space for RemoteSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        // Capture the whole request (target + verb + args) so the endpoint forwards
        // it verbatim; the caller's capability arrives via the Invocation on invoke.
        Resolution::Hit(Resolved {
            endpoint: Arc::new(ForwardingEndpoint {
                resolver: Arc::clone(&self.resolver),
                name: self.names.name_for(&request.target),
                request: request.clone(),
            }),
            bindings: Bindings::new(),
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // Forward the remote's catalog (a round-trip — off the hot path), keeping
        // the name map current so template probes resolve under the real names.
        let entries = self.resolver.entries()?;
        self.names.refresh(&entries);
        Some(entries)
    }
}

/// The endpoint a [`RemoteSpace`] resolves to: on invoke, forward the captured
/// request to the remote kernel under the invocation's capability (which the
/// server clamps to its authenticated principal).
struct ForwardingEndpoint {
    resolver: Arc<dyn Resolver>,
    request: Request,
    /// The remote endpoint's declared name for this target, when the mount's
    /// last-enumerated catalog names it (see [`RemoteNames`]) — the kernel's
    /// template-probe guard compares this against the catalog entry, so it must
    /// be the REMOTE's name, not a transport label. `None` falls back to
    /// `"remote"`.
    name: Option<String>,
}

#[async_trait]
impl Endpoint for ForwardingEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation, Error> {
        // Off the trace path: a plain forward. The resolver already yields a typed
        // Error, so a hung/unreachable remote surfaces as transient — a Retry or
        // Failover above this mount can act on it, not a blanket permanent failure.
        if inv.trace_span().is_none() {
            return self
                .resolver
                .issue_as(self.request.clone(), inv.capability)
                .map(|(representation, _status)| representation);
        }
        // The local kernel is recording: trace the forward too — install a collector
        // on the resolver so the round-trip goes as a traced call — then hand the
        // returned remote subtree to the local trace, which re-bases it under this
        // mount node (`inv.record_subtree`). So the remote execution shows stitched
        // into the tree instead of collapsed to one node.
        let collector = Arc::new(SpanCollector::default());
        self.resolver.set_tracer(collector.clone());
        let result = self.resolver.issue_as(self.request.clone(), inv.capability);
        self.resolver.clear_tracer();
        let (representation, _status) = result?;
        inv.record_subtree(collector.take());
        Ok(representation)
    }

    fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("remote")
    }

    fn describe(&self) -> Description {
        // Forward a Meta request (JSON face) so the engine can route named args by
        // the *remote* endpoint's own contract — otherwise `compose src=…` over a
        // mount loses its `src`. Best-effort: a bare description on any error.
        let meta = Request::new(Verb::Meta, self.request.target.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
        self.resolver
            .issue_as(meta, &Capability::root())
            .ok()
            .and_then(|(repr, _status)| serde_json::from_slice(&repr.bytes).ok())
            .unwrap_or_else(|| Description::new("remote"))
    }
}

/// A **prefix-mounted** remote kernel: requests under `prefix` are rewritten
/// (`<prefix>rest` → `urn:rest`) and forwarded, and the remote's catalog is
/// surfaced back **re-prefixed** (`urn:rest` → `<prefix>rest`) and tagged with
/// `origin` — so a federated `list` shows *where* each mounted resource resolves,
/// and a trace can name the mount node instead of rendering `?`. This is what
/// `Mount` + `Rewrite` + [`RemoteSpace`] did, combined into one space so that
/// entries actually flow (a `Rewrite` can't enumerate) and carry provenance.
pub struct MountedRemote {
    resolver: Arc<dyn Resolver>,
    prefix: String,
    origin: String,
    mode: MountMode,
    names: RemoteNames,
}

/// How a mount relates the local namespace to the remote one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountMode {
    /// **Alias** — `<prefix>rest` is rewritten to `urn:rest` before forwarding, and
    /// the remote's catalog comes back re-prefixed. The prefix is a LOCAL NAME for a
    /// remote namespace, so it must not collide with anything served locally (a
    /// local binding would win, and the mount would silently never be used).
    Alias,
    /// **Override** — the IRI is forwarded UNCHANGED, and the mount is composed
    /// BEFORE the local spaces, so the namespace genuinely resolves on the remote
    /// even when the local kernel binds it too. This is what makes
    /// `--override urn:llm:=quic://peer` mean "my LLM lives over there" with no
    /// alias and no rewriting at the call site.
    Override,
}

impl MountedRemote {
    /// Mount `resolver` at `prefix` as an ALIAS (see [`MountMode::Alias`]),
    /// labelling its bindings `origin` in the catalog.
    pub fn new(
        resolver: Arc<dyn Resolver>,
        prefix: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        MountedRemote {
            resolver,
            prefix: prefix.into(),
            origin: origin.into(),
            mode: MountMode::Alias,
            names: RemoteNames::new(),
        }
    }

    /// Mount `resolver` at `prefix` as an OVERRIDE (see [`MountMode::Override`]):
    /// IRIs forwarded unchanged. The caller is responsible for composing this
    /// BEFORE the local spaces — precedence is the other half of the semantics.
    pub fn overriding(
        resolver: Arc<dyn Resolver>,
        prefix: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        MountedRemote {
            resolver,
            prefix: prefix.into(),
            origin: origin.into(),
            mode: MountMode::Override,
            names: RemoteNames::new(),
        }
    }
}

impl Space for MountedRemote {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        // Only our namespace.
        let Some(rest) = request.target.as_str().strip_prefix(&self.prefix) else {
            return Resolution::Miss;
        };
        let mut forwarded = request.clone();
        if self.mode == MountMode::Alias {
            // The prefix is a local ALIAS: strip it (→ `urn:`) before forwarding.
            let Ok(target) = ikigai_core::Iri::parse(format!("urn:{rest}")) else {
                return Resolution::Miss;
            };
            forwarded.target = target;
        }
        // An OVERRIDE forwards the IRI verbatim — the remote serves this very
        // namespace, so there is nothing to rewrite. The name lookup happens on
        // the FORWARDED target, which is in the remote's namespace either way.
        Resolution::Hit(Resolved {
            endpoint: Arc::new(ForwardingEndpoint {
                resolver: Arc::clone(&self.resolver),
                name: self.names.name_for(&forwarded.target),
                request: forwarded,
            }),
            bindings: Bindings::new(),
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        let entries = self.resolver.entries()?;
        // Keep the name map current so template probes resolve under real names.
        self.names.refresh(&entries);
        match self.mode {
            // Surface the remote's catalog under the alias, tagged with its origin.
            MountMode::Alias => Some(
                entries
                    .into_iter()
                    .map(|entry| {
                        let pattern = entry
                            .pattern
                            .strip_prefix("urn:")
                            .map(|rest| format!("{}{rest}", self.prefix))
                            .unwrap_or(entry.pattern);
                        SpaceEntry::new(pattern, entry.endpoint).with_origin(&self.origin)
                    })
                    .collect(),
            ),
            // An override claims exactly its namespace: surface the remote's
            // bindings under it, unchanged, so a federated `list` shows the real
            // IRIs (tagged with where they resolve) and nothing outside the prefix.
            MountMode::Override => Some(
                entries
                    .into_iter()
                    .filter(|entry| entry.pattern.starts_with(&self.prefix))
                    .map(|entry| {
                        SpaceEntry::new(entry.pattern, entry.endpoint).with_origin(&self.origin)
                    })
                    .collect(),
            ),
        }
    }
}

/// What the REPL engine needs of a kernel, local or remote.
///
/// Synchronous by design (the REPL loop is blocking). Errors are surfaced as
/// human-readable strings — the engine reports them verbatim; a richer transport
/// error type can replace `String` when the wire protocol lands.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve `request` under the resolver's default authority, and report its
    /// representation and cache outcome.
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error>;

    /// Resolve `request` under an explicit `capability`.
    ///
    /// The default ignores the capability and delegates to [`issue`](Resolver::issue)
    /// — correct for a resolver that can't yet carry authority (a wire resolver,
    /// until capability-on-the-wire lands; the server resolves under its own
    /// default). The in-process kernel overrides this to enforce the capability,
    /// which is what lets the REPL's `cap` command attenuate a local session.
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        let _ = capability;
        self.issue(request)
    }

    /// Async resolution under an explicit `capability` — what the engine `await`s
    /// when it drives a stage on the scheduler, so a *spawned* branch (fork/map)
    /// parks rather than blocking a worker thread. The default runs the synchronous
    /// [`issue_as`](Resolver::issue_as) (correct for a resolver that hides a
    /// `block_on`/wire round-trip); the in-process kernel overrides it to await its
    /// own async issue with no `block_on`, which is what makes concurrent fan-out
    /// deadlock-free under a bounded pool.
    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as(request, capability)
    }

    /// Async resolution of a request whose input came from an upstream pipe stage,
    /// folding that upstream's [`Provenance`] into the result's cacheability — so
    /// `source <X> | transform` is no more cacheable than `X`. The default *ignores*
    /// the provenance and delegates to [`issue_as_async`](Resolver::issue_as_async):
    /// correct for a wire resolver, which doesn't yet propagate provenance across the
    /// wire (the remote kernel resolves each stage on its own merits). The in-process
    /// kernel overrides this to thread the provenance into its dependency merge.
    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        let _ = incoming;
        self.issue_as_async(request, capability).await
    }

    /// Install an execution [`Tracer`] for the next resolution — the `trace` command
    /// records one real `source` to show which worker each node ran on. Default
    /// no-op: a wire resolver can't yet trace the remote kernel; the in-process
    /// kernel forwards to [`Kernel::set_tracer`]. Paired with [`clear_tracer`].
    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        let _ = tracer;
    }

    /// Remove the installed tracer (default no-op).
    fn clear_tracer(&self) {}

    /// Whether resolving `request` under `capability` would be served from the
    /// cache, without resolving it. The capability matters because the cache is
    /// namespaced by authority — a probe reports "cached *for this capability*".
    fn is_cached(&self, request: &Request, capability: &Capability) -> bool;

    /// The resources bound in the kernel's space, or `None` if it can't enumerate.
    fn entries(&self) -> Option<Vec<SpaceEntry>>;

    /// A short human label for the transport this resolver speaks over — shown by
    /// the REPL's `trace` command. The default is the in-process kernel.
    fn transport(&self) -> String {
        "embedded · in-process".to_string()
    }
}

/// The in-process kernel as a [`Resolver`]: drive it directly, inferring the
/// cache outcome from its [`cache_len`](Kernel::cache_len) across the issue (a
/// hit returns the cached value without growing the cache; a cacheable miss
/// inserts one entry). All requests use the root capability — this is the
/// trusted, same-process path.
#[async_trait]
impl Resolver for Kernel {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Probe before issuing: a valid (thread-current) cached entry means a Hit;
        // a cut or absent one means we'll (re)compute. A cache-length delta would
        // misreport once golden-thread eviction is in play — evict + reinsert nets
        // zero — so the probe, not the delta, is the source of truth.
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation = block_on(Kernel::issue(self, request, capability))?;
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Same as `issue_as`, but awaits the kernel's async issue directly — no
        // `block_on`, so when the engine spawns this on the scheduler it parks
        // (freeing the worker for any sub-resolutions it fans out).
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation = Kernel::issue(self, request, capability).await?;
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Thread the upstream pipe provenance into the kernel's dependency merge, so
        // the result's cacheability is no greater than its piped input's. `is_cached`
        // probes the same content-keyed entry the merged result would store under.
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation =
            Kernel::issue_with_incoming(self, request, capability, incoming).await?;
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        Kernel::set_tracer(self, tracer);
    }

    fn clear_tracer(&self) {
        Kernel::clear_tracer(self);
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        Kernel::is_cached(self, request, capability)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        Kernel::entries(self)
    }
}

/// Resolve `request` on `kernel` recording the resolution's spans into `tracer`,
/// with the same cache-status probe as [`Resolver::issue_as`]. This is the
/// **per-call** traced path a wire server dispatches [`Call::IssueTraced`] on:
/// each connection's trace records into its own collector
/// ([`Kernel::issue_traced`]), so concurrent traced calls on the shared kernel
/// can no longer interleave into one process-global tracer (the cross-tenant
/// trace leak from the 2026-07-21 review).
pub fn issue_traced_as(
    kernel: &Kernel,
    request: Request,
    capability: &Capability,
    tracer: Arc<dyn Tracer>,
) -> Result<(Representation, CacheStatus), Error> {
    let was_cached = Kernel::is_cached(kernel, &request, capability);
    let representation = block_on(Kernel::issue_traced(kernel, request, capability, tracer))?;
    let status = cache_status(was_cached, &representation);
    Ok((representation, status))
}

/// The cache-status label for a resolved representation. Only `Always` is truly
/// uncacheable; `Never` and a time-based `At` deadline are both cacheable (so an
/// `At` read reports Hit/Miss, not Uncacheable).
fn cache_status(was_cached: bool, representation: &Representation) -> CacheStatus {
    if representation.expiry == Expiry::Always {
        CacheStatus::Uncacheable
    } else if was_cached {
        CacheStatus::Hit
    } else {
        CacheStatus::Miss
    }
}

/// An `Arc`-shared resolver is itself a resolver, delegating to the inner one. So
/// a kernel can be held as `Arc<Kernel>` and *shared* — driven by the engine, and
/// at the same time reached by a file watcher that cuts golden threads on the very
/// same kernel (and thus the same cache). Every method delegates, so the inner
/// resolver's overrides (e.g. the kernel's `issue_as`/`transport`) are preserved.
#[async_trait]
impl<R: Resolver + ?Sized> Resolver for Arc<R> {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        (**self).issue(request)
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        (**self).issue_as(request, capability)
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Delegate to the inner resolver's override (e.g. the kernel's true-async one).
        (**self).issue_as_async(request, capability).await
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Delegate so the inner resolver's override threads the pipe provenance —
        // otherwise the trait default would silently drop it here.
        (**self)
            .issue_as_async_with_incoming(request, capability, incoming)
            .await
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        (**self).set_tracer(tracer);
    }

    fn clear_tracer(&self) {
        (**self).clear_tracer();
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        (**self).is_cached(request, capability)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        (**self).entries()
    }

    fn transport(&self) -> String {
        (**self).transport()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Description, EndpointSpace, Exact, FnEndpoint, ReprType, Verb};

    fn kernel_with_a_gated_endpoint() -> Kernel {
        let ok = |name: &'static str| {
            FnEndpoint::new(name, |_inv| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            })
        };
        let space = EndpointSpace::new()
            .bind(
                Exact::new("urn:open"),
                ok("open").with_description(Description::new("open").verb(Verb::Source)),
            )
            .bind(
                Exact::new("urn:gated"),
                ok("gated").with_description(
                    Description::new("gated")
                        .verb(Verb::Source)
                        .requires("urn:cap:secret"),
                ),
            );
        Kernel::new(Arc::new(space))
    }

    #[test]
    fn scoped_entries_hides_what_the_capability_cannot_invoke() {
        let kernel = kernel_with_a_gated_endpoint();

        // Root authority enumerates both.
        let root = scoped_entries(&kernel, &Capability::root());
        assert!(root.iter().any(|e| e.pattern == "urn:open"));
        assert!(
            root.iter().any(|e| e.pattern == "urn:gated"),
            "root sees the gated endpoint"
        );

        // A capability without the gating scope sees only the open one — the gated
        // endpoint doesn't even appear (affordance = authorization).
        let scoped = scoped_entries(&kernel, &Capability::scoped(["urn:cap:other"]));
        assert!(scoped.iter().any(|e| e.pattern == "urn:open"));
        assert!(
            !scoped.iter().any(|e| e.pattern == "urn:gated"),
            "the gated endpoint is hidden from a principal that can't invoke it"
        );
    }

    /// A space whose entries carry an origin, the way a mounted remote's do.
    struct MountedFace {
        inner: Arc<dyn Space>,
    }

    impl Space for MountedFace {
        fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
            self.inner.resolve(request, scope)
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            Some(
                self.inner
                    .entries()?
                    .into_iter()
                    .map(|entry| entry.with_origin("test://peer"))
                    .collect(),
            )
        }
    }

    /// A remote kernel with one exact and one template binding, faked at the
    /// resolver seam: `entries` is its (already capability-scoped) wire catalog,
    /// and a Meta issue answers with the endpoint's JSON description — what the
    /// real wire's Meta face returns.
    struct FakeRemote {
        entries: Vec<SpaceEntry>,
        description: Description,
    }

    impl Resolver for FakeRemote {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            let bytes = if request.verb == Verb::Meta {
                serde_json::to_vec(&self.description).expect("description serializes")
            } else {
                b"ok".to_vec()
            };
            Ok((
                Representation::new(ReprType::new("application/json"), bytes),
                CacheStatus::Uncacheable,
            ))
        }

        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            Some(self.entries.clone())
        }
    }

    fn fake_remote() -> Arc<FakeRemote> {
        Arc::new(FakeRemote {
            entries: vec![
                SpaceEntry::new("urn:status", "status"),
                SpaceEntry::new("urn:file:{path}", "file"),
            ],
            description: Description::new("file")
                .verb(Verb::Source)
                .input(ikigai_core::ArgSpec::new("path").binding()),
        })
    }

    /// The regression this crate owns: a REMOTE template entry must survive the
    /// kernel's probe guard. `describe_entry` probe-expands `urn:remote:file:{path}`
    /// to `urn:remote:file:probe` and discards the hit unless the resolved
    /// endpoint's name matches the entry's — and the forwarding endpoint used to be
    /// flatly named `"remote"`, so every mounted template action vanished from the
    /// manifold/MCP projection while exact entries projected fine.
    #[test]
    fn a_mounted_template_entry_survives_the_probe_guard() {
        let mounted = MountedRemote::new(fake_remote(), "urn:remote:", "test://peer");
        let kernel = Kernel::new(Arc::new(mounted));
        let entries = scoped_entries(&kernel, &Capability::root());
        assert!(
            entries.iter().any(|e| e.pattern == "urn:remote:status"),
            "the exact remote entry is in the manifold"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.pattern == "urn:remote:file:{path}"),
            "the TEMPLATE remote entry is in the manifold: the probe resolves to a \
             forwarding endpoint named `file` (from the wire catalog), not `remote`; \
             got {entries:?}"
        );
    }

    /// Same through an OVERRIDE mount (the `--override`/`--prefer` shape): the IRI
    /// is forwarded unchanged, and the name lookup matches the remote's own
    /// namespace patterns.
    #[test]
    fn an_overriding_mounts_template_entry_survives_the_probe_guard() {
        let mounted = MountedRemote::overriding(fake_remote(), "urn:file:", "test://peer");
        let kernel = Kernel::new(Arc::new(mounted));
        let entries = scoped_entries(&kernel, &Capability::root());
        assert!(
            entries.iter().any(|e| e.pattern == "urn:file:{path}"),
            "the overridden template entry is in the manifold; got {entries:?}"
        );
    }

    /// The guard's shadow-detection must stay intact: when a LOCAL binding wins the
    /// probe IRI (alias mounts are tried after local), the probe resolves to the
    /// local endpoint, its name mismatches the remote entry's, and the row is
    /// discarded — better invisible than misdescribed.
    #[test]
    fn a_shadowed_remote_template_entry_is_still_discarded() {
        let shadow = EndpointSpace::new().bind(
            Exact::new("urn:remote:file:probe"),
            FnEndpoint::new("shadow", |_inv| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"shadow".to_vec(),
                ))
            })
            .with_description(Description::new("shadow").verb(Verb::Source)),
        );
        let mounted = MountedRemote::new(fake_remote(), "urn:remote:", "test://peer");
        let root = ikigai_core::Fallback::new(vec![
            Arc::new(shadow) as Arc<dyn Space>,
            Arc::new(mounted) as Arc<dyn Space>,
        ]);
        let kernel = Kernel::new(Arc::new(root));
        let entries = scoped_entries(&kernel, &Capability::root());
        assert!(
            !entries
                .iter()
                .any(|e| e.pattern == "urn:remote:file:{path}"),
            "a locally-shadowed probe IRI still discards the remote template row"
        );
    }

    /// Off the catalog walk (nothing enumerated yet), the forwarding endpoint keeps
    /// its transport fallback name — the name map only fills from `entries()`, never
    /// with a wire round-trip on the resolve path.
    #[test]
    fn an_unenumerated_target_falls_back_to_the_transport_name() {
        let mounted = MountedRemote::new(fake_remote(), "urn:remote:", "test://peer");
        let request = Request::new(
            Verb::Source,
            ikigai_core::Iri::parse("urn:remote:status").unwrap(),
        );
        let Resolution::Hit(resolved) = mounted.resolve(&request, &Scope::empty()) else {
            panic!("a mounted remote always hits under its prefix");
        };
        assert_eq!(resolved.endpoint.name(), "remote");
        // After one enumeration, the same resolve carries the remote's real name.
        let _ = mounted.entries();
        let Resolution::Hit(resolved) = mounted.resolve(&request, &Scope::empty()) else {
            panic!("a mounted remote always hits under its prefix");
        };
        assert_eq!(resolved.endpoint.name(), "status");
    }

    /// A remote whose catalog NESTS one route inside another — ikigai-browse's PR
    /// rows, with the shorter pattern listed first (the order that broke).
    struct NestedRemote;

    impl Resolver for NestedRemote {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            // Meta answers for the target asked about, the way the real wire does —
            // so the description is right even where the client's label is wrong.
            let bytes = if request.verb == Verb::Meta {
                let description = Description::new(name_of(request.target.as_str()))
                    .verb(Verb::Source)
                    .input(ikigai_core::ArgSpec::new("repo").binding())
                    .input(ikigai_core::ArgSpec::new("n").binding());
                serde_json::to_vec(&description).expect("description serializes")
            } else {
                b"ok".to_vec()
            };
            Ok((
                Representation::new(ReprType::new("application/json"), bytes),
                CacheStatus::Uncacheable,
            ))
        }

        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            Some(vec![
                SpaceEntry::new("urn:repo:{repo}:pr:{n}", "browse-pr"),
                SpaceEntry::new("urn:repo:{repo}:pr:{n}:explain", "browse-explain"),
                SpaceEntry::new("urn:repo:{repo}:pr:{n}:review", "browse-review"),
            ])
        }
    }

    /// The remote's own routing — the Rust logic no pattern string can express:
    /// the PR row rejects an `n` that spans a `:`, so the nested routes win.
    fn name_of(target: &str) -> &'static str {
        if target.ends_with(":explain") {
            "browse-explain"
        } else if target.ends_with(":review") {
            "browse-review"
        } else {
            "browse-pr"
        }
    }

    fn nested_name_for(target: &str) -> String {
        let mounted = MountedRemote::overriding(Arc::new(NestedRemote), "urn:repo:", "test://peer");
        let _ = mounted.entries(); // the catalog walk that fills the name map
        let request = Request::new(Verb::Source, ikigai_core::Iri::parse(target).unwrap());
        let Resolution::Hit(resolved) = mounted.resolve(&request, &Scope::empty()) else {
            panic!("a mounted remote always hits under its prefix");
        };
        resolved.endpoint.name().to_string()
    }

    /// A NESTED remote route must be named by its own catalog row. The parent
    /// pattern `urn:repo:{repo}:pr:{n}` matches `…:pr:12:explain` too (`{n}`
    /// captures `12:explain`), so replaying the catalog in order labelled every
    /// child route `browse-pr` — the client can't see the remote's rejection of an
    /// `n` spanning a `:`, only its pattern string. Most-specific-wins reads the
    /// nesting straight off the literals.
    #[test]
    fn a_nested_remote_route_is_named_by_its_own_row() {
        assert_eq!(
            nested_name_for("urn:repo:acme:pr:12:explain"),
            "browse-explain",
            "the longer row names the nested route, though the shorter one matches \
             and is listed first"
        );
        assert_eq!(
            nested_name_for("urn:repo:acme:pr:12:review"),
            "browse-review"
        );
        // …and the parent route still names itself: specificity narrows, it doesn't
        // just prefer the longest row in the catalog.
        assert_eq!(nested_name_for("urn:repo:acme:pr:12"), "browse-pr");
    }

    /// The nesting reaches the manifold: every PR-grain row survives the kernel's
    /// probe guard under its own name, so all three project as tools rather than
    /// two of them being swallowed by the shorter sibling's label.
    #[test]
    fn every_nested_row_reaches_the_mounted_manifold() {
        let mounted = MountedRemote::overriding(Arc::new(NestedRemote), "urn:repo:", "test://peer");
        let kernel = Kernel::new(Arc::new(mounted));
        let entries = scoped_entries(&kernel, &Capability::root());
        for pattern in [
            "urn:repo:{repo}:pr:{n}",
            "urn:repo:{repo}:pr:{n}:explain",
            "urn:repo:{repo}:pr:{n}:review",
        ] {
            assert!(
                entries.iter().any(|e| e.pattern == pattern),
                "`{pattern}` is in the mounted manifold; got {entries:?}"
            );
        }
    }

    /// The same rule, over a plain catalog slice — what the REPL's `trace` renderer
    /// applies to label a span with the endpoint that served it.
    #[test]
    fn naming_entry_picks_the_most_specific_row() {
        let entries = NestedRemote.entries().expect("catalog");
        let name = |target: &str| {
            naming_entry(&entries, &ikigai_core::Iri::parse(target).unwrap())
                .map(|entry| entry.endpoint.as_str())
        };
        assert_eq!(name("urn:repo:acme:pr:12:explain"), Some("browse-explain"));
        assert_eq!(name("urn:repo:acme:pr:12"), Some("browse-pr"));
        assert_eq!(name("urn:other:thing"), None);
    }

    /// An exact row outranks a template that also matches — its literals span the
    /// whole IRI, which a template's non-empty captures never leave room for.
    #[test]
    fn naming_entry_prefers_an_exact_row_over_a_template() {
        let entries = vec![
            SpaceEntry::new("urn:file:{path}", "file"),
            SpaceEntry::new("urn:file:special", "special"),
        ];
        let target = ikigai_core::Iri::parse("urn:file:special").unwrap();
        assert_eq!(
            naming_entry(&entries, &target).map(|e| e.endpoint.as_str()),
            Some("special")
        );
    }

    /// The wire catalog is rebuilt from the action manifold, but a mounted
    /// binding's PROVENANCE lives on the space entry — it must survive the
    /// rebuild, or a federated client sees `urn:py:*` rows indistinguishable
    /// from local bindings (the prefer-mount catalog bug, 2026-08-07).
    #[test]
    fn scoped_entries_preserve_a_mounted_bindings_origin() {
        let inner: Arc<dyn Space> = Arc::new(
            EndpointSpace::new().bind(
                Exact::new("urn:open"),
                FnEndpoint::new("open", |_inv| {
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"ok".to_vec(),
                    ))
                })
                .with_description(Description::new("open").verb(Verb::Source)),
            ),
        );
        let kernel = Kernel::new(Arc::new(MountedFace { inner }));
        let entries = scoped_entries(&kernel, &Capability::root());
        let row = entries
            .iter()
            .find(|e| e.pattern == "urn:open")
            .expect("the mounted binding is listed");
        assert_eq!(
            row.origin.as_deref(),
            Some("test://peer"),
            "the wire catalog names where a mounted binding resolves"
        );
    }
}
