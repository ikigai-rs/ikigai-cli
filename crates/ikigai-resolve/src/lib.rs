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

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Bindings, Capability, Clock, Description, Endpoint, Error, Expiry, Grammar, Invocation,
    Iri, IssueContext, Kernel, Limit, Provenance, Representation, Request, Resolution, Resolved,
    Scope, Space, SpaceEntry, Time, TraceEvent, Tracer, UriTemplate, Verb,
};
use serde::{Deserialize, Serialize};

// The one rule for a request-derived name joined under a directory (ledger #1307). It
// lives here because this is the one member every host-side crate of the workspace
// (embedded, intray, cli) already depends on; it has nothing to do with resolution.
mod file_name;
pub use file_name::is_plain_file_name;

// The one rule for a leading `~` in a path a person typed (ledger #1379), here for the same
// reason: the config-home readers in embedded and the binary's flags both reach it.
mod home;
pub use home::{expand_home, expand_home_str};

// The one rule for a principal a client supplied (ledger #1830): every door that builds a
// request removes it and stamps its own, here for the same reason as the two above.
mod principal;
pub use principal::{stamp_principal, without_principals, PRINCIPAL_ARG};

// The default clock a mount's bookkeeping reads (ledger #2194): native only, because
// platform time is a runtime panic on wasm32-unknown-unknown. See `default_clock`.
#[cfg(not(target_arch = "wasm32"))]
mod native_clock;

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
/// broken by catalog order — the same rule the private `RemoteNames` applies to a mount's
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
/// comes back as an error on invoke, not a resolution miss — except under `Meta`,
/// which is never invoked, so the peer is asked at resolve time and an absent name
/// is a hit on ⊥, i.e. `Unresolved` (see `ForwardingEndpoint::resolution`).
pub struct RemoteSpace {
    resolver: Arc<dyn Resolver>,
    names: RemoteNames,
    contracts: Arc<ContractMemo>,
    /// What the contract memo measures its TTL on. See [`default_clock`].
    clock: Option<Arc<dyn Clock>>,
}

impl RemoteSpace {
    /// Wrap a connected [`Resolver`] as a mountable space.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        RemoteSpace {
            resolver,
            names: RemoteNames::new(),
            contracts: Arc::new(ContractMemo::new(CONTRACT_TTL)),
            clock: default_clock(),
        }
    }

    /// Measure the contract TTL on `clock` (builder): give it the clock the host gave its
    /// kernel. On a native target the default is a monotonic clock; on wasm32 there is none
    /// (reading platform time there panics), so without this a browser host's space keeps
    /// no contract memo and asks the peer on every describe (ledger #2194).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// How long this space trusts a contract it read from the peer (builder; default
    /// [`CONTRACT_TTL`]). `Duration::ZERO` asks the peer on every describe, as before
    /// ledger #1577. See [`CONTRACT_TTL`] for what the bound guarantees.
    pub fn contract_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.contracts = Arc::new(ContractMemo::new(ttl));
        self
    }
}

impl Space for RemoteSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        // Capture the whole request (target + verb + args) so the endpoint forwards
        // it verbatim; the caller's capability arrives via the Invocation on invoke.
        // The constructor, not the literal: `Resolved` grows fields (`canonical` at
        // core 0.1.64, `answered_by` at 0.1.78), and a literal in a PUBLISHED crate
        // stops compiling for every lockless consumer the day core publishes one.
        // `Resolved::new` reports no canonical — nothing is rewritten here, the
        // request goes over the wire under the name it arrived with. (Even if it
        // were, it would not be a canonical: see `MountedRemote::resolve` below for
        // why a mount never reports one.)
        ForwardingEndpoint {
            resolver: Arc::clone(&self.resolver),
            name: self.names.name_for(&request.target),
            // A bare `RemoteSpace` is mounted by a caller that holds the resolver;
            // it carries no origin label of its own (`MountedRemote` does).
            origin: None,
            // …and with no mount identity, a failure here has nothing to be
            // attributed to, so it is not remembered. See `DescribeHealth`.
            health: None,
            request: request.clone(),
            contract: None,
            contracts: Arc::clone(&self.contracts),
            clock: self.clock.clone(),
        }
        .resolution(request)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // Forward the remote's catalog (a round-trip — off the hot path), keeping
        // the name map current so template probes resolve under the real names.
        let entries = self.resolver.entries()?;
        self.names.refresh(&entries);
        // A walk describes every row next: read them from the peer (see `ContractMemo`).
        self.contracts.clear();
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
    /// The mount's origin label (`ipc:~/.ikigai/dev.sock`, `quic:plasma:4433`), when the
    /// space that built this endpoint has one. Used only to NAME the peer in the
    /// contract-unavailable path ([`unavailable`]) — a diagnostic that says "a mounted
    /// peer" is one an operator with three mounts cannot act on.
    origin: Option<String>,
    /// What the mount has learned about this peer's ability to describe itself, when the
    /// space that built this endpoint tracks it. `None` for a [`RemoteSpace`], which has
    /// no mount identity to attribute a failure to.
    health: Option<Arc<DescribeHealth>>,
    /// The peer's contract, when it was read at RESOLVE time — which is what a `Meta`
    /// resolution does (see [`resolution`](Self::resolution)). `None` means nobody has
    /// asked yet, and [`describe`](Endpoint::describe) asks then — or takes it from
    /// `contracts`.
    contract: Option<Contract>,
    /// The mount's memo of contracts its peer declared, shared by every endpoint the mount
    /// hands out, so a hot read does not forward a `Meta` per read. See [`ContractMemo`].
    contracts: Arc<ContractMemo>,
    /// The mount's clock, which `health` and `contracts` are measured on. See
    /// [`default_clock`].
    clock: Option<Arc<dyn Clock>>,
}

/// What forwarding a `Meta` to the peer said about a mounted name.
enum Contract {
    /// The peer's own declaration.
    Read(Box<Description>),
    /// The peer did not answer with a contract, for this reason. Not "unbound": a peer
    /// that says nothing binds the name is [`Lookup::Unbound`], and never gets this far.
    Unavailable(String),
}

/// Why a contract could not be read — split because the two answers mean different
/// things to a resolution (ledger #1146).
enum Lookup {
    /// The peer resolved nothing at that name: it is not offered there.
    Unbound,
    /// The peer answered something other than a contract, or did not answer at all.
    Unavailable(String),
}

impl ForwardingEndpoint {
    /// What the mount's clock reads, if it has one.
    fn now(&self) -> Option<Time> {
        self.clock.as_ref().map(|clock| clock.now())
    }

    /// The resolution a mount reports for `request` (the request as it ARRIVED, under the
    /// local name), with this endpoint as the hit.
    ///
    /// ★ **A `Meta` asks the peer NOW, at resolve time, and an unbound name is
    /// UNRESOLVED.** Every other verb finds out on invoke — the forward fails with the
    /// peer's own `Unresolved` — but `Meta` is never invoked: the kernel renders
    /// [`describe`](Endpoint::describe), which cannot fail. So before ledger #1146 a
    /// `describe` of a mounted name nothing binds printed a "contract unavailable"
    /// placeholder and exited 0, and a script could not tell "not offered" from
    /// "offered" without parsing prose. The answer is core's own ⊥ — a hit on a
    /// [`Limit`]'s bottom — so the kernel reports the SAME `Unresolved`, byte for byte,
    /// that an unbound local name gets, and does not continue outward (an OVERRIDE mount
    /// must not fall through to a local binding of a name it claims). Every
    /// `entries → Meta → describe` walk drops a hit on ⊥ too, which mirrors the peer:
    /// a probe expansion the peer cannot resolve is a row its OWN catalog drops.
    ///
    /// It costs no round-trip: every caller that `Meta`-resolves describes the hit
    /// next, and the contract read here is what [`describe`](Endpoint::describe)
    /// returns, so the one forward moves from describe to resolve. A peer already known
    /// to be silent is not asked here either — [`DescribeHealth`] — and describes as
    /// [`unavailable`] exactly as before.
    fn resolution(mut self, request: &Request) -> Resolution {
        let silent = self
            .health
            .as_ref()
            .is_some_and(|h| h.failing(self.now()).is_some());
        if request.verb == Verb::Meta && !silent {
            // ★ A `Meta` is the "describe it NOW" operation, so it never takes the memo's
            // word for it — it refreshes the memo instead (see `ContractMemo`).
            let target = self.request.target.as_str().to_string();
            match self.lookup() {
                Ok(description) => {
                    self.contracts.put(&target, &description, self.now());
                    self.contract = Some(Contract::Read(Box::new(description)))
                }
                Err(Lookup::Unbound) => {
                    self.contracts.forget(&target);
                    return Limit::new(request.target.as_str()).resolve(request, &Scope::empty());
                }
                Err(Lookup::Unavailable(reason)) => {
                    self.contract = Some(Contract::Unavailable(reason))
                }
            }
        }
        Resolution::Hit(Resolved::new(Arc::new(self), Bindings::new()))
    }

    /// Stop trusting the memoized contract for this name when the peer REFUSED the forward:
    /// a `Denied` the local floor did not predict, or an `Unresolved` for a name it was
    /// described under, means the peer's contract may no longer be the one held here.
    fn distrust_on_refusal<T>(&self, result: &Result<T, Error>) {
        if matches!(result, Err(Error::Denied(_) | Error::Unresolved(_))) {
            self.contracts.forget(self.request.target.as_str());
        }
    }

    /// Forward a `Meta` (JSON face) for the target and read the peer's contract.
    fn lookup(&self) -> Result<Description, Lookup> {
        let meta = Request::new(Verb::Meta, self.request.target.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
        match self.resolver.issue_as(meta, &Capability::root()) {
            Ok((repr, _status)) => serde_json::from_slice::<Description>(&repr.bytes).map_err(
                // The shape that cost a day: a peer below `ikigai-vocab` 0.1.47 has no
                // JSON Meta renderer, answers `as=application/json` with the canonical
                // TURTLE, and the parse fails here — so the media type is named, because
                // "expected JSON, got text/turtle" is the whole diagnosis.
                |error| {
                    Lookup::Unavailable(format!(
                        "its Meta answer is {} ({} byte(s)), not a JSON Description: {error}",
                        repr.repr_type,
                        repr.bytes.len()
                    ))
                },
            ),
            // The peer's own words for "nothing binds that name here".
            Err(Error::Unresolved(_)) => Err(Lookup::Unbound),
            Err(error) => {
                // Silence here is the same silence an enumeration would meet, so it counts
                // against the same health — one row's timeout spares every later row.
                if let Some(health) = &self.health {
                    health.record(&error, self.now());
                }
                Err(Lookup::Unavailable(format!(
                    "it refused the Meta request: {error}"
                )))
            }
        }
    }
}

#[async_trait]
impl Endpoint for ForwardingEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation, Error> {
        // Off the trace path: a plain forward. The resolver already yields a typed
        // Error, so a hung/unreachable remote surfaces as transient — a Retry or
        // Failover above this mount can act on it, not a blanket permanent failure.
        // The run's context rides along (wire v9): what is left of its retry pool and its
        // deadline, so the peer bounds this sub-request by the run the door minted here.
        let run = RunContext::of(inv);
        if inv.trace_span().is_none() {
            let result = self
                .resolver
                .issue_as_in_run(self.request.clone(), inv.capability, &run);
            self.distrust_on_refusal(&result);
            return result.map(|(representation, _status)| as_held_here(representation));
        }
        // The local kernel is recording: trace the forward too — install a collector
        // on the resolver so the round-trip goes as a traced call — then hand the
        // returned remote subtree to the local trace, which re-bases it under this
        // mount node (`inv.record_subtree`). So the remote execution shows stitched
        // into the tree instead of collapsed to one node.
        let collector = Arc::new(SpanCollector::default());
        self.resolver.set_tracer(collector.clone());
        let result = self
            .resolver
            .issue_as_in_run(self.request.clone(), inv.capability, &run);
        self.resolver.clear_tracer();
        self.distrust_on_refusal(&result);
        let (representation, _status) = result?;
        inv.record_subtree(collector.take());
        Ok(as_held_here(representation))
    }

    fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("remote")
    }

    fn describe(&self) -> Description {
        // Forward a Meta request (JSON face) so the engine can route named args by
        // the *remote* endpoint's own contract — otherwise `compose src=…` over a
        // mount loses its `src`. Best-effort, and [`unavailable`] is what makes the
        // best-effort part audible rather than silent.
        // ★ A peer already known to be silent is NOT asked again. `describe()` is called
        // once per catalog row on a manifold read, so without this the transport's
        // deadline would be paid per row and a bounded call would still add up to an
        // unbounded walk — the deadline bounds a CALL, this bounds the WALK.
        // A `Meta` resolution already asked (see `resolution`): its answer is the answer.
        let reason = match &self.contract {
            Some(Contract::Read(description)) => return (**description).clone(),
            Some(Contract::Unavailable(reason)) => reason.clone(),
            None => {
                let now = self.now();
                if let Some(reason) = self.health.as_ref().and_then(|health| health.failing(now)) {
                    return unavailable(
                        self.origin.as_deref(),
                        self.request.target.as_str(),
                        &reason,
                    );
                }
                // The floor and a routing read land here once per resolution, because each
                // resolution is a fresh endpoint core's floor memo has not seen: answer from
                // the mount's own memo while it is fresh (ledger #1577).
                let target = self.request.target.as_str();
                if let Some(description) = self.contracts.get(target, now) {
                    return description;
                }
                match self.lookup() {
                    Ok(description) => {
                        self.contracts.put(target, &description, self.now());
                        return description;
                    }
                    // Asked off a `Meta` resolution — a floor or a routing read on a hit
                    // that resolved under another verb. The invoke will say "unresolved"
                    // itself; here there is only a contract to fail to read.
                    Err(Lookup::Unbound) => {
                        format!("it resolves nothing at `{}`", self.request.target)
                    }
                    Err(Lookup::Unavailable(reason)) => reason,
                }
            }
        };
        unavailable(
            self.origin.as_deref(),
            self.request.target.as_str(),
            &reason,
        )
    }
}

/// A peer's answer as the MOUNTING kernel may hold it: never cacheable here (ledger #92).
///
/// ★ **A mounted kernel can learn of a cut on its peer only by asking the peer again.** The
/// peer's cacheable answer is valid until the peer cuts one of its golden threads: one its
/// endpoint declared with `depends_on`, one it inherited from a sub-resource, or its own
/// target's, which every cacheable answer has carried since core 0.1.73. Those cuts happen on
/// the peer, made by a watcher, by `urn:kernel:cut`, or by a write that reaches the peer by
/// another route, and nothing crosses back to tell this kernel. Thread NAMES do not cross either
/// (`Representation::threads` is `serde(skip)`), but carrying them would not change this:
/// a name this kernel holds is cut only by what happens HERE, and the cuts that matter happen
/// THERE. So an answer this kernel stored would be served after the peer had moved on, for as
/// long as this process lives. A long-lived client (`ikigai mcp`, `ikigai serve`, a config-home
/// mount of gonk's socket) did exactly that until this rule (measured 2026-10-07: a watched
/// `urn:repo:{root}:tree` read stayed `[cached]` after a file was added under the root).
///
/// So the expiry is rewritten to [`Expiry::Always`], whatever the peer said, `Never` and a
/// time-bounded `At` alike (a deadline bounds staleness, it does not remove it: the peer may cut
/// before it). What a mounted read costs is then one round trip, to the PEER's cache, which
/// still holds the answer with its threads and is cut by the peer's own writes and watchers;
/// a composite over it is uncacheable here too, and `urn:kernel:uncached` lists the mounted
/// read as `declared` and the composite as `dependency <the mounted name>`. Only the expiry
/// changes: the bytes, the type and the peer's own cache status are untouched.
///
/// ⚠ What this does NOT give is a mounted read that is cached here AND fresh. That needs the
/// peer's cuts to cross the wire: core's cut listeners (`Kernel::listen`) already report them
/// on the peer, and a wire call that streamed them to the mounting side, which would cut the
/// threads it hung its copies on, is the shape. It is a protocol addition, not a fix, and it is
/// not built.
fn as_held_here(representation: Representation) -> Representation {
    representation.with_expiry(Expiry::Always)
}

/// The description a mounted endpoint gets when its peer's contract could not be read —
/// and the note that says so, once.
///
/// ## Why this is not just `Description::new("remote")`
///
/// It was, until 0.1.20, and the consequence is that a peer whose Meta answer cannot be
/// parsed becomes one anonymous, action-less row: the engine stops routing named arguments
/// (`compose src=…` over the mount silently loses its `src`), the catalog shows a contract
/// with no verbs, and **a whole federated kernel reads as SMALL rather than as broken**.
/// Both halves of that were paid for: `ikigai-dev-server` #8 took crate archaeology to
/// trace a `ikigai-vocab` floor below 0.1.47 back to this line, and `ikigai-web` #14 found
/// a walk over a renderer-less peer reporting `endpoints = 1` and reading as a small
/// kernel. The failure is indistinguishable from a peer that genuinely serves one thing.
///
/// So the fallback now SAYS it is a fallback, in two places:
///
/// * the description itself carries a title and a summary naming the peer and the reason,
///   so it is visible wherever a contract is — the catalog, `urn:kernel:actions`, MCP;
/// * one line on stderr per (peer, reason), because a description is only seen by someone
///   already looking at the catalog, and the operator who needs this is looking at a
///   command that lost an argument.
///
/// ⚠ The id stays `remote`. It is what core's template-probe guard compares against and
/// what a consumer (`ikigai-web`'s conformance walk, conformance PENDING #133) already
/// tests for; changing it would trade a known detector for a prettier string.
///
/// ## Why the note is deduplicated
///
/// `describe()` is called per dispatch, not once per mount (ikigai-core AUDIT 2026-09-08),
/// so an un-deduplicated note would print on every request through a degraded mount — which
/// is not "loud", it is noise that gets filtered out. Keyed by (peer, reason) so a peer that
/// later fails differently still says so; bounded by peers × failure kinds.
fn unavailable(origin: Option<&str>, target: &str, reason: &str) -> Description {
    let peer = origin.unwrap_or("a mounted peer");
    let once = format!("{peer}\u{1}{reason}");
    let first = {
        static SEEN: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
        // A poisoned lock here must not take down a describe: treat it as "already said".
        SEEN.lock()
            .map(|mut seen| seen.insert(once))
            .unwrap_or(false)
    };
    if first {
        eprintln!(
            "ikigai: {peer} did not answer with a contract for `{target}` — {reason}. \
             Its endpoints will present no actions and named arguments will not be routed \
             to them. (A peer needs a Meta renderer and `ikigai-vocab` >= 0.1.47 to serve \
             the JSON Meta face.)"
        );
    }
    Description::new("remote")
        .title("contract unavailable")
        .summary(format!(
            "{peer} did not answer with a contract for `{target}`: {reason}. This row is a \
             placeholder, not the peer's declaration — the actions it really offers are \
             unknown here, and named arguments are not routed."
        ))
}

/// How long a mount believes that its peer cannot describe itself, before asking again.
///
/// ★ **This is what actually bounds a manifold read, and the deadline alone does not.**
/// A manifold read is one `entries()` plus one `describe()` PER ROW — core's
/// `select_actions` walks the catalog and Metas every entry — so a per-call deadline over
/// a silent peer costs `rows × deadline`, which is not a bound a human would recognize as
/// one. Once a peer has missed its deadline, this mount stops asking for the length of the
/// cooldown and every later describe fails instantly, so a manifold read costs ONE deadline
/// per unhealthy mount, whatever the peer's catalog size.
///
/// Thirty seconds, matching the deadline itself and `ENTRIES_REDIAL_AFTER` in the CLI's
/// lazy mount: long enough that a single `urn:kernel:actions` never pays twice, short
/// enough that a peer which comes back is picked up by the next command rather than at the
/// end of the session. ⚠ It gates only SELF-DESCRIPTION. Resolutions through the mount are
/// untouched — a peer too slow to describe itself may still be serving reads perfectly, and
/// deciding otherwise on its behalf would be this fix causing the outage it prevents.
const DESCRIBE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// What a mount remembers about a peer that failed to describe itself: when, and why.
///
/// Shared by `Arc` between the [`MountedRemote`] (which enumerates) and every
/// [`ForwardingEndpoint`] it hands out (which describe), because those are the two calls
/// a manifold read makes and one peer's silence should be learned once, not per row.
#[derive(Default)]
struct DescribeHealth {
    /// `Some((when, why))` while the peer is considered undescribable, `when` read from the
    /// clock of the mount that saw it go silent.
    failed: Mutex<Option<(Time, String)>>,
}

/// One kernel's view of which of its PEERS can describe themselves — handed to every
/// [`MountedRemote`] a composer builds, so mounts of the same peer share one verdict.
///
/// ★ **Silence is a property of the PEER, not of the local name a mount gave it.** plasma
/// mounts one `ikigai-gonk` under two prefixes; with a record per mount, one silent process
/// cost TWO deadlines on every manifold read — measured at 60s where one deadline is 30s —
/// and a host mounting the same peer five times would have paid five. Keyed on the origin
/// label, which is the only peer identity a mount is given (two mounts of one socket carry
/// two connections, but one server process).
///
/// ⚠ **Scoped to a composition, deliberately not a process-global.** A `static` registry is
/// the obvious implementation and it is wrong twice: it makes two kernels in one process
/// share a verdict about peers they reached differently, and — the way it was caught — it
/// makes a test suite ORDER-DEPENDENT, because two tests naming a peer `test://peer` are
/// then the same peer. A composer knows which mounts are one kernel's; nothing else does.
#[derive(Default, Clone)]
pub struct PeerHealth(Arc<Mutex<std::collections::BTreeMap<String, Arc<DescribeHealth>>>>);

impl PeerHealth {
    /// The record for the peer at `origin`, creating it on first sight.
    fn get(&self, origin: &str) -> Arc<DescribeHealth> {
        let mut peers = match self.0.lock() {
            Ok(peers) => peers,
            // A poisoned lock must cost sharing, never a mount: this one gets its own.
            Err(_) => return Arc::new(DescribeHealth::default()),
        };
        Arc::clone(peers.entry(origin.to_string()).or_default())
    }
}

impl DescribeHealth {
    /// Why the peer is currently considered undescribable, if it is — clearing a record
    /// that has aged past [`DESCRIBE_COOLDOWN`] so the next call tries the peer again.
    /// With no clock (`now` is `None`) nothing is recorded, so nothing is failing.
    fn failing(&self, now: Option<Time>) -> Option<String> {
        let mut failed = match self.failed.lock() {
            Ok(failed) => failed,
            // A poisoned lock must cost knowledge, never a describe: forget the record.
            Err(poisoned) => poisoned.into_inner(),
        };
        match &*failed {
            Some((at, why)) if within(*at, now, DESCRIBE_COOLDOWN) => Some(why.clone()),
            Some(_) => {
                *failed = None;
                None
            }
            None => None,
        }
    }

    /// Record that the peer went silent, if `error` is the kind of failure that means
    /// silence. A [`Timeout`](Error::Timeout) or an [`Unavailable`](Error::Unavailable) is
    /// the transport saying nothing came back; anything else — a `Denied`, an endpoint
    /// error, a contract that parsed badly — is the peer ANSWERING, and a peer that answers
    /// is not one to stop asking.
    ///
    /// `now` is the mount's clock (see [`default_clock`]). With none — wasm32 with no clock
    /// installed — a silence is not remembered and every describe asks the peer, which is
    /// what a mount did before it kept this record; there is no cooldown to measure.
    fn record(&self, error: &Error, now: Option<Time>) {
        if !matches!(error, Error::Timeout(_) | Error::Unavailable(_)) {
            return;
        }
        let Some(now) = now else {
            return;
        };
        let mut failed = match self.failed.lock() {
            Ok(failed) => failed,
            Err(poisoned) => poisoned.into_inner(),
        };
        *failed = Some((now, error.to_string()));
    }

    /// Forget any record — the peer just answered.
    fn clear(&self) {
        let mut failed = match self.failed.lock() {
            Ok(failed) => failed,
            Err(poisoned) => poisoned.into_inner(),
        };
        *failed = None;
    }
}

/// How long a mount ([`MountedRemote`], [`RemoteSpace`]) trusts a contract it read from its
/// peer before reading it again, and the default for [`MountedRemote::contract_ttl`] and
/// [`RemoteSpace::contract_ttl`] (ledger #1577).
///
/// Five seconds: a hot read pays at most one `Meta` round trip per forwarded name per five
/// seconds instead of one per read, and a peer that was upgraded or rebound is described
/// afresh by the first read that starts five seconds after the mount last read its
/// contract. `Duration::ZERO` turns the memo off, which is the behavior before it: every
/// describe asks the peer.
///
/// ## The guarantee
///
/// * **Staleness is bounded by the TTL.** A contract is reused for at most this long after
///   it was read; the first describe after that asks the peer again. A peer that was
///   upgraded, restarted or rebound is seen within that bound, whatever the transport did
///   in between. (Invalidating on a reconnect instead would not be enough and is not
///   available: the IPC client heals a broken connection INSIDE one call, so a restart is
///   invisible to the mount, and a peer can rebind a name with no reconnect at all.)
/// * **A contract that changed never widens what a caller may do.** The local floor is a
///   pre-check. Every forwarded request carries the caller's capability, and the peer runs
///   its OWN current floor on it (the server clamps it to the channel's principal first).
///   So if the peer NARROWED a contract, a caller the stale local floor admits is refused by
///   the peer; and if the peer WIDENED one, the stale local floor refuses a caller the peer
///   would admit, until the TTL passes. Both directions err toward refusing. ⚠ This rests
///   on the peer enforcing its own floor, which every ikigai kernel does. A peer that does
///   not is trusting the mounting side's floor alone, and for such a peer a narrowed
///   contract can be under-enforced for up to the TTL; mount it with `Duration::ZERO`.
/// * **A refusal re-reads.** A forwarded request the peer answers with `Denied` or
///   `Unresolved` evicts that name, so a contract that is disagreeing with the peer is not
///   trusted for the rest of its TTL.
/// * **An enumeration re-reads everything.** `entries()` is a catalog walk's first step and
///   every row is described next, so a successful enumeration clears the memo and a
///   manifold read describes from the peer exactly as it did before.
/// * **A failure is never memoized.** Only a contract the peer actually declared is held. A
///   silent peer is the mount's health record's business (consulted first, as before), and
///   an unparseable answer is asked again on the next describe, as before (ledger #93).
/// * **`Meta` always asks.** A `Meta` resolution reads the peer at resolve time (ledger
///   #1146) and refreshes the entry with what it read, or evicts it when the peer no longer
///   binds the name.
pub const CONTRACT_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// How many forwarded names' contracts a mount holds before it sweeps: expired ones first,
/// then live ones down to three quarters, so a template mount (`urn:file:{path}`, one name
/// per path) is bounded in memory and degrades to the old per-read `Meta` rather than off a
/// cliff. The same shape as core's floor memo bound, for the same reason (ledger #791).
const CONTRACT_MEMO_BOUND: usize = 1024;

/// The clock a mount's bookkeeping (its [`ContractMemo`] and its [`DescribeHealth`]) reads
/// when its host installed none (ledger #2194): on a native target a monotonic one (the
/// private `native_clock` module); on wasm32 none at all, because there is no platform time
/// to read there without a host, and reading it anyway is a runtime panic. A mount with no
/// clock keeps neither record — every describe asks the peer, the behavior before either
/// existed — rather than guessing at time. A host installs one with
/// [`MountedRemote::with_clock`] or [`RemoteSpace::with_clock`].
fn default_clock() -> Option<Arc<dyn Clock>> {
    #[cfg(not(target_arch = "wasm32"))]
    let clock: Option<Arc<dyn Clock>> = Some(Arc::new(native_clock::Monotonic::new()));
    #[cfg(target_arch = "wasm32")]
    let clock: Option<Arc<dyn Clock>> = None;
    clock
}

/// A duration in whole milliseconds, the resolution of a core [`Time`].
fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Whether `now` is less than `window` after `at`. No clock reading is never within, and
/// neither is a reading EARLIER than `at` (an injected wall clock that stepped back): both
/// records then forget and ask the peer, which is the direction that cannot go stale.
fn within(at: Time, now: Option<Time>, window: std::time::Duration) -> bool {
    now.and_then(|now| now.as_millis().checked_sub(at.as_millis()))
        .is_some_and(|elapsed| elapsed < millis(window))
}

/// The contracts a mount has read from its peer, per forwarded name, each trusted for
/// [`CONTRACT_TTL`] (ledger #1577).
///
/// Core memoizes an endpoint's floor per endpoint ALLOCATION, and a mount hands out a fresh
/// [`ForwardingEndpoint`] per resolution (it must: each one carries the request it forwards),
/// so core's memo never hits and every mounted read called `describe()`, which forwarded a
/// `Meta` to the peer. Measured with the ledger #1570 harness: exactly one `Meta` per read,
/// half the round trips of a mounted read once every mounted answer became `Always`
/// (ledger #92). This memo is the mount's own, keyed by the forwarded NAME, so it hits
/// across the endpoints it hands out. What it guarantees, and why that is safe, is stated
/// on [`CONTRACT_TTL`].
struct ContractMemo {
    ttl: std::time::Duration,
    entries: Mutex<HashMap<String, (Time, Description)>>,
}

impl ContractMemo {
    fn new(ttl: std::time::Duration) -> Self {
        ContractMemo {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Time, Description)>> {
        // A poisoned lock must cost knowledge, never a describe: keep using the map.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The contract read for `target` less than the TTL ago by the mount's clock `now`, if
    /// there is one.
    fn get(&self, target: &str, now: Option<Time>) -> Option<Description> {
        let mut entries = self.lock();
        match entries.get(target) {
            Some((at, description)) if within(*at, now, self.ttl) => Some(description.clone()),
            Some(_) => {
                entries.remove(target);
                None
            }
            None => None,
        }
    }

    /// Remember the contract the peer just declared for `target`, read at `now` by the
    /// mount's clock. With no clock (wasm32 with none installed, see [`default_clock`])
    /// nothing is remembered: there is no TTL to measure, so every describe asks the peer,
    /// as a zero TTL does.
    fn put(&self, target: &str, description: &Description, now: Option<Time>) {
        if self.ttl.is_zero() {
            return;
        }
        let Some(now) = now else {
            return;
        };
        let mut entries = self.lock();
        if entries.len() >= CONTRACT_MEMO_BOUND && !entries.contains_key(target) {
            let ttl = self.ttl;
            entries.retain(|_, (at, _)| within(*at, Some(now), ttl));
            let mut excess = entries
                .len()
                .saturating_sub(CONTRACT_MEMO_BOUND - CONTRACT_MEMO_BOUND / 4);
            entries.retain(|_, _| {
                if excess == 0 {
                    return true;
                }
                excess -= 1;
                false
            });
        }
        entries.insert(target.to_string(), (now, description.clone()));
    }

    /// Stop trusting what was read for `target`.
    fn forget(&self, target: &str) {
        self.lock().remove(target);
    }

    /// Stop trusting anything read so far.
    fn clear(&self) {
        self.lock().clear();
    }
}

/// The IRI a mount claims for ITSELF, so a mount that could not enumerate its peer has
/// somewhere to say so: `{prefix}:ikigai:mount-unavailable`.
///
/// ★ **Why an IRI and not just a log line.** The requirement is that a degraded manifold
/// NAME the peer that did not answer, in a form a caller can act on — and a caller of
/// `urn:kernel:actions` reads a list of actions, not a terminal. So the statement has to be
/// a row in that list, which means it has to be an entry, which means it has to be an IRI
/// that resolves to something with a contract. It does: sourcing it returns the diagnosis.
///
/// ★ **And why INSIDE the mount's own prefix**, which looks like namespace pollution and is
/// the load-bearing choice. A host wraps a mount in whatever it needs — `ikigai-embedded`'s
/// `--prefer` puts a `PrefixGuard` in front of a `Failover`, and that guard answers `Miss`
/// for every IRI outside the prefix before the mount is ever consulted. A status IRI in a
/// neutral namespace therefore ENUMERATED (the guard passes entries straight through) and
/// then failed to RESOLVE, so the row appeared in `urn:kernel:catalog` and vanished from
/// `urn:kernel:actions` — visible in the listing nobody automates against, absent from the
/// one an agent reads. Measured on plasma, 2026-09-17. Inside the prefix it travels through
/// every prefix-scoped wrapper there is or will be, in this host and in any other, without
/// those wrappers knowing anything about it. The cost is that a peer resource of this exact
/// name would be shadowed by the mount; that is a trade taken deliberately.
///
/// It is keyed on the PREFIX rather than on the peer because the prefix is the namespace
/// whose contents are missing — plasma mounts one `ikigai-gonk` twice, and one row for two
/// silenced namespaces would under-report exactly the case this exists for. The peer is
/// named in the description instead, where the text can carry a socket path unmangled.
fn mount_status_iri(prefix: &str) -> String {
    let stem = prefix.trim_end_matches(':');
    format!("{stem}:ikigai:mount-unavailable")
}

/// The endpoint `urn:ikigai:mount:{slug}:unavailable` resolves to: a real, local,
/// capability-free resource whose whole content is *which peer did not answer, and why*.
///
/// It declares a `Source` action deliberately. A [`Description`] with no actions produces
/// no rows in `select_actions`, so a contract-only placeholder would appear in
/// `urn:kernel:catalog` and be **invisible in `urn:kernel:actions`** — which is the
/// resource an agent reads, and the resource #404 was about. Declaring the verb it really
/// serves is also just the recipe: declared capabilities equal enforced capabilities, and
/// this one needs none.
struct MountUnavailable {
    /// The mount's local prefix — the namespace whose contents are missing.
    prefix: String,
    /// The mount's origin label (`ipc:~/.ikigai/gonk.sock`, `quic:plasma:4433`).
    origin: String,
    /// The transport's own words for the failure, when this kernel holds a record of one.
    ///
    /// `None` is the honest answer to a caller that reached this row without an
    /// enumeration having failed *in this process* — a one-shot `ikigai -c` that read the
    /// IRI out of a manifold some earlier process printed. Saying "it did not answer"
    /// there would be a claim this kernel cannot support.
    reason: Option<String>,
}

impl MountUnavailable {
    fn summary(&self) -> String {
        match &self.reason {
            Some(reason) => format!(
                "`{}` is mounted from {}, and that peer did not answer an enumeration: {}. \
                 The resources under `{}` are NOT listed in this catalog — they are unknown \
                 here, not absent. This row is the statement that they are missing.",
                self.prefix, self.origin, reason, self.prefix
            ),
            None => format!(
                "`{}` is mounted from {}. This row exists to say so when that peer does not \
                 answer an enumeration, and this kernel holds no current record of one: \
                 either the peer has answered since, or nothing has asked it yet in this \
                 process. Enumerate (`source urn:kernel:catalog`) and read this again.",
                self.prefix, self.origin
            ),
        }
    }
}

#[async_trait]
impl Endpoint for MountUnavailable {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation, Error> {
        // The default expiry is `Always` — never cached — and that is what this wants:
        // the peer may be back before this line is read again, and a cached
        // "unavailable" is exactly the lie the row exists to prevent. Stated rather
        // than left implicit, because "don't cache this" is the load-bearing part.
        Ok(
            Representation::new(ikigai_core::ReprType::new("text/plain"), self.summary())
                .with_expiry(Expiry::Always),
        )
    }

    fn name(&self) -> &str {
        "mount-unavailable"
    }

    fn describe(&self) -> Description {
        Description::new("mount-unavailable")
            .title(format!("mount unavailable: {}", self.origin))
            .summary(self.summary())
            .verb(Verb::Source)
            .output("text/plain")
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
    /// What this mount has learned about its peer's ability to describe itself, shared
    /// with every [`ForwardingEndpoint`] it hands out. See [`DESCRIBE_COOLDOWN`].
    health: Arc<DescribeHealth>,
    /// The contracts this mount has read from its peer, shared with every
    /// [`ForwardingEndpoint`] it hands out. See [`ContractMemo`].
    contracts: Arc<ContractMemo>,
    /// What `health` and `contracts` are measured on. See [`default_clock`].
    clock: Option<Arc<dyn Clock>>,
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
            health: Arc::new(DescribeHealth::default()),
            contracts: Arc::new(ContractMemo::new(CONTRACT_TTL)),
            clock: default_clock(),
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
            health: Arc::new(DescribeHealth::default()),
            contracts: Arc::new(ContractMemo::new(CONTRACT_TTL)),
            clock: default_clock(),
        }
    }

    /// Share this mount's peer-health record through `peers` (builder), so every mount of
    /// the SAME origin reaches one verdict about that peer instead of each paying its own
    /// deadline. A composer that builds a kernel's mounts calls this with one
    /// [`PeerHealth`]; a mount built alone keeps a private record and behaves as before.
    ///
    /// Call it at construction. The record is captured by every forwarding endpoint the
    /// mount hands out, so replacing it later would leave endpoints consulting the old one.
    pub fn sharing(mut self, peers: &PeerHealth) -> Self {
        self.health = peers.get(&self.origin);
        self
    }

    /// How long this mount trusts a contract it read from its peer (builder; default
    /// [`CONTRACT_TTL`]). `Duration::ZERO` asks the peer on every describe, as before
    /// ledger #1577. See [`CONTRACT_TTL`] for what the bound guarantees.
    pub fn contract_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.contracts = Arc::new(ContractMemo::new(ttl));
        self
    }

    /// Measure the contract TTL and the describe cooldown on `clock` (builder): give it the
    /// clock the host gave its kernel. On a native target the default is a monotonic clock;
    /// on wasm32 there is none (reading platform time there panics), so without this a
    /// browser host's mount keeps no contract memo and no cooldown, and asks the peer on
    /// every describe (ledger #2194).
    ///
    /// Call it at construction, like [`sharing`](Self::sharing): a record already made was
    /// stamped by the clock it replaces.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// What this mount's clock reads, if it has one.
    fn now(&self) -> Option<Time> {
        self.clock.as_ref().map(|clock| clock.now())
    }

    /// The one row a mount contributes when its peer did not answer an enumeration:
    /// the mount's own status IRI (see [`mount_status_iri`]), tagged with the origin so a
    /// federated `list` shows it exactly where the peer's rows would have been.
    ///
    /// The stderr note is the second half, and it is deduplicated for the same reason
    /// [`unavailable`]'s is: `entries()` is called per catalog walk, not once per mount, so
    /// an un-deduplicated line prints on every `list` through a degraded mount — which is
    /// not loud, it is noise that gets filtered out. Keyed by (prefix, reason), so a peer
    /// that later fails differently still says so.
    fn unenumerated(&self, reason: &str) -> SpaceEntry {
        let once = format!("{}\u{1}{reason}", self.prefix);
        let first = {
            static SEEN: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
            // A poisoned lock must not take down an enumeration: treat it as "already said".
            SEEN.lock()
                .map(|mut seen| seen.insert(once))
                .unwrap_or(false)
        };
        if first {
            eprintln!(
                "ikigai: {} did not answer an enumeration — {reason}. The resources under \
                 `{}` are missing from this catalog and manifold; they are unknown, not \
                 absent. `source {}` says so, and `describe.timeout` (seconds, config home) \
                 is the bound that was reached.",
                self.origin,
                self.prefix,
                mount_status_iri(&self.prefix)
            );
        }
        SpaceEntry::new(mount_status_iri(&self.prefix), "mount-unavailable")
            .with_origin(&self.origin)
    }
}

impl Space for MountedRemote {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        // The mount's own status resource, claimed OUTSIDE the prefix on purpose: it must
        // not be forwarded (the peer it describes is the one that is not answering), and
        // it must not sit inside a namespace the peer owns, where a real remote resource
        // could collide with it.
        if request.target.as_str() == mount_status_iri(&self.prefix) {
            return Resolution::Hit(Resolved::new(
                Arc::new(MountUnavailable {
                    prefix: self.prefix.clone(),
                    origin: self.origin.clone(),
                    reason: self.health.failing(self.now()),
                }),
                Bindings::new(),
            ));
        }
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
        //
        // ★ A MOUNT REWRITES AND STILL REPORTS NO CANONICAL — which is why this is
        // the bare `Resolved::new` and not `.with_canonical(..)`. `Alias` mode just
        // rewrote the target above (`urn:edge:foo` → `urn:foo`), so a mechanical
        // sweep would forward that as `canonical` — and it would be wrong.
        // `Resolved::canonical` means "the same resource under another name IN
        // THIS KERNEL'S NAMESPACE": the kernel adopts it as the cache id and the
        // golden-thread key. A mount's rewrite crosses a namespace boundary —
        // `urn:foo` is meaningful in the REMOTE, and this kernel may serve an
        // entirely unrelated local `urn:foo`. Reporting it would fuse two
        // different resources into one cache entry and one thread. The stripped
        // name is a wire address, not a local name, so it stays inside the
        // forwarded request and never reaches the kernel's identity computation.
        //
        // If a mounted name and a local name should ever share identity, that
        // needs a concept that carries ORIGIN alongside the name; `canonical`,
        // which is a bare `Iri`, cannot express it.
        ForwardingEndpoint {
            resolver: Arc::clone(&self.resolver),
            name: self.names.name_for(&forwarded.target),
            origin: Some(self.origin.clone()),
            health: Some(Arc::clone(&self.health)),
            request: forwarded,
            contract: None,
            contracts: Arc::clone(&self.contracts),
            clock: self.clock.clone(),
        }
        .resolution(request)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // A peer already known to be silent is not asked again for the cooldown — a
        // manifold read must cost ONE deadline per unhealthy mount, not one per attempt.
        if let Some(reason) = self.health.failing(self.now()) {
            return Some(vec![self.unenumerated(&reason)]);
        }
        let entries = match self.resolver.try_entries() {
            Ok(Some(entries)) => {
                self.health.clear();
                // A walk describes every row next: read them from the peer (see
                // `ContractMemo`), so a manifold read is as fresh as it was before the memo.
                self.contracts.clear();
                entries
            }
            // The peer does not enumerate at all. Nothing is missing that it would have
            // named, so there is nothing to say — this is the old `None` and it is right.
            Ok(None) => return None,
            // ★ It should have answered and did not. Returning `None` here is what made a
            // silent peer read like an empty one; instead the mount contributes exactly
            // one row, which says whose resources are missing and why.
            Err(error) => {
                self.health.record(&error, self.now());
                return Some(vec![self.unenumerated(&error.to_string())]);
            }
        };
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
    /// Every resolver that can carry authority overrides this: the in-process kernel
    /// enforces the capability (which is what lets the REPL's `cap` command attenuate a
    /// local session), and both wire resolvers send it (`Call::IssueAs`), where the server
    /// clamps it to the principal the channel authenticated. A WRAPPER (a lazy dial, an
    /// off-thread hop, a test double) overrides it by forwarding the capability it is
    /// handed to the resolver it wraps.
    ///
    /// ★ **The default FAILS CLOSED** (ledger #849). It serves the root capability through
    /// [`issue`](Resolver::issue), and refuses any other with a typed
    /// [`Denied`](Error::Denied) naming the implementing type. It used to ignore the
    /// capability and call `issue` for every capability, on the reasoning that a wire
    /// resolver could not carry one yet. That stopped being true when capability-on-the-wire
    /// shipped, and the default went on silently PROMOTING the caller to the peer's own
    /// default authority: `ikigai-web`'s prefer-mount wrapper overrode only `issue`, so
    /// every scope a peer checks at runtime (gonk's per-graph SPARQL union, a browse root,
    /// a store graph) saw root. Root is served because `issue` IS root's resolution, so
    /// nothing is widened by it.
    ///
    /// ```
    /// use ikigai_core::{Capability, Error, Iri, Representation, Request, SpaceEntry, Verb};
    /// use ikigai_resolve::{CacheStatus, Resolver};
    ///
    /// /// Overrides `issue` only, so it says nothing about what it does with a capability.
    /// struct IssueOnly;
    /// impl Resolver for IssueOnly {
    ///     fn issue(&self, _: Request) -> Result<(Representation, CacheStatus), Error> {
    ///         Err(Error::Endpoint("never reached under a narrowed capability".into()))
    ///     }
    ///     fn is_cached(&self, _: &Request, _: &Capability) -> bool { false }
    ///     fn entries(&self) -> Option<Vec<SpaceEntry>> { None }
    /// }
    ///
    /// let read = Request::new(Verb::Source, Iri::parse("urn:x").unwrap());
    /// let narrowed = Capability::scoped(["urn:cap:x"]);
    /// match IssueOnly.issue_as(read, &narrowed) {
    ///     Err(Error::Denied(message)) => assert!(message.contains("IssueOnly")),
    ///     other => panic!("a resolver that cannot carry a capability refuses it: {other:?}"),
    /// }
    /// ```
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        if capability.is_root() {
            return self.issue(request);
        }
        Err(Error::Denied(format!(
            "{} cannot carry a narrowed capability: it does not override \
             `Resolver::issue_as`, and resolving through `issue` would answer under the \
             peer's own authority instead of the caller's. Forward the capability in an \
             `issue_as` override",
            std::any::type_name::<Self>()
        )))
    }

    /// Async resolution under an explicit `capability` — what the engine `await`s
    /// when it drives a stage on the scheduler, so a *spawned* branch (fork/map)
    /// parks rather than blocking a worker thread. The default runs the synchronous
    /// [`issue_as`](Resolver::issue_as) (correct for a resolver that hides a
    /// `block_on`/wire round-trip), so it inherits that method's refusal of a capability
    /// the resolver cannot carry; the in-process kernel overrides it to await its
    /// own async issue with no `block_on`, which is what makes concurrent fan-out
    /// deadlock-free under a bounded pool.
    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as(request, capability)
    }

    /// [`issue_as`](Resolver::issue_as), carrying what is left of the caller's RUN
    /// (ledger #1546, wire v9): its retry pool's remaining count and its deadline as time
    /// left. A mount calls this with [`RunContext::of`] its invocation, so a peer bounds the
    /// forwarded sub-request by the same run the door minted here. The default DROPS the
    /// context and resolves as [`issue_as`](Resolver::issue_as): the resolver cannot carry
    /// it, and the peer then runs under its own policy, which is what every peer did before
    /// v9. The two wire resolvers override it, and send the context only to a peer that
    /// negotiated v9 (the wire's `Call::for_peer` drops it for an older one). A
    /// WRAPPER forwards it like [`issue_as`](Resolver::issue_as), or it silently drops the
    /// context, the way the chain methods warn about below.
    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        let _ = run;
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

    /// Resolve **in a resolution chain** ([`Scope`]): the corridors it injects are consulted
    /// ahead of the root for this request and everything it gives rise to, and a temporal
    /// corridor's clock is the one [`Invocation::now`] reads. `incoming` is an upstream pipe
    /// stage's [`Provenance`], folded in exactly as
    /// [`issue_as_async_with_incoming`](Resolver::issue_as_async_with_incoming) does.
    ///
    /// ★ **The default REFUSES a non-empty chain** — it never resolves one as though it were
    /// empty. A chain is spaces and a clock held in this process; no transport carries either,
    /// so a wire resolver asked for `as-of=` would otherwise answer with the peer's LIVE time
    /// and nothing would say so. That is the failure an as-of resolution exists to rule out.
    /// The empty chain delegates to the unscoped methods, so an implementor that predates
    /// this is byte-identical for every request that carries no chain. The in-process kernel
    /// overrides it ([`Kernel::issue_in`] / [`Kernel::issue_with_incoming_in`]).
    async fn issue_as_async_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
    ) -> Result<(Representation, CacheStatus), Error> {
        if !scope.is_empty() {
            return Err(Error::Endpoint(format!(
                "cannot resolve in the chain `{scope}` over {}: a resolution chain is spaces \
                 and a clock held in this process, and no transport carries either — resolve \
                 against an in-process kernel",
                self.transport()
            )));
        }
        match incoming {
            Some(provenance) => {
                self.issue_as_async_with_incoming(request, capability, provenance)
                    .await
            }
            None => self.issue_as_async(request, capability).await,
        }
    }

    /// [`is_cached`](Resolver::is_cached) in a resolution chain — the cache is partitioned by
    /// the chain's fingerprint, so "cached" is a claim about one chain. The default answers
    /// `false` for any non-empty chain (it cannot resolve one, so nothing is cached in it) and
    /// delegates for the empty chain; the in-process kernel overrides it
    /// ([`Kernel::is_cached_in`]).
    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        scope.is_empty() && self.is_cached(request, capability)
    }

    /// Install an execution [`Tracer`] for the next resolution — the `trace` command
    /// records one real `source` to show which worker each node ran on. Default
    /// no-op: a wire resolver can't yet trace the remote kernel; the in-process
    /// kernel forwards to [`Kernel::set_tracer`]. Paired with [`Kernel::clear_tracer`].
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
    ///
    /// ⚠ This signature cannot tell "does not enumerate" from "failed to enumerate" —
    /// prefer [`try_entries`](Self::try_entries) wherever the difference matters, which
    /// is everywhere a caller would otherwise report a peer's silence as an empty peer.
    fn entries(&self) -> Option<Vec<SpaceEntry>>;

    /// Enumerate, keeping the failure.
    ///
    /// * `Ok(Some(entries))` — the peer answered.
    /// * `Ok(None)` — this resolver does not enumerate at all (a rewrite, a peer with no
    ///   catalog). Nothing is wrong and nothing is missing.
    /// * `Err(error)` — it should have answered and did not: a deadline, a dead socket, a
    ///   refusal. **Resources exist that are not in the returned catalog.**
    ///
    /// ★ That third case is the whole reason this method exists. [`entries`](Self::entries)
    /// collapses it into `None`, and a `None` mount contributes nothing to the catalog —
    /// so a peer that went silent reads exactly like a peer that has nothing, and the
    /// manifold quietly UNDER-OFFERS. A caller then concludes a capability does not exist
    /// when the truth is that nobody asked successfully. A bound must refuse, not truncate;
    /// this is the channel the refusal travels on.
    ///
    /// The default preserves the old lossy behaviour, so an implementor that predates this
    /// still compiles — at the cost of reporting every failure as `Ok(None)`.
    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        Ok(self.entries())
    }

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

    async fn issue_as_async_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
    ) -> Result<(Representation, CacheStatus), Error> {
        // The probe keys on the chain too: an entry cached in one chain is not a hit in
        // another, and the empty chain's probe is `is_cached` exactly.
        let was_cached = Kernel::is_cached_in(self, &request, capability, &scope);
        let representation = match incoming {
            Some(provenance) => {
                Kernel::issue_with_incoming_in(self, request, capability, provenance, scope).await?
            }
            None => Kernel::issue_in(self, request, capability, scope).await?,
        };
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        Kernel::is_cached_in(self, request, capability, scope)
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

/// What a caller's run has LEFT, carried across a mount to the peer that serves the
/// sub-request (ledger #1546, wire v9): the remaining count of its retry pool and the
/// time to its deadline. Both are relative, so two peers whose clocks disagree still mean
/// the same thing; the peer adds the time left to its own `now`. A `None` half says the
/// run has none of that, and the peer's own policy decides.
///
/// ```
/// use std::time::Duration;
/// use ikigai_resolve::RunContext;
///
/// let run = RunContext { retries: Some(1), time_left: Some(Duration::from_millis(1_500)) };
/// assert!(run.carries_context());
/// assert_eq!(run.time_left_millis(), Some(1_500));
/// // A sub-millisecond remainder rounds UP, so it is not read as expired.
/// let edge = RunContext { retries: None, time_left: Some(Duration::from_micros(1_200)) };
/// assert_eq!(edge.time_left_millis(), Some(2));
/// assert!(!RunContext::default().carries_context());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunContext {
    /// Re-issues the run has left anywhere below it, `None` under no pool.
    pub retries: Option<u32>,
    /// Time to the run's deadline, zero once it has passed, `None` under no deadline.
    pub time_left: Option<std::time::Duration>,
}

impl RunContext {
    /// The run `inv` is part of, as a mount reads it: the pool's
    /// [`remaining`](ikigai_core::RetryBudget::remaining) count and
    /// [`Invocation::time_left`].
    pub fn of(inv: &Invocation<'_>) -> Self {
        RunContext {
            retries: inv.retry_budget().map(|pool| pool.remaining()),
            time_left: inv.time_left(),
        }
    }

    /// Whether there is anything to carry: with neither half, a plain `issue_as` says it all.
    pub fn carries_context(&self) -> bool {
        self.retries.is_some() || self.time_left.is_some()
    }

    /// The time left in whole milliseconds, rounded UP: the wire's form.
    pub fn time_left_millis(&self) -> Option<u64> {
        self.time_left.map(|left| {
            let whole = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
            if left.subsec_nanos() % 1_000_000 == 0 {
                whole
            } else {
                whole.saturating_add(1)
            }
        })
    }
}

/// Resolve `request` on `kernel` under a caller's `context` (the retry pool limit and the
/// deadline a wire server rebuilt from a `Call::IssueWith`), with the same cache-status
/// probe as [`Resolver::issue_as`]. The kernel narrows the pool to what `capability` is
/// entitled to, and drops it on a kernel with no retry budget.
pub fn issue_as_with_context(
    kernel: &Kernel,
    request: Request,
    capability: &Capability,
    context: IssueContext,
) -> Result<(Representation, CacheStatus), Error> {
    let was_cached = Kernel::is_cached(kernel, &request, capability);
    let representation = block_on(kernel.issue_with_context(request, capability, context))?;
    let status = cache_status(was_cached, &representation);
    Ok((representation, status))
}

/// [`issue_as_with_context`] recording the resolution into `tracer`, as
/// [`issue_traced_as`] does: the path a wire server takes for a `Call::IssueWith` whose
/// caller is recording.
pub fn issue_traced_as_with_context(
    kernel: &Kernel,
    request: Request,
    capability: &Capability,
    tracer: Arc<dyn Tracer>,
    context: IssueContext,
) -> Result<(Representation, CacheStatus), Error> {
    let was_cached = Kernel::is_cached(kernel, &request, capability);
    let representation =
        block_on(kernel.issue_traced_with_context(request, capability, tracer, context))?;
    let status = cache_status(was_cached, &representation);
    Ok((representation, status))
}

/// Resolve `request` on `kernel` recording the resolution's spans into `tracer`,
/// with the same cache-status probe as [`Resolver::issue_as`]. This is the
/// **per-call** traced path a wire server dispatches `Call::IssueTraced` on:
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

    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        // Forwarded for the same reason as the chain methods: the default drops the run.
        (**self).issue_as_in_run(request, capability, run)
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

    // ⚠ Both chain methods are FORWARDED, for the reason `try_entries` below spells out: a
    // defaulted method an `Arc` does not forward is silently REPLACED by the default. Here
    // that default refuses every non-empty chain, and every engine holds its resolver as an
    // `Arc` — so without these two lines `as-of=` would be refused on the in-process kernel
    // that implements it.
    async fn issue_as_async_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
    ) -> Result<(Representation, CacheStatus), Error> {
        (**self)
            .issue_as_async_in(request, capability, incoming, scope)
            .await
    }

    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        (**self).is_cached_in(request, capability, scope)
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

    /// ⚠ **A DEFAULTED method that is not forwarded here is silently REPLACED, not
    /// inherited** — the same trap the `issue_as_async_with_incoming` arm above records,
    /// and it cost this arc a debugging round. Without this line, `Arc<dyn Resolver>` took
    /// the trait's default (`Ok(self.entries())`), which collapses a transport failure back
    /// into `Ok(None)`: every mount holds its resolver as an `Arc`, so the error channel
    /// existed, compiled, was implemented on both transports — and reached nobody.
    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        (**self).try_entries()
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

    /// Wire v9 (ledger #1546): a mount forwards the RUN's context, what its invocation
    /// says is left of the retry pool and of the deadline, through
    /// `Resolver::issue_as_in_run`, so the peer bounds the sub-request by the run the
    /// door minted here. Without a door context the run is the kernel's own: root's
    /// ceiling and no deadline.
    #[test]
    fn a_mount_forwards_the_runs_context_to_its_resolver() {
        struct Recording {
            seen: Mutex<Vec<RunContext>>,
        }
        impl Resolver for Recording {
            fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
                let bytes = if request.verb == Verb::Meta {
                    let description = Description::new("thing").verb(Verb::Source);
                    serde_json::to_vec(&description).expect("description serializes")
                } else {
                    b"ok".to_vec()
                };
                Ok((
                    Representation::new(ReprType::new("application/json"), bytes),
                    CacheStatus::Uncacheable,
                ))
            }
            fn issue_as_in_run(
                &self,
                request: Request,
                capability: &Capability,
                run: &RunContext,
            ) -> Result<(Representation, CacheStatus), Error> {
                self.seen.lock().unwrap().push(*run);
                self.issue_as(request, capability)
            }
            fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
                false
            }
            fn entries(&self) -> Option<Vec<SpaceEntry>> {
                None
            }
        }
        let recording = Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
        });
        let kernel = Kernel::new(Arc::new(MountedRemote::new(
            recording.clone(),
            "urn:remote:",
            "test://peer",
        )))
        .with_retry_budget(0, 3)
        .with_clock(Arc::new(ikigai_core::FixedClock::at(1_000)));
        let read = Request::new(Verb::Source, Iri::parse("urn:remote:thing").unwrap());
        block_on(kernel.issue(read.clone(), &Capability::root())).expect("forwarded");
        let run = IssueContext::new()
            .with_retry_limit(1)
            .with_not_after(ikigai_core::Time::from_millis(1_250));
        block_on(kernel.issue_with_context(read, &Capability::root(), run)).expect("forwarded");
        let seen = recording.seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            [
                RunContext {
                    retries: Some(3),
                    time_left: None,
                },
                RunContext {
                    retries: Some(1),
                    time_left: Some(std::time::Duration::from_millis(250)),
                },
            ],
            "the forward carries what the run has left"
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

    /// A peer that binds ONE name and says so the way a real kernel does — a `Meta` of
    /// anything else comes back `Unresolved` — counting the `Meta` forwards it serves.
    #[derive(Default)]
    struct OneNamePeer {
        metas: std::sync::atomic::AtomicUsize,
    }

    impl Resolver for OneNamePeer {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            if request.target.as_str() != "urn:status" {
                return Err(Error::Unresolved(request.target));
            }
            let bytes = if request.verb == Verb::Meta {
                self.metas.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                serde_json::to_vec(&Description::new("status").verb(Verb::Source))
                    .expect("description serializes")
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
            Some(vec![SpaceEntry::new("urn:status", "status")])
        }
    }

    fn meta(target: &str) -> Request {
        Request::new(Verb::Meta, ikigai_core::Iri::parse(target).unwrap())
            .with_arg("as", ArgRef::Inline(b"text/turtle".to_vec()))
    }

    /// Ledger #1146: `describe` of a mounted name the peer does not bind printed a
    /// "contract unavailable" placeholder and exited 0. It is now the kernel's own
    /// `Unresolved`, the same error an unbound LOCAL name gets — through an alias mount,
    /// an override mount and a bare `RemoteSpace` alike.
    #[test]
    fn a_meta_of_a_name_the_peer_does_not_bind_is_unresolved() {
        let spaces: Vec<(&str, Arc<dyn Space>)> = vec![
            (
                "urn:gk:nope",
                Arc::new(MountedRemote::new(
                    Arc::new(OneNamePeer::default()),
                    "urn:gk:",
                    "test://peer",
                )),
            ),
            (
                "urn:nope",
                Arc::new(MountedRemote::overriding(
                    Arc::new(OneNamePeer::default()),
                    "urn:",
                    "test://peer",
                )),
            ),
            (
                "urn:nope",
                Arc::new(RemoteSpace::new(Arc::new(OneNamePeer::default()))),
            ),
        ];
        for (target, space) in spaces {
            let kernel = Kernel::new(space);
            let error = block_on(kernel.issue(meta(target), &Capability::root()))
                .expect_err("an unbound mounted name must not describe");
            assert!(
                matches!(&error, Error::Unresolved(iri) if iri.as_str() == target),
                "`{target}`: expected Unresolved, got {error:?}"
            );
            assert_eq!(
                error.to_string(),
                format!("no endpoint resolved for {target}"),
                "byte-identical to an unbound local name"
            );
            let iri = ikigai_core::Iri::parse(target).unwrap();
            assert!(
                kernel.describe(&iri).is_none(),
                "`{target}` has no contract"
            );
        }
    }

    /// The bound half: the peer's own contract comes through, and the forward moved from
    /// `describe` to `resolve` rather than being paid twice — ONE `Meta` per description.
    #[test]
    fn a_meta_of_a_bound_mounted_name_forwards_once() {
        let peer = Arc::new(OneNamePeer::default());
        let mounted = MountedRemote::new(
            Arc::clone(&peer) as Arc<dyn Resolver>,
            "urn:gk:",
            "test://peer",
        );
        let kernel = Kernel::new(Arc::new(mounted));
        let iri = ikigai_core::Iri::parse("urn:gk:status").unwrap();
        let description = kernel.describe(&iri).expect("the peer binds it");
        assert_eq!(description.id, "status");
        assert_eq!(
            peer.metas.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one forward per describe"
        );
    }

    /// An OVERRIDE claims its namespace even over a local binding of the same name, so
    /// a name the PEER does not bind must not fall through to the local one: describing
    /// the local contract while every invoke goes to the peer would be a lie.
    #[test]
    fn an_override_does_not_fall_through_to_a_local_contract() {
        let local = EndpointSpace::new().bind(
            Exact::new("urn:nope"),
            FnEndpoint::new("local", |_inv| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"local".to_vec(),
                ))
            })
            .with_description(Description::new("local").verb(Verb::Source)),
        );
        let root = ikigai_core::Fallback::new(vec![
            Arc::new(MountedRemote::overriding(
                Arc::new(OneNamePeer::default()),
                "urn:",
                "test://peer",
            )) as Arc<dyn Space>,
            Arc::new(local) as Arc<dyn Space>,
        ]);
        let kernel = Kernel::new(Arc::new(root));
        let error = block_on(kernel.issue(meta("urn:nope"), &Capability::root()))
            .expect_err("the override's peer does not bind it");
        assert!(matches!(error, Error::Unresolved(_)), "got {error:?}");
    }

    /// A peer that ANSWERS but not with a contract is still the placeholder — "unknown",
    /// not "absent" — because only the peer's `Unresolved` says nothing binds the name.
    #[test]
    fn a_peer_that_cannot_describe_still_gets_the_placeholder() {
        struct Refusing;
        impl Resolver for Refusing {
            fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
                Err(Error::Endpoint(format!(
                    "no Meta renderer for {}",
                    request.target
                )))
            }
            fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
                false
            }
            fn entries(&self) -> Option<Vec<SpaceEntry>> {
                None
            }
        }
        let kernel = Kernel::new(Arc::new(MountedRemote::new(
            Arc::new(Refusing),
            "urn:gk:",
            "test://peer",
        )));
        let iri = ikigai_core::Iri::parse("urn:gk:thing").unwrap();
        let description = kernel.describe(&iri).expect("a placeholder, not a miss");
        assert_eq!(description.id, "remote");
        assert_eq!(description.title, "contract unavailable");
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

    // ---- Resolution chains (the engine's `as-of=`, ledger #532) ---------------------------

    fn doc_corridor() -> Scope {
        Scope::empty().with_named(
            Iri::parse("urn:ctx:doc:7").unwrap(),
            Arc::new(EndpointSpace::new().bind(
                Exact::new("urn:open"),
                FnEndpoint::new("in-the-corridor", |_inv| {
                    Ok(
                        Representation::new(ReprType::new("text/plain"), b"corridor".to_vec())
                            .cacheable(),
                    )
                }),
            )),
        )
    }

    fn open() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:open").unwrap())
    }

    /// ★ A resolver that cannot carry a chain REFUSES one rather than resolving as if it were
    /// empty — which for `as-of=` over a wire would be the peer's live answer, unmarked.
    #[test]
    fn a_resolver_that_cannot_carry_a_chain_refuses_one() {
        let remote = FakeRemote {
            entries: Vec::new(),
            description: Description::new("fake"),
        };
        let cap = Capability::root();
        let refused = block_on(remote.issue_as_async_in(open(), &cap, None, doc_corridor()))
            .expect_err("a non-empty chain must not be dropped on the floor");
        assert!(
            refused.to_string().contains("urn:ctx:doc:7 root"),
            "the refusal names the chain: {refused}"
        );
        assert!(!remote.is_cached_in(&open(), &cap, &doc_corridor()));
        // The empty chain is the unscoped path, byte for byte.
        let (repr, _) = block_on(remote.issue_as_async_in(open(), &cap, None, Scope::empty()))
            .expect("the empty chain delegates");
        assert_eq!(repr.bytes, b"ok");
    }

    /// The in-process kernel resolves in the chain, through an `Arc` AND through
    /// `Arc<dyn Resolver>` — the shape every engine holds. A forwarding arm missing from the
    /// `Arc` impl would silently fall to the refusing default, and this is where it shows.
    #[test]
    fn the_kernel_resolves_in_a_chain_through_every_arc() {
        let kernel = Arc::new(kernel_with_a_gated_endpoint());
        let cap = Capability::root();
        let (root, _) =
            block_on(kernel.issue_as_async_in(open(), &cap, None, Scope::empty())).expect("root");
        assert_eq!(root.bytes, b"ok");
        let (inside, first) =
            block_on(kernel.issue_as_async_in(open(), &cap, None, doc_corridor()))
                .expect("the corridor shadows the root's door");
        assert_eq!(inside.bytes, b"corridor");
        assert_eq!(first, CacheStatus::Miss);
        assert!(kernel.is_cached_in(&open(), &cap, &doc_corridor()));
        assert!(
            !Resolver::is_cached(&*kernel, &open(), &cap),
            "cached in the chain, not in the root"
        );

        let erased: Arc<dyn Resolver> = kernel;
        let (again, second) =
            block_on(erased.issue_as_async_in(open(), &cap, None, doc_corridor())).unwrap();
        assert_eq!(again.bytes, b"corridor");
        assert_eq!(second, CacheStatus::Hit);
    }

    /// The scope a [`peer_checking_at_runtime`] endpoint demands.
    const SECRET: &str = "urn:cap:secret";

    /// A PEER kernel whose one endpoint checks its scope AT RUNTIME, the way gonk's per-graph
    /// SPARQL union, a browse root and a store graph do: it declares no `requires`, so no
    /// kernel on the path refuses it from the contract, and the only thing standing between a
    /// narrowed caller and the answer is the capability the peer actually receives. It answers
    /// with that capability's scopes, so a test can see exactly what crossed.
    fn peer_checking_at_runtime() -> Arc<Kernel> {
        let space = EndpointSpace::new().bind(
            Exact::new("urn:peer:scoped"),
            FnEndpoint::new("scoped", |inv| {
                if !inv.capability.allows(SECRET) {
                    return Err(Error::Denied(format!("the peer wants {SECRET}")));
                }
                let seen = match inv.capability.scopes() {
                    None => "root".to_string(),
                    Some(scopes) => scopes.iter().cloned().collect::<Vec<_>>().join(" "),
                };
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    seen.into_bytes(),
                ))
            })
            .with_description(Description::new("scoped").verb(Verb::Source)),
        );
        Arc::new(Kernel::new(Arc::new(space)))
    }

    /// Run `work` on a thread of its own, as a wire resolver's round trip effectively is: the
    /// peer kernel's synchronous `Resolver` methods `block_on`, which panics when entered from
    /// the local kernel's own `block_on` further up this stack.
    fn as_if_over_a_wire<T: Send>(work: impl FnOnce() -> T + Send) -> T {
        std::thread::scope(|scope| scope.spawn(work).join().expect("the peer call"))
    }

    /// A wrapper that forwards `issue` and NOTHING ELSE: the shape of `ikigai-web`'s
    /// `LazyIpcResolver` before ikigai-rs/ikigai-web PR 19, which every `prefer` mount went
    /// through. Its `issue` reaches the peer under the peer's default authority, root.
    struct IssueOnly(Arc<Kernel>);

    impl Resolver for IssueOnly {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            as_if_over_a_wire(|| Resolver::issue(&*self.0, request))
        }

        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            Resolver::entries(&*self.0)
        }
    }

    /// The same wrapper done right: it forwards the capability it is handed.
    struct Forwarding(Arc<Kernel>);

    impl Resolver for Forwarding {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            self.issue_as(request, &Capability::root())
        }

        fn issue_as(
            &self,
            request: Request,
            capability: &Capability,
        ) -> Result<(Representation, CacheStatus), Error> {
            as_if_over_a_wire(|| Resolver::issue_as(&*self.0, request, capability))
        }

        fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
            Resolver::is_cached(&*self.0, request, capability)
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            Resolver::entries(&*self.0)
        }
    }

    /// A local kernel with `resolver` mounted over `urn:peer:` — an override mount, which
    /// forwards the IRI unchanged.
    fn mounting(resolver: Arc<dyn Resolver>) -> Kernel {
        Kernel::new(Arc::new(MountedRemote::overriding(
            resolver,
            "urn:peer:",
            "test://peer",
        )))
    }

    fn scoped_read() -> Request {
        Request::new(
            Verb::Source,
            ikigai_core::Iri::parse("urn:peer:scoped").unwrap(),
        )
    }

    /// ★ Ledger #849. A resolver that does not say what it does with a capability must not
    /// be taken to have honored it. Before the fix the trait's `issue_as` default dropped the
    /// capability and called `issue`, so a caller narrowed to `urn:cap:other` read a resource
    /// the peer reserves for `urn:cap:secret`, because the peer was asked as root.
    #[test]
    fn a_resolver_that_forgets_the_capability_refuses_rather_than_resolving_as_root() {
        let local = mounting(Arc::new(IssueOnly(peer_checking_at_runtime())));
        let narrowed = Capability::scoped(["urn:cap:other"]);
        let refused = Resolver::issue_as(&local, scoped_read(), &narrowed)
            .expect_err("a narrowed read through an issue-only wrapper must not succeed");
        assert!(
            matches!(&refused, Error::Denied(message) if message.contains("IssueOnly")),
            "a typed Denied naming the resolver that dropped the capability: {refused:?}"
        );
        // Even a capability that WOULD satisfy the peer is refused: the wrapper cannot carry
        // it, and carrying root instead is the widening this rule exists to stop.
        let sufficient = Capability::scoped([SECRET]);
        assert!(matches!(
            Resolver::issue_as(&local, scoped_read(), &sufficient),
            Err(Error::Denied(_))
        ));
        // Root needs no carrying, so a wrapper that only knows `issue` still serves it.
        let (answer, _) = Resolver::issue_as(&local, scoped_read(), &Capability::root())
            .expect("root through an issue-only wrapper");
        assert_eq!(answer.bytes, b"root");
    }

    /// The check that would have caught #849: drive a mount with a narrowed capability and
    /// assert the PEER saw exactly that capability, not merely that the read succeeded.
    #[test]
    fn a_mount_carries_a_narrowed_capability_to_its_peer() {
        let local = mounting(Arc::new(Forwarding(peer_checking_at_runtime())));
        let narrowed = Capability::scoped([SECRET]);
        let (answer, _) = Resolver::issue_as(&local, scoped_read(), &narrowed)
            .expect("a sufficient narrowed capability crosses the mount");
        assert_eq!(
            String::from_utf8_lossy(&answer.bytes),
            SECRET,
            "the peer saw the caller's capability, not root"
        );
        let refused = Resolver::issue_as(&local, scoped_read(), &Capability::scoped(["urn:x"]));
        assert!(
            matches!(&refused, Err(Error::Denied(message)) if message.contains("the peer wants")),
            "an insufficient one is refused BY THE PEER: {refused:?}"
        );
    }

    /// ★ Ledger #1570: what ledger #92's fix ([`as_held_here`]) costs, and that the kernel
    /// says so. A mounted answer is `Always` on the mounting side whatever the peer said, so a
    /// cacheable LOCAL composite over it is recomputed on every read, and `urn:kernel:uncached`
    /// names why: the mounted read as `declared`, the composite as `dependency <the mounted
    /// name>`. Before the fix the peer's `Never` crossed, the composite cached, and the second
    /// read below computed nothing, so neither row existed.
    ///
    /// The peer endpoint is PURE on purpose. It is where the rule costs most and buys least
    /// (nothing on the peer can go stale), so this is the case to see first when a host asks
    /// why a composite over a mount stopped caching.
    #[test]
    fn a_composite_over_a_mounted_read_is_uncached_and_says_why() {
        use ikigai_core::{AsyncFnEndpoint, Fallback};

        let pure = FnEndpoint::new("pure", |_inv| {
            Ok(Representation::new(ReprType::new("text/plain"), b"pure".to_vec()).cacheable())
        });
        let peer = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:peer:pure"), pure),
        )));
        let over = AsyncFnEndpoint::new("over", |inv: &Invocation<'_>| {
            Box::pin(async move {
                let inner = inv.source(&Iri::parse("urn:peer:pure").unwrap()).await?;
                Ok(Representation::new(ReprType::new("text/plain"), inner.bytes).cacheable())
            })
        });
        let local = Kernel::new(Arc::new(Fallback::new(vec![
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:local:over"), over))
                as Arc<dyn Space>,
            Arc::new(MountedRemote::overriding(
                Arc::new(Forwarding(Arc::clone(&peer))),
                "urn:peer:",
                "test://peer",
            )) as Arc<dyn Space>,
        ])));
        let read = |kernel: &Kernel, iri: &str| {
            let request = Request::new(Verb::Source, Iri::parse(iri).unwrap());
            Resolver::issue_as(kernel, request, &Capability::root())
                .unwrap_or_else(|error| panic!("{iri}: {error}"))
                .0
        };

        // The peer's own answer is cacheable: only the mounting side changes.
        assert_eq!(read(&peer, "urn:peer:pure").expiry, Expiry::Never);
        assert_eq!(read(&local, "urn:peer:pure").expiry, Expiry::Always);
        let first = read(&local, "urn:local:over");
        assert_eq!(first.bytes, b"pure");
        assert_eq!(
            first.expiry,
            Expiry::Always,
            "a cacheable composite over a mounted read is no more cacheable than the mount"
        );
        read(&local, "urn:local:over");

        let readout = String::from_utf8(read(&local, "urn:kernel:uncached").bytes).unwrap();
        let row = |name: &str| {
            readout
                .lines()
                .find(|line| line.split_whitespace().next() == Some(name))
                .unwrap_or_else(|| panic!("no `{name}` row in urn:kernel:uncached:\n{readout}"))
                .to_string()
        };
        let mounted = row("urn:peer:pure");
        assert!(
            mounted.contains("declared"),
            "the mounted read is uncacheable by its own (forwarded) answer: {mounted}"
        );
        let composite = row("urn:local:over");
        assert!(
            composite.contains("dependency urn:peer:pure"),
            "the composite names the mounted read as the reason: {composite}"
        );
        assert!(
            composite.contains("×2"),
            "and it was computed on BOTH reads, not served from the cache: {composite}"
        );
    }

    // ---- ledger #1577: the mount's contract memo ----

    /// A Meta renderer that answers every face with the description as JSON, the face a
    /// mount reads a contract through, so a test peer can be a real kernel with a real floor.
    struct JsonMeta;

    impl ikigai_core::MetaRenderer for JsonMeta {
        fn render(
            &self,
            description: &Description,
            _target: &ReprType,
        ) -> ikigai_core::Result<Representation> {
            let bytes =
                serde_json::to_vec(description).map_err(|e| Error::Endpoint(e.to_string()))?;
            Ok(Representation::new(
                ReprType::new("application/json"),
                bytes,
            ))
        }
    }

    /// A peer's root whose bindings can be swapped, the way an upgraded or rebound peer's are.
    struct Swappable(Mutex<Arc<dyn Space>>);

    impl Space for Swappable {
        fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
            let inner = Arc::clone(&self.0.lock().unwrap());
            inner.resolve(request, scope)
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            let inner = Arc::clone(&self.0.lock().unwrap());
            inner.entries()
        }
    }

    /// `urn:peer:doc`, a Source that requires `requires` when it is given.
    fn doc_space(requires: Option<&str>) -> Arc<dyn Space> {
        let mut description = Description::new("doc").verb(Verb::Source);
        if let Some(scope) = requires {
            description = description.requires(scope);
        }
        let doc = FnEndpoint::new("doc", |_inv| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"doc".to_vec(),
            ))
        })
        .with_description(description);
        Arc::new(EndpointSpace::new().bind(Exact::new("urn:peer:doc"), doc))
    }

    /// A peer kernel serving [`doc_space`], with the handle that rebinds it.
    fn swappable_peer(requires: Option<&str>) -> (Arc<Swappable>, Arc<Kernel>) {
        let space = Arc::new(Swappable(Mutex::new(doc_space(requires))));
        let kernel =
            Kernel::with_meta_renderer(Arc::clone(&space) as Arc<dyn Space>, Arc::new(JsonMeta));
        (space, Arc::new(kernel))
    }

    /// Change what the peer binds, and tell it so (its own floor memo forgets the old one).
    fn rebind(space: &Swappable, peer: &Kernel, now: Arc<dyn Space>) {
        *space.0.lock().unwrap() = now;
        peer.bindings_changed();
    }

    /// Counts what crosses the wire by verb: the ledger #1570 harness's instrument.
    struct Counted {
        inner: Arc<dyn Resolver>,
        metas: std::sync::atomic::AtomicUsize,
        others: std::sync::atomic::AtomicUsize,
    }

    impl Counted {
        fn over(peer: &Arc<Kernel>) -> Arc<Self> {
            Arc::new(Counted {
                inner: Arc::new(Forwarding(Arc::clone(peer))),
                metas: Default::default(),
                others: Default::default(),
            })
        }

        fn metas(&self) -> usize {
            self.metas.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn others(&self) -> usize {
            self.others.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Resolver for Counted {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            self.issue_as(request, &Capability::root())
        }

        fn issue_as(
            &self,
            request: Request,
            capability: &Capability,
        ) -> Result<(Representation, CacheStatus), Error> {
            let counter = if request.verb == Verb::Meta {
                &self.metas
            } else {
                &self.others
            };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.issue_as(request, capability)
        }

        fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
            self.inner.is_cached(request, capability)
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            self.inner.entries()
        }
    }

    /// A read through the KERNEL, not through `Resolver::issue_as`. These tests are about the
    /// MOUNT's memo, so they read without the resolver's cache-status probe
    /// (`Kernel::is_cached`) in the way. Core 0.1.105 and 0.1.106 made that probe resolve a
    /// `Meta` for the declared defaults, which a mount forwards to its peer at once (ledger
    /// #1146); since core 0.1.107 the probe keys a served name without resolving it (ledger
    /// #1884), so it asks the peer nothing. What the probe costs is pinned on its own, in
    /// `the_cache_probe_asks_a_mounts_peer_nothing_on_a_resolver_read`.
    fn read_as(
        kernel: &Kernel,
        iri: &str,
        capability: &Capability,
    ) -> Result<Representation, Error> {
        let request = Request::new(Verb::Source, Iri::parse(iri).unwrap());
        block_on(kernel.issue(request, capability))
    }

    /// ★ Ledger #1884. `Resolver::issue_as` probes `Kernel::is_cached` before each read (the
    /// engine's path). In core 0.1.105 and 0.1.106 that probe resolved a `Meta` for the
    /// target's declared defaults, and a mount's `Meta` resolution forwards to the peer at
    /// once, by design (ledger #1146), so every hot mounted read through the resolver cost
    /// one peer `Meta` and undid ledger #1577's memo: N reads, N `Meta`s. Since core 0.1.107
    /// the probe keys a served name without resolving it, so N resolver reads ask the peer
    /// for the contract once, the mount memo's one, the same as N reads through the kernel.
    #[test]
    fn the_cache_probe_asks_a_mounts_peer_nothing_on_a_resolver_read() {
        const N: usize = 10;
        let (_space, peer) = swappable_peer(None);
        let wire = Counted::over(&peer);
        let local = Kernel::new(Arc::new(MountedRemote::new(
            wire.clone(),
            "urn:mnt:",
            "test://peer",
        )));
        for _ in 0..N {
            let request = Request::new(Verb::Source, Iri::parse("urn:mnt:peer:doc").unwrap());
            let (answer, _) = Resolver::issue_as(&local, request, &Capability::root()).unwrap();
            assert_eq!(answer.bytes, b"doc");
        }
        assert_eq!(wire.others(), N, "every read is forwarded");
        assert_eq!(
            wire.metas(),
            1,
            "{N} resolver reads asked the peer for the contract once: the probe asks nothing"
        );
    }

    /// ★ Ledger #1577. Core's floor memo keys on the endpoint's allocation, and a mount
    /// hands out a fresh endpoint per resolution, so every mounted read forwarded a `Meta`
    /// for the floor: N reads, N `Meta`s (1.00 per read in the ledger #1570 harness). The
    /// mount's own memo makes it one per name per TTL, through an alias mount, an override
    /// mount and a bare `RemoteSpace` alike; an enumeration re-reads; and a TTL of zero is
    /// the old behavior.
    #[test]
    fn a_hot_mounted_read_asks_the_peer_for_its_contract_once() {
        const N: usize = 50;
        let (_space, peer) = swappable_peer(None);
        /// A label, the name read through it, its wire counter and the mounting space.
        type Case = (&'static str, &'static str, Arc<Counted>, Arc<dyn Space>);
        let cases: Vec<Case> = {
            let alias = Counted::over(&peer);
            let over = Counted::over(&peer);
            let bare = Counted::over(&peer);
            vec![
                (
                    "alias",
                    "urn:mnt:peer:doc",
                    Arc::clone(&alias),
                    Arc::new(MountedRemote::new(alias, "urn:mnt:", "test://peer")),
                ),
                (
                    "override",
                    "urn:peer:doc",
                    Arc::clone(&over),
                    Arc::new(MountedRemote::overriding(over, "urn:peer:", "test://peer")),
                ),
                (
                    "RemoteSpace",
                    "urn:peer:doc",
                    Arc::clone(&bare),
                    Arc::new(RemoteSpace::new(bare)),
                ),
            ]
        };
        for (label, iri, wire, space) in cases {
            let local = Kernel::new(Arc::clone(&space));
            for _ in 0..N {
                let answer = read_as(&local, iri, &Capability::root()).unwrap();
                assert_eq!(answer.bytes, b"doc", "{label}");
            }
            assert_eq!(wire.others(), N, "{label}: every read is forwarded");
            assert_eq!(
                wire.metas(),
                1,
                "{label}: {N} hot reads asked the peer for the contract once"
            );
            // An enumeration is a catalog walk's first step and every row is described
            // next, so it re-reads.
            space.entries().expect("the peer enumerates");
            read_as(&local, iri, &Capability::root()).unwrap();
            assert_eq!(
                wire.metas(),
                2,
                "{label}: an enumeration re-reads the contract"
            );
        }

        // `Duration::ZERO` is the opt-out, and the behavior before the memo.
        let wire = Counted::over(&peer);
        let local = Kernel::new(Arc::new(
            MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer")
                .contract_ttl(std::time::Duration::ZERO),
        ));
        for _ in 0..N {
            read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        }
        assert_eq!(wire.metas(), N, "a zero TTL asks on every read");
    }

    /// ★ Ledger #1577: a contract that changed never widens what a caller may do. Within the
    /// TTL the mount floors on the contract it read, so in BOTH directions the stale contract
    /// errs toward refusing: a contract the peer NARROWED is refused by the peer's own floor
    /// (the forward carries the caller's capability), and that refusal evicts the stale
    /// contract; a contract the peer WIDENED is refused by the local floor until the TTL ends.
    #[test]
    fn a_stale_contract_never_admits_what_the_peer_now_refuses() {
        let (space, peer) = swappable_peer(None);
        let wire = Counted::over(&peer);
        // An hour: everything below happens inside the TTL, whatever the machine's load.
        let local = Kernel::new(Arc::new(
            MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer")
                .contract_ttl(std::time::Duration::from_secs(3600)),
        ));
        let caller = Capability::scoped(["urn:cap:other"]);
        let doc = "urn:peer:doc";

        // Open: the caller reads, and the mount now holds the open contract.
        assert_eq!(read_as(&local, doc, &caller).unwrap().bytes, b"doc");
        assert_eq!((wire.metas(), wire.others()), (1, 1));

        // The peer NARROWS the contract. The local floor still holds the open one and
        // admits, and the PEER refuses: the caller is never served.
        rebind(&space, &peer, doc_space(Some(SECRET)));
        let refused = read_as(&local, doc, &caller);
        assert!(
            matches!(&refused, Err(Error::Denied(_))),
            "a narrowed contract refuses even through a stale memo: {refused:?}"
        );
        assert_eq!(
            (wire.metas(), wire.others()),
            (1, 2),
            "the stale contract was used (no re-read) and the peer refused the forward"
        );

        // That refusal evicted the stale contract: the next read re-reads it, and the
        // LOCAL floor now refuses without forwarding anything.
        let refused = read_as(&local, doc, &caller);
        assert!(matches!(&refused, Err(Error::Denied(_))), "{refused:?}");
        assert_eq!(
            (wire.metas(), wire.others()),
            (2, 2),
            "re-read once, refused locally, nothing forwarded"
        );
        // A caller holding the scope still reads.
        let holder = Capability::scoped([SECRET]);
        assert_eq!(read_as(&local, doc, &holder).unwrap().bytes, b"doc");

        // The peer WIDENS it again. Inside the TTL the mount floors on the narrow contract
        // it holds: the caller is refused here, not served (fail closed).
        rebind(&space, &peer, doc_space(None));
        let refused = read_as(&local, doc, &caller);
        assert!(
            matches!(&refused, Err(Error::Denied(_))),
            "a stale narrow contract refuses until the TTL passes: {refused:?}"
        );
        assert_eq!(
            wire.metas(),
            2,
            "inside the TTL the contract is not re-read"
        );
    }

    /// ★ Ledger #1577: the staleness bound holds. A contract the peer changed is read again
    /// by the first describe after the TTL, with no enumeration and no refusal to prompt it.
    #[test]
    fn a_changed_contract_is_seen_once_the_ttl_has_passed() {
        let ttl = std::time::Duration::from_millis(200);
        let (space, peer) = swappable_peer(Some(SECRET));
        let wire = Counted::over(&peer);
        let local = Kernel::new(Arc::new(
            MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer").contract_ttl(ttl),
        ));
        let caller = Capability::scoped(["urn:cap:other"]);
        assert!(matches!(
            read_as(&local, "urn:peer:doc", &caller),
            Err(Error::Denied(_))
        ));
        assert_eq!((wire.metas(), wire.others()), (1, 0), "refused locally");

        rebind(&space, &peer, doc_space(None));
        std::thread::sleep(ttl + std::time::Duration::from_millis(100));
        assert_eq!(
            read_as(&local, "urn:peer:doc", &caller).unwrap().bytes,
            b"doc",
            "past the TTL the widened contract is read and the caller is served"
        );
        assert_eq!((wire.metas(), wire.others()), (2, 1));
    }

    /// ★ Ledger #1577 beside #1146: `Meta` is the "describe it now" operation and never
    /// answers from the memo, so a name the peer stopped binding is `Unresolved` at once,
    /// even while a contract read a moment ago is held for it.
    #[test]
    fn a_meta_asks_the_peer_now_even_while_a_contract_is_memoized() {
        let (space, peer) = swappable_peer(None);
        let wire = Counted::over(&peer);
        let local = Kernel::new(Arc::new(
            MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer")
                .contract_ttl(std::time::Duration::from_secs(3600)),
        ));
        read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        assert_eq!(wire.metas(), 1);

        rebind(&space, &peer, Arc::new(EndpointSpace::new()));
        // Through the kernel, past the resolver's cache-status probe (see `read_as`).
        let answer = block_on(local.issue(meta("urn:peer:doc"), &Capability::root()));
        assert!(
            matches!(&answer, Err(Error::Unresolved(_))),
            "an unbound name is Unresolved at once, memo or not: {answer:?}"
        );
        assert_eq!(wire.metas(), 2, "the Meta asked the peer");
    }

    /// The memo is bounded: a template mount reads one name per path, so more names than
    /// the bound sweep it back below the bound instead of growing without limit, and a name
    /// put last is still held.
    #[test]
    fn the_contract_memo_is_bounded() {
        let memo = ContractMemo::new(std::time::Duration::from_secs(3600));
        let description = Description::new("doc").verb(Verb::Source);
        let now = Some(Time::from_millis(1_000));
        for n in 0..CONTRACT_MEMO_BOUND * 3 {
            memo.put(&format!("urn:file:{n}"), &description, now);
            assert!(memo.lock().len() <= CONTRACT_MEMO_BOUND, "after {n} puts");
        }
        let last = format!("urn:file:{}", CONTRACT_MEMO_BOUND * 3 - 1);
        assert!(
            memo.get(&last, now).is_some(),
            "the newest contract is held"
        );
    }

    // ---- ledger #2194: the mount's bookkeeping reads an injected clock ----

    /// A clock the test moves by hand, the way a host's clock moves under a mount.
    #[derive(Clone)]
    struct Stepped(Arc<std::sync::atomic::AtomicU64>);

    impl Stepped {
        fn at(millis: u64) -> Self {
            Stepped(Arc::new(std::sync::atomic::AtomicU64::new(millis)))
        }

        fn advance(&self, by: std::time::Duration) {
            self.0
                .fetch_add(millis(by), std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Clock for Stepped {
        fn now(&self) -> Time {
            Time::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    /// ★ Ledger #2194: the contract TTL is measured on the clock the mount was given, not
    /// on platform time, so a browser host can supply one and a test needs no sleep.
    #[test]
    fn the_contract_ttl_is_measured_on_the_mount_clock() {
        let (_space, peer) = swappable_peer(None);
        let wire = Counted::over(&peer);
        let clock = Stepped::at(1_000);
        let local = Kernel::new(Arc::new(
            MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer")
                .with_clock(Arc::new(clock.clone())),
        ));
        read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        assert_eq!(wire.metas(), 1);

        clock.advance(CONTRACT_TTL - std::time::Duration::from_millis(1));
        read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        assert_eq!(
            wire.metas(),
            1,
            "a millisecond inside the TTL, the memo answers"
        );

        clock.advance(std::time::Duration::from_millis(1));
        read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        assert_eq!(
            wire.metas(),
            2,
            "at the TTL by the mount's clock, the peer is asked"
        );
    }

    /// ★ Ledger #2194: a mount with NO clock — what every mount is on wasm32 unless its host
    /// installs one, because platform time panics there — keeps no memo and asks the peer
    /// on every describe, as a zero TTL does, instead of reading time it does not have.
    /// Before, `ContractMemo::put` read `Instant::now()` under the default TTL, and a
    /// mounted read in a browser panicked with "time not implemented on this platform".
    #[test]
    fn a_mount_with_no_clock_keeps_no_memo_and_still_reads() {
        let (_space, peer) = swappable_peer(None);
        let wire = Counted::over(&peer);
        let mut mount = MountedRemote::overriding(wire.clone(), "urn:peer:", "test://peer");
        mount.clock = None;
        let local = Kernel::new(Arc::new(mount));
        const N: usize = 3;
        for _ in 0..N {
            assert_eq!(
                read_as(&local, "urn:peer:doc", &Capability::root())
                    .unwrap()
                    .bytes,
                b"doc"
            );
        }
        assert_eq!(
            wire.metas(),
            N,
            "no clock, no memo: every read asks the peer"
        );

        // The same for a bare `RemoteSpace`.
        let wire = Counted::over(&peer);
        let mut space = RemoteSpace::new(wire.clone());
        space.clock = None;
        let local = Kernel::new(Arc::new(space));
        for _ in 0..N {
            read_as(&local, "urn:peer:doc", &Capability::root()).unwrap();
        }
        assert_eq!(wire.metas(), N);
    }

    /// A peer that never answers: every call times out, as a silent transport's does.
    struct Silent(std::sync::atomic::AtomicUsize);

    impl Resolver for Silent {
        fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
            self.issue_as(request, &Capability::root())
        }

        fn issue_as(
            &self,
            _request: Request,
            _capability: &Capability,
        ) -> Result<(Representation, CacheStatus), Error> {
            Err(Error::Timeout("no answer".into()))
        }

        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }

        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            None
        }

        fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(Error::Timeout("no answer".into()))
        }
    }

    /// ★ Ledger #2194: the describe cooldown is measured on the mount's clock too, and a
    /// mount with none records no silence (there is no cooldown to measure) rather than
    /// reading platform time — the `DescribeHealth::record` half of the wasm panic.
    #[test]
    fn the_describe_cooldown_is_measured_on_the_mount_clock() {
        let asked = |silent: &Silent| silent.0.load(std::sync::atomic::Ordering::SeqCst);

        let silent = Arc::new(Silent(Default::default()));
        let clock = Stepped::at(1_000);
        let mount = MountedRemote::new(silent.clone(), "urn:peer:", "test://cooldown")
            .with_clock(Arc::new(clock.clone()));
        mount
            .entries()
            .expect("a silent peer contributes its status row");
        mount
            .entries()
            .expect("a silent peer contributes its status row");
        assert_eq!(
            asked(&silent),
            1,
            "inside the cooldown the peer is not asked again"
        );
        clock.advance(DESCRIBE_COOLDOWN);
        mount
            .entries()
            .expect("a silent peer contributes its status row");
        assert_eq!(
            asked(&silent),
            2,
            "past the cooldown by the mount's clock it is"
        );

        let silent = Arc::new(Silent(Default::default()));
        let mut mount = MountedRemote::new(silent.clone(), "urn:peer:", "test://cooldown");
        mount.clock = None;
        mount
            .entries()
            .expect("a silent peer contributes its status row");
        mount
            .entries()
            .expect("a silent peer contributes its status row");
        assert_eq!(asked(&silent), 2, "no clock, no cooldown: every walk asks");
    }

    /// A clock that reads EARLIER than a record (an injected wall clock that stepped back)
    /// never keeps the record alive: both records forget and ask the peer.
    #[test]
    fn a_clock_that_steps_back_expires_rather_than_extends() {
        let window = std::time::Duration::from_secs(5);
        let at = Time::from_millis(10_000);
        assert!(within(at, Some(Time::from_millis(10_000)), window));
        assert!(within(at, Some(Time::from_millis(14_999)), window));
        assert!(!within(at, Some(Time::from_millis(15_000)), window));
        assert!(!within(at, Some(Time::from_millis(9_999)), window));
        assert!(!within(at, None, window));
    }
}
