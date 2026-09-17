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

use std::collections::BTreeSet;
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
                // A bare `RemoteSpace` is mounted by a caller that holds the resolver;
                // it carries no origin label of its own (`MountedRemote` does).
                origin: None,
                // …and with no mount identity, a failure here has nothing to be
                // attributed to, so it is not remembered. See `DescribeHealth`.
                health: None,
                request: request.clone(),
            }),
            bindings: Bindings::new(),
            // Nothing is rewritten here — the request goes over the wire under the
            // name it arrived with. (Even if it were, it would not be a canonical:
            // see `MountedRemote::resolve` below for why a mount never reports one.)
            canonical: None,
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
    /// The mount's origin label (`ipc:~/.ikigai/dev.sock`, `quic:plasma:4433`), when the
    /// space that built this endpoint has one. Used only to NAME the peer in the
    /// contract-unavailable path ([`unavailable`]) — a diagnostic that says "a mounted
    /// peer" is one an operator with three mounts cannot act on.
    origin: Option<String>,
    /// What the mount has learned about this peer's ability to describe itself, when the
    /// space that built this endpoint tracks it. `None` for a [`RemoteSpace`], which has
    /// no mount identity to attribute a failure to.
    health: Option<Arc<DescribeHealth>>,
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
        // mount loses its `src`. Best-effort, and [`unavailable`] is what makes the
        // best-effort part audible rather than silent.
        // ★ A peer already known to be silent is NOT asked again. `describe()` is called
        // once per catalog row on a manifold read, so without this the transport's
        // deadline would be paid per row and a bounded call would still add up to an
        // unbounded walk — the deadline bounds a CALL, this bounds the WALK.
        if let Some(reason) = self.health.as_ref().and_then(|health| health.failing()) {
            return unavailable(
                self.origin.as_deref(),
                self.request.target.as_str(),
                &reason,
            );
        }
        let meta = Request::new(Verb::Meta, self.request.target.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
        let reason = match self.resolver.issue_as(meta, &Capability::root()) {
            Ok((repr, _status)) => match serde_json::from_slice::<Description>(&repr.bytes) {
                Ok(description) => return description,
                // The shape that cost a day: a peer below `ikigai-vocab` 0.1.47 has no
                // JSON Meta renderer, answers `as=application/json` with the canonical
                // TURTLE, and the parse fails here — so the media type is named, because
                // "expected JSON, got text/turtle" is the whole diagnosis.
                Err(error) => format!(
                    "its Meta answer is {} ({} byte(s)), not a JSON Description: {error}",
                    repr.repr_type,
                    repr.bytes.len()
                ),
            },
            Err(error) => {
                // Silence here is the same silence an enumeration would meet, so it counts
                // against the same health — one row's timeout spares every later row.
                if let Some(health) = &self.health {
                    health.record(&error);
                }
                format!("it refused the Meta request: {error}")
            }
        };
        unavailable(
            self.origin.as_deref(),
            self.request.target.as_str(),
            &reason,
        )
    }
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
    /// `Some((when, why))` while the peer is considered undescribable.
    failed: Mutex<Option<(std::time::Instant, String)>>,
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
    fn failing(&self) -> Option<String> {
        let mut failed = match self.failed.lock() {
            Ok(failed) => failed,
            // A poisoned lock must cost knowledge, never a describe: forget the record.
            Err(poisoned) => poisoned.into_inner(),
        };
        match &*failed {
            Some((at, why)) if at.elapsed() < DESCRIBE_COOLDOWN => Some(why.clone()),
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
    fn record(&self, error: &Error) {
        if !matches!(error, Error::Timeout(_) | Error::Unavailable(_)) {
            return;
        }
        // Native-and-wasm: `ikigai-resolve` builds for wasm, where `Instant::now` is
        // provided by the browser shim the workspace already links. The kernel `Clock`
        // is not in scope on this path — a mount's health is transport bookkeeping, not
        // a resolution's notion of time — and this is a monotonic elapsed measure, which
        // is what `Instant` is for. Bound to a `let` so the opt-out covers this call
        // rather than widening over the whole method (an attribute on an assignment
        // expression is not stable, E0658).
        #[allow(clippy::disallowed_methods)]
        let now = std::time::Instant::now();
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
            return Resolution::Hit(Resolved {
                endpoint: Arc::new(MountUnavailable {
                    prefix: self.prefix.clone(),
                    origin: self.origin.clone(),
                    reason: self.health.failing(),
                }),
                bindings: Bindings::new(),
                canonical: None,
            });
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
        Resolution::Hit(Resolved {
            endpoint: Arc::new(ForwardingEndpoint {
                resolver: Arc::clone(&self.resolver),
                name: self.names.name_for(&forwarded.target),
                origin: Some(self.origin.clone()),
                health: Some(Arc::clone(&self.health)),
                request: forwarded,
            }),
            bindings: Bindings::new(),
            // ★ A MOUNT REWRITES AND STILL REPORTS NO CANONICAL. `Alias` mode just
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
            canonical: None,
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // A peer already known to be silent is not asked again for the cooldown — a
        // manifold read must cost ONE deadline per unhealthy mount, not one per attempt.
        if let Some(reason) = self.health.failing() {
            return Some(vec![self.unenumerated(&reason)]);
        }
        let entries = match self.resolver.try_entries() {
            Ok(Some(entries)) => {
                self.health.clear();
                entries
            }
            // The peer does not enumerate at all. Nothing is missing that it would have
            // named, so there is nothing to say — this is the old `None` and it is right.
            Ok(None) => return None,
            // ★ It should have answered and did not. Returning `None` here is what made a
            // silent peer read like an empty one; instead the mount contributes exactly
            // one row, which says whose resources are missing and why.
            Err(error) => {
                self.health.record(&error);
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
