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
    ArgRef, Bindings, Capability, Description, Endpoint, Error, Expiry, Invocation, Kernel,
    Provenance, Representation, Request, Resolution, Resolved, Scope, Space, SpaceEntry,
    TraceEvent, Tracer, Verb,
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
    let mut seen = std::collections::BTreeSet::new();
    kernel
        .select_actions(&query)
        .into_iter()
        .filter(|m| seen.insert(m.endpoint.clone()))
        .map(|m| SpaceEntry {
            pattern: m.endpoint,
            endpoint: m.id,
        })
        .collect()
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
}

impl RemoteSpace {
    /// Wrap a connected [`Resolver`] as a mountable space.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        RemoteSpace { resolver }
    }
}

impl Space for RemoteSpace {
    fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
        // Capture the whole request (target + verb + args) so the endpoint forwards
        // it verbatim; the caller's capability arrives via the Invocation on invoke.
        Resolution::Hit(Resolved {
            endpoint: Arc::new(ForwardingEndpoint {
                resolver: Arc::clone(&self.resolver),
                request: request.clone(),
            }),
            bindings: Bindings::new(),
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        // Forward the remote's catalog (a round-trip — off the hot path).
        self.resolver.entries()
    }
}

/// The endpoint a [`RemoteSpace`] resolves to: on invoke, forward the captured
/// request to the remote kernel under the invocation's capability (which the
/// server clamps to its authenticated principal).
struct ForwardingEndpoint {
    resolver: Arc<dyn Resolver>,
    request: Request,
}

#[async_trait]
impl Endpoint for ForwardingEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation, Error> {
        // Off the trace path: a plain forward.
        if inv.trace_span().is_none() {
            return self
                .resolver
                .issue_as(self.request.clone(), inv.capability)
                .map(|(representation, _status)| representation)
                .map_err(Error::Endpoint);
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
        let (representation, _status) = result.map_err(Error::Endpoint)?;
        inv.record_subtree(collector.take());
        Ok(representation)
    }

    fn name(&self) -> &str {
        "remote"
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

/// What the REPL engine needs of a kernel, local or remote.
///
/// Synchronous by design (the REPL loop is blocking). Errors are surfaced as
/// human-readable strings — the engine reports them verbatim; a richer transport
/// error type can replace `String` when the wire protocol lands.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve `request` under the resolver's default authority, and report its
    /// representation and cache outcome.
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String>;

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
    ) -> Result<(Representation, CacheStatus), String> {
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
    ) -> Result<(Representation, CacheStatus), String> {
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
    ) -> Result<(Representation, CacheStatus), String> {
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
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String> {
        self.issue_as(request, &Capability::root())
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), String> {
        // Probe before issuing: a valid (thread-current) cached entry means a Hit;
        // a cut or absent one means we'll (re)compute. A cache-length delta would
        // misreport once golden-thread eviction is in play — evict + reinsert nets
        // zero — so the probe, not the delta, is the source of truth.
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation =
            block_on(Kernel::issue(self, request, capability)).map_err(|e| e.to_string())?;
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), String> {
        // Same as `issue_as`, but awaits the kernel's async issue directly — no
        // `block_on`, so when the engine spawns this on the scheduler it parks
        // (freeing the worker for any sub-resolutions it fans out).
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation = Kernel::issue(self, request, capability)
            .await
            .map_err(|e| e.to_string())?;
        let status = cache_status(was_cached, &representation);
        Ok((representation, status))
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), String> {
        // Thread the upstream pipe provenance into the kernel's dependency merge, so
        // the result's cacheability is no greater than its piped input's. `is_cached`
        // probes the same content-keyed entry the merged result would store under.
        let was_cached = Kernel::is_cached(self, &request, capability);
        let representation = Kernel::issue_with_incoming(self, request, capability, incoming)
            .await
            .map_err(|e| e.to_string())?;
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
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String> {
        (**self).issue(request)
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), String> {
        (**self).issue_as(request, capability)
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), String> {
        // Delegate to the inner resolver's override (e.g. the kernel's true-async one).
        (**self).issue_as_async(request, capability).await
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), String> {
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
}
