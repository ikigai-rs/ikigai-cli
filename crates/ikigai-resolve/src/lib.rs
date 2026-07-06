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
    Capability, Expiry, Kernel, Provenance, Representation, Request, SpaceEntry, TraceEvent, Tracer,
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
