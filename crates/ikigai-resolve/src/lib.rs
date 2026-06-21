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

use std::sync::Arc;

use futures::executor::block_on;
use ikigai_core::{Capability, Expiry, Kernel, Representation, Request, SpaceEntry};
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

/// What the REPL engine needs of a kernel, local or remote.
///
/// Synchronous by design (the REPL loop is blocking). Errors are surfaced as
/// human-readable strings — the engine reports them verbatim; a richer transport
/// error type can replace `String` when the wire protocol lands.
pub trait Resolver {
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

    /// Whether resolving `request` would be served from the cache, without
    /// resolving it.
    fn is_cached(&self, request: &Request) -> bool;

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
        let was_cached = Kernel::is_cached(self, &request);
        let representation =
            block_on(Kernel::issue(self, request, capability)).map_err(|e| e.to_string())?;
        // Only `Always` is truly uncacheable; `Never` and a time-based `At`
        // deadline are both cacheable (so an `At` read still reports Hit/Miss, not
        // Uncacheable).
        let status = if representation.expiry == Expiry::Always {
            CacheStatus::Uncacheable
        } else if was_cached {
            CacheStatus::Hit
        } else {
            CacheStatus::Miss
        };
        Ok((representation, status))
    }

    fn is_cached(&self, request: &Request) -> bool {
        Kernel::is_cached(self, request)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        Kernel::entries(self)
    }
}

/// An `Arc`-shared resolver is itself a resolver, delegating to the inner one. So
/// a kernel can be held as `Arc<Kernel>` and *shared* — driven by the engine, and
/// at the same time reached by a file watcher that cuts golden threads on the very
/// same kernel (and thus the same cache). Every method delegates, so the inner
/// resolver's overrides (e.g. the kernel's `issue_as`/`transport`) are preserved.
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

    fn is_cached(&self, request: &Request) -> bool {
        (**self).is_cached(request)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        (**self).entries()
    }

    fn transport(&self) -> String {
        (**self).transport()
    }
}
