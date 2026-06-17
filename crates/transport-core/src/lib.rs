//! The seam between the REPL engine and a kernel — local or, later, remote.
//!
//! The engine drives a [`Backend`] rather than a concrete [`Kernel`], so the
//! same engine resolves against an in-process kernel today and an IPC- or
//! QUIC-attached one tomorrow. [`Backend`] is synchronous: the REPL runs a
//! blocking loop, so the local implementation hides `block_on` and a wire
//! implementation hides its socket round-trip behind the same surface.
//!
//! The trait is deliberately small — exactly what the engine needs: issue a
//! request, ask whether one is cached, and list the bound resources. Issue
//! reports the [`CacheStatus`] the resolution had, which a remote server knows
//! directly (no client-side cache probing across the wire).

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
pub trait Backend {
    /// Resolve `request` and report its representation and cache outcome.
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String>;

    /// Whether resolving `request` would be served from the cache, without
    /// resolving it.
    fn is_cached(&self, request: &Request) -> bool;

    /// The resources bound in the kernel's space, or `None` if it can't enumerate.
    fn entries(&self) -> Option<Vec<SpaceEntry>>;
}

/// The in-process kernel as a [`Backend`]: drive it directly, inferring the
/// cache outcome from its [`cache_len`](Kernel::cache_len) across the issue (a
/// hit returns the cached value without growing the cache; a cacheable miss
/// inserts one entry). All requests use the root capability — this is the
/// trusted, same-process path.
impl Backend for Kernel {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String> {
        let before = self.cache_len();
        let representation = block_on(Kernel::issue(self, request, &Capability::root()))
            .map_err(|e| e.to_string())?;
        let status = if representation.expiry != Expiry::Never {
            CacheStatus::Uncacheable
        } else if self.cache_len() > before {
            CacheStatus::Miss
        } else {
            CacheStatus::Hit
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
