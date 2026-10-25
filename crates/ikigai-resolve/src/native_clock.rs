//! The default clock a mount reads on a native target: monotonic, and the only place this
//! crate reads time from the platform (ledger #2194).
//!
//! **Native only.** `Instant::now()` and `SystemTime::now()` compile on
//! wasm32-unknown-unknown and panic when called ("time not implemented on this platform").
//! On wasm32 this module is not compiled, so a mount there has no default clock: it keeps no
//! contract memo and no describe cooldown unless the host installs a clock with
//! `with_clock`, as it does for its kernel. Before ledger #2194 both reads sat in `lib.rs`
//! under an opt-out that credited a "browser shim the workspace already links"; there is no
//! such shim (`web-time` in the lock is quinn's, with its own `Instant` type), and a mounted
//! read with the default contract TTL panicked in a browser.
//!
//! Monotonic on purpose, as in `ikigai-throttle`'s clock of the same name: a contract TTL or
//! a describe cooldown measured on the wall clock would stretch or vanish when it steps
//! (NTP, a laptop waking). This clock is anchored once at the wall clock, so its readings
//! are still milliseconds since the Unix epoch, and then advances only by `Instant`'s
//! elapsed time. That is the behavior both records had when they held an `Instant`, kept.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ikigai_core::{Clock, Time};

/// A [`Clock`] that never runs backward: the wall clock's reading when it was made,
/// advanced by the monotonic time elapsed since.
pub(crate) struct Monotonic {
    origin: Instant,
    epoch: u64,
}

impl Monotonic {
    pub(crate) fn new() -> Self {
        // Native-only: this module is `cfg(not(target_arch = "wasm32"))` (see above).
        #[allow(clippy::disallowed_methods)]
        let origin = Instant::now();
        #[allow(clippy::disallowed_methods)]
        let wall = SystemTime::now();
        Monotonic {
            origin,
            epoch: crate::millis(wall.duration_since(UNIX_EPOCH).unwrap_or_default()),
        }
    }
}

impl Clock for Monotonic {
    fn now(&self) -> Time {
        Time::from_millis(
            self.epoch
                .saturating_add(crate::millis(self.origin.elapsed())),
        )
    }
}
