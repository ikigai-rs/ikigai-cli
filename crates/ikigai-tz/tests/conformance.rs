//! The module recipe as one test: `ikigai-conformance` walks every endpoint
//! `ikigai_tz::space()` binds and reports every violation at once.
//!
//! Declarations, one per endpoint:
//!
//! - `tz-convert` is `pure` and `cacheable`: a function of its inline arguments and the
//!   static tz database, read through nothing that could change.
//! - `tz-now` declares nothing and opts out of `CACHEABLE`, with the reason below: it reads
//!   the invocation's clock, so it is not pure, and its answer is cacheable only until the
//!   next minute (`Expiry::At`) or, under a temporal corridor, for as long as the corridor's
//!   name. The purity rule reads "no thread but its own name" as "served forever", which an
//!   `At` deadline is not. The unit tests in `src/lib.rs` pin both expiries exactly
//!   (`a_live_clock_reads_the_kernels_time_and_caches_to_the_minute`,
//!   `a_temporal_corridor_pins_the_answer_and_makes_it_immutable`).
//!
//! One fixture: `tz-convert`'s minimal inputs (`x` for every string) are not a time zone, so
//! the suite is handed a real instant and zone. One space declaration: `space()` is
//! configuration-free, so it is self-named `urn:iki:space:tz`.
//!
//! BODIES (conformance 0.12.0) calls each endpoint's `invoke` and `invoke_body` directly, so
//! the kernel is built from one shared `Arc` of the space and the suite is handed the same
//! one. No argument is declared `reads_body`, so BODY-INPUTS has nothing to probe and no
//! content store is installed. `tz-now` answers `Expiry::At`, so BODIES lists it unprobed by
//! the suite's own reason (two independent calls to a clock cannot establish agreement); the
//! test pins that as the ONLY unprobed action, so the wiring cannot silently fall off.

use ikigai_conformance::{Check, Fixture, Suite};
use ikigai_core::{FixedClock, Kernel, Verb};
use std::sync::Arc;

/// 2026-09-27T12:34:56Z: the kernel's clock, so `tz-now` answers the same bytes on every run.
const NOW: u64 = 1_790_512_496_000;

#[test]
fn conforms() {
    let space = Arc::new(ikigai_tz::space());
    let kernel = Kernel::new(space.clone()).with_clock(Arc::new(FixedClock::at(NOW)));
    let report = Suite::new()
        .fixture(
            Fixture::new("tz-convert", Verb::Source)
                .arg("in", "2026-07-21T12:00:00-04:00")
                .arg("to", "UTC"),
        )
        .pure("tz-convert")
        .cacheable("tz-convert")
        .opt_out_check(
            "tz-now",
            Check::Cacheable,
            "bounded by time, not by a thread: the answer expires at the next minute \
             (Expiry::At) under a live clock, and is a pure function of the corridor's name \
             under a pinned one; the purity rule does not read an At deadline as a bound. \
             Both expiries are pinned by the unit tests in src/lib.rs",
        )
        // `space()` reads nothing while it is built, so it names itself; the suite calls it
        // twice and holds both calls to the same name over the same doors.
        .self_named_space("tz", ikigai_tz::space)
        .body_space(space)
        .run_blocking(&kernel);
    assert!(report.is_clean(), "{report}");
    assert_eq!(
        report.endpoints, 2,
        "both urn:tz:* doors are declared: {report}"
    );
    // Everything deterministic was observed: the one unprobed action is the clock's BODIES.
    let unprobed: Vec<(&str, Check)> = report
        .unprobed
        .iter()
        .map(|u| (u.endpoint.as_str(), u.check))
        .collect();
    assert_eq!(unprobed, [("tz-now", Check::Bodies)], "{report}");
    assert_eq!(ikigai_core::space_iri("tz").as_str(), ikigai_tz::SPACE_ID);
}
