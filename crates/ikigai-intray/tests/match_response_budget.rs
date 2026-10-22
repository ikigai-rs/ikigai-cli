//! A slow allocation while rendering matching ids must count toward the match budget.
//! Only the final response's exact allocation size is delayed, after seeding the space.
// Native-only filesystem endpoint: wall time measures the caller's budget deadline.
#![allow(clippy::disallowed_methods)]
mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Kernel, Request, Verb};
use ikigai_intray::{space_with_budget, CAP_OUT, CAP_READ};
use ikigai_store::budget::{EvaluationBudget, TimeBudget};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TUPLES: usize = 37;
// BLAKE3 hex ids are 64 bytes, separated by one newline, with no trailing newline.
const RESPONSE_BYTES: usize = TUPLES * 65 - 1;
static ARMED: AtomicBool = AtomicBool::new(false);
static DELAYED: AtomicBool = AtomicBool::new(false);
struct SlowResponseAllocation;

// SAFETY: every allocation and deallocation is delegated unchanged to System.
unsafe impl GlobalAlloc for SlowResponseAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == RESPONSE_BYTES && ARMED.swap(false, Ordering::SeqCst) {
            DELAYED.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(2));
        }
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the allocation came from System with this same layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: SlowResponseAllocation = SlowResponseAllocation;

#[test]
fn rendering_matching_ids_is_inside_the_time_budget() {
    let budget = EvaluationBudget::new(TimeBudget::new(Duration::from_millis(500)));
    let root = scratch("match-response-budget");
    let kernel = Kernel::new(Arc::new(space_with_budget(root, budget.clone())));
    for i in 0..TUPLES {
        drop_tuple(
            &kernel,
            &Capability::scoped([CAP_OUT]),
            "urn:space:jobs",
            format!("<urn:s:{i}> <urn:p> <urn:o> .").as_bytes(),
        )
        .unwrap();
    }
    ARMED.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let result = block_on(
        kernel.issue(
            Request::new(Verb::Source, iri("urn:space:jobs"))
                .with_arg("match", ArgRef::Inline(b"ASK {}".to_vec())),
            &Capability::scoped([CAP_READ]),
        ),
    );
    let elapsed = started.elapsed();
    ARMED.store(false, Ordering::SeqCst);
    assert!(
        DELAYED.load(Ordering::SeqCst),
        "the response allocation was exercised"
    );
    assert!(
        matches!(result, Err(Error::Timeout(_))),
        "slow response rendering escaped the budget: {result:?} after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "caller blocked for {elapsed:?}"
    );
    let until = Instant::now() + Duration::from_secs(5);
    while budget.overdue_evaluations() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(budget.overdue_evaluations(), 0);
}
