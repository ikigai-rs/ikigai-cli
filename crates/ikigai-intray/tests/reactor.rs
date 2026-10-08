//! Audit round 5 (ledger #877), the reactor: root causes 6 (a tuple dropped during the startup
//! catch-up was never handled), 4 (a watch over a root that did not exist yet never fired), 3
//! (what an identical re-drop after handling means, and a record that outlived its pass), and
//! the Hermes audit's `once-only-recovery` (a crashed sibling's claimed tuple stranded while
//! another reactor lived).

// Wall time for bounded waits on a live watcher: a native integration test of a native-only
// crate (notify, std::fs), never built for wasm.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{drop_tuple, scratch, Counting};
use ikigai_core::{Capability, Error, Kernel, ReprType, Representation, Request, SpaceEntry};
use ikigai_intray::{space, Outcome, SpaceReactor, CAP_OUT};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn out() -> Capability {
    Capability::scoped([CAP_OUT])
}

fn reactive(root: &Path, space: &str) {
    std::fs::create_dir_all(root.join(space)).unwrap();
    std::fs::write(root.join(space).join("handler"), "urn:test:handler").unwrap();
}

fn reactor(root: &Path, handler: Arc<dyn ikigai_resolve::Resolver>) -> SpaceReactor {
    SpaceReactor::new(
        root.to_path_buf(),
        handler,
        Capability::scoped(["urn:cap:demo"]),
    )
}

fn wait_for(what: impl Fn() -> bool, secs: u64) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end && !what() {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A short root under `/tmp` on purpose: on macOS `/tmp` is a symlink to `/private/tmp`, so
/// `notify` reports paths that differ from the one the reactor was given unless it
/// canonicalizes — the shape root cause 4 hid in.
fn tmp_root(tag: &str) -> PathBuf {
    let root = PathBuf::from("/tmp").join(format!("iir-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// A handler that composes within the fabric: on its FIRST call it drops a follow-up tuple into
/// the same space, then takes a moment (a calendar read, a mail send).
struct Composing {
    calls: AtomicUsize,
    kernel: Kernel,
}

impl ikigai_resolve::Resolver for Composing {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        _: Request,
        _: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            drop_tuple(&self.kernel, &out(), "urn:space:jobs", b"follow-up").unwrap();
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok((
            Representation::new(ReprType::new("text/plain"), Vec::new()),
            ikigai_resolve::CacheStatus::Uncacheable,
        ))
    }
    fn is_cached(&self, _: &Request, _: &Capability) -> bool {
        false
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }
}

/// Root cause 6, deterministic: the pending tuple's handler drops a follow-up DURING the
/// startup catch-up. On main the watch did not exist yet, so the follow-up was never handled
/// (it failed every run). The watch is live before the catch-up now.
#[test]
fn a_tuple_dropped_during_the_startup_catch_up_is_handled() {
    let root = tmp_root("gap");
    reactive(&root, "jobs");
    let k = Kernel::new(Arc::new(space(root.clone())));
    drop_tuple(&k, &out(), "urn:space:jobs", b"pending at startup").unwrap();
    let handler = Arc::new(Composing {
        calls: AtomicUsize::new(0),
        kernel: Kernel::new(Arc::new(space(root.clone()))),
    });
    Arc::new(reactor(&root, Arc::clone(&handler) as _)).watch();
    wait_for(|| handler.calls.load(Ordering::SeqCst) >= 2, 8);
    let calls = handler.calls.load(Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        calls, 2,
        "the follow-up dropped during the catch-up was never handled"
    );
}

fn watch_scenario(tag: &str, precreate_root: bool) -> usize {
    let base = tmp_root(tag);
    let root = base.join("spaces");
    if precreate_root {
        std::fs::create_dir_all(&root).unwrap();
    }
    let handler = Arc::new(Counting::new());
    Arc::new(reactor(&root, Arc::clone(&handler) as _)).watch();
    // A reactive space appears after the watch, then a tuple is dropped into it.
    std::fs::create_dir_all(root.join("jobs").join("inbox")).unwrap();
    std::fs::write(root.join("jobs").join("handler"), "urn:test:handler").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let k = Kernel::new(Arc::new(space(root.clone())));
    drop_tuple(&k, &out(), "urn:space:jobs", b"x").unwrap();
    wait_for(|| handler.calls() > 0, 5);
    let n = handler.calls();
    let _ = std::fs::remove_dir_all(&base);
    n
}

#[test]
fn watch_over_an_existing_root_fires() {
    assert_eq!(watch_scenario("ctl", true), 1);
}

/// Root cause 4: on main the root was canonicalized BEFORE it was created, the raw path was
/// kept, and no event ever matched it (failed every run on macOS).
#[test]
fn watch_over_a_root_that_does_not_exist_yet_fires() {
    assert_eq!(watch_scenario("fresh", false), 1);
}

#[test]
fn a_watch_that_cannot_start_says_why() {
    let base = scratch("unwatchable");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("a-file"), b"").unwrap();
    // A root UNDER a regular file can never be created.
    let r = Arc::new(reactor(
        &base.join("a-file").join("spaces"),
        Arc::new(Counting::new()),
    ))
    .try_watch();
    assert!(
        matches!(r, Err(ref why) if why.contains("cannot create")),
        "{r:?}"
    );
}

/// Root cause 3, decided: an identical drop after a pass has settled is a NEW request and
/// fires again (gonk's review queue depends on exactly that), and the record describes the
/// LAST pass — an answer from an earlier pass does not stand in for a pass that said nothing.
#[test]
fn a_redrop_after_handling_fires_again_and_the_record_is_the_last_pass() {
    let root = scratch("redrop");
    reactive(&root, "jobs");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let handler = Arc::new(Counting::new());
    // pop() order: the first pass answers, the second says nothing.
    *handler.answers.lock().unwrap() = vec!["", "first answer"];
    let reactor = reactor(&root, Arc::clone(&handler) as _);
    let id = drop_tuple(&k, &out(), "urn:space:jobs", b"book me").unwrap();
    assert_eq!(reactor.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    let answer = root.join("jobs/outbox").join(format!("{id}.out"));
    assert_eq!(std::fs::read_to_string(&answer).unwrap(), "first answer");
    assert_eq!(
        drop_tuple(&k, &out(), "urn:space:jobs", b"book me").unwrap(),
        id
    );
    assert_eq!(reactor.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    assert_eq!(
        handler.calls(),
        2,
        "an identical drop after handling is a new request"
    );
    assert!(
        !answer.exists(),
        "the first pass's answer outlived the pass that said nothing"
    );
}

/// A handler that fails its first call and succeeds after.
struct FailOnce(AtomicUsize);

impl ikigai_resolve::Resolver for FailOnce {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        _: Request,
        _: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        if self.0.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            return Err(Error::Endpoint("calendar unreachable".into()));
        }
        Ok((
            Representation::new(ReprType::new("text/plain"), b"booked".to_vec()),
            ikigai_resolve::CacheStatus::Uncacheable,
        ))
    }
    fn is_cached(&self, _: &Request, _: &Capability) -> bool {
        false
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }
}

/// Root cause 3b: a failed tuple re-dropped and handled stayed a dead letter on main, so
/// `dead_letters` (the heartbeat's FAILING line) went on reporting it; and the converse, a
/// failure after a success, leaves no stale success beside it.
#[test]
fn a_tuple_is_in_one_terminal_stage_after_each_pass() {
    let root = scratch("handled-and-dead");
    reactive(&root, "jobs");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let reactor = reactor(&root, Arc::new(FailOnce(AtomicUsize::new(0))));
    let id = drop_tuple(&k, &out(), "urn:space:jobs", b"book me").unwrap();
    let at = |s: &str, ext: &str| {
        root.join("jobs")
            .join(s)
            .join(format!("{id}.{ext}"))
            .exists()
    };
    reactor.drain("jobs"); // fails
    assert!(at("error", "tuple") && at("error", "err"));
    drop_tuple(&k, &out(), "urn:space:jobs", b"book me").unwrap();
    reactor.drain("jobs"); // succeeds
    assert!(at("outbox", "tuple") && at("outbox", "out"));
    assert!(
        !at("error", "tuple") && !at("error", "err"),
        "a stale dead letter"
    );
    assert_eq!(ikigai_intray::dead_letters(&root)[0].count, 0);
    drop_tuple(&k, &out(), "urn:space:jobs", b"book me").unwrap();
    reactor.drain("jobs"); // fails again
    assert!(at("error", "tuple"));
    assert!(
        !at("outbox", "tuple") && !at("outbox", "out"),
        "a stale success"
    );
}

/// Hermes `once-only-recovery`: reactor A is live; a sibling claims a tuple and dies mid-pass.
/// On main A never looked at `.processing/` again (recovery ran once), and a new reactor B
/// could not recover beside live A, so the tuple was stranded until A exited. A's next drain
/// now recovers it, because A is the only live reactor left.
#[test]
fn a_crashed_siblings_claimed_tuple_is_recovered_by_the_survivor() {
    let root = scratch("once-only");
    reactive(&root, "jobs");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let first = drop_tuple(&k, &out(), "urn:space:jobs", b"first").unwrap();
    let a = reactor(&root, Arc::new(Counting::new()));
    assert_eq!(a.drain("jobs"), vec![(first, Outcome::Handled)]);
    // The sibling: claimed into `.processing/`, never settled.
    let second = drop_tuple(&k, &out(), "urn:space:jobs", b"second").unwrap();
    let staged = root
        .join("jobs/.processing")
        .join(format!("{second}.tuple"));
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::rename(
        root.join("jobs/inbox").join(format!("{second}.tuple")),
        &staged,
    )
    .unwrap();
    let _ = a.drain("jobs");
    assert!(
        !staged.exists(),
        "stranded in `.processing/` beside a live reactor"
    );
    assert!(root
        .join("jobs/error")
        .join(format!("{second}.tuple"))
        .exists());
}

/// …but never while ANOTHER live reactor shares the root: its tuple may be in flight.
#[test]
fn a_sweep_beside_another_live_reactor_moves_nothing() {
    let root = scratch("sweep-beside");
    reactive(&root, "jobs");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let a = reactor(&root, Arc::new(Counting::new()));
    let b = reactor(&root, Arc::new(Counting::new()));
    let _ = a.drain("jobs");
    let _ = b.drain("jobs");
    let id = drop_tuple(&k, &out(), "urn:space:jobs", b"in flight in b").unwrap();
    let staged = root.join("jobs/.processing").join(format!("{id}.tuple"));
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::rename(root.join("jobs/inbox").join(format!("{id}.tuple")), &staged).unwrap();
    assert!(a.sweep_interrupted().is_empty());
    assert!(staged.exists(), "recovered out from under a live sibling");
    drop(b);
    assert_eq!(a.sweep_interrupted().len(), 1, "alone now, A recovers it");
}
