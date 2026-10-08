//! Ledger #887 item 6: the dead-letter hook ran UNDER the reactor's pass lock — inside
//! `process` (which holds it from claim to settle), inside the periodic recovery sweep, and
//! inside the startup recovery (a `OnceLock` initializer) — so a hook that drove the same
//! reactor (`drain`, `process`, `sweep_interrupted`) waited forever on a lock its own thread
//! held. Nothing did that yet; these are the guard. Each runs the reactor on its own thread and
//! fails if it has not returned in a bound, rather than hanging the suite.

// Wall time for the bounded waits: a native integration test of a native-only crate.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{drop_tuple, scratch, Counting};
use ikigai_core::{Capability, Error, Kernel, Representation, Request, SpaceEntry};
use ikigai_intray::{space, Outcome, SpaceReactor, CAP_OUT, PROCESSING_DIR};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

/// Long enough for any honest pass on a loaded CI box; a deadlock never finishes.
const BOUND: Duration = Duration::from_secs(20);

/// A handler that always fails, so every pass dead-letters.
struct Failing;

impl ikigai_resolve::Resolver for Failing {
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
        Err(Error::Endpoint("the mailer is down".to_string()))
    }
    fn is_cached(&self, _: &Request, _: &Capability) -> bool {
        false
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }
}

fn reactive(root: &Path, name: &str) {
    std::fs::create_dir_all(root.join(name)).unwrap();
    std::fs::write(root.join(name).join("handler"), "urn:test:handler").unwrap();
}

fn drop_into(root: &Path, name: &str, content: &[u8]) -> String {
    let k = Kernel::new(Arc::new(space(root.to_path_buf())));
    drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        &format!("urn:space:{name}"),
        content,
    )
    .unwrap()
}

/// Leave `id` in `name`'s `.processing/`, as a reactor that crashed mid-pass does.
fn strand(root: &Path, name: &str, id: &str) {
    let processing = root.join(name).join(PROCESSING_DIR);
    std::fs::create_dir_all(&processing).unwrap();
    std::fs::rename(
        root.join(name).join("inbox").join(format!("{id}.tuple")),
        processing.join(format!("{id}.tuple")),
    )
    .unwrap();
}

/// A reactor whose dead-letter hook DRIVES THE SAME REACTOR: it drains the `followup` space
/// (whose tuple a working handler... here the same failing one, which is fine: the point is
/// that the call returns) and records what it heard.
fn reentrant(
    root: PathBuf,
    handler: Arc<dyn ikigai_resolve::Resolver>,
) -> (Arc<SpaceReactor>, Arc<Mutex<Vec<String>>>) {
    let me: Arc<OnceLock<Weak<SpaceReactor>>> = Arc::new(OnceLock::new());
    let heard = Arc::new(Mutex::new(Vec::new()));
    let (hook_me, hook_heard) = (Arc::clone(&me), Arc::clone(&heard));
    let reactor = Arc::new(
        SpaceReactor::new(root, handler, Capability::root()).on_dead_letter(
            move |space, tuple, _why| {
                hook_heard.lock().unwrap().push(format!("{space}/{tuple}"));
                if let Some(reactor) = hook_me.get().and_then(Weak::upgrade) {
                    // Re-enter through every public entry that takes the pass lock.
                    reactor.drain("followup");
                    reactor.sweep_interrupted();
                }
            },
        ),
    );
    me.set(Arc::downgrade(&reactor)).unwrap();
    (reactor, heard)
}

/// Run `f` on its own thread and fail if it has not returned within [`BOUND`].
fn within_bound<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(BOUND).unwrap_or_else(|_| {
        panic!("{what} did not return in {BOUND:?}: the dead-letter hook deadlocked the reactor")
    })
}

/// A hook that drains the reactor from inside `process`'s dead letter.
#[test]
fn a_hook_can_drive_the_reactor_from_a_failed_pass() {
    let root = scratch("hook-process");
    reactive(&root, "jobs");
    reactive(&root, "followup");
    let id = drop_into(&root, "jobs", b"work");
    let follow = drop_into(&root, "followup", b"next");
    let (reactor, heard) = reentrant(root.clone(), Arc::new(Failing));
    // Startup recovery first, outside the bound under test.
    let _ = reactor.recover_interrupted();
    let outcome = within_bound("process", {
        let reactor = Arc::clone(&reactor);
        let id = id.clone();
        move || reactor.process("jobs", &id)
    });
    assert!(matches!(outcome, Outcome::Errored(_)), "{outcome:?}");
    assert_eq!(
        *heard.lock().unwrap(),
        vec![format!("jobs/{id}"), format!("followup/{follow}")],
        "the hook heard the pass, then the follow-up it drove itself"
    );
}

/// A hook that drives the reactor from a dead letter the PERIODIC sweep produced.
#[test]
fn a_hook_can_drive_the_reactor_from_the_periodic_sweep() {
    let root = scratch("hook-sweep");
    reactive(&root, "jobs");
    reactive(&root, "followup");
    let (reactor, heard) = reentrant(root.clone(), Arc::new(Counting::new()));
    assert_eq!(
        reactor.recover_interrupted(),
        Ok(&[][..]),
        "nothing at startup"
    );
    // A sibling crashed mid-pass after startup; the next sweep dead-letters its tuple.
    let id = drop_into(&root, "jobs", b"stranded");
    strand(&root, "jobs", &id);
    let recovered = within_bound("sweep_interrupted", {
        let reactor = Arc::clone(&reactor);
        move || reactor.sweep_interrupted()
    });
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert_eq!(*heard.lock().unwrap(), vec![format!("jobs/{id}")]);
}

/// A hook that drives the reactor from a dead letter the STARTUP recovery produced — inside
/// the `OnceLock` initializer, where re-entering `process` would wait on its own init.
#[test]
fn a_hook_can_drive_the_reactor_from_the_startup_recovery() {
    let root = scratch("hook-startup");
    reactive(&root, "jobs");
    reactive(&root, "followup");
    let id = drop_into(&root, "jobs", b"stranded at boot");
    strand(&root, "jobs", &id);
    let handler = Arc::new(Counting::new());
    let (reactor, heard) = reentrant(root.clone(), handler.clone());
    let follow = drop_into(&root, "followup", b"next");
    let report = within_bound("recover_interrupted", {
        let reactor = Arc::clone(&reactor);
        move || {
            reactor
                .recover_interrupted()
                .map(<[_]>::len)
                .map_err(str::to_string)
        }
    });
    assert_eq!(report, Ok(1));
    assert_eq!(*heard.lock().unwrap(), vec![format!("jobs/{id}")]);
    assert_eq!(
        handler.calls(),
        1,
        "the hook's drain ran the follow-up: {follow}"
    );
}
