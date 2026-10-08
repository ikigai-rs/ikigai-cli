//! Audit round 5, root cause 2 (ledger #877): every drop of a given tuple staged through the
//! ONE path `.dropping/<id>.tuple`, and every take through `.taking/<id>.tuple`. Identical
//! concurrent drops failed spuriously and could publish a torn tuple; a take that won its claim
//! could fail its read and lose the tuple. Plus the Hermes audit's `.taking` strand: a taker
//! that died mid-claim left a tuple no stage showed and no recovery looked at.

// Wall time and elapsed time for bounded races and claim ages: a native integration test of a
// native-only crate (notify, std::fs), never built for wasm.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{drop_tuple, iri, scratch, Counting};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Kernel, Request, Verb};
use ikigai_intray::{space, Outcome, SpaceReactor, CAP_OUT, CAP_READ, CAP_TAKE};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

fn all() -> Capability {
    Capability::scoped([CAP_OUT, CAP_READ, CAP_TAKE])
}

fn read(k: &Kernel, space: &str, args: &[(&str, &str)]) -> Result<Vec<u8>, Error> {
    let mut req = Request::new(Verb::Source, iri(space));
    for (n, v) in args {
        req = req.with_arg(*n, ArgRef::Inline(v.as_bytes().to_vec()));
    }
    block_on(k.issue(req, &all())).map(|r| r.bytes)
}

fn take(k: &Kernel, space: &str, args: &[(&str, &str)]) -> Result<Vec<u8>, Error> {
    let mut req = Request::new(Verb::Delete, iri(space));
    for (n, v) in args {
        req = req.with_arg(*n, ArgRef::Inline(v.as_bytes().to_vec()));
    }
    block_on(k.issue(req, &all())).map(|r| r.bytes)
}

/// The audit's `bug2`: 8 identical drops at once, 200 rounds. On main the losers failed with
/// `out publish: No such file or directory` for a drop documented as idempotent.
#[test]
fn concurrent_identical_drops_all_succeed() {
    let k = Arc::new(Kernel::new(Arc::new(space(scratch("dup-drop")))));
    let failures = Arc::new(Mutex::new(Vec::new()));
    for round in 0..200 {
        let content = format!("tuple {round}");
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (k, content, barrier, failures) = (
                    Arc::clone(&k),
                    content.clone(),
                    Arc::clone(&barrier),
                    Arc::clone(&failures),
                );
                std::thread::spawn(move || {
                    barrier.wait();
                    if let Err(e) = drop_tuple(&k, &all(), "urn:space:dup", content.as_bytes()) {
                        failures.lock().unwrap().push(e.to_string());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "{} identical drops failed; first: {:?}",
        failures.len(),
        failures.first()
    );
}

/// The audit's `bug2b`: a reader polling the inbox path while four identical 4 MiB drops race
/// must never see bytes that do not hash to the id.
#[test]
fn concurrent_identical_drops_never_publish_a_torn_tuple() {
    let root = scratch("torn");
    let k = Arc::new(Kernel::new(Arc::new(space(root.clone()))));
    let torn = Arc::new(AtomicUsize::new(0));
    for round in 0..40u32 {
        let mut content = vec![b'a'; 4 << 20];
        content[..4].copy_from_slice(&round.to_le_bytes());
        let id = blake3::hash(&content).to_hex().to_string();
        let path = root.join("big").join("inbox").join(format!("{id}.tuple"));
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (path, done, torn, id) = (
                path.clone(),
                Arc::clone(&done),
                Arc::clone(&torn),
                id.clone(),
            );
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    if let Ok(bytes) = std::fs::read(&path) {
                        if blake3::hash(&bytes).to_hex().as_str() != id {
                            torn.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        };
        let barrier = Arc::new(Barrier::new(4));
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let (k, content, barrier) = (Arc::clone(&k), content.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    drop_tuple(&k, &all(), "urn:space:big", &content).unwrap();
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        done.store(true, Ordering::SeqCst);
        reader.join().unwrap();
    }
    assert_eq!(
        torn.load(Ordering::SeqCst),
        0,
        "a reader saw an inbox tuple whose content does not hash to its id"
    );
}

/// The audit's `bug2c`, bounded: four takers by id against a dropper re-dropping identical
/// bytes for 5 s. A taker that won its claim must never come back with a read error (the
/// tuple consumed and delivered to nobody), and every successful take returns the tuple.
#[test]
fn a_take_that_wins_its_claim_always_delivers() {
    let k = Arc::new(Kernel::new(Arc::new(space(scratch("take-collide")))));
    let id = drop_tuple(&k, &all(), "urn:space:tc", b"same bytes").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let lost = Arc::new(Mutex::new(Vec::new()));
    let delivered = Arc::new(AtomicUsize::new(0));
    let dropper = {
        let (k, stop) = (Arc::clone(&k), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = drop_tuple(&k, &all(), "urn:space:tc", b"same bytes");
            }
        })
    };
    let end = Instant::now() + Duration::from_secs(5);
    let takers: Vec<_> = (0..4)
        .map(|_| {
            let (k, lost, delivered, id) = (
                Arc::clone(&k),
                Arc::clone(&lost),
                Arc::clone(&delivered),
                id.clone(),
            );
            std::thread::spawn(move || {
                while Instant::now() < end {
                    match take(&k, "urn:space:tc", &[("tuple", &id)]) {
                        Ok(bytes) => {
                            assert_eq!(bytes, b"same bytes");
                            delivered.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(Error::NotFound(_)) => {}
                        Err(e) => lost.lock().unwrap().push(e.to_string()),
                    }
                }
            })
        })
        .collect();
    for t in takers {
        t.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    dropper.join().unwrap();
    let lost = lost.lock().unwrap();
    assert!(
        lost.is_empty(),
        "{} takes failed after claiming ({} delivered); first: {:?}",
        lost.len(),
        delivered.load(Ordering::SeqCst),
        lost.first()
    );
    assert!(
        delivered.load(Ordering::SeqCst) > 0,
        "the race was exercised"
    );
}

/// The time-stamped claim name a take stages under, as of `age` ago.
fn claim_name(id: &str, age: Duration) -> String {
    let millis = (std::time::SystemTime::now() - age)
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{id}.{millis}.1.0.claim")
}

/// Strand a dropped tuple in `.taking/` the way a taker killed mid-claim does.
fn strand(root: &Path, space: &str, id: &str, file: &str) {
    let taking = root.join(space).join(".taking");
    std::fs::create_dir_all(&taking).unwrap();
    std::fs::rename(
        root.join(space).join("inbox").join(format!("{id}.tuple")),
        taking.join(file),
    )
    .unwrap();
}

/// Hermes `taking-strand`: a claim abandoned long enough ago goes back to the inbox at the
/// next rd or take, so it is neither invisible nor lost.
#[test]
fn an_abandoned_take_claim_is_requeued() {
    let root = scratch("strand");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"precious").unwrap();
    strand(
        &root,
        "jobs",
        &id,
        &claim_name(&id, Duration::from_secs(600)),
    );
    let listed = String::from_utf8(read(&k, "urn:space:jobs", &[]).unwrap()).unwrap();
    assert_eq!(listed, id, "the stranded tuple is back in the inbox");
    assert_eq!(
        take(&k, "urn:space:jobs", &[("tuple", &id)]).unwrap(),
        b"precious"
    );
}

/// …and the pre-unique-name spelling (`.taking/<id>.tuple`, the shape the Hermes probe
/// built), judged by its drop time since its name carries no claim time.
#[test]
fn an_abandoned_legacy_claim_is_requeued_by_its_age() {
    let root = scratch("strand-legacy");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"precious").unwrap();
    strand(&root, "jobs", &id, &format!("{id}.tuple"));
    // Fresh: a take might still be reading it, so it stays put.
    assert!(read(&k, "urn:space:jobs", &[]).unwrap().is_empty());
    let staged = root.join("jobs/.taking").join(format!("{id}.tuple"));
    let f = std::fs::File::options().write(true).open(&staged).unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(600))
        .unwrap();
    drop(f);
    let listed = String::from_utf8(read(&k, "urn:space:jobs", &[]).unwrap()).unwrap();
    assert_eq!(listed, id);
}

/// A claim younger than the bound belongs to a take that may still be reading it.
#[test]
fn a_recent_take_claim_is_left_alone() {
    let root = scratch("strand-fresh");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"in flight").unwrap();
    let file = claim_name(&id, Duration::from_secs(1));
    strand(&root, "jobs", &id, &file);
    assert!(read(&k, "urn:space:jobs", &[]).unwrap().is_empty());
    assert!(root.join("jobs/.taking").join(file).exists());
}

/// Write a file into an inbox under a tuple id its bytes do not hash to (what a torn or
/// out-of-band write leaves).
fn plant_corrupt(root: &Path, space: &str) -> String {
    let id = blake3::hash(b"the real tuple").to_hex().to_string();
    let inbox = root.join(space).join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    std::fs::write(inbox.join(format!("{id}.tuple")), b"the real tu").unwrap();
    id
}

#[test]
fn readers_do_not_trust_a_file_that_is_not_its_tuple() {
    let root = scratch("corrupt");
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = plant_corrupt(&root, "q");
    // rd by id refuses to hand it out, and leaves it (rd is non-destructive).
    let r = read(&k, "urn:space:q", &[("tuple", &id)]);
    assert!(
        matches!(r, Err(Error::Endpoint(ref e)) if e.contains("does not hash")),
        "{r:?}"
    );
    // A match never selects it.
    let m = read(&k, "urn:space:q", &[("match", "ASK { }")]).unwrap();
    assert!(m.is_empty(), "matched a corrupt tuple");
    // take by id dead-letters it instead of delivering it.
    let t = take(&k, "urn:space:q", &[("tuple", &id)]);
    assert!(
        matches!(t, Err(Error::Endpoint(ref e)) if e.contains("error/")),
        "{t:?}"
    );
    assert!(root.join("q/error").join(format!("{id}.tuple")).exists());
    assert!(root.join("q/error").join(format!("{id}.err")).exists());
    // A pop skips it and reports the space empty.
    let id2 = plant_corrupt(&root, "p");
    assert!(matches!(
        take(&k, "urn:space:p", &[]),
        Err(Error::NotFound(_))
    ));
    assert!(root.join("p/error").join(format!("{id2}.tuple")).exists());
}

#[test]
fn a_reactor_dead_letters_a_file_that_is_not_its_tuple() {
    let root = scratch("corrupt-reactor");
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs/handler"), "urn:test:handler").unwrap();
    let id = plant_corrupt(&root, "jobs");
    let handler = Arc::new(Counting::new());
    let reactor = SpaceReactor::new(
        root.clone(),
        Arc::clone(&handler) as Arc<dyn ikigai_resolve::Resolver>,
        Capability::scoped(["urn:cap:demo"]),
    );
    let outcomes = reactor.drain("jobs");
    assert!(
        matches!(&outcomes[..], [(i, Outcome::Errored(why))] if *i == id && why.contains("does not hash")),
        "{outcomes:?}"
    );
    assert_eq!(handler.calls(), 0, "the handler never saw the bytes");
}
