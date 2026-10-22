//! The tuple codec (ledger #2017): a space that stores its tuples encoded, through a codec
//! the host supplies, while every caller and every handler sees only the plaintext.
//!
//! The codec here is a test double, not a cipher: a one-byte key in front of the body, which
//! is XORed with it. `decode` opens a tuple stored under ANY key (it reads the key from the
//! file, as a multi-identity unsealer does), `is_current` says whether that key is the
//! codec's current one, and a file without the marker does not decode at all.

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, EndpointSpace, Error, Kernel, ReprType, Representation, Request,
    SpaceEntry, UriTemplate, Verb,
};
use ikigai_intray::{
    tuple_id, Interrupted, Outcome, SpaceEndpoint, SpaceReactor, TupleCodec, CAP_OUT, CAP_READ,
    CAP_RETRY, CAP_TAKE, DROPPING_DIR, ERROR_DIR, INBOX_DIR, OUTBOX_DIR, PROCESSING_DIR,
    SPACE_TEMPLATE, TAKING_DIR,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MARK: &[u8] = b"XOR1";

struct Xor {
    key: u8,
}

impl TupleCodec for Xor {
    fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = MARK.to_vec();
        out.push(self.key);
        out.extend(plain.iter().map(|b| b ^ self.key));
        Ok(out)
    }
    fn decode(&self, stored: &[u8]) -> Result<Vec<u8>, String> {
        let rest = stored
            .strip_prefix(MARK)
            .ok_or("no XOR1 marker: not a sealed tuple")?;
        let (&key, body) = rest.split_first().ok_or("no key byte")?;
        Ok(body.iter().map(|b| b ^ key).collect())
    }
    fn is_current(&self, stored: &[u8]) -> bool {
        stored.strip_prefix(MARK).and_then(|r| r.first()) == Some(&self.key)
    }
}

fn codec(key: u8) -> Arc<dyn TupleCodec> {
    Arc::new(Xor { key })
}

fn kernel(root: &Path, key: u8) -> Kernel {
    Kernel::new(Arc::new(EndpointSpace::new().bind(
        UriTemplate::parse(SPACE_TEMPLATE).unwrap(),
        SpaceEndpoint::new(root.to_path_buf()).with_codec(codec(key)),
    )))
}

fn all() -> Capability {
    Capability::scoped([CAP_OUT, CAP_READ, CAP_TAKE, CAP_RETRY])
}

fn issue(k: &Kernel, verb: Verb, args: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut request = Request::new(verb, iri("urn:space:jobs"));
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.to_vec()));
    }
    block_on(k.issue(request, &all())).map(|r| r.bytes)
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

fn tuple_file(root: &Path, stage: &str, id: &str) -> PathBuf {
    root.join("jobs").join(stage).join(format!("{id}.tuple"))
}

/// Plant a file in the inbox that is named by its own hash (so it passes the integrity check)
/// and does not decode: written past `out`, or sealed to a key the codec lost.
fn plant_undecodable(root: &Path) -> String {
    let bytes = b"plain text that was never sealed".to_vec();
    let id = tuple_id(&bytes);
    let inbox = root.join("jobs").join(INBOX_DIR);
    std::fs::create_dir_all(&inbox).unwrap();
    std::fs::write(inbox.join(format!("{id}.tuple")), &bytes).unwrap();
    id
}

const TURTLE: &[u8] = b"<urn:t:1> <urn:p:status> \"open\" .\n";
const ASK_OPEN: &str = "ASK { ?s <urn:p:status> \"open\" }";

#[test]
fn out_stores_encoded_bytes_and_the_id_is_their_hash() {
    let root = scratch("codec-out");
    let k = kernel(&root, 7);
    let id = drop_tuple(&k, &all(), "urn:space:jobs", TURTLE).unwrap();

    let stored = std::fs::read(tuple_file(&root, INBOX_DIR, &id)).unwrap();
    assert_ne!(stored, TURTLE, "the file on disk is not the plaintext");
    assert!(stored.starts_with(MARK));
    assert_eq!(
        id,
        tuple_id(&stored),
        "the id is the hash of the stored bytes"
    );
    assert_ne!(id, tuple_id(TURTLE), "and so not of the plaintext");
}

#[test]
fn rd_and_take_answer_the_plaintext() {
    let root = scratch("codec-rd-take");
    let k = kernel(&root, 7);
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"first").unwrap();
    let other = drop_tuple(&k, &all(), "urn:space:jobs", b"second").unwrap();

    assert_eq!(
        issue(&k, Verb::Source, &[("tuple", id.as_bytes())]).unwrap(),
        b"first"
    );
    // By `tuple=`, by the piped id, and as a work-queue pop: each answers plaintext.
    assert_eq!(
        issue(&k, Verb::Delete, &[("content", id.as_bytes())]).unwrap(),
        b"first"
    );
    assert_eq!(issue(&k, Verb::Delete, &[]).unwrap(), b"second");
    assert!(!tuple_file(&root, INBOX_DIR, &other).exists());
    assert!(matches!(
        issue(&k, Verb::Delete, &[]),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn match_is_evaluated_over_the_plaintext() {
    let root = scratch("codec-match");
    let k = kernel(&root, 7);
    let open = drop_tuple(&k, &all(), "urn:space:jobs", TURTLE).unwrap();
    let _closed = drop_tuple(
        &k,
        &all(),
        "urn:space:jobs",
        b"<urn:t:2> <urn:p:status> \"closed\" .\n",
    )
    .unwrap();

    let hits = text(issue(&k, Verb::Source, &[("match", ASK_OPEN.as_bytes())]).unwrap());
    assert_eq!(hits, open, "only the open tuple matches, read as plaintext");
    assert_eq!(
        issue(&k, Verb::Delete, &[("match", ASK_OPEN.as_bytes())]).unwrap(),
        TURTLE
    );
    assert!(!tuple_file(&root, INBOX_DIR, &open).exists());
}

#[test]
fn an_undecodable_tuple_is_a_typed_refusal_that_names_it() {
    let root = scratch("codec-corrupt");
    let k = kernel(&root, 7);
    let _good = drop_tuple(&k, &all(), "urn:space:jobs", TURTLE).unwrap();
    let bad = plant_undecodable(&root);

    let names_it = |result: Result<Vec<u8>, Error>| match result {
        Err(Error::Conflict(why)) => assert!(why.contains(&bad), "names the tuple: {why}"),
        other => panic!("expected a Conflict naming {bad}, got {other:?}"),
    };
    names_it(issue(&k, Verb::Source, &[("tuple", bad.as_bytes())]));
    // A match over a space holding it refuses; it does not answer as if the tuple were absent.
    names_it(issue(&k, Verb::Source, &[("match", ASK_OPEN.as_bytes())]));
    names_it(issue(&k, Verb::Delete, &[("tuple", bad.as_bytes())]));
    names_it(issue(&k, Verb::Delete, &[("match", ASK_OPEN.as_bytes())]));

    // A refused take is not a lost tuple: it is back in the inbox under its own id, and
    // nothing was quarantined or left staged.
    assert!(tuple_file(&root, INBOX_DIR, &bad).exists());
    assert!(!tuple_file(&root, ERROR_DIR, &bad).exists());
    let taking = root.join("jobs").join(TAKING_DIR);
    assert_eq!(
        std::fs::read_dir(&taking).map(|d| d.count()).unwrap_or(0),
        0
    );
}

#[test]
fn a_pop_refuses_rather_than_skipping_an_undecodable_tuple() {
    let root = scratch("codec-pop");
    let k = kernel(&root, 7);
    let bad = plant_undecodable(&root);
    match issue(&k, Verb::Delete, &[]) {
        Err(Error::Conflict(why)) => assert!(why.contains(&bad), "{why}"),
        other => panic!("expected a Conflict naming {bad}, got {other:?}"),
    }
    assert!(tuple_file(&root, INBOX_DIR, &bad).exists());
}

/// A handler double that records the `content` each fire carried.
struct Recording {
    contents: Mutex<Vec<Vec<u8>>>,
}

impl Recording {
    fn new() -> Arc<Self> {
        Arc::new(Recording {
            contents: Mutex::new(Vec::new()),
        })
    }
    fn contents(&self) -> Vec<Vec<u8>> {
        self.contents.lock().unwrap().clone()
    }
}

impl ikigai_resolve::Resolver for Recording {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        request: Request,
        _: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        if let Some(ArgRef::Inline(bytes)) = request.args.get("content") {
            self.contents.lock().unwrap().push(bytes.clone());
        }
        Ok((
            Representation::new(ReprType::new("text/plain"), b"done".to_vec()),
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

fn reactive(root: &Path) {
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs").join("handler"), "urn:test:handler").unwrap();
}

fn reactor(root: &Path, handler: Arc<Recording>, key: u8) -> SpaceReactor {
    SpaceReactor::new(
        root.to_path_buf(),
        handler,
        Capability::scoped(["urn:cap:demo"]),
    )
    .with_codec(codec(key))
}

#[test]
fn the_reactor_fires_its_handler_with_the_plaintext() {
    let root = scratch("codec-react");
    reactive(&root);
    let k = kernel(&root, 7);
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"work").unwrap();
    let handler = Recording::new();
    let r = reactor(&root, Arc::clone(&handler), 7);

    assert_eq!(r.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    assert_eq!(handler.contents(), vec![b"work".to_vec()]);
    // Settled under its stored id, still encoded, and readable as plaintext by `rd`.
    let settled = std::fs::read(tuple_file(&root, OUTBOX_DIR, &id)).unwrap();
    assert!(settled.starts_with(MARK));
    assert_eq!(
        issue(
            &k,
            Verb::Source,
            &[("tuple", id.as_bytes()), ("state", b"outbox")]
        )
        .unwrap(),
        b"work"
    );
}

#[test]
fn the_reactor_dead_letters_an_undecodable_tuple_without_firing() {
    let root = scratch("codec-react-bad");
    reactive(&root);
    let bad = plant_undecodable(&root);
    let handler = Recording::new();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let told = Arc::clone(&heard);
    let r = reactor(&root, Arc::clone(&handler), 7).on_dead_letter(move |_, id, why| {
        told.lock().unwrap().push((id.to_string(), why.to_string()));
    });

    let outcome = r.drain("jobs");
    assert!(
        matches!(&outcome[..], [(id, Outcome::Errored(why))] if *id == bad && why.contains(&bad)),
        "{outcome:?}"
    );
    assert!(handler.contents().is_empty(), "the handler was never fired");
    let note =
        std::fs::read_to_string(root.join("jobs").join(ERROR_DIR).join(format!("{bad}.err")))
            .unwrap();
    assert!(
        note.contains(&bad) && note.contains("does not decode"),
        "{note}"
    );
    assert_eq!(heard.lock().unwrap().len(), 1, "and the hook heard it");
}

#[test]
fn recovery_and_retry_move_encoded_tuples_by_name() {
    let root = scratch("codec-recover");
    reactive(&root);
    let k = kernel(&root, 7);
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"interrupted work").unwrap();
    // A reactor that stopped mid-pass left the (encoded) tuple claimed.
    let processing = root.join("jobs").join(PROCESSING_DIR);
    std::fs::create_dir_all(&processing).unwrap();
    std::fs::rename(
        tuple_file(&root, INBOX_DIR, &id),
        processing.join(format!("{id}.tuple")),
    )
    .unwrap();

    // The default policy dead-letters it, still encoded.
    let handler = Recording::new();
    let r = reactor(&root, Arc::clone(&handler), 7);
    let recovered = r.recover_interrupted().unwrap().to_vec();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].outcome, Ok(Interrupted::DeadLetter));
    assert!(std::fs::read(tuple_file(&root, ERROR_DIR, &id))
        .unwrap()
        .starts_with(MARK));
    // `rd state=error` reads it as plaintext.
    assert_eq!(
        issue(
            &k,
            Verb::Source,
            &[("tuple", id.as_bytes()), ("state", b"error")]
        )
        .unwrap(),
        b"interrupted work"
    );

    // `retry=` re-arms it, and the next pass fires the handler with the plaintext.
    assert_eq!(
        text(issue(&k, Verb::Sink, &[("retry", id.as_bytes())]).unwrap()).trim(),
        id
    );
    assert_eq!(r.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    assert_eq!(handler.contents(), vec![b"interrupted work".to_vec()]);
}

#[test]
fn a_requeued_interrupted_tuple_runs_again_with_the_plaintext() {
    let root = scratch("codec-requeue");
    reactive(&root);
    let k = kernel(&root, 7);
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"idempotent").unwrap();
    let processing = root.join("jobs").join(PROCESSING_DIR);
    std::fs::create_dir_all(&processing).unwrap();
    std::fs::rename(
        tuple_file(&root, INBOX_DIR, &id),
        processing.join(format!("{id}.tuple")),
    )
    .unwrap();

    let handler = Recording::new();
    let r = reactor(&root, Arc::clone(&handler), 7).on_interrupted(Interrupted::Requeue);
    assert_eq!(r.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    assert_eq!(handler.contents(), vec![b"idempotent".to_vec()]);
}

#[test]
fn reencode_moves_each_stale_tuple_to_a_new_id() {
    let root = scratch("codec-reencode");
    let old_key = kernel(&root, 7);
    let a = drop_tuple(&old_key, &all(), "urn:space:jobs", b"alpha").unwrap();
    let b = drop_tuple(&old_key, &all(), "urn:space:jobs", b"beta").unwrap();

    // The key rotates: the space opens the old tuples and stores new ones under the new key.
    let endpoint = SpaceEndpoint::new(root.clone()).with_codec(codec(9));
    let mut moved = endpoint.reencode("jobs").unwrap();
    moved.sort_by(|x, y| x.old.cmp(&y.old));
    let mut olds = vec![a.clone(), b.clone()];
    olds.sort();
    assert_eq!(
        moved.iter().map(|m| m.old.clone()).collect::<Vec<_>>(),
        olds
    );

    let new_key = kernel(&root, 9);
    for m in &moved {
        assert!(
            !tuple_file(&root, INBOX_DIR, &m.old).exists(),
            "old id gone"
        );
        let stored = std::fs::read(tuple_file(&root, INBOX_DIR, &m.new)).unwrap();
        assert_eq!(stored[MARK.len()], 9, "stored under the new key");
        assert_eq!(m.new, tuple_id(&stored));
    }
    let a_now = &moved.iter().find(|m| m.old == a).unwrap().new;
    assert_eq!(
        issue(&new_key, Verb::Source, &[("tuple", a_now.as_bytes())]).unwrap(),
        b"alpha"
    );
    // Nothing is left staged, and a second pass finds everything current.
    for stage in [DROPPING_DIR, TAKING_DIR] {
        let dir = root.join("jobs").join(stage);
        assert_eq!(std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0), 0);
    }
    assert!(endpoint.reencode("jobs").unwrap().is_empty());
}

#[test]
fn reencode_refuses_with_nothing_moved_when_one_tuple_does_not_decode() {
    let root = scratch("codec-reencode-bad");
    let old_key = kernel(&root, 7);
    let good = drop_tuple(&old_key, &all(), "urn:space:jobs", b"alpha").unwrap();
    let bad = plant_undecodable(&root);
    let endpoint = SpaceEndpoint::new(root.clone()).with_codec(codec(9));
    // A codec whose `is_current` is false for the planted file too, so it is attempted.
    match endpoint.reencode("jobs") {
        Err(Error::Conflict(why)) => assert!(why.contains(&bad), "{why}"),
        other => panic!("expected a Conflict naming {bad}, got {other:?}"),
    }
    assert!(
        tuple_file(&root, INBOX_DIR, &good).exists(),
        "nothing moved"
    );
}

#[test]
fn discard_staging_clears_leftover_drops_and_claims() {
    let root = scratch("codec-discard");
    let space = root.join("jobs");
    for (stage, file) in [
        (DROPPING_DIR, "x.1.2.3.drop"),
        (TAKING_DIR, "y.1.2.3.claim"),
    ] {
        std::fs::create_dir_all(space.join(stage)).unwrap();
        std::fs::write(space.join(stage).join(file), b"leftover").unwrap();
    }
    let endpoint = SpaceEndpoint::new(root.clone());
    assert_eq!(endpoint.discard_staging("jobs").unwrap(), 2);
    assert_eq!(endpoint.discard_staging("jobs").unwrap(), 0);
    assert!(endpoint.discard_staging("../jobs").is_err());
}
