//! `ikigai-intray` — the intray as a **tuplespace**.
//!
//! A tuplespace is Linda's coordination model (Gelernter): processes communicate by
//! dropping *tuples* into a shared space and reading them back by *associative match*,
//! decoupled in space and time. `urn:space:{name}` is that space on the ikigai substrate:
//!
//! - **`out`** — **Sink** a tuple into the space. Content-addressed (blake3), so an
//!   identical drop is idempotent while the tuple is pending; once a reactor has settled it,
//!   the same bytes dropped again are a new request and fire again.
//! - **`rd`** — **Source** the space: list the tuple ids, read one with `tuple=<id>`, or
//!   list the ids of tuples matching a `match=<ASK>` template. Non-destructive.
//! - **`take`** — **Delete** a tuple, *returning its content*: claim a specific tuple
//!   (`tuple=<id>`, or the id as the piped/trailing `content`: `delete urn:space:q <id>`),
//!   the first tuple matching a `match=<ASK>` template, or any tuple
//!   (no selector = a work-queue pop). Destructive and **atomic** — a rename-based
//!   compare-and-swap means two racers never both claim the same tuple.
//!
//! **Associative match** is a SPARQL ASK over the tuple's graph (`match=<query>`): a tuple
//! matches iff the ASK holds when its Turtle is the default graph. This is strictly more
//! than Linda's positional match — the whole graph-pattern language, not field equality —
//! and a non-RDF tuple simply never matches a template (take it by id or FIFO instead).
//! The one part of SPARQL a template may NOT use is `SERVICE`: a match is a question about a
//! tuple's own graph and never leaves the host (see `parse_match`). And a template is bounded
//! like every other door that parses caller SPARQL: refused over 1 MiB or nested past 64
//! levels or past the store's algebra bounds, and parsed and evaluated on a stack sized for
//! its text within a TIME budget, the caller answered with a `Timeout` at it (see
//! `with_template`).
//! A TUPLE is bounded the same way where a match parses it: one that nests RDF 1.2 triple
//! terms deeper than 64 is refused at `out`, and one already on disk is never parsed, so it
//! never matches (see `check_tuple_nesting`).
//!
//! The space is *physical and inspectable* — tuples are files under a jailed root, moving
//! through an **inbox → outbox → error** state machine. The [`SpaceReactor`] makes a space
//! ACTIVE (Linda's `eval`): a `handler` file names a URI, and a dropped tuple is claimed,
//! fired at that handler under the reactor's own scoped authority, and moved to `outbox`
//! (handled) or `error` (dead-letter). Two things Linda never had and this does: `out`/`take`
//! are **capability-gated**, and tuples can be **sealed** at rest by a host-supplied
//! [`TupleCodec`] ([`SpaceEndpoint::with_codec`], [`SpaceReactor::with_codec`]): `out` encodes
//! before the file is written, and `rd`, `take`, every `match=` and every reactor pass decode
//! after it is read, so a template matches PLAINTEXT and no caller ever sees the stored form.
//! The default is [`IdentityCodec`], which stores the tuple as given.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgRef, Capability, Description, Endpoint, EndpointSpace, Error, Invocation, Iri,
    ReprType, Representation, Request, Result, UriTemplate, Verb,
};
use ikigai_store::budget::{check_query, EvaluationBudget};
use ikigai_store::limits;
use ikigai_store::service::{self, refuse_service_with};
use notify::{RecursiveMode, Watcher};
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::sparql::{CancellationToken, QueryResults};
use oxigraph::store::Store;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The tuplespace URI template: `urn:space:{name}` — the `{name}` is the space's identity.
pub const SPACE_TEMPLATE: &str = "urn:space:{name}";

/// The XSD datatype every scalar input of this module declares.
///
/// A tuple id, a space name and a SPARQL ASK are all strings on the wire. `xsd:string` is a
/// claim about what the WIRE carries, not about the value's grammar — there is no XSD
/// datatype for "a query" — and the summaries carry the rest (conformance PENDING #14).
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// `out` (dropping a tuple) requires this capability — the gate a stranger drops under.
pub const CAP_OUT: &str = "urn:cap:space:out";
/// `rd` (reading the space, non-destructively) requires this capability, or the one space's
/// own [`cap_read_space`] grant.
pub const CAP_READ: &str = "urn:cap:space:read";

/// What `rd` DECLARES: the whole read family, `urn:cap:space:read*`. The kernel's floor reads a
/// trailing `*` as "holds any grant under this prefix" (the `CAP_READ_ANY` of ikigai-store,
/// for the same reason), so it is satisfied by the broad [`CAP_READ`] and by every per-space
/// [`cap_read_space`], and by nothing in the `out`/`take` families. `urn:cap:space:read:*`
/// would miss the broad token (no trailing colon on it). Which space a per-space grant opens
/// is the module's own check, made in `invoke` against the `{name}` being read.
pub const CAP_READ_ANY: &str = "urn:cap:space:read*";

/// The grant that reads ONE space: `urn:cap:space:read:{name}` (ledger #1513). A holder can
/// list, match and read every stage of that space and of no other; the broad [`CAP_READ`]
/// still reads them all. The parameter goes LAST, as in every per-name grant in the system
/// (`urn:cap:bayes:read:{model}`, `urn:cap:ledger:read:{name}`), and it is matched EXACTLY,
/// like every other grant: `urn:cap:space:read:contact` does not read `contact-blocks`.
///
/// ```
/// use ikigai_intray::cap_read_space;
/// assert_eq!(cap_read_space("contact"), "urn:cap:space:read:contact");
/// ```
///
/// What it is for: a reactor that must read one tuple of a NEIGHBORING space (the edge's
/// contact-blocks reactor reads the enquiry a "not spam" click names, out of the contact
/// space's outbox) without holding the read of every space on the host.
pub fn cap_read_space(name: &str) -> String {
    format!("{CAP_READ}:{name}")
}
/// `take` (removing a tuple) requires this capability — strictly more authority than read,
/// so a reader can observe the space without being able to consume from it.
pub const CAP_TAKE: &str = "urn:cap:space:take";
/// `retry=<id>` (re-arming a dead letter for another pass) requires this capability, on top
/// of [`CAP_OUT`] (ledger #887). A dead letter can be one the reactor parked ON PURPOSE — an
/// interrupted pass it refused to run twice ([`Interrupted::DeadLetter`]), or a handler the
/// host refused — so re-arming it is the operator's decision, not a dropper's: none of the
/// tuplespace verbs implies it, and no reactive handler holds it by default.
pub const CAP_RETRY: &str = "urn:cap:space:retry";

/// Where a [`SpaceReactor`] stages a tuple it has claimed for a pass:
/// `<root>/<space>/.processing/<id>.tuple`, renamed to `outbox` or `error` when the pass
/// settles. `rd state=processing` reads it.
///
/// Public because it is a stage of the queue like the other three, and anything that
/// COUNTS a space's queue must count it: a tuple here is neither waiting nor done, and a
/// depth that omits it reads as an empty queue while work is in flight — or stranded
/// (ledger #738). See [`SpaceReactor::recover_interrupted`] for what happens to one a
/// stopped reactor left behind.
pub const PROCESSING_DIR: &str = ".processing";

/// A space's live drops: `<root>/<space>/inbox/<id>.tuple`. `rd state=inbox`.
pub const INBOX_DIR: &str = "inbox";
/// Where a reactor moves a tuple its handler answered: `<root>/<space>/outbox/`, beside an
/// `<id>.out` note of what it said. `rd state=outbox`.
pub const OUTBOX_DIR: &str = "outbox";
/// The dead letters: `<root>/<space>/error/`, each beside an `<id>.err` note. `rd state=error`.
pub const ERROR_DIR: &str = "error";
/// Where `out` writes a tuple before it renames it into the inbox:
/// `<root>/<space>/.dropping/`. A file here was never published; see
/// [`SpaceEndpoint::discard_staging`].
pub const DROPPING_DIR: &str = ".dropping";
/// Where a take stages the tuple it claimed: `<root>/<space>/.taking/`. See
/// [`SpaceEndpoint::discard_staging`].
pub const TAKING_DIR: &str = ".taking";

/// Every directory this crate may create under a space (`<root>/<space>/…`), so a host that
/// keeps the tree private can make them itself, with its own mode, before the space first
/// needs one, without spelling a name this crate owns.
///
/// ```
/// use ikigai_intray::{SPACE_DIRS, INBOX_DIR, PROCESSING_DIR};
/// assert!(SPACE_DIRS.contains(&INBOX_DIR) && SPACE_DIRS.contains(&PROCESSING_DIR));
/// assert_eq!(SPACE_DIRS.len(), 6);
/// ```
pub const SPACE_DIRS: [&str; 6] = [
    INBOX_DIR,
    OUTBOX_DIR,
    ERROR_DIR,
    PROCESSING_DIR,
    DROPPING_DIR,
    TAKING_DIR,
];

/// How a space stores a tuple at rest, supplied by the HOST
/// ([`SpaceEndpoint::with_codec`], [`SpaceReactor::with_codec`]).
///
/// [`encode`](TupleCodec::encode) runs on `out`, before the file is written, and
/// [`decode`](TupleCodec::decode) wherever stored bytes are read for a caller or a handler:
/// `rd tuple=`, `take`, every `match=` evaluation (inside its time budget) and every reactor
/// pass. Nothing else in the crate looks inside a tuple file, so recovery, `retry=`, the stage
/// moves and dead letters handle an encoded file exactly as they handle any other: by name.
///
/// ★ **A tuple's id is the hash of its STORED bytes** ([`tuple_id`] over what `encode`
/// returned). Anyone who can list a space sees its ids, and a plaintext id would let them
/// confirm a guessed tuple and see which tuples are equal; the stored-bytes id reveals neither
/// for a codec that seals with fresh randomness. What it costs: two drops of the same
/// plaintext are two tuples when the codec is randomized (a deterministic codec still dedups),
/// and re-encoding a tuple ([`SpaceEndpoint::reencode`]) gives it a new id. The integrity check
/// every reader makes (the bytes hash to their id) is on the stored bytes, before decoding.
///
/// ⚠ A failed decode is a typed `Conflict` that names the tuple, never a skipped tuple: a
/// `match=` over a space holding one undecodable tuple refuses rather than answering as if it
/// were absent, a take refuses and leaves it in the inbox, and a reactor dead-letters it. A
/// tuple dropped through `out` always decodes under the codec that encoded it, so only a
/// file written past this crate, or a codec that lost its key, can be undecodable.
///
/// ⚠ The `.err` and `.out` NOTES a reactor writes beside a tuple are not encoded: an `.err`
/// note is this crate's sentence or the handler's error, and an `.out` note what the handler
/// answered. A host whose handlers echo tuple content into either should know that.
///
/// The `Err` is a reason, which the crate wraps in a refusal naming the space and the tuple.
///
/// ```
/// use ikigai_intray::TupleCodec;
///
/// /// Not a cipher: a test double that inverts every byte behind a marker.
/// struct Inverted;
/// impl TupleCodec for Inverted {
///     fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
///         Ok([b"INV:".as_slice(), &plain.iter().map(|b| !b).collect::<Vec<_>>()].concat())
///     }
///     fn decode(&self, stored: &[u8]) -> Result<Vec<u8>, String> {
///         let body = stored.strip_prefix(b"INV:").ok_or("not an inverted tuple")?;
///         Ok(body.iter().map(|b| !b).collect())
///     }
/// }
/// let stored = Inverted.encode(b"hello").unwrap();
/// assert_ne!(stored, b"hello");
/// assert_eq!(Inverted.decode(&stored).unwrap(), b"hello");
/// assert!(Inverted.decode(b"hello").is_err());
/// ```
pub trait TupleCodec: Send + Sync {
    /// The bytes to store for the tuple `plain`.
    fn encode(&self, plain: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// The tuple stored as `stored`, or why it cannot be read back.
    fn decode(&self, stored: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// Whether `stored` is already what [`encode`](TupleCodec::encode) would store now, so
    /// [`SpaceEndpoint::reencode`] leaves it alone. `false` after a key rotation for a tuple
    /// sealed to the old key. The default says every stored tuple is current.
    fn is_current(&self, stored: &[u8]) -> bool {
        let _ = stored;
        true
    }
}

/// The default [`TupleCodec`]: a tuple is stored exactly as it was dropped, so its id is the
/// hash of its own bytes.
///
/// ```
/// use ikigai_intray::{IdentityCodec, TupleCodec};
/// assert_eq!(IdentityCodec.encode(b"t").unwrap(), b"t");
/// assert_eq!(IdentityCodec.decode(b"t").unwrap(), b"t");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityCodec;

impl TupleCodec for IdentityCodec {
    fn encode(&self, plain: &[u8]) -> std::result::Result<Vec<u8>, String> {
        Ok(plain.to_vec())
    }
    fn decode(&self, stored: &[u8]) -> std::result::Result<Vec<u8>, String> {
        Ok(stored.to_vec())
    }
}

/// The refusal a tuple that does not decode is answered with: typed, and naming the tuple.
fn undecodable(space: &str, id: &str, why: &str) -> Error {
    Error::Conflict(format!(
        "space `{space}`: tuple `{id}` does not decode with this space's codec ({why}), so it \
         was not read"
    ))
}

/// Decode `stored`, the tuple `id` of `space`, or refuse naming it.
fn decode(codec: &dyn TupleCodec, space: &str, id: &str, stored: &[u8]) -> Result<Vec<u8>> {
    codec
        .decode(stored)
        .map_err(|why| undecodable(space, id, &why))
}

/// The lease every live reactor over a root holds on `<root>/.reactor.lock`: SHARED while
/// it works, EXCLUSIVE only for the moment it recovers interrupted tuples. See
/// [`SpaceReactor::recover_interrupted`].
const LEASE_FILE: &str = ".reactor.lock";

/// Mount the tuplespace at `urn:space:{name}`, backed by a directory under `root`
/// (`<root>/<name>/inbox/`). A host links this into its kernel. Every `match=` runs within
/// [`EvaluationBudget::default`] (the store's 5 s base, 120 s ceiling); see
/// [`space_with_budget`] to set another.
pub fn space(root: PathBuf) -> EndpointSpace {
    space_with_budget(root, EvaluationBudget::default())
}

/// [`space`], with every `match=` evaluation run within `budget` (ledger #1327).
///
/// The budget a request gets is chosen as `ikigai-store`'s doors choose theirs: the budget's
/// base, raised by a `urn:cap:store:budget:<ms>` grant the caller's capability holds, the
/// ceiling for root. Past it the caller is answered with a typed `Timeout`; an evaluation that
/// cannot be stopped at once is counted, and while [`TimeBudget::max_overdue`] are still
/// running a new `match=` is refused at once as `Unavailable`. Every space this mount serves
/// shares the one budget (and so the one overdue count): that is what caps the cores a reader
/// can pin, so pass the SAME budget (or a clone) to every mount over one host.
///
/// [`TimeBudget::max_overdue`]: ikigai_store::budget::TimeBudget::max_overdue
pub fn space_with_budget(root: PathBuf, budget: EvaluationBudget) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(SPACE_TEMPLATE).expect("SPACE_TEMPLATE is a valid template"),
        SpaceEndpoint::new(root).with_evaluation_budget(budget),
    )
}

/// The id a tuple has in every space: its content address, the lowercase hex of its BLAKE3
/// hash (64 characters). `out` names a drop by it and every stage files it under it, so a
/// tuple's id can be computed from its bytes alone, by anyone holding them.
///
/// The bytes are the STORED ones, what the space's [`TupleCodec`] encoded (see there for
/// why). Under the default [`IdentityCodec`] they are the dropped bytes themselves.
///
/// ```
/// let id = ikigai_intray::tuple_id(b"((message \"hello\"))");
/// assert_eq!(id.len(), 64);
/// assert!(id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
/// ```
pub fn tuple_id(content: &[u8]) -> String {
    blake3::hash(content).to_hex().to_string()
}

/// Whether `id` can be a tuple id: it is joined as `<id>.tuple` (and `.err`, `.out`) under a
/// stage directory, so it must keep that ONE plain entry on every platform
/// ([`ikigai_resolve::is_plain_file_name`]; a drive prefix like `C:x` would REPLACE the
/// directory on Windows, ledger #1307), and it has no `.` of its own, since a content hash
/// never does. Whether it is the RIGHT hash is checked against the bytes, after the read.
fn is_tuple_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('.')
        && ikigai_resolve::is_plain_file_name(&format!("{id}.tuple"))
}

/// A directory-backed tuplespace. Each named space is `<root>/<name>/inbox/`, and a tuple is
/// a `<blake3>.tuple` file in it.
pub struct SpaceEndpoint {
    root: PathBuf,
    /// The time budget every `match=` runs within, shared by every space under this root (and
    /// by every clone of it), so its overdue cap bounds the whole mount (ledger #1327).
    budget: EvaluationBudget,
    /// How a tuple is stored at rest (see [`TupleCodec`]).
    codec: Arc<dyn TupleCodec>,
}

impl SpaceEndpoint {
    /// A tuplespace under `root`, its `match=` evaluations within [`EvaluationBudget::default`],
    /// its tuples stored as dropped ([`IdentityCodec`]).
    pub fn new(root: PathBuf) -> Self {
        SpaceEndpoint {
            root,
            budget: EvaluationBudget::default(),
            codec: Arc::new(IdentityCodec),
        }
    }

    /// Run every `match=` within `budget` instead (see [`space_with_budget`]).
    pub fn with_evaluation_budget(mut self, budget: EvaluationBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Store every tuple of every space under this root through `codec` (see [`TupleCodec`]).
    /// ⚠ A reactor over the same root needs the same codec ([`SpaceReactor::with_codec`]):
    /// one left on the default [`IdentityCodec`] decodes nothing, so it fires its handlers
    /// with the STORED bytes.
    ///
    /// ```
    /// use ikigai_intray::{IdentityCodec, SpaceEndpoint};
    /// use std::sync::Arc;
    /// let _space = SpaceEndpoint::new("/tmp/spaces".into()).with_codec(Arc::new(IdentityCodec));
    /// ```
    pub fn with_codec(mut self, codec: Arc<dyn TupleCodec>) -> Self {
        self.codec = codec;
        self
    }

    /// The inbox directory of a named space. The name is a single segment (validated).
    fn inbox(&self, name: &str) -> PathBuf {
        self.root.join(name).join(INBOX_DIR)
    }

    /// A named stage of the space's state machine: `inbox` (live drops), `processing`
    /// (claimed by a reactor pass that has not settled yet — [`PROCESSING_DIR`]), `outbox`
    /// (handled by the reactor), or `error` (dead-letter). Any other name is rejected —
    /// the stage names are a fixed, inspectable set, not a path.
    fn state_dir(&self, name: &str, state: &str) -> Result<PathBuf> {
        match state {
            INBOX_DIR | OUTBOX_DIR | ERROR_DIR => Ok(self.root.join(name).join(state)),
            "processing" => Ok(self.root.join(name).join(PROCESSING_DIR)),
            other => Err(Error::InvalidArgument {
                name: "state".to_string(),
                detail: format!("`{other}` is not a stage (inbox | processing | outbox | error)"),
            }),
        }
    }

    /// The tuple ids currently in a space's inbox, sorted (a deterministic scan order — note
    /// this is id order, not arrival order; a FIFO queue is a later refinement).
    fn list_ids(inbox: &Path) -> Vec<String> {
        let mut ids: Vec<String> = match std::fs::read_dir(inbox) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|n| n.strip_suffix(".tuple"))
                        .map(String::from)
                })
                .collect(),
            Err(_) => Vec::new(), // an empty/absent space lists nothing
        };
        ids.sort();
        ids
    }

    /// Atomically claim a tuple by id: rename it out of the inbox into a staging file of
    /// this taker's OWN, read it, check it, and remove it. **This is the compare-and-swap the
    /// whole tier turns on.** `rename` is atomic on POSIX, so if two takers race the same id
    /// exactly one rename finds the source present; the loser gets [`Claim::Gone`].
    ///
    /// ★ The staging name is unique per claim ([`staging_name`]). It used to be
    /// `.taking/<id>.tuple`, shared by every taker of that id, so with an identical re-drop in
    /// between, a second taker's rename replaced the first one's staged file, the first read
    /// and removed it, and the second — which had WON its claim — failed its read: a tuple
    /// consumed and delivered to nobody (audit round 5, 2c, ledger #877).
    ///
    /// A claim whose read fails, or whose bytes do not decode ([`TupleCodec`]), is put back in
    /// the inbox (best effort) before the error returns, so a failed take is a failed take,
    /// never a lost tuple. The decoded tuple is what [`Claim::Taken`] carries. A claim left behind by
    /// a taker that died between the rename and the read is requeued by
    /// [`requeue_stale_claims`](SpaceEndpoint::requeue_stale_claims).
    fn claim(&self, name: &str, id: &str) -> Result<Claim> {
        if !is_tuple_id(id) {
            return Err(Error::InvalidArgument {
                name: "tuple".to_string(),
                detail: "a tuple id is a content hash".to_string(),
            });
        }
        let src = self.inbox(name).join(format!("{id}.tuple"));
        let staging = self.root.join(name).join(TAKING_DIR);
        std::fs::create_dir_all(&staging)
            .map_err(|e| Error::Endpoint(format!("space `{name}`: staging: {e}")))?;
        let staged = staging.join(staging_name(id, "claim"));
        match std::fs::rename(&src, &staged) {
            Ok(()) => {}
            // The source is gone — someone else claimed it first (or it never existed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Claim::Gone),
            Err(e) => return Err(Error::Endpoint(format!("space `{name}`: take: {e}"))),
        }
        let bytes = match std::fs::read(&staged) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = std::fs::rename(&staged, &src);
                return Err(Error::Endpoint(format!("space `{name}`: take read: {e}")));
            }
        };
        if !hashes_to(&bytes, id) {
            let why = quarantine(&self.root.join(name), id, &staged);
            return Ok(Claim::Corrupt(why));
        }
        // Decoded BEFORE the claim is removed: a tuple this codec cannot read stays in the
        // space (back in the inbox, under its own id) for a host that can.
        let plain = match decode(self.codec.as_ref(), name, id, &bytes) {
            Ok(plain) => plain,
            Err(e) => {
                let _ = std::fs::rename(&staged, &src);
                return Err(e);
            }
        };
        let _ = std::fs::remove_file(&staged);
        Ok(Claim::Taken(plain))
    }

    /// Store every pending tuple of a space again through this endpoint's codec, unless the
    /// codec says it is already current ([`TupleCodec::is_current`]): after a key rotation,
    /// say. Each moved tuple gets a NEW id (an id is the hash of the stored bytes), and the
    /// answer pairs each old id with its new one, in id order, so a host that indexes ids can
    /// follow them. Only the inbox: a tuple a reactor has settled (`outbox/`, `error/`) or is
    /// running (`.processing/`) is left as it is.
    ///
    /// Every tuple is read, checked against its id and decoded BEFORE anything moves, so a
    /// tuple that does not decode refuses the whole call (a typed `Conflict` naming it) with
    /// nothing changed. Then each is moved by the same steps as a take and a drop: the old one
    /// is claimed (so a rival taker gets it or this call does, never both), the new one
    /// published, the claim removed. One a rival took meanwhile is skipped. A stop between the
    /// publish and the removal leaves the tuple in `.taking/` too, which the space requeues
    /// after five minutes, so the same plaintext is then pending twice under two ids; a host
    /// that cannot bear that clears the staging first ([`discard_staging`](Self::discard_staging)).
    /// An I/O failure part way returns `Err` with the earlier tuples already moved.
    ///
    /// ```
    /// # use ikigai_intray::SpaceEndpoint;
    /// // Under the default codec every tuple is current, so nothing moves.
    /// let root = std::env::temp_dir().join(format!("intray-reencode-doc-{}", std::process::id()));
    /// let space = SpaceEndpoint::new(root);
    /// assert!(space.reencode("jobs").unwrap().is_empty());
    /// ```
    pub fn reencode(&self, name: &str) -> Result<Vec<Reencoded>> {
        if name.contains('.') || !ikigai_resolve::is_plain_file_name(name) {
            return Err(Error::InvalidArgument {
                name: "name".to_string(),
                detail: "a space name is a single segment".to_string(),
            });
        }
        let inbox = self.inbox(name);
        let mut planned = Vec::new();
        for id in Self::list_ids(&inbox) {
            let Ok(stored) = std::fs::read(inbox.join(format!("{id}.tuple"))) else {
                continue; // taken since it was listed
            };
            if !hashes_to(&stored, &id) || self.codec.is_current(&stored) {
                continue; // not the tuple its name says (a take quarantines it), or current
            }
            let plain = decode(self.codec.as_ref(), name, &id, &stored)?;
            let again = self.codec.encode(&plain).map_err(|why| {
                Error::Endpoint(format!("space `{name}`: re-encode tuple `{id}`: {why}"))
            })?;
            let new = tuple_id(&again);
            if new != id {
                planned.push((id, new, again));
            }
        }
        let mut moved = Vec::new();
        for (old, new, stored) in planned {
            let src = inbox.join(format!("{old}.tuple"));
            let staging = self.root.join(name).join(TAKING_DIR);
            std::fs::create_dir_all(&staging)
                .map_err(|e| Error::Endpoint(format!("space `{name}`: staging: {e}")))?;
            let claimed = staging.join(staging_name(&old, "claim"));
            match std::fs::rename(&src, &claimed) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // a rival took it
                Err(e) => return Err(Error::Endpoint(format!("space `{name}`: reencode: {e}"))),
            }
            if let Err(e) = self.publish(name, &new, &stored) {
                let _ = std::fs::rename(&claimed, &src);
                return Err(e);
            }
            let _ = std::fs::remove_file(&claimed);
            moved.push(Reencoded { old, new });
        }
        Ok(moved)
    }

    /// Remove every staged drop ([`DROPPING_DIR`]) and staged claim ([`TAKING_DIR`]) a space
    /// holds, and answer how many files went.
    ///
    /// ⚠ Only for a host that knows no drop or take is in flight over the space: one that
    /// owns the whole tree and has not yet served it, say at startup. A staged drop was never
    /// published, so removing it loses nothing a caller was told was stored. A staged claim is
    /// a take whose taker stopped after its claim and before removing it: the space itself would
    /// put it back in the inbox after five minutes, and this says instead that the take
    /// HAPPENED, which is right for a host that records its takes itself (a receipt) and
    /// wrong for any other.
    ///
    /// ```
    /// # use ikigai_intray::SpaceEndpoint;
    /// let root = std::env::temp_dir().join(format!("intray-discard-doc-{}", std::process::id()));
    /// assert_eq!(SpaceEndpoint::new(root).discard_staging("jobs").unwrap(), 0);
    /// ```
    pub fn discard_staging(&self, name: &str) -> std::io::Result<usize> {
        if name.contains('.') || !ikigai_resolve::is_plain_file_name(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a space name is a single segment",
            ));
        }
        let mut removed = 0;
        for stage in [DROPPING_DIR, TAKING_DIR] {
            let dir = self.root.join(name).join(stage);
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for entry in entries {
                let path = entry?.path();
                if path.is_file() {
                    std::fs::remove_file(&path)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Publish already-encoded `stored` as tuple `id` of `name`: written under a staging name
    /// of this drop's own, then renamed into the inbox, so a reader sees the whole tuple or
    /// nothing (see the Sink arm).
    fn publish(&self, name: &str, id: &str, stored: &[u8]) -> Result<()> {
        let inbox = self.inbox(name);
        std::fs::create_dir_all(&inbox)
            .map_err(|e| Error::Endpoint(format!("space `{name}`: create inbox: {e}")))?;
        let staging = self.root.join(name).join(DROPPING_DIR);
        std::fs::create_dir_all(&staging)
            .map_err(|e| Error::Endpoint(format!("space `{name}`: staging: {e}")))?;
        let tmp = staging.join(staging_name(id, "drop"));
        let published = std::fs::write(&tmp, stored)
            .map_err(|e| Error::Endpoint(format!("space `{name}`: out: {e}")))
            .and_then(|()| {
                std::fs::rename(&tmp, inbox.join(format!("{id}.tuple")))
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: out publish: {e}")))
            });
        if published.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        published
    }

    /// Put back every claim in a space's `.taking/` that is older than [`STALE_CLAIM`]: a
    /// taker died between its rename and its read, and the tuple was never delivered, so it
    /// goes back to the inbox (Hermes audit, ledger #877: such a tuple was invisible to every
    /// `rd state=` and no recovery looked at `.taking/`). Run at the start of every rd and
    /// take in the space. A live take holds its claim for one read, so the age bound only
    /// has to exceed that by a wide margin.
    fn requeue_stale_claims(&self, name: &str) {
        let staging = self.root.join(name).join(TAKING_DIR);
        let Ok(entries) = std::fs::read_dir(&staging) else {
            return; // nothing has ever been taken here
        };
        let now = wall_clock();
        for entry in entries.filter_map(|e| e.ok()) {
            let Some(file) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            let Some((id, claimed_at)) = parse_staging_name(&file, "claim").or_else(|| {
                // A claim from before unique staging names (`<id>.tuple`): no claim time in
                // the name, and its mtime is the DROP time (rename keeps it), so it is judged
                // by that, which is never younger than the claim.
                let id = file.strip_suffix(".tuple")?;
                let at = entry.metadata().and_then(|m| m.modified()).ok()?;
                Some((id.to_string(), at))
            }) else {
                continue;
            };
            if now.duration_since(claimed_at).unwrap_or_default() < STALE_CLAIM {
                continue;
            }
            let inbox = self.inbox(name);
            let _ = std::fs::create_dir_all(&inbox);
            let _ = std::fs::rename(entry.path(), inbox.join(format!("{id}.tuple")));
        }
    }
}

/// One tuple [`SpaceEndpoint::reencode`] stored again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reencoded {
    /// The id it had: no longer in the space.
    pub old: String,
    /// The id it has now, in the inbox.
    pub new: String,
}

/// How old a claim in [`TAKING_DIR`] must be before it counts as abandoned. A live take holds
/// its claim for one file read; five minutes is several orders of magnitude past that.
const STALE_CLAIM: std::time::Duration = std::time::Duration::from_secs(300);

/// What a take's claim found.
enum Claim {
    /// The tuple, decoded, now removed from the space.
    Taken(Vec<u8>),
    /// Not in the inbox: another taker won it, or it was never there.
    Gone,
    /// Its bytes do not hash to its id, so it was moved to `error/` (the reason says where)
    /// rather than delivered.
    Corrupt(String),
}

/// A staging file name no other writer can produce: `<id>.<millis>.<pid>.<n>.<suffix>`, where
/// `millis` is when it was made, `pid` this process and `n` a per-process counter. Two writers
/// of the same id — two identical drops, two takers — therefore never share an inode, and a
/// stale claim can be judged by the time in its own name.
///
/// ★ This replaced `<id>.tuple` for both drops and takes. Shared, an identical concurrent drop
/// re-truncated (`fs::write` is O_TRUNC) the very inode another drop was renaming into the
/// inbox, so a reader could see a tuple whose bytes did not hash to its id, and the losing
/// drops failed their rename (audit round 5, ledger #877).
fn staging_name(id: &str, suffix: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let millis = wall_clock()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{id}.{millis}.{}.{n}.{suffix}", std::process::id())
}

/// The filesystem's notion of now, for staging names and their age. Not the kernel's injected
/// `Clock`: a claim's age is compared with the same machine's file times and has to survive a
/// process restart, so it is wall time by definition.
#[allow(clippy::disallowed_methods)] // native-only crate (notify, std::fs); never built for wasm
fn wall_clock() -> std::time::SystemTime {
    std::time::SystemTime::now()
}

/// The id and creation time of a name [`staging_name`] made, or `None` for any other name.
fn parse_staging_name(file: &str, suffix: &str) -> Option<(String, std::time::SystemTime)> {
    let stem = file.strip_suffix(suffix)?.strip_suffix('.')?;
    let mut parts = stem.split('.');
    let (id, millis) = (parts.next()?, parts.next()?.parse::<u64>().ok()?);
    let (_pid, _n) = (parts.next()?, parts.next()?);
    if parts.next().is_some() || id.is_empty() {
        return None;
    }
    Some((
        id.to_string(),
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(millis),
    ))
}

/// Do these bytes hash to this tuple id? Every reader checks before it trusts a tuple: the id
/// IS the content hash, so a mismatch means the file is not the tuple it claims to be (torn,
/// truncated, or written by something other than this crate).
fn hashes_to(bytes: &[u8], id: &str) -> bool {
    blake3::hash(bytes).to_hex().as_str() == id
}

/// The note a tuple that fails [`hashes_to`] is dead-lettered with.
fn corrupt_note(id: &str) -> String {
    format!(
        "corrupt: this file's content does not hash to its id `{id}`, so it is not the tuple \
         that was dropped (torn, truncated, or written outside the space) and was not delivered"
    )
}

/// Put `text` at `<dir>/<id>.<ext>` ATOMICALLY: written under a staging name of its own
/// ([`staging_name`]) in `dir` itself, then renamed into place, so a reader finds the whole
/// note or none, never an empty or half-written one. A staging file is never mistaken for a
/// tuple or a note: readers look for `<id>.tuple`, `<id>.err` and `<id>.out` by name.
///
/// ★ ORDER (ledger #1595). A stage's note is placed BEFORE its tuple moves in (see
/// `SpaceReactor::move_to_stage` and [`quarantine`]). The tuple used to move first and the
/// note to follow, so a reader in between (`dead_letters`, the heartbeat's FAILING line,
/// `rd state=error`) saw a fresh dead letter with "(no .err note)" or an empty one: 7 of
/// 1,440 runs of gonk's trigger test under load.
fn place_note(dir: &Path, id: &str, ext: &str, text: &str) -> std::io::Result<()> {
    let tmp = dir.join(staging_name(id, &format!("{ext}-note")));
    let placed = std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, dir.join(format!("{id}.{ext}"))));
    if placed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    placed
}

/// Take back a note [`place_note`] placed for a tuple whose own move then failed, unless a
/// tuple with that id already sits in `dir` (an earlier pass of the same bytes, which the
/// note now describes): a note beside no tuple reads as a failure that never happened.
fn withdraw_note(dir: &Path, id: &str, ext: &str) {
    if !dir.join(format!("{id}.tuple")).exists() {
        let _ = std::fs::remove_file(dir.join(format!("{id}.{ext}")));
    }
}

// The test seam for ledger #1595: called on the thread that moved a tuple into a stage, the
// moment the move lands, so a test can look at the stage exactly as a racing reader would.
#[cfg(test)]
type StagedHook = Box<dyn Fn(&Path, &str)>;
#[cfg(test)]
thread_local! {
    static ON_STAGED: std::cell::RefCell<Option<StagedHook>> =
        const { std::cell::RefCell::new(None) };
}

/// A tuple `id` has just landed in the stage `dir` (a no-op outside this crate's tests).
fn staged(dir: &Path, id: &str) {
    #[cfg(test)]
    ON_STAGED.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(dir, id);
        }
    });
    #[cfg(not(test))]
    let _ = (dir, id);
}

/// Move a claimed file that failed [`hashes_to`] into the space's `error/` stage beside a
/// note saying why, and return a reason naming where it went (or why it could not). The
/// note goes first ([`place_note`]), so the quarantined file is never seen without it.
fn quarantine(space_dir: &Path, id: &str, claimed: &Path) -> String {
    let error = space_dir.join(ERROR_DIR);
    let moved = std::fs::create_dir_all(&error).and_then(|()| {
        let noted = place_note(&error, id, "err", &corrupt_note(id)).is_ok();
        let moved = std::fs::rename(claimed, error.join(format!("{id}.tuple")));
        if moved.is_err() && noted {
            withdraw_note(&error, id, "err");
        }
        moved
    });
    match moved {
        Ok(()) => {
            staged(&error, id);
            format!("tuple `{id}` does not hash to its id; it was moved to `error/`")
        }
        Err(e) => format!(
            "tuple `{id}` does not hash to its id, and moving it to `error/` failed: {e} \
             (it is at {})",
            claimed.display()
        ),
    }
}

/// An optional inline string argument: `None` when it is absent, an error when it is present
/// but unusable (not inline, or not UTF-8).
///
/// ⚠ Every selector goes through this rather than `inline_str(..).ok()`, because folding
/// "present but unreadable" into "absent" changes what a request MEANS: a `tuple=` that is not
/// UTF-8 read as no `tuple=`, and on take that is the no-selector work-queue pop, so a caller
/// naming one tuple consumed another; a non-UTF-8 `state=` silently read the inbox (audit
/// round 5, ledger #877).
fn opt_str<'a>(inv: &'a Invocation<'_>, name: &str) -> Result<Option<&'a str>> {
    match inv.inline_str(name) {
        Ok(value) => Ok(Some(value)),
        Err(Error::MissingArgument(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The tuple a take names, from `tuple=` or from `content` — or `None` for a take by
/// `match=` or a work-queue pop.
///
/// ★ `content` is read because the engine PUTS the value there: `delete urn:space:q <id>`, and
/// a value piped into a delete, both arrive as `content` (the field guide's pipeline rule for
/// Sink and Delete). Before this, take neither declared nor read it, so that request fell
/// through to the no-selector pop and consumed the FIRST tuple in id order instead of the one
/// named (audit round 5, ledger #877). An engine `delete` ALWAYS carries `content`, empty when
/// nothing followed the IRI, so empty (or only whitespace) means "not given", and surrounding
/// whitespace is trimmed because a piped value keeps its trailing newline. Both forms naming
/// DIFFERENT tuples is refused rather than resolved by picking one.
fn take_id<'a>(inv: &'a Invocation<'_>) -> Result<Option<&'a str>> {
    let named = opt_str(inv, "tuple")?;
    let piped = match inv.inline_arg("content") {
        Ok(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument {
                name: "content".to_string(),
                detail: "a tuple id to take is not valid UTF-8".to_string(),
            })?;
            Some(text.trim()).filter(|id| !id.is_empty())
        }
        Err(Error::MissingArgument(_)) => None,
        Err(e) => return Err(e),
    };
    match (named, piped) {
        (Some(a), Some(b)) if a != b => Err(Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!("names tuple `{b}` but `tuple=` names `{a}`; give the id once"),
        }),
        (Some(id), _) | (None, Some(id)) => Ok(Some(id)),
        (None, None) => Ok(None),
    }
}

/// Bound a `match=` template, then parse it and run `work` with it — every evaluation
/// included — on a thread whose stack is sized for its text (ledger #963), within a TIME
/// budget (ledger #1327).
///
/// oxigraph's SPARQL parser and evaluator are RECURSIVE, and running out of stack is not an
/// error a caller gets back: Rust aborts the whole process. Through cli 0.1.43 a template of
/// ~3,000 nested parentheses, or a flat `1 || 1 || …` chain of a few hundred terms, parsed
/// inline on the request's thread and took down the host — gonk wraps this space, and
/// `ikigai-embedded` mounts it unwrapped, so the bound lives HERE, where every host gets it.
/// The two layers are `ikigai-store`'s, the same ones its own SPARQL doors and `urn:sparql:*`
/// use: [`limits::check_sparql`] refuses text over 1 MiB or nested deeper than 64 as a typed
/// `InvalidArgument` on `match` before anything is parsed, and the parse, the `SERVICE` walk
/// and every per-tuple evaluation run on a stack of 16 MiB plus 512 bytes per byte of
/// template. ⚠ Like the store's, the stack layer is a RELEASE-build guarantee.
///
/// ★ **Time** (ledger #1327). Size and nesting do not bound time: a 340-byte ASK of 7
/// unconstrained triple patterns under one FILTER over all their variables is a cross product
/// of |tuple|^7 rows, and held a thread for 9 s on ONE 7-triple tuple (debug), about 10x a
/// pattern, for every pending tuple. So `work` runs inside [`EvaluationBudget::run`], which
/// replaces `on_sparql_stack` and sizes the same stack:
///
/// - the caller is answered at the budget with a typed `Timeout` naming it, never a partial
///   list, and the async thread it was waiting on is free again;
/// - `work` gets the evaluation's [`CancellationToken`], hands it to every evaluation
///   ([`tuple_matches`]) and checks it between tuples, so an abandoned scan stops at the next
///   tuple and an evaluation at its next dataset access;
/// - what cannot be stopped (a cross product over rows already in memory) is counted, and a
///   new match is refused as `Unavailable` while too many are, so readers cannot pin every core;
/// - and [`parse_match`] applies the store's ALGEBRA bounds ([`check_query`]), so a join wide
///   enough to make oxigraph's PLANNER the cost (which no token reaches) is refused first.
///
/// Decoding each tuple ([`TupleCodec::decode`]) happens inside `work`, so it counts inside the
/// budget too: a slow codec over a large space is a `Timeout`, never an unbounded scan.
///
/// `work` may outlive this call (an overdue evaluation runs on after its caller is answered),
/// so it owns what it uses and must not make an EFFECT the caller could be told did not
/// happen: a take decides which tuple matches in here and claims it outside.
fn with_template<T, F>(
    budget: &EvaluationBudget,
    cap: &Capability,
    query: &str,
    work: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&spargebra::Query, &CancellationToken) -> Result<T> + Send + 'static,
{
    limits::check_sparql(query, "match")?;
    let text = query.to_string();
    budget.run(query, cap, None, move |token| {
        work(&parse_match(&text)?, token)
    })
}

/// What a scan answers when its token fired between two tuples. Its caller was already
/// answered with the budget's own `Timeout`, so nobody reads this; it only ends the scan.
fn canceled() -> Error {
    Error::Timeout("match: canceled at its time budget".to_string())
}

/// Parse a `match=` argument into the template every tuple is tested against. Call it only
/// through [`with_template`], which bounds the text first and parses it on a sized stack.
///
/// Refused with a typed `InvalidArgument` (on `match`), before any tuple is read:
/// - a SPARQL syntax error;
/// - anything but an **ASK** (so a mistaken SELECT fails loudly rather than matching nothing);
/// - an algebra past the store's bounds ([`check_query`]: too many operands in one join, or
///   too many nodes in all), whose cost is in oxigraph's planner, before any token is checked
///   (ledger #1327);
/// - a **`SERVICE`** clause ANYWHERE in the query (audit round 5, ledger #877).
///
/// ★ Why `SERVICE` is refused rather than merely not evaluated: a match is a question about ONE
/// tuple's graph, and federated query is a network call. oxigraph answers `SERVICE` with an HTTP
/// request when its `http-client` feature is on — and in the host build it is, by feature
/// unification through rudof — so a caller holding only `urn:cap:space:read` (or `take`) could
/// make the host connect to an address of its choosing, and through `take` ship a tuple's own
/// triples there, with no `urn:cap:net:*` held or declared. The refusal is decided on the
/// ALGEBRA, so a `SERVICE` in a `FILTER EXISTS`, an `OPTIONAL`, a `MINUS` or a sub-select is
/// found, and the word in a literal or a comment is not mistaken for one. [`tuple_matches`]
/// ALSO evaluates with a service handler that refuses every call, so the guarantee holds even
/// if this walk ever missed a construct, whatever features the build carries.
///
/// Both halves are `ikigai-store`'s since 0.2.10 (`ikigai_store::service`, ledger #1085): the
/// walk is [`refuse_service_with`] and the evaluator [`service::evaluator`]. This crate carried
/// its own copy of each from ledger #877 until then; one copy, maintained where the store's ten
/// doors use it, is what keeps a new spargebra variant from being covered in one place and not
/// the other. The refusal is the store's shared sentence followed by THIS crate's remedy
/// ([`MATCH_REMEDY`], store 0.2.11's consumer form, ledger #1108): the store's own names its
/// remedy (`urn:iki:store:load`), which means nothing to a match.
fn parse_match(query: &str) -> Result<spargebra::Query> {
    let invalid = |detail: String| Error::InvalidArgument {
        name: "match".to_string(),
        detail,
    };
    let parsed = spargebra::SparqlParser::new()
        .parse_query(query)
        .map_err(|e| invalid(format!("SPARQL syntax error: {e}")))?;
    if !matches!(parsed, spargebra::Query::Ask { .. }) {
        return Err(invalid(
            "an associative match must be an ASK query".to_string(),
        ));
    }
    check_query(&parsed, "match")?;
    refuse_service_with(&parsed, "match", Some(MATCH_REMEDY))?;
    Ok(parsed)
}

/// What a `match=` refused for `SERVICE` should do instead: the remedy sentence after the
/// store's shared refusal (`ikigai_store::service::SERVICE_REFUSAL`).
const MATCH_REMEDY: &str = "A match is evaluated against one tuple's graph and never leaves \
     this host: put the data it needs in the tuple.";

/// Refuse a tuple that nests RDF 1.2 triple terms deeper than
/// [`ikigai_rdf::MAX_TURTLE_NESTING`] (64), as a typed `InvalidArgument` on `content`,
/// before anything is written (ledger #992).
///
/// Every `match=` parses every pending tuple as Turtle ([`tuple_matches`]), and in a build
/// with RDF 1.2 on (the host's, through rudof) oxttl builds a nested triple term, and oxrdf
/// copies and drops it, recursively, once per level. A stack overflow aborts the whole
/// process, so a caller holding only [`CAP_OUT`] could drop a tuple about 1 MB deep that
/// aborted the host on the next match ANYONE made, on a stack sized for the template, which
/// says nothing about the tuples. So `out` refuses it, and [`tuple_matches`] never parses one
/// that is already on disk (written before this bound, or by anything else that writes the
/// tree): it simply does not match, like a tuple that is not RDF, rather than failing the
/// match, since one planted tuple failing every caller's match would be the same denial by
/// another route.
///
/// The scan is RDF's ([`ikigai_rdf::check_turtle_nesting`]), whose lenient reading
/// also bounds the strict Turtle parser a match uses: the strict parser stops at the first
/// error, before any later nesting can be built. ⚠ It reads text, not
/// intent: a tuple that is not RDF but has more than 64 unclosed `<<` outside quotes, `<…>`
/// and `#` comments (a long C++ `cout << …` chain, say) is refused too. Seal or encode such a
/// tuple; a sealed one is ciphertext and never reads that way.
fn check_tuple_nesting(content: &[u8]) -> Result<()> {
    // Tuples may be arbitrary bytes. Replacing invalid UTF-8 preserves the ASCII Turtle
    // delimiters the scan reads, without refusing binary content or changing stored bytes.
    let text = String::from_utf8_lossy(content);
    ikigai_rdf::check_turtle_nesting(&text, "content").map_err(|e| match e {
        Error::InvalidArgument { .. } => Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!(
                "this tuple, read as Turtle the way every `match=` reads it, nests RDF 1.2 \
                     triple terms deeper than {} (MAX_RDF_NESTING), counting `<<( … )>>` and \
                     `<< … >>` outside literals, IRIs and comments: the RDF library copies a \
                     nested triple term recursively, once per level, where a stack overflow \
                     aborts the whole host. Nothing was dropped. A tuple that is not RDF and \
                     only reads this way: seal or encode it",
                ikigai_rdf::MAX_TURTLE_NESTING
            ),
        },
        other => other,
    })
}

/// Whether a tuple on disk nests too deep to parse: [`check_tuple_nesting`]'s question,
/// asked of a tuple a match is about to read.
fn nests_too_deep(bytes: &[u8]) -> bool {
    check_tuple_nesting(bytes).is_err()
}

/// Does a tuple's graph satisfy the template (from [`parse_match`])? The tuple is parsed as
/// Turtle into the default graph; a tuple that isn't valid RDF simply never matches. `token`
/// is the evaluation's, from [`with_template`]: oxigraph stops at its next dataset access once
/// it fires.
fn tuple_matches(
    template: &spargebra::Query,
    bytes: &[u8],
    token: &CancellationToken,
) -> Result<bool> {
    if nests_too_deep(bytes) {
        return Ok(false); // never parsed: see [`check_tuple_nesting`]
    }
    let store = Store::new().map_err(|e| Error::Endpoint(format!("match: store init: {e}")))?;
    if store
        .load_from_slice(RdfParser::from_format(RdfFormat::Turtle), bytes)
        .is_err()
    {
        return Ok(false); // non-RDF tuple: no template matches it
    }
    // `service::evaluator()` installs a default service handler that refuses every call: it
    // replaces oxigraph's HTTP one when the `http-client` feature is on and fills the empty slot
    // when it is off, so the outcome does not depend on the build's feature set. [`parse_match`]
    // already refuses a template with a `SERVICE`; this is the floor under it.
    match service::evaluator()
        .with_cancellation_token(token.clone())
        .for_query(template.clone())
        .on_store(&store)
        .execute()
        .map_err(|e| Error::Endpoint(format!("match: evaluation: {e}")))?
    {
        QueryResults::Boolean(b) => Ok(b),
        _ => Ok(false),
    }
}

#[async_trait]
impl Endpoint for SpaceEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = inv
            .bindings
            .get("name")
            .ok_or_else(|| Error::MissingArgument("name".to_string()))?;
        // The name is the space's identity — a single segment, never a path — by the
        // workspace's one rule for a joined name, so a Windows device name (`CON`) or a
        // trailing space is refused here too (ledger #1307), and no `.` at all.
        if name.contains('.') || !ikigai_resolve::is_plain_file_name(name) {
            return Err(Error::InvalidArgument {
                name: "name".to_string(),
                detail: "a space name is a single segment (no `/ \\ : .`, no trailing space, \
                         not a Windows device name)"
                    .to_string(),
            });
        }
        let inbox = self.inbox(name);

        match inv.request.verb {
            // out: drop a tuple. Content-addressed → an identical drop while the tuple is still
            // PENDING is a no-op (one file, one id). Once a reactor has settled it, the same
            // bytes dropped again are a NEW request and fire the handler again: that is the
            // defined re-drop semantics (ledger #877), and a consumer depends on it — gonk's
            // review queue drops one byte-identical tuple per file on every commit and expects
            // each drop after a pass to mean "review the file as it is now".
            Verb::Sink => {
                if !inv.capability.allows(CAP_OUT) {
                    return Err(Error::Denied(format!(
                        "dropping into a space needs `{CAP_OUT}`"
                    )));
                }
                // `retry=<id>` moves a dead-lettered tuple back to the inbox for another
                // pass, and drops its stale `.err` note. A failure is often ENVIRONMENTAL —
                // the handler could not reach the calendar, the mailer was down, a grant had
                // lapsed — which says "not now", not "this tuple is poison". Before this,
                // recovery meant knowing the on-disk layout and doing it by hand with `mv`,
                // which is not something a system should ask of the person it just failed.
                if let Some(id) = opt_str(inv, "retry")? {
                    // ★ Re-arming is the OPERATOR's call, so it needs more than the drop
                    // authority the Sink declares (ledger #887): a dead letter can be one the
                    // reactor parked on purpose (an interrupted pass it refused to run twice, a
                    // handler the host refused), and before this anyone who could drop could
                    // undo that. Checked before the tree is looked at, so a denied caller cannot
                    // learn which ids are dead letters. The verb's `requires` cannot say this (a
                    // plain drop must not need it), so the `retry` input's summary does.
                    if !inv.capability.allows(CAP_RETRY) {
                        return Err(Error::Denied(format!(
                            "re-arming a dead letter with `retry=` needs `{CAP_RETRY}` as well \
                             as `{CAP_OUT}`"
                        )));
                    }
                    if !is_tuple_id(id) {
                        return Err(Error::InvalidArgument {
                            name: "retry".to_string(),
                            detail: "a tuple id is a content hash".to_string(),
                        });
                    }
                    let from = self.root.join(name).join(ERROR_DIR);
                    std::fs::create_dir_all(&inbox).map_err(|e| {
                        Error::Endpoint(format!("space `{name}`: create inbox: {e}"))
                    })?;
                    std::fs::rename(
                        from.join(format!("{id}.tuple")),
                        inbox.join(format!("{id}.tuple")),
                    )
                    .map_err(|_| {
                        Error::NotFound(format!("no dead-lettered tuple `{id}` in space `{name}`"))
                    })?;
                    // Only after the tuple is safely back: a stale note beside no tuple
                    // would read as a failure that never happened.
                    let _ = std::fs::remove_file(from.join(format!("{id}.err")));
                    return Ok(Representation::new(
                        ReprType::new("text/plain"),
                        format!("{id}\n").into_bytes(),
                    ));
                }
                let content = inv
                    .inline_arg("content")
                    .map_err(|_| Error::MissingArgument("content".to_string()))?;
                // The PLAINTEXT is bounded, since that is what every `match=` parses.
                check_tuple_nesting(content)?;
                let stored = self
                    .codec
                    .encode(content)
                    .map_err(|why| Error::Endpoint(format!("space `{name}`: encode: {why}")))?;
                // The id is the hash of what is STORED (see [`TupleCodec`]).
                let id = tuple_id(&stored);
                // Atomic appearance: write to a staging file, then rename it into the inbox.
                // rename is atomic on POSIX, so a reactor's watcher never observes a
                // half-written tuple — it sees the whole tuple or nothing. The staging file is
                // this drop's OWN ([`staging_name`]): two identical drops at once each write
                // their own inode, and the second rename replaces the first with identical
                // bytes, so both succeed and no reader sees a torn tuple (ledger #877).
                self.publish(name, &id, &stored)?;
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    id.into_bytes(),
                ))
            }
            // rd: read the space — one tuple (`tuple=<id>`), the ids matching a `match=<ASK>`
            // template, or all ids. Non-destructive.
            Verb::Source => {
                if !inv.capability.allows(CAP_READ) && !inv.capability.allows(&cap_read_space(name))
                {
                    return Err(Error::Denied(format!(
                        "reading space `{name}` needs `{CAP_READ}` or `{}`",
                        cap_read_space(name)
                    )));
                }
                self.requeue_stale_claims(name);
                // `state=` selects which stage of the machine to read: the live `inbox`
                // (default), or the reactor's `outbox` (handled) / `error` (dead-letter).
                let dir = self.state_dir(name, opt_str(inv, "state")?.unwrap_or("inbox"))?;
                if let Some(id) = opt_str(inv, "tuple")? {
                    if !is_tuple_id(id) {
                        return Err(Error::InvalidArgument {
                            name: "tuple".to_string(),
                            detail: "a tuple id is a content hash".to_string(),
                        });
                    }
                    let bytes = std::fs::read(dir.join(format!("{id}.tuple"))).map_err(|_| {
                        Error::NotFound(format!("no tuple `{id}` in space `{name}`"))
                    })?;
                    if !hashes_to(&bytes, id) {
                        // rd is non-destructive (and holds only read), so it reports the file
                        // rather than moving it; a take or a reactor pass dead-letters it.
                        return Err(Error::Endpoint(format!(
                            "space `{name}`: {}",
                            corrupt_note(id)
                        )));
                    }
                    Ok(Representation::new(
                        ReprType::new("application/octet-stream"),
                        decode(self.codec.as_ref(), name, id, &bytes)?,
                    ))
                } else if let Some(query) = opt_str(inv, "match")? {
                    // Associative rd: the ids of tuples whose graph satisfies the ASK, the
                    // whole scan within the time budget (ledger #1327), decoding included: a
                    // template matches the PLAINTEXT, and a tuple that does not decode refuses
                    // the match rather than reading as absent.
                    let (codec, space) = (Arc::clone(&self.codec), name.to_string());
                    let hits = with_template(
                        &self.budget,
                        inv.capability,
                        query,
                        move |template, token| {
                            let mut hits = Vec::new();
                            for id in Self::list_ids(&dir) {
                                if token.is_cancelled() {
                                    return Err(canceled());
                                }
                                if let Ok(bytes) = std::fs::read(dir.join(format!("{id}.tuple"))) {
                                    // A file that is not the tuple its name says never matches.
                                    if !hashes_to(&bytes, &id) {
                                        continue;
                                    }
                                    let plain = decode(codec.as_ref(), &space, &id, &bytes)?;
                                    if tuple_matches(template, &plain, token)? {
                                        hits.push(id);
                                    }
                                }
                            }
                            Ok(hits)
                        },
                    )?;
                    Ok(Representation::new(
                        ReprType::new("text/plain").with_param("charset", "utf-8"),
                        hits.join("\n").into_bytes(),
                    ))
                } else {
                    // The tuple ids, one per line (the newline-list `..` map convention).
                    Ok(Representation::new(
                        ReprType::new("text/plain").with_param("charset", "utf-8"),
                        Self::list_ids(&dir).join("\n").into_bytes(),
                    ))
                }
            }
            // take: remove a tuple and return its content (Linda's `in`). Atomic per tuple.
            Verb::Delete => {
                if !inv.capability.allows(CAP_TAKE) {
                    return Err(Error::Denied(format!(
                        "taking from a space needs `{CAP_TAKE}`"
                    )));
                }
                self.requeue_stale_claims(name);
                // A specific tuple by id: claim it, or NotFound if already taken/absent.
                if let Some(id) = take_id(inv)? {
                    return match self.claim(name, id)? {
                        Claim::Taken(bytes) => Ok(Representation::new(
                            ReprType::new("application/octet-stream"),
                            bytes,
                        )),
                        Claim::Gone => Err(Error::NotFound(format!(
                            "no tuple `{id}` to take in space `{name}`"
                        ))),
                        Claim::Corrupt(why) => {
                            Err(Error::Endpoint(format!("space `{name}`: {why}")))
                        }
                    };
                }
                // Otherwise take the first tuple matching the template (or any). We scan
                // deterministically and claim the first that both matches and we win the
                // race for; a lost claim just moves to the next candidate.
                let taken = |bytes| {
                    Ok(Representation::new(
                        ReprType::new("application/octet-stream"),
                        bytes,
                    ))
                };
                let Some(query) = opt_str(inv, "match")? else {
                    for id in Self::list_ids(&inbox) {
                        // Lost the race, or a file that is not its tuple (now in `error/`): next.
                        if let Claim::Taken(bytes) = self.claim(name, &id)? {
                            return taken(bytes);
                        }
                    }
                    return Err(Error::NotFound(format!("space `{name}` is empty")));
                };
                // By template (ledger #1327): WHICH tuple matches is decided within the time
                // budget, and the claim, an effect, is made here once the budget has answered,
                // so a take whose caller was told it timed out never consumed a tuple (an
                // overdue scan runs on, but only reads). A claim lost to a rival resumes the
                // scan after that tuple under a fresh budget; each loss is a tuple another
                // taker consumed, so the reruns are bounded by the snapshot.
                let ids = Arc::new(Self::list_ids(&inbox));
                let mut from = 0;
                loop {
                    let (scan, dir) = (Arc::clone(&ids), inbox.clone());
                    let (codec, space) = (Arc::clone(&self.codec), name.to_string());
                    let found = with_template(
                        &self.budget,
                        inv.capability,
                        query,
                        move |template, token| {
                            for (i, id) in scan.iter().enumerate().skip(from) {
                                if token.is_cancelled() {
                                    return Err(canceled());
                                }
                                // A tuple that vanished between listing and read is no match.
                                if let Ok(bytes) = std::fs::read(dir.join(format!("{id}.tuple"))) {
                                    // A file that is not the tuple its name says is matched as
                                    // stored, as it always was here: if it matches, the claim
                                    // quarantines it and the scan goes on. Anything else is
                                    // decoded first, and refuses the take if it cannot be.
                                    let plain = if hashes_to(&bytes, id) {
                                        decode(codec.as_ref(), &space, id, &bytes)?
                                    } else {
                                        bytes
                                    };
                                    if tuple_matches(template, &plain, token)? {
                                        return Ok(Some(i));
                                    }
                                }
                            }
                            Ok(None)
                        },
                    )?;
                    let Some(i) = found else {
                        return Err(Error::NotFound(format!(
                            "no matching tuple to take in space `{name}`"
                        )));
                    };
                    // Lost the race, or a file that is not its tuple (now in `error/`): next.
                    if let Claim::Taken(bytes) = self.claim(name, &ids[i])? {
                        return taken(bytes);
                    }
                    from = i + 1;
                }
            }
            v => Err(Error::Endpoint(format!(
                "urn:space:* answers Source (rd), Sink (out), and Delete (take), not {v:?}"
            ))),
        }
    }

    fn describe(&self) -> Description {
        use ikigai_core::ArgSpec;
        // The space NAME is the `{name}` of `urn:space:{name}`. Declared on every action as a
        // binding input, because without it the manifold cannot form the IRI from the
        // contract: the action is reachable by resolution and undrivable from
        // `urn:kernel:actions` (the shape ikigai-log hit through four releases).
        let name = || {
            ArgSpec::new("name")
                .binding()
                .class(XSD_STRING)
                .summary("the space: the `{name}` of `urn:space:{name}`")
        };
        Description::new("space")
            .title("Tuplespace")
            .summary(
                "A physical tuplespace (Linda `out`/`rd`/`take`): Sink drops a content-addressed \
                 tuple; Source lists the ids (or those matching a `match=<ASK>` template), or \
                 reads one with `tuple=<id>`; Delete atomically takes a tuple and returns it.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("rd — list the tuple ids, read one (`tuple=<id>`), or filter (`match=<ASK>`)")
                    .input(name())
                    .input(
                        ArgSpec::new("tuple")
                            .optional()
                            .class(XSD_STRING)
                            .summary("a tuple id to read; omit to list"),
                    )
                    .input(
                        ArgSpec::new("match")
                            .optional()
                            // A SPARQL ASK query — a string to the wire, and there is no XSD
                            // datatype for "a query in a query language". `xsd:string` is
                            // what the wire carries, not a claim about the syntax.
                            .class(XSD_STRING)
                            .summary("a SPARQL ASK (no `SERVICE`); list only the tuple ids whose graph satisfies it"),
                    )
                    .input(
                        ArgSpec::new("state")
                            .optional()
                            .class(XSD_STRING)
                            .one_of(["inbox", "processing", "outbox", "error"])
                            .summary(
                                "which stage to read (default inbox): inbox | processing \
                                 (claimed by a reactor pass, not yet settled) | outbox | error",
                            ),
                    )
                    // TWO faces, because `tuple=` changes what a read IS: listing or matching
                    // answers ids (a newline list, the `..` map convention), reading one
                    // answers the tuple's own bytes, which the space never interprets.
                    .output("text/plain; charset=utf-8")
                    .output("application/octet-stream")
                    // The FAMILY: the broad read or one space's own (ledger #1513).
                    .requires(CAP_READ_ANY),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("out — drop a tuple (the piped content) into the space")
                    .input(name())
                    // The tuple itself. Declared because a mutating verb's pipe lands in
                    // `content` BY CONTRACT — the summary above has said "the piped content"
                    // since this was written, and a Sink that reads a payload it does not
                    // declare is a contract bug, not a convenience.
                    .input(
                        ArgSpec::new("content")
                            .optional()
                            .class(XSD_STRING)
                            .summary(
                                "the tuple to drop (the piped value); omit only with `retry=`. \
                                 Refused if, read as Turtle, it nests RDF 1.2 triple terms \
                                 deeper than 64",
                            ),
                    )
                    .input(
                        ArgSpec::new("retry")
                            .optional()
                            .class(XSD_STRING)
                            .summary(
                                "instead of dropping: move this dead-lettered tuple back to \
                                 the inbox for another pass (and clear its .err note); needs \
                                 `urn:cap:space:retry` as well as `urn:cap:space:out`",
                            ),
                    )
                    // The dropped tuple's id — the content hash, so a caller can read or
                    // take back exactly what it dropped.
                    .output("text/plain; charset=utf-8")
                    .requires(CAP_OUT),
            )
            .action(
                ActionSpec::new(Verb::Delete)
                    .summary("take — atomically remove a tuple and return it (by id, by match, or any)")
                    .input(name())
                    .input(
                        ArgSpec::new("tuple")
                            .optional()
                            .class(XSD_STRING)
                            .summary("take this specific tuple id"),
                    )
                    .input(
                        ArgSpec::new("match")
                            .optional()
                            .class(XSD_STRING)
                            .summary("a SPARQL ASK (no `SERVICE`); take the first tuple whose graph satisfies it"),
                    )
                    // Declared because a mutating verb's piped or trailing value lands in
                    // `content` BY CONTRACT (`delete urn:space:q <id>`), and take reads it as
                    // the id to take. Undeclared, the id was ignored and the request popped the
                    // first tuple instead (ledger #877).
                    .input(
                        ArgSpec::new("content")
                            .optional()
                            .class(XSD_STRING)
                            .summary(
                                "the tuple id to take, as the piped or trailing value (the same \
                                 as `tuple=`; empty = not given)",
                            ),
                    )
                    // The taken tuple itself, uninterpreted.
                    .output("application/octet-stream")
                    .requires(CAP_TAKE),
            )
    }
}

// =====================================================================================
// The reactor — the space made ACTIVE (Linda's `eval`).
// =====================================================================================

/// The outcome of processing one dropped tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The handler ran; the tuple moved to `outbox`.
    Handled,
    /// The handler failed; the tuple moved to `error` (dead-letter) with an `.err` note.
    Errored(String),
    /// Nothing to do: the space has no handler (not reactive), or the tuple was already
    /// claimed by another pass.
    Skipped(&'static str),
}

/// What a reactor does with a tuple it finds INTERRUPTED — claimed into
/// [`PROCESSING_DIR`] by a reactor that stopped before the pass settled (a restart, a
/// crash, a kill mid-handler). Chosen with [`SpaceReactor::on_interrupted`].
///
/// The handler of an interrupted tuple may have run not at all, in part, or in full
/// (it can have acted and died before its answer was recorded), and the reactor cannot
/// tell which. So the choice is between at-most-once and at-least-once, and only the HOST
/// knows which its handlers can bear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Interrupted {
    /// Dead-letter it into `error/` with an `.err` note saying it was interrupted, and fire
    /// the [`DeadLetterHook`]. The handler is NOT run again; `retry=<id>` on the space's
    /// Sink runs it again when a person (or a host) decides that is safe, which is why
    /// `retry=` needs [`CAP_RETRY`] and a dropper's [`CAP_OUT`] alone cannot re-arm it.
    ///
    /// The default, because the reactor's promise is that a handler fires once: a
    /// booking handler that sent its mail and died before settling must not send it
    /// twice. Dead-lettering keeps the tuple, says why, and is loud.
    #[default]
    DeadLetter,
    /// Move it back to `inbox/`, so the catch-up runs it again. For hosts whose handlers
    /// are idempotent (re-running a review pass costs a model call and harms nothing):
    /// at-least-once, with no person in the loop.
    Requeue,
}

/// One interrupted tuple a reactor recovered at startup — see
/// [`SpaceReactor::recover_interrupted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// The space it was claimed from.
    pub space: String,
    /// The tuple id.
    pub tuple: String,
    /// Where it went (`Ok` names the policy applied), or why it could not be moved, in
    /// which case it is still in [`PROCESSING_DIR`].
    pub outcome: std::result::Result<Interrupted, String>,
}

/// The reactor's startup recovery: the lease it holds for its life, and what it found.
struct Recovery {
    // Held for the reactor's life (dropping it releases the lease). Behind a lock because a
    // later sweep ([`SpaceReactor::sweep_interrupted`]) briefly trades it for the exclusive
    // lock and back.
    lease: std::sync::Mutex<Option<std::fs::File>>,
    report: std::result::Result<Vec<Recovered>, String>,
}

/// The note an interrupted tuple is dead-lettered with.
fn interrupted_note(space: &str, id: &str) -> String {
    format!(
        "interrupted: a reactor claimed this tuple for its handler and stopped before the \
         pass settled (a restart or crash mid-pass). The handler may have run in part or in \
         full, so it was not run again. `sink urn:space:{space} retry={id}` runs it again \
         (it needs `urn:cap:space:retry`)."
    )
}

/// The reactive engine over a directory of spaces. A dropped tuple is CLAIMED (the same
/// atomic rename-CAS as `take`, so it fires exactly once even under duplicate events), the
/// space's handler is fired with the tuple as `content`, and the tuple moves to `outbox`
/// on success or `error` on failure. "Transport dumb, resource smart": the reactor passes
/// bytes + the space/tuple ids; all policy lives in the handler.
///
/// The handler runs under the reactor's OWN `capability` — the owner's processing authority,
/// configured when the reactor is wired — NEVER the dropper's (who held only `out`) and never
/// root. A stranger's drop cannot escalate past what the handler is authorized to reach, and
/// that is STRUCTURAL: the only per-space adjustment is [`Capability::attenuate`], which can
/// subtract scopes and never add one (ledger #445); a host that wants authority out of the
/// space tree entirely uses [`with_host_authority`](SpaceReactor::with_host_authority).
/// WHAT fires is the space's `handler` file unless the host decides it with
/// [`with_host_handler`](SpaceReactor::with_host_handler) — install it, because the file is in
/// the drop tree too.
///
/// This is the deterministic core (`drain`/`process`); the live filesystem watcher that calls
/// `process` on each drop is a thin wrapper the host installs (Slice 3b).
pub struct SpaceReactor {
    root: PathBuf,
    // Path-qualified rather than `use`d: `ikigai_resolve::Resolver` has a 1-arg `issue` that
    // would shadow the inherent async `Kernel::issue` in this module's tests.
    resolver: Arc<dyn ikigai_resolve::Resolver>,
    capability: Capability,
    // `None` = decide a handler's authority from the space's `cap` file (attenuating this
    // reactor's own capability). `Some` = the HOST decides and the file is never read; see
    // `with_host_authority` for why a host may want the file out of the loop entirely.
    host_authority: Option<HostAuthority>,
    // `None` = the `handler` file decides what fires. `Some` = the HOST decides, given what the
    // file names; see `with_host_handler` for why the file alone is not to be trusted.
    host_handler: Option<HostHandler>,
    // Told about every tuple that settles as `Errored` — the host's way to make a dead letter
    // LOUD at the moment it happens. `None` = silent, which is what the `.err` note alone was.
    on_dead_letter: Option<DeadLetterHook>,
    // What to do with a tuple a stopped reactor left in `.processing/` (ledger #738).
    interrupted: Interrupted,
    // Run once, before this reactor's first claim; holds the lease for the reactor's life.
    recovery: std::sync::OnceLock<Recovery>,
    // Held for every pass (claim → handler → settle) and every later recovery sweep, so a
    // sweep never sees one of THIS reactor's own tuples in `.processing/` mid-pass, and the
    // startup catch-up and the watcher never run a pass at the same time.
    pass: std::sync::Mutex<()>,
    // How the spaces store their tuples; a handler is fired with the DECODED tuple.
    codec: Arc<dyn TupleCodec>,
}

/// Called with `(space, tuple id, reason)` for every claimed tuple that settles as
/// [`Outcome::Errored`], installed with [`SpaceReactor::on_dead_letter`].
///
/// Ledger #638: for eight days every booking dead-lettered into `error/` with a perfectly
/// good `.err` note, and nothing anywhere said so — the requester had already been told
/// their request was received. A note nobody reads is not an alarm; this is the seam a host
/// uses to raise one (a log line, a counter, a mail).
///
/// The hook runs on the thread that settled the tuple, AFTER the reactor has released every
/// lock of its own, so it may call back into the same reactor (`drain`, `process`,
/// `sweep_interrupted`). Until ledger #887 it ran under the pass lock, and such a hook
/// deadlocked. It still runs synchronously: a slow hook delays that thread's next pass.
pub type DeadLetterHook = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

/// One dead letter waiting to be told to the [`DeadLetterHook`]: `(space, tuple id, reason)`.
type Heard = (String, String, String);

/// A host's own answer to "what authority does this space's handler run under?", installed
/// with [`SpaceReactor::with_host_authority`]. `None` from the closure means "no opinion —
/// use the reactor's configured capability".
///
/// This is the TRUSTED path, at the same trust level as the capability passed to
/// [`SpaceReactor::new`]: whatever it returns is used as-is, because the host that built the
/// reactor is the authority that bounded it in the first place. The untrusted path — the
/// `cap` file, which lives in the tree droppers write into — can only ever attenuate.
pub type HostAuthority = Arc<dyn Fn(&str) -> Option<Capability> + Send + Sync>;

/// A host's answer to "what does this space's handler fire?", given what the space's `handler`
/// file names, installed with [`SpaceReactor::with_host_handler`].
pub type HostHandler = Arc<dyn Fn(&str, Option<&str>) -> Option<String> + Send + Sync>;

/// What [`SpaceReactor::process`] fires for a space.
enum Target {
    /// This IRI.
    Fire(String),
    /// Nothing: the `handler` file names this IRI and the host refused it.
    Refused(String),
    /// Nothing: the space is not reactive.
    None,
}

impl SpaceReactor {
    /// Build a reactor over `root` (the same tree the spaces live in), firing handlers
    /// through `resolver` under `capability`.
    ///
    /// `capability` is the CEILING for every handler this reactor fires: a space's `cap`
    /// file can narrow it per space, never widen it.
    pub fn new(
        root: PathBuf,
        resolver: Arc<dyn ikigai_resolve::Resolver>,
        capability: Capability,
    ) -> Self {
        SpaceReactor {
            root,
            resolver,
            capability,
            host_authority: None,
            host_handler: None,
            on_dead_letter: None,
            interrupted: Interrupted::default(),
            recovery: std::sync::OnceLock::new(),
            pass: std::sync::Mutex::new(()),
            codec: Arc::new(IdentityCodec),
        }
    }

    /// Decode every claimed tuple through `codec` before its handler is fired: the SAME codec
    /// the spaces' endpoint stores through ([`SpaceEndpoint::with_codec`]). A tuple that does
    /// not decode is dead-lettered with a note naming it, and its handler is not run; it
    /// stays encoded in `error/`, and `retry=` re-arms it once the codec can read it.
    /// Recovery, requeues and the stage moves never decode anything: they move files by name.
    pub fn with_codec(mut self, codec: Arc<dyn TupleCodec>) -> Self {
        self.codec = codec;
        self
    }

    /// Choose what happens to a tuple a stopped reactor left claimed but unsettled — see
    /// [`Interrupted`]. Default: [`Interrupted::DeadLetter`].
    pub fn on_interrupted(mut self, policy: Interrupted) -> Self {
        self.interrupted = policy;
        self
    }

    /// Recover the tuples a STOPPED reactor left in [`PROCESSING_DIR`], in every space
    /// under the root, according to [`on_interrupted`](SpaceReactor::on_interrupted).
    ///
    /// Runs ONCE per reactor, before its first claim: [`drain`](SpaceReactor::drain) and
    /// [`process`](SpaceReactor::process) both call it first, so the startup catch-up in
    /// [`watch`](SpaceReactor::watch) sees a requeued tuple. Later calls return the same
    /// report. Before this, a tuple claimed by a pass that never settled stayed in
    /// `.processing/` forever: the catch-up lists only `inbox/`, so it was neither run again
    /// nor dead-lettered, and every count of the queue read empty (ledger #738).
    ///
    /// ⚠ A tuple in `.processing/` is only interrupted if NO live reactor is working on it.
    /// So every reactor holds a lease on `<root>/.reactor.lock` for its whole life — shared
    /// while it works — and recovery needs it EXCLUSIVELY, which it gets only when no other
    /// live reactor (in this process or another) shares the root. A lock dies with its
    /// process, so a crashed reactor never blocks recovery. `Err` says why recovery was
    /// skipped (another live reactor, or a filesystem that cannot lock); nothing was moved.
    /// ⚠ Reactors from before this lease existed hold no lock and are not seen by it.
    pub fn recover_interrupted(&self) -> std::result::Result<&[Recovered], &str> {
        // The dead letters this call produced are told to the hook AFTER the initializer
        // returns: a hook that drove this reactor from inside it would wait on its own `OnceLock`
        // (ledger #887). `None` when another call initialized it.
        let mut heard = None;
        let recovery = self.recovery.get_or_init(|| {
            let mut told = Vec::new();
            let recovery = self.recover(&mut told);
            heard = Some(told);
            recovery
        });
        if let Some(heard) = heard {
            self.tell(heard);
        }
        recovery.report.as_deref().map_err(String::as_str)
    }

    /// Take the lease and, when it is exclusively ours, recover. See
    /// [`recover_interrupted`](SpaceReactor::recover_interrupted).
    fn recover(&self, heard: &mut Vec<Heard>) -> Recovery {
        let lease = match self.open_lease() {
            Ok(file) => file,
            Err(why) => {
                return Recovery {
                    lease: std::sync::Mutex::new(None),
                    report: Err(why),
                }
            }
        };
        let report = match lease.try_lock() {
            Ok(()) => {
                let recovered = self.recover_spaces(heard);
                // Downgrade to SHARED for the rest of this reactor's life. Between the two
                // calls another reactor could take it exclusively and recover — harmless,
                // because this reactor has claimed nothing yet.
                let _ = lease.unlock();
                Ok(recovered)
            }
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "another live reactor shares {}, so a tuple in its `{PROCESSING_DIR}/` may \
                 be in flight there; nothing was recovered",
                self.root.display()
            )),
            Err(std::fs::TryLockError::Error(e)) => {
                return Recovery {
                    lease: std::sync::Mutex::new(None),
                    report: Err(format!(
                        "cannot lock {}: {e}; nothing was recovered",
                        self.root.join(LEASE_FILE).display()
                    )),
                }
            }
        };
        // Blocks only while another reactor holds it exclusively, i.e. while it recovers.
        let lease = match lease.lock_shared() {
            Ok(()) => Some(lease),
            Err(_) => None,
        };
        Recovery {
            lease: std::sync::Mutex::new(lease),
            report,
        }
    }

    /// Recover interrupted tuples AGAIN, now, if this reactor is the only live one over the
    /// root — and report what moved. [`drain`](SpaceReactor::drain) calls it, and so does the
    /// [`watch`](SpaceReactor::watch) loop every [`SWEEP_EVERY`].
    ///
    /// ★ Why a second chance is needed (the Hermes audit's `once-only-recovery`, ledger #877):
    /// [`recover_interrupted`](SpaceReactor::recover_interrupted) runs once, at startup, and
    /// only when it gets the lease EXCLUSIVELY. With two live reactors over one root, a tuple
    /// the second one claimed and never settled (it crashed mid-pass) sat in `.processing/`
    /// until the first one exited, because nothing ever looked again. Now the survivor looks
    /// on every sweep: it sets its own shared lease down, tries for the exclusive lock, and
    /// recovers when it gets it, i.e. when no OTHER live reactor shares the root. That is safe
    /// because the sweep holds this reactor's pass lock, so none of its own tuples is in flight.
    ///
    /// ⚠ The bound: recovery still needs every other reactor over the root to be gone, so with
    /// three reactors a crashed one's tuples wait until only one is left. Telling a dead
    /// reactor's claims from a live one's while both have siblings needs per-claim ownership,
    /// which is reported up rather than built here.
    ///
    /// Empty when there was nothing to move, when another live reactor shares the root, or
    /// when the lease could never be opened (the startup report says why).
    pub fn sweep_interrupted(&self) -> Vec<Recovered> {
        let Some(recovery) = self.recovery.get() else {
            // The first sweep IS the startup recovery.
            return self
                .recover_interrupted()
                .map(<[_]>::to_vec)
                .unwrap_or_default();
        };
        let mut heard = Vec::new();
        let recovered = {
            let _pass = self.pass.lock().unwrap_or_else(|p| p.into_inner());
            let mut lease = recovery.lease.lock().unwrap_or_else(|p| p.into_inner());
            let Some(file) = lease.as_ref() else {
                return Vec::new();
            };
            let _ = file.unlock();
            let recovered = match file.try_lock() {
                Ok(()) => {
                    let recovered = self.recover_spaces(&mut heard);
                    let _ = file.unlock();
                    recovered
                }
                Err(_) => Vec::new(),
            };
            // Back to SHARED. Blocks only while another reactor holds it exclusively (its own
            // startup recovery). If it fails this reactor holds no lease, and says so once.
            if let Err(e) = file.lock_shared() {
                eprintln!(
                    "ikigai-intray: reactor over {} lost its lease ({e}); another reactor's \
                     recovery could now move this one's in-flight tuples",
                    self.root.display()
                );
                *lease = None;
            }
            recovered
        };
        // Only now, with the pass lock and the lease guard released (ledger #887).
        self.tell(heard);
        recovered
    }

    fn open_lease(&self) -> std::result::Result<std::fs::File, String> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| format!("cannot create {}: {e}", self.root.display()))?;
        let path = self.root.join(LEASE_FILE);
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}; nothing was recovered", path.display()))
    }

    /// Apply the [`Interrupted`] policy to every tuple in every space's `.processing/`.
    /// Called only under the exclusive lease.
    fn recover_spaces(&self, heard: &mut Vec<Heard>) -> Vec<Recovered> {
        let mut names = self.space_names();
        names.sort();
        let mut recovered = Vec::new();
        for name in names {
            let staging = self.root.join(&name).join(PROCESSING_DIR);
            for id in SpaceEndpoint::list_ids(&staging) {
                let claimed = staging.join(format!("{id}.tuple"));
                let outcome = match self.interrupted {
                    Interrupted::DeadLetter => {
                        let note = interrupted_note(&name, &id);
                        match self.settle(&name, &id, &claimed, Err(note.clone()), heard) {
                            Outcome::Errored(said) if said == note => Ok(Interrupted::DeadLetter),
                            Outcome::Errored(said) => Err(said),
                            other => Err(format!("unexpected outcome {other:?}")),
                        }
                    }
                    Interrupted::Requeue => {
                        let inbox = self.root.join(&name).join(INBOX_DIR);
                        std::fs::create_dir_all(&inbox)
                            .and_then(|()| {
                                std::fs::rename(&claimed, inbox.join(format!("{id}.tuple")))
                            })
                            .map(|()| Interrupted::Requeue)
                            .map_err(|e| format!("move back to `inbox`: {e}"))
                    }
                };
                recovered.push(Recovered {
                    space: name.clone(),
                    tuple: id,
                    outcome,
                });
            }
        }
        recovered
    }

    /// Tell the host about every dead letter as it happens: `hook(space, tuple id, reason)`
    /// runs for each claimed tuple that settles as [`Outcome::Errored`], after its `.err`
    /// note is written. See [`DeadLetterHook`].
    pub fn on_dead_letter<F>(mut self, hook: F) -> Self
    where
        F: Fn(&str, &str, &str) + Send + Sync + 'static,
    {
        self.on_dead_letter = Some(Arc::new(hook));
        self
    }

    /// Take a space's handler authority from the HOST instead of from the space tree.
    ///
    /// With this installed the reactor **never reads a `cap` file**. That is the difference
    /// between "safe because the file happens to be trustworthy" and "safe because the crate
    /// never reads authority off the dropper's tree at all" — a host with its own checked
    /// grant store (`ikigai-gonk` has one, and refuses `cap` files outright rather than use
    /// this path) can decide authority through the same door everything else goes through.
    ///
    /// The closure is called per tuple with the space name; `None` means "use the reactor's
    /// configured capability". A `cap` file left on disk under this policy is INERT, which is
    /// its own trap — [`ignored_cap_files`](SpaceReactor::ignored_cap_files) is there so a
    /// host can refuse to start rather than quietly disregard one.
    pub fn with_host_authority<F>(mut self, decide: F) -> Self
    where
        F: Fn(&str) -> Option<Capability> + Send + Sync + 'static,
    {
        self.host_authority = Some(Arc::new(decide));
        self
    }

    /// The spaces carrying a `cap` file that this reactor will NOT read — always empty
    /// unless [`with_host_authority`](SpaceReactor::with_host_authority) is installed, in
    /// which case it names every space whose on-disk `cap` file is being ignored. A host
    /// that supplies authority itself should call this at startup and refuse (or say so
    /// loudly) rather than leave an operator believing a file that does nothing.
    pub fn ignored_cap_files(&self) -> Vec<String> {
        if self.host_authority.is_none() {
            return Vec::new();
        }
        let mut names: Vec<String> = self
            .space_names()
            .into_iter()
            .filter(|name| self.root.join(name).join("cap").is_file())
            .collect();
        names.sort();
        names
    }

    /// A space is REACTIVE iff `<root>/<name>/handler` exists; its content (trimmed) is the
    /// handler URI a dropped tuple is fired at. Self-describing + inspectable — no config
    /// schema to invent. `None` = not reactive (drops just accumulate for `rd`/`take`).
    fn handler_uri(&self, name: &str) -> Option<String> {
        let raw = std::fs::read_to_string(self.root.join(name).join("handler")).ok()?;
        let uri = raw.trim();
        (!uri.is_empty()).then(|| uri.to_string())
    }

    /// What a dropped tuple in this space is fired at: the `handler` file's target, or —
    /// with [`with_host_handler`](SpaceReactor::with_host_handler) installed — whatever the
    /// host decides given that target.
    fn handler_target(&self, name: &str) -> Target {
        let file = self.handler_uri(name);
        match &self.host_handler {
            None => file.map_or(Target::None, Target::Fire),
            Some(decide) => match (decide(name, file.as_deref()), file) {
                (Some(uri), _) => Target::Fire(uri),
                (None, Some(refused)) => Target::Refused(refused),
                (None, None) => Target::None,
            },
        }
    }

    /// Let the HOST decide what each space's handler is, instead of the `handler` file alone.
    ///
    /// ★ Why (the Hermes audit's `handler-retarget`, ledger #877; the same class as #445): the
    /// `handler` file sits in `<root>/<name>/`, the directory a dropper writes into, so anyone
    /// who can write the tree chooses WHICH IRI every tuple is fired at — under the reactor's
    /// own host-granted authority, even with [`with_host_authority`] deciding that authority.
    /// #445 made the `cap` file attenuate-only; this is the handler's equivalent.
    ///
    /// The closure gets the space name and the file's target (`None` when there is no file)
    /// and answers what to fire:
    /// - `Some(uri)` fires `uri` — the file's target when the host allows it (an allow-list),
    ///   or the host's own (host config, with the file ignored);
    /// - `None` with a file present REFUSES it: the tuple is claimed and dead-lettered with a
    ///   note naming the target, and the [`DeadLetterHook`] hears about it — loud, where
    ///   leaving it in the inbox would be silent;
    /// - `None` with no file means the space is not reactive.
    ///
    /// Without this the file decides, exactly as before, and whoever can write the tree can
    /// retarget the handler. A host that grants its reactor anything worth stealing should
    /// install it.
    ///
    /// [`with_host_authority`]: SpaceReactor::with_host_authority
    pub fn with_host_handler<F>(mut self, decide: F) -> Self
    where
        F: Fn(&str, Option<&str>) -> Option<String> + Send + Sync + 'static,
    {
        self.host_handler = Some(Arc::new(decide));
        self
    }

    /// The capability a space's handler runs under.
    ///
    /// With a host seam installed ([`with_host_authority`](SpaceReactor::with_host_authority))
    /// this is whatever the host says, and no file is read. Otherwise it is the reactor's own
    /// capability **attenuated** by the scopes listed in `<root>/<name>/cap` (one per line;
    /// blank lines and `#` comments ignored), or the reactor's capability unchanged when there
    /// is no file, or the file lists no scopes.
    ///
    /// ★ **ATTENUATE, never mint.** `cap` sits in `<root>/<name>/` — the SAME directory as
    /// `inbox`, the directory a dropper writes into. Until 2026-09-19 this called
    /// `Capability::scoped(scopes)`, which REPLACES rather than intersects: any scope the file
    /// named was granted, whether or not the reactor ever held it, so anyone who could drop a
    /// tuple could also rewrite the authority it ran under. Filesystem permissions were the
    /// entire boundary. `attenuate` makes the non-escalation structural instead — the file can
    /// subtract from the reactor's ceiling and can never add to it (ledger #445).
    ///
    /// ⚠ The consequence for operators: a `cap` file only ever does something if the reactor
    /// itself was wired with at least those scopes. A scope the reactor does not hold is
    /// silently dropped here — and the handler then fails with the kernel's own permission
    /// error, which names the scope, in the tuple's `.err` note. A handler wanting more than
    /// its reactor holds needs the HOST to grant it — by widening the reactor's own ceiling or
    /// through the host seam — which is the point: a grant of authority is something the host
    /// did, not something a file in the drop tree claimed. `ikigai-embedded` takes the seam
    /// (ledger #638): it keeps one scope list per space under its config home, read with
    /// [`parse_scopes`], so under that host this `cap` path is never taken at all.
    ///
    /// ⚠ Intersection here is EXACT string matching ([`Capability::attenuate`]); the trailing-`*`
    /// family form is a property of DECLARED scopes, not of held grants, so a held scope is
    /// always concrete and exact intersection is the right primitive.
    fn capability_for(&self, name: &str) -> Capability {
        if let Some(decide) = &self.host_authority {
            return decide(name).unwrap_or_else(|| self.capability.clone());
        }
        match std::fs::read_to_string(self.root.join(name).join("cap")) {
            Ok(raw) => {
                let scopes = parse_scopes(&raw);
                if scopes.is_empty() {
                    self.capability.clone()
                } else {
                    // NOT `Capability::scoped(scopes)` — see the doc comment above. This is
                    // the whole fix: the reactor's capability is the ceiling, and the file
                    // chooses a subset of it.
                    self.capability.attenuate(scopes)
                }
            }
            Err(_) => self.capability.clone(),
        }
    }

    /// Process every pending tuple in a space's inbox — the startup catch-up pass, and the
    /// deterministic entry the live watcher and the tests both drive. Returns each
    /// `(tuple id, outcome)`.
    pub fn drain(&self, name: &str) -> Vec<(String, Outcome)> {
        // Before listing, so a REQUEUED interrupted tuple is in the list. The first call is
        // the startup recovery; later ones recover what a crashed SIBLING left, once it is
        // the only reactor left over the root.
        let _ = self.sweep_interrupted();
        self.drain_inbox(name)
    }

    /// [`drain`](SpaceReactor::drain) without the recovery sweep, for a caller that has just
    /// swept once for every space.
    fn drain_inbox(&self, name: &str) -> Vec<(String, Outcome)> {
        SpaceEndpoint::list_ids(&self.root.join(name).join(INBOX_DIR))
            .into_iter()
            .map(|id| {
                let outcome = self.process(name, &id);
                (id, outcome)
            })
            .collect()
    }

    /// Process ONE tuple: claim it, fire the handler, move it to `outbox`/`error`.
    pub fn process(&self, name: &str, id: &str) -> Outcome {
        // Before this reactor's first claim, whichever entry point makes it.
        let _ = self.recover_interrupted();
        let handler = match self.handler_target(name) {
            Target::Fire(uri) => Ok(uri),
            // Claimed and dead-lettered below, never fired: a refusal is loud (`error/`, the
            // dead-letter hook), where leaving it in the inbox would be silent.
            Target::Refused(uri) => Err(format!(
                "refused: this space's `handler` file names `{uri}`, which the host does not \
                 allow (`with_host_handler`); the handler was not run"
            )),
            Target::None => return Outcome::Skipped("no handler (not a reactive space)"),
        };
        let mut heard = Vec::new();
        let outcome = self.run_pass(name, id, handler, &mut heard);
        // ★ The hook runs HERE, after the pass lock is released, never inside it (ledger
        // #887): a hook that drove this reactor (`drain`, `process`, a sweep) would otherwise
        // wait forever on a lock its own thread held.
        self.tell(heard);
        outcome
    }

    /// One pass over a claimed tuple, under the pass lock: claim it, fire `handler` (or settle
    /// the refusal), move it to its terminal stage. Dead letters are recorded in `heard` for
    /// [`process`](SpaceReactor::process) to tell the hook once the lock is released.
    fn run_pass(
        &self,
        name: &str,
        id: &str,
        handler: std::result::Result<String, String>,
        heard: &mut Vec<Heard>,
    ) -> Outcome {
        // One pass at a time per reactor, held from the claim to the settle.
        let _pass = self.pass.lock().unwrap_or_else(|p| p.into_inner());
        // Claim atomically — rename out of the inbox into a private processing dir. If the
        // rename finds nothing, another pass already took this tuple: fire exactly once.
        let claimed = match self.claim(name, id) {
            Ok(Some(path)) => path,
            Ok(None) => return Outcome::Skipped("already claimed"),
            Err(e) => return Outcome::Errored(e),
        };
        let stored = match std::fs::read(&claimed) {
            Ok(b) if hashes_to(&b, id) => b,
            // Never fire a handler on bytes that are not the tuple that was dropped.
            Ok(_) => return self.settle(name, id, &claimed, Err(corrupt_note(id)), heard),
            Err(e) => {
                return self.settle(name, id, &claimed, Err(format!("read tuple: {e}")), heard)
            }
        };
        // Nor on bytes it cannot read back: a dead letter naming the tuple, never the stored
        // form handed on as if it were the tuple.
        let bytes = match decode(self.codec.as_ref(), name, id, &stored) {
            Ok(plain) => plain,
            Err(e) => return self.settle(name, id, &claimed, Err(e.to_string()), heard),
        };
        let handler = match handler {
            Ok(uri) => uri,
            Err(refused) => return self.settle(name, id, &claimed, Err(refused), heard),
        };
        // Fire the handler under the reactor's OWN authority, passing the tuple as content
        // plus the space/tuple ids (transport dumb, resource smart). A malformed handler URI
        // dead-letters the tuple rather than losing it.
        let result = match Iri::parse(&handler) {
            Ok(iri) => {
                // Offer the tuple under BOTH conventional piped-input names — `content`
                // (CLAUDE.md's piped-fallback) and `in` (the text/engine family) — since
                // extra args are tolerated and endpoints split between the two. (A fuller
                // version would Meta-describe the handler and route to its sole declared
                // input, the way the engine pipes a value; that needs structured describe
                // access the Resolver doesn't expose yet.)
                let request = Request::new(Verb::Source, iri)
                    .with_arg("content", ArgRef::Inline(bytes.clone()))
                    .with_arg("in", ArgRef::Inline(bytes))
                    .with_arg("space", ArgRef::Inline(name.as_bytes().to_vec()))
                    .with_arg("tuple", ArgRef::Inline(id.as_bytes().to_vec()));
                ikigai_resolve::Resolver::issue_as(
                    self.resolver.as_ref(),
                    request,
                    &self.capability_for(name),
                )
                // KEEP WHAT THE HANDLER SAID. Discarding it (`.map(|_| ())`) meant a
                // handled tuple recorded NOTHING but its own existence in `outbox`: no
                // record of what was decided, or whether the human it was supposed to
                // reach was ever told. On 2026-07-31 a booking handler ran, decided, and
                // failed to notify anyone — and there was no artifact anywhere saying so,
                // because the answer died here. The `.err` note on the failure path was
                // the only reason that outage was diagnosable at all; success deserves
                // the same courtesy.
                .map(|(repr, _status)| String::from_utf8_lossy(&repr.bytes).to_string())
                .map_err(|e| e.to_string())
            }
            Err(e) => Err(format!("bad handler URI `{handler}`: {e}")),
        };
        self.settle(name, id, &claimed, result, heard)
    }

    /// Move a claimed tuple to its terminal stage: `outbox` on Ok, `error` (+ an `.err` note)
    /// on failure, and record any `Errored` outcome in `heard` for the [`DeadLetterHook`] —
    /// which the CALLER tells once it holds no lock ([`tell`](SpaceReactor::tell)). Returns
    /// the matching [`Outcome`].
    fn settle(
        &self,
        name: &str,
        id: &str,
        claimed: &Path,
        result: std::result::Result<String, String>,
        heard: &mut Vec<Heard>,
    ) -> Outcome {
        let outcome = self.move_to_stage(name, id, claimed, result);
        if let Outcome::Errored(reason) = &outcome {
            heard.push((name.to_string(), id.to_string(), reason.clone()));
        }
        outcome
    }

    /// Tell the [`DeadLetterHook`] about each dead letter in `heard`, in order. Called only
    /// where this reactor holds no lock of its own — not the pass lock, not the lease, not
    /// inside the startup recovery's initializer — so a hook may drive this same reactor
    /// (ledger #887; `tests/hook_reentry.rs` is the guard).
    fn tell(&self, heard: Vec<Heard>) {
        if let Some(hook) = &self.on_dead_letter {
            for (space, tuple, reason) in heard {
                hook(&space, &tuple, &reason);
            }
        }
    }

    /// [`settle`](SpaceReactor::settle) without the hook: the moves and the notes.
    fn move_to_stage(
        &self,
        name: &str,
        id: &str,
        claimed: &Path,
        result: std::result::Result<String, String>,
    ) -> Outcome {
        let (stage, outcome) = match &result {
            Ok(_) => (OUTBOX_DIR, Outcome::Handled),
            Err(e) => (ERROR_DIR, Outcome::Errored(e.clone())),
        };
        // A failure to MOVE must not lose why the handler failed in the first place.
        let failed = |what: String| match &result {
            Err(why) => Outcome::Errored(format!("{why} (and then {what})")),
            Ok(_) => Outcome::Errored(what),
        };
        let dir = self.root.join(name).join(stage);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return failed(format!("create `{stage}`: {e}"));
        }
        // ★ The note FIRST, atomically, and only then the tuple (ledger #1595): a reader that
        // finds the tuple in its stage finds its whole note beside it. See [`place_note`].
        let placed = match &result {
            // A dead-letter note alongside the tuple, so a failure is inspectable via
            // `rd state=error`.
            //
            // A note that cannot be written (disk full, permissions) leaves the tuple in
            // `error/` with no record of WHY, which is the one thing `rd state=error` exists
            // to show, so the reason goes to stderr instead of being dropped (ledger #1548).
            // The tuple still moves.
            Err(msg) => match place_note(&dir, id, "err", msg) {
                Ok(()) => Some("err"),
                Err(e) => {
                    eprintln!(
                        "ikigai-intray: space `{name}`: dead letter {id} has no .err note \
                         ({e}); it failed with: {msg}"
                    );
                    None
                }
            },
            // The mirror image: what the handler ANSWERED, beside the handled tuple. This
            // is the difference between "a booking was processed" and knowing what was
            // decided and whether anyone was told. Empty answers write nothing. A note that
            // cannot be written is said on stderr, without the answer itself (which may be
            // long, and is the handler's to log), so its absence is not mistaken for silence.
            Ok(said) if !said.trim().is_empty() => match place_note(&dir, id, "out", said) {
                Ok(()) => Some("out"),
                Err(e) => {
                    eprintln!(
                        "ikigai-intray: space `{name}`: handled tuple {id} has no .out note \
                         ({e}); its answer was not recorded"
                    );
                    None
                }
            },
            // Said nothing THIS pass: an answer left by an earlier pass must not stand in
            // for it, not even for the moment before the tuple moves in.
            Ok(_) => {
                let _ = std::fs::remove_file(dir.join(format!("{id}.out")));
                None
            }
        };
        if let Err(e) = std::fs::rename(claimed, dir.join(format!("{id}.tuple"))) {
            if let Some(ext) = placed {
                withdraw_note(&dir, id, ext);
            }
            return failed(format!("move to `{stage}`: {e}"));
        }
        staged(&dir, id);
        // ★ A tuple's record describes its LAST pass, so it is in exactly one terminal stage.
        // The same bytes can be handled more than once — an identical drop after a pass has
        // settled is a NEW request (see the Sink arm) — and before this a success left the
        // failure it superseded in `error/`, so `dead_letters` (the heartbeat's FAILING line)
        // went on reporting a tuple that had since been handled (audit round 5, 3b, ledger
        // #877); a failure likewise leaves no stale success in `outbox/` beside it.
        let (other, note) = match stage {
            OUTBOX_DIR => (ERROR_DIR, "err"),
            _ => (OUTBOX_DIR, "out"),
        };
        let other = self.root.join(name).join(other);
        let _ = std::fs::remove_file(other.join(format!("{id}.tuple")));
        let _ = std::fs::remove_file(other.join(format!("{id}.{note}")));
        outcome
    }

    /// Atomically claim a tuple by renaming it out of the inbox into a private `.processing`
    /// dir (the same compare-and-swap as the endpoint's `take`). `Ok(None)` if it's already
    /// gone — another pass won the race.
    fn claim(&self, name: &str, id: &str) -> std::result::Result<Option<PathBuf>, String> {
        let src = self
            .root
            .join(name)
            .join(INBOX_DIR)
            .join(format!("{id}.tuple"));
        let staging = self.root.join(name).join(PROCESSING_DIR);
        std::fs::create_dir_all(&staging).map_err(|e| format!("staging: {e}"))?;
        let staged = staging.join(format!("{id}.tuple"));
        match std::fs::rename(&src, &staged) {
            Ok(()) => Ok(Some(staged)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("claim: {e}")),
        }
    }

    /// The names of the spaces currently on disk (the immediate subdirectories of `root`).
    fn space_names(&self) -> Vec<String> {
        match std::fs::read_dir(&self.root) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Go live: watch the spaces root, catch up on what is already pending, then `process`
    /// each tuple as it lands. Returns once the catch-up is done; the watch runs on a
    /// background thread for the life of the process (the `Arc<Self>` keeps the reactor alive).
    /// A non-reactive space (no `handler` file) is simply skipped — this is safe to call over
    /// the whole tree.
    ///
    /// A watch that cannot start is LOGGED to stderr (it used to end its thread silently, and
    /// a reactor that is not reacting looked exactly like a quiet one); use
    /// [`try_watch`](SpaceReactor::try_watch) to get the reason and refuse to start instead.
    pub fn watch(self: Arc<Self>) {
        let root = self.root.clone();
        if let Err(why) = self.try_watch() {
            eprintln!(
                "ikigai-intray: the reactor over {} is NOT watching: {why}; tuples dropped \
                 from now on wait for a restart",
                root.display()
            );
        }
    }

    /// [`watch`](SpaceReactor::watch), saying why when the watch could not be established.
    /// The catch-up does not run then: the caller decides whether to drain without a watch.
    ///
    /// ★ ORDER (audit round 5, ledger #877). The watch is established FIRST and the catch-up
    /// drain runs after. It used to be the other way round: a tuple landing after a space was
    /// listed and before the watch existed was in neither, so it waited in the inbox until the
    /// next restart — and a handler that composes, dropping a follow-up tuple while the
    /// catch-up runs it, hit that gap every time. Now events from the moment the watch is live
    /// queue in the channel while the catch-up runs and are served after it, and a tuple both
    /// paths see is claimed once (the second claim finds nothing: `Skipped`).
    ///
    /// The root is created before it is canonicalized: canonicalizing a root that did not
    /// exist yet failed, the raw path was kept, `notify` then reported canonical paths (macOS:
    /// `/tmp` → `/private/tmp`) that never matched it, and no drop was ever processed.
    ///
    /// Every [`SWEEP_EVERY`] without an event the loop also re-runs recovery
    /// ([`sweep_interrupted`](SpaceReactor::sweep_interrupted)) and the catch-up, so a tuple a
    /// crashed sibling reactor left claimed, or one whose event was missed, is not stranded
    /// for the life of the process.
    pub fn try_watch(self: Arc<Self>) -> std::result::Result<(), String> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| format!("cannot create {}: {e}", self.root.display()))?;
        // Make every known space's inbox exist BEFORE the watch is established.
        //
        // A recursive watch only covers directories that are there when it starts; one
        // created later is picked up by watching its parent for the create, which races
        // with a tuple written immediately after. On a fresh machine no inbox exists yet,
        // so the FIRST tuple a space ever receives is the one most likely to be missed —
        // and a missed tuple is silent, sitting in an inbox nobody looks at again until
        // something restarts. Creating them up front removes the race for known spaces.
        for name in self.space_names() {
            let _ = std::fs::create_dir_all(self.root.join(&name).join(INBOX_DIR));
        }
        // Canonicalize so the paths `notify` reports (it resolves symlinks — macOS maps
        // /var → /private/var) line up with `root` when we strip the prefix.
        let root = self
            .root
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", self.root.display()))?;
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })
        .map_err(|e| format!("cannot create a filesystem watcher: {e}"))?;
        watcher
            .watch(&root, RecursiveMode::Recursive)
            .map_err(|e| format!("cannot watch {}: {e}", root.display()))?;
        // The watch is live: anything that lands from here on queues in `rx`. Catch up on
        // what was already waiting (including tuples missed while this was not running).
        let _ = self.sweep_interrupted();
        self.catch_up();
        std::thread::spawn(move || {
            // Held to the end of this scope, keeping the watch alive; the loop runs until
            // the process exits.
            let _watcher = watcher;
            loop {
                match rx.recv_timeout(SWEEP_EVERY) {
                    Ok(Ok(event)) => self.react_to_event(&root, &event),
                    Ok(Err(e)) => eprintln!(
                        "ikigai-intray: watch error under {}: {e}; a drop may have been \
                         missed (the next sweep catches up)",
                        root.display()
                    ),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        for r in self.sweep_interrupted() {
                            eprintln!(
                                "ikigai-intray: recovered interrupted tuple {} in space `{}`: \
                                 {:?}",
                                r.tuple, r.space, r.outcome
                            );
                        }
                        self.catch_up();
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        eprintln!(
                            "ikigai-intray: the watcher over {} stopped; tuples dropped from \
                             now on wait for a restart",
                            root.display()
                        );
                        return;
                    }
                }
            }
        });
        Ok(())
    }

    /// What one watcher event does: each genuine drop it names ([`inbox_tuple`]) is
    /// processed, and a RESCAN drains every space's inbox at once.
    ///
    /// ★ A rescan says events were DROPPED and names no tuple that landed: FSEvents reports
    /// `MustScanSubDirs` (with `UserDropped`/`KernelDropped` when its queue overflowed) on a
    /// directory, and inotify reports `IN_Q_OVERFLOW` with no path at all; `notify` delivers
    /// both as an event flagged [`Flag::Rescan`](notify::event::Flag::Rescan). Its paths are
    /// directories, never `<id>.tuple`, so it used to match nothing and a tuple whose create
    /// event was lost waited for the next [`SWEEP_EVERY`] (ledger #1596). The served kernel's
    /// workspace watch treats a rescan the same way, by cutting every file thread (ledger
    /// #1534). Draining is safe to repeat: a tuple already claimed is `Skipped`.
    fn react_to_event(&self, root: &Path, event: &notify::Event) {
        if event.need_rescan() {
            self.catch_up();
            return;
        }
        if event.kind.is_access() {
            return; // a read doesn't add a tuple
        }
        for path in &event.paths {
            if let Some((name, id)) = inbox_tuple(root, path) {
                self.process(&name, &id);
            }
        }
    }

    /// Drain every space's inbox (no recovery sweep): what the watch does once it is live,
    /// on a rescan, and every [`SWEEP_EVERY`].
    fn catch_up(&self) {
        for name in self.space_names() {
            let _ = self.drain_inbox(&name);
        }
    }
}

/// How long a live reactor's watch loop waits without an event before it re-runs recovery
/// and the catch-up (see [`SpaceReactor::try_watch`]).
pub const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// One reactive space's dead letters: what [`dead_letters`] reports per space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceDeadLetters {
    /// The space's name (`bookings` for `urn:space:bookings`).
    pub space: String,
    /// How many tuples sit in its `error/` stage.
    pub count: usize,
    /// The most recent of them, when `count > 0`.
    pub newest: Option<DeadLetter>,
}

/// One dead-lettered tuple and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    /// The tuple id (its content hash).
    pub tuple: String,
    /// The `.err` note's text, verbatim — or a statement that there is none.
    pub reason: String,
    /// When it was dead-lettered: the `.err` note's modification time (the tuple's own mtime
    /// is its DROP time, since a rename keeps it), or the tuple's when there is no note.
    pub at: Option<std::time::SystemTime>,
}

/// Every REACTIVE space under `root` (a space with a non-empty `handler` file), sorted by
/// name, with the count of tuples in its `error/` stage and the newest one's reason.
///
/// Reactive spaces with nothing dead-lettered are included with `count: 0`, so a reader can
/// tell "no dead letters" from "not looked at". Read straight off the tree, so any process
/// sharing the workspace reports the same facts.
pub fn dead_letters(root: &Path) -> Vec<SpaceDeadLetters> {
    let spaces: Vec<String> = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|name| {
                std::fs::read_to_string(root.join(name).join("handler"))
                    .map(|raw| !raw.trim().is_empty())
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    dead_letters_of(root, spaces)
}

/// [`dead_letters`] for the spaces the CALLER names, sorted and deduplicated — for a host that
/// decides which spaces are reactive itself
/// ([`with_host_handler`](SpaceReactor::with_host_handler)), so a space it fires with no
/// `handler` file on disk is still counted. A name that is not a single path segment is skipped.
pub fn dead_letters_of(
    root: &Path,
    spaces: impl IntoIterator<Item = String>,
) -> Vec<SpaceDeadLetters> {
    let mut spaces: Vec<String> = spaces
        .into_iter()
        .filter(|name| {
            !name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != ".."
        })
        .collect();
    spaces.sort();
    spaces.dedup();
    spaces
        .into_iter()
        .map(|space| {
            let error = root.join(&space).join(ERROR_DIR);
            let ids = SpaceEndpoint::list_ids(&error);
            let modified = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
            let newest = ids
                .iter()
                .map(|id| {
                    let note = error.join(format!("{id}.err"));
                    match std::fs::read_to_string(&note) {
                        Ok(reason) => DeadLetter {
                            tuple: id.clone(),
                            reason,
                            at: modified(&note),
                        },
                        Err(_) => DeadLetter {
                            tuple: id.clone(),
                            reason: "(no .err note)".to_string(),
                            at: modified(&error.join(format!("{id}.tuple"))),
                        },
                    }
                })
                .max_by(|a, b| a.at.cmp(&b.at).then_with(|| a.tuple.cmp(&b.tuple)));
            SpaceDeadLetters {
                space,
                count: ids.len(),
                newest,
            }
        })
        .collect()
}

/// Parse a scope-list file: one capability scope IRI per line, surrounding whitespace
/// trimmed, blank lines and `#` comment lines ignored. Order is kept; nothing is validated
/// or deduplicated.
///
/// This is the format of a space's `cap` file, and it is public so a HOST that keeps the
/// same lists somewhere else (`ikigai-embedded` keeps one file per space under its config
/// home, installed through [`SpaceReactor::with_host_authority`]) reads them with the same
/// rules. One parser means a file moves between the two places without being edited.
///
/// ```
/// let scopes = ikigai_intray::parse_scopes(
///     "# the bookings handler\nurn:cap:lisp\n\n  urn:cap:space:out  \n",
/// );
/// assert_eq!(scopes, vec!["urn:cap:lisp", "urn:cap:space:out"]);
/// ```
pub fn parse_scopes(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Map a filesystem path to the `(space, tuple id)` it names, iff it is a tuple freshly in an
/// inbox: `<root>/<space>/inbox/<id>.tuple`. Anything else (an outbox move, a staging file, a
/// handler edit) yields `None`, so the watcher only fires on genuine drops.
fn inbox_tuple(root: &Path, path: &Path) -> Option<(String, String)> {
    let rel = path.strip_prefix(root).ok()?;
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    match parts.as_slice() {
        [space, "inbox", file] => {
            let id = file.strip_suffix(".tuple")?;
            Some((space.to_string(), id.to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use std::sync::{Arc, Mutex};

    fn kernel_at(sub: &str) -> Kernel {
        let root = std::env::temp_dir()
            .join(format!("ikigai-intray-test-{}", std::process::id()))
            .join(sub);
        let _ = std::fs::remove_dir_all(&root);
        Kernel::new(Arc::new(space(root)))
    }

    fn iri(s: &str) -> Iri {
        Iri::parse(s).unwrap()
    }

    /// Drop a tuple into a space, returning its id.
    fn out(k: &Kernel, cap: &Capability, space_iri: &str, content: &[u8]) -> String {
        let r = block_on(
            k.issue(
                Request::new(Verb::Sink, iri(space_iri))
                    .with_arg("content", ArgRef::Inline(content.to_vec())),
                cap,
            ),
        )
        .unwrap();
        String::from_utf8(r.bytes).unwrap()
    }

    #[test]
    fn out_then_rd_roundtrips_a_tuple() {
        let k = kernel_at("space-rt");
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);

        let id = out(&k, &cap, "urn:space:bookings", b"a booking");
        assert_eq!(id.len(), 64, "blake3 hex id");

        // rd (list) → the one id.
        let list =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:bookings")), &cap)).unwrap();
        assert_eq!(String::from_utf8(list.bytes).unwrap(), id);

        // rd (one) → the tuple bytes.
        let tuple = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:bookings"))
                    .with_arg("tuple", ArgRef::Inline(id.clone().into_bytes())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(tuple.bytes, b"a booking");

        // An identical drop is idempotent (same content hash → same id, still one tuple).
        let again = out(&k, &cap, "urn:space:bookings", b"a booking");
        assert_eq!(again, id);
        let list2 =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:bookings")), &cap)).unwrap();
        assert_eq!(
            String::from_utf8(list2.bytes).unwrap(),
            id,
            "still one tuple"
        );
    }

    #[test]
    fn out_and_rd_are_capability_gated() {
        let k = kernel_at("space-cap");
        let none = Capability::scoped(Vec::<String>::new());
        // out without the cap → Denied.
        let dropped = block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:x"))
                    .with_arg("content", ArgRef::Inline(b"x".to_vec())),
                &none,
            ),
        );
        assert!(matches!(dropped, Err(Error::Denied(_))), "got: {dropped:?}");
        // rd without the cap → Denied.
        let read = block_on(k.issue(Request::new(Verb::Source, iri("urn:space:x")), &none));
        assert!(matches!(read, Err(Error::Denied(_))), "got: {read:?}");
    }

    #[test]
    fn reading_a_missing_tuple_is_not_found() {
        let k = kernel_at("space-miss");
        let cap = Capability::scoped(vec![CAP_READ.to_string()]);
        let r = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:s"))
                    .with_arg("tuple", ArgRef::Inline(b"deadbeef".to_vec())),
                &cap,
            ),
        );
        assert!(matches!(r, Err(Error::NotFound(_))), "got: {r:?}");
    }

    /// A per-space read grant (ledger #1513) reads exactly its own space: one handled tuple by
    /// id out of the outbox, and nothing in any other space, a name it only prefixes included.
    #[test]
    fn a_per_space_read_grant_reads_its_own_space_and_no_other() {
        let root = std::env::temp_dir()
            .join(format!("ikigai-intray-test-{}", std::process::id()))
            .join("space-per-read");
        let _ = std::fs::remove_dir_all(&root);
        let k = Kernel::new(Arc::new(space(root.clone())));
        // A handled enquiry, where a reactor leaves one: `<root>/contact/outbox/<id>.tuple`.
        let enquiry = b"((name \"A Visitor\") (message \"hello\"))";
        let id = tuple_id(enquiry);
        let outbox = root.join("contact").join("outbox");
        std::fs::create_dir_all(&outbox).unwrap();
        std::fs::write(outbox.join(format!("{id}.tuple")), enquiry).unwrap();
        // Something in the neighbors, so a refusal is a refusal and not an empty space.
        let dropper = Capability::scoped(vec![CAP_OUT.to_string()]);
        out(&k, &dropper, "urn:space:people", b"((name \"someone\"))");
        out(
            &k,
            &dropper,
            "urn:space:contact-blocks",
            b"((label \"ham\"))",
        );

        let narrow = Capability::scoped(vec![cap_read_space("contact")]);
        let read = |space: &str, args: &[(&str, &str)], cap: &Capability| {
            let mut r = Request::new(Verb::Source, iri(space));
            for (n, v) in args {
                r = r.with_arg(*n, ArgRef::Inline(v.as_bytes().to_vec()));
            }
            block_on(k.issue(r, cap))
        };
        // The one tuple, by id, from the outbox: its own bytes.
        let got = read(
            "urn:space:contact",
            &[("tuple", &id), ("state", "outbox")],
            &narrow,
        )
        .expect("the per-space grant reads its own space");
        assert_eq!(got.bytes, enquiry);
        // A well-formed id that names nothing there is NotFound, not some other tuple.
        let unknown = "0".repeat(64);
        let miss = read(
            "urn:space:contact",
            &[("tuple", &unknown), ("state", "outbox")],
            &narrow,
        );
        assert!(matches!(miss, Err(Error::NotFound(_))), "got: {miss:?}");
        // Another space, and one whose name the granted one only prefixes, are refused.
        for other in ["urn:space:people", "urn:space:contact-blocks"] {
            let r = read(other, &[], &narrow);
            assert!(matches!(r, Err(Error::Denied(_))), "{other}: got {r:?}");
        }
        // It is a READ grant: taking from the space it reads is still refused.
        let take = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:contact"))
                    .with_arg("tuple", ArgRef::Inline(id.clone().into_bytes())),
                &narrow,
            ),
        );
        assert!(matches!(take, Err(Error::Denied(_))), "got: {take:?}");
        // The broad grant still reads every space.
        let broad = Capability::scoped(vec![CAP_READ.to_string()]);
        assert!(read("urn:space:people", &[], &broad).is_ok());
    }

    /// rd declares the read FAMILY, so the kernel's floor admits a per-space grant to the
    /// module's own check, and keeps admitting the broad one.
    #[test]
    fn rd_declares_the_read_family() {
        let d = SpaceEndpoint::new(std::env::temp_dir()).describe();
        let rd = d
            .action_specs()
            .into_iter()
            .find(|a| a.verb == Verb::Source)
            .expect("rd is declared");
        assert_eq!(rd.requires, vec![CAP_READ_ANY.to_string()]);
        for held in [CAP_READ.to_string(), cap_read_space("contact")] {
            assert!(
                Capability::scoped(vec![held.clone()]).satisfies(CAP_READ_ANY),
                "{held}"
            );
        }
        for not_read in [CAP_OUT, CAP_TAKE] {
            assert!(!Capability::scoped(vec![not_read.to_string()]).satisfies(CAP_READ_ANY));
        }
    }

    #[test]
    fn take_removes_and_returns_a_tuple() {
        let k = kernel_at("space-take");
        let cap = Capability::scoped(vec![
            CAP_OUT.to_string(),
            CAP_READ.to_string(),
            CAP_TAKE.to_string(),
        ]);
        let id = out(&k, &cap, "urn:space:q", b"payload");

        // take (by id) → the content, and the space is now empty.
        let taken = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:q"))
                    .with_arg("tuple", ArgRef::Inline(id.clone().into_bytes())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(taken.bytes, b"payload");
        let list = block_on(k.issue(Request::new(Verb::Source, iri("urn:space:q")), &cap)).unwrap();
        assert!(list.bytes.is_empty(), "space drained");

        // Taking it again → NotFound (a tuple is consumed exactly once).
        let again = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:q"))
                    .with_arg("tuple", ArgRef::Inline(id.into_bytes())),
                &cap,
            ),
        );
        assert!(matches!(again, Err(Error::NotFound(_))), "got: {again:?}");
    }

    #[test]
    fn take_any_is_a_work_queue() {
        let k = kernel_at("space-queue");
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_TAKE.to_string()]);
        let mut dropped = std::collections::HashSet::new();
        for i in 0..3 {
            dropped.insert(out(
                &k,
                &cap,
                "urn:space:jobs",
                format!("job {i}").as_bytes(),
            ));
        }
        // Three no-selector takes drain the three distinct tuples...
        let mut got = std::collections::HashSet::new();
        for _ in 0..3 {
            let r =
                block_on(k.issue(Request::new(Verb::Delete, iri("urn:space:jobs")), &cap)).unwrap();
            got.insert(blake3::hash(&r.bytes).to_hex().to_string());
        }
        assert_eq!(got, dropped, "each tuple taken exactly once");
        // ...and the fourth finds the space empty.
        let empty = block_on(k.issue(Request::new(Verb::Delete, iri("urn:space:jobs")), &cap));
        assert!(matches!(empty, Err(Error::NotFound(_))), "got: {empty:?}");
    }

    #[test]
    fn take_is_capability_gated() {
        let k = kernel_at("space-take-cap");
        let full = Capability::scoped(vec![CAP_OUT.to_string(), CAP_TAKE.to_string()]);
        let id = out(&k, &full, "urn:space:z", b"x");
        // Holding read (but not take) is not enough to consume.
        let read_only = Capability::scoped(vec![CAP_READ.to_string()]);
        let denied = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:z"))
                    .with_arg("tuple", ArgRef::Inline(id.into_bytes())),
                &read_only,
            ),
        );
        assert!(matches!(denied, Err(Error::Denied(_))), "got: {denied:?}");
    }

    #[test]
    fn associative_match_selects_by_graph() {
        let k = kernel_at("space-match");
        let cap = Capability::scoped(vec![
            CAP_OUT.to_string(),
            CAP_READ.to_string(),
            CAP_TAKE.to_string(),
        ]);
        let person = b"@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                       <urn:p:alice> a foaf:Person ; foaf:name \"Alice\" .";
        let place = b"@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                      <urn:pl:cafe> a foaf:Organization ; foaf:name \"Cafe\" .";
        let person_id = out(&k, &cap, "urn:space:people", person);
        let _place_id = out(&k, &cap, "urn:space:people", place);

        let ask = b"PREFIX foaf: <http://xmlns.com/foaf/0.1/> ASK { ?s a foaf:Person }".to_vec();

        // rd with match → only the person tuple's id.
        let hits = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:people"))
                    .with_arg("match", ArgRef::Inline(ask.clone())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(String::from_utf8(hits.bytes).unwrap(), person_id);

        // take with match → the person tuple; the place tuple stays behind.
        let taken = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:people"))
                    .with_arg("match", ArgRef::Inline(ask)),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(taken.bytes, person);
        let remaining =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:people")), &cap)).unwrap();
        assert_eq!(
            String::from_utf8(remaining.bytes).unwrap(),
            _place_id,
            "place remains"
        );
    }

    #[test]
    fn a_non_ask_match_is_rejected() {
        let k = kernel_at("space-badmatch");
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        out(&k, &cap, "urn:space:m", b"@prefix : <urn:> .\n:a :b :c .");
        let bad = block_on(k.issue(
            Request::new(Verb::Source, iri("urn:space:m")).with_arg(
                "match",
                ArgRef::Inline(b"SELECT * WHERE { ?s ?p ?o }".to_vec()),
            ),
            &cap,
        ));
        assert!(
            matches!(bad, Err(Error::InvalidArgument { ref name, .. }) if name == "match"),
            "got: {bad:?}"
        );
    }

    /// The floor under `parse_match`'s refusal: even a template that got past it (here built
    /// straight from the parser) is evaluated with a service handler that refuses, so no
    /// connection is attempted. This crate's tests build oxigraph WITH its HTTP client (see
    /// the dev-dependency), so without the handler this connects. The listener ANSWERS each
    /// connection (an empty result set), so a regression fails this test instead of hanging
    /// it on a request nobody replies to.
    #[test]
    fn evaluation_refuses_service_even_past_the_parse_check() {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let (hits, stop) = (Arc::clone(&hits), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut conn, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = conn.set_nonblocking(false);
                    let _ = conn.set_read_timeout(Some(std::time::Duration::from_millis(300)));
                    let _ = conn.read(&mut [0u8; 4096]);
                    let body = r#"{"head":{"vars":[]},"results":{"bindings":[]}}"#;
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/sparql-results+json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            })
        };
        let template = spargebra::SparqlParser::new()
            .parse_query(&format!(
                "ASK {{ ?s ?p ?o . SERVICE <http://127.0.0.1:{port}/sparql> {{ ?x ?y ?o }} }}"
            ))
            .unwrap();
        let r = tuple_matches(
            &template,
            b"<urn:a> <urn:b> \"c\" .",
            &CancellationToken::new(),
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "evaluation connected to the SERVICE endpoint ({r:?})"
        );
        assert!(
            matches!(r, Err(Error::Endpoint(ref e)) if e.contains("SERVICE")),
            "the refusal is an evaluation error naming SERVICE: {r:?}"
        );
    }

    /// The compare-and-swap under contention: many threads take from one space; every tuple
    /// must be claimed exactly once — no duplicates, no losses.
    #[test]
    fn concurrent_takes_claim_each_tuple_once() {
        let k = Arc::new(kernel_at("space-cas"));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_TAKE.to_string()]);
        const N: usize = 60;
        for i in 0..N {
            out(&k, &cap, "urn:space:race", format!("token {i}").as_bytes());
        }

        let taken: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let k = Arc::clone(&k);
            let cap = cap.clone();
            let taken = Arc::clone(&taken);
            handles.push(std::thread::spawn(move || loop {
                match block_on(k.issue(Request::new(Verb::Delete, iri("urn:space:race")), &cap)) {
                    Ok(r) => taken.lock().unwrap().push(r.bytes),
                    Err(Error::NotFound(_)) => break, // space drained
                    Err(e) => panic!("unexpected take error: {e:?}"),
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut got = taken.lock().unwrap().clone();
        got.sort();
        got.dedup();
        assert_eq!(
            got.len(),
            N,
            "every tuple claimed exactly once, none duplicated"
        );
    }

    // ---- the reactor (Slice 3a) -------------------------------------------------------

    /// A stub kernel handle: records the handler IRI + the capability each fire ran under,
    /// and returns Ok or Err on command. Overriding `issue_as` (not just `issue`) is what
    /// lets a test assert the handler ran under the reactor's configured authority.
    struct MockResolver {
        calls: Mutex<Vec<(String, Capability)>>,
        succeed: bool,
    }
    impl MockResolver {
        fn new(succeed: bool) -> Self {
            MockResolver {
                calls: Mutex::new(Vec::new()),
                succeed,
            }
        }
        fn calls(&self) -> Vec<(String, Capability)> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl ikigai_resolve::Resolver for MockResolver {
        fn issue(
            &self,
            request: Request,
        ) -> std::result::Result<(Representation, ikigai_resolve::CacheStatus), Error> {
            self.issue_as(request, &Capability::root())
        }
        fn issue_as(
            &self,
            request: Request,
            capability: &Capability,
        ) -> std::result::Result<(Representation, ikigai_resolve::CacheStatus), Error> {
            self.calls
                .lock()
                .unwrap()
                .push((request.target.as_str().to_string(), capability.clone()));
            if self.succeed {
                Ok((
                    Representation::new(ReprType::new("text/plain"), b"ok".to_vec()),
                    ikigai_resolve::CacheStatus::Uncacheable,
                ))
            } else {
                Err(Error::Endpoint("handler failed (mock)".to_string()))
            }
        }
        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }
        fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
            None
        }
    }

    /// Make a space reactive by writing its handler file, and return the shared root.
    fn reactive_root(sub: &str, space_name: &str, handler: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .join(format!("ikigai-intray-test-{}", std::process::id()))
            .join(sub);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(space_name)).unwrap();
        std::fs::write(root.join(space_name).join("handler"), handler).unwrap();
        root
    }

    /// What the handler ANSWERED must survive, beside the handled tuple.
    ///
    /// The regression: `process` did `.map(|_| ())`, so a handled tuple recorded nothing
    /// but its own existence. A booking handler could decide, fail to notify the human it
    /// was supposed to reach, and leave no artifact saying so anywhere in the system — the
    /// `.err` note on the failure path was the ONLY reason such an outage was diagnosable.
    #[test]
    fn a_handled_tuple_records_what_the_handler_said() {
        let root = reactive_root("react-said", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let reactor = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        );
        assert_eq!(reactor.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);

        let said =
            std::fs::read_to_string(root.join("jobs").join("outbox").join(format!("{id}.out")))
                .expect("a handled tuple carries the handler's answer beside it");
        assert_eq!(said, "ok", "verbatim, not summarized: {said}");
    }

    /// A dead-lettered tuple can be put back for another pass — because a failure is
    /// often ENVIRONMENTAL (no calendar, no mailer, a lapsed grant), which means "not
    /// now", not "this tuple is poison". Recovery must not require knowing the on-disk
    /// layout and running `mv` by hand.
    #[test]
    fn a_dead_lettered_tuple_can_be_retried() {
        let root = reactive_root("react-retry", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        // Re-arming needs the operator's `retry` grant beside `out` (ledger #887).
        let cap = Capability::scoped(vec![
            CAP_OUT.to_string(),
            CAP_READ.to_string(),
            CAP_RETRY.to_string(),
        ]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        // The environment is broken: the tuple dead-letters, with a note.
        let failing = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(false)),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        );
        assert!(matches!(failing.drain("jobs")[0].1, Outcome::Errored(_)));
        assert!(root
            .join("jobs")
            .join("error")
            .join(format!("{id}.err"))
            .exists());

        // Put it back.
        block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:jobs"))
                    .with_arg("retry", ArgRef::Inline(id.as_bytes().to_vec())),
                &cap,
            ),
        )
        .expect("retry moves it back to the inbox");
        assert!(
            !root.join("jobs").join("error").join(format!("{id}.err")).exists(),
            "the stale note goes with it — a note beside no tuple reads as a failure that never happened"
        );

        // The environment is fixed: the same tuple now succeeds.
        let working = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        );
        assert_eq!(working.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);
    }

    /// Retrying something that was never dead-lettered is a NotFound, not a silent no-op
    /// that answers as if it worked.
    #[test]
    fn retrying_an_unknown_tuple_is_not_found() {
        let root = reactive_root("react-retry-miss", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        // Re-arming needs the operator's `retry` grant beside `out` (ledger #887).
        let cap = Capability::scoped(vec![
            CAP_OUT.to_string(),
            CAP_READ.to_string(),
            CAP_RETRY.to_string(),
        ]);
        let err = block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:jobs"))
                    .with_arg("retry", ArgRef::Inline(b"deadbeef".to_vec())),
                &cap,
            ),
        )
        .expect_err("nothing to retry");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    }

    #[test]
    fn a_reactive_drop_is_handled_into_the_outbox() {
        let root = reactive_root("react-ok", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        // Fire the handler under a SCOPED processing authority (not root, not the dropper's).
        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(
            root.clone(),
            mock.clone(),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        );
        assert_eq!(reactor.drain("jobs"), vec![(id.clone(), Outcome::Handled)]);

        // The tuple moved inbox → outbox.
        let read_state = |state: &str| {
            let r = block_on(
                k.issue(
                    Request::new(Verb::Source, iri("urn:space:jobs"))
                        .with_arg("state", ArgRef::Inline(state.as_bytes().to_vec())),
                    &cap,
                ),
            )
            .unwrap();
            String::from_utf8(r.bytes).unwrap()
        };
        assert_eq!(read_state("outbox"), id, "handled tuple is in the outbox");
        assert!(read_state("inbox").is_empty(), "inbox drained");

        // Fired exactly once, at the configured handler, under the scoped cap — NOT root.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "urn:test:handler");
        assert!(calls[0].1.allows("urn:cap:demo"));
        assert!(
            !calls[0].1.allows("urn:cap:anything-else"),
            "the handler runs under the reactor's scoped authority, not root"
        );
    }

    #[test]
    fn watching_creates_each_inbox_before_a_tuple_can_race_it() {
        // A recursive watch only covers directories that exist when it starts; one created
        // later is caught by watching its parent, which races a tuple written immediately
        // after. On a fresh machine NO inbox exists, so the first tuple a space ever
        // receives is the likeliest to be missed — and a missed tuple is silent, sitting in
        // an inbox nothing re-reads until a restart. Observed in production on the first
        // enquiry a new edge received.
        let root = reactive_root("watch-precreate", "contact", "urn:contact:handle");
        assert!(
            !root.join("contact").join("inbox").exists(),
            "precondition: a fresh space has no inbox"
        );

        let reactor = Arc::new(SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::root(),
        ));
        reactor.watch();

        assert!(
            root.join("contact").join("inbox").is_dir(),
            "watch() must create the inbox up front, so no drop can land in an unwatched directory"
        );
    }

    #[test]
    fn a_failing_handler_dead_letters_to_error() {
        let root = reactive_root("react-err", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(false));
        let reactor = SpaceReactor::new(root.clone(), mock, Capability::root());
        assert!(matches!(
            reactor.drain("jobs").as_slice(),
            [(got, Outcome::Errored(_))] if *got == id
        ));

        // The tuple is dead-lettered to error, with an inspectable .err note.
        let errored = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:jobs"))
                    .with_arg("state", ArgRef::Inline(b"error".to_vec())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(String::from_utf8(errored.bytes).unwrap(), id);
        assert!(root
            .join("jobs")
            .join("error")
            .join(format!("{id}.err"))
            .exists());
    }

    /// Run `act` with [`ON_STAGED`] set, and return what a reader racing each stage saw the
    /// moment a tuple landed there: `(stage, the note beside it)`, `None` for no note.
    fn racing_reader(act: impl FnOnce()) -> Vec<(String, Option<String>)> {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let record = std::rc::Rc::clone(&seen);
        ON_STAGED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |dir: &Path, id: &str| {
                let stage = dir.file_name().unwrap().to_str().unwrap().to_string();
                let ext = if stage == "outbox" { "out" } else { "err" };
                let note = std::fs::read_to_string(dir.join(format!("{id}.{ext}"))).ok();
                record.borrow_mut().push((stage, note));
            }));
        });
        act();
        ON_STAGED.with(|hook| *hook.borrow_mut() = None);
        let seen = seen.borrow().clone();
        seen
    }

    /// Ledger #1595: a reader that finds a fresh dead letter in `error/` finds its whole
    /// `.err` note beside it. The tuple used to move first and the note to follow, so
    /// `dead_letters` (the heartbeat's FAILING line) and `rd state=error` read "(no .err
    /// note)" in between. The seam fires the instant the tuple lands, which is exactly when
    /// such a reader would look.
    #[test]
    fn a_dead_letter_is_never_staged_without_its_whole_note() {
        let root = reactive_root("staged-err", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        out(&k, &cap, "urn:space:jobs", b"work");
        let reactor = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(false)),
            Capability::root(),
        );
        let mut outcome = Vec::new();
        let seen = racing_reader(|| outcome = reactor.drain("jobs"));
        let [(_, Outcome::Errored(reason))] = outcome.as_slice() else {
            panic!("one dead letter: {outcome:?}");
        };
        assert_eq!(
            seen,
            vec![("error".to_string(), Some(reason.clone()))],
            "the tuple reached `error/` before its note did"
        );
    }

    /// The same order for a handled tuple: its `.out` (what the handler answered) is beside
    /// it the moment it reaches `outbox/`.
    #[test]
    fn a_handled_tuple_is_never_staged_without_its_answer() {
        let root = reactive_root("staged-out", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        out(&k, &cap, "urn:space:jobs", b"work");
        let reactor = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::root(),
        );
        let seen = racing_reader(|| {
            reactor.drain("jobs");
        });
        assert_eq!(seen, vec![("outbox".to_string(), Some("ok".to_string()))]);
    }

    /// And for a file a `take` quarantines because it does not hash to its id: the
    /// `corrupt:` note is there before the file is.
    #[test]
    fn a_quarantined_file_is_never_staged_without_its_note() {
        let root = std::env::temp_dir()
            .join(format!("ikigai-intray-test-{}", std::process::id()))
            .join("staged-quarantine");
        let _ = std::fs::remove_dir_all(&root);
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_TAKE.to_string()]);
        let id = out(&k, &cap, "urn:space:q", b"payload");
        // Torn: the inbox file no longer holds the bytes its name hashes.
        std::fs::write(
            root.join("q").join("inbox").join(format!("{id}.tuple")),
            b"pay",
        )
        .unwrap();
        let seen = racing_reader(|| {
            let taken = block_on(
                k.issue(
                    Request::new(Verb::Delete, iri("urn:space:q"))
                        .with_arg("tuple", ArgRef::Inline(id.clone().into_bytes())),
                    &cap,
                ),
            );
            assert!(taken.is_err(), "a torn tuple is not delivered: {taken:?}");
        });
        assert_eq!(seen, vec![("error".to_string(), Some(corrupt_note(&id)))]);
    }

    /// Ledger #1596: a RESCAN (events were dropped; it names a directory, or nothing) drains
    /// every inbox at once. It used to match no tuple path and was ignored, so a tuple whose
    /// create event was lost waited for the next [`SWEEP_EVERY`].
    #[test]
    fn a_rescan_drains_every_inbox_at_once() {
        use notify::event::{EventKind, Flag};
        use notify::Event;
        let root = reactive_root("rescan", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(root.clone(), mock.clone(), Capability::root());
        let handled = |id: &str| {
            root.join("jobs")
                .join("outbox")
                .join(format!("{id}.tuple"))
                .exists()
        };

        // FSEvents' form: MustScanSubDirs on a directory, which is no tuple's path.
        let first = out(&k, &cap, "urn:space:jobs", b"first");
        reactor.react_to_event(
            &root,
            &Event::new(EventKind::Other)
                .set_flag(Flag::Rescan)
                .add_path(root.join("jobs")),
        );
        assert!(
            handled(&first),
            "a rescan naming the space's directory drains its inbox"
        );

        // inotify's form: IN_Q_OVERFLOW carries no path at all.
        let second = out(&k, &cap, "urn:space:jobs", b"second");
        reactor.react_to_event(&root, &Event::new(EventKind::Other).set_flag(Flag::Rescan));
        assert!(handled(&second), "a rescan with no path drains every inbox");
        assert_eq!(mock.calls().len(), 2, "each tuple is handled once");
    }

    /// Leave `id` exactly as a reactor killed mid-pass leaves it: claimed into
    /// `.processing/` by `claim`'s own rename, and never settled.
    fn interrupt(root: &Path, space_name: &str, id: &str) -> PathBuf {
        let staging = root.join(space_name).join(".processing");
        std::fs::create_dir_all(&staging).unwrap();
        let staged = staging.join(format!("{id}.tuple"));
        std::fs::rename(
            root.join(space_name)
                .join("inbox")
                .join(format!("{id}.tuple")),
            &staged,
        )
        .unwrap();
        staged
    }

    /// A tuple in flight when the reactor stopped is ACCOUNTED FOR by the next reactor's
    /// catch-up, never stranded (ledger #738; gonk's restart scenario, ported). The
    /// default is at-most-once: the handler may already have acted, so it is dead-lettered
    /// with a note that says so and that `retry=` runs it again, and it is NOT re-fired.
    #[test]
    fn a_tuple_in_flight_at_restart_is_dead_lettered_not_stranded() {
        let root = reactive_root("react-interrupted", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");
        let staged = interrupt(&root, "jobs", &id);

        let heard: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = Arc::clone(&heard);
        let mock = Arc::new(MockResolver::new(true));
        let restarted = SpaceReactor::new(root.clone(), mock.clone(), Capability::root())
            .on_dead_letter(move |_, tuple, _| sink.lock().unwrap().push(tuple.to_string()));
        let drained = restarted.drain("jobs");

        assert!(
            !staged.exists(),
            "the interrupted tuple is still stranded in .processing after the catch-up \
             (drained {drained:?})"
        );
        let errored = root.join("jobs").join("error");
        assert!(
            errored.join(format!("{id}.tuple")).exists(),
            "dead-lettered"
        );
        let note = std::fs::read_to_string(errored.join(format!("{id}.err"))).unwrap();
        assert!(note.contains("interrupted"), "{note}");
        assert!(note.contains(&format!("retry={id}")), "{note}");
        assert!(
            mock.calls().is_empty(),
            "NOT re-fired: the handler may already have acted"
        );
        assert_eq!(*heard.lock().unwrap(), vec![id.clone()], "and it is loud");
    }

    /// A host whose handlers are idempotent opts into at-least-once: the interrupted tuple
    /// goes back to the inbox and the SAME catch-up runs it.
    #[test]
    fn an_interrupted_tuple_is_requeued_and_rerun_when_the_host_says_so() {
        let root = reactive_root("react-interrupted-requeue", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");
        interrupt(&root, "jobs", &id);

        let mock = Arc::new(MockResolver::new(true));
        let restarted = SpaceReactor::new(root.clone(), mock.clone(), Capability::root())
            .on_interrupted(Interrupted::Requeue);
        assert_eq!(
            restarted.drain("jobs"),
            vec![(id.clone(), Outcome::Handled)]
        );
        assert_eq!(mock.calls().len(), 1, "run again, once");
        assert_eq!(
            restarted.recover_interrupted(),
            Ok(&[Recovered {
                space: "jobs".to_string(),
                tuple: id,
                outcome: Ok(Interrupted::Requeue),
            }][..]),
            "the report says what was recovered, and a second call returns the same one"
        );
    }

    /// A tuple in `.processing/` is only interrupted if no LIVE reactor is working on it. A
    /// second reactor sharing the root (a `--react` session beside the daemon) must not
    /// steal the first one's in-flight tuple; once the first is gone, the next one recovers.
    #[test]
    fn a_live_reactors_in_flight_tuple_is_not_recovered_out_from_under_it() {
        let root = reactive_root("react-interrupted-live", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let live = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::root(),
        );
        assert_eq!(
            live.recover_interrupted(),
            Ok(&[][..]),
            "nothing to recover yet"
        );
        // `live` is now mid-pass on the tuple.
        let staged = interrupt(&root, "jobs", &id);

        let mock = Arc::new(MockResolver::new(true));
        let beside = SpaceReactor::new(root.clone(), mock.clone(), Capability::root());
        assert!(beside.drain("jobs").is_empty());
        let skipped = beside
            .recover_interrupted()
            .expect_err("a live reactor shares the root");
        assert!(skipped.contains("another live reactor"), "{skipped}");
        assert!(
            staged.exists(),
            "the live reactor's tuple is left where it is"
        );
        assert!(mock.calls().is_empty());

        // Both gone (the in-flight pass died with them): the next reactor recovers it.
        drop(live);
        drop(beside);
        let next = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(true)),
            Capability::root(),
        );
        assert_eq!(next.recover_interrupted().map(<[Recovered]>::len), Ok(1));
        assert!(!staged.exists());
        assert!(root
            .join("jobs")
            .join("error")
            .join(format!("{id}.tuple"))
            .exists());
    }

    /// The in-flight stage is readable like the other three, so a reader counting the
    /// queue can count it (ledger #738).
    #[test]
    fn rd_reads_the_processing_stage() {
        let root = reactive_root("react-processing-rd", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");
        interrupt(&root, "jobs", &id);
        let processing = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:jobs"))
                    .with_arg("state", ArgRef::Inline(b"processing".to_vec())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(String::from_utf8(processing.bytes).unwrap(), id);
    }

    #[test]
    fn processing_is_exactly_once() {
        let root = reactive_root("react-once", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(root, mock.clone(), Capability::root());
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        // A second pass finds the tuple already claimed — it does NOT fire again.
        assert!(matches!(reactor.process("jobs", &id), Outcome::Skipped(_)));
        assert_eq!(mock.calls().len(), 1, "the handler fires exactly once");
    }

    #[test]
    fn a_space_without_a_handler_is_not_reactive() {
        // No handler file → not reactive: the drop stays in the inbox for rd/take.
        let root = std::env::temp_dir()
            .join(format!("ikigai-intray-test-{}", std::process::id()))
            .join("react-none");
        let _ = std::fs::remove_dir_all(&root);
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);
        let id = out(&k, &cap, "urn:space:loose", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(root, mock.clone(), Capability::root());
        assert!(matches!(reactor.process("loose", &id), Outcome::Skipped(_)));
        assert!(mock.calls().is_empty(), "no handler fired");
        let inbox =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:loose")), &cap)).unwrap();
        assert_eq!(
            String::from_utf8(inbox.bytes).unwrap(),
            id,
            "tuple stays in inbox"
        );
    }

    #[test]
    fn inbox_tuple_matches_only_genuine_drops() {
        let root = Path::new("/spaces");
        // A real drop: <root>/<space>/inbox/<id>.tuple
        assert_eq!(
            inbox_tuple(root, Path::new("/spaces/jobs/inbox/abc123.tuple")),
            Some(("jobs".to_string(), "abc123".to_string()))
        );
        // Not a drop: an outbox move, a staging file, the handler, a non-tuple, outside root.
        assert_eq!(
            inbox_tuple(root, Path::new("/spaces/jobs/outbox/abc.tuple")),
            None
        );
        assert_eq!(
            inbox_tuple(root, Path::new("/spaces/jobs/.processing/abc.tuple")),
            None
        );
        assert_eq!(inbox_tuple(root, Path::new("/spaces/jobs/handler")), None);
        assert_eq!(
            inbox_tuple(root, Path::new("/spaces/jobs/inbox/abc.err")),
            None
        );
        assert_eq!(inbox_tuple(root, Path::new("/elsewhere/x.tuple")), None);
    }

    /// A space's `cap` file NARROWS the reactor's authority; it cannot mint.
    ///
    /// ★ This test is the inverse of the one it replaces
    /// (`a_space_cap_file_overrides_the_reactor_default`), which pinned the defect: `cap`
    /// called `Capability::scoped`, REPLACING the reactor's capability, so a file in the same
    /// directory as the inbox could grant a scope the reactor never held (ledger #445). Same
    /// fixture, opposite assertion — the file selects a subset of what the reactor already
    /// holds, and the comment lines and blank lines it may carry are still ignored.
    #[test]
    fn a_space_cap_file_can_only_narrow_the_reactor_capability() {
        let root = reactive_root("react-percap", "jobs", "urn:test:handler");
        std::fs::write(
            root.join("jobs").join("cap"),
            "urn:cap:demo:read\n# a comment, and a blank line below\n\n",
        )
        .unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        // The reactor holds two scopes; the cap file picks one of them.
        let reactor = SpaceReactor::new(
            root,
            mock.clone(),
            Capability::scoped(vec![
                "urn:cap:demo:read".to_string(),
                "urn:cap:demo:write".to_string(),
            ]),
        );
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].1.allows("urn:cap:demo:read"),
            "the scope the file named, which the reactor holds, is kept"
        );
        assert!(
            !calls[0].1.allows("urn:cap:demo:write"),
            "the scope the file did not name is dropped — the file still selects"
        );
    }

    /// The security property itself: a scope the reactor does not hold is DROPPED, not
    /// granted. `cap` lives beside `inbox`, so whoever can drop a tuple can write this file;
    /// the worst they can do is take authority away.
    #[test]
    fn a_cap_file_scope_the_reactor_does_not_hold_is_dropped() {
        let root = reactive_root("react-capmint", "jobs", "urn:test:handler");
        std::fs::write(
            root.join("jobs").join("cap"),
            // Everything an attacker would ask for: the broad store token gonk refuses on
            // every certificate, plus a scope the reactor was never given.
            "urn:cap:store:write\nurn:cap:exec\nurn:cap:demo:read\n",
        )
        .unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(
            root,
            mock.clone(),
            Capability::scoped(vec!["urn:cap:demo:read".to_string()]),
        );
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        let ran_under = &calls[0].1;
        assert!(
            !ran_under.allows("urn:cap:store:write"),
            "a file in the drop tree cannot mint the broad store token"
        );
        assert!(
            !ran_under.allows("urn:cap:exec"),
            "nor any other scope the reactor never held"
        );
        assert!(!ran_under.is_root(), "and never root");
        assert_eq!(
            ran_under.scopes().map(|s| s.len()),
            Some(1),
            "exactly the intersection survives: {ran_under:?}"
        );
        assert!(ran_under.allows("urn:cap:demo:read"));
    }

    /// A reactor wired with root is the one case where a `cap` file still gets exactly what
    /// it asks for — `Capability::root().attenuate(s) == scoped(s)` — which is how the
    /// documented per-space grant keeps working for a host that deliberately gave the
    /// reactor a root ceiling. Attenuation is the same operation either way.
    #[test]
    fn a_root_reactor_attenuates_to_exactly_the_cap_file() {
        let root = reactive_root("react-caproot", "jobs", "urn:test:handler");
        std::fs::write(
            root.join("jobs").join("cap"),
            "urn:cap:lisp\nurn:cap:space:out\n",
        )
        .unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(root, mock.clone(), Capability::root());
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let ran_under = mock.calls()[0].1.clone();
        assert!(!ran_under.is_root(), "the handler is narrowed, not root");
        assert!(ran_under.allows("urn:cap:lisp"));
        assert!(ran_under.allows("urn:cap:space:out"));
        assert!(!ran_under.allows("urn:cap:exec"));
    }

    /// The host seam: authority comes from the host, and the `cap` file is not read at all.
    /// This is what `ikigai-gonk` wanted and could not have — it refuses `cap` files outright
    /// (`refuse_cap_file`) rather than trust a file in the drop tree.
    #[test]
    fn a_host_seam_decides_authority_and_the_cap_file_is_never_read() {
        let root = reactive_root("react-capseam", "jobs", "urn:test:handler");
        std::fs::write(root.join("jobs").join("cap"), "urn:cap:from-file\n").unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(
            root.clone(),
            mock.clone(),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        )
        .with_host_authority(|space| {
            (space == "jobs").then(|| Capability::scoped(vec!["urn:cap:from-host".to_string()]))
        });

        // The file is inert under this policy — and the host can find out, rather than
        // leaving an operator believing a file that does nothing.
        assert_eq!(reactor.ignored_cap_files(), vec!["jobs".to_string()]);

        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let ran_under = mock.calls()[0].1.clone();
        assert!(ran_under.allows("urn:cap:from-host"), "the host decided");
        assert!(
            !ran_under.allows("urn:cap:from-file"),
            "the cap file was never read"
        );
        assert!(!ran_under.allows("urn:cap:demo"));
    }

    /// A host seam that has no opinion about a space falls back to the reactor's capability —
    /// still not the file.
    #[test]
    fn a_host_seam_with_no_opinion_falls_back_to_the_reactor_capability() {
        let root = reactive_root("react-capseam-none", "jobs", "urn:test:handler");
        std::fs::write(root.join("jobs").join("cap"), "urn:cap:from-file\n").unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(
            root,
            mock.clone(),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        )
        .with_host_authority(|_| None);
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let ran_under = mock.calls()[0].1.clone();
        assert!(ran_under.allows("urn:cap:demo"));
        assert!(!ran_under.allows("urn:cap:from-file"));
    }

    /// Without a host seam there is nothing to ignore, so the report is empty — a host that
    /// reads a `cap` file is not being told its own files are inert.
    #[test]
    fn ignored_cap_files_is_empty_without_a_host_seam() {
        let root = reactive_root("react-capseam-off", "jobs", "urn:test:handler");
        std::fs::write(root.join("jobs").join("cap"), "urn:cap:from-file\n").unwrap();
        let mock = Arc::new(MockResolver::new(true));
        let reactor = SpaceReactor::new(root, mock, Capability::root());
        assert!(reactor.ignored_cap_files().is_empty());
    }

    /// A dead letter is LOUD at the moment it happens: the hook hears the space, the tuple
    /// and the reason the `.err` note carries — and a handled tuple says nothing.
    #[test]
    fn the_dead_letter_hook_hears_every_errored_tuple() {
        let root = reactive_root("react-hook", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let heard: Arc<Mutex<Vec<(String, String, String)>>> = Arc::default();
        let sink = Arc::clone(&heard);
        let failing = SpaceReactor::new(
            root.clone(),
            Arc::new(MockResolver::new(false)),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        )
        .on_dead_letter(move |space, tuple, reason| {
            sink.lock()
                .unwrap()
                .push((space.to_string(), tuple.to_string(), reason.to_string()));
        });
        assert!(matches!(failing.process("jobs", &id), Outcome::Errored(_)));
        let heard_now = heard.lock().unwrap().clone();
        assert_eq!(heard_now.len(), 1);
        assert_eq!(heard_now[0].0, "jobs");
        assert_eq!(heard_now[0].1, id);
        let note =
            std::fs::read_to_string(root.join("jobs").join("error").join(format!("{id}.err")))
                .unwrap();
        assert_eq!(heard_now[0].2, note, "the hook hears what the note says");

        let quiet = Arc::clone(&heard);
        let working = SpaceReactor::new(
            root,
            Arc::new(MockResolver::new(true)),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        )
        .on_dead_letter(move |_, _, _| quiet.lock().unwrap().push(Default::default()));
        let second = out(&k, &cap, "urn:space:jobs", b"more work");
        assert_eq!(working.process("jobs", &second), Outcome::Handled);
        assert_eq!(
            heard.lock().unwrap().len(),
            1,
            "a handled tuple is not a dead letter"
        );
    }

    /// The dead-letter report: every reactive space, its `error/` count, and the newest
    /// tuple's reason. A non-reactive space is not reported; a reactive one with nothing
    /// dead-lettered is, with a zero.
    #[test]
    fn dead_letters_counts_each_reactive_space_and_names_the_newest() {
        let root = reactive_root("react-deadletters", "jobs", "urn:test:handler");
        std::fs::create_dir_all(root.join("quiet")).unwrap();
        std::fs::write(root.join("quiet").join("handler"), "urn:test:handler").unwrap();
        std::fs::create_dir_all(root.join("passive").join("error")).unwrap();
        std::fs::write(root.join("passive").join("error").join("x.tuple"), "x").unwrap();

        let error = root.join("jobs").join("error");
        std::fs::create_dir_all(&error).unwrap();
        std::fs::write(error.join("aaa.tuple"), "a").unwrap();
        std::fs::write(error.join("aaa.err"), "older reason").unwrap();
        // Make the second note measurably newer than the first.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(error.join("bbb.tuple"), "b").unwrap();
        std::fs::write(error.join("bbb.err"), "denied: newest reason").unwrap();
        // A note whose tuple was retried away is not a dead letter.
        std::fs::write(error.join("ccc.err"), "stale note").unwrap();

        let report = dead_letters(&root);
        assert_eq!(
            report.iter().map(|s| s.space.as_str()).collect::<Vec<_>>(),
            vec!["jobs", "quiet"],
            "reactive spaces only, sorted: {report:?}"
        );
        assert_eq!(report[0].count, 2);
        let newest = report[0].newest.as_ref().expect("a newest dead letter");
        assert_eq!(newest.tuple, "bbb");
        assert_eq!(newest.reason, "denied: newest reason");
        assert_eq!(report[1].count, 0);
        assert_eq!(report[1].newest, None);

        // The caller-named form: a space the HOST fires (no `handler` file) is counted, the
        // list comes back sorted and deduplicated, and a name that is not one segment is not
        // read at all.
        let named = dead_letters_of(
            &root,
            [
                "passive".to_string(),
                "jobs".to_string(),
                "passive".to_string(),
                "../jobs".to_string(),
                "..".to_string(),
            ],
        );
        assert_eq!(
            named
                .iter()
                .map(|s| (s.space.as_str(), s.count))
                .collect::<Vec<_>>(),
            vec![("jobs", 2), ("passive", 1)]
        );
    }

    /// Ledger #1307: a tuple id is joined as `<id>.tuple` under a stage directory, and on
    /// Windows `dir.join("C:x.tuple")` REPLACES `dir`, so a drive-prefixed id would read
    /// (`rd`), move into the space (`retry=`) or take (`delete`) a file outside it. Refused
    /// as an invalid id on every platform, by each of the three verbs that take one, before
    /// any path is built; a Windows device name (`CON`) likewise.
    #[test]
    fn a_tuple_id_that_would_escape_on_windows_is_refused_by_every_verb() {
        let root = reactive_root("space-drive-id", "jobs", "urn:test:handler");
        let k = Kernel::new(Arc::new(space(root)));
        let cap = Capability::scoped(vec![
            CAP_OUT.to_string(),
            CAP_READ.to_string(),
            CAP_TAKE.to_string(),
            CAP_RETRY.to_string(),
        ]);
        for id in ["C:x", "C:", "CON", "nul"] {
            for (verb, arg) in [
                (Verb::Source, "tuple"),
                (Verb::Delete, "tuple"),
                (Verb::Sink, "retry"),
            ] {
                let r = block_on(
                    k.issue(
                        Request::new(verb, iri("urn:space:jobs"))
                            .with_arg(arg, ArgRef::Inline(id.as_bytes().to_vec())),
                        &cap,
                    ),
                );
                assert!(
                    matches!(r, Err(Error::InvalidArgument { ref name, .. }) if name == arg),
                    "{verb:?} {arg}={id} must be refused as an invalid id, got: {r:?}"
                );
            }
        }
    }

    #[test]
    fn rd_rejects_an_unknown_state() {
        let k = kernel_at("react-badstate");
        let cap = Capability::scoped(vec![CAP_READ.to_string()]);
        let bad = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:s"))
                    .with_arg("state", ArgRef::Inline(b"nowhere".to_vec())),
                &cap,
            ),
        );
        assert!(
            matches!(bad, Err(Error::InvalidArgument { ref name, .. }) if name == "state"),
            "got: {bad:?}"
        );
    }
}
