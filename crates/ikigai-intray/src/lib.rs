//! `ikigai-intray` — the intray as a **tuplespace**.
//!
//! A tuplespace is Linda's coordination model (Gelernter): processes communicate by
//! dropping *tuples* into a shared space and reading them back by *associative match*,
//! decoupled in space and time. `urn:space:{name}` is that space on the ikigai substrate:
//!
//! - **`out`** — **Sink** a tuple into the space. Content-addressed (blake3), so an
//!   identical drop is idempotent.
//! - **`rd`** — **Source** the space: list the tuple ids, read one with `tuple=<id>`, or
//!   list the ids of tuples matching a `match=<ASK>` template. Non-destructive.
//! - **`take`** — **Delete** a tuple, *returning its content*: claim a specific tuple
//!   (`tuple=<id>`), the first tuple matching a `match=<ASK>` template, or any tuple
//!   (no selector = a work-queue pop). Destructive and **atomic** — a rename-based
//!   compare-and-swap means two racers never both claim the same tuple.
//!
//! **Associative match** is a SPARQL ASK over the tuple's graph (`match=<query>`): a tuple
//! matches iff the ASK holds when its Turtle is the default graph. This is strictly more
//! than Linda's positional match — the whole graph-pattern language, not field equality —
//! and a non-RDF tuple simply never matches a template (take it by id or FIFO instead).
//!
//! The space is *physical and inspectable* — tuples are files under a jailed root, moving
//! through an **inbox → outbox → error** state machine. The [`SpaceReactor`] makes a space
//! ACTIVE (Linda's `eval`): a `handler` file names a URI, and a dropped tuple is claimed,
//! fired at that handler under the reactor's own scoped authority, and moved to `outbox`
//! (handled) or `error` (dead-letter). A later slice adds **encrypt-on-drop** (sign-then-
//! encrypt to the owner's key — both primitives already shipped). Two things Linda never had
//! and this does: `out`/`take` are **capability-gated**, and tuples can be **sealed** so the
//! space holds ciphertext it cannot read.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgRef, Capability, Description, Endpoint, EndpointSpace, Error, Invocation, Iri,
    ReprType, Representation, Request, Result, UriTemplate, Verb,
};
use notify::{RecursiveMode, Watcher};
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The tuplespace URI template: `urn:space:{name}` — the `{name}` is the space's identity.
pub const SPACE_TEMPLATE: &str = "urn:space:{name}";

/// `out` (dropping a tuple) requires this capability — the gate a stranger drops under.
pub const CAP_OUT: &str = "urn:cap:space:out";
/// `rd` (reading the space, non-destructively) requires this capability.
pub const CAP_READ: &str = "urn:cap:space:read";
/// `take` (removing a tuple) requires this capability — strictly more authority than read,
/// so a reader can observe the space without being able to consume from it.
pub const CAP_TAKE: &str = "urn:cap:space:take";

/// Mount the tuplespace at `urn:space:{name}`, backed by a directory under `root`
/// (`<root>/<name>/inbox/`). A host links this into its kernel.
pub fn space(root: PathBuf) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(SPACE_TEMPLATE).expect("SPACE_TEMPLATE is a valid template"),
        SpaceEndpoint::new(root),
    )
}

/// A directory-backed tuplespace. Each named space is `<root>/<name>/inbox/`, and a tuple is
/// a `<blake3>.tuple` file in it.
pub struct SpaceEndpoint {
    root: PathBuf,
}

impl SpaceEndpoint {
    pub fn new(root: PathBuf) -> Self {
        SpaceEndpoint { root }
    }

    /// The inbox directory of a named space. The name is a single segment (validated).
    fn inbox(&self, name: &str) -> PathBuf {
        self.root.join(name).join("inbox")
    }

    /// A named stage of the space's state machine: `inbox` (live drops), `outbox`
    /// (handled by the reactor), or `error` (dead-letter). Any other name is rejected —
    /// the stage names are a fixed, inspectable set, not a path.
    fn state_dir(&self, name: &str, state: &str) -> Result<PathBuf> {
        match state {
            "inbox" | "outbox" | "error" => Ok(self.root.join(name).join(state)),
            other => Err(Error::InvalidArgument {
                name: "state".to_string(),
                detail: format!("`{other}` is not a stage (inbox | outbox | error)"),
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

    /// Atomically claim a tuple by id: rename it out of the inbox into a private staging
    /// dir, read it, and remove it. **This is the compare-and-swap the whole tier turns on.**
    /// `rename` is atomic on POSIX, so if two takers race the same id exactly one rename
    /// finds the source present; the loser gets `NotFound` → `Ok(None)` and moves on.
    fn claim(&self, name: &str, id: &str) -> Result<Option<Vec<u8>>> {
        if id.is_empty() || id.contains(['/', '\\', '.']) {
            return Err(Error::InvalidArgument {
                name: "tuple".to_string(),
                detail: "a tuple id is a content hash".to_string(),
            });
        }
        let src = self.inbox(name).join(format!("{id}.tuple"));
        let staging = self.root.join(name).join(".taking");
        std::fs::create_dir_all(&staging)
            .map_err(|e| Error::Endpoint(format!("space `{name}`: staging: {e}")))?;
        let staged = staging.join(format!("{id}.tuple"));
        match std::fs::rename(&src, &staged) {
            Ok(()) => {
                let bytes = std::fs::read(&staged)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: take read: {e}")))?;
                let _ = std::fs::remove_file(&staged);
                Ok(Some(bytes))
            }
            // The source is gone — someone else claimed it first (or it never existed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Endpoint(format!("space `{name}`: take: {e}"))),
        }
    }
}

/// Validate that a `match=` argument is a syntactically valid **ASK** query (so a mistaken
/// SELECT fails loudly rather than silently matching nothing). Runs it once against an empty
/// store — cheap, and the only way to confirm the query's result shape is Boolean.
fn validate_ask(query: &str) -> Result<()> {
    let store = Store::new().map_err(|e| Error::Endpoint(format!("match: store init: {e}")))?;
    let prepared =
        SparqlEvaluator::new()
            .parse_query(query)
            .map_err(|e| Error::InvalidArgument {
                name: "match".to_string(),
                detail: format!("SPARQL syntax error: {e}"),
            })?;
    match prepared
        .on_store(&store)
        .execute()
        .map_err(|e| Error::Endpoint(format!("match: evaluation: {e}")))?
    {
        QueryResults::Boolean(_) => Ok(()),
        _ => Err(Error::InvalidArgument {
            name: "match".to_string(),
            detail: "an associative match must be an ASK query".to_string(),
        }),
    }
}

/// Does a tuple's graph satisfy the ASK? The tuple is parsed as Turtle into the default
/// graph; a tuple that isn't valid RDF simply never matches a SPARQL template.
fn tuple_matches(query: &str, bytes: &[u8]) -> Result<bool> {
    let store = Store::new().map_err(|e| Error::Endpoint(format!("match: store init: {e}")))?;
    if store
        .load_from_slice(RdfParser::from_format(RdfFormat::Turtle), bytes)
        .is_err()
    {
        return Ok(false); // non-RDF tuple: no template matches it
    }
    let prepared =
        SparqlEvaluator::new()
            .parse_query(query)
            .map_err(|e| Error::InvalidArgument {
                name: "match".to_string(),
                detail: format!("SPARQL syntax error: {e}"),
            })?;
    match prepared
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
        // The name is the space's identity — a single segment, never a path.
        if name.is_empty() || name.contains(['/', '\\', ':', '.']) {
            return Err(Error::InvalidArgument {
                name: "name".to_string(),
                detail: "a space name is a single segment (no `/ \\ : .`)".to_string(),
            });
        }
        let inbox = self.inbox(name);

        match inv.request.verb {
            // out: drop a tuple. Content-addressed → an identical drop is a no-op.
            Verb::Sink => {
                if !inv.capability.allows(CAP_OUT) {
                    return Err(Error::Denied(format!(
                        "dropping into a space needs `{CAP_OUT}`"
                    )));
                }
                let content = inv
                    .inline_arg("content")
                    .map_err(|_| Error::MissingArgument("content".to_string()))?;
                let id = blake3::hash(content).to_hex().to_string();
                std::fs::create_dir_all(&inbox)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: create inbox: {e}")))?;
                // Atomic appearance: write to a staging file, then rename it into the inbox.
                // rename is atomic on POSIX, so a reactor's watcher never observes a
                // half-written tuple — it sees the whole tuple or nothing.
                let staging = self.root.join(name).join(".dropping");
                std::fs::create_dir_all(&staging)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: staging: {e}")))?;
                let tmp = staging.join(format!("{id}.tuple"));
                std::fs::write(&tmp, content)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: out: {e}")))?;
                std::fs::rename(&tmp, inbox.join(format!("{id}.tuple")))
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: out publish: {e}")))?;
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    id.into_bytes(),
                ))
            }
            // rd: read the space — one tuple (`tuple=<id>`), the ids matching a `match=<ASK>`
            // template, or all ids. Non-destructive.
            Verb::Source => {
                if !inv.capability.allows(CAP_READ) {
                    return Err(Error::Denied(format!("reading a space needs `{CAP_READ}`")));
                }
                // `state=` selects which stage of the machine to read: the live `inbox`
                // (default), or the reactor's `outbox` (handled) / `error` (dead-letter).
                let dir = self.state_dir(name, inv.inline_str("state").unwrap_or("inbox"))?;
                if let Ok(id) = inv.inline_str("tuple") {
                    if id.is_empty() || id.contains(['/', '\\', '.']) {
                        return Err(Error::InvalidArgument {
                            name: "tuple".to_string(),
                            detail: "a tuple id is a content hash".to_string(),
                        });
                    }
                    let bytes = std::fs::read(dir.join(format!("{id}.tuple"))).map_err(|_| {
                        Error::NotFound(format!("no tuple `{id}` in space `{name}`"))
                    })?;
                    Ok(Representation::new(
                        ReprType::new("application/octet-stream"),
                        bytes,
                    ))
                } else if let Ok(query) = inv.inline_str("match") {
                    // Associative rd: the ids of tuples whose graph satisfies the ASK.
                    validate_ask(query)?;
                    let mut hits = Vec::new();
                    for id in Self::list_ids(&dir) {
                        if let Ok(bytes) = std::fs::read(dir.join(format!("{id}.tuple"))) {
                            if tuple_matches(query, &bytes)? {
                                hits.push(id);
                            }
                        }
                    }
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
                // A specific tuple by id: claim it, or NotFound if already taken/absent.
                if let Ok(id) = inv.inline_str("tuple") {
                    return match self.claim(name, id)? {
                        Some(bytes) => Ok(Representation::new(
                            ReprType::new("application/octet-stream"),
                            bytes,
                        )),
                        None => Err(Error::NotFound(format!(
                            "no tuple `{id}` to take in space `{name}`"
                        ))),
                    };
                }
                // Otherwise take the first tuple matching the template (or any). We scan
                // deterministically and claim the first that both matches and we win the
                // race for; a lost claim just moves to the next candidate.
                let matcher = inv.inline_str("match").ok();
                if let Some(query) = matcher {
                    validate_ask(query)?;
                }
                for id in Self::list_ids(&inbox) {
                    if let Some(query) = matcher {
                        match std::fs::read(inbox.join(format!("{id}.tuple"))) {
                            Ok(bytes) if !tuple_matches(query, &bytes)? => continue,
                            Ok(_) => {}
                            Err(_) => continue, // vanished between listing and read
                        }
                    }
                    if let Some(bytes) = self.claim(name, &id)? {
                        return Ok(Representation::new(
                            ReprType::new("application/octet-stream"),
                            bytes,
                        ));
                    }
                }
                Err(Error::NotFound(match matcher {
                    Some(_) => format!("no matching tuple to take in space `{name}`"),
                    None => format!("space `{name}` is empty"),
                }))
            }
            v => Err(Error::Endpoint(format!(
                "urn:space:* answers Source (rd), Sink (out), and Delete (take), not {v:?}"
            ))),
        }
    }

    fn describe(&self) -> Description {
        use ikigai_core::ArgSpec;
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
                    .input(
                        ArgSpec::new("tuple")
                            .optional()
                            .summary("a tuple id to read; omit to list"),
                    )
                    .input(
                        ArgSpec::new("match")
                            .optional()
                            .summary("a SPARQL ASK; list only the tuple ids whose graph satisfies it"),
                    )
                    .input(
                        ArgSpec::new("state")
                            .optional()
                            .one_of(["inbox", "outbox", "error"])
                            .summary("which stage to read (default inbox): inbox | outbox | error"),
                    )
                    .requires(CAP_READ),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("out — drop a tuple (the piped content) into the space")
                    .requires(CAP_OUT),
            )
            .action(
                ActionSpec::new(Verb::Delete)
                    .summary("take — atomically remove a tuple and return it (by id, by match, or any)")
                    .input(
                        ArgSpec::new("tuple")
                            .optional()
                            .summary("take this specific tuple id"),
                    )
                    .input(
                        ArgSpec::new("match")
                            .optional()
                            .summary("a SPARQL ASK; take the first tuple whose graph satisfies it"),
                    )
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

/// The reactive engine over a directory of spaces. A dropped tuple is CLAIMED (the same
/// atomic rename-CAS as `take`, so it fires exactly once even under duplicate events), the
/// space's handler is fired with the tuple as `content`, and the tuple moves to `outbox`
/// on success or `error` on failure. "Transport dumb, resource smart": the reactor passes
/// bytes + the space/tuple ids; all policy lives in the handler.
///
/// The handler runs under the reactor's OWN `capability` — the owner's processing authority,
/// configured when the reactor is wired — NEVER the dropper's (who held only `out`) and never
/// root. A stranger's drop cannot escalate past what the handler is authorized to reach.
///
/// This is the deterministic core (`drain`/`process`); the live filesystem watcher that calls
/// `process` on each drop is a thin wrapper the host installs (Slice 3b).
pub struct SpaceReactor {
    root: PathBuf,
    // Path-qualified rather than `use`d: `ikigai_resolve::Resolver` has a 1-arg `issue` that
    // would shadow the inherent async `Kernel::issue` in this module's tests.
    resolver: Arc<dyn ikigai_resolve::Resolver>,
    capability: Capability,
}

impl SpaceReactor {
    /// Build a reactor over `root` (the same tree the spaces live in), firing handlers
    /// through `resolver` under `capability`.
    pub fn new(
        root: PathBuf,
        resolver: Arc<dyn ikigai_resolve::Resolver>,
        capability: Capability,
    ) -> Self {
        SpaceReactor {
            root,
            resolver,
            capability,
        }
    }

    /// A space is REACTIVE iff `<root>/<name>/handler` exists; its content (trimmed) is the
    /// handler URI a dropped tuple is fired at. Self-describing + inspectable — no config
    /// schema to invent. `None` = not reactive (drops just accumulate for `rd`/`take`).
    fn handler_uri(&self, name: &str) -> Option<String> {
        let raw = std::fs::read_to_string(self.root.join(name).join("handler")).ok()?;
        let uri = raw.trim();
        (!uri.is_empty()).then(|| uri.to_string())
    }

    /// The capability a space's handler runs under: the scopes listed in `<root>/<name>/cap`
    /// (one per line; blank lines and `#` comments ignored), else the reactor's default. This
    /// is how a space grants its handler *exactly* the authority it needs — the bookings space
    /// grants `{urn:cap:lisp, urn:cap:personal:calendar:read:freebusy, urn:cap:llm, urn:cap:space:out}`
    /// — never root, never the dropper's. Same inspectable file convention as `handler`.
    fn capability_for(&self, name: &str) -> Capability {
        match std::fs::read_to_string(self.root.join(name).join("cap")) {
            Ok(raw) => {
                let scopes: Vec<String> = raw
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect();
                if scopes.is_empty() {
                    self.capability.clone()
                } else {
                    Capability::scoped(scopes)
                }
            }
            Err(_) => self.capability.clone(),
        }
    }

    /// Process every pending tuple in a space's inbox — the startup catch-up pass, and the
    /// deterministic entry the live watcher and the tests both drive. Returns each
    /// `(tuple id, outcome)`.
    pub fn drain(&self, name: &str) -> Vec<(String, Outcome)> {
        SpaceEndpoint::list_ids(&self.root.join(name).join("inbox"))
            .into_iter()
            .map(|id| {
                let outcome = self.process(name, &id);
                (id, outcome)
            })
            .collect()
    }

    /// Process ONE tuple: claim it, fire the handler, move it to `outbox`/`error`.
    pub fn process(&self, name: &str, id: &str) -> Outcome {
        let Some(handler) = self.handler_uri(name) else {
            return Outcome::Skipped("no handler (not a reactive space)");
        };
        // Claim atomically — rename out of the inbox into a private processing dir. If the
        // rename finds nothing, another pass already took this tuple: fire exactly once.
        let claimed = match self.claim(name, id) {
            Ok(Some(path)) => path,
            Ok(None) => return Outcome::Skipped("already claimed"),
            Err(e) => return Outcome::Errored(e),
        };
        let bytes = match std::fs::read(&claimed) {
            Ok(b) => b,
            Err(e) => return self.settle(name, id, &claimed, Err(format!("read tuple: {e}"))),
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
                .map(|_| ())
                .map_err(|e| e.to_string())
            }
            Err(e) => Err(format!("bad handler URI `{handler}`: {e}")),
        };
        self.settle(name, id, &claimed, result)
    }

    /// Move a claimed tuple to its terminal stage: `outbox` on Ok, `error` (+ an `.err` note)
    /// on failure. Returns the matching [`Outcome`].
    fn settle(
        &self,
        name: &str,
        id: &str,
        claimed: &Path,
        result: std::result::Result<(), String>,
    ) -> Outcome {
        let (stage, outcome) = match &result {
            Ok(()) => ("outbox", Outcome::Handled),
            Err(e) => ("error", Outcome::Errored(e.clone())),
        };
        let dir = self.root.join(name).join(stage);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return Outcome::Errored(format!("create `{stage}`: {e}"));
        }
        if let Err(e) = std::fs::rename(claimed, dir.join(format!("{id}.tuple"))) {
            return Outcome::Errored(format!("move to `{stage}`: {e}"));
        }
        if let Err(msg) = &result {
            // A dead-letter note alongside the tuple, so a failure is inspectable via
            // `rd state=error`.
            let _ = std::fs::write(dir.join(format!("{id}.err")), msg);
        }
        outcome
    }

    /// Atomically claim a tuple by renaming it out of the inbox into a private `.processing`
    /// dir (the same compare-and-swap as the endpoint's `take`). `Ok(None)` if it's already
    /// gone — another pass won the race.
    fn claim(&self, name: &str, id: &str) -> std::result::Result<Option<PathBuf>, String> {
        let src = self
            .root
            .join(name)
            .join("inbox")
            .join(format!("{id}.tuple"));
        let staging = self.root.join(name).join(".processing");
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

    /// Go live: drain what's already pending (startup catch-up), then watch the spaces root
    /// and `process` each tuple as it lands. Returns immediately; the watch runs on a
    /// background thread for the life of the process (the `Arc<Self>` keeps the reactor alive).
    /// A non-reactive space (no `handler` file) is simply skipped — this is safe to call over
    /// the whole tree.
    pub fn watch(self: Arc<Self>) {
        for name in self.space_names() {
            let _ = self.drain(&name);
        }
        // Canonicalize so the paths `notify` reports (it resolves symlinks — macOS maps
        // /var → /private/var) line up with `root` when we strip the prefix.
        let root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        std::fs::create_dir_all(&root).ok();
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = match notify::recommended_watcher(move |res| {
                let _ = tx.send(res);
            }) {
                Ok(w) => w,
                Err(_) => return,
            };
            if watcher.watch(&root, RecursiveMode::Recursive).is_err() {
                return;
            }
            // `watcher` is held to the end of this scope, keeping the watch alive; the loop
            // blocks until the process exits.
            for event in rx.iter().flatten() {
                if event.kind.is_access() {
                    continue; // a read doesn't add a tuple
                }
                for path in &event.paths {
                    if let Some((name, id)) = inbox_tuple(&root, path) {
                        self.process(&name, &id);
                    }
                }
            }
        });
    }
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
        let root = std::env::temp_dir().join("ikigai-intray-test").join(sub);
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
        let root = std::env::temp_dir().join("ikigai-intray-test").join(sub);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(space_name)).unwrap();
        std::fs::write(root.join(space_name).join("handler"), handler).unwrap();
        root
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
            .join("ikigai-intray-test")
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

    #[test]
    fn a_space_cap_file_overrides_the_reactor_default() {
        // A space's `cap` file grants its handler exactly the authority it needs — the
        // booking payoff's per-space cap. When present, it wins over the reactor default.
        let root = reactive_root("react-percap", "jobs", "urn:test:handler");
        std::fs::write(
            root.join("jobs").join("cap"),
            "urn:cap:from-file\n# a comment, and a blank line below\n\n",
        )
        .unwrap();
        let k = Kernel::new(Arc::new(space(root.clone())));
        let cap = Capability::scoped(vec![CAP_OUT.to_string()]);
        let id = out(&k, &cap, "urn:space:jobs", b"work");

        let mock = Arc::new(MockResolver::new(true));
        // The reactor default is urn:cap:demo — the cap file must win over it.
        let reactor = SpaceReactor::new(
            root,
            mock.clone(),
            Capability::scoped(vec!["urn:cap:demo".to_string()]),
        );
        assert_eq!(reactor.process("jobs", &id), Outcome::Handled);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].1.allows("urn:cap:from-file"),
            "the cap file's scope is granted"
        );
        assert!(
            !calls[0].1.allows("urn:cap:demo"),
            "the reactor default is NOT used when a cap file is present"
        );
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
