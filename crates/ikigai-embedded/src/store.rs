//! The durable RDF store (`urn:iki:store:*`) and the work ledger (`urn:iki:ledger:*`)
//! that rides on it — the switch, the topology, and the refusal.
//!
//! **One switch binds both, because the ledger owns no bytes.** Every read
//! `ikigai-ledger` makes is a SPARQL query at `urn:iki:store:graph-select` and every write
//! an UPDATE at `urn:iki:store:graph-update`, each naming one ledger's named graph — so a
//! ledger space bound without a store space beside it is a set of resources that resolve
//! and then fail. They are composed here in one [`Fallback`], **store first**, matching
//! `ikigai-ledger`'s own composition; nothing else in this host binds either.
//!
//! Opt-in from the config home, exactly like the browse family next door and for exactly
//! the same reason: the dataset is a RocksDB directory, **RocksDB permits one writer per
//! directory** and enforces it with a `LOCK` file, and that is a property of the storage
//! engine rather than a detail of ours. It decides the topology, so it is written here
//! rather than discovered by an operator whose second terminal stopped working.
//!
//! ```toml
//! # ~/.config/ikigai/config.toml
//!
//! # (a) Solo: every ikigai process on this machine opens the dataset at startup.
//! #     Right for one operator with no daemon, and wrong the moment two run at once —
//! #     the second finds the directory held and says so (see [`refusal`]).
//! store = true
//!
//! # (b) Served: ONE named instance holds the directory and everything else resolves
//! #     through its socket. This is the topology of record, and the same one
//! #     `serve.browse.root` already uses.
//! serve.store = true
//! mount = "prefer urn:iki:store:=/Users/you/.ikigai/serve.sock"
//! # ⚠ A mount claims ONE prefix, so the ledger takes a second line — as the browse family
//! #   takes one for urn:repo: and one for urn:iki:annotation:. One switch binds both
//! #   locally; two lines reach both remotely.
//! mount = "prefer urn:iki:ledger:=/Users/you/.ikigai/serve.sock"
//! ```
//!
//! Mixing the two spellings is refused loud: a scoped line for instance A plus an
//! unscoped line every other process still honours re-creates precisely the collision
//! the scoping exists to prevent.
//!
//! **The switch lives here; the DIRECTORY lives in `store.toml`.** `ikigai-store` reads
//! its own layered `store.toml` (`<instance>.store.toml` overriding it) from the same
//! config home and defaults the dataset to `~/.ikigai/store` under the data home. Config
//! home for the setting, data home for the bytes, and no environment variable names
//! either — one setting, one spelling, one file that `ikigai config` can see.
//!
//! # Capabilities: the ledger needs the store's NARROW doors, never the broad one
//!
//! A sub-request carries the **caller's** capability unchanged, so whatever the ledger
//! asks the store for, the caller must hold. The everyday REPL session is root and needs
//! nothing. A narrowed session (`cap`), a served connection or an agent needs **both
//! halves** — the ledger's own grant and the store's per-graph token for that ledger's
//! graph — and [`grants_for`] is the whole list, computed rather than transcribed.
//!
//! ⚠ **The broad `urn:cap:store:write` does not work here, and it fails as a `Denied` that
//! looks like a bug in the ledger.** `urn:iki:store:graph-update` declares and enforces
//! `urn:cap:store:write:graph:*` — the broad key is not a prefix of that and is refused by
//! design, so a grant list that reaches for the powerful token produces a ledger that can
//! read nothing and write nothing. Narrow is not merely the better grant; it is the only
//! one that works.
//!
//! # ★ One open per PROCESS, not per kernel
//!
//! `ikigai_store::space` consumes a `DurableStore` by value, and a second
//! `DurableStore::open` on the same path **is refused inside one process too** (RocksDB
//! keeps its own registry; POSIX advisory locks would not have caught it). This host
//! builds more than one kernel per process in several modes — and its own test binaries
//! build a dozen — so the open is memoised in [`STORE_SPACE`] and every kernel gets an
//! `Arc` of the one space. Binding `ikigai_store::space(DurableStore::open(…))` per
//! kernel, which is what the crate's README composition shows, panics on the second
//! kernel.
//!
//! # Two failures, two different answers
//!
//! * **The directory is HELD** (`Error::Unavailable` — the typed, transient shape) — the
//!   space is not bound, and *whether anything is said depends on the config*. That is not
//!   a misconfiguration: the config is right and another process is simply running, and
//!   the ikigai answer to it is the wire. If `mount` lines cover both families the
//!   resource resolves there (mounts are tried after every local space, so the absent
//!   local binding is exactly what lets the mount answer) and this host says **nothing** —
//!   in topology (b) a held directory is not an event but every command forever, and a
//!   host that printed three lines on each one would be teaching its operator to ignore
//!   stderr. If the lines are missing, or cover only one of the two families, the operator
//!   gets the sentence that names what is missing. See [`refusal`].
//! * **Anything else** — an unwritable path, a `store.toml` that cannot be parsed, a
//!   config home that does not exist — is a misconfiguration, and it **panics**. A host
//!   that started anyway would be one whose durable store silently is not there.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ikigai_core::{Error, Fallback, Space};
use ikigai_store::DurableStore;

use crate::config;

/// The one open, memoised for the life of the process. `None` = not configured for this
/// instance, or configured and held by somebody else. See the module note.
///
/// `dyn Space` rather than `EndpointSpace`: what is bound is a [`Fallback`] over two
/// spaces — the store's and the ledger's — and the pair is what a kernel gets, always
/// together.
static STORE_SPACE: OnceLock<Option<Arc<dyn Space>>> = OnceLock::new();

/// A directory to open instead of the configured one.
static PATH_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Open the durable store at `dir` rather than at whatever `store.toml` names, and treat
/// it as configured whatever `config.toml` says.
///
/// The typed channel an **integration test** uses to stay hermetic, matching
/// [`crate::set_file_root`] and `set_code_signers_dir`: `cfg(test)` does not reach a
/// `tests/` binary, so the redirect has to be a call rather than a compile flag. Also the
/// seam a `--store <dir>` flag would use, if one is ever wanted.
///
/// Process-global and effective only **before the first kernel is built** — the open is
/// memoised, so a later call changes nothing and does not reopen anything.
pub fn set_store_path(dir: PathBuf) {
    *PATH_OVERRIDE.lock().expect("store path lock") = Some(dir);
}

/// The durable store's space with the ledger's beside it, when this instance is the one
/// that holds the dataset.
///
/// # Panics
///
/// On a misconfiguration — an unreadable `store.toml`, an unwritable dataset directory, a
/// `store` value that is neither `true` nor `false`, or scoped and unscoped switches in
/// one file. A held directory is *not* a misconfiguration and does not panic; see the
/// module note.
pub(crate) fn setup() -> Option<Arc<dyn Space>> {
    STORE_SPACE.get_or_init(build).clone()
}

/// Read the configuration and open, once.
fn build() -> Option<Arc<dyn Space>> {
    let path = path()?;
    match DurableStore::open(&path) {
        // ★ **Store FIRST.** `Fallback` tries its spaces in order, and the two grammars do
        // not overlap (`urn:iki:store:*` against `urn:iki:ledger:*`), so the order cannot
        // change which endpoint answers — but it is the order `ikigai-ledger`'s own tests
        // and README compose in, and a host that agrees with the crate it binds is one
        // fewer difference to reason about if a future grammar ever does overlap.
        Ok(store) => Some(Arc::new(Fallback::new(vec![
            Arc::new(ikigai_store::space(store)) as Arc<dyn Space>,
            Arc::new(ikigai_ledger::space()) as Arc<dyn Space>,
        ]))),
        // The typed transient: somebody else holds the directory. The binding is left out
        // so a mount can answer for it — and whether one *does* decides what to say.
        Err(e @ Error::Unavailable(_)) => {
            if let Some(message) = refusal(&path, &e, &mount_lines()) {
                eprintln!("{message}");
            }
            None
        }
        Err(e) => panic!(
            "ikigai: the durable store at {} cannot be opened: {e} — refusing to run \
             without it. Fix the path or its permissions, or point this host at another \
             directory with `path` in {}/store.toml.",
            path.display(),
            config_home_display()
        ),
    }
}

/// How much authority over one ledger a grant list should carry. Cumulative: each level
/// includes the ones above it, because there is no useful "may delete but may not read".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// `items`, `next`, `ledgers` and `item:{id}`.
    ///
    /// ⚠ `item:{id}` is the one that needed the workspace floor moved. Through
    /// `ikigai-ledger` 0.2.0 it over-declared the **broad** `urn:cap:store:read` on its
    /// `Source`/`Exists`, so a caller holding exactly this list could list a ledger and
    /// was denied on reading one item out of it. This list was deliberately NOT widened
    /// to work around that — adding `urn:cap:store:read` here would hand every ledger
    /// caller every graph in the dataset, which is the boundary the per-graph tokens
    /// exist to draw — and the floor moved to 0.2.1 instead, where the per-graph family
    /// is declared there too. Exercised by
    /// `ikigai-cli/tests/ledger.rs::the_narrow_per_graph_grants_work_and_the_broad_store_key_does_not`.
    Read,
    /// …plus `append`, `comment`, `close`, `reopen`, `claim`, `defer`, `link`, `label`
    /// and editing an item.
    Write,
    /// …plus `Delete` on an item, which moves its quads to that ledger's graveyard.
    Delete,
    /// …plus `purge`, which destroys the content in both graphs.
    Purge,
}

/// Every capability token a **non-root** caller needs to use the ledger called `ledger` at
/// `authority` — the ledger's own grant and the store's per-graph tokens underneath it,
/// in one list.
///
/// The everyday REPL session is root and needs none of this. This is the answer for
/// `ikigai serve --cap …`, for the REPL's `cap` command, and for an agent's ceiling.
///
/// ★ **Computed from both crates' own spellings, never transcribed.** A token is matched
/// exactly and a ledger's graph IRI is `ikigai-ledger`'s to name, so this calls
/// `Ledger::graph` and `ikigai_store::cap_read_graph` rather than formatting strings —
/// which means a host that is one version behind on either crate fails to compile instead
/// of handing an operator a grant list that silently denies.
///
/// ⚠ **Nothing here is `urn:cap:store:write`.** That token means the whole dataset,
/// `DROP ALL` included, and `urn:iki:store:graph-update` — which is the only write door
/// the ledger goes through — **refuses it**: the action declares and enforces
/// `urn:cap:store:write:graph:*`, and the broad key is not under that prefix. A grant list
/// built around the powerful token produces a ledger that cannot write, failing with a
/// `Denied` that reads like a bug in the ledger. See `docs/durable-store.md`.
///
/// ```no_run
/// # use ikigai_embedded::store::{grants_for, Authority};
/// let grants = grants_for("default", Authority::Write).unwrap();
/// assert!(grants.contains(&"urn:cap:ledger:write:default".to_string()));
/// assert!(grants.contains(
///     &"urn:cap:store:write:graph:urn:iki:ledger:graph:default".to_string()
/// ));
/// ```
///
/// # Errors
///
/// If `ledger` is not a usable ledger name — the wrong character class, too long, or one
/// of the eighteen words the bare-form sugar reserves.
pub fn grants_for(ledger: &str, authority: Authority) -> Result<Vec<String>, Error> {
    let ledger = ikigai_ledger::Ledger::parse(ledger)?;
    let graph = ledger.graph();
    // Read is the floor: every level below reads, and a ledger you may write and not read
    // is one whose own listing refuses.
    let mut grants = vec![ledger.cap_read(), ikigai_store::cap_read_graph(&graph)];
    if authority == Authority::Read {
        return Ok(grants);
    }
    grants.push(ledger.cap_write());
    grants.push(ikigai_store::cap_write_graph(&graph));
    if authority == Authority::Write {
        return Ok(grants);
    }
    // ⚠ The graveyard is a SECOND graph and a scoped write cannot reach across, so a
    // delete needs a second store write token. This is the line an operator gets wrong.
    grants.push(ledger.cap_delete());
    grants.push(ikigai_store::cap_write_graph(&ledger.deleted_graph()));
    if authority == Authority::Delete {
        return Ok(grants);
    }
    // A purge clears the graveyard and the live graph — the same two store tokens as a
    // delete, plus its own ledger grant, which is the whole difference in authority.
    grants.push(ledger.cap_purge());
    Ok(grants)
}

/// Which directory this process should hold, or `None` when it holds none.
fn path() -> Option<PathBuf> {
    if let Some(dir) = PATH_OVERRIDE.lock().expect("store path lock").clone() {
        return Some(dir);
    }
    // ⚠ `cfg(test)`: this crate's own unit tests build root kernels by the dozen, and on a
    // developer machine whose config.toml says `store = true` every one of them would
    // open the real dataset — the second in the process being refused outright. The same
    // trap `file_root` documents, and the same shape of answer. A `tests/` binary is NOT
    // `cfg(test)`: it calls [`set_store_path`].
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        if !enabled() {
            return None;
        }
        // Named in full rather than imported: the type is used only on this side of the
        // `cfg`, and an import that one configuration does not reach is an unused-import
        // error under `-D warnings`.
        let config =
            ikigai_store::StoreConfig::load(Some(crate::instance_name())).unwrap_or_else(|e| {
                panic!(
                    "ikigai: `store` is on for this instance but the store configuration \
                 cannot be read: {e}"
                )
            });
        Some(config.path)
    }
}

/// Is this instance the one that opens the dataset? See [`enabled_in`] for the rule.
#[cfg(not(test))]
fn enabled() -> bool {
    let instance = crate::instance_name();
    enabled_in(
        config::get(&format!("{instance}.store")),
        config::get("store"),
        &config::scoping_instances("store"),
    )
}

/// Which `store` spelling governs this instance: scoped lines when ANY instance scopes
/// the key — and then an unscoped line is refused loud, because every process honours one
/// and two processes cannot hold one directory — unscoped otherwise (the single-process
/// setup).
///
/// The twin of `browse::root_lines`, deliberately: one machine, one rule for "who holds
/// the lock", whichever exclusive resource is being held.
fn enabled_in(scoped: Option<String>, unscoped: Option<String>, scoping: &[String]) -> bool {
    if scoping.is_empty() {
        return truthy("store", unscoped.as_deref());
    }
    assert!(
        unscoped.is_none(),
        "ikigai: `store` is scoped to {} but the config also has an unscoped `store` \
         line — every process honours an unscoped line, so this would put a second \
         process on the dataset's exclusive lock. Scope ALL of them \
         (`<instance>.store = true`), designate ONE serving instance, and point every \
         other process at it: mount = \"prefer urn:iki:store:=<serve socket>\".",
        scoping
            .iter()
            .map(|i| format!("`{i}.store`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    truthy("store", scoped.as_deref())
}

/// A boolean switch, with **no third answer**: a value that is neither `true` nor `false`
/// is a typo, and a typo that silently means "off" looks exactly like a configuration
/// that is in effect.
fn truthy(key: &str, value: Option<&str>) -> bool {
    match value {
        None => false,
        Some("true") => true,
        Some("false") => false,
        Some(other) => panic!(
            "ikigai: `{key} = {other}` is neither true nor false — fix the config (a \
             value nobody can read would silently mean off, which looks the same as a \
             setting that is working)"
        ),
    }
}

/// The `mount` lines this config home carries, verbatim.
#[cfg(not(test))]
fn mount_lines() -> Vec<String> {
    config::all("mount")
}

/// Unit tests drive [`refusal`] directly; nothing here should read the developer's own
/// config home, for the reason [`path`] documents at length.
#[cfg(test)]
fn mount_lines() -> Vec<String> {
    Vec::new()
}

/// Does some `mount` line already answer for every IRI under `family`?
///
/// A mount claims an IRI PREFIX, so `urn:iki:` covers both families and
/// `urn:iki:ledger:` covers one — hence `family.starts_with(prefix)` rather than equality.
/// A mount NARROWER than the family (`urn:iki:store:select:`) answers for part of it and
/// is deliberately not counted: a partial answer is not an answer, and an operator whose
/// warning disappeared on one would lose the only signal they had.
///
/// The line is `[<mode>] <prefix>=<target>` (`prefer urn:iki:store:=/path/x.sock`), so
/// the prefix is the last whitespace-separated token before the first `=`.
fn some_mount_claims(lines: &[String], family: &str) -> bool {
    lines.iter().any(|line| {
        line.split('=')
            .next()
            .and_then(|head| head.split_whitespace().next_back())
            .is_some_and(|prefix| family.starts_with(prefix))
    })
}

/// What an operator sees when the dataset is already held — **or nothing at all**, when
/// the config already says where to reach it.
///
/// ★ The silence is the point, and it is what the module note promised before the code
/// did it: in the served topology (b) a held directory is not an event, it is *every
/// single command*, forever. A host that printed three lines of stderr on each one would
/// be training the operator to ignore the one channel it has for saying something real.
/// So when a `mount` covers BOTH families the absent local binding is the design working
/// and this returns `None`.
///
/// Otherwise three lines — the fact, the fix, and the underlying error — because the next
/// thing this operator sees is a bare "no endpoint resolved" for an IRI they just
/// configured, and a message that does not carry the whole answer leaves them where the
/// silence did.
///
/// ⚠ **Half a topology gets its own sentence.** One mount line rather than two is the
/// mistake this design actually generates — `docs/durable-store.md` warns about it twice
/// and the warning is easy to read past — and its symptom is the worst kind: the store
/// answers over the wire, the ledger does not, and the half that fails looks like a broken
/// ledger rather than a missing line. Naming the prefix that is missing turns that into a
/// one-line fix.
fn refusal(path: &Path, e: &Error, mounts: &[String]) -> Option<String> {
    let store = some_mount_claims(mounts, STORE_PREFIX);
    let ledger = some_mount_claims(mounts, LEDGER_PREFIX);
    if store && ledger {
        return None;
    }
    let fix = match (store, ledger) {
        (true, true) => unreachable!("returned above"),
        (true, false) => format!(
            "fix: a mount already reaches {STORE_PREFIX}* but NOTHING reaches \
             {LEDGER_PREFIX}* — a mount claims one prefix, so the ledger needs its own \
             line. Add mount = \"prefer {LEDGER_PREFIX}=<the holder's socket>\" to \
             {}/config.toml.",
            config_home_display()
        ),
        (false, true) => format!(
            "fix: a mount already reaches {LEDGER_PREFIX}* but NOTHING reaches \
             {STORE_PREFIX}* — and the ledger owns no bytes, so it will fail on the \
             store underneath it. Add mount = \"prefer {STORE_PREFIX}=<the holder's \
             socket>\" to {}/config.toml.",
            config_home_display()
        ),
        (false, false) => format!(
            "fix: this is topology, not a retry. Let ONE process hold the dataset and \
             resolve through it — mount = \"prefer {STORE_PREFIX}=<its socket>\" in \
             {}/config.toml, and a SECOND line for {LEDGER_PREFIX} (a mount matches one \
             prefix, so the ledger needs its own). See docs/durable-store.md.",
            config_home_display()
        ),
    };
    Some(format!(
        "ikigai: {STORE_PREFIX}* and {LEDGER_PREFIX}* are NOT bound here — the durable \
         store at {} is held by another process, and RocksDB permits one writer per \
         directory.\n  \
         {fix}\n  \
         underlying: {e}",
        path.display(),
    ))
}

/// The two IRI families this binding owns, named once so the refusal and the mount check
/// cannot drift from each other.
const STORE_PREFIX: &str = "urn:iki:store:";
const LEDGER_PREFIX: &str = "urn:iki:ledger:";

/// The config home as text, for a message that has to tell somebody which file to edit.
fn config_home_display() -> String {
    config::config_home()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/ikigai".to_string())
}

#[cfg(test)]
mod tests {
    use super::{enabled_in, grants_for, refusal, truthy, Authority};
    use ikigai_core::Error;
    use std::path::Path;

    /// ★ The grant list an operator copies, spelled out **as literals** — the one place in
    /// this crate that does not compute them.
    ///
    /// `grants_for` calls `Ledger::graph` and `ikigai_store::cap_read_graph`, so a test
    /// that built its expectation the same way would assert only that a function is
    /// deterministic. These strings are what goes into a config file and a `--cap` line,
    /// and a change to how either crate spells a graph IRI or a token has to fail HERE,
    /// where the operator's file would have to change too.
    #[test]
    fn the_write_grant_names_the_ledger_and_its_graph_and_nothing_broader() {
        let grants = grants_for("acme", Authority::Write).expect("a valid ledger name");
        assert_eq!(
            grants,
            vec![
                "urn:cap:ledger:read:acme",
                "urn:cap:store:read:graph:urn:iki:ledger:graph:acme",
                "urn:cap:ledger:write:acme",
                "urn:cap:store:write:graph:urn:iki:ledger:graph:acme",
            ]
        );
        // ⚠ The whole point: the broad key is ABSENT. `urn:iki:store:graph-update` refuses
        // it, so a list carrying it would be a ledger that cannot write — and the `Denied`
        // reads like a bug in the ledger rather than a grant that was never going to work.
        assert!(
            !grants.iter().any(|g| g == ikigai_store::CAP_WRITE),
            "the broad store write grant is DROP ALL and the narrow door refuses it: {grants:?}"
        );
        assert!(
            !grants.iter().any(|g| g == ikigai_store::CAP_READ),
            "{grants:?}"
        );
    }

    /// A delete needs write authority over TWO graphs, because the graveyard is a second
    /// graph and a scoped write cannot reach across. The row an operator gets wrong.
    #[test]
    fn a_delete_grant_carries_the_graveyard_too() {
        let grants = grants_for("acme", Authority::Delete).expect("a valid ledger name");
        assert!(
            grants.contains(&"urn:cap:ledger:delete:acme".to_string()),
            "{grants:?}"
        );
        assert!(
            grants.contains(
                &"urn:cap:store:write:graph:urn:iki:ledger:graph:acme:deleted".to_string()
            ),
            "the graveyard is a second graph and therefore a second token: {grants:?}"
        );
        // Purge adds its own ledger grant and no further store scope — the same two
        // graphs, a different authority over them.
        let purge = grants_for("acme", Authority::Purge).expect("a valid ledger name");
        assert_eq!(purge.len(), grants.len() + 1, "{purge:?}");
        assert!(
            purge.contains(&"urn:cap:ledger:purge:acme".to_string()),
            "{purge:?}"
        );
    }

    /// The bare `urn:iki:ledger:*` forms mean the ledger called `default`, and its grants
    /// say so — the name is in the token even when the request did not carry one.
    #[test]
    fn the_default_ledgers_grants_name_it_explicitly() {
        let grants = grants_for("default", Authority::Read).expect("default is a ledger name");
        assert_eq!(
            grants,
            vec![
                "urn:cap:ledger:read:default",
                "urn:cap:store:read:graph:urn:iki:ledger:graph:default",
            ]
        );
    }

    /// A name that cannot be a ledger is refused rather than turned into a token nothing
    /// will ever match — a capability is matched exactly, so a typo would be a silent
    /// denial at the first use instead of an error at the point of configuration.
    #[test]
    fn a_name_that_cannot_be_a_ledger_is_refused_here() {
        assert!(
            grants_for("items", Authority::Read).is_err(),
            "reserved by the sugar"
        );
        assert!(
            grants_for("Acme", Authority::Read).is_err(),
            "case is not a distinction"
        );
        assert!(
            grants_for("a:b", Authority::Read).is_err(),
            "would forge a token"
        );
    }

    /// Nobody scopes `store` ⇒ the unscoped line governs, and absence is off.
    #[test]
    fn unscoped_governs_when_nobody_scopes() {
        assert!(enabled_in(None, Some("true".into()), &[]));
        assert!(!enabled_in(None, Some("false".into()), &[]));
        assert!(!enabled_in(None, None, &[]));
    }

    /// Somebody scopes ⇒ only THIS instance's scoped line governs. Another instance's
    /// line is simply not ours, and this process holds nothing — which is the served
    /// topology working, not a failure.
    #[test]
    fn scoped_governs_only_its_instance() {
        let scoping = ["serve".to_string()];
        assert!(enabled_in(Some("true".into()), None, &scoping));
        assert!(!enabled_in(None, None, &scoping));
    }

    /// One scoped line plus one unscoped line would put two processes on the one
    /// exclusive lock — refused loud, not merged.
    #[test]
    #[should_panic(expected = "unscoped")]
    fn mixing_scoped_and_unscoped_is_refused() {
        enabled_in(
            Some("true".into()),
            Some("true".into()),
            &["serve".to_string()],
        );
    }

    /// A value that is neither `true` nor `false` is a typo, and a typo must not read as
    /// "off" — that is indistinguishable from a setting that is working.
    #[test]
    #[should_panic(expected = "neither true nor false")]
    fn a_third_answer_is_refused() {
        truthy("store", Some("yes"));
    }

    /// The held-directory line carries the whole answer: the path, why it cannot be
    /// shared, and the config line that fixes it. It is the only thing an operator sees
    /// before a bare "no endpoint" for an IRI they just configured.
    #[test]
    fn the_refusal_names_the_path_and_the_fix() {
        let text = held(&[]).expect("no mount, so the operator needs the sentence");
        assert!(text.contains("/tmp/ikigai-store"), "{text}");
        assert!(text.contains("one writer per directory"), "{text}");
        assert!(text.contains("prefer urn:iki:store:="), "{text}");
        assert!(text.contains("SECOND line for urn:iki:ledger:"), "{text}");
    }

    /// ★ **The served topology is SILENT.** A held directory under a config that already
    /// says where to reach it is not an event — it is every command this operator will
    /// ever type — and three lines of stderr on each one is how a channel stops being
    /// read. Both spellings that cover the two families are silent: the two exact lines
    /// the docs publish, and one broader prefix that covers both.
    #[test]
    fn a_mount_over_both_families_says_nothing() {
        assert_eq!(
            held(&[
                "prefer urn:iki:store:=/Users/you/.ikigai/serve.sock".into(),
                "prefer urn:iki:ledger:=/Users/you/.ikigai/serve.sock".into(),
            ]),
            None
        );
        // One mount at a shorter prefix answers for both families, so it is also complete.
        assert_eq!(held(&["prefer urn:iki:=peer:plasma".into()]), None);
        // …and a mount for some unrelated family is not an answer for either.
        assert!(held(&["prefer urn:llm:=peer:plasma".into()]).is_some());
    }

    /// ⚠ **Half a topology is the mistake this design generates**, and its symptom lies:
    /// the store answers over the wire, the ledger does not, and the operator reads that
    /// as a broken ledger rather than a missing config line. So the message names the
    /// prefix that is missing rather than re-printing the generic pair.
    #[test]
    fn one_mount_of_the_two_names_the_missing_prefix() {
        let store_only =
            held(&["prefer urn:iki:store:=/x.sock".into()]).expect("half a topology warns");
        assert!(
            store_only.contains("NOTHING reaches urn:iki:ledger:"),
            "{store_only}"
        );
        assert!(
            store_only.contains("prefer urn:iki:ledger:=<the holder's socket>"),
            "{store_only}"
        );

        let ledger_only =
            held(&["prefer urn:iki:ledger:=/x.sock".into()]).expect("half a topology warns");
        assert!(
            ledger_only.contains("NOTHING reaches urn:iki:store:"),
            "{ledger_only}"
        );
        // The ledger owns no bytes, so this half fails on the store underneath it — the
        // reason this case is not merely the mirror image of the one above.
        assert!(ledger_only.contains("owns no bytes"), "{ledger_only}");
    }

    /// A mount NARROWER than the family answers for part of it, which is not an answer —
    /// and silencing the warning on one would take away the operator's only signal.
    #[test]
    fn a_mount_narrower_than_the_family_is_not_an_answer() {
        assert!(held(&["prefer urn:iki:store:select=/x.sock".into()]).is_some());
    }

    /// The held-directory message for one set of `mount` lines.
    fn held(mounts: &[String]) -> Option<String> {
        refusal(
            Path::new("/tmp/ikigai-store"),
            &Error::Unavailable("the store at /tmp/ikigai-store is already held".into()),
            mounts,
        )
    }
}
