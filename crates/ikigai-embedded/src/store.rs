//! The durable RDF store (`urn:iki:store:*`) — the switch, the topology, and the refusal.
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
//! * **The directory is HELD** (`Error::Unavailable` — the typed, transient shape) — one
//!   loud line on stderr and the space is not bound. That is not a misconfiguration: the
//!   config is right and another process is simply running, and the ikigai answer to it
//!   is the wire. If a `mount` line names the holder the resource resolves there (mounts
//!   are tried after every local space, so the absent local binding is what lets the
//!   mount answer); if not, the operator has the sentence that says so.
//! * **Anything else** — an unwritable path, a `store.toml` that cannot be parsed, a
//!   config home that does not exist — is a misconfiguration, and it **panics**. A host
//!   that started anyway would be one whose durable store silently is not there.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ikigai_core::{EndpointSpace, Error};
use ikigai_store::DurableStore;

use crate::config;

/// The one open, memoised for the life of the process. `None` = not configured for this
/// instance, or configured and held by somebody else. See the module note.
static STORE_SPACE: OnceLock<Option<Arc<EndpointSpace>>> = OnceLock::new();

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

/// The durable store's space, when this instance is the one that holds the dataset.
///
/// # Panics
///
/// On a misconfiguration — an unreadable `store.toml`, an unwritable dataset directory, a
/// `store` value that is neither `true` nor `false`, or scoped and unscoped switches in
/// one file. A held directory is *not* a misconfiguration and does not panic; see the
/// module note.
pub(crate) fn setup() -> Option<Arc<EndpointSpace>> {
    STORE_SPACE.get_or_init(build).clone()
}

/// Read the configuration and open, once.
fn build() -> Option<Arc<EndpointSpace>> {
    let path = path()?;
    match DurableStore::open(&path) {
        Ok(store) => Some(Arc::new(ikigai_store::space(store))),
        // The typed transient: somebody else holds the directory. One line, and the
        // binding is left out so a mount can answer for it.
        Err(e @ Error::Unavailable(_)) => {
            eprintln!("{}", refusal(&path, &e));
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

/// What an operator sees when the dataset is already held.
///
/// Three lines — the fact, the fix, and the underlying error — because the next thing
/// this operator sees is a bare "no endpoint resolved" for an IRI they just configured,
/// and a message that does not carry the whole answer leaves them where the silence did.
fn refusal(path: &Path, e: &Error) -> String {
    format!(
        "ikigai: urn:iki:store:* is NOT bound here — the durable store at {} is held by \
         another process, and RocksDB permits one writer per directory.\n  \
         fix: this is topology, not a retry. Let ONE process hold the dataset and resolve \
         through it — mount = \"prefer urn:iki:store:=<its socket>\" in {}/config.toml \
         (and urn:iki:ledger: beside it for the ledger). See docs/durable-store.md.\n  \
         underlying: {e}",
        path.display(),
        config_home_display()
    )
}

/// The config home as text, for a message that has to tell somebody which file to edit.
fn config_home_display() -> String {
    config::config_home()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/ikigai".to_string())
}

#[cfg(test)]
mod tests {
    use super::{enabled_in, refusal, truthy};
    use ikigai_core::Error;
    use std::path::Path;

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
        let text = refusal(
            Path::new("/tmp/ikigai-store"),
            &Error::Unavailable("the store at /tmp/ikigai-store is already held".into()),
        );
        assert!(text.contains("/tmp/ikigai-store"), "{text}");
        assert!(text.contains("one writer per directory"), "{text}");
        assert!(text.contains("prefer urn:iki:store:="), "{text}");
    }
}
