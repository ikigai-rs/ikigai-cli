//! Browse-family wiring: `browse.*` config → roots, the persistent shared
//! store, and the explain tiers.
//!
//! Opt-in via the config home (`~/.config/ikigai/config.toml` — see
//! [`crate::config`]; no env vars). The RECOMMENDED grammar scopes the family
//! to ONE named instance (the topology decision of record: **the daemon
//! serves, others mount**), because the persistent store below takes an
//! exclusive lock — one process on a machine holds it, everyone else reaches
//! the family through that process's socket:
//!
//! ```toml
//! # The SERVING instance (`ikigai serve <sock>`, instance name "serve" unless
//! # --name says otherwise) is the one process that opens the store. One line
//! # per root; the URN repo name is the directory's basename
//! # (`urn:repo:ikigai-core:tree`, …). Repeatable, like `mount`.
//! serve.browse.root = "~/git-personal/ikigai-core"
//! serve.browse.root = "~/git-personal/ikigai-cli"
//!
//! # Everything below is optional; scoped spellings win, unscoped are shared.
//! serve.browse.store = "~/.ikigai/browse-store" # persistent archive (this IS the default)
//! browse.file_model = "coder"        # explain file grain: urn:llm:{id}:ask, or a full IRI
//! browse.dir_model = "ask"           # explain dir rollup ("ask" = urn:llm:ask)
//! browse.file_max_tokens = 400       # explain ceilings (S1 defaults shown)
//! browse.dir_max_tokens = 600
//!
//! # Every OTHER process on the machine mounts the family from the server.
//! # Two lines because the family spans two URN prefixes (`urn:repo:…` and
//! # `urn:iki:annotation:…`). `prefer` = through the server when it is up, quiet
//! # absence when it is down. The serving instance skips a mount that targets
//! # its own socket (see `serve_ipc` in the CLI), so these lines are safe in
//! # the one shared config file.
//! #
//! # ⚠ Note the MISSING trailing colon on the annotation line, and keep it: a
//! # mount prefix is matched with `starts_with`, and the family's resolvable
//! # BARE root `urn:iki:annotation` (Sink mints an id) is the only write path
//! # it has. `urn:iki:annotation:=` would route every read and no mint.
//! #
//! # ⚠ Write the mount in the CANONICAL spelling. This host aliases
//! # `urn:annotation` → `urn:iki:annotation` (`ikigai_embedded::alias_table`),
//! # and the alias wraps the ROOT while mounts sit inside it — so a mount
//! # matches the name AFTER the rewrite. An old-spelling mount line never
//! # matches again.
//! mount = "prefer urn:repo:=/path/to/serve.sock"
//! mount = "prefer urn:iki:annotation=/path/to/serve.sock"
//! ```
//!
//! Unscoped `browse.root` lines keep working for SINGLE-PROCESS setups (every
//! kernel-building process wires the family — fine when only one runs at a
//! time). Mixing the spellings is refused loud: one scoped line plus one
//! unscoped line would put two processes on the one store lock, which is
//! exactly the collision scoping exists to prevent.
//!
//! No `browse.root` lines for this instance ⇒ **no browse family at all** —
//! absence, not error: the module is opt-in, and an unconfigured host must not
//! even hint at it in the catalog. With roots configured, the store opens (or
//! fails LOUD — a persistent archive that silently fell back to memory would
//! "work" while quietly forgetting everything, the worst failure shape) and
//! the host binds [`ikigai_browse::space_with_explain`]: tree/file/state/hash
//! + the explanation archive + Web Annotations, all over ONE `Arc<Store>`.
//!
//! That same handle is what [`super::root_space_with_mounts`] gives
//! `ikigai_sparql::space_with_store`, so `urn:sparql:select` queries the
//! explanations and annotations live — the shared-graph thesis at host level.
//!
//! Persistence itself is switched on HERE: `ikigai-browse` and `ikigai-sparql`
//! both keep `oxigraph` at `default-features = false` (wasm-clean, no storage
//! engine), and this crate's `oxigraph`/`rocksdb` dependency feature-unifies
//! `Store::open` onto the one shared `Store` type they all use.

use std::path::PathBuf;
use std::sync::Arc;

use ikigai_core::EndpointSpace;
use ikigai_sparql::Store;

use crate::config;

/// Root names the browse grammar must not claim: `ikigai-repo` binds
/// `urn:repo:status` / `:log` / `:branch` / `:list` / `:pr:*` as Exacts, and a
/// root of the same name would put browse resources (`urn:repo:status:tree`)
/// in the same URN segment — two families interleaved under one name, with
/// which-one-wins decided by space order. Refused at startup instead.
const RESERVED_ROOTS: [&str; 5] = ["status", "log", "branch", "list", "pr"];

/// The wired browse family: the space to mount plus the persistent store
/// handle the host shares onward (sparql; anything else that joins the graph).
pub(crate) struct Browse {
    pub(crate) space: EndpointSpace,
    pub(crate) store: Arc<Store>,
}

/// Read the `browse.*` config and wire the family, or `None` when no root
/// lines apply to THIS instance (browse is opt-in; absence is not an error —
/// and under the scoped grammar, absence is precisely what every non-serving
/// process is configured for).
///
/// # Panics
///
/// Fails loud on a misconfiguration — a root that doesn't exist or isn't a
/// directory, a reserved root name, a store path that cannot open, a
/// non-numeric token ceiling. A host that starts anyway would either lie
/// (resolving against nothing) or silently forget (an in-memory "archive").
pub(crate) fn setup() -> Option<Browse> {
    let roots = roots();
    if roots.is_empty() {
        return None;
    }

    let store_path = scoped("browse.store")
        .map(|p| expand_home(&p))
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
            home.join(".ikigai").join("browse-store")
        });
    let store = Arc::new(Store::open(&store_path).unwrap_or_else(|e| {
        panic!(
            "ikigai: browse.store `{}` cannot open: {e} — refusing to run with an \
             in-memory archive (explanations and annotations would be silently lost). \
             ONE process holds the store at a time; if another ikigai holds this lock, \
             the fix is topology, not retry: scope the family to the SERVING instance \
             (`serve.browse.root = …`) and point this process at it instead — \
             mount = \"prefer urn:repo:=<serve socket>\" and \
             mount = \"prefer urn:iki:annotation=<serve socket>\" in the config home. \
             Otherwise fix the path/permissions.",
            store_path.display()
        )
    }));
    // Schema joins over the shared graph (`?e a/rdfs:subClassOf* ik:Endpoint`):
    // the shared store gets NOTHING automatically, so load the bundled ikigai
    // vocabulary the way space()'s private per-query store always has it.
    // Idempotent — same triples into the same named graph on every start.
    ikigai_sparql::load_vocabulary(&store)
        .unwrap_or_else(|e| panic!("ikigai: loading the vocabulary into browse.store: {e:?}"));

    let mut explain = ikigai_browse::ExplainConfig::new(Arc::clone(&store))
        .file_provider(provider_iri(
            &scoped("browse.file_model").unwrap_or_else(|| "coder".to_string()),
        ))
        .dir_provider(provider_iri(
            &scoped("browse.dir_model").unwrap_or_else(|| "ask".to_string()),
        ));
    if let Some(tokens) = ceiling("browse.file_max_tokens") {
        explain = explain.file_max_tokens(tokens);
    }
    if let Some(tokens) = ceiling("browse.dir_max_tokens") {
        explain = explain.dir_max_tokens(tokens);
    }

    Some(Browse {
        space: ikigai_browse::space_with_explain(roots, explain),
        store,
    })
}

/// The configured roots: one root line per `browse.root` (or scoped
/// `<instance>.browse.root`) config line, the URN name taken from the
/// directory's basename. Missing dirs and reserved names fail loud here with
/// the config line in hand; the emptiness/`:`/`/`/duplicate checks live in
/// `ikigai_browse`'s own mount-time validation.
fn roots() -> Vec<(String, PathBuf)> {
    root_lines(
        config::all(&format!("{}.browse.root", crate::instance_name())),
        config::all("browse.root"),
        &config::scoping_instances("browse.root"),
    )
    .into_iter()
    .map(|line| {
        let dir = expand_home(&line);
        assert!(
            dir.is_dir(),
            "ikigai: browse.root `{line}` is not a directory — fix the config \
                 (a root that resolves against nothing would answer every request \
                 with an error)"
        );
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(
            !RESERVED_ROOTS.contains(&name.as_str()),
            "ikigai: browse.root `{line}`: the name `{name}` is reserved — \
                 ikigai-repo binds urn:repo:{name} — rename the directory or \
                 browse it under a symlinked name"
        );
        (name, dir)
    })
    .collect()
}

/// Which `browse.root` spelling governs this instance: scoped lines when ANY
/// instance scopes the key (and then unscoped lines are refused loud — a
/// scoped line for instance A plus an unscoped line that instance B still
/// honoured would put two processes on the one store lock), unscoped lines
/// otherwise (the single-process setup, unchanged).
fn root_lines(scoped: Vec<String>, unscoped: Vec<String>, scoping: &[String]) -> Vec<String> {
    if scoping.is_empty() {
        return unscoped;
    }
    assert!(
        unscoped.is_empty(),
        "ikigai: browse.root is scoped to {} but the config also has unscoped \
         `browse.root` lines — every process honours an unscoped line, so this would \
         put a second process on the store's exclusive lock. Scope ALL of them \
         (`<instance>.browse.root`), designate ONE serving instance, and point every \
         other process at it: mount = \"prefer urn:repo:=<serve socket>\" + \
         mount = \"prefer urn:iki:annotation=<serve socket>\".",
        scoping
            .iter()
            .map(|i| format!("`{i}.browse.root`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    scoped
}

/// A browse setting, instance-scoped spelling first (`<instance>.browse.store`
/// wins over `browse.store`). Tunings — the store path, models, ceilings — may
/// be shared unscoped: they only take effect in a process that has roots, so
/// they cannot drag a second process onto the store lock the way a root line
/// can.
fn scoped(key: &str) -> Option<String> {
    config::get(&format!("{}.{key}", crate::instance_name())).or_else(|| config::get(key))
}

/// A provider id from config as an IRI: a full `urn:` IRI passes through,
/// `ask` names the facade (`urn:llm:ask`), and any other id is an
/// `urn:llm:{id}:ask` backend (`coder`, `mlx`, `big`, …).
fn provider_iri(value: &str) -> String {
    if value.starts_with("urn:") {
        value.to_string()
    } else if value == "ask" {
        "urn:llm:ask".to_string()
    } else {
        format!("urn:llm:{value}:ask")
    }
}

/// A configured token ceiling, or `None` when unset. Set-but-garbage fails
/// loud: a typo that silently fell back to the default would look configured.
fn ceiling(key: &str) -> Option<u32> {
    scoped(key).map(|v| {
        v.parse()
            .unwrap_or_else(|_| panic!("ikigai: {key} `{v}` is not a number — fix the config"))
    })
}

/// `~/`-expansion for config paths, matching the org-config convention.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::{provider_iri, root_lines};

    /// The three spellings a `browse.file_model` line can take: a backend id,
    /// the facade, and a full IRI.
    #[test]
    fn provider_ids_become_iris() {
        assert_eq!(provider_iri("coder"), "urn:llm:coder:ask");
        assert_eq!(provider_iri("ask"), "urn:llm:ask");
        assert_eq!(provider_iri("urn:llm:mlx:ask"), "urn:llm:mlx:ask");
    }

    /// Nobody scopes `browse.root` ⇒ the unscoped lines govern, unchanged —
    /// the single-process setup keeps working.
    #[test]
    fn unscoped_roots_govern_when_nobody_scopes() {
        assert_eq!(
            root_lines(vec![], vec!["~/a".into(), "~/b".into()], &[]),
            vec!["~/a".to_string(), "~/b".to_string()]
        );
    }

    /// Someone scopes ⇒ only THIS instance's scoped lines govern. Another
    /// instance's scoped lines are simply not ours — this process gets no
    /// browse family, which is the (b) topology working: it mounts instead.
    #[test]
    fn scoped_roots_govern_only_their_instance() {
        let scoping = ["serve".to_string()];
        // This process IS the scoped instance.
        assert_eq!(
            root_lines(vec!["~/a".into()], vec![], &scoping),
            vec!["~/a".to_string()]
        );
        // This process is some other instance: no roots, no store, no lock.
        assert!(root_lines(vec![], vec![], &scoping).is_empty());
    }

    /// One scoped line plus one unscoped line would put two processes on the
    /// store's exclusive lock — refused loud, not merged.
    #[test]
    #[should_panic(expected = "unscoped")]
    fn mixing_scoped_and_unscoped_roots_is_refused() {
        root_lines(
            vec!["~/a".into()],
            vec!["~/b".into()],
            &["serve".to_string()],
        );
    }
}
