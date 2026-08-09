//! Browse-family wiring: `browse.*` config → roots, the persistent shared
//! store, and the explain tiers.
//!
//! Opt-in via the config home (`~/.config/ikigai/config.toml` — see
//! [`crate::config`]; no env vars):
//!
//! ```toml
//! # One line per root; the URN repo name is the directory's basename
//! # (`urn:repo:ikigai-core:tree`, …). Repeatable, like `mount`.
//! browse.root = "~/git-personal/ikigai-core"
//! browse.root = "~/git-personal/ikigai-cli"
//!
//! # Everything below is optional.
//! browse.store = "~/.ikigai/browse-store"   # persistent archive (this IS the default)
//! browse.file_model = "coder"               # explain file grain: urn:llm:{id}:ask, or a full IRI
//! browse.dir_model = "ask"                  # explain dir rollup ("ask" = urn:llm:ask)
//! browse.file_max_tokens = 400              # explain ceilings (S1 defaults shown)
//! browse.dir_max_tokens = 600
//! ```
//!
//! No `browse.root` lines ⇒ **no browse family at all** — absence, not error:
//! the module is opt-in, and an unconfigured host must not even hint at it in
//! the catalog. With roots configured, the store opens (or fails LOUD — a
//! persistent archive that silently fell back to memory would "work" while
//! quietly forgetting everything, the worst failure shape) and the host binds
//! [`ikigai_browse::space_with_explain`]: tree/file/state/hash + the
//! explanation archive + Web Annotations, all over ONE `Arc<Store>`.
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

/// Read the `browse.*` config and wire the family, or `None` when no
/// `browse.root` lines exist (browse is opt-in; absence is not an error).
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

    let store_path = config::get("browse.store")
        .map(|p| expand_home(&p))
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
            home.join(".ikigai").join("browse-store")
        });
    let store = Arc::new(Store::open(&store_path).unwrap_or_else(|e| {
        panic!(
            "ikigai: browse.store `{}` cannot open: {e} — refusing to run with an \
             in-memory archive (explanations and annotations would be silently lost). \
             Fix the path/permissions, or note that ONE process holds the store at a \
             time (a running daemon with browse configured locks it).",
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
            &config::get("browse.file_model").unwrap_or_else(|| "coder".to_string()),
        ))
        .dir_provider(provider_iri(
            &config::get("browse.dir_model").unwrap_or_else(|| "ask".to_string()),
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

/// The configured roots: one `browse.root = "<dir>"` line per root, the URN
/// name taken from the directory's basename. Missing dirs and reserved names
/// fail loud here with the config line in hand; the emptiness/`:`/`/`/duplicate
/// checks live in `ikigai_browse`'s own mount-time validation.
fn roots() -> Vec<(String, PathBuf)> {
    config::all("browse.root")
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
    config::get(key).map(|v| {
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
    use super::provider_iri;

    /// The three spellings a `browse.file_model` line can take: a backend id,
    /// the facade, and a full IRI.
    #[test]
    fn provider_ids_become_iris() {
        assert_eq!(provider_iri("coder"), "urn:llm:coder:ask");
        assert_eq!(provider_iri("ask"), "urn:llm:ask");
        assert_eq!(provider_iri("urn:llm:mlx:ask"), "urn:llm:mlx:ask");
    }
}
