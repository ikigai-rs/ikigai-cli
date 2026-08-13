//! What file paths a *served* connection can actually address, and how a declared
//! `urn:cap:fs:<action>:<path>` scope maps into that namespace.
//!
//! A QUIC-served connection does not address the filesystem the way the local owner
//! does. Two floors sit under it, and a capability scope that ignores either one is
//! not a narrow grant — it is an inert one:
//!
//! 1. **The jail.** The served space binds the file module at
//!    [`file_root`](crate::file_root) (`$IKIGAI_FILES`, else `~/.ikigai/workspace`).
//!    `ikigai-fs` refuses absolute IRI paths outright and refuses anything resolving
//!    outside that root *regardless of capability* — a root capability cannot escape
//!    it either. So no client can ever name a file outside `file_root`.
//! 2. **The tenant rooting.** `ikigai-quic` rewrites `urn:file:x` →
//!    `urn:file:<segment>/x`, so a connection's IRIs land under
//!    `file_root/<segment>/…` and one tenant cannot name another's files.
//!
//! Together these fix the addressable universe of a connection at exactly
//! [`tenant_root`]. But `ikigai-fs` matches its path-ACL against the **resolved
//! absolute** target, which leaves two ways for an operator to write an fs scope that
//! looks like authority and grants nothing:
//!
//! - An **absolute** path outside the jail — `urn:cap:fs:read:/Users/brian/notes`,
//!   from `serve --cap` or from a per-identity grant in `clients.json`. It names a
//!   path no client can address. [`unaddressable_fs_scopes`] finds these so `serve`
//!   can refuse to start instead of running a grant that silently does nothing.
//! - A **relative** path — `urn:cap:fs:read:notes`. A relative rule never
//!   prefix-matches an absolute target, so it too matches nothing.
//!   [`root_fs_scopes`] resolves it against the connection's own [`tenant_root`] at
//!   mint time, which is the only reading under which it can mean anything: the
//!   tenant's `notes` directory, as the tenant addresses it (`urn:file:notes/…`).
//!
//! The division is deliberate. A relative path has one coherent meaning here, so it
//! is given it; an absolute path already means something specific and must not be
//! silently reinterpreted (`urn:cap:fs:read:/etc` must never quietly become the
//! tenant's own `etc`), so it is reported instead.
//!
//! The wildcard spelling `urn:cap:fs:<action>:*` is left alone by both. It is the
//! *declaration* form an action's `requires` uses — "holds some grant under this
//! prefix" — so it carries manifold visibility rather than a path, and rooting or
//! rejecting it would break the surface it selects.

use std::path::{Path, PathBuf};

use ikigai_core::Capability;

/// The absolute directory a connection's `urn:file:` IRIs resolve inside: the served
/// jail rooted at the connection's tenant segment. An empty segment (no rooting) is
/// the jail itself.
pub fn tenant_root(file_root: &Path, segment: &str) -> PathBuf {
    if segment.is_empty() {
        file_root.to_path_buf()
    } else {
        file_root.join(segment)
    }
}

/// Resolve `capability`'s **relative** fs scopes against `tenant_root`, so a scope
/// written the way the tenant addresses files means what it looks like.
///
/// Absolute scopes and the `*` wildcard pass through untouched, as does a root
/// capability (it carries no scopes to root). Deny rules (`-`) are resolved the same
/// way as allows — an exclusion that silently matched nothing would be the more
/// dangerous half of the same bug.
pub fn root_fs_scopes(capability: &Capability, tenant_root: &Path) -> Capability {
    let Some(scopes) = capability.scopes() else {
        return Capability::root();
    };
    Capability::scoped(
        scopes
            .iter()
            .map(|scope| root_fs_scope(scope, tenant_root))
            .collect::<Vec<_>>(),
    )
}

/// [`root_fs_scopes`] for one scope: unchanged unless it is an fs scope naming a
/// relative path.
fn root_fs_scope(scope: &str, tenant_root: &Path) -> String {
    let Some((action, deny, path)) = split_fs_scope(scope) else {
        return scope.to_string();
    };
    if path == "*" || Path::new(path).is_absolute() {
        return scope.to_string();
    }
    // An empty or `.` path names the tenant's whole workspace; joining either would
    // otherwise leave a trailing component that only muddies longest-prefix matching.
    let rooted = if path.is_empty() || path == "." {
        tenant_root.to_path_buf()
    } else {
        tenant_root.join(path)
    };
    let dash = if deny { "-" } else { "" };
    format!("urn:cap:fs:{action}:{dash}{}", rooted.display())
}

/// The fs scopes among `scopes` that **no** connection to this server could ever
/// exercise: an absolute path outside the jail at `file_root`.
///
/// A scope under `file_root` is addressable — `file_root` itself grants each tenant
/// its own segment, since every resolved target lands beneath it. Relative scopes are
/// never reported: [`root_fs_scopes`] gives them a reachable meaning.
pub fn unaddressable_fs_scopes(scopes: &[String], file_root: &Path) -> Vec<String> {
    scopes
        .iter()
        .filter(|scope| {
            let Some((_, _, path)) = split_fs_scope(scope) else {
                return false;
            };
            let path = Path::new(path);
            path != Path::new("*") && path.is_absolute() && !path.starts_with(file_root)
        })
        .cloned()
        .collect()
}

/// Split `urn:cap:fs:<action>:<path>` into its action, whether the rule is a deny
/// (leading `-` on the path), and the path. `None` for any other scope.
fn split_fs_scope(scope: &str) -> Option<(&str, bool, &str)> {
    let rest = scope.strip_prefix("urn:cap:fs:")?;
    let (action, path) = rest.split_once(':')?;
    // Only the actions `ikigai-fs` gates; anything else is not a path-ACL rule and
    // must not be rewritten into one.
    if !matches!(action, "read" | "write" | "delete") {
        return None;
    }
    match path.strip_prefix('-') {
        Some(path) => Some((action, true, path)),
        None => Some((action, false, path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/home/u/.ikigai/workspace";
    const SEG: &str = "0123456789abcdef";

    fn tenant() -> PathBuf {
        tenant_root(Path::new(ROOT), SEG)
    }

    fn scopes_of(capability: &Capability) -> Vec<String> {
        capability.scopes().unwrap().iter().cloned().collect()
    }

    /// The bug this module exists for: a relative scope is what an operator would
    /// write after seeing the tenant address `urn:file:notes/x`, and it must resolve
    /// to the path that IRI actually reaches.
    #[test]
    fn a_relative_scope_resolves_to_the_path_the_tenants_iri_reaches() {
        let capability = Capability::scoped(["urn:cap:fs:read:notes".to_string()]);
        assert_eq!(
            scopes_of(&root_fs_scopes(&capability, &tenant())),
            vec![format!("urn:cap:fs:read:{ROOT}/{SEG}/notes")]
        );
    }

    /// Deny rules are the more dangerous half: an operator writing an exclusion
    /// believes they have protected something, so an inert one is worse than an inert
    /// allow. It must be rooted into the same namespace as the allow it narrows.
    #[test]
    fn a_relative_deny_rule_is_rooted_like_the_allow_it_narrows() {
        let capability = Capability::scoped([
            "urn:cap:fs:read:.".to_string(),
            "urn:cap:fs:read:-secret".to_string(),
        ]);
        let mut rooted = scopes_of(&root_fs_scopes(&capability, &tenant()));
        rooted.sort();
        assert_eq!(
            rooted,
            vec![
                format!("urn:cap:fs:read:-{ROOT}/{SEG}/secret"),
                // `.` names the whole workspace, with no trailing component left to
                // skew longest-prefix matching against the deny.
                format!("urn:cap:fs:read:{ROOT}/{SEG}"),
            ]
        );
    }

    /// An absolute path already means something exact. Reinterpreting it relative to
    /// the tenant would turn `/etc` into the tenant's own `etc` — the astonishing
    /// reading. It passes through untouched (and is reported instead).
    #[test]
    fn an_absolute_scope_is_never_silently_reinterpreted() {
        let capability = Capability::scoped(["urn:cap:fs:read:/etc".to_string()]);
        assert_eq!(
            scopes_of(&root_fs_scopes(&capability, &tenant())),
            vec!["urn:cap:fs:read:/etc".to_string()]
        );
    }

    /// The wildcard is a declaration ("holds some grant under this prefix") that
    /// selects manifold visibility, not a path. Rooting it would make it match
    /// nothing it is supposed to match.
    #[test]
    fn the_wildcard_declaration_form_is_left_alone() {
        let capability = Capability::scoped(["urn:cap:fs:read:*".to_string()]);
        assert_eq!(
            scopes_of(&root_fs_scopes(&capability, &tenant())),
            vec!["urn:cap:fs:read:*".to_string()]
        );
        assert!(
            unaddressable_fs_scopes(&["urn:cap:fs:read:*".to_string()], Path::new(ROOT)).is_empty()
        );
    }

    /// Non-fs scopes are the common case in a grant (contacts, calendar) and must
    /// survive rooting untouched — as must a root capability, which has no scopes.
    #[test]
    fn non_file_scopes_and_root_pass_through() {
        let capability = Capability::scoped([
            "urn:cap:personal:contacts:read".to_string(),
            // Not a path-ACL action: `ikigai-fs` gates read/write/delete only.
            "urn:cap:fs:list:notes".to_string(),
        ]);
        let mut rooted = scopes_of(&root_fs_scopes(&capability, &tenant()));
        rooted.sort();
        assert_eq!(
            rooted,
            vec![
                "urn:cap:fs:list:notes".to_string(),
                "urn:cap:personal:contacts:read".to_string(),
            ]
        );
        assert!(root_fs_scopes(&Capability::root(), &tenant()).is_root());
    }

    /// The reported bug, as the startup check sees it: a path outside the jail names
    /// something no client can address, whether it came from `--cap` or a grant.
    #[test]
    fn an_absolute_scope_outside_the_jail_is_unaddressable() {
        let scopes = [
            "urn:cap:fs:read:/Users/brian/notes".to_string(),
            "urn:cap:fs:read:-/Users/brian/secrets".to_string(),
            "urn:cap:personal:contacts:read".to_string(),
        ];
        assert_eq!(
            unaddressable_fs_scopes(&scopes, Path::new(ROOT)),
            vec![
                "urn:cap:fs:read:/Users/brian/notes".to_string(),
                "urn:cap:fs:read:-/Users/brian/secrets".to_string(),
            ]
        );
    }

    /// The jail itself, and any subtree of it, IS addressable — every tenant's
    /// resolved target lands beneath `file_root`, so granting it is a real (if broad)
    /// grant and must not be refused.
    #[test]
    fn a_scope_inside_the_jail_is_addressable() {
        let scopes = [
            format!("urn:cap:fs:read:{ROOT}"),
            format!("urn:cap:fs:write:{ROOT}/{SEG}/notes"),
            "urn:cap:fs:read:notes".to_string(),
        ];
        assert!(unaddressable_fs_scopes(&scopes, Path::new(ROOT)).is_empty());
    }

    /// Containment is component-wise, so a sibling directory whose name merely starts
    /// with the jail's is outside it — the same rule `ikigai-fs` matches paths by.
    #[test]
    fn a_sibling_with_a_shared_name_prefix_is_outside_the_jail() {
        let scopes = [format!("urn:cap:fs:read:{ROOT}-backup")];
        assert_eq!(
            unaddressable_fs_scopes(&scopes, Path::new(ROOT)),
            vec![format!("urn:cap:fs:read:{ROOT}-backup")]
        );
    }

    // --- end to end, against the real file endpoint ---------------------------
    //
    // The rooting above is only correct if the path it computes is the SAME path
    // `ikigai-fs` resolves the tenant's IRI to. These drive the real endpoint, jailed
    // exactly as `served_space` jails it, over the IRI `ikigai-quic` would have
    // rewritten — so the two halves are checked against each other rather than each
    // against its own idea of the namespace.

    use ikigai_core::{Bindings, Endpoint, Error, Invocation, Iri, Request, Verb};

    /// What `ikigai_quic::localize` does to a client's IRI: `urn:file:<rel>` →
    /// `urn:file:<segment>/<rel>`. The endpoint sees the rewritten path.
    fn localized(segment: &str, rel: &str) -> String {
        format!("{segment}/{rel}")
    }

    /// Source `urn:file:<path>` through a real [`ikigai_fs::FileEndpoint`] jailed at
    /// `root`, under `capability` — the served configuration.
    fn source(root: &Path, path: &str, capability: &Capability) -> Result<(), Error> {
        let endpoint = ikigai_fs::FileEndpoint::new(root);
        let request = Request::new(Verb::Source, Iri::parse("urn:file:x").unwrap());
        let mut bindings = Bindings::new();
        bindings.insert("path", path);
        let invocation = Invocation::detached(&request, &bindings, capability);
        futures::executor::block_on(endpoint.invoke(&invocation)).map(|_| ())
    }

    /// A jail with one tenant's `notes/todo.txt` and a sibling `other/secret.txt`.
    fn jail() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ikigai-tenant-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        for dir in ["notes", "other"] {
            std::fs::create_dir_all(root.join(SEG).join(dir)).unwrap();
        }
        std::fs::write(root.join(SEG).join("notes/todo.txt"), b"todo").unwrap();
        std::fs::write(root.join(SEG).join("other/secret.txt"), b"secret").unwrap();
        root
    }

    /// THE BUG, end to end. A grant written as the client addresses files must
    /// actually authorize the file, and must still not reach outside what it named.
    #[test]
    fn a_rooted_relative_grant_authorizes_exactly_the_directory_it_names() {
        let root = jail();
        let granted = root_fs_scopes(
            &Capability::scoped(["urn:cap:fs:read:notes".to_string()]),
            &tenant_root(&root, SEG),
        );

        source(&root, &localized(SEG, "notes/todo.txt"), &granted)
            .expect("the grant names the directory this IRI resolves into");
        assert!(
            matches!(
                source(&root, &localized(SEG, "other/secret.txt"), &granted),
                Err(Error::Denied(_))
            ),
            "a grant for `notes` must not reach a sibling directory"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// The regression guard: UNROOTED, the same grant is the silent no-op that
    /// prompted this module — the relative rule never prefix-matches the absolute
    /// target `ikigai-fs` computes, so a scope that looks like authority denies.
    #[test]
    fn the_same_grant_unrooted_silently_authorizes_nothing() {
        let root = jail();
        let unrooted = Capability::scoped(["urn:cap:fs:read:notes".to_string()]);
        assert!(
            matches!(
                source(&root, &localized(SEG, "notes/todo.txt"), &unrooted),
                Err(Error::Denied(_))
            ),
            "an unrooted relative scope must not have started working by accident"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// The other half of the reported bug, end to end: an absolute grant outside the
    /// jail authorizes nothing, whatever the client asks for. `serve` refuses to start
    /// on one rather than run it — this is what it is refusing on behalf of.
    #[test]
    fn an_absolute_grant_outside_the_jail_authorizes_nothing() {
        let root = jail();
        let outside = Capability::scoped(["urn:cap:fs:read:/Users/brian/notes".to_string()]);
        assert!(
            matches!(
                source(&root, &localized(SEG, "notes/todo.txt"), &outside),
                Err(Error::Denied(_))
            ),
            "a path outside the jail cannot authorize anything inside it"
        );
        assert_eq!(
            unaddressable_fs_scopes(&["urn:cap:fs:read:/Users/brian/notes".to_string()], &root)
                .len(),
            1,
            "and the startup check must be what catches it"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
