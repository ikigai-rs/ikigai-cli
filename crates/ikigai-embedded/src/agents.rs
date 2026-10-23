//! Agents, the people they act for, and the file that says so: what `ikigai mcp --principal`
//! reads (ledger #1830, FND-A item 10).
//!
//! An MCP session is an AGENT acting for a person. The principal model's rule (FND-A section 2a)
//! is that **an agent's grant is a subset of its person's**, checked when grants load and
//! refused otherwise. This module is that check, over the MCP grants file (`grants.json`),
//! which gains one reserved top-level key, `principals`:
//!
//! ```json
//! {
//!   "brian":  { "scopes": ["urn:cap:ledger:read:default", "urn:cap:ledger:write:default"] },
//!   "claude": { "scopes": ["urn:cap:ledger:read:default"] },
//!   "principals": {
//!     "urn:collab:participant:brian": { "kind": "person", "grant": "brian" },
//!     "urn:collab:participant:hub": {
//!       "kind": "agent", "acts_for": "urn:collab:participant:brian", "grant": "claude"
//!     }
//!   }
//! }
//! ```
//!
//! - `kind` is `person`, `agent` or `machine`. Only an agent or a machine is served over MCP: a
//!   person's principal is never minted for a session whose caller is a program.
//! - `acts_for` names a `person` entry. Its `grant` (one name or a list) is the person's
//!   authority, and it bounds the agent's.
//! - The agent's authority is its own `grant` plus any `--grant`/`--scope` on the command line,
//!   and every scope in it must be one its person's grants list LITERALLY. Scopes are compared
//!   as strings, as `clamp` compares them: a person holding a family form (`urn:cap:fs:read:*`)
//!   does not cover an agent's narrower `urn:cap:fs:read:/x`, and the refusal names it. An
//!   exclusion (`x:-y`) only narrows, so an agent may carry one its person does not.
//! - No grant may name a principal scope (`urn:cap:principal:…`): only the door mints one.
//!
//! The refusal names every scope outside the person's grant. It never serves the intersection:
//! a grant the operator wrote that the check would silently trim is a grant nobody reviewed.
//!
//! **The file an agent session reads must be one the agent cannot write** ([`check_protected`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ikigai_core::{is_deny_scope, Capability, PRINCIPAL_SCOPE_PREFIX};
use serde_json::Value;

/// The reserved top-level key of the grants file that holds the principals table.
pub const PRINCIPALS_KEY: &str = "principals";

/// What a principal is, as the principals table types it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A person: may be acted for, is never served over MCP.
    Person,
    /// A program acting for a person.
    Agent,
    /// A host's automation, acting for its operator.
    Machine,
}

impl Kind {
    fn parse(word: &str) -> Option<Kind> {
        match word {
            "person" => Some(Kind::Person),
            "agent" => Some(Kind::Agent),
            "machine" => Some(Kind::Machine),
            _ => None,
        }
    }
}

/// One principals-table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Its kind.
    pub kind: Kind,
    /// The person it acts for (an agent's or a machine's).
    pub acts_for: Option<String>,
    /// The grant names that are its authority.
    pub grants: Vec<String>,
}

/// An agent session, checked: what `ikigai mcp --principal` serves under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSession {
    /// The agent's principal IRI, minted into [`capability`](Self::capability).
    pub principal: String,
    /// The person it acts for.
    pub person: String,
    /// Every grant name the session's authority came from (for its visibility profile).
    pub grants: Vec<String>,
    /// The session capability: the agent's scopes under its person's (exclusions included),
    /// with the agent's principal minted.
    pub capability: Capability,
}

/// The principals table of a parsed grants document.
///
/// # Errors
///
/// A malformed table or entry, named.
pub fn principals_in(doc: &Value) -> Result<BTreeMap<String, Principal>, String> {
    let Some(table) = doc.get(PRINCIPALS_KEY) else {
        return Ok(BTreeMap::new());
    };
    let table = table
        .as_object()
        .ok_or_else(|| format!("`{PRINCIPALS_KEY}` must be an object of principal IRIs"))?;
    let mut out = BTreeMap::new();
    for (iri, entry) in table {
        let kind = entry["kind"]
            .as_str()
            .and_then(Kind::parse)
            .ok_or_else(|| {
                format!("principal `{iri}` needs a `kind` of person, agent or machine")
            })?;
        let acts_for = entry["acts_for"].as_str().map(str::to_string);
        let grants = match &entry["grant"] {
            Value::String(name) => vec![name.clone()],
            Value::Array(names) => names
                .iter()
                .map(|n| {
                    n.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("principal `{iri}`: `grant` lists a non-string"))
                })
                .collect::<Result<_, _>>()?,
            Value::Null => Vec::new(),
            _ => {
                return Err(format!(
                    "principal `{iri}`: `grant` must be a name or a list"
                ))
            }
        };
        out.insert(
            iri.clone(),
            Principal {
                kind,
                acts_for,
                grants,
            },
        );
    }
    Ok(out)
}

/// The union of the named grants' scopes in `doc`, refusing any that resolves to nothing (an
/// unknown grant is undecided, never empty authority) or that names a principal scope.
fn scopes_of_grants(
    doc: &Value,
    names: &[String],
    whose: &str,
) -> Result<BTreeSet<String>, String> {
    let mut union = BTreeSet::new();
    let mut undecided = Vec::new();
    for name in names {
        let entry = if name == PRINCIPALS_KEY {
            &Value::Null
        } else {
            &doc[name.as_str()]
        };
        let scopes = crate::grant_entry_scopes(entry);
        if scopes.is_empty() {
            undecided.push(format!("`{name}`"));
        }
        union.extend(scopes);
    }
    if !undecided.is_empty() {
        return Err(format!(
            "{whose}: grant {} is unknown or grants no scopes",
            undecided.join(", ")
        ));
    }
    let principals: Vec<&String> = union
        .iter()
        .filter(|s| s.starts_with(PRINCIPAL_SCOPE_PREFIX))
        .collect();
    if !principals.is_empty() {
        return Err(format!(
            "{whose}: a grant may not name a principal scope ({}); only the door mints one",
            principals
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(union)
}

/// Check and build the session for `principal` from the grants document `text`, its own grant
/// widened by the command line's `extra_grants` and `extra_scopes`.
///
/// ```
/// use ikigai_embedded::agents::agent_session;
///
/// let grants = r#"{
///   "brian":  ["urn:cap:demo:read", "urn:cap:demo:write"],
///   "claude": ["urn:cap:demo:read"],
///   "principals": {
///     "urn:example:brian": {"kind": "person", "grant": "brian"},
///     "urn:example:hub": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "claude"}
///   }
/// }"#;
/// let session = agent_session(grants, "urn:example:hub", &[], &[]).unwrap();
/// assert_eq!(session.capability.principal(), Some("urn:example:hub"));
/// assert!(session.capability.allows("urn:cap:demo:read"));
/// assert!(!session.capability.allows("urn:cap:demo:write"));
///
/// // Outside the person's grant: refused, naming the scope.
/// let wider = agent_session(grants, "urn:example:hub", &[], &["urn:cap:other:x".into()]);
/// assert!(wider.unwrap_err().contains("`urn:cap:other:x`"));
/// ```
///
/// # Errors
///
/// Each refusal names what to fix: a document that does not parse, a principal not in the
/// table, a person (never served over MCP), an agent with no `acts_for` or acting for someone
/// who is not a person, a grant that resolves to nothing, a principal scope in a grant, a scope
/// outside the person's grant, and a principal core cannot carry.
pub fn agent_session(
    text: &str,
    principal: &str,
    extra_grants: &[String],
    extra_scopes: &[String],
) -> Result<AgentSession, String> {
    let doc: Value =
        serde_json::from_str(text).map_err(|e| format!("the grants file does not parse: {e}"))?;
    let principals = principals_in(&doc)?;
    let agent = principals.get(principal).ok_or_else(|| {
        format!("`{principal}` is not enrolled in the grants file's `{PRINCIPALS_KEY}` table")
    })?;
    if agent.kind == Kind::Person {
        return Err(format!(
            "`{principal}` is a person; an MCP session is a program acting for one, so serve \
             it as an agent whose `acts_for` names `{principal}`"
        ));
    }
    let person = agent.acts_for.as_deref().ok_or_else(|| {
        format!("`{principal}` has no `acts_for`: an agent's grant is checked against its person's")
    })?;
    match principals.get(person) {
        Some(p) if p.kind == Kind::Person => {}
        Some(_) => {
            return Err(format!(
                "`{principal}` acts for `{person}`, which is not a person"
            ))
        }
        None => {
            return Err(format!(
                "`{principal}` acts for `{person}`, who is not in the `{PRINCIPALS_KEY}` table"
            ))
        }
    }
    let person_grants = &principals[person].grants;
    let held = scopes_of_grants(&doc, person_grants, &format!("person `{person}`"))?;

    let mut grants = agent.grants.clone();
    grants.extend(extra_grants.iter().cloned());
    let mut asked = if grants.is_empty() {
        BTreeSet::new()
    } else {
        scopes_of_grants(&doc, &grants, &format!("agent `{principal}`"))?
    };
    asked.extend(extra_scopes.iter().cloned());
    if asked.is_empty() {
        return Err(format!(
            "`{principal}` holds no scopes: give its entry a `grant`, or pass --grant or --scope"
        ));
    }
    if let Some(scope) = asked.iter().find(|s| s.starts_with(PRINCIPAL_SCOPE_PREFIX)) {
        return Err(format!(
            "--scope `{scope}` names a principal; only the door mints one"
        ));
    }
    let outside: Vec<String> = asked
        .iter()
        .filter(|s| !is_deny_scope(s) && !held.contains(*s))
        .map(|s| format!("`{s}`"))
        .collect();
    if !outside.is_empty() {
        return Err(format!(
            "the authority of `{principal}` holds {} scope(s) that its person `{person}` does \
             not: {}",
            outside.len(),
            outside.join(", ")
        ));
    }
    let capability = Capability::scoped(held)
        .attenuate(asked)
        .with_principal(principal)
        .map_err(|e| format!("`{principal}` cannot be carried as a principal: {e}"))?;
    Ok(AgentSession {
        principal: principal.to_string(),
        person: person.to_string(),
        grants,
        capability,
    })
}

/// Why one path component would let `uid` replace or rewrite the file, if it would: the
/// pure rule [`check_protected`] applies to each component (the file and every directory
/// above it).
///
/// - Owned by `uid`: its owner can always change its mode, so a mode bit protects nothing.
/// - Writable by `uid` (as the operating system says): a file can be rewritten, a directory
///   can have the next component renamed away and replaced, unless the directory is STICKY
///   (`/tmp`'s mode), where only an entry's owner may rename it, and the next component's
///   owner is checked on its own.
///
/// ```
/// use ikigai_embedded::agents::replaceable_by;
///
/// // root-owned 0644 file, a 0755 root directory: protected from uid 501.
/// assert_eq!(replaceable_by(0, 501, false, false, false), None);
/// // Our own file, whatever its mode.
/// assert!(replaceable_by(501, 501, false, false, false).is_some());
/// // A directory we can write.
/// assert!(replaceable_by(0, 501, true, false, true).is_some());
/// // A sticky directory we can write (/tmp): the entry's own owner is what counts.
/// assert_eq!(replaceable_by(0, 501, true, true, true), None);
/// ```
pub fn replaceable_by(
    owner: u32,
    uid: u32,
    writable: bool,
    sticky: bool,
    is_dir: bool,
) -> Option<&'static str> {
    if owner == uid {
        return Some("it is owned by this user, who can change its mode");
    }
    if writable && !(is_dir && sticky) {
        return Some(if is_dir {
            "this user can write the directory, so can replace what is in it"
        } else {
            "this user can write it"
        });
    }
    None
}

/// Refuse a grants file that the user running this process could rewrite or replace: the
/// file itself, every directory above it, and every symbolic link on the way. An agent session
/// (`ikigai mcp --principal`) reads only a file it CANNOT write, so the agent it constrains
/// cannot widen itself, whether through a shell or through its own tools (ledger #1830;
/// threat model S19, gap 2). In practice: a file owned by root (or another account), not
/// writable by this user, in directories this user cannot write, such as
/// `/etc/ikigai/grants.json`, installed with `sudo install -o root -m 0644`.
///
/// Running as root is refused outright: root can rewrite every file, so nothing protects one.
///
/// # Errors
///
/// The path and the reason, naming the first component that fails.
#[cfg(unix)]
pub fn check_protected(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `getuid` reads a process attribute and cannot fail.
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        return Err(
            "this process runs as root, which can rewrite any grants file; run the agent \
             session as an ordinary user"
                .to_string(),
        );
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("{}: {e}", path.display()))?
            .join(path)
    };
    let refuse = |p: &Path, why: &str| {
        Err(format!(
            "{} cannot protect an agent session: {} ({why})",
            path.display(),
            p.display()
        ))
    };
    // A symbolic link this user owns can be pointed elsewhere, wherever its target lives.
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&prefix) {
            if meta.file_type().is_symlink() && meta.uid() == uid {
                return refuse(&prefix, "a symbolic link owned by this user");
            }
        }
    }
    let real = std::fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut here: Option<&Path> = Some(&real);
    while let Some(p) = here {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| format!("{}: a NUL in the path", p.display()))?;
        // SAFETY: `c` is a valid NUL-terminated path; `access` only reads it.
        let writable = unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0;
        let sticky = meta.mode() & 0o1000 != 0;
        if let Some(why) = replaceable_by(meta.uid(), uid, writable, sticky, meta.is_dir()) {
            return refuse(p, why);
        }
        here = p.parent();
    }
    Ok(())
}

/// Not Unix: there is no portable owner and mode to check, so nothing is protected.
///
/// # Errors
///
/// Always.
#[cfg(not(unix))]
pub fn check_protected(path: &Path) -> Result<(), String> {
    Err(format!(
        "{}: an agent session needs a grants file its user cannot write, and this platform \
         has no check for one",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRANTS: &str = r#"{
      "brian": ["urn:cap:demo:read", "urn:cap:demo:write", "urn:cap:demo:-secret"],
      "claude": ["urn:cap:demo:read"],
      "wide": ["urn:cap:demo:read", "urn:cap:other:x", "urn:cap:other:y"],
      "named": ["urn:cap:principal:urn:example:brian"],
      "principals": {
        "urn:example:brian": {"kind": "person", "grant": "brian"},
        "urn:example:hub": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "claude"},
        "urn:example:wide": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "wide"},
        "urn:example:named": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "named"},
        "urn:example:orphan": {"kind": "agent", "grant": "claude"},
        "urn:example:proxy": {"kind": "agent", "acts_for": "urn:example:hub", "grant": "claude"},
        "urn:example:box": {"kind": "machine", "acts_for": "urn:example:brian", "grant": ["claude"]}
      }
    }"#;

    fn refusal(principal: &str, grants: &[&str], scopes: &[&str]) -> String {
        let grants: Vec<String> = grants.iter().map(|s| s.to_string()).collect();
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        agent_session(GRANTS, principal, &grants, &scopes).unwrap_err()
    }

    #[test]
    fn an_agent_within_its_person_s_grant_is_served_named_and_keeps_the_exclusions() {
        let session = agent_session(GRANTS, "urn:example:hub", &[], &[]).unwrap();
        assert_eq!(session.person, "urn:example:brian");
        assert_eq!(session.grants, vec!["claude".to_string()]);
        let cap = &session.capability;
        assert_eq!(cap.principal(), Some("urn:example:hub"));
        assert!(cap.allows("urn:cap:demo:read"));
        assert!(!cap.allows("urn:cap:demo:write"));
        // The person's exclusion rides along: an agent cannot shed a narrowing.
        assert!(cap.scopes().unwrap().contains("urn:cap:demo:-secret"));
        // A machine acting for a person is served too, and a command-line scope inside the
        // person's grant widens within it.
        let machine = agent_session(
            GRANTS,
            "urn:example:box",
            &[],
            &["urn:cap:demo:write".into()],
        )
        .unwrap();
        assert!(machine.capability.allows("urn:cap:demo:write"));
    }

    #[test]
    fn scopes_outside_the_person_s_grant_are_refused_by_name_never_trimmed() {
        let why = refusal("urn:example:wide", &[], &[]);
        assert!(why.contains("2 scope(s)"), "{why}");
        assert!(
            why.contains("`urn:cap:other:x`") && why.contains("`urn:cap:other:y`"),
            "{why}"
        );
        let why = refusal("urn:example:hub", &["wide"], &[]);
        assert!(why.contains("`urn:cap:other:x`"), "{why}");
        let why = refusal("urn:example:hub", &[], &["urn:cap:demo:delete"]);
        assert!(why.contains("`urn:cap:demo:delete`"), "{why}");
    }

    #[test]
    fn the_wrong_kinds_and_shapes_are_refused() {
        assert!(refusal("urn:example:brian", &[], &[]).contains("is a person"));
        assert!(refusal("urn:example:nobody", &[], &[]).contains("not enrolled"));
        assert!(refusal("urn:example:orphan", &[], &[]).contains("no `acts_for`"));
        assert!(refusal("urn:example:proxy", &[], &[]).contains("not a person"));
        assert!(refusal("urn:example:named", &[], &[]).contains("may not name a principal"));
        assert!(
            refusal("urn:example:hub", &[], &["urn:cap:principal:urn:x:y"])
                .contains("names a principal")
        );
        assert!(refusal("urn:example:hub", &["missing"], &[]).contains("`missing`"));
        assert!(agent_session("{ nope", "urn:example:hub", &[], &[])
            .unwrap_err()
            .contains("does not parse"));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_this_user_owns_cannot_protect_an_agent_session() {
        // SAFETY: reads a process attribute.
        if unsafe { libc::getuid() } == 0 {
            return; // root is refused outright, which the message below would not say
        }
        let dir = std::env::temp_dir().join(format!("iki-agents-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("grants.json");
        std::fs::write(&file, "{}").unwrap();
        let why = check_protected(&file).unwrap_err();
        assert!(why.contains("owned by this user"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The accept path, on a file every Unix ships owned by root in root's directories.
    #[cfg(unix)]
    #[test]
    fn a_root_owned_file_in_root_owned_directories_protects_an_agent_session() {
        // SAFETY: reads a process attribute.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let hosts = Path::new("/etc/hosts");
        if !hosts.exists() {
            return;
        }
        assert_eq!(check_protected(hosts), Ok(()));
    }
}
