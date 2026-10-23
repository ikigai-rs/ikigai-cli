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
//!
//! **A principal may also name the local ACCOUNT it runs as** (ledger #2139), with `"uid": 502`
//! or `"user": "gonknode"` (one of them, never both). The socket door then admits a peer of
//! that UID bounded by the same checked session ([`socket_peers`]), so a node run as another
//! account on the same machine is held to its grant. The file must be one that ACCOUNT cannot
//! write ([`check_protected_from`]).

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

/// The local account a principals-table entry runs as, by its `uid` or `user` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Account {
    /// A numeric user id.
    Uid(u32),
    /// A user name, looked up in the system's user database by the door.
    User(String),
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Account::Uid(uid) => write!(f, "uid {uid}"),
            Account::User(name) => write!(f, "user `{name}`"),
        }
    }
}

/// One account the socket door admits, and the checked session it is admitted under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketPeer {
    /// The account, as the entry names it.
    pub account: Account,
    /// The session: the entry's grant checked against its person's, its principal minted.
    pub session: AgentSession,
}

/// Every principal in the grants document `text` that names a local account (`uid` or
/// `user`), each checked exactly as [`agent_session`] checks an MCP agent: an agent or a
/// machine acting for a person, its grant within the person's. The socket door's per-UID
/// admission (ledger #2139) reads this.
///
/// ```
/// use ikigai_embedded::agents::{socket_peers, Account};
///
/// let grants = r#"{
///   "brian": ["urn:cap:demo:read", "urn:cap:demo:write"],
///   "node":  ["urn:cap:demo:read"],
///   "principals": {
///     "urn:example:brian": {"kind": "person", "grant": "brian"},
///     "urn:example:node": {
///       "kind": "machine", "acts_for": "urn:example:brian", "grant": "node", "uid": 502
///     }
///   }
/// }"#;
/// let peers = socket_peers(grants).unwrap();
/// assert_eq!(peers.len(), 1);
/// assert_eq!(peers[0].account, Account::Uid(502));
/// assert_eq!(peers[0].session.capability.principal(), Some("urn:example:node"));
/// assert!(!peers[0].session.capability.allows("urn:cap:demo:write"));
/// ```
///
/// # Errors
///
/// A document that does not parse, an entry with both `uid` and `user` or a malformed one,
/// two entries naming the same account, and every refusal of [`agent_session`] (a person
/// cannot be admitted as an account: only a program runs as one), each naming the entry.
pub fn socket_peers(text: &str) -> Result<Vec<SocketPeer>, String> {
    let doc: Value =
        serde_json::from_str(text).map_err(|e| format!("the grants file does not parse: {e}"))?;
    let Some(table) = doc.get(PRINCIPALS_KEY).and_then(Value::as_object) else {
        // A malformed table is `principals_in`'s refusal, and absent means no accounts.
        principals_in(&doc)?;
        return Ok(Vec::new());
    };
    let mut peers: Vec<SocketPeer> = Vec::new();
    for (iri, entry) in table {
        let account = match (entry.get("uid"), entry.get("user")) {
            (None, None) => continue,
            (Some(_), Some(_)) => {
                return Err(format!(
                    "principal `{iri}` names both `uid` and `user`; name its account once"
                ))
            }
            (Some(uid), None) => Account::Uid(
                uid.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| format!("principal `{iri}`: `uid` must be a user id number"))?,
            ),
            (None, Some(user)) => Account::User(
                user.as_str()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| format!("principal `{iri}`: `user` must be a user name"))?
                    .to_string(),
            ),
        };
        if let Some(twin) = peers.iter().find(|p| p.account == account) {
            return Err(format!(
                "principals `{}` and `{iri}` both name {account}; an account is one principal",
                twin.session.principal
            ));
        }
        let session = agent_session(text, iri, &[], &[])
            .map_err(|e| format!("the account of `{iri}` ({account}): {e}"))?;
        peers.push(SocketPeer { account, session });
    }
    Ok(peers)
}

/// Why one path component, owned by `owner` with mode `mode`, would let ANOTHER account, `uid`,
/// replace or rewrite the file, if it would: [`check_protected_from`]'s rule. The account's
/// group memberships are not looked up, so any group-writable component is refused.
///
/// ```
/// use ikigai_embedded::agents::replaceable_by_account;
///
/// // The owner's 0644 file in its 0755 directory: protected from uid 502.
/// assert_eq!(replaceable_by_account(501, 0o100644, 502, false), None);
/// assert!(replaceable_by_account(502, 0o100644, 502, false).is_some());
/// assert!(replaceable_by_account(501, 0o100664, 502, false).is_some());
/// assert!(replaceable_by_account(501, 0o40777, 502, true).is_some());
/// // A sticky directory every user can write (/tmp): the entry's own owner is what counts.
/// assert_eq!(replaceable_by_account(0, 0o41777, 502, true), None);
/// ```
pub fn replaceable_by_account(
    owner: u32,
    mode: u32,
    uid: u32,
    is_dir: bool,
) -> Option<&'static str> {
    let writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if owner == uid {
        return Some("it is owned by that account, which can change its mode");
    }
    if writable && !(is_dir && sticky) {
        return Some(if is_dir {
            "its group or every user can write the directory, so can replace what is in it"
        } else {
            "its group or every user can write it"
        });
    }
    None
}

/// Refuse a grants file that the account `uid` could rewrite or replace: the file, every
/// directory above it and every symbolic link on the way, by owner and mode
/// ([`replaceable_by_account`]). What the socket door checks for each account it admits
/// (ledger #2139), so a node bounded by the file cannot widen itself in it. The door's own
/// user may write the file: that user is already the owner. Root (`uid` 0) is refused, since
/// it can rewrite every file.
///
/// # Errors
///
/// The path and the reason, naming the first component that fails.
#[cfg(unix)]
pub fn check_protected_from(path: &Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if uid == 0 {
        return Err(
            "root can rewrite any grants file, so it cannot be admitted as a bounded account"
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
            "{} cannot bound uid {uid}: {} ({why})",
            path.display(),
            p.display()
        ))
    };
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&prefix) {
            if meta.file_type().is_symlink() && meta.uid() == uid {
                return refuse(&prefix, "a symbolic link owned by that account");
            }
        }
    }
    let real = std::fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut here: Option<&Path> = Some(&real);
    while let Some(p) = here {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(why) = replaceable_by_account(meta.uid(), meta.mode(), uid, meta.is_dir()) {
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
pub fn check_protected_from(path: &Path, _uid: u32) -> Result<(), String> {
    Err(format!(
        "{}: a bounded account needs a grants file it cannot write, and this platform has no \
         check for one",
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

    fn with_accounts(accounts: &str) -> String {
        format!(
            r#"{{
              "brian": ["urn:cap:demo:read", "urn:cap:demo:write"],
              "node": ["urn:cap:demo:read"],
              "wide": ["urn:cap:other:x"],
              "principals": {{
                "urn:example:brian": {{"kind": "person", "grant": "brian"}},
                {accounts}
              }}
            }}"#
        )
    }

    #[test]
    fn an_account_is_admitted_under_its_checked_session() {
        let text = with_accounts(
            r#""urn:example:a": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node", "uid": 502},
               "urn:example:b": {"kind": "machine", "acts_for": "urn:example:brian", "grant": "node", "user": "nodeacct"},
               "urn:example:c": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node"}"#,
        );
        let peers = socket_peers(&text).unwrap();
        let accounts: Vec<&Account> = peers.iter().map(|p| &p.account).collect();
        assert_eq!(
            accounts,
            [&Account::Uid(502), &Account::User("nodeacct".into())]
        );
        assert_eq!(
            peers[1].session.capability.principal(),
            Some("urn:example:b")
        );
    }

    #[test]
    fn a_bad_account_entry_is_refused_naming_it() {
        let refuse = |accounts: &str| socket_peers(&with_accounts(accounts)).unwrap_err();
        let both = refuse(
            r#""urn:example:a": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node", "uid": 502, "user": "x"}"#,
        );
        assert!(both.contains("both `uid` and `user`"), "{both}");
        let twice = refuse(
            r#""urn:example:a": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node", "uid": 502},
               "urn:example:b": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node", "uid": 502}"#,
        );
        assert!(twice.contains("both name uid 502"), "{twice}");
        let person = refuse(r#""urn:example:p": {"kind": "person", "grant": "node", "uid": 503}"#);
        assert!(person.contains("is a person"), "{person}");
        let wider = refuse(
            r#""urn:example:a": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "wide", "uid": 502}"#,
        );
        assert!(wider.contains("`urn:cap:other:x`"), "{wider}");
        let negative = refuse(
            r#""urn:example:a": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "node", "uid": -1}"#,
        );
        assert!(negative.contains("user id number"), "{negative}");
    }

    #[cfg(unix)]
    #[test]
    fn a_grants_file_another_account_can_write_does_not_bound_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ikg-protect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("grants.json");
        std::fs::write(&file, "{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: `getuid` reads a process attribute and cannot fail.
        let me = unsafe { libc::getuid() };
        let other = me.wrapping_add(1);
        // The temp dir's ancestors may be writable by others only when sticky (/tmp), which
        // is allowed; macOS's per-user temp dir is ours. Either way, our own file passes.
        let ok = check_protected_from(&file, other);
        assert!(ok.is_ok(), "{ok:?}");
        let owned = check_protected_from(&file, me).unwrap_err();
        assert!(owned.contains("owned by that account"), "{owned}");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let open = check_protected_from(&file, other).unwrap_err();
        assert!(open.contains("can write it"), "{open}");
        assert!(check_protected_from(&file, 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
