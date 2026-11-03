//! Account-to-admission policy shared by Unix socket hosts.
//!
//! Call [`shared_socket`] before binding. For a shared door, pass its `gid` to
//! `ikigai_ipc::bind_shared` and its `admissions` to
//! `ikigai_ipc::serve_shared_on_admissions`. Refuse startup on any policy error.

/// The other accounts a socket door admits (ledger #2139): the principals table's `uid`/`user`
/// entries ([`crate::agents::socket_peers`]), each a bounded, named admission, and
/// the group the socket is shared with (`ipc.group` in the config home's `config.toml`).
pub struct SharedSocket {
    /// Kernel-verified UID admissions, including the owner.
    pub admissions: ikigai_ipc::Admissions,
    /// Group that may reach the shared socket.
    pub gid: u32,
    /// One line per admitted account: `uid 502 as urn:…`.
    pub accounts: Vec<String>,
}

/// Read [`SharedSocket`] from the grants file, or `None` when no principal names an account
/// (or there is no grants file): the door then admits only its own user, as before.
///
/// # Errors
///
/// Every reason the table cannot be honored, named: a grants file that does not parse or fails
/// a session check, an account that does not exist or is this user, a grants file the account
/// could write, and a missing or unknown `ipc.group`.
pub fn shared_socket() -> Result<Option<SharedSocket>, String> {
    let Some(path) = crate::grants_path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let peers =
        crate::agents::socket_peers(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    shared_socket_from(&path, peers, crate::config::get("ipc.group"))
}

/// [`shared_socket`] over the parsed accounts and the configured group, so the policy is
/// testable without a config home. An empty account list means owner-only.
///
/// # Errors
///
/// Returns the same account, protection, duplicate UID and group errors as [`shared_socket`].
pub fn shared_socket_from(
    path: &std::path::Path,
    peers: Vec<crate::agents::SocketPeer>,
    group: Option<String>,
) -> Result<Option<SharedSocket>, String> {
    use crate::agents::Account;
    if peers.is_empty() {
        return Ok(None);
    }
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    let me = unsafe { libc::getuid() };
    let group = group
        .map(|g| g.trim().trim_matches('"').to_string())
        .ok_or_else(|| {
            format!(
                "{} admits other accounts to the socket, so it needs a group to share the socket \
             with: set `ipc.group = \"<group>\"` in {}, a group those accounts are in",
                path.display(),
                crate::config::config_path().display()
            )
        })?;
    let gid = match group.parse::<u32>() {
        Ok(gid) => gid,
        Err(_) => ikigai_ipc::gid_of_group(&group).map_err(|e| format!("ipc.group: {e}"))?,
    };
    let mut admissions = ikigai_ipc::Admissions::owner_only();
    let mut accounts = Vec::new();
    for peer in peers {
        let uid = match &peer.account {
            Account::Uid(uid) => *uid,
            Account::User(name) => ikigai_ipc::uid_of_user(name)
                .map_err(|e| format!("the account of `{}`: {e}", peer.session.principal))?,
        };
        if uid == me {
            return Err(format!(
                "the account of `{}` is this user (uid {uid}): a same-uid client is the owner \
                 to the operating system and cannot be bounded; run it as another account",
                peer.session.principal
            ));
        }
        crate::agents::check_protected_from(path, uid)?;
        let ceiling = ikigai_resolve::without_principals(&peer.session.capability);
        let admission =
            ikigai_ipc::Admission::bounded(ceiling, Some(peer.session.principal.clone()))
                .map_err(|e| format!("`{}`: {e}", peer.session.principal))?;
        if admissions
            .admit(me, Some(uid))
            .is_ok_and(|a| a.principal().is_some())
        {
            return Err(format!(
                "uid {uid} is named by two principals; an account is one principal"
            ));
        }
        admissions = admissions.with_uid(uid, admission);
        accounts.push(format!("uid {uid} as {}", peer.session.principal));
    }
    Ok(Some(SharedSocket {
        admissions,
        gid,
        accounts,
    }))
}

/// The socket door's reading of the principals table's accounts (ledger #2139).
#[cfg(test)]
mod shared_socket_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me() -> u32 {
        // SAFETY: `getuid` reads a process attribute and cannot fail.
        unsafe { libc::getuid() }
    }

    /// A grants file only its owner (this user) can write, holding `account` on a machine
    /// principal, and the parsed accounts.
    fn grants(name: &str, account: &str) -> (std::path::PathBuf, Vec<crate::agents::SocketPeer>) {
        let dir = std::env::temp_dir().join(format!("ikss-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("grants.json");
        let text = format!(
            r#"{{
              "brian": ["urn:cap:demo:read", "urn:cap:demo:write"],
              "node": ["urn:cap:demo:read"],
              "principals": {{
                "urn:example:brian": {{"kind": "person", "grant": "brian"}},
                "urn:example:node": {{
                  "kind": "machine", "acts_for": "urn:example:brian", "grant": "node", {account}
                }}
              }}
            }}"#
        );
        std::fs::write(&path, &text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let peers = crate::agents::socket_peers(&text).unwrap();
        (path, peers)
    }

    fn own_gid(path: &std::path::Path) -> String {
        std::fs::metadata(path).unwrap().gid().to_string()
    }

    #[test]
    fn no_accounts_needs_no_group() {
        assert!(
            shared_socket_from(std::path::Path::new("unused"), vec![], None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn duplicate_accounts_and_writable_grants_are_refused() {
        let other = me().wrapping_add(1);
        let (path, mut peers) = grants("duplicate", &format!(r#""uid": {other}"#));
        let mut duplicate =
            crate::agents::socket_peers(&std::fs::read_to_string(&path).unwrap()).unwrap();
        duplicate[0].session.principal = "urn:example:second".to_string();
        peers.extend(duplicate);
        let refused = shared_socket_from(&path, peers, Some(own_gid(&path)))
            .err()
            .unwrap();
        assert!(refused.contains("two principals"), "{refused}");
        let peers = crate::agents::socket_peers(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(shared_socket_from(&path, peers, Some(own_gid(&path))).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn another_account_is_admitted_bounded_and_named_and_nobody_else() {
        let other = me().wrapping_add(1);
        let (path, peers) = grants("ok", &format!(r#""uid": {other}"#));
        let shared = shared_socket_from(&path, peers, Some(own_gid(&path)))
            .unwrap()
            .expect("an account is named");
        assert_eq!(
            shared.accounts,
            [format!("uid {other} as urn:example:node")]
        );
        let node = shared.admissions.admit(me(), Some(other)).unwrap();
        assert_eq!(node.principal(), Some("urn:example:node"));
        assert!(!node.ceiling().allows("urn:cap:demo:write"));
        assert!(shared
            .admissions
            .admit(me(), Some(me()))
            .unwrap()
            .ceiling()
            .is_root());
        assert!(shared
            .admissions
            .admit(me(), Some(other.wrapping_add(1)))
            .is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_door_s_own_user_cannot_be_bounded_as_an_account() {
        let (path, peers) = grants("self", &format!(r#""uid": {}"#, me()));
        let refused = shared_socket_from(&path, peers, Some(own_gid(&path)))
            .err()
            .unwrap();
        assert!(
            refused.contains("same-uid client is the owner"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_account_with_no_socket_group_or_no_such_user_stops_the_door() {
        let (path, peers) = grants("nogroup", &format!(r#""uid": {}"#, me().wrapping_add(1)));
        let refused = shared_socket_from(&path, peers, None).err().unwrap();
        assert!(refused.contains("ipc.group"), "{refused}");
        let (path2, peers) = grants("nouser", r#""user": "no-such-ikigai-account-2139""#);
        let refused = shared_socket_from(&path2, peers, Some(own_gid(&path2)))
            .err()
            .unwrap();
        assert!(refused.contains("no user named"), "{refused}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(path2.parent().unwrap());
    }
}
