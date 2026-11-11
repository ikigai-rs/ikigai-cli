//! The owner-and-mode check a door runs over the files it takes its authority from, before
//! it opens: private keys, trusted certificates and the directory that holds them,
//! `clients.json` and `grants.json`.
//!
//! The rule is the one [`crate::agents::check_protected`] and the passkey store apply, from
//! the door's side: every file and every directory above it must be owned by this process's
//! user or by root, and no group or other account may write it (a sticky directory such as
//! `/tmp` is fine: only an entry's owner can replace it). A private key must also not be
//! readable by any other account. A read-only group or world read of a certificate, of
//! `clients.json` or of a directory is fine. Each refusal names the path and the command that
//! fixes it.

use std::path::{Path, PathBuf};

/// What a path holds, which decides how much of its mode may be open to other accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A private key: no other account may read or write it.
    PrivateKey,
    /// A certificate, a trust directory or a configuration file: no other account may
    /// write it. Reading is fine.
    Public,
}

/// Why a path owned by `owner` with mode `mode` is not safe for the process running as `me`
/// to take authority from, if it is not: [`check`]'s rule, pure so every branch is testable.
///
/// ```
/// use ikigai_embedded::authority::{exposure, Kind};
///
/// // The user's own 0600 key and 0644 certificate in a 0700 directory: fine.
/// assert_eq!(exposure(501, 0o100600, 501, false, Kind::PrivateKey), None);
/// assert_eq!(exposure(501, 0o100644, 501, false, Kind::Public), None);
/// assert_eq!(exposure(501, 0o40700, 501, true, Kind::Public), None);
/// // Root-owned, read-only for the service: fine.
/// assert_eq!(exposure(0, 0o100644, 501, false, Kind::Public), None);
/// // A key others can read, a file its group can write, another account's file: refused.
/// assert!(exposure(501, 0o100640, 501, false, Kind::PrivateKey).is_some());
/// assert!(exposure(501, 0o100664, 501, false, Kind::Public).is_some());
/// assert!(exposure(502, 0o100644, 501, false, Kind::Public).is_some());
/// // A sticky directory every user can write (/tmp): fine.
/// assert_eq!(exposure(0, 0o41777, 501, true, Kind::Public), None);
/// ```
pub fn exposure(owner: u32, mode: u32, me: u32, is_dir: bool, kind: Kind) -> Option<String> {
    if owner != me && owner != 0 {
        return Some(format!(
            "is owned by uid {owner}, not by this process's uid {me} or root"
        ));
    }
    let sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !(is_dir && sticky) {
        return Some(format!(
            "is writable by its group or by everyone (mode {:04o})",
            mode & 0o7777
        ));
    }
    if kind == Kind::PrivateKey && !is_dir && mode & 0o044 != 0 {
        return Some(format!(
            "is a private key readable by its group or by everyone (mode {:04o})",
            mode & 0o7777
        ));
    }
    None
}

/// The command that fixes a path [`exposure`] refused.
fn remedy(path: &Path, owner: u32, me: u32, is_dir: bool, kind: Kind) -> String {
    let p = path.display();
    let chmod = if kind == Kind::PrivateKey && !is_dir {
        format!("`chmod 600 {p}`")
    } else {
        format!("`chmod go-w {p}`")
    };
    if owner != me && owner != 0 {
        format!("`chown {me} {p}` (as root), then {chmod}")
    } else {
        chmod
    }
}

/// Check every path in `paths`, each file or directory and every directory above it (both as
/// written and with symbolic links resolved), by [`exposure`]. A path that does not exist is
/// skipped: whoever reads it reports that.
///
/// # Errors
///
/// The first path that fails, why, and the command that fixes it.
#[cfg(unix)]
pub fn check(paths: &[(PathBuf, Kind)]) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot fail.
    let me = unsafe { libc::geteuid() };
    for (path, kind) in paths {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("{}: {e}", path.display()))?
                .join(path)
        };
        let Ok(real) = std::fs::canonicalize(&absolute) else {
            continue;
        };
        for chain in [&absolute, &real] {
            let mut here: Option<&Path> = Some(chain);
            let mut first = true;
            while let Some(p) = here {
                // The path itself is judged as its kind; the directories above it hold it.
                let kind = if first { *kind } else { Kind::Public };
                first = false;
                here = p.parent();
                let Ok(meta) = std::fs::metadata(p) else {
                    continue;
                };
                let is_dir = meta.is_dir();
                if let Some(why) = exposure(meta.uid(), meta.mode(), me, is_dir, kind) {
                    let fix = remedy(p, meta.uid(), me, is_dir, kind);
                    let shown = if p == path.as_path() || p == absolute || p == real {
                        String::new()
                    } else {
                        format!(", which holds {}", path.display())
                    };
                    return Err(format!(
                        "{}{shown} {why}, so this door will not take its authority from it; \
                         check that it is yours, then fix it with {fix}",
                        p.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Not Unix: there are no portable owner and mode bits, so the platform's ACLs govern.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
pub fn check(_paths: &[(PathBuf, Kind)]) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ikigai-authority-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn safe_modes_pass_and_a_readable_certificate_is_fine() {
        let dir = scratch("safe");
        let key = dir.join("server.key");
        let crt = dir.join("server.crt");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(&crt, "c").unwrap();
        chmod(&key, 0o600);
        chmod(&crt, 0o644);
        let paths = [
            (key, Kind::PrivateKey),
            (crt, Kind::Public),
            (dir.clone(), Kind::Public),
        ];
        assert_eq!(check(&paths), Ok(()));
        chmod(&dir, 0o755);
        assert_eq!(check(&paths), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loosened_mode_is_refused_naming_the_chmod() {
        let dir = scratch("loose");
        let key = dir.join("server.key");
        let crt = dir.join("client.crt");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(&crt, "c").unwrap();
        chmod(&key, 0o644);
        chmod(&crt, 0o644);
        let err = check(&[(key.clone(), Kind::PrivateKey)]).unwrap_err();
        assert!(
            err.contains(&format!("`chmod 600 {}`", key.display())),
            "{err}"
        );

        chmod(&key, 0o600);
        chmod(&crt, 0o666);
        let err = check(&[(crt.clone(), Kind::Public)]).unwrap_err();
        assert!(
            err.contains(&format!("`chmod go-w {}`", crt.display())),
            "{err}"
        );

        chmod(&crt, 0o644);
        chmod(&dir, 0o777);
        let err = check(&[(crt.clone(), Kind::Public)]).unwrap_err();
        assert!(
            err.contains(&format!("`chmod go-w {}`", dir.display())),
            "{err}"
        );
        chmod(&dir, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The environment variable that tells [`in_a_user_namespace_child`] it is the child.
    #[cfg(target_os = "linux")]
    const NS_CHILD: &str = "IKIGAI_AUTHORITY_NS_CHILD";

    /// The child half of [`a_sandboxed_door_takes_its_authority_in_a_real_user_namespace`]:
    /// it runs inside `unshare --user --map-current-user`, where `/` and the temp directory
    /// (root's, unmapped) read as the overflow uid, and does nothing when run on its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn in_a_user_namespace_child() {
        let Some(dir) = std::env::var_os(NS_CHILD) else {
            return;
        };
        let dir = PathBuf::from(dir);
        let paths = [
            (dir.join("server.key"), Kind::PrivateKey),
            (dir.join("server.crt"), Kind::Public),
            (dir.clone(), Kind::Public),
        ];
        // The directories above the door's own tree are root's, unmapped: accepted.
        assert_eq!(check(&paths), Ok(()));
        // The grants-file walk accepts them too: they are not this user's and it cannot
        // write them.
        let hosts = Path::new("/etc/hosts");
        if hosts.exists() {
            assert_eq!(crate::agents::check_protected(hosts), Ok(()));
        }
    }

    /// The edge's sandboxed door (ledger #3397): a systemd user unit with `PrivateUsers=yes`
    /// sees every unmapped owner, root included, as the overflow uid. Runs the check in a
    /// child under a real user namespace over a scratch certificate directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_sandboxed_door_takes_its_authority_in_a_real_user_namespace() {
        use std::process::Command;
        let probe = Command::new("unshare")
            .args(["--user", "--map-current-user", "true"])
            .output();
        match probe {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                eprintln!(
                    "SKIPPED: this runner refuses an unprivileged user namespace \
                     (`unshare --user --map-current-user true`: {}); on Ubuntu 24.04 that is \
                     AppArmor's kernel.apparmor_restrict_unprivileged_userns",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                return;
            }
            Err(e) => {
                eprintln!("SKIPPED: `unshare` cannot be run here ({e}), so no user namespace");
                return;
            }
        }
        let dir = scratch("userns");
        let key = dir.join("server.key");
        let crt = dir.join("server.crt");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(&crt, "c").unwrap();
        chmod(&key, 0o600);
        chmod(&crt, 0o644);
        let out = Command::new("unshare")
            .args(["--user", "--map-current-user"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authority::tests::in_a_user_namespace_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NS_CHILD, &dir)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the check refused inside a user namespace:\n{stdout}\n{stderr}"
        );
    }

    #[test]
    fn a_missing_file_is_left_to_its_reader() {
        let dir = scratch("missing");
        assert_eq!(check(&[(dir.join("grants.json"), Kind::Public)]), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
