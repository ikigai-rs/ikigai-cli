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
//!
//! In a user namespace that leaves root unmapped (a sandboxed user service: systemd's
//! `PrivateUsers=yes`, which a user unit's `ProtectSystem=` or `PrivateTmp=` imply), every
//! owner not mapped into it, root included, reads as the overflow uid. A DIRECTORY ABOVE an
//! authority path owned by the overflow uid counts as root's there ([`counts_as_root`]); the
//! authority paths themselves get no such allowance, and a refusal for an overflow-uid owner
//! never suggests a `chown` (ledger #3397). A namespace that maps root (a system unit's
//! `PrivateUsers=yes`) or the overflow uid itself gets no allowance at all: there the overflow
//! uid is never root ([`namespace_overflow`]).

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

/// The overflow uid when this process runs in a user namespace that leaves root unmapped,
/// from the namespace's `/proc/self/uid_map` and `/proc/sys/kernel/overflowuid`:
/// [`overflow_uid`]'s rule, pure so it is testable without a namespace. In such a namespace (a
/// sandboxed user unit's `PrivateUsers=yes`, or `unshare -r`) every owner not mapped into it,
/// root included, reads as the overflow uid, which is 65534 when `overflowuid` cannot be read.
///
/// `None` when an owner reading as the overflow uid cannot be root: when the map gives outside
/// uid 0 a place (the initial namespace's full identity map `0 0 4294967295`, a system unit's
/// `PrivateUsers=yes`, which maps root to itself, or `PrivateUsers=identity`), root reads as
/// itself and the overflow uid is only ever another account; and when the map gives the
/// overflow uid itself to a real account. A map this rule cannot read is `None` too, so no
/// allowance is made on a guess.
///
/// ```
/// use ikigai_embedded::authority::namespace_overflow;
///
/// assert_eq!(namespace_overflow("         0          0 4294967295\n", Some("65534\n")), None);
/// assert_eq!(namespace_overflow("      1000       1000          1\n", Some("65534\n")), Some(65534));
/// assert_eq!(namespace_overflow("0 1000 1\n", None), Some(65534));
/// assert_eq!(namespace_overflow("0 1000 1\n", Some("4242\n")), Some(4242));
/// // A system unit's `PrivateUsers=yes`: root maps to itself, so the overflow uid is not root.
/// assert_eq!(namespace_overflow("0 0 1\n1000 1000 1\n", Some("65534\n")), None);
/// ```
pub fn namespace_overflow(uid_map: &str, overflowuid: Option<&str>) -> Option<u32> {
    let overflow: u32 = overflowuid
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65534);
    for line in uid_map.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let [inside, outside, count] = fields[..] else {
            return None;
        };
        let (Ok(inside), Ok(outside), Ok(count)) = (
            inside.parse::<u64>(),
            outside.parse::<u64>(),
            count.parse::<u64>(),
        ) else {
            return None;
        };
        let holds = |start: u64, id: u64| start <= id && id < start.saturating_add(count);
        if holds(outside, 0) || holds(inside, u64::from(overflow)) {
            return None;
        }
    }
    Some(overflow)
}

/// The overflow uid if this process runs in a user namespace, `None` if it does not
/// ([`namespace_overflow`]). Linux only: elsewhere, and when `/proc/self/uid_map` cannot be
/// read, `None`, so nothing changes. The namespace fact both owner walks share: [`check`] and
/// the grants-file walk ([`crate::agents::check_protected`]).
pub fn overflow_uid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let map = std::fs::read_to_string("/proc/self/uid_map").ok()?;
        let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowuid").ok();
        namespace_overflow(&map, overflow.as_deref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Whether `owner` counts as root for a component of an owner walk: root itself, or, for a
/// directory ABOVE the path the walk checks (`above`), the overflow uid inside a user
/// namespace (`overflow` is `Some` only there), which is how an unmapped root reads. The path
/// itself gets no such allowance: its owner must be one this namespace can see.
///
/// ```
/// use ikigai_embedded::authority::counts_as_root;
///
/// assert!(counts_as_root(0, false, None));
/// assert!(counts_as_root(65534, true, Some(65534)));
/// assert!(!counts_as_root(65534, false, Some(65534)));
/// assert!(!counts_as_root(65534, true, None));
/// ```
pub fn counts_as_root(owner: u32, above: bool, overflow: Option<u32>) -> bool {
    owner == 0 || (above && overflow == Some(owner))
}

/// Whether an owner is the overflow uid of the user namespace this process runs in.
fn unmapped(owner: u32, overflow: Option<u32>) -> bool {
    overflow == Some(owner)
}

/// Why a path owned by `owner` with mode `mode` is not safe for the process running as `me`
/// to take authority from, if it is not: [`check`]'s rule, pure so every branch is testable.
/// `above` is true for a directory above an authority path, false for the path itself;
/// `overflow` is the overflow uid when this process runs in a user namespace
/// ([`overflow_uid`]), `None` when it does not.
///
/// ```
/// use ikigai_embedded::authority::{exposure, Kind};
///
/// // The user's own 0600 key and 0644 certificate in a 0700 directory: fine.
/// assert_eq!(exposure(501, 0o100600, 501, false, Kind::PrivateKey, false, None), None);
/// assert_eq!(exposure(501, 0o100644, 501, false, Kind::Public, false, None), None);
/// assert_eq!(exposure(501, 0o40700, 501, true, Kind::Public, false, None), None);
/// // Root-owned, read-only for the service: fine.
/// assert_eq!(exposure(0, 0o100644, 501, false, Kind::Public, false, None), None);
/// // A key others can read, a file its group can write, another account's file: refused.
/// assert!(exposure(501, 0o100640, 501, false, Kind::PrivateKey, false, None).is_some());
/// assert!(exposure(501, 0o100664, 501, false, Kind::Public, false, None).is_some());
/// assert!(exposure(502, 0o100644, 501, false, Kind::Public, false, None).is_some());
/// // A sticky directory every user can write (/tmp): fine.
/// assert_eq!(exposure(0, 0o41777, 501, true, Kind::Public, true, None), None);
/// // In a user namespace, a directory above owned by the overflow uid (an unmapped root)
/// // counts as root's; the authority path itself does not.
/// assert_eq!(exposure(65534, 0o40755, 501, true, Kind::Public, true, Some(65534)), None);
/// assert!(exposure(65534, 0o100644, 501, false, Kind::Public, false, Some(65534)).is_some());
/// ```
pub fn exposure(
    owner: u32,
    mode: u32,
    me: u32,
    is_dir: bool,
    kind: Kind,
    above: bool,
    overflow: Option<u32>,
) -> Option<String> {
    if owner != me && !counts_as_root(owner, above, overflow) {
        if unmapped(owner, overflow) {
            return Some(format!(
                "is owned by uid {owner}, the overflow uid: this process runs in a user \
                 namespace and the file's real owner is not mapped into it, so it is not \
                 known to be this process's uid {me} or root"
            ));
        }
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

/// The command that fixes a path [`exposure`] refused, with the same arguments. An owner
/// that is the overflow uid gets no `chown`: inside the namespace its real owner is unknown,
/// and the directory may be a system one (`/home`) that must never be handed to a service.
#[allow(clippy::too_many_arguments)]
fn remedy(
    path: &Path,
    owner: u32,
    me: u32,
    is_dir: bool,
    kind: Kind,
    above: bool,
    overflow: Option<u32>,
) -> String {
    let p = path.display();
    let chmod = if kind == Kind::PrivateKey && !is_dir {
        format!("`chmod 600 {p}`")
    } else {
        format!("`chmod go-w {p}`")
    };
    if owner == me || counts_as_root(owner, above, overflow) {
        chmod
    } else if unmapped(owner, overflow) {
        format!(
            "a change made outside the sandbox: keep {p} in this service's own tree and owned \
             by the account this door runs as, the account its user namespace maps (uid {me} \
             here), not by root or another account; then {chmod}"
        )
    } else {
        format!("`chown {me} {p}` (as root), then {chmod}")
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
    let overflow = overflow_uid();
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
                let above = !first;
                let kind = if first { *kind } else { Kind::Public };
                first = false;
                here = p.parent();
                let Ok(meta) = std::fs::metadata(p) else {
                    continue;
                };
                let is_dir = meta.is_dir();
                let (owner, mode) = (meta.uid(), meta.mode());
                if let Some(why) = exposure(owner, mode, me, is_dir, kind, above, overflow) {
                    let fix = remedy(p, owner, me, is_dir, kind, above, overflow);
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

    const OVERFLOW: u32 = 65534;
    const ME: u32 = 1000;

    #[test]
    fn an_overflow_uid_parent_passes_inside_a_namespace_and_is_refused_outside() {
        // `/home`, root's, as a sandboxed door sees it.
        let inside = exposure(
            OVERFLOW,
            0o40755,
            ME,
            true,
            Kind::Public,
            true,
            Some(OVERFLOW),
        );
        assert_eq!(inside, None);
        let outside = exposure(OVERFLOW, 0o40755, ME, true, Kind::Public, true, None);
        assert!(outside.unwrap().contains("owned by uid 65534"));
        // Another overflow uid than the one this namespace reports is just another account.
        assert!(exposure(OVERFLOW, 0o40755, ME, true, Kind::Public, true, Some(4242)).is_some());
    }

    #[test]
    fn an_overflow_uid_authority_path_is_refused_inside_a_namespace_without_a_chown() {
        for (mode, is_dir, kind) in [
            (0o100600, false, Kind::PrivateKey),
            (0o100644, false, Kind::Public),
            (0o40755, true, Kind::Public),
        ] {
            let why = exposure(OVERFLOW, mode, ME, is_dir, kind, false, Some(OVERFLOW)).unwrap();
            assert!(why.contains("user namespace"), "{why}");
            assert!(why.contains("not mapped into it"), "{why}");
            let fix = remedy(
                Path::new("/home/ikigai/.ikigai/quic-layers/edge-bundle/server.key"),
                OVERFLOW,
                ME,
                is_dir,
                kind,
                false,
                Some(OVERFLOW),
            );
            assert!(!fix.contains("chown"), "{fix}");
        }
    }

    #[test]
    fn an_overflow_uid_parent_that_others_can_write_is_refused_with_only_a_chmod() {
        let why = exposure(
            OVERFLOW,
            0o40775,
            ME,
            true,
            Kind::Public,
            true,
            Some(OVERFLOW),
        );
        assert!(why.unwrap().contains("writable by its group"));
        let fix = remedy(
            Path::new("/home"),
            OVERFLOW,
            ME,
            true,
            Kind::Public,
            true,
            Some(OVERFLOW),
        );
        assert_eq!(fix, "`chmod go-w /home`");
        // The sticky-directory exception is unchanged: /tmp, unmapped root's.
        let tmp = exposure(
            OVERFLOW,
            0o41777,
            ME,
            true,
            Kind::Public,
            true,
            Some(OVERFLOW),
        );
        assert_eq!(tmp, None);
    }

    #[test]
    fn the_remedy_for_an_overflow_uid_owner_never_names_a_chown() {
        for above in [false, true] {
            for (mode, is_dir, kind) in [
                (0o100666, false, Kind::PrivateKey),
                (0o100666, false, Kind::Public),
                (0o40777, true, Kind::Public),
            ] {
                // Every one of these is refused, for its mode or for its owner.
                let why = exposure(OVERFLOW, mode, ME, is_dir, kind, above, Some(OVERFLOW));
                assert!(why.is_some());
                let fix = remedy(
                    Path::new("/home"),
                    OVERFLOW,
                    ME,
                    is_dir,
                    kind,
                    above,
                    Some(OVERFLOW),
                );
                assert!(!fix.contains("chown"), "{fix}");
            }
        }
    }

    #[test]
    fn the_identity_map_is_no_namespace() {
        assert_eq!(namespace_overflow("0 0 4294967295", Some("65534")), None);
        assert_eq!(namespace_overflow("", Some("65534")), Some(65534));
        assert_eq!(
            namespace_overflow("\t0\t0\t4294967295\t\n", Some("65534")),
            None
        );
        assert_eq!(namespace_overflow("1000 1000 1", Some("junk")), Some(65534));
    }

    /// A system unit's `PrivateUsers=yes` maps root and the unit's own user to themselves
    /// (systemd.exec(5)), so root reads as 0 there and an owner reading as the overflow uid is
    /// some OTHER account: a directory it owns must not count as root's. The same holds for
    /// `PrivateUsers=identity` (0 to 65535 mapped, overflow uid included) and for any map that
    /// gives the overflow uid to a real account.
    #[test]
    fn an_overflow_uid_is_not_root_when_root_or_the_overflow_uid_is_mapped() {
        for map in [
            "         0          0          1\n      1000       1000          1\n",
            "0 0 65536\n",
            "0 0 100\n100 100 4294967195\n",
            "1000 1000 1\n65534 65534 1\n",
        ] {
            let overflow = namespace_overflow(map, Some("65534\n"));
            assert_eq!(overflow, None, "{map:?}");
            // So a directory above an authority path that another account owns is refused.
            assert!(
                exposure(OVERFLOW, 0o40755, ME, true, Kind::Public, true, overflow).is_some(),
                "{map:?}"
            );
        }
        // Root unmapped, the overflow uid unmapped: the sandboxed user unit and `unshare -r`.
        for map in [
            "      1000       1000          1\n",
            "0 1000 1\n",
            "0\t1000\t1\n",
        ] {
            assert_eq!(
                namespace_overflow(map, Some("65534\n")),
                Some(65534),
                "{map:?}"
            );
        }
        // A map this rule cannot read grants no allowance.
        assert_eq!(namespace_overflow("0 x 1\n", Some("65534\n")), None);
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
