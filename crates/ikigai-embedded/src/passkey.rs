//! The passkey second factor on the edge, as ikigai endpoints — the server side of the
//! WebAuthn ceremony that [`ikigai_passkey`] verifies.
//!
//! The emailed decision links ([`crate::contactblock`], [`crate::decide`]) are gated today by a
//! signed token in the URL. A passkey adds "…and the person at the registered device approved it,
//! now." This module holds the three moving parts, all on the edge, all reusing one verifier:
//!
//! | endpoint / helper | verb | does |
//! |---|---|---|
//! | `urn:passkey:challenge` | Source | issues a fresh single-use challenge + the registered ids |
//! | [`require_passkey`] | — | the gate a decision POST calls before it acts |
//! | `urn:passkey:enroll-open` | Sink | opens a short enrollment window (run from the box) |
//! | `urn:passkey:register` | Source/Sink | GET shows the enrol page, POST stores the credential |
//!
//! The challenge and the register page declare `urn:cap:passkey:challenge` and
//! `urn:cap:passkey:register`, so a door reaches them only under a ceiling that grants them (the
//! edge's HTTP face does); enroll-open declares `urn:cap:passkey:enroll`.
//!
//! ## Per-action, not a session — and inert until enrolled
//!
//! There is no cookie and no session store: the browser runs the ceremony on the button tap and
//! the assertion rides in the decision POST body, so a Touch-ID tap is *per decision* (the right
//! feel for a block or a decline) and nothing here touches the HTTP transport layer. And the gate
//! is **inert until a credential is registered** — [`require_passkey`] returns `Ok` when the
//! credential file is ABSENT, so deploying this cannot brick the working links; enrolling a
//! passkey is what switches it on.
//!
//! Once armed it **fails closed**: a credential file that is present but unreadable, or enrolled
//! credentials on an edge with no [`RelyingParty`] configured, refuse every gated decision and
//! say why on stderr — they never read as "not enrolled". The relying party comes from
//! `ikigai serve --passkey-rp-id <domain> [--passkey-origin <url>]` and has no default.
//!
//! ## Replay defense lives here
//!
//! [`ikigai_passkey::verify`] is stateless, so the freshness of a challenge is this module's job:
//! `urn:passkey:challenge` mints a random challenge and remembers it briefly; the gate consumes it
//! on use, so an assertion can be presented exactly once and only within the window.
//!
//! ## Enrollment trust
//!
//! Registering a passkey grants the authority to approve everything the links can, so it must be
//! bootstrapped from a trusted context. It uses a **local enrollment window with a one-time
//! code** (ledger #1689): `urn:passkey:enroll-open` is cap-gated (`urn:cap:passkey:enroll`), run
//! from the box, and answers with a fresh code that only the person at the box sees (it is
//! printed to their terminal, never served; the window file holds only its SHA-256). For a few
//! minutes one credential may register, and only by a POST that carries that code: an anonymous
//! POST of `{id, spki}` without it, or with a wrong one, is refused and logged. The first
//! registration SPENDS the window, so a second one in the same window is refused and logged too.
//! Before the code, the window was a race: anyone who reached `/passkey/register` while it was
//! open could enroll a key of their own first (threat model S1, gap 2). Anchoring the enrol
//! link in the Mac-held decide key remains a possible further hardening.

use crate::decide::{page, param};
use crate::file_root;
use base64::Engine;
use ikigai_core::{
    ActionSpec, Description, Endpoint, Error, Invocation, ReprType, Representation, Result, Verb,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Cap to open an enrollment window — held only where a human at the box runs it.
pub const CAP_PASSKEY_ENROLL: &str = "urn:cap:passkey:enroll";

/// Cap to mint a login challenge (`urn:passkey:challenge`). DECLARED, so the kernel's floor
/// refuses a caller without it and the manifold offers the endpoint only to one that holds it:
/// a door whose principals were never granted the passkey ceremony cannot reach it. The edge's
/// public HTTP face grants it in its `--cap` ceiling, beside the intake doors it serves.
pub const CAP_PASSKEY_CHALLENGE: &str = "urn:cap:passkey:challenge";

/// Cap to show the enrollment page and post a registration (`urn:passkey:register`, both
/// verbs). Declared for the same reason as [`CAP_PASSKEY_CHALLENGE`]; holding it is not
/// enough to enroll anything, since a registration also needs the window opened at the box
/// and its one-time code.
pub const CAP_PASSKEY_REGISTER: &str = "urn:cap:passkey:register";

/// How long a challenge stays good — long enough for a biometric prompt, short enough that a
/// leaked one is stale almost at once. Measured on the MONOTONIC clock, so a backward jump of
/// the wall clock cannot extend one.
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// How long an enrollment window stays open once a human opens it.
const ENROLL_WINDOW_SECONDS: i64 = 300;

/// Wall-clock seconds, for the enrollment window ONLY. That window is opened by one process
/// (`ikigai -c 'sink urn:passkey:enroll-open'` at the box) and read by another (the edge), so
/// its deadline has to be a number both can read from the file; an `Instant` means nothing
/// outside the process that took it. Challenges never leave this process, so they use one.
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

// =====================================================================================
// The relying party — configured by the host, never defaulted.
// =====================================================================================

/// The WebAuthn relying party this edge asserts under: the RP id (a registrable domain such as
/// `ikigai-rs.dev`) and the origin the browser reports (`https://ikigai-rs.dev`).
///
/// **There is no default.** A forgotten setting used to register passkeys silently under the
/// production hostname; now an edge that has not been told its relying party cannot enroll a
/// passkey, and an edge that HAS enrolled ones refuses every gated decision until it is told
/// (fail closed). `ikigai serve --passkey-rp-id <domain> [--passkey-origin <url>]` sets it.
///
/// ```
/// use ikigai_embedded::passkey::RelyingParty;
/// let rp = RelyingParty::new("ikigai-rs.dev", None).unwrap();
/// assert_eq!(rp.origin(), "https://ikigai-rs.dev");
/// let rp = RelyingParty::new("example.org", Some("https://login.example.org")).unwrap();
/// assert_eq!((rp.rp_id(), rp.origin()), ("example.org", "https://login.example.org"));
/// assert!(RelyingParty::new("https://example.org", None).is_err()); // an id, not a URL
/// assert!(RelyingParty::new("example.org", Some("https://example.org/path")).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    rp_id: String,
    origin: String,
}

impl RelyingParty {
    /// A relying party for `rp_id`, with `origin` defaulting to `https://<rp_id>`. Refuses an
    /// id that is not a bare host name and an origin that is not `scheme://host[:port]`.
    pub fn new(rp_id: &str, origin: Option<&str>) -> std::result::Result<Self, String> {
        let rp_id = rp_id.trim();
        if rp_id.is_empty()
            || rp_id
                .chars()
                .any(|c| matches!(c, '/' | ':' | '?' | '#' | '@') || c.is_whitespace())
        {
            return Err(format!(
                "a passkey RP id is a bare domain such as `ikigai-rs.dev`, not `{rp_id}`"
            ));
        }
        let origin = match origin {
            Some(o) => o.trim().trim_end_matches('/').to_string(),
            None => format!("https://{rp_id}"),
        };
        let host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or_else(|| format!("a passkey origin is `https://host[:port]`, not `{origin}`"))?;
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(format!(
                "a passkey origin is `https://host[:port]` with no path, not `{origin}`"
            ));
        }
        Ok(Self {
            rp_id: rp_id.to_string(),
            origin,
        })
    }
    /// The RP id the authenticator scopes its credential to.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    /// The origin `clientDataJSON` must carry.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

static RELYING_PARTY: Mutex<Option<RelyingParty>> = Mutex::new(None);

/// Tell this process's passkey endpoints which relying party they serve. Process-global like
/// the instance name, and set once at startup from `serve`'s flags.
pub fn set_relying_party(rp: RelyingParty) {
    *RELYING_PARTY.lock().unwrap_or_else(|e| e.into_inner()) = Some(rp);
}

/// The configured relying party, if any.
#[cfg(not(test))]
fn relying_party() -> Option<RelyingParty> {
    RELYING_PARTY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The tests override the relying party per thread (as they do `store_root`), so a test that
/// wants the unconfigured case cannot race one that configures it.
#[cfg(test)]
fn relying_party() -> Option<RelyingParty> {
    tests::test_rp()
}

/// The workspace root the passkey files live under. In production this is [`file_root`]; the
/// tests override it per-thread (each test runs on its own thread) so parallel tests never share
/// a credential file — a global env-var override would race across them.
fn store_root() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(p) = tests::test_root() {
        return p;
    }
    file_root()
}

fn credentials_path() -> std::path::PathBuf {
    store_root().join("passkey-credentials.json")
}
fn enroll_window_path() -> std::path::PathBuf {
    store_root().join("passkey-enroll.open")
}

// =====================================================================================
// The challenge store — process-global, in-memory. A restart just invalidates outstanding
// challenges (the user taps again); nothing here is worth persisting.
//
// BOUNDED (ledger #1717, threat model S1 gap 3). `urn:passkey:challenge` is capability-free and
// reachable by anyone on the public HTTP door and by every participant on a layer door, and each
// read used to add an entry that only the next read's sweep of EXPIRED entries could drop: the
// map held request rate × the TTL, with no ceiling. Now it holds at most [`max_challenges`].
//
// ★ Past the bound a NEW challenge is REFUSED; no outstanding one is ever evicted. Eviction
// (drop the oldest to make room) would let a flood push out the challenge of an honest ceremony
// already under way, and the person who just touched the sensor would be refused at the POST with
// no way to know why. A refusal costs the honest user a retry at worst, says why, and every
// ceremony already holding a challenge still completes.
// =====================================================================================

/// The most passkey challenges outstanding at once, unless `passkey.max_challenges` in the
/// config home says otherwise. One person taps one challenge per decision; 4096 is far above
/// any honest use and, at about a hundred bytes an entry, well under a megabyte. It is large on
/// purpose: a refusal past the bound is also a refusal to the honest user, so the bound should
/// take a flood to reach, not a burst.
pub const DEFAULT_MAX_CHALLENGES: usize = 4096;

/// The config-home key that overrides [`DEFAULT_MAX_CHALLENGES`].
pub const MAX_CHALLENGES_KEY: &str = "passkey.max_challenges";

/// The outstanding challenges, each with its expiry on the monotonic clock.
#[derive(Default)]
struct Challenges {
    live: HashMap<String, Instant>,
}

impl Challenges {
    /// Remember `challenge` until `now + CHALLENGE_TTL`, unless `max` are already outstanding.
    /// Expired entries are reclaimed first, so only challenges still in date count.
    fn issue(&mut self, challenge: String, now: Instant, max: usize) -> Result<()> {
        self.live.retain(|_, exp| *exp > now);
        if self.live.len() >= max {
            // When the soonest outstanding challenge expires and frees a place.
            let wait = self
                .live
                .values()
                .min()
                .map_or(CHALLENGE_TTL, |exp| exp.saturating_duration_since(now));
            return Err(Error::Unavailable(format!(
                "too many passkey challenges are outstanding ({max}); none is replaced, so a \
                 sign-in already under way still completes. Try again in {}s",
                wait.as_secs() + 1
            )));
        }
        self.live.insert(challenge, now + CHALLENGE_TTL);
        Ok(())
    }

    /// Spend `challenge`: true when it was issued here and is still in date. It is removed
    /// either way, so it cannot be presented twice.
    fn consume(&mut self, challenge: &str, now: Instant) -> bool {
        match self.live.remove(challenge) {
            Some(exp) => exp > now,
            None => false,
        }
    }
}

#[cfg(not(test))]
fn challenges() -> &'static Mutex<Challenges> {
    static STORE: OnceLock<Mutex<Challenges>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Challenges::default()))
}

/// Under test each thread has its own store (each test runs on its own thread, and the gate is
/// driven with a same-thread executor), so a test that fills the store to its bound cannot
/// refuse a parallel test's ceremony.
#[cfg(test)]
fn challenges() -> &'static Mutex<Challenges> {
    tests::test_challenges()
}

/// Read `passkey.max_challenges`: absent is the default, otherwise a whole number of at least 1
/// (TOML's `_` separators allowed).
///
/// ```
/// use ikigai_embedded::passkey::{max_challenges_from, DEFAULT_MAX_CHALLENGES};
/// assert_eq!(max_challenges_from(None), Ok(DEFAULT_MAX_CHALLENGES));
/// assert_eq!(max_challenges_from(Some("1_000")), Ok(1000));
/// assert!(max_challenges_from(Some("0")).is_err());
/// assert!(max_challenges_from(Some("lots")).is_err());
/// ```
pub fn max_challenges_from(value: Option<&str>) -> std::result::Result<usize, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_MAX_CHALLENGES);
    };
    let digits: String = value.chars().filter(|c| *c != '_').collect();
    match digits.parse::<usize>() {
        Ok(0) => Err(format!(
            "`{MAX_CHALLENGES_KEY} = {value}`: the least it can be is 1"
        )),
        Ok(n) if digits.chars().all(|c| c.is_ascii_digit()) => Ok(n),
        _ => Err(format!(
            "`{MAX_CHALLENGES_KEY} = {value}` is not a whole number (a count of challenges)"
        )),
    }
}

/// Check `passkey.max_challenges` in the config home. A serving door calls this at start-up and
/// refuses to start on an error, so a mistyped bound stops the door rather than being ignored.
pub fn check_config() -> std::result::Result<(), String> {
    max_challenges_from(crate::config::get(MAX_CHALLENGES_KEY).as_deref())
        .map(|_| ())
        .map_err(|e| format!("{e} (in {})", crate::config::config_path().display()))
}

/// The bound in force: the config home's `passkey.max_challenges`, read once. An invalid value
/// is reported once on stderr and the default stands; a door that checked [`check_config`] at
/// start-up never gets here with one.
fn max_challenges() -> usize {
    #[cfg(test)]
    if let Some(max) = tests::test_max_challenges() {
        return max;
    }
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        match max_challenges_from(crate::config::get(MAX_CHALLENGES_KEY).as_deref()) {
            Ok(max) => max,
            Err(e) => {
                eprintln!("ikigai passkey: {e}; the default {DEFAULT_MAX_CHALLENGES} stands");
                DEFAULT_MAX_CHALLENGES
            }
        }
    })
}

/// The monotonic clock challenges expire on. Native-only: the embedded host is a threaded,
/// filesystem-backed process that a wasm build replaces rather than compiles, and the injected
/// `Clock` offers wall time, which is exactly what a challenge's expiry must not follow. The
/// attribute is on the fn because the call is a trailing expression (an attribute on an
/// expression is not stable).
#[allow(clippy::disallowed_methods)]
fn monotonic_now() -> Instant {
    Instant::now()
}

/// Mint a fresh challenge, remember it with an expiry, and return its base64url text. Refused
/// with a transient [`Error::Unavailable`] when [`max_challenges`] are already outstanding.
fn issue_challenge() -> Result<String> {
    issue_challenge_at(monotonic_now())
}

/// [`issue_challenge`] at a given monotonic instant — the seam the expiry tests drive.
fn issue_challenge_at(now: Instant) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| Error::Endpoint(format!("no OS randomness for a challenge: {e}")))?;
    let challenge = b64().encode(raw);
    let max = max_challenges();
    // Held across no await: every critical section on this lock is a few map operations.
    let mut store = challenges().lock().expect("challenge store poisoned");
    store.issue(challenge.clone(), now, max)?;
    Ok(challenge)
}

/// Consume a challenge: it must be one we issued and still in date, and it is removed so it
/// cannot be presented twice.
fn consume_challenge(challenge: &str) -> bool {
    consume_challenge_at(challenge, monotonic_now())
}

/// [`consume_challenge`] at a given monotonic instant.
fn consume_challenge_at(challenge: &str, now: Instant) -> bool {
    let mut store = challenges().lock().expect("challenge store poisoned");
    store.consume(challenge, now)
}

// =====================================================================================
// The credential store — a small JSON file, the registered public key(s) for the one user.
//
// Three rules, each one a way the gate used to fail OPEN:
//
// - ABSENT means "not enrolled" (the gate is inert); PRESENT but unreadable or unparsable is an
//   error, and the gate refuses every decision until someone repairs it at the box. It used to
//   read as "not enrolled", so a truncated file silently downgraded every decision to token-only.
// - Writes are ATOMIC (temp file in the same directory, fsync, rename), so a crash leaves the old
//   file or the new one, never half of one.
// - load → verify → save runs under ONE process-wide lock, so two concurrent assertions cannot
//   each write back the copy they loaded and lower the stored signature counter.
// - The file is trusted only if nobody else could have WRITTEN it (ledger #828): write access is
//   the power to enroll a credential. Group/world-writable, or owned by another user, refuses
//   like an unparsable file; only group/world-READABLE is tightened to 0600 and logged. Checked
//   on the open handle, under the lock, before a byte is parsed. Saves were already 0600, but a
//   file enrolled before 0.1.39 is rewritten only when a counter advances, and a platform
//   passkey's counter stays 0, so without this check a loose file stayed loose for good.
// =====================================================================================

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct StoredCredential {
    /// base64url of the credentialId.
    id: String,
    /// base64url of the SubjectPublicKeyInfo DER public key.
    spki: String,
    /// The last signature counter seen, advanced on each successful assertion.
    #[serde(default)]
    sign_count: u32,
}

/// Serializes every read-modify-write of the credential file in this process. It guards no
/// data of its own (the file is the data), so a poisoned lock is safe to take over. Held across
/// no await: the gate and the register endpoint hold it only in synchronous code.
fn credential_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The registered credentials. `Ok(empty)` only when the file is ABSENT; a file that is present
/// but cannot be read or parsed, or that someone other than this process's user could have
/// written, is an `Err` naming it, which every caller treats as "refuse".
///
/// Takes the [`credential_lock`] guard so that every load provably runs under the lock: the
/// permission check (which may tighten the file) and the parse see one state of the file.
fn load_credentials(
    _held: &MutexGuard<'static, ()>,
) -> std::result::Result<Vec<StoredCredential>, String> {
    use std::io::Read;
    // The directory first, and whether or not the file is there: in a directory others can
    // write, ABSENT is not evidence of "not enrolled" (deleting the file is how they would
    // disarm the gate), and a present file may be one they put there.
    guard_directory(&store_root())?;
    let path = credentials_path();
    let unreadable =
        |e: std::io::Error| format!("{} is present but unreadable: {e}", path.display());
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(unreadable(e)),
    };
    // On the handle, not the path: what is judged is exactly what is then read.
    guard_permissions(&path, &file, Remedy::CheckThenChmod)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(unreadable)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "{} is present but not a credential list: {e}",
            path.display()
        )
    })
}

/// What the credential file's permission bits and owner allow.
#[derive(Debug, PartialEq, Eq)]
enum Permission {
    /// Owner-only, owned by this process's user.
    Private,
    /// Others can read it but not write it: nothing is at stake but disclosure of public keys,
    /// so it is tightened to 0600 rather than taking the gate down for a cosmetic reason.
    Tighten,
    /// Someone else could have written it, so its contents (which credentials are enrolled) are
    /// not trusted. Tightening it now would trust whatever they wrote; a person checks it.
    Refuse(String),
}

/// Judge a file `mode` owned by uid `owner`, read by a process running as uid `me`. Pure, so
/// every branch is testable, including the foreign-owner one a test cannot stage without root.
fn judge_permissions(mode: u32, owner: u32, me: u32) -> Permission {
    if owner != me {
        return Permission::Refuse(format!(
            "is owned by uid {owner}, not by this process's uid {me}, so its owner could have \
             enrolled a credential"
        ));
    }
    if mode & 0o022 != 0 {
        return Permission::Refuse(format!(
            "is writable by its group or by everyone (mode {:04o}), so anyone who can write it \
             could have enrolled a credential",
            mode & 0o7777
        ));
    }
    if mode & 0o044 != 0 {
        return Permission::Tighten;
    }
    Permission::Private
}

/// What a person at the box does about a passkey file someone else could have written.
#[derive(Clone, Copy)]
enum Remedy {
    /// The credential store: check every entry is theirs, then take the file back.
    CheckThenChmod,
    /// The enrollment window (ledger #850): remove it. Its timestamp is not theirs to vouch
    /// for, and a new window is one command away.
    Remove,
}

/// Refuse a passkey file someone else could have written; tighten one others can only read.
/// The command in the refusal is the exact fix: for the credential store, the `chmod` after the
/// person at the box has checked that every entry in the file is theirs; for the enrollment
/// window, removing it.
#[cfg(unix)]
fn guard_permissions(
    path: &std::path::Path,
    file: &std::fs::File,
    remedy: Remedy,
) -> std::result::Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = file
        .metadata()
        .map_err(|e| format!("{} is present but cannot be inspected: {e}", path.display()))?;
    // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot fail.
    let me = unsafe { libc::geteuid() };
    match judge_permissions(meta.mode(), meta.uid(), me) {
        Permission::Private => Ok(()),
        Permission::Tighten => {
            // fchmod on the open handle; owning the file is all it needs.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    format!(
                        "{} is readable by others (mode {:04o}) and could not be tightened: {e}; \
                         fix it at the box with `chmod 600 {}`",
                        path.display(),
                        meta.mode() & 0o7777,
                        path.display()
                    )
                })?;
            // Logged once: the file is 0600 from here on, so the next load is silent.
            eprintln!(
                "ikigai passkey: {} was readable by others (mode {:04o}); tightened it to 0600.",
                path.display(),
                meta.mode() & 0o7777
            );
            Ok(())
        }
        Permission::Refuse(why) => {
            let p = path.display();
            if let Remedy::Remove = remedy {
                let who = if meta.uid() == me { "" } else { " (as root)" };
                return Err(format!(
                    "{p} {why}, so the window it describes is not trusted; remove it at the box \
                     with `rm {p}`{who} and open a new one with `sink urn:passkey:enroll-open`"
                ));
            }
            let fix = if meta.uid() == me {
                format!("`chmod 600 {p}`")
            } else {
                format!("`chown {me} {p}` (as root), then `chmod 600 {p}`")
            };
            Err(format!(
                "{p} {why}; check that every entry in it is yours, then fix it at the box with \
                 {fix}"
            ))
        }
    }
}

/// No Unix permission bits to judge: a non-Unix host (none is deployed; the edge is Linux and the
/// desk macOS) trusts the platform's ACLs, as it did before this check existed.
#[cfg(not(unix))]
fn guard_permissions(
    _path: &std::path::Path,
    _file: &std::fs::File,
    _remedy: Remedy,
) -> std::result::Result<(), String> {
    Ok(())
}

/// Judge the DIRECTORY the passkey files live in (ledger #850): `Some(why)` when someone other
/// than this process's user could create, delete, rename or replace entries in it. Then nothing
/// in it is trusted, whatever its own mode says: they could plant an enrollment window, swap in
/// a symlink or hard link to a file of ours that happens to parse, or delete the credential file
/// and so disarm the gate. Readable by others is fine for a directory (0755 is ordinary); the
/// files in it are judged on their own. Pure, so the foreign-owner branch is testable.
fn judge_directory(mode: u32, owner: u32, me: u32) -> Option<String> {
    if owner != me {
        return Some(format!(
            "is owned by uid {owner}, not by this process's uid {me}"
        ));
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "is writable by its group or by everyone (mode {:04o})",
            mode & 0o7777
        ));
    }
    None
}

/// Refuse to trust anything in a passkey directory others could write. The fix in the refusal
/// is the exact command, after the person at the box has checked the files in it are theirs.
#[cfg(unix)]
fn guard_directory(dir: &std::path::Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let d = dir.display();
    let meta = std::fs::metadata(dir)
        .map_err(|e| format!("the passkey workspace {d} cannot be inspected: {e}"))?;
    // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot fail.
    let me = unsafe { libc::geteuid() };
    let Some(why) = judge_directory(meta.mode(), meta.uid(), me) else {
        return Ok(());
    };
    let fix = if meta.uid() == me {
        format!("`chmod go-w {d}`")
    } else {
        format!("`chown {me} {d}` (as root), then `chmod go-w {d}`")
    };
    Err(format!(
        "the passkey workspace {d} {why}, so anyone who can write it could have enrolled a \
         credential, opened enrollment or removed the credential store, and nothing in it is \
         trusted; check that the passkey files in it are yours, then fix it at the box with {fix}"
    ))
}

/// No Unix permission bits to judge (see the non-Unix [`guard_permissions`]).
#[cfg(not(unix))]
fn guard_directory(_dir: &std::path::Path) -> std::result::Result<(), String> {
    Ok(())
}

/// Check the credential store the way the gate will, at startup, so a store the gate would
/// refuse stops a serving door from coming up rather than surfacing at the first decision
/// someone taps. Absent is fine (not enrolled); a group/world-readable file is tightened here.
/// The workspace DIRECTORY is judged first (ledger #850): one others could write refuses,
/// naming it, whether or not a credential file is in it.
pub fn preflight() -> std::result::Result<(), String> {
    let held = credential_lock();
    load_credentials(&held).map(|_| ())
}

/// The loud half of failing closed: one line on stderr per refused request, naming the file.
fn store_unreadable(detail: &str) {
    eprintln!(
        "ikigai passkey: REFUSING every passkey-gated decision: {detail}. Repair or remove the \
         file at the box (removing it un-enrolls; enroll again with `sink urn:passkey:enroll-open`)."
    );
}

fn save_credentials(creds: &[StoredCredential]) -> Result<()> {
    let json = serde_json::to_vec_pretty(creds)
        .map_err(|e| Error::Endpoint(format!("cannot serialize credentials: {e}")))?;
    write_atomic(&credentials_path(), &json)
        .map_err(|e| Error::Endpoint(format!("cannot write credentials: {e}")))
}

/// Replace `path` with `bytes` whole: write a sibling temp file (owner-only), fsync it, rename it
/// over the target, then fsync the directory so the rename itself survives a crash. A reader —
/// or a crash at any point — sees the old file or the new one, never a truncated one.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Unique per process; within one, the credential lock serializes writers.
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // a leftover from a crash would refuse `create_new`
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let write_then_rename = |opts: &std::fs::OpenOptions| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    let written = write_then_rename(&opts);
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    // Durability of the rename, best-effort: not every platform can open a directory to sync it.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Whether the gate is armed. True when a credential is registered — and ALSO when the store is
/// present but unreadable, because then the gate refuses everything (it fails closed).
pub fn is_enrolled() -> bool {
    let held = credential_lock();
    load_credentials(&held).map_or(true, |c| !c.is_empty())
}

// =====================================================================================
// Browser glue. The one piece that runs on the device, not the edge.
//
// Served as a SAME-ORIGIN FILE, not inline: the edge's strict CSP is `default-src 'self'`,
// which forbids inline `<script>` but allows a script fetched from the same origin. So the
// pages carry only a `<script src="/passkey/app.js">` tag and the ceremony lives in
// `PASSKEY_APP_JS`, served by `urn:passkey:js` with a JavaScript content type (X-Content-Type-
// Options: nosniff is set, so the MIME must be right). No CSP loosening anywhere.
// =====================================================================================

/// What a decision page carries: a status line and the shared ceremony script. The page's form
/// must have `id="act"`; `PASSKEY_APP_JS` wires it — on submit, fetch a challenge, run
/// `navigator.credentials.get` if enrolled, attach the assertion as `pk_*` fields, submit.
///
/// The status line is a polite live region (WCAG 4.1.3, ledger #1624), empty in the served
/// markup so it exists before the script writes a message into it: a screen reader announces a
/// change to a region it already knows. `#666` on white is 5.7:1.
pub(crate) const DECISION_PASSKEY_JS: &str = "<p id=pkstatus role=status aria-live=polite \
     class=muted></p><script src=\"/passkey/app.js\"></script>";

/// The registration page body: a labeled field for the window's one-time code, and a button
/// (wired by `PASSKEY_APP_JS` via `id="reg"`) that runs `navigator.credentials.create`, then
/// POSTs the code, the new credential id and its SPKI public key. Its `#status` line is a live
/// region, like [`DECISION_PASSKEY_JS`]'s.
const REGISTER_PAGE_BODY: &str = r#"<p>Create a passkey for this site — your device will ask you to confirm with Face/Touch ID.</p>
<p><label for=code>One-time code (shown at the box when the window was opened)</label><br>
<input id=code name=code autocomplete=one-time-code autocapitalize=characters spellcheck=false required class=field></p>
<button id=reg>Create passkey</button>
<p id=status role=status aria-live=polite class=muted></p>
<script src="/passkey/app.js"></script>"#;

/// What `/passkey/register` shows on an edge started without `--passkey-rp-id`.
const NOT_CONFIGURED_BODY: &str = "<p>This edge has no passkey relying party configured, so a \
     passkey registered here would be bound to nothing. Restart it with <code>--passkey-rp-id \
     &lt;domain&gt;</code> (and <code>--passkey-origin</code> if the origin is not \
     <code>https://&lt;domain&gt;</code>), then open an enrollment window.</p>";

/// The one ceremony script, served same-origin (see the section note on CSP). It wires whichever
/// page it lands on: a decision form (`#act` → `navigator.credentials.get`) or the register
/// button (`#reg` → `navigator.credentials.create`). `form.submit()` does not re-fire the submit
/// handler, so the decision path has no re-entrancy.
const PASSKEY_APP_JS: &str = r#"(function(){
  var form=document.getElementById('act');
  var reg=document.getElementById('reg');
  if(form) decision(form);
  if(reg) register(reg);

  function decision(form){
    var status=document.getElementById('pkstatus');
    form.addEventListener('submit', function(ev){ ev.preventDefault();
      status.textContent='';
      fetch('/passkey/challenge',{headers:{accept:'application/json'}})
        .then(function(r){return r.json();})
        .then(function(opt){
          if(!opt.enrolled){ form.submit(); return; }
          status.textContent='Confirm with your passkey…';
          return navigator.credentials.get({publicKey:{
            challenge:u(opt.challenge), rpId:opt.rpId,
            allowCredentials:(opt.allowCredentials||[]).map(function(c){return {type:'public-key',id:u(c.id)};}),
            userVerification:opt.userVerification||'preferred', timeout:60000
          }}).then(function(a){
            add(form,'pk_id',b(a.rawId)); add(form,'pk_auth',b(a.response.authenticatorData));
            add(form,'pk_client',b(a.response.clientDataJSON)); add(form,'pk_sig',b(a.response.signature));
            form.submit();
          });
        })
        .catch(function(e){ status.textContent='Passkey step failed ('+((e&&e.message)||e)+'). Reopen the link to retry.'; });
    });
  }

  function register(btn){
    var status=document.getElementById('status');
    btn.addEventListener('click', function(){
      var code=document.getElementById('code');
      if(!code||!code.value.trim()){ status.textContent='Enter the one-time code shown at the box first.'; if(code) code.focus(); return; }
      status.textContent='Creating…';
      fetch('/passkey/challenge').then(function(r){return r.json();}).then(function(opt){
        return navigator.credentials.create({publicKey:{
          rp:{id:opt.rpId, name:'ikigai'},
          user:{id:new TextEncoder().encode('ikigai-owner'), name:'owner', displayName:'ikigai owner'},
          challenge:u(opt.challenge),
          pubKeyCredParams:[{type:'public-key',alg:-7}],
          authenticatorSelection:{userVerification:'preferred',residentKey:'preferred'},
          timeout:60000, attestation:'none'
        }});
      }).then(function(cred){
        var spki=cred.response.getPublicKey && cred.response.getPublicKey();
        if(!spki){ throw new Error('this browser did not expose the public key (needs WebAuthn L2)'); }
        var body='code='+encodeURIComponent(code.value.trim())+'&id='+encodeURIComponent(b(cred.rawId))+'&spki='+encodeURIComponent(b(spki));
        return fetch('/passkey/register',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body});
      }).then(function(res){ return res.text(); }).then(function(html){ document.open(); document.write(html); document.close(); })
        .catch(function(e){ status.textContent='Registration failed: '+((e&&e.message)||e); });
    });
  }

  function add(f,n,v){ var i=document.createElement('input'); i.type='hidden'; i.name=n; i.value=v; f.appendChild(i); }
  function u(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; var x=atob(s),y=new Uint8Array(x.length); for(var i=0;i<x.length;i++)y[i]=x.charCodeAt(i); return y.buffer; }
  function b(buf){ var y=new Uint8Array(buf),s=''; for(var i=0;i<y.length;i++)s+=String.fromCharCode(y[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
})();
"#;

/// Serves `PASSKEY_APP_JS` as a same-origin JavaScript file so the strict edge CSP admits it.
pub struct PasskeyJs;

#[async_trait::async_trait]
impl Endpoint for PasskeyJs {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        Ok(Representation::new(
            ReprType::new("application/javascript").with_param("charset", "utf-8"),
            PASSKEY_APP_JS.as_bytes().to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-js"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-js")
            .title("The passkey ceremony script")
            .summary("The same-origin script the decision and register pages load to run the WebAuthn ceremony.")
            // ★ ON THE ACTION, not beside it. `Description::action` takes an explicit
            // `ActionSpec` WHOLE — `action_specs()` never merges the flat `.output()` into
            // one — so the flat declaration below is invisible to every consumer that reads
            // the manifold's actions. Kept as well because `Description::outputs` is its own
            // public field; the action is the one that is read. (Conformance 0.2.0's OUTPUTS
            // check found all four passkey faces undeclared this way.)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the script")
                    .output("application/javascript; charset=utf-8"),
            )
            .output("application/javascript; charset=utf-8")
    }
}

// =====================================================================================
// The gate — what a decision POST calls before it acts.
// =====================================================================================

/// Require a valid passkey assertion for this action, UNLESS no credential is enrolled (in which
/// case the action proceeds token-only, exactly as before passkeys). The assertion rides in the
/// POST body as base64url fields the glue-JS adds: `pk_id`, `pk_auth`, `pk_client`, `pk_sig`.
///
/// "Not enrolled" means the credential file is ABSENT. A file that is present but unreadable, or
/// credentials with no [`RelyingParty`] configured to check them against, refuse every decision
/// and say why on stderr: the gate fails closed, never open.
///
/// On success the challenge is consumed (single-use) and any advanced signature counter persisted.
/// Every failure is one `Denied` — a prober learns nothing from which check tripped.
pub fn require_passkey(inv: &Invocation<'_>) -> Result<()> {
    let denied = || Error::Denied("this action needs your passkey".to_string());

    // One lock from load to save, so a concurrent assertion cannot write back a stale copy.
    let held = credential_lock();
    let creds = match load_credentials(&held) {
        Ok(creds) => creds,
        Err(detail) => {
            store_unreadable(&detail);
            return Err(denied());
        }
    };
    if creds.is_empty() {
        return Ok(()); // inert until enrolled
    }
    let Some(rp) = relying_party() else {
        eprintln!(
            "ikigai passkey: REFUSING every passkey-gated decision: a credential is enrolled but \
             this edge has no relying party configured (start it with `--passkey-rp-id <domain>`)."
        );
        return Err(denied());
    };

    // Pull the four assertion fields the glue-JS attaches, all base64url.
    let (id_b64, auth_b64, client_b64, sig_b64) = (
        param(inv, "pk_id")?,
        param(inv, "pk_auth")?,
        param(inv, "pk_client")?,
        param(inv, "pk_sig")?,
    );
    if id_b64.is_empty() || auth_b64.is_empty() || client_b64.is_empty() || sig_b64.is_empty() {
        return Err(denied());
    }
    let decode = |s: &str| b64().decode(s).map_err(|_| denied());
    let (cred_id, auth_data, client_data, signature) = (
        decode(&id_b64)?,
        decode(&auth_b64)?,
        decode(&client_b64)?,
        decode(&sig_b64)?,
    );

    // The challenge inside clientDataJSON must be one we issued and have not yet spent.
    let client_json: serde_json::Value =
        serde_json::from_slice(&client_data).map_err(|_| denied())?;
    let challenge = client_json
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(denied)?
        .to_string();
    if !consume_challenge(&challenge) {
        return Err(denied()); // stale, replayed, or never issued here
    }

    // The assertion must name a credential we registered; rebuild it for the verifier.
    let stored = creds
        .iter()
        .find(|c| c.id == id_b64)
        .ok_or_else(denied)?
        .clone();
    let spki = b64().decode(&stored.spki).map_err(|_| denied())?;
    let registered =
        ikigai_passkey::RegisteredCredential::from_spki_der(cred_id, &spki, stored.sign_count)
            .map_err(|_| denied())?;

    let policy = ikigai_passkey::Policy {
        rp_id: rp.rp_id(),
        origin: rp.origin(),
        challenge_b64url: &challenge,
        require_user_verified: true,
    };
    let assertion = ikigai_passkey::Assertion {
        credential_id: &registered.id,
        authenticator_data: &auth_data,
        client_data_json: &client_data,
        signature: &signature,
    };
    let new_count =
        ikigai_passkey::verify(&registered, &assertion, &policy).map_err(|_| denied())?;
    #[cfg(test)]
    tests::after_verify();

    // Persist an advanced counter so a cloned authenticator's replay is caught next time. The
    // copy written back is the one loaded under the lock still held, so nothing newer can be
    // overwritten, and the guard below means the stored counter only ever rises.
    if new_count > stored.sign_count {
        let mut all = creds;
        if let Some(c) = all.iter_mut().find(|c| c.id == id_b64) {
            c.sign_count = new_count;
        }
        // Best-effort: a failed write must not undo a real decision — but it is said out loud.
        if let Err(e) = save_credentials(&all) {
            eprintln!("ikigai passkey: could not persist the advanced signature counter: {e}");
        }
    }
    Ok(())
}

// =====================================================================================
// urn:passkey:challenge — hand the browser a fresh challenge + the registered ids.
// =====================================================================================

/// Issues the JSON a `navigator.credentials.get()` needs: a fresh challenge, the RP id, and the
/// credential ids to allow. Empty `allowCredentials` (nothing enrolled) tells the page to submit
/// without a ceremony — the gate is inert then anyway.
pub struct PasskeyChallenge;

#[async_trait::async_trait]
impl Endpoint for PasskeyChallenge {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        // The same fail-closed reading as the gate: a broken store or a missing relying party
        // with credentials enrolled is an error the page shows, not "nothing enrolled" (which
        // would tell the page to submit token-only into a gate that will refuse it anyway).
        let unavailable = || Error::Endpoint("passkey sign-in is unavailable on this edge".into());
        // Under the lock like every load, so the permission check sees one state of the file. A
        // block, so the (non-`Send`) guard is gone before anything else in this future runs.
        let loaded = {
            let held = credential_lock();
            load_credentials(&held)
        };
        let creds = loaded.map_err(|detail| {
            store_unreadable(&detail);
            unavailable()
        })?;
        let rp = relying_party();
        if rp.is_none() && !creds.is_empty() {
            eprintln!(
                "ikigai passkey: a credential is enrolled but this edge has no relying party \
                 configured (start it with `--passkey-rp-id <domain>`)."
            );
            return Err(unavailable());
        }
        let challenge = issue_challenge()?;
        let allow: Vec<_> = creds
            .into_iter()
            .map(|c| json!({ "type": "public-key", "id": c.id }))
            .collect();
        let body = json!({
            "challenge": challenge,
            "rpId": rp.as_ref().map(RelyingParty::rp_id),
            "allowCredentials": allow,
            "userVerification": "preferred",
            "enrolled": !allow.is_empty(),
        });
        Ok(Representation::new(
            ReprType::new("application/json").with_param("charset", "utf-8"),
            serde_json::to_vec(&body).expect("serializable").to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-challenge"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-challenge")
            .title("Issue a WebAuthn challenge")
            .summary("A fresh single-use challenge plus the registered credential ids, for a login ceremony.")
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint a challenge")
                    .output("application/json; charset=utf-8")
                    .requires(CAP_PASSKEY_CHALLENGE),
            )
            .output("application/json; charset=utf-8")
    }
}

// =====================================================================================
// urn:passkey:enroll-open — open a short enrollment window (run from the box).
// =====================================================================================

/// Opens a brief window during which one credential may register, and answers with the window's
/// one-time code. Cap-gated so only a human at the box can open it; the code goes back to that
/// human (their terminal) and nowhere else. The first registration spends the window.
pub struct PasskeyEnrollOpen;

#[async_trait::async_trait]
impl Endpoint for PasskeyEnrollOpen {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_PASSKEY_ENROLL) {
            return Err(Error::Denied(format!(
                "opening enrollment requires `{CAP_PASSKEY_ENROLL}`"
            )));
        }
        let code = enrollment_code()?;
        let window = EnrollWindow {
            until: now_secs() + ENROLL_WINDOW_SECONDS,
            code_sha256: code_digest(&code),
            spent: false,
        };
        // Owner-only and whole (ledger #850): `fs::write` left it 0664 under umask 002, and a
        // window that expires unused stays on disk, where anyone who can write it reopens it.
        write_window(&window)
            .map_err(|e| Error::Endpoint(format!("cannot open the enrollment window: {e}")))?;
        // The event goes to the log; the code does not (only the person who opened it has it).
        eprintln!(
            "ikigai passkey: enrollment window opened for {ENROLL_WINDOW_SECONDS}s (one \
             registration, by one-time code)"
        );
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!(
                "enrollment open for {ENROLL_WINDOW_SECONDS}s, for ONE passkey\n\
                 one-time code: {code}\n\
                 enter it on the register page (/passkey/register) before you create the \
                 passkey; it is shown only here\n"
            )
            .into_bytes(),
        ))
    }
    fn name(&self) -> &str {
        "passkey-enroll-open"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-enroll-open")
            .title("Open a passkey enrollment window")
            .summary("Opens a short window during which one passkey may be registered, and answers with the one-time code the registration must carry. Run from the box.")
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("open the window")
                    .output("text/plain; charset=utf-8")
                    .requires(CAP_PASSKEY_ENROLL),
            )
            .output("text/plain; charset=utf-8")
    }
}

/// An enrollment window as the box wrote it: when it closes, the SHA-256 of its one-time code
/// (never the code), and whether its one registration has happened.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EnrollWindow {
    until: i64,
    code_sha256: String,
    #[serde(default)]
    spent: bool,
}

/// What a registration finds when it looks at the window.
#[derive(Debug, PartialEq, Eq)]
enum WindowState {
    /// No window, an expired one, or one that is not trusted or not understood.
    Closed,
    /// Live, and its one registration has already happened.
    Spent,
    /// Live and unused.
    Open(EnrollWindow),
}

/// The window, judged. Fails CLOSED (ledger #850): the window file is judged with the credential
/// store's rule, and its directory with [`guard_directory`], so a file someone else could have
/// written or a workspace others can write keeps enrollment closed (said once per check on
/// stderr), never open. A file this version cannot read as a window (a bare timestamp, written
/// by an ikigai older than the one-time code) is closed too: it has no code to check against.
fn window_state() -> WindowState {
    match enroll_window() {
        Ok(Some(w)) if w.until > now_secs() => {
            if w.spent {
                WindowState::Spent
            } else {
                WindowState::Open(w)
            }
        }
        Ok(_) => WindowState::Closed,
        Err(detail) => {
            eprintln!("ikigai passkey: enrollment stays CLOSED: {detail}");
            WindowState::Closed
        }
    }
}

/// Whether an unused window opened at the box is live.
#[cfg(test)]
fn enrollment_open() -> bool {
    matches!(window_state(), WindowState::Open(_))
}

/// The window as written, `Ok(None)` when no window file exists or it does not parse as one
/// (a closed window), and `Err` naming the file or directory when it is not trusted.
fn enroll_window() -> std::result::Result<Option<EnrollWindow>, String> {
    use std::io::Read;
    let path = enroll_window_path();
    let p = path.display();
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{p} is present but unreadable: {e}")),
    };
    guard_directory(&store_root())?;
    // On the handle: what is judged is what is read. Readable-only is tightened; a file someone
    // else could have written is refused and left as it is, because its timestamp is theirs.
    guard_permissions(&path, &file, Remedy::Remove)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("{p} is present but unreadable: {e}"))?;
    match serde_json::from_str::<EnrollWindow>(text.trim()) {
        Ok(w) => Ok(Some(w)),
        Err(_) => {
            eprintln!(
                "ikigai passkey: {p} is not an enrollment window this version opened (it has no \
                 one-time code), so enrollment stays closed; open a new one with \
                 `sink urn:passkey:enroll-open`"
            );
            Ok(None)
        }
    }
}

fn write_window(window: &EnrollWindow) -> std::io::Result<()> {
    let json = serde_json::to_vec(window).map_err(std::io::Error::other)?;
    write_atomic(&enroll_window_path(), &json)
}

/// The alphabet of an enrollment code: Crockford's base 32 (no I, L, O or U), so it reads aloud
/// and types without ambiguity. 32 symbols, so one random byte masked to five bits is unbiased.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Symbols in a code: 16 × 5 bits = 80 bits, far past guessing inside one short window.
const CODE_SYMBOLS: usize = 16;

/// A fresh one-time enrollment code, `XXXX-XXXX-XXXX-XXXX`.
fn enrollment_code() -> Result<String> {
    let mut raw = [0u8; CODE_SYMBOLS];
    getrandom::getrandom(&mut raw)
        .map_err(|e| Error::Endpoint(format!("no OS randomness for an enrollment code: {e}")))?;
    let mut code = String::with_capacity(CODE_SYMBOLS + CODE_SYMBOLS / 4);
    for (i, byte) in raw.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        code.push(CODE_ALPHABET[usize::from(byte & 31)] as char);
    }
    Ok(code)
}

/// A code as typed, in the one spelling that is hashed: separators and spaces dropped, upper
/// case, and Crockford's look-alikes read as the digits they stand for (O → 0, I and L → 1).
///
/// ```text
/// "abcd-efgh ijkm-np0q"  →  "ABCDEFGH1JKMNP0Q"
/// ```
fn normalize_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// The lowercase hex SHA-256 of a code's normalized spelling: what the window file holds.
fn code_digest(code: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(normalize_code(code).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A short, non-secret handle for a credential id in a log line.
fn id_for_log(id_b64: &str) -> String {
    let head: String = id_b64.chars().take(12).collect();
    if head.len() < id_b64.len() {
        format!("{head}…")
    } else {
        head
    }
}

// =====================================================================================
// urn:passkey:register — GET shows the enrol page, POST stores the credential.
// =====================================================================================

/// The enrollment endpoint. GET renders the registration page (the glue-JS runs the WebAuthn
/// create ceremony); POST accepts `{code, id, spki}` — the window's one-time code as the box
/// printed it, and base64url of the credentialId and the SPKI public key — and stores the key, but
/// only while a window opened at the box is live and unused, and only with that window's code.
/// The first registration spends the window. A wrong code does NOT spend it: at 80 bits it cannot
/// be guessed inside the window, and spending on a wrong guess would let any passer-by close the
/// window on the person at the box.
pub struct PasskeyRegister;

#[async_trait::async_trait]
impl Endpoint for PasskeyRegister {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        match inv.request.verb {
            Verb::Source => {
                if relying_party().is_none() {
                    return Ok(page("Passkeys are not configured", NOT_CONFIGURED_BODY));
                }
                match window_state() {
                    WindowState::Open(_) => Ok(page("Register a passkey", REGISTER_PAGE_BODY)),
                    WindowState::Spent => Ok(page(
                        "Enrollment window used",
                        "<p>This window's one registration has happened. To register another \
                         passkey, open a new window at the box: <code>ikigai -c 'sink \
                         urn:passkey:enroll-open'</code>, then reload.</p>",
                    )),
                    WindowState::Closed => Ok(page(
                        "Enrollment closed",
                        "<p>Open a window at the box first: <code>ikigai -c 'sink \
                         urn:passkey:enroll-open'</code>, then reload.</p>",
                    )),
                }
            }
            Verb::Sink => {
                // Registering binds a credential to a relying party; with none configured there
                // is nothing correct to bind it to (the old default silently chose production).
                if relying_party().is_none() {
                    return Err(Error::Denied(
                        "this edge has no passkey relying party configured".to_string(),
                    ));
                }
                // ONE lock from judging the window to spending it, so two registrations in one
                // window cannot both see it unused (ledger #1689: before this, concurrent POSTs
                // inside one window all stored).
                let held = credential_lock();
                let window = match window_state() {
                    WindowState::Open(window) => window,
                    WindowState::Spent => {
                        eprintln!(
                            "ikigai passkey: REFUSED a registration: this enrollment window's \
                             one registration has already happened"
                        );
                        return Err(Error::Denied(
                            "this enrollment window has already been used — open a new one at \
                             the box"
                                .to_string(),
                        ));
                    }
                    WindowState::Closed => {
                        return Err(Error::Denied(
                            "no enrollment window is open — open one at the box first".to_string(),
                        ));
                    }
                };
                // The proof the enroller saw what only the person at the box has. Checked before
                // anything else in the request is looked at, and refused with one sentence
                // whether it is missing or wrong.
                let code = param(inv, "code")?;
                if code.is_empty() || code_digest(&code) != window.code_sha256 {
                    eprintln!(
                        "ikigai passkey: REFUSED a registration: {} enrollment code",
                        if code.is_empty() { "no" } else { "a wrong" }
                    );
                    return Err(Error::Denied(
                        "a registration needs the one-time code shown at the box when the \
                         window was opened"
                            .to_string(),
                    ));
                }
                let (id_b64, spki_b64) = (param(inv, "id")?, param(inv, "spki")?);
                if id_b64.is_empty() || spki_b64.is_empty() {
                    return Err(Error::InvalidArgument {
                        name: "id/spki".to_string(),
                        detail: "both the credential id and the SPKI public key are required"
                            .to_string(),
                    });
                }
                // Validate the key parses as an ES256 SPKI before we trust it.
                let spki = b64()
                    .decode(&spki_b64)
                    .map_err(|_| Error::InvalidArgument {
                        name: "spki".to_string(),
                        detail: "not base64url".to_string(),
                    })?;
                ikigai_passkey::RegisteredCredential::from_spki_der(b"probe".to_vec(), &spki, 0)
                    .map_err(|e| Error::InvalidArgument {
                        name: "spki".to_string(),
                        detail: format!("not a usable public key: {e}"),
                    })?;

                // A store that is present but unreadable (or that someone else could have
                // written) is not overwritten from the public face: the person at the box
                // repairs or removes it, then enrolls again.
                let mut creds = load_credentials(&held).map_err(|detail| {
                    store_unreadable(&detail);
                    Error::Endpoint(
                        "the passkey store on this edge is unreadable; repair or remove it at \
                         the box, then enroll again"
                            .to_string(),
                    )
                })?;
                // Spend the window BEFORE storing: if the store write then fails, the window is
                // closed and the person at the box opens a new one (fail closed), rather than a
                // stored credential leaving a window open for a second one.
                write_window(&EnrollWindow {
                    spent: true,
                    ..window
                })
                .map_err(|e| Error::Endpoint(format!("cannot close the enrollment window: {e}")))?;
                let logged = id_for_log(&id_b64);
                // Replace any existing entry with this id rather than duplicate it.
                creds.retain(|c| c.id != id_b64);
                creds.push(StoredCredential {
                    id: id_b64,
                    spki: spki_b64,
                    sign_count: 0,
                });
                save_credentials(&creds)?;
                eprintln!(
                    "ikigai passkey: ENROLLED credential {logged} with the window's one-time \
                     code; the window is spent"
                );
                Ok(page(
                    "Passkey registered",
                    "<p>Done. Decision links now ask for your passkey before they act.</p>",
                ))
            }
            other => Err(Error::Endpoint(format!(
                "register is GET to show or POST to store, not {other:?}"
            ))),
        }
    }
    fn name(&self) -> &str {
        "passkey-register"
    }
    fn describe(&self) -> Description {
        Description::new("passkey-register")
            .title("Register a passkey")
            .summary("GET shows the enrolment page; POST stores a credential while an enrollment window is open, given the window's one-time code.")
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("show the enrolment page")
                    .output("text/html; charset=utf-8")
                    .requires(CAP_PASSKEY_REGISTER),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("store a credential (needs an open window and its one-time code)")
                    .output("text/html; charset=utf-8")
                    .requires(CAP_PASSKEY_REGISTER),
            )
            .output("text/html; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey;
    use sha2::{Digest, Sha256};

    thread_local! {
        static TEST_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
        static TEST_RP: std::cell::RefCell<Option<RelyingParty>> =
            const { std::cell::RefCell::new(None) };
        static TEST_CHALLENGES: std::cell::Cell<&'static Mutex<Challenges>> =
            std::cell::Cell::new(Box::leak(Box::new(Mutex::new(Challenges::default()))));
        static TEST_MAX_CHALLENGES: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
    }

    /// This thread's challenge store (one leaked per test thread; see `challenges`). A test
    /// that runs part of a ceremony on a second thread hands it this one.
    pub(super) fn test_challenges() -> &'static Mutex<Challenges> {
        TEST_CHALLENGES.with(std::cell::Cell::get)
    }

    /// This thread's override of the challenge bound, if a test set one.
    pub(super) fn test_max_challenges() -> Option<usize> {
        TEST_MAX_CHALLENGES.with(std::cell::Cell::get)
    }

    /// The current thread's override root, if a test set one. `store_root()` consults this.
    pub(super) fn test_root() -> Option<std::path::PathBuf> {
        TEST_ROOT.with(|r| r.borrow().clone())
    }

    /// The current thread's relying party. `relying_party()` reads ONLY this under test, so the
    /// unconfigured case is reachable without racing the configured tests.
    pub(super) fn test_rp() -> Option<RelyingParty> {
        TEST_RP.with(|r| r.borrow().clone())
    }

    /// Ledger #1624 (ACCESSIBILITY.md, WCAG 4.1.3): the line the ceremony script writes its
    /// progress and failures into is a polite live region, and it is in the SERVED markup, ahead
    /// of the script, so it exists before any message is set: a screen reader announces a change
    /// to a region it already knows, not one inserted with its text.
    #[test]
    fn the_passkey_status_lines_are_live_regions_present_before_the_script() {
        for (id, html) in [
            ("pkstatus", DECISION_PASSKEY_JS),
            ("status", REGISTER_PAGE_BODY),
        ] {
            let open = format!("<p id={id} role=status aria-live=polite");
            let at = html
                .find(&open)
                .unwrap_or_else(|| panic!("#{id} is a live region: {html}"));
            let script = html.find("<script").expect("the ceremony script");
            assert!(at < script, "#{id} precedes the script: {html}");
            // And it is the element the script writes into: the region and the messages agree.
            assert!(
                PASSKEY_APP_JS.contains(&format!("document.getElementById('{id}')")),
                "the script writes #{id}"
            );
        }
    }

    /// Ledger #1834: the passkey pages' bodies carry no inline style (their look is the shell's
    /// linked stylesheet), so they render under an HTML door's `style-src 'self'` CSP.
    #[test]
    fn the_passkey_bodies_carry_no_inline_style() {
        for html in [DECISION_PASSKEY_JS, REGISTER_PAGE_BODY, NOT_CONFIGURED_BODY] {
            crate::decide::assert_no_inline_style(html);
        }
        // The classes they use are the stylesheet's.
        assert!(REGISTER_PAGE_BODY.contains("class=field"));
        assert!(DECISION_PASSKEY_JS.contains("class=muted"));
    }

    const RP_ID: &str = "edge.test";
    const ORIGIN: &str = "https://edge.test";

    fn test_relying_party() -> RelyingParty {
        RelyingParty::new(RP_ID, None).unwrap()
    }

    fn unconfigure() {
        TEST_RP.with(|r| *r.borrow_mut() = None);
    }

    // Give this test its own workspace root — set on THIS thread only, so parallel tests never
    // collide on the credential/window files (a global env var would race across them) — and a
    // configured relying party, which a test that wants none removes with `unconfigure`.
    fn isolate(name: &str) {
        let dir =
            std::env::temp_dir().join(format!("ikigai-passkey-ep-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Private whatever the umask: a workspace others can write is refused (ledger #850).
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        TEST_ROOT.with(|r| *r.borrow_mut() = Some(dir));
        TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
    }

    /// A stand-in authenticator: a fixed P-256 key that signs assertions as a device would.
    struct Device {
        key: SigningKey,
    }
    impl Device {
        fn new() -> Self {
            Self {
                key: SigningKey::from_slice(&[0x33u8; 32]).unwrap(),
            }
        }
        fn spki_b64(&self) -> String {
            let der = VerifyingKey::from(&self.key).to_public_key_der().unwrap();
            b64().encode(der.as_bytes())
        }
        fn register(&self) {
            let creds = vec![StoredCredential {
                id: b64().encode(b"cred-1"),
                spki: self.spki_b64(),
                sign_count: 0,
            }];
            save_credentials(&creds).unwrap();
        }
        /// Build the four base64url fields for a POST body, over the given challenge. `count` is
        /// the signature counter — a real authenticator advances it every assertion.
        fn assert_fields(&self, challenge: &str, flags: u8, count: u32) -> String {
            let client = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#
            )
            .into_bytes();
            let mut auth = Sha256::digest(RP_ID.as_bytes()).to_vec();
            auth.push(flags);
            auth.extend_from_slice(&count.to_be_bytes());
            let mut msg = auth.clone();
            msg.extend_from_slice(&Sha256::digest(&client));
            let sig: Signature = self.key.sign(&msg);
            format!(
                "pk_id={}&pk_auth={}&pk_client={}&pk_sig={}",
                b64().encode(b"cred-1"),
                b64().encode(&auth),
                b64().encode(&client),
                b64().encode(sig.to_der().as_bytes()),
            )
        }
    }

    /// A minimal invocation carrying a urlencoded body as `content` (how a POST arrives).
    fn post_inv(body: &str) -> (Kernel, Request) {
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new()));
        let req = Request::new(Verb::Sink, Iri::parse("urn:x").unwrap())
            .with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()));
        (kernel, req)
    }

    fn run_gate(body: &str) -> Result<()> {
        // require_passkey only reads params off the invocation; drive it through a tiny endpoint.
        struct Gate;
        #[async_trait::async_trait]
        impl Endpoint for Gate {
            async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
                require_passkey(inv)?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            }
            fn name(&self) -> &str {
                "gate"
            }
            fn describe(&self) -> Description {
                Description::new("gate").verb(Verb::Sink)
            }
        }
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new("urn:x"), Gate),
        ));
        let (_k, req) = post_inv(body);
        futures::executor::block_on(kernel.issue(req, &Capability::root())).map(|_| ())
    }

    #[test]
    fn the_gate_is_inert_until_a_credential_is_enrolled() {
        isolate("inert");
        // No credential file: any POST — even one with no passkey fields — passes.
        assert!(run_gate("id=abc&exp=1").is_ok());
    }

    #[test]
    fn a_valid_assertion_passes_the_gate_and_a_forged_one_does_not() {
        isolate("valid");
        let d = Device::new();
        d.register();
        let challenge = issue_challenge().unwrap();
        let body = d.assert_fields(&challenge, 0x05, 1); // UP | UV, counter 1
        assert!(run_gate(&body).is_ok(), "a valid assertion should pass");

        // A second ceremony (fresh challenge, advanced counter) also passes...
        let challenge2 = issue_challenge().unwrap();
        let good = d.assert_fields(&challenge2, 0x05, 2);
        assert!(run_gate(&good).is_ok());
        // ...but replaying that exact assertion is refused — the challenge was consumed.
        assert!(run_gate(&good).is_err(), "the challenge is single-use");
    }

    #[test]
    fn an_enrolled_gate_refuses_a_post_with_no_assertion() {
        isolate("missing");
        Device::new().register();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "enrolled + no passkey = refused"
        );
    }

    #[test]
    fn a_forged_signature_is_refused() {
        isolate("forged");
        let real = Device::new();
        real.register();
        // A different key signs, but the assertion claims the registered credential id.
        let imposter = Device {
            key: SigningKey::from_slice(&[0x44u8; 32]).unwrap(),
        };
        let challenge = issue_challenge().unwrap();
        let body = imposter.assert_fields(&challenge, 0x05, 1);
        assert!(
            run_gate(&body).is_err(),
            "a foreign signature must be refused"
        );
    }

    #[test]
    fn a_never_issued_challenge_is_refused() {
        isolate("nochallenge");
        let d = Device::new();
        d.register();
        // Craft an assertion over a challenge that was never issued here.
        let body = d.assert_fields("bmV2ZXItaXNzdWVk", 0x05, 1);
        assert!(
            run_gate(&body).is_err(),
            "an unissued challenge must be refused"
        );
    }

    #[test]
    fn challenges_are_single_use_and_expire() {
        isolate("challenge");
        let c = issue_challenge().unwrap();
        assert!(consume_challenge(&c), "a fresh challenge consumes once");
        assert!(!consume_challenge(&c), "and not twice");
        assert!(
            !consume_challenge("never-issued"),
            "unknown challenge is refused"
        );
    }

    thread_local! {
        static AFTER_VERIFY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The seam between a successful verification and the counter write-back: a test parks a
    /// closure here to interleave a second request at exactly the point the race lives.
    pub(super) fn after_verify() {
        if let Some(hook) = AFTER_VERIFY.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    fn stored_count() -> u32 {
        let bytes = std::fs::read(credentials_path()).unwrap();
        let creds: Vec<StoredCredential> = serde_json::from_slice(&bytes).unwrap();
        creds[0].sign_count
    }

    #[test]
    fn a_corrupt_credential_file_fails_closed() {
        isolate("corrupt");
        Device::new().register();
        // Truncate the store mid-document, as a crash during a non-atomic write would.
        let full = std::fs::read(credentials_path()).unwrap();
        std::fs::write(credentials_path(), &full[..full.len() / 2]).unwrap();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "a present but unparsable credential store must refuse, not read as `not enrolled`"
        );
        // An empty (zero-byte) file is present too: still refused.
        std::fs::write(credentials_path(), b"").unwrap();
        assert!(
            run_gate("id=abc&exp=1").is_err(),
            "a zero-byte store refuses"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_credential_write_replaces_the_file_rather_than_rewriting_it_in_place() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        isolate("atomic");
        let d = Device::new();
        d.register();
        let before = std::fs::metadata(credentials_path()).unwrap().ino();
        d.register();
        let meta = std::fs::metadata(credentials_path()).unwrap();
        // An in-place write (truncate, then write) keeps the inode, so a reader or a crash
        // between the two sees a truncated file. Temp + rename swaps in a new inode whole.
        assert_ne!(
            before,
            meta.ino(),
            "the store must be replaced by rename, not truncated and rewritten in place"
        );
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "owner-only");
        // And no temp file is left behind beside it.
        let leftovers: Vec<_> = std::fs::read_dir(store_root())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "passkey-credentials.json")
            .collect();
        assert!(leftovers.is_empty(), "stray files: {leftovers:?}");
    }

    #[cfg(unix)]
    fn set_mode(mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(credentials_path(), std::fs::Permissions::from_mode(mode))
            .unwrap();
    }

    #[cfg(unix)]
    fn mode() -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(credentials_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// Ledger #828, the reproduction: a file enrolled under 0.1.38 (`fs::write`, umask 002) is
    /// 0664, and a platform passkey keeps its counter at 0, so the 0600 atomic save never runs.
    /// Before the fix the gate trusted that file and left it 0664 for good; this test asserted
    /// exactly that against 0.1.39 and passed, then failed once the check landed.
    #[cfg(unix)]
    #[test]
    fn a_group_writable_store_refuses_every_face_and_is_left_for_a_person_to_check() {
        isolate("loose-writable");
        let d = Device::new();
        d.register();
        set_mode(0o664);
        let challenge = issue_challenge().unwrap();
        let body = d.assert_fields(&challenge, 0x05, 0); // a platform passkey: counter stays 0
        assert!(
            run_gate(&body).is_err(),
            "a store others could have written is not trusted, even with a valid assertion"
        );
        assert!(
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None
            )
            .is_err(),
            "the challenge refuses too"
        );
        open_window();
        let reg = format!(
            "id={}&spki={}",
            b64().encode(b"cred-2"),
            Device::new().spki_b64()
        );
        assert!(
            call(
                "urn:passkey:register",
                PasskeyRegister,
                Verb::Sink,
                Some(&reg)
            )
            .is_err(),
            "registration does not launder a store someone else could have written"
        );
        assert!(is_enrolled(), "an untrusted store counts as armed");
        assert!(preflight().is_err(), "and a serving door refuses to start");
        // Not silently fixed: tightening would trust whatever someone else wrote.
        assert_eq!(mode(), 0o664);
        let detail = {
            let held = credential_lock();
            load_credentials(&held).err().unwrap()
        };
        let path = credentials_path();
        assert!(
            detail.contains(&format!("`chmod 600 {}`", path.display())),
            "the refusal names the exact fix: {detail}"
        );
        assert!(detail.contains("0664"), "and the mode it found: {detail}");

        // World-writable alone is refused the same way.
        set_mode(0o602);
        assert!(preflight().is_err());

        // Once the person at the box has fixed it, the very same assertion's successor passes.
        set_mode(0o600);
        let challenge = issue_challenge().unwrap();
        assert!(run_gate(&d.assert_fields(&challenge, 0x05, 0)).is_ok());
        assert!(preflight().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_store_others_can_only_read_is_tightened_on_load() {
        isolate("loose-readable");
        let d = Device::new();
        d.register();
        set_mode(0o644);
        let challenge = issue_challenge().unwrap();
        assert!(
            run_gate(&d.assert_fields(&challenge, 0x05, 0)).is_ok(),
            "readable-only discloses public keys and nothing else: the gate keeps working"
        );
        assert_eq!(mode(), 0o600, "a counter-0 sign-in tightened it");

        // Every other load path tightens as well.
        set_mode(0o640);
        assert!(call(
            "urn:passkey:challenge",
            PasskeyChallenge,
            Verb::Source,
            None
        )
        .is_ok());
        assert_eq!(mode(), 0o600, "the challenge tightened it");
        set_mode(0o604);
        assert!(preflight().is_ok());
        assert_eq!(mode(), 0o600, "startup tightened it");
        set_mode(0o644);
        assert!(is_enrolled());
        assert_eq!(mode(), 0o600, "is_enrolled tightened it");
    }

    #[test]
    fn permissions_are_judged_on_writers_first_then_readers() {
        let me = 501;
        assert_eq!(judge_permissions(0o100600, me, me), Permission::Private);
        assert_eq!(judge_permissions(0o100400, me, me), Permission::Private);
        // Owner execute or setuid-style bits are not about who else can write.
        assert_eq!(judge_permissions(0o100700, me, me), Permission::Private);
        for readable in [0o100640, 0o100604, 0o100644, 0o100440] {
            assert_eq!(
                judge_permissions(readable, me, me),
                Permission::Tighten,
                "{readable:o}"
            );
        }
        for writable in [0o100620, 0o100602, 0o100664, 0o100666, 0o100622] {
            assert!(
                matches!(judge_permissions(writable, me, me), Permission::Refuse(_)),
                "{writable:o}"
            );
        }
        // Another user's file is refused even at 0600: its owner can write it, and only a
        // swap through a writable directory (or a hand edit) puts one there.
        match judge_permissions(0o100600, 0, me) {
            Permission::Refuse(why) => assert!(why.contains("uid 0"), "{why}"),
            other => panic!("a foreign owner must refuse, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_store_passes_preflight() {
        isolate("preflight-absent");
        assert!(
            preflight().is_ok(),
            "not enrolled is not a reason to refuse to start"
        );
        assert!(
            !credentials_path().exists(),
            "and preflight creates nothing"
        );
    }

    #[test]
    fn interleaved_assertions_never_lower_the_stored_counter() {
        isolate("race");
        let root = test_root().unwrap();
        let store = test_challenges();
        let d = Device::new();
        d.register();
        let c_low = issue_challenge().unwrap();
        let c_high = issue_challenge().unwrap();
        let low = d.assert_fields(&c_low, 0x05, 2);
        let high = d.assert_fields(&c_high, 0x05, 3);

        // Request A (counter 2) has verified and is about to write back; request B (counter 3)
        // runs now on another thread. Without a lock B completes inside A's window and A then
        // writes its stale copy over B's; with one, B waits for A and loads A's result.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let b = std::sync::Arc::new(std::sync::Mutex::new(None));
        let b_slot = b.clone();
        AFTER_VERIFY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let handle = std::thread::spawn(move || {
                    TEST_ROOT.with(|r| *r.borrow_mut() = Some(root));
                    TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
                    TEST_CHALLENGES.with(|c| c.set(store));
                    let r = run_gate(&high);
                    let _ = done_tx.send(());
                    r
                });
                // Give B the chance to finish inside A's window (it cannot, under a lock).
                let _ = done_rx.recv_timeout(std::time::Duration::from_millis(300));
                *b_slot.lock().unwrap() = Some(handle);
            }))
        });
        assert!(run_gate(&low).is_ok(), "A's assertion is valid");
        let handle = b.lock().unwrap().take().expect("the hook ran");
        assert!(handle.join().unwrap().is_ok(), "B's assertion is valid");
        assert_eq!(
            stored_count(),
            3,
            "the stored counter must be the highest seen, never a stale write-back"
        );
    }

    /// Issue `verb` at `iri` against a kernel that binds only `endpoint` there.
    fn call(
        iri: &str,
        endpoint: impl Endpoint + 'static,
        verb: Verb,
        body: Option<&str>,
    ) -> Result<Representation> {
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new(iri), endpoint),
        ));
        let mut req = Request::new(verb, Iri::parse(iri).unwrap());
        if let Some(body) = body {
            req = req.with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()));
        }
        futures::executor::block_on(kernel.issue(req, &Capability::root()))
    }

    /// The code every test window is opened with, as the box would print it.
    const TEST_CODE: &str = "TEST-C0DE-AAAA-BBBB";

    fn open_window() {
        write_window(&EnrollWindow {
            until: now_secs() + 60,
            code_sha256: code_digest(TEST_CODE),
            spent: false,
        })
        .unwrap();
    }

    /// A registration body for credential `id` from the test device, with `code` (none if None).
    fn registration(id: &[u8], code: Option<&str>) -> String {
        let code = code.map(|c| format!("code={c}&")).unwrap_or_default();
        format!(
            "{code}id={}&spki={}",
            b64().encode(id),
            Device::new().spki_b64()
        )
    }

    #[test]
    fn a_corrupt_store_errors_the_challenge_and_is_not_overwritten_by_registration() {
        isolate("corrupt-faces");
        std::fs::write(credentials_path(), b"[{\"id\":").unwrap();
        assert!(
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None
            )
            .is_err(),
            "the page must not be told `not enrolled` and submit token-only"
        );
        open_window();
        let body = registration(b"cred-2", Some(TEST_CODE));
        assert!(
            call(
                "urn:passkey:register",
                PasskeyRegister,
                Verb::Sink,
                Some(&body)
            )
            .is_err(),
            "registration does not paper over a broken store from the public face"
        );
        assert_eq!(std::fs::read(credentials_path()).unwrap(), b"[{\"id\":");
        assert!(is_enrolled(), "a broken store counts as armed");
    }

    #[test]
    fn an_enrolled_gate_with_no_relying_party_refuses_everything() {
        isolate("no-rp-enrolled");
        let d = Device::new();
        d.register();
        let challenge = issue_challenge().unwrap();
        let body = d.assert_fields(&challenge, 0x05, 1);
        unconfigure();
        assert!(run_gate(&body).is_err(), "no RP to check against = refuse");
        assert!(
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None
            )
            .is_err(),
            "and the challenge says so rather than naming no RP"
        );
    }

    #[test]
    fn an_unconfigured_edge_with_nothing_enrolled_stays_inert() {
        isolate("no-rp-inert");
        unconfigure();
        assert!(
            run_gate("id=abc&exp=1").is_ok(),
            "deploying cannot brick the links"
        );
        let rep = call(
            "urn:passkey:challenge",
            PasskeyChallenge,
            Verb::Source,
            None,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&rep.bytes).unwrap();
        assert_eq!(v["enrolled"], false);
        assert!(
            v["rpId"].is_null(),
            "no RP is reported as none, never a default"
        );
    }

    #[test]
    fn registration_needs_a_relying_party() {
        isolate("no-rp-register");
        open_window();
        let body = registration(b"cred-1", Some(TEST_CODE));
        unconfigure();
        assert!(
            call(
                "urn:passkey:register",
                PasskeyRegister,
                Verb::Sink,
                Some(&body)
            )
            .is_err(),
            "nothing to bind a credential to"
        );
        assert!(!credentials_path().exists());
        let page = call("urn:passkey:register", PasskeyRegister, Verb::Source, None).unwrap();
        assert!(String::from_utf8_lossy(&page.bytes).contains("--passkey-rp-id"));

        TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
        assert!(call(
            "urn:passkey:register",
            PasskeyRegister,
            Verb::Sink,
            Some(&body)
        )
        .is_ok());
        assert!(is_enrolled());
    }

    /// Ledger #1717: past the bound a new challenge is refused with a TRANSIENT error that says
    /// when to retry, and nothing outstanding is evicted to make room.
    #[test]
    fn past_the_bound_a_new_challenge_is_refused_and_none_is_evicted() {
        let mut store = Challenges::default();
        let t0 = monotonic_now();
        for n in 0..3 {
            store
                .issue(format!("c{n}"), t0 + Duration::from_secs(n), 3)
                .expect("under the bound");
        }
        let refused = store
            .issue("c3".into(), t0 + Duration::from_secs(10), 3)
            .expect_err("the fourth outstanding challenge is refused");
        assert!(refused.is_transient(), "a retry can succeed: {refused}");
        assert!(matches!(refused, Error::Unavailable(_)), "{refused:?}");
        // The soonest one (c0, issued at t0) frees a place at t0 + TTL: 110 s from t0 + 10.
        let wait = CHALLENGE_TTL.as_secs() - 10 + 1;
        assert!(
            refused
                .to_string()
                .contains(&format!("Try again in {wait}s")),
            "{refused}"
        );
        assert_eq!(store.live.len(), 3, "the refusal stored nothing");
        for n in 0..3 {
            assert!(
                store.consume(&format!("c{n}"), t0 + Duration::from_secs(11)),
                "c{n} was not evicted: an honest ceremony holding it still completes"
            );
        }
    }

    /// Expired challenges are reclaimed before the bound is judged, so a full store frees
    /// itself as its challenges age out, with no sweeper.
    #[test]
    fn expired_challenges_are_reclaimed_before_the_bound_is_judged() {
        let mut store = Challenges::default();
        let t0 = monotonic_now();
        store.issue("a".into(), t0, 2).unwrap();
        store
            .issue("b".into(), t0 + Duration::from_secs(60), 2)
            .unwrap();
        assert!(store
            .issue("c".into(), t0 + Duration::from_secs(61), 2)
            .is_err());
        // At t0 + TTL, `a` has expired: its place is free again, and only `a`'s.
        store.issue("c".into(), t0 + CHALLENGE_TTL, 2).unwrap();
        assert_eq!(store.live.len(), 2);
        assert!(
            !store.live.contains_key("a"),
            "the expired one was reclaimed"
        );
        assert!(store.issue("d".into(), t0 + CHALLENGE_TTL, 2).is_err());
    }

    /// The whole ceremony on a full store, through the endpoint and the gate: the challenge an
    /// honest device was handed before the flood still signs in; the flood's next read is
    /// refused at the endpoint (a 503 at the door: transient); and once the flood's challenges
    /// age out, a fresh read and sign-in work again.
    #[test]
    fn an_honest_ceremony_completes_on_a_full_store_and_the_endpoint_refuses_past_it() {
        isolate("bounded");
        TEST_MAX_CHALLENGES.with(|m| m.set(Some(8)));
        let d = Device::new();
        d.register();
        let read = || {
            call(
                "urn:passkey:challenge",
                PasskeyChallenge,
                Verb::Source,
                None,
            )
        };
        let challenge_of = |repr: Representation| -> String {
            let v: serde_json::Value = serde_json::from_slice(&repr.bytes).unwrap();
            v["challenge"].as_str().unwrap().to_string()
        };
        let honest = challenge_of(read().expect("an empty store issues"));
        // The flood: everything up to the bound is issued, and the next read is refused.
        for _ in 0..7 {
            read().expect("under the bound");
        }
        let refused = read().expect_err("the bound refuses the ninth");
        assert!(refused.is_transient(), "{refused}");
        // The honest device completes its sign-in with the challenge it already holds.
        assert!(
            run_gate(&d.assert_fields(&honest, 0x05, 1)).is_ok(),
            "an honest ceremony under way is not broken by the bound"
        );
        // Its place is free again, so the next honest read is served.
        let next = challenge_of(read().expect("a spent challenge frees its place"));
        assert!(run_gate(&d.assert_fields(&next, 0x05, 2)).is_ok());
        // And a store full of the flood's challenges frees itself once they expire.
        read().expect("the place the second sign-in spent");
        assert!(read().is_err(), "full again");
        let later = monotonic_now() + CHALLENGE_TTL;
        let after = issue_challenge_at(later).expect("expired entries are reclaimed");
        assert!(consume_challenge_at(&after, later));
        TEST_MAX_CHALLENGES.with(|m| m.set(None));
    }

    #[test]
    fn a_challenge_expires_on_the_monotonic_clock() {
        isolate("ttl");
        let t0 = monotonic_now();
        let fresh = issue_challenge_at(t0).unwrap();
        assert!(consume_challenge_at(
            &fresh,
            t0 + CHALLENGE_TTL - Duration::from_secs(1)
        ));
        let stale = issue_challenge_at(t0).unwrap();
        assert!(
            !consume_challenge_at(&stale, t0 + CHALLENGE_TTL),
            "a challenge is dead at its TTL"
        );
    }

    #[test]
    fn enrollment_window_gates_registration() {
        isolate("enroll");
        assert!(!enrollment_open(), "closed by default");
        // Opening requires the cap.
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new().bind(
            ikigai_core::Exact::new("urn:passkey:enroll-open"),
            PasskeyEnrollOpen,
        )));
        let open = |cap: &Capability| {
            futures::executor::block_on(kernel.issue(
                Request::new(Verb::Sink, Iri::parse("urn:passkey:enroll-open").unwrap()),
                cap,
            ))
        };
        assert!(
            open(&Capability::scoped(Vec::<String>::new())).is_err(),
            "no cap, no open"
        );
        assert!(open(&Capability::root()).is_ok(), "root opens it");
        assert!(enrollment_open(), "now open");
    }

    /// `urn:passkey:challenge` and `urn:passkey:register` DECLARE their capabilities, so the
    /// kernel's floor refuses a caller that holds neither, on any door that binds them, and the
    /// manifold offers them only to a caller that does. The edge's public HTTP face grants both
    /// in its ceiling; a door whose principals were never granted them cannot reach them.
    #[test]
    fn the_challenge_and_registration_declare_and_enforce_their_capabilities() {
        isolate("caps");
        TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
        open_window();
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new()
                .bind(
                    ikigai_core::Exact::new("urn:passkey:challenge"),
                    PasskeyChallenge,
                )
                .bind(
                    ikigai_core::Exact::new("urn:passkey:register"),
                    PasskeyRegister,
                ),
        ));
        let ask = |iri: &str, verb: Verb, cap: &Capability| {
            let mut req = Request::new(verb, Iri::parse(iri).unwrap());
            if verb == Verb::Sink {
                req = req.with_arg(
                    "content",
                    ArgRef::Inline(registration(b"cred-caps", Some(TEST_CODE)).into_bytes()),
                );
            }
            futures::executor::block_on(kernel.issue(req, cap))
        };
        let none = Capability::scoped(Vec::<String>::new());
        let wrong = Capability::scoped(["urn:cap:layer:say:talk"]);
        for (iri, verb, cap) in [
            ("urn:passkey:challenge", Verb::Source, CAP_PASSKEY_CHALLENGE),
            ("urn:passkey:register", Verb::Source, CAP_PASSKEY_REGISTER),
            ("urn:passkey:register", Verb::Sink, CAP_PASSKEY_REGISTER),
        ] {
            for held in [&none, &wrong] {
                match ask(iri, verb, held) {
                    Err(Error::Denied(why)) => {
                        assert!(why.contains(cap), "{iri} {verb:?} names `{cap}`: {why}")
                    }
                    other => panic!("{iri} {verb:?} without `{cap}` is denied, got {other:?}"),
                }
            }
        }
        assert!(!is_enrolled(), "nothing enrolled without the grant");
        // Granted, each works as before.
        let challenge = ask(
            "urn:passkey:challenge",
            Verb::Source,
            &Capability::scoped([CAP_PASSKEY_CHALLENGE]),
        )
        .expect("granted, a challenge");
        assert!(String::from_utf8_lossy(&challenge.bytes).contains("\"challenge\""));
        let register = Capability::scoped([CAP_PASSKEY_REGISTER]);
        ask("urn:passkey:register", Verb::Source, &register).expect("granted, the page");
        ask("urn:passkey:register", Verb::Sink, &register).expect("granted, it enrolls");
        assert!(is_enrolled());
    }

    #[cfg(unix)]
    fn chmod(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Whether a registration through the PUBLIC face (no enroll capability) stored anything.
    /// It carries the window's RIGHT code, so a refusal is the file or directory check's and
    /// not the code's.
    fn public_registration_succeeds() -> bool {
        let reg = registration(b"intruder", Some(TEST_CODE));
        call(
            "urn:passkey:register",
            PasskeyRegister,
            Verb::Sink,
            Some(&reg),
        )
        .is_ok()
    }

    /// ★ Ledger #850, the reproduction. `urn:passkey:enroll-open` wrote the window file with
    /// `fs::write`, so under umask 002 it is 0664, and a window that expires unused leaves it
    /// behind. Anyone in the group can then write a future timestamp into it and register a
    /// credential through the public face, without `urn:cap:passkey:enroll`. On main this test
    /// failed at its first assertion: `enrollment_open()` read the file with no mode check.
    #[cfg(unix)]
    #[test]
    fn an_enroll_file_others_could_have_written_keeps_enrollment_closed() {
        isolate("enroll-writable");
        for loose in [0o664, 0o602, 0o620] {
            open_window();
            chmod(&enroll_window_path(), loose);
            assert!(
                !enrollment_open(),
                "a window file others could have written is not a window ({loose:o})"
            );
            assert!(
                !public_registration_succeeds(),
                "nothing registers through it ({loose:o})"
            );
            assert!(!is_enrolled(), "and nothing was stored ({loose:o})");
            // Not silently fixed: tightening it would trust a timestamp someone else wrote.
            assert_eq!(mode_of(&enroll_window_path()), loose);
        }
        let refusal = enroll_window().expect_err("an untrusted window is an error, not absence");
        assert!(
            refusal.contains(&format!("`rm {}`", enroll_window_path().display())),
            "the refusal says to remove it, never to chmod a planted timestamp: {refusal}"
        );
        // Once fixed at the box, the same file is a window again.
        chmod(&enroll_window_path(), 0o600);
        assert!(enrollment_open());
    }

    #[test]
    fn the_workspace_directory_is_judged_on_writers_and_its_owner() {
        let me = 501;
        for private in [0o40700, 0o40755, 0o40750, 0o40711] {
            assert_eq!(judge_directory(private, me, me), None, "{private:o}");
        }
        for writable in [0o40775, 0o40770, 0o40757, 0o41777, 0o40730] {
            assert!(judge_directory(writable, me, me).is_some(), "{writable:o}");
        }
        let why = judge_directory(0o40700, 0, me).expect("a foreign owner refuses");
        assert!(why.contains("uid 0"), "{why}");
    }

    /// The other half of #850: a workspace DIRECTORY others can write lets them create or swap
    /// any file in it, so nothing in it is trusted: not the window, not the credential store.
    #[cfg(unix)]
    #[test]
    fn a_workspace_others_can_write_trusts_nothing_in_it() {
        isolate("workspace-writable");
        let root = test_root().unwrap();
        let d = Device::new();
        d.register();
        open_window();
        chmod(&root, 0o775);
        assert!(!enrollment_open(), "the window is not trusted");
        assert!(!public_registration_succeeds(), "so nothing registers");
        let challenge = issue_challenge().unwrap();
        assert!(
            run_gate(&d.assert_fields(&challenge, 0x05, 0)).is_err(),
            "the store in it is not trusted either, even with a valid assertion"
        );
        assert!(is_enrolled(), "an untrusted store counts as armed");
        let refusal = preflight().expect_err("a serving door refuses to start");
        assert!(
            refusal.contains(&root.display().to_string()) && refusal.contains("0775"),
            "the refusal names the directory and its mode: {refusal}"
        );
        assert!(
            refusal.contains(&format!("`chmod go-w {}`", root.display())),
            "and the exact fix: {refusal}"
        );
        // World-writable, sticky or not, is refused the same way.
        chmod(&root, 0o1777);
        assert!(preflight().is_err());
        assert!(!enrollment_open());

        // Once a person at the box has fixed the directory, everything in it is trusted again.
        chmod(&root, 0o755);
        assert!(preflight().is_ok());
        assert!(enrollment_open());
        let challenge = issue_challenge().unwrap();
        assert!(run_gate(&d.assert_fields(&challenge, 0x05, 0)).is_ok());
    }

    /// A window file others can only read discloses a timestamp: it is tightened, not refused.
    #[cfg(unix)]
    #[test]
    fn an_enroll_file_others_can_only_read_is_tightened() {
        isolate("enroll-readable");
        open_window();
        chmod(&enroll_window_path(), 0o644);
        assert!(enrollment_open());
        assert_eq!(mode_of(&enroll_window_path()), 0o600);
    }

    /// Opening a window writes it owner-only, whatever the umask, so a window that expires
    /// unused never leaves behind a file others could reopen.
    #[cfg(unix)]
    #[test]
    fn opening_a_window_writes_it_owner_only() {
        isolate("enroll-mode");
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new().bind(
            ikigai_core::Exact::new("urn:passkey:enroll-open"),
            PasskeyEnrollOpen,
        )));
        futures::executor::block_on(kernel.issue(
            Request::new(Verb::Sink, Iri::parse("urn:passkey:enroll-open").unwrap()),
            &Capability::root(),
        ))
        .unwrap();
        assert_eq!(mode_of(&enroll_window_path()), 0o600);
        assert!(enrollment_open());
    }

    // ---------------------------------------------------------------------------------
    // Ledger #1689: the one-time enrollment code.
    // ---------------------------------------------------------------------------------

    /// The ids of the credentials stored, in order.
    fn stored_ids() -> Vec<String> {
        match std::fs::read(credentials_path()) {
            Ok(bytes) => serde_json::from_slice::<Vec<StoredCredential>>(&bytes)
                .unwrap()
                .into_iter()
                .map(|c| c.id)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn register_with(body: &str) -> Result<Representation> {
        call(
            "urn:passkey:register",
            PasskeyRegister,
            Verb::Sink,
            Some(body),
        )
    }

    fn denied_with(outcome: Result<Representation>, needle: &str) {
        match outcome {
            Err(Error::Denied(message)) => assert!(
                message.contains(needle),
                "refused, naming `{needle}`: {message}"
            ),
            other => panic!("expected a Denied naming `{needle}`, got {other:?}"),
        }
    }

    /// ★ Ledger #1689, the reproduction: an anonymous POST of `{id, spki}` with no code, during
    /// an open window, used to be stored. It is refused, nothing is stored, and the window stays
    /// open for the person at the box.
    #[test]
    fn a_registration_without_the_code_is_refused() {
        isolate("code-missing");
        open_window();
        denied_with(
            register_with(&registration(b"stranger", None)),
            "one-time code",
        );
        denied_with(
            register_with(&registration(b"stranger", Some(""))),
            "one-time code",
        );
        assert!(stored_ids().is_empty(), "nothing stored");
        assert!(!is_enrolled());
        assert!(enrollment_open(), "the window is still the operator's");
    }

    #[test]
    fn a_registration_with_a_wrong_code_is_refused_and_does_not_spend_the_window() {
        isolate("code-wrong");
        open_window();
        for wrong in [
            "TEST-C0DE-AAAA-BBBC",
            "AAAA-AAAA-AAAA-AAAA",
            "TEST-C0DE-AAAA",
        ] {
            denied_with(
                register_with(&registration(b"stranger", Some(wrong))),
                "one-time code",
            );
        }
        assert!(stored_ids().is_empty(), "nothing stored");
        assert!(
            enrollment_open(),
            "a wrong guess cannot close the window on the person at the box"
        );
        // The operator, with the right code, still enrolls.
        assert!(register_with(&registration(b"mine", Some(TEST_CODE))).is_ok());
        assert_eq!(stored_ids(), vec![b64().encode(b"mine")]);
    }

    /// The right code enrolls ONCE: a second registration in the same window, even with the
    /// right code, is refused with its own sentence, and the first credential stands alone.
    #[test]
    fn the_right_code_enrolls_once_and_a_second_registration_is_refused() {
        isolate("code-once");
        open_window();
        assert!(register_with(&registration(b"first", Some(TEST_CODE))).is_ok());
        assert_eq!(stored_ids(), vec![b64().encode(b"first")]);
        assert_eq!(window_state(), WindowState::Spent);
        denied_with(
            register_with(&registration(b"second", Some(TEST_CODE))),
            "already been used",
        );
        assert_eq!(
            stored_ids(),
            vec![b64().encode(b"first")],
            "the second was not stored and did not replace the first"
        );
        let page = call("urn:passkey:register", PasskeyRegister, Verb::Source, None).unwrap();
        assert!(
            String::from_utf8_lossy(&page.bytes).contains("one registration has happened"),
            "the page says the window is used, not that none is open"
        );
    }

    /// Concurrent registrations inside one window: exactly one is stored, because the window is
    /// judged and spent under the credential lock. (Before ledger #1689 the window was checked
    /// outside the lock, so every POST that saw it open before the first closed it was stored.)
    #[test]
    fn concurrent_registrations_in_one_window_store_exactly_one() {
        isolate("code-race");
        open_window();
        let root = test_root().unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8u8)
            .map(|i| {
                let (root, start) = (root.clone(), start.clone());
                std::thread::spawn(move || {
                    TEST_ROOT.with(|r| *r.borrow_mut() = Some(root));
                    TEST_RP.with(|r| *r.borrow_mut() = Some(test_relying_party()));
                    start.wait();
                    register_with(&registration(&[b'c', i], Some(TEST_CODE))).is_ok()
                })
            })
            .collect();
        let stored = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(stored, 1, "one window, one registration");
        assert_eq!(stored_ids().len(), 1);
    }

    /// The window still expires: past its deadline, the right code enrolls nothing.
    #[test]
    fn an_expired_window_refuses_even_the_right_code() {
        isolate("code-expired");
        write_window(&EnrollWindow {
            until: now_secs() - 1,
            code_sha256: code_digest(TEST_CODE),
            spent: false,
        })
        .unwrap();
        assert_eq!(window_state(), WindowState::Closed);
        denied_with(
            register_with(&registration(b"late", Some(TEST_CODE))),
            "no enrollment window is open",
        );
        assert!(stored_ids().is_empty());
    }

    /// A window file from before the code (a bare timestamp) has no code to check against, so it
    /// is a closed window, never an open one.
    #[test]
    fn a_window_without_a_code_is_closed() {
        isolate("code-legacy");
        write_atomic(
            &enroll_window_path(),
            (now_secs() + 60).to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(window_state(), WindowState::Closed);
        denied_with(
            register_with(&registration(b"old", None)),
            "no enrollment window is open",
        );
        assert!(stored_ids().is_empty());
    }

    /// Opening a window answers with the code, to the person who opened it; the file on disk
    /// holds only its digest; and the code as printed (or typed loosely) enrolls.
    #[test]
    fn opening_a_window_answers_with_a_code_the_file_holds_only_the_digest_of() {
        isolate("code-open");
        let kernel = Kernel::new(std::sync::Arc::new(ikigai_core::EndpointSpace::new().bind(
            ikigai_core::Exact::new("urn:passkey:enroll-open"),
            PasskeyEnrollOpen,
        )));
        let open = || {
            futures::executor::block_on(kernel.issue(
                Request::new(Verb::Sink, Iri::parse("urn:passkey:enroll-open").unwrap()),
                &Capability::root(),
            ))
            .unwrap()
        };
        let text = String::from_utf8(open().bytes.to_vec()).unwrap();
        let code = text
            .lines()
            .find_map(|l| l.strip_prefix("one-time code: "))
            .unwrap_or_else(|| panic!("the answer carries the code: {text}"))
            .to_string();
        assert_eq!(code.len(), 19, "XXXX-XXXX-XXXX-XXXX: {code}");
        assert!(code
            .split('-')
            .all(|g| g.len() == 4 && g.bytes().all(|b| CODE_ALPHABET.contains(&b))));
        let on_disk = std::fs::read_to_string(enroll_window_path()).unwrap();
        assert!(
            !on_disk.contains(&code) && !on_disk.contains(&normalize_code(&code)),
            "the code is never written down: {on_disk}"
        );
        assert!(on_disk.contains(&code_digest(&code)));
        // Typed loosely: lower case, spaces instead of dashes.
        let typed = code.to_lowercase().replace('-', " ");
        assert!(register_with(&registration(b"mine", Some(&typed))).is_ok());
        assert_eq!(stored_ids(), vec![b64().encode(b"mine")]);
        // A new window, a new code.
        let again = open();
        assert!(!String::from_utf8_lossy(&again.bytes).contains(&code));
        assert!(enrollment_open(), "a new window is open and unused");
    }

    #[test]
    fn a_code_is_normalized_before_it_is_hashed() {
        assert_eq!(normalize_code("abcd-efgh ijkm-np0q"), "ABCDEFGH1JKMNP0Q");
        assert_eq!(normalize_code("o0Il-1"), "00111");
        assert_eq!(code_digest("abcd-efgh"), code_digest("ABCDEFGH"));
        assert_ne!(code_digest("ABCDEFGH"), code_digest("ABCDEFGJ"));
    }

    /// The register page asks for the code with a LABELED field the script reads, and the script
    /// sends it with the credential.
    #[test]
    fn the_register_page_has_a_labeled_code_field_the_script_sends() {
        assert!(REGISTER_PAGE_BODY.contains("<label for=code>"));
        assert!(REGISTER_PAGE_BODY.contains("<input id=code name=code"));
        assert!(
            REGISTER_PAGE_BODY.find("id=code") < REGISTER_PAGE_BODY.find("id=reg"),
            "the field comes before the button"
        );
        assert!(PASSKEY_APP_JS.contains("'code='+encodeURIComponent(code.value.trim())"));
    }
}
