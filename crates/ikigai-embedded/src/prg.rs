//! Post/Redirect/Get for the emailed decision pages (ledger #1879).
//!
//! A decision page (`/calendar-request/{action}`, `/contact-block`, `/contact-label`) is a GET
//! that shows what a signed link would do and a form that POSTs it back. The POST used to answer
//! with the result page itself, so a phone that restored the tab later restored a POST, and the
//! browser asked to send it again. Now every decision POST answers `303 See Other` to a GET of
//! the same page with `?outcome=<word>`, and that GET renders the outcome. Two rules hold it:
//!
//! - **No personal data in the URL.** The redirect carries one word from a closed set (and the
//!   path the door routed the POST to, which the browser already had); never the address, the
//!   decision's token, or an enquiry id. A browser shows, keeps and may sync that URL. The
//!   outcome page is therefore generic: it says what happened, not to whom.
//! - **A decision acts once.** The same signed link POSTed twice (a double tap, a "post again"
//!   on an older browser, a replayed request) records its intent once; the second answers
//!   `?outcome=already`. What is remembered is a digest of the link's token, which is a
//!   signature only the minting host can make, so only links that host minted ever enter the
//!   memory, and each is
//!   forgotten when its link expires (seven days at most).
//!
//! The memory is a FILE (ledger #4545): `decision-claims.json` beside the verifying key the
//! links are checked against, replaced whole on every change. A restart reads it back, so a link
//! used before the restart stays used. A claim file that is present but unreadable refuses every
//! decision until a person at the box repairs it: losing the memory must not reopen used links.
//! Each claim is named by a BLAKE3 digest of the endpoint and the token (never the token, never
//! a path), so the file holds no usable link and a config home moved elsewhere keeps its claims.
//! Releases before this one (0.6.2 and older) kept the memory in the process only and wrote no
//! file, so there is no older shape to migrate: an absent file is an empty memory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ikigai_core::{Error, ReprType, Representation, Result};

/// The media type of an ikigai-web entity envelope (`ikigai_web::HTTP_ENTITY`): header lines,
/// an empty line, then the content. Written by hand because this crate does not link the door;
/// the envelope is a documented byte format any language writes, and
/// `crates/ikigai-cli/tests/decision_prg.rs` drives it through the real door.
pub(crate) const HTTP_ENTITY: &str = "application/vnd.ikigai.http-entity";

/// The query name the outcome rides in.
pub(crate) const OUTCOME: &str = "outcome";

/// The outcome word for a POST that found its decision already made.
pub(crate) const ALREADY: &str = "already";

/// The most decisions remembered at once. Only links the minting host signed can enter, and
/// each leaves when it expires, so this is far past any real week of email; it exists so the
/// memory has a stated bound. Past it a decision is REFUSED (`503`, try again later), never
/// acted on unremembered, which would let a replay act twice.
const MAX_REMEMBERED: usize = 4096;

/// The version of the claim file's shape this release writes.
const CLAIMS_VERSION: u32 = 1;

/// The claim file: the decisions already acted on, each with its link's expiry (unix seconds),
/// keyed by [`name`]: a BLAKE3 digest of the endpoint and the link's token, never the token
/// itself (only membership is ever checked, so the file need not hold a usable link). The file
/// lives beside the verifying key, so two endpoints over two keys in two places (as tests build)
/// never share a memory, and the name holds no path, so moving the config home keeps it.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Claims {
    version: u32,
    claims: HashMap<String, i64>,
}

/// Serializes every read-modify-write of a claim file in this process.
fn claims_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where the claims for links verified by `key` live: beside it.
fn claims_path(key: &Path) -> PathBuf {
    key.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("decision-claims.json")
}

/// The claims in `path`: empty when ABSENT; an error (refusing the decision) when present but
/// unreadable, unparsable, or of a version this release does not know.
fn load(path: &Path) -> Result<Claims> {
    let refuse = |why: String| {
        eprintln!(
            "ikigai decide: REFUSING decision links: {why}. Repair it at the box; removing it \
             would let used links act again."
        );
        Error::Unavailable(
            "this host cannot read which decision links were used, so it acts on none; try again \
             later"
                .into(),
        )
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Claims {
                version: CLAIMS_VERSION,
                claims: HashMap::new(),
            })
        }
        Err(e) => return Err(refuse(format!("{} is unreadable: {e}", path.display()))),
    };
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|e| {
        refuse(format!(
            "{} is not a decision claim list: {e}",
            path.display()
        ))
    })?;
    if claims.version != CLAIMS_VERSION {
        return Err(refuse(format!(
            "{} has version {}, which this release does not read",
            path.display(),
            claims.version
        )));
    }
    Ok(claims)
}

/// Replace `path` with `claims`, whole.
fn save(path: &Path, claims: &Claims) -> Result<()> {
    let bytes = serde_json::to_vec(claims)
        .map_err(|e| Error::Endpoint(format!("cannot serialize decision claims: {e}")))?;
    crate::passkey::write_atomic(path, &bytes).map_err(|e| {
        Error::Unavailable(format!(
            "cannot record the decision as used in {}: {e}; nothing was done",
            path.display()
        ))
    })
}

/// Claim the decision `token` (a link valid until `exp`, verified against the key at `key`) at
/// the endpoint `scope` for acting on now: `Ok(true)`
/// the first time, `Ok(false)` when it was claimed before. The claim is taken BEFORE the action
/// so two POSTs racing each other cannot both act; [`release`] gives it back when the action
/// fails, so a failed attempt can be retried.
///
/// The claim is on disk before this returns `Ok(true)`: if it cannot be written, the decision is
/// refused rather than acted on unremembered.
pub(crate) fn claim(scope: &str, key: &Path, token: &str, exp: i64, now: i64) -> Result<bool> {
    let _held = claims_lock();
    let path = claims_path(key);
    let mut file = load(&path)?;
    file.claims.retain(|_, until| *until > now);
    let name = name(scope, token);
    if file.claims.contains_key(&name) {
        return Ok(false);
    }
    if file.claims.len() >= MAX_REMEMBERED {
        return Err(Error::Unavailable(format!(
            "{MAX_REMEMBERED} decisions are remembered and none has expired; try again later"
        )));
    }
    file.claims.insert(name, exp);
    save(&path, &file)?;
    Ok(true)
}

/// Give back a claim whose action failed (see [`claim`]). Best-effort: if the file cannot be
/// rewritten the link stays used, which is the safe side; it is said on stderr.
pub(crate) fn release(scope: &str, key: &Path, token: &str) {
    let _held = claims_lock();
    let path = claims_path(key);
    let Ok(mut file) = load(&path) else { return };
    if file.claims.remove(&name(scope, token)).is_some() {
        if let Err(e) = save(&path, &file) {
            eprintln!("ikigai decide: could not give back a failed decision's claim: {e}");
        }
    }
}

/// What a decision is remembered by in the claim file (see [`claim`]): `b3:<hex>`, the BLAKE3
/// content id of the endpoint `scope` and the link's `token`. Stable across a config-home move
/// (no path in it) and useless as a link if the file leaks (no token in it).
fn name(scope: &str, token: &str) -> String {
    ikigai_core::ContentId::of(format!("{scope}|{token}").as_bytes()).to_string()
}

/// The answer to a decision POST: `303 See Other` to this same page with `?outcome=<word>`, with
/// `page` as the body for a client that does not follow it. `word` is one of the endpoint's own
/// literals, so the Location is fixed text: no value from the request reaches it.
pub(crate) fn see_other(word: &'static str, page: Representation) -> Representation {
    debug_assert!(word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
    let mut bytes = format!(
        "Content-Type: {}\r\nLocation: ?{OUTCOME}={word}\r\n\r\n",
        page.repr_type
    )
    .into_bytes();
    bytes.extend_from_slice(&page.bytes);
    Representation::new(ReprType::new(HTTP_ENTITY), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private scratch directory holding a (pretend) verifying key path.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ikigai-prg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_decision_is_claimed_once_until_its_link_expires() {
        let dir = scratch("once");
        let key_path = dir.join("once.pub");
        let other_dir = scratch("once-other");
        let other_key = other_dir.join("other.pub");
        let (token, key) = ("prg-test-token-once", key_path.as_path());
        assert!(claim("t", key, token, 200, 100).unwrap());
        assert!(
            !claim("t", key, token, 200, 150).unwrap(),
            "the replay finds it"
        );
        assert!(
            claim("other", key, token, 200, 150).unwrap(),
            "scoped by endpoint"
        );
        assert!(
            claim("t", &other_key, token, 200, 150).unwrap(),
            "scoped by verifying key"
        );
        assert!(
            claim("t", key, token, 300, 250).unwrap(),
            "forgotten once expired"
        );
    }

    #[test]
    fn a_released_claim_can_be_taken_again() {
        let dir = scratch("release");
        let key_path = dir.join("release.pub");
        let (token, key) = ("prg-test-token-release", key_path.as_path());
        assert!(claim("t", key, token, i64::MAX, 0).unwrap());
        release("t", key, token);
        assert!(claim("t", key, token, i64::MAX, 0).unwrap());
    }

    /// Ledger #4545: the memory is the file, so a "restart" (nothing in the process but the
    /// file) still finds a used link used. The fixture is written by hand, as a previous
    /// process would have left it.
    #[test]
    fn a_used_link_stays_used_after_a_restart() {
        let dir = scratch("restart");
        let key = dir.join("decide.pub");
        assert!(claim("t", &key, "tok-a", 500, 100).unwrap());
        let on_disk = std::fs::read_to_string(dir.join("decision-claims.json")).unwrap();
        assert!(
            on_disk.contains(&name("t", "tok-a")),
            "the claim is on disk: {on_disk}"
        );
        assert!(
            !on_disk.contains("tok-a"),
            "as a digest, never the token: {on_disk}"
        );

        // What another process (the one before a restart) wrote.
        let fixture = format!(
            r#"{{"version":1,"claims":{{"{}":500}}}}"#,
            name("t", "tok-b")
        );
        std::fs::write(dir.join("decision-claims.json"), fixture).unwrap();
        assert!(
            !claim("t", &key, "tok-b", 500, 100).unwrap(),
            "used before the restart"
        );
        assert!(
            claim("t", &key, "tok-c", 500, 100).unwrap(),
            "a fresh link still acts"
        );
    }

    /// The claim is keyed by the token's digest, not by where the key lives: a config home moved
    /// (the directory renamed, as a machine move or a new `XDG_CONFIG_HOME` does) keeps its used
    /// links used.
    #[test]
    fn a_used_link_stays_used_after_the_config_home_moves() {
        let old = scratch("move-old");
        let new = std::env::temp_dir().join(format!("ikigai-prg-{}-move-new", std::process::id()));
        let _ = std::fs::remove_dir_all(&new);
        assert!(claim("t", &old.join("decide.pub"), "tok-moved", 500, 100).unwrap());
        std::fs::rename(&old, &new).unwrap();
        assert!(
            !claim("t", &new.join("decide.pub"), "tok-moved", 500, 100).unwrap(),
            "the used link stays used in its new home"
        );
        assert!(claim("t", &new.join("decide.pub"), "tok-fresh", 500, 100).unwrap());
    }

    /// The name is the shared content id (`b3:` and 64 hex digits of BLAKE3), and holds neither
    /// the token nor a path.
    #[test]
    fn a_claim_name_is_a_digest_of_scope_and_token() {
        let n = name("calendar-request", "tok-secret");
        let hex = n.strip_prefix("b3:").expect("a b3 content id");
        assert_eq!(hex.len(), 64, "{n}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{n}");
        assert!(!n.contains("tok-secret"), "{n}");
        assert_eq!(
            n,
            ikigai_core::ContentId::of(b"calendar-request|tok-secret").to_string()
        );
        assert_ne!(name("a", "tok"), name("b", "tok"), "scoped by endpoint");
    }

    #[test]
    fn an_unreadable_claim_file_refuses_rather_than_forgets() {
        let dir = scratch("corrupt");
        let key = dir.join("decide.pub");
        std::fs::write(dir.join("decision-claims.json"), b"{not json").unwrap();
        assert!(claim("t", &key, "tok", 500, 100).is_err());
        std::fs::write(
            dir.join("decision-claims.json"),
            br#"{"version":9,"claims":{}}"#,
        )
        .unwrap();
        assert!(
            claim("t", &key, "tok", 500, 100).is_err(),
            "an unknown version refuses"
        );
    }

    #[test]
    fn see_other_wraps_the_page_with_a_fixed_location() {
        let page = Representation::new(
            ReprType::new("text/html").with_param("charset", "utf-8"),
            b"<p>x</p>".to_vec(),
        );
        let answer = see_other("recorded", page);
        assert_eq!(answer.repr_type.to_string(), HTTP_ENTITY);
        assert_eq!(
            answer.bytes,
            b"Content-Type: text/html;charset=utf-8\r\nLocation: ?outcome=recorded\r\n\r\n<p>x</p>"
        );
    }
}
