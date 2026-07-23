//! Approve or decline a pending booking from an emailed link.
//!
//! The booking flow stops at a PENDING tuple in `urn:space:confirmations` and waits for a
//! person. `confirm.scm` is the way to answer at the Mac; this is the way to answer from a
//! phone. Three endpoints, deliberately split across the two machines:
//!
//! | endpoint | runs on | authority | does |
//! |---|---|---|---|
//! | `urn:decide:link` | Mac | `urn:cap:decide:mint` | mints the two signed URLs to email |
//! | `urn:calendar-request:{action}` | edge | public (route ceiling) | GET shows, POST records |
//! | `urn:decide:accept` | Mac | `urn:cap:decide:accept` | RE-verifies, then runs `confirm` |
//!
//! The public pair is `/calendar-request/approve` and `/calendar-request/decline` — the
//! action in the path, not a query flag. **GET shows; POST decides.** Mail scanners and
//! link-preview bots fetch every URL in a message, so a decision that happened on GET would
//! be made by a robot before the message was read.
//!
//! ## Why the Mac verifies a second time
//!
//! The edge is the airlock: it faces the internet and holds nothing precious. If it were the
//! only check, an attacker who took the edge could drop `(decide … "approve")` straight into
//! its own space and the Mac would dutifully write the calendar. So the token travels WITH
//! the decision and the Mac verifies it again before acting, against the same key. Only the
//! Mac holds the signing half, so a compromised edge cannot manufacture an approval — it can
//! only pass along ones that were genuinely minted here. The edge check is still worth doing:
//! it keeps a stranger's traffic from ever reaching the space.
//!
//! ## The token
//!
//! `base64url(Ed25519(<id>|<action>|<exp>))` — short enough for a URL, and bound to all
//! three fields, so a token for one booking cannot be replayed onto another, nor an
//! `approve` token re-pointed at `decline`. Expiry is checked on both ends.
//!
//! Replay of a *valid* token is harmless: deciding takes the pending tuple, so a second
//! decision for the same booking finds nothing and says so.

use crate::file_root;
use base64::Engine;
use ed25519_dalek::pkcs8::{spki::DecodePublicKey, DecodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, Error, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};

/// Mint a decide link. Held only by the host that also holds the signing key.
pub const CAP_DECIDE_MINT: &str = "urn:cap:decide:mint";
/// Act on a decision that came back from the edge.
pub const CAP_DECIDE_ACCEPT: &str = "urn:cap:decide:accept";

/// The space a verified decision is dropped into on the edge, and drained from by the Mac.
pub const DECISIONS_SPACE: &str = "urn:space:decisions";

/// The secret holding the Ed25519 signing key (private half). Mac only.
const SIGNING_SECRET: &str = "urn:secret:booking-decide";

/// How long an emailed link stays good. A booking request that has sat unanswered for a week
/// wants a fresh look, not a stale click.
const TTL_SECONDS: i64 = 7 * 24 * 3600;

/// The public (verifying) half, as a plain file in the workspace on BOTH machines.
///
/// Deliberately not a `urn:secret:` read: the public key is public, and keeping it as a file
/// means the internet-facing edge needs no secret-reading authority at all.
pub fn public_key_path() -> std::path::PathBuf {
    file_root().join("decide.pub")
}

/// Where the emailed links point (the collection; the action is the last path
/// segment). Override with `IKIGAI_DECIDE_BASE`.
fn decide_base() -> String {
    std::env::var("IKIGAI_DECIDE_BASE")
        .unwrap_or_else(|_| "https://ikigai-rs.dev/calendar-request".to_string())
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Exactly what gets signed. Every field the decision depends on is in here.
fn payload(id: &str, action: &str, exp: i64) -> String {
    format!("{id}|{action}|{exp}")
}

/// The two actions a link may carry. Anything else is refused before a key is even loaded.
fn known_action(action: &str) -> bool {
    action == "approve" || action == "decline"
}

/// A booking id is a content hash; it also becomes part of a signed payload and a filename
/// downstream, so it is checked against a strict alphabet here.
fn id_shaped(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Sign `payload` and render the token.
fn mint_token(id: &str, action: &str, exp: i64, key: &SigningKey) -> String {
    let sig = key.sign(payload(id, action, exp).as_bytes());
    b64().encode(sig.to_bytes())
}

/// Is `token` a signature this key made over exactly these fields, and still in date?
///
/// Every failure is a plain `false` — a bad token is an ordinary answer, not an error, and
/// the caller reports the same thing either way so a prober learns nothing from the shape of
/// the response.
fn token_valid(
    id: &str,
    action: &str,
    exp: i64,
    token: &str,
    key: &VerifyingKey,
    now: i64,
) -> bool {
    if !known_action(action) || !id_shaped(id) || exp <= now {
        return false;
    }
    let Ok(raw) = b64().decode(token) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    key.verify(
        payload(id, action, exp).as_bytes(),
        &Signature::from_bytes(&bytes),
    )
    .is_ok()
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Read the verifying key from `path`.
fn verifying_key_at(path: &std::path::Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::Endpoint(format!(
            "cannot read the decide public key at {}: {e}",
            path.display()
        ))
    })?;
    parse_verifying_key(&bytes).map_err(|e| Error::Endpoint(format!("{}: {e}", path.display())))
}

fn parse_verifying_key(bytes: &[u8]) -> std::result::Result<VerifyingKey, String> {
    if let Ok(pem) = std::str::from_utf8(bytes) {
        if let Ok(key) = VerifyingKey::from_public_key_pem(pem.trim()) {
            return Ok(key);
        }
    }
    VerifyingKey::from_public_key_der(bytes).map_err(|e| format!("not an SPKI Ed25519 key: {e}"))
}

fn parse_signing_key(bytes: &[u8]) -> std::result::Result<SigningKey, String> {
    if let Ok(pem) = std::str::from_utf8(bytes) {
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem.trim()) {
            return Ok(key);
        }
    }
    SigningKey::from_pkcs8_der(bytes).map_err(|e| format!("not a PKCS8 Ed25519 key: {e}"))
}

/// Percent-encode a query VALUE (RFC 3986 unreserved kept).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// One `(name "value")` field out of a tuple, unescaping `\"` and `\\`.
///
/// The decision tuple uses the same shape every other tuple in the system does, so this is
/// the Rust counterpart of the handlers' `(field …)`.
pub fn field(tuple: &str, name: &str) -> Option<String> {
    let needle = format!("({name} \"");
    let start = tuple.find(&needle)? + needle.len();
    let mut out = String::new();
    let mut chars = tuple[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => return Some(out),
            _ => out.push(c),
        }
    }
    None
}

/// Escape a value into a tuple literal.
fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

// =====================================================================================
// urn:decide:link — mint the links (Mac)
// =====================================================================================

/// Mints the approve/decline URLs for a pending booking. See the [module docs](crate::decide).
pub struct DecideLink;

#[async_trait::async_trait]
impl Endpoint for DecideLink {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_DECIDE_MINT) {
            return Err(Error::Denied(format!(
                "minting a decide link requires `{CAP_DECIDE_MINT}`"
            )));
        }
        let id = inv
            .inline_str("id")
            .map_err(|_| Error::MissingArgument("id".to_string()))?
            .trim()
            .to_string();
        if !id_shaped(&id) {
            return Err(Error::InvalidArgument {
                name: "id".to_string(),
                detail: format!("`{id}` is not a booking id"),
            });
        }

        // The signing key comes through the kernel, so its custody (Keychain, file, Touch ID)
        // is the secrets module's business and never this endpoint's.
        let secret = inv
            .issue(Request::new(
                Verb::Source,
                Iri::parse(SIGNING_SECRET).expect("literal IRI"),
            ))
            .await?;
        let key = parse_signing_key(&secret.bytes)
            .map_err(|e| Error::Endpoint(format!("{SIGNING_SECRET} is not a signing key: {e}")))?;

        let exp = now_secs() + TTL_SECONDS;
        let base = decide_base();
        let mut out = String::new();
        for action in ["approve", "decline"] {
            let token = mint_token(&id, action, exp, &key);
            out.push_str(&format!(
                "{base}/{action}?id={}&exp={exp}&t={}\n",
                urlencode(&id),
                urlencode(&token)
            ));
        }
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            out.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "decide-link"
    }

    fn describe(&self) -> Description {
        Description::new("decide-link")
            .title("Mint approve/decline links")
            .summary(
                "Two signed, expiring URLs for one pending booking — the approve link and \
                 the decline link, one per line, ready to email.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint — the signed links for a pending booking")
                    .requires(CAP_DECIDE_MINT)
                    .input(ArgSpec::new("id").summary("the pending booking's tuple id")),
            )
            .output("text/plain; charset=utf-8")
    }
}

// =====================================================================================
// urn:calendar-request:{action} — the clicked link (edge)
// =====================================================================================

/// `/calendar-request/approve` and `/calendar-request/decline` — one resource per action,
/// with the action in the path rather than a query flag, so the URL says what it is.
///
/// **GET shows, POST acts.** The emailed link is a GET: it verifies the token and renders
/// what the decision *would* be, with a button. Only the POST records anything.
///
/// That split is not ceremony. Mail providers, security scanners and link-preview bots fetch
/// every URL in an incoming message; if following the link were itself the decision, a
/// scanner would approve bookings on its own before the message was ever read. A GET is safe
/// to prefetch, and a POST is not something a prefetcher will do.
///
/// See the [module docs](crate::decide) for the token and the two-machine split.
pub struct CalendarRequest {
    /// Where the verifying (public) key lives. Injected so the host owns the layout and a
    /// test can point at its own key.
    pub key_path: std::path::PathBuf,
}

/// A small self-contained page. No stylesheet to fetch — this renders on a phone, once,
/// probably on cellular, and it should not depend on anything else being up.
fn page(title: &str, body: &str) -> Representation {
    Representation::new(
        ReprType::new("text/html").with_param("charset", "utf-8"),
        format!(
            "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">\
             <title>{title}</title>\
             <body style=\"font:16px/1.5 system-ui;margin:3rem auto;max-width:32rem;padding:0 1rem\">\
             <h1 style=\"font-size:1.3rem\">{title}</h1>{body}"
        )
        .into_bytes(),
    )
}

/// The action this resource IS, from the last segment of its own IRI
/// (`urn:calendar-request:approve` → `approve`).
fn action_of(inv: &Invocation<'_>) -> String {
    inv.request
        .target
        .as_str()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

#[async_trait::async_trait]
impl Endpoint for CalendarRequest {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let action = action_of(inv);
        let arg = |name: &str| inv.inline_str(name).unwrap_or("").trim().to_string();
        let (id, token) = (arg("id"), arg("t"));
        let exp: i64 = arg("exp").parse().unwrap_or(0);

        let key = verifying_key_at(&self.key_path)?;
        if !token_valid(&id, &action, exp, &token, &key, now_secs()) {
            // One answer for every kind of bad link — expired, forged, malformed, wrong
            // action. A prober learns nothing, and for a real person the cause is almost
            // always age.
            return Ok(page(
                "That link didn't work",
                "<p>It may have expired, or already been used. You can still decide it on \
                 your Mac.</p>",
            ));
        }

        match inv.request.verb {
            // SHOW: what this link would do, and a button to do it.
            Verb::Source => {
                let (verb_word, note) = if action == "approve" {
                    (
                        "Approve",
                        "The invitation goes out once your Mac picks this up.",
                    )
                } else {
                    (
                        "Decline",
                        "They'll be told, and asked to suggest other times.",
                    )
                };
                Ok(page(
                    &format!("{verb_word} this request?"),
                    &format!(
                        "<p>Booking <code>{id}</code>.</p>\
                         <form method=\"post\">\
                         <input type=hidden name=id value=\"{id}\">\
                         <input type=hidden name=exp value=\"{exp}\">\
                         <input type=hidden name=t value=\"{token}\">\
                         <button style=\"font:inherit;padding:.6rem 1.2rem\">{verb_word}</button>\
                         </form><p style=\"color:#666\">{note}</p>"
                    ),
                ))
            }
            // ACT: record the intent. The Mac does the real work when it next drains.
            Verb::Sink => {
                let tuple = format!(
                    "((decide {}) (id {}) (exp {}) (token {}))",
                    quoted(&action),
                    quoted(&id),
                    quoted(&exp.to_string()),
                    quoted(&token)
                );
                inv.issue(
                    Request::new(
                        Verb::Sink,
                        Iri::parse(DECISIONS_SPACE).expect("literal IRI"),
                    )
                    .with_arg("content", ArgRef::Inline(tuple.into_bytes())),
                )
                .await?;
                let what = if action == "approve" {
                    "Approved — the invitation goes out once your Mac picks this up."
                } else {
                    "Declined — they'll be told, and asked to suggest other times."
                };
                Ok(page("Recorded", &format!("<p>{what}</p>")))
            }
            other => Err(Error::Endpoint(format!(
                "a calendar request is shown with Source or decided with Sink, not {other:?}"
            ))),
        }
    }

    fn name(&self) -> &str {
        "calendar-request"
    }

    fn describe(&self) -> Description {
        Description::new("calendar-request")
            .title("Approve or decline a booking request")
            .summary(
                "The emailed decision link. GET verifies the token and shows what it would \
                 do; POST records the decision for the host to act on. Records intent only — \
                 nothing is scheduled or cancelled here.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("show — what this link would decide")
                    .input(ArgSpec::new("id").summary("the booking id"))
                    .input(ArgSpec::new("exp").summary("expiry, unix seconds"))
                    .input(ArgSpec::new("t").summary("the signature")),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("decide — record the decision")
                    .input(ArgSpec::new("id").summary("the booking id"))
                    .input(ArgSpec::new("exp").summary("expiry, unix seconds"))
                    .input(ArgSpec::new("t").summary("the signature")),
            )
            .output("text/html; charset=utf-8")
    }
}

// =====================================================================================
// urn:decide:accept — re-verify a drained decision and act on it (Mac)
// =====================================================================================

/// Re-checks a decision that came back from the edge and runs `confirm`.
/// See the [module docs](crate::decide) for why this verifies a second time.
pub struct DecideAccept {
    /// The same verifying key the edge uses — this host checks the decision itself.
    pub key_path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for DecideAccept {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_DECIDE_ACCEPT) {
            return Err(Error::Denied(format!(
                "acting on a decision requires `{CAP_DECIDE_ACCEPT}`"
            )));
        }
        let tuple = inv
            .inline_str("content")
            .map_err(|_| Error::MissingArgument("content".to_string()))?;

        let get = |name: &str| field(tuple, name).unwrap_or_default();
        let (action, id, token) = (get("decide"), get("id"), get("token"));
        let exp: i64 = get("exp").parse().unwrap_or(0);

        // THE gate. The edge already checked, but the edge is exposed and this machine is the
        // one with a calendar; a decision that isn't signed by our own key gets no further.
        let key = verifying_key_at(&self.key_path)?;
        if !token_valid(&id, &action, exp, &token, &key, now_secs()) {
            return Err(Error::Denied(format!(
                "decision for `{id}` is not signed by this host — refusing to act on it"
            )));
        }

        // Hand it to the same program a person would use at the terminal.
        let command = format!("({action} \"{id}\")");
        let out = inv
            .issue(
                Request::new(
                    Verb::Sink,
                    Iri::parse("urn:booking:confirm").expect("literal IRI"),
                )
                .with_arg("content", ArgRef::Inline(command.into_bytes())),
            )
            .await?;
        Ok(out)
    }

    fn name(&self) -> &str {
        "decide-accept"
    }

    fn describe(&self) -> Description {
        Description::new("decide-accept")
            .title("Act on a decision from the edge")
            .summary(
                "Re-verifies a drained decision against this host's own key, then runs the \
                 booking confirmation. A decision this host did not sign is refused.",
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("accept — verify a decision tuple and run confirm")
                    .requires(CAP_DECIDE_ACCEPT)
                    .input(ArgSpec::new("content").summary("the decision tuple")),
            )
            .output("text/plain; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        // A fixed seed: these tests are about the token contract, not key generation.
        SigningKey::from_bytes(&[7u8; 32])
    }

    const ID: &str = "abc123def456";
    const NOW: i64 = 1_800_000_000;
    const EXP: i64 = NOW + 600;

    #[test]
    fn a_freshly_minted_token_verifies() {
        let k = key();
        let t = mint_token(ID, "approve", EXP, &k);
        assert!(token_valid(ID, "approve", EXP, &t, &k.verifying_key(), NOW));
    }

    #[test]
    fn a_token_is_bound_to_its_booking_and_its_action() {
        let k = key();
        let v = k.verifying_key();
        let t = mint_token(ID, "approve", EXP, &k);
        // Re-pointing an approve token at another booking, or at decline, must not verify —
        // otherwise one emailed link would decide every booking.
        assert!(!token_valid("zzz999zzz999", "approve", EXP, &t, &v, NOW));
        assert!(!token_valid(ID, "decline", EXP, &t, &v, NOW));
        assert!(!token_valid(ID, "approve", EXP + 1, &t, &v, NOW));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let k = key();
        let t = mint_token(ID, "approve", EXP, &k);
        assert!(!token_valid(
            ID,
            "approve",
            EXP,
            &t,
            &k.verifying_key(),
            EXP + 1
        ));
    }

    #[test]
    fn another_key_cannot_sign_a_decision() {
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let t = mint_token(ID, "approve", EXP, &theirs);
        assert!(!token_valid(
            ID,
            "approve",
            EXP,
            &t,
            &key().verifying_key(),
            NOW
        ));
    }

    #[test]
    fn garbage_tokens_are_refused_without_panicking() {
        let v = key().verifying_key();
        for bad in ["", "!!!!", "c2hvcnQ", &"A".repeat(200)] {
            assert!(!token_valid(ID, "approve", EXP, bad, &v, NOW), "{bad}");
        }
    }

    #[test]
    fn an_unknown_action_or_malformed_id_never_reaches_the_signature_check() {
        let k = key();
        let v = k.verifying_key();
        let t = mint_token(ID, "approve", EXP, &k);
        assert!(!token_valid(ID, "delete-everything", EXP, &t, &v, NOW));
        assert!(!token_valid(
            "../../etc/passwd",
            "approve",
            EXP,
            &t,
            &v,
            NOW
        ));
        assert!(!token_valid("short", "approve", EXP, &t, &v, NOW));
    }

    #[test]
    fn fields_come_back_out_of_a_decision_tuple() {
        let tuple = format!(
            "((decide {}) (id {}) (exp {}) (token {}))",
            quoted("approve"),
            quoted(ID),
            quoted("1800000600"),
            quoted("sig==")
        );
        assert_eq!(field(&tuple, "decide").as_deref(), Some("approve"));
        assert_eq!(field(&tuple, "id").as_deref(), Some(ID));
        assert_eq!(field(&tuple, "token").as_deref(), Some("sig=="));
        assert_eq!(field(&tuple, "nope"), None);
    }

    #[test]
    fn an_escaped_value_survives_the_round_trip() {
        // A quote in a value must not end the literal early and truncate what we verify.
        let nasty = r#"a") (id "evil"#;
        let tuple = format!("((decide {}) (id {}))", quoted("approve"), quoted(nasty));
        assert_eq!(field(&tuple, "id").as_deref(), Some(nasty));
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{Capability, EndpointSpace, Exact, Kernel, UriTemplate};
    use std::sync::{Arc, Mutex};

    /// Records whatever is dropped into the decisions space.
    #[derive(Clone, Default)]
    struct Recorder {
        dropped: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Endpoint for Recorder {
        async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
            self.dropped
                .lock()
                .unwrap()
                .push(inv.inline_str("content").unwrap_or("").to_string());
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"ok".to_vec(),
            ))
        }
        fn name(&self) -> &str {
            "decisions"
        }
        fn describe(&self) -> Description {
            Description::new("decisions").verb(Verb::Sink)
        }
    }

    struct World {
        kernel: Kernel,
        dropped: Arc<Mutex<Vec<String>>>,
        key: SigningKey,
        _dir: std::path::PathBuf,
    }

    fn world(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("ikigai-decide-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        // Write the verifying half exactly as `urn:secret:generate` would: SPKI PEM.
        let pem = {
            use ed25519_dalek::pkcs8::EncodePublicKey;
            key.verifying_key()
                .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .unwrap()
        };
        let key_path = dir.join("decide.pub");
        std::fs::write(&key_path, pem).unwrap();

        let recorder = Recorder::default();
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    UriTemplate::parse("urn:calendar-request:{action}").unwrap(),
                    CalendarRequest {
                        key_path: key_path.clone(),
                    },
                )
                .bind(Exact::new(DECISIONS_SPACE), recorder.clone()),
        ));
        World {
            kernel,
            dropped: recorder.dropped,
            key,
            _dir: dir,
        }
    }

    const ID: &str = "abc123def456";

    impl World {
        fn call(&self, verb: Verb, action: &str, id: &str, exp: i64, token: &str) -> String {
            let rep = block_on(
                self.kernel.issue(
                    Request::new(
                        verb,
                        Iri::parse(format!("urn:calendar-request:{action}")).unwrap(),
                    )
                    .with_arg("id", ArgRef::Inline(id.as_bytes().to_vec()))
                    .with_arg("exp", ArgRef::Inline(exp.to_string().into_bytes()))
                    .with_arg("t", ArgRef::Inline(token.as_bytes().to_vec())),
                    &Capability::root(),
                ),
            )
            .expect("the page should render");
            String::from_utf8(rep.bytes.clone()).unwrap()
        }
        fn valid(&self, action: &str) -> (i64, String) {
            let exp = now_secs() + 600;
            (exp, mint_token(ID, action, exp, &self.key))
        }
        fn dropped(&self) -> Vec<String> {
            self.dropped.lock().unwrap().clone()
        }
    }

    #[test]
    fn a_get_shows_the_decision_but_records_nothing() {
        // THE property that makes emailing these links safe: a mail scanner or link-preview
        // bot fetching the URL must not decide anything.
        let w = world("get");
        let (exp, token) = w.valid("approve");
        let html = w.call(Verb::Source, "approve", ID, exp, &token);
        assert!(html.contains("Approve this request?"), "{html}");
        assert!(
            html.contains("method=\"post\""),
            "offers a POST button: {html}"
        );
        assert!(w.dropped().is_empty(), "a GET must record nothing");
    }

    #[test]
    fn a_post_records_the_decision_with_its_token() {
        let w = world("post");
        let (exp, token) = w.valid("approve");
        let html = w.call(Verb::Sink, "approve", ID, exp, &token);
        assert!(html.contains("Recorded"), "{html}");

        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(field(&dropped[0], "decide").as_deref(), Some("approve"));
        assert_eq!(field(&dropped[0], "id").as_deref(), Some(ID));
        // The token rides along so the Mac can verify it a second time.
        assert_eq!(field(&dropped[0], "token").as_deref(), Some(token.as_str()));
    }

    #[test]
    fn decline_is_its_own_resource() {
        let w = world("decline");
        let (exp, token) = w.valid("decline");
        assert!(w
            .call(Verb::Sink, "decline", ID, exp, &token)
            .contains("Recorded"));
        assert_eq!(field(&w.dropped()[0], "decide").as_deref(), Some("decline"));
    }

    #[test]
    fn a_token_minted_for_approve_cannot_post_a_decline() {
        // The action is in the path AND in the signature, so the two cannot be swapped.
        let w = world("swap");
        let (exp, token) = w.valid("approve");
        let html = w.call(Verb::Sink, "decline", ID, exp, &token);
        assert!(html.contains("didn't work"), "{html}");
        assert!(w.dropped().is_empty(), "nothing recorded");
    }

    #[test]
    fn a_forged_or_expired_token_records_nothing() {
        let w = world("forged");
        let (exp, _) = w.valid("approve");
        let forged = mint_token(ID, "approve", exp, &SigningKey::from_bytes(&[9u8; 32]));
        assert!(w
            .call(Verb::Sink, "approve", ID, exp, &forged)
            .contains("didn't work"));

        let stale = now_secs() - 1;
        let stale_token = mint_token(ID, "approve", stale, &w.key);
        assert!(w
            .call(Verb::Sink, "approve", ID, stale, &stale_token)
            .contains("didn't work"));

        assert!(w.dropped().is_empty(), "neither is recorded");
    }
}
