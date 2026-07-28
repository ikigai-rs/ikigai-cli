//! Block a contact enquiry's sender from an emailed link.
//!
//! Phase 1 gave the edge a blocklist (`urn:decisions`, `action=block`) that the public intake
//! consults to drop a known-bad sender at the door. Recording a block, though, meant a shell on
//! the box. This is the way to block from a phone: every enquiry email carries a "block this
//! sender" link, so an unwanted repeat is one tap away.
//!
//! It mirrors [`crate::decide`] deliberately — same token shape, same GET-shows/POST-acts split,
//! same "the public face only RECORDS into a space" airlock — and reuses its crypto and HTTP
//! helpers so there is one implementation of the delicate parts. The differences are all about
//! scope, and all in the direction of *less* authority:
//!
//! | | `decide` (booking) | `contactblock` (this) |
//! |---|---|---|
//! | signs | `<id>\|<action>\|<exp>` | `<email>\|<exp>` |
//! | key | `urn:secret:booking-decide`, **Mac-only**, Keychain | `contact-block.key`, **edge-local file** |
//! | worst case if forged | approve/decline a booking | block an enquiry sender |
//! | who acts | the **Mac** re-verifies, then writes the calendar | an edge reactor writes the edge blocklist |
//!
//! ## Two machines, three endpoints
//!
//! | endpoint | runs on | authority | does |
//! |---|---|---|---|
//! | `urn:contactblock:link` | edge daemon | `urn:cap:contactblock:mint` | mints the signed URL to email |
//! | `urn:contact-block` | edge http face | public (route ceiling) | GET shows, POST records |
//! | `urn:contactblock:apply` | edge daemon reactor | `urn:cap:decisions:write` | drains the space, writes the block |
//!
//! ## Why no second verify (unlike `decide`)
//!
//! `decide` verifies again on the Mac because the Mac is a *higher* trust domain than the edge —
//! a compromised edge must not be able to manufacture a calendar write. Here there is no such
//! hop: the click and the apply are both on the edge. The token is checked once, at the click,
//! and the airlock exists for one reason only — to keep `decisions:write` off the internet-facing
//! HTTP ceiling, so a bug in the public face can drop an *intent* but never write the blocklist.
//! The apply reactor, which is not internet-facing, holds that authority.
//!
//! ## The low-value key
//!
//! The signing half is a plain file (`contact-block.key`, PKCS8 PEM) in the workspace, generated
//! once on the edge with `openssl`. It earns no Keychain custody because the most a stolen key
//! buys is the power to block enquiry senders — annoying, fully recoverable, and confined to the
//! edge. The public half (`contact-block.pub`, SPKI PEM) is what the internet-facing face reads,
//! so that process needs no signing authority at all — exactly as `decide.pub` works for bookings.

use crate::decide::{
    b64, now_secs, page, param, parse_signing_key, quoted, urlencode, verifying_key_at,
};
use crate::file_root;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, Error, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};

/// Mint a block link. Held by the edge daemon (where the enquiry email is composed).
pub const CAP_CONTACTBLOCK_MINT: &str = "urn:cap:contactblock:mint";

/// The space a verified block is dropped into on the public face, and drained from by the
/// daemon's apply reactor.
pub const CONTACT_BLOCKS_SPACE: &str = "urn:space:contact-blocks";

/// How long an emailed block link stays good — the same week `decide` uses. A spammer worth
/// blocking is worth blocking now; a stale link just wants re-sending from a fresh enquiry.
const TTL_SECONDS: i64 = 7 * 24 * 3600;

/// The signing (private) half, a plain file in the workspace. Edge-only — see the module docs
/// for why this key does not earn Keychain custody.
pub fn private_key_path() -> std::path::PathBuf {
    file_root().join("contact-block.key")
}

/// The verifying (public) half, a plain file on the same machine. Read by the internet-facing
/// face so it needs no secret authority — the `decide.pub` pattern.
pub fn public_key_path() -> std::path::PathBuf {
    file_root().join("contact-block.pub")
}

/// Where the emailed link points. Override with `IKIGAI_CONTACTBLOCK_BASE`.
fn link_base() -> String {
    std::env::var("IKIGAI_CONTACTBLOCK_BASE")
        .unwrap_or_else(|_| "https://ikigai-rs.dev/contact-block".to_string())
}

/// Exactly what gets signed: the address to block and an expiry. The address is IN the payload,
/// so a valid link cannot be re-pointed at some other sender.
fn payload(email: &str, exp: i64) -> String {
    format!("{email}|{exp}")
}

/// A conservative address gate. The value is signed, so this is not a security boundary — it is
/// to keep a malformed address out of the tuple we drop and the block record we write. Deliberately
/// loose on the local/domain shape (real addresses are varied) but strict on length and on the
/// control characters that could reshape a tuple or an SMTP header downstream.
fn email_shaped(email: &str) -> bool {
    (3..=254).contains(&email.len())
        && email.contains('@')
        && !email.chars().any(|c| c.is_control())
        && !email.contains('"')
        && !email.contains('\\')
}

fn mint_token(email: &str, exp: i64, key: &SigningKey) -> String {
    let sig = key.sign(payload(email, exp).as_bytes());
    b64().encode(sig.to_bytes())
}

/// Is `token` a signature this key made over exactly this address and expiry, still in date?
/// Every failure is a plain `false`, so a prober learns nothing from the shape of the answer.
fn token_valid(email: &str, exp: i64, token: &str, key: &VerifyingKey, now: i64) -> bool {
    if !email_shaped(email) || exp <= now {
        return false;
    }
    let Ok(raw) = b64().decode(token) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    key.verify(
        payload(email, exp).as_bytes(),
        &Signature::from_bytes(&bytes),
    )
    .is_ok()
}

fn read_signing_key(path: &std::path::Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::Endpoint(format!(
            "cannot read the contact-block signing key at {}: {e}",
            path.display()
        ))
    })?;
    parse_signing_key(&bytes)
        .map_err(|e| Error::Endpoint(format!("{} is not a signing key: {e}", path.display())))
}

// =====================================================================================
// urn:contactblock:link — mint the link (edge daemon)
// =====================================================================================

/// Mints the signed block URL for one enquiry sender. Invoked by `contact-handler.scm` as it
/// composes the enquiry email. See the [module docs](crate::contactblock).
pub struct ContactBlockLink {
    /// Where the signing (private) key lives. Injected so the host owns the layout and a test
    /// can point at its own key.
    pub key_path: std::path::PathBuf,
}

impl Default for ContactBlockLink {
    fn default() -> Self {
        Self {
            key_path: private_key_path(),
        }
    }
}

#[async_trait::async_trait]
impl Endpoint for ContactBlockLink {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_CONTACTBLOCK_MINT) {
            return Err(Error::Denied(format!(
                "minting a block link requires `{CAP_CONTACTBLOCK_MINT}`"
            )));
        }
        let email = inv
            .inline_str("email")
            .map_err(|_| Error::MissingArgument("email".to_string()))?
            .trim()
            .to_string();
        if !email_shaped(&email) {
            return Err(Error::InvalidArgument {
                name: "email".to_string(),
                detail: format!("`{email}` is not an address to block"),
            });
        }

        let key = read_signing_key(&self.key_path)?;
        let exp = now_secs() + TTL_SECONDS;
        let token = mint_token(&email, exp, &key);
        let url = format!(
            "{}?email={}&exp={exp}&t={}\n",
            link_base(),
            urlencode(&email),
            urlencode(&token)
        );
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            url.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "contactblock-link"
    }

    fn describe(&self) -> Description {
        Description::new("contactblock-link")
            .title("Mint a block link for an enquiry sender")
            .summary(
                "A signed, expiring URL that blocks one address at the edge — ready to drop into \
                 the enquiry email.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint — the signed block link for one address")
                    .requires(CAP_CONTACTBLOCK_MINT)
                    .input(ArgSpec::new("email").summary("the sender address to block")),
            )
            .output("text/plain; charset=utf-8")
    }
}

// =====================================================================================
// urn:contact-block — the clicked link (edge http face)
// =====================================================================================

/// `/contact-block` — the emailed "block this sender" link. **GET shows** what it would block
/// with a button; **POST records** the block into a space for the daemon to apply.
///
/// The GET/POST split is the same guard `decide` documents: mail scanners and link-preview bots
/// fetch every URL in a message, so a decision that happened on GET would be made by a robot.
/// This face reads only a public key from a file and only DROPS into a space — it holds no
/// authority to write the blocklist itself.
pub struct ContactBlock {
    /// Where the verifying (public) key lives.
    pub key_path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for ContactBlock {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let email = param(inv, "email");
        let token = param(inv, "t");
        let exp: i64 = param(inv, "exp").parse().unwrap_or(0);

        let key = verifying_key_at(&self.key_path)?;
        if !token_valid(&email, exp, &token, &key, now_secs()) {
            // One answer for every kind of bad link — expired, forged, malformed. A prober
            // learns nothing, and for a real person the cause is almost always age.
            return Ok(page(
                "That link didn't work",
                "<p>It may have expired. A fresh enquiry from that sender carries a new one.</p>",
            ));
        }

        match inv.request.verb {
            // SHOW: the address this would block, and a button to do it.
            Verb::Source => Ok(page(
                "Block this sender?",
                &format!(
                    "<p>Future enquiries from <code>{email}</code> will be dropped, silently.</p>\
                     <form method=\"post\" id=\"act\">\
                     <input type=hidden name=email value=\"{email}\">\
                     <input type=hidden name=exp value=\"{exp}\">\
                     <input type=hidden name=t value=\"{token}\">\
                     <button style=\"font:inherit;padding:.6rem 1.2rem\">Block</button>\
                     </form>\
                     <p style=\"color:#666\">They are told nothing; from their side the form still \
                     accepts. You can undo this on the box.</p>{js}",
                    js = crate::passkey::DECISION_PASSKEY_JS,
                ),
            )),
            // ACT: record the intent. The daemon's reactor writes the blocklist when it drains.
            Verb::Sink => {
                // Passkey second factor — inert until a credential is enrolled, then required.
                // The assertion rides in the POST body (pk_* fields the glue-JS adds).
                if crate::passkey::require_passkey(inv).is_err() {
                    return Ok(page(
                        "Your passkey is needed",
                        "<p>Blocking this sender needs a tap on your registered device. Reopen \
                         the link and try again.</p>",
                    ));
                }
                let tuple = format!(
                    "((block-email {}) (exp {}))",
                    quoted(&email),
                    quoted(&exp.to_string())
                );
                inv.issue(
                    Request::new(
                        Verb::Sink,
                        Iri::parse(CONTACT_BLOCKS_SPACE).expect("literal IRI"),
                    )
                    .with_arg("content", ArgRef::Inline(tuple.into_bytes())),
                )
                .await?;
                Ok(page(
                    "Blocked",
                    &format!(
                        "<p>Enquiries from <code>{email}</code> will be dropped once the edge \
                         picks this up — usually at once.</p>"
                    ),
                ))
            }
            other => Err(Error::Endpoint(format!(
                "a block link is shown with Source or acted with Sink, not {other:?}"
            ))),
        }
    }

    fn name(&self) -> &str {
        "contact-block"
    }

    fn describe(&self) -> Description {
        Description::new("contact-block")
            .title("Block an enquiry sender")
            .summary(
                "The emailed block link. GET verifies the token and shows what it would block; \
                 POST records the block for the edge to apply. Records intent only.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("show — the address this link would block")
                    .input(ArgSpec::new("email").summary("the sender address"))
                    .input(ArgSpec::new("exp").summary("expiry, unix seconds"))
                    .input(ArgSpec::new("t").summary("the signature")),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("block — record the block")
                    .input(ArgSpec::new("email").summary("the sender address"))
                    .input(ArgSpec::new("exp").summary("expiry, unix seconds"))
                    .input(ArgSpec::new("t").summary("the signature")),
            )
            .output("text/html; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    const EMAIL: &str = "price@spam.example";
    const NOW: i64 = 1_800_000_000;
    const EXP: i64 = NOW + 600;

    #[test]
    fn a_freshly_minted_token_verifies() {
        let k = key();
        let t = mint_token(EMAIL, EXP, &k);
        assert!(token_valid(EMAIL, EXP, &t, &k.verifying_key(), NOW));
    }

    #[test]
    fn a_token_is_bound_to_its_address_and_expiry() {
        let k = key();
        let v = k.verifying_key();
        let t = mint_token(EMAIL, EXP, &k);
        // Re-pointing a block token at another address, or stretching its expiry, must not
        // verify — otherwise one link would block anyone.
        assert!(!token_valid("someone@else.example", EXP, &t, &v, NOW));
        assert!(!token_valid(EMAIL, EXP + 1, &t, &v, NOW));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let k = key();
        let t = mint_token(EMAIL, EXP, &k);
        assert!(!token_valid(EMAIL, EXP, &t, &k.verifying_key(), EXP + 1));
    }

    #[test]
    fn another_key_cannot_sign_a_block() {
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let t = mint_token(EMAIL, EXP, &theirs);
        assert!(!token_valid(EMAIL, EXP, &t, &key().verifying_key(), NOW));
    }

    #[test]
    fn garbage_tokens_are_refused_without_panicking() {
        let v = key().verifying_key();
        for bad in ["", "!!!!", "c2hvcnQ", &"A".repeat(200)] {
            assert!(!token_valid(EMAIL, EXP, bad, &v, NOW), "{bad}");
        }
    }

    #[test]
    fn a_malformed_address_never_reaches_the_signature_check() {
        let k = key();
        let v = k.verifying_key();
        let t = mint_token(EMAIL, EXP, &k);
        // No `@`, a quote/backslash that could reshape the tuple, a control char, empty, and
        // an over-long address are all rejected before the signature is even considered.
        for bad in [
            "no-at-sign",
            "x@y\"; DROP",
            "back\\slash@x",
            "with\nnewline@x",
            "",
        ] {
            assert!(!email_shaped(bad), "should be malformed: {bad:?}");
            assert!(!token_valid(bad, EXP, &t, &v, NOW), "{bad:?}");
        }
        assert!(!email_shaped(&format!("{}@x", "a".repeat(300))));
        assert!(email_shaped(EMAIL));
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePublicKey};
    use futures::executor::block_on;
    use ikigai_core::{Capability, EndpointSpace, Exact, Kernel};
    use std::sync::{Arc, Mutex};

    const EMAIL: &str = "price@spam.example";

    /// Records whatever is dropped into the contact-blocks space.
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
            "contact-blocks"
        }
        fn describe(&self) -> Description {
            Description::new("contact-blocks").verb(Verb::Sink)
        }
    }

    struct World {
        kernel: Kernel,
        dropped: Arc<Mutex<Vec<String>>>,
        key: SigningKey,
        _dir: std::path::PathBuf,
    }

    fn world(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("ikigai-contactblock-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        // Write the public half as `openssl … -pubout` would: SPKI PEM.
        let pub_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_path = dir.join("contact-block.pub");
        std::fs::write(&key_path, pub_pem).unwrap();

        let recorder = Recorder::default();
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:contact-block"), ContactBlock { key_path })
                .bind(Exact::new(CONTACT_BLOCKS_SPACE), recorder.clone()),
        ));
        World {
            kernel,
            dropped: recorder.dropped,
            key,
            _dir: dir,
        }
    }

    impl World {
        fn call(&self, verb: Verb, email: &str, exp: i64, token: &str) -> String {
            let rep = block_on(
                self.kernel.issue(
                    Request::new(verb, Iri::parse("urn:contact-block").unwrap())
                        .with_arg("email", ArgRef::Inline(email.as_bytes().to_vec()))
                        .with_arg("exp", ArgRef::Inline(exp.to_string().into_bytes()))
                        .with_arg("t", ArgRef::Inline(token.as_bytes().to_vec())),
                    &Capability::root(),
                ),
            )
            .expect("the page should render");
            String::from_utf8(rep.bytes.clone()).unwrap()
        }
        fn post_form(&self, email: &str, exp: i64, token: &str) -> String {
            let body = format!("email={}&exp={exp}&t={token}", urlencode(email));
            let rep = block_on(
                self.kernel.issue(
                    Request::new(Verb::Sink, Iri::parse("urn:contact-block").unwrap())
                        .with_arg("content", ArgRef::Inline(body.into_bytes())),
                    &Capability::root(),
                ),
            )
            .expect("the page should render");
            String::from_utf8(rep.bytes.clone()).unwrap()
        }
        fn valid(&self) -> (i64, String) {
            let exp = now_secs() + 600;
            (exp, mint_token(EMAIL, exp, &self.key))
        }
        fn dropped(&self) -> Vec<String> {
            self.dropped.lock().unwrap().clone()
        }
    }

    #[test]
    fn a_get_shows_the_block_but_records_nothing() {
        // THE property that makes emailing these links safe: a mail scanner fetching the URL
        // must not block anyone.
        let w = world("get");
        let (exp, token) = w.valid();
        let html = w.call(Verb::Source, EMAIL, exp, &token);
        assert!(html.contains("Block this sender?"), "{html}");
        assert!(html.contains(EMAIL), "{html}");
        assert!(
            html.contains("method=\"post\""),
            "offers a POST button: {html}"
        );
        assert!(w.dropped().is_empty(), "a GET must record nothing");
    }

    #[test]
    fn a_post_records_the_block() {
        let w = world("post");
        let (exp, token) = w.valid();
        let html = w.post_form(EMAIL, exp, &token);
        assert!(html.contains("Blocked"), "{html}");
        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(
            crate::decide::field(&dropped[0], "block-email").as_deref(),
            Some(EMAIL)
        );
    }

    #[test]
    fn a_forged_or_expired_token_records_nothing() {
        let w = world("forged");
        let (exp, _) = w.valid();
        let forged = mint_token(EMAIL, exp, &SigningKey::from_bytes(&[9u8; 32]));
        assert!(w.post_form(EMAIL, exp, &forged).contains("didn't work"));

        let stale = now_secs() - 1;
        let stale_token = mint_token(EMAIL, stale, &w.key);
        assert!(w
            .post_form(EMAIL, stale, &stale_token)
            .contains("didn't work"));

        assert!(w.dropped().is_empty(), "neither is recorded");
    }

    #[test]
    fn a_token_for_one_address_cannot_block_another() {
        // The address is in the signed payload, so swapping it in the POST body is refused.
        let w = world("swap");
        let (exp, token) = w.valid();
        let html = w.post_form("victim@example.com", exp, &token);
        assert!(html.contains("didn't work"), "{html}");
        assert!(w.dropped().is_empty(), "nothing recorded");
    }
}
