//! Block a contact enquiry's sender, or teach the spam filter about an enquiry, from an
//! emailed link.
//!
//! Phase 1 gave the edge a blocklist (`urn:decisions`, `action=block`) that the public intake
//! consults to drop a known-bad sender at the door. Recording a block, though, meant a shell on
//! the box. This is the way to block from a phone: every enquiry email carries a "block this
//! sender" link, so an unwanted repeat is one tap away.
//!
//! Since ledger #1513 the email also carries the spam filter's verdict (shadow mode: every
//! enquiry is still mailed) and two LABEL links, "not spam" and "spam after all", so Brian's
//! clicks teach the `contact` model. A block link that names its enquiry teaches it too: the
//! block is the strongest "this is spam" there is.
//!
//! It mirrors [`crate::decide`] deliberately — same token shape, same GET-shows/POST-acts split,
//! same "the public face only RECORDS into a space" airlock — and reuses its crypto and HTTP
//! helpers so there is one implementation of the delicate parts. The differences are all about
//! scope, and all in the direction of *less* authority:
//!
//! | | `decide` (booking) | `contactblock` (this) |
//! |---|---|---|
//! | signs | `<id>\|<action>\|<exp>` | `contact-block\|<email>\|<enquiry>\|<exp>`, `contact-label\|<label>\|<enquiry>\|<class>\|<exp>` |
//! | key | `urn:secret:booking-decide`, **Mac-only**, Keychain | `contact-block.key`, **edge-local file** |
//! | worst case if forged | approve/decline a booking | block an enquiry sender, or nudge the spam model |
//! | who acts | the **Mac** re-verifies, then writes the calendar | an edge reactor writes the edge blocklist and trains the model |
//!
//! ## Two machines, five endpoints
//!
//! | endpoint | runs on | authority | does |
//! |---|---|---|---|
//! | `urn:contactblock:link` | edge daemon | `urn:cap:contactblock:mint` | mints the signed block URL to email |
//! | `urn:contactlabel:link` | edge daemon | `urn:cap:contactblock:mint` | mints a signed label URL (`spam`/`ham`, with the filter's class) to email |
//! | `urn:contact-block` | edge http face | public (route ceiling) | GET shows, POST records a block |
//! | `urn:contact-label` | edge http face | public (route ceiling) | GET shows, POST records a label |
//! | `urn:contactblock:apply` | edge daemon reactor | its space's authority file | drains the space: writes the block, trains the model |
//!
//! ## One key, two actions, and why they cannot be confused
//!
//! The label links are signed with the SAME `contact-block.key` as the block links. Both
//! actions sit in one trust domain (the edge), the worst a stolen key buys is the same kind of
//! thing for both (block a sender; push the model toward a label, which an `untrain` or the
//! opposite click undoes), and whoever can read one key file can read a second beside it, so a
//! second key would add a deploy step and no separation. What keeps the two apart is the
//! payload: every payload STARTS with its action (`contact-block|`, `contact-label|`), so a
//! signature over one can never verify as the other, and every variable part has a fixed
//! grammar (an address with no `|`, a 64-hex enquiry id or nothing, a label from a closed set,
//! a class from a closed set or nothing, a number), so no field can be stretched to imitate the
//! next.
//!
//! A block link minted before ledger #1513 signed the bare `<email>|<exp>`. It is still
//! accepted, ONLY when the link names no enquiry, so a link already in someone's inbox keeps
//! working for its week; a bare payload can never verify as a label (no address shape starts
//! `contact-label|`, and an address may not contain `|`). Remove that branch once every such
//! link has expired: seven days after the edge runs this.
//!
//! ## The filter's class travels in the label link
//!
//! Since ledger #3868 a label link also signs the CLASS the spam filter gave the enquiry when
//! it was emailed (`spam`, `unsure`, `ham` or `unscored`, or empty when the minter was given
//! none), and the click's drop carries it as `class`. The apply program cannot read the contact
//! outbox's notes, and scoring the enquiry again would give today's class, not the one the
//! email showed; signing it means a link cannot be re-pointed at another class. A label link
//! minted before that signed the 4-field `contact-label|<label>|<enquiry>|<exp>`: it is still
//! accepted, ONLY when the link carries no class, and its drop carries none. Remove that branch
//! once every such link has expired: seven days after the edge runs this, so no earlier than
//! 2026-11-27.
//!
//! ## Naming the enquiry, never carrying it
//!
//! A link names its enquiry by the enquiry tuple's id in the contact space (its content
//! address, [`ikigai_intray::tuple_id`]), never by its text: the text stays on the edge, in
//! `spaces/contact/outbox/<id>.tuple`, where the reactor left it. The minters take the enquiry
//! tuple exactly as the reactor handed it to the handler, because the handler, a Lisp program,
//! reads its tuple through `(input)` and cannot see the `tuple=<id>` the reactor passes beside
//! it.
//!
//! That id is the hash of the STORED bytes. Under a sealed space ([`crate::space_seal`]) those
//! are age ciphertext, so the hash of the text a minter is handed names no stored tuple (ledger
//! #3713). The host therefore wraps the contact handler in [`HandlerTupleIds`]: while a pass
//! runs it, the reactor's `tuple=` is noted against the hash of the tuple's text, and a minter
//! handed that text names the noted id. Handed text no running pass noted (a minter called by
//! hand), it names the hash of the text, which is the stored id whenever the space is not
//! sealed. A reseal stores every tuple again under a new id and leaves a forward from the old
//! one ([`crate::space_seal::current_id`]), and the link faces follow it when they record the
//! click, so a link emailed before a reseal still names its enquiry after it.
//!
//! The apply reactor reads the text back through the
//! kernel, `source urn:space:contact tuple=<id> state=outbox`, under the one-space grant
//! `urn:cap:space:read:contact` ([`ikigai_intray::cap_read_space`]), and trains on it.
//!
//! ## Why no second verify (unlike `decide`)
//!
//! `decide` verifies again on the Mac because the Mac is a *higher* trust domain than the edge —
//! a compromised edge must not be able to manufacture a calendar write. Here there is no such
//! hop: the click and the apply are both on the edge. The token is checked once, at the click,
//! and the airlock exists for one reason only — to keep `decisions:write` and the model's
//! `bayes:train` off the internet-facing HTTP ceiling, so a bug in the public face can drop an
//! *intent* but never write the blocklist or teach the model. The apply reactor, which is not
//! internet-facing, holds that authority.
//!
//! ## The low-value key
//!
//! The signing half is a plain file (`contact-block.key`, PKCS8 PEM) in the workspace, generated
//! once on the edge with `openssl`. It earns no Keychain custody because the most a stolen key
//! buys is the power to block enquiry senders or mislabel enquiries — annoying, fully
//! recoverable, and confined to the edge. The public half (`contact-block.pub`, SPKI PEM) is what
//! the internet-facing face reads, so that process needs no signing authority at all — exactly
//! as `decide.pub` works for bookings.

use crate::decide::{
    b64, now_secs, page, param, parse_signing_key, quoted, urlencode, verifying_key_at,
};
use crate::{file_root, prg};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, Error, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};
use ikigai_fn::html::{attr, html_text};

/// Mint a block or label link. Held by the edge daemon (where the enquiry email is composed).
pub const CAP_CONTACTBLOCK_MINT: &str = "urn:cap:contactblock:mint";

/// The space a verified block or label is dropped into on the public face, and drained from by
/// the daemon's apply reactor.
pub const CONTACT_BLOCKS_SPACE: &str = "urn:space:contact-blocks";

/// How long an emailed link stays good — the same week `decide` uses. A spammer worth
/// blocking is worth blocking now; a stale link just wants re-sending from a fresh enquiry.
const TTL_SECONDS: i64 = 7 * 24 * 3600;

/// The labels a label link can teach. A closed set: the model's own two classes.
pub const LABELS: [&str; 2] = ["spam", "ham"];

/// The classes the spam filter can have given an enquiry when it was emailed, which a label
/// link carries signed (ledger #3868). A closed set; a link may also carry none.
pub const CLASSES: [&str; 4] = ["spam", "unsure", "ham", "unscored"];

/// The largest enquiry a minter accepts, in bytes. The intake's own field bounds keep a real
/// enquiry far below it; past it the mint is refused, never truncated (a truncated tuple would
/// name an enquiry that does not exist).
pub const MAX_ENQUIRY_BYTES: usize = 256 * 1024;

/// The action each signed payload starts with. Distinct, and neither is a possible address
/// (no `@`), so a token signed for one action never verifies as another.
const BLOCK_ACTION: &str = "contact-block";
const LABEL_ACTION: &str = "contact-label";

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

/// Where the emailed block link points. Override with `IKIGAI_CONTACTBLOCK_BASE`.
fn link_base() -> String {
    std::env::var("IKIGAI_CONTACTBLOCK_BASE")
        .unwrap_or_else(|_| "https://ikigai-rs.dev/contact-block".to_string())
}

/// Where the emailed label link points. Override with `IKIGAI_CONTACTLABEL_BASE`.
fn label_link_base() -> String {
    std::env::var("IKIGAI_CONTACTLABEL_BASE")
        .unwrap_or_else(|_| "https://ikigai-rs.dev/contact-label".to_string())
}

/// What a block link signs: the action, the address to block, the enquiry it came from (its
/// tuple id, or empty when the link names none) and an expiry. The address and the enquiry are
/// IN the payload, so a valid link cannot be re-pointed at another sender or another enquiry.
/// The bytes are pinned by `the_signed_payloads_start_with_their_action`.
fn block_payload(email: &str, enquiry: &str, exp: i64) -> String {
    format!("{BLOCK_ACTION}|{email}|{enquiry}|{exp}")
}

/// The payload a block link signed before ledger #1513: `<email>|<exp>`, no action, no
/// enquiry. Verified only, never minted; see the module docs for when it goes.
fn legacy_block_payload(email: &str, exp: i64) -> String {
    format!("{email}|{exp}")
}

/// What a label link signs: the action, the label, the enquiry's tuple id, the class the
/// filter gave the enquiry when it was emailed (empty when the link carries none) and an
/// expiry. The class is IN the payload, so a link cannot be re-pointed at another class.
/// The bytes are pinned by `the_signed_payloads_start_with_their_action`.
fn label_payload(label: &str, enquiry: &str, class: &str, exp: i64) -> String {
    format!("{LABEL_ACTION}|{label}|{enquiry}|{class}|{exp}")
}

/// The payload a label link signed before ledger #3868: `contact-label|<label>|<enquiry>|<exp>`,
/// no class. Verified only, never minted, and only for a link that carries no class. Remove it
/// (and its branch in [`label_valid`]) once every such link has expired: seven days after the
/// edge runs this, so no earlier than 2026-11-27.
fn legacy_label_payload(label: &str, enquiry: &str, exp: i64) -> String {
    format!("{LABEL_ACTION}|{label}|{enquiry}|{exp}")
}

/// A conservative address gate. The value is signed, so this is not a security boundary — it is
/// to keep a malformed address out of the tuple we drop and the block record we write. Deliberately
/// loose on the local/domain shape (real addresses are varied) but strict on length and on the
/// control characters that could reshape a tuple or an SMTP header downstream, and on `|`, the
/// payload's separator, so an address can never imitate the fields after it.
fn email_shaped(email: &str) -> bool {
    (3..=254).contains(&email.len())
        && email.contains('@')
        && !email.chars().any(|c| c.is_control())
        && !email.contains('"')
        && !email.contains('\\')
        && !email.contains('|')
}

/// An enquiry id: exactly the shape [`ikigai_intray::tuple_id`] produces, 64 lowercase hex
/// characters. Checked before any signature is, and again by the space when the apply reactor
/// reads the tuple.
fn enquiry_id_shaped(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sign(payload: &str, key: &SigningKey) -> String {
    b64().encode(key.sign(payload.as_bytes()).to_bytes())
}

/// Did this key sign exactly `payload`? Any decoding failure is a plain `false`.
fn signed(payload: &str, token: &str, key: &VerifyingKey) -> bool {
    let Ok(raw) = b64().decode(token) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    key.verify(payload.as_bytes(), &Signature::from_bytes(&bytes))
        .is_ok()
}

fn mint_block(email: &str, enquiry: &str, exp: i64, key: &SigningKey) -> String {
    sign(&block_payload(email, enquiry, exp), key)
}

fn mint_label(label: &str, enquiry: &str, class: &str, exp: i64, key: &SigningKey) -> String {
    sign(&label_payload(label, enquiry, class, exp), key)
}

/// Is `token` a block signature this key made over exactly this address, enquiry and expiry,
/// still in date? Every failure is a plain `false`, so a prober learns nothing from the shape of
/// the answer.
fn block_valid(
    email: &str,
    enquiry: &str,
    exp: i64,
    token: &str,
    key: &VerifyingKey,
    now: i64,
) -> bool {
    if !email_shaped(email) || !(enquiry.is_empty() || enquiry_id_shaped(enquiry)) || exp <= now {
        return false;
    }
    signed(&block_payload(email, enquiry, exp), token, key)
        // A link minted before the action tag: it named no enquiry, so it may name none now.
        || (enquiry.is_empty() && signed(&legacy_block_payload(email, exp), token, key))
}

/// Is `token` a label signature this key made over exactly this label, enquiry, class (empty
/// for none) and expiry, still in date? Same uniform `false` as [`block_valid`].
fn label_valid(
    label: &str,
    enquiry: &str,
    class: &str,
    exp: i64,
    token: &str,
    key: &VerifyingKey,
    now: i64,
) -> bool {
    if !LABELS.contains(&label)
        || !enquiry_id_shaped(enquiry)
        || !(class.is_empty() || CLASSES.contains(&class))
        || exp <= now
    {
        return false;
    }
    signed(&label_payload(label, enquiry, class, exp), token, key)
        // A link minted before the class (ledger #3868): it carried no class, so it may carry
        // none now. Remove once every such link has expired, no earlier than 2026-11-27.
        || (class.is_empty() && signed(&legacy_label_payload(label, enquiry, exp), token, key))
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

/// The id of the enquiry a minter was handed (`enquiry=`, the tuple as the reactor handed it),
/// or `None` when it was handed none and `required` is false.
fn enquiry_of(inv: &Invocation<'_>, required: bool) -> Result<Option<String>> {
    let text = match inv.optional_arg("enquiry")? {
        Some(bytes) => bytes,
        None if !required => return Ok(None),
        None => return Err(Error::MissingArgument("enquiry".to_string())),
    };
    if text.is_empty() || text.len() > MAX_ENQUIRY_BYTES {
        return Err(Error::InvalidArgument {
            name: "enquiry".to_string(),
            detail: format!(
                "the enquiry is {} bytes; a link names an enquiry of 1 to {MAX_ENQUIRY_BYTES} \
                 bytes (refused, not truncated)",
                text.len()
            ),
        });
    }
    Ok(Some(stored_id_of(text)))
}

// =====================================================================================
// The stored id of the tuple a handler is handling (ledger #3713)
// =====================================================================================

/// The stored ids of the tuples handlers are running on now, by the hash of each one's text.
/// A list per text: the same enquiry dropped twice is two tuples under a sealed space.
static HANDLING: std::sync::Mutex<std::collections::BTreeMap<String, Vec<String>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn handling() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<String, Vec<String>>> {
    HANDLING.lock().unwrap_or_else(|p| p.into_inner())
}

/// The id the space stores the tuple whose text is `text` under: the reactor's `tuple=` for a
/// pass running on it, else the hash of the text (the stored id when no codec is configured).
fn stored_id_of(text: &[u8]) -> String {
    let plain = ikigai_intray::tuple_id(text);
    handling()
        .get(&plain)
        .and_then(|ids| ids.last().cloned())
        .unwrap_or(plain)
}

/// Notes a running pass's stored id, and forgets it when the pass ends (or is dropped).
struct Noted {
    plain: String,
    stored: String,
}

impl Noted {
    fn new(plain: String, stored: String) -> Noted {
        handling()
            .entry(plain.clone())
            .or_default()
            .push(stored.clone());
        Noted { plain, stored }
    }
}

impl Drop for Noted {
    fn drop(&mut self) {
        let mut map = handling();
        if let Some(ids) = map.get_mut(&self.plain) {
            if let Some(at) = ids.iter().rposition(|id| *id == self.stored) {
                ids.remove(at);
            }
            if ids.is_empty() {
                map.remove(&self.plain);
            }
        }
    }
}

/// A reactor's handler, wrapped so the minters it calls name the tuple by the id the space
/// stores it under (see the [module docs](crate::contactblock)). Given the reactor's
/// `tuple=<id>` and its `content` (or `in`), it notes the id against the hash of the content
/// for as long as the handler runs; it changes nothing else about the call.
pub struct HandlerTupleIds<E> {
    inner: E,
}

impl<E> HandlerTupleIds<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<E: Endpoint> Endpoint for HandlerTupleIds<E> {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // optional-arg: deliberate: this best-effort annotation leaves argument validation
        // to the wrapped endpoint, which may accept input this wrapper cannot read inline.
        let stored = inv
            .inline_str("tuple")
            .ok()
            .filter(|id| enquiry_id_shaped(id))
            .map(str::to_string);
        // optional-arg: deliberate: only inline bytes can be hashed here, and the wrapped
        // endpoint still receives the original invocation, including any body or reference.
        let text = inv
            .inline_arg("content")
            .or_else(|_| inv.inline_arg("in"))
            .ok();
        let _noted = match (stored, text) {
            (Some(stored), Some(text)) => Some(Noted::new(ikigai_intray::tuple_id(text), stored)),
            _ => None,
        };
        self.inner.invoke(inv).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn describe(&self) -> Description {
        self.inner.describe()
    }
}

/// The id the enquiry a clicked link names has now in the contact space: the same id unless a
/// reseal moved the tuple since the link was minted ([`crate::space_seal::current_id`]). The
/// token was checked against the id as minted; only the recorded intent carries the new one.
fn current_enquiry(enquiry: &str) -> String {
    if enquiry.is_empty() {
        return String::new();
    }
    crate::space_seal::current_id(&file_root().join("spaces"), CONTACT_SPACE, enquiry)
}

/// The space the enquiries are dropped into, and which the links name them in.
pub const CONTACT_SPACE: &str = "contact";

fn enquiry_spec(summary: &str) -> ArgSpec {
    ArgSpec::new("enquiry")
        .summary(summary)
        .class(crate::XSD_STRING)
}

fn url_answer(url: String) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        url.into_bytes(),
    )
}

fn require_mint(inv: &Invocation<'_>, what: &str) -> Result<()> {
    if inv.capability.allows(CAP_CONTACTBLOCK_MINT) {
        Ok(())
    } else {
        Err(Error::Denied(
            format!("minting a {what} link requires `{CAP_CONTACTBLOCK_MINT}`").into(),
        ))
    }
}

// =====================================================================================
// urn:contactblock:link — mint the block link (edge daemon)
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
        require_mint(inv, "block")?;
        let email = inv.inline_str("email")?.trim().to_string();
        if !email_shaped(&email) {
            return Err(Error::InvalidArgument {
                name: "email".to_string(),
                detail: format!("`{email}` is not an address to block"),
            });
        }
        let enquiry = enquiry_of(inv, false)?.unwrap_or_default();

        let key = read_signing_key(&self.key_path)?;
        let exp = now_secs() + TTL_SECONDS;
        let token = mint_block(&email, &enquiry, exp, &key);
        let id = if enquiry.is_empty() {
            String::new()
        } else {
            format!("&id={enquiry}")
        };
        Ok(url_answer(format!(
            "{}?email={}{id}&exp={exp}&t={}\n",
            link_base(),
            urlencode(&email),
            urlencode(&token)
        )))
    }

    fn name(&self) -> &str {
        "contactblock-link"
    }

    fn describe(&self) -> Description {
        Description::new("contactblock-link")
            .title("Mint a block link for an enquiry sender")
            .summary(
                "A signed, expiring URL that blocks one address at the edge — ready to drop into \
                 the enquiry email. Given the enquiry, the block also teaches the spam filter \
                 that enquiry is spam.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint — the signed block link for one address")
                    .requires(CAP_CONTACTBLOCK_MINT)
                    .input(
                        ArgSpec::new("email")
                            .summary("the sender address to block")
                            .class(crate::XSD_STRING),
                    )
                    .input(enquiry_spec(
                        "the enquiry tuple exactly as the reactor handed it; the link names it \
                         by its id in the contact space, never by its text",
                    ).optional())
                    // On the ACTION: `action_specs()` takes an explicit `ActionSpec` WHOLE
                    // and never folds the flat `.output()` below into it, so the flat
                    // declaration alone announced nothing.
                    .output("text/plain; charset=utf-8"),
            )
            .output("text/plain; charset=utf-8")
    }
}

// =====================================================================================
// urn:contactlabel:link — mint a label link (edge daemon)
// =====================================================================================

/// Mints the signed label URL ("not spam" is `label=ham`, "spam after all" is `label=spam`)
/// for one enquiry. Invoked by `contact-handler.scm` as it composes the enquiry email. Same key
/// and same grant as [`ContactBlockLink`]; see the [module docs](crate::contactblock) for why.
pub struct ContactLabelLink {
    /// Where the signing (private) key lives.
    pub key_path: std::path::PathBuf,
}

impl Default for ContactLabelLink {
    fn default() -> Self {
        Self {
            key_path: private_key_path(),
        }
    }
}

#[async_trait::async_trait]
impl Endpoint for ContactLabelLink {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        require_mint(inv, "label")?;
        let label = inv.inline_str("label")?.trim().to_string();
        if !LABELS.contains(&label.as_str()) {
            return Err(Error::InvalidArgument {
                name: "label".to_string(),
                detail: format!("`{label}` is not a label ({})", LABELS.join(", ")),
            });
        }
        // The class the filter gave the enquiry, optional. Given, it must be one of the set
        // (an empty value is not "none": a caller that has no class leaves the argument out).
        let class = match inv.optional_str("class")? {
            Some(c) => {
                let c = c.trim().to_string();
                if !CLASSES.contains(&c.as_str()) {
                    return Err(Error::InvalidArgument {
                        name: "class".to_string(),
                        detail: format!("`{c}` is not a class ({})", CLASSES.join(", ")),
                    });
                }
                c
            }
            None => String::new(),
        };
        let enquiry = enquiry_of(inv, true)?.unwrap_or_default();

        let key = read_signing_key(&self.key_path)?;
        let exp = now_secs() + TTL_SECONDS;
        let token = mint_label(&label, &enquiry, &class, exp, &key);
        let class_param = if class.is_empty() {
            String::new()
        } else {
            format!("&class={class}")
        };
        Ok(url_answer(format!(
            "{}?id={enquiry}&label={label}{class_param}&exp={exp}&t={}\n",
            label_link_base(),
            urlencode(&token)
        )))
    }

    fn name(&self) -> &str {
        "contactlabel-link"
    }

    fn describe(&self) -> Description {
        Description::new("contactlabel-link")
            .title("Mint a spam-filter label link for an enquiry")
            .summary(
                "A signed, expiring URL that teaches the edge's spam filter one enquiry's label \
                 (`ham` = not spam, `spam` = spam after all) — ready to drop into the enquiry \
                 email. Names the enquiry by its id; never carries its text. Given `class`, the \
                 class the filter gave the enquiry, the link signs it and the click's drop \
                 carries it as `class`.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint — the signed label link for one enquiry")
                    .requires(CAP_CONTACTBLOCK_MINT)
                    .input(
                        ArgSpec::new("label")
                            .summary("the label the link teaches")
                            .class(crate::XSD_STRING)
                            .one_of(LABELS),
                    )
                    .input(
                        ArgSpec::new("class")
                            .summary(
                                "optional: the class the filter gave the enquiry when it was \
                                 emailed; signed into the link and carried by its drop",
                            )
                            .class(crate::XSD_STRING)
                            .one_of(CLASSES)
                            .optional(),
                    )
                    .input(enquiry_spec(
                        "the enquiry tuple exactly as the reactor handed it; the link names it \
                         by its id in the contact space, never by its text",
                    ))
                    .output("text/plain; charset=utf-8"),
            )
            .output("text/plain; charset=utf-8")
    }
}

// =====================================================================================
// urn:contact-block — the clicked block link (edge http face)
// =====================================================================================

/// One answer for every kind of bad link — expired, forged, malformed, swapped. A prober learns
/// nothing, and for a real person the cause is almost always age.
fn bad_link() -> Representation {
    page(
        "That link didn't work",
        "<p>It may have expired. A fresh enquiry from that sender carries a new one.</p>",
    )
}

/// The outcome words a block or label POST redirects with (see [`crate::prg`]), beside
/// [`prg::ALREADY`]. A label's word is the label itself, so its page can say which was taught.
const BLOCKED: &str = "blocked";
const INVALID: &str = "invalid";
const PASSKEY: &str = "passkey";

/// The page a block POST redirects to. Generic by design: its URL carries no address, so it
/// says what happened and never to whom.
fn block_outcome(word: &str) -> Representation {
    match word {
        BLOCKED => page(
            "Blocked",
            "<p>Enquiries from that sender will be dropped once the edge picks this up — \
             usually at once.</p>",
        ),
        prg::ALREADY => already_page(),
        PASSKEY => page(
            "Your passkey is needed",
            "<p>Blocking this sender needs a tap on your registered device. Reopen the link \
             and try again.</p>",
        ),
        _ => bad_link(),
    }
}

/// The page a label POST redirects to: the label taught (`ham` or `spam`), never the enquiry.
fn label_outcome(word: &str) -> Representation {
    match word {
        "ham" | "spam" => page(
            if word == "ham" {
                "Marked as not spam"
            } else {
                "Marked as spam"
            },
            "<p>The filter learns this once the edge picks it up — usually at once.</p>",
        ),
        prg::ALREADY => already_page(),
        PASSKEY => page(
            "Your passkey is needed",
            "<p>Labeling this enquiry needs a tap on your registered device. Reopen the link \
             and try again.</p>",
        ),
        _ => bad_link(),
    }
}

fn already_page() -> Representation {
    page(
        "Already recorded",
        "<p>This link's decision was recorded before. Nothing more was done.</p>",
    )
}

/// The `outcome` a GET of a link page may carry: the word its POST redirected with.
fn outcome_spec(words: &[&str]) -> ArgSpec {
    ArgSpec::new(prg::OUTCOME)
        .optional()
        .class(crate::XSD_STRING)
        .one_of(words.iter().copied())
        .summary(
            "the outcome a POST redirected to (Post/Redirect/Get); with it, the page shows what \
             happened and needs no link fields",
        )
}

/// Record `tuple` once for the link `token` (valid until `exp`), and answer the POST with the
/// redirect: `done` when it was recorded now, [`prg::ALREADY`] when this link was acted on
/// before. A failed drop gives the claim back, so the link can be tried again.
#[allow(clippy::too_many_arguments)] // one call per endpoint, each naming every part
async fn record_once(
    inv: &Invocation<'_>,
    scope: &str,
    key: &std::path::Path,
    token: &str,
    exp: i64,
    tuple: String,
    done: &'static str,
    outcome: fn(&str) -> Representation,
) -> Result<Representation> {
    if !prg::claim(scope, key, token, exp, now_secs())? {
        return Ok(prg::see_other(prg::ALREADY, outcome(prg::ALREADY)));
    }
    if let Err(e) = drop_intent(inv, tuple).await {
        prg::release(scope, key, token);
        return Err(e);
    }
    Ok(prg::see_other(done, outcome(done)))
}

/// The form both link pages post back to themselves, with the passkey glue. Values and the
/// button are escaped (ledger #1516); the names are this module's own literals.
fn confirm_form(fields: &[(&str, &str)], button: &str) -> String {
    let hidden: String = fields
        .iter()
        .map(|(name, value)| format!("<input type=hidden name={name} value=\"{}\">", attr(value)))
        .collect();
    format!(
        "<form method=\"post\" id=\"act\">{hidden}\
         <button>{}</button>\
         </form>",
        html_text(button)
    )
}

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
        // The page a block POST redirected to (Post/Redirect/Get, ledger #1879).
        if inv.request.verb == Verb::Source {
            let word = param(inv, prg::OUTCOME)?;
            if !word.is_empty() {
                return Ok(block_outcome(&word));
            }
        }
        let email = param(inv, "email")?;
        let enquiry = param(inv, "id")?;
        let token = param(inv, "t")?;
        let exp: i64 = param(inv, "exp")?.parse().unwrap_or(0);

        let key = verifying_key_at(&self.key_path)?;
        if !block_valid(&email, &enquiry, exp, &token, &key, now_secs()) {
            return Ok(match inv.request.verb {
                Verb::Sink => prg::see_other(INVALID, bad_link()),
                _ => bad_link(),
            });
        }
        let teaches = if enquiry.is_empty() {
            ""
        } else {
            " The spam filter also learns that this enquiry was spam."
        };

        match inv.request.verb {
            // SHOW: the address this would block, and a button to do it.
            Verb::Source => {
                let exp = exp.to_string();
                let mut fields = vec![("email", email.as_str())];
                if !enquiry.is_empty() {
                    fields.push(("id", enquiry.as_str()));
                }
                fields.extend([("exp", exp.as_str()), ("t", token.as_str())]);
                Ok(page(
                    "Block this sender?",
                    &format!(
                        "<p>Future enquiries from <code>{shown}</code> will be dropped, \
                         silently.{teaches}</p>{form}\
                         <p class=muted>They are told nothing; from their side the form \
                         still accepts. You can undo this on the box.</p>{js}",
                        shown = html_text(&email),
                        form = confirm_form(&fields, "Block"),
                        js = crate::passkey::DECISION_PASSKEY_JS,
                    ),
                ))
            }
            // ACT: record the intent. The daemon's reactor writes the blocklist when it drains.
            Verb::Sink => {
                // Passkey second factor — inert until a credential is enrolled, then required.
                // The assertion rides in the POST body (pk_* fields the glue-JS adds).
                if crate::passkey::require_passkey(inv).is_err() {
                    return Ok(prg::see_other(PASSKEY, block_outcome(PASSKEY)));
                }
                let named = if enquiry.is_empty() {
                    String::new()
                } else {
                    format!(" (enquiry {})", quoted(&current_enquiry(&enquiry)))
                };
                let tuple = format!(
                    "((block-email {}){named} (exp {}))",
                    quoted(&email),
                    quoted(&exp.to_string())
                );
                record_once(
                    inv,
                    BLOCK_ACTION,
                    &self.key_path,
                    &token,
                    exp,
                    tuple,
                    BLOCKED,
                    block_outcome,
                )
                .await
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
        let inputs = |spec: ActionSpec| {
            spec.input(
                ArgSpec::new("email")
                    .summary("the sender address")
                    .class(crate::XSD_STRING),
            )
            .input(
                ArgSpec::new("id")
                    .optional()
                    .summary(
                        "the enquiry the block also teaches the spam filter about (its tuple id); \
                         a link minted without one names none",
                    )
                    .class(crate::XSD_STRING),
            )
            .input(
                ArgSpec::new("exp")
                    .summary("expiry, unix seconds")
                    .class(crate::XSD_INTEGER),
            )
            .input(
                ArgSpec::new("t")
                    .summary("the signature")
                    .class(crate::XSD_STRING),
            )
            // ⚠ DECLARED because it is READ: a `<form method=post>` puts its fields in the
            // BODY, which the HTTP face hands over as the piped `content`, and `param()` looks
            // there when a name is not an argument. Undeclared, the one channel every browser
            // submission actually uses was invisible to the manifold.
            .input(form_body_spec())
        };
        Description::new("contact-block")
            .title("Block an enquiry sender")
            .summary(
                "The emailed block link. GET verifies the token and shows what it would block; \
                 POST records the block for the edge to apply. Records intent only.",
            )
            .action(
                inputs(
                    ActionSpec::new(Verb::Source)
                        .summary("show — the address this link would block, or what a block did"),
                )
                .input(outcome_spec(&[BLOCKED, prg::ALREADY, INVALID, PASSKEY]))
                .output("text/html; charset=utf-8"),
            )
            // Every POST answers Post/Redirect/Get: the outcome page in an ikigai-web entity
            // envelope whose `Location` makes it a `303` (ledger #1879).
            .action(
                inputs(ActionSpec::new(Verb::Sink).summary("block — record the block"))
                    .output(prg::HTTP_ENTITY),
            )
            .output("text/html; charset=utf-8")
    }
}

fn form_body_spec() -> ArgSpec {
    ArgSpec::new("content")
        .optional()
        .class(crate::XSD_STRING)
        .summary(
            "a urlencoded form body; the inputs above are read from it when they are not named \
             arguments",
        )
}

/// Drop a verified intent into the airlock for the daemon's apply reactor.
async fn drop_intent(inv: &Invocation<'_>, tuple: String) -> Result<()> {
    inv.issue(
        Request::new(
            Verb::Sink,
            Iri::parse(CONTACT_BLOCKS_SPACE).expect("literal IRI"),
        )
        .with_arg("content", ArgRef::Inline(tuple.into_bytes())),
    )
    .await
    .map(|_| ())
}

// =====================================================================================
// urn:contact-label — the clicked label link (edge http face)
// =====================================================================================

/// `/contact-label` — the emailed "not spam" / "spam after all" link. **GET shows** what it
/// would teach with a button; **POST records** the label into the same airlock the block link
/// uses, for the daemon's apply reactor to train on. This face never touches the model: it
/// verifies a link and drops a tuple, exactly as [`ContactBlock`] does.
pub struct ContactLabel {
    /// Where the verifying (public) key lives: the same `contact-block.pub`.
    pub key_path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for ContactLabel {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // The page a label POST redirected to (Post/Redirect/Get, ledger #1879).
        if inv.request.verb == Verb::Source {
            let word = param(inv, prg::OUTCOME)?;
            if !word.is_empty() {
                return Ok(label_outcome(&word));
            }
        }
        let label = param(inv, "label")?;
        let enquiry = param(inv, "id")?;
        let class = param(inv, "class")?;
        let token = param(inv, "t")?;
        let exp: i64 = param(inv, "exp")?.parse().unwrap_or(0);

        let key = verifying_key_at(&self.key_path)?;
        if !label_valid(&label, &enquiry, &class, exp, &token, &key, now_secs()) {
            return Ok(match inv.request.verb {
                Verb::Sink => prg::see_other(INVALID, bad_link()),
                _ => bad_link(),
            });
        }
        // Only a validated label and a 64-hex id reach the page, so nothing here is visitor text.
        let (title, button, effect) = if label == "ham" {
            (
                "Not spam?",
                "Not spam",
                "The spam filter learns that this enquiry was a real one, so enquiries like it \
                 score lower.",
            )
        } else {
            (
                "Spam after all?",
                "Spam",
                "The spam filter learns that this enquiry was spam, so enquiries like it score \
                 higher. It does not block the sender: the block link does that.",
            )
        };
        // Escaped anyway, so the page does not depend on the gate above (ledger #1516).
        let short = html_text(&enquiry[..12]);

        match inv.request.verb {
            Verb::Source => {
                let exp = exp.to_string();
                let mut fields = vec![("id", enquiry.as_str()), ("label", label.as_str())];
                if !class.is_empty() {
                    fields.push(("class", class.as_str()));
                }
                fields.extend([("exp", exp.as_str()), ("t", token.as_str())]);
                Ok(page(
                    title,
                    &format!(
                        "<p>{effect}</p><p>Enquiry <code>{short}</code>.</p>{form}\
                         <p class=muted>The sender is told nothing. Clicking the other \
                         link in the email later changes the label.</p>{js}",
                        form = confirm_form(&fields, button),
                        js = crate::passkey::DECISION_PASSKEY_JS,
                    ),
                ))
            }
            Verb::Sink => {
                if crate::passkey::require_passkey(inv).is_err() {
                    return Ok(prg::see_other(PASSKEY, label_outcome(PASSKEY)));
                }
                // A link that carried the filter's class drops it too (ledger #3868), read by
                // the apply program as `(get req 'class "")`. Only a verified class from the
                // closed set reaches here.
                let class_field = if class.is_empty() {
                    String::new()
                } else {
                    format!(" (class {})", quoted(&class))
                };
                let tuple = format!(
                    "((label {}) (enquiry {}) (exp {}){class_field})",
                    quoted(&label),
                    quoted(&current_enquiry(&enquiry)),
                    quoted(&exp.to_string())
                );
                let done = if label == "ham" { "ham" } else { "spam" };
                record_once(
                    inv,
                    LABEL_ACTION,
                    &self.key_path,
                    &token,
                    exp,
                    tuple,
                    done,
                    label_outcome,
                )
                .await
            }
            other => Err(Error::Endpoint(format!(
                "a label link is shown with Source or acted with Sink, not {other:?}"
            ))),
        }
    }

    fn name(&self) -> &str {
        "contact-label"
    }

    fn describe(&self) -> Description {
        let inputs = |spec: ActionSpec| {
            spec.input(
                ArgSpec::new("id")
                    .summary("the enquiry's tuple id in the contact space")
                    .class(crate::XSD_STRING),
            )
            .input(
                ArgSpec::new("label")
                    .summary("the label: `ham` (not spam) or `spam`")
                    .class(crate::XSD_STRING)
                    .one_of(LABELS),
            )
            .input(
                ArgSpec::new("class")
                    .summary(
                        "optional: the class the filter gave the enquiry, signed into the link",
                    )
                    .class(crate::XSD_STRING)
                    .one_of(CLASSES)
                    .optional(),
            )
            .input(
                ArgSpec::new("exp")
                    .summary("expiry, unix seconds")
                    .class(crate::XSD_INTEGER),
            )
            .input(
                ArgSpec::new("t")
                    .summary("the signature")
                    .class(crate::XSD_STRING),
            )
            .input(form_body_spec())
        };
        Description::new("contact-label")
            .title("Label an enquiry for the spam filter")
            .summary(
                "The emailed label link. GET verifies the token and shows what it would teach; \
                 POST records the label, and the filter's class when the link carries one, for \
                 the edge to train on. Records intent only.",
            )
            .action(
                inputs(
                    ActionSpec::new(Verb::Source)
                        .summary("show — the label this link would teach, or what a label did"),
                )
                .input(outcome_spec(&[
                    "ham",
                    "spam",
                    prg::ALREADY,
                    INVALID,
                    PASSKEY,
                ]))
                .output("text/html; charset=utf-8"),
            )
            // Every POST answers Post/Redirect/Get: the outcome page in an ikigai-web entity
            // envelope whose `Location` makes it a `303` (ledger #1879).
            .action(
                inputs(ActionSpec::new(Verb::Sink).summary("label — record the label"))
                    .output(prg::HTTP_ENTITY),
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

    fn enquiry() -> String {
        ikigai_intray::tuple_id(b"((message \"cheap pills\"))")
    }

    #[test]
    fn a_freshly_minted_token_verifies() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        assert!(block_valid(
            EMAIL,
            &q,
            EXP,
            &mint_block(EMAIL, &q, EXP, &k),
            &v,
            NOW
        ));
        assert!(block_valid(
            EMAIL,
            "",
            EXP,
            &mint_block(EMAIL, "", EXP, &k),
            &v,
            NOW
        ));
        for label in LABELS {
            assert!(label_valid(
                label,
                &q,
                "",
                EXP,
                &mint_label(label, &q, "", EXP, &k),
                &v,
                NOW
            ));
        }
    }

    #[test]
    fn the_signed_payloads_start_with_their_action() {
        // The shape that keeps the two actions apart, pinned as bytes.
        assert_eq!(
            block_payload("a@example.invalid", "", 1_800_000_000),
            "contact-block|a@example.invalid||1800000000"
        );
        // Since ledger #3868 a label signs the filter's class, empty when the link has none.
        assert_eq!(
            label_payload("ham", &"a".repeat(64), "unsure", 1_800_000_000),
            format!("contact-label|ham|{}|unsure|1800000000", "a".repeat(64))
        );
        assert_eq!(
            label_payload("ham", &"a".repeat(64), "", 1_800_000_000),
            format!("contact-label|ham|{}||1800000000", "a".repeat(64))
        );
        // The 4-field form a label link signed before then, verified only.
        assert_eq!(
            legacy_label_payload("ham", &"a".repeat(64), 1_800_000_000),
            format!("contact-label|ham|{}|1800000000", "a".repeat(64))
        );
    }

    #[test]
    fn a_label_token_is_bound_to_its_class() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        for class in CLASSES {
            let t = mint_label("ham", &q, class, EXP, &k);
            assert!(label_valid("ham", &q, class, EXP, &t, &v, NOW), "{class}");
            // Re-pointed at any other class, or stripped of it, the link fails.
            for other in CLASSES.iter().filter(|c| **c != class) {
                assert!(
                    !label_valid("ham", &q, other, EXP, &t, &v, NOW),
                    "{class}->{other}"
                );
            }
            assert!(
                !label_valid("ham", &q, "", EXP, &t, &v, NOW),
                "{class} stripped"
            );
        }
        // A link minted with no class cannot have one added.
        let none = mint_label("spam", &q, "", EXP, &k);
        assert!(label_valid("spam", &q, "", EXP, &none, &v, NOW));
        for class in CLASSES {
            assert!(
                !label_valid("spam", &q, class, EXP, &none, &v, NOW),
                "{class}"
            );
        }
        // A class outside the set never verifies, even one we signed by mistake.
        let odd = mint_label("ham", &q, "eggs", EXP, &k);
        assert!(!label_valid("ham", &q, "eggs", EXP, &odd, &v, NOW));
    }

    #[test]
    fn a_label_link_minted_before_the_class_still_verifies_with_no_class() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        for label in LABELS {
            let old = sign(&legacy_label_payload(label, &q, EXP), &k);
            assert!(label_valid(label, &q, "", EXP, &old, &v, NOW), "{label}");
            // It carried no class, so it cannot be given one.
            for class in CLASSES {
                assert!(
                    !label_valid(label, &q, class, EXP, &old, &v, NOW),
                    "{label} {class}"
                );
            }
            // Still bound to its label, enquiry and expiry, and still expires.
            let other = if label == "ham" { "spam" } else { "ham" };
            assert!(!label_valid(other, &q, "", EXP, &old, &v, NOW));
            assert!(!label_valid(label, &"b".repeat(64), "", EXP, &old, &v, NOW));
            assert!(!label_valid(label, &q, "", EXP + 1, &old, &v, NOW));
            assert!(!label_valid(label, &q, "", EXP, &old, &v, EXP));
            // And an old label signature is never a block one.
            assert!(!block_valid(EMAIL, &q, EXP, &old, &v, NOW));
            assert!(!block_valid(EMAIL, "", EXP, &old, &v, NOW));
        }
    }

    #[test]
    fn a_token_is_bound_to_its_address_enquiry_and_expiry() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        let t = mint_block(EMAIL, &q, EXP, &k);
        // Re-pointing a block token at another address, another enquiry (or none), or
        // stretching its expiry, must not verify — otherwise one link would block anyone.
        assert!(!block_valid("someone@else.example", &q, EXP, &t, &v, NOW));
        assert!(!block_valid(EMAIL, &"b".repeat(64), EXP, &t, &v, NOW));
        assert!(!block_valid(EMAIL, "", EXP, &t, &v, NOW));
        assert!(!block_valid(EMAIL, &q, EXP + 1, &t, &v, NOW));
    }

    #[test]
    fn a_label_token_is_bound_to_its_label_enquiry_and_expiry() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        let ham = mint_label("ham", &q, "", EXP, &k);
        // A SWAPPED ACTION: a "not spam" link edited to say spam (and the reverse) is refused.
        assert!(!label_valid("spam", &q, "", EXP, &ham, &v, NOW));
        let spam = mint_label("spam", &q, "", EXP, &k);
        assert!(!label_valid("ham", &q, "", EXP, &spam, &v, NOW));
        // Another enquiry, or a stretched expiry.
        assert!(!label_valid("ham", &"b".repeat(64), "", EXP, &ham, &v, NOW));
        assert!(!label_valid("ham", &q, "", EXP + 1, &ham, &v, NOW));
    }

    #[test]
    fn a_block_token_is_never_a_label_token_nor_the_reverse() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        // Whatever fields a replayer puts beside it, a block signature does not verify as a
        // label, in either payload form, and a label signature does not verify as a block.
        let block = mint_block(EMAIL, &q, EXP, &k);
        let legacy = sign(&legacy_block_payload(EMAIL, EXP), &k);
        for t in [&block, &legacy] {
            for label in LABELS {
                for class in std::iter::once("").chain(CLASSES) {
                    assert!(
                        !label_valid(label, &q, class, EXP, t, &v, NOW),
                        "{label} {class}"
                    );
                }
            }
        }
        // The action tag ALONE separates them: a block payload whose address slot holds a label
        // (no minter signs one; the address check refuses it) still never verifies as that label.
        for label in LABELS {
            let t = sign(&block_payload(label, &q, EXP), &k);
            assert!(!label_valid(label, &q, "", EXP, &t, &v, NOW), "{label}");
        }
        for label in LABELS {
            for class in std::iter::once("").chain(CLASSES) {
                let t = mint_label(label, &q, class, EXP, &k);
                assert!(!block_valid(EMAIL, &q, EXP, &t, &v, NOW));
                assert!(!block_valid(EMAIL, "", EXP, &t, &v, NOW));
                // Even a replayer who rewrites the address into the label payload's own
                // prefix: an address may not carry `|`, so it never reaches the signature check.
                let forged_email = format!("{LABEL_ACTION}|{label}|{q}");
                assert!(!block_valid(&forged_email, "", EXP, &t, &v, NOW));
                let forged_email = format!("{LABEL_ACTION}|{label}|{q}|{class}");
                assert!(!block_valid(&forged_email, "", EXP, &t, &v, NOW));
            }
        }
    }

    #[test]
    fn a_link_minted_before_the_action_tag_still_blocks_but_names_no_enquiry() {
        let k = key();
        let v = k.verifying_key();
        let legacy = sign(&legacy_block_payload(EMAIL, EXP), &k);
        assert!(block_valid(EMAIL, "", EXP, &legacy, &v, NOW));
        // It signed no enquiry, so it cannot be stretched to teach the filter about one.
        assert!(!block_valid(EMAIL, &enquiry(), EXP, &legacy, &v, NOW));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        let t = mint_block(EMAIL, &q, EXP, &k);
        assert!(!block_valid(EMAIL, &q, EXP, &t, &v, EXP + 1));
        let l = mint_label("ham", &q, "", EXP, &k);
        assert!(!label_valid("ham", &q, "", EXP, &l, &v, EXP));
    }

    #[test]
    fn another_key_cannot_sign_a_block_or_a_label() {
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let v = key().verifying_key();
        let q = enquiry();
        assert!(!block_valid(
            EMAIL,
            &q,
            EXP,
            &mint_block(EMAIL, &q, EXP, &theirs),
            &v,
            NOW
        ));
        assert!(!label_valid(
            "ham",
            &q,
            "",
            EXP,
            &mint_label("ham", &q, "", EXP, &theirs),
            &v,
            NOW
        ));
    }

    #[test]
    fn garbage_tokens_are_refused_without_panicking() {
        let v = key().verifying_key();
        let q = enquiry();
        for bad in ["", "!!!!", "c2hvcnQ", &"A".repeat(200)] {
            assert!(!block_valid(EMAIL, "", EXP, bad, &v, NOW), "{bad}");
            assert!(!label_valid("ham", &q, "", EXP, bad, &v, NOW), "{bad}");
        }
    }

    #[test]
    fn a_malformed_address_never_reaches_the_signature_check() {
        let k = key();
        let v = k.verifying_key();
        let t = mint_block(EMAIL, "", EXP, &k);
        // No `@`, a quote/backslash that could reshape the tuple, a control char, the payload's
        // `|`, empty, and an over-long address are all rejected before the signature is even
        // considered.
        for bad in [
            "no-at-sign",
            "x@y\"; DROP",
            "back\\slash@x",
            "with\nnewline@x",
            "pipe|in@x",
            "",
        ] {
            assert!(!email_shaped(bad), "should be malformed: {bad:?}");
            assert!(!block_valid(bad, "", EXP, &t, &v, NOW), "{bad:?}");
        }
        assert!(!email_shaped(&format!("{}@x", "a".repeat(300))));
        assert!(email_shaped(EMAIL));
    }

    #[test]
    fn an_unknown_label_or_a_malformed_enquiry_is_refused_before_the_signature() {
        let k = key();
        let v = k.verifying_key();
        let q = enquiry();
        // A label outside the model's two classes, even one we signed by mistake.
        let odd = mint_label("eggs", &q, "", EXP, &k);
        assert!(!label_valid("eggs", &q, "", EXP, &odd, &v, NOW));
        // An enquiry id that is not a tuple id: short, upper-case, a path, empty.
        for bad in [
            "abc".to_string(),
            q.to_uppercase(),
            format!("../{}", &q[3..]),
            String::new(),
        ] {
            assert!(!enquiry_id_shaped(&bad), "{bad:?}");
            let t = mint_label("ham", &bad, "", EXP, &k);
            assert!(!label_valid("ham", &bad, "", EXP, &t, &v, NOW), "{bad:?}");
            if !bad.is_empty() {
                let t = mint_block(EMAIL, &bad, EXP, &k);
                assert!(!block_valid(EMAIL, &bad, EXP, &t, &v, NOW), "{bad:?}");
            }
        }
        assert!(enquiry_id_shaped(&q));
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey};
    use futures::executor::block_on;
    use ikigai_core::{Capability, EndpointSpace, Exact, Kernel};
    use std::sync::{Arc, Mutex};

    const EMAIL: &str = "price@spam.example";
    const ENQUIRY: &str =
        "((name \"A Visitor\") (email \"visitor@example.invalid\") (message \"cheap pills\"))";

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
        let dir =
            std::env::temp_dir().join(format!("ikigai-contactblock-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        // Write the halves as `openssl` would: SPKI PEM public, PKCS8 PEM private.
        let pub_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_path = dir.join("contact-block.pub");
        std::fs::write(&key_path, pub_pem).unwrap();
        let private = dir.join("contact-block.key");
        std::fs::write(&private, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str()).unwrap();

        let recorder = Recorder::default();
        #[allow(clippy::disallowed_methods)]
        // internal: a test fixture's kernel; it routes no user arguments
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    Exact::new("urn:contact-block"),
                    ContactBlock {
                        key_path: key_path.clone(),
                    },
                )
                .bind(Exact::new("urn:contact-label"), ContactLabel { key_path })
                .bind(
                    Exact::new("urn:contactblock:link"),
                    ContactBlockLink {
                        key_path: private.clone(),
                    },
                )
                .bind(
                    Exact::new("urn:contactlabel:link"),
                    ContactLabelLink { key_path: private },
                )
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
        fn issue(&self, verb: Verb, iri: &str, args: &[(&str, &str)]) -> Result<String> {
            let mut r = Request::new(verb, Iri::parse(iri).unwrap());
            for (n, v) in args {
                r = r.with_arg(*n, ArgRef::Inline(v.as_bytes().to_vec()));
            }
            block_on(self.kernel.issue(r, &Capability::root()))
                .map(|rep| String::from_utf8(rep.bytes).unwrap())
        }
        fn call(&self, verb: Verb, email: &str, exp: i64, token: &str) -> String {
            self.issue(
                verb,
                "urn:contact-block",
                &[("email", email), ("exp", &exp.to_string()), ("t", token)],
            )
            .expect("the page should render")
        }
        fn post_form(&self, iri: &str, body: &str) -> String {
            self.issue(Verb::Sink, iri, &[("content", body)])
                .expect("the page should render")
        }
        fn post_block(&self, email: &str, exp: i64, token: &str) -> String {
            self.post_form(
                "urn:contact-block",
                &format!("email={}&exp={exp}&t={token}", urlencode(email)),
            )
        }
        fn post_label(&self, id: &str, label: &str, exp: i64, token: &str) -> String {
            self.post_form(
                "urn:contact-label",
                &format!("id={id}&label={label}&exp={exp}&t={}", urlencode(token)),
            )
        }
        fn valid(&self) -> (i64, String) {
            let exp = now_secs() + 600;
            (exp, mint_block(EMAIL, "", exp, &self.key))
        }
        fn dropped(&self) -> Vec<String> {
            self.dropped.lock().unwrap().clone()
        }
    }

    /// The query parameters of a minted URL.
    fn query(url: &str) -> std::collections::BTreeMap<String, String> {
        let (_, q) = url.trim().split_once('?').expect("a query");
        q.split('&')
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap();
                (
                    k.to_string(),
                    ikigai_fn::html::percent_decode(v, true).unwrap(),
                )
            })
            .collect()
    }

    /// Ledger #1516: the address is VISITOR text (whatever the contact form accepted) and it is
    /// signed, not sanitized, so a `<`, `&` or `'` in it reaches the page. It must render as text,
    /// on the GET, in the GET's hidden field, and on the POST's confirmation, while the drop
    /// still carries the address byte for byte. (`"` and `\` never get this far: `email_shaped`
    /// refuses them before the signature check.)
    #[test]
    fn markup_in_a_signed_address_renders_as_text() {
        let w = world("markup");
        let hostile = "<b>x</b>&amp;y'@spam.example";
        assert!(
            email_shaped(hostile),
            "the gate admits it, so the page must cope"
        );
        let escaped = "&lt;b&gt;x&lt;/b&gt;&amp;amp;y&#39;@spam.example";
        let exp = now_secs() + 600;
        let token = mint_block(hostile, "", exp, &w.key);

        let get = w.call(Verb::Source, hostile, exp, &token);
        assert!(get.contains("Block this sender?"), "{get}");
        assert!(!get.contains("<b>"), "markup rendered: {get}");
        assert!(get.contains(&format!("<code>{escaped}</code>")), "{get}");
        assert!(
            get.contains(&format!("name=email value=\"{escaped}\"")),
            "the hidden field: {get}"
        );

        // The POST answers Post/Redirect/Get (ledger #1879): its page names no address at all,
        // so there is nothing in it to escape.
        let post = w.post_block(hostile, exp, &token);
        assert!(post.contains("Location: ?outcome=blocked\r\n"), "{post}");
        assert!(post.contains("Blocked"), "{post}");
        assert!(!post.contains("<b>"), "markup rendered: {post}");
        assert!(
            !post.contains("spam.example"),
            "the address is not on the page: {post}"
        );
        assert_eq!(
            crate::decide::field(&w.dropped()[0], "block-email").as_deref(),
            Some(hostile),
            "the drop keeps the address exactly"
        );
    }

    /// The confirm form escapes its values and its button: a `"` cannot close the attribute.
    #[test]
    fn the_confirm_form_escapes_its_values() {
        let form = confirm_form(&[("t", "a\"><script>x</script>&")], "Go & <b>");
        assert!(!form.contains("<script>"), "{form}");
        assert!(!form.contains("<b>"), "{form}");
        assert!(
            form.contains("name=t value=\"a&quot;&gt;&lt;script&gt;x&lt;/script&gt;&amp;\""),
            "{form}"
        );
        assert!(form.contains(">Go &amp; &lt;b&gt;</button>"), "{form}");
    }

    /// Through `ikigai_fn::html` (ledger #1868): a C0 control in a value or the button becomes
    /// U+FFFD, and a hostile value (`javascript:`, quotes, a `<script>`) stays text inside its
    /// quoted attribute. The form builds no `href` from data, so nothing can become a link.
    #[test]
    fn the_confirm_form_maps_controls_and_keeps_a_hostile_value_inert() {
        let form = confirm_form(
            &[
                ("t", "x\u{0}y\u{7}z"),
                ("email", "javascript:alert(1)'\"><script>"),
            ],
            "Go\u{1b}",
        );
        assert!(
            form.contains("name=t value=\"x\u{FFFD}y\u{FFFD}z\""),
            "{form}"
        );
        assert!(form.contains("<button>Go\u{FFFD}</button>"), "{form}");
        assert!(
            form.contains("name=email value=\"javascript:alert(1)&#39;&quot;&gt;&lt;script&gt;\""),
            "{form}"
        );
        assert!(!form.contains("<script>"), "{form}");
        assert!(!form.contains("href="), "{form}");
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
        // No inline style, so it renders under an HTML door's CSP (ledger #1834).
        crate::decide::assert_no_inline_style(&html);
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
        let html = w.post_block(EMAIL, exp, &token);
        assert!(html.contains("Blocked"), "{html}");
        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(
            crate::decide::field(&dropped[0], "block-email").as_deref(),
            Some(EMAIL)
        );
        assert_eq!(crate::decide::field(&dropped[0], "enquiry"), None);
    }

    #[test]
    fn a_forged_or_expired_token_records_nothing() {
        let w = world("forged");
        let (exp, _) = w.valid();
        let forged = mint_block(EMAIL, "", exp, &SigningKey::from_bytes(&[9u8; 32]));
        assert!(w.post_block(EMAIL, exp, &forged).contains("didn't work"));

        let stale = now_secs() - 1;
        let stale_token = mint_block(EMAIL, "", stale, &w.key);
        assert!(w
            .post_block(EMAIL, stale, &stale_token)
            .contains("didn't work"));

        assert!(w.dropped().is_empty(), "neither is recorded");
    }

    #[test]
    fn a_token_for_one_address_cannot_block_another() {
        // The address is in the signed payload, so swapping it in the POST body is refused.
        let w = world("swap");
        let (exp, token) = w.valid();
        let html = w.post_block("victim@example.com", exp, &token);
        assert!(html.contains("didn't work"), "{html}");
        assert!(w.dropped().is_empty(), "nothing recorded");
    }

    /// Ledger #3713: a reseal stores the enquiry again under a new id and leaves a forward;
    /// a link minted before it still verifies (its token signs the old id) and the intent it
    /// records names the id the tuple has now.
    #[test]
    fn a_link_minted_before_a_reseal_records_the_enquirys_new_id() {
        let w = world("reseal-forward");
        let text = "((message \"resealed since the email\"))";
        let old = ikigai_intray::tuple_id(text.as_bytes());
        let new = ikigai_intray::tuple_id(b"the ciphertext it is stored as now");
        let forwards = file_root()
            .join("spaces")
            .join(CONTACT_SPACE)
            .join(crate::space_seal::FORWARDS_DIR);
        std::fs::create_dir_all(&forwards).unwrap();
        std::fs::write(forwards.join(&old), format!("{new}\n")).unwrap();

        let block = query(
            &w.issue(
                Verb::Source,
                "urn:contactblock:link",
                &[("email", EMAIL), ("enquiry", text)],
            )
            .unwrap(),
        );
        let label = query(
            &w.issue(
                Verb::Source,
                "urn:contactlabel:link",
                &[("label", "spam"), ("enquiry", text)],
            )
            .unwrap(),
        );
        assert_eq!(block["id"], old);
        let body = format!(
            "email={}&id={}&exp={}&t={}",
            urlencode(EMAIL),
            block["id"],
            block["exp"],
            urlencode(&block["t"])
        );
        assert!(w.post_form("urn:contact-block", &body).contains("Blocked"));
        assert!(w
            .post_label(
                &label["id"],
                "spam",
                label["exp"].parse().unwrap(),
                &label["t"]
            )
            .contains("spam"));
        let _ = std::fs::remove_file(forwards.join(&old));

        let dropped = w.dropped();
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        for tuple in &dropped {
            assert_eq!(
                crate::decide::field(tuple, "enquiry").as_deref(),
                Some(new.as_str()),
                "{tuple}"
            );
        }
    }

    #[test]
    fn a_minted_block_link_names_its_enquiry_and_its_post_records_it() {
        let w = world("block-enquiry");
        let url = w
            .issue(
                Verb::Source,
                "urn:contactblock:link",
                &[("email", EMAIL), ("enquiry", ENQUIRY)],
            )
            .unwrap();
        let q = query(&url);
        let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
        assert_eq!(q.get("id"), Some(&id), "{url}");
        assert!(
            !url.contains("cheap"),
            "the link never carries the text: {url}"
        );
        // The GET carries the id into the form, and says what the block also teaches.
        let get = w
            .issue(
                Verb::Source,
                "urn:contact-block",
                &[
                    ("email", EMAIL),
                    ("id", &q["id"]),
                    ("exp", &q["exp"]),
                    ("t", &q["t"]),
                ],
            )
            .unwrap();
        assert!(get.contains(&format!("name=id value=\"{id}\"")), "{get}");
        assert!(get.contains("spam filter"), "{get}");
        let body = format!(
            "email={}&id={}&exp={}&t={}",
            urlencode(EMAIL),
            q["id"],
            q["exp"],
            urlencode(&q["t"])
        );
        assert!(w.post_form("urn:contact-block", &body).contains("Blocked"));
        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(crate::decide::field(&dropped[0], "enquiry"), Some(id));
        assert_eq!(
            crate::decide::field(&dropped[0], "block-email").as_deref(),
            Some(EMAIL)
        );
    }

    #[test]
    fn a_minted_label_link_round_trips_into_one_label_drop() {
        let w = world("label-roundtrip");
        let url = w
            .issue(
                Verb::Source,
                "urn:contactlabel:link",
                &[("label", "ham"), ("enquiry", ENQUIRY)],
            )
            .unwrap();
        assert!(
            url.starts_with("https://ikigai-rs.dev/contact-label?"),
            "{url}"
        );
        assert!(
            !url.contains("cheap"),
            "the link never carries the text: {url}"
        );
        let q = query(&url);
        let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
        assert_eq!(q.get("id"), Some(&id));
        assert_eq!(q.get("label").map(String::as_str), Some("ham"));

        // GET shows, records nothing.
        let get = w
            .issue(
                Verb::Source,
                "urn:contact-label",
                &[
                    ("id", &q["id"]),
                    ("label", "ham"),
                    ("exp", &q["exp"]),
                    ("t", &q["t"]),
                ],
            )
            .unwrap();
        assert!(get.contains("Not spam?"), "{get}");
        assert!(get.contains("method=\"post\""), "{get}");
        crate::decide::assert_no_inline_style(&get);
        assert!(w.dropped().is_empty(), "a GET must record nothing");

        // POST records exactly one label tuple naming the enquiry by id.
        let exp: i64 = q["exp"].parse().unwrap();
        let html = w.post_label(&id, "ham", exp, &q["t"]);
        assert!(html.contains("Marked as not spam"), "{html}");
        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(
            crate::decide::field(&dropped[0], "label").as_deref(),
            Some("ham")
        );
        assert_eq!(crate::decide::field(&dropped[0], "enquiry"), Some(id));
        // Minted with no class: the link carries none and neither does its drop.
        assert!(!q.contains_key("class"), "{url}");
        assert_eq!(crate::decide::field(&dropped[0], "class"), None);
    }

    #[test]
    fn a_label_link_never_drops_an_unreadable_class() {
        let w = world("invalid-class");
        let base = Request::new(Verb::Source, Iri::parse("urn:contactlabel:link").unwrap())
            .with_arg("label", ArgRef::Inline(b"spam".to_vec()))
            .with_arg("enquiry", ArgRef::Inline(ENQUIRY.as_bytes().to_vec()));
        let endpoint = ContactLabelLink {
            key_path: w._dir.join("contact-block.key"),
        };
        let bindings = ikigai_core::Bindings::new();
        let cap = Capability::root();
        let issue =
            |req: &Request| block_on(endpoint.invoke(&Invocation::detached(req, &bindings, &cap)));
        let unclassified = issue(&base).unwrap();
        assert!(!String::from_utf8_lossy(&unclassified.bytes).contains("&class="));
        let classified = issue(
            &base
                .clone()
                .with_arg("class", ArgRef::Inline(b"spam".to_vec())),
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&classified.bytes).contains("&class=spam"));
        crate::optional_arguments_tests::rejects_unreadable(&base, &["class"], issue);
    }

    /// Ledger #3868: a link minted with the filter's class signs it, shows it on, and drops it.
    #[test]
    fn a_label_link_with_a_class_drops_that_class_exactly() {
        for class in CLASSES {
            let w = world(&format!("label-class-{class}"));
            let url = w
                .issue(
                    Verb::Source,
                    "urn:contactlabel:link",
                    &[("label", "spam"), ("class", class), ("enquiry", ENQUIRY)],
                )
                .unwrap();
            let q = query(&url);
            assert_eq!(q.get("class").map(String::as_str), Some(class), "{url}");
            let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
            let exp: i64 = q["exp"].parse().unwrap();
            // The token is the signature over the 5-field payload, class and all.
            assert_eq!(q["t"], mint_label("spam", &id, class, exp, &w.key));

            // GET carries the class on into the confirm form.
            let get = w
                .issue(
                    Verb::Source,
                    "urn:contact-label",
                    &[
                        ("id", &id),
                        ("label", "spam"),
                        ("class", class),
                        ("exp", &q["exp"]),
                        ("t", &q["t"]),
                    ],
                )
                .unwrap();
            assert!(get.contains("Spam after all?"), "{get}");
            assert!(
                get.contains(&format!("<input type=hidden name=class value=\"{class}\">")),
                "{get}"
            );

            // Re-pointed at another class (or stripped of it), the click records nothing.
            for other in CLASSES.iter().filter(|c| **c != class) {
                let body = format!(
                    "id={id}&label=spam&class={other}&exp={exp}&t={}",
                    urlencode(&q["t"])
                );
                let html = w.post_form("urn:contact-label", &body);
                assert!(html.contains("didn't work"), "{class}->{other}: {html}");
            }
            assert!(w
                .post_label(&id, "spam", exp, &q["t"])
                .contains("didn't work"));
            assert!(w.dropped().is_empty(), "{:?}", w.dropped());

            // The real click drops exactly one tuple, its class exactly the signed one, and
            // the rest of the drop as before.
            let body = format!(
                "id={id}&label=spam&class={class}&exp={exp}&t={}",
                urlencode(&q["t"])
            );
            let html = w.post_form("urn:contact-label", &body);
            assert!(html.contains("Marked as spam"), "{html}");
            let dropped = w.dropped();
            assert_eq!(dropped.len(), 1, "{dropped:?}");
            assert_eq!(
                dropped[0],
                format!(
                    "((label \"spam\") (enquiry \"{id}\") (exp \"{exp}\") (class \"{class}\"))"
                )
            );
            assert_eq!(
                crate::decide::field(&dropped[0], "class").as_deref(),
                Some(class)
            );
        }
    }

    /// A label link minted before ledger #3868 signed `contact-label|<label>|<enquiry>|<exp>`.
    /// Clicked now, it still records, and its drop carries no class.
    #[test]
    fn an_old_label_link_still_records_and_drops_no_class() {
        let w = world("label-legacy");
        let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
        let exp = now_secs() + 600;
        let old = sign(&legacy_label_payload("ham", &id, exp), &w.key);
        // Given a class it never signed, it fails.
        let body = format!(
            "id={id}&label=ham&class=spam&exp={exp}&t={}",
            urlencode(&old)
        );
        assert!(w
            .post_form("urn:contact-label", &body)
            .contains("didn't work"));
        assert!(w.dropped().is_empty());
        let html = w.post_label(&id, "ham", exp, &old);
        assert!(html.contains("Marked as not spam"), "{html}");
        let dropped = w.dropped();
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(
            dropped[0],
            format!("((label \"ham\") (enquiry \"{id}\") (exp \"{exp}\"))")
        );
        assert_eq!(crate::decide::field(&dropped[0], "class"), None);
    }

    /// Every refusal the label face makes, each answering the same bad-link page and recording
    /// nothing: a wrong signature, an expired link, a swapped action (label), an unknown or
    /// malformed id, and a block token presented as a label token.
    #[test]
    fn every_bad_label_link_records_nothing() {
        let w = world("label-refusals");
        let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
        let exp = now_secs() + 600;
        let good = mint_label("ham", &id, "", exp, &w.key);

        // A wrong signature: another key.
        let forged = mint_label("ham", &id, "", exp, &SigningKey::from_bytes(&[9u8; 32]));
        // Expired.
        let stale_exp = now_secs() - 1;
        let stale = mint_label("ham", &id, "", stale_exp, &w.key);
        // A block token for this very enquiry, replayed at the label door.
        let block = mint_block(EMAIL, &id, exp, &w.key);
        let other = "c".repeat(64);
        let cases: [(&str, &str, &str, i64, &str); 7] = [
            ("wrong signature", &id, "ham", exp, &forged),
            ("expired", &id, "ham", stale_exp, &stale),
            ("swapped action", &id, "spam", exp, &good),
            ("unknown id", &other, "ham", exp, &good),
            ("malformed id", "not-a-tuple-id", "ham", exp, &good),
            ("block token as label", &id, "spam", exp, &block),
            ("block token as label (ham)", &id, "ham", exp, &block),
        ];
        for (what, id, label, exp, token) in cases {
            let html = w.post_label(id, label, exp, token);
            assert!(html.contains("didn't work"), "{what}: {html}");
            let get = w
                .issue(
                    Verb::Source,
                    "urn:contact-label",
                    &[
                        ("id", id),
                        ("label", label),
                        ("exp", &exp.to_string()),
                        ("t", token),
                    ],
                )
                .unwrap();
            assert!(get.contains("didn't work"), "{what}: {get}");
        }
        assert!(
            w.dropped().is_empty(),
            "nothing recorded: {:?}",
            w.dropped()
        );
        // And the good one does record, so the refusals above are refusals.
        assert!(w
            .post_label(&id, "ham", exp, &good)
            .contains("Marked as not spam"));
        assert_eq!(w.dropped().len(), 1);
    }

    #[test]
    fn a_label_token_is_never_a_block_token() {
        let w = world("label-as-block");
        let id = ikigai_intray::tuple_id(ENQUIRY.as_bytes());
        let exp = now_secs() + 600;
        for label in LABELS {
            let t = mint_label(label, &id, "", exp, &w.key);
            let body = format!(
                "email={}&id={id}&exp={exp}&t={}",
                urlencode(EMAIL),
                urlencode(&t)
            );
            assert!(w
                .post_form("urn:contact-block", &body)
                .contains("didn't work"));
        }
        assert!(w.dropped().is_empty());
    }

    #[test]
    fn the_minters_refuse_without_the_grant_and_on_bad_input() {
        let w = world("mint-refusals");
        let no_grant = Capability::scoped(["urn:cap:email:send"]);
        for (iri, args) in [
            ("urn:contactblock:link", vec![("email", EMAIL)]),
            (
                "urn:contactlabel:link",
                vec![("label", "ham"), ("enquiry", ENQUIRY)],
            ),
        ] {
            let mut r = Request::new(Verb::Source, Iri::parse(iri).unwrap());
            for (n, v) in args {
                r = r.with_arg(n, ArgRef::Inline(v.as_bytes().to_vec()));
            }
            let got = block_on(w.kernel.issue(r, &no_grant));
            assert!(matches!(got, Err(Error::Denied(_))), "{iri}: {got:?}");
        }
        let bad_label = w.issue(
            Verb::Source,
            "urn:contactlabel:link",
            &[("label", "eggs"), ("enquiry", ENQUIRY)],
        );
        assert!(
            matches!(bad_label, Err(Error::InvalidArgument { ref name, .. }) if name == "label"),
            "{bad_label:?}"
        );
        // A class outside the filter's closed set, or given empty, is refused.
        for bad in ["eggs", "", "SPAM", "spam|ham"] {
            let bad_class = w.issue(
                Verb::Source,
                "urn:contactlabel:link",
                &[("label", "ham"), ("class", bad), ("enquiry", ENQUIRY)],
            );
            assert!(
                matches!(bad_class, Err(Error::InvalidArgument { ref name, .. }) if name == "class"),
                "{bad:?}: {bad_class:?}"
            );
        }
        let no_enquiry = w.issue(Verb::Source, "urn:contactlabel:link", &[("label", "ham")]);
        assert!(
            matches!(no_enquiry, Err(Error::MissingArgument(ref n)) if n == "enquiry"),
            "{no_enquiry:?}"
        );
        let huge = "x".repeat(MAX_ENQUIRY_BYTES + 1);
        let too_big = w.issue(
            Verb::Source,
            "urn:contactlabel:link",
            &[("label", "ham"), ("enquiry", &huge)],
        );
        assert!(
            matches!(too_big, Err(Error::InvalidArgument { ref name, .. }) if name == "enquiry"),
            "{too_big:?}"
        );
    }

    /// The block and label links read "not configured" for a missing key, without its path
    /// (the error crosses the wire to whoever followed the link).
    #[test]
    fn a_missing_key_says_not_configured_without_its_path() {
        let dir = std::env::temp_dir().join(format!("ikigai-cblock-{}-nokey", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("contact-block.pub");
        #[allow(clippy::disallowed_methods)]
        // internal: a test fixture's kernel; it routes no user arguments
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    Exact::new("urn:contact-block"),
                    ContactBlock {
                        key_path: key_path.clone(),
                    },
                )
                .bind(Exact::new("urn:contact-label"), ContactLabel { key_path }),
        ));
        for iri in ["urn:contact-block", "urn:contact-label"] {
            let err = block_on(kernel.issue(
                Request::new(Verb::Sink, Iri::parse(iri).unwrap()).with_arg(
                    "content",
                    ArgRef::Inline(b"email=a%40b.example&id=&exp=99999999999&t=AAAA".to_vec()),
                ),
                &Capability::root(),
            ))
            .expect_err("no key, no page")
            .to_string();
            assert!(err.contains("not configured"), "{iri}: {err}");
            assert!(err.contains("contact-block.pub"), "{iri}: {err}");
            assert!(
                !err.contains(dir.to_str().unwrap()),
                "{iri}: the error names no path: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
