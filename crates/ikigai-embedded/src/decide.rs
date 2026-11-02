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

use crate::{file_root, prg};
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

pub(crate) fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Exactly what gets signed. Every field the decision depends on is in here.
fn payload(id: &str, action: &str, exp: i64) -> String {
    format!("{id}|{action}|{exp}")
}

/// The actions a link may carry. Anything else is refused before a key is even loaded.
/// `approve-zoom` is approve plus a scheduled Zoom (the confirm handler's `approve-zoom` command).
fn known_action(action: &str) -> bool {
    matches!(action, "approve" | "approve-zoom" | "decline" | "block")
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

pub(crate) fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Read the verifying key from `path`.
///
/// ⚠ The error crosses the wire to whoever followed the link, so it says the key is "not
/// configured" and names the FILE (what an operator puts in place), never the directory it was
/// looked for in: an absolute path would disclose the host's file layout to every caller. The
/// same function reads the decide key and the contact-block key, so it names whichever file.
pub(crate) fn verifying_key_at(path: &std::path::Path) -> Result<VerifyingKey> {
    let file = path.file_name().map_or_else(
        || "its key file".to_string(),
        |f| f.to_string_lossy().into_owned(),
    );
    let bytes = std::fs::read(path).map_err(|e| {
        let why = match e.kind() {
            std::io::ErrorKind::NotFound => "it is absent".to_string(),
            kind => format!("it cannot be read ({kind})"),
        };
        Error::Endpoint(format!(
            "this link is not configured on this host: its public key ({file}) is not \
             configured, {why}"
        ))
    })?;
    parse_verifying_key(&bytes).map_err(|e| {
        Error::Endpoint(format!(
            "this link is not configured on this host: its public key ({file}) is not a \
             usable key ({e})"
        ))
    })
}

fn parse_verifying_key(bytes: &[u8]) -> std::result::Result<VerifyingKey, String> {
    if let Ok(pem) = std::str::from_utf8(bytes) {
        if let Ok(key) = VerifyingKey::from_public_key_pem(pem.trim()) {
            return Ok(key);
        }
    }
    VerifyingKey::from_public_key_der(bytes).map_err(|e| format!("not an SPKI Ed25519 key: {e}"))
}

pub(crate) fn parse_signing_key(bytes: &[u8]) -> std::result::Result<SigningKey, String> {
    if let Ok(pem) = std::str::from_utf8(bytes) {
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem.trim()) {
            return Ok(key);
        }
    }
    SigningKey::from_pkcs8_der(bytes).map_err(|e| format!("not a PKCS8 Ed25519 key: {e}"))
}

// Percent-encode a query VALUE (RFC 3986 unreserved kept): the ecosystem's one encoder,
// `ikigai_fn::html::url_segment` (ledger #1868), under the name this module's callers use.
pub(crate) use ikigai_fn::html::url_segment as urlencode;

/// One parameter, from the query string OR — on a form POST — the urlencoded body.
///
/// A browser submitting `<form method=post>` puts its fields in the BODY, which the HTTP
/// face hands over as the piped `content`; a GET puts them in the query, which arrives as
/// named args. The same resource answers both, so it looks in both places.
///
/// The body is decoded STRICTLY by [`ikigai_intake::form_pairs`] (over the ecosystem's one
/// decoder, `ikigai_fn::html::percent_decode`; ledger #1878): a malformed escape or a value
/// that is not UTF-8 once decoded, anywhere in the body, is an `InvalidArgument` on `content`
/// (a `400` at the door) whose sentence names the byte offset, never a literal `%` or a U+FFFD
/// handed to the caller as if it had been sent.
pub(crate) fn param(inv: &Invocation<'_>, name: &str) -> Result<String> {
    if let Ok(v) = inv.inline_str(name) {
        let v = v.trim();
        if !v.is_empty() {
            return Ok(v.to_string());
        }
    }
    if let Ok(body) = inv.inline_str("content") {
        if let Some((_, v)) = ikigai_intake::form_pairs(body)?
            .into_iter()
            .find(|(k, _)| k == name)
        {
            return Ok(v.trim().to_string());
        }
    }
    Ok(String::new())
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
pub(crate) fn quoted(value: &str) -> String {
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
        // `approve-zoom` is APPENDED, not inserted: a consumer that labels links by position
        // (the notify email) keeps the first three correct even before it learns the fourth.
        for action in ["approve", "decline", "block", "approve-zoom"] {
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
            .title("Mint the decide links")
            .summary(
                "Signed, expiring URLs for one pending booking — approve, decline, block, and \
                 approve-with-Zoom — one per line, ready to email.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("mint — the signed links for a pending booking")
                    .requires(CAP_DECIDE_MINT)
                    .input(
                        ArgSpec::new("id")
                            .summary("the pending booking's tuple id")
                            .class(crate::XSD_STRING),
                    ),
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

/// Where the page shell's stylesheet is served: the mechanical path of [`PAGE_CSS_IRI`], so a door
/// with no route table serves it as it stands, and a `--routes-only` door needs one route line
/// (`/decide/css` → `urn:decide:css`).
pub const PAGE_CSS_PATH: &str = "/decide/css";

/// The resource the page shell's stylesheet is: [`PageCss`].
pub const PAGE_CSS_IRI: &str = "urn:decide:css";

/// The one stylesheet every page through [`page`] links: the decision, contact-block, label and
/// passkey pages. It holds what used to be inline `style=` attributes, unchanged in value, so
/// the pages look as they did, and the pages carry no inline style at all: an HTML door's CSP
/// (`style-src 'self'`, ikigai-web's `HTML_DOOR_CSP`, ledger #1834) admits a same-origin
/// stylesheet and refuses every `style=` attribute and `<style>` element. The edge's default
/// CSP (`default-src 'self'`) refuses them too, so a browser was already dropping the inline
/// styles there.
///
/// The muted color is the `--muted` token by its UX-conventions name; `#666` on white is 5.7:1.
/// The class names are this module's own, used by [`show_body`], `contactblock`'s pages and
/// `passkey`'s.
const PAGE_CSS: &str = "\
:root{--muted:#666}
body{font:16px/1.5 system-ui;margin:3rem auto;max-width:32rem;padding:0 1rem}
h1{font-size:1.3rem}
button{font:inherit;padding:.6rem 1.2rem}
.field{font:inherit;padding:.4rem;width:100%;max-width:20rem}
.muted{color:var(--muted)}
";

/// A small page. It links one same-origin stylesheet ([`PAGE_CSS_PATH`]) and carries no inline
/// style, so it renders under an HTML door's CSP. It renders on a phone, once, probably on
/// cellular, so the stylesheet is tiny and served by the same door as the page; if it fails to
/// load, the page is still a readable, working form in the browser's defaults.
///
/// It states its language and holds its heading and body in one `<main>` (ACCESSIBILITY.md,
/// ledger #1624). `title` and `body` go in as markup, unescaped: escaping an interpolated value
/// is the caller's job (see [`show_body`]).
pub(crate) fn page(title: &str, body: &str) -> Representation {
    Representation::new(
        ReprType::new("text/html").with_param("charset", "utf-8"),
        format!(
            "<!doctype html><html lang=\"en\">\
             <meta name=viewport content=\"width=device-width,initial-scale=1\">\
             <title>{title}</title>\
             <link rel=stylesheet href=\"{PAGE_CSS_PATH}\">\
             <body><main><h1>{title}</h1>{body}</main></body></html>"
        )
        .into_bytes(),
    )
}

/// Serves the pages' stylesheet (`PAGE_CSS`) as a same-origin `text/css` file, so an HTML door's
/// `style-src 'self'` admits it. `X-Content-Type-Options: nosniff` is set on the door, so the type
/// must be right.
pub struct PageCss;

#[async_trait::async_trait]
impl Endpoint for PageCss {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        Ok(Representation::new(
            ReprType::new("text/css").with_param("charset", "utf-8"),
            PAGE_CSS.as_bytes().to_vec(),
        ))
    }
    fn name(&self) -> &str {
        "decide-css"
    }
    fn describe(&self) -> Description {
        Description::new("decide-css")
            .title("The decision pages' stylesheet")
            .summary(
                "The same-origin stylesheet the decision, contact-block, label and passkey pages \
                 link, so they carry no inline style.",
            )
            // On the ACTION, as `passkey-js` declares its face: an explicit `ActionSpec` is
            // taken whole, so a flat `.output()` alone is invisible to the manifold's actions.
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("the stylesheet")
                    .output("text/css; charset=utf-8"),
            )
            .output("text/css; charset=utf-8")
    }
}

/// The action this resource IS, from the last segment of its own IRI
/// (`urn:calendar-request:approve` → `approve`).
/// The `{action}` of `urn:calendar-request:{action}`, as a declared binding input.
///
/// Declared on BOTH actions because a template variable that is not a declared binding input
/// makes the action undrivable from `urn:kernel:actions`: the manifold cannot form the IRI
/// from the contract, however reachable the resource is by direct resolution. The `one_of` is
/// the closed set [`CalendarRequest::invoke`] branches on — `decline` is the `_` arm, so the
/// list is the whole grammar rather than a subset of it.
fn action_binding() -> ArgSpec {
    ArgSpec::new("action")
        .binding()
        .class(crate::XSD_STRING)
        .one_of(["approve", "approve-zoom", "decline", "block"])
        .summary("the decision: the `{action}` of `urn:calendar-request:{action}`")
}

fn action_of(inv: &Invocation<'_>) -> String {
    inv.request
        .target
        .as_str()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The SHOW page's body: what the link would decide, and the form that posts it back.
///
/// Every interpolated value is escaped (ledger #1516). The shape gate keeps markup out of a link
/// that verifies today, but the page must not depend on a check that lives somewhere else.
fn show_body(id: &str, exp: i64, token: &str, verb_word: &str, note: &str) -> String {
    use ikigai_fn::html::html_text as esc;
    let (id, token, verb_word, note) = (esc(id), esc(token), esc(verb_word), esc(note));
    format!(
        "<p>Booking <code>{id}</code>.</p>\
         <form method=\"post\" id=\"act\">\
         <input type=hidden name=id value=\"{id}\">\
         <input type=hidden name=exp value=\"{exp}\">\
         <input type=hidden name=t value=\"{token}\">\
         <button>{verb_word}</button>\
         </form><p class=muted>{note}</p>{js}",
        js = crate::passkey::DECISION_PASSKEY_JS,
    )
}

/// The outcome words a decision POST redirects with (see [`crate::prg`]): the decision was
/// recorded, the link did not verify, or the passkey step was missing. Beside them,
/// [`prg::ALREADY`].
const RECORDED: &str = "recorded";
const INVALID: &str = "invalid";
const PASSKEY: &str = "passkey";

/// One answer for every kind of bad link.
fn bad_link_page() -> Representation {
    page(
        "That link didn't work",
        "<p>It may have expired, or already been used. You can still decide it on \
         your Mac.</p>",
    )
}

/// The page a decision POST redirects to: what happened, for the `action` in the path. Generic
/// by design, since its URL carries no booking: it names the decision, never the booking or who
/// asked for it. An unknown word is the bad-link page.
fn outcome_page(action: &str, word: &str) -> Representation {
    match word {
        RECORDED => {
            let what = match action {
                "approve" => "Approved — the invitation goes out once your Mac picks this up.",
                "approve-zoom" => {
                    "Approved with Zoom — a meeting is scheduled and the invitation, with the \
                     join link, goes out once your Mac picks this up."
                }
                "block" => "Blocked — this and future requests from that address are dropped.",
                _ => "Declined — they'll be told, and asked to suggest other times.",
            };
            page("Recorded", &format!("<p>{what}</p>"))
        }
        prg::ALREADY => page(
            "Already recorded",
            "<p>This link's decision was recorded before. Nothing more was done.</p>",
        ),
        PASSKEY => page(
            "Your passkey is needed",
            "<p>This decision needs a tap on your registered device. Reopen the link and try \
             again.</p>",
        ),
        _ => bad_link_page(),
    }
}

/// The `outcome` a GET of the page may carry: the word a decision POST redirected with.
fn outcome_spec(words: &[&str]) -> ArgSpec {
    ArgSpec::new(prg::OUTCOME)
        .optional()
        .class(crate::XSD_STRING)
        .one_of(words.iter().copied())
        .summary(
            "the outcome a decision POST redirected to (Post/Redirect/Get); with it, the page \
             shows what happened and needs no link fields",
        )
}

#[async_trait::async_trait]
impl Endpoint for CalendarRequest {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let action = action_of(inv);
        // The page a decision POST redirected to (Post/Redirect/Get, ledger #1879): no token,
        // so nothing to verify, and nothing in it but the outcome word.
        if inv.request.verb == Verb::Source {
            let word = param(inv, prg::OUTCOME)?;
            if !word.is_empty() {
                return Ok(outcome_page(&action, &word));
            }
        }
        let (id, token) = (param(inv, "id")?, param(inv, "t")?);
        let exp: i64 = param(inv, "exp")?.parse().unwrap_or(0);

        let key = verifying_key_at(&self.key_path)?;
        let now = now_secs();
        if !token_valid(&id, &action, exp, &token, &key, now) {
            // One answer for every kind of bad link — expired, forged, malformed, wrong
            // action. A prober learns nothing, and for a real person the cause is almost
            // always age.
            return Ok(match inv.request.verb {
                Verb::Sink => prg::see_other(INVALID, bad_link_page()),
                _ => bad_link_page(),
            });
        }

        match inv.request.verb {
            // SHOW: what this link would do, and a button to do it.
            Verb::Source => {
                let (verb_word, note) = match action.as_str() {
                    "approve" => (
                        "Approve",
                        "The invitation goes out once your Mac picks this up.",
                    ),
                    "approve-zoom" => (
                        "Approve + Zoom",
                        "A Zoom is scheduled and the invitation — with the join link — goes out \
                         once your Mac picks this up.",
                    ),
                    "block" => (
                        "Block",
                        "This and future requests from that address are dropped, silently.",
                    ),
                    _ => (
                        "Decline",
                        "They'll be told, and asked to suggest other times.",
                    ),
                };
                Ok(page(
                    &format!("{verb_word} this request?"),
                    &show_body(&id, exp, &token, verb_word, note),
                ))
            }
            // ACT: record the intent. The Mac does the real work when it next drains.
            Verb::Sink => {
                // Passkey second factor — inert until a credential is enrolled, then required.
                // The assertion rides in the POST body (pk_* fields the glue-JS adds).
                if crate::passkey::require_passkey(inv).is_err() {
                    return Ok(prg::see_other(PASSKEY, outcome_page(&action, PASSKEY)));
                }
                // Once per link: a second POST of the same decision records nothing.
                if !prg::claim("calendar-request", &self.key_path, &token, exp, now)? {
                    return Ok(prg::see_other(
                        prg::ALREADY,
                        outcome_page(&action, prg::ALREADY),
                    ));
                }
                let tuple = format!(
                    "((decide {}) (id {}) (exp {}) (token {}))",
                    quoted(&action),
                    quoted(&id),
                    quoted(&exp.to_string()),
                    quoted(&token)
                );
                let dropped = inv
                    .issue(
                        Request::new(
                            Verb::Sink,
                            Iri::parse(DECISIONS_SPACE).expect("literal IRI"),
                        )
                        .with_arg("content", ArgRef::Inline(tuple.into_bytes())),
                    )
                    .await;
                if let Err(e) = dropped {
                    prg::release("calendar-request", &self.key_path, &token);
                    return Err(e);
                }
                Ok(prg::see_other(RECORDED, outcome_page(&action, RECORDED)))
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
                    .summary("show — what this link would decide, or what a decision did")
                    .input(action_binding())
                    .input(
                        ArgSpec::new("id")
                            .summary("the booking id")
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
                    // ⚠ DECLARED because it is READ: a `<form method=post>` puts its
                    // fields in the BODY, which the HTTP face hands over as the piped
                    // `content`, and `param()` looks there when a name is not an argument.
                    // Undeclared, the one channel every browser submission actually uses
                    // was invisible to the manifold.
                    .input(
                        ArgSpec::new("content")
                            .optional()
                            .class(crate::XSD_STRING)
                            .summary(
                                "a urlencoded form body; the inputs above are read from it \
                                 when they are not named arguments",
                            ),
                    )
                    // On the ACTION: an explicit `ActionSpec` is taken WHOLE by
                    // `action_specs()`, which never folds the flat `.output()` below into
                    // it — so the flat declaration alone left both faces unannounced.
                    .input(outcome_spec(&[RECORDED, prg::ALREADY, INVALID, PASSKEY]))
                    .output("text/html; charset=utf-8"),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("decide — record the decision")
                    .input(action_binding())
                    .input(
                        ArgSpec::new("id")
                            .summary("the booking id")
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
                    // ⚠ DECLARED because it is READ: a `<form method=post>` puts its
                    // fields in the BODY, which the HTTP face hands over as the piped
                    // `content`, and `param()` looks there when a name is not an argument.
                    // Undeclared, the one channel every browser submission actually uses
                    // was invisible to the manifold.
                    .input(
                        ArgSpec::new("content")
                            .optional()
                            .class(crate::XSD_STRING)
                            .summary(
                                "a urlencoded form body; the inputs above are read from it \
                                 when they are not named arguments",
                            ),
                    )
                    // Every POST answers Post/Redirect/Get: the outcome page wrapped in an
                    // ikigai-web entity envelope whose `Location` makes it a `303` (ledger #1879).
                    .output(prg::HTTP_ENTITY),
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
        //
        // ⚠ SOURCE, not Sink, although confirming writes the calendar and sends mail: a stored
        // program serves Source only since ikigai-lisp 0.2 (ledger #903, C-B9 — a Sink, an
        // Exists or a Delete on a program door used to RUN it, verb unexamined), so a Sink here
        // is refused as `InvalidArgument { name: "verb" }` and every approval clicked on the
        // edge would stop at this line. The command is the program's DATA, read by `(input)`.
        let command = format!("({action} \"{id}\")");
        let out = inv
            .issue(
                Request::new(
                    Verb::Source,
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
                    .input(
                        ArgSpec::new("content")
                            .summary("the decision tuple")
                            .class(crate::XSD_STRING),
                    ),
            )
            .output("text/plain; charset=utf-8")
    }
}

/// Test-only: `html` carries no inline style, neither a `style=` attribute nor a `<style>`
/// element, which an HTML door's `style-src 'self'` refuses (ledger #1834). Shared by the page
/// tests here, in `contactblock` and in `passkey`.
#[cfg(test)]
pub(crate) fn assert_no_inline_style(html: &str) {
    let lower = html.to_ascii_lowercase();
    assert!(
        !lower.contains("style="),
        "an inline style= attribute: {html}"
    );
    assert!(
        !lower.contains("<style"),
        "an inline <style> element: {html}"
    );
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

    /// Ledger #1624 (ACCESSIBILITY.md): every page the embedded host serves states its language
    /// (WCAG 3.1.1) and puts its heading and content in ONE `<main>` landmark. The decision,
    /// contact-block, label and passkey pages all come through [`page`], so pinning it pins them.
    #[test]
    fn a_page_states_its_language_and_has_one_main_holding_its_content() {
        let rep = page("Approve this request?", "<p>the body</p>");
        let html = String::from_utf8(rep.bytes).unwrap();
        assert!(
            html.starts_with("<!doctype html><html lang=\"en\">"),
            "html lang: {html}"
        );
        assert_eq!(html.matches("<html").count(), 1, "{html}");
        assert_eq!(html.matches("<main>").count(), 1, "one main: {html}");
        assert_eq!(html.matches("</main>").count(), 1, "{html}");
        let main = &html[html.find("<main>").unwrap()..html.find("</main>").unwrap()];
        assert!(
            main.contains("<h1") && main.contains("<p>the body</p>"),
            "the heading and the body are inside main: {html}"
        );
        assert!(html.ends_with("</main></body></html>"), "{html}");
        // Still the small self-contained page a phone renders: the viewport and the width cap.
        assert!(
            html.contains("width=device-width,initial-scale=1"),
            "{html}"
        );
        // The width cap moved to the stylesheet with the rest of the inline styles (ledger #1834).
        assert!(PAGE_CSS.contains("max-width:32rem"), "{PAGE_CSS}");
    }

    /// Ledger #1834 (UX conventions D6/D12): the page shell carries no inline style, so an HTML
    /// door's `style-src 'self'` CSP renders it as written; its look is one linked same-origin
    /// stylesheet instead, which defines every class the pages use.
    #[test]
    fn the_page_shell_links_its_stylesheet_and_carries_no_inline_style() {
        for html in [
            String::from_utf8(page("Approve this request?", "<p>the body</p>").bytes).unwrap(),
            show_body(ID, EXP, "tok", "Approve", "a note"),
        ] {
            assert_no_inline_style(&html);
        }
        let html = String::from_utf8(page("t", "").bytes).unwrap();
        assert_eq!(
            html.matches(&format!("<link rel=stylesheet href=\"{PAGE_CSS_PATH}\">"))
                .count(),
            1,
            "{html}"
        );
        let head = &html[..html.find("<body>").expect("a body")];
        assert!(
            head.contains("<link rel=stylesheet"),
            "linked in the head: {html}"
        );
        // The mechanical path of the IRI (`/decide/css` ⇄ `urn:decide:css`), so a door with no
        // route table serves it too.
        assert_eq!(
            PAGE_CSS_IRI,
            format!("urn{}", PAGE_CSS_PATH.replace('/', ":"))
        );
        for class in [".muted{", ".field{", "button{", "h1{", "body{"] {
            assert!(PAGE_CSS.contains(class), "{class} is styled: {PAGE_CSS}");
        }
    }

    #[test]
    fn the_stylesheet_is_served_as_text_css() {
        let kernel = ikigai_core::Kernel::new(std::sync::Arc::new(
            ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new(PAGE_CSS_IRI), PageCss),
        ));
        let rep = futures::executor::block_on(kernel.issue(
            Request::new(Verb::Source, Iri::parse(PAGE_CSS_IRI).unwrap()),
            &ikigai_core::Capability::root(),
        ))
        .expect("the stylesheet resolves");
        assert_eq!(rep.repr_type.canonical(), "text/css;charset=utf-8");
        assert_eq!(rep.bytes, PAGE_CSS.as_bytes());
    }

    /// Ledger #1516: every value the SHOW page interpolates is escaped, in text and in an
    /// attribute. The shape gate (`id_shaped`, a verified URL-safe signature) keeps markup out of
    /// a link that verifies today; this pins the page so it does not depend on that gate.
    #[test]
    fn the_show_page_renders_markup_in_its_fields_as_text() {
        let body = show_body("<b>x</b>&y'", EXP, "t\"><i>z</i>", "Approve", "a note");
        assert!(!body.contains("<b>"), "{body}");
        assert!(!body.contains("<i>"), "{body}");
        assert!(
            body.contains("<code>&lt;b&gt;x&lt;/b&gt;&amp;y&#39;</code>"),
            "the id as text: {body}"
        );
        assert!(
            body.contains("name=id value=\"&lt;b&gt;x&lt;/b&gt;&amp;y&#39;\""),
            "the id as an attribute: {body}"
        );
        assert!(
            body.contains("name=t value=\"t&quot;&gt;&lt;i&gt;z&lt;/i&gt;\""),
            "a quote cannot close the attribute: {body}"
        );
    }

    /// The page escapes through `ikigai_fn::html::html_text` (ledger #1868): a C0 control other
    /// than tab, line feed and carriage return becomes U+FFFD, and a hostile value (quotes, a
    /// `<script>`, a `javascript:` URL) stays text inside its attribute. The page builds no
    /// `href` from data at all, so the `javascript:` URL has no link to become.
    #[test]
    fn the_show_page_maps_controls_and_keeps_a_hostile_value_inert() {
        let body = show_body(
            "a\u{1}b\u{1b}c\td",
            EXP,
            "javascript:alert(1)\"><script>alert('x')</script>",
            "Approve",
            "a note",
        );
        assert!(
            body.contains("<code>a\u{FFFD}b\u{FFFD}c\td</code>"),
            "controls as U+FFFD, tab kept: {body}"
        );
        assert!(
            !body.contains('\u{1}') && !body.contains('\u{1b}'),
            "{body}"
        );
        assert!(!body.contains("<script>"), "{body}");
        assert!(
            body.contains(
                "name=t value=\"javascript:alert(1)&quot;&gt;&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;\""
            ),
            "{body}"
        );
        assert!(!body.contains("href=\"javascript:"), "{body}");
    }

    #[test]
    fn a_freshly_minted_token_verifies() {
        let k = key();
        let t = mint_token(ID, "approve", EXP, &k);
        assert!(token_valid(ID, "approve", EXP, &t, &k.verifying_key(), NOW));
    }

    #[test]
    fn approve_zoom_is_a_known_action_whose_token_round_trips_and_does_not_forge() {
        assert!(known_action("approve-zoom"));
        let k = key();
        let v = k.verifying_key();
        let t = mint_token(ID, "approve-zoom", EXP, &k);
        assert!(token_valid(ID, "approve-zoom", EXP, &t, &v, NOW));
        // An approve token is NOT an approve-zoom token — the action is in the signed payload,
        // so a plain-accept link can't be swapped into one that also books a Zoom.
        let a = mint_token(ID, "approve", EXP, &k);
        assert!(!token_valid(ID, "approve-zoom", EXP, &a, &v, NOW));
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
        let dir = std::env::temp_dir().join(format!("ikigai-decide-{}-{name}", std::process::id()));
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

        /// POST the way a browser actually does it: fields in a urlencoded BODY, not the query.
        fn post_form(&self, action: &str, id: &str, exp: i64, token: &str) -> String {
            let body = format!("id={id}&exp={exp}&t={token}");
            let rep = block_on(
                self.kernel.issue(
                    Request::new(
                        Verb::Sink,
                        Iri::parse(format!("urn:calendar-request:{action}")).unwrap(),
                    )
                    .with_arg("content", ArgRef::Inline(body.into_bytes())),
                    &Capability::root(),
                ),
            )
            .expect("the page should render");
            String::from_utf8(rep.bytes.clone()).unwrap()
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
        // No inline style, so it renders under an HTML door's CSP (ledger #1834).
        assert_no_inline_style(&html);
        // The page a phone opens from the email: its language and its one landmark (ledger #1624).
        assert!(html.contains("<html lang=\"en\">"), "{html}");
        assert_eq!(html.matches("<main>").count(), 1, "{html}");
        assert!(
            html.contains("method=\"post\""),
            "offers a POST button: {html}"
        );
        assert!(w.dropped().is_empty(), "a GET must record nothing");
    }

    /// ★ Ledger #1879: the POST answers Post/Redirect/Get (a `Location` to the outcome, which
    /// carries no booking), and the same link POSTed again records nothing more.
    #[test]
    fn a_post_redirects_to_its_outcome_and_a_replay_acts_once() {
        let w = world("prg");
        let (exp, token) = w.valid("decline");
        let first = w.call(Verb::Sink, "decline", ID, exp, &token);
        assert!(first.starts_with("Content-Type: text/html"), "{first}");
        assert!(
            first.contains("\r\nLocation: ?outcome=recorded\r\n"),
            "{first}"
        );
        assert!(!first.contains(ID), "the outcome names no booking: {first}");
        let again = w.call(Verb::Sink, "decline", ID, exp, &token);
        assert!(
            again.contains("\r\nLocation: ?outcome=already\r\n"),
            "{again}"
        );
        assert!(again.contains("Already recorded"), "{again}");
        assert_eq!(w.dropped().len(), 1, "the replay dropped nothing");
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

    #[test]
    fn a_browser_form_post_carries_its_fields_in_the_body() {
        // The shape a real <form method=post> sends. Reading only query args made every
        // browser submission fail while curl-with-query-params passed — caught by running
        // it, not by a unit test, so it gets one now.
        let w = world("formpost");
        let (exp, token) = w.valid("approve");
        let html = w.post_form("approve", ID, exp, &token);
        assert!(html.contains("Recorded"), "{html}");
        assert_eq!(w.dropped().len(), 1);
        assert_eq!(field(&w.dropped()[0], "id").as_deref(), Some(ID));
    }

    #[test]
    fn a_forged_token_in_a_form_body_is_refused_too() {
        let w = world("formforged");
        let (exp, _) = w.valid("approve");
        let forged = mint_token(ID, "approve", exp, &SigningKey::from_bytes(&[9u8; 32]));
        assert!(w
            .post_form("approve", ID, exp, &forged)
            .contains("didn't work"));
        assert!(w.dropped().is_empty());
    }

    /// ★ **An accepted decision reaches a REAL Lisp program.** The program a decision runs,
    /// `urn:booking:confirm`, is an `ikigai_lisp::program`, and since ikigai-lisp 0.2 a program
    /// door serves Source only (ledger #903, C-B9). This used to issue a Sink, which 0.2
    /// refuses as `InvalidArgument { name: "verb" }` — so every approval clicked on the edge
    /// would have been verified here and then dropped. The stand-in program echoes its
    /// `(input)`, which is the command a person would type at the terminal.
    #[test]
    fn an_accepted_decision_runs_the_confirm_program_through_lisp() {
        let w = world("accept-runs-lisp");
        let (exp, token) = w.valid("approve");
        w.post_form("approve", ID, exp, &token);
        let tuple = w.dropped().pop().expect("the edge recorded the decision");
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    Exact::new("urn:decide:accept"),
                    DecideAccept {
                        key_path: w._dir.join("decide.pub"),
                    },
                )
                .bind(
                    Exact::new("urn:booking:confirm"),
                    ikigai_lisp::program("confirm", "(input)"),
                ),
        ));
        let out = block_on(
            kernel.issue(
                Request::new(Verb::Sink, Iri::parse("urn:decide:accept").unwrap())
                    .with_arg("content", ArgRef::Inline(tuple.into_bytes())),
                &Capability::root(),
            ),
        )
        .expect("a decision this host signed is acted on");
        let out = String::from_utf8(out.bytes).unwrap();
        assert!(
            out.contains("(approve") && out.contains(ID),
            "the program ran on the command: {out}"
        );
    }

    /// A missing or unreadable verifying key reads "not configured" and never names WHERE the
    /// host looked: the error crosses the wire to whoever asked, and an absolute path in it
    /// discloses the host's file layout. The file's own name stays, so an operator knows what
    /// to put in place.
    #[test]
    fn a_missing_or_unreadable_key_says_not_configured_without_its_path() {
        let dir = std::env::temp_dir().join(format!("ikigai-decide-{}-nokey", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ask = |key_path: std::path::PathBuf| {
            let kernel = Kernel::new(Arc::new(EndpointSpace::new().bind(
                UriTemplate::parse("urn:calendar-request:{action}").unwrap(),
                CalendarRequest { key_path },
            )));
            block_on(
                kernel.issue(
                    Request::new(
                        Verb::Sink,
                        Iri::parse("urn:calendar-request:approve").unwrap(),
                    )
                    .with_arg(
                        "content",
                        ArgRef::Inline(b"id=abcdefgh12&exp=99999999999&t=AAAA".to_vec()),
                    ),
                    &Capability::root(),
                ),
            )
            .expect_err("no usable key, no page")
            .to_string()
        };
        let missing = ask(dir.join("decide.pub"));
        std::fs::write(dir.join("garbled.pub"), "not a key").unwrap();
        let garbled = ask(dir.join("garbled.pub"));
        for (what, err) in [("missing", &missing), ("garbled", &garbled)] {
            assert!(err.contains("not configured"), "{what}: {err}");
            assert!(
                !err.contains(dir.to_str().unwrap())
                    && !err.contains(&*std::env::temp_dir().to_string_lossy()),
                "{what}: the error names no path: {err}"
            );
        }
        assert!(missing.contains("decide.pub"), "{missing}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
