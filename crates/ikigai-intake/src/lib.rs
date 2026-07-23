//! `ikigai-intake` — the front door for a public form.
//!
//! One endpoint shape: accept an **untrusted** submission (a browser form POST or a
//! `fetch` of JSON), validate it against declared fields, and drop it into a tuplespace as
//! an s-expression. The reactive handler on that space then does the work — email an
//! enquiry, schedule a booking — with the submission already reduced to clean DATA.
//!
//! This exists so the boundary between "the open internet" and "a tuple in my space" is
//! ONE audited place:
//!
//! - **The body is parsed, never trusted.** `application/x-www-form-urlencoded` or JSON,
//!   sniffed from the payload. Percent-decoding works over **bytes**, not `&str` offsets —
//!   slicing a `&str` at a computed offset panics when a `%` precedes a multibyte
//!   character, which is a real defect found in a sibling decoder.
//! - **Fields are declared.** Anything not declared is DROPPED rather than carried
//!   through, so a submitter cannot smuggle an extra key into the tuple the handler reads.
//! - **Values are escaped for the s-expression.** A quote or backslash in a message would
//!   otherwise break out of the datum and reshape the tuple the handler parses. Escaping
//!   here is what lets the handler's `read` stay a pure data parse.
//! - **A honeypot field must stay empty.** Bots fill every input; humans never see it.
//!   The rejection is deliberately indistinguishable from success to the submitter.
//!
//! What this does NOT do is authorise: the endpoint is capability-gated, and rate limiting
//! belongs in an overlay above it. CORS is browser-side only and is not a defence here.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, Error, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};

const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// One accepted field. The `summary` is human-facing on purpose: it becomes the
/// `ArgSpec` summary, which is what `?description` projects and a generated form renders
/// as the field's LABEL — so the same declaration drives validation *and* the UI.
#[derive(Clone, Debug)]
pub struct IntakeField {
    pub name: String,
    pub required: bool,
    /// The label/help a generated form shows. Write it for a human.
    pub summary: String,
    /// Allowed values, if constrained — a generated form renders these as a select.
    pub one_of: Vec<String>,
    /// Validate this field as an IANA time zone (`Europe/London`).
    ///
    /// Not expressed as `one_of`: the tzdata list is ~400 names and would dominate the
    /// `?description` every consumer fetches. The check lives here instead, so a generated
    /// form is free to build its own picker from whatever tzdata it has (a browser ships
    /// its own) while the server stays the authority on what it will accept.
    pub iana_zone: bool,
}

impl IntakeField {
    /// A required free-text field.
    pub fn required(name: impl Into<String>, summary: impl Into<String>) -> Self {
        IntakeField {
            name: name.into(),
            required: true,
            summary: summary.into(),
            one_of: Vec::new(),
            iana_zone: false,
        }
    }
    /// An optional free-text field.
    pub fn optional(name: impl Into<String>, summary: impl Into<String>) -> Self {
        IntakeField {
            name: name.into(),
            required: false,
            summary: summary.into(),
            one_of: Vec::new(),
            iana_zone: false,
        }
    }
    /// Constrain this field to `values` (rendered as a select).
    pub fn one_of<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.one_of = values.into_iter().map(Into::into).collect();
        self
    }
    /// Require this field to name an IANA time zone.
    pub fn iana_zone(mut self) -> Self {
        self.iana_zone = true;
        self
    }
}

/// What a form intake accepts and where it lands.
#[derive(Clone, Debug)]
pub struct IntakeConfig {
    /// The endpoint's short name (traces, `describe`).
    pub id: String,
    /// The space a validated submission is dropped into (`urn:space:contact`).
    pub space: String,
    /// The accepted fields, in the order a generated form should show them.
    pub fields: Vec<IntakeField>,
    /// A field validated as an email address, if any (also used as the handler's reply-to).
    pub email_field: Option<String>,
    /// A honeypot input that must arrive empty — bots fill it, humans never see it.
    pub honeypot: Option<String>,
    /// The capability a submitter must hold. A public route grants exactly this.
    pub requires: String,
    /// Where to look up the **link token** a submission arrived with, as an IRI template
    /// containing `{token}` — e.g. `urn:client:{token}`. `None` (the default) ignores
    /// tokens entirely.
    ///
    /// A token is a bearer credential handed out in a link. Resolving it turns
    /// "somebody on the internet" into "whoever I gave this link to", which the handler
    /// can act on. It is not authority: the endpoint is capability-gated either way, and
    /// a submission with no token, an unknown one, or a revoked one is still an ordinary
    /// public submission — a rotated link should stop *attributing*, not start rejecting.
    pub clients: Option<String>,
    /// Fields to copy out of a resolved client record into the tuple, each prefixed
    /// `via-` — e.g. `earliest` lands as `(via-earliest "7")`.
    ///
    /// This is how a per-client POLICY reaches the handler. The handler cannot look the
    /// client up itself: the tuple records the client's *id*, deliberately not the token,
    /// and the registry is keyed by token. So the door — which does hold the token, for
    /// exactly one instant — copies across what the handler will need.
    ///
    /// The `via-` prefix is doing real work: it marks these as ATTESTED by whoever issued
    /// the link, as opposed to the sibling fields the submitter typed. A handler that
    /// widens a booking window on `via-earliest` must never widen it on `earliest`.
    pub attests: Vec<String>,
}

/// The query argument a link token arrives in (`…/booking/submit?k=TOKEN`).
///
/// It rides the URL rather than the form so it never becomes a field in the generated UI,
/// and — because only DECLARED fields are carried — the raw token never reaches the tuple.
/// What lands there is the resolved identity, not the credential that proved it.
pub const TOKEN_ARG: &str = "k";

/// The field a resolved token is recorded under.
pub const VIA_FIELD: &str = "via";

/// Is this a token we are willing to put in an IRI?
///
/// The token is substituted into a template that a host may well resolve to a path, so it
/// is checked against a strict alphabet BEFORE it is interpolated anywhere — `..` and `/`
/// can never appear. Belt and braces: whatever the template resolves to validates too.
pub fn token_shaped(token: &str) -> bool {
    (8..=64).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Build the intake endpoint described by `config`.
pub fn submit(config: IntakeConfig) -> IntakeEndpoint {
    IntakeEndpoint { config }
}

/// The intake endpoint. See the [module docs](crate).
pub struct IntakeEndpoint {
    config: IntakeConfig,
}

/// Percent-decode `+`-style form encoding over BYTES. Decoding over `&str` byte offsets
/// panics when a `%` precedes a multibyte character; bytes cannot land mid-codepoint, and
/// the final `from_utf8_lossy` handles anything malformed.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    // Not a valid escape — keep the '%' literally.
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve `template` for `token`, returning `(id, attested fields)` — or `None` for any
/// failure, which is always treated as "no token".
///
/// The id is the record's own when it has one, so what lands in the tuple is a name chosen
/// by whoever issued the link ("acme-jane") rather than the secret from the URL. A record
/// without an id falls back to the token, which is one more reason tokens stay opaque.
async fn lookup_client(
    inv: &Invocation<'_>,
    template: &str,
    token: &str,
    attests: &[String],
) -> Option<(String, Vec<(String, String)>)> {
    let iri = Iri::parse(template.replace("{token}", token)).ok()?;
    let found = inv.issue(Request::new(Verb::Source, iri)).await.ok()?;
    let text = std::str::from_utf8(&found.bytes).ok()?;
    let record: serde_json::Value = serde_json::from_str(text).ok()?;
    let id = record
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(token)
        .trim();
    if id.is_empty() {
        return None;
    }
    // Only the fields the intake was configured to carry — a record may hold notes and
    // contact details that are nobody's business downstream.
    let carried = attests
        .iter()
        .filter_map(|name| {
            let value = match record.get(name)? {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => return None,
                other => other.to_string(),
            };
            (!value.is_empty()).then(|| (format!("via-{name}"), value))
        })
        .collect();
    Some((id.to_string(), carried))
}

/// Parse a submission body into (field, value) pairs. JSON when it starts with `{`
/// (a `fetch` of `application/json`), otherwise urlencoded (a plain form POST).
fn parse_body(body: &str) -> Result<Vec<(String, String)>> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| Error::InvalidArgument {
                name: "content".to_string(),
                detail: format!("body is not valid JSON: {e}"),
            })?;
        let object = value.as_object().ok_or_else(|| Error::InvalidArgument {
            name: "content".to_string(),
            detail: "a JSON submission must be an object".to_string(),
        })?;
        return Ok(object
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), text)
            })
            .collect());
    }
    Ok(trimmed
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect())
}

/// Render a value as an s-expression string literal. A quote or backslash would otherwise
/// break out of the datum and reshape the tuple the handler parses; newlines are escaped so
/// the tuple stays one readable line.
fn sexpr_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A minimal address shape check — one `@`, something either side, a dotted domain, no
/// spaces. The MTA is the real authority; this turns obvious junk into a typed rejection.
fn address_like(value: &str) -> bool {
    let mut parts = value.split('@');
    matches!((parts.next(), parts.next(), parts.next()), (Some(local), Some(domain), None)
        if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
        && !value.contains(char::is_whitespace)
}

#[async_trait]
impl Endpoint for IntakeEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let config = &self.config;
        if !inv.capability.allows(&config.requires) {
            return Err(Error::Denied(format!(
                "submitting to `{}` requires `{}`",
                config.space, config.requires
            )));
        }
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "{} accepts a submission via Sink, not {:?}",
                config.id, inv.request.verb
            )));
        }

        let body = inv
            .inline_str("content")
            .or_else(|_| inv.inline_str("in"))
            .map_err(|_| Error::MissingArgument("content".to_string()))?;
        let fields = parse_body(body)?;
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.trim().to_string())
        };

        // The honeypot: bots fill every input. A filled one is accepted-looking and
        // discarded, so a spammer learns nothing from the response.
        if let Some(trap) = &config.honeypot {
            if get(trap).map(|v| !v.is_empty()).unwrap_or(false) {
                return Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    b"received\n".to_vec(),
                ));
            }
        }

        // Only DECLARED fields are carried — an undeclared key never reaches the tuple.
        let mut carried: Vec<(String, String)> = Vec::new();
        for field in &config.fields {
            let value = get(&field.name).filter(|v| !v.is_empty());
            match value {
                Some(value) => {
                    // A constrained field must hold one of its declared values — the same
                    // list a generated form renders as a select, enforced server-side
                    // because the form is only a suggestion to a submitter.
                    if !field.one_of.is_empty() && !field.one_of.contains(&value) {
                        return Err(Error::InvalidArgument {
                            name: field.name.clone(),
                            detail: format!("`{value}` is not one of: {}", field.one_of.join(", ")),
                        });
                    }
                    // A zone must be one the tzdata knows, checked at the DOOR. Otherwise a
                    // typo is accepted here and only fails later inside the handler, where
                    // there is no longer anyone to tell — the submitter is long gone.
                    if field.iana_zone && value.parse::<chrono_tz::Tz>().is_err() {
                        return Err(Error::InvalidArgument {
                            name: field.name.clone(),
                            detail: format!(
                                "`{value}` is not a known time zone \
                                 (an IANA name like `Europe/London`)"
                            ),
                        });
                    }
                    carried.push((field.name.clone(), value));
                }
                None if field.required => {
                    return Err(Error::InvalidArgument {
                        name: field.name.clone(),
                        detail: format!("`{}` is required", field.name),
                    })
                }
                None => {}
            }
        }
        if let Some(email_field) = &config.email_field {
            if let Some((_, value)) = carried.iter().find(|(k, _)| k == email_field) {
                if !address_like(value) {
                    return Err(Error::InvalidArgument {
                        name: email_field.clone(),
                        detail: format!("`{value}` is not an email address"),
                    });
                }
            }
        }

        // A LINK TOKEN, if one came along, is resolved to WHO the link was given to. The
        // lookup is best-effort by design: an absent, malformed, unknown or revoked token
        // leaves the submission anonymous rather than refusing it, so rotating a link
        // degrades a customer to an ordinary visitor instead of locking them out.
        if let Some(template) = &config.clients {
            if let Ok(token) = inv.inline_str(TOKEN_ARG) {
                let token = token.trim();
                if token_shaped(token) {
                    if let Some((id, attested)) =
                        lookup_client(inv, template, token, &config.attests).await
                    {
                        carried.push((VIA_FIELD.to_string(), id));
                        carried.extend(attested);
                    }
                }
            }
        }

        // PROVENANCE comes from the TRANSPORT, never the body. The web layer sets these
        // from the connection (`client` from the proxy's forwarded-for, `received` from
        // its clock); a submitter cannot forge them, because only DECLARED body fields are
        // carried above — a `client=` input in the form is simply dropped like any other
        // undeclared key. Keeping the two sources separate is the whole point.
        for name in ["received", "client"] {
            if let Ok(value) = inv.inline_str(name) {
                let value = value.trim();
                if !value.is_empty() {
                    carried.push((name.to_string(), value.to_string()));
                }
            }
        }

        // The tuple: an s-expression of escaped DATA, exactly what the handler's `read`
        // parses. Values cannot break out of their literal, so a hostile message is text.
        let tuple = format!(
            "({})",
            carried
                .iter()
                .map(|(k, v)| format!("({k} {})", sexpr_string(v)))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let space = Iri::parse(&config.space)
            .map_err(|e| Error::Endpoint(format!("bad space `{}`: {e}", config.space)))?;
        inv.issue(
            Request::new(Verb::Sink, space).with_arg("content", ArgRef::Inline(tuple.into_bytes())),
        )
        .await?;

        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            b"received\n".to_vec(),
        ))
    }

    fn name(&self) -> &str {
        &self.config.id
    }

    fn describe(&self) -> Description {
        let mut action = ActionSpec::new(Verb::Sink)
            .summary("submit — validate a public form submission and drop it as a tuple")
            .requires(&self.config.requires);
        // These ArgSpecs ARE the form: `?description` projects them, and a generated UI
        // renders each summary as a label and each `one_of` as a select. One declaration,
        // validated here and rendered there — they cannot drift.
        for field in &self.config.fields {
            let mut spec = ArgSpec::new(field.name.clone())
                .summary(field.summary.clone())
                .class(XSD_STRING);
            if !field.required {
                spec = spec.optional();
            }
            if !field.one_of.is_empty() {
                spec = spec.one_of(field.one_of.clone());
            }
            action = action.input(spec);
        }
        Description::new(self.config.id.clone())
            .title("Form intake")
            .summary(format!(
                "Accepts a urlencoded or JSON submission, validates the declared fields, \
                 and drops them into {} as an escaped s-expression for the reactive \
                 handler. Undeclared fields are dropped; values cannot break out of their \
                 literal.",
                self.config.space
            ))
            .action(action)
            .output("text/plain; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{Capability, EndpointSpace, Exact, Kernel, UriTemplate};
    use std::sync::{Arc, Mutex};

    /// A stand-in space that records the tuples dropped into it.
    struct RecordingSpace {
        dropped: Arc<Mutex<Vec<String>>>,
    }
    #[async_trait]
    impl Endpoint for RecordingSpace {
        async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
            let body = inv.inline_str("content").unwrap_or_default().to_string();
            self.dropped.lock().unwrap().push(body);
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"ok".to_vec(),
            ))
        }
    }

    fn config() -> IntakeConfig {
        IntakeConfig {
            id: "contact".to_string(),
            space: "urn:space:contact".to_string(),
            fields: vec![
                IntakeField::required("name", "Your name"),
                IntakeField::required("email", "Your email address"),
                IntakeField::optional("organisation", "Organisation (optional)"),
                IntakeField::required("message", "Your message"),
            ],
            email_field: Some("email".to_string()),
            honeypot: Some("_honey".to_string()),
            requires: "urn:cap:contact:submit".to_string(),
            clients: None,
            attests: Vec::new(),
        }
    }

    fn kernel() -> (Kernel, Arc<Mutex<Vec<String>>>) {
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:contact:submit"), submit(config()))
            .bind(
                Exact::new("urn:space:contact"),
                RecordingSpace {
                    dropped: dropped.clone(),
                },
            );
        (Kernel::new(Arc::new(space)), dropped)
    }

    fn post(body: &str) -> Request {
        Request::new(Verb::Sink, Iri::parse("urn:contact:submit").unwrap())
            .with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()))
    }

    fn cap() -> Capability {
        Capability::scoped(["urn:cap:contact:submit"])
    }

    #[test]
    fn a_form_post_becomes_an_escaped_tuple() {
        let (k, dropped) = kernel();
        block_on(k.issue(
            post("name=Ada+Lovelace&email=ada%40example.com&organisation=Analytical&message=Hello+there"),
            &cap(),
        ))
        .unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        assert!(tuple.contains(r#"(name "Ada Lovelace")"#), "{tuple}");
        assert!(
            tuple.contains(r#"(email "ada@example.com")"#),
            "percent-decoded: {tuple}"
        );
        assert!(tuple.contains(r#"(message "Hello there")"#), "{tuple}");
        assert!(tuple.starts_with('(') && tuple.ends_with(')'));
    }

    /// A stand-in client registry: one known token, and a record of what was asked for.
    struct Registry {
        asked: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Endpoint for Registry {
        async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
            let iri = inv.request.target.as_str().to_string();
            self.asked.lock().unwrap().push(iri.clone());
            if iri == "urn:client:tok-abcdefgh" {
                return Ok(Representation::new(
                    ReprType::new("application/json"),
                    br#"{"id":"acme-jane","note":"retainer"}"#.to_vec(),
                ));
            }
            Err(Error::NotFound("no such client".into()))
        }
        fn name(&self) -> &str {
            "client"
        }
    }

    /// A kernel, the tuples dropped into its space, and the IRIs the registry was asked for.
    type TokenedKernel = (Kernel, Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<String>>>);

    /// An intake that resolves link tokens, plus the registry's record of lookups.
    fn tokened_kernel() -> TokenedKernel {
        let mut cfg = config();
        cfg.clients = Some("urn:client:{token}".to_string());
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:contact:submit"), submit(cfg))
            .bind(
                Exact::new("urn:space:contact"),
                RecordingSpace {
                    dropped: dropped.clone(),
                },
            )
            .bind(
                UriTemplate::parse("urn:client:{token}").unwrap(),
                Registry {
                    asked: asked.clone(),
                },
            );
        (Kernel::new(Arc::new(space)), dropped, asked)
    }

    fn with_token(body: &str, token: &str) -> Request {
        post(body).with_arg(TOKEN_ARG, ArgRef::Inline(token.as_bytes().to_vec()))
    }

    #[test]
    fn a_known_token_attributes_the_submission_without_storing_the_token() {
        let (k, dropped, _) = tokened_kernel();
        block_on(k.issue(
            with_token("name=X&email=x%40y.com&message=hi", "tok-abcdefgh"),
            &cap(),
        ))
        .unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        // The RECORD's id lands — a name chosen by the person who issued the link…
        assert!(tuple.contains(r#"(via "acme-jane")"#), "{tuple}");
        // …and the secret that proved it does NOT. The tuple names an identity, and the
        // credential stays at the door.
        assert!(
            !tuple.contains("tok-abcdefgh"),
            "token must not persist: {tuple}"
        );
    }

    #[test]
    fn an_unknown_token_is_still_an_ordinary_submission() {
        let (k, dropped, _) = tokened_kernel();
        // Revoking a link (deleting the record) must degrade a customer to a visitor, not
        // lock them out — so this is accepted, just unattributed.
        block_on(k.issue(
            with_token("name=X&email=x%40y.com&message=hi", "tok-revoked1"),
            &cap(),
        ))
        .unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        assert!(tuple.contains(r#"(name "X")"#), "accepted: {tuple}");
        assert!(!tuple.contains("(via "), "not attributed: {tuple}");
    }

    #[test]
    fn a_submission_without_a_token_is_unaffected() {
        let (k, dropped, asked) = tokened_kernel();
        block_on(k.issue(post("name=X&email=x%40y.com&message=hi"), &cap())).unwrap();
        assert!(!dropped.lock().unwrap()[0].contains("(via "));
        assert!(asked.lock().unwrap().is_empty(), "no lookup attempted");
    }

    #[test]
    fn a_token_that_could_escape_the_template_never_reaches_the_registry() {
        let (k, dropped, asked) = tokened_kernel();
        // A token is interpolated into an IRI a host may resolve to a PATH. These are
        // refused on shape, before the substitution — the registry is never even asked.
        for bad in [
            "../../etc/passwd",
            "tok/../../secret",
            "urn:file:secrets",
            "short",
            "tok abcdefgh",
        ] {
            block_on(k.issue(with_token("name=X&email=x%40y.com&message=hi", bad), &cap()))
                .unwrap();
        }
        assert!(
            asked.lock().unwrap().is_empty(),
            "malformed tokens were passed through: {:?}",
            asked.lock().unwrap()
        );
        // All five still submitted normally, just unattributed.
        assert_eq!(dropped.lock().unwrap().len(), 5);
        assert!(dropped.lock().unwrap().iter().all(|t| !t.contains("(via ")));
    }

    /// An intake with a zone field, to exercise the tzdata check.
    fn zoned_kernel() -> (Kernel, Arc<Mutex<Vec<String>>>) {
        let mut cfg = config();
        cfg.fields
            .push(IntakeField::required("zone", "Your timezone").iana_zone());
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:contact:submit"), submit(cfg))
            .bind(
                Exact::new("urn:space:contact"),
                RecordingSpace {
                    dropped: dropped.clone(),
                },
            );
        (Kernel::new(Arc::new(space)), dropped)
    }

    #[test]
    fn a_real_zone_is_accepted() {
        let (k, dropped) = zoned_kernel();
        block_on(k.issue(
            post("name=X&email=x%40y.com&message=hi&zone=Australia%2FLord_Howe"),
            &cap(),
        ))
        .unwrap();
        // A half-hour-off oddity, deliberately: it must survive as the submitter wrote it.
        assert!(
            dropped.lock().unwrap()[0].contains(r#"(zone "Australia/Lord_Howe")"#),
            "{:?}",
            dropped.lock().unwrap()[0]
        );
    }

    #[test]
    fn a_zone_that_tzdata_does_not_know_is_refused_at_the_door() {
        let (k, dropped) = zoned_kernel();
        let err = block_on(k.issue(
            post("name=X&email=x%40y.com&message=hi&zone=Europe%2FLundun"),
            &cap(),
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("not a known time zone"),
            "should say what's wrong: {err}"
        );
        // And nothing reached the space — the handler is never handed a zone it can't use.
        assert!(dropped.lock().unwrap().is_empty(), "nothing dropped");
    }

    #[test]
    fn a_zone_is_not_an_offset_or_an_abbreviation() {
        let (k, _) = zoned_kernel();
        // "PST" and "+05:30" are the two things people reach for instead of a zone name;
        // neither survives DST arithmetic, so neither is accepted.
        for bad in ["PST", "%2B05%3A30"] {
            let err = block_on(k.issue(
                post(&format!("name=X&email=x%40y.com&message=hi&zone={bad}")),
                &cap(),
            ))
            .unwrap_err();
            assert!(
                err.to_string().contains("not a known time zone"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn a_hostile_value_cannot_break_out_of_the_datum() {
        let (k, dropped) = kernel();
        // A quote + parens in the message would reshape the tuple the handler reads.
        block_on(k.issue(
            post("name=X&email=x%40y.com&message=%22)+(evil+%22pwned"),
            &cap(),
        ))
        .unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        // The payload survives as TEXT inside one escaped literal — every quote escaped,
        // so it cannot close the string and start a new datum. (The characters `(evil` do
        // appear, but inertly, inside the literal — which is exactly the point.)
        assert!(
            tuple.contains(r#"(message "\") (evil \"pwned")"#),
            "the whole payload stays inside one escaped literal: {tuple}"
        );
        // NOTE: the invariant is "every quote is escaped", NOT "parens balance" — parens
        // inside a string literal are inert text and need not balance. Asserting balance
        // would fail on a safe payload like "(((".
    }

    #[test]
    fn undeclared_fields_are_dropped() {
        let (k, dropped) = kernel();
        block_on(k.issue(
            post("name=X&email=x%40y.com&message=hi&role=admin&_next=http://evil"),
            &cap(),
        ))
        .unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        assert!(!tuple.contains("role"), "undeclared key dropped: {tuple}");
        assert!(!tuple.contains("_next"), "{tuple}");
    }

    #[test]
    fn json_is_accepted_too() {
        let (k, dropped) = kernel();
        block_on(k.issue(
            post(r#"{"name":"Ada","email":"ada@example.com","message":"From fetch"}"#),
            &cap(),
        ))
        .unwrap();
        assert!(dropped.lock().unwrap()[0].contains(r#"(message "From fetch")"#));
    }

    #[test]
    fn a_filled_honeypot_is_silently_discarded() {
        let (k, dropped) = kernel();
        let rep = block_on(k.issue(
            post("name=Bot&email=b%40y.com&message=spam&_honey=gotcha"),
            &cap(),
        ))
        .unwrap();
        assert_eq!(
            String::from_utf8(rep.bytes).unwrap(),
            "received\n",
            "looks like success"
        );
        assert!(dropped.lock().unwrap().is_empty(), "but nothing is dropped");
    }

    #[test]
    fn missing_and_malformed_fields_are_typed_rejections() {
        let (k, _) = kernel();
        let err = block_on(k.issue(post("name=X&email=x%40y.com"), &cap())).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument { ref name, .. } if name == "message"),
            "got: {err:?}"
        );
        let err = block_on(k.issue(post("name=X&email=nope&message=hi"), &cap())).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument { ref name, .. } if name == "email"),
            "got: {err:?}"
        );
    }

    #[test]
    fn provenance_comes_from_the_transport_and_cannot_be_forged_in_the_body() {
        let (k, dropped) = kernel();
        // The body TRIES to claim a different client; the transport arg is the real one.
        let request = post("name=X&email=x%40y.com&message=hi&client=1.2.3.4")
            .with_arg("client", ArgRef::Inline(b"203.0.113.9".to_vec()))
            .with_arg("received", ArgRef::Inline(b"2026-07-22T19:40:00Z".to_vec()));
        block_on(k.issue(request, &cap())).unwrap();
        let tuple = dropped.lock().unwrap()[0].clone();
        assert!(
            tuple.contains(r#"(client "203.0.113.9")"#),
            "the transport's client wins: {tuple}"
        );
        assert!(
            !tuple.contains("1.2.3.4"),
            "a body field cannot forge provenance: {tuple}"
        );
        assert!(
            tuple.contains(r#"(received "2026-07-22T19:40:00Z")"#),
            "{tuple}"
        );
    }

    #[test]
    fn submitting_is_capability_gated() {
        let (k, dropped) = kernel();
        let err = block_on(k.issue(
            post("name=X&email=x%40y.com&message=hi"),
            &Capability::scoped(Vec::<String>::new()),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "got: {err:?}");
        assert!(dropped.lock().unwrap().is_empty());
    }

    #[test]
    fn percent_decoding_survives_multibyte_after_an_escape() {
        // Decoding over &str offsets panics here; over bytes it cannot.
        assert_eq!(percent_decode("%41é"), "Aé");
        assert_eq!(percent_decode("a%2Fb+c"), "a/b c");
        assert_eq!(percent_decode("100%"), "100%", "a stray % stays literal");
    }
}
