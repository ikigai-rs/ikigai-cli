//! `ikigai-email` — outbound email as a resource.
//!
//! `urn:email:send` is a **Sink**: sending is a side effect, so it takes the message body
//! as the piped `content` and named arguments (`to`, `subject`, optional `cc`, `bcc`, and
//! `reply_to`). Each recipient field takes one or more comma-separated bare email addresses,
//! ignoring surrounding whitespace. `to` is required and must not be empty. All recipients
//! are validated before delivery. A bad recipient refuses the whole send and the diagnostic
//! names the field and the offending entry’s position without quoting its value.
//! `cc` goes in the Cc header and the SMTP envelope, while
//! `bcc` goes only in the envelope and is not printed in the success receipt.
//! Gated by [`CAP_SEND`], because reaching the outside world on your behalf is
//! authority, not a convenience.
//!
//! **Deliverability shapes the design.** Submission goes to a *local* SMTP (Postfix on
//! `localhost`), which relays onward through a transactional service. That keeps DKIM/SPF
//! and relay credentials in the MTA where they belong — this module never holds a secret,
//! and a contact-form enquiry doesn't silently land in a spam folder.
//!
//! **Two deliberate choices, both learned the hard way:**
//!
//! 1. **Failures are TYPED.** A refused connection or a 4xx greylist is
//!    [`Error::Unavailable`] (transient), a rejected address is
//!    [`Error::InvalidArgument`], a 5xx is [`Error::Endpoint`] (permanent). `is_transient`
//!    only matches `Timeout | Unavailable`, so a module that funnels everything into
//!    `Endpoint` silently disables the `Retry`/`CircuitBreaker`/`Failover` overlays. Mail
//!    is exactly the workload that wants them.
//! 2. **Headers are guarded against injection.** The envelope fields are fed from a PUBLIC
//!    contact form. A newline in `to`/`cc`/`bcc`/`subject`/`reply_to` is classic SMTP header
//!    injection (smuggling a `Bcc:` to turn your contact form into an open relay), so any
//!    control character in those fields is rejected before a message is built.
//!
//! **Attachments are NAMED, never inlined.** The optional `attach` argument takes one or
//! more resource IRIs (newline-separated, the map convention). Each is SOURCED through the
//! kernel under the CALLER's own capability, so an attachment is only ever something the
//! caller could already read: a refused read refuses the whole send. Attaching is also its
//! own authority, [`CAP_ATTACH`], checked before anything is read, so a holder of
//! [`CAP_SEND`] alone (a contact form's handler) cannot turn mail into an exfiltration path.
//! The part's media type is the representation's, its filename the IRI's last segment unless
//! `attach_name` names it. The message becomes `multipart/mixed`: the body first (or the
//! iMIP alternative, kept whole, when `ics` is given), then each attachment, built with
//! lettre's own types. Bounds REFUSE, never truncate: at most [`MAX_ATTACHMENTS`] parts and
//! [`MAX_ATTACHMENT_BYTES`] in total. A content holding a PEM private key block or an age
//! secret key is refused, so a `.key` is never mailed by mistake.
//!
//! The transport is behind [`MailTransport`] — the same seam `ikigai-http` uses — so the
//! validation, envelope, and error mapping are testable without an SMTP server.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, Iri,
    ListSeparator, ReprType, Representation, Result, Verb,
};
use std::sync::Arc;

/// Sending mail requires this capability.
pub const CAP_SEND: &str = "urn:cap:email:send";

/// Attaching a resource requires this capability as well as [`CAP_SEND`]: mailing out
/// something the kernel can read is more authority than sending a message. Checked by the
/// endpoint whenever `attach` is given, before any attachment is read.
pub const CAP_ATTACH: &str = "urn:cap:email:attach";

/// The most attachments one message may carry. More is refused, never truncated.
pub const MAX_ATTACHMENTS: usize = 10;

/// The most bytes all of one message's attachments may hold together: 10 MiB. More is
/// refused, never truncated.
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// The class of the `attach` argument: each line is a resource IRI.
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";

/// The XSD `string` datatype IRI — the declared class of the envelope arguments.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const TEXT_PLAIN_UTF8: &str = "text/plain; charset=utf-8";

/// Where a message goes and who it says it is from — injected by the host at bind time,
/// never read from the environment here (same discipline as the other module crates).
#[derive(Clone, Debug)]
pub struct EmailConfig {
    /// The submission host — normally `localhost`, a Postfix that relays onward.
    pub host: String,
    /// The submission port (25 for a local Postfix, 587 for a submission service).
    pub port: u16,
    /// The envelope `From` — a mailbox the relay is authorized to send as.
    pub from: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        EmailConfig {
            host: "localhost".to_string(),
            port: 25,
            from: "ikigai@localhost".to_string(),
        }
    }
}

/// One validated outbound message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub from: String,
    /// Primary recipients, also written to the To header.
    pub to: Vec<String>,
    /// Copy recipients, also written to the Cc header.
    pub cc: Vec<String>,
    /// Blind copy recipients, only used in the SMTP envelope.
    pub bcc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body: String,
    /// An optional iCalendar invite (a full VCALENDAR). When present the message is a proper
    /// iMIP invitation — a `multipart/alternative` of the plain body and a
    /// `text/calendar; method=REQUEST` part — so a mail client shows an add-to-calendar /
    /// RSVP card. It carries its OWN `METHOD` line; the transport does not add one.
    pub ics: Option<String>,
    /// Files to attach, in the order named. Empty for a message with none.
    pub attachments: Vec<Attachment>,
}

/// One attachment, already read through the kernel and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// The filename the part carries (header-safe).
    pub filename: String,
    /// The media type of the representation it was read as, with its parameters.
    pub media_type: String,
    /// The representation's bytes, carried unchanged.
    pub bytes: Vec<u8>,
}

/// Why a delivery failed, split the way the kernel's error taxonomy needs: a `Transient`
/// failure is worth retrying (connection refused, greylisted), a `Permanent` one is not.
#[derive(Debug)]
pub enum MailError {
    Transient(String),
    Permanent(String),
}

/// The submission seam. A real transport speaks SMTP; a test one records what it was
/// handed — so envelope construction and error mapping are provable without a server.
pub trait MailTransport: Send + Sync {
    /// Deliver `message`, returning a short receipt for the log.
    fn deliver(&self, message: &Outgoing) -> std::result::Result<String, MailError>;
}

/// Mount `urn:email:send` over `transport`, sending as `config.from`.
pub fn space(config: EmailConfig, transport: Arc<dyn MailTransport>) -> EndpointSpace {
    EndpointSpace::new().bind(Exact::new("urn:email:send"), send(config, transport))
}

/// Construct the [`urn:email:send`](SendEndpoint) endpoint.
pub fn send(config: EmailConfig, transport: Arc<dyn MailTransport>) -> SendEndpoint {
    SendEndpoint { config, transport }
}

/// The `urn:email:send` endpoint. See the [module docs](crate).
pub struct SendEndpoint {
    config: EmailConfig,
    transport: Arc<dyn MailTransport>,
}

/// Reject an envelope field that could smuggle SMTP headers. A CR or LF (or any other
/// control character) in `to`/`subject`/`reply_to` ends the current header and starts a
/// new one — the classic way a public contact form becomes an open relay via an injected
/// `Bcc:`. Empty is rejected too, so a blank `to` never reaches the transport.
fn header_safe(name: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidArgument {
            name: name.to_string(),
            detail: format!("`{name}` must not be empty"),
        });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidArgument {
            name: name.to_string(),
            detail: format!("`{name}` must not contain control characters (SMTP header injection)"),
        });
    }
    Ok(value.to_string())
}

/// RFC 5322 `specials` other than `@` and `.`. A bare address never contains one; they only
/// appear in display names (`Bob <a@x>`), groups, comments, quoted local parts, domain
/// literals and address lists.
const ADDRESS_SPECIALS: &[char] = &['<', '>', '(', ')', '[', ']', ':', ';', ',', '"', '\\'];

/// A minimal address shape check — one `@`, something either side, no spaces and none of
/// the [`ADDRESS_SPECIALS`]. Not RFC 5322 (that way lies madness); the transport is the real
/// authority. This exists to turn obvious junk from a public form into a typed 400 instead of
/// an SMTP round trip, and to require each mailbox to be a bare address: `Your Bank<a@x.example>`
/// would otherwise go out with a display name whoever filled the form chose.
fn address_like(name: &str, value: &str) -> Result<String> {
    let value = header_safe(name, value)?;
    let mut parts = value.split('@');
    let ok = matches!((parts.next(), parts.next(), parts.next()), (Some(local), Some(domain), None)
        if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
        && !value.contains(|c: char| c.is_whitespace() || ADDRESS_SPECIALS.contains(&c));
    if !ok {
        return Err(Error::InvalidArgument {
            name: name.to_string(),
            // Never the value: a public form can fill an address, and a refusal's text can be
            // written in the clear (a dead-lettered tuple's `.err` note). Name the argument
            // and the rule, so the sentence still says what to fix.
            detail: format!(
                "`{name}` is not an email address: it needs one @ with a name before it and a \
                 domain with a dot after it, and no spaces or any of < > ( ) [ ] : ; , \" \\"
            ),
        });
    }
    Ok(value)
}

/// Check each recipient individually, naming its position on refusal.
fn recipient_list(name: &str, value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .enumerate()
        .map(|(index, entry)| {
            let invalid = |reason| Error::InvalidArgument {
                name: name.to_string(),
                detail: format!("`{name}` entry {}: {reason}", index + 1),
            };
            // Do not let trimming hide line breaks, including at a list boundary.
            if entry.contains(['\r', '\n']) {
                return Err(invalid(
                    "must not contain control characters (SMTP header injection)".to_string(),
                ));
            }
            let address = address_like(name, entry).map_err(|err| match err {
                Error::InvalidArgument { detail, .. } => invalid(detail),
                err => err,
            })?;
            // The SMTP library has stricter syntax rules than the public-form shape check.
            // Apply them here too, before handing even the valid recipients to a transport.
            address
                .parse::<lettre::Address>()
                .map_err(|_| invalid("not a valid SMTP address".to_string()))?;
            Ok(address)
        })
        .collect()
}

fn invalid(name: &str, detail: String) -> Error {
    Error::InvalidArgument {
        name: name.to_string(),
        detail,
    }
}

/// The filename an IRI names by default: its last segment, after the last `/` or `:`, with
/// any query or fragment dropped.
fn default_filename(iri: &str) -> &str {
    let path = iri.split(['?', '#']).next().unwrap_or(iri);
    path.rsplit(['/', ':']).next().unwrap_or(path)
}

/// Does `bytes` hold secret key material: a PEM private key block (`-----BEGIN … PRIVATE
/// KEY-----`, which covers PKCS#8, its encrypted form, the RSA/EC/DSA forms, OpenSSH and a
/// PGP private key block) or an age secret key (`AGE-SECRET-KEY-`)? Named, so the refusal
/// can say which.
fn secret_key_kind(bytes: &[u8]) -> Option<&'static str> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    let mut rest = bytes;
    while let Some(at) = find(rest, BEGIN) {
        rest = &rest[at + BEGIN.len()..];
        let label_end = find(rest, DASHES).unwrap_or(rest.len());
        let label = &rest[..label_end];
        if !label.contains(&b'\n') && find(&label.to_ascii_uppercase(), b"PRIVATE KEY").is_some() {
            return Some("a PEM private key block");
        }
    }
    find(&bytes.to_ascii_uppercase(), b"AGE-SECRET-KEY-").map(|_| "an age secret key")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Read and check the `attach` argument's resources (see the [module docs](crate)).
async fn attachments(inv: &Invocation<'_>) -> Result<Vec<Attachment>> {
    let Some(attach) = inv.optional_str("attach")? else {
        if inv.optional_str("attach_name")?.is_some() {
            return Err(invalid(
                "attach_name",
                "`attach_name` names attachments, so it needs `attach`".to_string(),
            ));
        }
        return Ok(Vec::new());
    };
    let iris = ListSeparator::Newline.split(attach);
    if iris.is_empty() {
        return Err(invalid(
            "attach",
            "`attach` must name at least one resource IRI".to_string(),
        ));
    }
    // Authority before anything is read, so a caller without it learns nothing about the
    // resources it named.
    if !inv.capability.allows(CAP_ATTACH) {
        return Err(Error::Denied(
            format!("attaching a resource to mail requires `{CAP_ATTACH}`").into(),
        ));
    }
    if iris.len() > MAX_ATTACHMENTS {
        return Err(invalid(
            "attach",
            format!(
                "`attach` names {} resources; a message may carry at most {MAX_ATTACHMENTS} \
                 attachments",
                iris.len()
            ),
        ));
    }
    let names = match inv.optional_str("attach_name")? {
        None => None,
        Some(value) => {
            let names = ListSeparator::Newline.split(value);
            if names.len() != iris.len() {
                return Err(invalid(
                    "attach_name",
                    format!(
                        "`attach_name` gives {} names for {} attachments; give one name per \
                         line for each `attach` line, in the same order",
                        names.len(),
                        iris.len()
                    ),
                ));
            }
            Some(names)
        }
    };
    let mut parsed = Vec::with_capacity(iris.len());
    for (index, &iri) in iris.iter().enumerate() {
        let entry = index + 1;
        let target = Iri::parse(iri).map_err(|_| {
            invalid(
                "attach",
                format!("`attach` entry {entry} is not a resource IRI"),
            )
        })?;
        let (field, filename) = match &names {
            Some(names) => ("attach_name", names[index]),
            None => ("attach", default_filename(iri)),
        };
        let filename = header_safe(field, filename).map_err(|err| match err {
            Error::InvalidArgument { detail, .. } => invalid(
                field,
                format!("the filename for attachment {entry}: {detail}"),
            ),
            err => err,
        })?;
        parsed.push((entry, target, filename));
    }

    let mut total = 0usize;
    let mut out = Vec::with_capacity(parsed.len());
    for (entry, target, filename) in parsed {
        // Under the caller's own capability: a Denied read refuses the whole send.
        let rep = inv.source_body(&target).await?;
        // The running total is held to the cap AS each resource is read: a body whose
        // declared length is already past what is left is refused before it is read, and a
        // stream is refused at the first chunk past it, never read whole first.
        let left = MAX_ATTACHMENT_BYTES - total;
        let bytes = rep.bytes.collect(left).await.map_err(|err| match err {
            Error::OverBudget { .. } => invalid(
                "attach",
                format!(
                    "the attachments come to more than {MAX_ATTACHMENT_BYTES} bytes (10 MiB), \
                     the most one message may carry"
                ),
            ),
            err => err,
        })?;
        total += bytes.len();
        let bytes = bytes.to_vec();
        if let Some(kind) = secret_key_kind(&bytes) {
            return Err(invalid(
                "attach",
                format!(
                    "attachment {entry} holds {kind}, and secret keys are never mailed; \
                     attach the public certificate or key instead"
                ),
            ));
        }
        let media_type = rep.repr_type.canonical();
        lettre::message::header::ContentType::parse(&media_type).map_err(|_| {
            invalid(
                "attach",
                format!("attachment {entry} has a media type mail cannot carry"),
            )
        })?;
        out.push(Attachment {
            filename,
            media_type,
            bytes,
        });
    }
    Ok(out)
}

#[async_trait]
impl Endpoint for SendEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_SEND) {
            return Err(Error::Denied(
                format!("sending mail requires `{CAP_SEND}`").into(),
            ));
        }
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "urn:email:send is a Sink (sending is a side effect), not {:?}",
                inv.request.verb
            )));
        }
        // Refuse rather than ship a sender nobody owns. An unconfigured `from` otherwise goes
        // out as a placeholder (e.g. `ikigai@localhost`), which any sender-aligned relay
        // rejects — silently, from the caller's side. The host sets this once, in one place.
        if self.config.from.trim().is_empty() {
            return Err(Error::Endpoint(
                "email has no configured sender — set `mail.from` in the host config \
                 (~/.config/ikigai/config.toml, or IKIGAI_MAIL_FROM) before sending"
                    .to_string(),
            ));
        }

        let to = recipient_list("to", inv.inline_str("to")?)?;
        let optional_recipients = |name| match inv.optional_str(name)? {
            Some(value) => recipient_list(name, value),
            None => Ok(Vec::new()),
        };
        let cc = optional_recipients("cc")?;
        let bcc = optional_recipients("bcc")?;
        let subject = header_safe("subject", inv.inline_str("subject")?)?;
        let reply_to = match inv.optional_str("reply_to")? {
            Some(value) if !value.trim().is_empty() => Some(address_like("reply_to", value)?),
            _ => None,
        };
        // The body is the piped content (`content`, falling back to `in`) — a Sink's body.
        let body = match inv.optional_str("content")? {
            Some(body) => body,
            None => inv
                .optional_str("in")?
                .ok_or_else(|| Error::MissingArgument("content".to_string()))?,
        }
        .to_string();

        // An optional calendar invite. Not header-checked (it is a body part, not a
        // header) but it must be non-empty to count.
        let ics = inv
            .optional_str("ics")?
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty());

        // Attachments last: every other argument is checked before anything is read.
        let attachments = attachments(inv).await?;

        let message = Outgoing {
            from: self.config.from.clone(),
            to,
            cc,
            bcc,
            reply_to,
            subject,
            body,
            ics,
            attachments,
        };
        match self.transport.deliver(&message) {
            Ok(receipt) => Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                format!("sent to {}: {receipt}\n", message.to.join(", ")).into_bytes(),
            )),
            // TYPED failures: transient ones are retryable, so `is_transient` is true and
            // the Retry/CircuitBreaker overlays can actually engage.
            Err(MailError::Transient(detail)) => Err(Error::Unavailable(format!(
                "mail submission failed (retryable): {detail}"
            ))),
            Err(MailError::Permanent(detail)) => {
                Err(Error::Endpoint(format!("mail rejected: {detail}")))
            }
        }
    }

    fn name(&self) -> &str {
        "send"
    }

    fn describe(&self) -> Description {
        Description::new("send")
            .title("Send email")
            .summary(
                "Submit a message over SMTP. The body is the `content` (piped or explicit); \
                 `to` and `subject` are required, `cc`, `bcc`, and `reply_to` optional. \
                 Recipient lists are comma-separated, and blind copies are envelope-only. An optional `ics` \
                 VCALENDAR makes it an iMIP calendar invitation. An optional `attach` names \
                 one or more resources to attach (newline-separated IRIs, read under the \
                 caller's own capability, never inlined bytes), for example a public \
                 certificate (`urn:file:…/server.crt`), an Open Badges credential \
                 (`application/ld+json`) or a certificate PDF; attaching also requires \
                 `urn:cap:email:attach`. At most 10 attachments and 10 MiB in total; a \
                 private key or age secret key is refused. Envelope fields and filenames \
                 are rejected if they contain control characters (SMTP header injection). \
                 Submission \
                 goes to a local MTA that relays onward, so DKIM/SPF and relay credentials \
                 stay in the MTA. A refused or greylisted submission is a TRANSIENT error, \
                 so Retry/CircuitBreaker overlays apply.",
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("send — submit the piped body as an email")
                    .input(
                        ArgSpec::new("to")
                            .summary("one or more comma-separated primary recipient addresses")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("cc")
                            .optional()
                            .summary("comma-separated copy recipients for the Cc header")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("bcc")
                            .optional()
                            .summary("comma-separated blind copy recipients (SMTP envelope only)")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("subject")
                            .summary("the subject line")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("content")
                            .summary(
                                "the message body — this endpoint's piped content, or an \
                                      explicit `content` argument",
                            )
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("reply_to")
                            .optional()
                            .summary("an optional Reply-To (e.g. the enquirer's address)")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("ics")
                            .optional()
                            .summary(
                                "an iCalendar document (a VCALENDAR, e.g. METHOD:REQUEST) \
                                      sent as a text/calendar iMIP part, so the message is an \
                                      add-to-calendar / RSVP invitation",
                            )
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("attach")
                            .optional()
                            .summary(
                                "resources to attach, one IRI per line: each is read under \
                                 your own capability and sent with its media type, for \
                                 example a public certificate, a credential (an Open \
                                 Badges JSON-LD document) or a PDF. Needs \
                                 `urn:cap:email:attach`; at most 10 attachments and 10 MiB \
                                 in total; private keys and age secret keys are refused",
                            )
                            .list(ListSeparator::Newline)
                            .class(XSD_ANY_URI),
                    )
                    .input(
                        ArgSpec::new("attach_name")
                            .optional()
                            .summary(
                                "filenames for the attachments, one per line in `attach` \
                                 order (default: each IRI's last segment)",
                            )
                            .list(ListSeparator::Newline)
                            .needs(["attach"])
                            .class(XSD_STRING),
                    )
                    .requires(CAP_SEND),
            )
            .output(TEXT_PLAIN_UTF8)
    }
}

/// The real transport: blocking SMTP submission to `host:port`, no TLS and no auth —
/// because it submits to a *local* MTA which owns the onward relay (and its credentials).
pub struct SmtpSubmission {
    host: String,
    port: u16,
}

impl SmtpSubmission {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        SmtpSubmission {
            host: host.into(),
            port,
        }
    }
}

/// Build the wire message from an [`Outgoing`] — plain, or an iMIP invitation when it
/// carries an `.ics`. Split out from delivery so the MIME structure is provable without an
/// SMTP server.
fn build_message(message: &Outgoing) -> std::result::Result<lettre::Message, MailError> {
    use lettre::{address::Envelope, message::Mailbox, Address};

    let from: Mailbox = message
        .from
        .parse()
        .map_err(|e| MailError::Permanent(format!("bad From address: {e}")))?;
    let mut builder = lettre::Message::builder()
        .from(from.clone())
        .subject(message.subject.clone());
    let parse = |field, value: &str| {
        value
            .parse::<Address>()
            .map_err(|e| MailError::Permanent(format!("bad {field} address: {e}")))
    };
    let mut recipients = Vec::new();
    for value in &message.to {
        let address = parse("To", value)?;
        builder = builder.to(Mailbox::new(None, address.clone()));
        recipients.push(address);
    }
    for value in &message.cc {
        let address = parse("Cc", value)?;
        builder = builder.cc(Mailbox::new(None, address.clone()));
        recipients.push(address);
    }
    for value in &message.bcc {
        recipients.push(parse("Bcc", value)?);
    }
    // Build the envelope directly so blind addresses never enter the header builder.
    let envelope = Envelope::new(Some(from.email), recipients)
        .map_err(|e| MailError::Permanent(format!("building the envelope: {e}")))?;
    builder = builder.envelope(envelope);
    if let Some(reply_to) = &message.reply_to {
        builder = builder.reply_to(
            reply_to
                .parse()
                .map_err(|e| MailError::Permanent(format!("bad Reply-To address: {e}")))?,
        );
    }
    use lettre::message::{header, MultiPart, SinglePart};
    // The message's own content: the plain body, or the iMIP alternative when it carries an
    // invite. iMIP: the plain body and the invite as two alternatives of the same message. A
    // client that understands calendars shows the RSVP card; one that does not falls back
    // to the text. The `method=REQUEST` on the part is what makes it an invitation rather
    // than a mere event to file.
    let alternative = match &message.ics {
        None => None,
        Some(ics) => {
            let calendar =
                header::ContentType::parse("text/calendar; charset=utf-8; method=REQUEST")
                    .map_err(|e| MailError::Permanent(format!("calendar content-type: {e}")))?;
            Some(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(message.body.clone()))
                    .singlepart(SinglePart::builder().header(calendar).body(ics.clone())),
            )
        }
    };
    if message.attachments.is_empty() {
        return match alternative {
            None => builder
                .body(message.body.clone())
                .map_err(|e| MailError::Permanent(format!("building the message: {e}"))),
            Some(alternative) => builder
                .multipart(alternative)
                .map_err(|e| MailError::Permanent(format!("building the invite: {e}"))),
        };
    }
    // With attachments: multipart/mixed, the content first and each attachment after it.
    let mut mixed = match alternative {
        None => MultiPart::mixed().singlepart(SinglePart::plain(message.body.clone())),
        Some(alternative) => MultiPart::mixed().multipart(alternative),
    };
    for (index, attachment) in message.attachments.iter().enumerate() {
        let content_type = header::ContentType::parse(&attachment.media_type).map_err(|_| {
            MailError::Permanent(format!("attachment {}: bad media type", index + 1))
        })?;
        mixed = mixed.singlepart(
            lettre::message::Attachment::new(attachment.filename.clone())
                .body(attachment.bytes.clone(), content_type),
        );
    }
    builder
        .multipart(mixed)
        .map_err(|e| MailError::Permanent(format!("building the message: {e}")))
}

impl MailTransport for SmtpSubmission {
    fn deliver(&self, message: &Outgoing) -> std::result::Result<String, MailError> {
        use lettre::Transport as _;
        let email = build_message(message)?;
        let mailer = lettre::SmtpTransport::builder_dangerous(&self.host)
            .port(self.port)
            .build();
        match mailer.send(&email) {
            Ok(response) => Ok(format!("{:?}", response.code())),
            // A permanent SMTP reply (5xx) is the server refusing outright; everything
            // else — refused connection, timeout, 4xx greylist — is worth retrying.
            Err(e) if e.is_permanent() => Err(MailError::Permanent(e.to_string())),
            Err(e) => Err(MailError::Transient(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use std::sync::Mutex;

    /// Records what it was handed, and can be told to fail — so envelope construction and
    /// the transient/permanent mapping are provable without an SMTP server.
    struct FakeMail {
        sent: Mutex<Vec<Outgoing>>,
        outcome: Option<MailError>,
    }
    impl FakeMail {
        fn ok() -> Arc<Self> {
            Arc::new(FakeMail {
                sent: Mutex::new(Vec::new()),
                outcome: None,
            })
        }
    }
    impl MailTransport for FakeMail {
        fn deliver(&self, message: &Outgoing) -> std::result::Result<String, MailError> {
            self.sent.lock().unwrap().push(message.clone());
            match &self.outcome {
                None => Ok("250".to_string()),
                Some(MailError::Transient(d)) => Err(MailError::Transient(d.clone())),
                Some(MailError::Permanent(d)) => Err(MailError::Permanent(d.clone())),
            }
        }
    }

    #[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
    fn kernel(transport: Arc<dyn MailTransport>) -> Kernel {
        let config = EmailConfig {
            host: "localhost".to_string(),
            port: 25,
            from: "site@example.com".to_string(),
        };
        Kernel::new(Arc::new(space(config, transport)))
    }

    fn send_request(args: &[(&str, &str)]) -> Request {
        let mut request =
            Request::new(Verb::Sink, Iri::parse("urn:email:send").expect("valid IRI"));
        for (name, value) in args {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        request
    }

    fn cap() -> Capability {
        Capability::scoped([CAP_SEND])
    }

    #[test]
    fn a_send_builds_the_envelope_and_reports_the_receipt() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        let rep = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "Enquiry from example.com"),
                ("reply_to", "someone@example.com"),
                ("content", "Hello, I would like to talk."),
            ]),
            &cap(),
        ))
        .unwrap();
        assert!(String::from_utf8(rep.bytes)
            .unwrap()
            .contains("sent to owner@example.com"));
        let sent = mail.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, "site@example.com", "the configured From");
        assert_eq!(sent[0].reply_to.as_deref(), Some("someone@example.com"));
        assert_eq!(sent[0].body, "Hello, I would like to talk.");
    }

    #[test]
    fn recipients_reach_the_envelope_and_only_visible_recipients_reach_headers() {
        let mail = FakeMail::ok();
        let receipt = block_on(kernel(mail.clone()).issue(
            send_request(&[
                ("to", " one@example.com , two@example.com "),
                ("cc", " three@example.com , four@example.com "),
                ("bcc", " five@example.com , six@example.com "),
                ("subject", "Hello"),
                ("content", "Body"),
            ]),
            &cap(),
        ))
        .unwrap();
        assert_eq!(
            receipt.bytes,
            b"sent to one@example.com, two@example.com: 250\n"
        );
        let sent = mail.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let message = build_message(&sent[0]).unwrap();
        let recipients: Vec<_> = message
            .envelope()
            .to()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            recipients,
            [
                "one@example.com",
                "two@example.com",
                "three@example.com",
                "four@example.com",
                "five@example.com",
                "six@example.com",
            ]
        );

        let wire = String::from_utf8(message.formatted()).unwrap();
        let (headers, _) = wire.split_once("\r\n\r\n").unwrap();
        assert!(
            headers.contains("To: one@example.com, two@example.com"),
            "{headers}"
        );
        assert!(
            headers.contains("Cc: three@example.com, four@example.com"),
            "{headers}"
        );
        assert!(!headers.to_ascii_lowercase().contains("bcc:"), "{headers}");
        for address in ["five@example.com", "six@example.com"] {
            assert!(!headers.contains(address), "{headers}");
        }
    }

    #[test]
    fn recipient_arguments_are_declared_on_the_sink_contract() {
        let description = send(EmailConfig::default(), FakeMail::ok()).describe();
        let sink = description
            .actions
            .iter()
            .find(|action| action.verb == Verb::Sink)
            .unwrap();
        for (name, required) in [("to", true), ("cc", false), ("bcc", false)] {
            let input = sink.inputs.iter().find(|input| input.name == name).unwrap();
            assert_eq!(input.required, required);
            assert_eq!(input.class.as_deref(), Some(XSD_STRING));
            assert!(!input.summary.is_empty());
        }
    }

    #[test]
    fn copies_do_not_replace_the_required_to() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        let args = [
            ("cc", "copy@example.com"),
            ("bcc", "blind@example.com"),
            ("subject", "Hello"),
            ("content", "Body"),
        ];
        let err = block_on(k.issue(send_request(&args), &cap())).unwrap_err();
        assert!(
            matches!(err, Error::MissingArgument(ref name) if name == "to"),
            "{err:?}"
        );
        assert!(mail.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_refused_recipient_is_never_echoed() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        for field in ["to", "cc", "bcc"] {
            let list = "valid@example.com,visitor-secret";
            let mut args = [
                ("to", "owner@example.com"),
                ("cc", "copy@example.com"),
                ("bcc", "blind@example.com"),
                ("subject", "Hello"),
                ("content", "Body"),
            ];
            args.iter_mut().find(|(name, _)| *name == field).unwrap().1 = list;
            let err = block_on(k.issue(send_request(&args), &cap())).unwrap_err();
            let text = format!("{err} {err:?}");
            assert!(
                !text.contains("visitor-secret"),
                "refused value leaked: {text}"
            );
            assert!(text.contains(&format!("`{field}` entry 2")), "{text}");
        }
        assert!(mail.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_bad_recipient_names_the_field_and_entry_without_delivering() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        for field in ["to", "cc", "bcc"] {
            for bad in ["not-an-address", ".leading-dot@example.com", ""] {
                let list = format!("valid@example.com,{bad}");
                let mut args = [
                    ("to", "owner@example.com"),
                    ("cc", "copy@example.com"),
                    ("bcc", "blind@example.com"),
                    ("subject", "Hello"),
                    ("content", "Body"),
                ];
                args.iter_mut().find(|(name, _)| *name == field).unwrap().1 = &list;
                let err = block_on(k.issue(send_request(&args), &cap())).unwrap_err();
                assert!(
                    matches!(&err, Error::InvalidArgument { name, detail }
                        if name == field && detail.contains(&format!("`{field}` entry 2"))
                            && (bad.is_empty() || !detail.contains(bad))
                            && !detail.contains("valid@example.com")),
                    "{err:?}"
                );
            }
        }
        assert!(mail.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn line_breaks_in_copy_lists_are_refused_even_next_to_a_separator() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        for field in ["cc", "bcc"] {
            for (list, position) in [
                ("copy@example.com\rInjected: value", 1),
                ("copy@example.com,\nsecond@example.com", 2),
            ] {
                let err = block_on(k.issue(
                    send_request(&[
                        ("to", "owner@example.com"),
                        (field, list),
                        ("subject", "Hello"),
                        ("content", "Body"),
                    ]),
                    &cap(),
                ))
                .unwrap_err();
                assert!(
                    matches!(&err, Error::InvalidArgument { name, detail }
                        if name == field && detail.contains(&format!("`{field}` entry {position}"))
                            && !detail.contains("example.com")
                            && detail.contains("SMTP header injection")
                            && !detail.contains(['\r', '\n'])),
                    "{err:?}"
                );
            }
        }
        assert!(mail.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_send_refuses_unreadable_arguments_without_delivering() {
        let mail = FakeMail::ok();
        let endpoint = SendEndpoint {
            config: EmailConfig {
                host: "localhost".to_string(),
                port: 25,
                from: "site@example.com".to_string(),
            },
            transport: mail.clone(),
        };
        let base = send_request(&[
            ("to", "owner@example.com"),
            ("subject", "Hello"),
            ("content", "Body"),
        ]);
        let bindings = ikigai_core::Bindings::new();
        let cap = cap();
        let issue =
            |req: &Request| block_on(endpoint.invoke(&Invocation::detached(req, &bindings, &cap)));
        issue(&base).unwrap();
        let explicit = base
            .clone()
            .with_arg("reply_to", ArgRef::Inline(b"sender@example.com".to_vec()))
            .with_arg(
                "ics",
                ArgRef::Inline(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_vec()),
            );
        issue(&explicit).unwrap();
        {
            let sent = mail.sent.lock().unwrap();
            assert_eq!(sent[0].reply_to, None);
            assert_eq!(sent[0].ics, None);
            assert_eq!(sent[1].reply_to.as_deref(), Some("sender@example.com"));
            assert!(sent[1]
                .ics
                .as_deref()
                .unwrap()
                .starts_with("BEGIN:VCALENDAR"));
        }

        // An alias is a fallback for absence, not for a broken explicit body.
        let alias = send_request(&[
            ("to", "owner@example.com"),
            ("subject", "Hello"),
            ("in", "Via alias"),
        ]);
        issue(&alias).unwrap();
        assert_eq!(mail.sent.lock().unwrap()[2].body, "Via alias");
        for name in [
            "reply_to", "ics", "to", "cc", "bcc", "subject", "content", "in",
        ] {
            for (arg, reason) in [
                (ArgRef::Inline(vec![0xff]), "not valid UTF-8"),
                (
                    ArgRef::Reference(Iri::parse("urn:test:argument").unwrap()),
                    "expected an inline value",
                ),
                (
                    ArgRef::Content(ikigai_core::ContentId::of(b"body")),
                    "expected an inline value",
                ),
            ] {
                let request = alias.clone().with_arg(name, arg);
                let err = issue(&request).expect_err(name);
                assert!(
                    matches!(&err, Error::InvalidArgument { name: actual, detail }
                        if actual == name && detail.contains(reason)),
                    "{err:?}"
                );
            }
        }
        assert_eq!(mail.sent.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_send_with_no_configured_sender_is_refused() {
        // An unset `from` must fail loudly and actionably, not silently ship a placeholder
        // sender that a sender-aligned relay rejects (the bug this guards against).
        let config = EmailConfig {
            host: "localhost".to_string(),
            port: 25,
            from: "   ".to_string(),
        };
        let mail = FakeMail::ok();
        #[allow(clippy::disallowed_methods)]
        // internal: a test fixture's kernel; it routes no user arguments
        let k = Kernel::new(Arc::new(space(config, mail.clone())));
        let err = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "x"),
                ("content", "y"),
            ]),
            &cap(),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::Endpoint(_)), "{err:?}");
        assert!(err.to_string().contains("mail.from"), "actionable: {err}");
        assert!(
            mail.sent.lock().unwrap().is_empty(),
            "refused before the transport"
        );
    }

    #[test]
    fn header_injection_is_rejected_before_the_transport() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        // A newline in the subject would end the header and smuggle a Bcc — the way a
        // public contact form becomes an open relay.
        let err = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "Hi\nBcc: victim@example.com"),
                ("content", "body"),
            ]),
            &cap(),
        ))
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument { ref name, .. } if name == "subject"),
            "got: {err:?}"
        );
        // Same for the recipient itself.
        let err = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com\nBcc: victim@example.com"),
                ("subject", "Hi"),
                ("content", "body"),
            ]),
            &cap(),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument { .. }), "got: {err:?}");
        assert!(
            mail.sent.lock().unwrap().is_empty(),
            "nothing reaches the transport"
        );
    }

    #[test]
    fn junk_addresses_are_a_typed_invalid_argument() {
        let k = kernel(FakeMail::ok());
        for bad in ["not-an-address", "a@b", "@example.com", "a b@example.com"] {
            let err = block_on(k.issue(
                send_request(&[("to", bad), ("subject", "Hi"), ("content", "b")]),
                &cap(),
            ))
            .unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument { ref name, .. } if name == "to"),
                "`{bad}` should be rejected, got: {err:?}"
            );
        }
    }

    /// Recipients must be bare addresses and Reply-To must be a single bare address. A
    /// display name, angle brackets, a group or a list reached lettre before, which turned `Your Bank<a@x.example>` into
    /// `Reply-To: Your Bank <a@x.example>`: text a form's submitter chose, in a header.
    #[test]
    fn each_recipient_and_reply_to_must_be_a_bare_address() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        for bad in [
            "Your Bank<a@x.example>",
            "Bank<a@x.example>",
            "<a@x.example>",
            "a,b@x.example",
            "g:a@x.example;",
            "a(c)@x.example",
            "\"a\"@x.example",
            "a@[192.0.2.1]",
        ] {
            for field in ["to", "reply_to"] {
                let mut args = vec![
                    ("to", "owner@example.com"),
                    ("subject", "Hi"),
                    ("content", "b"),
                ];
                args.retain(|(n, _)| *n != field);
                args.push((field, bad));
                let err = block_on(k.issue(send_request(&args), &cap())).unwrap_err();
                assert!(
                    matches!(err, Error::InvalidArgument { ref name, .. } if name == field),
                    "`{bad}` in `{field}` should be refused, got: {err:?}"
                );
            }
        }
        assert!(mail.sent.lock().unwrap().is_empty());
        // Ordinary atext still passes.
        block_on(k.issue(
            send_request(&[
                ("to", "o'brien+tag@mail.example.com"),
                ("subject", "Hi"),
                ("content", "b"),
            ]),
            &cap(),
        ))
        .unwrap();
        assert_eq!(mail.sent.lock().unwrap().len(), 1);
    }

    /// A Reply-To refusal never echoes the value it refused. A contact form feeds `reply_to` from a
    /// stranger; when the send fails the reactor dead-letters the tuple and the error text
    /// becomes a plaintext `.err` note, so whatever they typed would be written in the clear.
    /// The sentence names the argument and the rule instead.
    #[test]
    fn a_refused_reply_to_is_never_echoed() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        let secret = "visitor-secret";
        for bad in [
            "visitor-secret",
            "visitor-secret@nodot",
            "Your Bank<visitor-secret@x.example>",
            "visitor-secret @x.example",
        ] {
            let field = "reply_to";
            let err = block_on(k.issue(
                send_request(&[
                    ("to", "owner@example.com"),
                    ("subject", "Hi"),
                    ("content", "b"),
                    (field, bad),
                ]),
                &cap(),
            ))
            .unwrap_err();
            let Error::InvalidArgument {
                ref name,
                ref detail,
            } = err
            else {
                panic!("`{field}` should be an invalid argument, got: {err:?}");
            };
            assert_eq!(name, field);
            let text = format!("{err} {detail} {err:?}");
            assert!(
                !text.contains(secret),
                "the refused value is echoed: {text}"
            );
            assert_eq!(
                detail,
                &format!(
                    "`{field}` is not an email address: it needs one @ with a name before \
                     it and a domain with a dot after it, and no spaces or any of \
                     < > ( ) [ ] : ; , \" \\"
                )
            );
        }
        assert!(mail.sent.lock().unwrap().is_empty());
    }

    /// The transport's own refusals of an address name the header, not the value.
    #[test]
    fn a_transport_refusal_of_an_address_is_never_echoed() {
        let message = Outgoing {
            from: "site@example.com".to_string(),
            to: vec!["visitor-secret".to_string()],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: Some("visitor-secret".to_string()),
            subject: "Hi".to_string(),
            body: "b".to_string(),
            ics: None,
            attachments: Vec::new(),
        };
        let Err(MailError::Permanent(detail)) = build_message(&message) else {
            panic!("a bare word is not an address");
        };
        assert!(!detail.contains("visitor-secret"), "To echoed: {detail}");
        let message = Outgoing {
            to: vec!["owner@example.com".to_string()],
            ..message
        };
        let Err(MailError::Permanent(detail)) = build_message(&message) else {
            panic!("a bare word is not an address");
        };
        assert!(
            !detail.contains("visitor-secret"),
            "Reply-To echoed: {detail}"
        );
        let message = Outgoing {
            from: "visitor-secret".to_string(),
            reply_to: None,
            ..message
        };
        let Err(MailError::Permanent(detail)) = build_message(&message) else {
            panic!("a bare word is not an address");
        };
        assert!(!detail.contains("visitor-secret"), "From echoed: {detail}");
    }

    #[test]
    fn a_refused_submission_is_transient_so_retry_can_engage() {
        let mail = Arc::new(FakeMail {
            sent: Mutex::new(Vec::new()),
            outcome: Some(MailError::Transient("connection refused".to_string())),
        });
        let k = kernel(mail);
        let err = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "Hi"),
                ("content", "b"),
            ]),
            &cap(),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "got: {err:?}");
        assert!(
            err.is_transient(),
            "a refused submission must be retryable — that is what lets the overlays work"
        );
        // A 5xx rejection is permanent and must NOT be retried.
        let permanent = Arc::new(FakeMail {
            sent: Mutex::new(Vec::new()),
            outcome: Some(MailError::Permanent("550 no such user".to_string())),
        });
        let err = block_on(kernel(permanent).issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "Hi"),
                ("content", "b"),
            ]),
            &cap(),
        ))
        .unwrap_err();
        assert!(!err.is_transient(), "a 5xx is permanent: {err:?}");
    }

    #[test]
    fn sending_is_capability_gated() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        let err = block_on(k.issue(
            send_request(&[
                ("to", "owner@example.com"),
                ("subject", "Hi"),
                ("content", "b"),
            ]),
            &Capability::scoped(Vec::<String>::new()),
        ))
        .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "got: {err:?}");
        assert!(mail.sent.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod ics_tests {
    use super::*;

    fn msg(ics: Option<&str>) -> Outgoing {
        Outgoing {
            from: "owner@example.com".to_string(),
            to: vec!["nigel@ukclient.example".to_string()],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: None,
            subject: "Your meeting is confirmed".to_string(),
            body: "We're on for tomorrow.".to_string(),
            ics: ics.map(str::to_string),
            attachments: Vec::new(),
        }
    }

    const INVITE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\n\
                          UID:abc@example.com\r\nSUMMARY:Call with Ada Lovelace\r\n\
                          END:VEVENT\r\nEND:VCALENDAR\r\n";

    /// A wire-bytes rendering of the built message, for structural assertions.
    fn wire(m: &Outgoing) -> String {
        String::from_utf8(build_message(m).unwrap().formatted()).unwrap()
    }

    #[test]
    fn a_plain_message_has_no_calendar_part() {
        let w = wire(&msg(None));
        assert!(w.contains("We're on for tomorrow."), "body present");
        assert!(
            !w.contains("text/calendar"),
            "no invite when none was given: {w}"
        );
    }

    #[test]
    fn an_invite_is_an_imip_alternative_with_the_calendar() {
        let w = wire(&msg(Some(INVITE)));
        // The interactive-invite signal: a text/calendar part carrying method=REQUEST.
        assert!(w.contains("multipart/alternative"), "{w}");
        assert!(w.to_lowercase().contains("text/calendar"), "{w}");
        assert!(w.to_lowercase().contains("method=request"), "{w}");
        // The plain body survives as the fallback alternative.
        assert!(w.contains("We're on for tomorrow."), "{w}");
        // And the invite itself is in there.
        assert!(w.contains("SUMMARY:Call with Ada Lovelace"), "{w}");
    }

    #[test]
    fn the_endpoint_carries_an_ics_arg_through() {
        use futures::executor::block_on;
        use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};
        // Reach the transport through the endpoint, and check the recorded Outgoing.
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Outgoing>::new()));
        struct Rec(std::sync::Arc<std::sync::Mutex<Vec<Outgoing>>>);
        impl MailTransport for Rec {
            fn deliver(&self, m: &Outgoing) -> std::result::Result<String, MailError> {
                self.0.lock().unwrap().push(m.clone());
                Ok("250".into())
            }
        }
        #[allow(clippy::disallowed_methods)]
        // internal: a test fixture's kernel; it routes no user arguments
        let kernel = Kernel::new(std::sync::Arc::new(space(
            EmailConfig::default(),
            std::sync::Arc::new(Rec(sent.clone())),
        )));
        block_on(
            kernel.issue(
                Request::new(Verb::Sink, Iri::parse("urn:email:send").unwrap())
                    .with_arg("to", ArgRef::Inline(b"nigel@ukclient.example".to_vec()))
                    .with_arg("subject", ArgRef::Inline(b"Confirmed".to_vec()))
                    .with_arg("content", ArgRef::Inline(b"body".to_vec()))
                    .with_arg("ics", ArgRef::Inline(INVITE.as_bytes().to_vec())),
                &Capability::scoped([CAP_SEND]),
            ),
        )
        .unwrap();
        let got = sent.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert!(
            got[0].ics.as_deref().unwrap().contains("METHOD:REQUEST"),
            "ics threaded through"
        );
    }
}

/// Attachments, through the [`MailTransport`] seam: named by resource, read under the
/// caller's capability, bounded, and refused when they hold a secret key.
#[cfg(test)]
mod attach_tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, FnEndpoint, Kernel, Request};
    use std::sync::Mutex;

    /// Who may read `urn:test:private`: a scope the default test caller does not hold.
    const CAP_PRIVATE: &str = "urn:cap:test:private";
    const CERT: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n";
    const BADGE: &[u8] = br#"{"@context":["https://www.w3.org/ns/credentials/v2","https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],"type":["VerifiableCredential","OpenBadgeCredential"],"credentialSubject":{"achievement":{"name":"Rust I"}}}"#;
    /// Not text: a NUL, high bytes and a bare CR, so "byte for byte" means something.
    const PDF: &[u8] = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\x00\xff\xfe\r<< >>\nendobj\n%%EOF\n";

    #[derive(Default)]
    struct Rec(Mutex<Vec<Outgoing>>);
    impl MailTransport for Rec {
        fn deliver(&self, message: &Outgoing) -> std::result::Result<String, MailError> {
            self.0.lock().unwrap().push(message.clone());
            Ok("250".to_string())
        }
    }

    fn fixed(media: &'static str, bytes: Vec<u8>) -> FnEndpoint {
        FnEndpoint::new("fixture", move |_| {
            Ok(Representation::new(ReprType::new(media), bytes.clone()))
        })
    }

    #[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
    fn kernel(mail: Arc<Rec>, extra: &[(&'static str, &'static str, Vec<u8>)]) -> Kernel {
        let config = EmailConfig {
            from: "site@example.com".to_string(),
            ..EmailConfig::default()
        };
        let mut space = space(config, mail)
            .bind(
                Exact::new("urn:test:server.crt"),
                fixed("application/x-pem-file", CERT.to_vec()),
            )
            .bind(
                Exact::new("urn:test:credentials/rust-1"),
                fixed("application/ld+json", BADGE.to_vec()),
            )
            .bind(
                Exact::new("urn:test:certificate.pdf"),
                fixed("application/pdf", PDF.to_vec()),
            )
            .bind(
                Exact::new("urn:test:private"),
                FnEndpoint::new("private", |inv| {
                    if !inv.capability.allows(CAP_PRIVATE) {
                        return Err(Error::Denied(
                            format!("reading this requires `{CAP_PRIVATE}`").into(),
                        ));
                    }
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"private".to_vec(),
                    ))
                }),
            );
        for (iri, media, bytes) in extra {
            space = space.bind(Exact::new(*iri), fixed(media, bytes.clone()));
        }
        Kernel::new(Arc::new(space))
    }

    fn caller() -> Capability {
        Capability::scoped([CAP_SEND, CAP_ATTACH])
    }

    fn request(extra: &[(&str, &str)]) -> Request {
        let mut request = Request::new(Verb::Sink, Iri::parse("urn:email:send").unwrap())
            .with_arg("to", ArgRef::Inline(b"learner@example.com".to_vec()))
            .with_arg("subject", ArgRef::Inline(b"What you earned".to_vec()))
            .with_arg("content", ArgRef::Inline(b"Attached.".to_vec()));
        for (name, value) in extra {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        request
    }

    fn send(k: &Kernel, extra: &[(&str, &str)], cap: &Capability) -> Result<Representation> {
        block_on(k.issue(request(extra), cap))
    }

    /// The wire bytes, for a MIME reader that is not lettre (the `mailparse`
    /// dev-dependency) to check the structure and the decoded bytes independently.
    fn parsed(message: &Outgoing) -> Vec<u8> {
        build_message(message).unwrap().formatted()
    }

    fn refused(err: &Error, name: &str, needle: &str) -> bool {
        matches!(err, Error::InvalidArgument { name: n, detail } if n == name && detail.contains(needle))
    }

    #[test]
    fn one_attachment_is_named_by_its_resource_and_carried_as_mixed() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        send(&k, &[("attach", "urn:test:server.crt")], &caller()).unwrap();
        let sent = mail.0.lock().unwrap();
        assert_eq!(
            sent[0].attachments,
            [Attachment {
                filename: "server.crt".to_string(),
                media_type: "application/x-pem-file".to_string(),
                bytes: CERT.to_vec(),
            }]
        );
        let wire = parsed(&sent[0]);
        let mail = mailparse::parse_mail(&wire).unwrap();
        assert_eq!(mail.ctype.mimetype, "multipart/mixed");
        assert_eq!(mail.subparts.len(), 2);
        assert_eq!(mail.subparts[0].ctype.mimetype, "text/plain");
        assert_eq!(mail.subparts[0].get_body().unwrap().trim_end(), "Attached.");
        let part = &mail.subparts[1];
        assert_eq!(part.ctype.mimetype, "application/x-pem-file");
        let disposition = part.get_content_disposition();
        assert_eq!(
            disposition.disposition,
            mailparse::DispositionType::Attachment
        );
        assert_eq!(
            disposition.params.get("filename").map(String::as_str),
            Some("server.crt")
        );
        assert_eq!(part.get_body_raw().unwrap(), CERT);
    }

    /// The learn use: a credential (Open Badges 3.0, JSON-LD) and a certificate PDF, each
    /// carried byte for byte with its own media type, and `attach_name` naming them.
    #[test]
    fn two_attachments_a_credential_and_a_pdf_are_carried_byte_for_byte() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        send(
            &k,
            &[
                (
                    "attach",
                    "urn:test:credentials/rust-1\n\n urn:test:certificate.pdf \n",
                ),
                ("attach_name", "rust-1.jsonld\nRust I certificate.pdf"),
            ],
            &caller(),
        )
        .unwrap();
        let sent = mail.0.lock().unwrap();
        let wire = parsed(&sent[0]);
        let mail = mailparse::parse_mail(&wire).unwrap();
        assert_eq!(mail.ctype.mimetype, "multipart/mixed");
        assert_eq!(mail.subparts.len(), 3);
        for (part, (media, name, bytes)) in mail.subparts[1..].iter().zip([
            ("application/ld+json", "rust-1.jsonld", BADGE),
            ("application/pdf", "Rust I certificate.pdf", PDF),
        ]) {
            assert_eq!(part.ctype.mimetype, media);
            assert_eq!(
                part.get_content_disposition()
                    .params
                    .get("filename")
                    .map(String::as_str),
                Some(name)
            );
            assert_eq!(part.get_body_raw().unwrap(), bytes, "{name}");
        }
    }

    #[test]
    fn with_ics_the_imip_alternative_is_kept_whole_before_the_attachment() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        let invite = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n";
        send(
            &k,
            &[("attach", "urn:test:certificate.pdf"), ("ics", invite)],
            &caller(),
        )
        .unwrap();
        let sent = mail.0.lock().unwrap();
        let wire = parsed(&sent[0]);
        let mail = mailparse::parse_mail(&wire).unwrap();
        assert_eq!(mail.ctype.mimetype, "multipart/mixed");
        assert_eq!(mail.subparts.len(), 2);
        let alternative = &mail.subparts[0];
        assert_eq!(alternative.ctype.mimetype, "multipart/alternative");
        assert_eq!(alternative.subparts[0].ctype.mimetype, "text/plain");
        assert_eq!(alternative.subparts[1].ctype.mimetype, "text/calendar");
        assert_eq!(
            alternative.subparts[1]
                .ctype
                .params
                .get("method")
                .map(String::as_str),
            Some("REQUEST")
        );
        assert_eq!(mail.subparts[1].ctype.mimetype, "application/pdf");
        assert_eq!(mail.subparts[1].get_body_raw().unwrap(), PDF);
    }

    /// The read runs under the CALLER's capability: what they cannot read, they cannot mail,
    /// and the refusal stops the whole send.
    #[test]
    fn a_denied_read_refuses_the_whole_send() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        let err = send(
            &k,
            &[("attach", "urn:test:server.crt\nurn:test:private")],
            &caller(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(mail.0.lock().unwrap().is_empty());
        // The same caller holding the read scope sends it.
        let reader = Capability::scoped([CAP_SEND, CAP_ATTACH, CAP_PRIVATE]);
        send(&k, &[("attach", "urn:test:private")], &reader).unwrap();
        assert_eq!(mail.0.lock().unwrap().len(), 1);
    }

    /// Sending alone is not attaching: a holder of `urn:cap:email:send` only (a contact
    /// form's handler) is refused before anything is read.
    #[test]
    fn attaching_needs_its_own_capability() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        let send_only = Capability::scoped([CAP_SEND, CAP_PRIVATE]);
        let err = send(&k, &[("attach", "urn:test:server.crt")], &send_only).unwrap_err();
        assert!(
            matches!(&err, Error::Denied(_)) && err.to_string().contains(CAP_ATTACH),
            "{err:?}"
        );
        assert!(mail.0.lock().unwrap().is_empty());
        // Without `attach` the same caller still sends a plain message.
        send(&k, &[], &send_only).unwrap();
        assert!(mail.0.lock().unwrap()[0].attachments.is_empty());
    }

    #[test]
    fn more_than_the_count_cap_is_refused_naming_the_limit() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        let at_cap = ["urn:test:server.crt"; MAX_ATTACHMENTS].join("\n");
        send(&k, &[("attach", &at_cap)], &caller()).unwrap();
        assert_eq!(mail.0.lock().unwrap()[0].attachments.len(), MAX_ATTACHMENTS);
        let over = ["urn:test:server.crt"; MAX_ATTACHMENTS + 1].join("\n");
        let err = send(&k, &[("attach", &over)], &caller()).unwrap_err();
        assert!(refused(&err, "attach", "at most 10 attachments"), "{err:?}");
        assert_eq!(mail.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn more_than_the_size_cap_is_refused_naming_the_limit() {
        let mail = Arc::new(Rec::default());
        let half = MAX_ATTACHMENT_BYTES / 2;
        let k = kernel(
            mail.clone(),
            &[
                (
                    "urn:test:half",
                    "application/octet-stream",
                    vec![b'a'; half],
                ),
                ("urn:test:one", "application/octet-stream", vec![b'b'; 1]),
            ],
        );
        // Exactly the cap passes…
        send(&k, &[("attach", "urn:test:half\nurn:test:half")], &caller()).unwrap();
        // …one byte more is refused, not truncated.
        let err = send(
            &k,
            &[("attach", "urn:test:half\nurn:test:half\nurn:test:one")],
            &caller(),
        )
        .unwrap_err();
        assert!(
            refused(&err, "attach", "10485760 bytes (10 MiB)"),
            "{err:?}"
        );
        assert_eq!(mail.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_private_key_or_age_secret_key_is_refused_with_the_reason() {
        let keys: [&[u8]; 7] = [
            b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
            b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nMIIE\n-----END RSA PRIVATE KEY-----\n",
            b"-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----\n",
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n-----END ENCRYPTED PRIVATE KEY-----\n",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\n",
            // A bundle: a certificate first does not hide the key after it.
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
            b"# created: 2026-11-27\n# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\nAGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS\n",
        ];
        let mail = Arc::new(Rec::default());
        let extra: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let iri: &'static str = Box::leak(format!("urn:test:key{i}").into_boxed_str());
                (iri, "application/octet-stream", key.to_vec())
            })
            .collect();
        let k = kernel(mail.clone(), &extra);
        for (i, _) in keys.iter().enumerate() {
            let iri = format!("urn:test:server.crt\nurn:test:key{i}");
            let err = send(&k, &[("attach", &iri)], &caller()).unwrap_err();
            let kind = if i == 6 {
                "an age secret key"
            } else {
                "a PEM private key block"
            };
            assert!(
                refused(
                    &err,
                    "attach",
                    &format!("attachment 2 holds {kind}, and secret keys are never mailed")
                ),
                "key {i}: {err:?}"
            );
        }
        assert!(mail.0.lock().unwrap().is_empty());
        // A public certificate alone is not a key.
        send(&k, &[("attach", "urn:test:server.crt")], &caller()).unwrap();
    }

    /// A filename is held to the envelope fields' header-injection rule, whether it comes
    /// from `attach_name` or from the IRI's last segment.
    #[test]
    fn a_filename_with_a_control_character_is_refused() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        // A bare CR stays inside one line of `attach_name` (a LF would start the next name).
        for name in [
            "cert\rBcc: victim@example.com",
            "cert\u{7}.crt",
            "cert\t.crt",
        ] {
            let err = send(
                &k,
                &[("attach", "urn:test:server.crt"), ("attach_name", name)],
                &caller(),
            )
            .unwrap_err();
            assert!(
                refused(&err, "attach_name", "SMTP header injection"),
                "{name:?}: {err:?}"
            );
        }
        // The default name is the IRI's last segment, without its query or fragment.
        assert_eq!(
            default_filename("urn:file:/a/b/server.crt?x=1#y"),
            "server.crt"
        );
        assert_eq!(default_filename("urn:test:credentials/rust-1"), "rust-1");
        assert!(mail.0.lock().unwrap().is_empty());
    }

    #[test]
    fn malformed_attach_arguments_are_refused_before_any_read() {
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        for (args, name, needle) in [
            (
                vec![("attach", " \n ")],
                "attach",
                "at least one resource IRI",
            ),
            (
                vec![("attach", "not an iri")],
                "attach",
                "entry 1 is not a resource IRI",
            ),
            (
                vec![("attach_name", "orphan.pdf")],
                "attach_name",
                "it needs `attach`",
            ),
            (
                vec![
                    ("attach", "urn:test:server.crt\nurn:test:certificate.pdf"),
                    ("attach_name", "only-one.crt"),
                ],
                "attach_name",
                "1 names for 2 attachments",
            ),
            (
                vec![("attach", "urn:test:dir/")],
                "attach",
                "must not be empty",
            ),
        ] {
            let err = send(&k, &args, &caller()).unwrap_err();
            assert!(refused(&err, name, needle), "{args:?}: {err:?}");
        }
        assert!(mail.0.lock().unwrap().is_empty());
    }

    #[test]
    fn attach_arguments_are_declared_on_the_sink_contract() {
        let description = send_endpoint().describe();
        let sink = description
            .actions
            .iter()
            .find(|action| action.verb == Verb::Sink)
            .unwrap();
        for (name, class) in [("attach", XSD_ANY_URI), ("attach_name", XSD_STRING)] {
            let input = sink.inputs.iter().find(|input| input.name == name).unwrap();
            assert!(!input.required, "{name} is optional");
            assert_eq!(input.class.as_deref(), Some(class));
            assert!(!input.summary.is_empty());
        }
        let attach = sink.inputs.iter().find(|i| i.name == "attach").unwrap();
        assert!(attach.summary.contains("credential"), "{}", attach.summary);
        assert!(description.summary.contains("Open Badges credential"));
        // Attaching is not a verb-level requirement: a plain send needs only `email:send`.
        assert_eq!(sink.requires, [CAP_SEND]);
    }

    /// `attach` and `attach_name` are newline lists: `attach=a attach=b` is one call whose
    /// `attach` holds both IRIs, the class applies to each item, and `attach_name` needs
    /// `attach` on the contract too.
    #[test]
    fn attach_is_a_newline_list_and_attach_name_needs_it() {
        use ikigai_core::ProposedArgs;
        let description = send_endpoint().describe();
        let sink = description
            .actions
            .iter()
            .find(|action| action.verb == Verb::Sink)
            .unwrap();
        for name in ["attach", "attach_name"] {
            let input = sink.inputs.iter().find(|i| i.name == name).unwrap();
            assert_eq!(input.list, Some(ListSeparator::Newline), "{name}");
        }
        let name = sink
            .inputs
            .iter()
            .find(|i| i.name == "attach_name")
            .unwrap();
        assert_eq!(name.needs, ["attach"]);

        let base = ProposedArgs::new()
            .with("to", "learner@example.com")
            .with("subject", "What you earned")
            .with("content", "Attached.");
        let repeated = base
            .clone()
            .with("attach", "urn:test:credentials/rust-1")
            .with("attach", "urn:test:certificate.pdf")
            .with("attach_name", "rust-1.jsonld")
            .with("attach_name", "certificate.pdf");
        assert!(
            sink.check(&repeated).is_empty(),
            "{:?}",
            sink.check(&repeated)
        );
        let joined = sink.join_repeats(&repeated).unwrap();
        assert_eq!(
            joined.get("attach"),
            Some("urn:test:credentials/rust-1\nurn:test:certificate.pdf")
        );
        assert!(!sink
            .check(&base.with("attach_name", "orphan.pdf"))
            .is_empty());

        // The joined call sends both, in order, with their names.
        let mail = Arc::new(Rec::default());
        let k = kernel(mail.clone(), &[]);
        let args: Vec<(&str, &str)> = ["attach", "attach_name"]
            .into_iter()
            .map(|name| (name, joined.get(name).unwrap()))
            .collect();
        send(&k, &args, &caller()).unwrap();
        let sent = mail.0.lock().unwrap();
        let names: Vec<&str> = sent[0]
            .attachments
            .iter()
            .map(|a| a.filename.as_str())
            .collect();
        assert_eq!(names, ["rust-1.jsonld", "certificate.pdf"]);
    }

    /// The size cap holds the RUNNING total as each resource is read: a stream past what is
    /// left is refused at the first chunk over it, never read whole, and a body whose
    /// declared length is already over is refused without being opened.
    #[test]
    fn the_size_cap_refuses_as_it_reads_not_after() {
        use ikigai_core::{Body, ByteStream, Bytes, Replay};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        const CHUNK: usize = 1024 * 1024;
        /// 64 MiB in 1 MiB chunks, counting each chunk handed out.
        struct Endless(Arc<AtomicUsize>);
        #[async_trait]
        impl Endpoint for Endless {
            async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
                unreachable!("an attachment is read as a body")
            }
            async fn invoke_body(&self, _inv: &Invocation<'_>) -> Result<Representation<Body>> {
                let pulled = self.0.clone();
                let chunks = futures::stream::iter(0..64).map(move |_| {
                    pulled.fetch_add(1, Ordering::SeqCst);
                    Ok(Bytes::from(vec![b'a'; CHUNK]))
                });
                Ok(Representation::from_body(
                    ReprType::new("application/octet-stream"),
                    Body::once(chunks),
                ))
            }
        }
        /// Declares 11 MiB; records whether it was ever opened.
        struct Declared(Arc<AtomicBool>);
        impl Replay for Declared {
            fn open(&self) -> ByteStream {
                self.0.store(true, Ordering::SeqCst);
                Box::pin(futures::stream::empty())
            }
            fn len_hint(&self) -> Option<u64> {
                Some((MAX_ATTACHMENT_BYTES + CHUNK) as u64)
            }
        }
        struct Big(Arc<AtomicBool>);
        #[async_trait]
        impl Endpoint for Big {
            async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
                unreachable!("an attachment is read as a body")
            }
            async fn invoke_body(&self, _inv: &Invocation<'_>) -> Result<Representation<Body>> {
                Ok(Representation::from_body(
                    ReprType::new("application/octet-stream"),
                    Body::replay(Declared(self.0.clone())),
                ))
            }
        }
        use futures::StreamExt as _;

        let mail = Arc::new(Rec::default());
        let pulled = Arc::new(AtomicUsize::new(0));
        let opened = Arc::new(AtomicBool::new(false));
        let config = EmailConfig {
            from: "site@example.com".to_string(),
            ..EmailConfig::default()
        };
        #[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel
        let k = Kernel::new(Arc::new(
            space(config, mail.clone())
                .bind(
                    Exact::new("urn:test:server.crt"),
                    fixed("application/x-pem-file", CERT.to_vec()),
                )
                .bind(Exact::new("urn:test:endless"), Endless(pulled.clone()))
                .bind(Exact::new("urn:test:big"), Big(opened.clone())),
        ));

        let err = send(&k, &[("attach", "urn:test:endless")], &caller()).unwrap_err();
        assert!(refused(&err, "attach", "10 MiB"), "{err:?}");
        let read = pulled.load(Ordering::SeqCst);
        assert!(
            read <= 11,
            "read {read} MiB of a 64 MiB stream before refusing"
        );

        // The running total counts what came before: after the certificate, less is left.
        pulled.store(0, Ordering::SeqCst);
        let err = send(
            &k,
            &[("attach", "urn:test:server.crt\nurn:test:endless")],
            &caller(),
        )
        .unwrap_err();
        assert!(refused(&err, "attach", "10 MiB"), "{err:?}");
        assert!(pulled.load(Ordering::SeqCst) <= 11);

        let err = send(&k, &[("attach", "urn:test:big")], &caller()).unwrap_err();
        assert!(refused(&err, "attach", "10 MiB"), "{err:?}");
        assert!(
            !opened.load(Ordering::SeqCst),
            "a declared length over the cap is never opened"
        );
        assert!(mail.0.lock().unwrap().is_empty());
    }

    fn send_endpoint() -> SendEndpoint {
        super::send(EmailConfig::default(), Arc::new(Rec::default()))
    }
}
