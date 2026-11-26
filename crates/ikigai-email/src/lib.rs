//! `ikigai-email` — outbound email as a resource.
//!
//! `urn:email:send` is a **Sink**: sending is a side effect, so it takes the message body
//! as the piped `content` and named arguments (`to`, `subject`, optional `cc`, `bcc`, and
//! `reply_to`). Each recipient field takes one or more comma-separated bare email addresses,
//! ignoring surrounding whitespace. `to` is required and must not be empty. All recipients
//! are validated before delivery. A bad recipient refuses the whole send and the diagnostic
//! names the field and quotes only the offending entry, escaping control characters.
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
//! The transport is behind [`MailTransport`] — the same seam `ikigai-http` uses — so the
//! validation, envelope, and error mapping are testable without an SMTP server.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, ReprType,
    Representation, Result, Verb,
};
use std::sync::Arc;

/// Sending mail requires this capability.
pub const CAP_SEND: &str = "urn:cap:email:send";

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
            // Never the value: a public form fills `reply_to`, and a refusal's text can be
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

/// Check each recipient individually, naming the offending entry on refusal.
fn recipient_list(name: &str, value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .map(|entry| {
            let invalid = |reason| Error::InvalidArgument {
                name: name.to_string(),
                detail: format!("recipient {entry:?}: {reason}"),
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

        let message = Outgoing {
            from: self.config.from.clone(),
            to,
            cc,
            bcc,
            reply_to,
            subject,
            body,
            ics,
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
                 VCALENDAR makes it an iMIP calendar invitation. Envelope fields are rejected \
                 if they contain control characters (SMTP header injection). Submission \
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
    match &message.ics {
        None => builder
            .body(message.body.clone())
            .map_err(|e| MailError::Permanent(format!("building the message: {e}"))),
        Some(ics) => {
            use lettre::message::{header, MultiPart, SinglePart};
            // iMIP: the plain body and the invite as two alternatives of the same
            // message. A client that understands calendars shows the RSVP card; one that
            // does not falls back to the text. The `method=REQUEST` on the part is what
            // makes it an invitation rather than a mere event to file.
            let calendar =
                header::ContentType::parse("text/calendar; charset=utf-8; method=REQUEST")
                    .map_err(|e| MailError::Permanent(format!("calendar content-type: {e}")))?;
            let alternative = MultiPart::alternative()
                .singlepart(SinglePart::plain(message.body.clone()))
                .singlepart(SinglePart::builder().header(calendar).body(ics.clone()));
            builder
                .multipart(alternative)
                .map_err(|e| MailError::Permanent(format!("building the invite: {e}")))
        }
    }
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
                        if name == field && detail.contains(&format!("recipient {bad:?}"))
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
            for (list, entry) in [
                (
                    "copy@example.com\rInjected: value",
                    "copy@example.com\rInjected: value",
                ),
                (
                    "copy@example.com,\nsecond@example.com",
                    "\nsecond@example.com",
                ),
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
                        if name == field && detail.contains(&format!("recipient {entry:?}"))
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
