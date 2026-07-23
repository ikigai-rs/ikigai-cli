//! `ikigai-email` — outbound email as a resource.
//!
//! `urn:email:send` is a **Sink**: sending is a side effect, so it takes the message body
//! as the piped `content` and the envelope as named arguments (`to`, `subject`, optional
//! `reply_to`). Gated by [`CAP_SEND`], because reaching the outside world on your behalf is
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
//!    contact form. A newline in `to`/`subject`/`reply_to` is classic SMTP header
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
    /// The envelope `From` — a mailbox the relay is authorised to send as.
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
    pub to: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body: String,
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

/// A minimal address shape check — one `@`, something either side, no spaces. Not RFC
/// 5322 (that way lies madness); the transport is the real authority. This exists to turn
/// obvious junk from a public form into a typed 400 instead of an SMTP round trip.
fn address_like(name: &str, value: &str) -> Result<String> {
    let value = header_safe(name, value)?;
    let mut parts = value.split('@');
    let ok = matches!((parts.next(), parts.next(), parts.next()), (Some(local), Some(domain), None)
        if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
        && !value.contains(' ');
    if !ok {
        return Err(Error::InvalidArgument {
            name: name.to_string(),
            detail: format!("`{value}` is not an email address"),
        });
    }
    Ok(value)
}

#[async_trait]
impl Endpoint for SendEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_SEND) {
            return Err(Error::Denied(format!("sending mail requires `{CAP_SEND}`")));
        }
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "urn:email:send is a Sink (sending is a side effect), not {:?}",
                inv.request.verb
            )));
        }

        let to = address_like("to", inv.inline_str("to").unwrap_or_default())?;
        let subject = header_safe("subject", inv.inline_str("subject").unwrap_or_default())?;
        let reply_to = match inv.inline_str("reply_to") {
            Ok(value) if !value.trim().is_empty() => Some(address_like("reply_to", value)?),
            _ => None,
        };
        // The body is the piped content (`content`, falling back to `in`) — a Sink's body.
        let body = inv
            .inline_str("content")
            .or_else(|_| inv.inline_str("in"))
            .map_err(|_| Error::MissingArgument("content".to_string()))?
            .to_string();

        let message = Outgoing {
            from: self.config.from.clone(),
            to,
            reply_to,
            subject,
            body,
        };
        match self.transport.deliver(&message) {
            Ok(receipt) => Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                format!("sent to {}: {receipt}\n", message.to).into_bytes(),
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
                "Submit a message over SMTP. The body is the piped content; `to` and \
                 `subject` are required, `reply_to` optional. Envelope fields are rejected \
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
                            .summary("the recipient address")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("subject")
                            .summary("the subject line")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("reply_to")
                            .optional()
                            .summary("an optional Reply-To (e.g. the enquirer's address)")
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

impl MailTransport for SmtpSubmission {
    fn deliver(&self, message: &Outgoing) -> std::result::Result<String, MailError> {
        use lettre::Transport as _;
        let mut builder =
            lettre::Message::builder()
                .from(message.from.parse().map_err(|e| {
                    MailError::Permanent(format!("bad From `{}`: {e}", message.from))
                })?)
                .to(message
                    .to
                    .parse()
                    .map_err(|e| MailError::Permanent(format!("bad To `{}`: {e}", message.to)))?)
                .subject(message.subject.clone());
        if let Some(reply_to) = &message.reply_to {
            builder = builder.reply_to(
                reply_to
                    .parse()
                    .map_err(|e| MailError::Permanent(format!("bad Reply-To: {e}")))?,
            );
        }
        let email = builder
            .body(message.body.clone())
            .map_err(|e| MailError::Permanent(format!("building the message: {e}")))?;

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

    fn kernel(transport: Arc<dyn MailTransport>) -> Kernel {
        let config = EmailConfig {
            host: "localhost".to_string(),
            port: 25,
            from: "site@bosatsu.net".to_string(),
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
                ("to", "brian@bosatsu.net"),
                ("subject", "Enquiry from bosatsu.net"),
                ("reply_to", "someone@example.com"),
                ("content", "Hello, I would like to talk."),
            ]),
            &cap(),
        ))
        .unwrap();
        assert!(String::from_utf8(rep.bytes)
            .unwrap()
            .contains("sent to brian@bosatsu.net"));
        let sent = mail.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].from, "site@bosatsu.net", "the configured From");
        assert_eq!(sent[0].reply_to.as_deref(), Some("someone@example.com"));
        assert_eq!(sent[0].body, "Hello, I would like to talk.");
    }

    #[test]
    fn header_injection_is_rejected_before_the_transport() {
        let mail = FakeMail::ok();
        let k = kernel(mail.clone());
        // A newline in the subject would end the header and smuggle a Bcc — the way a
        // public contact form becomes an open relay.
        let err = block_on(k.issue(
            send_request(&[
                ("to", "brian@bosatsu.net"),
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
                ("to", "brian@bosatsu.net\nBcc: victim@example.com"),
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

    #[test]
    fn a_refused_submission_is_transient_so_retry_can_engage() {
        let mail = Arc::new(FakeMail {
            sent: Mutex::new(Vec::new()),
            outcome: Some(MailError::Transient("connection refused".to_string())),
        });
        let k = kernel(mail);
        let err = block_on(k.issue(
            send_request(&[
                ("to", "brian@bosatsu.net"),
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
                ("to", "brian@bosatsu.net"),
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
                ("to", "brian@bosatsu.net"),
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
