//! The decision log — and the blocklist that is a query over it.
//!
//! Every approve / decline / block is appended here, so there is a durable, readable record
//! of what was decided without hunting through the calendar. One resource, `urn:decisions`,
//! serves three things off the same append-only file:
//!
//! - `sink urn:decisions …`                — append a decision (the confirm program does this)
//! - `source urn:decisions`                — the whole log, newest first
//! - `source urn:decisions blocked=<email>`— "yes"/"no": is this address blocked?
//!   `source urn:decisions action=block`   — the blocked addresses, one per line
//!
//! The blocklist is not a second store to keep in sync: a block is just a decision whose
//! action is `block`, and "who is blocked" is a filter over the log. One source of truth.
//!
//! The record is a small JSON object per line (JSONL) — appendable without parsing the
//! whole file, and trivial to read back. Fields: `action`, `id`, `name`, `email`, `when`
//! (the meeting time, for the human record), and `at` (when the decision was made).

use crate::file_root;
use crate::jsonl::{field, json_str, now_rfc3339, read_lines};
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, Error, Invocation, ReprType, Representation,
    Result, Verb,
};

/// Append a decision to the log.
pub const CAP_DECISIONS_WRITE: &str = "urn:cap:decisions:write";
/// Read the log / query the blocklist.
pub const CAP_DECISIONS_READ: &str = "urn:cap:decisions:read";

/// The append-only log file.
pub fn log_path() -> std::path::PathBuf {
    file_root().join("decisions.jsonl")
}

/// Emails with a `block` decision — case-folded, deduplicated, most-recent first.
fn blocked_emails(lines: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in lines {
        if field(line, "action").as_deref() == Some("block") {
            if let Some(email) = field(line, "email") {
                let key = email.trim().to_ascii_lowercase();
                if !key.is_empty() && seen.insert(key) {
                    out.push(email.trim().to_string());
                }
            }
        }
    }
    out
}

/// Is `email` blocked, per the log at `path`? Case-insensitive, so a spammer varying the
/// case gains nothing.
fn is_blocked_at(path: &std::path::Path, email: &str) -> bool {
    let needle = email.trim().to_ascii_lowercase();
    !needle.is_empty()
        && blocked_emails(&read_lines(path))
            .iter()
            .any(|e| e.to_ascii_lowercase() == needle)
}

/// The `urn:decisions` endpoint. See the [module docs](crate::decisions).
pub struct DecisionLog {
    /// The log file. Injected so the host owns the layout (`log_path()`) and a test can
    /// point at its own — the process-global `IKIGAI_FILES` would race across parallel tests.
    pub path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for DecisionLog {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        match inv.request.verb {
            // Append one decision.
            Verb::Sink => {
                if !inv.capability.allows(CAP_DECISIONS_WRITE) {
                    return Err(Error::Denied(format!(
                        "recording a decision requires `{CAP_DECISIONS_WRITE}`"
                    )));
                }
                let arg = |name: &str| inv.inline_str(name).unwrap_or("").trim().to_string();
                let action = arg("action");
                if !matches!(action.as_str(), "approve" | "decline" | "block") {
                    return Err(Error::InvalidArgument {
                        name: "action".to_string(),
                        detail: format!("`{action}` is not approve, decline or block"),
                    });
                }
                let record = format!(
                    "{{\"action\":{},\"id\":{},\"name\":{},\"email\":{},\"when\":{},\"at\":{}}}\n",
                    json_str(&action),
                    json_str(&arg("id")),
                    json_str(&arg("name")),
                    json_str(&arg("email")),
                    json_str(&arg("when")),
                    json_str(&now_rfc3339()),
                );
                crate::jsonl::append(&self.path, &record, "decisions")?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"recorded".to_vec(),
                ))
            }
            // Read the log, or answer a query.
            Verb::Source => {
                if !inv.capability.allows(CAP_DECISIONS_READ) {
                    return Err(Error::Denied(format!(
                        "reading decisions requires `{CAP_DECISIONS_READ}`"
                    )));
                }
                let lines = read_lines(&self.path);

                // `blocked=<email>` — the membership check the booking handler makes.
                if let Ok(email) = inv.inline_str("blocked") {
                    let yes = is_blocked_at(&self.path, email);
                    return Ok(Representation::new(
                        ReprType::new("text/plain"),
                        if yes { b"yes".to_vec() } else { b"no".to_vec() },
                    ));
                }

                // `action=block` — the blocklist, one address per line.
                if inv
                    .inline_str("action")
                    .map(|a| a.trim() == "block")
                    .unwrap_or(false)
                {
                    let body = blocked_emails(&lines).join("\n");
                    return Ok(Representation::new(
                        ReprType::new("text/plain").with_param("charset", "utf-8"),
                        body.into_bytes(),
                    ));
                }

                // Otherwise the whole log, newest first, one readable line each.
                let body = lines
                    .iter()
                    .map(|l| {
                        format!(
                            "{}  {:8}  {} <{}>  {}",
                            field(l, "at").unwrap_or_default(),
                            field(l, "action").unwrap_or_default(),
                            field(l, "name").unwrap_or_default(),
                            field(l, "email").unwrap_or_default(),
                            field(l, "when").unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    body.into_bytes(),
                ))
            }
            other => Err(Error::Endpoint(format!(
                "decisions accepts Source (read/query) or Sink (append), not {other:?}"
            ))),
        }
    }

    fn name(&self) -> &str {
        "decisions"
    }

    fn describe(&self) -> Description {
        Description::new("decisions")
            .title("Decision log & blocklist")
            .summary(
                "An append-only record of every booking decision. Read it whole, or query \
                 `action=block` for the blocklist or `blocked=<email>` for a membership \
                 check. A block is just a decision — the blocklist is a filter, not a \
                 second store.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("read the log, or query the blocklist")
                    .requires(CAP_DECISIONS_READ)
                    .input(
                        ArgSpec::new("action")
                            .optional()
                            .summary("filter — `block` lists blocked addresses"),
                    )
                    .input(
                        ArgSpec::new("blocked")
                            .optional()
                            .summary("an email — answers yes/no"),
                    ),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("append a decision")
                    .requires(CAP_DECISIONS_WRITE)
                    .input(ArgSpec::new("action").summary("approve, decline or block"))
                    .input(ArgSpec::new("id").optional().summary("the booking id"))
                    .input(ArgSpec::new("name").optional().summary("the requester"))
                    .input(
                        ArgSpec::new("email")
                            .optional()
                            .summary("the requester's address"),
                    )
                    .input(ArgSpec::new("when").optional().summary("the meeting time")),
            )
            .output("text/plain; charset=utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Exact, Iri, Kernel, Request};
    use std::sync::Arc;

    fn kernel(name: &str) -> Kernel {
        let dir = std::env::temp_dir().join(format!("ikigai-decisions-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Kernel::new(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:decisions"),
            DecisionLog {
                path: dir.join("decisions.jsonl"),
            },
        )))
    }

    fn record(k: &Kernel, action: &str, name: &str, email: &str) {
        block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:decisions").unwrap())
                    .with_arg("action", ArgRef::Inline(action.into()))
                    .with_arg("id", ArgRef::Inline(b"abc123def456".to_vec()))
                    .with_arg("name", ArgRef::Inline(name.into()))
                    .with_arg("email", ArgRef::Inline(email.into()))
                    .with_arg("when", ArgRef::Inline(b"2026-07-24T10:00".to_vec())),
                &Capability::scoped([CAP_DECISIONS_WRITE]),
            ),
        )
        .unwrap();
    }

    fn read(k: &Kernel, arg: Option<(&str, &str)>) -> String {
        let mut req = Request::new(Verb::Source, Iri::parse("urn:decisions").unwrap());
        if let Some((key, val)) = arg {
            req = req.with_arg(key, ArgRef::Inline(val.into()));
        }
        let rep = block_on(k.issue(req, &Capability::scoped([CAP_DECISIONS_READ]))).unwrap();
        String::from_utf8(rep.bytes.clone()).unwrap()
    }

    #[test]
    fn the_log_records_every_decision_newest_first() {
        let k = kernel("log");
        record(&k, "approve", "Ada", "ada@x.example");
        record(&k, "decline", "Bo", "bo@x.example");
        let out = read(&k, None);
        // Newest first.
        assert!(out.lines().next().unwrap().contains("decline"), "{out}");
        assert!(out.contains("Ada <ada@x.example>"), "{out}");
        assert!(out.contains("approve") && out.contains("decline"), "{out}");
    }

    #[test]
    fn a_block_is_a_decision_and_shows_in_the_blocklist() {
        let k = kernel("block");
        record(&k, "approve", "Ada", "ada@x.example");
        record(&k, "block", "Spammer", "spam@x.example");
        // In the full log…
        assert!(read(&k, None).contains("block"));
        // …and surfaced by the blocklist filter, but the approved one is NOT.
        let list = read(&k, Some(("action", "block")));
        assert_eq!(list.trim(), "spam@x.example");
    }

    #[test]
    fn blocked_membership_is_case_insensitive() {
        let k = kernel("member");
        record(&k, "block", "Spammer", "Spam@X.Example");
        assert_eq!(read(&k, Some(("blocked", "spam@x.example"))), "yes");
        assert_eq!(read(&k, Some(("blocked", "SPAM@X.EXAMPLE"))), "yes");
        assert_eq!(read(&k, Some(("blocked", "someone@else.example"))), "no");
    }

    #[test]
    fn an_empty_log_is_empty_not_an_error() {
        let k = kernel("empty");
        assert_eq!(read(&k, None), "");
        assert_eq!(read(&k, Some(("action", "block"))), "");
        assert_eq!(read(&k, Some(("blocked", "anyone@x.example"))), "no");
    }

    #[test]
    fn reading_and_writing_are_separately_gated() {
        let k = kernel("caps");
        let denied = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:decisions").unwrap())
                    .with_arg("action", ArgRef::Inline(b"block".to_vec())),
                &Capability::scoped([CAP_DECISIONS_READ]), // read cap can't write
            ),
        )
        .unwrap_err();
        assert!(matches!(denied, Error::Denied(_)), "{denied:?}");
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_the_record_line() {
        let k = kernel("escape");
        record(&k, "block", r#"a" ,"action":"approve"#, "x@y.example");
        // The injected `"action":"approve"` must not be read as a second field: this is
        // still a block, and the blocklist still contains exactly the one address.
        assert_eq!(read(&k, Some(("action", "block"))).trim(), "x@y.example");
    }
}
