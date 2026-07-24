//! The people ledger — a durable roster of everyone who has reached out.
//!
//! The [decision log](crate::decisions) records everyone you *decided* on. But a booking
//! request that found no free slot, or that you never got to, and every contact enquiry —
//! those people's addresses were nowhere durable, so reaching back meant hunting through
//! mail. This captures each contact at INGESTION, before scheduling, so "who asked to reach
//! me" is a query rather than a search.
//!
//! One resource, `urn:people`, over the same append-only JSONL file the decision log uses:
//!
//! - `sink urn:people name= email= source= note=`  — record a contact (the handlers do this)
//! - `source urn:people`                            — the roster, one person per line, folded
//!   to one entry per address, most-recent contact first
//! - `source urn:people email=<addr>`               — every time that one address reached out
//!
//! A record is a small JSON object per line. Fields: `name`, `email` (the key), `source`
//! (`booking` / `contact` / whatever the caller passes), `note` (freeform — the client link
//! a booking came in on, an organisation, …), and `at` (when it was recorded).

use crate::file_root;
use crate::jsonl::{append, field, json_str, now_rfc3339, read_lines};
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, Error, Invocation, ReprType, Representation,
    Result, Verb,
};

/// Record a contact in the ledger.
pub const CAP_PEOPLE_WRITE: &str = "urn:cap:people:write";
/// Read the roster / look someone up.
pub const CAP_PEOPLE_READ: &str = "urn:cap:people:read";

/// The append-only ledger file.
pub fn ledger_path() -> std::path::PathBuf {
    file_root().join("people.jsonl")
}

/// The roster: one line per distinct address, most-recent contact first. Because [`read_lines`]
/// yields newest-first, the first record seen for an address is its most recent — so that is
/// the name and source shown.
fn roster(lines: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in lines {
        let Some(email) = field(line, "email") else {
            continue;
        };
        let key = email.trim().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        let name = field(line, "name").unwrap_or_default();
        let name = if name.trim().is_empty() {
            "(no name)".to_string()
        } else {
            name
        };
        let source = field(line, "source").unwrap_or_default();
        let at = field(line, "at").unwrap_or_default();
        out.push(format!("{name} <{}>  {source}  {at}", email.trim()));
    }
    out
}

/// Every record for one address (case-insensitive), most-recent first — the contact history
/// behind a single person.
fn history(lines: &[String], email: &str) -> Vec<String> {
    let needle = email.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    lines
        .iter()
        .filter(|l| {
            field(l, "email")
                .map(|e| e.trim().to_ascii_lowercase() == needle)
                .unwrap_or(false)
        })
        .map(|l| {
            format!(
                "{}  {}  {}",
                field(l, "at").unwrap_or_default(),
                field(l, "source").unwrap_or_default(),
                field(l, "note").unwrap_or_default(),
            )
        })
        .collect()
}

/// The `urn:people` endpoint. See the [module docs](crate::people).
pub struct PeopleLedger {
    /// The ledger file. Injected so the host owns the layout ([`ledger_path`]) and a test can
    /// point at its own — the process-global `IKIGAI_FILES` would race across parallel tests.
    pub path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl Endpoint for PeopleLedger {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        match inv.request.verb {
            // Record one contact.
            Verb::Sink => {
                if !inv.capability.allows(CAP_PEOPLE_WRITE) {
                    return Err(Error::Denied(format!(
                        "recording a contact requires `{CAP_PEOPLE_WRITE}`"
                    )));
                }
                let arg = |name: &str| inv.inline_str(name).unwrap_or("").trim().to_string();
                let email = arg("email");
                // The address is the whole point of the ledger — a record without one can
                // never be reached, so reject it rather than store a dead entry.
                if email.is_empty() {
                    return Err(Error::InvalidArgument {
                        name: "email".to_string(),
                        detail: "a contact needs an email address".to_string(),
                    });
                }
                let record = format!(
                    "{{\"name\":{},\"email\":{},\"source\":{},\"note\":{},\"at\":{}}}\n",
                    json_str(&arg("name")),
                    json_str(&email),
                    json_str(&arg("source")),
                    json_str(&arg("note")),
                    json_str(&now_rfc3339()),
                );
                append(&self.path, &record, "people")?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"recorded".to_vec(),
                ))
            }
            // Read the roster, or one person's history.
            Verb::Source => {
                if !inv.capability.allows(CAP_PEOPLE_READ) {
                    return Err(Error::Denied(format!(
                        "reading the people ledger requires `{CAP_PEOPLE_READ}`"
                    )));
                }
                let lines = read_lines(&self.path);
                // `email=<addr>` — one person's contact history.
                let body = if let Ok(email) = inv.inline_str("email") {
                    history(&lines, email).join("\n")
                } else {
                    // Otherwise the roster, folded to one entry per address.
                    roster(&lines).join("\n")
                };
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    body.into_bytes(),
                ))
            }
            other => Err(Error::Endpoint(format!(
                "people accepts Source (roster/lookup) or Sink (record), not {other:?}"
            ))),
        }
    }

    fn name(&self) -> &str {
        "people"
    }

    fn describe(&self) -> Description {
        Description::new("people")
            .title("People ledger")
            .summary(
                "A durable roster of everyone who has reached out — captured at ingestion, so a \
                 request that found no slot or was never decided still leaves a way to reach the \
                 person. Read it whole for the roster (one entry per address, newest first), or \
                 pass `email=<addr>` for that one person's contact history.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("read the roster, or one person's history")
                    .requires(CAP_PEOPLE_READ)
                    .input(
                        ArgSpec::new("email")
                            .optional()
                            .summary("an address — its full contact history"),
                    ),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("record a contact")
                    .requires(CAP_PEOPLE_WRITE)
                    .input(ArgSpec::new("email").summary("the address — the ledger key"))
                    .input(ArgSpec::new("name").optional().summary("who they are"))
                    .input(
                        ArgSpec::new("source")
                            .optional()
                            .summary("where they came from — booking, contact, …"),
                    )
                    .input(
                        ArgSpec::new("note")
                            .optional()
                            .summary("freeform — the client link, an organisation, …"),
                    ),
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
        let dir = std::env::temp_dir().join(format!("ikigai-people-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Kernel::new(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:people"),
            PeopleLedger {
                path: dir.join("people.jsonl"),
            },
        )))
    }

    fn record(k: &Kernel, name: &str, email: &str, source: &str, note: &str) -> Result<()> {
        block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:people").unwrap())
                    .with_arg("name", ArgRef::Inline(name.into()))
                    .with_arg("email", ArgRef::Inline(email.into()))
                    .with_arg("source", ArgRef::Inline(source.into()))
                    .with_arg("note", ArgRef::Inline(note.into())),
                &Capability::scoped([CAP_PEOPLE_WRITE]),
            ),
        )
        .map(|_| ())
    }

    fn read(k: &Kernel, email: Option<&str>) -> String {
        let mut req = Request::new(Verb::Source, Iri::parse("urn:people").unwrap());
        if let Some(e) = email {
            req = req.with_arg("email", ArgRef::Inline(e.into()));
        }
        let rep = block_on(k.issue(req, &Capability::scoped([CAP_PEOPLE_READ]))).unwrap();
        String::from_utf8(rep.bytes.clone()).unwrap()
    }

    #[test]
    fn the_roster_has_one_entry_per_address_newest_first() {
        let k = kernel("roster");
        record(&k, "Ada", "ada@x.example", "booking", "via nigel").unwrap();
        record(&k, "Bo", "bo@x.example", "contact", "Acme Ltd").unwrap();
        let out = read(&k, None);
        // Newest first, and both people present.
        assert!(
            out.lines().next().unwrap().contains("bo@x.example"),
            "{out}"
        );
        assert!(out.contains("Ada <ada@x.example>"), "{out}");
        assert_eq!(out.lines().count(), 2, "{out}");
    }

    #[test]
    fn a_repeat_contact_folds_to_the_most_recent_entry() {
        let k = kernel("fold");
        record(&k, "Ada", "ada@x.example", "contact", "first").unwrap();
        record(&k, "Ada Lovelace", "ADA@x.example", "booking", "second").unwrap();
        // One roster line — case-insensitive on the address — showing the LATEST name/source.
        let roster = read(&k, None);
        assert_eq!(roster.lines().count(), 1, "{roster}");
        assert!(roster.contains("Ada Lovelace"), "latest name: {roster}");
        assert!(roster.contains("booking"), "latest source: {roster}");
        // …but the history keeps both contacts.
        let history = read(&k, Some("ada@x.example"));
        assert_eq!(history.lines().count(), 2, "{history}");
    }

    #[test]
    fn a_lookup_is_case_insensitive_on_the_address() {
        let k = kernel("lookup");
        record(&k, "Ada", "Ada@X.Example", "booking", "note").unwrap();
        assert!(read(&k, Some("ada@x.example")).contains("booking"));
        assert!(read(&k, Some("ADA@X.EXAMPLE")).contains("booking"));
        assert_eq!(read(&k, Some("someone@else.example")).trim(), "");
    }

    #[test]
    fn a_contact_without_an_address_is_rejected() {
        let k = kernel("noemail");
        let err = record(&k, "Nameless", "", "booking", "note").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument { .. }), "{err:?}");
        // Nothing was written.
        assert_eq!(read(&k, None), "");
    }

    #[test]
    fn an_empty_ledger_is_empty_not_an_error() {
        let k = kernel("empty");
        assert_eq!(read(&k, None), "");
        assert_eq!(read(&k, Some("anyone@x.example")), "");
    }

    #[test]
    fn reading_and_writing_are_separately_gated() {
        let k = kernel("caps");
        // A read cap cannot record.
        let denied = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:people").unwrap())
                    .with_arg("email", ArgRef::Inline(b"x@y.example".to_vec())),
                &Capability::scoped([CAP_PEOPLE_READ]),
            ),
        )
        .unwrap_err();
        assert!(matches!(denied, Error::Denied(_)), "{denied:?}");
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_the_record_line() {
        let k = kernel("escape");
        // A name carrying a fake second field must not be read back as one.
        record(
            &k,
            r#"a" ,"source":"forged"#,
            "x@y.example",
            "booking",
            "note",
        )
        .unwrap();
        // Exactly one record, and its SOURCE column is the real `booking` — not the `forged`
        // one smuggled into the name. (The word "forged" does appear in the name column, which
        // is exactly why this checks the column after the address rather than the whole line.)
        let out = read(&k, None);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(
            out.contains("x@y.example>  booking  "),
            "the injected field did not become the source: {out}"
        );
    }
}
