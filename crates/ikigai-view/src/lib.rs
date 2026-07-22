//! The consolidated-view (Brian-Busy) derivation, as a focused domain crate.
//!
//! This is the org⊕calendar reconciliation the CLI's P4 "Brian-Busy" plan grew:
//! materialize one **view calendar** whose contents are `desired = org agenda ∪
//! the allowlisted source calendars` over a rolling window, by diffing `desired`
//! against `current` (the view) and applying the delta — delete the gone/changed,
//! create the new/changed, identity carried as `urn:event:{uid}` so the pass is
//! idempotent.
//!
//! **Layering.** This crate links ONLY [`ikigai_core`] (plus `oxrdf`/`oxrdfio` for
//! Turtle parsing). It never links `ikigai-personal`, `ikigai-org`, or `ikigai-rdf`
//! — it composes them ENTIRELY THROUGH THE KERNEL via [`Invocation::issue`]
//! (`urn:personal:calendar` Source/Sink/Delete, `urn:org:agenda`, `urn:rdf:diff`,
//! `urn:view:ingest`). That is what makes it a thin composition crate correctly
//! layered *above* personal/org/rdf (it could not live in `ikigai-personal` — that
//! would invert the layering) and what makes the whole reconciliation testable
//! against an in-memory kernel whose personal/diff spaces are simple fakes.
//!
//! **Config is injected, not read from globals.** The host owns config loading
//! (calendar.json) and hands the resolved [`ViewConfig`] to the endpoints at bind
//! time. Nothing here touches the process environment or the filesystem, so the
//! endpoints are host-agnostic and hermetically testable.

use std::collections::{BTreeMap, BTreeSet};

use ikigai_core::{
    ArgRef, Description, Endpoint, Error, Invocation, Iri, ReprType, Representation, Request,
    Result, Verb,
};

/// The resolved configuration a derivation pass needs, injected by the host at
/// bind time (loaded from calendar.json). Keeping it a plain value — with no
/// dependency on `ikigai-personal`'s `CalendarConfig` — is what keeps this crate
/// off the personal/org layer and lets a test construct one directly.
#[derive(Clone, Debug, Default)]
pub struct ViewConfig {
    /// The consolidated view calendar — the Sink/Delete target the pass writes.
    pub view: String,
    /// The allowlisted source calendars unioned into the view.
    pub sources: Vec<String>,
    /// The phone-capture inbox calendar drained by ingest (`None` = no ingest).
    pub inbox: Option<String>,
    /// The org files as `urn:orgfile:…` IRIs; the first is the ingest append
    /// target, and a non-empty list is what makes derive fold in the org agenda.
    pub org_files: Vec<String>,
    /// Per-source detail projection (e.g. `"Bosatsu" -> "busy"`): the source's
    /// events render into the view as `Busy (<source>)` with location/alarms
    /// withheld. Absent source ⇒ pass-through.
    pub projections: BTreeMap<String, String>,
}

/// One event as the deriver applies it, lifted from the skolemized graph.
#[derive(Clone, Debug, PartialEq)]
struct ViewEvent {
    uid: String,
    title: String,
    start: String,
    end: String,
    all_day: bool,
    location: Option<String>,
    /// The notes body (ical:description) — a captured invite's full text, or
    /// (on org-sourced events) just the join link the :URL: drawer carries.
    description: Option<String>,
    /// The event's REAL URL (ical:url) — a Teams invite's join link as read
    /// from the source. Never written back: the Sink's URL field is the
    /// urn:event:{uid} identity token, so the link travels via `description`.
    url: Option<String>,
    /// Alarms: minutes before start (ik:alert, multi-valued).
    alerts: Vec<u32>,
}

/// Parse a skolemized event graph (Turtle) into events keyed by uid.
fn events_by_uid(turtle: &str) -> BTreeMap<String, ViewEvent> {
    const ICAL: &str = "http://www.w3.org/2002/12/cal/ical#";
    const IK: &str = "https://ikigai-rs.dev/ns#";
    let mut props: BTreeMap<String, BTreeMap<String, String>> = Default::default();
    let mut alert_map: BTreeMap<String, Vec<u32>> = Default::default();
    for quad in
        oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(turtle.as_bytes())
    {
        let Ok(quad) = quad else { continue };
        let oxrdf::NamedOrBlankNode::NamedNode(subject) = &quad.subject else {
            continue;
        };
        let Some(uid) = subject.as_str().strip_prefix("urn:event:") else {
            continue;
        };
        let value = match &quad.object {
            oxrdf::Term::Literal(l) => l.value().to_string(),
            oxrdf::Term::NamedNode(n) => n.as_str().to_string(),
            _ => continue,
        };
        // ik:alert is MULTI-valued — collect separately from the single-valued props.
        if quad.predicate.as_str() == "https://ikigai-rs.dev/ns#alert" {
            if let Ok(minutes) = value.parse::<u32>() {
                alert_map.entry(uid.to_string()).or_default().push(minutes);
            }
            continue;
        }
        props
            .entry(uid.to_string())
            .or_default()
            .insert(quad.predicate.as_str().to_string(), value);
    }
    props
        .into_iter()
        .filter_map(|(uid, p)| {
            let mut alerts = alert_map.get(&uid).cloned().unwrap_or_default();
            alerts.sort_unstable();
            alerts.dedup();
            Some((
                uid.clone(),
                ViewEvent {
                    // the ical:uid literal is authoritative (subjects are IRI-safe
                    // mangled); fall back to the subject-derived uid
                    uid: p.get(&format!("{ICAL}uid")).cloned().unwrap_or(uid),
                    title: p.get(&format!("{ICAL}summary")).cloned()?,
                    start: p.get(&format!("{ICAL}dtstart")).cloned()?,
                    end: p.get(&format!("{ICAL}dtend")).cloned()?,
                    all_day: p
                        .get(&format!("{IK}allDay"))
                        .map(|v| v == "true")
                        .unwrap_or(false),
                    location: p.get(&format!("{ICAL}location")).cloned(),
                    description: p.get(&format!("{ICAL}description")).cloned(),
                    url: p.get(&format!("{ICAL}url")).cloned(),
                    alerts,
                },
            ))
        })
        .collect()
}

/// The uids of every event subject appearing in a (possibly partial) graph. Unlike
/// [`events_by_uid`], this keeps a subject that carries only its *changed* triples — a
/// triple-level diff of a time/location edit is exactly that (just the differing
/// `ical:dtstart`/`dtend`, no `summary`), and reconstructing an event from it would drop
/// it. The deriver maps these uids back to the FULL event in desired/current.
fn subject_uids(turtle: &str) -> BTreeSet<String> {
    oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .filter_map(|quad| {
            let quad = quad.ok()?;
            let oxrdf::NamedOrBlankNode::NamedNode(subject) = &quad.subject else {
                return None;
            };
            subject
                .as_str()
                .strip_prefix("urn:event:")
                .map(str::to_string)
        })
        .collect()
}

/// Re-serialize a graph (as N-Triples, which is valid Turtle) normalized for the
/// convergence diff — dropping triples that always differ between a source and its derived
/// copy for reasons that aren't real edits, so the deriver doesn't loop forever recreating
/// them. The event DATA a create uses comes from the full graphs, not this.
///
/// Dropped:
/// - **`ik:calendar`** — provenance naming the calendar an event lives on ("Brian" vs
///   "Brian-Busy"); by construction it always differs source vs view.
/// - **`ical:dtend` on all-day events** — the org face emits the *exclusive* next-midnight
///   (iCal convention) while EventKit stores/reads all-day events with an *inclusive*
///   `23:59:59` end; same span, different string, never converges.
/// - **`ik:alert` on all-day events** — EventKit adds a *default* all-day alarm (9am the
///   day before, i.e. 900 min) that the source never asked for, so a created all-day event
///   reads back with an alert the desired lacks. Timed-event alerts are untouched (they
///   round-trip and are source-controlled).
/// - **`ical:url`** — a source event's real URL (a Teams invite's join link). It can
///   never round-trip: the create deliberately writes the `urn:event:{uid}` identity
///   token into the view copy's URL field, so the view reads back no `ical:url` and
///   comparing it would churn every linked event. The link still reaches the view via
///   `ical:description` (EKEvent .notes) — which IS kept in the diff: a note round-trips
///   through .notes as written, and if EventKit ever normalizes it the breaker will name
///   it (exclude it here then, like the all-day fields).
fn normalize_for_diff(turtle: &str) -> String {
    const IK_CALENDAR: &str = "https://ikigai-rs.dev/ns#calendar";
    const IK_ALLDAY: &str = "https://ikigai-rs.dev/ns#allDay";
    const IK_ALERT: &str = "https://ikigai-rs.dev/ns#alert";
    const ICAL_DTEND: &str = "http://www.w3.org/2002/12/cal/ical#dtend";
    const ICAL_URL: &str = "http://www.w3.org/2002/12/cal/ical#url";
    let quads: Vec<oxrdf::Quad> = oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .filter_map(|q| q.ok())
        .collect();
    // Subjects flagged all-day (the flag is only emitted when true).
    let all_day: std::collections::HashSet<String> = quads
        .iter()
        .filter(|q| q.predicate.as_str() == IK_ALLDAY)
        .map(|q| q.subject.to_string())
        .collect();
    let mut out = String::new();
    for quad in &quads {
        let pred = quad.predicate.as_str();
        if pred == IK_CALENDAR || pred == ICAL_URL {
            continue;
        }
        if (pred == ICAL_DTEND || pred == IK_ALERT) && all_day.contains(&quad.subject.to_string()) {
            continue;
        }
        // N-Triples line: `<subject> <predicate> object .` (object Displays canonically).
        out.push_str(&quad.subject.to_string());
        out.push(' ');
        out.push_str(&quad.predicate.to_string());
        out.push(' ');
        out.push_str(&quad.object.to_string());
        out.push_str(" .\n");
    }
    out
}

/// The derivation window: a rolling `today-7d..today+400d` range rather than
/// the calendar year, so a late-December derive still carries January into the
/// view, and a week of just-past events survives for the diff to leave alone.
fn derive_window() -> String {
    let today = chrono::Local::now().date_naive();
    format!(
        "{}..{}",
        today - chrono::Duration::days(7),
        today + chrono::Duration::days(400)
    )
}

/// Minutes-before-start as the friendly token both the org `:ALERT:` parser
/// and the calendar `alert=` argument accept.
fn alert_token(minutes: u32) -> String {
    if minutes > 0 && minutes.is_multiple_of(1440) {
        format!("{}d", minutes / 1440)
    } else if minutes > 0 && minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// The join link for a captured event: the event's real URL when it is already
/// a Teams link, else the first Teams URL found in the notes (the narrow match
/// — a stable, single-line token fit for a drawer property).
fn join_link(event: &ViewEvent) -> Option<String> {
    const TEAMS: &str = "https://teams.microsoft.com/";
    if let Some(url) = &event.url {
        if url.starts_with(TEAMS) {
            return Some(url.clone());
        }
    }
    let notes = event.description.as_deref()?;
    let at = notes.find(TEAMS)?;
    let link: String = notes[at..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !"<>\"'".contains(*c))
        .collect();
    Some(link.trim_end_matches(['.', ',', ')', ';']).to_string())
}

/// One captured event as an org heading: title, a `:PROPERTIES:` drawer carrying
/// the identity (plus `:LOCATION:`/`:URL:` when known), an active timestamp the
/// agenda parser round-trips, and the FULL description as the heading body —
/// that's for reading in org; only the drawer link re-surfaces to the derived
/// calendar.
fn org_heading(event: &ViewEvent) -> String {
    let stamp = org_stamp(event);
    let mut drawer = format!("  :PROPERTIES:\n  :ID: {}\n", event.uid);
    if let Some(location) = &event.location {
        // Drawer properties are single-line by construction.
        drawer.push_str(&format!("  :LOCATION: {}\n", location.replace('\n', " ")));
    }
    if let Some(link) = join_link(event) {
        drawer.push_str(&format!("  :URL: {link}\n"));
    }
    drawer.push_str("  :END:\n");
    let alert = if event.alerts.is_empty() {
        String::new()
    } else {
        let tokens: Vec<String> = event.alerts.iter().map(|m| alert_token(*m)).collect();
        format!("  :ALERT: {}\n", tokens.join(" "))
    };
    // The body comes LAST: the agenda parser reads :ID:/:ALERT: lines anywhere
    // under a headline, so untrusted invite text placed before the stamp could
    // hijack the entry's identity or alarms. Lines that would parse as a new
    // headline (leading '*') get org's comma escape.
    let body: String = event
        .description
        .as_deref()
        .map(|text| {
            text.lines()
                .map(|line| {
                    let escaped = if line.trim_start().starts_with('*') {
                        format!(",{line}")
                    } else {
                        line.to_string()
                    };
                    match escaped.trim_end() {
                        "" => "\n".to_string(),
                        line => format!("  {line}\n"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    format!("\n* {}\n{drawer}{alert}  {stamp}\n{body}", event.title)
}

fn org_stamp(event: &ViewEvent) -> String {
    let date = event
        .start
        .split_once('T')
        .map(|(d, _)| d)
        .unwrap_or(&event.start);
    let day = date
        .parse::<chrono::NaiveDate>()
        .map(|d| d.format("%a").to_string())
        .unwrap_or_default();
    if event.all_day {
        return format!("<{date} {day}>");
    }
    let hhmm = |s: &str| {
        s.split_once('T')
            .map(|(_, t)| t[..5.min(t.len())].to_string())
            .unwrap_or_default()
    };
    format!("<{date} {day} {}-{}>", hhmm(&event.start), hhmm(&event.end))
}

/// Apply a source's projection mode to its event graph (Turtle in, Turtle out).
/// `busy`: titles become "Busy (<source>)"; locations, descriptions, links, and
/// alarms are withheld. Anything else (or no mode) passes through untouched.
fn project_source(turtle: String, source: &str, mode: Option<&str>) -> String {
    if mode != Some("busy") {
        return turtle;
    }
    let events = events_by_uid(&turtle);
    let mut out = String::from(
        "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         @prefix ik: <https://ikigai-rs.dev/ns#> .\n",
    );
    for event in events.values() {
        let mut props = vec![
            "a ical:Vevent".to_string(),
            format!("ical:uid {}", view_ttl_str(&event.uid)),
            format!("ical:summary {}", view_ttl_str(&format!("Busy ({source})"))),
            format!("ical:dtstart {}", view_ttl_str(&event.start)),
            format!("ical:dtend {}", view_ttl_str(&event.end)),
            format!("ik:calendar {}", view_ttl_str(source)),
        ];
        if event.all_day {
            props.push("ik:allDay true".to_string());
        }
        out.push_str(&format!(
            "\n<urn:event:{}> {} .\n",
            event.uid.replace(['<', '>', ' '], "-"),
            props.join(" ;\n    ")
        ));
    }
    out
}

fn view_ttl_str(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('\"', "\\\"")
            .replace('\n', " ")
    )
}

/// `urn:view:ingest` — drain the phone-capture inbox (config `inbox`, e.g.
/// Brian-New) into the org system of record: each event becomes an org heading
/// (its iCal UID recorded as `:ID:`, which the org parser prefers — one
/// identity from capture to Brian-Busy), APPENDED through the kernel to the
/// first configured org file, then deleted from the inbox. Append-then-delete
/// + skip-if-ID-present make a crash between the two harmless.
pub struct IngestEndpoint {
    config: Option<ViewConfig>,
}

impl IngestEndpoint {
    /// Bind the ingest endpoint with the host-resolved config (`None` when
    /// calendar.json is absent — the endpoint then reports the missing config).
    pub fn new(config: Option<ViewConfig>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Endpoint for IngestEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let Some(config) = &self.config else {
            return Err(Error::Endpoint(
                "urn:view:ingest: no calendar config — see urn:personal:calendar:config"
                    .to_string(),
            ));
        };
        let Some(inbox) = &config.inbox else {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"no inbox configured - nothing to ingest\n".to_vec(),
            ));
        };
        let Some(target) = config.org_files.first() else {
            return Err(Error::Endpoint(
                "urn:view:ingest: no org_files configured".to_string(),
            ));
        };

        // The inbox's events (the rolling window), as the graph everything speaks.
        let captured = inv
            .issue(
                Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                        .expect("valid IRI"),
                )
                .with_arg("calendar", ArgRef::Inline(inbox.as_bytes().to_vec()))
                .with_arg("as", ArgRef::Inline(b"text/turtle".to_vec())),
            )
            .await?;
        let events = events_by_uid(&String::from_utf8_lossy(&captured.bytes));
        if events.is_empty() {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                format!("{inbox}: empty - nothing to ingest\n").into_bytes(),
            ));
        }

        // Read the target org file through the kernel (same jailed space the
        // agenda reads), append a heading per event, write it back, THEN drain.
        let target_iri = Iri::parse(target.as_str())
            .map_err(|e| Error::Endpoint(format!("urn:view:ingest: bad org IRI: {e}")))?;
        let current = inv.source(&target_iri).await?;
        let mut org = String::from_utf8_lossy(&current.bytes).to_string();

        let mut ingested = 0usize;
        let mut drained = 0usize;
        for event in events.values() {
            // Idempotency: an ID already in the file was ingested by an earlier
            // (possibly crashed) pass — just drain the inbox copy.
            if !org.contains(&format!(":ID: {}", event.uid)) {
                org.push_str(&org_heading(event));
                ingested += 1;
            }
        }
        if ingested > 0 {
            inv.issue(
                Request::new(Verb::Sink, target_iri.clone())
                    .with_arg("content", ArgRef::Inline(org.into_bytes())),
            )
            .await?;
        }
        // Only after the org write landed: drain the inbox.
        for event in events.values() {
            let request = Request::new(
                Verb::Delete,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg("calendar", ArgRef::Inline(inbox.as_bytes().to_vec()))
            .with_arg("uid", ArgRef::Inline(event.uid.as_bytes().to_vec()))
            .with_arg("start", ArgRef::Inline(event.start.as_bytes().to_vec()));
            inv.issue(request).await?;
            drained += 1;
        }
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            format!("{inbox}: ingested {ingested} into {target} · drained {drained}\n")
                .into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "view-ingest"
    }

    fn describe(&self) -> Description {
        Description::new("view-ingest")
            .title("Ingest the capture inbox")
            .summary(
                "Drain the phone-capture inbox calendar into the org system of record:                  each event becomes an org heading (:ID: = its iCal UID, one identity                  from capture to the consolidated view), appended through the kernel,                  then removed from the inbox. Idempotent; derive runs it first.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8")
    }
}

/// `urn:view:derive` — one materialization pass of the consolidated view (the
/// Brian-Busy plan's P4): desired = org agenda ∪ the allowlisted source
/// calendars (over a rolling window); current = the view calendar; the delta comes
/// from `urn:rdf:diff` THROUGH the kernel; apply = Delete the gone/changed, Sink the
/// new/changed (identity carried as urn:event:{uid} — the round-trip that makes
/// this idempotent). Drive it on a timer: `source urn:time:schedule
/// target=urn:view:derive every=300s`.
///
/// A healthy derive converges — `created 0 · removed 0`. A run of passes that keep
/// changing the same events means something isn't round-tripping (the deriver rewrites it,
/// the store-watcher re-fires the derive — an infinite loop that spams subscribers). After
/// [`CHURN_LIMIT`] consecutive churning passes a [`DeriveBreaker`] trips: further passes
/// are skipped until the daemon restarts, containing a runaway to a handful of passes.
#[derive(Default)]
struct DeriveBreaker {
    churn: std::sync::atomic::AtomicUsize,
    tripped: std::sync::atomic::AtomicBool,
}

/// Consecutive churning passes before the breaker trips. Generous enough that a legitimate
/// burst (a backlog catch-up, or a few rapid edits) — each of which converges on the next
/// pass — never trips; only sustained non-convergence does.
const CHURN_LIMIT: usize = 5;

impl DeriveBreaker {
    fn is_tripped(&self) -> bool {
        self.tripped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a pass by how many events it changed. `None` if it converged (counter
    /// resets); `Some(streak)` if it churned — tripping at [`CHURN_LIMIT`].
    fn record(&self, changed: usize) -> Option<usize> {
        use std::sync::atomic::Ordering::Relaxed;
        if changed == 0 {
            self.churn.store(0, Relaxed);
            return None;
        }
        let streak = self.churn.fetch_add(1, Relaxed) + 1;
        if streak >= CHURN_LIMIT {
            self.tripped.store(true, Relaxed);
        }
        Some(streak)
    }
}

pub struct DeriveEndpoint {
    config: Option<ViewConfig>,
    breaker: DeriveBreaker,
}

impl DeriveEndpoint {
    /// Bind the derive endpoint with the host-resolved config (`None` when
    /// calendar.json is absent — the endpoint then reports the missing config).
    /// Each binding gets its own convergence breaker.
    pub fn new(config: Option<ViewConfig>) -> Self {
        Self {
            config,
            breaker: DeriveBreaker::default(),
        }
    }
}

#[async_trait::async_trait]
impl Endpoint for DeriveEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // Breaker tripped: skip the pass entirely (no diff, no writes) so a non-converging
        // sync can't keep spamming. Restart the daemon after fixing the mismatch.
        if self.breaker.is_tripped() {
            return Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"auto-sync PAUSED (breaker tripped - not converging); restart after fixing\n"
                    .to_vec(),
            ));
        }
        let Some(config) = &self.config else {
            return Err(Error::Endpoint(
                "urn:view:derive: no calendar config — see urn:personal:calendar:config"
                    .to_string(),
            ));
        };
        // Drain the capture inbox into org FIRST, so a phone capture reaches the
        // consolidated view in the same pass. Failure here must not block the
        // derivation (the inbox may be mid-sync); it reports on the next tick.
        let _ = inv
            .issue(Request::new(
                Verb::Source,
                Iri::parse("urn:view:ingest").expect("valid IRI"),
            ))
            .await;

        let turtle_of = |mut request: Request| {
            request = request.with_arg("as", ArgRef::Inline(b"text/turtle".to_vec()));
            request
        };

        // DESIRED: the org agenda plus each allowlisted source calendar, over
        // the rolling window. Concatenated Turtle is legal (re-declared
        // prefixes are fine); the diff parses it with set semantics.
        let mut desired = String::new();
        if !config.org_files.is_empty() {
            let org = inv
                .issue(turtle_of(Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:org:agenda:{}", derive_window())).expect("valid IRI"),
                )))
                .await?;
            desired.push_str(&String::from_utf8_lossy(&org.bytes));
        }
        for source in &config.sources {
            let part = inv
                .issue(
                    turtle_of(Request::new(
                        Verb::Source,
                        Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                            .expect("valid IRI"),
                    ))
                    .with_arg("calendar", ArgRef::Inline(source.as_bytes().to_vec())),
                )
                .await?;
            desired.push_str(&project_source(
                String::from_utf8_lossy(&part.bytes).to_string(),
                source,
                config.projections.get(source).map(String::as_str),
            ));
        }

        // CURRENT: what the view calendar holds now.
        let current = inv
            .issue(
                turtle_of(Request::new(
                    Verb::Source,
                    Iri::parse(format!("urn:personal:calendar:{}", derive_window()))
                        .expect("valid IRI"),
                ))
                .with_arg("calendar", ArgRef::Inline(config.view.as_bytes().to_vec())),
            )
            .await?;
        let current = String::from_utf8_lossy(&current.bytes).to_string();

        // THE DELTA — urn:rdf:diff through the kernel, both directions. Compare with the
        // `ik:calendar` provenance stripped: it names the calendar an event lives on, so
        // it always differs between a source and the derived view — comparing it would
        // flag every event as changed on every pass (an infinite delete-recreate loop).
        // The event DATA below still comes from the full desired/current graphs.
        let desired_cmp = normalize_for_diff(&desired);
        let current_cmp = normalize_for_diff(&current);
        let diff = |mode: &'static str, a: String, b: String| {
            Request::new(Verb::Source, Iri::parse("urn:rdf:diff").expect("valid IRI"))
                .with_arg("content", ArgRef::Inline(a.into_bytes()))
                .with_arg("with", ArgRef::Inline(b.into_bytes()))
                .with_arg("mode", ArgRef::Inline(mode.as_bytes().to_vec()))
        };
        let added = inv
            .issue(diff("added", desired_cmp.clone(), current_cmp.clone()))
            .await?;
        let removed = inv
            .issue(diff("removed", desired_cmp.clone(), current_cmp))
            .await?;

        // Subjects in `removed` = gone or changed -> Delete (data from CURRENT).
        // Subjects in `added` = new or changed -> Sink (data from DESIRED).
        // A changed event is in both: delete first, recreate after = an update.
        // Extract the SUBJECT uids from the diff graphs, not full events: a triple-level
        // diff of a property-only edit carries just the changed triples (no summary), so
        // reconstructing an event from the diff would drop it — the uid then maps back to
        // the full event in desired/current.
        let desired_events = events_by_uid(&desired);
        let current_events = events_by_uid(&current);
        let to_delete: Vec<&ViewEvent> = subject_uids(&String::from_utf8_lossy(&removed.bytes))
            .iter()
            .filter_map(|uid| current_events.get(uid))
            .collect();
        let to_create: Vec<&ViewEvent> = subject_uids(&String::from_utf8_lossy(&added.bytes))
            .iter()
            .filter_map(|uid| desired_events.get(uid))
            .collect();

        let mut deleted = 0usize;
        let mut failed = 0usize;
        let mut first_failure: Option<String> = None;
        for event in &to_delete {
            let request = Request::new(
                Verb::Delete,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg("calendar", ArgRef::Inline(config.view.as_bytes().to_vec()))
            .with_arg("uid", ArgRef::Inline(event.uid.as_bytes().to_vec()))
            .with_arg("start", ArgRef::Inline(event.start.as_bytes().to_vec()));
            match inv.issue(request).await {
                Ok(_) => deleted += 1,
                // One bad event must not abort the pass: everything else still
                // syncs, and the failure is REPORTED (the heartbeat carries it)
                // instead of wedging the whole view on one entry.
                Err(e) => {
                    failed += 1;
                    first_failure.get_or_insert_with(|| format!("delete \"{}\": {e}", event.title));
                }
            }
        }
        let mut created = 0usize;
        for event in &to_create {
            let mut request = Request::new(
                Verb::Sink,
                Iri::parse("urn:personal:calendar").expect("valid IRI"),
            )
            .with_arg("calendar", ArgRef::Inline(config.view.as_bytes().to_vec()))
            .with_arg("title", ArgRef::Inline(event.title.as_bytes().to_vec()))
            .with_arg("start", ArgRef::Inline(event.start.as_bytes().to_vec()))
            .with_arg("end", ArgRef::Inline(event.end.as_bytes().to_vec()))
            .with_arg("uid", ArgRef::Inline(event.uid.as_bytes().to_vec()));
            if event.all_day {
                request = request.with_arg("all_day", ArgRef::Inline(b"true".to_vec()));
            }
            if let Some(location) = &event.location {
                request =
                    request.with_arg("location", ArgRef::Inline(location.as_bytes().to_vec()));
            }
            // The description (a captured invite's join link, or a source
            // event's notes) rides into the view copy's .notes. The event's
            // real URL is deliberately NOT passed: the Sink's URL field is the
            // urn:event:{uid} identity token.
            if let Some(description) = &event.description {
                request = request.with_arg(
                    "description",
                    ArgRef::Inline(description.as_bytes().to_vec()),
                );
            }
            if !event.alerts.is_empty() {
                let minutes: Vec<String> = event.alerts.iter().map(u32::to_string).collect();
                request = request.with_arg("alert", ArgRef::Inline(minutes.join(",").into_bytes()));
            }
            match inv.issue(request).await {
                Ok(_) => created += 1,
                Err(e) => {
                    failed += 1;
                    first_failure.get_or_insert_with(|| format!("create \"{}\": {e}", event.title));
                }
            }
        }

        let unchanged = current_events.len().saturating_sub(deleted);
        let mut report = format!(
            "{}: created {created} · removed {deleted} · unchanged {unchanged}",
            config.view
        );
        if failed > 0 {
            report.push_str(&format!(
                " · FAILED {failed} ({})",
                first_failure.as_deref().unwrap_or("unknown")
            ));
        }
        // Circuit breaker: converge or contain. A churning pass surfaces WHAT keeps
        // changing on BOTH sides — `+` = desired-not-view (created), `-` = view-not-desired
        // (removed) — so a create OR a remove pass names the mismatched field; it counts
        // toward tripping. A converged pass resets it.
        if let Some(streak) = self.breaker.record(created + deleted + failed) {
            let side = |label: &str, bytes: &[u8]| {
                let text = String::from_utf8_lossy(bytes);
                let lines: Vec<&str> = text.lines().take(4).collect();
                if lines.is_empty() {
                    String::new()
                } else {
                    format!(" {label} {}", lines.join(" | ").trim())
                }
            };
            report.push_str(&format!(
                "\n  churn {streak}/{CHURN_LIMIT}:{}{}",
                side("+", &added.bytes),
                side("-", &removed.bytes),
            ));
            if self.breaker.is_tripped() {
                report.push_str(
                    "\n  NOT CONVERGING — auto-sync PAUSED. Exclude/normalize the churning \
                     field above in the deriver, then restart the daemon.",
                );
            }
        }
        report.push('\n');
        Ok(Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            report.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "view-derive"
    }

    fn describe(&self) -> Description {
        Description::new("view-derive")
            .title("Derive the consolidated view")
            .summary(
                "One materialization pass: desired (org agenda ∪ the configured source                  calendars, over a rolling today-7d..+400d window) minus current (the view calendar) via urn:rdf:diff —                  gone/changed events deleted, new/changed created, identity carried as                  urn:event:{uid} so the pass is idempotent. Drive it on a timer.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8")
    }
}

/// A local-time stamp (`YYYY-MM-DD HH:MM:SS`) prefixed on every daemon-log derive
/// report, so the heartbeat in the daemon log doubles as a freshness clock — you can
/// see *when* the last sync ran, not just that one did.
fn stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// `urn:view:derive:tick` — the standing-sync face of the derivation: issues
/// `urn:view:derive` and reports the pass to stderr (the daemon log), so the
/// timer leaves a heartbeat. Silence in the log then MEANS the sync is not
/// running — never that a healthy pass had nothing to say.
pub struct DeriveTickEndpoint;

impl DeriveTickEndpoint {
    /// Bind the tick endpoint. It carries no config — it composes `urn:view:derive`
    /// entirely through the kernel, so the config lives on the derive endpoint only.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DeriveTickEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Endpoint for DeriveTickEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let result = inv
            .issue(Request::new(
                Verb::Source,
                Iri::parse("urn:view:derive").expect("valid IRI"),
            ))
            .await;
        match &result {
            Ok(report) => eprintln!(
                "{} ikigai: timer → {}",
                stamp(),
                String::from_utf8_lossy(&report.bytes).trim_end()
            ),
            Err(e) => eprintln!("{} ikigai: timer → derive failed: {e}", stamp()),
        }
        result
    }

    fn name(&self) -> &str {
        "view-derive-tick"
    }

    fn describe(&self) -> Description {
        Description::new("view-derive-tick")
            .title("Derive the consolidated view (reporting)")
            .summary(
                "urn:view:derive plus a stderr report of the pass — the standing sync                  schedules this face so the daemon log carries a heartbeat.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain;charset=utf-8")
    }
}

#[cfg(test)]
mod tests;
