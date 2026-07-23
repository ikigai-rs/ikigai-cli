//! Hermetic tests for the consolidated-view derivation.
//!
//! The reconciliation composes `urn:personal:calendar` (Source/Sink/Delete),
//! `urn:org:agenda`, and `urn:rdf:diff` entirely through the kernel — so it can be
//! driven against an in-memory test kernel whose personal/org/diff spaces are simple
//! fakes: a mutable calendar store, a fixed org agenda, and a faithful triple-level
//! diff. That is coverage the delta-apply never had while it was welded to host
//! config reads and live EventKit.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use ikigai_core::{Capability, EndpointSpace, Exact, Kernel, UriTemplate};

// ---- pure-helper unit tests (preserved from the host crate) -----------------

#[test]
fn a_property_only_change_is_not_dropped_by_the_deriver() {
    // A triple-level diff of a time-only edit is just the changed dtstart/dtend —
    // no summary. events_by_uid (needs summary+dtstart+dtend) drops it; the deriver
    // used to extract its create/delete set from exactly this, so the change vanished.
    let partial_diff = "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         <urn:event:4D7E3E55> ical:dtstart \"2026-07-20T10:00:00-07:00\" ;\n\
         \x20   ical:dtend \"2026-07-20T11:30:00-07:00\" .\n";
    assert!(
        events_by_uid(partial_diff).is_empty(),
        "the diff graph has no summary, so a full-event parse drops it"
    );
    // subject_uids still recovers the changed subject → the deriver maps it back to
    // the full event in desired/current and applies the update.
    assert!(
        subject_uids(partial_diff).contains("4D7E3E55"),
        "the changed subject's uid is recovered from the diff graph"
    );
}

#[test]
fn alerts_round_trip_from_graph_to_org_heading() {
    // Multi-valued ik:alert on one subject → sorted/deduped minutes on the
    // ViewEvent → a friendly `:ALERT:` line in the captured org heading.
    let turtle = r#"@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:event:abc> a ical:Vevent ;
    ical:uid "abc" ;
    ical:summary "Dentist" ;
    ical:dtstart "2026-07-10T09:00:00" ;
    ical:dtend "2026-07-10T10:00:00" ;
    ik:alert 1440 ;
    ik:alert 60 ;
    ik:alert 60 .
"#;
    let events = events_by_uid(turtle);
    let event = events.get("abc").expect("event parsed");
    assert_eq!(event.alerts, vec![60, 1440], "sorted and deduped");

    let heading = org_heading(event);
    assert!(heading.contains(":ID: abc"));
    assert!(
        heading.contains(":ALERT: 1h 1d"),
        "friendly tokens, not raw minutes: {heading}"
    );

    assert_eq!(alert_token(30), "30m");
    assert_eq!(alert_token(90), "90m", "not a whole hour → minutes");
    assert_eq!(alert_token(2880), "2d");
}

#[test]
fn calendar_provenance_does_not_count_as_a_change() {
    // A source event and its Brian-Busy copy differ ONLY in ik:calendar (the calendar
    // it lives on). Stripped, the two are the same triple set — so the diff finds
    // nothing to sync, and the derive converges instead of looping forever.
    let src = "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         @prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         <urn:event:X> ical:summary \"E\" ; ical:dtstart \"2026-07-20T10:00:00-07:00\" ; \
         ical:dtend \"2026-07-20T11:30:00-07:00\" ; ik:calendar \"Brian\" .\n";
    let view = src.replace("\"Brian\"", "\"Brian-Busy\"");
    let sorted = |t: &str| {
        let mut v: Vec<String> = normalize_for_diff(t).lines().map(str::to_string).collect();
        v.sort();
        v
    };
    assert_eq!(
        sorted(src),
        sorted(&view),
        "same event on different calendars = no substantive difference"
    );
    assert!(!normalize_for_diff(src).contains("ns#calendar"));
    assert!(normalize_for_diff(src).contains("dtstart"));
}

#[test]
fn all_day_dtend_convention_does_not_count_as_a_change() {
    // Same all-day span. Two EventKit artifacts differ from the org source: the end
    // convention (org emits the exclusive next-midnight, EventKit the inclusive
    // 23:59:59) and a DEFAULT all-day alarm (900 = 9am the day before) EventKit adds
    // that the source never asked for. Both are excluded for all-day → converges.
    let org = "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         @prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         <urn:event:U> ical:summary \"Span\" ; ical:dtstart \"2026-07-14T00:00:00-07:00\" ; \
         ical:dtend \"2026-07-18T00:00:00-07:00\" ; ik:allDay true ; ik:calendar \"Brian\" .\n";
    let busy = org
        .replace("2026-07-18T00:00:00", "2026-07-17T23:59:59")
        .replace("\"Brian\"", "\"Brian-Busy\"")
        .replace("ik:allDay true", "ik:allDay true ; ik:alert 900");
    let sorted = |t: &str| {
        let mut v: Vec<String> = normalize_for_diff(t).lines().map(str::to_string).collect();
        v.sort();
        v
    };
    assert_eq!(
        sorted(org),
        sorted(&busy),
        "all-day end convention + default alarm aren't changes"
    );
    // A TIMED event keeps both dtend and alert (they round-trip and are source-owned).
    let timed = org.replace("ik:allDay true ; ", "").replace(
        "ik:calendar \"Brian\" .",
        "ik:calendar \"Brian\" ; ik:alert 60 .",
    );
    let n = normalize_for_diff(&timed);
    assert!(n.contains("dtend"), "dtend kept for non-all-day events");
    assert!(n.contains("ns#alert"), "alert kept for non-all-day events");
}

#[test]
fn the_derive_breaker_contains_a_runaway() {
    let b = DeriveBreaker::default();
    // A churning pass followed by convergence never trips — a legitimate edit converges
    // on the next pass, so the streak resets.
    assert_eq!(b.record(3), Some(1));
    assert_eq!(b.record(0), None);
    assert!(!b.is_tripped());
    // Sustained non-convergence trips exactly at the limit.
    for expected in 1..CHURN_LIMIT {
        assert_eq!(b.record(1), Some(expected));
        assert!(!b.is_tripped());
    }
    assert_eq!(b.record(1), Some(CHURN_LIMIT));
    assert!(
        b.is_tripped(),
        "auto-sync pauses after CHURN_LIMIT non-converging passes"
    );
}

#[test]
fn the_join_link_prefers_the_real_url_and_falls_back_to_the_notes() {
    let mut event = ViewEvent {
        uid: "T1".to_string(),
        title: "Planning".to_string(),
        start: "2026-07-23T09:00:00".to_string(),
        end: "2026-07-23T10:00:00".to_string(),
        all_day: false,
        location: None,
        description: Some(
            "Microsoft Teams meeting\nJoin: <https://teams.microsoft.com/l/meetup-join/abc>.\nSee you there"
                .to_string(),
        ),
        url: Some("https://teams.microsoft.com/l/meetup-join/primary".to_string()),
        attendees: Vec::new(),
        alerts: Vec::new(),
    };
    assert_eq!(
        join_link(&event).as_deref(),
        Some("https://teams.microsoft.com/l/meetup-join/primary"),
        "a real Teams URL on the event wins"
    );
    event.url = Some("urn:not-a-teams-link".to_string());
    assert_eq!(
        join_link(&event).as_deref(),
        Some("https://teams.microsoft.com/l/meetup-join/abc"),
        "else the narrow match in the notes, unwrapped from <>. and punctuation"
    );
    event.description = Some("no link here".to_string());
    assert_eq!(join_link(&event), None);
}

#[test]
fn the_join_link_is_provider_agnostic_and_host_matched() {
    let event = |url: Option<&str>, notes: Option<&str>| ViewEvent {
        uid: "T2".to_string(),
        title: "Sync".to_string(),
        start: "2026-07-23T09:00:00".to_string(),
        end: "2026-07-23T10:00:00".to_string(),
        all_day: false,
        location: None,
        description: notes.map(str::to_string),
        url: url.map(str::to_string),
        attendees: Vec::new(),
        alerts: Vec::new(),
    };

    // A provider subdomain matches (zoom/webex put the tenant in the host).
    assert_eq!(
        join_link(&event(
            None,
            Some("Join: https://us02web.zoom.us/j/123?pwd=x")
        ))
        .as_deref(),
        Some("https://us02web.zoom.us/j/123?pwd=x")
    );
    assert_eq!(
        join_link(&event(Some("https://acme.webex.com/meet/brian"), None)).as_deref(),
        Some("https://acme.webex.com/meet/brian")
    );
    // Google Meet + Jitsi on the event's own URL.
    assert_eq!(
        join_link(&event(Some("https://meet.google.com/abc-defg-hij"), None)).as_deref(),
        Some("https://meet.google.com/abc-defg-hij")
    );

    // A LOOKALIKE host must NOT match (substring matching would wrongly accept this).
    assert_eq!(
        join_link(&event(Some("https://evilzoom.us/j/1"), None)),
        None
    );

    // A non-meeting URL earlier in the notes is skipped; the real link is still found.
    assert_eq!(
        join_link(&event(
            None,
            Some("Unsubscribe: https://mail.example.com/u/1\nJoin: https://zoom.us/j/9 thanks")
        ))
        .as_deref(),
        Some("https://zoom.us/j/9"),
        "scan past non-meeting URLs rather than stopping at the first http"
    );

    // No known host anywhere → nothing lands in :URL:.
    assert_eq!(
        join_link(&event(
            Some("https://docs.example.com/agenda"),
            Some("notes with https://example.com/x only")
        )),
        None
    );
}

#[test]
fn a_captured_invite_becomes_a_heading_with_drawers_and_a_body() {
    let event = ViewEvent {
        uid: "cap-1".to_string(),
        title: "Quarterly sync".to_string(),
        start: "2026-07-23T09:00:00".to_string(),
        end: "2026-07-23T10:00:00".to_string(),
        all_day: false,
        location: Some("Microsoft Teams Meeting".to_string()),
        description: Some(
            "Agenda:\n* budget\n\nJoin: https://teams.microsoft.com/l/meetup-join/abc".to_string(),
        ),
        url: None,
        attendees: vec!["Ada Lovelace".to_string(), "grace@example.com".to_string()],
        alerts: Vec::new(),
    };
    let heading = org_heading(&event);
    assert!(heading.contains(":ID: cap-1"));
    assert!(heading.contains(":LOCATION: Microsoft Teams Meeting"));
    assert!(heading.contains(":URL: https://teams.microsoft.com/l/meetup-join/abc"));
    // The full description is the heading body, AFTER the stamp (body text must
    // not be able to hijack the entry's :ID:/:ALERT: or precede the timestamp).
    let stamp_at = heading.find("<2026-07-23").expect("stamp present");
    let body_at = heading.find("Agenda:").expect("body present");
    assert!(body_at > stamp_at, "body comes after the stamp: {heading}");
    // A body line that looks like a headline gets org's comma escape.
    assert!(
        heading.contains(",* budget"),
        "leading '*' must not become a new headline: {heading}"
    );
    // Attendees close the body — read-only in EventKit, the org record is
    // where they live.
    let attendees_at = heading
        .find("Attendees: Ada Lovelace, grace@example.com")
        .expect("attendee line present");
    assert!(
        attendees_at > body_at,
        "attendees follow the description: {heading}"
    );
}

#[test]
fn a_real_url_does_not_count_as_a_change_but_the_description_does() {
    // The view copy can never echo ical:url (its URL field is the identity
    // token) nor ical:attendee (read-only in EventKit), so a source's link and
    // attendee list must not churn the diff. ical:description DOES round-trip
    // through .notes and stays comparable.
    let src = "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
         @prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         <urn:event:X> ical:summary \"E\" ; ical:dtstart \"2026-07-20T10:00:00-07:00\" ; \
         ical:dtend \"2026-07-20T11:30:00-07:00\" ; \
         ical:description \"https://teams.microsoft.com/l/meetup-join/abc\" ; \
         ical:attendee \"Ada\" ; ical:attendee \"Grace\" ; \
         ical:url \"https://teams.microsoft.com/l/meetup-join/abc\" ; ik:calendar \"Bosatsu\" .\n";
    let view = src
        .replace(
            " ical:url \"https://teams.microsoft.com/l/meetup-join/abc\" ;",
            "",
        )
        .replace(" ical:attendee \"Ada\" ; ical:attendee \"Grace\" ;", "")
        .replace("\"Bosatsu\"", "\"Brian-Busy\"");
    let sorted = |t: &str| {
        let mut v: Vec<String> = normalize_for_diff(t).lines().map(str::to_string).collect();
        v.sort();
        v
    };
    assert_eq!(
        sorted(src),
        sorted(&view),
        "a source-only ical:url is not a substantive difference"
    );
    assert!(
        normalize_for_diff(src).contains("description"),
        "ical:description stays in the convergence diff"
    );
}

// ---- the hermetic reconciliation harness ------------------------------------

/// One event held by the fake calendar store, in the shape the deriver's
/// Sink/Delete arguments carry.
#[derive(Clone, Debug)]
struct StoredEvent {
    uid: String,
    title: String,
    start: String,
    end: String,
    all_day: bool,
    location: Option<String>,
    description: Option<String>,
    alerts: Vec<u32>,
}

impl StoredEvent {
    /// Serialize as the skolemized event graph the calendar face speaks — the
    /// same triples `events_by_uid`/`subject_uids` read and the diff compares.
    fn to_turtle(&self) -> String {
        let mut props = vec![
            "a ical:Vevent".to_string(),
            format!("ical:uid {}", ttl(&self.uid)),
            format!("ical:summary {}", ttl(&self.title)),
            format!("ical:dtstart {}", ttl(&self.start)),
            format!("ical:dtend {}", ttl(&self.end)),
        ];
        if self.all_day {
            props.push("ik:allDay true".to_string());
        }
        if let Some(loc) = &self.location {
            props.push(format!("ical:location {}", ttl(loc)));
        }
        if let Some(description) = &self.description {
            props.push(format!("ical:description {}", ttl(description)));
        }
        for minutes in &self.alerts {
            props.push(format!("ik:alert {minutes}"));
        }
        format!(
            "<urn:event:{}> {} .\n",
            self.uid.replace(['<', '>', ' '], "-"),
            props.join(" ;\n    ")
        )
    }
}

fn ttl(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The whole `urn:personal:calendar` verb-triple as a shared in-memory store,
/// keyed `(calendar, uid)`. Bound to both the bare IRI (Sink/Delete) and the
/// period grammar (Source) so one instance backs the round-trip.
#[derive(Clone, Default)]
struct FakeCalendar {
    store: Arc<Mutex<BTreeMap<(String, String), StoredEvent>>>,
}

impl FakeCalendar {
    fn seed(&self, calendar: &str, events: Vec<StoredEvent>) {
        let mut store = self.store.lock().unwrap();
        for event in events {
            store.insert((calendar.to_string(), event.uid.clone()), event);
        }
    }

    fn events_in(&self, calendar: &str) -> Vec<StoredEvent> {
        self.store
            .lock()
            .unwrap()
            .iter()
            .filter(|((cal, _), _)| cal == calendar)
            .map(|(_, e)| e.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl Endpoint for FakeCalendar {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let calendar = inv.inline_str("calendar").unwrap_or("").to_string();
        match inv.request.verb {
            Verb::Source => {
                let mut body = String::from(
                    "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
                     @prefix ik: <https://ikigai-rs.dev/ns#> .\n",
                );
                let store = self.store.lock().unwrap();
                for ((cal, _), event) in store.iter() {
                    if *cal == calendar {
                        body.push_str(&event.to_turtle());
                    }
                }
                Ok(Representation::new(
                    ReprType::new("text/turtle"),
                    body.into_bytes(),
                ))
            }
            Verb::Sink => {
                let get = |k: &str| inv.inline_str(k).unwrap_or("").to_string();
                let uid = get("uid");
                let alerts = inv
                    .inline_str("alert")
                    .ok()
                    .map(|s| s.split(',').filter_map(|m| m.trim().parse().ok()).collect())
                    .unwrap_or_default();
                let event = StoredEvent {
                    uid: uid.clone(),
                    title: get("title"),
                    start: get("start"),
                    end: get("end"),
                    all_day: inv
                        .inline_str("all_day")
                        .map(|v| v == "true")
                        .unwrap_or(false),
                    location: inv.inline_str("location").ok().map(str::to_string),
                    description: inv.inline_str("description").ok().map(str::to_string),
                    alerts,
                };
                self.store.lock().unwrap().insert((calendar, uid), event);
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok\n".to_vec(),
                ))
            }
            Verb::Delete => {
                let uid = inv.inline_str("uid").unwrap_or("").to_string();
                self.store.lock().unwrap().remove(&(calendar, uid));
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok\n".to_vec(),
                ))
            }
            _ => Err(Error::Endpoint(
                "fake calendar: unsupported verb".to_string(),
            )),
        }
    }

    fn name(&self) -> &str {
        "fake-calendar"
    }

    fn describe(&self) -> Description {
        Description::new("fake-calendar")
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Delete)
    }
}

/// The `urn:org:agenda:{window}` face as a fixed graph — the DESIRED side of the
/// diff. (The real endpoint reads org files; here the graph is what a test sets.)
struct FakeOrgAgenda {
    turtle: String,
}

#[async_trait::async_trait]
impl Endpoint for FakeOrgAgenda {
    async fn invoke(&self, _inv: &Invocation<'_>) -> Result<Representation> {
        Ok(Representation::new(
            ReprType::new("text/turtle"),
            self.turtle.clone().into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "fake-org-agenda"
    }

    fn describe(&self) -> Description {
        Description::new("fake-org-agenda").verb(Verb::Source)
    }
}

/// A faithful `urn:rdf:diff`: the triples on one side only, at the parsed-triple
/// level. `mode=added` (default): in `content` (desired) not in `with` (current);
/// `mode=removed`: in `with` not in `content`. This is exactly what the deriver
/// feeds `subject_uids`, so it exercises the real reconciliation.
struct FakeDiff;

fn triples(turtle: &str) -> Vec<(String, String)> {
    oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle)
        .for_slice(turtle.as_bytes())
        .filter_map(|quad| {
            let quad = quad.ok()?;
            let key = format!("{} {} {}", quad.subject, quad.predicate, quad.object);
            let line = format!("{key} .");
            Some((key, line))
        })
        .collect()
}

#[async_trait::async_trait]
impl Endpoint for FakeDiff {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let content = inv.inline_str("content").unwrap_or("").to_string();
        let with = inv.inline_str("with").unwrap_or("").to_string();
        let mode = inv.inline_str("mode").unwrap_or("added").to_string();
        let ours = triples(&content);
        let theirs = triples(&with);
        let (keep, exclude) = match mode.as_str() {
            "removed" => (&theirs, &ours),
            _ => (&ours, &theirs),
        };
        let exclude_keys: BTreeSet<&String> = exclude.iter().map(|(k, _)| k).collect();
        let mut out = String::new();
        for (key, line) in keep {
            if !exclude_keys.contains(key) {
                out.push_str(line);
                out.push('\n');
            }
        }
        Ok(Representation::new(
            ReprType::new("text/turtle"),
            out.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "fake-diff"
    }

    fn describe(&self) -> Description {
        Description::new("fake-diff").verb(Verb::Source)
    }
}

/// A view-only config (no source calendars, no inbox, one org file so the agenda
/// is folded in) — the shape every reconciliation test uses.
fn view_config() -> ViewConfig {
    ViewConfig {
        view: "View".to_string(),
        sources: Vec::new(),
        inbox: None,
        org_files: vec!["urn:orgfile:agenda.org".to_string()],
        projections: BTreeMap::new(),
    }
}

/// Wire an in-memory kernel: the shared calendar, the fixed org agenda (DESIRED),
/// a faithful diff, and the real [`DeriveEndpoint`] under test. Returns the kernel
/// and a handle on the store for asserting the post-pass view.
fn harness(desired_org: &str) -> (Kernel, FakeCalendar) {
    let calendar = FakeCalendar::default();
    let cal_arc: Arc<dyn Endpoint> = Arc::new(calendar.clone());
    let space = EndpointSpace::new()
        .bind_arc(Exact::new("urn:personal:calendar"), Arc::clone(&cal_arc))
        .bind_arc(
            UriTemplate::parse("urn:personal:calendar:{period}").expect("valid template"),
            cal_arc,
        )
        .bind(
            UriTemplate::parse("urn:org:agenda:{period}").expect("valid template"),
            FakeOrgAgenda {
                turtle: desired_org.to_string(),
            },
        )
        .bind(Exact::new("urn:rdf:diff"), FakeDiff)
        .bind(
            Exact::new("urn:view:derive"),
            DeriveEndpoint::new(Some(view_config())),
        );
    (Kernel::new(Arc::new(space)), calendar)
}

fn derive(kernel: &Kernel) -> String {
    let request = Request::new(
        Verb::Source,
        Iri::parse("urn:view:derive").expect("valid IRI"),
    );
    let repr = block_on(kernel.issue(request, &Capability::root())).expect("derive");
    String::from_utf8(repr.bytes).unwrap()
}

fn event(uid: &str, title: &str, start: &str, end: &str) -> StoredEvent {
    StoredEvent {
        uid: uid.to_string(),
        title: title.to_string(),
        start: start.to_string(),
        end: end.to_string(),
        all_day: false,
        location: None,
        description: None,
        alerts: Vec::new(),
    }
}

const ORG_HEADER: &str = "@prefix ical: <http://www.w3.org/2002/12/cal/ical#> .\n\
     @prefix ik: <https://ikigai-rs.dev/ns#> .\n";

#[test]
fn property_only_change_is_deleted_then_recreated() {
    // The #150 regression, end to end: the view holds E1 at 10:00; the org agenda
    // wants E1 at 11:00 — same uid/summary/end, only dtstart differs. The diff
    // carries just the changed triple (no summary), so the pass must recover the
    // subject and re-apply the FULL event, not drop it.
    let desired = format!(
        "{ORG_HEADER}{}",
        event(
            "E1",
            "Standup",
            "2026-07-20T11:00:00",
            "2026-07-20T11:30:00"
        )
        .to_turtle()
    );
    let (kernel, calendar) = harness(&desired);
    calendar.seed(
        "View",
        vec![event(
            "E1",
            "Standup",
            "2026-07-20T10:00:00",
            "2026-07-20T11:30:00",
        )],
    );

    let report = derive(&kernel);
    assert!(
        report.contains("created 1 · removed 1"),
        "a property-only change is one delete + one recreate: {report}"
    );
    let view = calendar.events_in("View");
    assert_eq!(
        view.len(),
        1,
        "still exactly one E1, not vanished or doubled"
    );
    assert_eq!(
        view[0].start, "2026-07-20T11:00:00",
        "the new time landed in the view"
    );
}

#[test]
fn a_whole_new_event_is_created() {
    let desired = format!(
        "{ORG_HEADER}{}",
        event(
            "N1",
            "New talk",
            "2026-07-21T09:00:00",
            "2026-07-21T10:00:00"
        )
        .to_turtle()
    );
    let (kernel, calendar) = harness(&desired);
    // View starts empty.

    let report = derive(&kernel);
    assert!(
        report.contains("created 1 · removed 0"),
        "a brand-new event is a pure create: {report}"
    );
    let view = calendar.events_in("View");
    assert_eq!(view.len(), 1);
    assert_eq!(view[0].uid, "N1");
}

#[test]
fn a_dropped_event_is_removed_from_the_view() {
    // The org agenda no longer wants G1; the view still holds it.
    let (kernel, calendar) = harness(ORG_HEADER);
    calendar.seed(
        "View",
        vec![event(
            "G1",
            "Cancelled",
            "2026-07-22T14:00:00",
            "2026-07-22T15:00:00",
        )],
    );

    let report = derive(&kernel);
    assert!(
        report.contains("created 0 · removed 1"),
        "a gone event is a pure delete: {report}"
    );
    assert!(
        calendar.events_in("View").is_empty(),
        "the view no longer holds the dropped event"
    );
}

#[test]
fn a_second_pass_is_a_no_op() {
    // Idempotency: the created event re-serializes to the SAME triples the desired
    // graph carries, so once the view matches, another pass creates and deletes
    // nothing. (A drift here — an un-round-tripped field — would show as a spurious
    // create or delete on the second pass.)
    let desired = format!(
        "{ORG_HEADER}{}",
        event(
            "E1",
            "Standup",
            "2026-07-20T11:00:00",
            "2026-07-20T11:30:00"
        )
        .to_turtle()
    );
    let (kernel, calendar) = harness(&desired);

    let first = derive(&kernel);
    assert!(
        first.contains("created 1 · removed 0"),
        "first pass creates: {first}"
    );

    let second = derive(&kernel);
    assert!(
        second.contains("created 0 · removed 0"),
        "the second pass is a no-op: {second}"
    );
    assert_eq!(
        calendar.events_in("View").len(),
        1,
        "still exactly one event"
    );
}

#[test]
fn a_linked_event_carries_its_description_and_converges() {
    // An org event whose :URL: drawer emitted the join link as ical:description:
    // the pass must write it into the view copy (the wife's join button), and —
    // because the fake store echoes it back like EKEvent .notes does — the
    // second pass must converge instead of delete-recreating the linked event.
    let mut linked = event(
        "L1",
        "Planning call",
        "2026-07-23T09:00:00",
        "2026-07-23T10:00:00",
    );
    linked.description = Some("https://teams.microsoft.com/l/meetup-join/abc".to_string());
    linked.location = Some("Microsoft Teams Meeting".to_string());
    let desired = format!("{ORG_HEADER}{}", linked.to_turtle());
    let (kernel, calendar) = harness(&desired);

    let first = derive(&kernel);
    assert!(
        first.contains("created 1 · removed 0"),
        "first pass creates the linked event: {first}"
    );
    let view = calendar.events_in("View");
    assert_eq!(
        view[0].description.as_deref(),
        Some("https://teams.microsoft.com/l/meetup-join/abc"),
        "the join link landed in the view copy's notes"
    );
    assert_eq!(view[0].location.as_deref(), Some("Microsoft Teams Meeting"));

    let second = derive(&kernel);
    assert!(
        second.contains("created 0 · removed 0"),
        "a linked event round-trips and converges: {second}"
    );
}

#[test]
fn derive_without_config_reports_the_missing_config() {
    // Config absent (host had no calendar.json) → a clean error naming the config
    // resource, not a panic.
    let space = EndpointSpace::new().bind(Exact::new("urn:view:derive"), DeriveEndpoint::new(None));
    let kernel = Kernel::new(Arc::new(space));
    let request = Request::new(
        Verb::Source,
        Iri::parse("urn:view:derive").expect("valid IRI"),
    );
    let err = block_on(kernel.issue(request, &Capability::root())).unwrap_err();
    assert!(
        format!("{err}").contains("no calendar config"),
        "missing config is reported: {err}"
    );
}
