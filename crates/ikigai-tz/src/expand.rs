//! `urn:tz:expand`: an RFC 5545 recurrence rule, expanded in a zone over a window.
//!
//! `rule + start + zone + window (+ exdate) → occurrences`. The recurrence itself (`FREQ`,
//! `INTERVAL`, `COUNT`, `UNTIL`, every `BY*` part, `WKST`) is computed by the vetted
//! [`rrule`](https://docs.rs/rrule) crate; nothing here re-implements RFC 5545's rule
//! grammar or its expansion.
//!
//! **Wall-clock recurrence.** RFC 5545 repeats a `DTSTART` with a `TZID` at the same local
//! time in that zone, so a class at 09:00 in `America/New_York` is at 09:00 EDT in summer and
//! 09:00 EST in winter, never at a fixed UTC instant. So the crate is asked for the series of
//! LOCAL WALL TIMES (the rule expanded in floating time, with UTC standing in as a zone
//! without transitions), and each wall time is then placed in the zone by [`resolve_local`],
//! which applies RFC 5545's rule for the two local times that need one (section 3.3.5):
//!
//! - a local time that does not exist (a spring-forward gap) is read with the offset in
//!   effect BEFORE the gap, so 02:30 on the day New York springs forward is 03:30 EDT;
//! - a local time that occurs twice (a fall-back overlap) is the FIRST of the two.
//!
//! The crate's own placement agrees with that rule in most zones, but it places a gap time
//! by adding the time of day to local midnight, so in a zone whose clocks change AT midnight
//! (America/Santiago, for one) an occurrence inside the gap is dropped from the series; and a
//! Z-less `UNTIL` is read in the host's local zone. Expanding in floating time and placing the
//! wall times here keeps every occurrence the rule names, and a Z-less `UNTIL` is refused, as
//! RFC 5545 requires `UNTIL` in UTC when the start has a zone. `start`, `from`, `until` and
//! `exdate` written as wall times are placed by the same function, so an `exdate` names
//! exactly the instant of the occurrence it skips.
//!
//! The answer is a pure function of the arguments and the tz database bundled at build time,
//! so it is cacheable.

use chrono::offset::LocalResult;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use ikigai_core::{ArgSpec, Description, Error, FnEndpoint, Invocation, Result, Verb};
use rrule::{RRule, RRuleSet, Unvalidated};

use crate::{parse_naive, text, zone_arg, XSD_STRING};

/// The most occurrences one expansion answers. A window that holds more is refused, never cut
/// short: a list that silently stops would read as "nothing after this".
pub const MAX_OCCURRENCES: usize = 1000;

fn invalid(name: &str, detail: impl Into<String>) -> Error {
    Error::InvalidArgument {
        name: name.to_string(),
        detail: detail.into(),
    }
}

/// The instant a local wall time denotes in `tz`, by RFC 5545's rule (see the module docs):
/// an ambiguous time is the earlier instant; a nonexistent one takes the offset in effect
/// before the gap.
pub fn resolve_local(tz: Tz, local: NaiveDateTime) -> DateTime<Tz> {
    match tz.from_local_datetime(&local) {
        LocalResult::Single(dt) => dt,
        LocalResult::Ambiguous(earlier, _) => earlier,
        LocalResult::None => {
            // In a gap. Step back to the last local time that exists, read its offset (the
            // one in effect before the gap) and apply it to the wall time asked for. Gaps in
            // the tz database are at most a day long (Samoa skipped 2011-12-30), so stepping
            // back 15 minutes at a time for 48 hours always leaves the gap.
            let before = (1..=192)
                .map(|step| local - Duration::minutes(15 * step))
                .find_map(|earlier| tz.from_local_datetime(&earlier).earliest())
                .map(|dt| dt.offset().fix());
            match before {
                Some(offset) => tz.from_utc_datetime(&(local - offset)),
                // Unreachable with the bundled database; answer the UTC reading rather than
                // panic in an endpoint.
                None => tz.from_utc_datetime(&local),
            }
        }
    }
}

/// Parse a naive date-time: the shapes `urn:tz:convert` reads, plus RFC 5545's basic form
/// (`19970902T090000`).
fn parse_local(s: &str) -> Option<NaiveDateTime> {
    parse_naive(s).or_else(|| NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%S").ok())
}

/// A time argument in `tz`: RFC 3339 (or RFC 5545's UTC basic form, `19970902T090000Z`)
/// carries its own instant; anything else is a wall time in `tz`.
fn parse_time(raw: &str, tz: Tz, name: &str) -> Result<DateTime<Tz>> {
    let s = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&tz));
    }
    if let Some(utc) = s.strip_suffix('Z') {
        if let Ok(naive) = NaiveDateTime::parse_from_str(utc, "%Y%m%dT%H%M%S") {
            return Ok(Utc.from_utc_datetime(&naive).with_timezone(&tz));
        }
    }
    parse_local(s)
        .map(|naive| resolve_local(tz, naive))
        .ok_or_else(|| {
            invalid(
                name,
                format!(
                    "unparseable date-time `{s}`: want RFC 3339 (2026-09-01T18:00:00-04:00), \
                     RFC 5545 (20260901T180000 or 20260901T220000Z) or a wall time in the zone \
                     (2026-09-01 18:00)"
                ),
            )
        })
}

/// The start as a wall time in `tz`: RFC 5545 repeats DTSTART's LOCAL time, so a wall time
/// is kept exactly as written (even one in a gap, which every occurrence then repeats and
/// [`resolve_local`] places), and an instant (RFC 3339, or RFC 5545's UTC form) is read as
/// the wall time it shows in `tz`.
fn parse_start(raw: &str, tz: Tz) -> Result<NaiveDateTime> {
    let s = raw.trim();
    match parse_local(s) {
        Some(wall) => Ok(wall),
        None => parse_time(s, tz, "start").map(|dt| dt.naive_local()),
    }
}

/// One skipped date: an exact occurrence, or every occurrence on a local date.
enum Skip {
    At(DateTime<Tz>),
    Day(NaiveDate),
}

/// Parse `exdate`: a comma-separated list. A bare date (`2026-12-24` or `20261224`) skips
/// every occurrence on that local date; a date-time skips the occurrence at that instant.
fn parse_skips(raw: &str, tz: Tz) -> Result<Vec<Skip>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            for fmt in ["%Y-%m-%d", "%Y%m%d"] {
                if let Ok(day) = NaiveDate::parse_from_str(s, fmt) {
                    return Ok(Skip::Day(day));
                }
            }
            parse_time(s, tz, "exdate").map(Skip::At)
        })
        .collect()
}

/// Parse the rule: an RRULE value, with or without the `RRULE:` property name.
fn parse_rule(raw: &str) -> Result<RRule<Unvalidated>> {
    let s = raw.trim();
    let value = s
        .get(..6)
        .filter(|head| head.eq_ignore_ascii_case("RRULE:"))
        .map_or(s, |_| &s[6..]);
    if value.contains(['\n', '\r']) {
        return Err(invalid(
            "rule",
            "one RRULE value is expected (FREQ=WEEKLY;BYDAY=TU), not several lines; \
             pass the start as start= and skipped dates as exdate=",
        ));
    }
    value
        .parse::<RRule<Unvalidated>>()
        .map_err(|e| invalid("rule", format!("not an RFC 5545 RRULE: {e}")))
}

/// A wall time as the floating date-time the crate expands: the same fields, in UTC.
fn floating(wall: NaiveDateTime) -> DateTime<rrule::Tz> {
    Utc.from_utc_datetime(&wall).with_timezone(&rrule::Tz::UTC)
}

/// A day of slack on each side of the floating window: a wall time and the instant it is
/// placed at differ by the zone's offset, which is always less than a day.
fn slack() -> Duration {
    Duration::days(1)
}

/// Expand `rule` from the wall time `start` in `tz`, keeping the occurrences `o` with `from <= o < until`
/// that `exdate` does not name, in order. See the [module docs](self) for how wall times
/// are placed.
///
/// Refused with [`Error::InvalidArgument`]: a malformed rule (or one the `rrule` crate's
/// validator rejects), an `UNTIL` that is not UTC, a window that ends before it starts, more
/// than [`MAX_OCCURRENCES`] in the window, or a rule the crate stops expanding at its
/// iteration bound before the window ends (so the list would be incomplete).
pub fn occurrences(
    rule: &str,
    start: NaiveDateTime,
    tz: Tz,
    from: DateTime<Tz>,
    until: DateTime<Tz>,
    exdate: Option<&str>,
) -> Result<Vec<DateTime<Tz>>> {
    if until < from {
        return Err(invalid(
            "until",
            format!("the window ends ({until}) before it starts ({from})"),
        ));
    }
    let skips = exdate
        .map(|e| parse_skips(e, tz))
        .transpose()?
        .unwrap_or_default();
    let mut rule = parse_rule(rule)?;
    // RFC 5545: with a zoned DTSTART, UNTIL is UTC. It bounds the series by instant, so the
    // floating series is bounded a day late and the instant is applied exactly below.
    let rule_until = match rule.get_until().copied() {
        Some(u) if u.timezone().is_local() || u.offset().fix().local_minus_utc() != 0 => {
            return Err(invalid(
                "rule",
                "UNTIL must be a UTC date-time ending in Z (UNTIL=20261231T235959Z): RFC 5545 \
                 requires it when the start has a zone",
            ));
        }
        Some(u) => {
            let u = u.with_timezone(&tz);
            rule = rule.until(floating(u.naive_local() + slack()));
            Some(u)
        }
        None => None,
    };
    let set: RRuleSet = rule
        .build(floating(start))
        .map_err(|e| invalid("rule", e.to_string()))?;
    // `u16::MAX` from the crate, at most `MAX_OCCURRENCES` answered: the floating window's
    // slack days may hold occurrences outside the real one.
    let limit = u16::MAX;
    let result = set
        .after(floating(from.naive_local() - slack()))
        .before(floating(until.naive_local() + slack()))
        .all(limit);
    let mut placed: Vec<DateTime<Tz>> = result
        .dates
        .iter()
        .map(|wall| resolve_local(tz, wall.naive_utc()))
        .collect();
    // Placing is monotone but not strict: a wall time in a gap may land on (or past) a later
    // one, as 02:30 and 03:30 do on a spring-forward day. One occurrence per instant, in order.
    placed.sort();
    placed.dedup();
    let reached_limit = result.dates.len() >= usize::from(limit);
    if reached_limit && placed.last().is_none_or(|last| *last < until) {
        return Err(invalid(
            "until",
            format!(
                "the window holds more than {MAX_OCCURRENCES} occurrences; ask for a shorter one"
            ),
        ));
    }
    // The crate reports `limited` both when it stopped at `limit` (handled above) and when
    // its own iteration bound stopped it early.
    if result.limited && !reached_limit {
        return Err(invalid(
            "rule",
            "the rule found no next occurrence within the rrule crate's iteration bound \
             before the window ended, so the list would be incomplete",
        ));
    }
    let dates: Vec<DateTime<Tz>> = placed
        .into_iter()
        .filter(|dt| from <= *dt && *dt < until)
        .filter(|dt| rule_until.is_none_or(|u| *dt <= u))
        .filter(|dt| {
            !skips.iter().any(|skip| match skip {
                Skip::At(at) => at == dt,
                Skip::Day(day) => dt.date_naive() == *day,
            })
        })
        .collect();
    if dates.len() > MAX_OCCURRENCES {
        return Err(invalid(
            "until",
            format!(
                "the window holds more than {MAX_OCCURRENCES} occurrences; ask for a shorter one"
            ),
        ));
    }
    Ok(dates)
}

/// `urn:tz:expand`: the occurrences of an RRULE in a zone over a window. See the
/// [module docs](self).
pub fn expand() -> FnEndpoint {
    FnEndpoint::new("tz-expand", |inv: &Invocation<'_>| {
        let tz = zone_arg(inv, "zone")?;
        let rule = inv.inline_str("rule")?;
        let start = parse_start(inv.inline_str("start")?, tz)?;
        let from = parse_time(inv.inline_str("from")?, tz, "from")?;
        let until = parse_time(inv.inline_str("until")?, tz, "until")?;
        let exdate = inv.optional_str("exdate")?;
        let dates = occurrences(rule, start, tz, from, until, exdate)?;
        let body: String = dates
            .iter()
            .map(|dt| format!("{}\n", dt.to_rfc3339()))
            .collect();
        Ok(text(body).cacheable())
    })
    .with_description(
        Description::new("tz-expand")
            .title("Recurrence expansion")
            .summary(
                "The occurrences of an RFC 5545 recurrence rule (RRULE, with EXDATE) in an \
                 IANA time zone, over a window: one RFC 3339 instant per line, in the zone, in \
                 order. The rule repeats start's wall time in the zone, so it is DST-correct: \
                 a nonexistent local time takes the offset before the gap and an ambiguous one \
                 is the first. Keeps occurrences at or after from and before until; at most \
                 1000, else refused. Expanded by the rrule crate. Pure and cacheable; open (no \
                 capability).",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("rule")
                    .summary(
                        "an RRULE value, e.g. FREQ=WEEKLY;BYDAY=TU,TH;COUNT=10 (RRULE: optional)",
                    )
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("start")
                    .summary("DTSTART: a wall time in zone (2026-09-01 18:00), or RFC 3339")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("zone")
                    .summary("the IANA zone the rule repeats in, e.g. Europe/Berlin")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("from")
                    .summary("the window's start, inclusive: a wall time in zone, or RFC 3339")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("until")
                    .summary("the window's end, exclusive: a wall time in zone, or RFC 3339")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("exdate")
                    .summary(
                        "skipped dates, comma-separated: a date skips that local day, a \
                         date-time that one occurrence",
                    )
                    .class(XSD_STRING)
                    .optional(),
            )
            .output("text/plain;charset=utf-8"),
    )
}
