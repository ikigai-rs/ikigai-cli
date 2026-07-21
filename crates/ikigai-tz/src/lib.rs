//! `ikigai-tz` — timezone conversion as a parameterized transreptor, plus a zoned clock.
//!
//! Two endpoints, backed by the IANA time-zone database (`chrono-tz`), so conversions
//! are **DST- and offset-correct for a real date** — not a fixed integer offset:
//!
//! - [`urn:tz:convert`](convert) — re-represent an instant in another zone. Pass a
//!   datetime as `in` (or piped `content`) and the target IANA zone as `to=`; the
//!   result is the SAME instant rendered in that zone (RFC 3339). An RFC-3339 input
//!   carries its own offset; a *naive* datetime needs `from=<zone>` to fix the instant.
//!   Parameterized (the zone is an argument), like the JSON-LD / XSLT transreptors.
//! - [`urn:tz:now`](now) — the current instant as RFC 3339 in `zone=<IANA>` (default:
//!   the host's local zone). A full *zoned* clock (date + time + offset), the companion
//!   to `urn:time:now`'s bare `HH:MM`.
//!
//! Both are pure functions of their inputs (the tz database is static), so `convert`
//! is cacheable and `now` is cacheable until the next minute. Open (no capability) —
//! nothing sensitive, just arithmetic.
#![forbid(unsafe_code)]

use chrono::offset::LocalResult;
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use ikigai_core::{
    ArgSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, ReprType,
    Representation, Result, Time, Verb,
};

/// The XSD `string` datatype IRI — the `class` of the datetime/zone arguments.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// Mount the module: `urn:tz:convert` + `urn:tz:now`.
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:tz:convert"), convert())
        .bind(Exact::new("urn:tz:now"), now())
}

/// A `text/plain; charset=utf-8` representation.
fn text(body: String) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.into_bytes(),
    )
}

/// Parse an IANA zone name from a required argument.
fn zone_arg(inv: &Invocation<'_>, name: &'static str) -> Result<Tz> {
    let raw = inv
        .inline_str(name)
        .map_err(|_| Error::MissingArgument(name.to_string()))?;
    parse_zone(raw.trim(), name)
}

/// Parse an IANA zone name (e.g. `America/New_York`, `UTC`), or a typed error.
fn parse_zone(raw: &str, name: &'static str) -> Result<Tz> {
    raw.parse::<Tz>().map_err(|_| Error::InvalidArgument {
        name: name.to_string(),
        detail: format!("unknown IANA time zone `{raw}` (e.g. America/New_York, UTC)"),
    })
}

/// Parse a naive datetime (no offset) in a few common shapes.
fn parse_naive(s: &str) -> Option<NaiveDateTime> {
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    // A bare date → midnight.
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
}

/// Fix the instant an input denotes: an RFC-3339 string carries its own offset; a naive
/// datetime is interpreted in the `from=` zone (required, DST-aware).
fn to_instant(s: &str, inv: &Invocation<'_>) -> Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    let naive = parse_naive(s).ok_or_else(|| Error::InvalidArgument {
        name: "in".to_string(),
        detail: format!(
            "unparseable datetime `{s}` — want RFC 3339 (2026-07-21T12:00:00-04:00) \
             or a naive datetime with from=<zone>"
        ),
    })?;
    let from = zone_arg(inv, "from")?;
    match from.from_local_datetime(&naive) {
        LocalResult::Single(dt) => Ok(dt.with_timezone(&Utc)),
        // DST fall-back overlap: two valid instants — take the earlier, deterministically.
        LocalResult::Ambiguous(earlier, _later) => Ok(earlier.with_timezone(&Utc)),
        LocalResult::None => Err(Error::InvalidArgument {
            name: "in".to_string(),
            detail: format!("`{s}` is in a DST spring-forward gap in the from zone"),
        }),
    }
}

/// `urn:tz:convert` — re-represent an instant in the `to=` zone. See the [module docs](crate).
pub fn convert() -> FnEndpoint {
    FnEndpoint::new("tz-convert", |inv: &Invocation<'_>| {
        let input = inv
            .inline_str("in")
            .or_else(|_| inv.inline_str("content"))
            .map_err(|_| {
                Error::Endpoint(
                    "urn:tz:convert: pass the datetime as `in` (or piped `content`)".to_string(),
                )
            })?;
        let to = zone_arg(inv, "to")?;
        let instant = to_instant(input.trim(), inv)?;
        Ok(text(instant.with_timezone(&to).to_rfc3339()).cacheable())
    })
    .with_description(
        Description::new("tz-convert")
            .title("Timezone convert")
            .summary(
                "Re-represent a datetime in another IANA time zone, DST- and offset-correct. \
                 Pass the datetime as `in` (RFC 3339 carries its own offset; a naive datetime \
                 needs from=<zone>) and the target zone as to=<IANA zone>. Output is RFC 3339 \
                 in the target zone. Pure and cacheable; open (no capability).",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("in")
                    .summary("the datetime — RFC 3339, or a naive datetime with from=")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("to")
                    .summary("target IANA zone, e.g. America/Los_Angeles")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("from")
                    .summary("source IANA zone — required only for a naive `in`")
                    .class(XSD_STRING)
                    .optional(),
            )
            .output("text/plain;charset=utf-8"),
    )
}

/// `urn:tz:now` — the current instant as RFC 3339 in `zone=` (default: host local).
pub fn now() -> FnEndpoint {
    FnEndpoint::new("tz-now", |inv: &Invocation<'_>| {
        let now = Utc::now();
        let body = match inv.inline_str("zone") {
            Ok(z) => now
                .with_timezone(&parse_zone(z.trim(), "zone")?)
                .to_rfc3339(),
            Err(_) => now.with_timezone(&Local).to_rfc3339(),
        };
        let next_minute = ((now.timestamp_millis().max(0) as u64) / 60_000 + 1) * 60_000;
        Ok(text(body).cacheable_until(Time::from_millis(next_minute)))
    })
    .with_description(
        Description::new("tz-now")
            .title("Zoned clock")
            .summary(
                "The current instant as RFC 3339 in zone=<IANA zone> (default: the host's local \
                 zone) — a full zoned clock (date + time + offset), the companion to \
                 urn:time:now's HH:MM. Cacheable until the next minute.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("zone")
                    .summary("IANA zone, e.g. Europe/London (default: the host's local zone)")
                    .class(XSD_STRING)
                    .optional(),
            )
            .output("text/plain;charset=utf-8"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use std::sync::Arc;

    /// Convert `input` with the given args through a real kernel; return the body text.
    fn convert_ok(input: &str, args: &[(&str, &str)]) -> String {
        let kernel = Kernel::new(Arc::new(space()));
        let mut req = Request::new(Verb::Source, Iri::parse("urn:tz:convert").unwrap())
            .with_arg("in", ArgRef::Inline(input.as_bytes().to_vec()));
        for (k, v) in args {
            req = req.with_arg(*k, ArgRef::Inline(v.as_bytes().to_vec()));
        }
        let rep = block_on(kernel.issue(req, &Capability::scoped(Vec::<String>::new()))).unwrap();
        String::from_utf8(rep.bytes).unwrap()
    }

    fn convert_err(input: &str, args: &[(&str, &str)]) -> bool {
        let kernel = Kernel::new(Arc::new(space()));
        let mut req = Request::new(Verb::Source, Iri::parse("urn:tz:convert").unwrap())
            .with_arg("in", ArgRef::Inline(input.as_bytes().to_vec()));
        for (k, v) in args {
            req = req.with_arg(*k, ArgRef::Inline(v.as_bytes().to_vec()));
        }
        block_on(kernel.issue(req, &Capability::scoped(Vec::<String>::new()))).is_err()
    }

    #[test]
    fn rfc3339_input_converts_to_target_zone() {
        // NY noon EDT → LA 9am PDT — the same instant.
        assert_eq!(
            convert_ok(
                "2026-07-21T12:00:00-04:00",
                &[("to", "America/Los_Angeles")]
            ),
            "2026-07-21T09:00:00-07:00"
        );
    }

    #[test]
    fn naive_input_uses_the_from_zone() {
        assert_eq!(
            convert_ok(
                "2026-07-21 12:00",
                &[("from", "America/New_York"), ("to", "America/Los_Angeles")]
            ),
            "2026-07-21T09:00:00-07:00"
        );
    }

    #[test]
    fn dst_is_honoured_the_offset_depends_on_the_date() {
        // THE POINT: same wall-clock, NY zone, → UTC. Winter EST(-5)→17:00Z; summer EDT(-4)→16:00Z.
        assert_eq!(
            convert_ok(
                "2026-01-15 12:00",
                &[("from", "America/New_York"), ("to", "UTC")]
            ),
            "2026-01-15T17:00:00+00:00"
        );
        assert_eq!(
            convert_ok(
                "2026-07-15 12:00",
                &[("from", "America/New_York"), ("to", "UTC")]
            ),
            "2026-07-15T16:00:00+00:00"
        );
    }

    #[test]
    fn the_day_rolls_across_the_date_line() {
        // NY 8pm EDT → Tokyo next-day 9am.
        assert_eq!(
            convert_ok("2026-07-21T20:00:00-04:00", &[("to", "Asia/Tokyo")]),
            "2026-07-22T09:00:00+09:00"
        );
    }

    #[test]
    fn a_half_hour_zone_is_exact() {
        // India is UTC+5:30 — the whole-hour model couldn't express this; chrono-tz can.
        assert_eq!(
            convert_ok("2026-07-21T12:00:00+00:00", &[("to", "Asia/Kolkata")]),
            "2026-07-21T17:30:00+05:30"
        );
    }

    #[test]
    fn an_unknown_zone_is_an_error() {
        assert!(convert_err(
            "2026-07-21T12:00:00-04:00",
            &[("to", "Mars/Olympus")]
        ));
    }

    #[test]
    fn a_naive_input_without_from_is_an_error() {
        assert!(convert_err("2026-07-21 12:00", &[("to", "UTC")]));
    }
}
