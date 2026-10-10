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
//! `convert` is a pure function of its inputs (the tz database is static), so it is
//! cacheable. `now` reads time **through the invocation** ([`read_now`]) — never the OS
//! clock behind the caller's back — so a temporal corridor (`Scope::with_named_at`, the
//! engine's `as-of=`) pins it like any other resolution: cacheable until the next minute
//! under a live clock, [`Expiry::Never`](ikigai_core::Expiry) under a pinned one. Open (no
//! capability) — nothing sensitive, just arithmetic.
//!
//! [`space`] names itself `urn:iki:space:tz` ([`SPACE_ID`]).
#![forbid(unsafe_code)]

use chrono::offset::LocalResult;
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
#[cfg(doc)]
use ikigai_core::Expiry;
use ikigai_core::{
    space_iri, ArgSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, ReprType,
    Representation, Result, Time, Verb,
};

/// The XSD `string` datatype IRI — the `class` of the datetime/zone arguments.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// The name [`space`] claims: `urn:iki:space:tz`.
pub const SPACE_ID: &str = "urn:iki:space:tz";

/// Mount the module: `urn:tz:convert` + `urn:tz:now`, named [`SPACE_ID`].
///
/// Configuration-free (no parameters, nothing read while building it), so every call holds
/// the same two doors and the name is a true claim. `urn:tz:now`'s default zone is the host's
/// local zone, read when it ANSWERS, not here. A host that binds another door onto this space
/// drops the name (core 0.1.89), so an extended copy never answers to `urn:iki:space:tz`.
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:tz:convert"), convert())
        .bind(Exact::new("urn:tz:now"), now())
        .named(space_iri("tz"))
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

/// Where a reading of "now" came from — and so how long anything computed from it may be
/// cached. [`read_now`] answers it; [`fresh`] turns it into an expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NowSource {
    /// A **temporal corridor** pinned the instant: the resolution chain carries the clock
    /// its corridor derived at injection (`Scope::with_named_at` — the engine's `as-of=`).
    /// The answer is a pure function of the corridor's NAME, which the cache already keys
    /// on, so it is cacheable for as long as the name is: [`Expiry::Never`].
    Pinned,
    /// The kernel's own clock (`Kernel::with_clock`): live time, cacheable until the next
    /// minute boundary.
    Live,
    /// Neither — a kernel built with no clock, so the OS clock is read directly. The one
    /// fallback, declared in each description that uses it: nothing can pin this reading,
    /// which is exactly why every other case goes through the invocation.
    Ambient,
}

/// "Now" **as this invocation should see it**, and where that came from.
///
/// [`Invocation::now`] is the seam: it prefers a clock attached to the invocation, then the
/// resolution chain's (a temporal corridor's), then the kernel's — so a pinned corridor pins
/// this read the same way it pins every sub-request that resolves `urn:time:now`. Only when
/// it answers `None` is the OS clock read, and that answer is [`NowSource::Ambient`].
///
/// `Pinned` is decided by the CHAIN carrying a clock, because that is the clock a corridor
/// derived; a clock attached to the invocation itself (`Invocation::with_clock`) outranks it
/// in `now()` and would be reported as pinned too — no endpoint in this workspace attaches one.
pub fn read_now(inv: &Invocation<'_>) -> Result<(DateTime<Utc>, NowSource)> {
    let Some(time) = inv.now() else {
        return Ok((Utc::now(), NowSource::Ambient));
    };
    let source = if inv.scope().clock().is_some() {
        NowSource::Pinned
    } else {
        NowSource::Live
    };
    // `timestamp_millis_opt`, not `DateTime::from_timestamp_millis`: the manifest pins chrono
    // at "0.4", and the TimeZone method is the one every 0.4 release has.
    let instant = i64::try_from(time.as_millis())
        .ok()
        .and_then(|millis| Utc.timestamp_millis_opt(millis).single())
        .ok_or_else(|| {
            Error::Endpoint(format!(
                "the invocation's clock reads {} ms since the epoch, which is not a datetime",
                time.as_millis()
            ))
        })?;
    Ok((instant, source))
}

/// The expiry a reading of "now" earns: [`Expiry::Never`] under a pinned corridor, else the
/// next minute boundary (both endpoints render to the minute or finer, and a minute is the
/// resolution the REPL clock re-renders at).
///
/// ⚠ Under a pin, `cacheable_until(pinned + window)` would be WRONG, not merely short: the
/// kernel judges every `At` deadline on its OWN clock (ledger #517), so a window computed from
/// a pinned past is already expired and one from a pinned future outlives itself. Core's
/// `Invocation::now` documents the wrinkle; as-of data declares `cacheable()`.
pub fn fresh(repr: Representation, now: DateTime<Utc>, source: NowSource) -> Representation {
    match source {
        NowSource::Pinned => repr.cacheable(),
        NowSource::Live | NowSource::Ambient => {
            let next_minute = ((now.timestamp_millis().max(0) as u64) / 60_000 + 1) * 60_000;
            repr.cacheable_until(Time::from_millis(next_minute))
        }
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
///
/// "Current" as the INVOCATION sees it ([`read_now`]): a temporal corridor's pinned instant,
/// else the kernel's clock, else — only on a kernel with no clock at all — the OS clock. The
/// description says so, because an endpoint whose answer a corridor cannot pin would make
/// every as-of resolution that reaches it silently live.
pub fn now() -> FnEndpoint {
    FnEndpoint::new("tz-now", |inv: &Invocation<'_>| {
        let (now, source) = read_now(inv)?;
        let body = match inv.inline_str("zone") {
            Ok(z) => now
                .with_timezone(&parse_zone(z.trim(), "zone")?)
                .to_rfc3339(),
            Err(_) => now.with_timezone(&Local).to_rfc3339(),
        };
        Ok(fresh(text(body), now, source))
    })
    .with_description(
        Description::new("tz-now")
            .title("Zoned clock")
            .summary(
                "The current instant as RFC 3339 in zone=<IANA zone> (default: the host's local \
                 zone) — a full zoned clock (date + time + offset), the companion to \
                 urn:time:now's HH:MM. \"Current\" is the invocation's clock: a temporal \
                 corridor's pinned instant (as-of) when the request carries one — then the \
                 answer is cacheable for as long as the corridor's name — else the kernel's \
                 clock, cacheable until the next minute. Only a kernel with no clock at all \
                 falls back to reading the OS clock, which nothing can pin.",
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
    use ikigai_core::{
        ArgRef, Capability, Endpoint, Expiry, FixedClock, Iri, Kernel, Request, Scope,
    };
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

    // ---- urn:tz:now reads the invocation (ledger #532) ------------------------------------

    /// 2026-09-25T18:00:00Z — the instant a corridor pins.
    const PINNED: u64 = 1_790_359_200_000;
    /// 2026-09-27T12:34:56Z — the kernel's live clock.
    const LIVE: u64 = 1_790_512_496_000;
    /// The next minute boundary after [`LIVE`].
    const LIVE_NEXT_MINUTE: u64 = 1_790_512_500_000;

    fn now_in_utc() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:tz:now").unwrap())
            .with_arg("zone", ArgRef::Inline(b"UTC".to_vec()))
    }

    fn open() -> Capability {
        Capability::scoped(Vec::<String>::new())
    }

    /// The corridor the engine's `as-of=` injects: named for its instant, binding the same
    /// door, carrying the clock derived from that instant.
    ///
    /// The doors go into a FRESH, anonymous space rather than `space()` itself: `space()` is
    /// named `urn:iki:space:tz`, and injecting a named space under a different name panics in
    /// core's `check_claim` (the corridor's name and the space's own must agree). The engine's
    /// `as-of=` builds its corridor the same way, from `ikigai_embedded::time_doors()`.
    fn pinned_at(millis: u64) -> Scope {
        Scope::empty().with_named_at(
            Iri::parse("urn:ctx:time:2026-09-25T18:00:00Z").unwrap(),
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:tz:now"), now())),
            Arc::new(FixedClock::at(millis)),
        )
    }

    #[test]
    fn a_live_clock_reads_the_kernels_time_and_caches_to_the_minute() {
        let kernel = Kernel::new(Arc::new(space())).with_clock(Arc::new(FixedClock::at(LIVE)));
        let rep = block_on(kernel.issue(now_in_utc(), &open())).unwrap();
        assert_eq!(rep.bytes, b"2026-09-27T12:34:56+00:00");
        assert_eq!(rep.expiry, Expiry::At(Time::from_millis(LIVE_NEXT_MINUTE)));
    }

    /// ★ The point of the item: a corridor pins BOTH the answer and its cacheability. The
    /// kernel's clock is live and says otherwise; the chain's clock wins for what the endpoint
    /// computes, and the answer — a pure function of the corridor's name — is `Never`.
    #[test]
    fn a_temporal_corridor_pins_the_answer_and_makes_it_immutable() {
        let kernel = Kernel::new(Arc::new(space())).with_clock(Arc::new(FixedClock::at(LIVE)));
        let rep = block_on(kernel.issue_in(now_in_utc(), &open(), pinned_at(PINNED))).unwrap();
        assert_eq!(rep.bytes, b"2026-09-25T18:00:00+00:00");
        assert_eq!(rep.expiry, Expiry::Never);
        assert!(kernel.is_cached_in(&now_in_utc(), &open(), &pinned_at(PINNED)));
        // The pin is per chain: the root is still live and still to-the-minute.
        let live = block_on(kernel.issue(now_in_utc(), &open())).unwrap();
        assert_eq!(live.bytes, b"2026-09-27T12:34:56+00:00");
        assert!(matches!(live.expiry, Expiry::At(_)));
    }

    /// A corridor pins a door the ROOT binds too: the corridor need not rebind it, because the
    /// root's `urn:tz:now` reads the chain's clock through the invocation. (That is exactly
    /// what calling `Utc::now()` directly made impossible.)
    #[test]
    fn a_corridor_that_binds_nothing_still_pins_the_roots_door() {
        let kernel = Kernel::new(Arc::new(space())).with_clock(Arc::new(FixedClock::at(LIVE)));
        let empty_corridor = Scope::empty().with_named_at(
            Iri::parse("urn:ctx:time:2026-09-25T18:00:00Z").unwrap(),
            Arc::new(EndpointSpace::new()),
            Arc::new(FixedClock::at(PINNED)),
        );
        let rep = block_on(kernel.issue_in(now_in_utc(), &open(), empty_corridor)).unwrap();
        assert_eq!(rep.bytes, b"2026-09-25T18:00:00+00:00");
        assert_eq!(rep.expiry, Expiry::Never);
    }

    /// The declared fallback: a kernel with no clock reads the OS clock, and says it is live.
    #[test]
    fn a_kernel_without_a_clock_falls_back_to_the_os_clock() {
        let before = Utc::now();
        let rep = block_on(Kernel::new(Arc::new(space())).issue(now_in_utc(), &open())).unwrap();
        let read = DateTime::parse_from_rfc3339(std::str::from_utf8(&rep.bytes).unwrap())
            .unwrap()
            .with_timezone(&Utc);
        // RFC 3339 from chrono keeps sub-second digits, so the read is not before `before`
        // truncated to the second.
        assert!(read.timestamp() >= before.timestamp(), "{read} vs {before}");
        assert!(matches!(rep.expiry, Expiry::At(_)));
    }

    /// The description states the fallback — the manifold must not claim a pinnable clock
    /// that is secretly the OS's.
    #[test]
    fn the_description_declares_where_now_comes_from() {
        let summary = now().describe().summary;
        assert!(summary.contains("corridor"), "{summary}");
        assert!(summary.contains("OS clock"), "{summary}");
    }
}
