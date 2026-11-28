//! `urn:tz:expand` (ledger #4517) through a real kernel: RFC 5545's own examples (section
//! 3.8.5.3, all in `America/New_York`, several across the 1997 and 1998 DST changes), EXDATE,
//! the DST boundaries of 2026 in New York and Berlin, Sydney's southern-hemisphere ones and
//! Santiago's change at midnight; then cacheability and the refusals.

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Expiry, Iri, Kernel, Request, Result, Verb};
use std::sync::Arc;

const NY: &str = "America/New_York";
const BERLIN: &str = "Europe/Berlin";

/// Issue `urn:tz:expand` with `args` through a kernel over `space()`.
fn issue(args: &[(&str, &str)]) -> Result<ikigai_core::Representation> {
    #[allow(clippy::disallowed_methods)]
    // internal: a test fixture's kernel; it routes no user arguments
    let kernel = Kernel::new(Arc::new(ikigai_tz::space()));
    let mut request = Request::new(Verb::Source, Iri::parse("urn:tz:expand").unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    block_on(kernel.issue(request, &Capability::scoped(Vec::<String>::new())))
}

/// The occurrences, one per line, of `rule` from `start` in `zone` over `[from, until)`.
fn expand(rule: &str, start: &str, zone: &str, from: &str, until: &str) -> Vec<String> {
    lines(issue(&[
        ("rule", rule),
        ("start", start),
        ("zone", zone),
        ("from", from),
        ("until", until),
    ]))
}

fn expand_skipping(
    rule: &str,
    start: &str,
    zone: &str,
    window: (&str, &str),
    exdate: &str,
) -> Vec<String> {
    lines(issue(&[
        ("rule", rule),
        ("start", start),
        ("zone", zone),
        ("from", window.0),
        ("until", window.1),
        ("exdate", exdate),
    ]))
}

fn lines(result: Result<ikigai_core::Representation>) -> Vec<String> {
    let rep = result.expect("expands");
    String::from_utf8(rep.bytes)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// RFC 5545's 1997 examples: a whole window around them, so only the rule bounds the series.
const WINDOW_1997: (&str, &str) = ("1997-01-01 00:00", "1999-01-01 00:00");

fn rfc(rule: &str, start: &str) -> Vec<String> {
    expand(rule, start, NY, WINDOW_1997.0, WINDOW_1997.1)
}

/// `dates` at `time` with `offset`, e.g. `at("1997-09-", &["02", "03"], "09:00", "-04:00")`.
fn at(prefix: &str, days: &[&str], time: &str, offset: &str) -> Vec<String> {
    days.iter()
        .map(|day| format!("{prefix}{day}T{time}:00{offset}"))
        .collect()
}

// ---- RFC 5545, section 3.8.5.3 ---------------------------------------------------------

/// "Daily for 10 occurrences": DTSTART;TZID=America/New_York:19970902T090000,
/// RRULE:FREQ=DAILY;COUNT=10 → (1997 9:00 AM EDT) September 2-11.
#[test]
fn rfc_daily_for_ten_occurrences() {
    assert_eq!(
        rfc("FREQ=DAILY;COUNT=10", "19970902T090000"),
        at(
            "1997-09-",
            &["02", "03", "04", "05", "06", "07", "08", "09", "10", "11"],
            "09:00",
            "-04:00"
        )
    );
}

/// "Daily until December 24, 1997": RRULE:FREQ=DAILY;UNTIL=19971224T000000Z → (1997 9:00 AM
/// EDT) September 2-30; October 1-25, then (1997 9:00 AM EST) October 26-31; November 1-30;
/// December 1-23. The wall time holds across the change of October 26; the instant moves.
#[test]
fn rfc_daily_until_december_24_keeps_nine_am_across_the_october_change() {
    let got = rfc("FREQ=DAILY;UNTIL=19971224T000000Z", "19970902T090000");
    assert_eq!(got.len(), 29 + 31 + 30 + 23, "{got:?}");
    assert_eq!(got.first().unwrap(), "1997-09-02T09:00:00-04:00");
    assert!(got.contains(&"1997-10-25T09:00:00-04:00".to_string()));
    assert!(got.contains(&"1997-10-26T09:00:00-05:00".to_string()));
    assert_eq!(got.last().unwrap(), "1997-12-23T09:00:00-05:00");
    assert!(got.iter().all(|o| o.contains("T09:00:00-0")), "{got:?}");
}

/// "Weekly on Tuesday and Thursday for five weeks":
/// RRULE:FREQ=WEEKLY;UNTIL=19971007T000000Z;WKST=SU;BYDAY=TU,TH and the COUNT=10 form, the
/// same ten dates: (1997 9:00 AM EDT) September 2,4,9,11,16,18,23,25,30; October 2.
#[test]
fn rfc_weekly_on_tuesday_and_thursday_for_five_weeks() {
    let want: Vec<String> = at(
        "1997-09-",
        &["02", "04", "09", "11", "16", "18", "23", "25", "30"],
        "09:00",
        "-04:00",
    )
    .into_iter()
    .chain(at("1997-10-", &["02"], "09:00", "-04:00"))
    .collect();
    assert_eq!(
        rfc(
            "FREQ=WEEKLY;UNTIL=19971007T000000Z;WKST=SU;BYDAY=TU,TH",
            "19970902T090000"
        ),
        want
    );
    assert_eq!(
        rfc(
            "FREQ=WEEKLY;COUNT=10;WKST=SU;BYDAY=TU,TH",
            "19970902T090000"
        ),
        want
    );
}

/// "Every other week on Monday, Wednesday, and Friday until December 24, 1997, starting on
/// Monday, September 1, 1997": 25 occurrences, the last eleven in EST.
#[test]
fn rfc_every_other_week_monday_wednesday_friday() {
    let want: Vec<String> = [
        at(
            "1997-09-",
            &["01", "03", "05", "15", "17", "19", "29"],
            "09:00",
            "-04:00",
        ),
        at(
            "1997-10-",
            &["01", "03", "13", "15", "17"],
            "09:00",
            "-04:00",
        ),
        at("1997-10-", &["27", "29", "31"], "09:00", "-05:00"),
        at(
            "1997-11-",
            &["10", "12", "14", "24", "26", "28"],
            "09:00",
            "-05:00",
        ),
        at("1997-12-", &["08", "10", "12", "22"], "09:00", "-05:00"),
    ]
    .concat();
    assert_eq!(
        rfc(
            "RRULE:FREQ=WEEKLY;INTERVAL=2;UNTIL=19971224T000000Z;WKST=SU;BYDAY=MO,WE,FR",
            "19970901T090000"
        ),
        want
    );
}

/// "Monthly on the first Friday for 10 occurrences": both changes of the series, 1997's fall
/// back and 1998's spring forward (April 5, after the April 3 occurrence).
#[test]
fn rfc_monthly_on_the_first_friday_crosses_both_changes() {
    let want: Vec<String> = [
        at("1997-", &["09-05", "10-03"], "09:00", "-04:00"),
        at("1997-", &["11-07", "12-05"], "09:00", "-05:00"),
        at(
            "1998-",
            &["01-02", "02-06", "03-06", "04-03"],
            "09:00",
            "-05:00",
        ),
        at("1998-", &["05-01", "06-05"], "09:00", "-04:00"),
    ]
    .concat();
    assert_eq!(
        rfc("FREQ=MONTHLY;COUNT=10;BYDAY=1FR", "19970905T090000"),
        want
    );
}

/// "Monthly on the second-to-last Monday of the month for 6 months".
#[test]
fn rfc_monthly_on_the_second_to_last_monday() {
    let want: Vec<String> = [
        at("1997-", &["09-22", "10-20"], "09:00", "-04:00"),
        at("1997-", &["11-17", "12-22"], "09:00", "-05:00"),
        at("1998-", &["01-19", "02-16"], "09:00", "-05:00"),
    ]
    .concat();
    assert_eq!(
        rfc("FREQ=MONTHLY;COUNT=6;BYDAY=-2MO", "19970922T090000"),
        want
    );
}

/// "Every Friday the 13th, forever", with the RFC's EXDATE of the start itself
/// (EXDATE;TZID=America/New_York:19970902T090000): the window bounds a rule with no end.
#[test]
fn rfc_every_friday_the_thirteenth_with_the_start_excluded() {
    let got = expand_skipping(
        "FREQ=MONTHLY;BYDAY=FR;BYMONTHDAY=13",
        "19970902T090000",
        NY,
        ("1997-01-01 00:00", "2000-11-01 00:00"),
        "19970902T090000",
    );
    let want: Vec<String> = [
        at("1998-", &["02-13", "03-13"], "09:00", "-05:00"),
        at("1998-", &["11-13"], "09:00", "-05:00"),
        at("1999-", &["08-13"], "09:00", "-04:00"),
        at("2000-", &["10-13"], "09:00", "-04:00"),
    ]
    .concat();
    assert_eq!(got, want);
}

// ---- EXDATE --------------------------------------------------------------------------

/// A skipped date: a bare date skips every occurrence that local day; a wall time, an RFC
/// 5545 UTC time and an RFC 3339 instant each skip the one occurrence at that instant.
#[test]
fn exdate_skips_days_and_single_occurrences() {
    let got = expand_skipping(
        "FREQ=WEEKLY;COUNT=10;WKST=SU;BYDAY=TU,TH",
        "1997-09-02 09:00",
        NY,
        WINDOW_1997,
        "1997-09-09, 1997-09-11 09:00,19970916T130000Z,1997-09-18T09:00:00-04:00",
    );
    let want: Vec<String> = [
        at(
            "1997-09-",
            &["02", "04", "23", "25", "30"],
            "09:00",
            "-04:00",
        ),
        at("1997-10-", &["02"], "09:00", "-04:00"),
    ]
    .concat();
    assert_eq!(got, want);
}

/// An EXDATE naming a time no occurrence has skips nothing (EXDATE removes; it never moves).
#[test]
fn an_exdate_off_the_series_skips_nothing() {
    let got = expand_skipping(
        "FREQ=DAILY;COUNT=3",
        "2026-09-01 18:00",
        BERLIN,
        ("2026-09-01", "2026-10-01"),
        "2026-09-02 18:30",
    );
    assert_eq!(got.len(), 3, "{got:?}");
}

// ---- DST boundaries, 2026 ----------------------------------------------------------------

/// A weekly evening class in New York across November 1, 2026: the same 18:00 on the wall,
/// an hour later in UTC once standard time returns.
#[test]
fn new_york_weekly_class_keeps_its_wall_time_across_the_fall_change() {
    assert_eq!(
        expand(
            "FREQ=WEEKLY;BYDAY=TU",
            "2026-10-20 18:00",
            NY,
            "2026-10-01 00:00",
            "2026-11-11 00:00"
        ),
        [
            at("2026-10-", &["20", "27"], "18:00", "-04:00"),
            at("2026-11-", &["03", "10"], "18:00", "-05:00"),
        ]
        .concat()
    );
}

/// New York's spring gap (2026-03-08, 02:00 → 03:00): a daily 02:30 that does not exist that
/// day is read with the offset before the gap, 03:30 EDT (RFC 5545, 3.3.5), and the days
/// around it keep 02:30. An EXDATE of 02:30 that day, as a wall time, names that instant.
#[test]
fn new_york_spring_gap_takes_the_offset_before_it() {
    let rule = "FREQ=DAILY";
    let window = ("2026-03-07 00:00", "2026-03-10 00:00");
    assert_eq!(
        expand(rule, "2026-03-01 02:30", NY, window.0, window.1),
        [
            "2026-03-07T02:30:00-05:00",
            "2026-03-08T03:30:00-04:00",
            "2026-03-09T02:30:00-04:00"
        ]
    );
    assert_eq!(
        expand_skipping(rule, "2026-03-01 02:30", NY, window, "2026-03-08 02:30"),
        ["2026-03-07T02:30:00-05:00", "2026-03-09T02:30:00-04:00"]
    );
}

/// New York's fall overlap (2026-11-01, 01:00-02:00 twice): a daily 01:30 is the FIRST
/// 01:30 (EDT), once.
#[test]
fn new_york_fall_overlap_is_the_first_of_the_two() {
    assert_eq!(
        expand(
            "FREQ=DAILY",
            "2026-10-25 01:30",
            NY,
            "2026-10-31 00:00",
            "2026-11-03 00:00"
        ),
        [
            "2026-10-31T01:30:00-04:00",
            "2026-11-01T01:30:00-04:00",
            "2026-11-02T01:30:00-05:00"
        ]
    );
}

/// Berlin's spring change (2026-03-29): a Monday class at 18:00 moves from 17:00Z to 16:00Z;
/// a daily 02:30 in the gap is 03:30 CEST.
#[test]
fn berlin_spring_change_and_gap() {
    assert_eq!(
        expand(
            "FREQ=WEEKLY;BYDAY=MO;COUNT=3",
            "2026-03-23 18:00",
            BERLIN,
            "2026-03-01",
            "2026-05-01"
        ),
        [
            "2026-03-23T18:00:00+01:00",
            "2026-03-30T18:00:00+02:00",
            "2026-04-06T18:00:00+02:00"
        ]
    );
    assert_eq!(
        expand(
            "FREQ=DAILY;COUNT=3",
            "2026-03-28 02:30",
            BERLIN,
            "2026-03-01",
            "2026-05-01"
        ),
        [
            "2026-03-28T02:30:00+01:00",
            "2026-03-29T03:30:00+02:00",
            "2026-03-30T02:30:00+02:00"
        ]
    );
}

/// Berlin's fall overlap (2026-10-25, 02:00-03:00 twice): 02:30 is the first, CEST.
#[test]
fn berlin_fall_overlap_is_the_first_of_the_two() {
    assert_eq!(
        expand(
            "FREQ=DAILY;COUNT=3",
            "2026-10-24 02:30",
            BERLIN,
            "2026-10-01",
            "2026-11-01"
        ),
        [
            "2026-10-24T02:30:00+02:00",
            "2026-10-25T02:30:00+02:00",
            "2026-10-26T02:30:00+01:00"
        ]
    );
}

/// The window is in instants, so the same window asked in another zone's terms selects the
/// same occurrences: `from` inclusive, `until` exclusive.
#[test]
fn the_window_is_inclusive_then_exclusive_in_instants() {
    let rule = "FREQ=DAILY";
    let start = "2026-03-28 18:00";
    // 2026-03-29T18:00+02:00 is 16:00Z; 2026-03-31T18:00+02:00 is 16:00Z.
    assert_eq!(
        expand(
            rule,
            start,
            BERLIN,
            "2026-03-29T16:00:00Z",
            "2026-03-31T16:00:00Z"
        ),
        ["2026-03-29T18:00:00+02:00", "2026-03-30T18:00:00+02:00"]
    );
    assert!(expand(rule, start, BERLIN, "2026-01-01", "2026-03-01").is_empty());
}

/// The southern hemisphere: Sydney leaves daylight time on 2026-04-05 and enters it on
/// 2026-10-04, so a Wednesday 19:00 class is +11:00, then +10:00, then +11:00 again.
#[test]
fn sydney_changes_the_other_way_round() {
    let got = expand(
        "FREQ=WEEKLY;BYDAY=WE",
        "2026-04-01 19:00",
        "Australia/Sydney",
        "2026-04-01",
        "2026-10-15",
    );
    assert_eq!(got.first().unwrap(), "2026-04-01T19:00:00+11:00");
    assert!(got.contains(&"2026-04-08T19:00:00+10:00".to_string()));
    assert!(got.contains(&"2026-09-30T19:00:00+10:00".to_string()));
    assert_eq!(got.last().unwrap(), "2026-10-14T19:00:00+11:00");
}

/// Santiago changes at midnight (2026-09-06 00:00 → 01:00). A daily 00:30 that day does not
/// exist; it is 00:30 with the offset before the gap (-04:00), so 01:30 -03:00, and the series
/// keeps all three days. (The rrule crate's own placement drops it: see the module docs.)
#[test]
fn santiago_midnight_gap_keeps_the_occurrence() {
    assert_eq!(
        expand(
            "FREQ=DAILY;COUNT=3",
            "2026-09-05 00:30",
            "America/Santiago",
            "2026-09-01",
            "2026-10-01"
        ),
        [
            "2026-09-05T00:30:00-04:00",
            "2026-09-06T01:30:00-03:00",
            "2026-09-07T00:30:00-03:00"
        ]
    );
}

// ---- the answer --------------------------------------------------------------------------

/// A pure function of its arguments: cacheable for good, plain text, one line per occurrence.
#[test]
fn the_answer_is_cacheable_text() {
    let rep = issue(&[
        ("rule", "FREQ=DAILY;COUNT=2"),
        ("start", "2026-09-01 18:00"),
        ("zone", BERLIN),
        ("from", "2026-09-01"),
        ("until", "2026-10-01"),
    ])
    .unwrap();
    assert_eq!(rep.expiry, Expiry::Never);
    assert_eq!(rep.repr_type.to_string(), "text/plain;charset=utf-8");
    assert_eq!(
        rep.bytes,
        b"2026-09-01T18:00:00+02:00\n2026-09-02T18:00:00+02:00\n"
    );
}

// ---- refusals ----------------------------------------------------------------------------

fn refused(args: &[(&str, &str)]) -> (String, String) {
    match issue(args) {
        Err(Error::InvalidArgument { name, detail }) => (name, detail),
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

fn args<'a>(
    rule: &'a str,
    start: &'a str,
    from: &'a str,
    until: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("rule", rule),
        ("start", start),
        ("zone", NY),
        ("from", from),
        ("until", until),
    ]
}

#[test]
fn a_malformed_rule_is_invalid() {
    for rule in ["FREQ=FORTNIGHTLY", "BYDAY=TU", "FREQ=WEEKLY;BYDAY=XX", ""] {
        let (name, _) = refused(&args(rule, "2026-09-01 18:00", "2026-09-01", "2026-10-01"));
        assert_eq!(name, "rule", "{rule}");
    }
}

#[test]
fn several_lines_are_refused_with_where_each_part_goes() {
    let (name, detail) = refused(&args(
        "RRULE:FREQ=DAILY\nEXDATE:20260902T180000",
        "2026-09-01 18:00",
        "2026-09-01",
        "2026-10-01",
    ));
    assert_eq!(name, "rule");
    assert!(detail.contains("exdate="), "{detail}");
}

/// RFC 5545: with a zoned start, UNTIL is UTC. A Z-less UNTIL would otherwise be read in the
/// host's own zone, so the same request would answer differently on two hosts.
#[test]
fn a_local_until_is_refused() {
    let (name, detail) = refused(&args(
        "FREQ=DAILY;UNTIL=20260910T000000",
        "2026-09-01 18:00",
        "2026-09-01",
        "2026-10-01",
    ));
    assert_eq!(name, "rule");
    assert!(detail.contains("UTC"), "{detail}");
}

#[test]
fn an_unknown_zone_or_an_unparseable_time_is_invalid() {
    let mut bad_zone = args("FREQ=DAILY", "2026-09-01 18:00", "2026-09-01", "2026-10-01");
    bad_zone[2] = ("zone", "Mars/Olympus");
    assert_eq!(refused(&bad_zone).0, "zone");
    for (name, index) in [("start", 1), ("from", 3), ("until", 4)] {
        let mut bad = args("FREQ=DAILY", "2026-09-01 18:00", "2026-09-01", "2026-10-01");
        bad[index] = (name, "next tuesday");
        assert_eq!(refused(&bad).0, name);
    }
    let mut bad_skip = args("FREQ=DAILY", "2026-09-01 18:00", "2026-09-01", "2026-10-01");
    bad_skip.push(("exdate", "2026-09-02,soon"));
    assert_eq!(refused(&bad_skip).0, "exdate");
}

#[test]
fn a_window_that_ends_before_it_starts_is_invalid() {
    let (name, _) = refused(&args(
        "FREQ=DAILY",
        "2026-09-01 18:00",
        "2026-10-01",
        "2026-09-01",
    ));
    assert_eq!(name, "until");
}

/// More than the cap is refused, never cut short; exactly the cap is answered.
#[test]
fn a_window_over_the_cap_is_refused_and_the_cap_itself_is_answered() {
    let (name, detail) = refused(&args(
        "FREQ=MINUTELY",
        "2026-09-01 00:00",
        "2026-09-01 00:00",
        "2026-09-02 00:00",
    ));
    assert_eq!(name, "until");
    assert!(detail.contains("1000"), "{detail}");
    let exactly = expand(
        "FREQ=MINUTELY",
        "2026-09-01 00:00",
        NY,
        "2026-09-01 00:00",
        "2026-09-01 16:40",
    );
    assert_eq!(exactly.len(), ikigai_tz::expand::MAX_OCCURRENCES);
}

#[test]
fn missing_arguments_are_typed() {
    for missing in ["rule", "start", "zone", "from", "until"] {
        let all = args("FREQ=DAILY", "2026-09-01 18:00", "2026-09-01", "2026-10-01");
        let without: Vec<_> = all.into_iter().filter(|(n, _)| *n != missing).collect();
        match issue(&without) {
            Err(Error::MissingArgument(name)) => assert_eq!(name, missing),
            other => panic!("expected MissingArgument({missing}), got {other:?}"),
        }
    }
}
