//! Per-SOURCE rate limits at the door (ledger #1717, threat model S1 gap 1).
//!
//! A public door's anonymous writes (a contact form, a booking request) each cost something
//! real downstream, an email to a person, so one client must not be able to send them as fast
//! as it can type `curl`. The limit is keyed on WHO is asking, and only this door knows that:
//! the connection's peer, or, behind a proxy this door trusts, the hop that proxy appended to
//! `X-Forwarded-For` (see `client_ip`). Nothing below the transport sees an address, which is
//! why this lives here and not in a kernel overlay.
//!
//! ★ Why not `ikigai_throttle::RateLimit`. That overlay keys a window on a URI PREFIX alone,
//! with one shared window per prefix: on a public intake it would let one client spend
//! everyone's budget, and the honest visitors would be the ones refused. Its refusal is also an
//! untyped `Error::Endpoint` string with no retry hint a door could turn into `Retry-After`.
//! The window arithmetic is the same (a sliding log of instants, at most `max` long).
//!
//! The limiter's own memory is bounded: at most [`DEFAULT_MAX_SOURCES`] (or the configured
//! number of) source windows are tracked at once. Windows that have emptied are reclaimed
//! first; past the bound a NEW source is refused, never let through untracked, so the limit
//! cannot be outrun by spreading a flood over more addresses than the table holds, and an
//! unbounded map is not traded for another one.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many (rule, source) windows a [`SourceLimits`] tracks at once unless told otherwise.
/// Each holds at most its rule's `max` instants, so 4096 windows of a ten-request rule is
/// well under a megabyte.
pub const DEFAULT_MAX_SOURCES: usize = 4096;

/// One rule: at most `max` requests per `window` from ONE source to any resource whose IRI
/// begins with `prefix`. Every verb counts (a read of a challenge as much as a form's write);
/// `OPTIONS` and the `?description` face never reach the limiter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRate {
    /// The IRI prefix the rule governs, e.g. `urn:contact:submit`. Longest prefix wins.
    pub prefix: String,
    /// The most requests one source may make within `window`. At least 1.
    pub max: u32,
    /// The sliding window.
    pub window: Duration,
}

impl SourceRate {
    /// `max` requests per `window` from one source, to IRIs beginning with `prefix`.
    pub fn new(prefix: impl Into<String>, max: u32, window: Duration) -> Self {
        SourceRate {
            prefix: prefix.into(),
            max,
            window,
        }
    }
}

/// A door's per-source rate limits: a set of [`SourceRate`] rules and the windows they keep.
/// Set it as [`EdgeConfig::source_limits`](crate::EdgeConfig::source_limits).
///
/// A request past its rule's budget is answered `429 Too Many Requests` with `Retry-After`
/// (whole seconds until the source's oldest counted request ages out), before the resource is
/// invoked. The body is a sentence beginning `rate-limited:` (a page for a browser), or, with
/// [`ErrorBody::Json`](crate::ErrorBody::Json), `{"kind":"rate-limited","message":…,
/// "retry_after":…}`.
///
/// Clones share their windows, so a host that serves one config on two listeners keeps one
/// budget per source across both.
///
/// ```
/// use ikigai_web::{SourceLimits, SourceRate};
/// use std::time::Duration;
///
/// let limits = SourceLimits::new(vec![
///     SourceRate::new("urn:contact:submit", 10, Duration::from_secs(3600)),
///     SourceRate::new("urn:booking:submit", 10, Duration::from_secs(3600)),
/// ])
/// .max_sources(1024);
/// assert_eq!(limits.rules().len(), 2);
/// ```
#[derive(Clone)]
pub struct SourceLimits {
    rules: Vec<SourceRate>,
    max_sources: usize,
    windows: Windows,
}

/// Each (rule index, source key) window: the instants of the requests it counted, oldest first.
type Windows = Arc<Mutex<HashMap<(usize, String), VecDeque<Instant>>>>;

/// Why a request was refused, and when the source may try again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Limited {
    pub(crate) rule: SourceRate,
    pub(crate) retry_after: Duration,
    /// True when the refusal is the limiter's own table being full, not this source's budget.
    pub(crate) table_full: bool,
}

impl Limited {
    /// Whole seconds for `Retry-After`: rounded UP, and never 0 (a client told 0 retries
    /// straight into the same refusal).
    pub(crate) fn retry_after_secs(&self) -> u64 {
        let d = self.retry_after;
        (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
    }

    /// The sentence the refused client is told.
    pub(crate) fn message(&self) -> String {
        let rule = &self.rule;
        if self.table_full {
            format!(
                "rate-limited: this door is tracking as many clients as it can for `{}`; \
                 retry after {}s",
                rule.prefix,
                self.retry_after_secs()
            )
        } else {
            format!(
                "rate-limited: `{}` takes at most {} request(s) per {}s from one client; \
                 retry after {}s",
                rule.prefix,
                rule.max,
                rule.window.as_secs().max(1),
                self.retry_after_secs()
            )
        }
    }
}

impl SourceLimits {
    /// Limits with these rules, tracking at most [`DEFAULT_MAX_SOURCES`] windows. A rule with
    /// `max` 0 refuses every request it governs.
    pub fn new(mut rules: Vec<SourceRate>) -> Self {
        // Longest prefix first, so the first match is the most specific.
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.prefix.len()));
        SourceLimits {
            rules,
            max_sources: DEFAULT_MAX_SOURCES,
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Track at most `n` (rule, source) windows at once (builder). `0` refuses every governed
    /// request, since no window can be kept.
    pub fn max_sources(mut self, n: usize) -> Self {
        self.max_sources = n;
        self
    }

    /// The rules, most specific first.
    pub fn rules(&self) -> &[SourceRate] {
        &self.rules
    }

    /// Count a request from `source` to `target`, or refuse it. `None` admits it (and counts
    /// it, when a rule governs `target`).
    pub(crate) fn check(&self, target: &str, source: &str) -> Option<Limited> {
        // Native-only: `ikigai-web` is the inbound HTTP transport (a tokio TcpListener) and has
        // no wasm build. A rate window must not move when the wall clock does.
        #[allow(clippy::disallowed_methods)]
        let now = Instant::now();
        self.check_at(target, source, now)
    }

    /// [`check`](Self::check) at a given monotonic instant: the seam the tests drive.
    pub(crate) fn check_at(&self, target: &str, source: &str, now: Instant) -> Option<Limited> {
        let (index, rule) = self
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| target.starts_with(&rule.prefix))?;
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let key = (index, source.to_string());
        if !windows.contains_key(&key) && windows.len() >= self.max_sources {
            // Reclaim every window that has emptied before judging the bound.
            let rules = &self.rules;
            windows.retain(|(i, _), hits| {
                expire(hits, rules[*i].window, now);
                !hits.is_empty()
            });
            if windows.len() >= self.max_sources {
                return Some(Limited {
                    rule: rule.clone(),
                    retry_after: rule.window,
                    table_full: true,
                });
            }
        }
        let hits = windows.entry(key).or_default();
        expire(hits, rule.window, now);
        if hits.len() >= rule.max as usize {
            let retry_after = hits.front().map_or(rule.window, |&t| {
                rule.window.saturating_sub(now.saturating_duration_since(t))
            });
            return Some(Limited {
                rule: rule.clone(),
                retry_after,
                table_full: false,
            });
        }
        hits.push_back(now);
        None
    }
}

/// Drop the instants in `hits` that have aged out of `window`.
fn expire(hits: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while hits
        .front()
        .is_some_and(|&t| now.saturating_duration_since(t) >= window)
    {
        hits.pop_front();
    }
}

/// The key a request's source is counted under: its address, with an IPv6 address reduced to
/// its /64 (one subscriber's allocation, which a client can rotate through at will; counting
/// each address apart would give one client 2^64 budgets) and an IPv4-mapped IPv6 address
/// counted as the IPv4 address it is. Anything that is not an address is counted as it is, and
/// no address at all as `unknown`, one shared window.
///
/// ```
/// use ikigai_web::source_key;
/// assert_eq!(source_key(Some("203.0.113.9")), "203.0.113.9");
/// assert_eq!(source_key(Some("::ffff:203.0.113.9")), "203.0.113.9");
/// assert_eq!(source_key(Some("2001:db8:1:2:aaaa:bbbb:cccc:dddd")), "2001:db8:1:2::/64");
/// assert_eq!(source_key(Some("2001:db8:1:2::1")), source_key(Some("2001:db8:1:2:ffff::9")));
/// assert_eq!(source_key(None), "unknown");
/// ```
pub fn source_key(addr: Option<&str>) -> String {
    let Some(addr) = addr else {
        return "unknown".to_string();
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                let prefix = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                format!("{prefix}/64")
            }
        },
        Err(_) => addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// An origin for a test's instants. Native-only like the crate (see `check`); every test
    /// drives `check_at` with explicit offsets from it, so the wall clock never matters.
    #[allow(clippy::disallowed_methods)]
    fn start() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_source_past_its_budget_is_refused_until_its_oldest_request_ages_out() {
        let limits = SourceLimits::new(vec![SourceRate::new("urn:contact:submit", 3, secs(60))]);
        let t0 = start();
        for n in 0..3 {
            assert_eq!(
                limits.check_at("urn:contact:submit", "a", t0 + secs(n)),
                None,
                "request {n} is within the budget"
            );
        }
        let refused = limits
            .check_at("urn:contact:submit", "a", t0 + secs(10))
            .expect("the fourth within a minute is refused");
        assert!(!refused.table_full);
        assert_eq!(
            refused.retry_after_secs(),
            50,
            "the first ages out at t0 + 60"
        );
        // Another source has its own budget.
        assert_eq!(
            limits.check_at("urn:contact:submit", "b", t0 + secs(10)),
            None
        );
        // A target no rule governs is never counted.
        assert_eq!(limits.check_at("urn:foaf", "a", t0 + secs(10)), None);
        // Once the oldest ages out, one more is admitted, and only one.
        assert_eq!(
            limits.check_at("urn:contact:submit", "a", t0 + secs(60)),
            None
        );
        assert!(limits
            .check_at("urn:contact:submit", "a", t0 + secs(60))
            .is_some());
    }

    #[test]
    fn a_refusal_is_not_counted_against_the_source() {
        let limits = SourceLimits::new(vec![SourceRate::new("urn:x", 1, secs(60))]);
        let t0 = start();
        assert_eq!(limits.check_at("urn:x", "a", t0), None);
        for n in 1..50 {
            assert!(limits.check_at("urn:x", "a", t0 + secs(n % 59)).is_some());
        }
        // Hammering while refused did not push the window out: it reopens at t0 + 60.
        assert_eq!(limits.check_at("urn:x", "a", t0 + secs(60)), None);
    }

    #[test]
    fn the_longest_prefix_governs_and_each_rule_keeps_its_own_window() {
        let limits = SourceLimits::new(vec![
            SourceRate::new("urn:", 100, secs(60)),
            SourceRate::new("urn:contact:submit", 1, secs(60)),
        ]);
        let t0 = start();
        assert_eq!(limits.check_at("urn:contact:submit", "a", t0), None);
        let refused = limits.check_at("urn:contact:submit", "a", t0).unwrap();
        assert_eq!(refused.rule.prefix, "urn:contact:submit");
        assert_eq!(limits.check_at("urn:booking:submit", "a", t0), None);
    }

    #[test]
    fn the_table_is_bounded_reclaims_emptied_windows_and_refuses_a_new_source_past_it() {
        let limits = SourceLimits::new(vec![SourceRate::new("urn:x", 5, secs(60))]).max_sources(2);
        let t0 = start();
        assert_eq!(limits.check_at("urn:x", "a", t0), None);
        assert_eq!(limits.check_at("urn:x", "b", t0 + secs(40)), None);
        let full = limits
            .check_at("urn:x", "c", t0 + secs(41))
            .expect("a third source is refused while two windows are live");
        assert!(full.table_full);
        assert!(
            full.message().starts_with("rate-limited: "),
            "{}",
            full.message()
        );
        // A source already tracked is still served.
        assert_eq!(limits.check_at("urn:x", "a", t0 + secs(42)), None);
        assert_eq!(limits.check_at("urn:x", "b", t0 + secs(80)), None);
        // Once a's window empties (both its requests age out) and b's has not, c takes a's
        // place and b keeps its own.
        assert_eq!(limits.check_at("urn:x", "c", t0 + secs(103)), None);
        assert_eq!(limits.windows.lock().unwrap().len(), 2);
    }

    /// A fact `docs/no-tracking-certificate.md` relies on: the limiter bounds the addresses
    /// it holds by COUNT, not by time. A window that empties keeps its key, the address, in
    /// memory until the table is full and a new source needs the place; nothing sweeps it
    /// when its window ends. A certificate that says "held for one window" would be wrong.
    #[test]
    fn an_emptied_window_keeps_its_address_until_the_table_needs_the_place() {
        let limits = SourceLimits::new(vec![SourceRate::new("urn:x", 5, secs(60))]).max_sources(2);
        let held = |addr: &str| {
            limits
                .windows
                .lock()
                .unwrap()
                .contains_key(&(0, addr.to_string()))
        };
        let t0 = start();
        assert_eq!(limits.check_at("urn:x", "203.0.113.9", t0), None);
        // An hour on, far past the 60s window, a second source arrives. The table has room,
        // so nothing is reclaimed: the first address is still held.
        assert_eq!(
            limits.check_at("urn:x", "198.51.100.4", t0 + secs(3600)),
            None
        );
        assert!(
            held("203.0.113.9"),
            "the emptied window is still keyed by its address"
        );
        // A third source finds the table full: the emptied window is reclaimed, the live one kept.
        assert_eq!(limits.check_at("urn:x", "192.0.2.1", t0 + secs(3601)), None);
        assert!(!held("203.0.113.9"), "reclaimed once its place was needed");
        assert!(held("198.51.100.4"), "a live window is kept");
    }

    #[test]
    fn retry_after_rounds_up_and_is_never_zero() {
        let rule = SourceRate::new("urn:x", 1, secs(60));
        let at = |retry_after| Limited {
            rule: rule.clone(),
            retry_after,
            table_full: false,
        };
        assert_eq!(at(Duration::from_millis(1500)).retry_after_secs(), 2);
        assert_eq!(at(Duration::ZERO).retry_after_secs(), 1);
        assert_eq!(at(secs(7)).retry_after_secs(), 7);
    }
}
