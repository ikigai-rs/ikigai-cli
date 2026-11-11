//! One retry policy for a host's links to other hosts (ledger #3383): the `connect.retry.*`
//! keys of `config.toml`, applied to `--connect quic://…` and to every remote mount.
//!
//! The policy is ikigai-throttle's overlays, never a reimplementation: a [`Retry`] (backoff
//! with full jitter under an overall time limit) above ONE [`CircuitBreaker`] shared by every
//! mount on the host. What is resent is throttle's decision: a read (an idempotent verb), a
//! call the transport proved never ran (it fails transient), and a Sink whose contract
//! declares a resend safe, with its declared key present. Anything else that may have run
//! comes back to the caller as it failed. A final failure after retrying is core's typed
//! [`Error::GaveUp`](ikigai_core::Error::GaveUp), naming the attempts and the elapsed time.
//!
//! No `connect.retry.*` key means no policy: the host behaves exactly as before.

use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{CachePolicy, EntryFacts, Fallback, Kernel, Request, Resolution, Scope, Space};
use ikigai_throttle::{CircuitBreaker, Jitter, Retry};

/// The config keys of the policy, every one of them optional.
pub const KEYS: &[&str] = &[
    "connect.retry.limit_minutes",
    "connect.retry.initial_backoff_ms",
    "connect.retry.max_backoff_ms",
    "connect.retry.jitter",
    "connect.retry.breaker_threshold",
    "connect.retry.breaker_cooloff_seconds",
];

/// The retry policy `connect.retry.*` configures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// The overall time limit for every attempt and wait of one call.
    pub limit: Duration,
    /// The first backoff, doubling to `max_backoff`.
    pub initial_backoff: Duration,
    /// The largest backoff.
    pub max_backoff: Duration,
    /// Full jitter (the default) or the exact exponential delay.
    pub jitter: bool,
    /// Consecutive transient failures of one target that open its circuit; `None` keeps no
    /// breaker.
    pub breaker_threshold: Option<u32>,
    /// How long an open circuit stays open before a probe.
    pub breaker_cooloff: Duration,
}

impl RetryPolicy {
    /// Read the policy from the host config: `Ok(None)` when no `connect.retry.*` key is
    /// set, and the sentence that stops the host for a value it cannot use.
    pub fn from_config() -> Result<Option<RetryPolicy>, String> {
        RetryPolicy::parse(crate::config::get)
    }

    /// Read the policy through `get` (the config reader, or a test's table).
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<RetryPolicy>, String> {
        if KEYS.iter().all(|key| get(key).is_none()) {
            return Ok(None);
        }
        let number = |key: &str, allow_zero: bool| -> Result<Option<u64>, String> {
            match get(key) {
                None => Ok(None),
                Some(raw) => match raw.trim().parse::<u64>() {
                    Ok(0) if !allow_zero => {
                        Err(format!("config: `{key}` must be above zero, not `{raw}`"))
                    }
                    Ok(value) => Ok(Some(value)),
                    Err(_) => Err(format!(
                        "config: `{key}` must be a whole number, not `{raw}`"
                    )),
                },
            }
        };
        let limit = number("connect.retry.limit_minutes", false)?
            .map_or(DEFAULT_LIMIT, |minutes| {
                Duration::from_secs(minutes.saturating_mul(60))
            });
        let initial_backoff = number("connect.retry.initial_backoff_ms", true)?
            .map_or(DEFAULT_INITIAL, Duration::from_millis);
        let max_backoff = number("connect.retry.max_backoff_ms", true)?
            .map_or(DEFAULT_MAXIMUM, Duration::from_millis);
        if initial_backoff > max_backoff {
            return Err(format!(
                "config: `connect.retry.initial_backoff_ms` ({} ms) is above `connect.retry.max_backoff_ms` ({} ms)",
                initial_backoff.as_millis(),
                max_backoff.as_millis()
            ));
        }
        let jitter = match get("connect.retry.jitter").as_deref().map(str::trim) {
            None | Some("true") => true,
            Some("false") => false,
            Some(other) => {
                return Err(format!(
                    "config: `connect.retry.jitter` must be `true` or `false`, not `{other}`"
                ))
            }
        };
        let breaker_threshold = number("connect.retry.breaker_threshold", false)?
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        let breaker_cooloff = number("connect.retry.breaker_cooloff_seconds", false)?
            .map_or(DEFAULT_COOLOFF, Duration::from_secs);
        Ok(Some(RetryPolicy {
            limit,
            initial_backoff,
            max_backoff,
            jitter,
            breaker_threshold,
            breaker_cooloff,
        }))
    }

    /// The host's ONE shared breaker for `spaces` (the remote mounts, in the order the host
    /// tries them), under the retry: what each mount resolves through [`Governed::slot`].
    pub fn govern(&self, spaces: Vec<Arc<dyn Space>>) -> Governed {
        let combined = Fallback::new(spaces);
        let breaker: Arc<dyn Space> = match self.breaker_threshold {
            Some(threshold) => Arc::new(self.retry(CircuitBreaker::new(
                combined,
                threshold,
                self.breaker_cooloff,
            ))),
            None => Arc::new(self.retry(combined)),
        };
        Governed { shared: breaker }
    }

    fn retry<S: Space>(&self, inner: S) -> Retry<S> {
        // The overall limit bounds the calls, not a count: as many attempts as fit in it.
        let retry = Retry::new(inner, u32::MAX)
            .with_backoff(self.initial_backoff, self.max_backoff)
            .with_time_limit(self.limit)
            .with_max_wait(self.limit);
        if self.jitter {
            retry
        } else {
            retry.with_jitter(Arc::new(NoJitter))
        }
    }
}

/// The defaults of a member left unset, once any `connect.retry.*` key turns the policy on.
pub const DEFAULT_LIMIT: Duration = Duration::from_secs(60);
/// See [`DEFAULT_LIMIT`].
pub const DEFAULT_INITIAL: Duration = Duration::from_millis(100);
/// See [`DEFAULT_LIMIT`].
pub const DEFAULT_MAXIMUM: Duration = Duration::from_secs(10);
/// See [`DEFAULT_LIMIT`].
pub const DEFAULT_COOLOFF: Duration = Duration::from_secs(30);

/// The exact exponential delay: the jitter a `connect.retry.jitter = false` asks for.
struct NoJitter;

impl Jitter for NoJitter {
    fn sample(&self, upper: Duration) -> Duration {
        upper
    }
}

/// The governed mounts: one retry and one breaker for all of them.
pub struct Governed {
    shared: Arc<dyn Space>,
}

impl Governed {
    /// The space a mount takes in the host's composition: it claims what `own` claims, and
    /// resolves it through the shared governor, whose combined mounts answer it with the same
    /// mount (they are combined in the host's own order, and every mount ahead of this one
    /// has already missed the same request).
    pub fn slot(&self, own: Arc<dyn Space>) -> Arc<dyn Space> {
        Arc::new(Slot {
            own,
            shared: Arc::clone(&self.shared),
        })
    }
}

struct Slot {
    own: Arc<dyn Space>,
    shared: Arc<dyn Space>,
}

impl Space for Slot {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        match self.own.resolve(request, scope) {
            Resolution::Hit(_) => self.shared.resolve(request, scope),
            other => other,
        }
    }

    fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
        self.own.entries()
    }

    fn id(&self) -> Option<ikigai_core::Iri> {
        self.own.id()
    }

    fn topology(&self) -> ikigai_core::Topology {
        self.own.topology()
    }
}

/// A cache-less issuer around one remote resolver, for `--connect` (ledger #3383): a kernel
/// over the governed remote whose cache admits nothing, so every read still goes to the hub
/// and freshness is the hub's, exactly as without the policy.
pub fn connect_issuer(
    policy: &RetryPolicy,
    resolver: Arc<dyn ikigai_resolve::Resolver>,
    origin: &str,
) -> Kernel {
    let remote: Arc<dyn Space> = Arc::new(ikigai_resolve::MountedRemote::overriding(
        resolver,
        "urn:".to_string(),
        origin.to_string(),
    ));
    let governed = policy.govern(vec![Arc::clone(&remote)]);
    Kernel::new(governed.slot(remote)).with_cache_policy(Arc::new(NoCache))
}

/// Run `attempt` (a `--connect` dial and its admission check) under the policy's
/// [`Retry`], so a hub that is down when the client starts is waited for, within the same
/// overall limit and backoff as every later call (ledger #3383). Only a transient failure
/// (`Unavailable`, `Timeout`, `GaveUp`) is tried again; a refusal such as `Denied` comes back at once,
/// unchanged. The retry is throttle's, not a loop of this crate's: the attempt is an endpoint
/// read through a `Retry` over it, and its final failure is the typed
/// [`Error::GaveUp`](ikigai_core::Error::GaveUp).
pub fn first_dial<T: Send + 'static>(
    policy: &RetryPolicy,
    attempt: impl Fn() -> Result<T, ikigai_core::Error> + Send + Sync + 'static,
) -> Result<T, ikigai_core::Error> {
    use std::sync::Mutex;
    const DIAL: &str = "urn:ikigai:connect:dial";
    let made: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&made);
    let endpoint = ikigai_core::FnEndpoint::new("connect-dial", move |_| {
        let value = attempt()?;
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
        Ok(ikigai_core::Representation::new(
            ikigai_core::ReprType::new("text/plain"),
            b"dialed".to_vec(),
        ))
    });
    let space = ikigai_core::EndpointSpace::new().bind(ikigai_core::Exact::new(DIAL), endpoint);
    let kernel = Kernel::new(Arc::new(policy.retry(space))).with_cache_policy(Arc::new(NoCache));
    let read = Request::new(
        ikigai_core::Verb::Source,
        ikigai_core::Iri::parse(DIAL).expect("a valid IRI"),
    );
    futures::executor::block_on(kernel.issue(read, &ikigai_core::Capability::root()))?;
    let value = made.lock().unwrap_or_else(|e| e.into_inner()).take();
    value.ok_or_else(|| ikigai_core::Error::Endpoint("connect: the dial left no connection".into()))
}

/// A cache that stores nothing.
struct NoCache;

impl CachePolicy for NoCache {
    fn admit(&self, _: &EntryFacts<'_>) -> bool {
        false
    }

    fn victim(&self, resident: &[EntryFacts<'_>]) -> Option<usize> {
        (!resident.is_empty()).then_some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(pairs: &[(&str, &str)]) -> Result<Option<RetryPolicy>, String> {
        let table: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        RetryPolicy::parse(|key| table.get(key).cloned())
    }

    #[test]
    fn no_key_is_no_policy() {
        assert_eq!(parse(&[]), Ok(None));
    }

    #[test]
    fn every_member_reads_and_the_rest_default() {
        let policy = parse(&[
            ("connect.retry.limit_minutes", "2"),
            ("connect.retry.breaker_threshold", "3"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(policy.limit, Duration::from_secs(120));
        assert_eq!(policy.initial_backoff, DEFAULT_INITIAL);
        assert_eq!(policy.max_backoff, DEFAULT_MAXIMUM);
        assert!(policy.jitter);
        assert_eq!(policy.breaker_threshold, Some(3));
        assert_eq!(policy.breaker_cooloff, DEFAULT_COOLOFF);
    }

    #[test]
    fn an_unusable_value_names_its_key() {
        let err = parse(&[("connect.retry.limit_minutes", "soon")]).unwrap_err();
        assert!(err.contains("connect.retry.limit_minutes"), "{err}");
        let err = parse(&[("connect.retry.jitter", "yes")]).unwrap_err();
        assert!(err.contains("connect.retry.jitter"), "{err}");
        let err = parse(&[
            ("connect.retry.initial_backoff_ms", "500"),
            ("connect.retry.max_backoff_ms", "100"),
        ])
        .unwrap_err();
        assert!(err.contains("max_backoff_ms"), "{err}");
    }
}
