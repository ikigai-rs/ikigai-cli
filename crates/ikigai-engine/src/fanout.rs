//! How wide a fan-out really is, and what that entitles it to ask for.
//!
//! `( a ; b )` forks and `..` maps build their complete request vector before
//! dispatching any of it, so at that moment the engine knows the fan-out's width as an
//! integer. That number is worth carrying: backend choice follows load shape. Measured
//! on one machine against one model (2026-08-18), a single request ran ~1.8× better on
//! the serializing backend (53.0 vs 28.9 tok/s) while ten concurrent ones finished in
//! 17.9s against the batching backend and 49.3s against the other. `ikigai-llm` 0.12
//! lets a caller *declare* the shape with `needs=batchAt<=W`; this module lets the
//! runtime supply W, because the runtime is the one that knows it.
//!
//! Three properties hold the design together, and each is a net loss if dropped.
//!
//! **Nominal width is not effective concurrency.** [`Scheduler::Single`] does not spawn
//! — it hands back an inline future polled cooperatively on one thread — and the native
//! HTTP transport is blocking `ureq`, so a ten-wide fan-out there issues one request at
//! a time. Routing *that* to the batching backend is the 1.8×-slower case, arrived at
//! deliberately. [`effective_width`] therefore bounds the request count by what the
//! spawner says it can actually carry, and reads an unknown width (`None`) as **1**:
//! the damaging guess is "wide", so unknown must never mean wide.
//!
//! **The hint must not enter request identity for anything that isn't routing on it.**
//! The kernel caches on request id ⊕ capability fingerprint, so an argument added to
//! every fanned-out request would split the cache by width — the same resource resolved
//! inside a 3-wide map and a 10-wide map becoming two entries, a miss manufactured out
//! of nothing on every cacheable endpoint reached through `..` or a fork. So the hint is
//! offered only where it is *read*: a target whose self-description declares an
//! **optional** `needs` argument. Everything else is left byte-identical, which is what
//! [`hint_for`] enforces and what the cache-hit test in `engine.rs` pins.
//!
//! **`needs=` is a hard filter, and a no-match is a loud error.** `urn:llm:ask` fails
//! rather than falling back, and at width 1 *nothing* qualifies unless an operator
//! declared `batchAt: 1`. So the low-width case is the ABSENCE of the term, not a
//! different term (there is no declared data to route on for the serializing side), and
//! a fan-out whose hint no-matches retries once **without** it — see
//! [`is_hint_no_match`].
//!
//! [`Scheduler::Single`]: https://docs.rs/ikigai-scheduler

use std::fmt;

use ikigai_core::{Description, InputSource, Request};

/// The argument a backend-routing endpoint reads to select on declared traits.
const NEEDS: &str = "needs";

/// The argument that names a backend outright. Explicit routing always outranks an
/// automatic one, so its presence suppresses the hint.
const PROVIDER: &str = "provider";

/// What one fan-out actually did — recorded whether or not a hint was applied, because
/// "you asked for ten and got one" is the single most useful thing an operator can learn
/// about a fan-out, and from outside the process a serialized run and a slow server look
/// identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FanOut {
    /// How many requests the construct produced — branch count, or mapped item count.
    pub nominal: usize,
    /// How many of them can be in flight at once (see [`effective_width`]).
    pub effective: usize,
    /// The `needs=` term appended to the requests that were willing to read it, if any.
    pub hint: Option<String>,
}

impl fmt::Display for FanOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fan-out {} → {} wide", self.nominal, self.effective)?;
        match &self.hint {
            Some(hint) => write!(f, " · needs={hint}"),
            None => Ok(()),
        }
    }
}

/// How many of a fan-out's `nominal` requests are genuinely in flight at once.
///
/// `spawner` is [`Spawner::width`](ikigai_core::Spawner::width): the number of spawned
/// tasks that make progress *simultaneously*. A single-threaded or inline executor
/// answers `Some(1)`; `None` means the executor genuinely cannot say.
///
/// **`None` reads as 1.** It is not a shorthand for "small", but the caller has to pick
/// something, and the two guesses are not symmetric: reading unknown as wide routes a
/// serialized workload to a batching backend and runs it ~1.8× slower, while reading it
/// as narrow only declines an optimization. Never widen on ignorance.
pub fn effective_width(nominal: usize, spawner: Option<usize>) -> usize {
    nominal.min(spawner.unwrap_or(1)).max(1)
}

/// The `needs=` term expressing a fan-out of `width`: "the declared crossover is at or
/// below my width", which is exactly what `caps.batchAt` means.
pub fn batch_at_term(width: usize) -> String {
    format!("batchAt<={width}")
}

/// The hint to append to `request`, or `None` to leave it exactly as it is.
///
/// The precedence encoded here, widest to narrowest:
///
/// 1. `provider=` — an explicit backend, never overridden.
/// 2. `needs=` — an explicit requirement expression, never widened or replaced.
/// 3. the automatic width hint — only when `enabled`, only at an effective width of 2 or
///    more, and only for a target that declares an **optional** `needs` argument.
/// 4. whatever the endpoint's own default routing decides.
///
/// Rule 3's describe check is what keeps this off request identity everywhere else: an
/// endpoint that does not read `needs` never sees the argument, so its cache key is
/// untouched by the width of the construct it happened to be resolved inside. Requiring
/// the declaration to be *optional* also excludes `urn:llm:select`, whose `needs` is
/// required — a caller always supplies it, and it is a cacheable pure function of the
/// registry that has no business varying with the caller's fan-out.
///
/// Width 1 gets no term at all. `batchAt<=1` would match only a backend an operator
/// explicitly declared as a crossover-at-one, and since `needs=` is a hard filter, on
/// every other host it would turn a working ask into an error.
pub fn hint_for(
    enabled: bool,
    effective: usize,
    request: &Request,
    description: Option<&Description>,
) -> Option<String> {
    if !enabled || effective < 2 {
        return None;
    }
    if explicitly_routed(request) {
        return None;
    }
    declares_optional_needs(description?).then(|| batch_at_term(effective))
}

/// Whether a request already names its own routing — `provider=` or `needs=`. Explicit
/// routing outranks the automatic hint, and checking it costs nothing, so it is also the
/// cheap gate that keeps an already-routed request from paying for a contract lookup.
pub fn explicitly_routed(request: &Request) -> bool {
    request.args.contains_key(PROVIDER) || request.args.contains_key(NEEDS)
}

/// Whether a target declares an optional by-value `needs` argument — i.e. whether it
/// routes on requirements but does not demand them. Both authoring forms count: the flat
/// `inputs` (the single-verb 93% case) and any per-verb `ActionSpec`.
fn declares_optional_needs(description: &Description) -> bool {
    let optional_needs = |spec: &ikigai_core::ArgSpec| {
        spec.name == NEEDS && !spec.required && spec.source == InputSource::Argument
    };
    description.inputs.iter().any(optional_needs)
        || description
            .action_specs()
            .iter()
            .any(|action| action.inputs.iter().any(optional_needs))
}

/// Whether `error` is the selection no-match that `term` itself caused — the signal to
/// retry the request without the hint.
///
/// `ikigai-llm` reports a no-match as an endpoint error quoting the whole `needs`
/// expression back (`no configured backend satisfies \`batchAt<=8\``). Because the hint
/// is only ever added when the caller supplied no `needs` of their own, that expression
/// *is* our term, so matching on the term is a tight test: no other failure carries the
/// exact string `batchAt<=8`.
///
/// This is a string match across a crate boundary, which is a real weakness — the day
/// `ikigai-llm` rewords that message, the retry stops firing. It degrades LOUDLY (the
/// operator gets the no-match error instead of a silent reroute), which is the right
/// direction to fail, but a typed selection error would be better and is worth asking
/// for.
pub fn is_hint_no_match(error: &str, term: &str) -> bool {
    error.contains(term)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{ArgSpec, Description, Iri, Verb};

    fn request(args: &[(&str, &str)]) -> Request {
        let mut request = Request::new(Verb::Source, Iri::parse("urn:llm:ask").unwrap());
        for (name, value) in args {
            request = request.with_arg(
                *name,
                ikigai_core::ArgRef::Inline(value.as_bytes().to_vec()),
            );
        }
        request
    }

    /// A router: `provider=` and `needs=` both optional, the `urn:llm:ask` shape.
    fn router() -> Description {
        Description::new("llm-ask")
            .input(ArgSpec::new("provider").optional())
            .input(ArgSpec::new("needs").optional())
    }

    /// An endpoint that reads no requirements at all — the overwhelming majority, and
    /// the ones whose cache keys must not move.
    fn plain() -> Description {
        Description::new("upper").input(ArgSpec::new("in"))
    }

    /// Unknown width is width 1. Stated first because it is the inversion that costs:
    /// read as "wide", a serialized run goes to the batching backend and runs ~1.8×
    /// slower than sequencing it would have.
    #[test]
    fn an_unknown_spawner_width_is_one_never_wide() {
        assert_eq!(effective_width(10, None), 1);
        assert_eq!(effective_width(1, None), 1);
    }

    /// The scheduler bounds the fan-out, and the fan-out bounds the scheduler: ten
    /// branches on a two-wide pool are two-wide, and two branches on a ten-wide pool are
    /// two-wide. Reporting a width the run will not achieve is the whole failure mode.
    #[test]
    fn effective_width_is_the_smaller_of_the_two() {
        assert_eq!(effective_width(10, Some(2)), 2);
        assert_eq!(effective_width(2, Some(10)), 2);
        assert_eq!(effective_width(10, Some(1)), 1, "the default `single` host");
        assert_eq!(
            effective_width(0, Some(8)),
            1,
            "an empty fan-out is not 0-wide"
        );
    }

    /// The term says "your declared crossover is at or below my width".
    #[test]
    fn the_term_is_a_batch_at_upper_bound() {
        assert_eq!(batch_at_term(8), "batchAt<=8");
    }

    /// The hint reaches a target that declares it can read requirements.
    #[test]
    fn a_router_gets_the_width_as_a_needs_term() {
        assert_eq!(
            hint_for(true, 8, &request(&[]), Some(&router())),
            Some("batchAt<=8".to_string())
        );
    }

    /// ★ The property that keeps the cache whole: an endpoint that does not route on
    /// requirements never sees the argument, so its request identity — and therefore its
    /// cache key — is byte-identical whatever width it was resolved inside.
    #[test]
    fn an_endpoint_that_does_not_route_on_needs_is_left_alone() {
        assert_eq!(hint_for(true, 8, &request(&[]), Some(&plain())), None);
        assert_eq!(hint_for(true, 8, &request(&[]), None), None, "no contract");
    }

    /// A required `needs` is `urn:llm:select`'s shape: the caller always supplies it, and
    /// the result is a cacheable pure function of the registry. Nothing to inject into.
    #[test]
    fn a_required_needs_is_not_an_injection_site() {
        let select = Description::new("llm-select").input(ArgSpec::new("needs"));
        assert_eq!(hint_for(true, 8, &request(&[]), Some(&select)), None);
    }

    /// Explicit routing outranks automatic routing, both spellings. `ikigai-browse` folds
    /// model identity into a durable archive key, so an automatic override of an explicit
    /// choice would write width-dependent nondeterminism permanently into a store.
    #[test]
    fn explicit_provider_and_explicit_needs_both_win() {
        let by_provider = request(&[("provider", "ollama")]);
        assert_eq!(hint_for(true, 8, &by_provider, Some(&router())), None);

        let by_needs = request(&[("needs", "vision, ctx>=32k")]);
        assert_eq!(hint_for(true, 8, &by_needs, Some(&router())), None);
    }

    /// Off is off: the switch is the whole opt-in, and with it off the request that
    /// reaches the kernel is the request that reached it before this existed.
    #[test]
    fn the_switch_off_means_no_hint_anywhere() {
        assert_eq!(hint_for(false, 8, &request(&[]), Some(&router())), None);
    }

    /// Width 1 is the absence of the term, not `batchAt<=1`. `needs=` is a hard filter:
    /// `batchAt<=1` matches only a backend an operator declared as crossing over at one,
    /// so emitting it would turn every ordinary single ask into a loud no-match.
    #[test]
    fn width_one_appends_nothing_rather_than_asking_for_batch_at_one() {
        assert_eq!(hint_for(true, 1, &request(&[]), Some(&router())), None);
    }

    /// The retry trigger: our own term echoed back inside a selection failure.
    #[test]
    fn a_no_match_quoting_our_term_is_recognised() {
        let error = "endpoint error: urn:llm:ask: no configured backend satisfies \
                     `batchAt<=8` (providers: ollama, rapid) — see urn:llm:models";
        assert!(is_hint_no_match(error, "batchAt<=8"));
        // A different failure is NOT a reason to re-issue an expensive call.
        assert!(!is_hint_no_match(
            "endpoint error: connection refused",
            "batchAt<=8"
        ));
        // Nor is a no-match on a requirement the caller wrote themselves.
        let theirs = "endpoint error: urn:llm:ask: no configured backend satisfies `vision`";
        assert!(!is_hint_no_match(theirs, "batchAt<=8"));
    }

    /// The note an operator reads. Both halves matter: the width that was asked for and
    /// the width that was achieved.
    #[test]
    fn the_fan_out_note_names_both_widths_and_the_hint() {
        let serialized = FanOut {
            nominal: 10,
            effective: 1,
            hint: None,
        };
        assert_eq!(serialized.to_string(), "fan-out 10 → 1 wide");
        let routed = FanOut {
            nominal: 10,
            effective: 8,
            hint: Some("batchAt<=8".to_string()),
        };
        assert_eq!(routed.to_string(), "fan-out 10 → 8 wide · needs=batchAt<=8");
    }
}
