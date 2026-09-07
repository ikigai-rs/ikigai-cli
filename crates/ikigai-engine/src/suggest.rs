//! Near-name suggestions for a resolution failure.
//!
//! `no endpoint resolved for urn:iki:fn:toUpper` is true and useless: it is
//! indistinguishable from a typo, from a module that was never loaded, and from
//! the case that actually costs time — a host whose bindings predate a namespace
//! rename, where the name you want is bound under its *old* spelling.
//!
//! This module is the **face** enriching a typed error, not a change to the error.
//! [`ikigai_core::Error::Unresolved`] still carries exactly one fact (the IRI that
//! resolved to nothing); the engine consults the catalog it already has and appends
//! a line when — and only when — a near name is genuinely bound.
//!
//! It cuts both ways, which is why it needs no knowledge of aliases, migrations or
//! versions. On an **old** host the suggestion names the old spelling, because that
//! is what the host binds — so the reader learns their host is behind. On a **new**
//! host the alias resolves the old name and no error is raised at all.
//!
//! # The rule
//!
//! A candidate must be a bound pattern whose **final `:`-separated segment is
//! exactly** the failed IRI's final segment. Among those, the ones sharing the
//! **longest run of trailing segments** win, and ties beyond [`MAX`] are dropped
//! entirely.
//!
//! Two limits, both deliberate and both worth knowing:
//!
//! * **A tie at one shared segment can be weak.** `urn:iki:kernel:catalog` on a host
//!   that binds `urn:style:catalog` (a stylesheet) and nothing else ending in
//!   `catalog` offers that one — a real binding, just not the one meant. The
//!   alternative was to demand that the two names differ only by *inserted* segments,
//!   which would reject a sibling rename (`urn:iki:fn:x` → `urn:iki:text:x`) — the
//!   very shape this has to survive. One stray line naming a real binding is the
//!   cheaper failure.
//! * **A template binding is never a candidate** (see the `{`-guard below), so a host
//!   that binds `urn:annotation:{id}` cannot suggest itself for `urn:iki:annotation:7`.
//!   Matching through a slot means a pattern whose leaf is a slot matches *every*
//!   leaf, which is a much wider surface than this arc wanted to open.
//!
//! Deliberately *not* here: edit distance over the final segment. It was
//! considered for typos (`toUppr`) and rejected. The exact-segment rule has no
//! false positives by construction — every name it offers really is bound and
//! really does share a name with what was asked for. Distance-1 over a catalog of
//! hundreds of short leaf segments (`now`, `new`, `state`, `stat`, `tree`) matches
//! broadly, and the tie-break below cannot separate the hits because they all sit
//! at the same distance. The case that cost a day is the namespace rename, and the
//! exact rule covers it completely; the typo case is speculative, and it can be
//! added later without changing the shape of the message.

/// Beyond this many equally-near candidates, say nothing. A leaf segment that
/// names a dozen bindings (`…:tree` under every repo) is not a suggestion, it is
/// a listing — and noise on an error path teaches people to stop reading errors.
const MAX: usize = 3;

/// The `:`-separated segments of an IRI.
fn segments(iri: &str) -> Vec<&str> {
    iri.split(':').collect()
}

/// How many trailing segments `a` and `b` share. `urn:iki:fn:toUpper` and
/// `urn:fn:toUpper` share two (`fn`, `toUpper`); `urn:repo:folio:tree` and
/// `urn:repo:ikigai-cli:tree` share one.
fn shared_tail(a: &[&str], b: &[&str]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// The bound patterns nearest `target`, best-first — empty when nothing is near.
///
/// `patterns` is the catalog as this host sees it, mounted bindings included: a
/// federated name is resolvable from here, so it is a legitimate suggestion.
pub fn nearest(target: &str, patterns: &[String]) -> Vec<String> {
    let want = segments(target);
    let Some(leaf) = want.last() else {
        return Vec::new();
    };
    // A template's final segment is a slot (`{path}`), not a name — it can never be
    // what someone meant to type, so it is not a candidate.
    if leaf.starts_with('{') {
        return Vec::new();
    }
    let mut scored: Vec<(usize, &str)> = Vec::new();
    for pattern in patterns {
        if pattern == target {
            continue; // bound and still unresolved (a scope refused it): not a typo
        }
        let have = segments(pattern);
        if have.last() != Some(leaf) {
            continue;
        }
        scored.push((shared_tail(&want, &have), pattern.as_str()));
    }
    let Some(best) = scored.iter().map(|(run, _)| *run).max() else {
        return Vec::new();
    };
    let mut names: Vec<String> = scored
        .iter()
        .filter(|(run, _)| *run == best)
        .map(|(_, pattern)| (*pattern).to_string())
        .collect();
    names.sort();
    names.dedup();
    if names.len() > MAX {
        return Vec::new();
    }
    names
}

/// The suggestion line for a failed `target`, or `None` when nothing is near.
///
/// Returned without indentation: each face decides how to attach it (the REPL and
/// the TUI hang it under the `error: ` prefix; `trace` puts it under the tree row).
pub fn note(target: &str, patterns: &[String]) -> Option<String> {
    let names = nearest(target, patterns);
    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    let list = match quoted.split_last() {
        None => return None,
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    };
    Some(format!("did you mean {list}? (bound here)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn the_namespace_rename_is_the_case_this_exists_for() {
        let bound = catalog(&["urn:fn:toUpper", "urn:fn:reverseList", "urn:echo"]);
        assert_eq!(
            note("urn:iki:fn:toUpper", &bound).as_deref(),
            Some("did you mean `urn:fn:toUpper`? (bound here)")
        );
    }

    /// The regression that matters more than the suggestion itself: with nothing
    /// near, the face must add NOTHING, so the message stays byte-identical.
    #[test]
    fn nothing_near_says_nothing() {
        let bound = catalog(&["urn:fn:toUpper", "urn:echo", "urn:file:{path}"]);
        assert_eq!(note("urn:iki:fn:sideways", &bound), None);
        assert_eq!(note("urn:totally:unrelated", &bound), None);
        assert_eq!(note("urn:fn:toUpper", &bound), None); // itself is not a candidate
    }

    /// A typo is NOT matched — the rule is exact on the final segment, by choice.
    #[test]
    fn a_typo_in_the_leaf_gets_no_suggestion() {
        let bound = catalog(&["urn:fn:toUpper"]);
        assert_eq!(note("urn:iki:fn:toUppr", &bound), None);
        assert_eq!(note("urn:fn:toupper", &bound), None); // case is part of the name
    }

    #[test]
    fn a_template_slot_is_never_a_candidate() {
        let bound = catalog(&["urn:repo:folio:file:{path}", "urn:file:{path}"]);
        assert_eq!(note("urn:iki:repo:folio:file:{path}", &bound), None);
        // …and a template never suggests itself for a concrete request either.
        assert_eq!(note("urn:iki:repo:folio:file", &bound), None);
    }

    /// The longest shared trailing run wins, so a leaf that many bindings share
    /// still resolves to the one the reader meant.
    #[test]
    fn the_longest_shared_tail_wins() {
        let bound = catalog(&[
            "urn:repo:folio:tree",
            "urn:repo:ikigai-cli:tree",
            "urn:repo:ikigai-core:tree",
        ]);
        assert_eq!(
            note("urn:iki:repo:ikigai-cli:tree", &bound).as_deref(),
            Some("did you mean `urn:repo:ikigai-cli:tree`? (bound here)")
        );
    }

    /// …and when the run cannot separate them, a leaf shared by many bindings is a
    /// listing, not a suggestion. Say nothing.
    #[test]
    fn too_many_equally_near_names_is_noise_not_a_suggestion() {
        let bound = catalog(&[
            "urn:repo:folio:tree",
            "urn:repo:ikigai-cli:tree",
            "urn:repo:ikigai-core:tree",
            "urn:repo:ikigai-web:tree",
        ]);
        assert_eq!(nearest("urn:tree", &bound).len(), 0);
        assert_eq!(note("urn:tree", &bound), None);
    }

    /// Up to MAX ties read as one sentence.
    #[test]
    fn a_small_tie_names_each_candidate() {
        let bound = catalog(&["urn:a:ping", "urn:b:ping"]);
        assert_eq!(
            note("urn:ping", &bound).as_deref(),
            Some("did you mean `urn:a:ping` or `urn:b:ping`? (bound here)")
        );
        let bound = catalog(&["urn:a:ping", "urn:b:ping", "urn:c:ping"]);
        assert_eq!(
            note("urn:ping", &bound).as_deref(),
            Some("did you mean `urn:a:ping`, `urn:b:ping` or `urn:c:ping`? (bound here)")
        );
    }

    /// The rule must not know about `urn:iki:` or any other namespace by name: it
    /// works in the other direction, and after the next rename, unchanged.
    #[test]
    fn the_rule_is_direction_and_namespace_agnostic() {
        let old_host = catalog(&["urn:fn:toUpper"]);
        let new_host = catalog(&["urn:iki:fn:toUpper"]);
        assert_eq!(
            note("urn:iki:fn:toUpper", &old_host).as_deref(),
            Some("did you mean `urn:fn:toUpper`? (bound here)")
        );
        assert_eq!(
            note("urn:fn:toUpper", &new_host).as_deref(),
            Some("did you mean `urn:iki:fn:toUpper`? (bound here)")
        );
    }

    #[test]
    fn shared_tail_counts_trailing_segments_only() {
        assert_eq!(
            shared_tail(&segments("urn:iki:fn:x"), &segments("urn:fn:x")),
            2
        );
        assert_eq!(shared_tail(&segments("urn:a:x"), &segments("urn:b:x")), 1);
        assert_eq!(shared_tail(&segments("urn:a:x"), &segments("urn:a:y")), 0);
    }
}
