//! What a DOOR does with a principal the client supplied: the one rule, for every door that
//! builds a [`Request`] (QUIC, the Unix socket, MCP over stdio; ledger #1830).
//!
//! A principal is WHO a request is for, and only a door that authenticated someone may say
//! who. A client reaches an endpoint with a name two ways, and a door closes both:
//!
//! - the **`principal` argument** ([`PRINCIPAL_ARG`]), the older channel a host reads off a
//!   request (gonk's claim-kind stamper, an access log). [`stamp_principal`] removes whatever
//!   the client sent under that name, by value or by reference, and writes the door's own.
//! - a **carried capability** naming one (`urn:cap:principal:<iri>`). Under a scoped ceiling
//!   core's `clamp` already keeps the CEILING's principal, so a door with one needs nothing
//!   more. Under a ROOT ceiling `clamp` returns the carried capability, principal included
//!   (root may act as anyone), so a root door that authenticated no principal calls
//!   [`without_principals`] on what it was handed before resolving under it.
//!
//! It lives here because this is the one member every door crate of the workspace already
//! depends on, as [`is_plain_file_name`](crate::is_plain_file_name) does. The HTTP doors
//! (`ikigai-web`, the layers front) drop a `?principal=` from the QUERY before a request
//! exists, which is the same rule applied one representation earlier.

use ikigai_core::{ArgRef, Capability, Request, PRINCIPAL_SCOPE_PREFIX};

/// The inline argument a door's principal arrives under, on every request it admits: the
/// name `ikigai-web` stamps on a write, so a host reads one argument whichever door a request
/// came through.
pub const PRINCIPAL_ARG: &str = "principal";

/// Put the door's `principal` on `request` under [`PRINCIPAL_ARG`], removing whatever the
/// client sent there first (in any form, inline or by reference), so the only principal an
/// endpoint can read off the request is the one the door named. `None` removes and writes
/// nothing.
///
/// ```
/// use ikigai_core::{ArgRef, Iri, Request, Verb};
/// use ikigai_resolve::{stamp_principal, PRINCIPAL_ARG};
///
/// let mut forged = Request::new(Verb::Source, Iri::parse("urn:test:whoami").unwrap())
///     .with_arg(PRINCIPAL_ARG, ArgRef::Inline(b"urn:example:mallory".to_vec()));
/// stamp_principal(&mut forged, None);
/// assert!(forged.args.get(PRINCIPAL_ARG).is_none());
///
/// stamp_principal(&mut forged, Some("urn:example:alice"));
/// assert_eq!(
///     forged.args.get(PRINCIPAL_ARG),
///     Some(&ArgRef::Inline(b"urn:example:alice".to_vec()))
/// );
/// ```
pub fn stamp_principal(request: &mut Request, principal: Option<&str>) {
    request.args.remove(PRINCIPAL_ARG);
    if let Some(principal) = principal {
        request.args.insert(
            PRINCIPAL_ARG.to_string(),
            ArgRef::Inline(principal.as_bytes().to_vec()),
        );
    }
}

/// `carried` with every scope under `urn:cap:principal:` removed: what a door that
/// authenticated NO principal resolves a client's own capability under, so a name the door
/// did not mint never reaches an endpoint. Root stays root (it names nobody already), and
/// every other scope, exclusions included, is kept: this drops a claim, never a narrowing.
///
/// ```
/// use ikigai_core::Capability;
/// use ikigai_resolve::without_principals;
///
/// let forged = Capability::scoped(["urn:cap:demo:read"])
///     .with_principal("urn:example:mallory")
///     .unwrap();
/// let admitted = without_principals(&forged);
/// assert_eq!(admitted.principal(), None);
/// assert_eq!(admitted, Capability::scoped(["urn:cap:demo:read"]));
/// assert_eq!(without_principals(&Capability::root()), Capability::root());
/// ```
pub fn without_principals(carried: &Capability) -> Capability {
    match carried.scopes() {
        None => Capability::root(),
        Some(scopes) => Capability::scoped(
            scopes
                .iter()
                .filter(|scope| !scope.starts_with(PRINCIPAL_SCOPE_PREFIX))
                .cloned(),
        ),
    }
}
