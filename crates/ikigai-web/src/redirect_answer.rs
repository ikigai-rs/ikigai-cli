//! A Source's typed redirect answer on the HTTP face (ledger #3151).
//!
//! Core's [`Redirect`] is a representation of a reserved type, read only through core's
//! `as_redirect`. A read that answers one is sent as its status with `Location` set to the
//! absolute location, off-site allowed: the answer is typed and explicit, so this is not the
//! same-origin rule for a write's `Location` ([`crate::entity`]), which is unchanged, and not
//! Post/Redirect/Get ([`crate::redirect`]) or a host's declared redirects
//! ([`crate::read_redirect`]). A write that answers this type is served as it came.
//!
//! The answer has a body for a client that does not follow it: a short page (the error page's
//! shape, with the target as a link) for a client that asks for HTML, and a sentence as
//! `text/plain` for any other. It is built here and then goes through [`read_resp`] as any
//! answer does, so its `ETag` is that of the bytes sent, `Cache-Control` follows the
//! representation's expiry, and `If-None-Match` can answer `304`.
use crate::{
    entity, error_page, read_resp, reason_phrase, Freshness, HeaderRefusal, HttpRequest, Resp,
    Served,
};
use ikigai_core::{Redirect, ReprType, Representation};
use ikigai_fn::html::{attr, html_text, safe_href, url_reserved};

const HTML: &str = "text/html; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

/// The door's answer to a read whose representation is `redirect`. `Err` when the location
/// cannot be carried in a header at all, which today means only that it is too long.
pub(crate) fn read(
    req: &HttpRequest,
    redirect: &Redirect,
    served: Served,
    freshness: Freshness,
    vary: Vec<String>,
) -> Result<Resp, HeaderRefusal> {
    // An IRI may hold what a URI may not, and a header carries only the URI.
    let location = url_reserved(redirect.location.as_str());
    entity::check_value("Location", &location)?;
    let status = redirect.status.code();
    let reason = reason_phrase(status);
    let (content_type, body) = if error_page::wants_html(req.header("accept")) {
        (HTML, page(status, reason, redirect, &location))
    } else {
        (
            TEXT,
            format!("{status} {reason}: {}\n", redirect.location.as_str()),
        )
    };
    let answer = Served {
        repr: Representation::new(ReprType::new(content_type), body)
            .with_expiry(served.repr.expiry),
        content_type: content_type.to_string(),
        asked: served.asked,
        shared: served.shared,
    };
    let mut resp = read_resp(req, answer, freshness, vary);
    resp.add_vary("Accept");
    // Anything else is the `304` a matching `If-None-Match` earned, which carries no target.
    if resp.status == 200 {
        resp.status = status;
        resp.reason = reason;
        resp.headers.push(("Location".to_string(), location));
    }
    Ok(resp)
}

/// The page for a client that asks for HTML. A location the door would not link (any absolute
/// IRI reads, `javascript:` among them) is shown as text: `Location` says it, the client judges
/// it, and the page never makes it something to click.
fn page(status: u16, reason: &str, redirect: &Redirect, location: &str) -> String {
    let shown = html_text(redirect.location.as_str());
    let target = match safe_href(location) {
        Some(href) => format!("<a href=\"{}\">{shown}</a>", attr(href)),
        None => shown,
    };
    error_page::shell(
        &format!("{status} {reason}"),
        &format!("<p>This resource is at {target}.</p>"),
    )
}
