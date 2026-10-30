//! An error a browser asked for as a page (ledger #117), and the door's own page for it
//! (ledger #2025).
//!
//! Every refusal this door writes is a sentence. A client that names `text/html` in `Accept`
//! (a browser navigating) and prefers it to `text/plain` gets that sentence as a minimal,
//! accessible HTML page; anything else (curl's `*/*`, a script asking for JSON, no `Accept`
//! at all) gets it as `text/plain`, exactly as before. The status is the same either way.
//!
//! A door with an [`ErrorPageFn`](crate::ErrorPageFn) is asked for the page first, when the
//! client is a browser (it sent `Sec-Fetch-Mode`) and not htmx asking for a fragment
//! (`HX-Request`); `None` from the hook keeps the minimal page.
use crate::{
    bare_media, match_of, parse_accept, EdgeConfig, ErrorView, HttpRequest, MatchedBy, Resp,
};
use ikigai_fn::html::html_text;

/// Answer `resp` as the client asked, when it is an error whose body is a plain sentence:
/// rewritten as a page for a client that asks for HTML, and in either case marked `Vary:
/// Accept`, because the body now depends on it (a `404` is cacheable by default, RFC 9110
/// §15.1). Any other answer, including a JSON error body a door chose, is left alone.
///
/// The page is the door's own ([`EdgeConfig::error_page`]) when it has one, the request is
/// one a browser made ([`from_a_browser`]) and the hook answers `Some`; otherwise the minimal
/// [`page`]. With a hook set, `Vary` also names `Sec-Fetch-Mode` and `HX-Request`, which then
/// select the body too. Only the body and its type change: the status and every header the
/// answer already carries (`Retry-After`, `Allow`) are the ones it was built with, and the
/// edge policy (the door's CSP among it) is applied after this, to whichever page it is.
pub(crate) fn negotiate(resp: Resp, req: &HttpRequest, config: &EdgeConfig) -> Resp {
    negotiate_with_hook(resp, req, config.error_page.as_ref())
}

/// A pre-admission refusal must not call a host page hook that may assume authentication.
pub(crate) fn negotiate_builtin(resp: Resp, req: &HttpRequest) -> Resp {
    negotiate_with_hook(resp, req, None)
}

fn negotiate_with_hook(
    mut resp: Resp,
    req: &HttpRequest,
    hook: Option<&crate::ErrorPageFn>,
) -> Resp {
    if resp.status < 400 || bare_media(&resp.content_type) != "text/plain" {
        return resp;
    }
    resp.add_vary("Accept");
    if hook.is_some() {
        resp.add_vary("Sec-Fetch-Mode");
        resp.add_vary("HX-Request");
    }
    if !wants_html(req.header("accept")) {
        return resp;
    }
    let message = String::from_utf8_lossy(&resp.body).into_owned();
    let door_page = hook.filter(|_| from_a_browser(req)).and_then(|hook| {
        let view = ErrorView {
            status: resp.status,
            reason: resp.reason,
            message: &message,
            error: resp.error.as_ref(),
            refusal: resp.refusal.as_ref(),
            class: resp.class,
            navigation: req.header("sec-fetch-mode") == Some("navigate"),
        };
        hook(req, &view)
    });
    resp.body = door_page
        .unwrap_or_else(|| page(resp.status, resp.reason, &message))
        .into_bytes();
    resp.content_type = "text/html; charset=utf-8".to_string();
    resp
}

/// Whether a browser made the request, so a door's own page may answer it: it carries the
/// fetch metadata only a browser sends (`Sec-Fetch-Mode`, W3C Fetch Metadata), and it is not
/// htmx asking for a fragment (`HX-Request: true`), which would swap a whole page into part of
/// one. curl naming `text/html` carries neither, and gets the minimal page.
///
/// ⚠ A browser sends fetch metadata only to a potentially trustworthy origin (HTTPS, or
/// `localhost`), so a door served as plain `http://` on a LAN address never offers its page
/// and answers the minimal one.
fn from_a_browser(req: &HttpRequest) -> bool {
    req.header("sec-fetch-mode").is_some()
        && !req
            .header("hx-request")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Whether `Accept` asks for HTML over plain text: `text/html` NAMED (a wildcard tolerates
/// HTML without asking for it, and is what curl sends), at a quality above zero and above
/// `text/plain`'s. A tie stays plain, the answer this door gave before pages existed.
fn wants_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let ranges = parse_accept(accept);
    let Some(html) = match_of("text/html", &ranges) else {
        return false;
    };
    let plain = match_of("text/plain", &ranges).map_or(0.0, |m| m.q);
    html.by == MatchedBy::Name && html.q > 0.0 && html.q > plain
}

/// The page: a language, a title, a `main` landmark, a heading naming the status, and the
/// message, escaped. No style and no script, so the strict default CSP has nothing to block.
///
/// ```text
/// <!DOCTYPE html>
/// <html lang="en">
/// <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>404 Not Found</title></head>
/// <body><main><h1>404 Not Found</h1><p>no route</p></main></body>
/// </html>
/// ```
pub(crate) fn page(status: u16, reason: &str, message: &str) -> String {
    let title = html_text(format!("{status} {reason}").trim());
    let message = message.trim();
    let paragraph = if message.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", html_text(message))
    };
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head>\n<body><main><h1>{title}</h1>{paragraph}</main></body>\n</html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_gets_a_page_and_curl_does_not() {
        let browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        assert!(wants_html(Some(browser)));
        for other in [
            None,
            Some("*/*"),
            Some("application/json"),
            Some("text/*"),
            Some("text/plain, text/html"),
            Some("text/html;q=0"),
            Some("text/plain, text/html;q=0.5"),
        ] {
            assert!(!wants_html(other), "{other:?}");
        }
    }

    #[test]
    fn the_page_escapes_the_message_and_names_the_status() {
        let html = page(404, "Not Found", "no <script>alert('x')</script> & \"y\"");
        assert!(html.contains("<html lang=\"en\">"), "{html}");
        assert!(html.contains("<title>404 Not Found</title>"), "{html}");
        assert!(html.contains("<main><h1>404 Not Found</h1>"), "{html}");
        assert!(
            html.contains(
                "<p>no &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;y&quot;</p>"
            ),
            "{html}"
        );
        assert!(!html.contains("<script>"), "{html}");
        // An empty sentence is a heading alone.
        assert!(!page(431, "Request Header Fields Too Large", "").contains("<p>"));
    }

    /// The escape is `ikigai_fn::html::html_text` (ledger #1868): a C0 control other than tab,
    /// line feed and carriage return becomes U+FFFD, so the page stays parseable as XML too, and
    /// a `javascript:` URL in the message is text, never a link.
    #[test]
    fn a_control_character_in_the_message_becomes_u_fffd() {
        let html = page(
            400,
            "Bad Request",
            "bad\u{0}byte\u{1b}[31m\there \"javascript:alert(1)\"",
        );
        assert!(
            html.contains(
                "<p>bad\u{FFFD}byte\u{FFFD}[31m\there &quot;javascript:alert(1)&quot;</p>"
            ),
            "{html}"
        );
        assert!(
            !html.contains('\u{0}') && !html.contains('\u{1b}'),
            "{html}"
        );
        assert!(!html.contains("href"), "{html}");
    }
}
