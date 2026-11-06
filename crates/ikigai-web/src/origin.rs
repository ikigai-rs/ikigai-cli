//! The Origin check a door that serves HTML puts in front of its writes (ledger #1813).
//!
//! A browser attaches a door's cookies to a request any page makes, so a page on another
//! origin can make a signed-in person's browser POST to the door: cross-site request forgery.
//! What the browser cannot let that page do is lie about where the request came from. Every
//! current browser names the initiating origin in `Origin` on every request that is not a
//! `GET` or `HEAD`, and adds `Sec-Fetch-Site`, so a door that knows its OWN origin, from its
//! configuration, can refuse a write that another origin started.
use crate::{AdmitFn, HttpRequest, Refusal};
use std::sync::Arc;

/// The methods a request may use without changing anything (RFC 9110 §9.2.1), which the
/// check lets through. This door maps `GET` and `HEAD` to `Source` and answers `OPTIONS`
/// itself, so no route the library serves changes state on one of them. Every other method,
/// `POST`, `PUT`, `PATCH`, `DELETE` and any extension method alike, is checked.
const SAFE_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

/// One origin as RFC 6454 compares them: a scheme, a lowercase host and a port, with the
/// scheme's default port filled in, so `https://Example.com:443` and `https://example.com`
/// are the same origin.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: &'static str,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse a serialized origin (`scheme://host[:port]`). `None` for anything else: an opaque
    /// `null`, a scheme other than `http` or `https`, userinfo, a path, a query or a fragment,
    /// an empty host, a bad port, or a host that is not ASCII (a browser sends an IDN host in
    /// its punycode form, so that is the form a door configures).
    fn parse(text: &str) -> Option<Origin> {
        let (scheme, rest) = text.split_once("://")?;
        let (scheme, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "http" => ("http", 80),
            "https" => ("https", 443),
            _ => return None,
        };
        if rest.is_empty()
            || !rest.is_ascii()
            || rest
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || "/?#@\\".contains(c))
        {
            return None;
        }
        let (host, port): (&str, Option<&str>) = if rest.starts_with('[') {
            // An IPv6 literal: `[` hex digits, `:` and `.` `]`, then nothing or `:port`.
            let close = rest.find(']')?;
            let inside = &rest[1..close];
            if inside.is_empty()
                || !inside
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || ":.".contains(c))
            {
                return None;
            }
            let after = &rest[close + 1..];
            let port = if after.is_empty() {
                None
            } else {
                Some(after.strip_prefix(':')?)
            };
            (&rest[..=close], port)
        } else {
            let (host, port) = match rest.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            };
            if host.contains(['[', ']']) {
                return None;
            }
            (host, port)
        };
        if host.is_empty() {
            return None;
        }
        let port = match port {
            None => default_port,
            Some(digits) if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) => {
                digits.parse().ok()?
            }
            Some(_) => return None,
        };
        Some(Origin {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// A door's configured origin that does not parse; see [`OriginCheck::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOrigin {
    origin: String,
    reason: &'static str,
}

impl InvalidOrigin {
    /// The configured text that was refused.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl std::fmt::Display for InvalidOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid door origin {:?}: {}", self.origin, self.reason)
    }
}

impl std::error::Error for InvalidOrigin {}

/// Refuse a state-changing request that another origin started. Build it from the door's own
/// origins, as configured; it never reads them off the request's `Host`, which is whatever
/// name the client used and, under DNS rebinding, the attacker's.
///
/// For `GET`, `HEAD` and `OPTIONS` it admits everything. For every other method it decides,
/// in this order:
///
/// 1. **`Origin` present**: admitted only when it is one of the configured origins (compared
///    as RFC 6454 compares them: scheme, lowercase host, port with the default filled in).
///    Anything else is refused, the opaque `Origin: null` (a sandboxed frame, or a request
///    redirected across origins) and a malformed value included. A request carrying two
///    `Origin` headers is refused.
/// 2. **No `Origin`, `Sec-Fetch-Site` present**: admitted when it is `same-origin` or `none`
///    (a person typed the address or chose a bookmark); refused when it is `same-site`,
///    `cross-site` or anything else. `same-site` is refused because a site is wider than an
///    origin: another port on `localhost`, or a sibling subdomain, is the same site.
/// 3. **Neither header**: the request did not come from a current browser, which sends
///    `Origin` on every write. It is admitted **only when it carries no ambient credential**:
///    no `Cookie` header, and no `Authorization` header in a scheme a browser replays on its
///    own (anything but `Bearer`; a browser re-sends cached `Basic`, `Digest` or `Negotiate`
///    credentials to the door, while a bearer token is only ever sent by a script that holds
///    it). So `curl -X POST` and an API client with a bearer token keep working, and a request
///    that brings a cookie must say where it came from. A non-browser client that sends its
///    own cookie adds the `Origin` header of the door it means.
///
/// A refusal is `403 Forbidden` with a fixed sentence; it never echoes the request's headers.
///
/// ```
/// use ikigai_web::{HttpRequest, OriginCheck};
///
/// let check = OriginCheck::new(["https://door.example"]).unwrap();
/// let post = |headers: &[(&str, &str)]| HttpRequest {
///     method: "POST".into(),
///     path: "/note/x".into(),
///     raw_target: "/note/x".into(),
///     query: vec![],
///     headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
///     body: vec![],
///     peer: None,
/// };
/// // Our own page writes; the default port is the same origin.
/// assert_eq!(check.check(&post(&[("origin", "https://door.example")])), None);
/// assert_eq!(check.check(&post(&[("origin", "https://DOOR.example:443")])), None);
/// // Another origin does not, nor an opaque one, nor another port.
/// for origin in ["https://evil.example", "null", "https://door.example:8443", "http://door.example"] {
///     assert_eq!(check.check(&post(&[("origin", origin)])).unwrap().status, 403, "{origin}");
/// }
/// // Without Origin, Sec-Fetch-Site decides.
/// assert_eq!(check.check(&post(&[("sec-fetch-site", "same-origin")])), None);
/// assert!(check.check(&post(&[("sec-fetch-site", "same-site")])).is_some());
/// // Neither: admitted without a cookie, refused with one.
/// assert_eq!(check.check(&post(&[])), None);
/// assert_eq!(check.check(&post(&[("authorization", "Bearer t")])), None);
/// assert!(check.check(&post(&[("cookie", "s=1")])).is_some());
/// assert!(check.check(&post(&[("authorization", "Basic dTpw")])).is_some());
/// // A read is never checked.
/// let mut get = post(&[("origin", "https://evil.example")]);
/// get.method = "GET".into();
/// assert_eq!(check.check(&get), None);
/// // A configured origin must be an origin.
/// assert!(OriginCheck::new(["https://door.example/app"]).is_err());
/// assert!(OriginCheck::new(Vec::<String>::new()).is_err());
/// ```
///
/// A door with checks of its own (a `Host` allowlist, say) calls [`check`](Self::check) inside
/// its own [`AdmitFn`] rather than taking [`admit_fn`](Self::admit_fn).
#[derive(Debug, Clone)]
pub struct OriginCheck {
    origins: Vec<Origin>,
}

const FOREIGN_ORIGIN: &str =
    "a write from another origin is refused: its Origin header does not name this door";
const OPAQUE_ORIGIN: &str =
    "a write whose Origin is opaque (null) or malformed is refused: this door cannot tell where it came from";
const FOREIGN_SITE: &str =
    "a write from another site is refused: its Sec-Fetch-Site header does not say same-origin";
const AMBIENT_WITHOUT_ORIGIN: &str =
    "a write that carries a cookie or browser credentials but no Origin or Sec-Fetch-Site is \
     refused: every current browser names its origin on a write, so a client sending its own \
     credentials sends the Origin header of this door too";
const DUPLICATE: &str = "a write carrying more than one Origin or Sec-Fetch-Site header is refused";

impl OriginCheck {
    /// A check that admits writes from these origins, each `scheme://host[:port]` with the
    /// scheme `http` or `https` and the host in ASCII (punycode for an IDN). A single trailing
    /// `/` is tolerated, since that is how a URL is often written down; a path, query,
    /// fragment, userinfo or `null` is refused, and so is an empty list, which would refuse
    /// every write and is more likely a missing configuration value than a policy.
    pub fn new<I, S>(origins: I) -> Result<OriginCheck, InvalidOrigin>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for text in origins {
            let text = text.as_ref();
            let trimmed = text.trim();
            let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
            let origin = Origin::parse(trimmed).ok_or_else(|| InvalidOrigin {
                origin: text.to_string(),
                reason: "expected scheme://host[:port] with scheme http or https, an ASCII host, \
                         and no path, query, fragment or userinfo",
            })?;
            if !parsed.contains(&origin) {
                parsed.push(origin);
            }
        }
        if parsed.is_empty() {
            return Err(InvalidOrigin {
                origin: String::new(),
                reason: "no origin configured: a door must name at least one origin of its own",
            });
        }
        Ok(OriginCheck { origins: parsed })
    }

    /// The refusal for `req`, or `None` to admit it. See [`OriginCheck`] for the rules.
    pub fn check(&self, req: &HttpRequest) -> Option<Refusal> {
        if SAFE_METHODS
            .iter()
            .any(|m| req.method.eq_ignore_ascii_case(m))
        {
            return None;
        }
        let refuse = |reason: &str| {
            Some(Refusal {
                status: 403,
                reason: reason.to_string(),
            })
        };
        let (Ok(origin), Ok(site)) = (only(req, "origin"), only(req, "sec-fetch-site")) else {
            return refuse(DUPLICATE);
        };
        if let Some(origin) = origin {
            return match Origin::parse(origin.trim()) {
                Some(o) if self.origins.contains(&o) => None,
                Some(_) => refuse(FOREIGN_ORIGIN),
                None => refuse(OPAQUE_ORIGIN),
            };
        }
        if let Some(site) = site {
            return match site.trim().to_ascii_lowercase().as_str() {
                "same-origin" | "none" => None,
                _ => refuse(FOREIGN_SITE),
            };
        }
        if carries_ambient_credential(req) {
            return refuse(AMBIENT_WITHOUT_ORIGIN);
        }
        None
    }

    /// This check as an [`AdmitFn`], for [`EdgeConfig::admit_fn`](crate::EdgeConfig::admit_fn).
    pub fn admit_fn(self) -> AdmitFn {
        Arc::new(move |req: &HttpRequest| self.check(req))
    }
}

/// The one value of header `name`: `Ok(None)` when absent, `Err` when it appears twice.
fn only<'a>(req: &'a HttpRequest, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = req
        .headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str());
    let first = values.next();
    match values.next() {
        Some(_) => Err(()),
        None => Ok(first),
    }
}

/// A credential a browser attaches to a request on its own, whichever page started it: any
/// `Cookie`, and `Authorization` in any scheme but `Bearer`.
fn carries_ambient_credential(req: &HttpRequest) -> bool {
    req.headers.iter().any(|(k, v)| {
        k == "cookie"
            || (k == "authorization"
                && !v
                    .trim_start()
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("bearer ")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_compare_as_rfc_6454_does() {
        let o = |s| Origin::parse(s);
        assert_eq!(o("https://a.example"), o("HTTPS://A.Example:443"));
        assert_eq!(o("http://a.example"), o("http://a.example:80"));
        assert_ne!(o("http://a.example"), o("https://a.example"));
        assert_ne!(o("http://a.example:8080"), o("http://a.example"));
        assert_eq!(o("http://[::1]:7000"), o("http://[::1]:7000"));
        assert_eq!(o("http://[::1]").unwrap().port, 80);
        for bad in [
            "null",
            "",
            "a.example",
            "ftp://a.example",
            "https://",
            "https://a.example/",
            "https://a.example/x",
            "https://u@a.example",
            "https://a.example?q",
            "https://a.example#f",
            "https://a.example:",
            "https://a.example:99999",
            "https://a.example:8x",
            "https://a b.example",
            "https://\u{e9}.example",
            "http://[::1",
            "http://[::1]x",
            "http://[zz]",
            "http://::1",
        ] {
            assert_eq!(o(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_configured_trailing_slash_is_tolerated_and_duplicates_collapse() {
        let check = OriginCheck::new(["https://a.example/", "https://A.example:443"]).unwrap();
        assert_eq!(check.origins.len(), 1);
        let err = OriginCheck::new(["https://a.example", "null"]).unwrap_err();
        assert_eq!(err.origin(), "null");
        assert!(
            err.to_string().contains("invalid door origin \"null\""),
            "{err}"
        );
    }
}
