//! Host-declared read redirects, independent of endpoint write redirects.
use crate::{entity, HeaderRefusal, HttpRequest, Resp};

/// An opt-in same-origin read redirect for [`crate::EdgeConfig::read_redirects`].
/// Matching uses the raw, encoded path, is case-sensitive, and ignores the query.
/// Rules run in declaration order, before push or resource dispatch, including on
/// routes-only doors. They never invoke an endpoint or change a write's response.
#[derive(Clone, Debug)]
pub struct ReadRedirect {
    rule: Rule,
}

#[derive(Clone, Debug)]
enum Rule {
    Exact { path: String, destination: String },
    TrailingSlash { prefix: String },
}

impl ReadRedirect {
    /// Redirect exactly `path` to `destination`. Both must be same-origin absolute
    /// paths without a query or fragment. The request's raw query is appended unchanged.
    pub fn exact(path: &str, destination: &str) -> Result<Self, HeaderRefusal> {
        check_path(path)?;
        check_path(destination)?;
        Ok(Self {
            rule: Rule::Exact {
                path: path.into(),
                destination: destination.into(),
            },
        })
    }

    /// Append `/` to the bare prefix or exactly one non-empty segment below it.
    /// `prefix` must end in `/`; `/face/name/` matches `/face/name` and
    /// `/face/name/board`, but not `/face/name/board/app.js` or `/face/names`.
    /// Already-slashed paths are unchanged. Segments use the raw encoded path,
    /// so an encoded slash (`%2f`) is part of a segment, not a separator.
    pub fn trailing_slash(prefix: &str) -> Result<Self, HeaderRefusal> {
        check_path(prefix)?;
        if !prefix.ends_with('/') {
            return Err(HeaderRefusal::new(
                "Location",
                "read redirect prefix must end in /",
            ));
        }
        Ok(Self {
            rule: Rule::TrailingSlash {
                prefix: prefix.into(),
            },
        })
    }
}

fn check_path(path: &str) -> Result<(), HeaderRefusal> {
    entity::check_value("Location", path)?;
    entity::check_same_origin("Location", path)?;
    if !path.starts_with('/')
        || path.contains(['?', '#'])
        || path.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(HeaderRefusal::new(
            "Location",
            "read redirect must be an absolute path without a query, fragment or whitespace",
        ));
    }
    Ok(())
}

pub(super) fn response(rules: &[ReadRedirect], req: &HttpRequest) -> Option<Resp> {
    if !matches!(req.method.as_str(), "GET" | "HEAD") {
        return None;
    }
    let (path, query) = req
        .raw_target
        .split_once('?')
        .map_or((req.raw_target.as_str(), None), |(p, q)| (p, Some(q)));
    for rule in rules {
        let destination = match &rule.rule {
            Rule::Exact {
                path: source,
                destination,
            } if path == source && path != destination => destination.clone(),
            Rule::TrailingSlash { prefix }
                if !path.ends_with('/')
                    && (path == &prefix[..prefix.len() - 1]
                        || path.strip_prefix(prefix).is_some_and(|segment| {
                            !segment.is_empty() && !segment.contains('/')
                        })) =>
            {
                format!("{path}/")
            }
            _ => continue,
        };
        let location = match query {
            Some(query) => format!("{destination}?{query}"),
            None => destination,
        };
        // A raw request path is untrusted too: it must not turn Location into an
        // off-origin reference, nor write bytes the header writer cannot carry.
        if check_path(
            location
                .split_once('?')
                .map_or(location.as_str(), |(p, _)| p),
        )
        .is_err()
            || entity::check_value("Location", &location).is_err()
        {
            return Some(Resp::text(
                400,
                "Bad Request",
                "invalid read redirect location",
            ));
        }
        let mut resp = Resp::status(308, "Permanent Redirect");
        resp.headers.push(("Location".into(), location));
        return Some(resp);
    }
    None
}
