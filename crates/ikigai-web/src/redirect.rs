//! A route's page IRI stays on this door, using the same table as the POST.
use crate::{decode_path, entity, iri_from_path, placeholder, RouteTable};

/// Prefer an authored page route; only use the mechanical mapping when the door allows
/// it. Round-trip every candidate through first-match routing: a shadowed path, a strict
/// capture refusal, or a different target is not a path to this page.
pub(super) fn page_path(table: &RouteTable, iri: &str, routes_only: bool) -> Option<String> {
    ikigai_core::Iri::parse(iri).ok()?;
    let reaches_page = |path: &str| {
        if entity::check_value("Location", path).is_err()
            || entity::check_same_origin("Location", path).is_err()
        {
            return false;
        }
        let Ok(decoded) = decode_path(path.as_bytes()) else {
            return false;
        };
        match table.match_path(&decoded) {
            Some(matched) => matched.iri.as_deref() == Ok(iri),
            None => !routes_only && iri_from_path(&decoded) == iri,
        }
    };
    for route in &table.routes {
        let Some(binds) = bindings(&route.iri_template, iri) else {
            continue;
        };
        let segments: Option<Vec<String>> = route
            .pattern
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|segment| {
                let value = match placeholder(segment) {
                    Some((name, _)) => binds.iter().find(|(n, _)| *n == name)?.1,
                    None => segment,
                };
                segment_url(value)
            })
            .collect();
        if let Some(segments) = segments {
            let path = format!("/{}", segments.join("/"));
            if reaches_page(&path) {
                return Some(path);
            }
        }
    }
    if !routes_only {
        let segments: Option<Vec<String>> = iri
            .strip_prefix("urn:")?
            .split(':')
            .map(segment_url)
            .collect();
        let path = format!("/{}", segments?.join("/"));
        if reaches_page(&path) {
            return Some(path);
        }
    }
    None
}

fn segment_url(value: &str) -> Option<String> {
    // Browsers remove dot segments even when the dots are percent-encoded.
    if matches!(value, "" | "." | "..") {
        return None;
    }
    Some(ikigai_fn::html::url_segment(value))
}

/// Invert simple/reserved template expansion. Adjacent placeholders have no boundary, so
/// cannot supply a unique path. Repeated names must carry the same value.
fn bindings<'a>(mut template: &'a str, mut iri: &'a str) -> Option<Vec<(&'a str, &'a str)>> {
    let mut binds = Vec::new();
    while let Some(open) = template.find('{') {
        iri = iri.strip_prefix(&template[..open])?;
        template = &template[open..];
        let close = template.find('}')?;
        let (name, _) = placeholder(&template[..=close])?;
        template = &template[close + 1..];
        let literal = template.split('{').next()?;
        let end = if template.is_empty() {
            iri.len()
        } else if literal.is_empty() {
            return None;
        } else {
            iri.find(literal)?
        };
        let (value, rest) = iri.split_at(end);
        if binds.iter().any(|(n, v)| *n == name && *v != value) {
            return None;
        }
        binds.push((name, value));
        iri = rest;
    }
    (template == iri).then_some(binds)
}
