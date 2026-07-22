//! Load an [`ikigai_web::RouteTable`] from an RDF route resource (e.g. `urn:web:routes`).
//!
//! The route table is *authored data*. An RDF route graph (`ik:Route` nodes, in Turtle /
//! JSON-LD / …) is queried through the kernel's own SPARQL (`urn:sparql:select`) rather than
//! parsed with a bespoke RDF reader in the transport. A plain **non-LD JSON** route file is
//! parsed directly — the LD-allergy authoring face — so a developer can write routes without
//! touching RDF. The loader sniffs which it is. The route resource is resolved by IRI, so it
//! can be a watched file (`urn:file:web/routes.ttl` → hot-reload), a mounted config resource,
//! or anything else the kernel can `Source`.

use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};
use ikigai_web::{CorsPolicy, Route, RouteTable};

/// One row per `ik:Route`; multi-valued fields (`ik:cap`, the CORS lists) are folded with
/// `GROUP_CONCAT` (newline-separated) so each route is a single solution. Ordered by
/// `ik:order` so first-match-wins is deterministic.
const ROUTE_QUERY: &str = r#"
PREFIX ik: <https://ikigai-rs.dev/ns#>
SELECT ?match ?target ?order ?csp ?corsCredentials ?corsMaxAge
       (GROUP_CONCAT(DISTINCT ?cap; SEPARATOR="\n") AS ?caps)
       (GROUP_CONCAT(DISTINCT ?corsOrigin; SEPARATOR="\n") AS ?corsOrigins)
       (GROUP_CONCAT(DISTINCT ?corsMethod; SEPARATOR="\n") AS ?corsMethods)
       (GROUP_CONCAT(DISTINCT ?corsHeader; SEPARATOR="\n") AS ?corsHeaders)
WHERE {
  ?route a ik:Route ;
         ik:match  ?match ;
         ik:target ?target .
  OPTIONAL { ?route ik:order ?order }
  OPTIONAL { ?route ik:csp   ?csp }
  OPTIONAL { ?route ik:cap   ?cap }
  OPTIONAL {
    ?route ik:cors ?cors .
    OPTIONAL { ?cors ik:corsOrigin      ?corsOrigin }
    OPTIONAL { ?cors ik:corsMethod      ?corsMethod }
    OPTIONAL { ?cors ik:corsHeader      ?corsHeader }
    OPTIONAL { ?cors ik:corsCredentials ?corsCredentials }
    OPTIONAL { ?cors ik:corsMaxAge      ?corsMaxAge }
  }
}
GROUP BY ?route ?match ?target ?order ?csp ?corsCredentials ?corsMaxAge
ORDER BY ?order
"#;

/// If `routes_iri` is a `urn:file:<rel>` resource, its path under `file_root` — the file to
/// watch for hot-reload. Other IRIs (a mounted config resource, a remote) have no local
/// mtime to poll, so they return `None` (loaded once, no auto-reload).
pub fn watch_path(routes_iri: &str, file_root: &std::path::Path) -> Option<std::path::PathBuf> {
    routes_iri
        .strip_prefix("urn:file:")
        .map(|rel| file_root.join(rel.trim_start_matches('/')))
}

/// Load the [`RouteTable`] from `routes_iri`, choosing the parser by format: a plain-JSON
/// route file (the non-LD authoring face) is parsed directly; anything else is treated as an
/// RDF route graph and queried through the kernel's SPARQL.
pub async fn load_route_table(
    kernel: &Kernel,
    routes_iri: &str,
    cap: &Capability,
) -> Result<RouteTable, String> {
    // Peek the resource to pick the format.
    let iri = Iri::parse(routes_iri).map_err(|e| format!("bad routes IRI `{routes_iri}`: {e}"))?;
    let peek = kernel
        .issue(Request::new(Verb::Source, iri), cap)
        .await
        .map_err(|e| format!("resolving {routes_iri}: {e}"))?;
    if looks_like_json(&peek.bytes) {
        return parse_json_routes(&peek.bytes);
    }
    if routes_iri.ends_with(".yaml") || routes_iri.ends_with(".yml") {
        return parse_yaml_routes(&peek.bytes);
    }
    // An RDF graph → query it through the kernel's SPARQL (dogfood).
    let select = Iri::parse("urn:sparql:select").map_err(|e| e.to_string())?;
    let request = Request::new(Verb::Source, select)
        .with_arg("query", ArgRef::Inline(ROUTE_QUERY.as_bytes().to_vec()))
        .with_arg("graph", ArgRef::Inline(routes_iri.as_bytes().to_vec()));
    let repr = kernel
        .issue(request, cap)
        .await
        .map_err(|e| format!("querying {routes_iri}: {e}"))?;
    parse_route_solutions(&repr.bytes)
}

/// The first non-whitespace byte is `{` — a JSON object (the non-LD route face). A Turtle
/// graph never starts that way (`@prefix`, `<…>`, `#`, `PREFIX`…), so this cleanly splits the
/// two authoring formats without a media-type dependency.
fn looks_like_json(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .map(|b| *b == b'{')
        .unwrap_or(false)
}

/// Parse the plain non-LD route JSON directly into a [`RouteTable`] — no `@`-noise, no RDF:
/// the LD-allergy authoring face. Shape:
///
/// ```json
/// { "routes": [ { "match": "/book/{host}", "target": "urn:schedule:{host}",
///                 "order": 10, "cap": ["urn:cap:…"], "csp": "…",
///                 "cors": { "origin": ["https://…"], "maxAge": 600 } } ] }
/// ```
///
/// Extra keys (e.g. a friendly `"id"`) are ignored; `order` sorts (first-match-wins).
pub fn parse_json_routes(bytes: &[u8]) -> Result<RouteTable, String> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("route JSON: {e}"))?;
    routes_from_value(&v)
}

/// The same non-LD route shape authored in YAML — which parses to the same value tree, so it
/// shares [`routes_from_value`]. (YAML is a superset of JSON; a Turtle graph isn't valid YAML,
/// so YAML is selected by the resource's `.yaml`/`.yml` suffix, not by sniffing.)
pub fn parse_yaml_routes(bytes: &[u8]) -> Result<RouteTable, String> {
    let v: serde_json::Value =
        serde_yaml::from_slice(bytes).map_err(|e| format!("route YAML: {e}"))?;
    routes_from_value(&v)
}

/// Build the [`RouteTable`] from a parsed non-LD route document (JSON or YAML → the same
/// value tree).
fn routes_from_value(v: &serde_json::Value) -> Result<RouteTable, String> {
    let arr = v
        .get("routes")
        .and_then(|r| r.as_array())
        .ok_or_else(|| "route JSON: missing a `routes` array".to_string())?;
    let strs = |val: &serde_json::Value, k: &str| -> Vec<String> {
        val.get(k)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut ordered: Vec<(i64, Route)> = Vec::new();
    for r in arr {
        let (pattern, iri_template) = match (
            r.get("match").and_then(|x| x.as_str()),
            r.get("target").and_then(|x| x.as_str()),
        ) {
            (Some(m), Some(t)) => (m.to_string(), t.to_string()),
            _ => continue,
        };
        let cors = r.get("cors").filter(|c| c.is_object()).and_then(|c| {
            let origins = strs(c, "origin");
            let methods = strs(c, "method");
            let headers = strs(c, "header");
            let credentials = c
                .get("credentials")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let max_age = c.get("maxAge").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let empty = origins.is_empty()
                && methods.is_empty()
                && headers.is_empty()
                && !credentials
                && max_age == 0;
            (!empty).then_some(CorsPolicy {
                allowed_origins: origins,
                allowed_methods: methods,
                allowed_headers: headers,
                allow_credentials: credentials,
                max_age,
            })
        });
        let caps = strs(r, "cap");
        let order = r.get("order").and_then(|x| x.as_i64()).unwrap_or(0);
        ordered.push((
            order,
            Route {
                pattern,
                iri_template,
                cap: (!caps.is_empty()).then_some(caps),
                cors,
                csp: r.get("csp").and_then(|x| x.as_str()).map(String::from),
            },
        ));
    }
    ordered.sort_by_key(|(o, _)| *o);
    Ok(RouteTable::new(
        ordered.into_iter().map(|(_, r)| r).collect(),
    ))
}

/// Parse SPARQL SELECT results (`application/sparql-results+json`) into a [`RouteTable`].
pub fn parse_route_solutions(json: &[u8]) -> Result<RouteTable, String> {
    let v: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("route results are not JSON: {e}"))?;
    let bindings = v
        .get("results")
        .and_then(|r| r.get("bindings"))
        .and_then(|b| b.as_array())
        .ok_or_else(|| "route results: missing results.bindings".to_string())?;

    let mut routes = Vec::new();
    for b in bindings {
        let val = |k: &str| {
            b.get(k)
                .and_then(|x| x.get("value"))
                .and_then(|x| x.as_str())
        };
        // A GROUP_CONCAT field back into its list (empty string → no values).
        let list = |k: &str| -> Vec<String> {
            val(k)
                .map(|s| {
                    s.split('\n')
                        .filter(|t| !t.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        };

        // match + target are required; a Route missing either is malformed — skip it.
        let (pattern, iri_template) = match (val("match"), val("target")) {
            (Some(m), Some(t)) => (m.to_string(), t.to_string()),
            _ => continue,
        };

        let origins = list("corsOrigins");
        let methods = list("corsMethods");
        let headers = list("corsHeaders");
        let credentials = val("corsCredentials") == Some("true");
        let max_age = val("corsMaxAge")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let cors = if !origins.is_empty()
            || !methods.is_empty()
            || !headers.is_empty()
            || credentials
            || max_age > 0
        {
            Some(CorsPolicy {
                allowed_origins: origins,
                allowed_methods: methods,
                allowed_headers: headers,
                allow_credentials: credentials,
                max_age,
            })
        } else {
            None
        };

        let caps = list("caps");
        routes.push(Route {
            pattern,
            iri_template,
            cap: if caps.is_empty() { None } else { Some(caps) },
            cors,
            csp: val("csp").map(String::from),
        });
    }
    Ok(RouteTable::new(routes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_route_with_cap_csp_and_cors() {
        // A SPARQL results JSON as urn:sparql:select would return for one route.
        let json = br#"{
          "head": {"vars": ["match","target","csp","caps","corsOrigins","corsMaxAge"]},
          "results": {"bindings": [
            {
              "match":  {"type":"literal","value":"/book/{host}"},
              "target": {"type":"literal","value":"urn:schedule:{host}"},
              "csp":    {"type":"literal","value":"default-src 'self'"},
              "caps":   {"type":"literal","value":"urn:cap:personal:calendar:read:freebusy"},
              "corsOrigins": {"type":"literal","value":"https://sletten.com"},
              "corsMaxAge":  {"type":"literal","value":"600"}
            }
          ]}
        }"#;
        let table = parse_route_solutions(json).unwrap();
        assert_eq!(table.routes.len(), 1);
        let r = &table.routes[0];
        assert_eq!(r.pattern, "/book/{host}");
        assert_eq!(r.iri_template, "urn:schedule:{host}");
        assert_eq!(
            r.cap.as_deref(),
            Some(&["urn:cap:personal:calendar:read:freebusy".to_string()][..])
        );
        assert_eq!(r.csp.as_deref(), Some("default-src 'self'"));
        let cors = r.cors.as_ref().expect("cors");
        assert_eq!(cors.allowed_origins, vec!["https://sletten.com"]);
        assert_eq!(cors.max_age, 600);
    }

    #[test]
    fn multivalued_caps_split_on_newline() {
        let json = br#"{"head":{"vars":[]},"results":{"bindings":[
          {"match":{"type":"literal","value":"/a"},"target":{"type":"literal","value":"urn:a"},
           "caps":{"type":"literal","value":"urn:cap:x\nurn:cap:y"}}
        ]}}"#;
        let table = parse_route_solutions(json).unwrap();
        assert_eq!(
            table.routes[0].cap.as_deref(),
            Some(&["urn:cap:x".to_string(), "urn:cap:y".to_string()][..])
        );
    }

    #[test]
    fn a_route_without_cors_or_cap_is_bare() {
        let json = br#"{"head":{"vars":[]},"results":{"bindings":[
          {"match":{"type":"literal","value":"/a"},"target":{"type":"literal","value":"urn:a"}}
        ]}}"#;
        let table = parse_route_solutions(json).unwrap();
        let r = &table.routes[0];
        assert!(r.cap.is_none() && r.cors.is_none() && r.csp.is_none());
    }

    #[test]
    fn no_bindings_is_an_empty_table() {
        let json = br#"{"head":{"vars":[]},"results":{"bindings":[]}}"#;
        assert_eq!(parse_route_solutions(json).unwrap().routes.len(), 0);
    }

    #[test]
    fn json_route_file_parses_directly() {
        let json = br#"{
          "routes": [
            { "id": "api", "order": 20, "match": "/api/{what}", "target": "urn:kernel:{what}",
              "cap": ["urn:cap:a", "urn:cap:b"],
              "cors": { "origin": ["https://app.example"], "maxAge": 600 } },
            { "id": "home", "order": 10, "match": "/", "target": "urn:host:info" }
          ]
        }"#;
        let table = parse_json_routes(json).unwrap();
        assert_eq!(table.routes.len(), 2);
        // sorted by order → home (10) first, api (20) second
        assert_eq!(table.routes[0].pattern, "/");
        assert_eq!(table.routes[1].pattern, "/api/{what}");
        let api = &table.routes[1];
        assert_eq!(api.iri_template, "urn:kernel:{what}");
        assert_eq!(
            api.cap.as_deref(),
            Some(&["urn:cap:a".to_string(), "urn:cap:b".to_string()][..])
        );
        let cors = api.cors.as_ref().unwrap();
        assert_eq!(cors.allowed_origins, vec!["https://app.example"]);
        assert_eq!(cors.max_age, 600);
        // The bare home route has no cap/cors/csp.
        assert!(table.routes[0].cap.is_none() && table.routes[0].cors.is_none());
    }

    #[test]
    fn yaml_route_file_parses_to_the_same_table() {
        let yaml = br#"
routes:
  - id: api
    order: 20
    match: "/api/{what}"
    target: "urn:kernel:{what}"
    cap: [urn:cap:a, urn:cap:b]
    cors:
      origin: [https://app.example]
      maxAge: 600
  - id: home
    order: 10
    match: "/"
    target: urn:host:info
"#;
        let table = parse_yaml_routes(yaml).unwrap();
        assert_eq!(table.routes.len(), 2);
        assert_eq!(table.routes[0].pattern, "/"); // order 10 first
        let api = &table.routes[1];
        assert_eq!(api.iri_template, "urn:kernel:{what}");
        assert_eq!(
            api.cap.as_deref(),
            Some(&["urn:cap:a".to_string(), "urn:cap:b".to_string()][..])
        );
        assert_eq!(api.cors.as_ref().unwrap().max_age, 600);
    }

    #[test]
    fn looks_like_json_splits_the_formats() {
        assert!(looks_like_json(b"  \n { \"routes\": [] }"));
        assert!(!looks_like_json(
            b"@prefix ik: <https://ikigai-rs.dev/ns#> ."
        ));
        assert!(!looks_like_json(b"# a comment\n@prefix ik: <...> ."));
        assert!(!looks_like_json(b""));
    }

    #[test]
    fn watch_path_only_resolves_urn_file_resources() {
        let root = std::path::Path::new("/root");
        assert_eq!(
            watch_path("urn:file:web/routes.ttl", root),
            Some(std::path::PathBuf::from("/root/web/routes.ttl"))
        );
        // A non-file resource has no local mtime to poll.
        assert_eq!(watch_path("urn:web:routes", root), None);
        assert_eq!(watch_path("https://example.com/routes.ttl", root), None);
    }
}
