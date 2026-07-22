//! Load an [`ikigai_web::RouteTable`] from an RDF route resource (e.g. `urn:web:routes`).
//!
//! The route table is *authored data* — a graph of `ik:Route` nodes — so it's queried
//! through the kernel's own SPARQL (`urn:sparql:select` over the route graph) rather than
//! parsed with a bespoke RDF reader wired into the HTTP transport. The route resource is
//! resolved by IRI, so it can be a watched file (`urn:file:web/routes.ttl` → golden-thread
//! reload), a mounted config resource, or anything else the kernel can `Source`.

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

/// Query `routes_iri` through the kernel's SPARQL and build the [`RouteTable`].
pub async fn load_route_table(
    kernel: &Kernel,
    routes_iri: &str,
    cap: &Capability,
) -> Result<RouteTable, String> {
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
}
