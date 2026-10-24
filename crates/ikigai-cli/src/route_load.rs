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
///
/// ★ `ik:cap` is read as `STR(?cap)`, so a capability authored as a literal
/// (`ik:cap "urn:cap:…"`) and one authored as an IRI (`ik:cap <urn:cap:…>`) both load
/// (ledger #30). `GROUP_CONCAT` over a set holding even one IRI leaves the WHOLE aggregate
/// unbound, and before this the route then loaded with no ceiling at all, which is the
/// server's default capability: fail-open. `?capCount` counts the cap triples on their own,
/// so [`parse_route_solutions`] can refuse a route that has caps but reads as none.
///
/// The CORS lists (`ik:corsOrigin`, `ik:corsMethod`, `ik:corsHeader`) are read the same way,
/// each with its own count. One IRI among them used to drop the whole list silently, and an
/// empty method or header list is not "none allowed": it means the resource's own `Allow`
/// list, or echo the requested headers, which is wider than what was authored.
const ROUTE_QUERY: &str = r#"
PREFIX ik: <https://ikigai-rs.dev/ns#>
SELECT ?match ?target ?order ?csp ?redirect ?corsCredentials ?corsMaxAge
       (GROUP_CONCAT(DISTINCT STR(?cap); SEPARATOR="\n") AS ?caps)
       (COUNT(DISTINCT ?cap) AS ?capCount)
       (GROUP_CONCAT(DISTINCT STR(?corsOrigin); SEPARATOR="\n") AS ?corsOrigins)
       (COUNT(DISTINCT ?corsOrigin) AS ?corsOriginCount)
       (GROUP_CONCAT(DISTINCT STR(?corsMethod); SEPARATOR="\n") AS ?corsMethods)
       (COUNT(DISTINCT ?corsMethod) AS ?corsMethodCount)
       (GROUP_CONCAT(DISTINCT STR(?corsHeader); SEPARATOR="\n") AS ?corsHeaders)
       (COUNT(DISTINCT ?corsHeader) AS ?corsHeaderCount)
WHERE {
  ?route a ik:Route ;
         ik:match  ?match ;
         ik:target ?target .
  OPTIONAL { ?route ik:order ?order }
  OPTIONAL { ?route ik:csp   ?csp }
  OPTIONAL { ?route ik:redirect ?redirect }
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
GROUP BY ?route ?match ?target ?order ?csp ?redirect ?corsCredentials ?corsMaxAge
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
/// Patterns and templates pass through as written, so a raw `{+var}` (see
/// [`ikigai_web::Route`]) needs no loader support.
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
                redirect: r.get("redirect").and_then(|x| x.as_str()).map(String::from),
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
///
/// Fail-closed on capabilities: a solution whose `capCount` says the route has `ik:cap`
/// values but whose `caps` yields none (a blank node has no string form and unbinds the
/// aggregate; an empty literal concatenates to nothing) is a load ERROR, never a route
/// without a ceiling. The CORS lists get the same check against `corsOriginCount`,
/// `corsMethodCount` and `corsHeaderCount`.
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

        let origins = counted(
            &pattern,
            "ik:corsOrigin",
            list("corsOrigins"),
            val("corsOriginCount"),
        )?;
        let methods = counted(
            &pattern,
            "ik:corsMethod",
            list("corsMethods"),
            val("corsMethodCount"),
        )?;
        let headers = counted(
            &pattern,
            "ik:corsHeader",
            list("corsHeaders"),
            val("corsHeaderCount"),
        )?;
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

        let caps = counted(&pattern, "ik:cap", list("caps"), val("capCount"))?;
        routes.push(Route {
            pattern,
            iri_template,
            redirect: val("redirect").map(String::from),
            cap: if caps.is_empty() { None } else { Some(caps) },
            cors,
            csp: val("csp").map(String::from),
        });
    }
    Ok(RouteTable::new(routes))
}

/// A `GROUP_CONCAT` list checked against its own `COUNT`: when the route has values for
/// `prop` (`count` > 0) and none reads as a string (a blank node has no `STR`, which unbinds
/// the aggregate; an empty literal concatenates to nothing), loading it without them would
/// silently change what the route allows, so it is a load ERROR naming the route.
fn counted(
    pattern: &str,
    prop: &str,
    values: Vec<String>,
    count: Option<&str>,
) -> Result<Vec<String>, String> {
    let lost = if prop == "ik:cap" {
        "its ceiling"
    } else {
        "that list"
    };
    let count = match count {
        None => 0,
        Some(n) => n
            .parse::<u64>()
            .map_err(|_| format!("route `{pattern}`: the `{prop}` count is not a count: `{n}`"))?,
    };
    if count > 0 && values.is_empty() {
        return Err(format!(
            "route `{pattern}` has {count} `{prop}` value(s) and none reads as a string (a \
             blank node or an empty string?); refusing to load it without {lost}"
        ));
    }
    Ok(values)
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
            { "id": "api", "order": 20, "match": "/api/{what}", "target": "urn:kernel:{what}", "redirect": "urn:page:{what}",
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
        assert_eq!(api.redirect.as_deref(), Some("urn:page:{what}"));
        assert!(table.routes[0].redirect.is_none());
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
    redirect: "urn:page:{what}"
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
        assert_eq!(api.redirect.as_deref(), Some("urn:page:{what}"));
        assert!(table.routes[0].redirect.is_none());
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

    // ---- The RDF face through the real `urn:sparql:select` (ledger #30, step 1) ----------
    //
    // The tests above hand `parse_route_solutions` canned results, so they cannot see what the
    // QUERY does with an `ik:cap` value. These run `ROUTE_QUERY` through ikigai-sparql exactly
    // as `load_route_table` does in the binary, over a Turtle route graph that a fixture
    // endpoint serves at `urn:test:routes`.

    /// `load_route_table` over the Turtle `body` (the `ik:` prefix is supplied).
    fn load_turtle(body: &str) -> Result<RouteTable, String> {
        use ikigai_core::{Exact, FnEndpoint, Invocation, ReprType, Representation};
        let ttl = format!("@prefix ik: <https://ikigai-rs.dev/ns#> .\n{body}");
        let doc = FnEndpoint::new("routes-fixture", move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/turtle"),
                ttl.clone().into_bytes(),
            ))
        });
        let kernel = Kernel::new(std::sync::Arc::new(
            ikigai_sparql::space().bind(Exact::new("urn:test:routes"), doc),
        ));
        futures::executor::block_on(load_route_table(
            &kernel,
            "urn:test:routes",
            &Capability::root(),
        ))
    }

    #[test]
    fn a_redirect_page_iri_loads_from_turtle_as_an_iri_or_literal() {
        let table = load_turtle(
            r#"<urn:test:route:iri> a ik:Route ; ik:match "/note" ;
                 ik:target "urn:note" ; ik:redirect <urn:page:inspector> .
               <urn:test:route:literal> a ik:Route ; ik:match "/note/{name}" ;
                 ik:target "urn:note:{name}" ; ik:redirect "urn:page:{name}" .
               <urn:test:route:plain> a ik:Route ; ik:match "/plain" ;
                 ik:target "urn:plain" ."#,
        )
        .expect("loads");
        for (pattern, expected) in [
            ("/note", Some("urn:page:inspector")),
            ("/note/{name}", Some("urn:page:{name}")),
            ("/plain", None),
        ] {
            let route = table.routes.iter().find(|r| r.pattern == pattern).unwrap();
            assert_eq!(route.redirect.as_deref(), expected);
        }
    }

    /// The sorted caps of the route matching `pattern`.
    fn caps_of(table: &RouteTable, pattern: &str) -> Option<Vec<String>> {
        let route = table
            .routes
            .iter()
            .find(|r| r.pattern == pattern)
            .unwrap_or_else(|| {
                let patterns: Vec<&str> = table.routes.iter().map(|r| r.pattern.as_str()).collect();
                panic!("no route `{pattern}` in {patterns:?}")
            });
        route.cap.clone().map(|mut caps| {
            caps.sort();
            caps
        })
    }

    #[test]
    fn a_literal_cap_loads() {
        let table = load_turtle(
            r#"<urn:test:route:a> a ik:Route ; ik:match "/a" ; ik:target "urn:a" ;
                 ik:cap "urn:cap:a" , "urn:cap:b" ."#,
        )
        .expect("loads");
        assert_eq!(
            caps_of(&table, "/a"),
            Some(vec!["urn:cap:a".to_string(), "urn:cap:b".to_string()])
        );
    }

    /// The hazard the design note measured: `GROUP_CONCAT(?cap)` over a set holding one IRI
    /// leaves the WHOLE aggregate unbound, so the route loaded with no ceiling at all and the
    /// server's default capability applied. Fail-open; `STR(?cap)` reads both spellings.
    #[test]
    fn an_iri_cap_loads_as_its_ceiling() {
        let table = load_turtle(
            r#"<urn:test:route:a> a ik:Route ; ik:match "/a" ; ik:target "urn:a" ;
                 ik:cap <urn:cap:a> ."#,
        )
        .expect("loads");
        assert_eq!(caps_of(&table, "/a"), Some(vec!["urn:cap:a".to_string()]));
    }

    #[test]
    fn a_mixed_table_loads_every_cap_on_every_route() {
        let table = load_turtle(
            r#"<urn:test:route:lit> a ik:Route ; ik:match "/lit" ; ik:target "urn:lit" ;
                 ik:order 1 ; ik:cap "urn:cap:lit" .
               <urn:test:route:iri> a ik:Route ; ik:match "/iri" ; ik:target "urn:iri" ;
                 ik:order 2 ; ik:cap <urn:cap:iri> .
               <urn:test:route:both> a ik:Route ; ik:match "/both" ; ik:target "urn:both" ;
                 ik:order 3 ; ik:cap <urn:cap:x> , "urn:cap:y" .
               <urn:test:route:none> a ik:Route ; ik:match "/none" ; ik:target "urn:none" ;
                 ik:order 4 ."#,
        )
        .expect("loads");
        assert_eq!(table.routes.len(), 4);
        assert_eq!(
            caps_of(&table, "/lit"),
            Some(vec!["urn:cap:lit".to_string()])
        );
        assert_eq!(
            caps_of(&table, "/iri"),
            Some(vec!["urn:cap:iri".to_string()])
        );
        assert_eq!(
            caps_of(&table, "/both"),
            Some(vec!["urn:cap:x".to_string(), "urn:cap:y".to_string()])
        );
        // A route that declares no cap is still the server default, by design.
        assert_eq!(caps_of(&table, "/none"), None);
    }

    /// A route whose `ik:cap` triples exist but read as no capability string must not load
    /// as a route without a ceiling. A blank node has no `STR`, so the aggregate comes back
    /// unbound; an empty literal concatenates to nothing. Both are refused, naming the route.
    #[test]
    fn a_route_whose_caps_read_as_nothing_is_a_load_error() {
        for (label, cap) in [("a blank node", "[]"), ("an empty literal", r#""""#)] {
            let body = format!(
                r#"<urn:test:route:ok> a ik:Route ; ik:match "/ok" ; ik:target "urn:ok" .
                   <urn:test:route:bad> a ik:Route ; ik:match "/bad" ; ik:target "urn:bad" ;
                     ik:cap {cap} ."#
            );
            let Err(err) = load_turtle(&body) else {
                panic!("{label}: the route loaded without its ceiling");
            };
            assert!(
                err.contains("/bad") && err.contains("ik:cap"),
                "{label}: {err}"
            );
        }
    }

    /// The same check on the parsed results: a solution that counts caps but carries none.
    #[test]
    fn a_counted_cap_with_no_value_is_refused_by_the_parser() {
        let json = br#"{"head":{"vars":[]},"results":{"bindings":[
          {"match":{"type":"literal","value":"/a"},"target":{"type":"literal","value":"urn:a"},
           "capCount":{"type":"literal","value":"1",
                       "datatype":"http://www.w3.org/2001/XMLSchema#integer"}}
        ]}}"#;
        let Err(err) = parse_route_solutions(json) else {
            panic!("a counted cap with no value loaded without its ceiling");
        };
        assert!(err.contains("/a"), "{err}");
    }

    /// The parser's half for a CORS list: a solution that counts origins but carries none.
    #[test]
    fn a_counted_cors_origin_with_no_value_is_refused_by_the_parser() {
        let json = br#"{"head":{"vars":[]},"results":{"bindings":[
          {"match":{"type":"literal","value":"/a"},"target":{"type":"literal","value":"urn:a"},
           "corsOriginCount":{"type":"literal","value":"2",
                       "datatype":"http://www.w3.org/2001/XMLSchema#integer"}}
        ]}}"#;
        let Err(err) = parse_route_solutions(json) else {
            panic!("a counted origin with no value loaded without its list");
        };
        assert!(err.contains("/a") && err.contains("ik:corsOrigin"), "{err}");
    }

    // ---- The CORS lists: the same aggregate hazard as `ik:cap` ----------------------------

    /// The CORS policy of the route matching `pattern`, its lists sorted.
    fn cors_of(table: &RouteTable, pattern: &str) -> Option<CorsPolicy> {
        let route = table.routes.iter().find(|r| r.pattern == pattern)?;
        route.cors.clone().map(|mut c| {
            c.allowed_origins.sort();
            c.allowed_methods.sort();
            c.allowed_headers.sort();
            c
        })
    }

    fn strings(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn literal_cors_lists_load() {
        let table = load_turtle(
            r#"<urn:test:route:a> a ik:Route ; ik:match "/a" ; ik:target "urn:a" ;
                 ik:cors [ ik:corsOrigin "https://a.example" , "https://b.example" ;
                           ik:corsMethod "GET" ; ik:corsHeader "x-one" ] ."#,
        )
        .expect("loads");
        let cors = cors_of(&table, "/a").expect("a CORS policy");
        assert_eq!(
            cors.allowed_origins,
            strings(&["https://a.example", "https://b.example"])
        );
        assert_eq!(cors.allowed_methods, strings(&["GET"]));
        assert_eq!(cors.allowed_headers, strings(&["x-one"]));
    }

    /// `GROUP_CONCAT` over a set holding even one IRI leaves the WHOLE aggregate unbound, so
    /// an origin authored as `<https://…>` silently dropped every origin on the route, and an
    /// empty method or header list then means "the resource's own Allow list" or "echo the
    /// requested headers": a WIDER policy than the one authored. `STR(…)` reads both.
    #[test]
    fn iri_cors_values_load_beside_literals() {
        let table = load_turtle(
            r#"<urn:test:route:a> a ik:Route ; ik:match "/a" ; ik:target "urn:a" ;
                 ik:cors [ ik:corsOrigin <https://a.example> , "https://b.example" ;
                           ik:corsMethod <urn:test:GET> , "POST" ;
                           ik:corsHeader <urn:test:x-one> , "x-two" ] ."#,
        )
        .expect("loads");
        let cors = cors_of(&table, "/a").expect("a CORS policy");
        assert_eq!(
            cors.allowed_origins,
            strings(&["https://a.example", "https://b.example"])
        );
        assert_eq!(cors.allowed_methods, strings(&["POST", "urn:test:GET"]));
        assert_eq!(cors.allowed_headers, strings(&["urn:test:x-one", "x-two"]));
    }

    /// A CORS list whose triples exist but read as no string (a blank node, an empty literal)
    /// is a load error naming the route and the property, never a policy that silently lost
    /// the list.
    #[test]
    fn a_cors_list_that_reads_as_nothing_is_a_load_error() {
        for prop in ["ik:corsOrigin", "ik:corsMethod", "ik:corsHeader"] {
            for (label, value) in [("a blank node", "[]"), ("an empty literal", r#""""#)] {
                let body = format!(
                    r#"<urn:test:route:ok> a ik:Route ; ik:match "/ok" ; ik:target "urn:ok" .
                       <urn:test:route:bad> a ik:Route ; ik:match "/bad" ; ik:target "urn:bad" ;
                         ik:cors [ {prop} {value} ; ik:corsMaxAge 600 ] ."#
                );
                let Err(err) = load_turtle(&body) else {
                    panic!("{prop}, {label}: the route loaded without its list");
                };
                assert!(
                    err.contains("/bad") && err.contains(prop),
                    "{prop}, {label}: {err}"
                );
            }
        }
    }
}
