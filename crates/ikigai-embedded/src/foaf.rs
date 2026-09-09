//! `urn:foaf` — one RDF document, every face by negotiation.
//!
//! `https://api.bosatsu.net/foaf?src=https://w3id.org/people/bsletten`: in a browser it
//! renders as a page; with no preference it returns the RDF/XML exactly as fetched; with
//! `Accept: application/ld+json` it returns compacted JSON-LD; with `text/turtle`,
//! `application/n-triples` and the other RDF syntaxes it re-serializes. The w3id link
//! itself ignores `Accept` and hands every client the raw RDF/XML, and browser-side XSLT
//! is leaving Chrome, so the `xml-stylesheet` trick is not a path. This is the smallest
//! live demonstration that **content negotiation is transreption**: one resource, one
//! fetch, and the face is a function of `as`.
//!
//! ## How the parts fit
//!
//! - The HTTP adapter (`ikigai-web`) turns the first media type of `Accept` into the `as`
//!   argument unless it is `*/*`, and query parameters into named arguments — so `src`
//!   arrives as `src`, a browser's `text/html` arrives as `as`, and `curl`'s `*/*` arrives
//!   as nothing. `as` is the adapter's argument, not declared here.
//! - Every step is issued THROUGH the kernel (`inv.issue`), never called as a library:
//!   `urn:httpGet` fetches, `urn:xslt:transform` styles, `urn:rdf:transrept` re-serializes,
//!   `urn:jsonld:compact` shortens. That is what makes the capability, the cache and the
//!   golden threads propagate — the result is no fresher than the fetched document and
//!   depends on the stylesheet and context files, so an edit to either on disk cuts the
//!   derived face and nothing else.
//! - **Authority IS the allowlist.** This endpoint does not validate `src`. `urn:httpGet`
//!   enforces `urn:cap:net:<host>[/<prefix>]` and owns redirect-following, re-running that
//!   ACL against every hop, so `--cap urn:cap:net:w3id.org/people --cap
//!   urn:cap:net:www.bosatsu.net/foaf` on the HTTP unit is the whole policy: a `src`
//!   anywhere else — or a redirect to anywhere else — is a typed `Denied`, which the HTTP
//!   face maps to 403. The declared `requires` is the wildcard family form
//!   (`urn:cap:net:*`); the concrete host grants are the unit's.
//! - **A compiled endpoint, not an `.scm` handler.** The edge has two doors with two
//!   authorities, and the public HTTP door holds no `urn:cap:lisp`: the stored programs
//!   are bound for the REACTOR under a space's `cap` file, never on the public face. So the
//!   renderer is Rust, and the only things edited on disk are the stylesheet and the
//!   context — data, not code.
//!
//! ## Faces
//!
//! | `as` | what | built by |
//! |---|---|---|
//! | absent, `*/*`, `application/rdf+xml` | the fetched document, unchanged | — |
//! | `text/html` | a page (`fragment=1`: only `<main id="main">`) | `urn:xslt:transform` with `urn:file:foaf.xsl` / `urn:file:foaf-fragment.xsl` |
//! | `application/ld+json` | JSON-LD, compacted against `urn:file:foaf.context.jsonld` | `urn:rdf:transrept` then `urn:jsonld:compact` |
//! | `text/turtle`, `application/n-triples`, `application/n-quads`, `application/trig` | the graph re-serialized | `urn:rdf:transrept` |
//!
//! Anything else is a typed `InvalidArgument` naming the faces that exist, which the HTTP
//! face maps to 400 (the adapter has no 406 mapping today). The stylesheet renders a
//! *person*, not arbitrary RDF; the generic "RDF → HTML for any graph" face is
//! `urn:rdf:transrept as=text/html`, a different resource.
//!
//! ## What the declaration does not say
//!
//! The HTML and JSON-LD faces read their stylesheet / context through `urn:file:*`, which
//! enforces `urn:cap:fs:read:<path>` — a grant the unit carries for exactly those two
//! files. `requires` is per action, not per face, so declaring `urn:cap:fs:read:*` here
//! would refuse the RDF/XML face to a caller holding only the net grant; it is left to the
//! nested read instead, where the denial names the file.

use async_trait::async_trait;
use ikigai_core::{
    ArgRef, ArgSpec, Description, Endpoint, Error, Invocation, Iri, ReprType, Representation,
    Request, Result, Verb,
};

/// The stylesheet for the page face: a workspace resource, so it is edited on disk.
pub const STYLESHEET: &str = "urn:file:foaf.xsl";
/// The stylesheet for `fragment=1`: only `<main id="main">…</main>`, for transclusion.
pub const FRAGMENT_STYLESHEET: &str = "urn:file:foaf-fragment.xsl";
/// The JSON-LD context the JSON-LD face is compacted against.
pub const CONTEXT: &str = "urn:file:foaf.context.jsonld";

const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";

const RDF_XML: &str = "application/rdf+xml";
const HTML: &str = "text/html";
const JSON_LD: &str = "application/ld+json";

/// Every face this document has, in the order the description declares them. The list
/// is the contract: `as` must name one of these, and a test resolves each of them, so a
/// face declared here is a face the chain actually reaches.
pub const FACES: &[&str] = &[
    HTML,
    RDF_XML,
    JSON_LD,
    "text/turtle",
    "application/n-triples",
    "application/n-quads",
    "application/trig",
];

/// `urn:foaf` — see the module docs.
pub struct Foaf;

#[async_trait]
impl Endpoint for Foaf {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let src = inv.inline_str("src")?;
        let face = requested_face(inv)?;
        let fragment = flag(inv, "fragment")?;

        // 1. The document. Its own expiry (from the origin's `Cache-Control`) and thread
        //    ride along: the kernel meets this result's expiry with every dependency's.
        let doc = inv
            .issue(
                Request::new(Verb::Source, iri("urn:httpGet"))
                    .with_arg("url", ArgRef::Inline(src.as_bytes().to_vec())),
            )
            .await?;

        let repr = match face {
            // 2. The default face is the document itself, typed as what it is rather than
            //    as whatever the origin said (a static host may call it `text/xml`).
            RDF_XML => Representation::new(ReprType::new(RDF_XML), doc.bytes),
            // 3. The page: the stylesheet over the document. `content=` carries the
            //    document (the transform accepts a piped or explicit document as well as
            //    a `src=` reference); the stylesheet is a resource reference the transform
            //    resolves through the kernel, so it is read under the caller's capability.
            HTML => {
                let stylesheet = if fragment {
                    FRAGMENT_STYLESHEET
                } else {
                    STYLESHEET
                };
                let styled = inv
                    .issue(
                        Request::new(Verb::Source, iri("urn:xslt:transform"))
                            .with_arg("content", ArgRef::Inline(doc.bytes))
                            .with_arg("stylesheet", ArgRef::Inline(stylesheet.as_bytes().to_vec()))
                            .with_arg("as", ArgRef::Inline(HTML.as_bytes().to_vec())),
                    )
                    .await?;
                Representation::new(styled.repr_type, styled.bytes).depends_on(stylesheet)
            }
            // 4. JSON-LD: the serializer emits the expanded form, which nobody can read, so
            //    it is compacted against the workspace context (`foaf:`, `schema:`,
            //    `rdfs:` …) — edited on disk like the stylesheet, and a dependency like it.
            JSON_LD => {
                let expanded = transrept(inv, doc.bytes, JSON_LD).await?;
                let compacted = inv
                    .issue(
                        Request::new(Verb::Source, iri("urn:jsonld:compact"))
                            .with_arg("content", ArgRef::Inline(expanded.bytes))
                            .with_arg("context", ArgRef::Inline(CONTEXT.as_bytes().to_vec())),
                    )
                    .await?;
                Representation::new(compacted.repr_type, compacted.bytes).depends_on(CONTEXT)
            }
            // 5. Every other RDF syntax is a plain re-serialization.
            other => {
                let out = transrept(inv, doc.bytes, other).await?;
                Representation::new(out.repr_type, out.bytes)
            }
        };
        // Cacheable as a pure function of its inputs; the kernel meets this with the
        // document's expiry (a live fetch with no `Cache-Control` keeps it uncacheable)
        // and unions in every thread the chain touched.
        Ok(repr.cacheable())
    }

    fn name(&self) -> &str {
        "foaf"
    }

    fn describe(&self) -> Description {
        let mut description = Description::new("foaf")
            .title("FOAF document, negotiated")
            .summary(
                "Render one FOAF (RDF/XML) document as a page, as JSON-LD, or as any RDF \
                 syntax — `Accept` selects the face; with no preference the document itself \
                 is returned. The source must be under a granted `urn:cap:net:` host.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("src")
                    .summary("the RDF document to render")
                    .class(XSD_ANY_URI),
            )
            .input(
                ArgSpec::new("fragment")
                    .summary(
                        "HTML face only: emit just `<main id=\"main\">` (for transclusion) \
                         instead of a whole page",
                    )
                    .class(XSD_BOOLEAN)
                    .default_value("false"),
            )
            // The net ACL is parameterized (`urn:cap:net:<host-rule>`); the wildcard form
            // is the family, satisfied by any grant under it. The inner `urn:httpGet`
            // enforces the host.
            .requires("urn:cap:net:*");
        for face in FACES {
            description = description.output(*face);
        }
        description
    }
}

/// The face `as` names, parameters stripped and lower-cased: absent, empty or `*/*` is
/// the document itself; anything not in [`FACES`] is a typed bad request naming the faces
/// that exist.
fn requested_face(inv: &Invocation<'_>) -> Result<&'static str> {
    let asked = inv
        .inline_str("as")
        .ok()
        .map(|s| media_base(s).to_ascii_lowercase())
        .unwrap_or_default();
    if asked.is_empty() || asked == "*/*" {
        return Ok(RDF_XML);
    }
    FACES
        .iter()
        .copied()
        .find(|face| *face == asked)
        .ok_or_else(|| Error::InvalidArgument {
            name: "as".to_string(),
            detail: format!(
                "`{asked}` is not a face of this document; the faces are {}",
                FACES.join(", ")
            ),
        })
}

/// The bare media type (parameters and surrounding whitespace stripped).
fn media_base(media: &str) -> &str {
    media.split(';').next().unwrap_or(media).trim()
}

/// An optional boolean argument: absent is `false`; the usual spellings are accepted,
/// anything else is a typed bad request.
fn flag(inv: &Invocation<'_>, name: &str) -> Result<bool> {
    let Ok(raw) = inv.inline_str(name) else {
        return Ok(false);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        other => Err(Error::InvalidArgument {
            name: name.to_string(),
            detail: format!("`{other}` is not a boolean (use true or false)"),
        }),
    }
}

/// Re-serialize `bytes` (any RDF syntax; the transreptor sniffs it) as `as`.
async fn transrept(inv: &Invocation<'_>, bytes: Vec<u8>, as_type: &str) -> Result<Representation> {
    inv.issue(
        Request::new(Verb::Source, iri("urn:rdf:transrept"))
            .with_arg("content", ArgRef::Inline(bytes))
            .with_arg("as", ArgRef::Inline(as_type.as_bytes().to_vec())),
    )
    .await
}

fn iri(s: &str) -> Iri {
    Iri::parse(s).expect("a constant IRI")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{Capability, EndpointSpace, Exact, Fallback, Kernel, Space, SystemClock};
    use ikigai_http::{HttpRequest, HttpResponse, HttpTransport};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const IDENTIFIER: &str = "https://w3id.org/people/bsletten";
    const DOCUMENT: &str = "https://www.bosatsu.net/foaf/brian.rdf";
    /// A granted host that redirects OUT of the allowlist.
    const ESCAPE: &str = "https://w3id.org/people/escape";

    const FIXTURE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:foaf="http://xmlns.com/foaf/0.1/">
  <foaf:Person rdf:about="https://w3id.org/people/bsletten">
    <foaf:name>Brian Sletten</foaf:name>
    <foaf:homepage rdf:resource="https://www.bosatsu.net/"/>
  </foaf:Person>
</rdf:RDF>
"#;

    /// A page stylesheet with a marker element, so a second version is distinguishable.
    fn page_xsl(heading: &str) -> String {
        format!(
            r#"<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:foaf="http://xmlns.com/foaf/0.1/">
  <xsl:template match="/"><html lang="en"><body><{heading}><xsl:value-of select="//foaf:name"/></{heading}></body></html></xsl:template>
</xsl:stylesheet>"#
        )
    }

    const FRAGMENT_XSL: &str = r#"<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:foaf="http://xmlns.com/foaf/0.1/">
  <xsl:template match="/"><main id="main"><h1><xsl:value-of select="//foaf:name"/></h1></main></xsl:template>
</xsl:stylesheet>"#;

    const CONTEXT_JSON: &str = r#"{
  "@context": {
    "foaf": "http://xmlns.com/foaf/0.1/",
    "name": "foaf:name",
    "homepage": { "@id": "foaf:homepage", "@type": "@id" }
  }
}"#;

    /// The stubbed web: the identifier redirects to the document (the granted pair), the
    /// document is the fixture with a freshness window, `ESCAPE` redirects to an ungranted
    /// host, anything else is a 404. Counts fetches so a denial can be shown to happen
    /// BEFORE any I/O.
    struct Web {
        fetches: AtomicUsize,
    }

    #[async_trait]
    impl HttpTransport for Web {
        async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let redirect = |to: &str| HttpResponse {
                status: 302,
                headers: vec![("location".to_string(), to.to_string())],
                body: Vec::new(),
            };
            Ok(match request.url.as_str() {
                IDENTIFIER => redirect(DOCUMENT),
                ESCAPE => redirect("https://example.com/x"),
                DOCUMENT => HttpResponse {
                    status: 200,
                    headers: vec![
                        ("content-type".to_string(), "text/xml".to_string()),
                        ("cache-control".to_string(), "max-age=3600".to_string()),
                    ],
                    body: FIXTURE.as_bytes().to_vec(),
                },
                _ => HttpResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: b"no such page".to_vec(),
                },
            })
        }
    }

    /// A throwaway workspace holding the stylesheet and context, one per test.
    fn workspace(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ikigai-foaf-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Canonical, because the jail compares canonical paths and the capability's
        // path rule must name the same spelling (`/var` is `/private/var` on macOS).
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("foaf.xsl"), page_xsl("h1")).unwrap();
        std::fs::write(root.join("foaf-fragment.xsl"), FRAGMENT_XSL).unwrap();
        std::fs::write(root.join("foaf.context.jsonld"), CONTEXT_JSON).unwrap();
        root
    }

    /// The HTTP door's shape, hermetically: `urn:foaf` beside the chain it resolves
    /// through, the web stubbed, the workspace a scratch directory. A clock is injected so
    /// the document's `max-age` becomes a deadline the cache can honor.
    fn kernel(root: &Path) -> (Arc<Kernel>, Arc<Web>) {
        let web = Arc::new(Web {
            fetches: AtomicUsize::new(0),
        });
        let spaces: Vec<Arc<dyn Space>> = vec![
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:foaf"), Foaf)),
            Arc::new(ikigai_http::space(
                Arc::clone(&web) as Arc<dyn HttpTransport>
            )),
            Arc::new(ikigai_rdf::space()),
            Arc::new(ikigai_xslt::space()),
            Arc::new(ikigai_jsonld::space()),
            Arc::new(ikigai_fs::cacheable_space(root)),
        ];
        let kernel = Kernel::new(Arc::new(Fallback::new(spaces))).with_clock(Arc::new(SystemClock));
        (Arc::new(kernel), web)
    }

    /// The unit's ceiling: the two hosts of the granted pair and read on the workspace.
    fn ceiling(root: &Path) -> Capability {
        Capability::scoped([
            "urn:cap:net:w3id.org/people".to_string(),
            "urn:cap:net:www.bosatsu.net/foaf".to_string(),
            format!("urn:cap:fs:read:{}", root.display()),
        ])
    }

    fn request(src: &str, args: &[(&str, &str)]) -> Request {
        let mut request = Request::new(Verb::Source, iri("urn:foaf"))
            .with_arg("src", ArgRef::Inline(src.as_bytes().to_vec()));
        for (name, value) in args {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        request
    }

    fn resolve(kernel: &Kernel, cap: &Capability, args: &[(&str, &str)]) -> Result<Representation> {
        block_on(kernel.issue(request(IDENTIFIER, args), cap))
    }

    fn text(repr: &Representation) -> &str {
        std::str::from_utf8(&repr.bytes).unwrap()
    }

    #[test]
    fn the_default_face_is_the_document_itself() {
        let root = workspace("default");
        let (kernel, web) = kernel(&root);
        let cap = ceiling(&root);
        // No preference (curl), an explicit wildcard, and the document's own type all
        // return the fetched bytes unchanged — typed as RDF/XML whatever the origin said.
        for args in [
            &[][..],
            &[("as", "*/*")][..],
            &[("as", "application/rdf+xml")][..],
        ] {
            let repr = resolve(&kernel, &cap, args).unwrap();
            assert_eq!(
                repr.repr_type.to_string(),
                "application/rdf+xml",
                "{args:?}"
            );
            assert_eq!(text(&repr), FIXTURE, "{args:?}");
        }
        // The identifier redirected to the document: two hops, both granted, once — the
        // later reads were served from the cache under the document's max-age.
        assert_eq!(web.fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_html_face_is_the_stylesheet_over_the_document() {
        let root = workspace("html");
        let (kernel, _) = kernel(&root);
        let cap = ceiling(&root);
        let page = resolve(&kernel, &cap, &[("as", "text/html")]).unwrap();
        assert_eq!(page.repr_type.to_string(), "text/html;charset=utf-8");
        assert!(
            text(&page).contains("<h1>Brian Sletten</h1>"),
            "{}",
            text(&page)
        );
        assert!(
            text(&page).contains("<html"),
            "a whole page: {}",
            text(&page)
        );
        // A parameterized value — what a caller passing the raw header would send — is the
        // same face.
        let same = resolve(&kernel, &cap, &[("as", "text/html;q=0.9")]).unwrap();
        assert_eq!(same.bytes, page.bytes);
    }

    #[test]
    fn fragment_selects_the_transclusion_stylesheet() {
        let root = workspace("fragment");
        let (kernel, _) = kernel(&root);
        let cap = ceiling(&root);
        let main = resolve(&kernel, &cap, &[("as", "text/html"), ("fragment", "1")]).unwrap();
        // (xrust serializes attributes single-quoted — `<main id='main'>` — so the
        // assertion names the element, not the quoting.)
        assert!(text(&main).starts_with("<main id="), "{}", text(&main));
        assert!(
            !text(&main).contains("<html"),
            "only the fragment: {}",
            text(&main)
        );
        // The flag is a boolean, so a non-boolean is a bad request rather than a guess.
        let err =
            resolve(&kernel, &cap, &[("as", "text/html"), ("fragment", "maybe")]).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument { name, .. } if name == "fragment"),
            "{err:?}"
        );
    }

    #[test]
    fn the_jsonld_face_is_compacted_against_the_context() {
        let root = workspace("jsonld");
        let (kernel, _) = kernel(&root);
        let cap = ceiling(&root);
        let repr = resolve(&kernel, &cap, &[("as", "application/ld+json")]).unwrap();
        assert!(
            repr.repr_type
                .to_string()
                .starts_with("application/ld+json"),
            "{}",
            repr.repr_type
        );
        let body = text(&repr);
        let doc: serde_json::Value = serde_json::from_str(body).unwrap();
        // Compacted: the context's short terms, not the expanded IRIs, and `@context` leads.
        assert_eq!(doc["name"], "Brian Sletten", "{body}");
        assert_eq!(doc["homepage"], "https://www.bosatsu.net/", "{body}");
        assert_eq!(doc["@id"], IDENTIFIER, "{body}");
        assert!(doc.get("@context").is_some(), "{body}");
        assert!(
            !body.contains("http://xmlns.com/foaf/0.1/name"),
            "not compacted: {body}"
        );
        assert!(
            body.find("\"@context\"").unwrap() < body.find("\"@id\"").unwrap(),
            "@context first: {body}"
        );
    }

    #[test]
    fn every_declared_face_is_reachable() {
        let root = workspace("faces");
        let (kernel, _) = kernel(&root);
        let cap = ceiling(&root);
        for face in FACES {
            let repr = resolve(&kernel, &cap, &[("as", face)]).unwrap();
            assert!(
                repr.repr_type.to_string().starts_with(face),
                "{face}: got {}",
                repr.repr_type
            );
            assert!(
                text(&repr).contains("Brian Sletten"),
                "{face}: {}",
                text(&repr)
            );
        }
        // And the two the brief named are the graph, not a table of it.
        let turtle = resolve(&kernel, &cap, &[("as", "text/turtle")]).unwrap();
        assert!(
            text(&turtle).contains("<https://w3id.org/people/bsletten>"),
            "{}",
            text(&turtle)
        );
        let nt = resolve(&kernel, &cap, &[("as", "application/n-triples")]).unwrap();
        assert!(
            text(&nt).contains("<http://xmlns.com/foaf/0.1/name> \"Brian Sletten\""),
            "{}",
            text(&nt)
        );
        // The description declares exactly these.
        let outputs = Foaf.describe().outputs;
        assert_eq!(
            outputs,
            FACES.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_face_the_chain_does_not_reach_is_a_typed_bad_request() {
        let root = workspace("unreachable");
        let (kernel, _) = kernel(&root);
        let cap = ceiling(&root);
        let err = resolve(&kernel, &cap, &[("as", "image/png")]).unwrap_err();
        match &err {
            Error::InvalidArgument { name, detail } => {
                assert_eq!(name, "as");
                for face in FACES {
                    assert!(detail.contains(face), "names every face: {detail}");
                }
            }
            other => panic!("expected InvalidArgument (→ 400), got {other:?}"),
        }
    }

    #[test]
    fn a_source_outside_the_granted_hosts_is_denied_before_any_fetch() {
        let root = workspace("denied");
        let (kernel, web) = kernel(&root);
        let cap = ceiling(&root);
        let err = block_on(kernel.issue(request("https://example.com/x", &[]), &cap)).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert_eq!(
            web.fetches.load(Ordering::SeqCst),
            0,
            "denied at the floor, not after I/O"
        );
        // A granted path prefix is a prefix: elsewhere on the same host is still denied.
        let err =
            block_on(kernel.issue(request("https://w3id.org/other/x", &[]), &cap)).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert_eq!(web.fetches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_redirect_out_of_the_allowlist_is_denied_at_that_hop() {
        let root = workspace("redirect");
        let (kernel, web) = kernel(&root);
        let cap = ceiling(&root);
        let err = block_on(kernel.issue(request(ESCAPE, &[]), &cap)).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        // The first hop was granted and fetched; the second was refused before it left.
        assert_eq!(web.fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_missing_src_is_a_typed_bad_request() {
        let root = workspace("missing");
        let (kernel, _) = kernel(&root);
        let err =
            block_on(kernel.issue(Request::new(Verb::Source, iri("urn:foaf")), &ceiling(&root)))
                .unwrap_err();
        assert!(
            matches!(err, Error::MissingArgument(ref name) if name == "src"),
            "{err:?}"
        );
    }

    #[test]
    fn without_a_net_grant_the_door_refuses() {
        let root = workspace("floor");
        let (kernel, web) = kernel(&root);
        // Read on the workspace but no `urn:cap:net:` grant at all: the declared floor
        // refuses before the endpoint is entered.
        let cap = Capability::scoped([format!("urn:cap:fs:read:{}", root.display())]);
        let err = resolve(&kernel, &cap, &[]).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert_eq!(web.fetches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_html_face_recomputes_when_the_stylesheet_thread_is_cut() {
        let root = workspace("cut");
        let (kernel, web) = kernel(&root);
        let cap = ceiling(&root);
        let html = &[("as", "text/html")][..];
        let first = resolve(&kernel, &cap, html).unwrap();
        assert!(text(&first).contains("<h1>Brian Sletten</h1>"));
        assert!(
            kernel.is_cached(&request(IDENTIFIER, html), &cap),
            "cached under the document's max-age"
        );

        // Edit the stylesheet on disk. Nothing has told the kernel, so the cached page
        // stands — the cut is what invalidates, and this is exactly what the workspace
        // watcher does on an out-of-band change.
        std::fs::write(root.join("foaf.xsl"), page_xsl("h2")).unwrap();
        let stale = resolve(&kernel, &cap, html).unwrap();
        assert_eq!(
            stale.bytes, first.bytes,
            "no cut yet, so still the cached page"
        );

        kernel.cut(STYLESHEET);
        let fresh = resolve(&kernel, &cap, html).unwrap();
        assert!(
            text(&fresh).contains("<h2>Brian Sletten</h2>"),
            "{}",
            text(&fresh)
        );
        // The document itself was never refetched: the stylesheet thread invalidated the
        // page, not the fetch it was derived from.
        assert_eq!(web.fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_description_carries_the_class_and_the_family_grant() {
        let d = Foaf.describe();
        let src = d
            .inputs
            .iter()
            .find(|i| i.name == "src")
            .expect("src declared");
        assert!(src.required);
        assert_eq!(src.class.as_deref(), Some(XSD_ANY_URI));
        let fragment = d
            .inputs
            .iter()
            .find(|i| i.name == "fragment")
            .expect("fragment declared");
        assert!(!fragment.required);
        assert_eq!(fragment.class.as_deref(), Some(XSD_BOOLEAN));
        assert!(
            d.inputs.iter().all(|i| i.name != "as"),
            "`as` is the adapter's"
        );
        assert_eq!(d.requires, vec!["urn:cap:net:*".to_string()]);
        assert!(d.verbs.contains(&Verb::Source));
    }
}
