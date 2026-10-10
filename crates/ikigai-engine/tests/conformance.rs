//! The module recipe as one test over the plan space: `ikigai-conformance` walks every
//! endpoint `ikigai_engine::plan_space::space()` binds and reports every violation at once.
//!
//! Reader-only, like the round trip: without `plan-reader` there is no plan space.
#![cfg(feature = "plan-reader")]

//! The kernel is the smallest one the three plan doors can answer in:
//!
//! - the plan space itself, the space under test;
//! - `ikigai_shacl::space()`, because `urn:plan:validate` (and `urn:plan:eval`, which
//!   validates first) is a sub-request to `urn:shacl:validate`. It is ANOTHER module's door,
//!   held to the recipe by its own conformance test in ikigai-shacl, so this walk opts it
//!   out rather than re-judging it;
//! - one stub step target, `urn:t:hello`, declared here and held to the recipe like the
//!   plan doors: the plan every fixture passes is one `Source` of it;
//! - a JSON Meta renderer, because `urn:plan:requires` reads each step's contract with a
//!   `Meta` request rendered as `application/json`, as the engine does.
//!
//! Each plan door is declared `cacheable`: every answer is marked cacheable and is exactly as
//! cacheable as what it read, and over a pure step that is cacheable, so a dependency that
//! silently made one volatile is a red test here.
//!
//! One space declaration: `plan_space::space()` is configuration-free, so it is self-named
//! `urn:iki:space:engine:plan`.

use ikigai_conformance::{Fixture, Suite};
use ikigai_core::{
    Description, EndpointSpace, Exact, Fallback, FnEndpoint, Invocation, Kernel, MetaRenderer,
    ReprType, Representation, Space, Verb,
};
use std::sync::Arc;

/// One step, `source urn:t:hello`, and its result is the plan's.
const PLAN: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:hello> a ik:Process ;
    ik:output "text/plain" ;
    ik:step <urn:plan:hello:step:1> ;
    ik:result <urn:plan:hello:step:1> .
<urn:plan:hello:step:1> a ik:Step ;
    ik:verb "Source" ;
    ik:resolves <urn:t:hello> .
"#;

/// The three plan doors, by description id.
const PLAN_DOORS: [&str; 3] = ["plan-eval", "plan-validate", "plan-requires"];

struct JsonRenderer;
impl MetaRenderer for JsonRenderer {
    fn render(
        &self,
        description: &Description,
        _target: &ReprType,
    ) -> ikigai_core::Result<Representation> {
        Ok(Representation::new(
            ReprType::new("application/json"),
            serde_json::to_vec(description).expect("serialize description"),
        ))
    }
}

fn hello() -> FnEndpoint {
    FnEndpoint::new("hello", |_inv: &Invocation<'_>| {
        Ok(Representation::new(ReprType::new("text/plain"), b"hello".to_vec()).cacheable())
    })
    .with_description(
        Description::new("hello")
            .title("Hello")
            .summary("A constant: the step every conformance plan resolves.")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain"),
    )
}

#[test]
fn conforms() {
    let kernel = Kernel::with_meta_renderer(
        Arc::new(Fallback::new(vec![
            Arc::new(ikigai_engine::plan_space::space()) as Arc<dyn Space>,
            Arc::new(ikigai_shacl::space()),
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:t:hello"), hello())),
        ])),
        Arc::new(JsonRenderer),
    );
    let suite = PLAN_DOORS
        .iter()
        .fold(Suite::new(), |suite, id| {
            suite
                .fixture(Fixture::new(*id, Verb::Source).arg("in", PLAN))
                .cacheable(*id)
        })
        .pure("hello")
        .cacheable("hello")
        .opt_out(
            "shacl-validate",
            None,
            "ikigai-shacl's door, bound only because urn:plan:validate composes it; \
             held to the recipe by ikigai-shacl's own conformance test",
        )
        .self_named_space("engine:plan", ikigai_engine::plan_space::space);
    let report = suite.run_blocking(&kernel);
    assert!(report.is_clean(), "{report}");
    // The three plan doors, `shacl-validate` and the stub: a fourth plan door bound without
    // a fixture and a `cacheable` line changes this count.
    assert_eq!(
        report.endpoints, 5,
        "every door in the kernel is accounted for: {report}"
    );
    assert_eq!(
        ikigai_core::space_iri("engine:plan").as_str(),
        ikigai_engine::plan_space::SPACE_ID
    );
}
