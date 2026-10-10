//! Plan execution as a RESOURCE: `urn:plan:eval`, `urn:plan:validate`, `urn:plan:requires`.
//!
//! A plan (an `ik:Process` graph) is a script in the most analyzable language the kernel
//! has: finite, validatable before it runs, and with a capability that can be DERIVED from
//! its steps rather than declared. Until these three names existed it had no evaluator
//! resource — the runner was a REPL command — so nothing could run a plan by sub-request.
//! Now three resources answer for one, each over the plan passed as `in` (Turtle, inline
//! or by reference):
//!
//! | name | answers |
//! |---|---|
//! | `urn:plan:eval` | the plan's result: every step a sub-request under the CALLER's capability |
//! | `urn:plan:validate` | the SHACL report against `ikigai_vocab::SHAPES`, plus the checks the shapes cannot make |
//! | `urn:plan:requires` | the capability the plan needs, derived from each step's contract without invoking it |
//!
//! ## Composition, not a second validator
//!
//! Validation is a sub-request to `urn:shacl:validate` with the published shapes, not a
//! SHACL engine in this crate: the shapes already have a resource that applies them, and a
//! second one here would be a second opinion about the same rules. What the shapes CANNOT
//! say — a cycle closed through an `ik:ref` (the hop goes through a name, which no property
//! path takes), and anything else this executor cannot run as written — is the reader's
//! (`Plan::read`, crate-private), and it is reported beside the shapes' results in the same report.
//!
//! ## Authority
//!
//! **None of the three declares a capability of its own** — declared = enforced, and there
//! is nothing here to enforce. `urn:plan:eval` issues every step through the invocation,
//! so each step runs under exactly the caller's capability and meets its own target's
//! floor: a plan can never do what its caller could not do one request at a time.
//! `urn:plan:requires` reads each step's contract with a `Meta` request, which no floor
//! gates and which invokes nothing, and reports both what each step requires and what the
//! asking capability LACKS — the exact place a run under that capability would be refused.
//!
//! ## Cacheability
//!
//! Each answer is marked cacheable and is exactly as cacheable as what it read: every
//! step, the validation and every contract fetch is a recorded sub-request, so the kernel
//! folds their expiries and threads into the answer. A plan with a `Sink` step is
//! therefore never cached (a write's receipt is volatile), and a plan of pure reads is
//! cached under its steps' threads.

use std::collections::{BTreeMap, BTreeSet};

use ikigai_core::{
    space_iri, ArgRef, ArgSpec, AsyncFnEndpoint, ContentId, Description, EndpointSpace, Error,
    Exact, Invocation, Iri, Provenance, ReprType, Representation, Request, Result, Verb,
};
use oxrdf::{Literal, NamedNode, NamedOrBlankNode, Term, Triple};
use oxttl::{TurtleParser, TurtleSerializer};

use crate::engine::Staged;
use crate::plan::{
    execute, literal, verb_name, NodeRef, Plan, PlanHost, RefTo, Refusal, RunError, IK, RDF_TYPE,
};

/// Run a plan: `in` = the plan, `as` = the face of its result, and each declared
/// parameter by name.
pub const EVAL: &str = "urn:plan:eval";
/// The SHACL report plus the reader's checks, for the plan in `in`.
pub const VALIDATE: &str = "urn:plan:validate";
/// The capability the plan in `in` needs, derived from its steps' contracts.
pub const REQUIRES: &str = "urn:plan:requires";

/// The resource every plan is validated by.
const SHACL_VALIDATE: &str = "urn:shacl:validate";

const SH: &str = "http://www.w3.org/ns/shacl#";
const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const TURTLE: &str = "text/turtle";
const TEXT: &str = "text/plain";

/// Where `urn:plan:requires` names its outcomes: `{OUTCOME}{word}`, the closed set
/// `ik:outcome` takes on the plan (`complete`, `incomplete`) and on each step (`resolved`,
/// `unresolved`) — the same shape as `urn:kernel:explain`'s `urn:ikigai:explain:outcome:`.
const OUTCOME: &str = "urn:ikigai:plan:requires:outcome:";

/// The name [`space`] claims: `urn:iki:space:engine:plan`.
///
/// `engine:plan`, a PART of the engine crate, rather than `engine` or `plan`: these three
/// doors are not everything the engine is (the REPL grammar is not a space at all), and no
/// crate is called `ikigai-plan`, so a bare `plan` would claim a module that does not exist.
pub const SPACE_ID: &str = "urn:iki:space:engine:plan";

/// The space binding the three plan resources, named [`SPACE_ID`]. A host binds it where
/// its operator's requests resolve; see the crate's README for which hosts do.
///
/// Configuration-free (no parameters, nothing read while building it), so every call holds
/// the same three doors and the name is a true claim. A host that binds another door onto it
/// drops the name (core 0.1.89).
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new(EVAL), eval_endpoint())
        .bind(Exact::new(VALIDATE), validate_endpoint())
        .bind(Exact::new(REQUIRES), requires_endpoint())
        .named(space_iri("engine:plan"))
}

// --- the three endpoints ----------------------------------------------------------

fn plan_input(what: &str) -> ArgSpec {
    ArgSpec::new("in")
        .summary(format!(
            "the plan, an ik:Process graph as Turtle — inline, or the IRI of a resource \
             holding one; {what}"
        ))
        .class(XSD_STRING)
}

fn eval_endpoint() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("plan-eval", |inv| Box::pin(eval(inv))).with_description(
        Description::new("plan-eval")
            .title("Evaluate a plan")
            .summary(
                "Run an ik:Process plan and answer with its ik:result's representation. The \
                 plan is validated first (urn:plan:validate) and never runs if it does not \
                 conform. Every step is a sub-request under the CALLER's capability — this \
                 resource declares no authority of its own — so the answer is exactly as \
                 cacheable as its least cacheable step. A parameter the plan declares \
                 (ik:input) is passed as a further argument by its own name; one it does not \
                 declare is refused.",
            )
            .verb(Verb::Source)
            .input(plan_input("piped in, it is the sole required input"))
            .input(
                ArgSpec::new("as")
                    .summary(
                        "the face of the result: when the result was served as another media \
                         type it is transrepted through the selected chain, and refused when \
                         nothing converts it",
                    )
                    .class(XSD_STRING)
                    .optional(),
            )
            // A join (a fork, or a map's rejoined items) is newline-joined text; a single
            // step's result keeps whatever type that step served, which no declaration
            // can list in advance.
            .output("text/plain"),
    )
}

fn validate_endpoint() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("plan-validate", |inv| Box::pin(validate_face(inv))).with_description(
        Description::new("plan-validate")
            .title("Validate a plan")
            .summary(
                "Validate an ik:Process plan against ikigai_vocab::SHAPES (through \
                 urn:shacl:validate) and against the checks the shapes cannot make — a cycle \
                 closed through an ik:ref, and anything else the executor cannot run as \
                 written. The report is the SHACL report graph (text/turtle) with those \
                 checks added as results, or a summary (text/plain). urn:plan:eval refuses \
                 exactly the plans this does not pass.",
            )
            .verb(Verb::Source)
            .input(plan_input("piped in, it is the sole required input"))
            .input(
                ArgSpec::new("as")
                    .summary("the report's face: text/plain (a summary) or text/turtle")
                    .class(XSD_STRING)
                    .one_of([TEXT, TURTLE])
                    .default_value(TEXT)
                    .optional(),
            )
            .output("text/plain")
            .output("text/turtle"),
    )
}

fn requires_endpoint() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("plan-requires", |inv| Box::pin(requires_face(inv))).with_description(
        Description::new("plan-requires")
            .title("What a plan requires")
            .summary(
                "The capability an ik:Process plan needs, DERIVED from each step's own \
                 contract (Description::required_scopes for the step's verb) through a Meta \
                 request that invokes nothing — never read from the plan's own ik:requires. \
                 Reports what each step requires, what the asking capability lacks (where a \
                 run under it would be refused), and every step whose target resolves \
                 nowhere, in which case the union is a floor and says so.",
            )
            .verb(Verb::Source)
            .input(plan_input("piped in, it is the sole required input"))
            .input(
                ArgSpec::new("as")
                    .summary("text/plain (default) or text/turtle (ik:requires / ik:lacks)")
                    .class(XSD_STRING)
                    .one_of([TEXT, TURTLE])
                    .default_value(TEXT)
                    .optional(),
            )
            .output("text/plain")
            .output("text/turtle"),
    )
}

// --- inputs ---------------------------------------------------------------------

/// An argument's text: inline bytes as UTF-8, or the representation of the resource a
/// reference names (sourced under the caller's capability, and recorded).
async fn arg_text(inv: &Invocation<'_>, name: &str) -> Result<Option<String>> {
    let bytes = match inv.request.args.get(name) {
        None => return Ok(None),
        Some(ArgRef::Inline(bytes)) => bytes.clone(),
        Some(ArgRef::Reference(iri)) => inv.source(iri).await?.bytes,
        Some(ArgRef::Content(_)) => {
            return Err(Error::InvalidArgument {
                name: name.to_string(),
                detail: "a content-store reference is not supported here; pass the value \
                         inline or as a resource IRI"
                    .to_string(),
            })
        }
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| Error::InvalidArgument {
            name: name.to_string(),
            detail: "not UTF-8 text".to_string(),
        })
}

/// The plan, as Turtle.
async fn plan_text(inv: &Invocation<'_>) -> Result<String> {
    arg_text(inv, "in")
        .await?
        .ok_or_else(|| Error::MissingArgument("in".to_string()))
}

/// The requested face of a report: `text/plain` unless `as` says `text/turtle`.
fn report_face(inv: &Invocation<'_>, endpoint: &str) -> Result<bool> {
    match inv.inline_str("as").ok().map(|s| bare(s.trim())) {
        None | Some(TEXT) => Ok(false),
        Some(TURTLE) => Ok(true),
        Some(other) => Err(Error::InvalidArgument {
            name: "as".to_string(),
            detail: format!("`{other}` is not a face of {endpoint} (text/plain, text/turtle)"),
        }),
    }
}

fn bare(media: &str) -> &str {
    media.split(';').next().unwrap_or("").trim()
}

fn text(body: String) -> Representation {
    Representation::new(
        ReprType::new(TEXT).with_param("charset", "utf-8"),
        body.into_bytes(),
    )
    .cacheable()
}

fn turtle(body: String) -> Representation {
    Representation::new(
        ReprType::new(TURTLE).with_param("charset", "utf-8"),
        body.into_bytes(),
    )
    .cacheable()
}

// --- the invocation as a plan host -------------------------------------------------

/// The invocation serving `urn:plan:eval`, as the runner's host: every request goes out
/// through [`Invocation::issue`], so it runs under the CALLER's capability, one nesting
/// level down, and is recorded as a dependency of the answer — which is why `incoming`
/// is ignored: the kernel folds what the sub-requests read without being told.
struct InvocationHost<'a, 'b> {
    inv: &'a Invocation<'b>,
}

impl PlanHost for InvocationHost<'_, '_> {
    type Error = Error;

    async fn issue(&self, request: Request, _incoming: Provenance) -> Result<Staged> {
        Ok(Staged::from(self.inv.issue(request).await?))
    }

    async fn describe(&self, iri: &Iri) -> Option<Description> {
        contract(self.inv, iri).await.ok()
    }
}

/// A target's contract, read with `Meta as=application/json` — the request a Meta floor
/// never gates and that invokes nothing. `Err` says why it could not be read.
async fn contract(inv: &Invocation<'_>, iri: &Iri) -> std::result::Result<Description, String> {
    let request = Request::new(Verb::Meta, iri.clone())
        .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
    let representation = inv.issue(request).await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&representation.bytes).map_err(|e| {
        format!(
            "its contract is not readable as JSON ({e}) — this kernel's Meta renderer does not \
             emit application/json"
        )
    })
}

// --- validation ------------------------------------------------------------------

/// One problem a validation found.
struct Problem {
    /// What names the rule: the SHACL constraint (or shape, or component) — or, for the
    /// reader's checks, `urn:ikigai:plan:check:{acyclic,executable}`.
    rule: String,
    focus: String,
    message: String,
}

/// A plan's validation: the shapes' report and the reader's verdict.
struct Validation {
    /// The SHACL report graph, as `urn:shacl:validate` served it.
    report: Vec<Triple>,
    /// Its `sh:ValidationReport` node.
    report_node: NamedOrBlankNode,
    shapes_conform: bool,
    problems: Vec<Problem>,
    /// The reader's verdict — the plan, or why it will not run.
    plan: std::result::Result<Plan, Refusal>,
    /// The `ik:Process` node, when the graph has exactly one.
    process: Option<String>,
}

impl Validation {
    fn conforms(&self) -> bool {
        self.shapes_conform && self.plan.is_ok()
    }

    fn summary(&self) -> String {
        let subject = self
            .process
            .as_deref()
            .map_or_else(|| "the plan".to_string(), |iri| format!("<{iri}>"));
        if self.conforms() {
            return format!(
                "{subject} conforms: it satisfies ikigai_vocab::SHAPES and the executor's \
                 checks\n"
            );
        }
        let mut out = format!(
            "{subject} does not conform — {} problem{}\n",
            self.problems.len(),
            if self.problems.len() == 1 { "" } else { "s" }
        );
        for problem in &self.problems {
            out.push_str(&format!(
                "  {} at <{}>: {}\n",
                problem.rule, problem.focus, problem.message
            ));
        }
        out
    }

    /// The report graph with the reader's checks folded in: `sh:conforms` corrected, and
    /// a refusal added as one more `sh:result`.
    fn to_turtle(&self) -> Result<String> {
        let sh = |term: &str| NamedNode::new_unchecked(format!("{SH}{term}"));
        let mut triples: Vec<Triple> = self
            .report
            .iter()
            .filter(|t| !(t.subject == self.report_node && t.predicate == sh("conforms")))
            .cloned()
            .collect();
        triples.push(Triple::new(
            self.report_node.clone(),
            sh("conforms"),
            Literal::from(self.conforms()),
        ));
        if let Err(refusal) = &self.plan {
            let node = NamedNode::new_unchecked(format!(
                "urn:ikigai:plan:check:{}",
                ContentId::of(refusal.message.as_bytes())
            ));
            let focus = self
                .process
                .as_deref()
                .map_or_else(|| node.clone(), NamedNode::new_unchecked);
            triples.push(Triple::new(
                self.report_node.clone(),
                sh("result"),
                node.clone(),
            ));
            for (predicate, object) in [
                (
                    NamedNode::new_unchecked(RDF_TYPE),
                    Term::from(sh("ValidationResult")),
                ),
                (sh("focusNode"), Term::from(focus)),
                (sh("resultSeverity"), Term::from(sh("Violation"))),
                (
                    sh("sourceConstraint"),
                    Term::from(NamedNode::new_unchecked(refusal.kind.check_iri())),
                ),
                (
                    sh("resultMessage"),
                    Term::from(Literal::new_simple_literal(&refusal.message)),
                ),
            ] {
                triples.push(Triple::new(node.clone(), predicate, object));
            }
        }
        let serializer = TurtleSerializer::new()
            .with_prefix("sh", SH)
            .and_then(|s| s.with_prefix("ik", IK))
            .map_err(|e| Error::Endpoint(format!("{VALIDATE}: {e}")))?;
        let mut writer = serializer.for_writer(Vec::new());
        for triple in &triples {
            writer
                .serialize_triple(triple)
                .map_err(|e| Error::Endpoint(format!("{VALIDATE}: {e}")))?;
        }
        let bytes = writer
            .finish()
            .map_err(|e| Error::Endpoint(format!("{VALIDATE}: {e}")))?;
        String::from_utf8(bytes).map_err(|e| Error::Endpoint(format!("{VALIDATE}: {e}")))
    }
}

/// Validate `plan`: the shapes through `urn:shacl:validate`, then the reader.
async fn validate(inv: &Invocation<'_>, plan: &str) -> Result<Validation> {
    // Syntax first, so a document that is not Turtle is a bad ARGUMENT here rather than
    // an opaque failure inside the validator.
    let mut process = BTreeSet::new();
    for triple in TurtleParser::new().for_slice(plan.as_bytes()) {
        let triple = triple.map_err(|e| Error::InvalidArgument {
            name: "in".to_string(),
            detail: format!("the plan is not valid Turtle: {e}"),
        })?;
        if triple.predicate.as_str() == RDF_TYPE
            && matches!(&triple.object, Term::NamedNode(class) if class.as_str() == format!("{IK}Process"))
        {
            if let NamedOrBlankNode::NamedNode(node) = triple.subject {
                process.insert(node.into_string());
            }
        }
    }
    let process = (process.len() == 1).then(|| process.into_iter().next().expect("one"));

    let request = Request::new(
        Verb::Source,
        Iri::parse(SHACL_VALIDATE).expect("a valid IRI"),
    )
    .with_arg("data", ArgRef::Inline(plan.as_bytes().to_vec()))
    .with_arg(
        "shapes",
        ArgRef::Inline(ikigai_vocab::SHAPES.as_bytes().to_vec()),
    )
    .with_arg("as", ArgRef::Inline(TURTLE.as_bytes().to_vec()));
    let served = inv.issue(request).await.map_err(|e| match e {
        // Failing closed: a plan that cannot be validated does not run, and the reason
        // should name the missing piece rather than read as the plan's fault.
        Error::Unresolved(_) => Error::Endpoint(format!(
            "plans are validated against ikigai_vocab::SHAPES through {SHACL_VALIDATE}, which \
             this kernel does not bind — so no plan is validated here, and none runs"
        )),
        other => other,
    })?;
    let report: Vec<Triple> = TurtleParser::new()
        .for_slice(&served.bytes)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| {
            Error::Endpoint(format!("{SHACL_VALIDATE} served an unreadable report: {e}"))
        })?;

    let sh = |term: &str| format!("{SH}{term}");
    let report_node = report
        .iter()
        .find(|t| {
            t.predicate.as_str() == RDF_TYPE
                && matches!(&t.object, Term::NamedNode(c) if c.as_str() == sh("ValidationReport"))
        })
        .map(|t| t.subject.clone())
        .ok_or_else(|| {
            Error::Endpoint(format!(
                "{SHACL_VALIDATE} served a report with no sh:ValidationReport"
            ))
        })?;
    let objects = |subject: &NamedOrBlankNode, predicate: &str| -> Vec<Term> {
        report
            .iter()
            .filter(|t| &t.subject == subject && t.predicate.as_str() == predicate)
            .map(|t| t.object.clone())
            .collect()
    };
    let shapes_conform = objects(&report_node, &sh("conforms"))
        .iter()
        .any(|o| matches!(o, Term::Literal(l) if l.value() == "true"));

    let mut problems = Vec::new();
    for result in objects(&report_node, &sh("result")) {
        let node = match result {
            Term::NamedNode(n) => NamedOrBlankNode::NamedNode(n),
            Term::BlankNode(b) => NamedOrBlankNode::BlankNode(b),
            _ => continue,
        };
        let first = |predicate: &str| -> Option<String> {
            objects(&node, &sh(predicate))
                .into_iter()
                .next()
                .map(|o| match o {
                    Term::NamedNode(n) => n.into_string(),
                    Term::Literal(l) => l.value().to_string(),
                    other => other.to_string(),
                })
        };
        problems.push(Problem {
            // The most specific name the report gives: the SPARQL constraint, then the
            // shape, then the constraint component.
            rule: first("sourceConstraint")
                .or_else(|| first("sourceShape"))
                .or_else(|| first("sourceConstraintComponent"))
                .unwrap_or_else(|| "a SHACL constraint".to_string()),
            focus: first("focusNode").unwrap_or_default(),
            message: first("resultMessage").unwrap_or_default(),
        });
    }
    problems.sort_by(|a, b| (&a.rule, &a.focus, &a.message).cmp(&(&b.rule, &b.focus, &b.message)));

    let read = Plan::read(plan);
    if let Err(refusal) = &read {
        problems.push(Problem {
            rule: refusal.kind.check_iri().to_string(),
            focus: process.clone().unwrap_or_default(),
            message: refusal.message.clone(),
        });
    }
    Ok(Validation {
        report,
        report_node,
        shapes_conform,
        problems,
        plan: read,
        process,
    })
}

async fn validate_face(inv: &Invocation<'_>) -> Result<Representation> {
    let as_turtle = report_face(inv, VALIDATE)?;
    let plan = plan_text(inv).await?;
    let validation = validate(inv, &plan).await?;
    Ok(if as_turtle {
        turtle(validation.to_turtle()?)
    } else {
        text(validation.summary())
    })
}

// --- evaluation ------------------------------------------------------------------

async fn eval(inv: &Invocation<'_>) -> Result<Representation> {
    let source = plan_text(inv).await?;
    let validation = validate(inv, &source).await?;
    if !validation.conforms() {
        let first = validation
            .problems
            .first()
            .map(|p| format!("{} at <{}>: {}", p.rule, p.focus, p.message))
            .unwrap_or_default();
        let more = match validation.problems.len() {
            0 | 1 => String::new(),
            n => format!(" (and {} more — {VALIDATE} reports them all)", n - 1),
        };
        return Err(Error::InvalidArgument {
            name: "in".to_string(),
            detail: format!("the plan does not validate, so it does not run: {first}{more}"),
        });
    }
    let plan = validation
        .plan
        .expect("a conforming validation carries the plan it read");

    let mut supplied = BTreeMap::new();
    for name in inv.request.args.keys() {
        if name == "in" || name == "as" {
            continue;
        }
        if let Some(value) = arg_text(inv, name).await? {
            supplied.insert(name.clone(), value);
        }
    }

    let staged = execute(&InvocationHost { inv }, &plan, &supplied)
        .await
        .map_err(|e| match e {
            RunError::Plan(detail) => Error::InvalidArgument {
                name: "in".to_string(),
                detail,
            },
            RunError::Parameter { name, detail } => Error::InvalidArgument { name, detail },
            RunError::MissingParameter(name) => Error::MissingArgument(name),
            RunError::Step(error) => error,
        })?;

    let media = staged
        .media
        .clone()
        .unwrap_or_else(|| ReprType::new(TEXT).with_param("charset", "utf-8"));
    let answer = Representation::new(media, staged.bytes).cacheable();
    let Some(wanted) = inv.inline_str("as").ok().map(str::trim) else {
        return Ok(answer);
    };
    let served = answer.repr_type.media_type.clone();
    if bare(wanted) == bare(&served) {
        return Ok(answer);
    }
    let chain = inv
        .select_transreptor(&served, wanted)
        .ok_or_else(|| Error::InvalidArgument {
            name: "as".to_string(),
            detail: format!(
                "the plan's result is `{served}`, and nothing converts it to `{wanted}`"
            ),
        })?;
    let mut current = answer;
    for step in chain {
        let iri = Iri::parse(&step.endpoint).map_err(|e| {
            Error::Endpoint(format!("bad transreptor IRI `{}`: {e}", step.endpoint))
        })?;
        let request = Request::new(Verb::Source, iri)
            .with_arg("content", ArgRef::Inline(current.bytes))
            .with_arg("as", ArgRef::Inline(step.to.into_bytes()));
        current = inv.issue(request).await?;
    }
    Ok(current.cacheable())
}

// --- derived authority -------------------------------------------------------------

/// What one step needs, read from its contracts.
struct Needs {
    node: String,
    verb: Verb,
    resolves: String,
    requires: BTreeSet<String>,
    lacks: BTreeSet<String>,
    /// Each contract that could not be read — the step's target, or a resource one of its
    /// arguments sources — with the reason.
    unresolved: Vec<String>,
}

async fn requires_face(inv: &Invocation<'_>) -> Result<Representation> {
    let as_turtle = report_face(inv, REQUIRES)?;
    let source = plan_text(inv).await?;
    let plan = Plan::read(&source).map_err(|refusal| Error::InvalidArgument {
        name: "in".to_string(),
        detail: refusal.message,
    })?;
    let order = plan.run_order().map_err(|refusal| Error::InvalidArgument {
        name: "in".to_string(),
        detail: refusal.message,
    })?;

    let mut steps = Vec::new();
    for node in order {
        let NodeRef::Step(index) = node else { continue };
        let step = &plan.steps[index];
        let mut needs = Needs {
            node: plan.node_iri(node),
            verb: step.verb,
            resolves: step.resolves.as_str().to_string(),
            requires: BTreeSet::new(),
            lacks: BTreeSet::new(),
            unresolved: Vec::new(),
        };
        // The target, under the step's verb — and every resource an argument sources,
        // which the run reads with a `Source` before the step's own request.
        let mut targets = vec![(step.resolves.clone(), step.verb)];
        targets.extend(step.refs.values().filter_map(|to| match to {
            RefTo::Resource(iri) => Some((iri.clone(), Verb::Source)),
            RefTo::Name(_) => None,
        }));
        for (target, verb) in targets {
            match contract(inv, &target).await {
                Ok(description) => {
                    needs.requires.extend(description.required_scopes(verb));
                    needs
                        .lacks
                        .extend(description.unsatisfied_scopes(verb, inv.capability));
                }
                Err(reason) => needs
                    .unresolved
                    .push(format!("<{}>: {reason}", target.as_str())),
            }
        }
        steps.push(needs);
    }
    let reached: BTreeSet<&str> = steps.iter().map(|s| s.node.as_str()).collect();
    let unreached: Vec<String> = (0..plan.steps.len())
        .map(|i| plan.node_iri(NodeRef::Step(i)))
        .filter(|iri| !reached.contains(iri.as_str()))
        .collect();

    Ok(if as_turtle {
        turtle(requires_turtle(&plan, &steps))
    } else {
        text(requires_text(&plan, &steps, &unreached))
    })
}

fn union<'a>(sets: impl Iterator<Item = &'a BTreeSet<String>>) -> BTreeSet<String> {
    sets.flatten().cloned().collect()
}

fn requires_text(plan: &Plan, steps: &[Needs], unreached: &[String]) -> String {
    let requires = union(steps.iter().map(|s| &s.requires));
    let lacks = union(steps.iter().map(|s| &s.lacks));
    let unresolved = steps.iter().filter(|s| !s.unresolved.is_empty()).count();
    let list = |set: &BTreeSet<String>| {
        if set.is_empty() {
            "nothing".to_string()
        } else {
            set.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    };
    let mut out = if unresolved == 0 {
        format!("<{}> requires {}\n", plan.iri(), list(&requires))
    } else {
        format!(
            "<{}> requires AT LEAST {} — incomplete: {unresolved} step{} could not be read, \
             so this is a floor, not the requirement\n",
            plan.iri(),
            list(&requires),
            if unresolved == 1 {
                "'s contract"
            } else {
                "s' contracts"
            }
        )
    };
    if lacks.is_empty() {
        out.push_str("this capability holds all of it\n");
    } else {
        out.push_str(&format!(
            "this capability lacks {} — a run under it is refused at the steps below that \
             lack it\n",
            list(&lacks)
        ));
    }
    for needs in steps {
        out.push_str(&format!(
            "  {}  {} <{}>  requires {}",
            needs.node,
            verb_name(needs.verb),
            needs.resolves,
            list(&needs.requires)
        ));
        if !needs.lacks.is_empty() {
            out.push_str(&format!("  LACKS {}", list(&needs.lacks)));
        }
        for reason in &needs.unresolved {
            out.push_str(&format!("  UNRESOLVED {reason}"));
        }
        out.push('\n');
    }
    if !unreached.is_empty() {
        out.push_str(&format!(
            "never run (the result does not depend on {}): {}\n",
            if unreached.len() == 1 { "it" } else { "them" },
            unreached.join(", ")
        ));
    }
    out
}

fn requires_turtle(plan: &Plan, steps: &[Needs]) -> String {
    let complete = steps.iter().all(|s| s.unresolved.is_empty());
    let iris = |set: &BTreeSet<String>| {
        set.iter()
            .map(|scope| format!("<{scope}>"))
            .collect::<Vec<_>>()
            .join(" , ")
    };
    let mut out = format!(
        "@prefix ik:   <{IK}> .\n@prefix rdfs: <{RDFS}> .\n\n<{}> a ik:Process ;\n    \
         ik:outcome <{OUTCOME}{}>",
        plan.iri(),
        if complete { "complete" } else { "incomplete" }
    );
    // The union only when it IS the union: a partial one would let a pre-flight pass a
    // plan the kernel then denies. The per-step requirements below are always there.
    let requires = union(steps.iter().map(|s| &s.requires));
    if complete && !requires.is_empty() {
        out.push_str(&format!(" ;\n    ik:requires {}", iris(&requires)));
    }
    let lacks = union(steps.iter().map(|s| &s.lacks));
    if !lacks.is_empty() {
        out.push_str(&format!(" ;\n    ik:lacks {}", iris(&lacks)));
    }
    if !steps.is_empty() {
        let nodes: Vec<String> = steps.iter().map(|s| format!("<{}>", s.node)).collect();
        out.push_str(&format!(" ;\n    ik:step {}", nodes.join(" , ")));
    }
    out.push_str(" .\n");
    for needs in steps {
        out.push_str(&format!(
            "\n<{}> a ik:Step ;\n    ik:verb {} ;\n    ik:resolves <{}> ;\n    ik:outcome <{OUTCOME}{}>",
            needs.node,
            literal(verb_name(needs.verb)),
            needs.resolves,
            if needs.unresolved.is_empty() {
                "resolved"
            } else {
                "unresolved"
            }
        ));
        if !needs.requires.is_empty() {
            out.push_str(&format!(" ;\n    ik:requires {}", iris(&needs.requires)));
        }
        if !needs.lacks.is_empty() {
            out.push_str(&format!(" ;\n    ik:lacks {}", iris(&needs.lacks)));
        }
        for reason in &needs.unresolved {
            out.push_str(&format!(" ;\n    rdfs:comment {}", literal(reason)));
        }
        out.push_str(" .\n");
    }
    out
}
