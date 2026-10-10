//! A pipeline as a resource: the engine's `ik:Process` face.
//!
//! The REPL grammar is a *text* face over a plan — a DAG of requests. This module is the
//! graph face of the same thing, in the process vocabulary published at
//! `https://ikigai-rs.dev/ns#` (`ik:Process`, `ik:Step`, `ik:Argument`, `ik:Fork`). Two
//! directions, and they are inverses:
//!
//! * [`Engine::build_plan`] parses a spec and resolves it into a [`Plan`];
//!   [`Plan::to_turtle`] renders that as a graph — the `plan <spec>` command.
//! * [`Plan::from_turtle`] reads such a graph back and [`execute`] runs it — the
//!   `run <spec>` command, which resolves a resource and executes what it holds, AND
//!   `urn:plan:eval` (see `plan_space`), which runs the plan it is handed. **One runner**:
//!   both call [`execute`], each through its own [`PlanHost`] — the REPL's session
//!   ([`Engine`]) or the invocation that is serving the resource.
//!
//! **Why bother**: a workflow that is a graph is a file you can diff, sign, review in a
//! pull request, and *refuse before it runs*. A shell pipeline can be none of those.
//!
//! ## What the graph says that the text does not
//!
//! The text face routes a positional value to "the one declared argument left unnamed",
//! which only the target's contract knows. A plan is the **explicit** form: rendering
//! resolves that routing once — against the live contracts, by the same rule a run uses
//! ([`route_value_name`]) — and writes the argument's name into the graph. That is what
//! makes a plan checkable ahead of time, and it is also why rendering can fail where the
//! text merely defers the same failure to the moment the stage runs.
//!
//! A *piped* value is deliberately not resolved this way: the vocabulary says the piped
//! input is not an argument, it arrives through `ik:pipeFrom` / `ik:mapOver`. So the plan
//! names the edge and the host routes it at run time, exactly as the text face does.
//!
//! ## Named results and parameters
//!
//! A graph may bind a step's representation to a name (`ik:binds`), declare the plan's
//! own parameters (`ik:input` ArgSpec nodes), and pass either to a step by reference
//! (`ik:ref <urn:plan:{id}:var:{name}>`). The runner executes all three: a reference to a
//! bound name is an EDGE (the binder runs first, its bytes are the argument), a reference
//! to a parameter is the value the caller supplied or the parameter's `ik:default`, and a
//! reference to any other IRI is sourced and its representation passed. The text face has
//! no spelling for them yet (`x = …`, `@x`), so [`Engine::build_plan`] never emits them.
//!
//! An `ik:ref` edge is the one the SHACL shapes cannot follow (it goes through a NAME, a
//! hop no property path takes), so the reader closes it here: a plan whose references make
//! a cycle is refused before anything runs, wherever the cycle is — not only on the part
//! the result reaches.
//!
//! ## What is deliberately not here
//!
//! * **Conditionals and loops.** A plan is deliberately not Turing complete — that is
//!   what makes it total, validatable and refusable. When a plan cannot express
//!   something the answer is a new *resource* (`urn:iki:fn:conditional` is branching as a
//!   resource, and being a resource it recomputes and can take the other branch when a
//!   thread is cut), never new syntax.
//! * **`ik:requires` and `ik:output` as INPUT.** A graph may carry them (the fixtures do),
//!   and the reader ignores them: what a plan needs is derived from its steps' contracts
//!   by `urn:plan:requires`, never believed from the plan, because a plan that understated
//!   its needs would let a pre-flight pass a plan the kernel then denies.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use ikigai_core::{ContentId, Iri, Verb};
#[cfg(feature = "plan-reader")]
use oxrdf::{NamedOrBlankNode, Term};
#[cfg(feature = "plan-reader")]
use oxttl::TurtleParser;

#[cfg(feature = "plan-reader")]
use ikigai_core::{ArgRef, Description, Provenance, Request};

#[cfg(feature = "plan-reader")]
use crate::engine::{combine_outputs, root_provenance, Staged};
use crate::engine::{
    declared_arguments, parse_spec, parse_target, route_value_name, Connector, Engine, Node,
    Pipeline,
};

/// The ikigai vocabulary namespace — the terms a plan graph is written in.
#[cfg(feature = "plan-reader")]
pub(crate) const IK: &str = "https://ikigai-rs.dev/ns#";
#[cfg(feature = "plan-reader")]
pub(crate) const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// A node of a plan: a step, or a fork — which stands where a step can, as an upstream or
/// as the plan's result.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum NodeRef {
    Step(usize),
    Fork(usize),
}

/// How a step receives its input — at most one way, which the `ik:Step` shape enforces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Feed {
    /// Nothing flows in: the plan's first stage, or a branch of an upstream-less fork.
    None,
    /// `|` — the whole upstream representation (`ik:pipeFrom`).
    Pipe(NodeRef),
    /// `..` — once per newline-separated item of the upstream (`ik:mapOver`).
    Map(NodeRef),
    /// A branch of a fork, at a position in the join (`ik:forkOf` + `ik:order`).
    Branch { fork: usize, order: usize },
}

/// What a by-reference argument (`ik:ref`) names.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    not(feature = "plan-reader"),
    allow(
        dead_code,
        reason = "only the reader constructs a reference; the renderer, always built, writes one"
    )
)]
pub(crate) enum RefTo {
    /// `@name` — `urn:plan:{id}:var:{name}`: a step's `ik:binds` or one of the plan's own
    /// parameters, which share one namespace.
    Name(String),
    /// Any other resource: sourced when the step runs, and its representation passed.
    Resource(Iri),
}

/// A declared parameter of a plan — the ArgSpec node an endpoint would carry as `ik:input`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Param {
    pub name: String,
    pub required: bool,
    pub default: Option<String>,
    /// `ik:source` — "argument" or "binding". Either way the value arrives BY NAME at run
    /// time; the mode is carried so a stored plan describes itself as an endpoint does.
    pub source: Option<String>,
    pub class: Option<String>,
    pub summary: Option<String>,
}

/// One request of a plan: one verb against one IRI, with named arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Step {
    pub verb: Verb,
    pub resolves: Iri,
    /// Named arguments carrying literal values, sorted by name — so the graph a spec
    /// renders to is canonical and two plans diff on meaning rather than word order.
    pub arguments: BTreeMap<String, String>,
    /// Named arguments carrying a reference (`ik:ref`), sorted by name. Disjoint from
    /// `arguments`: an argument is given once, one way.
    pub refs: BTreeMap<String, RefTo>,
    /// `ik:binds` — the name this step's representation is bound to, if any.
    pub binds: Option<String>,
    pub feed: Feed,
}

/// A set of branches over one upstream representation, joined in order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Fork {
    /// Absent when the fork is the plan's first stage and its branches take no input.
    pub upstream: Option<NodeRef>,
}

/// A plan: the parameters, the steps, the forks, and which node's representation is the
/// answer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Plan {
    /// `{plan-id}` — the content address of the spec, for an anonymous plan.
    pub id: String,
    /// The plan's declared parameters, sorted by name.
    pub params: Vec<Param>,
    /// Steps in text-face order; index `i` is `urn:plan:{id}:step:{i + 1}`.
    pub steps: Vec<Step>,
    /// Forks in text-face order; index `i` is `urn:plan:{id}:fork:{i + 1}`.
    pub forks: Vec<Fork>,
    pub result: NodeRef,
}

// --- rendering ---------------------------------------------------------------

impl Plan {
    /// The IRI of the plan itself.
    pub fn iri(&self) -> String {
        ikigai_vocab::plan::process_iri(&self.id)
    }

    pub(crate) fn node_iri(&self, node: NodeRef) -> String {
        match node {
            NodeRef::Step(i) => ikigai_vocab::plan::step_iri(&self.id, i + 1),
            NodeRef::Fork(i) => ikigai_vocab::plan::fork_iri(&self.id, i + 1),
        }
    }

    /// Render the plan as an `ik:Process` graph.
    ///
    /// `text_face` is the spec this plan came from, carried as `rdfs:comment` so a
    /// reviewer reads what the author wrote next to what it means. It is
    /// **documentation only**: nothing executes it and [`Plan::from_turtle`] ignores it —
    /// the graph is the plan.
    pub fn to_turtle(&self, text_face: Option<&str>) -> String {
        let plan = self.iri();
        let mut out = String::new();
        out.push_str(
            "@prefix ik:   <https://ikigai-rs.dev/ns#> .\n\
             @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\n",
        );

        out.push_str(&format!("<{plan}> a ik:Process ;\n"));
        if let Some(text) = text_face {
            out.push_str(&format!("    rdfs:comment {} ;\n", literal(text)));
        }
        if !self.params.is_empty() {
            let inputs: Vec<String> = self
                .params
                .iter()
                .map(|param| format!("<{}>", ikigai_vocab::plan::input_iri(&self.id, &param.name)))
                .collect();
            out.push_str(&format!(
                "    ik:input {} ;\n",
                inputs.join(" ,\n             ")
            ));
        }
        let steps: Vec<String> = (0..self.steps.len())
            .map(|i| format!("<{}>", self.node_iri(NodeRef::Step(i))))
            .collect();
        out.push_str(&format!(
            "    ik:step {} ;\n    ik:result <{}> .\n",
            steps.join(" ,\n            "),
            self.node_iri(self.result)
        ));

        for param in &self.params {
            out.push_str(&format!(
                "\n<{}> ik:inputName {} ;\n",
                ikigai_vocab::plan::input_iri(&self.id, &param.name),
                literal(&param.name)
            ));
            if let Some(source) = &param.source {
                out.push_str(&format!("    ik:source {} ;\n", literal(source)));
            }
            if let Some(summary) = &param.summary {
                out.push_str(&format!("    ik:summary {} ;\n", literal(summary)));
            }
            if let Some(class) = &param.class {
                out.push_str(&format!("    ik:class <{class}> ;\n"));
            }
            if let Some(default) = &param.default {
                out.push_str(&format!("    ik:default {} ;\n", literal(default)));
            }
            // A Turtle boolean literal: `xsd:boolean`, which the parameter shape requires.
            out.push_str(&format!("    ik:required {} .\n", param.required));
        }

        for (i, fork) in self.forks.iter().enumerate() {
            out.push_str(&format!(
                "\n<{}> a ik:Fork ;\n",
                self.node_iri(NodeRef::Fork(i))
            ));
            if let Some(upstream) = fork.upstream {
                out.push_str(&format!(
                    "    ik:upstream <{}> ;\n",
                    self.node_iri(upstream)
                ));
            }
            // The only join the engine performs. Stated rather than left to the default,
            // so a reader never has to know what the default was when this was written.
            out.push_str("    ik:join \"newline\" .\n");
        }

        for (i, step) in self.steps.iter().enumerate() {
            out.push_str(&format!(
                "\n<{}> a ik:Step ;\n",
                self.node_iri(NodeRef::Step(i))
            ));
            out.push_str(&format!("    ik:verb \"{}\" ;\n", verb_name(step.verb)));
            out.push_str(&format!("    ik:resolves <{}> ;\n", step.resolves.as_str()));
            if let Some(name) = &step.binds {
                out.push_str(&format!("    ik:binds {} ;\n", literal(name)));
            }
            match step.feed {
                Feed::None => {}
                Feed::Pipe(up) => {
                    out.push_str(&format!("    ik:pipeFrom <{}> ;\n", self.node_iri(up)));
                }
                Feed::Map(up) => {
                    out.push_str(&format!("    ik:mapOver <{}> ;\n", self.node_iri(up)));
                }
                Feed::Branch { fork, order } => {
                    out.push_str(&format!(
                        "    ik:forkOf <{}> ;\n    ik:order {order} ;\n",
                        self.node_iri(NodeRef::Fork(fork))
                    ));
                }
            }
            // By value and by reference, one sorted list: the argument IRI is named by the
            // argument, so the two kinds interleave in the graph exactly as they would in
            // the text face's words.
            let mut names: Vec<&String> = step.arguments.keys().chain(step.refs.keys()).collect();
            names.sort();
            let args: Vec<String> = names
                .iter()
                .map(|name| format!("<{}>", self.argument_iri(i, name)))
                .collect();
            if args.is_empty() {
                // Nothing follows, so the predicate just written ends the description.
                close_description(&mut out);
            } else {
                out.push_str(&format!(
                    "    ik:argument {} .\n",
                    args.join(" ,\n                ")
                ));
                for name in names {
                    let object = match (step.arguments.get(name), step.refs.get(name)) {
                        (Some(value), _) => format!("ik:value {}", literal(value)),
                        (None, Some(RefTo::Name(var))) => {
                            format!("ik:ref <{}>", ikigai_vocab::plan::var_iri(&self.id, var))
                        }
                        (None, Some(RefTo::Resource(iri))) => format!("ik:ref <{}>", iri.as_str()),
                        (None, None) => unreachable!("the name came from one of the two maps"),
                    };
                    out.push_str(&format!(
                        "\n<{}> a ik:Argument ;\n    ik:inputName {} ;\n    {object} .\n",
                        self.argument_iri(i, name),
                        literal(name),
                    ));
                }
            }
        }
        out
    }

    fn argument_iri(&self, step: usize, name: &str) -> String {
        ikigai_vocab::plan::argument_iri(&self.id, step + 1, name)
    }
}

/// Turn the `;` that ends the last written predicate into the `.` that ends the
/// description — used when the predicate that would have followed turned out to be
/// absent (a step with no arguments).
fn close_description(out: &mut String) {
    if out.ends_with(";\n") {
        out.truncate(out.len() - 2);
        out.push_str(".\n");
    }
}

pub(crate) fn verb_name(verb: Verb) -> &'static str {
    match verb {
        Verb::Source => "Source",
        Verb::Sink => "Sink",
        Verb::Exists => "Exists",
        Verb::Delete => "Delete",
        Verb::Meta => "Meta",
    }
}

#[cfg(feature = "plan-reader")]
fn parse_verb(name: &str) -> Option<Verb> {
    Some(match name {
        "Source" => Verb::Source,
        "Sink" => Verb::Sink,
        "Exists" => Verb::Exists,
        "Delete" => Verb::Delete,
        "Meta" => Verb::Meta,
        _ => return None,
    })
}

/// A Turtle double-quoted literal.
///
/// `ikigai-vocab` escapes literals the same way for the endpoint faces but keeps it
/// private. The rule is small, and the alternative — emitting an author's text
/// unescaped — is a parse failure for every consumer, so it is restated rather than
/// worked around.
pub(crate) fn literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A name a plan binds — a step's `ik:binds` or a parameter's `ik:inputName` — is an
/// identifier: the pattern both shapes state, `^[A-Za-z_][A-Za-z0-9_-]*$`.
#[cfg(feature = "plan-reader")]
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// --- reading -----------------------------------------------------------------

#[cfg(feature = "plan-reader")]
/// An object of a triple: a plan graph is skolemized, so only IRIs and literals appear.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Obj {
    Iri(String),
    Literal(String),
}

#[cfg(feature = "plan-reader")]
impl Obj {
    fn iri(&self, subject: &str, predicate: &str) -> Result<&str, String> {
        match self {
            Obj::Iri(iri) => Ok(iri),
            Obj::Literal(value) => Err(format!(
                "<{subject}> ik:{predicate} \"{value}\" — expected an IRI, got a literal"
            )),
        }
    }

    fn literal(&self, subject: &str, predicate: &str) -> Result<&str, String> {
        match self {
            Obj::Literal(value) => Ok(value),
            Obj::Iri(iri) => Err(format!(
                "<{subject}> ik:{predicate} <{iri}> — expected a literal, got an IRI"
            )),
        }
    }
}

/// The parsed triples, indexed by subject then predicate — enough of a graph to read a
/// plan out of, and no more.
#[cfg(feature = "plan-reader")]
struct Graph {
    subjects: BTreeMap<String, BTreeMap<String, Vec<Obj>>>,
}

#[cfg(feature = "plan-reader")]
impl Graph {
    fn parse(turtle: &str) -> Result<Graph, String> {
        let mut subjects: BTreeMap<String, BTreeMap<String, Vec<Obj>>> = BTreeMap::new();
        for triple in TurtleParser::new().for_slice(turtle.as_bytes()) {
            let triple = triple.map_err(|e| format!("the plan is not valid Turtle: {e}"))?;
            let subject = match triple.subject {
                NamedOrBlankNode::NamedNode(node) => node.into_string(),
                NamedOrBlankNode::BlankNode(node) => {
                    return Err(blank_node_refusal(node.as_str()));
                }
            };
            // ⚠ An `if let` ladder, not a `match`, and deliberately: `oxrdf::Term` grows a
            // `Triple` variant under oxrdf's `rdf-12` feature, which ANOTHER crate in the
            // graph can turn on. An exhaustive match then needs an arm that does not exist
            // with the feature off, and a catch-all arm is an unreachable-pattern warning
            // with it off — so a `match` here compiles or fails depending on feature
            // unification elsewhere in the workspace, which is not a property this file
            // should have. (`cargo check -p ikigai-engine` and `cargo build --workspace`
            // disagreed about exactly this.)
            let object = if let Term::NamedNode(node) = &triple.object {
                Obj::Iri(node.as_str().to_string())
            } else if let Term::Literal(value) = &triple.object {
                Obj::Literal(value.value().to_string())
            } else if let Term::BlankNode(node) = &triple.object {
                return Err(blank_node_refusal(node.as_str()));
            } else {
                return Err(format!(
                    "a plan graph holds IRIs and literals; `{}` is neither",
                    triple.object
                ));
            };
            subjects
                .entry(subject)
                .or_default()
                .entry(triple.predicate.into_string())
                .or_default()
                .push(object);
        }
        Ok(Graph { subjects })
    }

    fn objects(&self, subject: &str, predicate: &str) -> &[Obj] {
        self.subjects
            .get(subject)
            .and_then(|preds| preds.get(&format!("{IK}{predicate}")))
            .map_or(&[], Vec::as_slice)
    }

    fn one(&self, subject: &str, predicate: &str) -> Result<&Obj, String> {
        match self.objects(subject, predicate) {
            [only] => Ok(only),
            [] => Err(format!("<{subject}> has no ik:{predicate}")),
            many => Err(format!(
                "<{subject}> has {} ik:{predicate} values; exactly one is allowed",
                many.len()
            )),
        }
    }

    fn at_most_one(&self, subject: &str, predicate: &str) -> Result<Option<&Obj>, String> {
        match self.objects(subject, predicate) {
            [] => Ok(None),
            [only] => Ok(Some(only)),
            many => Err(format!(
                "<{subject}> has {} ik:{predicate} values; at most one is allowed",
                many.len()
            )),
        }
    }

    /// Every subject asserted to be of the given `ik:` class.
    fn of_class(&self, class: &str) -> Vec<&str> {
        let class = format!("{IK}{class}");
        self.subjects
            .iter()
            .filter(|(_, preds)| {
                preds
                    .get(RDF_TYPE)
                    .is_some_and(|types| types.contains(&Obj::Iri(class.clone())))
            })
            .map(|(subject, _)| subject.as_str())
            .collect()
    }
}

#[cfg(feature = "plan-reader")]
fn blank_node_refusal(label: &str) -> String {
    format!(
        "a plan graph is skolemized, so every node has a stable IRI — `_:{label}` is a \
         blank node and nothing can reference it"
    )
}

/// Which rule a refused plan broke: the one the shapes cannot see, or any other.
///
/// The distinction is for `urn:plan:validate`, which reports a reader refusal beside the
/// SHACL report: a CYCLE is the check the shapes' own header hands to "the validator arc"
/// (a reference goes through a name, a hop no property path takes), and every other
/// refusal is a graph this executor cannot run as written.
#[cfg(feature = "plan-reader")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RefusalKind {
    /// The plan is not a DAG, counting the edges an `ik:ref` makes through a bound name.
    Cycle,
    /// Anything else the reader refuses.
    Unexecutable,
}

#[cfg(feature = "plan-reader")]
impl RefusalKind {
    /// The IRI `urn:plan:validate` names the check by, in `sh:sourceConstraint`.
    pub(crate) fn check_iri(self) -> &'static str {
        match self {
            RefusalKind::Cycle => "urn:ikigai:plan:check:acyclic",
            RefusalKind::Unexecutable => "urn:ikigai:plan:check:executable",
        }
    }
}

/// Why the reader refused a graph.
#[cfg(feature = "plan-reader")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Refusal {
    pub kind: RefusalKind,
    pub message: String,
}

#[cfg(feature = "plan-reader")]
impl From<String> for Refusal {
    fn from(message: String) -> Self {
        Refusal {
            kind: RefusalKind::Unexecutable,
            message,
        }
    }
}

#[cfg(feature = "plan-reader")]
impl Plan {
    /// Read a plan back out of an `ik:Process` graph.
    ///
    /// Strict on purpose: a plan is a thing you *refuse before it runs*, so anything this
    /// engine cannot execute exactly as written is an error rather than a best effort.
    pub fn from_turtle(turtle: &str) -> Result<Plan, String> {
        Plan::read(turtle).map_err(|refusal| refusal.message)
    }

    /// [`from_turtle`](Self::from_turtle), saying which kind of rule a refusal broke.
    pub(crate) fn read(turtle: &str) -> Result<Plan, Refusal> {
        let graph = Graph::parse(turtle)?;

        let plan_iri = match graph.of_class("Process").as_slice() {
            [only] => (*only).to_string(),
            [] => {
                return Err("no ik:Process in this graph — it is not a plan"
                    .to_string()
                    .into())
            }
            many => {
                return Err(format!(
                    "{} ik:Process nodes in one graph; a plan resource holds exactly one",
                    many.len()
                )
                .into())
            }
        };
        let id = plan_iri
            .strip_prefix("urn:plan:")
            .ok_or_else(|| format!("a plan is named `urn:plan:{{id}}`, not <{plan_iri}>"))?
            .to_string();

        let mut params = Vec::new();
        for object in graph.objects(&plan_iri, "input") {
            params.push(read_param(&graph, object.iri(&plan_iri, "input")?)?);
        }
        params.sort_by(|a, b| a.name.cmp(&b.name));

        let step_iris = ordered_steps(&graph, &plan_iri)?;
        let fork_iris = ordered_forks(&graph, &plan_iri);
        let index: BTreeMap<&str, NodeRef> = step_iris
            .iter()
            .enumerate()
            .map(|(i, iri)| (iri.as_str(), NodeRef::Step(i)))
            .chain(
                fork_iris
                    .iter()
                    .enumerate()
                    .map(|(i, iri)| (iri.as_str(), NodeRef::Fork(i))),
            )
            .collect();
        let node_ref = |iri: &str, whose: &str| -> Result<NodeRef, String> {
            index
                .get(iri)
                .copied()
                .ok_or_else(|| format!("<{iri}> ({whose}) is not a step or fork of <{plan_iri}>"))
        };

        let var_prefix = format!("{plan_iri}:var:");
        let mut steps = Vec::with_capacity(step_iris.len());
        for step_iri in &step_iris {
            steps.push(read_step(&graph, step_iri, &var_prefix, &node_ref)?);
        }

        let mut forks = Vec::with_capacity(fork_iris.len());
        for fork_iri in &fork_iris {
            let upstream = match graph.at_most_one(fork_iri, "upstream")? {
                Some(object) => Some(node_ref(
                    object.iri(fork_iri, "upstream")?,
                    "a fork's upstream",
                )?),
                None => None,
            };
            if let Some(join) = graph.at_most_one(fork_iri, "join")? {
                let join = join.literal(fork_iri, "join")?;
                if join != "newline" {
                    return Err(format!(
                        "<{fork_iri}> joins its branches by \"{join}\"; this engine performs \
                         only the \"newline\" join"
                    )
                    .into());
                }
            }
            forks.push(Fork { upstream });
        }

        let result = node_ref(
            graph.one(&plan_iri, "result")?.iri(&plan_iri, "result")?,
            "the plan's result",
        )?;

        let plan = Plan {
            id,
            params,
            steps,
            forks,
            result,
        };
        plan.check()?;
        Ok(plan)
    }

    /// The step that binds `name`, if one does (a parameter is a name too, but not a step).
    pub(crate) fn binder(&self, name: &str) -> Option<usize> {
        self.steps
            .iter()
            .position(|step| step.binds.as_deref() == Some(name))
    }

    /// The structural rules a reader must hold that reading one node at a time cannot
    /// see. The SHACL shapes state most of these too — but a graph is validated by
    /// whoever chooses to, and an executor may not assume anyone did. Acyclicity through
    /// a named reference is one the shapes CANNOT state, and it is checked here for the
    /// whole graph, not only the part the result reaches.
    fn check(&self) -> Result<(), Refusal> {
        // Single assignment: a name is bound once, across steps and parameters.
        let mut bound: BTreeMap<&str, usize> = BTreeMap::new();
        for name in self
            .params
            .iter()
            .map(|param| param.name.as_str())
            .chain(self.steps.iter().filter_map(|step| step.binds.as_deref()))
        {
            *bound.entry(name).or_default() += 1;
        }
        if let Some((name, count)) = bound.iter().find(|(_, count)| **count > 1) {
            return Err(format!(
                "<{}> binds the name `{name}` {count} times — a plan is single-assignment, \
                 across its steps' ik:binds and its parameters",
                self.iri()
            )
            .into());
        }
        for (i, step) in self.steps.iter().enumerate() {
            for (argument, to) in &step.refs {
                if let RefTo::Name(name) = to {
                    if !bound.contains_key(name.as_str()) {
                        return Err(format!(
                            "<{}> passes `{argument}=@{name}`, a name this plan never binds",
                            self.node_iri(NodeRef::Step(i))
                        )
                        .into());
                    }
                }
            }
            if step.verb == Verb::Sink
                && !matches!(step.feed, Feed::None)
                && (step.arguments.contains_key("content") || step.refs.contains_key("content"))
            {
                return Err(format!(
                    "<{}> is fed by the plan AND names `content` — two bodies, with no rule \
                     for choosing between them",
                    self.node_iri(NodeRef::Step(i))
                )
                .into());
            }
            if let Feed::Branch { fork, .. } = step.feed {
                if fork >= self.forks.len() {
                    return Err(format!(
                        "<{}> is a branch of a fork this plan does not hold",
                        self.node_iri(NodeRef::Step(i))
                    )
                    .into());
                }
            }
        }
        // Every node, so a cycle among steps the result never reaches is refused too: a
        // plan is a graph someone reviews, and a cyclic one is wrong wherever it is. This
        // also takes every fork's branch tails, so a fork with no branch, two branches at
        // one order, or a branch with no single tail is refused here.
        let mut marks = BTreeMap::new();
        let nodes = (0..self.steps.len())
            .map(NodeRef::Step)
            .chain((0..self.forks.len()).map(NodeRef::Fork));
        for node in nodes {
            self.visit(node, &mut marks, &mut Vec::new(), &mut Vec::new())?;
        }
        Ok(())
    }

    /// The nodes a run evaluates, dependencies first: everything the result depends on,
    /// and nothing else — the plan is a dependency graph, not a script.
    pub(crate) fn run_order(&self) -> Result<Vec<NodeRef>, Refusal> {
        let mut order = Vec::new();
        self.visit(
            self.result,
            &mut BTreeMap::new(),
            &mut Vec::new(),
            &mut order,
        )?;
        Ok(order)
    }

    /// What `node` needs before it can run: its feed's upstream, the steps that bind the
    /// names its arguments reference (the edge the shapes cannot follow), and — for a
    /// fork — the tail of each branch, in join order.
    fn deps(&self, node: NodeRef) -> Result<Vec<NodeRef>, Refusal> {
        match node {
            NodeRef::Fork(fork) => self.branch_tails(fork),
            NodeRef::Step(index) => {
                let step = &self.steps[index];
                let mut deps = Vec::new();
                match step.feed {
                    Feed::None => {}
                    Feed::Pipe(up) | Feed::Map(up) => deps.push(up),
                    Feed::Branch { fork, .. } => deps.extend(self.forks[fork].upstream),
                }
                for to in step.refs.values() {
                    if let RefTo::Name(name) = to {
                        deps.extend(self.binder(name).map(NodeRef::Step));
                    }
                }
                Ok(deps)
            }
        }
    }

    /// Depth-first, dependencies first. `marks` holds `false` while a node is on the
    /// current path and `true` once it is done, so meeting a `false` is a cycle — and the
    /// path says which nodes close it.
    fn visit(
        &self,
        node: NodeRef,
        marks: &mut BTreeMap<NodeRef, bool>,
        path: &mut Vec<NodeRef>,
        order: &mut Vec<NodeRef>,
    ) -> Result<(), Refusal> {
        match marks.get(&node) {
            Some(true) => return Ok(()),
            Some(false) => {
                let start = path.iter().position(|n| *n == node).unwrap_or(0);
                let cycle: Vec<String> = path[start..]
                    .iter()
                    .chain(std::iter::once(&node))
                    .map(|n| format!("<{}>", self.node_iri(*n)))
                    .collect();
                return Err(Refusal {
                    kind: RefusalKind::Cycle,
                    message: format!(
                        "<{}> depends on itself — a plan is a DAG, and this one is not: {} \
                         (each node needs the next, counting the edge an ik:ref makes through \
                         a bound name)",
                        self.node_iri(node),
                        cycle.join(" → ")
                    ),
                });
            }
            None => {}
        }
        marks.insert(node, false);
        path.push(node);
        for dep in self.deps(node)? {
            self.visit(dep, marks, path, order)?;
        }
        path.pop();
        marks.insert(node, true);
        order.push(node);
        Ok(())
    }

    /// The tail of each branch of `fork`, in join order: the branches are the steps whose
    /// `ik:forkOf` names it, and a branch that is itself a pipeline is the chain from
    /// that head — what the fork joins is the chain's last node.
    pub(crate) fn branch_tails(&self, fork: usize) -> Result<Vec<NodeRef>, Refusal> {
        let mut heads: Vec<(usize, usize)> = self
            .steps
            .iter()
            .enumerate()
            .filter_map(|(i, step)| match step.feed {
                Feed::Branch { fork: of, order } if of == fork => Some((order, i)),
                _ => None,
            })
            .collect();
        heads.sort_unstable();
        if heads.is_empty() {
            return Err(format!(
                "<{}> has no branch (no step names it with ik:forkOf)",
                self.node_iri(NodeRef::Fork(fork))
            )
            .into());
        }
        if heads.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(format!(
                "<{}> has two branches at the same ik:order, so the join has no order",
                self.node_iri(NodeRef::Fork(fork))
            )
            .into());
        }
        heads
            .into_iter()
            .map(|(_, head)| self.chain_tail(NodeRef::Step(head)))
            .collect()
    }

    /// Follow the chain forward from a branch head to the node nothing else consumes.
    fn chain_tail(&self, head: NodeRef) -> Result<NodeRef, Refusal> {
        let mut current = head;
        for _ in 0..=(self.steps.len() + self.forks.len()) {
            let mut next = Vec::new();
            for (i, step) in self.steps.iter().enumerate() {
                if matches!(step.feed, Feed::Pipe(up) | Feed::Map(up) if up == current) {
                    next.push(NodeRef::Step(i));
                }
            }
            for (i, fork) in self.forks.iter().enumerate() {
                if fork.upstream == Some(current) {
                    next.push(NodeRef::Fork(i));
                }
            }
            match next.as_slice() {
                [] => return Ok(current),
                [one] => current = *one,
                many => {
                    return Err(format!(
                        "<{}> feeds {} downstream nodes, so the branch it is in has no single \
                         tail for a fork to join",
                        self.node_iri(current),
                        many.len()
                    )
                    .into())
                }
            }
        }
        Err(Refusal {
            kind: RefusalKind::Cycle,
            message: format!(
                "the edges from <{}> form a cycle — a plan is a DAG",
                self.node_iri(head)
            ),
        })
    }
}

/// The plan's steps, ordered by the `{n}` in their skolem IRIs.
#[cfg(feature = "plan-reader")]
fn ordered_steps(graph: &Graph, plan_iri: &str) -> Result<Vec<String>, String> {
    let mut iris: Vec<String> = graph
        .objects(plan_iri, "step")
        .iter()
        .map(|object| object.iri(plan_iri, "step").map(str::to_string))
        .collect::<Result<_, _>>()?;
    if iris.is_empty() {
        return Err(format!(
            "<{plan_iri}> has no ik:step — a plan runs something"
        ));
    }
    number_by_iri(&mut iris, &format!("{plan_iri}:step:"));
    Ok(iris)
}

/// The plan's forks. Nothing links a process to them — they are reached through the steps
/// that branch off them — so the graph's own `a ik:Fork` assertions are the list.
#[cfg(feature = "plan-reader")]
fn ordered_forks(graph: &Graph, plan_iri: &str) -> Vec<String> {
    let mut iris: Vec<String> = graph
        .of_class("Fork")
        .iter()
        .map(|s| s.to_string())
        .collect();
    number_by_iri(&mut iris, &format!("{plan_iri}:fork:"));
    iris
}

/// Order skolemized nodes by the `{n}` their IRIs carry, falling back to the IRI itself.
///
/// `{n}` is only a node's position in the text face, so nothing *depends* on it — but
/// reading it back preserves the numbering a render produced, which keeps a plan's
/// rendered form stable across a round trip and therefore diffable. Turtle is unordered,
/// so without this the numbering would follow whatever order the document happened to
/// have, and a plan would not survive being reserialized.
#[cfg(feature = "plan-reader")]
fn number_by_iri(iris: &mut Vec<String>, prefix: &str) {
    iris.sort_by_key(|iri| {
        let n = iri
            .strip_prefix(prefix)
            .and_then(|rest| rest.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        (n, iri.clone())
    });
    iris.dedup();
}

/// One `ik:input` ArgSpec node of the process.
#[cfg(feature = "plan-reader")]
fn read_param(graph: &Graph, node: &str) -> Result<Param, String> {
    let name = graph
        .one(node, "inputName")?
        .literal(node, "inputName")?
        .to_string();
    if !is_identifier(&name) {
        return Err(format!(
            "<{node}> names the parameter `{name}`; a parameter name is an identifier \
             (letters, digits, _ and -)"
        ));
    }
    let source = match graph.at_most_one(node, "source")? {
        None => None,
        Some(object) => match object.literal(node, "source")? {
            mode @ ("argument" | "binding") => Some(mode.to_string()),
            other => {
                return Err(format!(
                    "<{node}> ik:source \"{other}\" — a parameter arrives as an \"argument\" \
                     or a \"binding\""
                ))
            }
        },
    };
    let required = match graph.at_most_one(node, "required")? {
        // An ArgSpec is required unless it says otherwise — the same default
        // `ArgSpec::new` has, so a plan's parameter means what an endpoint's input means.
        None => true,
        Some(object) => match object.literal(node, "required")? {
            "true" | "1" => true,
            "false" | "0" => false,
            other => return Err(format!("<{node}> ik:required \"{other}\" is not a boolean")),
        },
    };
    let default = graph
        .at_most_one(node, "default")?
        .map(|object| object.literal(node, "default").map(str::to_string))
        .transpose()?;
    let class = graph
        .at_most_one(node, "class")?
        .map(|object| object.iri(node, "class").map(str::to_string))
        .transpose()?;
    let summary = graph
        .at_most_one(node, "summary")?
        .map(|object| object.literal(node, "summary").map(str::to_string))
        .transpose()?;
    Ok(Param {
        name,
        required,
        default,
        source,
        class,
        summary,
    })
}

#[cfg(feature = "plan-reader")]
fn read_step(
    graph: &Graph,
    step_iri: &str,
    var_prefix: &str,
    node_ref: &impl Fn(&str, &str) -> Result<NodeRef, String>,
) -> Result<Step, String> {
    let verb_name = graph.one(step_iri, "verb")?.literal(step_iri, "verb")?;
    let verb = parse_verb(verb_name).ok_or_else(|| {
        format!(
            "<{step_iri}> issues \"{verb_name}\"; a step issues one of Source, Sink, Exists, \
             Delete, Meta"
        )
    })?;
    let resolves = graph.one(step_iri, "resolves")?.iri(step_iri, "resolves")?;
    let resolves = Iri::parse(resolves).map_err(|e| format!("<{step_iri}> ik:resolves: {e}"))?;

    let binds = match graph.at_most_one(step_iri, "binds")? {
        None => None,
        Some(object) => {
            let name = object.literal(step_iri, "binds")?;
            if !is_identifier(name) {
                return Err(format!(
                    "<{step_iri}> binds `{name}`; a bound name is an identifier (letters, \
                     digits, _ and -)"
                ));
            }
            Some(name.to_string())
        }
    };

    let pipe = graph.at_most_one(step_iri, "pipeFrom")?;
    let map = graph.at_most_one(step_iri, "mapOver")?;
    let fork = graph.at_most_one(step_iri, "forkOf")?;
    let order = graph.at_most_one(step_iri, "order")?;
    let feed = match (pipe, map, fork) {
        (None, None, None) => {
            if order.is_some() {
                return Err(format!(
                    "<{step_iri}> carries ik:order but no ik:forkOf — a position without a join"
                ));
            }
            Feed::None
        }
        (Some(up), None, None) => Feed::Pipe(node_ref(up.iri(step_iri, "pipeFrom")?, "a pipe")?),
        (None, Some(up), None) => Feed::Map(node_ref(up.iri(step_iri, "mapOver")?, "a map")?),
        (None, None, Some(of)) => {
            let order = order
                .ok_or_else(|| format!("<{step_iri}> is a fork branch but carries no ik:order"))?;
            let order: usize = order
                .literal(step_iri, "order")?
                .parse()
                .map_err(|_| format!("<{step_iri}> ik:order is not a positive integer"))?;
            if order == 0 {
                return Err(format!("<{step_iri}> ik:order is not a positive integer"));
            }
            match node_ref(of.iri(step_iri, "forkOf")?, "a fork")? {
                NodeRef::Fork(fork) => Feed::Branch { fork, order },
                NodeRef::Step(_) => {
                    return Err(format!("<{step_iri}> ik:forkOf names a step, not a fork"))
                }
            }
        }
        _ => {
            return Err(format!(
                "<{step_iri}> is fed more than one way — a step takes at most one of \
                 ik:pipeFrom, ik:mapOver, ik:forkOf"
            ))
        }
    };

    let mut arguments = BTreeMap::new();
    let mut refs = BTreeMap::new();
    for object in graph.objects(step_iri, "argument") {
        let arg_iri = object.iri(step_iri, "argument")?;
        let name = graph
            .one(arg_iri, "inputName")?
            .literal(arg_iri, "inputName")?
            .to_string();
        if arguments.contains_key(&name) || refs.contains_key(&name) {
            return Err(format!(
                "<{step_iri}> gives the argument `{name}` more than once"
            ));
        }
        match (
            graph.at_most_one(arg_iri, "value")?,
            graph.at_most_one(arg_iri, "ref")?,
        ) {
            (Some(value), None) => {
                arguments.insert(name, value.literal(arg_iri, "value")?.to_string());
            }
            (None, Some(target)) => {
                let target = target.iri(arg_iri, "ref")?;
                let to = match target.strip_prefix(var_prefix) {
                    Some(var) if is_identifier(var) => RefTo::Name(var.to_string()),
                    Some(var) => {
                        return Err(format!(
                            "<{arg_iri}> references `@{var}`; a bound name is an identifier"
                        ))
                    }
                    None => RefTo::Resource(
                        Iri::parse(target).map_err(|e| format!("<{arg_iri}> ik:ref: {e}"))?,
                    ),
                };
                refs.insert(name, to);
            }
            _ => {
                return Err(format!(
                    "<{arg_iri}> carries {} — an argument carries exactly one of ik:value \
                     and ik:ref",
                    if graph.objects(arg_iri, "value").is_empty() {
                        "neither ik:value nor ik:ref"
                    } else {
                        "both ik:value and ik:ref"
                    }
                ))
            }
        }
    }

    Ok(Step {
        verb,
        resolves,
        arguments,
        refs,
        binds,
        feed,
    })
}

// --- building a plan from the text face ---------------------------------------

/// The plan under construction, behind a `RefCell` so the recursive async walk can share
/// it without holding a borrow across an `await`.
#[derive(Default)]
struct Builder {
    steps: Vec<Step>,
    forks: Vec<Fork>,
}

impl Engine {
    /// Parse a pipeline spec and resolve it into a [`Plan`].
    ///
    /// Contracts are consulted exactly where the text face consults them — to recognize a
    /// `key=value` word as a named argument, and to route a positional value — so a plan
    /// is what the spec *means*, resolved once, rather than a transcription of its words.
    pub(crate) async fn build_plan(&self, spec: &str) -> Result<Plan, String> {
        let pipeline = parse_spec(spec)?;
        let builder = RefCell::new(Builder::default());
        let result = self
            .build_pipeline(&pipeline, Feed::None, false, &builder)
            .await?;
        let builder = builder.into_inner();
        Ok(Plan {
            // An anonymous plan is named by its content, so the same spec is the same
            // plan wherever it is rendered and two renders of it diff to nothing.
            id: ContentId::of(spec.trim().as_bytes()).to_string(),
            // The text face has no spelling for parameters, named results or references
            // yet, so a rendered plan carries none of them.
            params: Vec::new(),
            steps: builder.steps,
            forks: builder.forks,
            result,
        })
    }

    /// Build one pipeline, returning the node whose representation it produces.
    /// `head_feed` is how the pipeline's first stage is fed; `has_input` says whether
    /// anything actually flows in, which a fork's absent upstream makes different from
    /// the feed being present.
    fn build_pipeline<'a>(
        &'a self,
        pipeline: &'a Pipeline,
        head_feed: Feed,
        has_input: bool,
        builder: &'a RefCell<Builder>,
    ) -> Pin<Box<dyn Future<Output = Result<NodeRef, String>> + 'a>> {
        Box::pin(async move {
            let mut current = self
                .build_node(&pipeline.first, head_feed, has_input, builder)
                .await?;
            for step in &pipeline.rest {
                let feed = match step.connector {
                    Connector::Pipe => Feed::Pipe(current),
                    Connector::Map => Feed::Map(current),
                };
                current = self.build_node(&step.node, feed, true, builder).await?;
            }
            Ok(current)
        })
    }

    fn build_node<'a>(
        &'a self,
        node: &'a Node,
        feed: Feed,
        has_input: bool,
        builder: &'a RefCell<Builder>,
    ) -> Pin<Box<dyn Future<Output = Result<NodeRef, String>> + 'a>> {
        Box::pin(async move {
            match node {
                Node::Source(words) => {
                    let (target, args) = words.split_first().ok_or("expected an IRI")?;
                    let iri = parse_target(target)?;
                    // Exactly the lookup `source_request` makes, on exactly the same
                    // condition — a bare stage needs no contract.
                    let description = if !args.is_empty() || has_input {
                        self.describe_struct(&iri).await
                    } else {
                        None
                    };
                    let declared = declared_arguments(description.as_ref());

                    let mut arguments = BTreeMap::new();
                    let mut positional: Vec<&str> = Vec::new();
                    for arg in args {
                        match arg.split_once('=') {
                            Some(("as", value)) => {
                                arguments.insert("as".to_string(), value.to_string());
                            }
                            Some((key, value)) if declared.iter().any(|name| name == key) => {
                                arguments.insert(key.to_string(), value.to_string());
                            }
                            _ => positional.push(arg),
                        }
                    }
                    let positional = positional.join(" ");
                    if has_input && !positional.is_empty() {
                        return Err(format!(
                            "`{}` takes its input from the pipe — drop the literal input",
                            iri.as_str()
                        ));
                    }
                    if !positional.is_empty() {
                        // The text face's one implicit routing decision, made explicit —
                        // which is the whole reason a plan can be checked before it runs.
                        let named: Vec<&str> = arguments.keys().map(String::as_str).collect();
                        let name = route_value_name(&iri, description.as_ref(), &named)?;
                        arguments.insert(name, positional);
                    }
                    Ok(push_step(
                        builder,
                        Step {
                            verb: Verb::Source,
                            resolves: iri,
                            arguments,
                            refs: BTreeMap::new(),
                            binds: None,
                            feed,
                        },
                    ))
                }
                Node::Sink(words) => {
                    let (target, args) = words.split_first().ok_or("`sink` needs a target IRI")?;
                    let iri = parse_target(target)?;
                    let declared = if args.iter().any(|arg| arg.contains('=')) {
                        declared_arguments(self.describe_struct(&iri).await.as_ref())
                    } else {
                        Vec::new()
                    };
                    let mut arguments = BTreeMap::new();
                    for arg in args {
                        match arg.split_once('=') {
                            Some(("as", value)) => {
                                arguments.insert("as".to_string(), value.to_string());
                            }
                            Some((key, value)) if declared.iter().any(|name| name == key) => {
                                arguments.insert(key.to_string(), value.to_string());
                            }
                            _ => {
                                return Err(format!(
                                    "`sink {}` takes its content from the pipe — name \
                                     arguments with `key=value` (unexpected `{arg}`)",
                                    iri.as_str()
                                ))
                            }
                        }
                    }
                    if has_input {
                        if arguments.contains_key("content") {
                            return Err(format!(
                                "`sink {}` was given content twice — named `content=` and the \
                                 piped value; drop one",
                                iri.as_str()
                            ));
                        }
                    } else {
                        // Nothing flows in, so the body is empty — which `sink_request`
                        // sends as an empty `content`. A plan says that rather than
                        // leaving the next reader to know it.
                        arguments.entry("content".to_string()).or_default();
                    }
                    Ok(push_step(
                        builder,
                        Step {
                            verb: Verb::Sink,
                            resolves: iri,
                            arguments,
                            refs: BTreeMap::new(),
                            binds: None,
                            feed,
                        },
                    ))
                }
                Node::Fork(branches) => {
                    let upstream = match feed {
                        Feed::None => None,
                        Feed::Pipe(up) => Some(up),
                        // ⚠ Both of these are grammar the process vocabulary cannot spell,
                        // because ik:mapOver, ik:forkOf and ik:order are properties of an
                        // ik:Step and a fork is not one. Refusing beats rendering
                        // something that would come back meaning something else.
                        Feed::Map(_) => {
                            return Err("`.. ( … )` — mapping over a fork — has no plan spelling: \
                                 ik:mapOver is a property of an ik:Step, and a fork is not a \
                                 step. Map over a stage, or make the fork's work one resource."
                                .to_string())
                        }
                        Feed::Branch { .. } => {
                            return Err("a `( … )` fork directly inside a fork branch has no plan \
                                 spelling: ik:forkOf and ik:order are properties of an \
                                 ik:Step. Put a stage at the head of the branch, or make the \
                                 inner fork one resource."
                                .to_string())
                        }
                    };
                    let fork = {
                        let mut builder = builder.borrow_mut();
                        builder.forks.push(Fork { upstream });
                        builder.forks.len() - 1
                    };
                    for (index, branch) in branches.iter().enumerate() {
                        self.build_pipeline(
                            branch,
                            Feed::Branch {
                                fork,
                                order: index + 1,
                            },
                            upstream.is_some(),
                            builder,
                        )
                        .await?;
                    }
                    Ok(NodeRef::Fork(fork))
                }
            }
        })
    }
}

fn push_step(builder: &RefCell<Builder>, step: Step) -> NodeRef {
    let mut builder = builder.borrow_mut();
    builder.steps.push(step);
    NodeRef::Step(builder.steps.len() - 1)
}

// --- executing a plan ---------------------------------------------------------

/// What the runner needs from whoever is running a plan: a way to issue a step's request
/// and a way to read a target's contract. Two hosts, one runner — the REPL session
/// ([`Engine`]: the session's capability, the line's chain, the cache tally) and the
/// invocation serving `urn:plan:eval` (the CALLER's capability, every step recorded as a
/// dependency of the answer, so it is exactly as cacheable as its least cacheable step).
///
/// `async fn` in a crate-private trait on purpose: the runner is generic over the host, so
/// whether its future is `Send` is decided per host — the invocation's is (an endpoint's
/// future must be), the session's is not (the REPL is single-threaded by design) — without
/// a second copy of the runner for each.
#[cfg(feature = "plan-reader")]
pub(crate) trait PlanHost {
    /// How a failed request is reported — kept as the host's own type, so a typed
    /// `Denied` from a step reaches `urn:plan:eval`'s caller as a typed `Denied`.
    type Error;

    /// Issue one request. `incoming` is the provenance of everything the request was built
    /// from (its feed and its references), for a host that folds it into the result's
    /// cacheability itself; a host whose sub-requests are recorded for it may ignore it.
    async fn issue(&self, request: Request, incoming: Provenance) -> Result<Staged, Self::Error>;

    /// The target's contract, for routing a fed value — `None` when it cannot be read,
    /// which routes to the conventional `in` exactly as the text face does.
    async fn describe(&self, iri: &Iri) -> Option<Description>;

    /// A fan-out happened, `nominal` wide, and ran sequentially.
    fn fan_out(&self, _nominal: usize) {}
}

/// Why a run did not produce an answer.
#[cfg(feature = "plan-reader")]
#[derive(Debug)]
pub(crate) enum RunError<E> {
    /// The plan cannot run as written: a structural refusal, a value the routing rule
    /// cannot place, a map over bytes that are not text.
    Plan(String),
    /// A supplied parameter the plan does not declare.
    Parameter { name: String, detail: String },
    /// A required parameter with no default, and no value supplied.
    MissingParameter(String),
    /// A step's request failed; the host's error, untouched.
    Step(E),
}

#[cfg(feature = "plan-reader")]
impl RunError<String> {
    /// The message a text face prints.
    pub(crate) fn into_message(self) -> String {
        match self {
            RunError::Plan(message) | RunError::Step(message) => message,
            RunError::Parameter { detail, .. } => detail,
            RunError::MissingParameter(name) => format!(
                "the plan's parameter `{name}` is required and has no default, and `run` \
                 supplies no parameters — give it an ik:default, or evaluate the plan through \
                 `urn:plan:eval` with `{name}` as an argument"
            ),
        }
    }
}

#[cfg(feature = "plan-reader")]
impl Plan {
    /// Every parameter's value for one run: what the caller supplied, else its
    /// `ik:default`, else nothing (an optional parameter with no default is left UNSET —
    /// a step's argument referencing it is omitted, as an unset optional input is).
    pub(crate) fn parameter_values<E>(
        &self,
        supplied: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, Option<String>>, RunError<E>> {
        if let Some(unknown) = supplied
            .keys()
            .find(|name| !self.params.iter().any(|param| &param.name == *name))
        {
            let declared: Vec<&str> = self.params.iter().map(|p| p.name.as_str()).collect();
            return Err(RunError::Parameter {
                name: unknown.clone(),
                detail: format!(
                    "<{}> declares no parameter `{unknown}` (it declares {})",
                    self.iri(),
                    if declared.is_empty() {
                        "none".to_string()
                    } else {
                        declared.join(", ")
                    }
                ),
            });
        }
        let mut values = BTreeMap::new();
        for param in &self.params {
            let value = supplied
                .get(&param.name)
                .cloned()
                .or_else(|| param.default.clone());
            if value.is_none() && param.required {
                return Err(RunError::MissingParameter(param.name.clone()));
            }
            values.insert(param.name.clone(), value);
        }
        Ok(values)
    }
}

/// Run a plan and return the representation of its `ik:result`.
///
/// THE runner — the REPL's `run` and `urn:plan:eval` both call it. Nodes nothing reaches
/// from the result are not run: the plan is a dependency graph, not a script, so what runs
/// is what the answer depends on, dependencies first ([`Plan::run_order`]). Sequential:
/// a fork's branches and a map's items run one after another.
#[cfg(feature = "plan-reader")]
pub(crate) async fn execute<H: PlanHost>(
    host: &H,
    plan: &Plan,
    supplied: &BTreeMap<String, String>,
) -> Result<Staged, RunError<H::Error>> {
    let values = plan.parameter_values(supplied)?;
    let order = plan
        .run_order()
        .map_err(|refusal| RunError::Plan(refusal.message))?;
    let mut done: BTreeMap<NodeRef, Staged> = BTreeMap::new();
    for node in order {
        let staged = match node {
            NodeRef::Step(index) => run_step(host, plan, index, &done, &values).await?,
            NodeRef::Fork(index) => {
                let tails = plan
                    .branch_tails(index)
                    .map_err(|refusal| RunError::Plan(refusal.message))?;
                // Sequential, so the achieved width is 1 however many branches there are —
                // the same honest number `run_node`'s no-spawner fork path records. ⚠ The
                // text face has a concurrent path for single-`source` branches
                // (`run_parallel`); a plan does not yet, so moving a wide fork into a plan
                // costs its concurrency today.
                host.fan_out(tails.len());
                combine_outputs(tails.iter().map(|tail| done[tail].clone()).collect())
            }
        };
        done.insert(node, staged);
    }
    Ok(done
        .remove(&plan.result)
        .expect("the result is the last node of its own run order"))
}

/// One step: its arguments (by value, and by reference — resolved once, for every item of
/// a map), then its request — once, or once per item of a mapped upstream.
#[cfg(feature = "plan-reader")]
async fn run_step<H: PlanHost>(
    host: &H,
    plan: &Plan,
    index: usize,
    done: &BTreeMap<NodeRef, Staged>,
    values: &BTreeMap<String, Option<String>>,
) -> Result<Staged, RunError<H::Error>> {
    let step = &plan.steps[index];
    let upstream: Option<&Staged> = match step.feed {
        Feed::None => None,
        Feed::Pipe(up) | Feed::Map(up) => Some(&done[&up]),
        Feed::Branch { fork, .. } => plan.forks[fork].upstream.map(|up| &done[&up]),
    };

    let mut arguments: Vec<(String, Vec<u8>)> = step
        .arguments
        .iter()
        .map(|(name, value)| (name.clone(), value.as_bytes().to_vec()))
        .collect();
    // Everything the request is built from, for its provenance: the feed, every bound
    // name it references, and every resource it sources.
    let mut inputs: Vec<Provenance> = upstream.iter().map(|up| up.provenance()).collect();
    for (name, to) in &step.refs {
        match to {
            RefTo::Name(var) => match plan.binder(var) {
                Some(binder) => {
                    let bound = &done[&NodeRef::Step(binder)];
                    arguments.push((name.clone(), bound.bytes.clone()));
                    inputs.push(bound.provenance());
                }
                // A parameter: its value for this run, or — unset and optional — no
                // argument at all.
                None => {
                    if let Some(Some(value)) = values.get(var) {
                        arguments.push((name.clone(), value.as_bytes().to_vec()));
                    }
                }
            },
            RefTo::Resource(iri) => {
                let sourced = host
                    .issue(Request::new(Verb::Source, iri.clone()), root_provenance())
                    .await
                    .map_err(RunError::Step)?;
                inputs.push(sourced.provenance());
                arguments.push((name.clone(), sourced.bytes));
            }
        }
    }
    let provenance = fold_provenance(inputs);

    // Where a fed value goes: `content` for a mutating verb, and the one declared argument
    // left unnamed for a read — the text face's rule, through the one function both use.
    let fed_name = match upstream {
        None => None,
        Some(_) => Some(match step.verb {
            Verb::Sink | Verb::Delete => "content".to_string(),
            _ => {
                let description = host.describe(&step.resolves).await;
                let named: Vec<&str> = step
                    .arguments
                    .keys()
                    .chain(step.refs.keys())
                    .map(String::as_str)
                    .collect();
                route_value_name(&step.resolves, description.as_ref(), &named)
                    .map_err(RunError::Plan)?
            }
        }),
    };
    let request = |value: Option<&[u8]>| {
        let mut request = Request::new(step.verb, step.resolves.clone());
        for (name, bytes) in &arguments {
            request = request.with_arg(name, ArgRef::Inline(bytes.clone()));
        }
        if let (Some(name), Some(value)) = (&fed_name, value) {
            request = request.with_arg(name, ArgRef::Inline(value.to_vec()));
        }
        request
    };

    let Some(upstream) = upstream else {
        return host
            .issue(request(None), provenance)
            .await
            .map_err(RunError::Step);
    };
    if !matches!(step.feed, Feed::Map(_)) {
        return host
            .issue(request(Some(&upstream.bytes)), provenance)
            .await
            .map_err(RunError::Step);
    }

    // `..` — the same newline-item convention `run_map` uses, item for item.
    let text = std::str::from_utf8(&upstream.bytes).map_err(|_| {
        RunError::Plan(
            "`..` maps over newline-separated text items, but the piped value is not \
             UTF-8 text — use a plain `|` to pass the bytes through whole"
                .to_string(),
        )
    })?;
    host.fan_out(text.split('\n').count());
    let mut outputs = Vec::new();
    for item in text.split('\n') {
        outputs.push(
            host.issue(request(Some(item.as_bytes())), provenance.clone())
                .await
                .map_err(RunError::Step)?,
        );
    }
    Ok(combine_outputs(outputs))
}

/// The provenance of a request built from `inputs`: the most restrictive expiry and every
/// thread — the identity (`Never`, no threads) when it was built from nothing.
#[cfg(feature = "plan-reader")]
fn fold_provenance(inputs: Vec<Provenance>) -> Provenance {
    inputs.into_iter().fold(root_provenance(), |acc, part| {
        let mut threads = acc.threads;
        threads.extend(part.threads);
        Provenance::new(acc.expiry.most_restrictive(part.expiry), threads)
    })
}

/// The REPL session as a plan host: its capability, its line's chain, its cache tally.
#[cfg(feature = "plan-reader")]
impl PlanHost for Engine {
    type Error = String;

    async fn issue(&self, request: Request, incoming: Provenance) -> Result<Staged, String> {
        self.run_staged(request, Some(incoming)).await
    }

    async fn describe(&self, iri: &Iri) -> Option<Description> {
        self.describe_struct(iri).await
    }

    fn fan_out(&self, nominal: usize) {
        self.record_sequential_fan_out(nominal);
    }
}

impl Engine {
    /// `plan <spec>` — render the spec as an `ik:Process` graph instead of running it.
    pub(crate) async fn run_plan(&self, spec: &str) -> Result<String, String> {
        if spec.trim().is_empty() {
            return Err("usage: plan <spec> — the pipeline to render as a graph".to_string());
        }
        let plan = self.build_plan(spec).await?;
        Ok(plan.to_turtle(Some(spec.trim())))
    }

    /// `run <spec>` — resolve `<spec>` (the full `source` grammar) and execute the
    /// `ik:Process` graph it returns. `sink` stores a plan; this runs a stored one, through
    /// the same runner `urn:plan:eval` uses. Parameters take their defaults: the text face
    /// has no spelling for supplying one yet.
    #[cfg(feature = "plan-reader")]
    pub(crate) async fn run_stored_plan(&self, spec: &str) -> Result<String, String> {
        if spec.trim().is_empty() {
            return Err(
                "usage: run <spec> — resolve a resource and run the plan it holds".to_string(),
            );
        }
        let turtle = self.run_pipeline(spec).await?;
        let plan = Plan::from_turtle(&turtle)?;
        execute(self, &plan, &BTreeMap::new())
            .await
            .map_err(RunError::into_message)?
            .into_text()
    }

    /// Without the reader there is no Turtle parser in this build, so say which feature is
    /// missing rather than pretending the command does not exist — a wasm host still
    /// RENDERS plans, and a `run` that answers "unknown command" would read like a bug.
    #[cfg(not(feature = "plan-reader"))]
    pub(crate) async fn run_stored_plan(&self, _spec: &str) -> Result<String, String> {
        Err(
            "`run` needs the `plan-reader` feature of ikigai-engine — this build renders \
             plans (`plan <spec>`) but cannot read one back"
                .to_string(),
        )
    }
}

// Every test here reads a rendered plan back — that IS the assertion, since a renderer is
// only right if what it wrote means what the spec meant. So the module needs the reader;
// `cargo test --all-features` (the gates and CI) has it.
#[cfg(all(test, feature = "plan-reader"))]
mod tests {
    use super::*;

    fn iri(s: &str) -> Iri {
        Iri::parse(s).expect("valid IRI")
    }

    fn step(resolves: &str, feed: Feed, arguments: &[(&str, &str)]) -> Step {
        Step {
            verb: Verb::Source,
            resolves: iri(resolves),
            arguments: arguments
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            refs: BTreeMap::new(),
            binds: None,
            feed,
        }
    }

    /// Every term the engine emits, in one plan: a bare first stage, a pipe, a map, a fork
    /// with two ordered branches over an upstream, arguments, and a fork as the result.
    fn every_shape() -> Plan {
        Plan {
            id: "demo".to_string(),
            params: Vec::new(),
            steps: vec![
                step("urn:t:one", Feed::None, &[("in", "hello")]),
                step("urn:t:two", Feed::Pipe(NodeRef::Step(0)), &[]),
                step(
                    "urn:t:three",
                    Feed::Map(NodeRef::Step(1)),
                    &[("as", "text/plain")],
                ),
                step(
                    "urn:t:four",
                    Feed::Branch { fork: 0, order: 1 },
                    &[("flavor", "salty")],
                ),
                step("urn:t:five", Feed::Branch { fork: 0, order: 2 }, &[]),
            ],
            forks: vec![Fork {
                upstream: Some(NodeRef::Step(2)),
            }],
            result: NodeRef::Fork(0),
        }
    }

    /// What a graph can say that the text face cannot yet: parameters, a bound name, and
    /// references to a name, to a parameter, and to a resource.
    fn named() -> Plan {
        let mut first = step("urn:t:one", Feed::None, &[("as", "text/plain")]);
        first.binds = Some("greeting".to_string());
        first
            .refs
            .insert("in".to_string(), RefTo::Name("who".to_string()));
        let mut second = step("urn:t:two", Feed::None, &[]);
        second
            .refs
            .insert("in".to_string(), RefTo::Name("greeting".to_string()));
        second
            .refs
            .insert("style".to_string(), RefTo::Resource(iri("urn:t:style")));
        Plan {
            id: "named".to_string(),
            params: vec![Param {
                name: "who".to_string(),
                required: false,
                default: Some("world".to_string()),
                source: Some("argument".to_string()),
                class: Some("http://www.w3.org/2001/XMLSchema#string".to_string()),
                summary: Some("whom to greet".to_string()),
            }],
            steps: vec![first, second],
            forks: Vec::new(),
            result: NodeRef::Step(1),
        }
    }

    #[test]
    fn a_plan_reads_back_as_itself() {
        let plan = every_shape();
        let read = Plan::from_turtle(&plan.to_turtle(Some("the text face"))).expect("read back");
        assert_eq!(read, plan);
        // `rdfs:comment` is documentation: the graph is the plan, so dropping the text face
        // changes nothing about what runs — and the re-render is byte-identical, which is
        // what makes a stored plan diffable after a round trip.
        assert_eq!(read.to_turtle(None), plan.to_turtle(None));
    }

    #[test]
    fn named_results_and_parameters_read_back_as_themselves() {
        let plan = named();
        let turtle = plan.to_turtle(None);
        assert!(turtle.contains("ik:binds \"greeting\""), "{turtle}");
        assert!(turtle.contains("<urn:plan:named:var:who>"), "{turtle}");
        assert!(turtle.contains("ik:ref <urn:t:style>"), "{turtle}");
        let read = Plan::from_turtle(&turtle).expect("read back");
        assert_eq!(read, plan);
        assert_eq!(read.to_turtle(None), turtle);
    }

    #[test]
    fn a_reference_is_an_edge_so_the_binder_runs_first() {
        let plan = named();
        assert_eq!(
            plan.run_order().expect("a DAG"),
            vec![NodeRef::Step(0), NodeRef::Step(1)]
        );
    }

    #[test]
    fn a_cycle_through_a_reference_is_refused_as_a_cycle() {
        // Two steps that each reference the other's name: no pipe, map or fork edge, so
        // the shapes' edge-cycle constraint cannot see it — this is the hop it hands over.
        let turtle = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:loop> a ik:Process ;
    ik:step <urn:plan:loop:step:1> , <urn:plan:loop:step:2> ;
    ik:result <urn:plan:loop:step:2> .
<urn:plan:loop:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:a> ;
    ik:binds "a" ; ik:argument <urn:plan:loop:step:1:arg:in> .
<urn:plan:loop:step:1:arg:in> a ik:Argument ; ik:inputName "in" ; ik:ref <urn:plan:loop:var:b> .
<urn:plan:loop:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:b> ;
    ik:binds "b" ; ik:argument <urn:plan:loop:step:2:arg:in> .
<urn:plan:loop:step:2:arg:in> a ik:Argument ; ik:inputName "in" ; ik:ref <urn:plan:loop:var:a> .
"#;
        let refusal = Plan::read(turtle).expect_err("a cycle");
        assert_eq!(refusal.kind, RefusalKind::Cycle, "{}", refusal.message);
        assert!(refusal.message.contains("DAG"), "{}", refusal.message);
    }

    #[test]
    fn a_cycle_the_result_never_reaches_is_refused_too() {
        // Step 1 is the result and depends on nothing; steps 2 and 3 reference each other.
        // A run would never reach them — and the plan is still wrong, so it is refused.
        let turtle = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:aside> a ik:Process ;
    ik:step <urn:plan:aside:step:1> , <urn:plan:aside:step:2> , <urn:plan:aside:step:3> ;
    ik:result <urn:plan:aside:step:1> .
<urn:plan:aside:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:a> .
<urn:plan:aside:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:b> ;
    ik:binds "b" ; ik:argument <urn:plan:aside:step:2:arg:in> .
<urn:plan:aside:step:2:arg:in> a ik:Argument ; ik:inputName "in" ; ik:ref <urn:plan:aside:var:c> .
<urn:plan:aside:step:3> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:c> ;
    ik:binds "c" ; ik:pipeFrom <urn:plan:aside:step:2> .
"#;
        assert_eq!(
            Plan::read(turtle).expect_err("a cycle").kind,
            RefusalKind::Cycle
        );
    }

    #[test]
    fn names_are_single_assignment_and_references_must_be_bound() {
        let mut twice = named();
        twice.steps[1].binds = Some("who".to_string());
        let err = Plan::from_turtle(&twice.to_turtle(None)).expect_err("bound twice");
        assert!(err.contains("single-assignment"), "{err}");

        let mut dangling = named();
        dangling.steps[1]
            .refs
            .insert("extra".to_string(), RefTo::Name("nobody".to_string()));
        let err = Plan::from_turtle(&dangling.to_turtle(None)).expect_err("unbound");
        assert!(err.contains("never binds"), "{err}");
    }

    #[test]
    fn parameter_values_take_the_supplied_then_the_default_and_refuse_strangers() {
        let plan = named();
        let none = BTreeMap::new();
        let values = plan.parameter_values::<String>(&none).expect("defaults");
        assert_eq!(values["who"].as_deref(), Some("world"));
        let supplied = BTreeMap::from([("who".to_string(), "Brian".to_string())]);
        let values = plan
            .parameter_values::<String>(&supplied)
            .expect("supplied");
        assert_eq!(values["who"].as_deref(), Some("Brian"));
        let stranger = BTreeMap::from([("whom".to_string(), "x".to_string())]);
        assert!(matches!(
            plan.parameter_values::<String>(&stranger),
            Err(RunError::Parameter { name, .. }) if name == "whom"
        ));
        let mut required = named();
        required.params[0].default = None;
        required.params[0].required = true;
        assert!(matches!(
            required.parameter_values::<String>(&none),
            Err(RunError::MissingParameter(name)) if name == "who"
        ));
    }

    #[test]
    fn a_step_with_no_arguments_still_ends_its_description() {
        // The `;` of the last predicate has to become a `.` when no `ik:argument` follows,
        // or the graph is a Turtle syntax error that only shows up on the way back in.
        let plan = Plan {
            id: "bare".to_string(),
            params: Vec::new(),
            steps: vec![step("urn:t:one", Feed::None, &[])],
            forks: Vec::new(),
            result: NodeRef::Step(0),
        };
        let read = Plan::from_turtle(&plan.to_turtle(None)).expect("read back");
        assert_eq!(read, plan);
    }

    #[test]
    fn a_value_carrying_turtle_syntax_survives() {
        // An argument is author-supplied text: a bare `"` in it would close the literal and
        // everything after would parse as Turtle. The round trip is the only real check.
        let quoted = "say \"hi\" \\ then\na newline\ttab";
        let plan = Plan {
            id: "quoted".to_string(),
            params: Vec::new(),
            steps: vec![step("urn:t:one", Feed::None, &[("in", quoted)])],
            forks: Vec::new(),
            result: NodeRef::Step(0),
        };
        let read = Plan::from_turtle(&plan.to_turtle(None)).expect("read back");
        assert_eq!(read.steps[0].arguments["in"], quoted);
    }

    #[test]
    fn step_numbering_comes_from_the_iris_not_the_graph_order() {
        // Turtle is unordered and the parser hands the triples back in whatever order the
        // document had; `{n}` is what preserves the text face's positions across a round
        // trip, so it is read rather than re-derived.
        let plan = every_shape();
        let turtle = plan.to_turtle(None);
        // Reverse the document's paragraphs: same graph, different serialization order.
        let mut blocks: Vec<&str> = turtle.split("\n\n").collect();
        let header = blocks.remove(0);
        blocks.reverse();
        let shuffled = format!("{header}\n\n{}", blocks.join("\n\n"));
        assert_eq!(Plan::from_turtle(&shuffled).expect("read back"), plan);
    }

    #[test]
    fn a_graph_missing_the_pieces_says_which() {
        let cases = [
            ("<urn:a> <urn:b> \"c\" .", "not a plan"),
            (
                "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                 <urn:plan:x> a ik:Process ; ik:result <urn:plan:x:step:1> .",
                "no ik:step",
            ),
            (
                "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                 <urn:plan:x> a ik:Process ; ik:step <urn:plan:x:step:1> ;\n\
                   ik:result <urn:plan:x:step:1> .\n\
                 <urn:plan:x:step:1> a ik:Step ; ik:verb \"Shout\" ;\n\
                   ik:resolves <urn:t:one> .",
                "Source, Sink, Exists, Delete, Meta",
            ),
            (
                "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                 <urn:plan:x> a ik:Process ; ik:step <urn:plan:x:step:1> ;\n\
                   ik:result <urn:plan:x:step:1> .\n\
                 <urn:plan:x:step:1> a ik:Step ; ik:verb \"Source\" ;\n\
                   ik:resolves <urn:t:one> ; ik:pipeFrom <urn:elsewhere> .",
                "not a step or fork",
            ),
            (
                "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                 <urn:plan:x> a ik:Process ; ik:step <urn:plan:x:step:1> ;\n\
                   ik:result <urn:plan:x:step:1> .\n\
                 <urn:plan:x:step:1> a ik:Step ; ik:verb \"Source\" ;\n\
                   ik:resolves <urn:t:one> ; ik:argument [ ik:inputName \"in\" ] .",
                "blank node",
            ),
            (
                "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                 <urn:plan:x> a ik:Process ; ik:step <urn:plan:x:step:1> ;\n\
                   ik:result <urn:plan:x:step:1> .\n\
                 <urn:plan:x:step:1> a ik:Step ; ik:verb \"Source\" ;\n\
                   ik:resolves <urn:t:one> ; ik:argument <urn:plan:x:step:1:arg:in> .\n\
                 <urn:plan:x:step:1:arg:in> ik:inputName \"in\" .",
                "exactly one of ik:value and ik:ref",
            ),
        ];
        for (turtle, expected) in cases {
            let err = Plan::from_turtle(turtle).expect_err("should refuse");
            assert!(err.contains(expected), "expected `{expected}`, got `{err}`");
        }
    }

    #[test]
    fn a_sink_fed_by_the_plan_may_not_also_name_its_content() {
        // The same two-bodies refusal the text face makes — a graph can state it just as
        // easily, and an executor that picked one would be picking silently.
        let plan = Plan {
            id: "two".to_string(),
            params: Vec::new(),
            steps: vec![
                step("urn:t:one", Feed::None, &[]),
                Step {
                    verb: Verb::Sink,
                    resolves: iri("urn:t:store"),
                    arguments: [("content".to_string(), "named".to_string())]
                        .into_iter()
                        .collect(),
                    refs: BTreeMap::new(),
                    binds: None,
                    feed: Feed::Pipe(NodeRef::Step(0)),
                },
            ],
            forks: Vec::new(),
            result: NodeRef::Step(1),
        };
        let err = Plan::from_turtle(&plan.to_turtle(None)).expect_err("should refuse");
        assert!(err.contains("two bodies"), "{err}");
    }
}
