//! A pipeline as a resource: the engine's `ik:Process` face.
//!
//! The REPL grammar is a *text* face over a plan — a DAG of requests. This module is the
//! graph face of the same thing, in the process vocabulary published at
//! `https://ikigai-rs.dev/ns#` (`ik:Process`, `ik:Step`, `ik:Argument`, `ik:Fork`). Two
//! directions, and they are inverses:
//!
//! * [`Engine::build_plan`] parses a spec and resolves it into a [`Plan`];
//!   [`Plan::to_turtle`] renders that as a graph — the `plan <spec>` command.
//! * [`Plan::from_turtle`] reads such a graph back and [`Engine::execute_plan`] runs it —
//!   the `run <spec>` command, which resolves a resource and executes what it holds.
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
//! ## What is deliberately not here
//!
//! * **Named results** (`x = …`, `@x` — `ik:binds`, `ik:ref`, a process's `ik:input`).
//!   The grammar has no spelling for them yet, so nothing emits them; a graph that
//!   *carries* them is REFUSED rather than run with the references quietly dropped.
//! * **Conditionals and loops.** A plan is deliberately not Turing complete — that is
//!   what makes it total, validatable and refusable. When a plan cannot express
//!   something the answer is a new *resource* (`urn:iki:fn:conditional` is branching as a
//!   resource, and being a resource it recomputes and can take the other branch when a
//!   thread is cut), never new syntax.
//! * **`ik:requires` and `ik:output`** — the capability union and the result's media
//!   type. Both are optional in the shapes, and computing either honestly needs every
//!   step's contract; a *partial* union is worse than none, because it would let a
//!   pre-flight pass a plan the kernel then denies. The plan validator arc owns them.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use ikigai_core::{ArgRef, ContentId, Iri, Request, Verb};
use oxrdf::{NamedOrBlankNode, Term};
use oxttl::TurtleParser;

use crate::engine::{
    combine_outputs, declared_arguments, parse_spec, parse_target, root_provenance,
    route_value_name, Connector, Engine, Node, Pipeline, Staged,
};

/// The ikigai vocabulary namespace — the terms a plan graph is written in.
const IK: &str = "https://ikigai-rs.dev/ns#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

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

/// One request of a plan: one verb against one IRI, with named arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Step {
    pub verb: Verb,
    pub resolves: Iri,
    /// Named arguments carrying literal values, sorted by name — so the graph a spec
    /// renders to is canonical and two plans diff on meaning rather than word order.
    pub arguments: BTreeMap<String, String>,
    pub feed: Feed,
}

/// A set of branches over one upstream representation, joined in order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Fork {
    /// Absent when the fork is the plan's first stage and its branches take no input.
    pub upstream: Option<NodeRef>,
}

/// A plan: the steps, the forks, and which node's representation is the answer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Plan {
    /// `{plan-id}` — the content address of the spec, for an anonymous plan.
    pub id: String,
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

    fn node_iri(&self, node: NodeRef) -> String {
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
        let steps: Vec<String> = (0..self.steps.len())
            .map(|i| format!("<{}>", self.node_iri(NodeRef::Step(i))))
            .collect();
        out.push_str(&format!(
            "    ik:step {} ;\n    ik:result <{}> .\n",
            steps.join(" ,\n            "),
            self.node_iri(self.result)
        ));

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
            let args: Vec<String> = step
                .arguments
                .keys()
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
                for (name, value) in &step.arguments {
                    out.push_str(&format!(
                        "\n<{}> a ik:Argument ;\n    ik:inputName {} ;\n    ik:value {} .\n",
                        self.argument_iri(i, name),
                        literal(name),
                        literal(value)
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

fn verb_name(verb: Verb) -> &'static str {
    match verb {
        Verb::Source => "Source",
        Verb::Sink => "Sink",
        Verb::Exists => "Exists",
        Verb::Delete => "Delete",
        Verb::Meta => "Meta",
    }
}

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
fn literal(s: &str) -> String {
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

// --- reading -----------------------------------------------------------------

/// An object of a triple: a plan graph is skolemized, so only IRIs and literals appear.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Obj {
    Iri(String),
    Literal(String),
}

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
struct Graph {
    subjects: BTreeMap<String, BTreeMap<String, Vec<Obj>>>,
}

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

fn blank_node_refusal(label: &str) -> String {
    format!(
        "a plan graph is skolemized, so every node has a stable IRI — `_:{label}` is a \
         blank node and nothing can reference it"
    )
}

impl Plan {
    /// Read a plan back out of an `ik:Process` graph.
    ///
    /// Strict on purpose: a plan is a thing you *refuse before it runs*, so anything this
    /// engine cannot execute exactly as written is an error rather than a best effort.
    pub fn from_turtle(turtle: &str) -> Result<Plan, String> {
        let graph = Graph::parse(turtle)?;

        let plan_iri = match graph.of_class("Process").as_slice() {
            [only] => (*only).to_string(),
            [] => return Err("no ik:Process in this graph — it is not a plan".to_string()),
            many => {
                return Err(format!(
                    "{} ik:Process nodes in one graph; a plan resource holds exactly one",
                    many.len()
                ))
            }
        };
        let id = plan_iri
            .strip_prefix("urn:plan:")
            .ok_or_else(|| format!("a plan is named `urn:plan:{{id}}`, not <{plan_iri}>"))?
            .to_string();

        // Named results are step 3. A graph that carries them means something this engine
        // cannot yet honour, and running it with the references dropped would be a
        // different plan that looked like it worked.
        for (subject, predicates) in &graph.subjects {
            for term in ["binds", "ref", "input"] {
                if predicates.contains_key(&format!("{IK}{term}")) {
                    return Err(format!(
                        "<{subject}> uses ik:{term} — named results (`x = …`, `@x`) are not \
                         executable yet, and a plan that names them will not be run with the \
                         references dropped"
                    ));
                }
            }
        }

        let step_iris = ordered_nodes(&graph, &plan_iri, "step", "Step")?;
        let fork_iris = ordered_nodes(&graph, &plan_iri, "fork", "Fork")?;
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

        let mut steps = Vec::with_capacity(step_iris.len());
        for step_iri in &step_iris {
            steps.push(read_step(&graph, step_iri, &node_ref)?);
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
                    ));
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
            steps,
            forks,
            result,
        };
        plan.check()?;
        Ok(plan)
    }

    /// The structural rules a reader must hold that reading one node at a time cannot
    /// see. The SHACL shapes state all of these too — but a graph is validated by
    /// whoever chooses to, and an executor may not assume anyone did.
    fn check(&self) -> Result<(), String> {
        for (i, step) in self.steps.iter().enumerate() {
            if step.verb == Verb::Sink
                && !matches!(step.feed, Feed::None)
                && step.arguments.contains_key("content")
            {
                return Err(format!(
                    "<{}> is fed by the plan AND names `content` — two bodies, with no rule \
                     for choosing between them",
                    self.node_iri(NodeRef::Step(i))
                ));
            }
            if let Feed::Branch { fork, .. } = step.feed {
                if fork >= self.forks.len() {
                    return Err(format!(
                        "<{}> is a branch of a fork this plan does not hold",
                        self.node_iri(NodeRef::Step(i))
                    ));
                }
            }
        }
        // Every fork has at least one branch, and its branches join in distinct order —
        // both of which `branch_tails` needs to be true before it walks anything.
        for fork in 0..self.forks.len() {
            self.branch_tails(fork)?;
        }
        Ok(())
    }

    /// The tail of each branch of `fork`, in join order: the branches are the steps whose
    /// `ik:forkOf` names it, and a branch that is itself a pipeline is the chain from
    /// that head — what the fork joins is the chain's last node.
    fn branch_tails(&self, fork: usize) -> Result<Vec<NodeRef>, String> {
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
            ));
        }
        if heads.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(format!(
                "<{}> has two branches at the same ik:order, so the join has no order",
                self.node_iri(NodeRef::Fork(fork))
            ));
        }
        heads
            .into_iter()
            .map(|(_, head)| self.chain_tail(NodeRef::Step(head)))
            .collect()
    }

    /// Follow the chain forward from a branch head to the node nothing else consumes.
    fn chain_tail(&self, head: NodeRef) -> Result<NodeRef, String> {
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
                    ))
                }
            }
        }
        Err(format!(
            "the edges from <{}> form a cycle — a plan is a DAG",
            self.node_iri(head)
        ))
    }
}

/// The `ik:{predicate}` nodes of the plan, ordered by the `{n}` in their skolem IRIs.
///
/// `{n}` is only a step's position in the text face, so nothing depends on it — but
/// reading it back preserves the numbering a render produced, which keeps a plan's
/// rendered form stable across a round trip and therefore diffable.
fn ordered_nodes(
    graph: &Graph,
    plan_iri: &str,
    predicate: &str,
    class: &str,
) -> Result<Vec<String>, String> {
    let mut iris: Vec<String> = if predicate == "step" {
        graph
            .objects(plan_iri, predicate)
            .iter()
            .map(|object| object.iri(plan_iri, predicate).map(str::to_string))
            .collect::<Result<_, _>>()?
    } else {
        // Forks are not linked from the process — they are reached through the steps that
        // branch off them, so the graph's own `a ik:Fork` assertions are the list.
        graph
            .of_class(class)
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    if predicate == "step" && iris.is_empty() {
        return Err(format!(
            "<{plan_iri}> has no ik:step — a plan runs something"
        ));
    }
    let prefix = format!("{plan_iri}:{predicate}:");
    iris.sort_by_key(|iri| {
        let n = iri
            .strip_prefix(&prefix)
            .and_then(|rest| rest.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        (n, iri.clone())
    });
    iris.dedup();
    Ok(iris)
}

fn read_step(
    graph: &Graph,
    step_iri: &str,
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
    for object in graph.objects(step_iri, "argument") {
        let arg_iri = object.iri(step_iri, "argument")?;
        let name = graph
            .one(arg_iri, "inputName")?
            .literal(arg_iri, "inputName")?
            .to_string();
        let value = graph
            .one(arg_iri, "value")?
            .literal(arg_iri, "value")?
            .to_string();
        if arguments.insert(name.clone(), value).is_some() {
            return Err(format!(
                "<{step_iri}> gives the argument `{name}` more than once"
            ));
        }
    }

    Ok(Step {
        verb,
        resolves,
        arguments,
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
    /// Contracts are consulted exactly where the text face consults them — to recognise a
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

/// Per-run state: each node's representation, computed once, and the stack that catches a
/// cycle the shapes did not (a graph is validated by whoever chooses to).
#[derive(Default)]
struct Run {
    done: RefCell<BTreeMap<NodeRef, Staged>>,
    visiting: RefCell<Vec<NodeRef>>,
}

impl Engine {
    /// Run a plan and return the representation of its `ik:result`.
    ///
    /// Nodes nothing reaches from the result are not run — the plan is a dependency
    /// graph, not a script, so what runs is what the answer depends on.
    pub(crate) async fn execute_plan(&self, plan: &Plan) -> Result<Staged, String> {
        let run = Run::default();
        self.eval_node(plan, plan.result, &run).await
    }

    fn eval_node<'a>(
        &'a self,
        plan: &'a Plan,
        node: NodeRef,
        run: &'a Run,
    ) -> Pin<Box<dyn Future<Output = Result<Staged, String>> + 'a>> {
        Box::pin(async move {
            if let Some(staged) = run.done.borrow().get(&node) {
                return Ok(staged.clone());
            }
            {
                let mut visiting = run.visiting.borrow_mut();
                if visiting.contains(&node) {
                    return Err(format!(
                        "<{}> depends on itself — a plan is a DAG",
                        plan.node_iri(node)
                    ));
                }
                visiting.push(node);
            }
            let staged = match node {
                NodeRef::Step(index) => self.eval_step(plan, index, run).await,
                NodeRef::Fork(index) => self.eval_fork(plan, index, run).await,
            };
            run.visiting.borrow_mut().pop();
            let staged = staged?;
            run.done.borrow_mut().insert(node, staged.clone());
            Ok(staged)
        })
    }

    async fn eval_step(&self, plan: &Plan, index: usize, run: &Run) -> Result<Staged, String> {
        let step = &plan.steps[index];
        let upstream = match step.feed {
            Feed::None => None,
            Feed::Pipe(up) | Feed::Map(up) => Some(self.eval_node(plan, up, run).await?),
            Feed::Branch { fork, .. } => match plan.forks[fork].upstream {
                Some(up) => Some(self.eval_node(plan, up, run).await?),
                None => None,
            },
        };
        let Some(upstream) = upstream else {
            let request = self.plan_request(step, None).await?;
            return self.run_staged(request, Some(root_provenance())).await;
        };
        if !matches!(step.feed, Feed::Map(_)) {
            let request = self.plan_request(step, Some(&upstream.bytes)).await?;
            return self.run_staged(request, Some(upstream.provenance())).await;
        }

        // `..` — the same newline-item convention `run_map` uses, item for item.
        let text = std::str::from_utf8(&upstream.bytes).map_err(|_| {
            "`..` maps over newline-separated text items, but the piped value is not \
             UTF-8 text — use a plain `|` to pass the bytes through whole"
                .to_string()
        })?;
        let provenance = upstream.provenance();
        self.record_sequential_fan_out(text.split('\n').count());
        let mut outputs = Vec::new();
        for item in text.split('\n') {
            let request = self.plan_request(step, Some(item.as_bytes())).await?;
            outputs.push(self.run_staged(request, Some(provenance.clone())).await?);
        }
        Ok(combine_outputs(outputs))
    }

    async fn eval_fork(&self, plan: &Plan, index: usize, run: &Run) -> Result<Staged, String> {
        let tails = plan.branch_tails(index)?;
        // Sequential, so the achieved width is 1 however many branches there are — the
        // same honest number `run_node`'s no-spawner fork path records. ⚠ The text face
        // has a concurrent path for single-`source` branches (`run_parallel`); a plan does
        // not yet, so moving a wide fork into a plan costs its concurrency today.
        self.record_sequential_fan_out(tails.len());
        let mut outputs = Vec::with_capacity(tails.len());
        for tail in tails {
            outputs.push(self.eval_node(plan, tail, run).await?);
        }
        Ok(combine_outputs(outputs))
    }

    /// Build a step's [`Request`]: the graph's arguments verbatim, plus the fed value
    /// routed the way the text face routes it — `content` for a mutating verb, and the
    /// one declared argument left unnamed for a read.
    async fn plan_request(&self, step: &Step, incoming: Option<&[u8]>) -> Result<Request, String> {
        let mut request = Request::new(step.verb, step.resolves.clone());
        for (name, value) in &step.arguments {
            request = request.with_arg(name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        if let Some(value) = incoming {
            let name = match step.verb {
                Verb::Sink | Verb::Delete => "content".to_string(),
                _ => {
                    let description = self.describe_struct(&step.resolves).await;
                    let named: Vec<&str> = step.arguments.keys().map(String::as_str).collect();
                    route_value_name(&step.resolves, description.as_ref(), &named)?
                }
            };
            request = request.with_arg(name, ArgRef::Inline(value.to_vec()));
        }
        Ok(request)
    }

    /// `plan <spec>` — render the spec as an `ik:Process` graph instead of running it.
    pub(crate) async fn run_plan(&self, spec: &str) -> Result<String, String> {
        if spec.trim().is_empty() {
            return Err("usage: plan <spec> — the pipeline to render as a graph".to_string());
        }
        let plan = self.build_plan(spec).await?;
        Ok(plan.to_turtle(Some(spec.trim())))
    }

    /// `run <spec>` — resolve `<spec>` (the full `source` grammar) and execute the
    /// `ik:Process` graph it returns. `sink` stores a plan; this runs a stored one.
    pub(crate) async fn run_stored_plan(&self, spec: &str) -> Result<String, String> {
        if spec.trim().is_empty() {
            return Err(
                "usage: run <spec> — resolve a resource and run the plan it holds".to_string(),
            );
        }
        let turtle = self.run_pipeline(spec).await?;
        let plan = Plan::from_turtle(&turtle)?;
        self.execute_plan(&plan).await?.into_text()
    }
}

#[cfg(test)]
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
            feed,
        }
    }

    /// Every term the engine emits, in one plan: a bare first stage, a pipe, a map, a fork
    /// with two ordered branches over an upstream, arguments, and a fork as the result.
    fn every_shape() -> Plan {
        Plan {
            id: "demo".to_string(),
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
    fn a_step_with_no_arguments_still_ends_its_description() {
        // The `;` of the last predicate has to become a `.` when no `ik:argument` follows,
        // or the graph is a Turtle syntax error that only shows up on the way back in.
        let plan = Plan {
            id: "bare".to_string(),
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
            steps: vec![
                step("urn:t:one", Feed::None, &[]),
                Step {
                    verb: Verb::Sink,
                    resolves: iri("urn:t:store"),
                    arguments: [("content".to_string(), "named".to_string())]
                        .into_iter()
                        .collect(),
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
