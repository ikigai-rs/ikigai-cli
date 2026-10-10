# A pipeline is a resource: the engine's plan face

The REPL grammar is a *text* face over a plan — a DAG of requests. `plan` renders that
plan as a graph in the published process vocabulary, and `run` executes one that was
stored. The point is not a new way to type a pipeline: it is that a workflow which is a
**graph** is a file you can diff, sign, review in a pull request, and **refuse before it
runs**. A shell pipeline can be none of those.

```
plan <spec>     render a pipeline as an ik:Process graph (Turtle) instead of running it
run  <spec>     resolve <spec> — the full `source` grammar — and RUN the graph it returns
```

`<spec>` is what you would type after `source`, so `plan` and `source` take the same input
and answer two different questions about it.

```sh
# render, store, run — the whole loop
ikigai -c 'plan urn:iki:fn:toUpper hello | urn:iki:fn:toUpper' > ~/.ikigai/workspace/shout.ttl
ikigai -c 'run urn:file:shout.ttl'
```

From inside the REPL, `sink urn:file:shout.ttl content="…"` stores one (that spelling works
as of #328; before it, a named `content=` was silently discarded). `run` takes a whole
source pipeline, so a plan can come from anywhere the kernel can reach — a file, the store,
a peer.

## What the graph says that the text does not

The text face routes a positional value to "the one declared argument left unnamed", and
only the target's contract knows which that is. **A plan is the resolved form.** Rendering
makes that decision once — against the live contracts, by the same rule a run uses — and
writes the argument's name into the graph:

```
source urn:iki:fn:toUpper hello
```

```turtle
<…:step:1> a ik:Step ;
    ik:verb "Source" ;
    ik:resolves <urn:iki:fn:toUpper> ;
    ik:argument <…:step:1:arg:in> .

<…:step:1:arg:in> a ik:Argument ;
    ik:inputName "in" ;
    ik:value "hello" .
```

That is what makes a plan checkable ahead of time, and it is also why `plan` can fail
where the text merely *defers* the same failure to the moment the stage runs.

A **piped** value is deliberately not resolved this way: the vocabulary says the piped
input is not an argument, it arrives through `ik:pipeFrom` / `ik:mapOver`. The plan names
the edge; the host routes it at run time, exactly as the text face does.

A plan is named by the **content address of its spec** (`urn:plan:b3:…`), so the same
pipeline renders to the same plan wherever it is rendered, and two renders of it diff to
nothing. The spec itself rides along as `rdfs:comment` — documentation for a reviewer,
never executed, and dropped when the graph is read back.

## The bar: a round trip

`crates/ikigai-engine/tests/plan_round_trip.rs` runs each spec, renders it, reads the
graph back, runs *that*, and requires **the same execution** — the exact sequence of
requests every endpoint received. Not the same syntax tree: a plan is the resolved form,
so the two trees differ while the two runs do not. Every rendered graph is also validated
against `ikigai_vocab::SHAPES`, so a renderer that emits a shape-invalid plan fails the
build rather than the reader.

## Two shapes the vocabulary cannot spell — refused, not degraded

`ik:mapOver`, `ik:forkOf` and `ik:order` are properties of an `ik:Step`, and a fork is not
a step. So two grammatical pipelines have no plan spelling, and `plan` **refuses** them by
name rather than rendering something that would come back meaning something else:

| spec | why |
| --- | --- |
| `a \| ( ( b ; c ) ; d )` | a fork directly as a fork's branch would need `ik:forkOf` and `ik:order` on an `ik:Fork` |
| `a .. ( b ; c )` | a mapped fork would need `ik:mapOver` on an `ik:Fork` |

Both still **run** as text — this is a gap in the graph, not in the grammar. The workaround
in both cases is the same one the design asks for everywhere: put a stage at the head of
the branch, or make the inner fork **one resource**.

## What a plan deliberately is not

* **Not Turing complete.** No conditional, no loop, no "now". That is what makes it total,
  validatable and refusable. When a plan cannot express something, the answer is a new
  **resource**, never new syntax — `urn:iki:fn:conditional` is branching as a resource, and
  being a resource it recomputes and can take the other branch when a thread is cut, which
  an `if` in a script can never do. `ikigai-throttle`'s `Retry` and `Timeout` are bounded
  repetition and deadlines the same way.
* **Not a workflow engine.** The plan is data. The runner walks the dependency graph from
  the result, so what runs is what the answer depends on; nothing schedules, retries, or
  resumes.

## ⚠ The reader is a feature, and that is about wasm

`ikigai-engine` is documented as compiling to `wasm32-unknown-unknown` —
`ikigai-web-demo` runs the kernel in a browser — and reading a plan back needs a Turtle
parser, which pulls `oxrdf` → `rand` → `getrandom`, and **getrandom does not compile for
wasm32-unknown-unknown** without a rustflag only the final consumer can set. So:

* **`plan` costs nothing** and is always available.
* **`run` is behind `ikigai-engine/plan-reader`**, off by default, enabled by `ikigai-cli`.
  A build without it answers `run` by naming the missing feature rather than acting as if
  the command does not exist.

The claim that this crate builds for wasm was a comment and nothing checked it; `ci.yml`
now runs `cargo clippy -p ikigai-engine --lib --target wasm32-unknown-unknown` under
default features, so it is a gate.

## Plans as resources: `urn:plan:eval`, `urn:plan:validate`, `urn:plan:requires`

`run` is a REPL command, and a command cannot be reached by a sub-request. So the same
runner also answers three resources (ledger #956), each over the plan passed as `in`
(Turtle, inline or as the IRI of a resource holding one). They are bound on the embedded
host's local root (`ikigai-embedded`), and nowhere else yet:

| name | answers |
| --- | --- |
| `urn:plan:eval` | the plan's `ik:result`, with every step a sub-request under the **caller's** capability; `as=` names the result's face (transrepted, or refused if nothing converts it); each declared parameter is a further argument by its own name |
| `urn:plan:validate` | the SHACL report against `ikigai_vocab::SHAPES` (through `urn:shacl:validate`), plus the checks the shapes cannot make; `text/plain` or `text/turtle` |
| `urn:plan:requires` | the capability the plan needs, **derived** from each step's contract (`Description::required_scopes` for the step's verb, read with a `Meta` request that invokes nothing), what the asking capability lacks, and every step whose target resolves nowhere |

```sh
ikigai -c 'source urn:file:shout.ttl | urn:plan:eval'
ikigai -c 'source urn:file:shout.ttl | urn:plan:requires'
```

* **One runner.** `run` and `urn:plan:eval` both call `plan::execute`, each through its own
  host — the REPL session, or the invocation serving the resource. The test that holds this
  (`tests/plan_eval.rs`) runs the four CMS link-check fixtures from `ikigai-vocab` both ways
  and requires the same answer AND the same requests at every stub.
* **No authority of its own.** None of the three declares a scope. `eval` issues every step
  through the invocation, so each step meets its own target's floor under the caller's
  capability — a plan can never do what its caller could not do one request at a time —
  and a step's typed `Denied` reaches the caller typed. `requires` says where: the first step
  it reports as lacking is the step a run under that capability is refused at.
* **Validation fails closed.** `eval` validates first and refuses a non-conforming plan
  with `InvalidArgument` naming the shape. A kernel that does not bind `urn:shacl:validate`
  runs no plan at all, and says why.
* **As cacheable as its least cacheable step.** Every step, the validation and every
  contract read is a recorded sub-request, so the kernel folds them into the answer: a plan
  of pure reads is served from the cache the second time; a plan with a `Sink` runs again.
* **Not on the HTTP door or the served kernels.** A plan is a request *amplifier* — one
  request, many steps, a map over a list. Whether a public or peer surface should offer
  one is a posture decision, not a default.

## Named results and parameters

A graph may bind a step's representation to a name (`ik:binds`), declare the plan's own
parameters (`ik:input`, the ArgSpec nodes an endpoint carries), and pass either by
reference (`ik:ref <urn:plan:{id}:var:{name}>`). The runner executes all three: a
reference to a bound name is an **edge** (the binder runs first), a reference to a
parameter is the caller's value or its `ik:default`, and a reference to any other IRI is
sourced and its representation passed. `run` supplies no parameters (defaults only);
`urn:plan:eval` takes them by name and refuses one the plan does not declare.

The grammar still has no spelling for them (`x = …`, `@x`), so `plan` never emits them.

An `ik:ref` edge goes through a NAME, which no SHACL property path can follow, so the
shapes cannot see a cycle closed that way. The reader can: a plan whose references form a
cycle — anywhere in the graph, not only on the part the result reaches — is refused before
anything runs, and `urn:plan:validate` reports it as `urn:ikigai:plan:check:acyclic`.

## Not built yet

* **Parameters from the text face.** `run` uses defaults; supplying a value needs a
  spelling the grammar does not have.
* **A concurrent fork.** The text face resolves single-`source` fork branches and mapped
  items on the injected scheduler; `run` is sequential, and records the width it actually
  reaches (1) rather than the one it does not.
* **A resolvable plan face.** `urn:program:{name}` — a stored plan that answers `Source` by
  running, and describes itself from its `ik:input` parameters. The parameters and the
  evaluator exist now; `ikigai-script`'s `language=plan` is where a stored plan is meant
  to become a resource (ledger #936).
