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
* **Not a workflow engine.** The plan is data. `run` walks the dependency graph from the
  result, so what runs is what the answer depends on; nothing schedules, retries, or
  resumes.

## Not built yet

* **Named results** (`x = …`, `@x` — `ik:binds`, `ik:ref`, a process's `ik:input`). The
  grammar has no spelling for them, so nothing emits them. A graph that *carries* them is
  refused rather than run with the references quietly dropped.
* **`ik:requires` and `ik:output`.** A plan's capability union and its result's media type
  are both optional in the shapes, and computing either honestly needs every step's
  contract — a *partial* union is worse than none, because a pre-flight would then pass a
  plan the kernel goes on to deny.
* **A concurrent fork.** The text face resolves single-`source` fork branches and mapped
  items on the injected scheduler; `run` is sequential, and records the width it actually
  reaches (1) rather than the one it does not.
* **A resolvable plan face.** `urn:program:{name}` — a stored plan that answers `Source` by
  running, and describes itself from its `ik:input` parameters — needs those parameters,
  so it waits on named results.
