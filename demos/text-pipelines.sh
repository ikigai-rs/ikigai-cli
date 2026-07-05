#!/usr/bin/env bash
# urn:text:* — Unix-like text endpoints as ikigai pipeline citizens.
#
# The engine already speaks Unix: `|` pipes a stage's output into the next,
# `..` maps a stage over newline-separated items. The urn:text:* family
# (wc/head/tail/grep/sort/uniq/nl/rev) makes the REPL a coreutils analog whose
# "files" are RESOURCES — and whose tools are typed, cacheable, self-describing
# endpoints in the same manifold as everything else.
#
# Run:  ./demos/text-pipelines.sh   (built binary at ./target/debug/ikigai)
set -euo pipefail
IK="${IK:-./target/debug/ikigai}"
run() { printf '\n\033[1m$ %s\033[0m\n' "$*"; "$IK" --plain -c "$*"; }

# 1. grep over a piped list — the pipe fills grep's `in`, pattern= binds by name.
run 'source urn:demo:split "apple,banana,avocado,cherry,apricot" | urn:text:grep pattern=ap'
#   apple
#   apricot

# 2. A classic three-stage pipeline: produce a list, sort it, take the top 3.
run 'source urn:demo:split "delta,alpha,charlie,bravo,echo" | urn:text:sort | urn:text:head n=3'
#   alpha / bravo / charlie

# 3. `..` maps a stage over each item — reverse every string.
run 'source urn:demo:split "banana,apple,cherry" .. urn:text:rev'
#   ananab / elppa / yrrehc

# 4. Dogfood: count the kernel's OWN endpoints by piping its catalog through
#    grep and wc. ikigai analyzing itself with Unix tools.
run 'source urn:kernel:catalog | urn:text:grep pattern="a ik:Endpoint" | urn:text:wc'
#   66

# 5. The tools are first-class manifold citizens: typed, self-describing, and
#    therefore selectable/validatable/MCP-projectable like any other action.
run 'describe urn:text:wc'
#   … ik:input <…:wc:input:count> ; ik:oneOf "lines","words","bytes" ; ik:default "lines" …
