# Working in this repository

`ikigai-cli` is the main ikigai host: the `ikigai` binary and REPL, the embedded host, and the
libraries it is built from (engine, resolution, transports, scheduler, the inbound HTTP door,
and more). These rules are for every agent and every person working here. `CLAUDE.md` is a link
to this file.

- **Read [ACCESSIBILITY.md](ACCESSIBILITY.md) before any change to UI or rendered output**: the
  HTTP door's error pages, the embedded host's pages, the full-screen and line REPLs, and any
  other text the binary writes for people to read. It lists the rules that output follows and
  what has been tested.
- Security reports go through the organization's security policy (GitHub private vulnerability
  reporting), never a public issue.
- Every change lands through a pull request with green CI (`.github/workflows/ci.yml`: fmt,
  clippy with warnings denied, tests and docs across the workspace, plus its other jobs).
- Never invent testing, tool results or conformance evidence, and never weaken a test to make a
  change pass.
- Use American spelling in everything you write: code comments, docs, commit messages and pull
  requests.
