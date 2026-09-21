# Contributing

Thanks for your interest. ikigai is pre-1.0 and in active use: APIs can change in a minor release, and do.

- Open an issue to discuss substantial changes before a PR. **Substantial** means a change
  someone has to carry somewhere else: a public type or signature (the crates that depend on
  this one have to move with it), a change to what resolution, caching or capability
  enforcement *does* to callers whose code still compiles, or a change to a wire format or the
  engine grammar (other hosts and clients move with it). A bug fix that keeps the signature, a
  test, or a documentation change does not — open the PR.
- Contributions are accepted under the project's MIT OR Apache-2.0 dual license.
