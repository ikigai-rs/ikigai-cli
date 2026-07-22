//! `ikigai-intray` — the intray as a **tuplespace**.
//!
//! A tuplespace is Linda's coordination model (Gelernter): processes communicate by
//! dropping *tuples* into a shared space and reading them back by *associative match*,
//! decoupled in space and time. `urn:space:{name}` is that space on the ikigai substrate:
//!
//! - **`out`** — **Sink** a tuple into the space. Content-addressed (blake3), so an
//!   identical drop is idempotent.
//! - **`rd`** — **Source** the space: list the tuple ids, or read one with `tuple=<id>`.
//!   Non-destructive (Linda's `rd`).
//!
//! The space is *physical and inspectable* — tuples are files under a jailed root — which is
//! the seed of the inbox/outbox/error state machine. Later slices add **`in`** (take — the
//! destructive read), **associative match** (a SPARQL/SHACL template, strictly more than
//! Linda's positional match), the **reactive engine** (a watcher fires a handler on drop),
//! and **encrypt-on-drop** (sign-then-encrypt to the owner's key — both primitives already
//! shipped). Two things Linda never had and this does: `out` is **capability-gated**, and
//! tuples can be **sealed** so the space holds ciphertext it cannot read.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, Description, Endpoint, EndpointSpace, Error, Invocation, ReprType, Representation,
    Result, UriTemplate, Verb,
};
use std::path::PathBuf;

/// The tuplespace URI template: `urn:space:{name}` — the `{name}` is the space's identity.
pub const SPACE_TEMPLATE: &str = "urn:space:{name}";

/// `out` (dropping a tuple) requires this capability — the gate a stranger drops under.
pub const CAP_OUT: &str = "urn:cap:space:out";
/// `rd` (reading the space) requires this capability.
pub const CAP_READ: &str = "urn:cap:space:read";

/// Mount the tuplespace at `urn:space:{name}`, backed by a directory under `root`
/// (`<root>/<name>/inbox/`). A host links this into its kernel.
pub fn space(root: PathBuf) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(SPACE_TEMPLATE).expect("SPACE_TEMPLATE is a valid template"),
        SpaceEndpoint::new(root),
    )
}

/// A directory-backed tuplespace. Each named space is `<root>/<name>/inbox/`, and a tuple is
/// a `<blake3>.tuple` file in it.
pub struct SpaceEndpoint {
    root: PathBuf,
}

impl SpaceEndpoint {
    pub fn new(root: PathBuf) -> Self {
        SpaceEndpoint { root }
    }

    /// The inbox directory of a named space. The name is a single segment (validated).
    fn inbox(&self, name: &str) -> PathBuf {
        self.root.join(name).join("inbox")
    }
}

#[async_trait]
impl Endpoint for SpaceEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = inv
            .bindings
            .get("name")
            .ok_or_else(|| Error::MissingArgument("name".to_string()))?;
        // The name is the space's identity — a single segment, never a path.
        if name.is_empty() || name.contains(['/', '\\', ':', '.']) {
            return Err(Error::InvalidArgument {
                name: "name".to_string(),
                detail: "a space name is a single segment (no `/ \\ : .`)".to_string(),
            });
        }
        let inbox = self.inbox(name);

        match inv.request.verb {
            // out: drop a tuple. Content-addressed → an identical drop is a no-op.
            Verb::Sink => {
                if !inv.capability.allows(CAP_OUT) {
                    return Err(Error::Denied(format!(
                        "dropping into a space needs `{CAP_OUT}`"
                    )));
                }
                let content = inv
                    .inline_arg("content")
                    .map_err(|_| Error::MissingArgument("content".to_string()))?;
                let id = blake3::hash(content).to_hex().to_string();
                std::fs::create_dir_all(&inbox)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: create inbox: {e}")))?;
                std::fs::write(inbox.join(format!("{id}.tuple")), content)
                    .map_err(|e| Error::Endpoint(format!("space `{name}`: out: {e}")))?;
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    id.into_bytes(),
                ))
            }
            // rd: read the space — one tuple (`tuple=<id>`) or the list of ids. Non-destructive.
            Verb::Source => {
                if !inv.capability.allows(CAP_READ) {
                    return Err(Error::Denied(format!("reading a space needs `{CAP_READ}`")));
                }
                if let Ok(id) = inv.inline_str("tuple") {
                    if id.is_empty() || id.contains(['/', '\\', '.']) {
                        return Err(Error::InvalidArgument {
                            name: "tuple".to_string(),
                            detail: "a tuple id is a content hash".to_string(),
                        });
                    }
                    let bytes = std::fs::read(inbox.join(format!("{id}.tuple"))).map_err(|_| {
                        Error::NotFound(format!("no tuple `{id}` in space `{name}`"))
                    })?;
                    Ok(Representation::new(
                        ReprType::new("application/octet-stream"),
                        bytes,
                    ))
                } else {
                    // The tuple ids, one per line (the newline-list `..` map convention).
                    let mut ids: Vec<String> = match std::fs::read_dir(&inbox) {
                        Ok(entries) => entries
                            .filter_map(|e| e.ok())
                            .filter_map(|e| {
                                e.file_name()
                                    .to_str()
                                    .and_then(|n| n.strip_suffix(".tuple"))
                                    .map(String::from)
                            })
                            .collect(),
                        Err(_) => Vec::new(), // an empty/absent space lists nothing
                    };
                    ids.sort();
                    Ok(Representation::new(
                        ReprType::new("text/plain").with_param("charset", "utf-8"),
                        ids.join("\n").into_bytes(),
                    ))
                }
            }
            v => Err(Error::Endpoint(format!(
                "urn:space:* answers Source (rd) and Sink (out), not {v:?}"
            ))),
        }
    }

    fn describe(&self) -> Description {
        use ikigai_core::ArgSpec;
        Description::new("space")
            .title("Tuplespace")
            .summary(
                "A physical tuplespace (Linda `out`/`rd`): Sink drops a content-addressed tuple; \
                 Source lists the tuple ids, or reads one with `tuple=<id>`.",
            )
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("rd — list the tuple ids, or read one (`tuple=<id>`)")
                    .input(
                        ArgSpec::new("tuple")
                            .optional()
                            .summary("a tuple id to read; omit to list"),
                    )
                    .requires(CAP_READ),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("out — drop a tuple (the piped content) into the space")
                    .requires(CAP_OUT),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
    use std::sync::Arc;

    fn kernel_at(sub: &str) -> Kernel {
        let root = std::env::temp_dir().join("ikigai-intray-test").join(sub);
        let _ = std::fs::remove_dir_all(&root);
        Kernel::new(Arc::new(space(root)))
    }

    fn iri(s: &str) -> Iri {
        Iri::parse(s).unwrap()
    }

    #[test]
    fn out_then_rd_roundtrips_a_tuple() {
        let k = kernel_at("space-rt");
        let cap = Capability::scoped(vec![CAP_OUT.to_string(), CAP_READ.to_string()]);

        // out → a content-addressed id.
        let out = block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:bookings"))
                    .with_arg("content", ArgRef::Inline(b"a booking".to_vec())),
                &cap,
            ),
        )
        .unwrap();
        let id = String::from_utf8(out.bytes).unwrap();
        assert_eq!(id.len(), 64, "blake3 hex id");

        // rd (list) → the one id.
        let list =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:bookings")), &cap)).unwrap();
        assert_eq!(String::from_utf8(list.bytes).unwrap(), id);

        // rd (one) → the tuple bytes.
        let tuple = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:bookings"))
                    .with_arg("tuple", ArgRef::Inline(id.clone().into_bytes())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(tuple.bytes, b"a booking");

        // An identical drop is idempotent (same content hash → same id, still one tuple).
        let again = block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:bookings"))
                    .with_arg("content", ArgRef::Inline(b"a booking".to_vec())),
                &cap,
            ),
        )
        .unwrap();
        assert_eq!(String::from_utf8(again.bytes).unwrap(), id);
        let list2 =
            block_on(k.issue(Request::new(Verb::Source, iri("urn:space:bookings")), &cap)).unwrap();
        assert_eq!(
            String::from_utf8(list2.bytes).unwrap(),
            id,
            "still one tuple"
        );
    }

    #[test]
    fn out_and_rd_are_capability_gated() {
        let k = kernel_at("space-cap");
        let none = Capability::scoped(Vec::<String>::new());
        // out without the cap → Denied.
        let dropped = block_on(
            k.issue(
                Request::new(Verb::Sink, iri("urn:space:x"))
                    .with_arg("content", ArgRef::Inline(b"x".to_vec())),
                &none,
            ),
        );
        assert!(matches!(dropped, Err(Error::Denied(_))), "got: {dropped:?}");
        // rd without the cap → Denied.
        let read = block_on(k.issue(Request::new(Verb::Source, iri("urn:space:x")), &none));
        assert!(matches!(read, Err(Error::Denied(_))), "got: {read:?}");
    }

    #[test]
    fn reading_a_missing_tuple_is_not_found() {
        let k = kernel_at("space-miss");
        let cap = Capability::scoped(vec![CAP_READ.to_string()]);
        let r = block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:s"))
                    .with_arg("tuple", ArgRef::Inline(b"deadbeef".to_vec())),
                &cap,
            ),
        );
        assert!(matches!(r, Err(Error::NotFound(_))), "got: {r:?}");
    }
}
