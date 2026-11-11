//! Terminal face policy, applied only to the CLI engine's requests.
//!
//! A terminal asks for text/plain when the target contract offers it and the caller
//! supplies no `as`, after parsing and before cache lookup/resolution.
//! The underlying kernel, HTTP door, and nested endpoint requests keep their defaults.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgRef, Body, Capability, Error, Provenance, Representation, Request, Scope, SpaceEntry,
    Tracer, Verb,
};
use ikigai_resolve::{CacheStatus, Resolver, RunContext};

pub struct TerminalResolver<R>(pub R);

// Use the same Meta request as the engine's argument routing. The underlying
// resolver owns contract caching and invalidation; this adapter adds no second cache.
fn contract_request(request: &Request) -> Option<Request> {
    (request.verb == Verb::Source && !request.args.contains_key("as")).then(|| {
        Request::new(Verb::Meta, request.target.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()))
    })
}

fn terminal_request(
    mut request: Request,
    description: Option<ikigai_core::Description>,
) -> Request {
    let action = description.and_then(|d| {
        d.action_specs()
            .into_iter()
            .find(|a| a.verb == Verb::Source)
    });
    if contract_request(&request).is_some() {
        let face = action.and_then(|a| {
            let faces = a
                .inputs
                .iter()
                .find(|i| i.name == "as")
                .filter(|i| !i.one_of.is_empty())
                .map(|i| &i.one_of)
                .unwrap_or(&a.outputs);
            faces
                .iter()
                .find(|face| {
                    face.split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("text/plain")
                })
                .cloned()
        });
        if let Some(face) = face {
            request
                .args
                .insert("as".into(), ArgRef::Inline(face.into_bytes()));
        }
    }
    request
}

// A description-shaped body in another representation is not the JSON contract
// we requested. Fail closed before parsing, including on the streamed body path.
fn json_description(repr: Representation) -> Option<ikigai_core::Description> {
    if !repr
        .repr_type
        .media_type
        .eq_ignore_ascii_case("application/json")
    {
        return None;
    }
    serde_json::from_slice(&repr.bytes).ok()
}

fn prepare(
    request: Request,
    fetch: impl FnOnce(Request) -> Result<(Representation, CacheStatus), Error>,
) -> Request {
    let description = contract_request(&request)
        .and_then(|meta| fetch(meta).ok())
        .and_then(|(repr, _)| json_description(repr));
    terminal_request(request, description)
}

async fn prepare_async<
    F: std::future::Future<Output = Result<(Representation, CacheStatus), Error>>,
>(
    request: Request,
    fetch: impl FnOnce(Request) -> F,
) -> Request {
    let description = match contract_request(&request) {
        Some(meta) => fetch(meta)
            .await
            .ok()
            .and_then(|(repr, _)| json_description(repr)),
        None => None,
    };
    terminal_request(request, description)
}

#[async_trait]
impl<R: Resolver> Resolver for TerminalResolver<R> {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        self.0.issue(prepare(request, |meta| self.0.issue(meta)))
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0.issue_as(
            prepare(request, |meta| self.0.issue_as(meta, capability)),
            capability,
        )
    }

    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        let request = prepare(request, |meta| {
            self.0.issue_as_in_run(meta, capability, run)
        });
        self.0.issue_as_in_run(request, capability, run)
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        let request = prepare_async(request, |meta| self.0.issue_as_async(meta, capability)).await;
        self.0.issue_as_async(request, capability).await
    }

    async fn issue_body_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation<Body>, CacheStatus), Error> {
        let description = if let Some(meta) = contract_request(&request) {
            match self.0.issue_body_as_in_run(meta, capability, run).await {
                Ok((repr, _))
                    if repr
                        .repr_type
                        .media_type
                        .eq_ignore_ascii_case("application/json") =>
                {
                    repr.bytes
                        .collect(
                            usize::try_from(ikigai_core::DEFAULT_STREAM_MEMORY)
                                .unwrap_or(usize::MAX),
                        )
                        .await
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                }
                Ok(_) | Err(_) => None,
            }
        } else {
            None
        };
        let request = terminal_request(request, description);
        self.0.issue_body_as_in_run(request, capability, run).await
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        let request = prepare_async(request, |meta| self.0.issue_as_async(meta, capability)).await;
        self.0
            .issue_as_async_with_incoming(request, capability, incoming)
            .await
    }

    async fn issue_as_async_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
    ) -> Result<(Representation, CacheStatus), Error> {
        let request = prepare_async(request, |meta| {
            self.0
                .issue_as_async_in(meta, capability, None, scope.clone())
        })
        .await;
        self.0
            .issue_as_async_in(request, capability, incoming, scope)
            .await
    }

    async fn issue_attached_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
        attach: Option<(String, Body)>,
    ) -> Result<(Representation, CacheStatus), Error> {
        let request = prepare_async(request, |meta| {
            self.0
                .issue_as_async_in(meta, capability, None, scope.clone())
        })
        .await;
        self.0
            .issue_attached_in(request, capability, incoming, scope, attach)
            .await
    }

    async fn issue_body_attached_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
        attach: Option<(String, Body)>,
    ) -> Result<(Representation<Body>, CacheStatus), Error> {
        let request = prepare_async(request, |meta| {
            self.0
                .issue_as_async_in(meta, capability, None, scope.clone())
        })
        .await;
        self.0
            .issue_body_attached_in(request, capability, incoming, scope, attach)
            .await
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        self.0.set_tracer(tracer);
    }

    fn clear_tracer(&self) {
        self.0.clear_tracer();
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        self.is_cached_in(request, capability, &Scope::default())
    }

    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        if contract_request(request).is_none() {
            return self.0.is_cached_in(request, capability, scope);
        }
        // Resolver's cache probe is synchronous, including when the engine calls it
        // inside eval_async. Fetch on a scoped thread to avoid nesting its executor.
        // Only the explicit `cache` command takes this path, not ordinary reads.
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    let request =
                        futures::executor::block_on(prepare_async(request.clone(), |meta| {
                            self.0
                                .issue_as_async_in(meta, capability, None, scope.clone())
                        }));
                    self.0.is_cached_in(&request, capability, scope)
                })
                .join()
                .expect("terminal contract cache probe")
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.0.entries()
    }

    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        self.0.try_entries()
    }

    fn transport(&self) -> String {
        self.0.transport()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::Iri;

    struct JsonRenderer;
    impl ikigai_core::MetaRenderer for JsonRenderer {
        fn render(
            &self,
            description: &ikigai_core::Description,
            _: &ikigai_core::ReprType,
        ) -> Result<Representation, Error> {
            Ok(Representation::new(
                ikigai_core::ReprType::new("application/json"),
                serde_json::to_vec(description).unwrap(),
            ))
        }
    }

    fn page(description: ikigai_core::Description) -> ikigai_core::FnEndpoint {
        ikigai_core::FnEndpoint::new("page", |inv: &ikigai_core::Invocation<'_>| {
            let face = inv.inline_str("as").unwrap_or("text/html");
            Ok(
                Representation::new(ikigai_core::ReprType::new(face), face.as_bytes().to_vec())
                    .cacheable(),
            )
        })
        .with_description(description)
    }

    fn page_kernel(description: ikigai_core::Description) -> ikigai_core::Kernel {
        ikigai_core::Kernel::with_meta_renderer(
            Arc::new(
                ikigai_core::EndpointSpace::new()
                    .bind(ikigai_core::Exact::new("urn:test:page"), page(description)),
            ),
            Arc::new(JsonRenderer),
        )
    }

    fn output(engine: &ikigai_engine::Engine, command: &str) -> String {
        match engine.eval(command) {
            ikigai_engine::Action::Output(entry) => entry.result.unwrap(),
            _ => panic!("expected output for {command}"),
        }
    }

    struct TypedJsonRenderer(&'static str);

    impl ikigai_core::MetaRenderer for TypedJsonRenderer {
        fn render(
            &self,
            description: &ikigai_core::Description,
            _: &ikigai_core::ReprType,
        ) -> Result<Representation, Error> {
            Ok(Representation::new(
                ikigai_core::ReprType::new(self.0).with_param("charset", "utf-8"),
                serde_json::to_vec(description).unwrap(),
            ))
        }
    }

    #[test]
    fn denied_absent_and_malformed_contracts_leave_the_request_unchanged() {
        use futures::executor::block_on;
        use ikigai_core::ReprType;

        let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
        let answers = [
            Err(Error::Denied("contract denied".into())),
            Err(Error::Unresolved(request.target.clone())),
            Ok((
                Representation::new(ReprType::new("application/json"), b"not JSON".to_vec()),
                CacheStatus::Miss,
            )),
            Ok((
                Representation::new(ReprType::new("application/json"), b"[]".to_vec()),
                CacheStatus::Miss,
            )),
        ];
        for answer in answers {
            // Each form runs separately because Error is not Clone.
            let prepared = match answer {
                Ok((repr, status)) => {
                    let sync = prepare(request.clone(), |meta| {
                        assert_eq!(Some(meta), contract_request(&request));
                        Ok((repr.clone(), status))
                    });
                    assert_eq!(sync, request);
                    block_on(prepare_async(request.clone(), |_| async {
                        Ok((repr, status))
                    }))
                }
                Err(error) => prepare(request.clone(), |_| Err(error)),
            };
            assert_eq!(prepared, request);
        }
    }

    #[test]
    fn non_json_meta_answers_do_not_select_a_terminal_face() {
        use futures::executor::block_on;
        use ikigai_core::{Description, EndpointSpace, Exact, Kernel};

        for (media_type, expected) in [
            ("text/plain", "text/html"),
            ("text/html", "text/html"),
            ("application/octet-stream", "text/html"),
            ("application/json", "text/plain"),
            ("Application/JSON", "text/plain"),
        ] {
            let resolver = TerminalResolver(Kernel::with_meta_renderer(
                Arc::new(
                    EndpointSpace::new().bind(
                        Exact::new("urn:test:page"),
                        page(
                            Description::new("page")
                                .verb(Verb::Source)
                                .output("text/html")
                                .output("text/plain"),
                        ),
                    ),
                ),
                Arc::new(TypedJsonRenderer(media_type)),
            ));
            let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
            let capability = Capability::root();
            let run = RunContext::default();
            let sync = resolver.issue(request.clone()).unwrap().0.bytes;
            let asynchronous = block_on(resolver.issue_as_async_in(
                request.clone(),
                &capability,
                None,
                Scope::default(),
            ))
            .unwrap()
            .0
            .bytes;
            let body = block_on(async {
                resolver
                    .issue_body_as_in_run(request, &capability, &run)
                    .await
                    .unwrap()
                    .0
                    .bytes
                    .collect(1024)
                    .await
                    .unwrap()
            });
            for (path, bytes) in [
                ("sync", sync.as_slice()),
                ("async", asynchronous.as_slice()),
                ("body", body.as_ref()),
            ] {
                assert_eq!(bytes, expected.as_bytes(), "{media_type}: {path}");
            }
        }
    }

    #[test]
    fn the_selected_face_preserves_its_declared_parameters_and_spelling() {
        use ikigai_core::{ArgSpec, Description};

        for face in ["text/plain;charset=utf-8", "Text/Plain"] {
            let resolver = TerminalResolver(page_kernel(
                Description::new("page")
                    .verb(Verb::Source)
                    .input(ArgSpec::new("as").optional().one_of(["text/html", face]))
                    .output("text/html"),
            ));
            let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
            assert_eq!(resolver.issue(request).unwrap().0.bytes, face.as_bytes());
        }
    }

    // Manual audit reproductions: these need an engine/Resolver seam change, not
    // a second contract cache or command-string parsing in the CLI adapter.
    #[test]
    #[ignore = "audit #3417: engine routing and terminal policy fetch Meta separately"]
    fn audit_routing_and_face_selection_fetch_one_contract() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountMeta {
            kernel: ikigai_core::Kernel,
            calls: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Resolver for CountMeta {
            fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
                if request.verb == Verb::Meta {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                }
                Resolver::issue(&self.kernel, request)
            }
            async fn issue_as_async(
                &self,
                request: Request,
                capability: &Capability,
            ) -> Result<(Representation, CacheStatus), Error> {
                if request.verb == Verb::Meta {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                }
                self.kernel.issue_as_async(request, capability).await
            }
            fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
                self.kernel.is_cached(request, capability)
            }
            fn entries(&self) -> Option<Vec<SpaceEntry>> {
                self.kernel.entries()
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let engine = ikigai_engine::Engine::new(TerminalResolver(CountMeta {
            kernel: page_kernel(
                ikigai_core::Description::new("page")
                    .verb(Verb::Source)
                    .input(ikigai_core::ArgSpec::new("name").optional())
                    .output("text/html")
                    .output("text/plain"),
            ),
            calls: calls.clone(),
        }));
        assert_eq!(
            output(&engine, "source urn:test:page name=example"),
            "text/plain"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[ignore = "audit #3417: by-reference pipe bypasses terminal face selection"]
    fn audit_reference_and_value_pipes_receive_the_same_face() {
        use ikigai_core::{
            ArgSpec, AsyncFnEndpoint, Description, EndpointSpace, Exact, FnEndpoint, Kernel,
            ReprType,
        };

        let description = || {
            Description::new("copy")
                .verb(Verb::Source)
                .input(ArgSpec::new("content"))
        };
        let copy_bytes = FnEndpoint::new("copy-bytes", |inv| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                inv.inline_arg("content")?.to_vec(),
            ))
        })
        .with_description(description());
        let copy_reference = AsyncFnEndpoint::new("copy-reference", |inv| {
            Box::pin(async move {
                let body = inv.content_body("content").await?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    inv.collect(body).await?.to_vec(),
                ))
            })
        })
        .with_description(
            description()
                .transreptor(["text/html", "text/plain"], ["text/plain"])
                .incremental(),
        );
        let engine = ikigai_engine::Engine::new(TerminalResolver(Kernel::with_meta_renderer(
            Arc::new(
                EndpointSpace::new()
                    .bind(
                        Exact::new("urn:test:page"),
                        page(
                            Description::new("page")
                                .verb(Verb::Source)
                                .output("text/html")
                                .output("text/plain"),
                        ),
                    )
                    .bind(Exact::new("urn:test:copy-bytes"), copy_bytes)
                    .bind(Exact::new("urn:test:copy-reference"), copy_reference),
            ),
            Arc::new(JsonRenderer),
        )));
        let by_value = output(&engine, "source urn:test:page | urn:test:copy-bytes");
        let by_reference = output(&engine, "source urn:test:page | urn:test:copy-reference");
        assert_eq!(by_value, by_reference);
    }

    #[test]
    fn rebinding_invalidates_the_contract_and_keeps_terminal_cache_identity_separate() {
        use ikigai_core::{Description, EndpointSpace, Exact, Kernel, Resolution, Space};
        use std::sync::Mutex;

        struct Rebindable(Mutex<Arc<dyn Space>>);
        impl Space for Rebindable {
            fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
                self.0.lock().unwrap().resolve(request, scope)
            }
        }
        let binding = |text| {
            let mut description = Description::new("page")
                .verb(Verb::Source)
                .output("text/html");
            if text {
                description = description.output("text/plain");
            }
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:test:page"), page(description)))
                as Arc<dyn Space>
        };
        let space = Arc::new(Rebindable(Mutex::new(binding(true))));
        let kernel = Arc::new(Kernel::with_meta_renderer(
            space.clone(),
            Arc::new(JsonRenderer),
        ));
        let resolver = TerminalResolver(kernel.clone());
        let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
        assert_eq!(kernel.issue(request.clone()).unwrap().0.bytes, b"text/html");
        assert_eq!(
            resolver.issue(request.clone()).unwrap().0.bytes,
            b"text/plain"
        );
        assert_eq!(kernel.issue(request.clone()).unwrap().0.bytes, b"text/html");
        for (text, expected) in [(false, "text/html"), (true, "text/plain")] {
            *space.0.lock().unwrap() = binding(text);
            kernel.bindings_changed();
            assert_eq!(
                resolver.issue(request.clone()).unwrap().0.bytes,
                expected.as_bytes()
            );
            assert_eq!(kernel.issue(request.clone()).unwrap().0.bytes, b"text/html");
        }
    }

    #[test]
    fn another_html_family_uses_its_declared_text_face() {
        let kernel = Arc::new(page_kernel(
            ikigai_core::Description::new("page")
                .verb(Verb::Source)
                .output("text/html")
                .output("text/plain"),
        ));
        let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
        let resolver = Arc::new(TerminalResolver(Arc::clone(&kernel)));
        assert_eq!(resolver.issue(request).unwrap().0.bytes, b"text/plain");
        let engine = ikigai_engine::Engine::new(resolver);
        assert_eq!(output(&engine, "source urn:test:page"), "text/plain");
        assert_eq!(
            output(&engine, "source urn:test:page as=text/html"),
            "text/html"
        );
        assert_eq!(output(&engine, "cache urn:test:page"), "cached");
        assert_eq!(
            output(&ikigai_engine::Engine::new(kernel), "source urn:test:page"),
            "text/html"
        );
    }

    #[test]
    fn a_resource_without_a_text_face_keeps_its_default() {
        let engine = ikigai_engine::Engine::new(TerminalResolver(page_kernel(
            ikigai_core::Description::new("page")
                .verb(Verb::Source)
                .output("text/html"),
        )));
        assert_eq!(output(&engine, "source urn:test:page"), "text/html");
        assert_eq!(output(&engine, "cache urn:test:page"), "cached");
    }

    #[test]
    fn the_as_inputs_one_of_list_takes_precedence_over_outputs() {
        use ikigai_core::{ArgSpec, Description};
        for (faces, expected) in [
            (vec!["text/html"], "text/html"),
            (vec!["text/html", "text/plain"], "text/plain"),
        ] {
            let engine = ikigai_engine::Engine::new(TerminalResolver(page_kernel(
                Description::new("page")
                    .verb(Verb::Source)
                    .output("text/html")
                    .output("text/plain")
                    .input(
                        ArgSpec::new("as")
                            .optional()
                            .one_of(faces)
                            .default_value("text/html"),
                    ),
            )));
            assert_eq!(output(&engine, "source urn:test:page"), expected);
        }
    }

    #[test]
    fn the_contract_and_cache_probe_use_the_requests_scope_and_capability() {
        use ikigai_core::{Description, EndpointSpace, Exact};
        let kernel = Arc::new(page_kernel(
            Description::new("root")
                .verb(Verb::Source)
                .output("text/html"),
        ));
        let scope = Scope::default().with_named(
            Iri::parse("urn:test:corridor").unwrap(),
            Arc::new(
                EndpointSpace::new().bind(
                    Exact::new("urn:test:page"),
                    page(
                        Description::new("scoped")
                            .verb(Verb::Source)
                            .output("text/html")
                            .output("text/plain"),
                    ),
                ),
            ),
        );
        let resolver = Arc::new(TerminalResolver(kernel));
        let capability = Capability::scoped(["urn:cap:test"]);
        let engine =
            ikigai_engine::Engine::with_identity(Arc::clone(&resolver), capability.clone())
                .with_scope(scope);
        assert_eq!(output(&engine, "cache urn:test:page"), "not cached");
        assert_eq!(output(&engine, "source urn:test:page"), "text/plain");
        assert_eq!(output(&engine, "cache urn:test:page"), "cached");
        let root = ikigai_engine::Engine::with_identity(resolver, capability);
        assert_eq!(output(&root, "cache urn:test:page"), "not cached");
        assert_eq!(output(&root, "source urn:test:page"), "text/html");
    }

    #[test]
    fn an_unreadable_contract_keeps_the_original_request() {
        let resolver = TerminalResolver(ikigai_core::Kernel::new(Arc::new(
            ikigai_core::EndpointSpace::new().bind(
                ikigai_core::Exact::new("urn:test:page"),
                page(
                    ikigai_core::Description::new("page")
                        .verb(Verb::Source)
                        .output("text/plain"),
                ),
            ),
        )));
        let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
        assert_eq!(resolver.issue(request).unwrap().0.bytes, b"text/html");
    }

    #[test]
    fn explicit_faces_and_non_source_requests_are_preserved() {
        for (verb, target) in [
            (Verb::Meta, "urn:runbook:basics"),
            (Verb::Sink, "urn:runbook:basics"),
            (Verb::Delete, "urn:runbook:basics"),
        ] {
            let request = Request::new(verb, Iri::parse(target).unwrap());
            assert_eq!(
                terminal_request(
                    request.clone(),
                    Some(
                        ikigai_core::Description::new("page")
                            .verb(Verb::Source)
                            .output("text/plain")
                    )
                ),
                request
            );
        }
        for face in ["text/html", "application/json", "", "unsupported/type"] {
            let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap())
                .with_arg("as", ArgRef::Inline(face.as_bytes().to_vec()));
            assert_eq!(
                terminal_request(
                    request.clone(),
                    Some(
                        ikigai_core::Description::new("page")
                            .verb(Verb::Source)
                            .output("text/plain")
                    )
                ),
                request
            );
        }
    }

    #[test]
    fn cache_probes_use_the_same_face_as_resolution() {
        use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Kernel, ReprType};

        let kernel = Kernel::with_meta_renderer(
            Arc::new(
                EndpointSpace::new().bind(
                    Exact::new("urn:test:page"),
                    FnEndpoint::new("page", |inv: &ikigai_core::Invocation<'_>| {
                        assert_eq!(inv.inline_str("as").unwrap(), "text/plain");
                        Ok(
                            Representation::new(ReprType::new("text/plain"), b"page".to_vec())
                                .cacheable(),
                        )
                    })
                    .with_description(
                        ikigai_core::Description::new("page")
                            .verb(Verb::Source)
                            .output("text/plain"),
                    ),
                ),
            ),
            Arc::new(JsonRenderer),
        );
        let resolver = TerminalResolver(kernel);
        let request = Request::new(Verb::Source, Iri::parse("urn:test:page").unwrap());
        let cap = Capability::root();
        assert!(!resolver.is_cached(&request, &cap));
        resolver.issue_as(request.clone(), &cap).unwrap();
        assert!(resolver.is_cached(&request, &cap));
        assert!(resolver.is_cached_in(&request, &cap, &Scope::default()));
        assert!(!resolver.0.is_cached(&request, &cap));
    }
}
