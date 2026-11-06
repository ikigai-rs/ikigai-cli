//! The embedded REPL's resolution boundary.
//!
//! The engine's tracer hooks belong to this session, never to the shared kernel:
//! scheduled jobs and other sessions must not record into a command's trace.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ikigai_core::{
    Body, BodyIssue, Capability, Error, Expiry, Kernel, Provenance, Representation, Request, Scope,
    SpaceEntry, Tracer,
};
use ikigai_resolve::{CacheStatus, Resolver, RunContext};

pub struct LocalResolver {
    kernel: Arc<Kernel>,
    tracer: Mutex<Option<Arc<dyn Tracer>>>,
}

impl LocalResolver {
    pub fn new(kernel: Arc<Kernel>) -> Self {
        Self {
            kernel,
            tracer: Mutex::new(None),
        }
    }
}

#[async_trait]
impl Resolver for LocalResolver {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        self.kernel.issue(request)
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.kernel.issue_as(request, capability)
    }

    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.kernel.issue_as_in_run(request, capability, run)
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.kernel.issue_as_async(request, capability).await
    }

    async fn issue_body_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation<Body>, CacheStatus), Error> {
        self.kernel
            .issue_body_as_in_run(request, capability, run)
            .await
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.kernel
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
        let tracer = self.tracer.lock().expect("session tracer").clone();
        let Some(tracer) = tracer else {
            return self
                .kernel
                .issue_as_async_in(request, capability, incoming, scope)
                .await;
        };
        // The trace command comes through this method. BodyIssue carries its tracer
        // through the invocation's descendants, including work on other threads,
        // without installing a process-wide observer. Keep the chain, upstream
        // provenance, and capability identical to an ordinary resolution.
        let was_cached = self.kernel.is_cached_in(&request, capability, &scope);
        let mut issue = BodyIssue::new().in_scope(scope).traced(tracer);
        if let Some(incoming) = incoming {
            issue = issue.with_incoming(incoming);
        }
        let representation = self.kernel.issue_with(request, capability, issue).await?;
        let status = if representation.expiry == Expiry::Always {
            CacheStatus::Uncacheable
        } else if was_cached {
            CacheStatus::Hit
        } else {
            CacheStatus::Miss
        };
        Ok((representation, status))
    }

    async fn issue_attached_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
        attach: Option<(String, Body)>,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.kernel
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
        self.kernel
            .issue_body_attached_in(request, capability, incoming, scope, attach)
            .await
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        *self.tracer.lock().expect("session tracer") = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer.lock().expect("session tracer") = None;
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        self.kernel.is_cached(request, capability)
    }

    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        self.kernel.is_cached_in(request, capability, scope)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.kernel.entries()
    }

    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        self.kernel.try_entries()
    }

    fn transport(&self) -> String {
        "embedded · in-process · trace includes only this request's chain".to_string()
    }
}

#[cfg(test)]
mod tests {
    use ikigai_core::{
        AsyncFnEndpoint, EndpointSpace, Exact, FnEndpoint, Iri, Kernel, ReprType, Representation,
        Request, Verb,
    };
    use ikigai_engine::{Action, Engine};
    use ikigai_resolve::Resolver;
    use std::sync::{Arc, Barrier};

    #[test]
    fn traced_requests_keep_cache_status_and_failure_events() {
        use ikigai_core::{Error, Expiry};
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(
                    Exact::new("urn:test:cached"),
                    FnEndpoint::new("cached", |_| {
                        Ok(
                            Representation::new(ReprType::new("text/plain"), b"ok".to_vec())
                                .with_expiry(Expiry::Never),
                        )
                    }),
                )
                .bind(
                    Exact::new("urn:test:failed"),
                    FnEndpoint::new("failed", |_| {
                        Err(Error::Endpoint("intentional failure".into()))
                    }),
                ),
        )));
        let engine = Engine::new(super::LocalResolver::new(kernel));
        let eval = |command| match engine.eval(command) {
            Action::Output(entry) => entry.result.unwrap(),
            _ => panic!("expected output"),
        };
        let first = eval("trace urn:test:cached");
        assert!(first.contains("· computed ·"), "{first}");
        let cached = eval("trace urn:test:cached");
        assert!(cached.contains("· cached ·"), "{cached}");
        let failed = eval("trace urn:test:failed");
        assert!(failed.contains("· failed ·"), "{failed}");
        assert!(failed.contains("intentional failure"), "{failed}");
        let after = eval("trace urn:test:cached");
        assert!(after.contains("· cached ·"), "{after}");
        assert!(!after.contains("urn:test:failed"), "{after}");
    }

    #[test]
    fn session_tracers_are_independent_and_leave_the_kernel_observer_alone() {
        use futures::executor::block_on;
        use ikigai_core::{Capability, Scope};
        use ikigai_resolve::SpanCollector;

        let answer = || {
            FnEndpoint::new("answer", |_| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            })
        };
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:first"), answer())
                .bind(Exact::new("urn:test:second"), answer())
                .bind(Exact::new("urn:time:now"), answer()),
        )));
        let observer = Arc::new(SpanCollector::default());
        kernel.set_tracer(observer.clone());
        let first = super::LocalResolver::new(kernel.clone());
        let second = super::LocalResolver::new(kernel.clone());
        let first_trace = Arc::new(SpanCollector::default());
        let second_trace = Arc::new(SpanCollector::default());
        first.set_tracer(first_trace.clone());
        second.set_tracer(second_trace.clone());
        let request = |target| Request::new(Verb::Source, Iri::parse(target).unwrap());
        block_on(first.issue_as_async_in(
            request("urn:test:first"),
            &Capability::root(),
            None,
            Scope::empty(),
        ))
        .unwrap();
        first.clear_tracer();
        block_on(second.issue_as_async_in(
            request("urn:test:second"),
            &Capability::root(),
            None,
            Scope::empty(),
        ))
        .unwrap();
        second.clear_tracer();
        kernel.issue(request("urn:time:now")).unwrap();
        let targets = |collector: &SpanCollector| {
            collector
                .take()
                .into_iter()
                .map(|event| event.target)
                .collect::<Vec<_>>()
        };
        assert_eq!(targets(&first_trace), ["urn:test:first"]);
        assert_eq!(targets(&second_trace), ["urn:test:second"]);
        assert_eq!(targets(&observer), ["urn:time:now"]);
    }

    #[test]
    fn a_trace_excludes_a_clock_request_on_another_thread() {
        // Rendezvous inside the traced endpoint: the background request completes
        // while the trace is open, without depending on a one-second timer or timing luck.
        let entered = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));
        let root_entered = entered.clone();
        let root_done = done.clone();
        let root = AsyncFnEndpoint::new("root", move |inv| {
            let entered = root_entered.clone();
            let done = root_done.clone();
            Box::pin(async move {
                entered.wait();
                done.wait();
                std::thread::scope(|threads| {
                    threads
                        .spawn(|| {
                            futures::executor::block_on(inv.issue(Request::new(
                                Verb::Source,
                                Iri::parse("urn:test:child").unwrap(),
                            )))
                        })
                        .join()
                        .unwrap()
                })
            })
        });
        let answer = || {
            FnEndpoint::new("answer", |_| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            })
        };
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:root"), root)
                .bind(Exact::new("urn:test:child"), answer())
                .bind(Exact::new("urn:time:now"), answer()),
        )));
        let background_kernel = kernel.clone();
        let background = std::thread::spawn(move || {
            entered.wait();
            let result = background_kernel.issue(Request::new(
                Verb::Source,
                Iri::parse("urn:time:now").unwrap(),
            ));
            done.wait();
            result.unwrap();
        });
        let engine = Engine::new(super::LocalResolver::new(kernel));
        let output = match engine.eval("trace urn:test:root") {
            Action::Output(entry) => entry.result.unwrap(),
            _ => panic!("expected trace output"),
        };
        background.join().unwrap();
        assert!(output.contains("urn:test:root"), "{output}");
        assert!(output.contains("urn:test:child"), "{output}");
        assert!(!output.contains("urn:time:now"), "{output}");
        assert!(
            output.contains("trace includes only this request's chain"),
            "{output}"
        );
    }
}
