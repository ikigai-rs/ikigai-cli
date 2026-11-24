//! The org-directory file jail has its own endpoint identity, so a declared
//! arrangement can distinguish it from the workspace's `file` endpoint.

use std::path::PathBuf;

use ikigai_core::{Body, Description, Endpoint, Invocation, Representation, Result};

pub(super) struct OrgFileEndpoint(ikigai_fs::FileEndpoint);

impl OrgFileEndpoint {
    pub(super) fn new(root: PathBuf) -> Self {
        Self(ikigai_fs::FileEndpoint::new(root))
    }
}

#[async_trait::async_trait]
impl Endpoint for OrgFileEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        self.0.invoke(inv).await
    }

    async fn invoke_body(&self, inv: &Invocation<'_>) -> Result<Representation<Body>> {
        self.0.invoke_body(inv).await
    }

    fn name(&self) -> &str {
        "orgfile"
    }

    fn describe(&self) -> Description {
        let mut description = self.0.describe();
        description.id = self.name().to_string();
        description
    }
}
