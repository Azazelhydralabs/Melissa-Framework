//! An adapter for task-scoped services with single-writer derived state (C07).
//! Share one gate per root task. Reopen AFTER queue admission, so another role's
//! checkpoint is read before mutation. Native model IO remains concurrent.
//! Factories must be read-only preparations; authority is checked again by the
//! real dispatcher. This does not retry effects or waive native CAS conflicts.
use melissa_model_gateway::{
    ErrorKind, GatewayError, Result, ToolCall,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub type SharedToolGate = Arc<tokio::sync::Mutex<()>>;
pub type ReloadFactory = Arc<dyn Fn() -> Result<Box<dyn ToolDispatcher>> + Send + Sync>;
pub struct ReloadingDispatcher {
    task: String,
    profile: String,
    gate: SharedToolGate,
    factory: ReloadFactory,
    definitions: Vec<BoundTool>,
    fingerprint: Vec<u8>,
}
fn fingerprint(definitions: &[BoundTool]) -> Result<Vec<u8>> {
    serde_json::to_vec(
        &definitions
            .iter()
            .map(|d| serde_json::json!({"canonical_id":d.canonical_id,"definition":d.definition}))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| GatewayError::invalid("dispatcher definition serialization failed"))
}
impl ReloadingDispatcher {
    pub fn new(
        task: String,
        profile: String,
        gate: SharedToolGate,
        factory: ReloadFactory,
    ) -> Result<Self> {
        let definitions = factory()?.definitions();
        let fingerprint = fingerprint(&definitions)?;
        Ok(Self {
            task,
            profile,
            gate,
            factory,
            definitions,
            fingerprint,
        })
    }
    fn fresh(&self) -> Result<Box<dyn ToolDispatcher>> {
        let next = (self.factory)()?;
        if fingerprint(&next.definitions())? != self.fingerprint {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "reloaded native tools changed after prompt admission",
            ));
        }
        Ok(next)
    }
}
impl ToolDispatcher for ReloadingDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        self.definitions.clone()
    }
    fn validate_call(&self, call: &ToolCall) -> Result<()> {
        self.fresh()?.validate_call(call)
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            if ctx.task_id != self.task || ctx.profile_id != self.profile {
                return Err(GatewayError::new(
                    ErrorKind::Authorization,
                    "shared service belongs to another root/profile",
                ));
            }
            let gate = self.gate.clone();
            let _guard = loop {
                if cancel.load(Ordering::Acquire) {
                    return Err(GatewayError::new(
                        ErrorKind::Cancelled,
                        "queued service cancelled before execution",
                    ));
                }
                tokio::select! {g=gate.lock()=>break g,_=tokio::time::sleep(Duration::from_millis(10))=>{}}
            };
            if cancel.load(Ordering::Acquire) {
                return Err(GatewayError::new(
                    ErrorKind::Cancelled,
                    "service cancelled before preparation",
                ));
            }
            let mut next = self.fresh()?;
            next.validate_call(&call)?;
            // No retry on an error: dispatch may have produced an effect.
            next.execute(call, ctx, cancel).await
        })
    }
}
