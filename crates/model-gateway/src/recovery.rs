//! Optional trusted-host recovery observation. Feedback never grants tool authority.
use crate::{Result, ToolCall, tools::ToolExecution};
use melissa_local_store::LocalStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    InvalidArguments,
    StalePatch,
    BuildError,
    ToolFailure,
    InvalidOutput,
    ProviderTimeout,
    AuthorityDenied,
    UnknownEffect,
    NoProgress,
}
#[derive(Clone)]
pub struct RecoveryEvent {
    pub task: String,
    pub run: String,
    pub request: String,
    pub kind: FailureKind,
    pub calls: Vec<ToolCall>,
    pub diagnostic: String,
    pub evidence: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct RecoveryDirective {
    pub continue_run: bool,
    pub feedback: String,
}
/// Implementations own durable classification/no-progress state. A stop cannot
/// be overridden by the model. All original broker checks still execute.
pub trait RecoveryHook: Send {
    fn binding_digest(&self, store: &LocalStore) -> Result<String>;
    fn failure(
        &mut self,
        store: &mut LocalStore,
        event: RecoveryEvent,
    ) -> Result<RecoveryDirective>;
    fn classify_observation(&self, call: &ToolCall, observation: &ToolExecution) -> FailureKind;
    fn success(
        &mut self,
        _store: &mut LocalStore,
        _event: RecoveryEvent,
    ) -> Result<Option<RecoveryDirective>> {
        Ok(None)
    }
}
