//! Inspect durable outcomes before considering retry. A supplied idempotency
//! string is never evidence that an external effect did or did not occur.
use crate::{Result, checked, store_error};
use melissa_core_contracts::InvocationState;
use melissa_local_store::LocalStore;
use melissa_model_gateway::ErrorKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetryDecision {
    ReuseStoredResult { artifact: String },
    ReobserveReadOnly,
    FreshHostProposalRequired,
    ReconciliationRequired,
    ReconciledDoNotReplay,
}
pub fn inspect_retry(store: &LocalStore, task: &str, invocation: &str) -> Result<RetryDecision> {
    let native = store
        .journal()
        .invocation(invocation)
        .map_err(store_error)?;
    checked(
        native.task_id == task,
        ErrorKind::Authorization,
        "retry inspection outside task",
    )?;
    match native.state {
        InvocationState::Succeeded => {
            let artifact = native
                .result_artifact_id
                .ok_or_else(|| store_error("completed operation lacks receipt"))?;
            store.get_artifact(task, &artifact).map_err(store_error)?;
            Ok(RetryDecision::ReuseStoredResult { artifact })
        }
        InvocationState::OutcomeUnknown | InvocationState::NeedsReconciliation => {
            Ok(RetryDecision::ReconciliationRequired)
        }
        InvocationState::Reconciled => Ok(RetryDecision::ReconciledDoNotReplay),
        InvocationState::Failed
            if matches!(
                native.tool_id.as_str(),
                "fs.read" | "fs.list" | "fs.hash" | "fs.search"
            ) =>
        {
            Ok(RetryDecision::ReobserveReadOnly)
        }
        _ => Ok(RetryDecision::FreshHostProposalRequired),
    }
}
