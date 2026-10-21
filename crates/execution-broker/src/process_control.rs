//! A separately authenticated control plane for managed invocations only.
use crate::{
    BrokerError, BrokerResult, PolicyControl,
    control_policy::{ControlTool, ProcessControlRequest, SignedControlPermit},
    policy::{PermitAuthority, PermitRequest, authenticated_digest},
    unix_ms,
};
use melissa_core_contracts::{InvocationState, catalog::Catalog};
use melissa_local_store::{
    ArtifactRequest, LocalStore,
    journal::{ControlAdmission, InvocationRecord},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct ProcessControlService {
    store: LocalStore,
    catalog: Arc<Catalog>,
    authority: Arc<PermitAuthority>,
    policy: PolicyControl,
    resource_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessControlOutcome {
    pub schema_version: String,
    pub permit_id: String,
    pub tool_id: String,
    pub task_id: String,
    pub target: InvocationRecord,
    pub cancellation_requested: bool,
    pub termination_confirmed: bool,
    pub artifact_id: String,
}
impl ProcessControlService {
    pub(crate) fn new(
        store: LocalStore,
        catalog: Arc<Catalog>,
        authority: Arc<PermitAuthority>,
        policy: PolicyControl,
        resource_id: String,
    ) -> Self {
        Self {
            store,
            catalog,
            authority,
            policy,
            resource_id,
        }
    }
    fn target(&self, request: &ProcessControlRequest) -> BrokerResult<InvocationRecord> {
        if request.resource_id != self.resource_id {
            return Err(BrokerError::Denied(
                "control outside this managed resource".into(),
            ));
        }
        let target = self.store.journal().invocation(&request.invocation_id)?;
        let admission = self
            .store
            .journal()
            .managed_execution(&request.invocation_id)?;
        if target.task_id != request.task_id
            || target.generation != request.generation
            || admission.task_id != request.task_id
            || admission.resource_id != request.resource_id
            || admission.generation != request.generation
        {
            return Err(BrokerError::Denied(
                "control target ownership/generation/resource mismatch".into(),
            ));
        }
        Ok(target)
    }
    pub fn issue_permit(
        &self,
        request: ProcessControlRequest,
        permit: PermitRequest,
    ) -> BrokerResult<SignedControlPermit> {
        self.target(&request)?;
        let task = self.store.journal().task(&request.task_id)?;
        let policy = self.policy.snapshot()?;
        Ok(self.authority.issue_control(
            &self.catalog,
            &task.contract,
            request,
            permit,
            &policy,
            unix_ms()?,
        )?)
    }
    pub fn execute(&mut self, signed: &SignedControlPermit) -> BrokerResult<ProcessControlOutcome> {
        let request = &signed.binding.request;
        let target = self.target(request)?;
        let task = self.store.journal().task(&request.task_id)?;
        let policy = self
            .policy
            .state
            .read()
            .map_err(|_| BrokerError::Denied("policy lock poisoned".into()))?;
        let now = unix_ms()?;
        self.authority.verify_control(
            &self.catalog,
            &task.contract,
            signed,
            request,
            &policy,
            now,
        )?;
        let target = self.store.journal_mut().admit_control(&ControlAdmission {
            permit_id: signed.permit.permit_id.clone(),
            nonce: signed.permit.nonce.clone(),
            permit_digest: authenticated_digest(signed)?,
            task_id: request.task_id.clone(),
            principal_id: signed.permit.principal_id.clone(),
            profile_id: signed.binding.profile_id.clone(),
            target_invocation_id: request.invocation_id.clone(),
            generation: request.generation,
            resource_id: request.resource_id.clone(),
            tool_id: request.tool.tool_id().into(),
            arguments_digest: signed.permit.arguments_digest.clone(),
            expected_task_version: task.record.version,
            expected_invocation_version: target.version,
            not_before_unix_ms: signed.permit.not_before_unix_ms,
            expires_at_unix_ms: signed.permit.expires_at_unix_ms,
            consumed_at_unix_ms: now,
        })?;
        drop(policy);
        // Cancel receipt proves durable intent, not that the asynchronous Job
        // watcher has already stopped the target. A fresh inspect confirms it.
        let artifact_id = format!(
            "control:{}:observation",
            blake3::hash(signed.permit.permit_id.as_bytes()).to_hex()
        );
        let cancellation_requested = match self.store.journal().is_cancel_requested(
            &request.task_id,
            &request.invocation_id,
            request.generation,
        ) {
            Ok(value) => request.tool == ControlTool::Cancel || value,
            Err(error) => return Err(BrokerError::AfterDispatch(Box::new(error.into()))),
        };
        let outcome = ProcessControlOutcome {
            schema_version: "melissa.process-control-result/v1".into(),
            permit_id: signed.permit.permit_id.clone(),
            tool_id: request.tool.tool_id().into(),
            task_id: request.task_id.clone(),
            cancellation_requested,
            termination_confirmed: matches!(
                target.state,
                InvocationState::Succeeded | InvocationState::Failed | InvocationState::Cancelled
            ),
            target,
            artifact_id: artifact_id.clone(),
        };
        let persist = (|| -> BrokerResult<()> {
            self.store.put_artifact(
                &ArtifactRequest {
                    artifact_id: artifact_id.clone(),
                    task_id: request.task_id.clone(),
                    content_type: "application/json".into(),
                    logical_type: "process.control_observation".into(),
                    schema_version: outcome.schema_version.clone(),
                    retain_until_ms: 0,
                    legal_hold: false,
                },
                &serde_json::to_vec(&outcome)?,
            )?;
            self.store
                .pin_artifact(&request.task_id, &artifact_id, &signed.permit.permit_id)?;
            Ok(())
        })();
        persist.map_err(|error| BrokerError::AfterDispatch(Box::new(error)))?;
        Ok(outcome)
    }
    pub fn stored_receipt(&self, permit_id: &str) -> BrokerResult<ControlAdmission> {
        let receipt = self.store.journal().control_admission(permit_id)?;
        if receipt.resource_id != self.resource_id {
            return Err(BrokerError::Denied(
                "control receipt outside resource".into(),
            ));
        }
        Ok(receipt)
    }
}

pub fn parse_control_request(bytes: &[u8]) -> BrokerResult<ProcessControlRequest> {
    melissa_core_contracts::json::parse_contract(bytes, 16 * 1024)
        .map_err(|error| BrokerError::Invalid(error.to_string()))
}
pub fn parse_control_permit(bytes: &[u8]) -> BrokerResult<SignedControlPermit> {
    melissa_core_contracts::json::parse_contract(bytes, 64 * 1024)
        .map_err(|error| BrokerError::Invalid(error.to_string()))
}
