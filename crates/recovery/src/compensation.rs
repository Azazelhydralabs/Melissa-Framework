//! A compensation is a separate, exactly authorized operation. It never erases
//! the forward operation, and a lost compensation result is never replayed.
use crate::{
    Binding, Result, checked, digest, fail,
    session::{Refresh, put},
    store_error,
};
use melissa_local_store::{LocalStore, StoreError};
use melissa_model_gateway::{
    ErrorKind, ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationPlan {
    pub id: String,
    pub binding: Binding,
    pub authorization: String,
    pub forward_invocation: String,
    pub forward_artifact: String,
    pub forward_digest: String,
    pub before_source: String,
    pub expected_after_source: String,
    pub call: ToolCall,
    pub context: CompensationContext,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationContext {
    pub request: String,
    pub invocation: String,
    pub attempt: String,
    pub generation: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Planned,
    Compensating,
    Compensated,
    Failed,
    Cancelled,
    NeedsReconciliation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationState {
    pub plan: CompensationPlan,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub phase: Phase,
    pub receipt_artifact: Option<String>,
    pub after_source: Option<String>,
}
fn cp(plan: &CompensationPlan, n: u64) -> String {
    format!("compensation:{}:{}:{n}", plan.binding.task, plan.id)
}
pub struct Compensation {
    plan: CompensationPlan,
    refresh: Refresh,
}
impl Compensation {
    pub fn create(
        store: &mut LocalStore,
        plan: CompensationPlan,
        refresh: Refresh,
    ) -> Result<Self> {
        checked(
            !plan.id.is_empty() && plan.id.len() <= 160 && !plan.id.chars().any(char::is_control),
            ErrorKind::Invalid,
            "invalid compensation identity",
        )?;
        let task = store
            .journal()
            .task(&plan.binding.task)
            .map_err(store_error)?;
        let forward = store
            .journal()
            .invocation(&plan.forward_invocation)
            .map_err(store_error)?;
        checked(
            task.contract
                .authorization_refs
                .contains(&plan.authorization)
                && task
                    .contract
                    .selected_profile_ids
                    .contains(&plan.binding.profile)
                && forward.task_id == plan.binding.task
                && matches!(
                    forward.state,
                    melissa_core_contracts::InvocationState::Succeeded
                        | melissa_core_contracts::InvocationState::Failed
                )
                && forward.active_attempt_id.is_none()
                && task.record.unknown_invocation_id.is_none(),
            ErrorKind::Authorization,
            "compensation needs separate host authority and known owned forward effect",
        )?;
        let bytes = store
            .get_artifact(&plan.binding.task, &plan.forward_artifact)
            .map_err(store_error)?;
        checked(
            digest(&bytes) == plan.forward_digest,
            ErrorKind::Store,
            "forward evidence digest changed",
        )?;
        // Only an authentic task-owned broker observation may identify the
        // operation to compensate; a source/model-authored reference is insufficient.
        let observation: serde_json::Value = serde_json::from_slice(&bytes).map_err(store_error)?;
        checked(
            observation["task_id"] == plan.binding.task
                && observation["invocation_id"] == plan.forward_invocation,
            ErrorKind::Authorization,
            "forward observation belongs to another operation",
        )?;
        let fresh = refresh()?;
        checked(
            fresh.source == plan.before_source && fresh.policy == plan.binding.policy,
            ErrorKind::Authorization,
            "compensation source/policy changed",
        )?;
        checked(
            matches!(
                store
                    .journal()
                    .checkpoint(&cp(&plan, 0), &plan.binding.task),
                Err(StoreError::NotFound(_))
            ),
            ErrorKind::Store,
            "compensation already exists or cannot be checked",
        )?;
        Self::write(
            store,
            &CompensationState {
                plan: plan.clone(),
                sequence: 0,
                previous_digest: None,
                phase: Phase::Planned,
                receipt_artifact: None,
                after_source: None,
            },
        )?;
        Ok(Self { plan, refresh })
    }
    pub fn reopen(store: &LocalStore, plan: CompensationPlan, refresh: Refresh) -> Result<Self> {
        let owned = Self { plan, refresh };
        owned.state(store)?;
        Ok(owned)
    }
    fn write(store: &mut LocalStore, s: &CompensationState) -> Result<()> {
        let bytes = serde_json::to_vec(s).map_err(store_error)?;
        let id = format!(
            "compensation-state:{}:{}:{}",
            s.plan.binding.task,
            s.plan.id,
            digest(&bytes)
        );
        put(
            store,
            &s.plan.binding.task,
            &id,
            "recovery.compensation",
            &bytes,
        )?;
        let version = store
            .journal()
            .task(&s.plan.binding.task)
            .map_err(store_error)?
            .record
            .version;
        store
            .journal_mut()
            .append_checkpoint(
                &cp(&s.plan, s.sequence),
                &s.plan.binding.task,
                version,
                &id,
                json!({"compensation_digest":digest(&bytes)}),
            )
            .map_err(store_error)?;
        Ok(())
    }
    pub fn state(&self, store: &LocalStore) -> Result<CompensationState> {
        let mut last = None;
        let mut previous = None;
        for n in 0..8u64 {
            let c = match store
                .journal()
                .checkpoint(&cp(&self.plan, n), &self.plan.binding.task)
            {
                Ok(c) => c,
                Err(StoreError::NotFound(_)) => break,
                Err(e) => return Err(store_error(e)),
            };
            let bytes = store
                .get_artifact(&self.plan.binding.task, &c.artifact_id)
                .map_err(store_error)?;
            let state: CompensationState = serde_json::from_slice(&bytes).map_err(store_error)?;
            checked(
                serde_json::to_value(&state.plan).map_err(store_error)?
                    == serde_json::to_value(&self.plan).map_err(store_error)?
                    && state.sequence == n
                    && state.previous_digest == previous
                    && c.data == json!({"compensation_digest":digest(&bytes)}),
                ErrorKind::Store,
                "compensation chain/plan mismatch",
            )?;
            previous = Some(digest(&bytes));
            last = Some(state);
        }
        last.ok_or_else(|| fail(ErrorKind::Store, "missing compensation state"))
    }
    fn advance(
        &self,
        store: &mut LocalStore,
        old: &CompensationState,
        mut next: CompensationState,
    ) -> Result<CompensationState> {
        checked(
            serde_json::to_vec(&self.state(store)?).map_err(store_error)?
                == serde_json::to_vec(old).map_err(store_error)?,
            ErrorKind::Store,
            "stale compensation state",
        )?;
        next.sequence = old.sequence + 1;
        next.previous_digest = Some(digest(&serde_json::to_vec(old).map_err(store_error)?));
        Self::write(store, &next)?;
        Ok(next)
    }
    pub async fn execute(
        &self,
        store: &mut LocalStore,
        dispatcher: &mut dyn ToolDispatcher,
        cancelled: Arc<AtomicBool>,
    ) -> Result<CompensationState> {
        let old = self.state(store)?;
        checked(
            old.phase == Phase::Planned,
            ErrorKind::Authorization,
            "compensation is single-use; pending/failed/completed operations cannot replay",
        )?;
        let fresh = (self.refresh)()?;
        checked(
            fresh.source == self.plan.before_source && fresh.policy == self.plan.binding.policy,
            ErrorKind::Authorization,
            "compensation preimage/policy changed",
        )?;
        let task = store
            .journal()
            .task(&self.plan.binding.task)
            .map_err(store_error)?;
        let budget = store
            .journal()
            .model_budget(&self.plan.binding.task)
            .map_err(store_error)?;
        checked(
            task.contract
                .authorization_refs
                .contains(&self.plan.authorization)
                && task.record.unknown_invocation_id.is_none()
                && budget.active_requests == 0
                && budget.unknown_requests == 0
                && !budget.budget_exceeded,
            ErrorKind::Authorization,
            "compensation authority/effect/usage hold",
        )?;
        let definition = dispatcher
            .definitions()
            .into_iter()
            .find(|d| d.definition.name == self.plan.call.name)
            .ok_or_else(|| fail(ErrorKind::Authorization, "compensation tool is not granted"))?;
        melissa_model_gateway::schema::validate_output(
            &definition.definition.parameters,
            &self.plan.call.arguments,
        )?;
        dispatcher.validate_call(&self.plan.call)?;
        let mut next = old.clone();
        if cancelled.load(Ordering::Acquire) {
            next.phase = Phase::Cancelled;
            return self.advance(store, &old, next);
        }
        next.phase = Phase::Compensating;
        let pending = self.advance(store, &old, next)?; // durable one-use admission before effect
        let c = &self.plan.context;
        let context = ToolContext {
            task_id: self.plan.binding.task.clone(),
            profile_id: self.plan.binding.profile.clone(),
            run_id: self.plan.binding.run.clone(),
            request_id: c.request.clone(),
            invocation_id: c.invocation.clone(),
            attempt_id: c.attempt.clone(),
            generation: c.generation,
        };
        let result = dispatcher
            .execute(self.plan.call.clone(), context, cancelled)
            .await;
        let mut next = pending.clone();
        match result {
            Ok(observation) => {
                let source = (self.refresh)()?.source;
                next.phase = if observation.requires_reconciliation {
                    Phase::NeedsReconciliation
                } else if observation.cancelled {
                    Phase::Cancelled
                } else if observation.success && source == self.plan.expected_after_source {
                    Phase::Compensated
                } else {
                    Phase::Failed
                };
                next.after_source = Some(source);
                let bytes=serde_json::to_vec(&json!({"content":observation.content,"success":observation.success,"cancelled":observation.cancelled,"requires_reconciliation":observation.requires_reconciliation,"artifact_refs":observation.artifact_refs,"task_accepted":false})).map_err(store_error)?;
                let id = format!("compensation-receipt:{}:{}", self.plan.id, digest(&bytes));
                put(
                    store,
                    &self.plan.binding.task,
                    &id,
                    "recovery.compensation_receipt",
                    &bytes,
                )?;
                next.receipt_artifact = Some(id);
            }
            Err(_) => next.phase = Phase::NeedsReconciliation,
        }
        self.advance(store, &pending, next)
    }
    /// Adopt the native result of THIS compensation after lost delivery. The
    /// operation is not run again; failed/unknown outcomes never become success.
    pub fn reconcile_native(&self, store: &mut LocalStore) -> Result<CompensationState> {
        let old = self.state(store)?;
        checked(
            matches!(old.phase, Phase::Compensating | Phase::NeedsReconciliation),
            ErrorKind::Authorization,
            "compensation has no pending result to reconcile",
        )?;
        let native = store
            .journal()
            .invocation(&self.plan.context.invocation)
            .map_err(store_error)?;
        checked(
            native.task_id == self.plan.binding.task
                && native.generation == self.plan.context.generation
                && native.active_attempt_id.is_none()
                && matches!(
                    native.state,
                    melissa_core_contracts::InvocationState::Succeeded
                        | melissa_core_contracts::InvocationState::Failed
                ),
            ErrorKind::Store,
            "compensation native effect remains unresolved",
        )?;
        let receipt = native
            .result_artifact_id
            .ok_or_else(|| store_error("native compensation receipt missing"))?;
        store
            .get_artifact(&self.plan.binding.task, &receipt)
            .map_err(store_error)?;
        let fresh = (self.refresh)()?;
        checked(
            fresh.policy == self.plan.binding.policy,
            ErrorKind::Authorization,
            "compensation policy changed",
        )?;
        let mut next = old.clone();
        next.receipt_artifact = Some(receipt);
        next.after_source = Some(fresh.source.clone());
        next.phase = if native.state == melissa_core_contracts::InvocationState::Succeeded
            && fresh.source == self.plan.expected_after_source
        {
            Phase::Compensated
        } else {
            Phase::Failed
        };
        self.advance(store, &old, next)
    }
}
