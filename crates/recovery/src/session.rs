use crate::{FailureKind, Result, checked, digest, fail, now, store_error};
use melissa_local_store::{ArtifactRequest, LocalStore, StoreError};
use melissa_model_gateway::{
    ErrorKind, ToolCall,
    recovery::{RecoveryDirective, RecoveryEvent, RecoveryHook},
    tools::ToolExecution,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub task: String,
    pub run: String,
    pub profile: String,
    pub initial_source: String,
    pub policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    pub source: String,
    pub policy: String,
}
pub type Refresh = Arc<dyn Fn() -> Result<Freshness> + Send + Sync>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub max_repairs: u32,
    pub max_same_failure: u32,
    pub deadline_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Active,
    Repairing,
    Blocked,
    NeedsReconciliation,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRecord {
    pub request: String,
    pub kind: FailureKind,
    pub source: String,
    pub fingerprint: String,
    pub evidence_artifact: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema_version: String,
    pub binding: Binding,
    pub policy: Policy,
    pub source_at_start: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub last_clock_ms: u64,
    pub phase: Phase,
    pub failures: Vec<FailureRecord>,
    pub repeats: BTreeMap<String, u32>,
    pub reason: String,
}
pub struct RecoverySession {
    pub(crate) binding: Binding,
    pub(crate) refresh: Refresh,
    pub(crate) tool_failures: BTreeMap<String, FailureKind>,
}
fn cp(binding: &Binding, n: u64) -> String {
    format!("recovery:{}:{}:{n}", binding.task, binding.run)
}
pub(crate) fn put(
    store: &mut LocalStore,
    task: &str,
    id: &str,
    kind: &str,
    bytes: &[u8],
) -> Result<()> {
    match store.artifact_metadata(task, id) {
        Ok(_) => checked(
            store.get_artifact(task, id).map_err(store_error)? == bytes,
            ErrorKind::Store,
            "recovery artifact identity collision",
        ),
        Err(StoreError::NotFound(_)) => {
            store
                .put_artifact(
                    &ArtifactRequest {
                        artifact_id: id.into(),
                        task_id: task.into(),
                        content_type: "application/json".into(),
                        logical_type: kind.into(),
                        schema_version: "melissa.recovery/v1".into(),
                        retain_until_ms: 0,
                        legal_hold: false,
                    },
                    bytes,
                )
                .map_err(store_error)?;
            Ok(())
        }
        Err(e) => Err(store_error(e)),
    }
}
impl RecoverySession {
    pub fn create(
        store: &mut LocalStore,
        binding: Binding,
        policy: Policy,
        refresh: Refresh,
        tool_failures: BTreeMap<String, FailureKind>,
    ) -> Result<Self> {
        let task = store.journal().task(&binding.task).map_err(store_error)?;
        checked(
            !binding.run.is_empty()
                && binding.run.len() <= 160
                && !binding.run.chars().any(char::is_control)
                && task
                    .contract
                    .selected_profile_ids
                    .contains(&binding.profile)
                && task.contract.input_snapshot_digest == binding.initial_source
                && policy.max_repairs > 0
                && policy.max_repairs <= 4096
                && policy.max_same_failure > 0
                && policy.max_same_failure <= policy.max_repairs
                && policy.deadline_ms > now()?,
            ErrorKind::Invalid,
            "recovery binding/policy outside original task",
        )?;
        let current = refresh()?;
        checked(
            current.policy == binding.policy
                && current.source.starts_with("blake3:")
                && current.source.len() == 71,
            ErrorKind::Authorization,
            "initial recovery source/policy mismatch",
        )?;
        checked(
            matches!(
                store.journal().checkpoint(&cp(&binding, 0), &binding.task),
                Err(StoreError::NotFound(_))
            ),
            ErrorKind::Store,
            "recovery identity already exists or cannot be checked",
        )?;
        let state = State {
            schema_version: "melissa.recovery-state/v1".into(),
            binding: binding.clone(),
            policy,
            source_at_start: current.source,
            sequence: 0,
            previous_digest: None,
            last_clock_ms: now()?,
            phase: Phase::Active,
            failures: vec![],
            repeats: BTreeMap::new(),
            reason: "host-bound recovery session".into(),
        };
        Self::write(store, &state)?;
        Ok(Self {
            binding,
            refresh,
            tool_failures,
        })
    }
    pub fn reopen(
        store: &LocalStore,
        binding: Binding,
        refresh: Refresh,
        tool_failures: BTreeMap<String, FailureKind>,
    ) -> Result<Self> {
        let session = Self {
            binding,
            refresh,
            tool_failures,
        };
        let state = session.state(store)?;
        checked(
            state.binding == session.binding,
            ErrorKind::Authorization,
            "reopened recovery identity differs",
        )?;
        checked(
            (session.refresh)()?.policy == session.binding.policy,
            ErrorKind::Authorization,
            "recovery policy changed",
        )?;
        Ok(session)
    }
    pub fn state(&self, store: &LocalStore) -> Result<State> {
        let mut previous = None;
        let mut latest = None;
        for n in 0..=8192u64 {
            let point = match store
                .journal()
                .checkpoint(&cp(&self.binding, n), &self.binding.task)
            {
                Ok(v) => v,
                Err(StoreError::NotFound(_)) => break,
                Err(e) => return Err(store_error(e)),
            };
            let bytes = store
                .get_artifact(&self.binding.task, &point.artifact_id)
                .map_err(store_error)?;
            let state: State = serde_json::from_slice(&bytes).map_err(store_error)?;
            checked(
                state.schema_version == "melissa.recovery-state/v1"
                    && state.binding == self.binding
                    && state.sequence == n
                    && state.previous_digest == previous
                    && point.data == json!({"recovery_digest":digest(&bytes)}),
                ErrorKind::Store,
                "recovery checkpoint chain mismatch",
            )?;
            previous = Some(digest(&bytes));
            latest = Some(state);
        }
        latest.ok_or_else(|| fail(ErrorKind::Store, "missing recovery checkpoint"))
    }
    fn write(store: &mut LocalStore, state: &State) -> Result<()> {
        let bytes = serde_json::to_vec(state).map_err(store_error)?;
        let h = digest(&bytes);
        let id = format!(
            "recovery-state:{}:{}:{h}",
            state.binding.task, state.binding.run
        );
        put(store, &state.binding.task, &id, "recovery.state", &bytes)?;
        let version = store
            .journal()
            .task(&state.binding.task)
            .map_err(store_error)?
            .record
            .version;
        store
            .journal_mut()
            .append_checkpoint(
                &cp(&state.binding, state.sequence),
                &state.binding.task,
                version,
                &id,
                json!({"recovery_digest":h}),
            )
            .map_err(store_error)?;
        Ok(())
    }
    pub(crate) fn commit(
        &self,
        store: &mut LocalStore,
        old: &State,
        mut next: State,
    ) -> Result<State> {
        checked(
            serde_json::to_vec(&self.state(store)?).map_err(store_error)?
                == serde_json::to_vec(old).map_err(store_error)?,
            ErrorKind::Store,
            "stale recovery revision",
        )?;
        checked(
            now()? >= old.last_clock_ms,
            ErrorKind::Store,
            "recovery clock rollback",
        )?;
        next.sequence = old
            .sequence
            .checked_add(1)
            .ok_or_else(|| fail(ErrorKind::Store, "recovery sequence overflow"))?;
        next.previous_digest = Some(digest(&serde_json::to_vec(old).map_err(store_error)?));
        next.last_clock_ms = now()?;
        Self::write(store, &next)?;
        Ok(next)
    }
    pub fn cancel(&self, store: &mut LocalStore) -> Result<State> {
        let old = self.state(store)?;
        let mut next = old.clone();
        next.phase = Phase::Cancelled;
        next.reason = "host cancellation; never task acceptance".into();
        self.commit(store, &old, next)
    }
    /// Re-open recovery after the exact native operation was resolved. This
    /// neither replays that operation nor rewrites a completed native run.
    pub fn resolve_from_native(&self, store: &mut LocalStore) -> Result<State> {
        let old = self.state(store)?;
        checked(
            old.phase == Phase::NeedsReconciliation,
            ErrorKind::Authorization,
            "recovery has no unknown hold",
        )?;
        let last = old
            .failures
            .last()
            .ok_or_else(|| store_error("missing unknown event"))?;
        let bytes = store
            .get_artifact(&self.binding.task, &last.evidence_artifact)
            .map_err(store_error)?;
        let event: Value = serde_json::from_slice(&bytes).map_err(store_error)?;
        let calls = event["calls"]
            .as_array()
            .ok_or_else(|| store_error("missing calls"))?;
        if calls.is_empty() {
            let request = store
                .journal()
                .model_request(&last.request)
                .map_err(store_error)?;
            let settled = request
                .settlement
                .ok_or_else(|| store_error("unsettled model request"))?;
            checked(
                request.reservation.task_id == self.binding.task
                    && matches!(
                        request.state,
                        melissa_local_store::journal::ModelRequestState::Succeeded
                            | melissa_local_store::journal::ModelRequestState::Failed
                            | melissa_local_store::journal::ModelRequestState::NeverDispatched
                    )
                    && settled.usage.input_tokens.is_some()
                    && settled.usage.output_tokens.is_some()
                    && settled.usage.cost_micro_usd.is_some(),
                ErrorKind::Store,
                "provider outcome/usage remains unknown",
            )?;
        } else {
            for call in calls {
                let id = call["id"]
                    .as_str()
                    .ok_or_else(|| store_error("missing call identity"))?;
                let hash = blake3::hash(id.as_bytes()).to_hex().to_string();
                let inv = format!("model-tool:{}:{}", self.binding.run, &hash[..24]);
                let owned = store.journal().invocation(&inv).map_err(store_error)?;
                checked(
                    owned.task_id == self.binding.task
                        && owned.active_attempt_id.is_none()
                        && matches!(
                            owned.state,
                            melissa_core_contracts::InvocationState::Succeeded
                                | melissa_core_contracts::InvocationState::Failed
                                | melissa_core_contracts::InvocationState::Reconciled
                        ),
                    ErrorKind::Store,
                    "owned operation remains unknown; no replay",
                )?;
            }
        }
        let task = store
            .journal()
            .task(&self.binding.task)
            .map_err(store_error)?;
        let budget = store
            .journal()
            .model_budget(&self.binding.task)
            .map_err(store_error)?;
        checked(
            task.record.unknown_invocation_id.is_none()
                && budget.active_requests == 0
                && budget.unknown_requests == 0
                && budget.unknown_input_requests == 0
                && budget.unknown_output_requests == 0
                && budget.unknown_cost_requests == 0
                && !budget.budget_exceeded,
            ErrorKind::Store,
            "another unresolved task effect/usage remains",
        )?;
        checked(
            (self.refresh)()?.policy == self.binding.policy,
            ErrorKind::Authorization,
            "resolved effect cannot expand policy",
        )?;
        let mut next = old.clone();
        next.phase = Phase::Repairing;
        next.reason =
            "exact native result resolved; previous operation remains consumed and cannot replay"
                .into();
        self.commit(store, &old, next)
    }
    pub fn eligibility(&self, store: &LocalStore) -> Result<()> {
        let state = self.state(store)?;
        checked(
            matches!(state.phase, Phase::Active | Phase::Repairing),
            ErrorKind::Authorization,
            "recovery is stopped or requires reconciliation",
        )?;
        checked(
            now()? <= state.policy.deadline_ms,
            ErrorKind::Timeout,
            "recovery deadline",
        )?;
        let task = store
            .journal()
            .task(&self.binding.task)
            .map_err(store_error)?;
        checked(
            matches!(
                task.record.state,
                melissa_core_contracts::TaskState::Running
                    | melissa_core_contracts::TaskState::Repairing
                    | melissa_core_contracts::TaskState::Verifying
            ),
            ErrorKind::Cancelled,
            "task no longer permits recovery",
        )?;
        let b = store
            .journal()
            .model_budget(&self.binding.task)
            .map_err(store_error)?;
        checked(
            b.active_requests == 0
                && b.unknown_requests == 0
                && b.unknown_input_requests == 0
                && b.unknown_output_requests == 0
                && b.unknown_cost_requests == 0
                && !b.budget_exceeded
                && task.record.unknown_invocation_id.is_none(),
            ErrorKind::Budget,
            "unsettled task effect or usage blocks recovery",
        )?;
        checked(
            (self.refresh)()?.policy == self.binding.policy,
            ErrorKind::Authorization,
            "recovery cannot change policy",
        )
    }
}
impl RecoveryHook for RecoverySession {
    fn binding_digest(&self, store: &LocalStore) -> Result<String> {
        let state = self.state(store)?;
        Ok(digest(&serde_json::to_vec(&json!({"binding":self.binding,"policy":state.policy,"source_at_start":state.source_at_start,"tool_failure_categories":self.tool_failures})).map_err(store_error)?))
    }
    fn success(
        &mut self,
        store: &mut LocalStore,
        event: RecoveryEvent,
    ) -> Result<Option<RecoveryDirective>> {
        checked(
            event.task == self.binding.task && event.run == self.binding.run,
            ErrorKind::Authorization,
            "progress crossed task/run scope",
        )?;
        self.eligibility(store)?;
        let old = self.state(store)?;
        let fresh = (self.refresh)()?;
        let calls:Vec<_>=event.calls.iter().map(|c|json!({"name":c.name,"arguments":melissa_model_gateway::strict_json(&c.arguments).unwrap_or_else(|_|json!({"raw_digest":digest(c.arguments.as_bytes())}))})).collect();
        let fingerprint = format!(
            "success:{}",
            digest(
                &serde_json::to_vec(&json!({"calls":calls,"source":fresh.source}))
                    .map_err(store_error)?
            )
        );
        let mut next = old.clone();
        let n = next.repeats.entry(fingerprint).or_default();
        *n += 1;
        let blocked = *n >= old.policy.max_same_failure;
        if blocked {
            next.phase = Phase::Blocked;
            next.reason = "no_progress: repeated successful call on unchanged source".into();
        }
        self.commit(store, &old, next)?;
        Ok(blocked.then(|| RecoveryDirective {
            continue_run: false,
            feedback: "no_progress: repeated identical successful call without source progress"
                .into(),
        }))
    }
    fn classify_observation(&self, call: &ToolCall, observation: &ToolExecution) -> FailureKind {
        if observation.requires_reconciliation {
            return FailureKind::UnknownEffect;
        }
        // Categories are configured by the trusted adapter host. Arbitrary
        // strings from source files/model/tool stdout do not confer authority.
        self.tool_failures
            .get(&call.name)
            .copied()
            .unwrap_or(FailureKind::ToolFailure)
    }
    fn failure(
        &mut self,
        store: &mut LocalStore,
        event: RecoveryEvent,
    ) -> Result<RecoveryDirective> {
        checked(
            event.task == self.binding.task && event.run == self.binding.run,
            ErrorKind::Authorization,
            "failure crossed task/run scope",
        )?;
        let old = self.state(store)?;
        let current = (self.refresh)()?;
        checked(
            current.policy == self.binding.policy,
            ErrorKind::Authorization,
            "recovery source policy changed",
        )?;
        let normalized:Vec<Value>=event.calls.iter().map(|c|json!({"name":c.name,"arguments":melissa_model_gateway::strict_json(&c.arguments).unwrap_or_else(|_|json!({"raw_digest":digest(c.arguments.as_bytes())}))})).collect();
        let fingerprint = digest(
            &serde_json::to_vec(
                &json!({"kind":event.kind,"source":current.source,"calls":normalized}),
            )
            .map_err(store_error)?,
        );
        let evidence = json!({"task":event.task,"run":event.run,"request":event.request,"kind":event.kind,"calls":event.calls,"diagnostic":event.diagnostic,"evidence":event.evidence,"source":current.source,"task_accepted":false});
        let bytes = serde_json::to_vec(&evidence).map_err(store_error)?;
        let id = format!(
            "recovery-failure:{}:{}:{}",
            self.binding.run,
            old.sequence + 1,
            digest(&bytes)
        );
        put(store, &self.binding.task, &id, "recovery.failure", &bytes)?;
        let mut next = old.clone();
        let repeated = next.repeats.entry(fingerprint.clone()).or_default();
        *repeated += 1;
        let looped = *repeated >= old.policy.max_same_failure;
        next.failures.push(FailureRecord {
            request: event.request,
            kind: event.kind,
            source: current.source,
            fingerprint,
            evidence_artifact: id.clone(),
        });
        let unknown = event.kind == FailureKind::UnknownEffect;
        let denied = event.kind == FailureKind::AuthorityDenied;
        let eligible = self.eligibility(store).is_ok();
        let proceed = eligible
            && !unknown
            && !denied
            && event.kind != FailureKind::NoProgress
            && !looped
            && next.failures.len() < old.policy.max_repairs as usize;
        next.phase = if unknown {
            Phase::NeedsReconciliation
        } else if proceed {
            Phase::Repairing
        } else {
            Phase::Blocked
        };
        next.reason = if looped {
            "no_progress: same source and failed proposal recur"
        } else if unknown {
            "unknown effect: inspect/reconcile, do not replay"
        } else if denied {
            "authority denied; no tool switching to bypass"
        } else if !proceed {
            "host policy/deadline/usage/repair guard"
        } else {
            "known failure: model must repair from actual diagnostic"
        }
        .into();
        let next = self.commit(store, &old, next)?;
        let instruction = match event.kind {
            FailureKind::InvalidArguments => {
                "Read the supplied tool schema and diagnostic. Correct your next proposal; no call in the rejected batch executed. Use new tool-call IDs."
            }
            FailureKind::StalePatch => {
                "Read the current source and version before preparing a new expected-hash patch. Preserve concurrent user edits. Never reuse the stale preimage."
            }
            FailureKind::BuildError => {
                "Inspect the actual compiler/test diagnostic. Repair the source within task scope, then run the relevant checks again. A failed check is not success."
            }
            FailureKind::InvalidOutput => {
                "Produce a new complete candidate under the unchanged output contract. The host did not edit or repair your output."
            }
            FailureKind::ProviderTimeout => {
                "Only a request proven not sent can be retried automatically. Sent/unknown usage requires reconciliation and retains reservation."
            }
            FailureKind::UnknownEffect => {
                "Stop new effectful work. Inspect the exact owned operation and reconcile from evidence. Never blindly replay."
            }
            FailureKind::AuthorityDenied => {
                "Stop this action. A denial grants no alternative route or expanded scope."
            }
            FailureKind::ToolFailure => {
                "Inspect the unchanged tool observation, determine the cause, and propose a different justified next step within existing authority."
            }
            FailureKind::NoProgress => {
                "Stop the repeated action and report the concrete blocker. No success or silent budget reset is permitted."
            }
        };
        Ok(RecoveryDirective{continue_run:proceed,feedback:json!({"status":"recovery_required","kind":event.kind,"diagnostic":event.diagnostic,"instruction":instruction,"continue_run":proceed,"reason":next.reason,"evidence_artifact":id,"task_accepted":false}).to_string()})
    }
}
