//! Per-run continuation over a SHARED native task ledger. The CODE-07 hook
//! deliberately keeps its single-run task contract unchanged. This adapter
//! authenticates own run IDs and settled monotonic known accounting while
//! allowing other admitted nodes to charge the same root task.
use crate::{
    Kind, Result, digest, error,
    gate::{SharedScheduler, lock},
    require,
    scheduler::WorkPacket,
};
use melissa_local_store::{ArtifactRequest, LocalStore, StoreError};
use melissa_model_gateway::{
    ErrorKind, GatewayError,
    continuation::{ContinuationStore, Phase, TurnCheckpoint},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    state: TurnCheckpoint,
    handoff_digest: String,
    known_cost: u64,
    known_input: u64,
    known_output: u64,
}
pub struct WorkflowContinuation {
    owner: SharedScheduler,
    packet: WorkPacket,
    sequence: u64,
}
fn gateway(e: crate::Error) -> GatewayError {
    GatewayError::new(ErrorKind::Store, e.to_string())
}
impl WorkflowContinuation {
    pub fn new(owner: SharedScheduler, packet: WorkPacket) -> Self {
        Self {
            owner,
            packet,
            sequence: 0,
        }
    }
    fn cp(&self, n: u64) -> String {
        format!("workflow-turn:{}:{n}", self.packet.lease.run)
    }
    fn current(&self, store: &LocalStore) -> Result<(u64, u64, u64, BTreeSet<String>)> {
        lock(&self.owner)?.check(&self.packet.lease)?;
        let budget = store
            .journal()
            .model_budget(&self.packet.parent_task.task_id)?;
        require(
            budget.unknown_requests == 0 && !budget.budget_exceeded,
            Kind::Uncertain,
            "unknown root usage blocks continuation",
        )?;
        let prefix = format!("model:{}:", self.packet.lease.run);
        let own = store
            .journal()
            .model_requests(&self.packet.parent_task.task_id)?
            .into_iter()
            .filter(|r| r.reservation.request_id.starts_with(&prefix))
            .collect::<Vec<_>>();
        require(
            own.iter().all(|r| {
                !matches!(
                    r.state,
                    melissa_local_store::journal::ModelRequestState::Reserved
                        | melissa_local_store::journal::ModelRequestState::Dispatched
                        | melissa_local_store::journal::ModelRequestState::OutcomeUnknown
                )
            }),
            Kind::Uncertain,
            "own model request is unsettled",
        )?;
        let mut invocations = std::collections::BTreeMap::new();
        let tool_prefix = format!("model-tool:{}:", self.packet.lease.run);
        for event in store.journal().events(&self.packet.parent_task.task_id)? {
            if let Some(i) = event.invocation
                && i.invocation_id.starts_with(&tool_prefix)
            {
                invocations.insert(i.invocation_id.clone(), i);
            }
        }
        require(
            invocations.values().all(|i| i.active_attempt_id.is_none()),
            Kind::Uncertain,
            "own native tool effect is active",
        )?;
        Ok((
            budget.known_cost_micro_usd,
            budget.known_input_tokens,
            budget.known_output_tokens,
            own.into_iter().map(|r| r.reservation.request_id).collect(),
        ))
    }
}
impl ContinuationStore for WorkflowContinuation {
    fn begin(
        &mut self,
        store: &mut LocalStore,
        binding: &str,
        task: &str,
        run: &str,
    ) -> melissa_model_gateway::Result<Option<TurnCheckpoint>> {
        (|| -> Result<_> {
            require(
                task == self.packet.parent_task.task_id && run == self.packet.lease.run,
                Kind::Authority,
                "continuation task/run mismatch",
            )?;
            let (cost, input, output, ids) = self.current(store)?;
            match store.artifact_metadata(task, &format!("model-run:{run}:result")) {
                Ok(_) => return Err(error(Kind::Conflict, "terminal run cannot be replayed")),
                Err(StoreError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            let mut last = None;
            loop {
                match store.journal().checkpoint(&self.cp(self.sequence), task) {
                    Ok(cp) => {
                        let bytes = store.get_artifact(task, &cp.artifact_id)?;
                        require(
                            cp.data["digest"] == digest(&bytes),
                            Kind::Store,
                            "continuation index/content mismatch",
                        )?;
                        last = Some(serde_json::from_slice::<Envelope>(&bytes)?);
                        self.sequence += 1;
                    }
                    Err(StoreError::NotFound(_)) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(last) = last {
                let own_ids = last
                    .state
                    .result
                    .request_ids
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                require(
                    last.state.binding_digest == binding
                        && last.state.phase == Phase::Safe
                        && last.handoff_digest == digest(&serde_json::to_vec(&self.packet)?)
                        && own_ids == ids
                        && cost >= last.known_cost
                        && input >= last.known_input
                        && output >= last.known_output,
                    Kind::Stale,
                    "pending/stale/incomplete run history or accounting rollback",
                )?;
                Ok(Some(last.state))
            } else {
                require(
                    ids.is_empty(),
                    Kind::Stale,
                    "missing checkpoint for an already used run",
                )?;
                Ok(None)
            }
        })()
        .map_err(gateway)
    }
    fn publish(
        &mut self,
        store: &mut LocalStore,
        state: &TurnCheckpoint,
    ) -> melissa_model_gateway::Result<()> {
        (|| -> Result<_> {
            let (cost, input, output, ids) = self.current(store)?;
            require(
                state.result.task_id == self.packet.parent_task.task_id
                    && state.result.run_id == self.packet.lease.run
                    && state
                        .result
                        .request_ids
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        == ids,
                Kind::Store,
                "checkpoint does not cover own native request history",
            )?;
            let e = Envelope {
                state: state.clone(),
                handoff_digest: digest(&serde_json::to_vec(&self.packet)?),
                known_cost: cost,
                known_input: input,
                known_output: output,
            };
            let bytes = serde_json::to_vec(&e)?;
            let id = self.cp(self.sequence);
            let artifact = format!("{id}:artifact");
            let task = &self.packet.parent_task.task_id;
            store.put_artifact(
                &ArtifactRequest {
                    artifact_id: artifact.clone(),
                    task_id: task.clone(),
                    content_type: "application/json".into(),
                    logical_type: "workflow.native-continuation".into(),
                    schema_version: "melissa.workflow-continuation/v1".into(),
                    retain_until_ms: 0,
                    legal_hold: false,
                },
                &bytes,
            )?;
            let version = store.journal().task(task)?.record.version;
            store.append_checkpoint(
                &id,
                task,
                version,
                &artifact,
                json!({"digest":digest(&bytes),"phase":state.phase}),
            )?;
            self.sequence += 1;
            Ok(())
        })()
        .map_err(gateway)
    }
}
