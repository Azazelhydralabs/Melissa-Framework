//! Quota/ownership-aware encrypted Journal continuation, shared by native Gateway.
use crate::{Namespace, Result, digest, json, require};
use melissa_core_contracts::{TaskState, design::SkillPin};
use melissa_local_store::{ArtifactRequest, LocalStore, StoreError};
use melissa_model_gateway::{
    ErrorKind, GatewayError,
    continuation::{ContinuationStore, Phase, TurnCheckpoint},
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub namespace: Namespace,
    pub workspace_digest: String,
    pub skill_pins: Vec<SkillPin>,
    pub policy_digest: String,
    pub authorization_ref: String,
    pub cancellation_ref: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    state: TurnCheckpoint,
    freshness: Freshness,
    charged_cost: u64,
    known_requests: u64,
}
pub struct JournalContinuation {
    task: String,
    run: String,
    sequence: u64,
    refresh: Box<dyn Fn() -> Result<Freshness> + Send>,
    cancelled: Arc<AtomicBool>,
}
impl JournalContinuation {
    pub fn new(
        task: String,
        run: String,
        cancelled: Arc<AtomicBool>,
        refresh: Box<dyn Fn() -> Result<Freshness> + Send>,
    ) -> Self {
        Self {
            task,
            run,
            sequence: 0,
            refresh,
            cancelled,
        }
    }
    fn current(&self, store: &LocalStore) -> Result<(Freshness, u64, u64)> {
        require(
            !self.cancelled.load(Ordering::Acquire),
            "continuation cancelled or authority revoked",
        )?;
        let task = store.journal().task(&self.task)?;
        require(
            matches!(
                task.record.state,
                TaskState::Running | TaskState::Repairing | TaskState::Verifying
            ) && task.record.unknown_invocation_id.is_none(),
            "task inactive or requires reconciliation",
        )?;
        let mut latest = std::collections::BTreeMap::new();
        for e in store.journal().events(&self.task)? {
            if let Some(i) = e.invocation {
                latest.insert(i.invocation_id.clone(), i);
            }
        }
        require(
            latest.values().all(|i| i.active_attempt_id.is_none()),
            "active owned invocation blocks checkpoint/resume",
        )?;
        let b = store.journal().model_budget(&self.task)?;
        require(
            b.active_requests == 0 && b.unknown_requests == 0 && !b.budget_exceeded,
            "unsettled model ledger blocks continuation",
        )?;
        let f = (self.refresh)()?;
        f.namespace.validate()?;
        require(
            task.contract
                .authorization_refs
                .contains(&f.authorization_ref),
            "continuation authorization no longer in task",
        )?;
        let n = store.journal().model_requests(&self.task)?.len() as u64;
        Ok((f, b.charged_cost_micro_usd, n))
    }
    fn cp(&self, n: u64) -> String {
        format!("gateway-cp:{}:{n}", self.run)
    }
}
fn gateway(e: crate::Error) -> GatewayError {
    GatewayError::new(ErrorKind::Store, e.to_string())
}
impl ContinuationStore for JournalContinuation {
    fn begin(
        &mut self,
        store: &mut LocalStore,
        binding: &str,
        task: &str,
        run: &str,
    ) -> melissa_model_gateway::Result<Option<TurnCheckpoint>> {
        (|| -> Result<_> {
            require(
                task == self.task && run == self.run,
                "continuation host identity mismatch",
            )?;
            let (fresh, cost, requests) = self.current(store)?;
            match store.artifact_metadata(task, &format!("model-run:{run}:result")) {
                Ok(_) => return Err(crate::Error("terminal run cannot be replayed".into())),
                Err(StoreError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            let mut latest = None;
            loop {
                match store.journal().checkpoint(&self.cp(self.sequence), task) {
                    Ok(c) => {
                        let bytes = store.get_artifact(task, &c.artifact_id)?;
                        require(
                            c.data["digest"].as_str() == Some(digest(&bytes).as_str()),
                            "checkpoint index/content mismatch",
                        )?;
                        latest = Some(json::<Envelope>(&bytes)?);
                        self.sequence += 1;
                    }
                    Err(StoreError::NotFound(_)) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(e) = latest {
                require(
                    e.state.binding_digest == binding
                        && e.freshness == fresh
                        && e.charged_cost == cost
                        && e.known_requests == requests
                        && e.state.phase == Phase::Safe,
                    "stale context, changed budget, pending model/tool or policy mismatch",
                )?;
                let ids: std::collections::BTreeSet<_> = store
                    .journal()
                    .model_requests(task)?
                    .iter()
                    .map(|r| r.reservation.request_id.clone())
                    .collect();
                require(
                    e.state.result.request_ids.iter().all(|id| ids.contains(id))
                        && e.state.result.request_ids.len() == requests as usize,
                    "checkpoint does not cover the complete native model history",
                )?;
                Ok(Some(e.state))
            } else {
                require(
                    requests == 0,
                    "missing continuation for an already used task",
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
        (||->Result<()>{
            let(fresh,cost,requests)=self.current(store)?;
            require(state.result.task_id==self.task&&state.result.run_id==self.run,"checkpoint task mismatch")?;
            let e=Envelope{state:state.clone(),freshness:fresh,charged_cost:cost,known_requests:requests};let bytes=serde_json::to_vec(&e)?;
            let id=self.cp(self.sequence);let artifact=format!("{id}:artifact");
            let meta=store.put_artifact(&ArtifactRequest{artifact_id:artifact.clone(),task_id:self.task.clone(),content_type:"application/json".into(),logical_type:"gateway.native_continuation".into(),schema_version:"melissa.gateway-continuation/v1".into(),retain_until_ms:0,legal_hold:false},&bytes)?;
            let v=store.journal().task(&self.task)?.record.version;
            store.journal_mut().append_checkpoint(&id,&self.task,v,&artifact,serde_json::json!({"digest":digest(&bytes),"phase":state.phase,"content_digest":meta.digest}))?;
            self.sequence+=1;Ok(())
        })().map_err(gateway)
    }
}
