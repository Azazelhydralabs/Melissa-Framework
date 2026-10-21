//! Safe-boundary restart for native Gateway history. Pending effects block
//! replay even if a controller disappeared before receiving its receipt.
use crate::{
    Binding, Result, checked, digest,
    session::{Refresh, put},
    store_error,
};
use melissa_local_store::{LocalStore, StoreError};
use melissa_model_gateway::{
    ErrorKind,
    continuation::{ContinuationStore, Phase, TurnCheckpoint},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    binding: Binding,
    native: TurnCheckpoint,
    source: String,
    policy: String,
    cost: u64,
    input: u64,
    output: u64,
}
pub struct RecoveryContinuation {
    binding: Binding,
    refresh: Refresh,
    sequence: u64,
}
impl RecoveryContinuation {
    pub fn new(binding: Binding, refresh: Refresh) -> Self {
        Self {
            binding,
            refresh,
            sequence: 0,
        }
    }
    fn id(&self, n: u64) -> String {
        format!(
            "recovery-turn:{}:{}:{n}",
            self.binding.task, self.binding.run
        )
    }
    fn settled(&self, store: &LocalStore) -> Result<(u64, u64, u64)> {
        let task = store
            .journal()
            .task(&self.binding.task)
            .map_err(store_error)?;
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
            ErrorKind::Store,
            "pending/unknown usage/effect blocks native recovery resume",
        )?;
        let mut invocations = std::collections::BTreeMap::new();
        for event in store
            .journal()
            .events(&self.binding.task)
            .map_err(store_error)?
        {
            if let Some(i) = event.invocation {
                invocations.insert(i.invocation_id.clone(), i);
            }
        }
        checked(
            invocations.values().all(|i| i.active_attempt_id.is_none()),
            ErrorKind::Store,
            "active worker blocks recovery resume",
        )?;
        Ok((
            b.known_cost_micro_usd,
            b.known_input_tokens,
            b.known_output_tokens,
        ))
    }
}
impl ContinuationStore for RecoveryContinuation {
    fn begin(
        &mut self,
        store: &mut LocalStore,
        binding: &str,
        task: &str,
        run: &str,
    ) -> Result<Option<TurnCheckpoint>> {
        checked(
            task == self.binding.task && run == self.binding.run,
            ErrorKind::Authorization,
            "native recovery task/run mismatch",
        )?;
        // Cleanup is automatic on restart, but cannot resolve program output or
        // provider billing. settled() still blocks any unresolved task effect.
        crate::sweep::recover_on_restart(store, task)?;
        let totals = self.settled(store)?;
        let fresh = (self.refresh)()?;
        checked(
            fresh.policy == self.binding.policy,
            ErrorKind::Authorization,
            "native recovery policy changed",
        )?;
        let mut latest = None;
        for n in 0..1_000_000u64 {
            let point = match store.journal().checkpoint(&self.id(n), task) {
                Ok(v) => v,
                Err(StoreError::NotFound(_)) => {
                    self.sequence = n;
                    break;
                }
                Err(e) => return Err(store_error(e)),
            };
            let bytes = store
                .get_artifact(task, &point.artifact_id)
                .map_err(store_error)?;
            checked(
                point.data == json!({"native_recovery_digest":digest(&bytes)}),
                ErrorKind::Store,
                "native recovery checkpoint digest differs",
            )?;
            let e: Envelope = serde_json::from_slice(&bytes).map_err(store_error)?;
            checked(
                e.binding == self.binding
                    && e.native.binding_digest == binding
                    && e.native.result.task_id == task
                    && e.native.result.run_id == run
                    && !e.native.result.task_accepted,
                ErrorKind::Store,
                "native recovery history binding differs",
            )?;
            latest = Some(e);
        }
        if let Some(e) = latest {
            checked(
                e.native.phase == Phase::Safe,
                ErrorKind::Store,
                "pending inference/tools require inspection, never automatic replay",
            )?;
            checked(
                e.source == fresh.source
                    && e.policy == fresh.policy
                    && totals.0 >= e.cost
                    && totals.1 >= e.input
                    && totals.2 >= e.output,
                ErrorKind::Store,
                "resume source/policy/accounting changed",
            )?;
            let prefix = format!("model:{}:", self.binding.run);
            let ids: std::collections::BTreeSet<_> = store
                .journal()
                .model_requests(task)
                .map_err(store_error)?
                .into_iter()
                .filter(|r| r.reservation.request_id.starts_with(&prefix))
                .map(|r| r.reservation.request_id)
                .collect();
            checked(
                ids == e.native.result.request_ids.iter().cloned().collect(),
                ErrorKind::Store,
                "run history omits a native request",
            )?;
            Ok(Some(e.native))
        } else {
            Ok(None)
        }
    }
    fn publish(&mut self, store: &mut LocalStore, state: &TurnCheckpoint) -> Result<()> {
        checked(
            state.result.task_id == self.binding.task
                && state.result.run_id == self.binding.run
                && !state.result.task_accepted,
            ErrorKind::Authorization,
            "native checkpoint scope differs",
        )?;
        let fresh = (self.refresh)()?;
        checked(
            fresh.policy == self.binding.policy,
            ErrorKind::Authorization,
            "policy changed while publishing native recovery",
        )?;
        let b = store
            .journal()
            .model_budget(&self.binding.task)
            .map_err(store_error)?;
        let bytes = serde_json::to_vec(&Envelope {
            binding: self.binding.clone(),
            native: state.clone(),
            source: fresh.source,
            policy: fresh.policy,
            cost: b.known_cost_micro_usd,
            input: b.known_input_tokens,
            output: b.known_output_tokens,
        })
        .map_err(store_error)?;
        let id = format!(
            "recovery-native:{}:{}:{}",
            self.binding.task,
            self.binding.run,
            digest(&bytes)
        );
        put(
            store,
            &self.binding.task,
            &id,
            "recovery.native_history",
            &bytes,
        )?;
        let version = store
            .journal()
            .task(&self.binding.task)
            .map_err(store_error)?
            .record
            .version;
        store
            .journal_mut()
            .append_checkpoint(
                &self.id(self.sequence),
                &self.binding.task,
                version,
                &id,
                json!({"native_recovery_digest":digest(&bytes)}),
            )
            .map_err(store_error)?;
        self.sequence += 1;
        Ok(())
    }
}
