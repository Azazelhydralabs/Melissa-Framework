//! Durable, encrypted, task-owned CAS/checkpoint admission. Unique checkpoint
//! sequence keys fence concurrent schedulers before any lease is returned.
//! Abandoned publication artifacts do not consume a checkpoint identity.
use crate::{
    Kind, Result, digest, error, now,
    plan::{Node, Plan, conflicts, identifier},
    require,
};
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreError,
    journal::{ModelBudgetSnapshot, ModelRequestState},
};
use melissa_model_gateway::{
    agent_loop::{RunResult, RunStatus},
    schema,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub workspace_digest: String,
    pub policy_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pending,
    Leased,
    Candidate,
    Failed,
    NeedsReconciliation,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub task: String,
    pub plan_digest: String,
    pub revision: u64,
    pub node: String,
    pub generation: u64,
    pub worker: String,
    pub run: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub phase: Phase,
    pub generation: u64,
    pub lease: Option<Lease>,
    pub output: Option<Value>,
    pub native_run_ref: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema_version: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub plan: Plan,
    pub slots: BTreeMap<String, Slot>,
    pub cancel_requested: bool,
    pub cancellation_settled: bool,
    pub no_progress: u32,
    pub last_clock_ms: u64,
    pub started_at_ms: u64,
    pub deadline_ms: u64,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPacket {
    pub schema_version: String,
    pub parent_task: TaskContractV1,
    pub node: Node,
    pub lease: Lease,
    pub bound_inputs: BTreeMap<String, Value>,
    pub dependency_run_refs: BTreeMap<String, String>,
    pub shared_budget: ModelBudgetSnapshot,
    pub input_trust: String,
    pub completion_authority: String,
}
pub type Refresh = Arc<dyn Fn() -> Result<Freshness> + Send + Sync>;
pub struct Scheduler {
    store: LocalStore,
    task: String,
    workflow: String,
    refresh: Refresh,
    cancelled: Arc<AtomicBool>,
}
fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| error(Kind::Store, "non-UTF8 owned workflow record"))?;
    Ok(serde_json::from_value(melissa_model_gateway::strict_json(
        text,
    )?)?)
}
fn cp(task: &str, workflow: &str, n: u64) -> String {
    format!("workflow:{task}:{workflow}:checkpoint:{n}")
}
fn idle(store: &LocalStore, task: &str) -> Result<()> {
    let b = store.journal().model_budget(task)?;
    require(
        b.active_requests == 0 && b.unknown_requests == 0,
        Kind::Uncertain,
        "active/unknown provider effects retain workflow ownership",
    )?;
    let mut invocations = BTreeMap::new();
    for event in store.journal().events(task)? {
        if let Some(i) = event.invocation {
            invocations.insert(i.invocation_id.clone(), i);
        }
    }
    require(
        invocations.values().all(|i| i.active_attempt_id.is_none())
            && store
                .journal()
                .task(task)?
                .record
                .unknown_invocation_id
                .is_none(),
        Kind::Uncertain,
        "active/unknown worker effects retain workflow ownership",
    )
}
impl Scheduler {
    pub fn create(
        mut store: LocalStore,
        plan: Plan,
        catalog: &Catalog,
        refresh: Refresh,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let parent = store.journal().task(&plan.task)?;
        plan.validate(&parent.contract, catalog)?;
        require(
            plan.revision == 1 && plan.workspace_digest == parent.contract.input_snapshot_digest,
            Kind::Stale,
            "initial plan must bind exact parent input snapshot",
        )?;
        let started = now()?;
        let deadline = started
            .checked_add(parent.contract.limits.max_wall_time_ms)
            .ok_or_else(|| error(Kind::Invalid, "root deadline overflow"))?;
        let initial = State {
            schema_version: "melissa.workflow-state/v1".into(),
            sequence: 0,
            previous_digest: None,
            slots: plan
                .nodes
                .iter()
                .map(|n| {
                    (
                        n.id.clone(),
                        Slot {
                            phase: Phase::Pending,
                            generation: 0,
                            lease: None,
                            output: None,
                            native_run_ref: None,
                        },
                    )
                })
                .collect(),
            plan: plan.clone(),
            cancel_requested: false,
            cancellation_settled: false,
            no_progress: 0,
            last_clock_ms: started,
            started_at_ms: started,
            deadline_ms: deadline,
            reason: "host-validated initial plan".into(),
        };
        require(
            matches!(
                store
                    .journal()
                    .checkpoint(&cp(&plan.task, &plan.id, 0), &plan.task),
                Err(StoreError::NotFound(_))
            ),
            Kind::Conflict,
            "workflow identity already consumed or unavailable",
        )?;
        let owner = Self {
            store: store.connect()?,
            task: plan.task.clone(),
            workflow: plan.id.clone(),
            refresh,
            cancelled,
        };
        owner.fresh(&initial)?;
        Self::write(&mut store, &initial)?;
        Ok(Self { store, ..owner })
    }
    pub fn open(
        store: LocalStore,
        task: String,
        workflow: String,
        refresh: Refresh,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        require(
            identifier(&workflow),
            Kind::Invalid,
            "invalid workflow identity",
        )?;
        let scheduler = Self {
            store,
            task,
            workflow,
            refresh,
            cancelled,
        };
        let state = scheduler.state()?;
        if state.cancel_requested
            || state
                .slots
                .values()
                .any(|v| v.phase == Phase::NeedsReconciliation)
        {
            scheduler.cancelled.store(true, Ordering::Release);
        }
        Ok(scheduler)
    }
    pub fn store(&self) -> &LocalStore {
        &self.store
    }
    pub fn flag(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn task_id(&self) -> &str {
        &self.task
    }
    pub fn state(&self) -> Result<State> {
        let mut latest = None;
        let mut previous = None;
        for n in 0..1_000_000u64 {
            let checkpoint = match self
                .store
                .journal()
                .checkpoint(&cp(&self.task, &self.workflow, n), &self.task)
            {
                Ok(v) => v,
                Err(StoreError::NotFound(_)) => break,
                Err(e) => return Err(e.into()),
            };
            let bytes = self
                .store
                .get_artifact(&self.task, &checkpoint.artifact_id)?;
            let s: State = parse(&bytes)?;
            require(
                s.schema_version == "melissa.workflow-state/v1"
                    && s.sequence == n
                    && s.previous_digest == previous
                    && s.plan.task == self.task
                    && s.plan.id == self.workflow,
                Kind::Store,
                "workflow checkpoint chain mismatch",
            )?;
            require(
                checkpoint.data == json!({"workflow_digest":digest(&bytes)}),
                Kind::Store,
                "workflow checkpoint artifact binding mismatch",
            )?;
            previous = Some(digest(&bytes));
            latest = Some(s);
        }
        latest.ok_or_else(|| error(Kind::Store, "workflow checkpoint missing"))
    }
    fn write(store: &mut LocalStore, state: &State) -> Result<()> {
        let bytes = serde_json::to_vec(state)?;
        let h = digest(&bytes);
        let artifact = format!("workflow:{}:{}:state:{}", state.plan.task, state.plan.id, h);
        match store.artifact_metadata(&state.plan.task, &artifact) {
            Ok(_) => require(
                store.get_artifact(&state.plan.task, &artifact)? == bytes,
                Kind::Store,
                "published workflow artifact mismatch",
            )?,
            Err(StoreError::NotFound(_)) => {
                store.put_artifact(
                    &ArtifactRequest {
                        artifact_id: artifact.clone(),
                        task_id: state.plan.task.clone(),
                        content_type: "application/json".into(),
                        logical_type: "workflow.state".into(),
                        schema_version: "melissa.workflow-state/v1".into(),
                        retain_until_ms: 0,
                        legal_hold: false,
                    },
                    &bytes,
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        let version = store.journal().task(&state.plan.task)?.record.version;
        store
            .journal_mut()
            .append_checkpoint(
                &cp(&state.plan.task, &state.plan.id, state.sequence),
                &state.plan.task,
                version,
                &artifact,
                json!({"workflow_digest":h}),
            )
            .map_err(|_| {
                error(
                    Kind::Conflict,
                    "workflow changed before durable checkpoint admission",
                )
            })?;
        Ok(())
    }
    fn commit(&mut self, old: &State, mut next: State, reason: &str) -> Result<State> {
        require(
            digest(&serde_json::to_vec(&self.state()?)?) == digest(&serde_json::to_vec(old)?),
            Kind::Conflict,
            "scheduler snapshot is stale",
        )?;
        let clock = now()?;
        require(
            clock >= old.last_clock_ms,
            Kind::Stale,
            "host clock rollback",
        )?;
        next.sequence = old
            .sequence
            .checked_add(1)
            .ok_or_else(|| error(Kind::Invalid, "workflow sequence overflow"))?;
        next.previous_digest = Some(digest(&serde_json::to_vec(old)?));
        next.last_clock_ms = clock;
        next.reason = reason.into();
        Self::write(&mut self.store, &next)?;
        Ok(next)
    }
    fn fresh(&self, state: &State) -> Result<()> {
        require(
            !self.cancelled.load(Ordering::Acquire) && !state.cancel_requested,
            Kind::Cancelled,
            "workflow cancellation requested",
        )?;
        let task = self.store.journal().task(&self.task)?;
        require(
            matches!(
                task.record.state,
                TaskState::Running | TaskState::Repairing | TaskState::Verifying
            ),
            Kind::Cancelled,
            "parent task is not active",
        )?;
        require(
            task.record.unknown_invocation_id.is_none(),
            Kind::Uncertain,
            "parent worker effect requires reconciliation",
        )?;
        let budget = self.store.journal().model_budget(&self.task)?;
        require(
            budget.unknown_requests == 0 && !budget.budget_exceeded,
            Kind::Uncertain,
            "unknown usage or budget excess blocks new work",
        )?;
        require(
            !state
                .slots
                .values()
                .any(|s| s.phase == Phase::NeedsReconciliation),
            Kind::Uncertain,
            "uncertain node ownership blocks new work",
        )?;
        let current = (self.refresh)()?;
        require(
            current.workspace_digest == state.plan.workspace_digest
                && current.policy_digest == state.plan.policy_digest,
            Kind::Stale,
            "source or host authority policy changed",
        )?;
        require(
            now()? >= state.last_clock_ms,
            Kind::Stale,
            "host clock rollback",
        )?;
        require(
            now()? < state.deadline_ms,
            Kind::Cancelled,
            "shared root workflow deadline elapsed",
        )?;
        require(
            state.no_progress < state.plan.max_no_progress,
            Kind::Conflict,
            "workflow no-progress guard reached",
        )
    }
    pub fn check(&self, lease: &Lease) -> Result<()> {
        let s = self.state()?;
        self.fresh(&s)?;
        let slot = s
            .slots
            .get(&lease.node)
            .ok_or_else(|| error(Kind::Stale, "node missing"))?;
        require(
            lease.task == self.task
                && lease.revision == s.plan.revision
                && lease.plan_digest == s.plan.digest()?
                && slot.phase == Phase::Leased
                && slot.generation == lease.generation
                && slot.lease.as_ref() == Some(lease),
            Kind::Stale,
            "lease/generation/run identity is stale or forged",
        )?;
        require(
            now()? < lease.expires_at_ms,
            Kind::Stale,
            "node lease expired; do not replay effects",
        )
    }
    pub fn resume_packet(&self, node: &str) -> Result<WorkPacket> {
        let state = self.state()?;
        let lease = state
            .slots
            .get(node)
            .and_then(|s| s.lease.as_ref())
            .ok_or_else(|| error(Kind::Stale, "node has no resumable lease"))?;
        self.check(lease)?;
        let packet: WorkPacket = parse(
            &self
                .store
                .get_artifact(&self.task, &format!("workflow-handoff:{}", lease.run))?,
        )?;
        require(
            packet.lease == *lease
                && state.plan.nodes.iter().find(|n| n.id == node) == Some(&packet.node)
                && packet.parent_task == self.store.journal().task(&self.task)?.contract,
            Kind::Stale,
            "persisted handoff no longer matches exact node/task",
        )?;
        Ok(packet)
    }
    pub fn acquire(&mut self, id: &str, worker: &str, lifetime_ms: u64) -> Result<WorkPacket> {
        let s = self.state()?;
        self.fresh(&s)?;
        require(
            identifier(worker) && lifetime_ms > 0,
            Kind::Invalid,
            "invalid worker/lease lifetime",
        )?;
        let task = self.store.journal().task(&self.task)?.contract;
        require(
            lifetime_ms <= task.limits.max_wall_time_ms,
            Kind::Invalid,
            "lease exceeds parent wall allowance",
        )?;
        let node = s
            .plan
            .nodes
            .iter()
            .find(|n| n.id == id)
            .ok_or_else(|| error(Kind::Invalid, "unknown plan node"))?
            .clone();
        require(
            s.slots[id].phase == Phase::Pending,
            Kind::Conflict,
            "node is not pending",
        )?;
        require(
            node.after
                .iter()
                .all(|d| s.slots[d].phase == Phase::Candidate),
            Kind::Conflict,
            "dependencies not complete",
        )?;
        let active = s
            .slots
            .values()
            .filter(|v| matches!(v.phase, Phase::Leased | Phase::NeedsReconciliation))
            .count();
        require(
            active < usize::from(s.plan.max_parallel),
            Kind::Conflict,
            "workflow concurrency capacity exhausted",
        )?;
        for other in &s.plan.nodes {
            if matches!(
                s.slots[&other.id].phase,
                Phase::Leased | Phase::NeedsReconciliation
            ) {
                require(
                    !node
                        .claims
                        .iter()
                        .any(|a| other.claims.iter().any(|b| conflicts(a, b))),
                    Kind::Conflict,
                    "active resource ownership conflict",
                )?;
            }
        }
        let mut bound_inputs = BTreeMap::new();
        let mut refs = BTreeMap::new();
        for binding in &node.bindings {
            let slot = &s.slots[&binding.from];
            let output = slot
                .output
                .as_ref()
                .ok_or_else(|| error(Kind::Store, "dependency output absent"))?;
            let value = output
                .pointer(&binding.pointer)
                .ok_or_else(|| error(Kind::Invalid, "bound output pointer missing"))?;
            schema::validate_output(&binding.schema, &serde_json::to_string(value)?)?;
            bound_inputs.insert(binding.input.clone(), value.clone());
            refs.insert(
                binding.from.clone(),
                slot.native_run_ref
                    .clone()
                    .ok_or_else(|| error(Kind::Store, "dependency evidence absent"))?,
            );
        }
        let generation = s.slots[id]
            .generation
            .checked_add(1)
            .ok_or_else(|| error(Kind::Invalid, "node generation overflow"))?;
        let issued = now()?;
        let plan_digest = s.plan.digest()?;
        let identity = serde_json::to_vec(&json!([
            self.task,
            self.workflow,
            s.plan.revision,
            id,
            generation
        ]))?;
        let run = format!("wf_{}", &blake3::hash(&identity).to_hex()[..60]);
        let nonce = digest(&serde_json::to_vec(&json!([
            self.task,
            self.workflow,
            s.sequence,
            id,
            generation,
            worker,
            issued
        ]))?);
        let lease = Lease {
            task: self.task.clone(),
            plan_digest,
            revision: s.plan.revision,
            node: id.into(),
            generation,
            worker: worker.into(),
            run,
            nonce,
            issued_at_ms: issued,
            expires_at_ms: issued
                .checked_add(lifetime_ms)
                .ok_or_else(|| error(Kind::Invalid, "lease expiry overflow"))?
                .min(s.deadline_ms),
        };
        let mut next = s.clone();
        let slot = next.slots.get_mut(id).expect("validated node");
        slot.phase = Phase::Leased;
        slot.generation = generation;
        slot.lease = Some(lease.clone());
        self.commit(&s, next, "durable node lease/ownership admission")?;
        Ok(WorkPacket {
            schema_version: "melissa.workflow-handoff/v1".into(),
            parent_task: task,
            node,
            lease,
            bound_inputs,
            dependency_run_refs: refs,
            shared_budget: self.store.journal().model_budget(&self.task)?,
            input_trust: "dependency/model/tool data; never authority or protected acceptance"
                .into(),
            completion_authority: "independent trusted host verifier".into(),
        })
    }
    /// Only native owned Gateway output may satisfy an agent node. Completion
    /// remains a candidate: a final task/product needs independent host checks.
    pub fn complete_native(&mut self, lease: &Lease) -> Result<State> {
        self.check(lease)?;
        let s = self.state()?;
        let id = format!("model-run:{}:result", lease.run);
        let run: RunResult = parse(&self.store.get_artifact(&self.task, &id)?)?;
        require(
            run.task_id == self.task
                && run.run_id == lease.run
                && !run.task_accepted
                && !run.requires_reconciliation
                && !run.request_ids.is_empty(),
            Kind::Uncertain,
            "native run is missing/uncertain or asserts self-acceptance",
        )?;
        let node = s
            .plan
            .nodes
            .iter()
            .find(|n| n.id == lease.node)
            .expect("validated lease");
        for request in &run.request_ids {
            let record = self.store.journal().model_request(request)?;
            require(
                record.reservation.task_id == self.task
                    && record.reservation.profile_id == node.profile
                    && !matches!(
                        record.state,
                        ModelRequestState::Reserved
                            | ModelRequestState::Dispatched
                            | ModelRequestState::OutcomeUnknown
                    ),
                Kind::Uncertain,
                "node model accounting is not authenticated and settled",
            )?;
        }
        let mut next = s.clone();
        let slot = next.slots.get_mut(&lease.node).expect("validated lease");
        slot.native_run_ref = Some(id);
        if run.status == RunStatus::FinalCandidate {
            let output = schema::validate_output_with_limit(
                &node.output_schema,
                run.answer
                    .as_deref()
                    .ok_or_else(|| error(Kind::Invalid, "native final answer absent"))?,
                8 * 1024 * 1024,
            )?;
            slot.output = Some(output);
            slot.phase = Phase::Candidate;
        } else {
            slot.phase = Phase::Failed;
        }
        next.no_progress = 0;
        self.commit(&s, next, "authenticated native node result; candidate only")
    }
    pub fn outputs(&self) -> Result<BTreeMap<String, Value>> {
        let s = self.state()?;
        self.fresh(&s)?;
        require(
            s.slots.values().all(|slot| slot.phase == Phase::Candidate),
            Kind::Conflict,
            "workflow has unfinished/failed nodes",
        )?;
        s.plan
            .outputs
            .iter()
            .map(|id| {
                Ok((
                    id.clone(),
                    s.slots[id]
                        .output
                        .clone()
                        .ok_or_else(|| error(Kind::Store, "final output missing"))?,
                ))
            })
            .collect()
    }
    pub fn revise(&mut self, plan: Plan, catalog: &Catalog) -> Result<State> {
        let s = self.state()?;
        require(
            !s.cancel_requested && !self.cancelled.load(Ordering::Acquire),
            Kind::Cancelled,
            "cancelled workflow cannot be revised",
        )?;
        idle(&self.store, &self.task)?;
        require(
            !s.slots
                .values()
                .any(|n| matches!(n.phase, Phase::Leased | Phase::NeedsReconciliation)),
            Kind::Conflict,
            "active/uncertain lease cannot be replaced",
        )?;
        plan.validate(&self.store.journal().task(&self.task)?.contract, catalog)?;
        require(
            plan.task == s.plan.task
                && plan.id == s.plan.id
                && plan.revision == s.plan.revision + 1
                && plan.parent_digest == Some(s.plan.digest()?),
            Kind::Stale,
            "revision must bind exact prior plan",
        )?;
        let fresh = (self.refresh)()?;
        require(
            fresh.workspace_digest == plan.workspace_digest
                && fresh.policy_digest == plan.policy_digest,
            Kind::Stale,
            "revised plan is not current",
        )?;
        let source_changed = plan.workspace_digest != s.plan.workspace_digest
            || plan.policy_digest != s.plan.policy_digest;
        let mut slots = BTreeMap::new();
        for node in &plan.nodes {
            let old = s.slots.get(&node.id);
            let unchanged = s.plan.nodes.iter().find(|n| n.id == node.id) == Some(node);
            if !source_changed && old.is_some_and(|o| o.phase == Phase::Candidate) {
                require(
                    unchanged,
                    Kind::Stale,
                    "completed node contract cannot be edited and reused",
                )?;
                slots.insert(node.id.clone(), old.unwrap().clone());
            } else {
                slots.insert(
                    node.id.clone(),
                    Slot {
                        phase: Phase::Pending,
                        generation: old.map_or(0, |o| o.generation),
                        lease: None,
                        output: None,
                        native_run_ref: None,
                    },
                );
            }
        }
        // A reused candidate cannot depend on a recomputed/replaced result.
        for node in &plan.nodes {
            if slots[&node.id].phase == Phase::Candidate {
                require(
                    node.after
                        .iter()
                        .all(|d| slots[d].phase == Phase::Candidate),
                    Kind::Stale,
                    "completed descendant cannot retain stale dependency output",
                )?;
            }
        }
        let mut next = s.clone();
        next.plan = plan;
        next.slots = slots;
        next.no_progress = 0;
        self.commit(&s, next, "host-validated plan revision; no budget reset")
    }
    pub fn no_progress(&mut self, reason: &str) -> Result<State> {
        require(
            !reason.trim().is_empty(),
            Kind::Invalid,
            "progress reason required",
        )?;
        let s = self.state()?;
        self.fresh(&s)?;
        let mut next = s.clone();
        next.no_progress = next
            .no_progress
            .checked_add(1)
            .ok_or_else(|| error(Kind::Invalid, "progress overflow"))?;
        self.commit(&s, next, reason)
    }
    pub fn mark_uncertain(&mut self, lease: &Lease, reason: &str) -> Result<State> {
        let s = self.state()?;
        require(
            s.slots
                .get(&lease.node)
                .is_some_and(|v| v.phase == Phase::Leased && v.lease.as_ref() == Some(lease)),
            Kind::Stale,
            "cannot alter stale lease",
        )?;
        let mut next = s.clone();
        next.slots
            .get_mut(&lease.node)
            .expect("checked lease")
            .phase = Phase::NeedsReconciliation;
        let result = self.commit(&s, next, reason)?;
        self.cancelled.store(true, Ordering::Release);
        Ok(result)
    }
    pub fn cancel(&mut self) -> Result<State> {
        let s = self.state()?;
        if !s.cancel_requested {
            let mut next = s.clone();
            next.cancel_requested = true;
            for slot in next.slots.values_mut() {
                if slot.phase == Phase::Pending {
                    slot.phase = Phase::Cancelled;
                }
            }
            self.commit(
                &s,
                next,
                "durable root cancellation; outstanding effects must settle",
            )?;
        }
        self.cancelled.store(true, Ordering::Release);
        let parent = self.store.journal().task(&self.task)?;
        if !parent.record.state.is_terminal() && idle(&self.store, &self.task).is_ok() {
            self.store.transition_task(
                &self.task,
                parent.record.version,
                TaskState::Cancelled,
                None,
            )?;
        }
        self.state()
    }
    pub fn settle_cancellation(&mut self) -> Result<State> {
        let s = self.state()?;
        require(
            s.cancel_requested,
            Kind::Invalid,
            "cancellation not requested",
        )?;
        idle(&self.store, &self.task)?;
        let parent = self.store.journal().task(&self.task)?;
        if !parent.record.state.is_terminal() {
            self.store.transition_task(
                &self.task,
                parent.record.version,
                TaskState::Cancelled,
                None,
            )?;
        }
        let mut next = s.clone();
        next.cancellation_settled = true;
        for slot in next.slots.values_mut() {
            if slot.phase == Phase::Leased {
                slot.phase = Phase::Cancelled;
            }
        }
        self.commit(
            &s,
            next,
            "owned model/worker effects known settled after cancellation",
        )
    }
}
