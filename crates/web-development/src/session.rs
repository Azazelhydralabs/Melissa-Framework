//! One isolated worker per durable host-admitted session. No command replay.
use crate::{
    Error, Result, digest, identifier,
    plan::WebPlan,
    protocol::{Command, Method, Reply, Service},
    put,
};
use melissa_container_executor::{
    ContainerReport, Conversation, Executor, ExecutorError, TerminationReason,
};
use melissa_core_contracts::{TaskState, catalog::Catalog};
use melissa_execution_broker::unix_ms;
use melissa_local_store::{
    LocalStore,
    journal::{AdmissionRequest, AttemptState, InvocationRequest},
};
use melissa_model_gateway::tools::ToolContext;
use melissa_repository::Repository;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
#[path = "binary.rs"]
mod binary;

/// Created by the trusted host, never parsed from an agent/repository response.
#[derive(Clone, Serialize)]
pub struct Policy {
    pub task_id: String,
    pub profile_id: String,
    pub principal_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub expires_at_ms: u64,
}
pub struct WebSession {
    repo: Arc<Repository>,
    store: LocalStore,
    catalog: Catalog,
    policy: Policy,
    plan: WebPlan,
    context: ToolContext,
    session_id: String,
    permit_id: String,
    input: Option<mpsc::Sender<Vec<u8>>>,
    answers: mpsc::Receiver<Vec<u8>>,
    worker: Option<thread::JoinHandle<std::result::Result<ContainerReport, ExecutorError>>>,
    monitor: Option<thread::JoinHandle<()>>,
    monitor_done: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
    expires: u64,
    sequence: u64,
    closed: bool,
    poisoned: bool,
    last: Option<Reply>,
    artifacts: Vec<String>,
    pending_api_effect: bool,
    pending_database_effect: bool,
    unknown_sql_effect: bool,
    pending_api_sequences: std::collections::BTreeSet<u64>,
}
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub success: bool,
    pub session_id: String,
    pub source_digest: String,
    pub native_attempt_id: String,
    pub cleanup_confirmed: bool,
    pub source_current: bool,
    pub requires_reconciliation: bool,
    pub developer_output_trusted: bool,
    pub protected_acceptance: bool,
    pub task_completed: bool,
    pub artifact_refs: Vec<String>,
    pub worker: Option<ContainerReport>,
    pub executor_error: Option<String>,
    pub application_outcome_unknown: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    schema_version: String,
    seq: u64,
    index: u64,
    parts: u64,
    total_bytes: u64,
    data_hex: String,
}
fn entropy() -> Result<String> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| Error::Invalid("web session entropy unavailable"))?;
    Ok(blake3::hash(&b).to_hex().to_string())
}
fn required(service: Service) -> (&'static str, &'static str, &'static str) {
    match service {
        Service::Browser => ("browser.navigate", "browser.interact_scoped", "browser"),
        Service::Api => ("code.tests", "network.test_scoped", "generic"),
        Service::Database => ("data.profile", "database.local_fixture", "generic"),
    }
}
fn authority(
    store: &LocalStore,
    catalog: &Catalog,
    p: &Policy,
    plan: &WebPlan,
    canonical: Option<&str>,
) -> Result {
    let t = store.journal().task(&p.task_id)?;
    let profile = catalog
        .profiles
        .get(&p.profile_id)
        .ok_or(Error::Invalid("unknown web profile"))?;
    let effects: BTreeSet<_> = t.contract.allowed_effects.iter().collect();
    let permits = |e: &str| {
        effects.contains(&e.to_string())
            && profile.authority.capability_ceiling.iter().any(|x| x == e)
    };
    if !identifier(&p.principal_id)
        || unix_ms().map_err(|_| Error::Invalid("host clock unavailable"))? >= p.expires_at_ms
        || t.record.state != TaskState::Running
        || t.record.unknown_invocation_id.is_some()
        || t.contract.workspace_ref != p.resource_id
        || !t.contract.allowed_resource_ids.contains(&p.resource_id)
        || !t.contract.selected_profile_ids.contains(&p.profile_id)
        || !t.contract.authorization_refs.contains(&p.authorization_ref)
        || !permits("workspace.read")
        || !permits("evidence.append")
        || canonical.is_some_and(|id| !profile.tool_ids.iter().any(|x| x == id))
    {
        return Err(Error::Invalid("web task/profile/resource/authority denied"));
    }
    for service in &plan.registration.services {
        let (tool, effect, worker) = required(*service);
        if !permits(effect)
            || !profile.tool_ids.iter().any(|x| x == tool)
            || !profile.worker_types.iter().any(|x| x == worker)
        {
            return Err(Error::Invalid(
                "registered web service exceeds role authority",
            ));
        }
    }
    let l = &plan.request.limits;
    if l.wall_time_ms > t.contract.limits.max_wall_time_ms
        || l.disk_bytes > t.contract.limits.max_disk_bytes
        || l.output_bytes
            .checked_add(l.export_bytes)
            .is_none_or(|n| n > t.contract.limits.max_output_bytes)
    {
        return Err(Error::Invalid(
            "web operation exceeds task resource ceiling",
        ));
    }
    Ok(())
}
impl WebSession {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        repo: Arc<Repository>,
        mut store: LocalStore,
        catalog: Catalog,
        policy: Policy,
        plan: WebPlan,
        context: ToolContext,
        cancel: Arc<AtomicBool>,
        revoked: Arc<AtomicBool>,
    ) -> Result<Self> {
        if context.task_id != policy.task_id
            || context.profile_id != policy.profile_id
            || context.generation != 1
            || [
                &context.run_id,
                &context.request_id,
                &context.invocation_id,
                &context.attempt_id,
            ]
            .iter()
            .any(|s| !identifier(s))
            || revoked.load(Ordering::Acquire)
            || cancel.load(Ordering::Acquire)
        {
            return Err(Error::Invalid("web session context denied"));
        }
        authority(&store, &catalog, &policy, &plan, None)?;
        repo.validate_snapshot(&plan.source, &cancel)?;
        let issued = unix_ms().map_err(|_| Error::Invalid("host clock"))?;
        let expires = issued
            .checked_add(plan.request.limits.wall_time_ms)
            .ok_or(Error::Invalid("web expiry overflow"))?
            .min(policy.expires_at_ms);
        if expires <= issued {
            return Err(Error::Invalid("web lease expired"));
        }
        let token = entropy()?;
        let session_id = format!("web:{token}");
        let permit_id = format!("permit:web:{token}");
        let input_id = format!("{}:web-input", context.invocation_id);
        let proposal_id = format!("{}:web-proposal", context.invocation_id);
        put(
            &mut store,
            &context.task_id,
            &input_id,
            "web.input",
            &serde_json::to_vec(&plan.snapshot)?,
        )?;
        let metadata = json!({"schema_version":"melissa.web-dispatch/v1","policy":policy,"request":plan.request,"source_digest":plan.source.digest,"snapshot_digest":plan.snapshot.digest().map_err(|_|Error::Invalid("web input digest"))?,"input_artifact_id":input_id,"permit_id":permit_id,"expires_at_ms":expires,"run_id":context.run_id,"request_id":context.request_id,"session_id":session_id});
        let encoded = serde_json::to_vec(&metadata)?;
        put(
            &mut store,
            &context.task_id,
            &proposal_id,
            "web.proposal",
            &encoded,
        )?;
        let canonical = required(
            *plan
                .registration
                .services
                .iter()
                .next()
                .ok_or(Error::Invalid("empty web registration"))?,
        )
        .0;
        let task = store.journal().task(&context.task_id)?;
        let proposed=store.journal_mut().propose_invocation(&InvocationRequest{invocation_id:context.invocation_id.clone(),task_id:context.task_id.clone(),tool_id:canonical.into(),arguments:json!({"proposal_artifact_id":proposal_id,"proposal_digest":digest(&encoded),"permit_id":permit_id,"resource_id":policy.resource_id,"authorization_ref":policy.authorization_ref}),idempotency_key:None,generation:1},task.record.version)?;
        let admission = AdmissionRequest {
            permit_id: permit_id.clone(),
            nonce: format!("nonce:web:{token}"),
            permit_digest: digest(&encoded),
            task_id: context.task_id.clone(),
            principal_id: policy.principal_id.clone(),
            profile_id: policy.profile_id.clone(),
            tool_id: canonical.into(),
            resource_id: policy.resource_id.clone(),
            arguments_digest: proposed.arguments_digest,
            invocation_id: context.invocation_id.clone(),
            attempt_id: context.attempt_id.clone(),
            generation: 1,
            expected_task_version: store.journal().task(&context.task_id)?.record.version,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: issued,
            expires_at_unix_ms: expires,
            consumed_at_unix_ms: unix_ms().map_err(|_| Error::Invalid("web admission clock"))?,
        };
        if let Err(e) = store.journal_mut().admit_dispatch(&admission) {
            if store.journal().attempt(&context.attempt_id).is_ok() {
                return Err(Error::AfterDispatch(Box::new(e.into())));
            }
            let task = store.journal().task(&context.task_id)?;
            store.journal_mut().reject_proposed_invocation(
                &context.invocation_id,
                task.record.version,
                proposed.version,
            )?;
            return Err(e.into());
        }
        // Any failure after atomic admission must remain non-replayable.
        let effect = (|| -> Result<Self> {
            let (input, receiver) = mpsc::channel();
            let (output, answers) = mpsc::sync_channel(8);
            let mut observer_store = store.connect()?;
            let monitor_store = store.connect()?;
            let session_store = store.connect()?;
            let done = Arc::new(AtomicBool::new(false));
            let stop = done.clone();
            let signal = cancel.clone();
            let rev = revoked.clone();
            let tid = context.task_id.clone();
            let inv = context.invocation_id.clone();
            let pid = permit_id.clone();
            let monitor = thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let invalid = rev.load(Ordering::Acquire)
                        || unix_ms().map_or(true, |n| n < issued || n >= expires)
                        || !matches!(monitor_store.journal().is_permit_revoked(&pid), Ok(false))
                        || !matches!(
                            monitor_store.journal().is_cancel_requested(&tid, &inv, 1),
                            Ok(false)
                        )
                        || monitor_store.journal().task(&tid).map_or(true, |t| {
                            t.record.state != TaskState::Running
                                || t.record.unknown_invocation_id.is_some()
                        });
                    if invalid {
                        signal.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(Duration::from_millis(40));
                }
            });
            let request = plan.request.clone();
            let snapshot = plan.snapshot.clone();
            let signal = cancel.clone();
            let ctx = context.clone();
            let permit_digest = admission.permit_digest.clone();
            let worker = thread::spawn(move || {
                Executor::run_with_io(
                    &request,
                    &snapshot,
                    &signal,
                    &mut |id| {
                        let v = json!({"container_id":id,"image":request.image_id,"task_id":ctx.task_id,"invocation_id":ctx.invocation_id,"attempt_id":ctx.attempt_id,"permit_digest":permit_digest});
                        put(
                            &mut observer_store,
                            &ctx.task_id,
                            &format!("{}:web-container-identity", ctx.attempt_id),
                            "web.container-identity",
                            &serde_json::to_vec(&v)
                                .map_err(|e| ExecutorError::Control(e.to_string()))?,
                        )
                        .map_err(|e| ExecutorError::Control(e.to_string()))
                    },
                    Some(Conversation {
                        input: receiver,
                        output,
                    }),
                )
            });
            let mut session = Self {
                repo,
                store: session_store,
                catalog,
                policy,
                plan,
                context,
                session_id,
                permit_id,
                input: Some(input),
                answers,
                worker: Some(worker),
                monitor: Some(monitor),
                monitor_done: done,
                cancel,
                revoked,
                expires,
                sequence: 0,
                closed: false,
                poisoned: false,
                last: None,
                artifacts: vec![input_id, proposal_id],
                pending_api_effect: false,
                pending_database_effect: false,
                unknown_sql_effect: false,
                pending_api_sequences: std::collections::BTreeSet::new(),
            };
            session.command(Command::Start {})?;
            Ok(session)
        })();
        match effect {
            Ok(s) => Ok(s),
            Err(e) => {
                if let Ok(g) = store.journal().attempt_guard(&admission.attempt_id) {
                    let _ = store.finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                Err(Error::AfterDispatch(Box::new(e)))
            }
        }
    }
    pub fn id(&self) -> &str {
        &self.session_id
    }
    pub fn context_matches(&self, ctx: &ToolContext) -> bool {
        ctx.task_id == self.context.task_id
            && ctx.profile_id == self.context.profile_id
            && ctx.run_id == self.context.run_id
            && ctx.generation == 1
    }
    pub fn last_reply(&self) -> Option<&Reply> {
        self.last.as_ref()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }
    pub fn artifact_refs(&self) -> &[String] {
        &self.artifacts
    }
    pub(crate) fn pending_api_effect(&self) -> bool {
        self.pending_api_effect
    }
    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.pending_api_effect
            || self.pending_database_effect
            || self.unknown_sql_effect
            || self.poisoned
    }
    pub fn validate(&self, op: &Command) -> Result {
        op.validate()?;
        if self.closed
            || self.poisoned
            || self.revoked.load(Ordering::Acquire)
            || self.cancel.load(Ordering::Acquire)
            || unix_ms().map_err(|_| Error::Invalid("host clock"))? >= self.expires
            || self.store.journal().is_permit_revoked(&self.permit_id)?
            || self.store.journal().is_cancel_requested(
                &self.context.task_id,
                &self.context.invocation_id,
                1,
            )?
            || op
                .service()
                .is_some_and(|s| !self.plan.registration.services.contains(&s))
            || matches!(op,Command::Migration{name} if !self.plan.registration.migrations.contains_key(name))
            || matches!(op,Command::Execute{statement,..} if !self.plan.registration.statements.contains_key(statement))
            || matches!(op,Command::SqlParallel{scripts} if scripts.iter().flat_map(|s|&s.steps).any(|s|matches!(s,crate::protocol::SqlStep::Execute{statement,..} if !self.plan.registration.statements.contains_key(statement))))
            || matches!(op,Command::ReconcileApi{sequence} if !self.pending_api_sequences.contains(sequence))
            || (matches!(op, Command::Start {}) && self.sequence != 0)
            || (self.pending_api_effect
                && (matches!(op,Command::Api{request} if request.method!=Method::Get)
                    || matches!(op,Command::ApiConcurrent{requests} if requests.iter().any(|r|r.method!=Method::Get))))
            || ((self.pending_api_effect || self.unknown_sql_effect)
                && matches!(
                    op,
                    Command::Execute { .. }
                        | Command::Begin { .. }
                        | Command::Commit { .. }
                        | Command::Migration { .. }
                        | Command::SqlParallel { .. }
                ))
        {
            return Err(Error::Invalid(
                "web session expired, foreign, closed or outside registration",
            ));
        }
        authority(
            &self.store,
            &self.catalog,
            &self.policy,
            &self.plan,
            op.canonical(),
        )?;
        self.repo
            .validate_snapshot(&self.plan.source, &self.cancel)?;
        Ok(())
    }
    pub fn command(&mut self, op: Command) -> Result<Reply> {
        self.validate(&op)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Invalid("web sequence overflow"))?;
        let bytes = serde_json::to_vec(&json!({"seq":sequence,"operation":op}))?;
        if bytes.len() >= 64 * 1024 {
            return Err(Error::Invalid("web request frame exceeded"));
        }
        let id = format!("{}:web-request:{sequence}", self.context.attempt_id);
        put(
            &mut self.store,
            &self.context.task_id,
            &id,
            "web.request",
            &bytes,
        )?;
        self.artifacts.push(id);
        self.sequence = sequence;
        let effect = (|| -> Result<Reply> {
            let mut frame = bytes;
            frame.push(b'\n');
            self.input
                .as_ref()
                .ok_or(Error::Invalid("web input closed"))?
                .send(frame)
                .map_err(|_| Error::Invalid("web worker disconnected"))?;
            let wall = self
                .expires
                .saturating_sub(unix_ms().map_err(|_| Error::Invalid("host clock"))?);
            let deadline = Instant::now()
                + Duration::from_millis(wall.min(if matches!(op, Command::Start {}) {
                    120_000
                } else {
                    40_000
                }));
            let mut assembled = Vec::new();
            let mut expected: Option<(u64, u64)> = None;
            let mut next = 0;
            let raw = loop {
                if self.cancel.load(Ordering::Acquire)
                    || self.revoked.load(Ordering::Acquire)
                    || Instant::now() >= deadline
                {
                    return Err(Error::Invalid("web response interrupted or timed out"));
                }
                match self.answers.recv_timeout(Duration::from_millis(40)) {
                    Ok(b) => {
                        let value = melissa_model_gateway::strict_json(
                            std::str::from_utf8(&b)
                                .map_err(|_| Error::Invalid("web fragment encoding"))?,
                        )
                        .map_err(|_| Error::Invalid("web fragment JSON"))?;
                        let part: Fragment = serde_json::from_value(value)?;
                        if part.schema_version != "melissa.web-fragment/v1"
                            || part.seq != sequence
                            || part.index != next
                            || part.total_bytes == 0
                            || part.total_bytes > 4 * 1024 * 1024
                            || part.parts != part.total_bytes.div_ceil(24576)
                            || part.index >= part.parts
                            || expected.is_some_and(|x| x != (part.parts, part.total_bytes))
                        {
                            return Err(Error::Invalid(
                                "web fragment identity or envelope mismatch",
                            ));
                        }
                        let size = (part.total_bytes - part.index * 24576).min(24576) as usize;
                        if part.data_hex.len() != size * 2
                            || !part
                                .data_hex
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        {
                            return Err(Error::Invalid(
                                "web fragment byte count/encoding mismatch",
                            ));
                        }
                        for pair in part.data_hex.as_bytes().as_chunks::<2>().0 {
                            let h = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
                            assembled.push(h(pair[0]) * 16 + h(pair[1]));
                        }
                        expected = Some((part.parts, part.total_bytes));
                        next += 1;
                        let mut ack =
                            serde_json::to_vec(&json!({"ack":sequence,"index":part.index}))?;
                        ack.push(b'\n');
                        self.input
                            .as_ref()
                            .ok_or(Error::Invalid("web acknowledgement pipe closed"))?
                            .send(ack)
                            .map_err(|_| Error::Invalid("web acknowledgement send failed"))?;
                        if next == part.parts {
                            break assembled;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
                            return Err(Error::Invalid(
                                "web worker exited without matching response",
                            ));
                        }
                    }
                    Err(_) => return Err(Error::Invalid("web response pipe closed")),
                }
            };
            let value = melissa_model_gateway::strict_json(
                std::str::from_utf8(&raw).map_err(|_| Error::Invalid("web response encoding"))?,
            )
            .map_err(|_| Error::Invalid("strict web response JSON"))?;
            let reply: Reply = serde_json::from_value(value)?;
            if reply.schema_version != "melissa.web-reply/v1"
                || reply.seq != self.sequence
                || reply.source_digest != self.plan.source.digest
                || reply.task_completed
                || reply.closed != matches!(op, Command::Close {})
                || reply.ok != (reply.error.is_none())
                || reply.ok != (reply.body.is_some())
            {
                return Err(Error::Invalid(
                    "web response sequence/source/status mismatch",
                ));
            }
            self.receive_binary(&reply, deadline)?;
            // Validate authority again before accepting an observed result.
            authority(
                &self.store,
                &self.catalog,
                &self.policy,
                &self.plan,
                op.canonical(),
            )?;
            self.repo
                .validate_snapshot(&self.plan.source, &self.cancel)?;
            let id = format!("{}:web-reply:{}", self.context.attempt_id, self.sequence);
            put(
                &mut self.store,
                &self.context.task_id,
                &id,
                "web.reply",
                &raw,
            )?;
            self.artifacts.push(id);
            self.closed = reply.closed;
            if matches!(op, Command::Api { .. } | Command::ApiConcurrent { .. })
                && reply.body.as_ref().is_some_and(|body| {
                    body["effect"] == "outcome_unknown"
                        || body["responses"]
                            .as_array()
                            .is_some_and(|rs| rs.iter().any(|r| r["effect"] == "outcome_unknown"))
                })
            {
                self.pending_api_effect = true;
                self.pending_api_sequences.insert(sequence);
            }
            if let Command::ReconcileApi { sequence: pending } = op
                && reply.ok
                && reply.body.as_ref().is_some_and(|b| {
                    b["reconciled"] == true
                        && b["sequence"] == pending
                        && b["automatic_retry"] == false
                })
            {
                self.pending_api_sequences.remove(&pending);
                self.pending_api_effect = !self.pending_api_sequences.is_empty();
            }
            if matches!(op, Command::Migration { .. })
                && reply.ok
                && let Some(names) = reply
                    .body
                    .as_ref()
                    .and_then(|b| b["unresolved_migrations"].as_array())
            {
                self.pending_database_effect = !names.is_empty();
            }
            if reply
                .error
                .as_ref()
                .is_some_and(|e| e["effect"] == "outcome_unknown")
                || reply
                    .body
                    .as_ref()
                    .is_some_and(|b| b["database_effect_unknown"] == true)
            {
                self.unknown_sql_effect = true;
            }
            self.last = Some(reply.clone());
            Ok(reply)
        })();
        effect.map_err(|e| {
            self.poisoned = true;
            self.cancel.store(true, Ordering::Release);
            // Fence another native/model dispatch before returning the error.
            // Cleanup does not prove whether the interrupted application action ran.
            if let Ok(g) = self.store.journal().attempt_guard(&self.context.attempt_id) {
                let _ = self
                    .store
                    .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
            }
            Error::AfterDispatch(Box::new(e))
        })
    }
    pub fn finish(mut self) -> Result<Outcome> {
        if !self.closed && !self.poisoned && self.command(Command::Close {}).is_err() {
            self.poisoned = true;
            self.cancel.store(true, Ordering::Release);
        }
        match self.settle() {
            Ok(r) => Ok(r),
            Err(e) => {
                if let Ok(g) = self.store.journal().attempt_guard(&self.context.attempt_id) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                Err(Error::AfterDispatch(Box::new(e)))
            }
        }
    }
    fn settle(&mut self) -> Result<Outcome> {
        self.input.take();
        let joined = self
            .worker
            .take()
            .ok_or(Error::Invalid("web worker already settled"))?
            .join();
        self.monitor_done.store(true, Ordering::Release);
        if let Some(m) = self.monitor.take() {
            let _ = m.join();
        }
        let (worker, executor_error) = match joined {
            Ok(Ok(r)) => (Some(r), None),
            Ok(Err(e)) => (None, Some(e.to_string())),
            Err(_) => (None, Some("web executor thread unwound".into())),
        };
        let cleanup = worker.as_ref().is_some_and(|r| {
            r.cleanup_confirmed
                && r.tree_confirmed_stopped
                && r.policy_verified
                && r.monitor_error.is_none()
        });
        let current = self
            .repo
            .validate_snapshot(&self.plan.source, &AtomicBool::new(false))
            .is_ok();
        let valid = worker.as_ref().is_some_and(|r| {
            r.input_digest == self.plan.snapshot.digest().unwrap_or_default()
                && r.image_id == self.plan.request.image_id
                && !r.output_truncated
                && !r.export_truncated
                && r.exit_code == Some(0)
                && r.termination == TerminationReason::Exited
        });
        let close_ok = self.last.as_ref().is_some_and(|r| {
            r.closed
                && r.ok
                && r.body.as_ref().is_some_and(|b| {
                    b["source_unchanged"] == true
                        && b["open_transactions"]
                            .as_array()
                            .is_some_and(|a| a.is_empty())
                })
        });
        let prior = self.store.journal().attempt(&self.context.attempt_id)?;
        let already_unknown = prior.state == AttemptState::OutcomeUnknown;
        let unknown = !cleanup
            || self.poisoned
            || self.pending_api_effect
            || self.pending_database_effect
            || self.unknown_sql_effect
            || already_unknown;
        let result_id = format!("{}:web-final", self.context.attempt_id);
        let mut outcome = Outcome {
            success: valid && current && close_ok && !unknown,
            session_id: self.session_id.clone(),
            source_digest: self.plan.source.digest.clone(),
            native_attempt_id: self.context.attempt_id.clone(),
            cleanup_confirmed: cleanup,
            source_current: current,
            requires_reconciliation: unknown,
            developer_output_trusted: false,
            protected_acceptance: false,
            task_completed: false,
            artifact_refs: self.artifacts.clone(),
            worker,
            executor_error,
            application_outcome_unknown: self.pending_api_effect,
        };
        put(
            &mut self.store,
            &self.context.task_id,
            &result_id,
            "web.final",
            &serde_json::to_vec(&outcome)?,
        )?;
        let g = self
            .store
            .journal()
            .attempt_guard(&self.context.attempt_id)?;
        if !already_unknown {
            self.store.finish_attempt(
                &g,
                if unknown {
                    AttemptState::OutcomeUnknown
                } else if valid && current && close_ok {
                    AttemptState::Succeeded
                } else if self.cancel.load(Ordering::Acquire) {
                    AttemptState::Cancelled
                } else {
                    AttemptState::Failed
                },
                Some(&result_id),
            )?;
        }
        outcome.artifact_refs.push(result_id);
        Ok(outcome)
    }
}
impl Drop for WebSession {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancel.store(true, Ordering::Release);
            self.poisoned = true;
            let _ = self.settle();
        }
    }
}
