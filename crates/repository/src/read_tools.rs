//! Least-privilege broker for finite repository read services. A profile's
//! git/search/LSP capability authorizes a fixed internal isolated procedure;
//! it never receives process.exec or model-selected commands/backends.
use super::*;
use crate::{
    analysis::{AnalysisPlan, AnalysisQuery, LspMethod, TOOLING_IMAGE},
    git::{GitOperation, GitPlan},
};
use melissa_container_executor::{
    ContainerLimits, ContainerRequest, EXECUTION_CONTRACT, Executor, Snapshot, TerminationReason,
};
use melissa_core_contracts::catalog::Catalog;
use melissa_local_store::journal::{AdmissionRequest, AttemptState, InvocationRequest};
use std::{sync::atomic::Ordering, time::Instant};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "service", content = "operation", rename_all = "snake_case")]
pub enum RepositoryRead {
    Git(GitOperation),
    Analysis(AnalysisQuery),
}
/// Host-owned exact operations and bounded worker resources. No Deserialize.
pub struct RepositoryReadPolicy {
    pub task_id: String,
    pub profile_id: String,
    pub principal_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub expires_at_ms: u64,
    pub limits: ContainerLimits,
    pub operations: Vec<RepositoryRead>,
}
enum Plan {
    Git(GitPlan),
    Analysis(AnalysisPlan),
}
impl Plan {
    fn input(&self) -> (&ContainerRequest, &Snapshot) {
        match self {
            Self::Git(p) => (&p.request, &p.snapshot),
            Self::Analysis(p) => (&p.request, &p.snapshot),
        }
    }
}
struct ReadHost {
    repo: Repository,
    store: LocalStore,
    catalog: Catalog,
    policy: RepositoryReadPolicy,
    operations: BTreeMap<String, RepositoryRead>,
}
pub struct RepositoryReadDispatcher {
    host: Arc<Mutex<ReadHost>>,
}
fn route(op: &RepositoryRead) -> (&'static str, &'static str) {
    match op {
        RepositoryRead::Git(g) => match g {
            GitOperation::Status => ("git_status", "git.status"),
            GitOperation::Diff { .. } => ("git_diff", "git.diff"),
            GitOperation::Log { .. } => ("git_log", "git.log"),
            GitOperation::WorktreeList => ("git_worktree_list", "git.worktree"),
            GitOperation::WorktreeCreate { .. } => ("git_worktree_create", "git.worktree"),
        },
        RepositoryRead::Analysis(q) => match q {
            AnalysisQuery::Ripgrep { .. } => ("fs_ripgrep", "fs.search"),
            AnalysisQuery::Lsp {
                method: LspMethod::References,
                ..
            } => ("code_lsp_references", "code.references"),
            AnalysisQuery::Lsp {
                method: LspMethod::Definition,
                ..
            } => ("code_lsp_definition", "code.references"),
            AnalysisQuery::Lsp {
                method: LspMethod::DocumentSymbol,
                ..
            } => ("code_lsp_symbols", "code.symbols"),
        },
    }
}
impl ReadHost {
    fn authority(&self, op: &RepositoryRead) -> crate::Result {
        let p = &self.policy;
        let n = melissa_execution_broker::unix_ms().map_err(Error::Broker)?;
        let t = self.store.journal().task(&p.task_id)?;
        let profile = self
            .catalog
            .profiles
            .get(&p.profile_id)
            .ok_or(Error::Denied("unknown read-service profile"))?;
        if n >= p.expires_at_ms
            || t.record.state != TaskState::Running
            || t.record.unknown_invocation_id.is_some()
            || t.contract.workspace_ref != p.resource_id
            || !t.contract.allowed_resource_ids.contains(&p.resource_id)
            || !t.contract.selected_profile_ids.contains(&p.profile_id)
            || !t.contract.authorization_refs.contains(&p.authorization_ref)
            || !t
                .contract
                .allowed_effects
                .iter()
                .any(|e| e == "workspace.read")
            || !profile
                .authority
                .capability_ceiling
                .iter()
                .any(|e| e == "workspace.read")
            || !profile.tool_ids.iter().any(|id| id == route(op).1)
            || !profile.worker_types.iter().any(|w| w == "generic")
        {
            return Err(Error::Denied("repository read-service scope/profile/task"));
        }
        if matches!(op, RepositoryRead::Git(_))
            && (!t.contract.allowed_effects.iter().any(|e| e == "git.read")
                || !profile
                    .authority
                    .capability_ceiling
                    .iter()
                    .any(|e| e == "git.read"))
        {
            return Err(Error::Denied("Git read authority required"));
        }
        Ok(())
    }
    fn plan(&self, op: &RepositoryRead, cancel: &AtomicBool) -> crate::Result<Plan> {
        self.authority(op)?;
        let s = self.repo.snapshot(cancel)?;
        match op {
            RepositoryRead::Git(g) => Ok(Plan::Git(GitPlan::prepare(
                &self.repo,
                &s,
                g,
                "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4",
                self.policy.limits.clone(),
                cancel,
            )?)),
            RepositoryRead::Analysis(q) => Ok(Plan::Analysis(AnalysisPlan::prepare(
                &self.repo,
                &s,
                q.clone(),
                TOOLING_IMAGE,
                self.policy.limits.clone(),
                cancel,
            )?)),
        }
    }
    fn put(&mut self, id: &str, kind: &str, schema: &str, bytes: &[u8]) -> crate::Result {
        self.store.put_artifact(
            &ArtifactRequest {
                artifact_id: id.into(),
                task_id: self.policy.task_id.clone(),
                content_type: "application/json".into(),
                logical_type: kind.into(),
                schema_version: schema.into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            bytes,
        )?;
        Ok(())
    }
    fn validate(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        let op = self
            .operations
            .get(&c.name)
            .ok_or_else(|| GatewayError::unsupported("read service is not bound"))?;
        self.authority(op).map_err(err)?;
        if c.id.is_empty()
            || c.id.len() > 256
            || c.id.chars().any(char::is_control)
            || melissa_model_gateway::strict_json(&c.arguments)?
                != serde_json::to_value(op).map_err(|_| GatewayError::invalid("read operation"))?
        {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "exact host-bound read operation required",
            ));
        }
        Ok(())
    }
    fn execute(
        &mut self,
        c: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> crate::Result<ToolExecution> {
        self.validate(&c)
            .map_err(|_| Error::Denied("read service call/authority"))?;
        if ctx.task_id != self.policy.task_id
            || ctx.profile_id != self.policy.profile_id
            || ctx.generation != 1
        {
            return Err(Error::Denied("read service context"));
        }
        for s in [
            &ctx.run_id,
            &ctx.request_id,
            &ctx.invocation_id,
            &ctx.attempt_id,
        ] {
            crate::broker::identifier(s)?;
        }
        check_cancel(&cancel)?;
        let op = self
            .operations
            .get(&c.name)
            .ok_or(Error::Invalid("read service route"))?
            .clone();
        let plan = self.plan(&op, &cancel)?;
        let (req, snapshot) = plan.input();
        let task = self.store.journal().task(&self.policy.task_id)?;
        if req.limits.wall_time_ms > task.contract.limits.max_wall_time_ms
            || req.limits.disk_bytes > task.contract.limits.max_disk_bytes
            || req
                .limits
                .output_bytes
                .checked_add(req.limits.export_bytes)
                .is_none_or(|n| n > task.contract.limits.max_output_bytes)
        {
            return Err(Error::Quota("read service task resources"));
        }
        let version = task.record.version;
        let issued = melissa_execution_broker::unix_ms().map_err(Error::Broker)?;
        let expires = issued
            .checked_add(req.limits.wall_time_ms)
            .ok_or(Error::Invalid("read service deadline"))?
            .min(self.policy.expires_at_ms);
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::Denied("read service entropy"))?;
        let token = blake3::hash(&entropy).to_hex().to_string();
        let permit = format!("permit:repository-read:{token}");
        let nonce = format!("nonce:repository-read:{token}");
        let input_id = format!("{}:read-input", ctx.invocation_id);
        let proposal_id = format!("{}:read-proposal", ctx.invocation_id);
        self.put(
            &input_id,
            "repository_read_input",
            "melissa.repository-read-input/v1",
            &serde_json::to_vec(snapshot)?,
        )?;
        let metadata = json!({"schema_version":"melissa.repository-read-dispatch/v1","root_identity":self.repo.root_identity(),"operation":op,"request":req,"snapshot_digest":snapshot.digest().map_err(|_|Error::Invalid("read source digest"))?,"input_artifact_id":input_id,"principal_id":self.policy.principal_id,"profile_id":ctx.profile_id,"resource_id":self.policy.resource_id,"authorization_ref":self.policy.authorization_ref,"wire_call_id":c.id,"wire_name":c.name,"arguments_digest":digest(c.arguments.as_bytes()),"run_id":ctx.run_id,"request_id":ctx.request_id,"permit_id":permit,"nonce":nonce,"expires_at_ms":expires,"capability":route(&op).1,"raw_process_authority":false});
        self.put(
            &proposal_id,
            "repository_read_proposal",
            "melissa.repository-read-dispatch/v1",
            &serde_json::to_vec(&metadata)?,
        )?;
        self.authority(&op)?;
        check_cancel(&cancel)?;
        let proposed=self.store.journal_mut().propose_invocation(&InvocationRequest{invocation_id:ctx.invocation_id.clone(),task_id:ctx.task_id.clone(),tool_id:route(&op).1.into(),arguments:json!({"proposal_artifact_id":proposal_id,"proposal_digest":digest(&serde_json::to_vec(&metadata)?),"permit_id":permit,"resource_id":self.policy.resource_id,"authorization_ref":self.policy.authorization_ref}),idempotency_key:None,generation:1},version)?;
        let v = self.store.journal().task(&ctx.task_id)?.record.version;
        let admission = AdmissionRequest {
            permit_id: permit.clone(),
            nonce,
            permit_digest: digest(&serde_json::to_vec(&metadata)?),
            task_id: ctx.task_id.clone(),
            principal_id: self.policy.principal_id.clone(),
            profile_id: ctx.profile_id.clone(),
            tool_id: route(&op).1.into(),
            resource_id: self.policy.resource_id.clone(),
            arguments_digest: proposed.arguments_digest,
            invocation_id: ctx.invocation_id.clone(),
            attempt_id: ctx.attempt_id.clone(),
            generation: 1,
            expected_task_version: v,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: issued,
            expires_at_unix_ms: expires,
            consumed_at_unix_ms: melissa_execution_broker::unix_ms().map_err(Error::Broker)?,
        };
        if let Err(e) = self.store.journal_mut().admit_dispatch(&admission) {
            if let Ok(a) = self.store.journal().attempt(&ctx.attempt_id)
                && a.invocation_id == ctx.invocation_id
            {
                if let Ok(g) = self.store.journal().attempt_guard(&ctx.attempt_id) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                return Err(Error::AfterDispatch(Box::new(Error::Store(e))));
            }
            if let Ok(t) = self.store.journal().task(&ctx.task_id) {
                let _ = self.store.journal_mut().reject_proposed_invocation(
                    &ctx.invocation_id,
                    t.record.version,
                    proposed.version,
                );
            }
            return Err(e.into());
        }
        let effect = (|| -> crate::Result<ToolExecution> {
            let monitor = self.store.connect()?;
            let signal = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let watch_signal = signal.clone();
            let watch_stop = stop.clone();
            let task_id = ctx.task_id.clone();
            let inv = ctx.invocation_id.clone();
            let permit_id = permit.clone();
            let external = cancel.clone();
            let started = Instant::now();
            let wall = req.limits.wall_time_ms;
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let watcher = std::thread::spawn(move || {
                let mut ready = Some(ready_tx);
                while !watch_stop.load(Ordering::Acquire) {
                    let t = monitor.journal().task(&task_id);
                    let clock = melissa_execution_broker::unix_ms();
                    let revoked = monitor.journal().is_permit_revoked(&permit_id);
                    let requested = monitor.journal().is_cancel_requested(&task_id, &inv, 1);
                    let invalid = external.load(Ordering::Acquire)
                        || started.elapsed().as_millis() >= u128::from(wall)
                        || clock.is_err()
                        || clock.as_ref().is_ok_and(|n| *n < issued || *n >= expires)
                        || !matches!(revoked, Ok(false))
                        || !matches!(requested, Ok(false))
                        || t.as_ref().map_or(true, |t| {
                            t.record.state != TaskState::Running
                                || t.record.unknown_invocation_id.is_some()
                        });
                    if invalid {
                        watch_signal.store(true, Ordering::Release);
                    }
                    if let Some(r) = ready.take() {
                        let _ = r.send(());
                    }
                    if invalid {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            let ready = ready_rx.recv_timeout(Duration::from_secs(2)).is_ok();
            let run = if ready && !signal.load(Ordering::Acquire) {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(||Executor::run_with_observer(req,snapshot,&signal,&mut|container_id|{self.put(&format!("{}:container-identity",ctx.attempt_id),"process.container_identity","melissa.container-identity/v1",&serde_json::to_vec(&json!({"schema_version":"melissa.container-identity/v1","container_id":container_id,"image_id":req.image_id,"task_id":ctx.task_id,"invocation_id":ctx.invocation_id,"attempt_id":ctx.attempt_id,"generation":1,"permit_digest":admission.permit_digest,"snapshot_digest":snapshot.digest().map_err(|e|melissa_container_executor::ExecutorError::Control(e.to_string()))?,"execution_contract":EXECUTION_CONTRACT}))?).map_err(|e|melissa_container_executor::ExecutorError::Control(e.to_string()))}))).unwrap_or_else(|_|Err(melissa_container_executor::ExecutorError::Control("read service unwound".into())))
            } else {
                Err(melissa_container_executor::ExecutorError::CancelledBeforeLaunch)
            };
            stop.store(true, Ordering::Release);
            if watcher.join().is_err() {
                return Err(Error::Denied("read monitor unwound"));
            }
            let report = match run {
                Ok(r) => r,
                Err(melissa_container_executor::ExecutorError::CancelledBeforeLaunch) => {
                    let id = format!("{}:read-result", ctx.invocation_id);
                    let content = json!({"status":"cancelled_before_launch","task_accepted":false})
                        .to_string();
                    self.put(
                        &id,
                        "repository_tool_result",
                        "melissa.repository-tool-evidence/v1",
                        content.as_bytes(),
                    )?;
                    let g = self.store.journal().attempt_guard(&ctx.attempt_id)?;
                    self.store
                        .finish_attempt(&g, AttemptState::Cancelled, Some(&id))?;
                    return Ok(ToolExecution {
                        content,
                        success: false,
                        cancelled: true,
                        requires_reconciliation: false,
                        artifact_refs: vec![input_id.clone(), proposal_id.clone(), id],
                    });
                }
                Err(_) => return Err(Error::Denied("read worker failed after dispatch")),
            };
            let report_id = format!("{}:read-worker-report", ctx.invocation_id);
            self.put(
                &report_id,
                "repository_read_worker_report",
                "melissa.repository-read-worker/v1",
                &serde_json::to_vec(&report)?,
            )?;
            if !report.cleanup_confirmed
                || !report.tree_confirmed_stopped
                || !report.policy_verified
                || report.monitor_error.is_some()
            {
                return Err(Error::Denied("read worker cleanup/policy is unknown"));
            }
            let cancelled = matches!(report.termination, TerminationReason::Cancelled);
            let worker_ok = matches!(report.termination, TerminationReason::Exited)
                && report.exit_code == Some(0)
                && !report.output_truncated
                && !report.export_truncated;
            let decoded = if worker_ok {
                match &plan {
                    Plan::Git(p) => (|| {
                        let s = self.repo.snapshot(&AtomicBool::new(false))?;
                        let RepositoryRead::Git(git_op) = &op else {
                            return Err(Error::Invalid("Git operation binding"));
                        };
                        let current = GitPlan::prepare(
                            &self.repo,
                            &s,
                            git_op,
                            &p.request.image_id,
                            p.request.limits.clone(),
                            &AtomicBool::new(false),
                        )?;
                        if s.digest != p.source_snapshot_digest
                            || current.metadata_digest != p.metadata_digest
                        {
                            return Err(Error::Stale("Git read source or metadata changed"));
                        }
                        Ok(
                            json!({"tool_id":route(&op).1,"stdout_bytes":report.stdout,"stderr_bytes":report.stderr,"source_snapshot_digest":p.source_snapshot_digest,"task_accepted":false}),
                        )
                    })(),
                    Plan::Analysis(p) => p
                        .decode(&self.repo, &report, &AtomicBool::new(false))
                        .and_then(|r| serde_json::to_value(r).map_err(Error::from)),
                }
            } else {
                Err(Error::Invalid(
                    "read worker did not complete a usable result",
                ))
            };
            let success = decoded.is_ok();
            let value = match decoded {
                Ok(v) => v,
                Err(e) => {
                    json!({"status":if cancelled{"cancelled"}else{"failed"},"error":e.to_string(),"worker_report_artifact_id":report_id,"task_accepted":false})
                }
            };
            let full = serde_json::to_string(&value)?;
            if full.len() as u64 > task.contract.limits.max_output_bytes {
                return Err(Error::Quota("read result bytes"));
            }
            let result_id = format!("{}:read-result", ctx.invocation_id);
            self.put(
                &result_id,
                "repository_tool_result",
                "melissa.repository-tool-evidence/v1",
                full.as_bytes(),
            )?;
            let g = self.store.journal().attempt_guard(&ctx.attempt_id)?;
            self.store.finish_attempt(
                &g,
                if success {
                    AttemptState::Succeeded
                } else if cancelled {
                    AttemptState::Cancelled
                } else {
                    AttemptState::Failed
                },
                Some(&result_id),
            )?;
            let content = if full.len() > 768 * 1024 {
                json!({"delivery":"paged_result","artifact_id":result_id,"digest":digest(full.as_bytes()),"total_bytes":full.len(),"next_offset":0,"complete":false,"task_accepted":false}).to_string()
            } else {
                full
            };
            Ok(ToolExecution {
                content,
                success,
                cancelled,
                requires_reconciliation: false,
                artifact_refs: vec![input_id.clone(), proposal_id.clone(), report_id, result_id],
            })
        })();
        match effect {
            Ok(r) => Ok(r),
            Err(e) => {
                if let Ok(g) = self.store.journal().attempt_guard(&ctx.attempt_id) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                Err(Error::AfterDispatch(Box::new(e)))
            }
        }
    }
}
impl RepositoryReadDispatcher {
    pub fn new(
        repo: Repository,
        store: LocalStore,
        catalog: Catalog,
        policy: RepositoryReadPolicy,
    ) -> crate::Result<Self> {
        for id in [
            &policy.task_id,
            &policy.profile_id,
            &policy.principal_id,
            &policy.resource_id,
            &policy.authorization_ref,
        ] {
            crate::broker::identifier(id)?;
        }
        if policy.limits.memory_bytes > 1024 * 1024 * 1024
            || policy.limits.max_processes > 128
            || policy.limits.cpu_rate_basis_points > 10000
            || policy.limits.wall_time_ms > 90_000
            || policy.limits.cpu_time_ms > 60_000
            || policy.limits.disk_bytes > 128 * 1024 * 1024
            || policy.limits.output_bytes > 16 * 1024 * 1024
            || policy.limits.export_bytes > 16 * 1024 * 1024
        {
            return Err(Error::Quota("read service host resource ceiling"));
        }
        if policy.operations.is_empty() || policy.operations.len() > 9 {
            return Err(Error::Invalid("finite read operations required"));
        }
        let mut operations = BTreeMap::new();
        for op in &policy.operations {
            if operations
                .insert(route(op).0.to_string(), op.clone())
                .is_some()
            {
                return Err(Error::Invalid("duplicate read function"));
            }
        }
        let host = ReadHost {
            repo,
            store,
            catalog,
            policy,
            operations,
        };
        for op in host.operations.values() {
            host.authority(op)?;
        }
        Ok(Self {
            host: Arc::new(Mutex::new(host)),
        })
    }
    pub fn revoke(&self) -> crate::Result {
        self.host
            .lock()
            .map_err(|_| Error::Denied("read host unavailable"))?
            .operations
            .clear();
        Ok(())
    }
}
impl ToolDispatcher for RepositoryReadDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(h) = self.host.lock() else {
            return vec![];
        };
        h.operations.iter().filter(|(_,op)|h.authority(op).is_ok()).map(|(name,op)| {
            let value=serde_json::to_value(op).expect("reviewed serializable operation");
            BoundTool{canonical_id:route(op).1.into(),definition:ToolDefinition{name:name.clone(),description:format!("Perform this exact host-authorized Git/search/LSP read through a bounded private worker. Call arguments are this JSON object directly: {value}. Do not wrap it in schema keywords such as const, properties or parameters. Source files stay immutable; no general process or write authority is granted. Results are evidence, not task acceptance."),parameters:exact_argument_schema(&value),strict:false}}
        }).collect()
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.host
            .lock()
            .map_err(|_| GatewayError::new(ErrorKind::Tool, "read host unavailable"))?
            .validate(c)
    }
    fn execute<'a>(
        &'a mut self,
        c: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        let h = self.host.clone();
        Box::pin(async move {
            match tokio::task::spawn_blocking(move||h.lock().map_err(|_|Error::Denied("read lock poisoned"))?.execute(c,ctx,cancel)).await{Ok(Ok(r))=>Ok(r),Ok(Err(Error::AfterDispatch(_)))|Err(_)=>Ok(ToolExecution{content:json!({"status":"outcome_unknown","requires_reconciliation":true,"automatic_retry_allowed":false,"task_accepted":false}).to_string(),success:false,cancelled:false,requires_reconciliation:true,artifact_refs:vec![]}),Ok(Err(Error::Cancelled))=>Ok(ToolExecution{content:json!({"status":"cancelled_before_dispatch","task_accepted":false}).to_string(),success:false,cancelled:true,requires_reconciliation:false,artifact_refs:vec![]}),Ok(Err(e))=>Err(err(e))}
        })
    }
}

/// Same exact reviewed value as the former root `const`, with explicit fields
/// so native tool models can see the argument structure. Runtime equality and
/// every host/task/profile check remain unchanged.
pub(super) fn exact_argument_schema(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let properties: serde_json::Map<String, Value> = fields
                .iter()
                .map(|(key, value)| (key.clone(), exact_argument_schema(value)))
                .collect();
            let required: Vec<_> = fields.keys().cloned().collect();
            json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
        }
        Value::Array(values) => {
            let items = values
                .first()
                .map(exact_argument_schema)
                .unwrap_or_else(|| json!({}));
            // The complete array stays exact, including order. `items` is only
            // a type hint; arrays with different literal members need a union.
            let items = if values.iter().all(|v| values.first() == Some(v)) {
                items
            } else {
                json!({})
            };
            json!({"type":"array","items":items,"const":value,"minItems":values.len(),"maxItems":values.len()})
        }
        Value::String(_) => json!({"type":"string","const":value}),
        Value::Bool(_) => json!({"type":"boolean","const":value}),
        Value::Number(_) => json!({"type":"integer","const":value}),
        Value::Null => json!({"type":"null","const":null}),
    }
}

#[cfg(test)]
#[path = "read_schema_tests.rs"]
mod schema_tests;
