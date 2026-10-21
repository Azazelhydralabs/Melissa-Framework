//! Host registered finite CODE-06 procedures. Model arguments never select a
//! process, image, SDK, environment, policy, harness registration or source root.
use crate::{
    Error, Result,
    debug::{Breakpoint, DebugCommand, DebugPlan, DebugSession},
    full::{HarnessRegistration, Language, Operation, ProcedurePlan, put},
    semantic::{SemanticMethod, SemanticPlan, SemanticQuery},
};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_core_contracts::{TaskState, catalog::Catalog};
use melissa_execution_broker::{
    InvocationIdentity,
    container_broker::ContainerBroker,
    container_policy::container_execution_digest,
    policy::{AuthorityGrant, HostPolicy, PermitRequest, authenticated_digest},
    unix_ms,
};
use melissa_local_store::LocalStore;
use melissa_model_gateway::{
    ErrorKind, GatewayError, ToolCall, ToolDefinition,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use melissa_repository::Repository;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Serialize)]
#[serde(tag = "service", rename_all = "snake_case")]
pub enum CodeOperation {
    Procedure {
        language: Language,
        operation: Operation,
        harness: Option<HarnessRegistration>,
    },
    Semantic {
        language: Language,
        query: SemanticQuery,
        build_scripts: bool,
    },
    Debug {
        language: Language,
        entry: String,
        breakpoints: Vec<Breakpoint>,
        expected_binary_sha256: Option<String>,
    },
}
impl CodeOperation {
    pub fn canonical(&self) -> &'static str {
        match self {
            Self::Procedure { operation, .. } => match operation {
                Operation::Build {} => "code.build",
                Operation::Check {} => "code.diagnostics",
                Operation::Lint {} | Operation::FormatCheck {} => "code.lint",
                Operation::Test { .. } => "code.tests",
            },
            Self::Semantic { query, .. } => match query.method {
                SemanticMethod::Definition | SemanticMethod::References => "code.references",
                SemanticMethod::Symbols => "code.symbols",
                _ => "code.diagnostics",
            },
            Self::Debug { .. } => "code.diagnostics",
        }
    }
    fn process(&self) -> bool {
        !matches!(
            self,
            Self::Semantic {
                build_scripts: false,
                ..
            }
        )
    }
}
/// This is trusted host configuration, deliberately not Deserialize.
pub struct CodeToolPolicy {
    pub task_id: String,
    pub profile_id: String,
    pub principal_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub expires_at_ms: u64,
    pub limits: ContainerLimits,
    pub operations: BTreeMap<String, CodeOperation>,
    pub process_policy: Option<HostPolicy>,
}
pub(crate) struct Host {
    pub(crate) repo: Arc<Repository>,
    pub(crate) store: LocalStore,
    pub(crate) catalog: Catalog,
    pub(crate) policy: CodeToolPolicy,
    pub(crate) revoked: Arc<AtomicBool>,
    session: Option<DebugSession>,
    session_context: Option<ToolContext>,
    active_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    results: BTreeMap<String, CodeOperation>,
}
pub struct CodeDispatcher {
    host: Arc<Mutex<Host>>,
    revoked: Arc<AtomicBool>,
    active_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}
#[derive(Clone)]
pub struct CodeRevocation {
    revoked: Arc<AtomicBool>,
    active_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}
impl CodeRevocation {
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        if let Ok(active) = self.active_cancel.lock()
            && let Some(signal) = active.as_ref()
        {
            signal.store(true, Ordering::Release);
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCall {
    session_id: String,
    operation: DebugCommand,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageCall {
    artifact_id: String,
    offset: u64,
    max_bytes: u32,
}
fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
pub(crate) fn denied() -> Error {
    Error::Invalid("CODE-06 task/profile/resource/capability/host authority denied")
}
fn err(e: Error) -> GatewayError {
    GatewayError::new(ErrorKind::Authorization, e.to_string())
}
impl Host {
    pub(crate) fn authority(&self, op: &CodeOperation) -> Result {
        let p = &self.policy;
        let t = self.store.journal().task(&p.task_id)?;
        let profile = self
            .catalog
            .profiles
            .get(&p.profile_id)
            .ok_or_else(denied)?;
        let allows = |e: &str| {
            t.contract.allowed_effects.iter().any(|x| x == e)
                && profile.authority.capability_ceiling.iter().any(|x| x == e)
        };
        if self.revoked.load(Ordering::Acquire)
            || unix_ms()? >= p.expires_at_ms
            || t.record.state != TaskState::Running
            || t.record.unknown_invocation_id.is_some()
            || t.contract.workspace_ref != p.resource_id
            || !t.contract.allowed_resource_ids.contains(&p.resource_id)
            || !t.contract.selected_profile_ids.contains(&p.profile_id)
            || !t.contract.authorization_refs.contains(&p.authorization_ref)
            || !profile.tool_ids.iter().any(|x| x == op.canonical())
            || !profile.worker_types.iter().any(|x| x == "generic")
            || !allows("workspace.read")
        {
            return Err(denied());
        }
        if op.process() && (!allows("process.execute_scoped") || p.process_policy.is_none()) {
            return Err(denied());
        }
        if op.process() {
            let h = p.process_policy.as_ref().ok_or_else(denied)?;
            let c = &h.ceiling;
            let l = &p.limits;
            if !h.allow_monitored_cpu
                || h.enforcement.cpu_time
                || !h.enforcement.disk_quota
                || !h.enforcement.filesystem_isolation
                || !h.enforcement.network_isolation
                || !h.enforcement.memory
                || !h.enforcement.process_tree
                || !h.enforcement.output_limit
                || c.disk_mode != melissa_execution_broker::policy::DiskLimitMode::Strict
                || c.cpu_mode != melissa_execution_broker::policy::CpuLimitMode::MonitoredTotal
                || l.wall_time_ms > c.wall_time_ms
                || l.wall_time_ms > h.max_permit_lifetime_ms
                || l.cpu_time_ms > c.cpu_time_ms
                || l.cpu_rate_basis_points > u32::from(c.cpu_rate_basis_points)
                || l.memory_bytes > c.memory_bytes
                || l.disk_bytes > c.disk_bytes
                || l.max_processes > c.max_processes
                || l.output_bytes
                    .checked_add(l.export_bytes)
                    .is_none_or(|n| n > c.output_bytes)
                || h.revoked_authorization_refs.contains(&p.authorization_ref)
            {
                return Err(denied());
            }
        }
        if matches!(op, CodeOperation::Debug { .. })
            && (!allows("workspace.apply_patch_scoped")
                || !profile.tool_ids.iter().any(|x| x == "process.exec"))
        {
            return Err(denied());
        }
        let l = &p.limits;
        if l.wall_time_ms > t.contract.limits.max_wall_time_ms
            || l.disk_bytes > t.contract.limits.max_disk_bytes
            || l.output_bytes
                .checked_add(l.export_bytes)
                .is_none_or(|n| n > t.contract.limits.max_output_bytes)
        {
            return Err(Error::Invalid("CODE-06 task resource ceiling"));
        }
        Ok(())
    }
    fn context(&self, ctx: &ToolContext) -> Result {
        if ctx.task_id != self.policy.task_id
            || ctx.profile_id != self.policy.profile_id
            || ctx.generation != 1
            || [
                &ctx.run_id,
                &ctx.request_id,
                &ctx.invocation_id,
                &ctx.attempt_id,
            ]
            .iter()
            .any(|s| !identifier(s))
        {
            return Err(denied());
        }
        Ok(())
    }
    fn parse(&self, call: &ToolCall) -> Result<Option<SessionCall>> {
        if !identifier(&call.id) || call.arguments.len() > 64 * 1024 {
            return Err(denied());
        }
        let value = melissa_model_gateway::strict_json(&call.arguments).map_err(|_| denied())?;
        if call.name == "code_result_page" {
            let page: PageCall = serde_json::from_value(value)?;
            self.page_authority(&page)?;
            return Ok(None);
        }
        if call.name == "code_debug_command" {
            let wire: SessionCall = serde_json::from_value(value)?;
            let s = self.session.as_ref().ok_or_else(denied)?;
            if s.id() != wire.session_id || matches!(wire.operation, DebugCommand::Start {}) {
                return Err(denied());
            }
            let op = self
                .policy
                .operations
                .values()
                .find(|o| matches!(o, CodeOperation::Debug { .. }))
                .ok_or_else(denied)?;
            self.authority(op)?;
            return Ok(Some(wire));
        }
        if self.session.is_some() {
            return Err(Error::Invalid(
                "close the active debug session before another procedure",
            ));
        }
        let op = self.policy.operations.get(&call.name).ok_or_else(denied)?;
        self.authority(op)?;
        if value != serde_json::to_value(op)? {
            return Err(Error::Invalid(
                "exact host registered procedure arguments required",
            ));
        }
        Ok(None)
    }
    fn page_authority(&self, page: &PageCall) -> Result {
        let op = self.results.get(&page.artifact_id).ok_or_else(denied)?;
        self.authority(op)?;
        if page.max_bytes == 0
            || page.max_bytes > 65536
            || !self
                .catalog
                .profiles
                .get(&self.policy.profile_id)
                .is_some_and(|p| p.tool_ids.iter().any(|x| x == "fs.read"))
        {
            return Err(denied());
        }
        Ok(())
    }
    fn broker(
        &self,
        op: &CodeOperation,
        req: &ContainerRequest,
        snapshot: &Snapshot,
    ) -> Result<(
        ContainerBroker,
        melissa_execution_broker::container_policy::SignedContainerPermit,
    )> {
        self.authority(op)?;
        let mut policy = self.policy.process_policy.clone().ok_or_else(denied)?;
        let now = unix_ms()?;
        let task = self.store.journal().task(&self.policy.task_id)?;
        let expires = now
            .checked_add(req.limits.wall_time_ms)
            .ok_or_else(denied)?
            .min(self.policy.expires_at_ms);
        policy.grants.clear();
        policy.control_grants.clear();
        policy.allowed_env_names = req.env.keys().cloned().collect();
        policy.grants.insert(
            self.policy.authorization_ref.clone(),
            AuthorityGrant {
                authorization_ref: self.policy.authorization_ref.clone(),
                task_id: self.policy.task_id.clone(),
                task_digest: authenticated_digest(&task.contract)
                    .map_err(melissa_execution_broker::BrokerError::from)?,
                principal_id: self.policy.principal_id.clone(),
                profile_id: self.policy.profile_id.clone(),
                resource_id: self.policy.resource_id.clone(),
                process_digest: container_execution_digest(
                    req,
                    &snapshot.digest().map_err(|_| denied())?,
                )
                .map_err(melissa_execution_broker::BrokerError::from)?,
                allow_monitored_disk: policy.allow_monitored_disk,
                allow_monitored_cpu: policy.allow_monitored_cpu,
                allowed_effects: task.contract.allowed_effects.iter().cloned().collect(),
                not_before_unix_ms: now,
                expires_at_unix_ms: expires,
            },
        );
        let b = ContainerBroker::new(
            self.store.connect()?,
            self.catalog.clone(),
            self.policy.resource_id.clone(),
            policy,
        )?;
        let token = token()?;
        let permit = b.issue_permit(
            &self.policy.task_id,
            req.clone(),
            snapshot,
            PermitRequest {
                permit_id: format!("permit:code06:{token}"),
                nonce: format!("nonce:code06:{token}"),
                principal_id: self.policy.principal_id.clone(),
                profile_id: self.policy.profile_id.clone(),
                resource_id: self.policy.resource_id.clone(),
                authorization_ref: self.policy.authorization_ref.clone(),
                not_before_unix_ms: now,
                expires_at_unix_ms: expires,
            },
        )?;
        Ok((b, permit))
    }
    fn execute(
        &mut self,
        call: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Result<ToolExecution> {
        self.context(&ctx)?;
        let command = self.parse(&call)?;
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Invalid("CODE-06 tool cancelled before dispatch"));
        }
        if call.name == "code_result_page" {
            let page: PageCall = serde_json::from_str(&call.arguments)?;
            self.page_authority(&page)?;
            let bytes = self.store.get_artifact(&ctx.task_id, &page.artifact_id)?;
            let start = usize::try_from(page.offset).map_err(|_| denied())?;
            if start > bytes.len() {
                return Err(denied());
            }
            let end = start
                .saturating_add(page.max_bytes as usize)
                .min(bytes.len());
            let value = json!({"schema_version":"melissa.code06-result-page/v1","artifact_id":page.artifact_id,"offset":start,"next_offset":end,"total_bytes":bytes.len(),"digest":crate::full::digest(&bytes),"data_hex":crate::hex(&bytes[start..end]),"complete":end==bytes.len(),"historical_observation":true,"task_completed":false});
            let id = format!("{}:code06-page", ctx.invocation_id);
            put(
                &mut self.store,
                &ctx.task_id,
                &id,
                "code06.result-page",
                "application/json",
                &serde_json::to_vec(&value)?,
            )
            .map_err(|e| match e {
                Error::AfterDispatch(inner) => *inner,
                e => e,
            })?;
            return Ok(ToolExecution {
                content: value.to_string(),
                success: true,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: vec![page.artifact_id, id],
            });
        }
        if let Some(wire) = command {
            let parent = self.session_context.as_ref().ok_or_else(denied)?;
            let id = format!("{}:debug-call", ctx.invocation_id);
            put(
                &mut self.store,
                &ctx.task_id,
                &id,
                "debug.model-call",
                "application/json",
                &serde_json::to_vec(
                    &json!({"call_id":call.id,"name":call.name,"arguments":call.arguments,"run":ctx.run_id,"request":ctx.request_id,"parent_invocation":parent.invocation_id,"parent_attempt":parent.attempt_id}),
                )?,
            )?;
            let closed = matches!(wire.operation, DebugCommand::Close {});
            let reply = self
                .session
                .as_mut()
                .ok_or_else(denied)?
                .command(wire.operation)?;
            let mut refs = vec![id];
            let value = if closed {
                let s = self.session.take().ok_or_else(denied)?;
                self.session_context.take();
                if let Ok(mut active) = self.active_cancel.lock() {
                    active.take();
                }
                let outcome = s.finish()?;
                refs.extend(outcome.artifact_refs);
                json!({"reply":reply,"session_id":outcome.session_id,"success":outcome.success,"binary_bytes_authenticated":outcome.binary_bytes_authenticated,"source_current":outcome.host_source_current,"protected_acceptance":false,"task_completed":false})
            } else {
                json!({"session_id":wire.session_id,"reply":reply,"protected_acceptance":false,"task_completed":false})
            };
            let result_id = format!("{}:debug-tool-result", ctx.invocation_id);
            put(
                &mut self.store,
                &ctx.task_id,
                &result_id,
                "debug.model-result",
                "application/json",
                &serde_json::to_vec(&value)?,
            )
            .map_err(|e| Error::AfterDispatch(Box::new(e)))?;
            refs.push(result_id);
            let success = reply.ok && (!closed || value["success"] == true);
            return Ok(ToolExecution {
                content: value.to_string(),
                success,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: refs,
            });
        }
        let op = self
            .policy
            .operations
            .get(&call.name)
            .ok_or_else(denied)?
            .clone();
        let source = self.repo.snapshot(&cancel)?;
        let identity = InvocationIdentity {
            invocation_id: ctx.invocation_id.clone(),
            attempt_id: ctx.attempt_id.clone(),
            generation: 1,
            idempotency_key: None,
        };
        match &op {
            CodeOperation::Procedure {
                language,
                operation,
                harness,
            } => {
                let plan = ProcedurePlan::prepare(
                    &self.repo,
                    &source,
                    *language,
                    operation.clone(),
                    harness.as_ref(),
                    self.policy.limits.clone(),
                    &cancel,
                )?;
                let result = crate::semantic_service::execute(
                    self,
                    &op,
                    crate::semantic_service::Plan::Procedure(&plan),
                    &call,
                    &ctx,
                    cancel,
                )?;
                self.results.insert(
                    format!("{}:semantic-service-result", ctx.invocation_id),
                    op.clone(),
                );
                Ok(result)
            }
            CodeOperation::Semantic {
                language,
                query,
                build_scripts,
            } => {
                let plan = SemanticPlan::prepare(
                    &self.repo,
                    &source,
                    *language,
                    query.clone(),
                    *build_scripts,
                    self.policy.limits.clone(),
                    &cancel,
                )?;
                let result = crate::semantic_service::execute(
                    self,
                    &op,
                    crate::semantic_service::Plan::Semantic(&plan),
                    &call,
                    &ctx,
                    cancel,
                )?;
                self.results.insert(
                    format!("{}:semantic-service-result", ctx.invocation_id),
                    op.clone(),
                );
                Ok(result)
            }
            CodeOperation::Debug {
                language,
                entry,
                breakpoints,
                expected_binary_sha256,
            } => {
                let plan = DebugPlan::prepare(
                    &self.repo,
                    &source,
                    *language,
                    entry.clone(),
                    breakpoints.clone(),
                    expected_binary_sha256.clone(),
                    self.policy.limits.clone(),
                    &cancel,
                )?;
                let (b, p) = self.broker(&op, plan.request(), plan.snapshot())?;
                *self.active_cancel.lock().map_err(|_| denied())? = Some(cancel.clone());
                if self.revoked.load(Ordering::Acquire) {
                    cancel.store(true, Ordering::Release);
                }
                let s = plan.start(
                    self.repo.clone(),
                    Arc::new(Mutex::new(b)),
                    ctx.task_id.clone(),
                    p,
                    identity,
                    cancel,
                )?;
                let reply = s.last_reply().cloned().ok_or_else(denied)?;
                let id = s.id().to_owned();
                if !reply.ok {
                    let result = s.finish()?;
                    if let Ok(mut active) = self.active_cancel.lock() {
                        active.take();
                    }
                    return Ok(ToolExecution {
                        content: json!({"session_id":id,"reply":reply,"task_completed":false})
                            .to_string(),
                        success: false,
                        cancelled: false,
                        requires_reconciliation: result.execution.requires_reconciliation,
                        artifact_refs: result.artifact_refs,
                    });
                }
                self.session = Some(s);
                self.session_context = Some(ctx);
                Ok(ToolExecution {
                    content: json!({"session_id":id,"reply":reply,"task_completed":false})
                        .to_string(),
                    success: true,
                    cancelled: false,
                    requires_reconciliation: false,
                    artifact_refs: vec![],
                })
            }
        }
    }
}
pub(crate) fn token() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| denied())?;
    Ok(blake3::hash(&b).to_hex().to_string())
}
impl CodeDispatcher {
    pub fn new(
        repo: Repository,
        store: LocalStore,
        catalog: Catalog,
        policy: CodeToolPolicy,
    ) -> Result<Self> {
        if [
            &policy.task_id,
            &policy.profile_id,
            &policy.principal_id,
            &policy.resource_id,
            &policy.authorization_ref,
        ]
        .iter()
        .any(|s| !identifier(s))
            || policy.operations.is_empty()
            || policy.operations.len() > 32
            || policy.operations.keys().any(|s| {
                !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || s == "code_debug_command"
                    || s == "code_result_page"
                    || s.len() > 64
            })
            || policy
                .operations
                .values()
                .filter(|o| matches!(o, CodeOperation::Debug { .. }))
                .count()
                > 1
        {
            return Err(denied());
        }
        ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: crate::toolchain::COMPLETE_IMAGE.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec![],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits: policy.limits.clone(),
        }
        .validate()
        .map_err(|_| denied())?;
        let revoked = Arc::new(AtomicBool::new(false));
        let active_cancel = Arc::new(Mutex::new(None));
        let h = Host {
            repo: Arc::new(repo),
            store,
            catalog,
            policy,
            revoked: revoked.clone(),
            session: None,
            session_context: None,
            active_cancel: active_cancel.clone(),
            results: BTreeMap::new(),
        };
        for op in h.policy.operations.values() {
            h.authority(op)?;
        }
        Ok(Self {
            host: Arc::new(Mutex::new(h)),
            revoked,
            active_cancel,
        })
    }
    pub fn revoke(&self) {
        self.revocation_handle().revoke();
    }
    pub fn revocation_handle(&self) -> CodeRevocation {
        CodeRevocation {
            revoked: self.revoked.clone(),
            active_cancel: self.active_cancel.clone(),
        }
    }
}
impl ToolDispatcher for CodeDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(h) = self.host.lock() else {
            return vec![];
        };
        if !h.policy.operations.values().any(|o| h.authority(o).is_ok()) {
            return vec![];
        }
        if h.session.is_some() {
            return vec![BoundTool{canonical_id:"code.diagnostics".into(),definition:ToolDefinition{name:"code_debug_command".into(),description:"Operate the active owned DAP session. Use its session_id and only returned stop-scoped handles. Frame handles come only from stackFrames or inspect.frame; breakpoint IDs are never frame handles. Step/resume invalidates prior handles. Close always when done. No evaluate, arbitrary commands, host attach or authority changes.".into(),parameters:debug_schema(),strict:false}}];
        }
        let mut definitions:Vec<_>=h.policy.operations.iter().filter(|(_,o)|h.authority(o).is_ok()).map(|(name,o)|BoundTool{canonical_id:o.canonical().into(),definition:ToolDefinition{name:name.clone(),description:format!("Run this exact host registered CODE-06 procedure: {}. Supply this object directly. The private worker uses a pinned SDK, captured current source and bounded authority. Raw logs/test output are untrusted observations; task acceptance is separate. Debug start returns a session_id; use code_debug_command to inspect/step/close.",serde_json::to_value(o).unwrap()),parameters:exact(&serde_json::to_value(o).unwrap()),strict:false}}).collect();
        if h.policy
            .operations
            .values()
            .any(|o| matches!(o, CodeOperation::Debug { .. }) && h.authority(o).is_ok())
        {
            definitions.push(BoundTool{canonical_id:"code.diagnostics".into(),definition:ToolDefinition{name:"code_debug_command".into(),description:"After a successful debug start, operate that exact session_id using returned stop-scoped handles. Frame handles come only from stackFrames or inspect.frame, never breakpoint IDs. Start is a separate tool. Close when done; no evaluate, arbitrary expression or attach.".into(),parameters:debug_schema(),strict:false}});
        }
        if h.catalog
            .profiles
            .get(&h.policy.profile_id)
            .is_some_and(|p| p.tool_ids.iter().any(|x| x == "fs.read"))
        {
            definitions.push(BoundTool{canonical_id:"fs.read".into(),definition:ToolDefinition{name:"code_result_page".into(),description:"Read an exact byte page of a normalized CODE-06 result artifact returned in this task. data_hex preserves UTF-8 boundaries/bytes without loss. Continue with next_offset until complete. Historical observations never accept a task.".into(),parameters:json!({"type":"object","properties":{"artifact_id":{"type":"string"},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":65536}},"required":["artifact_id","offset","max_bytes"],"additionalProperties":false}),strict:false}});
        }
        definitions
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.host
            .lock()
            .map_err(|_| GatewayError::invalid("CODE-06 host lock"))?
            .parse(c)
            .map(|_| ())
            .map_err(err)
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
            match tokio::task::spawn_blocking(move||h.lock().map_err(|_|denied())?.execute(c,ctx,cancel)).await {
                Ok(Ok(r))=>Ok(r),Ok(Err(Error::AfterDispatch(_)))|Err(_)=>Ok(ToolExecution{content:json!({"status":"outcome_unknown","automatic_retry_allowed":false,"task_completed":false}).to_string(),success:false,cancelled:false,requires_reconciliation:true,artifact_refs:vec![]}),
                Ok(Err(e))=>Err(err(e)),
            }
        })
    }
}
fn exact(value: &Value) -> Value {
    match value {
        Value::Object(o) => {
            json!({"type":"object","properties":o.iter().map(|(k,v)|(k.clone(),exact(v))).collect::<BTreeMap<_,_>>(),"required":o.keys().collect::<Vec<_>>(),"additionalProperties":false})
        }
        Value::Array(a) => {
            json!({"type":"array","items":{},"const":value,"minItems":a.len(),"maxItems":a.len()})
        }
        Value::String(_) => json!({"type":"string","const":value}),
        Value::Bool(_) => json!({"type":"boolean","const":value}),
        Value::Number(_) => json!({"type":"integer","const":value}),
        Value::Null => json!({"type":"null","const":null}),
    }
}
fn debug_schema() -> Value {
    let handle = |kind: &str| json!({"type":"object","properties":{"session_id":{"type":"string"},"epoch":{"type":"integer","minimum":0},"kind":{"type":"string","enum":[kind]},"id":{"type":"integer"}},"required":["session_id","epoch","kind","id"],"additionalProperties":false});
    let variant = |command: &str, extra: Value| {
        let mut p = serde_json::Map::new();
        p.insert("command".into(), json!({"type":"string","enum":[command]}));
        if let Some(o) = extra.as_object() {
            p.extend(o.clone());
        }
        let keys = p.keys().cloned().collect::<Vec<_>>();
        json!({"type":"object","properties":p,"required":keys,"additionalProperties":false})
    };
    let mut variants = vec![];
    for name in [
        "stack", "next", "step_in", "step_out", "continue", "pause", "close",
    ] {
        variants.push(variant(name, json!({})));
    }
    variants.extend([variant("inspect",json!({"count":{"type":"integer","minimum":1,"maximum":100}})),variant("wait",json!({"timeout_ms":{"type":"integer","minimum":1,"maximum":30000}})),variant("scopes",json!({"frame":handle("frame")})),variant("variables",json!({"reference":handle("variables"),"start":{"type":"integer","minimum":0},"count":{"type":"integer","minimum":1,"maximum":100}})),variant("breakpoints",json!({"breakpoints":{"type":"array","maxItems":128,"items":{"type":"object","properties":{"path":{"type":"string"},"line":{"type":"integer","minimum":1}},"required":["path","line"],"additionalProperties":false}}}))]);
    json!({"type":"object","properties":{"session_id":{"type":"string"},"operation":{"oneOf":variants}},"required":["session_id","operation"],"additionalProperties":false})
}
