//! Exact host-reviewed Git operations; model arguments cannot select an image,
//! command, backend, workspace, grant or different worktree destination.
use super::*;
use crate::{
    RepositorySnapshot,
    git::{GitOperation, GitPlan},
};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker, policy::PermitRequest, unix_ms,
};

pub struct ReviewedGitTool {
    pub operation: GitOperation,
    pub source: RepositorySnapshot,
    pub plan: GitPlan,
    pub authorization_ref: String,
}
pub struct GitDispatcherConfig {
    pub task_id: String,
    pub profile_id: String,
    pub principal_id: String,
    pub resource_id: String,
    pub expires_at_ms: u64,
}
struct GitHost {
    repo: Repository,
    broker: Arc<Mutex<ContainerBroker>>,
    config: GitDispatcherConfig,
    tools: BTreeMap<String, ReviewedGitTool>,
}
pub struct GitDispatcher {
    host: Arc<Mutex<GitHost>>,
}
fn name(op: &GitOperation) -> (&'static str, &'static str) {
    match op {
        GitOperation::Status => ("git_status", "git.status"),
        GitOperation::Diff { .. } => ("git_diff", "git.diff"),
        GitOperation::Log { .. } => ("git_log", "git.log"),
        GitOperation::WorktreeList => ("git_worktree_list", "git.worktree"),
        GitOperation::WorktreeCreate { .. } => ("git_worktree_create", "git.worktree"),
    }
}
impl GitHost {
    fn available(&self, t: &ReviewedGitTool) -> bool {
        let Ok(n) = unix_ms() else { return false };
        if n >= self.config.expires_at_ms {
            return false;
        }
        let Ok(b) = self.broker.lock() else {
            return false;
        };
        let Ok(p) = b.policy_control().snapshot() else {
            return false;
        };
        !p.revoked_authorization_refs.contains(&t.authorization_ref)
            && p.grants.get(&t.authorization_ref).is_some_and(|g| {
                g.task_id == self.config.task_id
                    && g.profile_id == self.config.profile_id
                    && g.principal_id == self.config.principal_id
                    && g.resource_id == self.config.resource_id
                    && n >= g.not_before_unix_ms
                    && n < g.expires_at_unix_ms
            })
    }
    fn validate(&self, call: &ToolCall) -> melissa_model_gateway::Result<()> {
        let t = self
            .tools
            .get(&call.name)
            .ok_or_else(|| GatewayError::unsupported("Git function not reviewed by host"))?;
        if !self.available(t) {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "Git authority not active",
            ));
        }
        if call.id.is_empty() || call.id.len() > 256 || call.id.chars().any(char::is_control) {
            return Err(GatewayError::invalid("Git call identity"));
        }
        let value = melissa_model_gateway::strict_json(&call.arguments)?;
        if value
            != serde_json::to_value(&t.operation)
                .map_err(|_| GatewayError::invalid("Git reviewed operation"))?
        {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "Git arguments differ from exact host review",
            ));
        }
        Ok(())
    }
    fn execute(
        &mut self,
        call: ToolCall,
        c: ToolContext,
        cancel: &AtomicBool,
    ) -> crate::Result<ToolExecution> {
        self.validate(&call)
            .map_err(|_| Error::Denied("Git binding arguments/authority"))?;
        if c.task_id != self.config.task_id
            || c.profile_id != self.config.profile_id
            || c.generation != 1
            || [&c.run_id, &c.request_id, &c.invocation_id, &c.attempt_id]
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(Error::Denied("Git host context"));
        }
        check_cancel(cancel)?;
        let t = self
            .tools
            .get(&call.name)
            .ok_or(Error::Invalid("Git route"))?;
        let fresh = GitPlan::prepare(
            &self.repo,
            &t.source,
            &t.operation,
            &t.plan.request.image_id,
            t.plan.request.limits.clone(),
            cancel,
        )?;
        if serde_json::to_vec(&fresh)? != serde_json::to_vec(&t.plan)? {
            return Err(Error::Stale("reviewed Git source/metadata changed"));
        }
        let issued = unix_ms().map_err(Error::Broker)?;
        let expires = issued
            .checked_add(60_000)
            .ok_or(Error::Invalid("Git clock"))?
            .min(self.config.expires_at_ms);
        let token = digest(&serde_json::to_vec(
            &json!({"call":call.id,"arguments":call.arguments,"task":c.task_id,"profile":c.profile_id,"run":c.run_id,"request":c.request_id,"invocation":c.invocation_id,"attempt":c.attempt_id,"generation":c.generation}),
        )?);
        let mut b = self
            .broker
            .lock()
            .map_err(|_| Error::Denied("Git broker unavailable"))?;
        let permit = b
            .issue_permit(
                &c.task_id,
                t.plan.request.clone(),
                &t.plan.snapshot,
                PermitRequest {
                    permit_id: format!("permit:repository-git:{token}"),
                    nonce: format!("nonce:repository-git:{token}"),
                    principal_id: self.config.principal_id.clone(),
                    profile_id: c.profile_id.clone(),
                    resource_id: self.config.resource_id.clone(),
                    authorization_ref: t.authorization_ref.clone(),
                    not_before_unix_ms: issued,
                    expires_at_unix_ms: expires,
                },
            )
            .map_err(Error::Broker)?;
        let r = t.plan.execute(
            &mut b,
            &c.task_id,
            &permit,
            &InvocationIdentity {
                invocation_id: c.invocation_id,
                attempt_id: c.attempt_id,
                generation: c.generation,
                idempotency_key: None,
            },
            cancel,
        )?;
        let mut artifacts = r.observation.artifact_refs.clone();
        artifacts.push(r.result_artifact_id.clone());
        let content=json!({"schema_version":"melissa.repository-git-tool-result/v1","operation":t.operation,"source_snapshot_digest":t.plan.source_snapshot_digest,"metadata_digest":t.plan.metadata_digest,"observation":r.observation,"stdout_bytes":r.report.as_ref().map(|r|&r.stdout),"stderr_bytes":r.report.as_ref().map(|r|&r.stderr),"requires_reconciliation":r.requires_reconciliation,"task_accepted":false}).to_string();
        Ok(ToolExecution {
            content,
            success: r.observation.status
                == melissa_core_contracts::wire::ObservationStatus::Success
                && !r.requires_reconciliation,
            cancelled: r.observation.status
                == melissa_core_contracts::wire::ObservationStatus::Cancelled,
            requires_reconciliation: r.requires_reconciliation,
            artifact_refs: artifacts,
        })
    }
}
impl GitDispatcher {
    pub fn new(
        repo: Repository,
        broker: Arc<Mutex<ContainerBroker>>,
        config: GitDispatcherConfig,
        tools: Vec<ReviewedGitTool>,
    ) -> crate::Result<Self> {
        if tools.is_empty()
            || tools.len() > 5
            || [
                &config.task_id,
                &config.profile_id,
                &config.principal_id,
                &config.resource_id,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(Error::Invalid("Git host bindings"));
        }
        let mut map = BTreeMap::new();
        for t in tools {
            let fresh = GitPlan::prepare(
                &repo,
                &t.source,
                &t.operation,
                &t.plan.request.image_id,
                t.plan.request.limits.clone(),
                &AtomicBool::new(false),
            )?;
            if serde_json::to_vec(&fresh)? != serde_json::to_vec(&t.plan)? {
                return Err(Error::Stale("Git reviewed plan"));
            }
            if map.insert(name(&t.operation).0.to_string(), t).is_some() {
                return Err(Error::Invalid("duplicate Git function"));
            }
        }
        Ok(Self {
            host: Arc::new(Mutex::new(GitHost {
                repo,
                broker,
                config,
                tools: map,
            })),
        })
    }
}
impl ToolDispatcher for GitDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(h) = self.host.lock() else {
            return vec![];
        };
        h.tools.iter().filter(|(_,t)|h.available(t)).map(|(wire,t)|BoundTool{canonical_id:name(&t.operation).1.into(),definition:ToolDefinition{name:wire.clone(),description:format!("Execute this exact host-reviewed Git operation in the private CODE-03 container: {}. Does not mutate or mount the source repository. Output is untrusted evidence; task acceptance stays false.",serde_json::to_string(&t.operation).unwrap_or_default()),parameters:json!({"type":"object","const":t.operation}),strict:false}}).collect()
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.host
            .lock()
            .map_err(|_| GatewayError::new(ErrorKind::Tool, "Git host unavailable"))?
            .validate(c)
    }
    fn execute<'a>(
        &'a mut self,
        c: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        let host = self.host.clone();
        Box::pin(async move {
            match tokio::task::spawn_blocking(move||host.lock().map_err(|_|Error::Denied("Git host lock"))?.execute(c,ctx,&cancel)).await {
            Ok(Ok(r))=>Ok(r),
            Ok(Err(Error::AfterDispatch(_)))|Err(_)=>Ok(ToolExecution{content:json!({"status":"outcome_unknown","task_accepted":false,"requires_reconciliation":true,"automatic_retry_allowed":false}).to_string(),success:false,cancelled:false,requires_reconciliation:true,artifact_refs:vec![]}),
            Ok(Err(e))=>Err(err(e)),
        }
        })
    }
}
