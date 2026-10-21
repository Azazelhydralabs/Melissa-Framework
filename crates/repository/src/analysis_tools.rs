//! Gateway bindings for exact reviewed read-only language/search workers.
use super::*;
use crate::analysis::{AnalysisPlan, AnalysisQuery, LspMethod};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker, policy::PermitRequest, unix_ms,
};
pub struct ReviewedAnalysisTool {
    pub plan: AnalysisPlan,
    pub authorization_ref: String,
}
struct AnalysisHost {
    repo: Repository,
    broker: Arc<Mutex<ContainerBroker>>,
    config: GitDispatcherConfig,
    tools: BTreeMap<String, ReviewedAnalysisTool>,
}
pub struct AnalysisDispatcher {
    host: Arc<Mutex<AnalysisHost>>,
}
fn wire(q: &AnalysisQuery) -> (&'static str, &'static str) {
    match q {
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
    }
}
impl AnalysisHost {
    fn active(&self, t: &ReviewedAnalysisTool) -> bool {
        let Ok(n) = unix_ms() else { return false };
        let Ok(b) = self.broker.lock() else {
            return false;
        };
        let Ok(p) = b.policy_control().snapshot() else {
            return false;
        };
        let Ok(task) = b.store().journal().task(&self.config.task_id) else {
            return false;
        };
        n < self.config.expires_at_ms
            && task.record.state == TaskState::Running
            && task.record.unknown_invocation_id.is_none()
            && task
                .contract
                .allowed_effects
                .iter()
                .any(|e| e == "workspace.read")
            && !p.revoked_authorization_refs.contains(&t.authorization_ref)
            && p.grants.get(&t.authorization_ref).is_some_and(|g| {
                g.task_id == self.config.task_id
                    && g.profile_id == self.config.profile_id
                    && g.principal_id == self.config.principal_id
                    && g.resource_id == self.config.resource_id
                    && n >= g.not_before_unix_ms
                    && n < g.expires_at_unix_ms
            })
    }
    fn validate(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        let t = self
            .tools
            .get(&c.name)
            .ok_or_else(|| GatewayError::unsupported("unreviewed analysis tool"))?;
        if !self.active(t) {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "analysis authority inactive",
            ));
        }
        if c.id.is_empty()
            || c.id.len() > 256
            || c.id.chars().any(char::is_control)
            || melissa_model_gateway::strict_json(&c.arguments)?
                != serde_json::to_value(&t.plan.query)
                    .map_err(|_| GatewayError::invalid("query encoding"))?
        {
            return Err(GatewayError::invalid(
                "exact reviewed analysis query required",
            ));
        }
        Ok(())
    }
    fn execute(
        &mut self,
        c: ToolCall,
        ctx: ToolContext,
        cancel: &AtomicBool,
    ) -> crate::Result<ToolExecution> {
        self.validate(&c)
            .map_err(|_| Error::Denied("analysis call/grant"))?;
        if ctx.task_id != self.config.task_id
            || ctx.profile_id != self.config.profile_id
            || ctx.generation != 1
            || [
                &ctx.run_id,
                &ctx.request_id,
                &ctx.invocation_id,
                &ctx.attempt_id,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(Error::Denied("analysis context"));
        }
        check_cancel(cancel)?;
        let t = self
            .tools
            .get(&c.name)
            .ok_or(Error::Invalid("analysis route"))?;
        let fresh = AnalysisPlan::prepare(
            &self.repo,
            &t.plan.source,
            t.plan.query.clone(),
            &t.plan.request.image_id,
            t.plan.request.limits.clone(),
            cancel,
        )?;
        if fresh.digest()? != t.plan.digest()? {
            return Err(Error::Stale("analysis reviewed plan"));
        }
        let n = unix_ms().map_err(Error::Broker)?;
        let token = digest(&serde_json::to_vec(
            &json!({"call":c.id,"arguments":c.arguments,"task":ctx.task_id,"profile":ctx.profile_id,"run":ctx.run_id,"request":ctx.request_id,"invocation":ctx.invocation_id,"attempt":ctx.attempt_id}),
        )?);
        let mut b = self
            .broker
            .lock()
            .map_err(|_| Error::Denied("analysis broker unavailable"))?;
        let permit = b
            .issue_permit(
                &ctx.task_id,
                t.plan.request.clone(),
                &t.plan.snapshot,
                PermitRequest {
                    permit_id: format!("permit:analysis:{token}"),
                    nonce: format!("nonce:analysis:{token}"),
                    principal_id: self.config.principal_id.clone(),
                    profile_id: ctx.profile_id.clone(),
                    resource_id: self.config.resource_id.clone(),
                    authorization_ref: t.authorization_ref.clone(),
                    not_before_unix_ms: n,
                    expires_at_unix_ms: n.saturating_add(90_000).min(self.config.expires_at_ms),
                },
            )
            .map_err(Error::Broker)?;
        let r = t.plan.execute(
            &self.repo,
            &mut b,
            &ctx.task_id,
            &permit,
            &InvocationIdentity {
                invocation_id: ctx.invocation_id.clone(),
                attempt_id: ctx.attempt_id,
                generation: 1,
                idempotency_key: None,
            },
            cancel,
        )?;
        if r.requires_reconciliation {
            return Err(Error::AfterDispatch(Box::new(Error::Denied(
                "analysis worker needs reconciliation",
            ))));
        }
        let mut refs = r.observation.artifact_refs.clone();
        refs.push(r.result_artifact_id.clone());
        let Some(report) = r.report.as_ref() else {
            return Ok(ToolExecution {
                content: json!({"observation":r.observation,"task_accepted":false}).to_string(),
                success: false,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: refs,
            });
        };
        if r.observation.status != melissa_core_contracts::wire::ObservationStatus::Success {
            return Ok(ToolExecution{content:json!({"observation":r.observation,"stderr_bytes":report.stderr,"task_accepted":false}).to_string(),success:false,cancelled:r.observation.status==melissa_core_contracts::wire::ObservationStatus::Cancelled,requires_reconciliation:false,artifact_refs:refs});
        }
        let result = t.plan.decode(&self.repo, report, cancel)?;
        let full = serde_json::to_string(&result)?;
        let id = format!("{}:analysis-result", ctx.invocation_id);
        let mut store = b.store().connect()?;
        store.put_artifact(
            &ArtifactRequest {
                artifact_id: id.clone(),
                task_id: ctx.task_id,
                content_type: "application/json".into(),
                logical_type: "repository_tool_result".into(),
                schema_version: "melissa.repository-tool-evidence/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            full.as_bytes(),
        )?;
        refs.push(id.clone());
        let content = if full.len() > 768 * 1024 {
            json!({"delivery":"paged_result","artifact_id":id,"digest":digest(full.as_bytes()),"total_bytes":full.len(),"next_offset":0,"complete":false,"task_accepted":false}).to_string()
        } else {
            full
        };
        Ok(ToolExecution {
            content,
            success: true,
            cancelled: false,
            requires_reconciliation: false,
            artifact_refs: refs,
        })
    }
}
impl AnalysisDispatcher {
    pub fn new(
        repo: Repository,
        broker: Arc<Mutex<ContainerBroker>>,
        config: GitDispatcherConfig,
        tools: Vec<ReviewedAnalysisTool>,
    ) -> crate::Result<Self> {
        if tools.is_empty() || tools.len() > 4 {
            return Err(Error::Invalid("analysis bindings required"));
        }
        let mut map = BTreeMap::new();
        for t in tools {
            let fresh = AnalysisPlan::prepare(
                &repo,
                &t.plan.source,
                t.plan.query.clone(),
                &t.plan.request.image_id,
                t.plan.request.limits.clone(),
                &AtomicBool::new(false),
            )?;
            if fresh.digest()? != t.plan.digest()? {
                return Err(Error::Stale("analysis plan construction"));
            }
            if map.insert(wire(&t.plan.query).0.to_string(), t).is_some() {
                return Err(Error::Invalid("duplicate analysis function"));
            }
        }
        Ok(Self {
            host: Arc::new(Mutex::new(AnalysisHost {
                repo,
                broker,
                config,
                tools: map,
            })),
        })
    }
}
impl ToolDispatcher for AnalysisDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(h) = self.host.lock() else {
            return vec![];
        };
        h.tools.iter().filter(|(_,t)|h.active(t)).map(|(name,t)|BoundTool{canonical_id:wire(&t.plan.query).1.into(),definition:ToolDefinition{name:name.clone(),description:"Run this exact reviewed source-bound semantic LSP or ripgrep analysis inside the immutable isolated worker. Model output cannot change the query, grant, source, image or backend. Task acceptance remains false.".into(),parameters:json!({"type":"object","const":t.plan.query}),strict:false}}).collect()
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.host
            .lock()
            .map_err(|_| GatewayError::new(ErrorKind::Tool, "analysis host unavailable"))?
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
            match tokio::task::spawn_blocking(move||host.lock().map_err(|_|Error::Denied("analysis lock poisoned"))?.execute(c,ctx,&cancel)).await{Ok(Ok(r))=>Ok(r),Ok(Err(Error::AfterDispatch(_)))|Err(_)=>Ok(ToolExecution{content:json!({"status":"outcome_unknown","requires_reconciliation":true,"automatic_retry_allowed":false,"task_accepted":false}).to_string(),success:false,cancelled:false,requires_reconciliation:true,artifact_refs:vec![]}),Ok(Err(e))=>Err(err(e))}
        })
    }
}
