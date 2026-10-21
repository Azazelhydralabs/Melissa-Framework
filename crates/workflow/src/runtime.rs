//! Native Gateway driver and existing canonical task.spawn/status/wait/cancel
//! bindings. Only already validated nodes may be spawned. The factory is a
//! trusted host boundary selecting actual tools/permits and complete context.
use crate::{
    Kind, Result, digest, error,
    gate::{NodeDispatcher, SharedScheduler, lock},
    require,
    scheduler::{Phase, State, WorkPacket},
};
use melissa_core_contracts::catalog::Catalog;
use melissa_local_store::ArtifactRequest;
use melissa_model_gateway::{
    ErrorKind, GatewayError, ToolCall, ToolDefinition,
    agent_loop::{Gateway, RunSpec},
    schema, strict_json,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct PreparedRun {
    pub gateway: Gateway,
    pub spec: RunSpec,
    pub dispatcher: Box<dyn ToolDispatcher>,
}
pub type Factory = Arc<dyn Fn(&WorkPacket) -> Result<PreparedRun> + Send + Sync>;
#[derive(Clone)]
pub struct Runtime {
    pub scheduler: SharedScheduler,
    pub factory: Factory,
    pub lease_ms: u64,
}
struct Watch(Option<tokio::task::JoinHandle<()>>);
impl Watch {
    async fn stop(mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
            let _ = h.await;
        }
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(h) = &self.0 {
            h.abort();
        }
    }
}
impl Runtime {
    pub async fn resume(&self, node: &str) -> Result<State> {
        let packet = lock(&self.scheduler)?.resume_packet(node)?;
        let completed = {
            let s = lock(&self.scheduler)?;
            s.store()
                .artifact_metadata(
                    &packet.parent_task.task_id,
                    &format!("model-run:{}:result", packet.lease.run),
                )
                .is_ok()
        };
        if completed {
            return lock(&self.scheduler)?.complete_native(&packet.lease);
        }
        self.run_packet(&packet).await
    }
    pub async fn run(&self, node: &str) -> Result<State> {
        let packet = lock(&self.scheduler)?.acquire(node, "host:native-gateway", self.lease_ms)?;
        let result = self.run_packet(&packet).await;
        if result.is_err() {
            let mut s = lock(&self.scheduler)?;
            let state = s.state()?;
            if !state.cancel_requested
                && state
                    .slots
                    .get(&packet.node.id)
                    .is_some_and(|v| v.phase == Phase::Leased)
            {
                s.mark_uncertain(
                    &packet.lease,
                    "native node stopped; inspect owned effects before any replay",
                )?;
            }
        }
        result
    }
    async fn run_packet(&self, packet: &WorkPacket) -> Result<State> {
        let mut prepared = (self.factory)(packet)?;
        require(
            prepared.spec.task_id == packet.parent_task.task_id
                && prepared.spec.profile_id == packet.node.profile
                && prepared.spec.run_id == packet.lease.run
                && prepared.spec.output_schema.as_ref() == Some(&packet.node.output_schema),
            Kind::Authority,
            "prepared native run differs from exact handoff",
        )?;
        let user = strict_json(&prepared.spec.user_message)?;
        let handoff = if let Some(v) = user.get("user_request").and_then(Value::as_str) {
            strict_json(v)?
        } else {
            user.clone()
        };
        require(
            handoff == serde_json::to_value(packet)?,
            Kind::Stale,
            "native prompt omits or changes complete handoff",
        )?;
        if !packet.node.skills.is_empty() {
            require(
                complete_context(&user, &packet.node.skills)?,
                Kind::Invalid,
                "selected full skills/context were not assembled",
            )?;
        }
        let bytes = serde_json::to_vec(packet)?;
        let handoff_id = format!("workflow-handoff:{}", packet.lease.run);
        match prepared
            .gateway
            .store()
            .artifact_metadata(&packet.parent_task.task_id, &handoff_id)
        {
            Ok(_) => require(
                prepared
                    .gateway
                    .store()
                    .get_artifact(&packet.parent_task.task_id, &handoff_id)?
                    == bytes,
                Kind::Stale,
                "existing handoff bytes changed",
            )?,
            Err(melissa_local_store::StoreError::NotFound(_)) => {
                prepared.gateway.store_mut().put_artifact(
                    &ArtifactRequest {
                        artifact_id: handoff_id,
                        task_id: packet.parent_task.task_id.clone(),
                        content_type: "application/json".into(),
                        logical_type: "workflow.handoff".into(),
                        schema_version: packet.schema_version.clone(),
                        retain_until_ms: 0,
                        legal_hold: false,
                    },
                    &bytes,
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        let mut dispatcher =
            NodeDispatcher::new(self.scheduler.clone(), packet.clone(), prepared.dispatcher)?;
        let flag = lock(&self.scheduler)?.flag();
        let owner = self.scheduler.clone();
        let lease = packet.lease.clone();
        let cancel = flag.clone();
        let watcher = Watch(Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if lock(&owner).and_then(|s| s.check(&lease)).is_err() {
                    cancel.store(true, Ordering::Release);
                    break;
                }
            }
        })));
        lock(&self.scheduler)?.check(&packet.lease)?;
        let result = prepared
            .gateway
            .run(&prepared.spec, &mut dispatcher, flag)
            .await;
        watcher.stop().await;
        result?;
        let mut s = lock(&self.scheduler)?;
        if s.state()?.cancel_requested {
            return s.state();
        }
        s.complete_native(&packet.lease)
    }
    pub fn cancel(&self) -> Result<State> {
        lock(&self.scheduler)?.cancel()
    }
}

fn gateway(e: crate::Error) -> GatewayError {
    GatewayError::new(ErrorKind::Tool, e.to_string())
}
pub struct CoordinatorDispatcher {
    runtime: Runtime,
    profile: String,
}
impl CoordinatorDispatcher {
    pub fn new(runtime: Runtime, profile: String, catalog: &Catalog) -> Result<Self> {
        let s = lock(&runtime.scheduler)?;
        let p = catalog
            .profiles
            .get(&profile)
            .ok_or_else(|| error(Kind::Authority, "unknown workflow coordinator"))?;
        let parent = s.store().journal().task(s.task_id())?;
        require(
            parent.contract.selected_profile_ids.contains(&profile)
                && ["task.spawn", "task.status", "task.wait", "task.cancel"]
                    .iter()
                    .all(|id| p.tool_ids.iter().any(|v| v == id))
                && ["task.delegate", "task.read"].iter().all(|id| {
                    p.authority.capability_ceiling.iter().any(|v| v == id)
                        && parent.contract.allowed_effects.iter().any(|v| v == id)
                }),
            Kind::Authority,
            "coordinator lacks existing task delegation/read authority",
        )?;
        drop(s);
        Ok(Self { runtime, profile })
    }
    fn parameters(name: &str, nodes: Vec<String>) -> Value {
        match name {
            "task_spawn" => {
                json!({"type":"object","properties":{"node":{"type":"string","enum":nodes}},"required":["node"],"additionalProperties":false})
            }
            "task_wait" => {
                json!({"type":"object","properties":{"node":{"type":"string","enum":nodes},"wait_ms":{"type":"integer","minimum":1,"maximum":30000}},"required":["node","wait_ms"],"additionalProperties":false})
            }
            _ => {
                json!({"type":"object","properties":{},"required":[],"additionalProperties":false})
            }
        }
    }
}
impl ToolDispatcher for CoordinatorDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let nodes = lock(&self.runtime.scheduler)
            .and_then(|s| s.state())
            .map(|s| {
                s.plan
                    .nodes
                    .iter()
                    .map(|n| n.id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        [("task_spawn","task.spawn","Run one existing host-validated node with its exact handoff; dependencies and shared budget are enforced. Results are candidates, not protected acceptance."),("task_status","task.status","Read the durable workflow state and shared task ledger."),("task_wait","task.wait","Wait for an already running node; does not spawn or replay it."),("task_cancel","task.cancel","Request cancellation for this owned task tree; uncertain effects must still be reconciled.")].into_iter().map(|(wire,id,description)|BoundTool{canonical_id:id.into(),definition:ToolDefinition{name:wire.into(),description:description.into(),parameters:Self::parameters(wire,nodes.clone()),strict:true}}).collect()
    }
    fn validate_call(&self, call: &ToolCall) -> melissa_model_gateway::Result<()> {
        let d = self
            .definitions()
            .into_iter()
            .find(|d| d.definition.name == call.name)
            .ok_or_else(|| GatewayError::invalid("unknown workflow tool"))?;
        schema::validate_output(&d.definition.parameters, &call.arguments)?;
        Ok(())
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        Box::pin(async move {
            self.validate_call(&call)?;
            {
                let s = lock(&self.runtime.scheduler).map_err(gateway)?;
                require(
                    context.task_id == s.task_id() && context.profile_id == self.profile,
                    Kind::Authority,
                    "workflow call owner/profile mismatch",
                )
                .map_err(gateway)?;
            }
            if cancelled.load(Ordering::Acquire) && call.name != "task_cancel" {
                return Err(GatewayError::new(
                    ErrorKind::Cancelled,
                    "coordinator cancelled",
                ));
            }
            let args = strict_json(&call.arguments)?;
            let state = match call.name.as_str() {
                "task_spawn" => self
                    .runtime
                    .run(args["node"].as_str().expect("schema validated"))
                    .await
                    .map_err(gateway)?,
                "task_cancel" => self.runtime.cancel().map_err(gateway)?,
                "task_wait" => {
                    let node = args["node"].as_str().expect("schema validated");
                    let end = tokio::time::Instant::now()
                        + Duration::from_millis(
                            args["wait_ms"].as_u64().expect("schema validated"),
                        );
                    loop {
                        let state = lock(&self.runtime.scheduler)
                            .and_then(|s| s.state())
                            .map_err(gateway)?;
                        if state.slots[node].phase != Phase::Leased
                            || tokio::time::Instant::now() >= end
                            || cancelled.load(Ordering::Acquire)
                        {
                            break state;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                _ => lock(&self.runtime.scheduler)
                    .and_then(|s| s.state())
                    .map_err(gateway)?,
            };
            let s = lock(&self.runtime.scheduler).map_err(gateway)?;
            let budget = s
                .store()
                .journal()
                .model_budget(s.task_id())
                .map_err(crate::Error::from)
                .map_err(gateway)?;
            let output = json!({"schema_version":"melissa.workflow-observation/v1","state":state,"shared_budget":budget,"task_accepted":false,"protected_acceptance":false});
            let bytes = serde_json::to_vec(&output)
                .map_err(crate::Error::from)
                .map_err(gateway)?;
            let id = format!("{}:workflow-result", context.invocation_id);
            let task = s.task_id().to_string();
            let mut store = s
                .store()
                .connect()
                .map_err(crate::Error::from)
                .map_err(gateway)?;
            store
                .put_artifact(
                    &ArtifactRequest {
                        artifact_id: id.clone(),
                        task_id: task,
                        content_type: "application/json".into(),
                        logical_type: "workflow.tool_result".into(),
                        schema_version: "melissa.workflow-observation/v1".into(),
                        retain_until_ms: 0,
                        legal_hold: false,
                    },
                    &bytes,
                )
                .map_err(crate::Error::from)
                .map_err(gateway)?;
            let _content_digest = digest(&bytes);
            Ok(ToolExecution {
                content: String::from_utf8(bytes).expect("JSON UTF8"),
                success: true,
                cancelled: state.cancel_requested,
                requires_reconciliation: state
                    .slots
                    .values()
                    .any(|v| v.phase == Phase::NeedsReconciliation),
                artifact_refs: vec![id],
            })
        })
    }
}

// Assembly supplies seven mandatory host/source sections plus one full item
// for EACH selected pin. A multi-skill single-agent arm must retain them all.
fn complete_context(
    user: &Value,
    pins: &[melissa_core_contracts::design::SkillPin],
) -> Result<bool> {
    if user["selected_skill_pins"] != serde_json::to_value(pins)? {
        return Ok(false);
    }
    let Some(items) = user["context_sections"].as_array() else {
        return Ok(false);
    };
    if items.len() != 7 + pins.len()
        || !items.iter().all(|i| {
            i["full_content"] == true
                && i["content"]
                    .as_str()
                    .is_some_and(|s| i["payload_digest"] == digest(s.as_bytes()))
        })
    {
        return Ok(false);
    }
    for section in [
        "system_contract",
        "task_contract",
        "remaining_budget",
        "output_schema",
        "workspace_context",
        "evidence",
        "recent_observations",
    ] {
        if items.iter().filter(|i| i["section"] == section).count() != 1 {
            return Ok(false);
        }
    }
    Ok(pins.iter().all(|p| {
        items
            .iter()
            .filter(|i| {
                i["section"] == "relevant_skills"
                    && i["source"] == p.skill_id
                    && i["version"] == p.semantic_version
                    && i["source_digest"] == p.content_digest
            })
            .count()
            == 1
    }))
}
#[cfg(test)]
mod context_tests {
    use super::*;
    fn full() -> (Value, Vec<melissa_core_contracts::design::SkillPin>) {
        let pins = (0..3)
            .map(|n| melissa_core_contracts::design::SkillPin {
                skill_id: format!("skill:{n}"),
                semantic_version: "1.0.0".into(),
                content_digest: digest(format!("pin{n}").as_bytes()),
            })
            .collect::<Vec<_>>();
        let mut items=["system_contract","task_contract","remaining_budget","output_schema","workspace_context","evidence","recent_observations"].into_iter().map(|section|json!({"section":section,"full_content":true,"content":"complete host content","payload_digest":digest(b"complete host content")})).collect::<Vec<_>>();
        items.extend(pins.iter().map(|p|json!({"section":"relevant_skills","source":p.skill_id,"version":p.semantic_version,"source_digest":p.content_digest,"full_content":true,"content":"entire pinned material","payload_digest":digest(b"entire pinned material")})));
        (
            json!({"selected_skill_pins":pins,"context_sections":items}),
            pins,
        )
    }
    #[test]
    fn multi_skill_single_agent_preserves_all_full_context_items() {
        let (v, p) = full();
        assert!(complete_context(&v, &p).unwrap());
    }
    #[test]
    fn omitted_or_substituted_selected_skill_is_rejected() {
        let (mut v, p) = full();
        v["context_sections"][8]["source_digest"] = json!(digest(b"wrong"));
        assert!(!complete_context(&v, &p).unwrap());
        let (mut v, p) = full();
        v["context_sections"].as_array_mut().unwrap().pop();
        assert!(!complete_context(&v, &p).unwrap());
    }
    #[test]
    fn summarized_or_duplicate_host_context_is_rejected() {
        let (mut v, p) = full();
        v["context_sections"][0]["full_content"] = json!(false);
        assert!(!complete_context(&v, &p).unwrap());
        let (mut v, p) = full();
        v["context_sections"][0]["content"] = json!("partial");
        assert!(!complete_context(&v, &p).unwrap());
        let (mut v, p) = full();
        v["context_sections"][0] = v["context_sections"][1].clone();
        assert!(!complete_context(&v, &p).unwrap());
    }
}
