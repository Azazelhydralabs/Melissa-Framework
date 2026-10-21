//! Public development tests of proposed files in an admitted C03 worker.
//! No golden implementation, private mutation, or acceptance oracle is present.
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_core_contracts::{catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker,
    container_policy::container_execution_digest, policy::*,
};
use melissa_local_store::{ArtifactRequest, LocalStore};
use melissa_model_gateway::{
    ErrorKind, GatewayError, Result, ToolCall, ToolDefinition,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Clone)]
pub struct CandidateTestConfig {
    pub task: TaskContractV1,
    pub profile: String,
    pub run: String,
    pub authorization: String,
    pub expires_at_ms: u64,
    pub image: String,
    pub python: String,
    pub public_source: Snapshot,
    pub function: String,
    pub fixed_solution: Option<Vec<u8>>,
    pub public_guard: Vec<u8>,
    pub policy: HostPolicy,
}
pub struct CandidateTests {
    store: LocalStore,
    catalog: Catalog,
    config: CandidateTestConfig,
}
fn denied(message: &str) -> GatewayError {
    GatewayError::new(ErrorKind::Authorization, message)
}
fn host_error(error: impl std::fmt::Display) -> GatewayError {
    GatewayError::new(
        ErrorKind::Store,
        format!(
            "public candidate test evidence failed; inspect native effect before any replay: {error}"
        ),
    )
}
const DRIVER:&[u8]=br#"from pathlib import Path
import json
policy={}
exec(compile(Path('public_blackbox_guard.py').read_text(encoding='utf-8'),'public_blackbox_guard.py','exec'),policy)
source=Path('solution.py').read_text(encoding='utf-8')
tests=Path('test_solution.py').read_text(encoding='utf-8')
policy['black_box'](tests)
implementation={'__name__':'owned_solution'}
exec(compile(source,'solution.py','exec'),implementation)
checks={'__name__':'owned_development_tests'}
exec(compile(tests,'test_solution.py','exec'),checks)
function=json.loads(Path('public_candidate_config.json').read_text())['function']
checks['test_candidate'](implementation[function])
print('CODE08_PUBLIC_SELFTEST_OK')
"#;
/// Exact public driver bytes for independent source-bound development audits.
pub fn public_driver_bytes() -> &'static [u8] {
    DRIVER
}
impl CandidateTests {
    pub fn new(store: LocalStore, catalog: Catalog, config: CandidateTestConfig) -> Result<Self> {
        let current = store
            .journal()
            .task(&config.task.task_id)
            .map_err(host_error)?;
        if serde_json::to_value(&current.contract).map_err(host_error)?
            != serde_json::to_value(&config.task).map_err(host_error)?
            || !config.task.selected_profile_ids.contains(&config.profile)
            || !config
                .task
                .authorization_refs
                .contains(&config.authorization)
            || config.function.is_empty()
            || !config
                .function
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || config
                .public_source
                .files
                .contains_key("protected_oracle.py")
        {
            return Err(denied(
                "candidate test configuration outside exact public task",
            ));
        }
        Ok(Self {
            store,
            catalog,
            config,
        })
    }
    fn parameters(&self) -> Value {
        let mut p = json!({"test_code":{"type":"string","minLength":1}});
        let mut required = vec!["test_code"];
        if self.config.fixed_solution.is_none() {
            p["solution_code"] = json!({"type":"string","minLength":1});
            required.push("solution_code");
        }
        json!({"type":"object","properties":p,"required":required,"additionalProperties":false})
    }
    fn snapshot(&self, call: &ToolCall) -> Result<Snapshot> {
        if call.name != "candidate_test" {
            return Err(denied("wrong development test wire name"));
        }
        let args =
            melissa_model_gateway::schema::validate_output(&self.parameters(), &call.arguments)?;
        let mut files = self.config.public_source.files.clone();
        let solution = if let Some(s) = &self.config.fixed_solution {
            s.clone()
        } else {
            args["solution_code"]
                .as_str()
                .ok_or_else(|| GatewayError::invalid("solution source required"))?
                .as_bytes()
                .to_vec()
        };
        files.insert("solution.py".into(), solution);
        files.insert(
            "test_solution.py".into(),
            args["test_code"]
                .as_str()
                .ok_or_else(|| GatewayError::invalid("test source required"))?
                .as_bytes()
                .to_vec(),
        );
        files.insert(
            "public_blackbox_guard.py".into(),
            self.config.public_guard.clone(),
        );
        files.insert("public_candidate_driver.py".into(), DRIVER.to_vec());
        files.insert(
            "public_candidate_config.json".into(),
            serde_json::to_vec(&json!({"function":self.config.function})).map_err(host_error)?,
        );
        let snapshot = Snapshot { files };
        snapshot
            .validate(self.config.task.limits.max_disk_bytes)
            .map_err(host_error)?;
        Ok(snapshot)
    }
}
impl ToolDispatcher for CandidateTests {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: "code.tests".into(),
            definition: ToolDefinition {
                name: "candidate_test".into(),
                description: format!(
                    "Execute YOUR candidate implementation and test_candidate tests in the native isolated pinned Python worker, including the PUBLIC direct-call/no-introspection syntax contract below. This is a developer selftest; no private correct reference or mutation oracle is exposed and a pass is not independent acceptance. Return full test code; {}. Read actual stdout/stderr and correct your own code/tests after a failure before submission. Public syntax contract: {}",
                    if self.config.fixed_solution.is_some() {
                        "implementation is fixed by the prior specialist; only test_code is accepted"
                    } else {
                        "provide solution_code and test_code"
                    },
                    String::from_utf8_lossy(&self.config.public_guard)
                ),
                parameters: self.parameters(),
                strict: false,
            },
        }]
    }
    fn validate_call(&self, call: &ToolCall) -> Result<()> {
        self.snapshot(call).map(|_| ())
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            if ctx.task_id != self.config.task.task_id
                || ctx.profile_id != self.config.profile
                || ctx.run_id != self.config.run
                || cancel.load(Ordering::Acquire)
            {
                return Err(denied(
                    "candidate test differs from leased native role or is cancelled",
                ));
            }
            let snapshot = self.snapshot(&call)?;
            let snapshot_digest = snapshot.digest().map_err(host_error)?;
            let record = self
                .store
                .journal()
                .model_request(&ctx.request_id)
                .map_err(host_error)?;
            if record.reservation.task_id != ctx.task_id
                || record.reservation.profile_id != ctx.profile_id
            {
                return Err(denied("candidate test request owner mismatch"));
            }
            let response: Value = serde_json::from_slice(
                &self
                    .store
                    .get_artifact(&ctx.task_id, &format!("{}:response", ctx.request_id))
                    .map_err(host_error)?,
            )
            .map_err(host_error)?;
            if !response["calls"].as_array().is_some_and(|calls| {
                calls.iter().any(|c| {
                    c["id"] == call.id && c["name"] == call.name && c["arguments"] == call.arguments
                })
            }) {
                return Err(denied(
                    "candidate files were not proposed by this native model request",
                ));
            }
            let mut store = self.store.connect().map_err(host_error)?;
            let catalog = self.catalog.clone();
            let cfg = self.config.clone();
            tokio::task::spawn_blocking(move||->Result<ToolExecution>{
    let now=melissa_execution_broker::unix_ms().map_err(host_error)?;let remaining=cfg.expires_at_ms.saturating_sub(now);if remaining==0||cancel.load(Ordering::Acquire){return Err(denied("candidate test lease expired before worker admission"));}
    let output_budget=cfg.task.limits.max_output_bytes.min(cfg.policy.ceiling.output_bytes);
    if output_budget<2{return Err(denied("public test requires bounded stdout and export budgets"));}
    let stdout_budget=(4*1024*1024).min(output_budget/2);
    let request=ContainerRequest{schema_version:"melissa.container-exec/v1".into(),image_id:cfg.image.clone(),executable:cfg.python.clone(),argv:vec!["-I".into(),"-S".into(),"public_candidate_driver.py".into()],cwd:".".into(),env:BTreeMap::new(),limits:ContainerLimits{wall_time_ms:remaining.min(60000).min(cfg.task.limits.max_wall_time_ms).min(cfg.policy.ceiling.wall_time_ms),cpu_time_ms:60000,cpu_rate_basis_points:10000,memory_bytes:2*1024*1024*1024,disk_bytes:cfg.task.limits.max_disk_bytes.min(cfg.policy.ceiling.disk_bytes).min(256*1024*1024),output_bytes:stdout_budget,max_processes:128,export_bytes:(8*1024*1024).min(output_budget-stdout_budget)}};
    let mut policy=cfg.policy.clone();policy.grants.clear();policy.grants.insert(cfg.authorization.clone(),AuthorityGrant{authorization_ref:cfg.authorization.clone(),task_id:ctx.task_id.clone(),task_digest:authenticated_digest(&cfg.task).map_err(host_error)?,principal_id:"principal:workflow-development-test".into(),profile_id:ctx.profile_id.clone(),resource_id:cfg.task.workspace_ref.clone(),process_digest:container_execution_digest(&request,&snapshot_digest).map_err(host_error)?,allow_monitored_disk:false,allow_monitored_cpu:true,allowed_effects:cfg.task.allowed_effects.iter().cloned().collect(),not_before_unix_ms:now.saturating_sub(1),expires_at_unix_ms:cfg.expires_at_ms.min(now+120000)});
    let mut broker=ContainerBroker::new(store.connect().map_err(host_error)?,catalog,cfg.task.workspace_ref.clone(),policy).map_err(host_error)?;
    let identity=crate::digest(ctx.invocation_id.as_bytes());let permit=broker.issue_permit(&ctx.task_id,request,&snapshot,PermitRequest{permit_id:format!("permit:selftest:{identity}"),nonce:format!("nonce:selftest:{identity}"),principal_id:"principal:workflow-development-test".into(),profile_id:ctx.profile_id.clone(),resource_id:cfg.task.workspace_ref.clone(),authorization_ref:cfg.authorization.clone(),not_before_unix_ms:now,expires_at_unix_ms:cfg.expires_at_ms.min(now+90000)}).map_err(host_error)?;
    let executed=broker.execute(&ctx.task_id,&permit,&snapshot,&InvocationIdentity{invocation_id:ctx.invocation_id.clone(),attempt_id:ctx.attempt_id.clone(),generation:ctx.generation,idempotency_key:None},&cancel).map_err(host_error)?;
    let raw=store.get_artifact(&ctx.task_id,&executed.result_artifact_id).map_err(host_error)?;let observation:Value=serde_json::from_slice(&raw).map_err(host_error)?;
    let(mut stdout,mut stderr,mut report)=(String::new(),String::new(),Value::Null);let mut refs=vec![executed.result_artifact_id.clone()];
    for a in observation["artifacts"].as_array().into_iter().flatten(){let Some(id)=a["uri"].as_str()else{continue};let bytes=store.get_artifact(&ctx.task_id,id).map_err(host_error)?;refs.push(id.into());match a["type"].as_str(){Some("process.stdout")=>stdout=String::from_utf8_lossy(&bytes).into_owned(),Some("process.stderr")=>stderr=String::from_utf8_lossy(&bytes).into_owned(),Some("process.execution_report")=>report=serde_json::from_slice(&bytes).map_err(host_error)?,_=>{}}}
    let success=observation["status"]=="success"&&!executed.requires_reconciliation&&report["report"]["exit_code"]==0&&report["report"]["cleanup_confirmed"]==true&&report["report"]["tree_confirmed_stopped"]==true&&report["report"]["input_digest"]==snapshot_digest&&report["report"]["output_truncated"]==false&&stdout.contains("CODE08_PUBLIC_SELFTEST_OK");
    let result=json!({"schema_version":"melissa.public-development-test/v1","success":success,"protected_acceptance":false,"task_accepted":false,"snapshot_digest":snapshot_digest,"source_digests":{"solution.py":crate::digest(&snapshot.files["solution.py"]),"test_solution.py":crate::digest(&snapshot.files["test_solution.py"])},"stdout":stdout,"stderr":stderr,"native_observation":observation,"no_private_oracle":true});
    let bytes=serde_json::to_vec(&result).map_err(host_error)?;let id=format!("{}:public-development-result",ctx.invocation_id);store.put_artifact(&ArtifactRequest{artifact_id:id.clone(),task_id:ctx.task_id,content_type:"application/json".into(),logical_type:"code.public-development-test".into(),schema_version:"melissa.public-development-test/v1".into(),retain_until_ms:0,legal_hold:false},&bytes).map_err(host_error)?;refs.push(id);
    Ok(ToolExecution{content:serde_json::to_string(&result).map_err(host_error)?,success,cancelled:cancel.load(Ordering::Acquire),requires_reconciliation:executed.requires_reconciliation,artifact_refs:refs})
   }).await.map_err(host_error)?
        })
    }
}
