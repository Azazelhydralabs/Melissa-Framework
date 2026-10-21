//! Host-owned bindings from wire function names to the existing CODE-03
//! broker. Parsing model arguments neither creates nor modifies a grant.
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use melissa_container_executor::{ContainerRequest, Snapshot};
use melissa_core_contracts::wire::{ObservationStatus, ToolObservationV2};
use melissa_execution_broker::{
    Broker, BrokerError, InvocationIdentity, PolicyControl,
    container_broker::{ContainerBroker, container_tool_schema, parse_container_request},
    control_policy::{ControlTool, ProcessControlRequest},
    parse_process_request,
    policy::{PermitRequest, ProcessSpec},
    process_control::{ProcessControlService, parse_control_request},
    process_tool_schema, unix_ms,
};
use serde_json::{Value, json};

use crate::{ErrorKind, GatewayError, Result, ToolCall, ToolDefinition};

#[derive(Debug, Clone)]
pub struct BoundTool {
    pub canonical_id: String,
    pub definition: ToolDefinition,
}

#[derive(Debug, Clone)]
pub struct ToolContext {
    pub task_id: String,
    pub profile_id: String,
    pub run_id: String,
    pub request_id: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub generation: u64,
}

#[derive(Clone)]
pub struct ToolExecution {
    pub content: String,
    pub success: bool,
    pub cancelled: bool,
    pub requires_reconciliation: bool,
    pub artifact_refs: Vec<String>,
}
impl std::fmt::Debug for ToolExecution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolExecution")
            .field("success", &self.success)
            .field("cancelled", &self.cancelled)
            .field("requires_reconciliation", &self.requires_reconciliation)
            .field("artifact_refs", &self.artifact_refs)
            .field("content", &"[redacted]")
            .finish()
    }
}

pub trait ToolDispatcher: Send {
    fn definitions(&self) -> Vec<BoundTool>;
    fn validate_call(&self, call: &ToolCall) -> Result<()>;
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct BrokerDispatcherConfig {
    pub principal_id: String,
    pub resource_id: String,
    /// Trusted host references only. Keys are canonical catalog IDs.
    pub authorization_refs: BTreeMap<String, String>,
    pub permit_lifetime_ms: u64,
}

#[derive(Clone)]
enum Backend {
    Native(Arc<Mutex<Broker>>),
    Container {
        broker: Arc<Mutex<ContainerBroker>>,
        snapshot: Arc<Snapshot>,
    },
}

/// Clones share the broker and its one-use journal. A separate control-store
/// connection lets an authorized inspect/cancel proceed while execution holds
/// the broker mutex. No caller PID or automatic backend fallback exists.
#[derive(Clone)]
pub struct BrokerDispatcher {
    backend: Backend,
    control: Arc<Mutex<ProcessControlService>>,
    policy: PolicyControl,
    config: BrokerDispatcherConfig,
}

enum ParsedCall {
    Native(ProcessSpec),
    Container(ContainerRequest),
    Control(ProcessControlRequest),
}

impl BrokerDispatcher {
    pub fn native(broker: Arc<Mutex<Broker>>, config: BrokerDispatcherConfig) -> Result<Self> {
        validate_config(&config)?;
        let (control, policy) = {
            let broker = broker
                .lock()
                .map_err(|_| GatewayError::new(ErrorKind::Tool, "broker lock poisoned"))?;
            (
                broker.control_service().map_err(map_broker_error)?,
                broker.policy_control(),
            )
        };
        Ok(Self {
            backend: Backend::Native(broker),
            control: Arc::new(Mutex::new(control)),
            policy,
            config,
        })
    }

    pub fn container(
        broker: Arc<Mutex<ContainerBroker>>,
        snapshot: Arc<Snapshot>,
        config: BrokerDispatcherConfig,
    ) -> Result<Self> {
        validate_config(&config)?;
        let (control, policy) = {
            let broker = broker
                .lock()
                .map_err(|_| GatewayError::new(ErrorKind::Tool, "broker lock poisoned"))?;
            (
                broker.control_service().map_err(map_broker_error)?,
                broker.policy_control(),
            )
        };
        Ok(Self {
            backend: Backend::Container { broker, snapshot },
            control: Arc::new(Mutex::new(control)),
            policy,
            config,
        })
    }

    fn parse(&self, call: &ToolCall) -> Result<ParsedCall> {
        if !identifier(&call.id, 256) || call.arguments.len() > 512 * 1024 {
            return Err(GatewayError::invalid("tool identity or argument bounds"));
        }
        let canonical = canonical(&call.name).ok_or_else(|| {
            GatewayError::unsupported("wire function is not bound to a broker route")
        })?;
        if !self.config.authorization_refs.contains_key(canonical) {
            return Err(GatewayError::new(
                ErrorKind::Authorization,
                "host did not configure this tool authority",
            ));
        }
        match call.name.as_str() {
            "process_exec" => match &self.backend {
                Backend::Native(_) => parse_process_request(call.arguments.as_bytes())
                    .map(ParsedCall::Native)
                    .map_err(map_broker_error),
                Backend::Container { .. } => parse_container_request(call.arguments.as_bytes())
                    .map(ParsedCall::Container)
                    .map_err(map_broker_error),
            },
            "process_inspect" | "process_cancel" => {
                let request =
                    parse_control_request(call.arguments.as_bytes()).map_err(map_broker_error)?;
                if request.tool.tool_id() != canonical
                    || request.resource_id != self.config.resource_id
                {
                    return Err(GatewayError::new(
                        ErrorKind::Authorization,
                        "control tool or managed resource does not match binding",
                    ));
                }
                Ok(ParsedCall::Control(request))
            }
            _ => Err(GatewayError::unsupported("unbound wire function")),
        }
    }
}

impl ToolDispatcher for BrokerDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(policy) = self.policy.snapshot() else {
            return Vec::new();
        };
        let Ok(now) = unix_ms() else {
            return Vec::new();
        };
        let usable =
            |authorization: &str| !policy.revoked_authorization_refs.contains(authorization);
        let mut out = Vec::new();
        if let Some(authorization) = self.config.authorization_refs.get("process.exec")
            && usable(authorization)
            && policy.grants.get(authorization).is_some_and(|grant| {
                grant.principal_id == self.config.principal_id
                    && grant.resource_id == self.config.resource_id
                    && grant.not_before_unix_ms <= now
                    && grant.expires_at_unix_ms > now
            })
        {
            let (parameters, description) = match self.backend {
                Backend::Native(_) => (
                    process_tool_schema(),
                    "Execute the exact host-authorized native Windows process in the owned staging workspace. A successful process exit does not accept the task.",
                ),
                Backend::Container { .. } => (
                    container_tool_schema(),
                    "Execute the exact host-authorized immutable Linux image command with the supplied owned snapshot. The archive remains untrusted; process success does not accept the task.",
                ),
            };
            out.push(BoundTool {
                canonical_id: "process.exec".into(),
                definition: ToolDefinition {
                    name: "process_exec".into(),
                    description: description.into(),
                    parameters,
                    strict: false,
                },
            });
        }
        for (canonical_id, name, kind) in [
            ("process.inspect", "process_inspect", ControlTool::Inspect),
            ("process.cancel", "process_cancel", ControlTool::Cancel),
        ] {
            let Some(authorization) = self.config.authorization_refs.get(canonical_id) else {
                continue;
            };
            let Some(grant) = policy.control_grants.get(authorization) else {
                continue;
            };
            if !usable(authorization)
                || grant.tool != kind
                || grant.principal_id != self.config.principal_id
                || grant.resource_id != self.config.resource_id
                || grant.not_before_unix_ms > now
                || grant.expires_at_unix_ms <= now
            {
                continue;
            }
            let mut parameters: Value =
                serde_json::from_str(include_str!("../../../schemas/process-control.schema.json"))
                    .expect("committed control schema");
            parameters["properties"]["tool"] = json!({"const":canonical_id,"type":"string"});
            parameters["properties"]["task_id"] = json!({"const":grant.task_id,"type":"string"});
            parameters["properties"]["resource_id"] =
                json!({"const":grant.resource_id,"type":"string"});
            parameters["properties"]["invocation_id"] =
                json!({"const":grant.invocation_id,"type":"string"});
            parameters["properties"]["generation"] =
                json!({"const":grant.generation,"type":"integer"});
            out.push(BoundTool { canonical_id:canonical_id.into(), definition:ToolDefinition {name:name.into(),
                description:if kind == ControlTool::Inspect {"Inspect only the exact host-authorized managed invocation and generation."} else {"Record cancellation intent for the exact host-authorized managed invocation. A receipt does not prove process termination; inspect afterward."}.into(),
                parameters,strict:false} });
        }
        out
    }

    fn validate_call(&self, call: &ToolCall) -> Result<()> {
        self.parse(call).map(|_| ())
    }

    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            validate_context(&context)?;
            let parsed = self.parse(&call)?;
            if let ParsedCall::Control(request) = &parsed
                && request.task_id != context.task_id
            {
                return Err(GatewayError::new(
                    ErrorKind::Authorization,
                    "control target belongs to another task",
                ));
            }
            let backend = self.backend.clone();
            let control = Arc::clone(&self.control);
            let config = self.config.clone();
            let recovery = context.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let canonical_id = canonical(&call.name).expect("parsed binding");
                let permit = host_permit(&config,&context,&call,canonical_id)?;
                let identity = InvocationIdentity { invocation_id:context.invocation_id.clone(), attempt_id:context.attempt_id.clone(), generation:context.generation, idempotency_key:None };
                match (parsed,backend) {
                    (ParsedCall::Native(spec),Backend::Native(broker)) => {
                        let mut broker = broker.lock().map_err(|_|GatewayError::new(ErrorKind::Tool,"broker lock poisoned"))?;
                        let pinned = broker.resolve(&spec).map_err(map_broker_error)?;
                        let signed = broker.issue_permit(&context.task_id,&pinned,permit).map_err(map_broker_error)?;
                        match broker.execute(&context.task_id,&signed,&identity,&cancelled) {
                            Ok(outcome) => execution(&outcome.observation,&outcome.result_artifact_id,outcome.requires_reconciliation,
                                outcome.report.as_ref().map(|report|report.stdout.as_slice()),outcome.report.as_ref().map(|report|report.stderr.as_slice())),
                            Err(BrokerError::AfterDispatch(_)) => Ok(unknown(&context)),
                            Err(error) => Err(map_broker_error(error)),
                        }
                    }
                    (ParsedCall::Container(request),Backend::Container {broker,snapshot}) => {
                        let mut broker = broker.lock().map_err(|_|GatewayError::new(ErrorKind::Tool,"broker lock poisoned"))?;
                        let signed = broker.issue_permit(&context.task_id,request,&snapshot,permit).map_err(map_broker_error)?;
                        match broker.execute(&context.task_id,&signed,&snapshot,&identity,&cancelled) {
                            Ok(outcome) => execution(&outcome.observation,&outcome.result_artifact_id,outcome.requires_reconciliation,
                                outcome.report.as_ref().map(|report|report.stdout.as_slice()),outcome.report.as_ref().map(|report|report.stderr.as_slice())),
                            Err(BrokerError::AfterDispatch(_)) => Ok(unknown(&context)),
                            Err(error) => Err(map_broker_error(error)),
                        }
                    }
                    (ParsedCall::Control(request),_) => {
                        if cancelled.load(Ordering::Acquire) {
                            return Ok(ToolExecution {content:json!({"schema_version":"melissa.tool-control/v1","status":"cancelled_before_dispatch","task_accepted":false}).to_string(),success:false,cancelled:true,requires_reconciliation:false,artifact_refs:Vec::new()});
                        }
                        let mut service = control.lock().map_err(|_|GatewayError::new(ErrorKind::Tool,"control lock poisoned"))?;
                        let signed = service.issue_permit(request,permit).map_err(map_broker_error)?;
                        match service.execute(&signed) {
                            Ok(outcome) => Ok(ToolExecution { content:serde_json::to_string(&outcome).map_err(|_|GatewayError::new(ErrorKind::Tool,"control outcome serialization"))?,
                                success:true,cancelled:false,requires_reconciliation:false,artifact_refs:vec![outcome.artifact_id] }),
                            Err(BrokerError::AfterDispatch(_)) => Ok(unknown(&context)),
                            Err(error) => Err(map_broker_error(error)),
                        }
                    }
                    _ => Err(GatewayError::unsupported("execution backend binding changed")),
                }
            }).await;
            // A worker panic may follow durable admission. It is not evidence
            // that no process ran, and must never trigger an automatic retry.
            joined.unwrap_or_else(|_| Ok(unknown(&recovery)))
        })
    }
}

fn host_permit(
    config: &BrokerDispatcherConfig,
    context: &ToolContext,
    call: &ToolCall,
    canonical: &str,
) -> Result<PermitRequest> {
    let now = unix_ms().map_err(map_broker_error)?;
    let expires = now
        .checked_add(config.permit_lifetime_ms)
        .ok_or_else(|| GatewayError::invalid("permit clock overflow"))?;
    let identity = json!({"schema_version":"melissa.model-tool-identity/v1","task":context.task_id,"profile":context.profile_id,
        "run":context.run_id,"request":context.request_id,"invocation":context.invocation_id,"attempt":context.attempt_id,
        "generation":context.generation,"call":call.id,"tool":canonical,"arguments_digest":blake3::hash(call.arguments.as_bytes()).to_hex().to_string()});
    let digest = blake3::hash(identity.to_string().as_bytes())
        .to_hex()
        .to_string();
    Ok(PermitRequest {
        permit_id: format!("permit:code04:{digest}"),
        nonce: format!("nonce:code04:{digest}"),
        principal_id: config.principal_id.clone(),
        profile_id: context.profile_id.clone(),
        resource_id: config.resource_id.clone(),
        authorization_ref: config
            .authorization_refs
            .get(canonical)
            .ok_or_else(|| {
                GatewayError::new(ErrorKind::Authorization, "tool authority not configured")
            })?
            .clone(),
        not_before_unix_ms: now,
        expires_at_unix_ms: expires,
    })
}

fn execution(
    observation: &ToolObservationV2,
    result_artifact: &str,
    reconciliation: bool,
    stdout: Option<&[u8]>,
    stderr: Option<&[u8]>,
) -> Result<ToolExecution> {
    let mut artifacts: BTreeSet<String> = observation.artifact_refs.iter().cloned().collect();
    artifacts.insert(result_artifact.into());
    let content = json!({"schema_version":"melissa.broker-tool-result/v1","observation":observation,"stdout":preview(stdout),"stderr":preview(stderr),"result_artifact_id":result_artifact,"requires_reconciliation":reconciliation,"task_accepted":false}).to_string();
    Ok(ToolExecution {
        content,
        success: observation.status == ObservationStatus::Success && !reconciliation,
        cancelled: observation.status == ObservationStatus::Cancelled,
        requires_reconciliation: reconciliation,
        artifact_refs: artifacts.into_iter().collect(),
    })
}
fn preview(bytes: Option<&[u8]>) -> Value {
    let Some(bytes) = bytes else {
        return Value::Null;
    };
    let end = bytes.len().min(32 * 1024);
    let prefix = &bytes[..end];
    json!({"text":String::from_utf8_lossy(prefix),"encoding":if std::str::from_utf8(prefix).is_ok() {"utf8"} else {"utf8_lossy"},"preview_truncated":end<bytes.len(),"full_bytes":bytes.len(),"raw_evidence":"see observation artifact_refs"})
}
fn unknown(context: &ToolContext) -> ToolExecution {
    ToolExecution {content:json!({"schema_version":"melissa.broker-tool-result/v1","status":"outcome_unknown",
        "task_id":context.task_id,"invocation_id":context.invocation_id,"attempt_id":context.attempt_id,
        "requires_reconciliation":true,"automatic_retry_allowed":false,"task_accepted":false}).to_string(),
        success:false,cancelled:false,requires_reconciliation:true,artifact_refs:Vec::new()}
}
fn canonical(name: &str) -> Option<&'static str> {
    match name {
        "process_exec" => Some("process.exec"),
        "process_inspect" => Some("process.inspect"),
        "process_cancel" => Some("process.cancel"),
        _ => None,
    }
}
fn identifier(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn validate_context(context: &ToolContext) -> Result<()> {
    if [
        &context.task_id,
        &context.profile_id,
        &context.run_id,
        &context.request_id,
    ]
    .iter()
    .any(|value| !identifier(value, 256))
        || !identifier(&context.invocation_id, 160)
        || !identifier(&context.attempt_id, 160)
        || context.generation > i64::MAX as u64
    {
        return Err(GatewayError::invalid("host tool context bounds"));
    }
    Ok(())
}
fn validate_config(config: &BrokerDispatcherConfig) -> Result<()> {
    if !identifier(&config.principal_id, 256)
        || !identifier(&config.resource_id, 256)
        || config.permit_lifetime_ms == 0
        || config.permit_lifetime_ms > 1_800_000
        || config.authorization_refs.is_empty()
        || config.authorization_refs.iter().any(|(tool, reference)| {
            !matches!(
                tool.as_str(),
                "process.exec" | "process.inspect" | "process.cancel"
            ) || !identifier(reference, 256)
        })
    {
        return Err(GatewayError::invalid("host dispatcher configuration"));
    }
    Ok(())
}
fn map_broker_error(error: BrokerError) -> GatewayError {
    let kind = match error {
        BrokerError::Denied(_) | BrokerError::Policy(_) | BrokerError::StaleTarget(_) => {
            ErrorKind::Authorization
        }
        BrokerError::Invalid(_) | BrokerError::Json(_) => ErrorKind::Invalid,
        BrokerError::Store(_) => ErrorKind::Store,
        _ => ErrorKind::Tool,
    };
    GatewayError::new(
        kind,
        "broker rejected the operation; host authorization or execution evidence must be reviewed",
    )
}
