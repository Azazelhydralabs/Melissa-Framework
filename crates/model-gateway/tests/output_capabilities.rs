#![allow(dead_code)]
//! Actual loopback HTTP with deterministic provider data; no live AI service.
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_model_gateway::{
    DecoderLimits, ErrorKind, GatewayError, Protocol, Result, ToolCall, ToolDefinition,
    agent_loop::{Gateway, GatewayPolicy, RunSpec, RunStatus},
    routing::{
        Capabilities, Measurements, ModelRegistration, PriceSource, RateCard, RouteRequirements,
    },
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
    transport::{ApiKey, EndpointTrust, ProviderEndpoint},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
};

const TASK: &str = "task:agent-loop";
const PROFILE: &str = "melissa.code.debugger";
const RESOURCE: &str = "provider:loopback";
const AUTH: &str = "authorization:provider:loopback";

struct HttpPlan {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}
impl HttpPlan {
    fn sse(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            delay: Duration::ZERO,
        }
    }
}
struct HttpFixture {
    url: String,
    requests: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn http_fixture(plans: Vec<HttpPlan>) -> HttpFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&requests);
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&bodies);
    let task = tokio::spawn(async move {
        for plan in plans {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            let end = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() < 2 * 1024 * 1024);
                if let Some(i) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while bytes.len() - end < length {
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            captured
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&bytes[end..end + length]).unwrap());
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(plan.delay).await;
            let headers = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                plan.status,
                if plan.status == 400 {
                    "application/json"
                } else {
                    "text/event-stream"
                },
                plan.body.len()
            );
            if socket.write_all(headers.as_bytes()).await.is_err() {
                continue;
            }
            let _ = socket.write_all(&plan.body).await;
        }
    });
    HttpFixture {
        url: format!("http://{address}/v1/responses"),
        requests,
        bodies,
        task,
    }
}
fn wire(mut events: Vec<Value>) -> Vec<u8> {
    for (i, e) in events.iter_mut().enumerate() {
        e["sequence_number"] = json!(i);
    }
    events
        .iter()
        .map(|e| format!("event: {}\ndata: {}\n\n", e["type"].as_str().unwrap(), e))
        .collect::<String>()
        .into_bytes()
}
fn created() -> Value {
    json!({"type":"response.created","response":{"id":"resp_fixture","model":"fixture-snapshot","status":"in_progress","output":[]}})
}
fn completed(output: Vec<Value>, usage: bool) -> Value {
    json!({"type":"response.completed","response":{"id":"resp_fixture","model":"fixture-snapshot","status":"completed","error":null,"incomplete_details":null,"output":output,"usage":if usage{json!({"input_tokens":12,"output_tokens":4,"total_tokens":16,"input_tokens_details":{"cached_tokens":3}})}else{Value::Null}}})
}
fn text_response(text: &str, refusal: bool, usage: bool) -> Vec<u8> {
    let kind = if refusal { "refusal" } else { "output_text" };
    let field = if refusal { "refusal" } else { "text" };
    let prefix = if refusal {
        "response.refusal"
    } else {
        "response.output_text"
    };
    let mut part = json!({"type":kind,field:text});
    if !refusal {
        part["annotations"] = json!([]);
        part["logprobs"] = json!([]);
    }
    let mut initial_part = part.clone();
    initial_part[field] = json!("");
    let item = json!({"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[part]});
    let mut initial = item.clone();
    initial["status"] = json!("in_progress");
    initial["content"] = json!([]);
    wire(vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":initial}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_1","content_index":0,"part":initial_part}),
        json!({"type":format!("{prefix}.delta"),"output_index":0,"item_id":"msg_1","content_index":0,"delta":text}),
        json!({"type":format!("{prefix}.done"),"output_index":0,"item_id":"msg_1","content_index":0,field:text}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_1","content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":item.clone()}),
        completed(vec![item], usage),
    ])
}
fn tool_response(calls: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut events = vec![created()];
    let mut output = Vec::new();
    for (index, (id, name, args)) in calls.iter().enumerate() {
        let item_id = format!("fc_{index}");
        let item = json!({"id":item_id,"type":"function_call","call_id":id,"name":name,"arguments":args,"status":"completed"});
        let mut initial = item.clone();
        initial["arguments"] = json!("");
        initial["status"] = json!("in_progress");
        events.extend([json!({"type":"response.output_item.added","output_index":index,"item":initial}),json!({"type":"response.function_call_arguments.delta","output_index":index,"item_id":item_id,"delta":args}),json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":item_id,"arguments":args}),json!({"type":"response.output_item.done","output_index":index,"item":item.clone()})]);
        output.push(item);
    }
    events.push(completed(output, true));
    wire(events)
}
fn store(root: &Path, input_budget: u64) -> LocalStore {
    let mut s = LocalStore::open(
        root,
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = TASK.into();
    task.selected_profile_ids = vec![PROFILE.into()];
    task.allowed_resource_ids.push(RESOURCE.into());
    task.authorization_refs.push(AUTH.into());
    task.limits.max_input_tokens = input_budget;
    task.limits.max_output_tokens = 1000;
    task.limits.max_cost_micro_usd = 100_000;
    task.limits.max_parallel_jobs = 4;
    s.journal_mut().create_task(&task).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = s.journal().task(TASK).unwrap().record.version;
        s.transition_task(TASK, version, state, None).unwrap();
    }
    s
}
fn policy() -> GatewayPolicy {
    GatewayPolicy {
        allowed_registrations: BTreeSet::from(["fixture-route".into()]),
        max_requests: 5,
        max_turns: 4,
        max_tools: 4,
        max_wall_time_ms: 5000,
        expires_at_unix_ms: melissa_execution_broker::unix_ms().unwrap() + 30_000,
        allow_fallback: false,
        max_backoff_ms: 0,
        decoder_limits: DecoderLimits::default(),
    }
}
fn gateway(
    store: LocalStore,
    http: &HttpFixture,
    policy: GatewayPolicy,
    native_schema: bool,
) -> Gateway {
    Gateway::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        vec![ModelRegistration {
            registration_id: "fixture-route".into(),
            endpoint: ProviderEndpoint::new(
                "fixture-provider".into(),
                RESOURCE.into(),
                AUTH.into(),
                Protocol::OpenAiResponses,
                EndpointTrust::LoopbackFixture,
                &http.url,
                ApiKey::new("fixture-not-a-secret".into()).unwrap(),
            )
            .unwrap(),
            model_id: "fixture-model".into(),
            capabilities: Capabilities {
                tool_calling: true,
                structured_output: native_schema,
                vision: false,
                streaming: true,
            },
            categories: BTreeSet::from(["coding".into()]),
            context_tokens: 1024,
            max_output_tokens: 128,
            timeout_ms: 5000,
            max_concurrency: 4,
            rate_card: Some(RateCard {
                source: PriceSource::Fixture,
                input_micro_usd_per_million: 1_000_000,
                output_micro_usd_per_million: 1_000_000,
                cached_input_micro_usd_per_million: Some(1_000_000),
                cache_creation_micro_usd_per_million: None,
            }),
            measurements: Measurements::default(),
            slots: Arc::new(Semaphore::new(4)),
        }],
        policy,
        true,
    )
    .unwrap()
    .with_output_capabilities(vec![
        melissa_model_gateway::output_capabilities::OutputCapabilityRegistration {
            registration_id: "fixture-route".into(),
            provider_id: "fixture-provider".into(),
            resource_id: RESOURCE.into(),
            authorization_ref: AUTH.into(),
            model_id: "fixture-model".into(),
            protocol: Protocol::OpenAiResponses,
            endpoint: http.url.clone(),
            json_object: true,
            native_json_schema: native_schema,
            evidence_ref: "fixture:typed-json-output-contract".into(),
        },
    ])
    .unwrap()
}
fn spec(run: &str) -> RunSpec {
    RunSpec {
        run_id: run.into(),
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        user_message: "Use only authorized tools and report observations accurately.".into(),
        route: RouteRequirements {
            category: "coding".into(),
            tools: false,
            structured_output: false,
            vision: false,
            minimum_success_ppm: None,
            maximum_p95_ms: None,
        },
        max_output_tokens: 128,
        output_schema: None,
        required_tool_names: BTreeSet::new(),
    }
}
#[derive(Default)]
struct FakeTools {
    executed: Arc<AtomicUsize>,
    contexts: Arc<Mutex<Vec<ToolContext>>>,
    cancel_preflight: Option<Arc<AtomicBool>>,
    failure: Option<ErrorKind>,
    unsuccessful: bool,
    unknown: bool,
}
impl ToolDispatcher for FakeTools {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: "process.exec".into(),
            definition: ToolDefinition {
                name: "process_exec".into(),
                description: "Deterministic local fixture only".into(),
                parameters: json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}),
                strict: true,
            },
        }]
    }
    fn validate_call(&self, call: &ToolCall) -> Result<()> {
        if let Some(flag) = &self.cancel_preflight {
            flag.store(true, Ordering::Release);
        }
        if call.name != "process_exec" {
            return Err(GatewayError::unsupported("fixture tool unavailable"));
        }
        melissa_model_gateway::schema::validate_output(
            &self.definitions()[0].definition.parameters,
            &call.arguments,
        )
        .map(|_| ())
    }
    fn execute<'a>(
        &'a mut self,
        _call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            self.executed.fetch_add(1, Ordering::SeqCst);
            self.contexts.lock().unwrap().push(context);
            if let Some(kind) = self.failure {
                return Err(GatewayError::new(kind, "injected fixture fault"));
            }
            Ok(ToolExecution {
                content:
                    json!({"status":if self.unsuccessful{"failed"}else{"observed"},"fixture":true})
                        .to_string(),
                success: !self.unsuccessful,
                cancelled: cancelled.load(Ordering::Acquire),
                requires_reconciliation: self.unknown,
                artifact_refs: vec![],
            })
        })
    }
}

fn output_schema() -> Value {
    json!({"type":"object","properties":{"page_text":{"type":"string","pattern":"\\n$"}},"required":["page_text"],"additionalProperties":false})
}

use melissa_model_gateway::output_capabilities::{
    OutputCapabilityRegistration, OutputCapabilityRegistry, OutputMode,
};
use melissa_model_gateway::routing::select_routes_for_output_mode;
fn record(
    http: &HttpFixture,
    json_object: bool,
    native_json_schema: bool,
) -> OutputCapabilityRegistration {
    OutputCapabilityRegistration {
        registration_id: "fixture-route".into(),
        provider_id: "fixture-provider".into(),
        resource_id: RESOURCE.into(),
        authorization_ref: AUTH.into(),
        model_id: "fixture-model".into(),
        protocol: Protocol::OpenAiResponses,
        endpoint: http.url.clone(),
        json_object,
        native_json_schema,
        evidence_ref: "fixture:output-modes-v2".into(),
    }
}
fn model(
    http: &HttpFixture,
    registration: &str,
    provider: &str,
    id: &str,
    native: bool,
) -> ModelRegistration {
    ModelRegistration {
        registration_id: registration.into(),
        endpoint: ProviderEndpoint::new(
            provider.into(),
            RESOURCE.into(),
            AUTH.into(),
            Protocol::OpenAiResponses,
            EndpointTrust::LoopbackFixture,
            &http.url,
            ApiKey::new("fixture-not-a-secret".into()).unwrap(),
        )
        .unwrap(),
        model_id: id.into(),
        capabilities: Capabilities {
            tool_calling: true,
            structured_output: native,
            vision: false,
            streaming: true,
        },
        categories: BTreeSet::from(["coding".into()]),
        context_tokens: 1024,
        max_output_tokens: 128,
        timeout_ms: 5000,
        max_concurrency: 1,
        rate_card: Some(RateCard {
            source: PriceSource::Fixture,
            input_micro_usd_per_million: 1_000_000,
            output_micro_usd_per_million: 1_000_000,
            cached_input_micro_usd_per_million: None,
            cache_creation_micro_usd_per_million: None,
        }),
        measurements: Measurements::default(),
        slots: Arc::new(Semaphore::new(1)),
    }
}
#[tokio::test]
async fn missing_json_object_evidence_stops_before_reservation_http_and_tools_even_with_native_schema()
 {
    for native in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![]).await;
        let mut g = gateway(
            store(&dir.path().join("store"), 10_000),
            &http,
            policy(),
            native,
        )
        .with_output_capabilities(vec![])
        .unwrap()
        .with_json_object_output();
        let mut s = spec("unknown-output");
        s.output_schema = Some(output_schema());
        let mut tools = FakeTools::default();
        let e = g
            .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
        assert_eq!(http.requests.load(Ordering::SeqCst), 0);
        assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn explicitly_unsupported_mode_does_not_downgrade_to_native_or_send_a_probe() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![]).await;
    let mut g = gateway(
        store(&dir.path().join("store"), 10_000),
        &http,
        policy(),
        true,
    )
    .with_output_capabilities(vec![record(&http, false, true)])
    .unwrap()
    .with_json_object_output();
    let mut s = spec("unsupported-json");
    s.output_schema = Some(output_schema());
    assert_eq!(
        g.run(
            &s,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
}
#[tokio::test]
async fn json_mode_does_not_imply_native_and_explicit_native_rejection_is_respected() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![]).await;
    let mut g = gateway(
        store(&dir.path().join("store"), 10_000),
        &http,
        policy(),
        true,
    )
    .with_output_capabilities(vec![record(&http, true, false)])
    .unwrap();
    let mut s = spec("unsupported-native");
    s.output_schema = Some(output_schema());
    assert_eq!(
        g.run(
            &s,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
}
#[tokio::test]
async fn capability_binding_cannot_be_borrowed_by_another_provider_model_endpoint_or_authority() {
    let http = http_fixture(vec![]).await;
    for field in [
        "registration",
        "provider",
        "model",
        "endpoint",
        "resource",
        "authorization",
        "protocol",
        "upgrade",
        "evidence",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut r = record(&http, true, false);
        match field {
            "registration" => r.registration_id = "other-route".into(),
            "provider" => r.provider_id = "other-provider".into(),
            "model" => r.model_id = "other-model".into(),
            "endpoint" => r.endpoint = format!("{}-other", http.url),
            "resource" => r.resource_id = "other-resource".into(),
            "authorization" => r.authorization_ref = "other-auth".into(),
            "protocol" => r.protocol = Protocol::AnthropicMessages,
            "upgrade" => r.native_json_schema = true,
            "evidence" => r.evidence_ref = String::new(),
            _ => unreachable!(),
        }
        let g = gateway(
            store(&dir.path().join("store"), 10_000),
            &http,
            policy(),
            false,
        );
        assert!(g.with_output_capabilities(vec![r]).is_err(), "{field}");
    }
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn capability_registry_rejects_duplicates_ambiguous_wire_identity_and_protocol_misclaims() {
    let http = http_fixture(vec![]).await;
    let r = record(&http, true, false);
    assert!(OutputCapabilityRegistry::new(vec![r.clone(), r.clone()]).is_err());
    let mut alias = r.clone();
    alias.registration_id = "alias-route".into();
    assert!(OutputCapabilityRegistry::new(vec![r.clone(), alias]).is_err());
    let mut anthropic = r;
    anthropic.protocol = Protocol::AnthropicMessages;
    assert!(OutputCapabilityRegistry::new(vec![anthropic]).is_err());
    let m = model(&http, "r", "p", "m", false);
    assert!(
        OutputCapabilityRegistration::for_model(&m, false, true, "fixture:upgrade".into()).is_err()
    );
}
#[tokio::test]
async fn routing_keeps_requested_mode_quality_and_provider_model_scope_without_native_flag_rewriting()
 {
    let http = http_fixture(vec![]).await;
    let mut models = vec![
        model(&http, "native-only", "provider-a", "same-model", true),
        model(&http, "json-only", "provider-b", "same-model", false),
        model(&http, "unknown", "provider-c", "same-model", true),
    ];
    let caps = OutputCapabilityRegistry::new(vec![
        OutputCapabilityRegistration::for_model(&models[0], false, true, "fixture:native".into())
            .unwrap(),
        OutputCapabilityRegistration::for_model(&models[1], true, false, "fixture:json".into())
            .unwrap(),
    ])
    .unwrap();
    let allowed = models.iter().map(|m| m.registration_id.clone()).collect();
    let mut requirements = spec("routing").route;
    requirements.structured_output = true;
    let routes = select_routes_for_output_mode(
        &models,
        &requirements,
        &allowed,
        OutputMode::JsonObject,
        &caps,
    )
    .unwrap();
    assert_eq!(routes, vec![1]);
    let native = select_routes_for_output_mode(
        &models,
        &requirements,
        &allowed,
        OutputMode::NativeJsonSchema,
        &caps,
    )
    .unwrap();
    assert!(native.contains(&0) && native.contains(&2) && !native.contains(&1));
    requirements.minimum_success_ppm = Some(900_000);
    assert!(
        select_routes_for_output_mode(
            &models,
            &requirements,
            &allowed,
            OutputMode::JsonObject,
            &caps
        )
        .is_err()
    );
    models[1].measurements.task_success_ppm = Some(950_000);
    assert_eq!(
        select_routes_for_output_mode(
            &models,
            &requirements,
            &allowed,
            OutputMode::JsonObject,
            &caps
        )
        .unwrap(),
        vec![1]
    );
    assert!(models[0].capabilities.structured_output && !models[1].capabilities.structured_output);
}
#[tokio::test]
async fn transport_checks_the_same_bound_evidence_on_actual_send_not_only_router_selection() {
    use melissa_model_gateway::{Message, TurnRequest, transport::HttpTransport};
    let http = http_fixture(vec![]).await;
    let m = model(
        &http,
        "fixture-route",
        "fixture-provider",
        "fixture-model",
        false,
    );
    let request = TurnRequest {
        model: m.model_id.clone(),
        system_prompt: "Return JSON".into(),
        messages: vec![Message::User {
            text: "Return the observed result".into(),
        }],
        tools: vec![],
        max_output_tokens: 128,
        output_schema: Some(output_schema()),
    };
    let unknown = HttpTransport::new(true).unwrap().with_json_object_output();
    assert!(unknown.request_body(&m.endpoint, &request).is_err());
    let t = HttpTransport::new(true)
        .unwrap()
        .with_json_object_output()
        .with_output_capabilities(vec![record(&http, true, false)])
        .unwrap();
    assert_eq!(
        t.request_body(&m.endpoint, &request).unwrap()["text"]["format"]["type"],
        "json_object"
    );
    let mut changed = m.endpoint.clone();
    changed.url = url::Url::parse(&format!("{}-changed", http.url)).unwrap();
    assert!(t.request_body(&changed, &request).is_err());
    let mut changed_model = request.clone();
    changed_model.model = "different".into();
    assert!(t.request_body(&m.endpoint, &changed_model).is_err());
    let denied = HttpTransport::new(true)
        .unwrap()
        .with_json_object_output()
        .with_output_capabilities(vec![record(&http, false, true)])
        .unwrap();
    assert!(denied.request_body(&m.endpoint, &request).is_err());
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn actual_json_request_preserves_capability_evidence_and_strict_validation_without_false_completion()
 {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "{\"page_text\":\"observed\\n\"}",
        false,
        true,
    ))])
    .await;
    let mut g = gateway(
        store(&dir.path().join("store"), 10_000),
        &http,
        policy(),
        false,
    )
    .with_output_capabilities(vec![record(&http, true, false)])
    .unwrap()
    .with_json_object_output();
    let mut s = spec("capability-wire");
    s.output_schema = Some(output_schema());
    let result = g
        .run(
            &s,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert!(!result.task_accepted);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    let bytes = g
        .store()
        .get_artifact(TASK, "model:capability-wire:1:request")
        .unwrap();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["configured_output_mode"], "json_object");
    assert_eq!(envelope["capabilities"]["structured_output"], false);
    assert_eq!(
        envelope["output_capability_evidence"]["evidence_ref"],
        "fixture:output-modes-v2"
    );
    assert_eq!(
        envelope["output_capability_evidence"]["model_id"],
        "fixture-model"
    );
    assert_eq!(
        envelope["body"]["text"]["format"],
        json!({"type":"json_object"})
    );
    assert!(
        envelope["body"]["instructions"]
            .as_str()
            .unwrap()
            .contains("FINAL OUTPUT CONTRACT")
    );
    assert_eq!(
        g.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}
