//! Actual loopback HTTP with deterministic provider data; no live AI service.
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{
    LocalStore, StoreConfig, StoreKey,
    journal::{ModelRequestState, ModelReservation},
};
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
fn gateway(store: LocalStore, http: &HttpFixture, policy: GatewayPolicy) -> Gateway {
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
                structured_output: true,
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
}
fn gateway_unpriced(store: LocalStore, http: &HttpFixture, policy: GatewayPolicy) -> Gateway {
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
                structured_output: true,
                vision: false,
                streaming: true,
            },
            categories: BTreeSet::from(["coding".into()]),
            context_tokens: 1024,
            max_output_tokens: 128,
            timeout_ms: 5000,
            max_concurrency: 4,
            rate_card: None,
            measurements: Measurements::default(),
            slots: Arc::new(Semaphore::new(4)),
        }],
        policy,
        true,
    )
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

#[tokio::test]
async fn final_candidate_is_persisted_with_usage_and_never_completes_the_task() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "A candidate, awaiting independent verification.",
        false,
        true,
    ))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut tools = FakeTools::default();
    let r = g
        .run(&spec("final"), &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert!(!r.task_accepted);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    assert_eq!(
        g.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .known_input_tokens,
        12
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert!(r.artifact_refs.len() >= 5);
    for id in &r.artifact_refs {
        let bytes = g.store().get_artifact(TASK, id).unwrap();
        assert!(
            !bytes
                .windows(b"fixture-not-a-secret".len())
                .any(|value| value == b"fixture-not-a-secret")
        );
    }
    let request_bytes = g
        .store()
        .get_artifact(TASK, "model:final:1:request")
        .unwrap();
    let envelope: Value = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(envelope["configured_context_tokens"], 1024);
    assert_eq!(envelope["configured_max_output_tokens"], 128);
    assert_eq!(
        envelope["capabilities"],
        json!({"tool_calling":true,"structured_output":true,"vision":false,"streaming":true})
    );
    assert_eq!(
        envelope["pricing_snapshot"]["source"],
        json!({"kind":"fixture"})
    );
    assert_eq!(
        envelope["pricing_snapshot"]["input_micro_usd_per_million"],
        1_000_000
    );
    assert_eq!(
        envelope["pricing_snapshot"]["output_micro_usd_per_million"],
        1_000_000
    );
    assert_eq!(
        envelope["pricing_snapshot"]["cached_input_micro_usd_per_million"],
        1_000_000
    );
    assert!(envelope["pricing_snapshot"]["cache_creation_micro_usd_per_million"].is_null());
    let pricing: RateCard = serde_json::from_value(envelope["pricing_snapshot"].clone()).unwrap();
    let record = g
        .store()
        .journal()
        .model_request(&r.request_ids[0])
        .unwrap();
    assert_eq!(record.reservation.pricing_digest, Some(pricing.digest()));
    assert_eq!(
        record.reservation.request_digest,
        format!("blake3:{}", blake3::hash(&request_bytes))
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn successful_tool_observation_returns_to_the_next_model_turn_with_bound_context() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "call_1",
            "process_exec",
            r#"{"value":"real fixture output"}"#,
        )])),
        HttpPlan::sse(text_response("Observed the result.", false, true)),
    ])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut tools = FakeTools::default();
    let mut s = spec("tools");
    s.required_tool_names.insert("process_exec".into());
    let r = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 1);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 1);
    let context = tools.contexts.lock().unwrap()[0].clone();
    assert_eq!(
        (&context.task_id, &context.profile_id, &context.run_id),
        (&s.task_id, &s.profile_id, &s.run_id)
    );
    assert_eq!(context.request_id, r.request_ids[0]);
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    let bodies = http.bodies.lock().unwrap();
    assert!(
        bodies[1]["input"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["type"] == "function_call_output")
    );
    assert!(!r.task_accepted);
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn required_tool_cannot_be_replaced_by_a_model_claim_or_failed_observation() {
    for failed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut plans = Vec::new();
        if failed {
            plans.push(HttpPlan::sse(tool_response(&[(
                "call_1",
                "process_exec",
                r#"{"value":"x"}"#,
            )])));
        }
        plans.push(HttpPlan::sse(text_response(
            "I ran all tests successfully.",
            false,
            true,
        )));
        let http = http_fixture(plans).await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let mut tools = FakeTools {
            unsuccessful: failed,
            ..Default::default()
        };
        let mut s = spec("noaction");
        s.required_tool_names.insert("process_exec".into());
        let r = g
            .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert_eq!(r.status, RunStatus::NoAction);
        assert!(!r.task_accepted);
        assert!(r.answer.is_none());
    }
}

#[tokio::test]
async fn malformed_or_duplicate_tool_batches_execute_nothing() {
    for calls in [
        vec![
            ("call_1", "process_exec", r#"{"value":"ok"}"#),
            ("call_2", "process_exec", r#"{"value":3}"#),
        ],
        vec![
            ("same", "process_exec", r#"{"value":"ok"}"#),
            ("same", "process_exec", r#"{"value":"ok"}"#),
        ],
        vec![("call_1", "process_exec", r#"{"value":"x","value":"y"}"#)],
        vec![
            ("call_1", "process_exec", r#"{"value":"ok"}"#),
            ("call_2", "unbound_tool", r#"{"value":"ok"}"#),
        ],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![
            HttpPlan::sse(tool_response(&calls)),
            HttpPlan::sse(text_response("No execution happened.", false, true)),
        ])
        .await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let mut tools = FakeTools::default();
        let mut s = spec("invalidbatch");
        s.required_tool_names.insert("process_exec".into());
        let r = g
            .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert!(matches!(
            r.status,
            RunStatus::NoAction | RunStatus::ProviderFailed
        ));
        assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
        assert_eq!(r.tool_calls, 0);
        assert!(!r.task_accepted);
        g.store().integrity_check().unwrap();
    }
}

#[tokio::test]
async fn input_budget_is_reserved_before_send_and_denial_creates_no_model_request() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "must never arrive",
        false,
        true,
    ))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 1023), &http, policy());
    let mut tools = FakeTools::default();
    let r = g
        .run(
            &spec("budget"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::BudgetExhausted);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn missing_usage_stays_unknown_and_conservatively_charged_after_complete_response() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "Complete response without billing data.",
        false,
        false,
    ))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let r = g
        .run(
            &spec("unknownusage"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(
        (
            budget.charged_input_tokens,
            budget.charged_output_tokens,
            budget.charged_cost_micro_usd
        ),
        (1024, 128, 1152)
    );
    assert_eq!(
        (
            budget.unknown_input_requests,
            budget.unknown_output_requests,
            budget.unknown_cost_requests
        ),
        (1, 1, 1)
    );
    let record = g
        .store()
        .journal()
        .model_request(&r.request_ids[0])
        .unwrap();
    assert_eq!(record.state, ModelRequestState::Succeeded);
    assert_eq!(record.settlement.unwrap().usage.input_tokens, None);
    assert!(!r.task_accepted);
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn http_typed_refusal_stops_without_fallback_tools_or_forged_known_usage() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::to_vec(&json!({"error":{"message":"PRIVATE_PROVIDER_PROSE","type":"invalid_request_error","code":"refusal","param":null,"refusal_reason":"content_policy"}})).unwrap();
    let http = http_fixture(vec![HttpPlan {
        status: 400,
        body: body.clone(),
        delay: Duration::ZERO,
    }])
    .await;
    let mut allowed = policy();
    allowed.allow_fallback = true;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, allowed);
    let mut tools = FakeTools::default();
    let result = g
        .run(
            &spec("httprefused"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::Refused);
    assert!(result.answer.is_none() && !result.task_accepted && result.requires_reconciliation);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    let record = g
        .store()
        .journal()
        .model_request("model:httprefused:1")
        .unwrap();
    assert_eq!(record.state, ModelRequestState::OutcomeUnknown);
    let usage = &record.settlement.as_ref().unwrap().usage;
    assert!(
        usage.input_tokens.is_none()
            && usage.output_tokens.is_none()
            && usage.cost_micro_usd.is_none()
    );
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(budget.unknown_requests, 1);
    assert_eq!(budget.active_requests, 1);
    assert!(budget.charged_cost_micro_usd > 0);
    assert_eq!(
        g.store()
            .get_artifact(TASK, "model:httprefused:1:raw-sse")
            .unwrap(),
        body
    );
    assert!(!format!("{result:?}").contains("PRIVATE_PROVIDER_PROSE"));
    assert_eq!(
        g.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}

#[tokio::test]
async fn refusal_and_provider_output_limits_do_not_execute_or_fake_a_final_result() {
    for refusal in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let body = if refusal {
            text_response("I cannot do that.", true, true)
        } else {
            wire(vec![
                created(),
                json!({"type":"response.incomplete","response":{"id":"resp_fixture","model":"fixture-snapshot","status":"incomplete","output":[],"usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16},"error":null,"incomplete_details":{"reason":"max_output_tokens"}}}),
            ])
        };
        let http = http_fixture(vec![HttpPlan::sse(body)]).await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let mut tools = FakeTools::default();
        let r = g
            .run(
                &spec("refusedorlimited"),
                &mut tools,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status,
            if refusal {
                RunStatus::Refused
            } else {
                RunStatus::InvalidOutput
            }
        );
        assert!(r.answer.is_none());
        assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
        assert!(!r.task_accepted);
    }
}

#[tokio::test]
async fn stream_ending_after_tool_arguments_without_terminal_snapshot_executes_zero_and_reserves_unknown()
 {
    let dir = tempfile::tempdir().unwrap();
    let complete = tool_response(&[("partial_call", "process_exec", r#"{"value":"do not run"}"#)]);
    let text = String::from_utf8(complete).unwrap();
    let terminal = text.rfind("event: response.completed").unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text.as_bytes()[..terminal].to_vec())]).await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut tools = FakeTools::default();
    let r = g
        .run(
            &spec("partial"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::ProviderFailed);
    assert!(r.requires_reconciliation);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(
        (budget.unknown_requests, budget.charged_cost_micro_usd),
        (1, 1152)
    );
    assert_eq!(
        g.store()
            .journal()
            .model_request(&r.request_ids[0])
            .unwrap()
            .state,
        ModelRequestState::OutcomeUnknown
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn cancellation_before_run_makes_no_http_request_or_tool_execution() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "should not send",
        false,
        true,
    ))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut tools = FakeTools::default();
    let r = g
        .run(
            &spec("precancel"),
            &mut tools,
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(r.request_ids.is_empty());
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancel_during_http_wait_returns_without_waiting_for_provider_and_preserves_possible_charge()
 {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan {
        status: 200,
        body: text_response("late response", false, true),
        delay: Duration::from_millis(5000),
    }])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let external = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&external);
    let request_count = Arc::clone(&http.requests);
    let cancel_at = Arc::new(Mutex::new(None));
    let marked_at = Arc::clone(&cancel_at);
    let canceller = tokio::spawn(async move {
        while request_count.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        *marked_at.lock().unwrap() = Some(std::time::Instant::now());
        flag.store(true, Ordering::Release);
    });
    let mut tools = FakeTools::default();
    let r = g
        .run(&spec("duringcancel"), &mut tools, external)
        .await
        .unwrap();
    canceller.await.unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert!(cancel_at.lock().unwrap().unwrap().elapsed() < Duration::from_secs(2));
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    assert!(r.requires_reconciliation);
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .charged_cost_micro_usd,
        1152
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn cancellation_during_tool_preflight_is_checked_before_starting_any_tool() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "call_cancel",
        "process_exec",
        r#"{"value":"must not run"}"#,
    )]))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let external = Arc::new(AtomicBool::new(false));
    let mut tools = FakeTools {
        cancel_preflight: Some(Arc::clone(&external)),
        ..Default::default()
    };
    let r = g
        .run(&spec("cancelpreflight"), &mut tools, external)
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_structured_final_answer_is_invalid_output_without_task_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        r#"{"answer":42,"extra":true}"#,
        false,
        true,
    ))])
    .await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut s = spec("badstructured");
    s.output_schema = Some(
        json!({"type":"object","properties":{"answer":{"type":"integer"}},"required":["answer"],"additionalProperties":false}),
    );
    let r = g
        .run(
            &s,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::InvalidOutput);
    assert!(r.answer.is_none());
    assert!(!r.task_accepted);
    assert_eq!(
        g.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}

#[tokio::test]
async fn request_turn_and_tool_limits_stop_bounded_loops_without_extra_http() {
    for limit in ["request", "turn", "tool"] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![
            HttpPlan::sse(tool_response(&[(
                "call_limit",
                "process_exec",
                r#"{"value":"x"}"#,
            )])),
            HttpPlan::sse(text_response("extra request forbidden", false, true)),
        ])
        .await;
        let mut p = policy();
        match limit {
            "request" => p.max_requests = 1,
            "turn" => p.max_turns = 1,
            _ => p.max_tools = 0,
        }
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, p);
        let mut tools = FakeTools::default();
        let r = g
            .run(
                &spec("bounded"),
                &mut tools,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status,
            match limit {
                "request" => RunStatus::RequestLimit,
                "turn" => RunStatus::TurnLimit,
                _ => RunStatus::ToolLimit,
            }
        );
        assert_eq!(http.requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            tools.executed.load(Ordering::SeqCst),
            if limit == "tool" { 0 } else { 1 }
        );
        assert!(!r.task_accepted);
    }
}

#[tokio::test]
async fn run_identity_replay_never_sends_again_or_duplicates_an_unknown_record() {
    for unknown in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let body = if unknown {
            wire(vec![created()])
        } else {
            text_response("a final candidate", false, true)
        };
        let http = http_fixture(vec![
            HttpPlan::sse(body),
            HttpPlan::sse(text_response("must not send twice", false, true)),
        ])
        .await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let s = spec("replay");
        let mut tools = FakeTools::default();
        let first = g
            .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        let original = g
            .store()
            .journal()
            .model_request(&first.request_ids[0])
            .unwrap();
        let error = g
            .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Store);
        assert_eq!(http.requests.load(Ordering::SeqCst), 1);
        assert_eq!(g.store().journal().model_requests(TASK).unwrap().len(), 1);
        assert_eq!(
            g.store()
                .journal()
                .model_request(&first.request_ids[0])
                .unwrap(),
            original
        );
        if unknown {
            assert!(first.requires_reconciliation);
            assert_eq!(original.state, ModelRequestState::OutcomeUnknown);
        }
        g.store().integrity_check().unwrap();
    }
}

#[tokio::test]
async fn tool_authority_denial_and_unknown_observations_are_explicit_terminal_states() {
    for kind in ["authorization", "error", "unknown"] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
            "call_fault",
            "process_exec",
            r#"{"value":"x"}"#,
        )]))])
        .await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let mut tools = FakeTools {
            failure: match kind {
                "authorization" => Some(ErrorKind::Authorization),
                "error" => Some(ErrorKind::Tool),
                _ => None,
            },
            unknown: kind == "unknown",
            ..Default::default()
        };
        let r = g
            .run(
                &spec("toolfault"),
                &mut tools,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status,
            if kind == "authorization" {
                RunStatus::NeedsAuthorization
            } else {
                RunStatus::NeedsReconciliation
            }
        );
        assert_eq!(r.requires_reconciliation, kind != "authorization");
        assert!(r.answer.is_none());
        assert_eq!(http.requests.load(Ordering::SeqCst), 1);
        assert!(!r.task_accepted);
    }
}

#[tokio::test]
async fn explicit_bounded_fallback_uses_new_ids_and_keeps_failed_attempt_unknown_charge() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![
        HttpPlan {
            status: 429,
            body: b"fixture rate limit".to_vec(),
            delay: Duration::ZERO,
        },
        HttpPlan::sse(text_response("fallback candidate", false, true)),
    ])
    .await;
    let mut p = policy();
    p.allow_fallback = true;
    p.max_requests = 2;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, p);
    let mut tools = FakeTools::default();
    let r = g
        .run(
            &spec("fallback"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.request_ids.len(), 2);
    assert_ne!(r.request_ids[0], r.request_ids[1]);
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    assert!(r.requires_reconciliation);
    let first = g
        .store()
        .journal()
        .model_request(&r.request_ids[0])
        .unwrap();
    assert_eq!(first.state, ModelRequestState::OutcomeUnknown);
    let second = g
        .store()
        .journal()
        .model_request(&r.request_ids[1])
        .unwrap();
    assert_eq!(second.state, ModelRequestState::Succeeded);
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(
        (
            budget.unknown_requests,
            budget.charged_input_tokens,
            budget.charged_cost_micro_usd
        ),
        (1, 1036, 1168)
    );
    assert!(!r.task_accepted);
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn host_deadline_interrupts_provider_wait_and_keeps_billing_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan {
        status: 200,
        body: text_response("too late", false, true),
        delay: Duration::from_millis(12000),
    }])
    .await;
    let mut p = policy();
    p.max_wall_time_ms = 3000;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, p);
    let mut tools = FakeTools::default();
    let r = g
        .run(
            &spec("deadline"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::Deadline);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    assert!(r.requires_reconciliation);
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .unknown_requests,
        1
    );
}

#[tokio::test]
async fn host_schema_profile_required_tool_and_vision_denials_happen_before_http() {
    for kind in ["schema", "profile", "required", "vision"] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![HttpPlan::sse(text_response(
            "must not send",
            false,
            true,
        ))])
        .await;
        let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
        let mut s = spec("denied");
        match kind {
            "schema" => s.output_schema = Some(json!({"$ref":"file:///private"})),
            "profile" => s.profile_id = "melissa.code.implementer".into(),
            "required" => {
                s.required_tool_names.insert("unprovided_tool".into());
            }
            _ => s.route.vision = true,
        }
        let error = g
            .run(
                &s,
                &mut FakeTools::default(),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind,
            match kind {
                "profile" => ErrorKind::Authorization,
                "required" => ErrorKind::Invalid,
                _ => ErrorKind::Unsupported,
            }
        );
        assert_eq!(http.requests.load(Ordering::SeqCst), 0);
        assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
    }
}

#[tokio::test]
async fn reopened_pending_request_is_unknown_and_same_run_cannot_replay_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "explicit fresh run candidate",
        false,
        true,
    ))])
    .await;
    let mut g = gateway(store(&root, 10_000), &http, policy());
    let task_version = g.store().journal().task(TASK).unwrap().record.version;
    let time = melissa_execution_broker::unix_ms().unwrap();
    let reservation = ModelReservation {
        schema_version: "melissa.model-reservation/v1".into(),
        request_id: "model:interrupted:1".into(),
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        provider_id: "fixture-provider".into(),
        model_id: "fixture-model".into(),
        request_digest: format!("blake3:{}", "a".repeat(64)),
        pricing_digest: Some(format!("blake3:{}", "b".repeat(64))),
        reserved_input_tokens: 1024,
        reserved_output_tokens: 128,
        reserved_cost_micro_usd: 1152,
        created_at_unix_ms: time,
    };
    g.store_mut()
        .journal_mut()
        .reserve_model_request(&reservation, task_version)
        .unwrap();
    g.store_mut()
        .journal_mut()
        .dispatch_model_request(&reservation.request_id, 0, time)
        .unwrap();
    drop(g);
    let reopened = LocalStore::open(
        &root,
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let recovered = reopened
        .journal()
        .model_request(&reservation.request_id)
        .unwrap();
    assert_eq!(recovered.state, ModelRequestState::OutcomeUnknown);
    assert_eq!(recovered.version, 2);
    let mut g = gateway(reopened, &http, policy());
    let error = g
        .run(
            &spec("interrupted"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Store);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        g.store()
            .journal()
            .model_request(&reservation.request_id)
            .unwrap(),
        recovered
    );
    let result = g
        .run(
            &spec("explicit-fresh"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .unknown_requests,
        1
    );
    assert_eq!(
        g.store()
            .journal()
            .model_request(&reservation.request_id)
            .unwrap(),
        recovered
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn expired_host_authority_stops_before_creating_or_sending_a_model_request() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        "must not send",
        false,
        true,
    ))])
    .await;
    let mut p = policy();
    p.expires_at_unix_ms = melissa_execution_broker::unix_ms()
        .unwrap()
        .saturating_sub(1);
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, p);
    let result = g
        .run(
            &spec("expired"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::Deadline);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(g.store().journal().model_requests(TASK).unwrap().is_empty());
    assert!(!result.requires_reconciliation);
}

#[tokio::test]
async fn provider_usage_overrun_is_durably_recorded_and_blocks_tool_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let raw = String::from_utf8(tool_response(&[(
        "overrun_call",
        "process_exec",
        r#"{"value":"do not execute"}"#,
    )]))
    .unwrap();
    let mut events = Vec::new();
    for line in raw.lines().filter_map(|line| line.strip_prefix("data: ")) {
        let mut event: Value = serde_json::from_str(line).unwrap();
        if event["type"] == "response.completed" {
            event["response"]["usage"]["output_tokens"] = json!(1500);
            event["response"]["usage"]["total_tokens"] = json!(1512);
        }
        events.push(event);
    }
    let http = http_fixture(vec![HttpPlan::sse(wire(events))]).await;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, policy());
    let mut tools = FakeTools::default();
    let result = g
        .run(
            &spec("overrun"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::BudgetExhausted);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert!(budget.budget_exceeded);
    assert_eq!(budget.known_output_tokens, 1500);
    assert_eq!(budget.charged_cost_micro_usd, 1512);
    assert!(!result.task_accepted);
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn proven_connection_failure_before_send_has_zero_usage_and_no_unknown_hold_or_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut http = http_fixture(vec![]).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    http.url = format!("http://{}/responses", closed.local_addr().unwrap());
    drop(closed);
    let mut p = policy();
    p.max_wall_time_ms = 20_000;
    let mut g = gateway(store(&dir.path().join("store"), 10_000), &http, p);
    let mut tools = FakeTools::default();
    let s = spec("notsent");
    let result = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::ProviderFailed);
    assert!(
        !result.requires_reconciliation,
        "{:?}",
        g.store()
            .journal()
            .model_request(&result.request_ids[0])
            .unwrap()
            .settlement
    );
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
    let budget = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(
        (
            budget.charged_input_tokens,
            budget.charged_output_tokens,
            budget.charged_cost_micro_usd,
            budget.unknown_requests,
            budget.active_requests
        ),
        (0, 0, 0, 0, 0)
    );
    let original = g
        .store()
        .journal()
        .model_request(&result.request_ids[0])
        .unwrap();
    assert_eq!(original.state, ModelRequestState::Failed);
    assert_eq!(
        original.settlement.as_ref().unwrap().usage.cost_micro_usd,
        Some(0)
    );
    let error = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Store);
    assert_eq!(g.store().journal().model_requests(TASK).unwrap().len(), 1);
    assert_eq!(
        g.store()
            .journal()
            .model_request(&result.request_ids[0])
            .unwrap(),
        original
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn unpriced_model_with_exhausted_cost_budget_stops_as_budget_exhausted() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response("never", false, true))]).await;
    let mut st = store(&dir.path().join("store"), 100_000);
    // Reserve the whole cost budget so nothing is left for the next request.
    let task = st.journal().task(TASK).unwrap();
    let reservation = ModelReservation {
        schema_version: "melissa.model-reservation/v1".into(),
        request_id: "pre".into(),
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        provider_id: "x".into(),
        model_id: "y".into(),
        request_digest: format!("blake3:{}", "0".repeat(64)),
        pricing_digest: None,
        reserved_input_tokens: 0,
        reserved_output_tokens: 0,
        reserved_cost_micro_usd: 100_000,
        created_at_unix_ms: melissa_execution_broker::unix_ms().unwrap(),
    };
    st.journal_mut()
        .reserve_model_request(&reservation, task.record.version)
        .unwrap();
    let mut g = gateway_unpriced(st, &http, policy());
    let result = g
        .run(
            &spec("unpriced"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::BudgetExhausted);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}
