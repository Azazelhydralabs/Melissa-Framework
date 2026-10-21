//! Additional deterministic loopback acceptance cases. These are not live-model
//! evidence, autonomous product recovery, or independent task acceptance.
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey, journal::ModelRequestState};
use melissa_model_gateway::{
    DecoderLimits, Protocol, Result, ToolCall, ToolDefinition,
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

const TASK: &str = "task:remaining-acceptance";
const PROFILE: &str = "melissa.code.debugger";
const RESOURCE: &str = "provider:remaining-fixture";
const AUTH: &str = "authorization:remaining-fixture";

struct Plan {
    body: Vec<u8>,
    delay: Duration,
}
impl Plan {
    fn sse(events: Vec<Value>) -> Self {
        let mut wire = String::new();
        for (sequence, mut event) in events.into_iter().enumerate() {
            event["sequence_number"] = json!(sequence);
            wire.push_str(&format!(
                "event: {}\ndata: {}\n\n",
                event["type"].as_str().unwrap(),
                event
            ));
        }
        Self {
            body: wire.into_bytes(),
            delay: Duration::ZERO,
        }
    }
}

struct Fixture {
    url: String,
    received: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture(plans: Vec<Plan>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&received);
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
                assert!(bytes.len() <= 2 * 1024 * 1024);
                if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break offset + 4;
                }
            };
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 2 * 1024 * 1024);
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
                "HTTP/1.1 200 Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                plan.body.len()
            );
            if socket.write_all(headers.as_bytes()).await.is_ok() {
                let _ = socket.write_all(&plan.body).await;
            }
        }
    });
    Fixture {
        url: format!("http://{address}/v1/responses"),
        received,
        bodies,
        task,
    }
}

fn start() -> Value {
    json!({"type":"response.created","response":{"id":"resp_remaining","model":"fixture-snapshot","status":"in_progress","output":[]}})
}
fn terminal(output: Vec<Value>, known_usage: bool) -> Value {
    json!({"type":"response.completed","response":{"id":"resp_remaining","model":"fixture-snapshot","status":"completed","error":null,"incomplete_details":null,"output":output,"usage":if known_usage{json!({"input_tokens":12,"output_tokens":4,"total_tokens":16})}else{Value::Null}}})
}
fn calls(calls: &[(&str, &str)]) -> Vec<Value> {
    let mut events = vec![start()];
    let mut output = Vec::new();
    for (index, (call_id, arguments)) in calls.iter().enumerate() {
        let id = format!("fc_{index}");
        let item = json!({"id":id,"type":"function_call","call_id":call_id,"name":"process_exec","arguments":arguments,"status":"completed"});
        let mut initial = item.clone();
        initial["arguments"] = json!("");
        initial["status"] = json!("in_progress");
        events.extend([
            json!({"type":"response.output_item.added","output_index":index,"item":initial}),
            json!({"type":"response.function_call_arguments.delta","output_index":index,"item_id":id,"delta":arguments}),
            json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":id,"arguments":arguments}),
            json!({"type":"response.output_item.done","output_index":index,"item":item.clone()}),
        ]);
        output.push(item);
    }
    events.push(terminal(output, true));
    events
}
fn text(text: &str, refusal: bool, known_usage: bool) -> Vec<Value> {
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
    let item = json!({"id":"msg_remaining","type":"message","role":"assistant","status":"completed","content":[part]});
    let mut initial = item.clone();
    initial["status"] = json!("in_progress");
    initial["content"] = json!([]);
    vec![
        start(),
        json!({"type":"response.output_item.added","output_index":0,"item":initial}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_remaining","content_index":0,"part":initial_part}),
        json!({"type":format!("{prefix}.delta"),"output_index":0,"item_id":"msg_remaining","content_index":0,"delta":text}),
        json!({"type":format!("{prefix}.done"),"output_index":0,"item_id":"msg_remaining","content_index":0,field:text}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_remaining","content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":item.clone()}),
        terminal(vec![item], known_usage),
    ]
}
fn store(root: &Path, input_budget: u64) -> LocalStore {
    let mut store = LocalStore::open(
        root,
        StoreKey::from_bytes([119; 32]),
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
    store.journal_mut().create_task(&task).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = store.journal().task(TASK).unwrap().record.version;
        store.transition_task(TASK, version, state, None).unwrap();
    }
    store
}
fn gateway(store: LocalStore, http: &Fixture, max_requests: u32, timeout_ms: u64) -> Gateway {
    Gateway::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        vec![ModelRegistration {
            registration_id: "remaining-route".into(),
            endpoint: ProviderEndpoint::new(
                "remaining-provider".into(),
                RESOURCE.into(),
                AUTH.into(),
                Protocol::OpenAiResponses,
                EndpointTrust::LoopbackFixture,
                &http.url,
                ApiKey::new("remaining-fixture-not-a-secret".into()).unwrap(),
            )
            .unwrap(),
            model_id: "remaining-model".into(),
            capabilities: Capabilities {
                tool_calling: true,
                structured_output: true,
                vision: false,
                streaming: true,
            },
            categories: BTreeSet::from(["coding".into()]),
            context_tokens: 1024,
            max_output_tokens: 128,
            timeout_ms,
            max_concurrency: 1,
            rate_card: Some(RateCard {
                source: PriceSource::Fixture,
                input_micro_usd_per_million: 1_000_000,
                output_micro_usd_per_million: 1_000_000,
                cached_input_micro_usd_per_million: Some(1_000_000),
                cache_creation_micro_usd_per_million: None,
            }),
            measurements: Measurements::default(),
            slots: Arc::new(Semaphore::new(1)),
        }],
        GatewayPolicy {
            allowed_registrations: BTreeSet::from(["remaining-route".into()]),
            max_requests,
            max_turns: 8,
            max_tools: 8,
            max_wall_time_ms: 15_000,
            expires_at_unix_ms: melissa_execution_broker::unix_ms().unwrap() + 60_000,
            allow_fallback: false,
            max_backoff_ms: 0,
            decoder_limits: DecoderLimits::default(),
        },
        true,
    )
    .unwrap()
}
fn spec(run_id: &str) -> RunSpec {
    RunSpec {
        run_id: run_id.into(),
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        user_message: "Return observations for this owned deterministic fixture.".into(),
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
        required_tool_names: BTreeSet::from(["process_exec".into()]),
    }
}
#[derive(Default)]
struct CountingTools {
    executed: Vec<String>,
    cancel_after_first: Option<Arc<AtomicBool>>,
}
impl ToolDispatcher for CountingTools {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: "process.exec".into(),
            definition: ToolDefinition {
                name: "process_exec".into(),
                description: "Count owned local fixture dispatches only".into(),
                parameters: json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}),
                strict: false,
            },
        }]
    }
    fn validate_call(&self, call: &ToolCall) -> Result<()> {
        melissa_model_gateway::schema::validate_output(
            &self.definitions()[0].definition.parameters,
            &call.arguments,
        )
        .map(|_| ())
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        _context: ToolContext,
        _cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            self.executed.push(call.id);
            if let Some(flag) = &self.cancel_after_first {
                flag.store(true, Ordering::Release);
            }
            Ok(ToolExecution {
                content:
                    json!({"status":"observed","fixture":true,"marker":"OBSERVED_REPAIRED_CALL"})
                        .to_string(),
                success: true,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: vec![],
            })
        })
    }
}
fn artifact(gateway: &Gateway, id: &str) -> Value {
    serde_json::from_slice(&gateway.store().get_artifact(TASK, id).unwrap()).unwrap()
}
fn assert_running(gateway: &Gateway) {
    assert_eq!(
        gateway.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    gateway.store().integrity_check().unwrap();
}

#[tokio::test]
async fn entire_bad_batch_is_rejected_then_one_fresh_corrected_call_can_be_observed() {
    // These valid JSON argument errors reach host schema preflight, rather than
    // being rejected by the wire decoder before bounded repair is possible.
    for bad_arguments in [r#"{}"#, r#"{"value":"x","extra":true}"#, r#"{"value":7}"#] {
        let dir = tempfile::tempdir().unwrap();
        let http = fixture(vec![
            Plan::sse(calls(&[
                (
                    "initial_valid",
                    r#"{"value":"must also remain unexecuted"}"#,
                ),
                ("initial_invalid", bad_arguments),
            ])),
            Plan::sse(calls(&[("fresh_repaired", r#"{"value":"corrected"}"#)])),
            Plan::sse(text("Observed the single repaired call.", false, true)),
        ])
        .await;
        let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 3, 5000);
        let mut tools = CountingTools::default();
        let result = gateway
            .run(
                &spec("repair"),
                &mut tools,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(result.status, RunStatus::FinalCandidate);
        assert_eq!(result.tool_calls, 1);
        assert_eq!(tools.executed, ["fresh_repaired"]);
        assert_eq!(http.received.load(Ordering::SeqCst), 3);
        assert!(!result.task_accepted);
        assert!(!result.requires_reconciliation);
        let rejected = artifact(&gateway, "model:repair:1:tool-preflight");
        assert_eq!(rejected["batch_valid"], false);
        assert_eq!(rejected["executed"], false);
        assert_eq!(
            rejected["call_ids"],
            json!(["initial_valid", "initial_invalid"])
        );
        assert_eq!(
            artifact(&gateway, "model:repair:2:tool-preflight")["batch_valid"],
            true
        );
        let bodies = http.bodies.lock().unwrap();
        let feedback: Vec<_> = bodies[1]["input"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["type"] == "function_call_output")
            .collect();
        assert_eq!(feedback.len(), 2);
        for item in feedback {
            let envelope: Value = serde_json::from_str(item["output"].as_str().unwrap()).unwrap();
            assert_eq!(envelope["is_error"], true);
            let content: Value =
                serde_json::from_str(envelope["content"].as_str().unwrap()).unwrap();
            assert_eq!(
                content,
                json!({"status":"invalid_arguments_or_tool","executed":false})
            );
        }
        assert!(bodies[2]["input"].as_array().unwrap().iter().any(|item| {
            item["type"] == "function_call_output"
                && item["call_id"] == "fresh_repaired"
                && item["output"]
                    .as_str()
                    .is_some_and(|v| v.contains("OBSERVED_REPAIRED_CALL"))
        }));
        assert_running(&gateway);
    }
}

#[tokio::test]
async fn repeated_invalid_arguments_stop_at_request_limit_without_dispatch_or_extra_send() {
    let dir = tempfile::tempdir().unwrap();
    let http = fixture(vec![
        Plan::sse(calls(&[("bad_1", "{}")])),
        Plan::sse(calls(&[("bad_2", "{}")])),
        Plan::sse(calls(&[("forbidden_third", r#"{"value":"too late"}"#)])),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 2, 5000);
    let mut tools = CountingTools::default();
    let result = gateway
        .run(
            &spec("boundedrepair"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::RequestLimit);
    assert_eq!(http.received.load(Ordering::SeqCst), 2);
    assert_eq!(result.request_ids.len(), 2);
    assert!(tools.executed.is_empty());
    assert_eq!(result.tool_calls, 0);
    assert!(result.answer.is_none());
    assert!(!result.task_accepted);
    assert_running(&gateway);
}

#[tokio::test]
async fn provider_refusal_after_an_observed_tool_is_terminal_and_never_task_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let http = fixture(vec![
        Plan::sse(calls(&[("before_refusal", r#"{"value":"observed"}"#)])),
        Plan::sse(text("Fixture typed refusal.", true, true)),
        Plan::sse(text("forbidden retry", false, true)),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 3, 5000);
    let mut tools = CountingTools::default();
    let result = gateway
        .run(
            &spec("laterrefusal"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::Refused);
    assert_eq!(tools.executed, ["before_refusal"]);
    assert_eq!(result.tool_calls, 1);
    assert_eq!(http.received.load(Ordering::SeqCst), 2);
    assert!(result.answer.is_none());
    assert!(!result.task_accepted);
    assert!(!result.requires_reconciliation);
    assert_eq!(
        artifact(&gateway, "model:laterrefusal:2:response")["stop"],
        "refusal"
    );
    assert_running(&gateway);
}

#[tokio::test]
async fn completed_tool_item_inside_max_token_terminal_never_executes() {
    let dir = tempfile::tempdir().unwrap();
    let mut events = calls(&[("complete_but_truncated", r#"{"value":"do not run"}"#)]);
    let terminal = events.last_mut().unwrap();
    terminal["type"] = json!("response.incomplete");
    terminal["response"]["status"] = json!("incomplete");
    terminal["response"]["incomplete_details"] = json!({"reason":"max_output_tokens"});
    let http = fixture(vec![Plan::sse(events)]).await;
    let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 2, 5000);
    let mut tools = CountingTools::default();
    let result = gateway
        .run(
            &spec("truncatedtool"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::InvalidOutput);
    assert_eq!(http.received.load(Ordering::SeqCst), 1);
    assert!(tools.executed.is_empty());
    assert_eq!(result.tool_calls, 0);
    assert!(!result.task_accepted);
    assert!(!result.requires_reconciliation);
    assert_eq!(
        artifact(&gateway, "model:truncatedtool:1:response")["stop"],
        "max_tokens"
    );
    assert_eq!(
        gateway
            .store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .known_input_tokens,
        12
    );
    assert_running(&gateway);
}

#[tokio::test]
async fn successful_response_with_unknown_usage_retains_budget_and_blocks_a_fresh_run_before_http()
{
    let dir = tempfile::tempdir().unwrap();
    let http = fixture(vec![
        Plan::sse(text("Candidate without usage.", false, false)),
        Plan::sse(text("must not be sent", false, true)),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("store"), 2047), &http, 2, 5000);
    let mut first_spec = spec("usageunknown");
    first_spec.required_tool_names.clear();
    let first = gateway
        .run(
            &first_spec,
            &mut CountingTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(first.status, RunStatus::FinalCandidate);
    let original = gateway
        .store()
        .journal()
        .model_request(&first.request_ids[0])
        .unwrap();
    assert_eq!(original.state, ModelRequestState::Succeeded);
    let budget = gateway.store().journal().model_budget(TASK).unwrap();
    assert_eq!(budget.charged_input_tokens, 1024);
    assert_eq!(budget.charged_output_tokens, 128);
    assert_eq!(budget.charged_cost_micro_usd, 1152);
    assert_eq!(budget.unknown_input_requests, 1);
    assert_eq!(budget.unknown_output_requests, 1);
    assert_eq!(budget.unknown_cost_requests, 1);
    let second = gateway
        .run(
            &spec("freshafterunknown"),
            &mut CountingTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(second.status, RunStatus::BudgetExhausted);
    assert!(second.request_ids.is_empty());
    assert_eq!(http.received.load(Ordering::SeqCst), 1);
    assert_eq!(
        gateway
            .store()
            .journal()
            .model_requests(TASK)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        gateway
            .store()
            .journal()
            .model_request(&first.request_ids[0])
            .unwrap(),
        original
    );
    assert_eq!(
        gateway.store().journal().model_budget(TASK).unwrap(),
        budget
    );
    assert!(!first.task_accepted && !second.task_accepted);
    assert_running(&gateway);
}

#[tokio::test]
async fn provider_timeout_after_confirmed_send_is_distinct_from_host_deadline_and_keeps_unknown_hold()
 {
    let dir = tempfile::tempdir().unwrap();
    let mut delayed = Plan::sse(text("too late", false, true));
    delayed.delay = Duration::from_secs(5);
    let http = fixture(vec![delayed]).await;
    let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 2, 500);
    let mut tools = CountingTools::default();
    let result = gateway
        .run(
            &spec("providertimeout"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(
        http.received.load(Ordering::SeqCst),
        1,
        "the server must have received the request"
    );
    assert_eq!(result.status, RunStatus::ProviderFailed);
    assert_eq!(result.request_ids.len(), 1);
    assert!(result.requires_reconciliation);
    assert!(tools.executed.is_empty());
    assert!(!result.task_accepted);
    let receipt = artifact(&gateway, "model:providertimeout:1:receipt");
    assert_eq!(receipt["error_kind"], "timeout");
    assert_eq!(receipt["accepted_complete"], false);
    assert_ne!(receipt["delivery"], "not_sent");
    let record = gateway
        .store()
        .journal()
        .model_request(&result.request_ids[0])
        .unwrap();
    assert_eq!(record.state, ModelRequestState::OutcomeUnknown);
    let budget = gateway.store().journal().model_budget(TASK).unwrap();
    assert_eq!(budget.unknown_requests, 1);
    assert_eq!(budget.charged_cost_micro_usd, 1152);
    assert_running(&gateway);
}

#[tokio::test]
async fn cancellation_after_first_observation_prevents_the_second_preflighted_call() {
    let dir = tempfile::tempdir().unwrap();
    let http = fixture(vec![Plan::sse(calls(&[
        ("first_observed", r#"{"value":"first"}"#),
        ("second_forbidden", r#"{"value":"second"}"#),
    ]))])
    .await;
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut gateway = gateway(store(&dir.path().join("store"), 10_000), &http, 2, 5000);
    let mut tools = CountingTools {
        cancel_after_first: Some(Arc::clone(&cancelled)),
        ..Default::default()
    };
    let result = gateway
        .run(&spec("betweenbatchcalls"), &mut tools, cancelled)
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::Cancelled);
    assert_eq!(tools.executed, ["first_observed"]);
    assert_eq!(result.tool_calls, 1);
    assert_eq!(http.received.load(Ordering::SeqCst), 1);
    assert!(result.answer.is_none());
    assert!(!result.task_accepted);
    assert!(!result.requires_reconciliation);
    assert_eq!(
        artifact(&gateway, "model:betweenbatchcalls:1:tool-preflight")["batch_valid"],
        true
    );
    assert_running(&gateway);
}
