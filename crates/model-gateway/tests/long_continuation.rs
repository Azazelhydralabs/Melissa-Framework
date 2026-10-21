//! Real loopback HTTP and encrypted CAS acceptance for finite, lossless native
//! history. Model/tool output is synthetic. No live key, model or worker runs.
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey, journal::ModelRequestState};
use melissa_model_gateway::{
    DecoderLimits, ErrorKind, Message, ModelResponse, Protocol, RequestLimits, Result, StopReason,
    ToolCall, ToolDefinition, TurnRequest, Usage,
    agent_loop::{Gateway, GatewayPolicy, RunSpec, RunStatus},
    routing::{
        Capabilities, Measurements, ModelRegistration, PriceSource, RateCard, RouteRequirements,
    },
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
    transport::{ApiKey, EndpointTrust, HttpTransport, ProviderEndpoint},
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

const TASK: &str = "task:long-history-fixture";
const PROFILE: &str = "melissa.code.debugger";
const RESOURCE: &str = "provider:long-history-fixture";
const AUTH: &str = "authorization:long-history-fixture";
const MODEL: &str = "owned-long-fixture-model";
const HISTORY: usize = 48 * 1024 * 1024;

fn limits() -> DecoderLimits {
    DecoderLimits {
        max_event_bytes: 8 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_output_bytes: 8 * 1024 * 1024,
        ..DecoderLimits::default()
    }
}
fn wire(events: Vec<Value>) -> Vec<u8> {
    let mut raw = String::new();
    for (sequence, mut event) in events.into_iter().enumerate() {
        event["sequence_number"] = json!(sequence);
        raw.push_str(&format!("data: {event}\n\n"));
    }
    raw.into_bytes()
}
fn created(id: &str) -> Value {
    json!({"type":"response.created","response":{"id":id,"model":MODEL,"status":"in_progress","output":[]}})
}
fn completed(id: &str, output: Vec<Value>) -> Value {
    // Known synthetic usage fields exercise ledger settlement, not tokenization.
    json!({"type":"response.completed","response":{"id":id,"model":MODEL,"status":"completed","error":null,"incomplete_details":null,"output":output,"usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16}}})
}
fn add_text(events: &mut Vec<Value>, index: usize, id: &str, text: &str) -> Value {
    let part = json!({"type":"output_text","text":text,"annotations":[],"logprobs":[]});
    let item =
        json!({"type":"message","id":id,"role":"assistant","status":"completed","content":[part]});
    let mut initial = item.clone();
    initial["status"] = json!("in_progress");
    initial["content"] = json!([]);
    let mut empty_part = part.clone();
    empty_part["text"] = json!("");
    events.extend([
        json!({"type":"response.output_item.added","output_index":index,"item":initial}),
        json!({"type":"response.content_part.added","output_index":index,"item_id":id,"content_index":0,"part":empty_part}),
        json!({"type":"response.output_text.delta","output_index":index,"item_id":id,"content_index":0,"delta":text}),
        json!({"type":"response.output_text.done","output_index":index,"item_id":id,"content_index":0,"text":text}),
        json!({"type":"response.content_part.done","output_index":index,"item_id":id,"content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":index,"item":item}),
    ]);
    item
}
fn long_tool_response(text: &str, opaque: &str) -> Vec<u8> {
    let mut events = vec![created("resp_long_tool")];
    let reasoning = json!({"id":"rs_long","type":"reasoning","status":"completed","summary":[],"encrypted_content":opaque});
    events.extend([
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"rs_long","type":"reasoning","status":"in_progress","summary":[]}}),
        json!({"type":"response.output_item.done","output_index":0,"item":reasoning}),
    ]);
    let message = add_text(&mut events, 1, "msg_long", text);
    let call = json!({"id":"fc_long","type":"function_call","call_id":"call_long","name":"process_exec","arguments":"{\"value\":\"owned\"}","status":"completed"});
    let mut initial = call.clone();
    initial["arguments"] = json!("");
    initial["status"] = json!("in_progress");
    events.extend([
        json!({"type":"response.output_item.added","output_index":2,"item":initial}),
        json!({"type":"response.function_call_arguments.delta","output_index":2,"item_id":"fc_long","delta":call["arguments"]}),
        json!({"type":"response.function_call_arguments.done","output_index":2,"item_id":"fc_long","arguments":call["arguments"]}),
        json!({"type":"response.output_item.done","output_index":2,"item":call}),
        completed("resp_long_tool", vec![reasoning, message, call]),
    ]);
    wire(events)
}
fn final_response(text: &str) -> Vec<u8> {
    let mut events = vec![created("resp_long_final")];
    let message = add_text(&mut events, 0, "msg_long_final", text);
    events.push(completed("resp_long_final", vec![message]));
    wire(events)
}
struct Fixture {
    url: String,
    count: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture(plans: Vec<Vec<u8>>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let received = Arc::clone(&count);
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&bodies);
    let task = tokio::spawn(async move {
        for body in plans {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 16381];
            let end = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() < 64 * 1024);
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
            assert!(length <= HISTORY);
            while bytes.len() - end < length {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            captured
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&bytes[end..end + length]).unwrap());
            received.fetch_add(1, Ordering::SeqCst);
            let headers = format!(
                "HTTP/1.1 200 Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            // An odd chunk size also crosses multi-byte Unicode boundaries.
            for bytes in body.chunks(16381) {
                socket.write_all(bytes).await.unwrap();
            }
        }
    });
    Fixture {
        url: format!("http://{address}/v1/responses"),
        count,
        bodies,
        task,
    }
}
fn endpoint(url: &str) -> ProviderEndpoint {
    ProviderEndpoint::new(
        "owned-long-provider".into(),
        RESOURCE.into(),
        AUTH.into(),
        Protocol::OpenAiResponses,
        EndpointTrust::LoopbackFixture,
        url,
        ApiKey::new("owned-loopback-not-a-live-credential".into()).unwrap(),
    )
    .unwrap()
}
fn gateway(root: &Path, fixture: &Fixture, large_history: bool) -> Gateway {
    gateway_with_stream(root, fixture, large_history, false)
}
fn gateway_with_stream(
    root: &Path,
    fixture: &Fixture,
    large_history: bool,
    large_stream: bool,
) -> Gateway {
    let fixture_wall = if large_stream { 300_000 } else { 120_000 };
    let mut store = LocalStore::open(
        root,
        StoreKey::from_bytes([74; 32]),
        StoreConfig {
            max_blob_bytes: if large_stream { 256 } else { 64 } * 1024 * 1024,
            max_cas_bytes: if large_stream { 1024 } else { 512 } * 1024 * 1024,
            ..StoreConfig::default()
        },
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
    task.limits.max_input_tokens = 2_097_152;
    task.limits.max_output_tokens = 786_432;
    task.limits.max_cost_micro_usd = 1_000_000;
    task.limits.max_wall_time_ms = fixture_wall;
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
    let gateway = Gateway::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        vec![ModelRegistration {
            registration_id: "owned-long-route".into(),
            endpoint: endpoint(&fixture.url),
            model_id: MODEL.into(),
            capabilities: Capabilities {
                tool_calling: true,
                structured_output: true,
                vision: false,
                streaming: true,
            },
            categories: BTreeSet::from(["coding".into()]),
            context_tokens: 1_048_576,
            max_output_tokens: 393_216,
            timeout_ms: fixture_wall,
            max_concurrency: 1,
            rate_card: Some(RateCard {
                source: PriceSource::Fixture,
                input_micro_usd_per_million: 1,
                output_micro_usd_per_million: 1,
                cached_input_micro_usd_per_million: Some(1),
                cache_creation_micro_usd_per_million: None,
            }),
            measurements: Measurements::default(),
            slots: Arc::new(Semaphore::new(1)),
        }],
        GatewayPolicy {
            allowed_registrations: BTreeSet::from(["owned-long-route".into()]),
            max_requests: 2,
            max_turns: 2,
            max_tools: 1,
            max_wall_time_ms: fixture_wall,
            expires_at_unix_ms: melissa_execution_broker::unix_ms().unwrap() + fixture_wall,
            allow_fallback: false,
            max_backoff_ms: 0,
            decoder_limits: {
                let mut selected = limits();
                if large_stream {
                    selected.max_total_bytes = 256 * 1024 * 1024;
                }
                selected
            },
        },
        true,
    )
    .unwrap();
    if large_history {
        gateway
            .with_request_limits(RequestLimits {
                max_history_bytes: HISTORY,
            })
            .unwrap()
    } else {
        gateway
    }
}
fn spec(schema: Option<Value>) -> RunSpec {
    RunSpec {
        run_id: "long_history".into(),
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        user_message: "Owned local fixture: use the tool and read the resulting observation."
            .into(),
        route: RouteRequirements {
            category: "coding".into(),
            tools: true,
            structured_output: schema.is_some(),
            vision: false,
            minimum_success_ppm: None,
            maximum_p95_ms: None,
        },
        max_output_tokens: 393_216,
        output_schema: schema,
        required_tool_names: BTreeSet::from(["process_exec".into()]),
    }
}
#[derive(Default)]
struct Observation {
    calls: usize,
}
impl ToolDispatcher for Observation {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: "process.exec".into(),
            definition: ToolDefinition {
                name: "process_exec".into(),
                description: "Owned synthetic observation; does not execute a process".into(),
                parameters: json!({"type":"object","properties":{"value":{"const":"owned"}},"required":["value"],"additionalProperties":false}),
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
        context: ToolContext,
        _cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            self.calls += 1;
            assert_eq!(call.id, "call_long");
            assert_eq!(context.task_id, TASK);
            Ok(ToolExecution {
                content: json!({"status":"observed","fixture":true,"marker":"GERÇEK_GÖZLEM_🦀"})
                    .to_string(),
                success: true,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: vec![],
            })
        })
    }
}
fn hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

#[tokio::test]
async fn unicode_long_output_opaque_continuation_tool_and_second_http_are_lossless_in_encrypted_cas()
 {
    let text = "ş🦀Z\n".repeat(500_000); //4MiB UTF-8; repeated SSE framing exceeds old16MiB CAS.
    let opaque = "opaque_owned_".repeat(30_000);
    let raw = long_tool_response(&text, &opaque);
    assert!(raw.len() > 16 * 1024 * 1024);
    assert!(raw.len() < limits().max_total_bytes);
    let expected_raw_hash = blake3::hash(&raw);
    let raw_length = raw.len();
    let answer_text = "nihai_ş🦀".repeat(40_000);
    let answer = json!({"answer":answer_text}).to_string();
    assert!(answer.len() > 256 * 1024);
    let schema = json!({"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false});
    let fixture = fixture(vec![raw, final_response(&answer)]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut gateway = gateway(&dir.path().join("store"), &fixture, true);
    let mut tools = Observation::default();
    let result = gateway
        .run(
            &spec(Some(schema)),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert!(!result.task_accepted);
    assert!(!result.requires_reconciliation);
    assert_eq!(result.request_ids.len(), 2);
    assert_eq!(tools.calls, 1);
    assert_eq!(result.answer.as_deref(), Some(answer.as_str()));
    let first_raw = gateway
        .store()
        .get_artifact(TASK, "model:long_history:1:raw-sse")
        .unwrap();
    assert_eq!(first_raw.len(), raw_length);
    assert_eq!(blake3::hash(&first_raw), expected_raw_hash);
    let response: ModelResponse = serde_json::from_slice(
        &gateway
            .store()
            .get_artifact(TASK, "model:long_history:1:response")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(hash(&response.text), hash(&text));
    assert_eq!(response.text.as_bytes(), text.as_bytes());
    assert_eq!(
        hash(
            response.continuation[0]["encrypted_content"]
                .as_str()
                .unwrap()
        ),
        hash(&opaque)
    );
    let bytes = gateway
        .store()
        .get_artifact(TASK, "model:long_history:2:request")
        .unwrap();
    assert!(bytes.len() > 2 * 1024 * 1024);
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    let bodies = fixture.bodies.lock().unwrap();
    assert_eq!(fixture.count.load(Ordering::SeqCst), 2);
    assert_eq!(envelope["body"], bodies[1]);
    assert_eq!(envelope["configured_max_history_bytes"], HISTORY);
    assert_eq!(bodies[0]["max_output_tokens"], 393216);
    assert_eq!(bodies[1]["max_output_tokens"], 393216);
    assert_eq!(bodies[1]["store"], false);
    assert_eq!(bodies[1]["input"][1]["encrypted_content"], opaque);
    assert_eq!(
        hash(
            bodies[1]["input"][2]["content"][0]["text"]
                .as_str()
                .unwrap()
        ),
        hash(&text)
    );
    assert_eq!(bodies[1]["input"][3]["call_id"], "call_long");
    assert_eq!(bodies[1]["input"][4]["call_id"], "call_long");
    let observation: Value =
        serde_json::from_str(bodies[1]["input"][4]["output"].as_str().unwrap()).unwrap();
    assert_eq!(observation["marker"], "GERÇEK_GÖZLEM_🦀");
    assert_eq!(observation["fixture"], true);
    let records = gateway.store().journal().model_requests(TASK).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|r| r.state == ModelRequestState::Succeeded)
    );
    assert_eq!(
        gateway.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    gateway.store().integrity_check().unwrap();
    drop(bodies);
    // CAS files are ciphertext; the artifact API above authenticates/decrypts.
    let inventory = gateway
        .store()
        .artifact_metadata(TASK, "model:long_history:1:raw-sse")
        .unwrap();
    assert!(inventory.stored_bytes > inventory.plain_bytes);
    assert_eq!(inventory.plain_bytes, raw_length as u64);
    println!(
        "LONG_CONTINUATION_EVIDENCE {}",
        json!({
            "scope":"local_loopback_fixture_not_live_model", "http_requests":2,
            "raw_sse_bytes":raw_length,"raw_sse_blake3":expected_raw_hash.to_hex().to_string(),
            "normalized_utf8_bytes":text.len(),"normalized_text_blake3":hash(&text),
            "opaque_bytes":opaque.len(),"opaque_blake3":hash(&opaque),
            "second_request_evidence_bytes":bytes.len(),"second_wire_equals_evidence":true,
            "final_structured_utf8_bytes":answer.len(),"tool_observations":1,
            "encrypted_cas_verified":true,"task_accepted":false,"inference_requests":0
        })
    );
}

#[tokio::test]
async fn explicit_large_stream_policy_preserves_over_64mib_wire_cas_and_native_continuation() {
    let text = "\u{0001}🦀".repeat(200_000);
    let body = long_tool_response(&text, "owned opaque");
    let comment = format!(":{}\n\n", "p".repeat(8192));
    let mut raw = Vec::with_capacity(72 * 1024 * 1024 + body.len());
    while raw.len() < 70 * 1024 * 1024 {
        raw.extend_from_slice(comment.as_bytes());
    }
    raw.extend_from_slice(&body);
    assert!(raw.len() > 64 * 1024 * 1024 && raw.len() < 256 * 1024 * 1024);
    let expected_len = raw.len();
    let expected_hash = blake3::hash(&raw);
    let fixture = fixture(vec![raw, final_response("large stream observed")]).await;
    let root = tempfile::tempdir().unwrap();
    let mut gateway = gateway_with_stream(&root.path().join("store"), &fixture, true, true);
    let mut tools = Observation::default();
    let result = gateway
        .run(&spec(None), &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(tools.calls, 1);
    assert_eq!(result.request_ids.len(), 2);
    assert!(!result.task_accepted && !result.requires_reconciliation);
    let raw = gateway
        .store()
        .get_artifact(TASK, "model:long_history:1:raw-sse")
        .unwrap();
    assert_eq!(raw.len(), expected_len);
    assert_eq!(blake3::hash(&raw), expected_hash);
    let response: ModelResponse = serde_json::from_slice(
        &gateway
            .store()
            .get_artifact(TASK, "model:long_history:1:response")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.text, text);
    let second: Value = serde_json::from_slice(
        &gateway
            .store()
            .get_artifact(TASK, "model:long_history:2:request")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second["body"], fixture.bodies.lock().unwrap()[1]);
    assert_eq!(second["body"]["input"][2]["content"][0]["text"], text);
    gateway.store().integrity_check().unwrap();
    println!(
        "LARGE_STREAM_EVIDENCE {}",
        json!({"scope":"local_loopback_not_live_model","raw_bytes":expected_len,"raw_blake3":expected_hash.to_hex().to_string(),"text_utf8_bytes":text.len(),"encrypted_cas_and_second_wire_exact":true,"inference_requests":0})
    );
}

#[test]
fn extended_stream_policy_keeps_defaults_and_rejects_over_256mib_before_dispatch() {
    assert_eq!(DecoderLimits::default().max_total_bytes, 8 * 1024 * 1024);
    let mut selected = limits();
    selected.max_total_bytes = 256 * 1024 * 1024;
    selected.validate().unwrap();
    selected.max_total_bytes += 1;
    assert!(selected.validate().is_err());
    selected.max_total_bytes = 256 * 1024 * 1024;
    selected.max_output_bytes = 8 * 1024 * 1024 + 1;
    assert!(selected.validate().is_err());
}

#[tokio::test]
async fn unchanged_default_rejects_large_history_before_second_dispatch_without_shortening() {
    let fixture = fixture(vec![
        long_tool_response(&"ş🦀Z".repeat(180_000), "opaque"),
        final_response("unused"),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut gateway = gateway(&dir.path().join("store"), &fixture, false);
    let error = gateway
        .run(
            &spec(None),
            &mut Observation::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Invalid);
    assert_eq!(error.message, "request total bytes");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
    let records = gateway.store().journal().model_requests(TASK).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, ModelRequestState::Succeeded);
    assert!(
        !gateway
            .store()
            .get_artifact(TASK, "model:long_history:1:raw-sse")
            .unwrap()
            .is_empty()
    );
}

fn history_request(response: ModelResponse) -> TurnRequest {
    TurnRequest {
        model: MODEL.into(),
        system_prompt: "trusted host".into(),
        messages: vec![
            Message::User {
                text: "owned".into(),
            },
            Message::Assistant { response },
        ],
        tools: vec![],
        max_output_tokens: 393216,
        output_schema: None,
    }
}
fn response(protocol: Protocol, text: String, continuation: Vec<Value>) -> ModelResponse {
    ModelResponse {
        protocol,
        requested_model: MODEL.into(),
        model: MODEL.into(),
        response_id: "owned".into(),
        text,
        calls: vec![],
        stop: StopReason::EndTurn,
        usage: Usage::default(),
        continuation,
        refusal: None,
    }
}
#[test]
fn finite_host_history_policy_rejects_over_64mib_and_never_disables_ordering_or_native_validation()
{
    assert_eq!(RequestLimits::default().max_history_bytes, 2 * 1024 * 1024);
    for max in [0, RequestLimits::MAX_HISTORY_BYTES + 1, usize::MAX] {
        assert!(
            RequestLimits {
                max_history_bytes: max
            }
            .validate()
            .is_err()
        );
    }
    let selected = RequestLimits {
        max_history_bytes: RequestLimits::MAX_HISTORY_BYTES,
    };
    selected.validate().unwrap();
    // Exactly64MiB of text already exceeds64MiB once request metadata is counted.
    let too_big = history_request(response(
        Protocol::OpenAiResponses,
        "x".repeat(selected.max_history_bytes),
        vec![],
    ));
    assert_eq!(
        too_big.validate_with_limits(selected).unwrap_err().message,
        "request total bytes"
    );
    drop(too_big);
    let text = "ş🦀".repeat(200_000);
    let item = json!({"id":"msg_owned","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":text,"annotations":[],"logprobs":[]}]});
    let request = history_request(response(
        Protocol::OpenAiResponses,
        text.clone(),
        vec![item],
    ));
    assert!(HttpTransport::body(&endpoint("http://127.0.0.1:9/v1/responses"), &request).is_err());
    let body = HttpTransport::body_with_limits(
        &endpoint("http://127.0.0.1:9/v1/responses"),
        &request,
        selected,
    )
    .unwrap();
    assert_eq!(body["input"][1]["content"][0]["text"], text);
    for change in [
        "model",
        "protocol",
        "normalized_text",
        "pending_tool",
        "unmatched_observation",
    ] {
        let mut bad = request.clone();
        match change {
            "unmatched_observation" => bad.messages.push(Message::ToolResult {
                call_id: "invented".into(),
                content: "observed".into(),
                is_error: false,
            }),
            _ => {
                if let Message::Assistant { response } = &mut bad.messages[1] {
                    match change {
                        "model" => response.requested_model = "other-model".into(),
                        "protocol" => response.protocol = Protocol::AnthropicMessages,
                        "normalized_text" => response.text.push('!'),
                        _ => response.calls.push(ToolCall {
                            id: "unanswered".into(),
                            name: "process_exec".into(),
                            arguments: "{}".into(),
                        }),
                    }
                }
            }
        }
        assert!(
            HttpTransport::body_with_limits(
                &endpoint("http://127.0.0.1:9/v1/responses"),
                &bad,
                selected
            )
            .is_err(),
            "{change}"
        );
    }
}

#[test]
fn anthropic_additive_history_replays_full_signed_blocks_and_retains_protocol_call_checks() {
    let text = "ş🦀".repeat(200_000);
    let signature = "owned_signature".repeat(100);
    let blocks = vec![
        json!({"type":"thinking","thinking":"owned reasoning","signature":signature}),
        json!({"type":"text","text":text}),
    ];
    let request = history_request(response(Protocol::AnthropicMessages, text.clone(), blocks));
    assert!(melissa_model_gateway::anthropic::build_request(&request).is_err());
    let selected = RequestLimits {
        max_history_bytes: HISTORY,
    };
    let body =
        melissa_model_gateway::anthropic::build_request_with_limits(&request, selected).unwrap();
    assert_eq!(body["messages"][1]["content"][1]["text"], text);
    assert_eq!(body["messages"][1]["content"][0]["signature"], signature);
    let mut bad = request;
    if let Message::Assistant { response } = &mut bad.messages[1] {
        response.continuation[0]["signature"] = json!("");
    }
    assert!(melissa_model_gateway::anthropic::build_request_with_limits(&bad, selected).is_err());
}

#[test]
fn final_schema_output_can_use_explicit_decoder_capacity_while_tool_args_and_strict_checks_stay_bounded()
 {
    let schema = json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false});
    let text = json!({"text":"ş🦀".repeat(60_000)}).to_string();
    assert!(text.len() > 256 * 1024);
    assert!(melissa_model_gateway::schema::validate_output(&schema, &text).is_err());
    let value = melissa_model_gateway::schema::validate_output_with_limit(
        &schema,
        &text,
        limits().max_output_bytes,
    )
    .unwrap();
    assert_eq!(
        hash(value["text"].as_str().unwrap()),
        hash(&"ş🦀".repeat(60_000))
    );
    for bad in [
        "{\"text\":\"a\",\"text\":\"b\"}",
        "{\"text\":1}",
        "{\"text\":\"a\",\"extra\":true}",
        "{\"text\":\"partial",
    ] {
        assert!(
            melissa_model_gateway::schema::validate_output_with_limit(
                &schema,
                bad,
                limits().max_output_bytes
            )
            .is_err()
        );
    }
    assert!(
        melissa_model_gateway::schema::validate_output_with_limit(
            &json!({"$ref":"https://example.invalid/schema"}),
            "{}",
            limits().max_output_bytes
        )
        .is_err()
    );
    for max in [0, 8 * 1024 * 1024 + 1, usize::MAX] {
        assert!(
            melissa_model_gateway::schema::validate_output_with_limit(&schema, &text, max).is_err()
        );
    }
}
