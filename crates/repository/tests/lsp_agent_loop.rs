//! Real Gateway HTTP/SSE -> repository broker -> filesystem -> continuation.
//! Deterministic owned loopback data, not live model or product acceptance.
#![cfg(windows)]
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_model_gateway::{
    DecoderLimits, Protocol,
    agent_loop::{Gateway, GatewayPolicy, RunSpec, RunStatus},
    routing::{
        Capabilities, Measurements, ModelRegistration, PriceSource, RateCard, RouteRequirements,
    },
    transport::{ApiKey, EndpointTrust, ProviderEndpoint},
};
use melissa_repository::{Limits, Repository};
mod support;
use melissa_repository::{
    analysis::{AnalysisPlan, AnalysisQuery, LspMethod, TOOLING_IMAGE},
    tools::{RepositoryRead, RepositoryReadDispatcher, RepositoryReadPolicy},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
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
const TASK: &str = "task:repository-agent-loop";
const PROFILE: &str = "melissa.code.repository-analyst";
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
fn store(root: &Path, input_budget: u64, input_digest: String) -> LocalStore {
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
    task.input_snapshot_digest = input_digest;
    task.authorization_refs.push("auth:closeout".into());
    task.selected_profile_ids = vec![PROFILE.into()];
    task.allowed_effects = vec!["workspace.read".into(), "git.read".into()];
    task.limits.max_output_bytes = 32 * 1024 * 1024;
    task.limits.max_disk_bytes = 256 * 1024 * 1024;
    task.limits.max_wall_time_ms = 120_000;
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
        max_wall_time_ms: 60_000,
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
            context_tokens: 32768,
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

#[tokio::test]
async fn real_lsp_gateway_sse_worker_result_reaches_the_next_model_request() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("lib.rs"),
        b"pub fn selected(){}\npub fn caller(){selected();}\n",
    )
    .unwrap();
    let repo = Repository::open_for_git(&root, Limits::default()).unwrap();
    let source = repo.snapshot(&AtomicBool::new(false)).unwrap();
    let query = AnalysisQuery::Lsp {
        method: LspMethod::References,
        path: "lib.rs".into(),
        line: 0,
        character: 8,
        include_declaration: false,
        root_modules: vec!["lib.rs".into()],
    };
    let plan = AnalysisPlan::prepare(
        &repo,
        &source,
        query.clone(),
        TOOLING_IMAGE,
        support::limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let operation = RepositoryRead::Analysis(query);
    let args = serde_json::to_string(&operation).unwrap();
    let http=http_fixture(vec![HttpPlan::sse(tool_response(&[("call_semantic","code_lsp_references",&args)])),HttpPlan::sse(text_response("The semantic source-bound reference is observed; independent task acceptance stays pending.",false,true))]).await;
    let mut g = gateway(
        store(
            &dir.path().join("store"),
            200_000,
            plan.snapshot.digest().unwrap(),
        ),
        &http,
        policy(),
    );
    let t = g.store().journal().task(TASK).unwrap().contract;
    let mut tools = RepositoryReadDispatcher::new(
        repo,
        g.store().connect().unwrap(),
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        RepositoryReadPolicy {
            task_id: TASK.into(),
            profile_id: PROFILE.into(),
            principal_id: "principal:closeout".into(),
            resource_id: t.workspace_ref,
            authorization_ref: "auth:closeout".into(),
            expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120_000,
            limits: support::limits(),
            operations: vec![operation],
        },
    )
    .unwrap();
    assert!(
        !g.store()
            .journal()
            .task(TASK)
            .unwrap()
            .contract
            .allowed_effects
            .iter()
            .any(|e| e.starts_with("process."))
    );
    let mut s = spec("semantic_loop");
    s.required_tool_names.insert("code_lsp_references".into());
    let r = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 1);
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    assert!(!r.task_accepted);
    let bodies = http.bodies.lock().unwrap();
    let observed = bodies[1]["input"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "function_call_output")
        .unwrap();
    let result: Value = serde_json::from_str(observed["output"].as_str().unwrap()).unwrap();
    assert_eq!(result["locations"].as_array().unwrap().len(), 1);
    assert_eq!(result["locations"][0]["version"]["path"], "lib.rs");
    assert_eq!(result["task_accepted"], false);
    g.store().integrity_check().unwrap();
}
