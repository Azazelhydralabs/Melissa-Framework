#![allow(dead_code, unused_imports)]
//! Derived readonly helper fixture from accepted gateway tests; no duplicated old tests.
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
const PROFILE: &str = "melissa.code.implementer";
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
    task.allowed_effects.extend([
        "workspace.read".into(),
        "memory.propose".into(),
        "workspace.apply_patch_scoped".into(),
    ]);
    task.allowed_effects.sort();
    task.allowed_effects.dedup();
    task.workspace_ref = "workspace:code07".into();
    task.allowed_resource_ids.push(task.workspace_ref.clone());
    task.allowed_resource_ids.push(RESOURCE.into());
    task.authorization_refs.push(AUTH.into());
    task.limits.max_input_tokens = input_budget;
    task.limits.max_output_tokens = 1000000;
    task.limits.max_cost_micro_usd = 100_000_000;
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
        max_tools: 16,
        max_wall_time_ms: 120000,
        expires_at_unix_ms: melissa_execution_broker::unix_ms().unwrap() + 30_000,
        allow_fallback: false,
        max_backoff_ms: 0,
        decoder_limits: DecoderLimits::default(),
    }
}
fn gateway(store: LocalStore, http: &HttpFixture, policy: GatewayPolicy) -> Gateway {
    Gateway::new(
        store,
        extend_catalog(
            &Catalog::load(&root()).unwrap(),
            &BTreeSet::from([PROFILE.into()]),
        )
        .unwrap(),
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
            context_tokens: 1048576,
            max_output_tokens: 393216,
            timeout_ms: 30000,
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
        max_output_tokens: 393216,
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

mod common;
use melissa_skill_context::{
    assembly::{Assembly, load_packages},
    digest as cdigest,
    durable::{Freshness, JournalContinuation},
    package::SkillPolicy,
    release::*,
    runtime::{ContextDispatcher, ContextRuntime, RuntimeGrant, extend_catalog},
};
use std::collections::BTreeMap;
fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
fn current() -> Vec<melissa_core_contracts::design::SkillPin> {
    serde_json::from_slice(&std::fs::read(root().join("skills/code/code07-current.json")).unwrap())
        .unwrap()
}
fn setup_runtime(
    repo: Arc<melissa_repository::Repository>,
    s: LocalStore,
    pin: melissa_core_contracts::design::SkillPin,
) -> ContextRuntime {
    let registry = load_packages(&root(), std::slice::from_ref(&pin)).unwrap();
    let base = Catalog::load(&root()).unwrap();
    let catalog = extend_catalog(&base, &BTreeSet::from([PROFILE.into()])).unwrap();
    let profile = &catalog.profiles[PROFILE];
    let policy = SkillPolicy {
        epoch: "code07:test:1".into(),
        reviewed: BTreeSet::from([pin.content_digest.clone()]),
        publishers: BTreeSet::from(["melissa-local-development".into()]),
        revoked: BTreeSet::new(),
        tools: profile.tool_ids.iter().cloned().collect(),
        capabilities: profile
            .authority
            .capability_ceiling
            .iter()
            .cloned()
            .collect(),
        allow_helpers: true,
    };
    ContextRuntime::open(
        repo,
        s,
        catalog,
        RuntimeGrant {
            task_id: TASK.into(),
            profile_id: PROFILE.into(),
            principal_id: "principal:code07".into(),
            resource_id: "workspace:code07".into(),
            authorization_ref: AUTH.into(),
            namespace: common::namespace(),
            expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
            policy_epoch: policy.epoch.clone(),
            enabled: [
                "skill_load",
                "context_search",
                "memory_search",
                "memory_propose",
                "context_template",
                "skill_helper",
                "context_script",
                "context_factory",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            skill_policy: policy,
            pins: vec![pin],
        },
        registry,
        &[],
    )
    .unwrap()
}
fn fixture_repo(dir: &Path) -> Arc<melissa_repository::Repository> {
    let p = dir.join("repo");
    std::fs::create_dir(&p).unwrap();
    std::fs::write(
        p.join("calc.py"),
        b"def add(a: int, b: int) -> int:\n    return a+b\n",
    )
    .unwrap();
    std::fs::write(
        p.join("main.py"),
        b"from calc import add\nprint(add(2,3))\n",
    )
    .unwrap();
    Arc::new(
        melissa_repository::Repository::open(&p, melissa_repository::Limits::default(), vec![])
            .unwrap(),
    )
}
fn skill(s: &str) -> melissa_core_contracts::design::SkillPin {
    current()
        .into_iter()
        .find(|p| p.skill_id.ends_with(s))
        .unwrap()
}
fn signed(p: &melissa_skill_context::package::Package) -> (SignedRelease, PublisherPolicy) {
    let key = PublisherKey::generate().unwrap();
    let d = cdigest(b"independent test evidence");
    let r = EvaluationReceipt {
        provider_model: "loopback/fixture".into(),
        prompt_digest: cdigest(b"full prepared prompt"),
        source_digest: cdigest(b"real fixture source"),
        pin: p.version().pin.clone(),
        test_receipt_digest: d.clone(),
        evaluation_digest: cdigest(b"live task and protected oracle"),
        review_digest: cdigest(b"independent review"),
        verifier_digest: cdigest(b"verifier"),
        environment_digest: cdigest(b"immutable sdk"),
        passed: 1,
        total: 1,
    };
    let admitted = BTreeSet::from([
        r.test_receipt_digest.clone(),
        r.evaluation_digest.clone(),
        r.review_digest.clone(),
    ]);
    let policy = PublisherPolicy {
        keys: BTreeMap::from([(
            "key:test".into(),
            (p.version().publisher_id.clone(), key.public_key()),
        )]),
        revoked_keys: BTreeSet::new(),
        revoked_publishers: BTreeSet::new(),
        revoked_pins: BTreeSet::new(),
        epoch: 1,
        now_ms: 10,
        accepted_receipts: admitted,
    };
    let release = key
        .sign(ReleaseStatement {
            schema_version: "melissa.signed-skill-release/v1".into(),
            receipt: r,
            definition_digest: p.version().definition_digest.clone(),
            version_record_digest: cdigest(&serde_json::to_vec(p.version()).unwrap()),
            publisher: p.version().publisher_id.clone(),
            key_id: "key:test".into(),
            epoch: 1,
            expires_at_ms: u64::MAX,
        })
        .unwrap();
    (release, policy)
}

#[tokio::test]
async fn native_patch_preview_and_owned_cleanup_never_write_or_delete_user_source() {
    use melissa_repository::{
        ByteEdit, FilePatch, PatchPolicy, PatchProposal,
        tools::{RepositoryDispatcher, RepositoryToolPolicy},
    };
    use melissa_skill_context::runtime::NativeScriptRoute;
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let before = repo.snapshot(&AtomicBool::new(false)).unwrap();
    let (version, bytes) = repo.read("calc.py").unwrap();
    let pos = bytes.windows(3).position(|b| b == b"a+b").unwrap();
    let proposal = PatchProposal {
        schema_version: "melissa.repository-patch/v1".into(),
        root_identity: repo.root_identity().into(),
        files: vec![FilePatch {
            before: version,
            edits: vec![ByteEdit {
                start: pos as u64,
                end: pos as u64 + 3,
                expected: b"a+b".to_vec(),
                replacement: b"a-b".to_vec(),
            }],
        }],
    };
    let s = store(&dir.path().join("store"), 10000000);
    let native = RepositoryDispatcher::new(
        melissa_repository::Repository::open(
            &dir.path().join("repo"),
            melissa_repository::Limits::default(),
            vec![],
        )
        .unwrap(),
        s.connect().unwrap(),
        RepositoryToolPolicy {
            files: PatchPolicy {
                task_id: TASK.into(),
                principal_id: "principal:code07".into(),
                profile_id: PROFILE.into(),
                resource_id: "workspace:code07".into(),
                authorization_ref: AUTH.into(),
                expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
                epoch: 1,
                writable_paths: BTreeSet::new(),
                protected_paths: BTreeSet::from(["calc.py".into()]),
            },
            read_repository: true,
            enabled_tools: BTreeSet::from(["fs_diff".into()]),
        },
    )
    .unwrap();
    let host = setup_runtime(
        repo.clone(),
        s.connect().unwrap(),
        skill("implementation-refactor"),
    )
    .with_native_scripts(
        Box::new(native),
        BTreeMap::from([(
            "generate_patch_preview".into(),
            NativeScriptRoute {
                wire_name: "fs_diff".into(),
                fixed_input: Some(serde_json::to_value(proposal).unwrap()),
                cache_build: false,
            },
        )]),
    )
    .unwrap();
    let mut tools = ContextDispatcher::new(host);
    let preview =
        json!({"operation":"common_script","id":"generate_patch_preview","input":{}}).to_string();
    let cleanup =
        json!({"operation":"common_script","id":"artifact_cleanup","input":{}}).to_string();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[
            ("p", "context_script", &preview),
            ("c", "context_script", &cleanup),
        ])),
        HttpPlan::sse(text_response("preview only", false, true)),
    ])
    .await;
    let mut g = gateway(s, &http, policy());
    let r = g
        .run(
            &spec("preview-cleanup"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 2);
    assert_eq!(
        repo.snapshot(&AtomicBool::new(false)).unwrap().digest,
        before.digest
    );
    let h = tools.host();
    assert_eq!(h.lock().unwrap().telemetry()["cache.explicit_cleanup"], 1);
    let altered=json!({"operation":"common_script","id":"generate_patch_preview","input":{"writable_paths":["calc.py"]}}).to_string();
    assert!(
        tools
            .validate_call(&ToolCall {
                id: "inject".into(),
                name: "context_script".into(),
                arguments: altered
            })
            .is_err()
    );
}
