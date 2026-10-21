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
#[test]
fn crypto_signature_and_independent_receipts_reject_tampering_rotation_and_revocation() {
    let p = common::one(0);
    let (r, mut policy) = signed(&p);
    assert!(r.verify(&p, &policy).is_ok());
    let mut x = r.clone();
    x.signature[0] ^= 1;
    assert!(x.verify(&p, &policy).is_err());
    let mut x = r.clone();
    x.statement.receipt.passed = 0;
    assert!(x.verify(&p, &policy).is_err());
    let mut x = r.clone();
    x.statement.receipt.review_digest = cdigest(b"forgery");
    assert!(x.verify(&p, &policy).is_err());
    policy.revoked_keys.insert("key:test".into());
    assert!(r.verify(&p, &policy).is_err());
    policy.revoked_keys.clear();
    policy.epoch = 2;
    assert!(r.verify(&p, &policy).is_err());
    policy.epoch = 1;
    policy.now_ms = u64::MAX;
    assert!(r.verify(&p, &policy).is_err());
    policy.now_ms = 1;
    policy
        .revoked_publishers
        .insert(p.version().publisher_id.clone());
    assert!(r.verify(&p, &policy).is_err());
    policy.revoked_publishers.clear();
    policy
        .revoked_pins
        .insert(p.version().pin.content_digest.clone());
    assert!(r.verify(&p, &policy).is_err());
    policy.revoked_pins.clear();
    policy.accepted_receipts.clear();
    assert!(r.verify(&p, &policy).is_err());
    assert!(r.verify(&common::one(1), &policy).is_err());
    let (d, v, files, pin) = common::raw(0);
    let mut version: melissa_core_contracts::design::SkillVersion =
        serde_json::from_slice(&v).unwrap();
    let mut target = pin.clone();
    target.semantic_version = "0.9.0".into();
    target.content_digest = cdigest(b"older reviewed package");
    version.rollback_to = Some(target);
    let altered = melissa_skill_context::package::Package::load(
        &d,
        &serde_json::to_vec(&version).unwrap(),
        files,
        &pin,
    )
    .unwrap();
    let (r, policy) = signed(&p);
    assert!(
        r.verify(&altered, &policy).is_err(),
        "version metadata is part of the signed release binding"
    );
}
#[test]
fn all_ten_current_versions_load_under_actual_owner_tools_and_caps_without_expansion() {
    let pins = current();
    assert_eq!(pins.len(), 10);
    let registry = load_packages(&root(), &pins).unwrap();
    let catalog = Catalog::load(&root()).unwrap();
    for profile in catalog
        .profiles
        .values()
        .filter(|p| p.id.starts_with("melissa.code."))
    {
        let slug = melissa_skill_context::assembly::owner_skill(&profile.id).unwrap();
        let pin = pins.iter().find(|p| p.skill_id.ends_with(slug)).unwrap();
        let policy = SkillPolicy {
            epoch: "scope".into(),
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
        registry
            .load(pin, &policy)
            .unwrap_or_else(|e| panic!("{}: {e}", profile.id));
    }
    assert_eq!(catalog.profiles.len(), 62);
    assert_eq!(catalog.tools.tools.len(), 150);
}
#[test]
fn all_fifteen_pure_common_script_purposes_and_seven_templates_keep_failures_and_provenance() {
    use melissa_skill_context::scripts::*;
    let cases = vec![
        (
            "summarize_logs",
            json!({"text":"error A\nerror A\nerror B\n"}),
        ),
        (
            "extract_stacktraces",
            json!({"text":"Traceback\n File calc.py\nValueError exception\n"}),
        ),
        (
            "find_duplicate_errors",
            json!({"text":"error A\nerror A\nerror B\n"}),
        ),
        (
            "parse_compiler_diagnostics",
            json!({"text":"{\"reason\":\"compiler-message\",\"message\":\"bad\"}\nunparsed"}),
        ),
        (
            "compare_artifacts",
            json!({"left":{"digest":"a","bytes":1,"metadata":{}},"right":{"digest":"b","bytes":1,"metadata":{}}}),
        ),
        (
            "detect_environment_drift",
            json!({"baseline":{"sdk":1},"current":{"sdk":2}}),
        ),
        (
            "normalize_tool_output",
            json!({"status":"failed","exit_code":1,"truncated":true,"raw_ref":"raw:1","metrics":{},"warnings":[]}),
        ),
        (
            "redact_secrets",
            json!({"text":"api_key=private\nkeep\nABC", "secrets":["ABC"]}),
        ),
        (
            "compact_context",
            json!({"required":[{"id":"e","source_ref":"raw","digest":"hash","outcome":"failed"}],"rejected_hypotheses":["A"],"open_issues":["B"],"authorization_ref":"auth","remaining_budget":7,"raw_refs":["raw"]}),
        ),
        (
            "extract_structured_data",
            json!({"columns":["time"],"rows":[[1],[2]],"source_region":"A1:A3","units":{"time":"ms"}}),
        ),
        (
            "validate_json_schema",
            json!({"schema":{"type":"integer"},"value":"bad"}),
        ),
        (
            "benchmark_runner",
            json!({"task_set_digest":"a","runs":[{"task_set_digest":"a","model":"m","tool_version":"t","environment_digest":"e","repeat":1,"outcome":"failed","elapsed_ms":1,"input_digest":"i"}]}),
        ),
        (
            "trace_analyzer",
            json!({"steps":[{"status":"failed","raw_ref":"raw:1","hypothesis":"unknown"}],"raw_trace_ref":"raw:trace"}),
        ),
        (
            "cost_report",
            json!({"entries":[{"id":"a","cost_micro_usd":10},{"id":"b","cost_micro_usd":null}]}),
        ),
        (
            "evidence_manifest",
            json!({"artifacts":[{"id":"a","input_digest":"i","output_digest":"o","verifier_digest":"v","source_ref":"raw"}],"final_source_digest":"s"}),
        ),
    ];
    assert_eq!(cases.len(), 15);
    for (id, input) in cases {
        let v = execute(id, &input).unwrap();
        assert_eq!(v["protected_acceptance"], false);
        assert_eq!(v["authority"], "untrusted_observation");
        assert!(execute(id, &json!({})).is_err());
    }
    for id in IDS.into_iter().filter(|id| native(id)) {
        assert!(execute(id, &json!({})).is_err());
    }
    assert!(
        execute(
            "cost_report",
            &json!({"entries":[{"cost_micro_usd":u64::MAX},{"cost_micro_usd":1}]})
        )
        .is_err()
    );
    assert!(
        execute(
            "extract_structured_data",
            &json!({"columns":["a"],"rows":[[1,2]],"units":{},"source_region":"x"})
        )
        .is_err()
    );
    let fields = [
        ("task_plan", vec!["goal", "acceptance", "steps", "risks"]),
        (
            "code_review",
            vec!["source_digest", "findings", "counterexamples", "evidence"],
        ),
        (
            "bugfix",
            vec!["reproducer", "root_cause", "patch_scope", "regression"],
        ),
        (
            "pull_request",
            vec!["problem", "behavior", "changes", "validation"],
        ),
        (
            "research",
            vec!["question", "sources", "findings", "uncertainties"],
        ),
        (
            "report",
            vec!["task", "observations", "evidence", "open_issues"],
        ),
        (
            "data_analysis",
            vec![
                "dataset",
                "source_regions",
                "units",
                "method",
                "results",
                "limitations",
            ],
        ),
    ];
    for (category, keys) in fields {
        let mut input = serde_json::Map::new();
        for k in keys {
            input.insert(k.into(), json!("literal {{placeholder}}"));
        }
        let value = Value::Object(input);
        let out = template(category, &value).unwrap();
        assert_eq!(out["fields"], value);
        assert_eq!(out["verified"], false);
        assert!(template(category, &json!({})).is_err());
    }
}
#[tokio::test]
async fn native_gateway_context_memory_templates_and_worker_use_actual_admission_and_caches() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let s = store(&dir.path().join("store"), 10000000);
    let pin = skill("debug-root-cause");
    let runtime = setup_runtime(repo.clone(), s.connect().unwrap(), pin.clone());
    let mut tools = ContextDispatcher::new(runtime);
    let h = tools.host();
    let calls = vec![
        (
            "s1",
            "context_search",
            json!({"operation":"search","query":"add","limit":10,"symbols":["add"]}),
        ),
        (
            "s2",
            "context_search",
            json!({"operation":"search","query":"add","limit":10,"symbols":["add"]}),
        ),
        (
            "l1",
            "skill_load",
            json!({"operation":"skill_load","pin":pin}),
        ),
        (
            "l2",
            "skill_load",
            json!({"operation":"skill_load","pin":pin}),
        ),
        (
            "h",
            "skill_helper",
            json!({"operation":"helper","pin":pin,"path":"scripts/assess.py","input":{"lines":["error A","error B"]}}),
        ),
        (
            "t1",
            "context_template",
            json!({"operation":"template","pin":pin,"path":"assets/report.md","fields":{"task":"t","sources":"calc.py","observations":"raw","open_issues":"pending","acceptance":"unverified"}}),
        ),
        (
            "t2",
            "context_template",
            json!({"operation":"template","pin":pin,"path":"assets/report.md","fields":{"task":"t","sources":"calc.py","observations":"raw","open_issues":"pending","acceptance":"unverified"}}),
        ),
        (
            "m1",
            "memory_propose",
            json!({"operation":"memory_propose","key":"addition","claim":"add returns the sum","source_ids":["calc.py"]}),
        ),
        (
            "m2",
            "memory_search",
            json!({"operation":"memory_search","query":"addition"}),
        ),
        (
            "g",
            "context_script",
            json!({"operation":"common_script","id":"dependency_graph","input":{}}),
        ),
        (
            "f",
            "context_factory",
            json!({"operation":"shared_template","category":"bugfix","input":{"reproducer":"bad","root_cause":"x","patch_scope":"calc.py","regression":"negative"}}),
        ),
    ];
    let args = calls
        .iter()
        .map(|(id, name, v)| (*id, *name, v.to_string()))
        .collect::<Vec<_>>();
    let borrowed = args
        .iter()
        .map(|(id, n, a)| (*id, *n, a.as_str()))
        .collect::<Vec<_>>();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&borrowed)),
        HttpPlan::sse(text_response(
            "Observed, independent acceptance pending.",
            false,
            true,
        )),
    ])
    .await;
    let mut g = gateway(s, &http, policy());
    let r = g
        .run(
            &spec("context-native"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 11);
    assert!(!r.task_accepted);
    let host = h.lock().unwrap();
    assert!(host.telemetry()["parse.hit"] >= 1);
    assert!(host.telemetry()["retrieval.hit"] >= 1);
    assert!(host.telemetry()["prompt.hit"] >= 1);
    let mut proposal = None;
    for id in &r.artifact_refs {
        if id.ends_with(":context-result") {
            let v: Value =
                serde_json::from_slice(&g.store().get_artifact(TASK, id).unwrap()).unwrap();
            if v["observation"]["data"]["status"] == "proposed" {
                proposal = Some(v["observation"]["data"].clone());
            }
            if !v["observation"]["data"]["accepted"].is_null() {
                assert_eq!(v["observation"]["data"]["accepted"], json!([]));
            }
        }
    }
    drop(host);
    let p = proposal.unwrap();
    let mut host = h.lock().unwrap();
    assert!(
        host.review_memory(
            p["id"].as_str().unwrap(),
            p["proposal_digest"].as_str().unwrap(),
            true,
            "missing",
            &BTreeSet::new()
        )
        .is_err()
    );
    host.review_memory(
        p["id"].as_str().unwrap(),
        p["proposal_digest"].as_str().unwrap(),
        true,
        &r.artifact_refs[0],
        &BTreeSet::new(),
    )
    .unwrap();
    let artifact = r.artifact_refs[0].clone();
    host.artifact(&artifact).unwrap();
    host.artifact(&artifact).unwrap();
    assert_eq!(host.telemetry()["artifact.hit"], 1);
    drop(host);
    g.store().integrity_check().unwrap();
}

struct StopAfter {
    inner: JournalContinuation,
    phase: melissa_model_gateway::continuation::Phase,
    turn: u32,
}
impl melissa_model_gateway::continuation::ContinuationStore for StopAfter {
    fn begin(
        &mut self,
        s: &mut LocalStore,
        b: &str,
        t: &str,
        r: &str,
    ) -> Result<Option<melissa_model_gateway::continuation::TurnCheckpoint>> {
        melissa_model_gateway::continuation::ContinuationStore::begin(&mut self.inner, s, b, t, r)
    }
    fn publish(
        &mut self,
        s: &mut LocalStore,
        c: &melissa_model_gateway::continuation::TurnCheckpoint,
    ) -> Result<()> {
        melissa_model_gateway::continuation::ContinuationStore::publish(&mut self.inner, s, c)?;
        if c.phase == self.phase && c.next_turn == self.turn {
            return Err(GatewayError::new(
                ErrorKind::Store,
                "injected stop AFTER durable publication",
            ));
        }
        Ok(())
    }
}
fn continuation(
    run: &str,
    repo: Arc<melissa_repository::Repository>,
    flag: Arc<AtomicBool>,
) -> JournalContinuation {
    JournalContinuation::new(
        TASK.into(),
        run.into(),
        flag,
        Box::new(move || {
            Ok(Freshness {
                namespace: common::namespace(),
                workspace_digest: repo
                    .snapshot(&AtomicBool::new(false))
                    .map_err(|e| melissa_skill_context::Error(e.to_string()))?
                    .digest,
                skill_pins: vec![],
                policy_digest: cdigest(b"host policy"),
                authorization_ref: AUTH.into(),
                cancellation_ref: "cancel:code07".into(),
            })
        }),
    )
}
#[tokio::test]
async fn durable_gateway_resume_reopens_encrypted_journal_without_repeating_a_settled_tool_or_budget()
 {
    use melissa_model_gateway::continuation::Phase;
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "call_raw_id",
            "process_exec",
            r#"{"value":"lossless native args"}"#,
        )])),
        HttpPlan::sse(text_response("final after restart", false, true)),
    ])
    .await;
    let p = policy();
    let s = store(&dir.path().join("store"), 10000000);
    let mut tools = FakeTools::default();
    let count = tools.executed.clone();
    let flag = Arc::new(AtomicBool::new(false));
    let mut g = gateway(s, &http, p.clone()).with_continuation(Box::new(StopAfter {
        inner: continuation("resume", repo.clone(), flag.clone()),
        phase: Phase::Safe,
        turn: 1,
    }));
    let mut run = spec("resume");
    run.required_tool_names.insert("process_exec".into());
    assert!(g.run(&run, &mut tools, flag.clone()).await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let spent = g
        .store()
        .journal()
        .model_budget(TASK)
        .unwrap()
        .charged_cost_micro_usd;
    assert!(spent > 0);
    drop(g);
    let s = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut g = gateway(s, &http, p).with_continuation(Box::new(continuation(
        "resume",
        repo,
        flag.clone(),
    )));
    let result = g.run(&run, &mut tools, flag).await.unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(result.request_ids, vec!["model:resume:1", "model:resume:2"]);
    assert_eq!(result.tool_calls, 1);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    {
        let b = http.bodies.lock().unwrap();
        assert!(b[1]["input"].to_string().contains("lossless native args"));
        assert!(b[1]["input"].to_string().contains("call_raw_id"));
        assert!(b[1]["input"].to_string().contains("function_call_output"));
    }
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .charged_cost_micro_usd,
        spent * 2
    );
    assert!(
        g.run(&run, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    g.store().integrity_check().unwrap();
}
#[tokio::test]
async fn pending_native_phases_changed_sources_and_cancellation_deny_before_any_resume_http() {
    use melissa_model_gateway::continuation::Phase;
    for phase in [Phase::InferencePending, Phase::ToolsPending, Phase::Safe] {
        let dir = tempfile::tempdir().unwrap();
        let repo = fixture_repo(dir.path());
        let plans = if phase == Phase::InferencePending {
            vec![]
        } else {
            vec![HttpPlan::sse(tool_response(&[(
                "x",
                "process_exec",
                r#"{"value":"x"}"#,
            )]))]
        };
        let http = http_fixture(plans).await;
        let p = policy();
        let flag = Arc::new(AtomicBool::new(false));
        let mut g = gateway(store(&dir.path().join("store"), 10000000), &http, p.clone())
            .with_continuation(Box::new(StopAfter {
                inner: continuation("deny", repo.clone(), flag.clone()),
                phase,
                turn: if phase == Phase::Safe { 1 } else { 0 },
            }));
        let mut tools = FakeTools::default();
        assert!(
            g.run(&spec("deny"), &mut tools, flag.clone())
                .await
                .is_err()
        );
        let calls = http.requests.load(Ordering::SeqCst);
        if phase == Phase::Safe {
            std::fs::write(dir.path().join("repo/calc.py"), b"def changed(): pass\n").unwrap();
        }
        drop(g);
        let s = LocalStore::open(
            &dir.path().join("store"),
            StoreKey::from_bytes([117; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        let mut g =
            gateway(s, &http, p).with_continuation(Box::new(continuation("deny", repo, flag)));
        assert!(
            g.run(&spec("deny"), &mut tools, Arc::new(AtomicBool::new(false)))
                .await
                .is_err()
        );
        assert_eq!(calls, http.requests.load(Ordering::SeqCst));
    }
}
#[tokio::test]
async fn full_skill_assembly_reaches_native_request_without_eval_answers_and_binds_same_prepared_message()
 {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let mut s = store(&dir.path().join("store"), 10000000);
    let pin = skill("debug-root-cause");
    let registry = load_packages(&root(), std::slice::from_ref(&pin)).unwrap();
    let catalog = Catalog::load(&root()).unwrap();
    let p = &catalog.profiles[PROFILE];
    let policy = SkillPolicy {
        epoch: "assembly".into(),
        reviewed: BTreeSet::from([pin.content_digest.clone()]),
        publishers: BTreeSet::from(["melissa-local-development".into()]),
        revoked: BTreeSet::new(),
        tools: p.tool_ids.iter().cloned().collect(),
        capabilities: p.authority.capability_ceiling.iter().cloned().collect(),
        allow_helpers: true,
    };
    let a = Assembly {
        namespace: common::namespace(),
        resource_id: "workspace:code07",
        pins: vec![pin.clone()],
        registry: &registry,
        policy: &policy,
        catalog: &catalog,
        repo: &repo,
        context_tokens: 1048576,
    };
    let original = spec("assembled");
    let bound = a.bind(&mut s, &original, &[]).unwrap();
    let again = a.bind(&mut s, &original, &[]).unwrap();
    assert_eq!(bound.user_message, again.user_message);
    let envelope: Value = serde_json::from_str(&bound.user_message).unwrap();
    let sections = envelope["context_sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["section"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sections,
        BTreeSet::from([
            "system_contract",
            "task_contract",
            "relevant_skills",
            "workspace_context",
            "evidence",
            "recent_observations",
            "remaining_budget",
            "output_schema"
        ])
    );

    assert!(bound.user_message.contains("scripts/assess.py"));
    assert!(bound.user_message.contains("schemas/input.json"));
    assert!(!bound.user_message.contains("expected_status"));
    let http = http_fixture(vec![HttpPlan::sse(text_response("candidate", false, true))]).await;
    let mut g = gateway(s, &http, policy_for_assembly());
    let r = g
        .run(
            &bound,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    let b = http.bodies.lock().unwrap();
    assert!(b[0]["input"].to_string().contains("scripts/assess.py"));
    assert!(b[0]["input"].to_string().contains(&pin.content_digest));
}
fn policy_for_assembly() -> GatewayPolicy {
    policy()
}

#[test]
fn production_signature_gate_and_evaluation_cache_recheck_live_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let s = store(&dir.path().join("store"), 10000000);
    let pin = skill("debug-root-cause");
    let reg = load_packages(&root(), std::slice::from_ref(&pin)).unwrap();
    let (_, all, _) = common::setup();
    let p = reg.load(&pin, &all).unwrap();
    let (r, policy) = signed(p);
    let mut host = setup_runtime(repo, s, pin.clone());
    host.verify_release(&pin, &r, &policy).unwrap();
    host.verify_release(&pin, &r, &policy).unwrap();
    assert_eq!(host.telemetry()["skill_evaluation.hit"], 1);
    let live = Arc::new(Mutex::new(policy));
    let copy = live.clone();
    let host = host
        .with_signed_releases(melissa_skill_context::runtime::ReleaseGate {
            releases: BTreeMap::from([(pin.content_digest.clone(), r)]),
            refresh: Box::new(move || Ok(copy.lock().unwrap().clone())),
        })
        .unwrap();
    let d = ContextDispatcher::new(host);
    let c = ToolCall {
        id: "signed".into(),
        name: "skill_load".into(),
        arguments: json!({"operation":"skill_load","pin":pin}).to_string(),
    };
    d.validate_call(&c).unwrap();
    live.lock().unwrap().revoked_keys.insert("key:test".into());
    assert!(d.validate_call(&c).is_err());
}
#[tokio::test]
async fn expired_cancelled_and_wrong_scope_context_calls_have_no_admitted_effect() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let s = store(&dir.path().join("store"), 10000000);
    let pin = skill("debug-root-cause");
    let host = setup_runtime(repo, s.connect().unwrap(), pin.clone());
    let revoked = host.revocation();
    let mut d = ContextDispatcher::new(host);
    let call = ToolCall {
        id: "scope".into(),
        name: "skill_load".into(),
        arguments: json!({"operation":"skill_load","pin":pin}).to_string(),
    };
    d.validate_call(&call).unwrap();
    revoked.store(true, Ordering::Release);
    assert!(d.validate_call(&call).is_err());
    let ctx = ToolContext {
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        run_id: "wrong".into(),
        request_id: "no-request".into(),
        invocation_id: "no-effect".into(),
        attempt_id: "no-attempt".into(),
        generation: 1,
    };
    let e = d
        .execute(call, ctx, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Authorization);
    assert!(
        s.journal()
            .events(TASK)
            .unwrap()
            .iter()
            .all(|e| e.invocation.is_none())
    );
}
#[test]
fn durable_crash_child() {
    let Ok(base) = std::env::var("MELISSA_CODE07_CRASH_STORE") else {
        assert!(std::env::var("MELISSA_CODE07_CRASH_URL").is_err());
        return;
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            let base = std::path::PathBuf::from(base);
            let url = std::env::var("MELISSA_CODE07_CRASH_URL").unwrap();
            let expiry: u64 = std::env::var("MELISSA_CODE07_CRASH_EXPIRY")
                .unwrap()
                .parse()
                .unwrap();
            let repo = fixture_repo(&base);
            let s = store(&base.join("store"), 10000000);
            let mut tools = ContextDispatcher::new(setup_runtime(
                repo.clone(),
                s.connect().unwrap(),
                skill("debug-root-cause"),
            ));
            let http = HttpFixture {
                url,
                requests: Arc::new(AtomicUsize::new(0)),
                bodies: Arc::new(Mutex::new(vec![])),
                task: tokio::spawn(std::future::pending()),
            };
            let mut p = policy();
            p.expires_at_unix_ms = expiry;
            let mut g = gateway(s, &http, p).with_continuation(Box::new(CrashAfter(continuation(
                "real-crash",
                repo,
                Arc::new(AtomicBool::new(false)),
            ))));
            let _ = g
                .run(
                    &spec("real-crash"),
                    &mut tools,
                    Arc::new(AtomicBool::new(false)),
                )
                .await;
            panic!("child did not reach durable exit");
        });
}
struct CrashAfter(JournalContinuation);
impl melissa_model_gateway::continuation::ContinuationStore for CrashAfter {
    fn begin(
        &mut self,
        s: &mut LocalStore,
        b: &str,
        t: &str,
        r: &str,
    ) -> Result<Option<melissa_model_gateway::continuation::TurnCheckpoint>> {
        melissa_model_gateway::continuation::ContinuationStore::begin(&mut self.0, s, b, t, r)
    }
    fn publish(
        &mut self,
        s: &mut LocalStore,
        c: &melissa_model_gateway::continuation::TurnCheckpoint,
    ) -> Result<()> {
        melissa_model_gateway::continuation::ContinuationStore::publish(&mut self.0, s, c)?;
        if c.phase == melissa_model_gateway::continuation::Phase::Safe && c.next_turn == 1 {
            std::process::exit(77);
        }
        Ok(())
    }
}
#[tokio::test]
async fn actual_process_exit_after_completed_c03_helper_resumes_same_native_history_once() {
    let dir = tempfile::tempdir().unwrap();
    let pin = skill("debug-root-cause");
    let args=json!({"operation":"helper","pin":pin,"path":"scripts/assess.py","input":{"lines":["error A","error B"]}}).to_string();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[("crash-helper", "skill_helper", &args)])),
        HttpPlan::sse(text_response("after real process exit", false, true)),
    ])
    .await;
    let mut p = policy();
    p.expires_at_unix_ms = melissa_execution_broker::unix_ms().unwrap() + 120000;
    let base = dir.path().to_path_buf();
    let url = http.url.clone();
    let expiry = p.expires_at_unix_ms;
    let child = tokio::task::spawn_blocking(move || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durable_crash_child", "--nocapture"])
            .env("MELISSA_CODE07_CRASH_STORE", base)
            .env("MELISSA_CODE07_CRASH_URL", url)
            .env("MELISSA_CODE07_CRASH_EXPIRY", expiry.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        child.status.code(),
        Some(77),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let repo = Arc::new(
        melissa_repository::Repository::open(
            &dir.path().join("repo"),
            melissa_repository::Limits::default(),
            vec![],
        )
        .unwrap(),
    );
    let s = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut d = ContextDispatcher::new(setup_runtime(repo.clone(), s.connect().unwrap(), pin));
    let mut g = gateway(s, &http, p).with_continuation(Box::new(continuation(
        "real-crash",
        repo,
        Arc::new(AtomicBool::new(false)),
    )));
    let r = g
        .run(
            &spec("real-crash"),
            &mut d,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 1);
    assert_eq!(r.request_ids.len(), 2);
    let events = g.store().journal().events(TASK).unwrap();
    let mut attempts = BTreeMap::new();
    for e in events {
        if let Some(a) = e.attempt {
            attempts.insert(a.attempt_id.clone(), a);
        }
    }
    assert_eq!(attempts.len(), 1);
    assert!(
        attempts
            .values()
            .all(|a| a.state == melissa_local_store::journal::AttemptState::Succeeded)
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 2);
    assert!(
        http.bodies.lock().unwrap()[1]["input"]
            .to_string()
            .contains("helper-raw")
    );
    g.store().integrity_check().unwrap();
}

#[tokio::test]
async fn visual_frontend_profile_cannot_be_silently_sent_to_the_text_only_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir.path().join("store"), 10000000);
    let mut t = s.journal().task(TASK).unwrap().contract;
    t.task_id = "task:frontend-visual-guard".into();
    t.selected_profile_ids = vec!["melissa.code.frontend".into()];
    s.journal_mut().create_task(&t).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = s.journal().task(&t.task_id).unwrap().record.version;
        s.transition_task(&t.task_id, v, state, None).unwrap();
    }
    struct NoTools;
    impl ToolDispatcher for NoTools {
        fn definitions(&self) -> Vec<BoundTool> {
            vec![]
        }
        fn validate_call(&self, _: &ToolCall) -> Result<()> {
            Err(GatewayError::unsupported("no tools"))
        }
        fn execute<'a>(
            &'a mut self,
            _: ToolCall,
            _: ToolContext,
            _: Arc<AtomicBool>,
        ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
            Box::pin(async { Err(GatewayError::unsupported("no execution")) })
        }
    }
    let http = http_fixture(vec![]).await;
    let mut g = gateway(s, &http, policy());
    let mut run = spec("visual-denied");
    run.task_id = t.task_id.clone();
    run.profile_id = t.selected_profile_ids[0].clone();
    let err = g
        .run(&run, &mut NoTools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(
        g.store()
            .journal()
            .model_requests(&t.task_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn helper_interpreter_and_descriptor_caps_are_checked_before_any_worker_or_model_request() {
    for extra_cap in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let repo = fixture_repo(dir.path());
        let s = store(&dir.path().join("store"), 10000000);
        let all = current();
        let original = skill("debug-root-cause");
        let old: Vec<melissa_core_contracts::design::SkillPin> =
            serde_json::from_slice(&std::fs::read(root().join("skills/code/index.json")).unwrap())
                .unwrap();
        let idx = old
            .iter()
            .position(|p| p.skill_id == original.skill_id)
            .unwrap();
        let (d, v, files, _) = common::raw(idx);
        let mut def: melissa_core_contracts::design::SkillDefinition =
            serde_json::from_slice(&d).unwrap();
        if extra_cap {
            def.scripts[0].required_capabilities = vec!["secrets.exfiltrate".into()];
            def.manifest
                .required_capabilities
                .push("secrets.exfiltrate".into());
        } else {
            def.scripts[0].interpreter_ref = "unsupported-interpreter/v1".into();
        }
        let mut version: melissa_core_contracts::design::SkillVersion =
            serde_json::from_slice(&v).unwrap();
        version.required_capabilities = def.manifest.required_capabilities.clone();
        let v = serde_json::to_vec(&version).unwrap();
        let d = serde_json::to_vec(&def).unwrap();
        let (v, pin) = common::repin(&d, &files, &v);
        let p = melissa_skill_context::package::Package::load(&d, &v, files, &pin).unwrap();
        let mut reg = melissa_skill_context::package::Registry::default();
        reg.insert(p).unwrap();
        let catalog = extend_catalog(
            &Catalog::load(&root()).unwrap(),
            &BTreeSet::from([PROFILE.into()]),
        )
        .unwrap();
        let profile = &catalog.profiles[PROFILE];
        let policy = SkillPolicy {
            epoch: "helper-guard".into(),
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
        let opened = ContextRuntime::open(
            repo,
            s.connect().unwrap(),
            catalog,
            RuntimeGrant {
                task_id: TASK.into(),
                profile_id: PROFILE.into(),
                principal_id: "principal:guard".into(),
                resource_id: "workspace:code07".into(),
                authorization_ref: AUTH.into(),
                namespace: common::namespace(),
                expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
                policy_epoch: policy.epoch.clone(),
                enabled: BTreeSet::from(["skill_helper".into()]),
                skill_policy: policy,
                pins: vec![pin.clone()],
            },
            reg,
            &[],
        );
        if extra_cap {
            assert!(opened.is_err());
            assert!(s.journal().model_requests(TASK).unwrap().is_empty());
            assert!(
                s.journal()
                    .events(TASK)
                    .unwrap()
                    .iter()
                    .all(|e| e.invocation.is_none())
            );
            continue;
        }
        let d = ContextDispatcher::new(opened.unwrap());
        let call=ToolCall{id:"unsupported-helper".into(),name:"skill_helper".into(),arguments:json!({"operation":"helper","pin":pin,"path":"scripts/assess.py","input":{"lines":["error"]}}).to_string()};
        assert!(d.validate_call(&call).is_err());
        assert!(s.journal().model_requests(TASK).unwrap().is_empty());
        assert!(
            s.journal()
                .events(TASK)
                .unwrap()
                .iter()
                .all(|e| e.invocation.is_none())
        );
        assert_eq!(all.len(), 10);
    }
}

#[tokio::test]
async fn known_native_observation_is_withheld_after_revocation_without_unknown_or_a_second_model_call()
 {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let s = store(&dir.path().join("store"), 10000000);
    let runtime = setup_runtime(repo, s.connect().unwrap(), skill("debug-root-cause"));
    let flag = runtime.revocation();
    struct RevokeResult(Arc<AtomicBool>);
    impl ToolDispatcher for RevokeResult {
        fn definitions(&self) -> Vec<BoundTool> {
            vec![BoundTool{canonical_id:"fs.read".into(),definition:ToolDefinition{name:"known_read".into(),description:"No external effect: deterministic unit fixture for delivery-time revocation".into(),parameters:json!({"type":"object","properties":{},"additionalProperties":false}),strict:false}}]
        }
        fn validate_call(&self, c: &ToolCall) -> Result<()> {
            if c.name == "known_read" && c.arguments == "{}" {
                Ok(())
            } else {
                Err(GatewayError::invalid("fixture args"))
            }
        }
        fn execute<'a>(
            &'a mut self,
            _: ToolCall,
            _: ToolContext,
            _: Arc<AtomicBool>,
        ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
            self.0.store(true, Ordering::Release);
            Box::pin(async {
                Ok(ToolExecution {
                    content: json!({"must_not_be_sent_after_revoke":"owned fixture data"})
                        .to_string(),
                    success: true,
                    cancelled: false,
                    requires_reconciliation: false,
                    artifact_refs: vec![],
                })
            })
        }
    }
    let runtime = runtime
        .with_native_scripts(
            Box::new(RevokeResult(flag)),
            BTreeMap::from([(
                "benchmark_runner".into(),
                melissa_skill_context::runtime::NativeScriptRoute {
                    wire_name: "known_read".into(),
                    fixed_input: Some(json!({})),
                    cache_build: false,
                },
            )]),
        )
        .unwrap();
    let mut d = ContextDispatcher::new(runtime);
    let args = json!({"operation":"common_script","id":"benchmark_runner","input":{}}).to_string();
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "revoked-delivery",
        "context_script",
        &args,
    )]))])
    .await;
    let mut g = gateway(s, &http, policy());
    let r = g
        .run(
            &spec("revoke-result"),
            &mut d,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert!(!r.requires_reconciliation);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert!(
        !http.bodies.lock().unwrap()[0]
            .to_string()
            .contains("must_not_be_sent_after_revoke")
    );
    assert!(
        g.store()
            .journal()
            .task(TASK)
            .unwrap()
            .record
            .unknown_invocation_id
            .is_none()
    );
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .unknown_requests,
        0
    );
}

#[test]
fn portable_wire_roots_and_pin_types_keep_strict_host_script_and_template_validation() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let s = store(&dir.path().join("store"), 10000000);
    let pin = skill("debug-root-cause");
    let d = ContextDispatcher::new(setup_runtime(repo, s.connect().unwrap(), pin.clone()));
    for tool in d.definitions() {
        let p = &tool.definition.parameters;
        assert_eq!(p["type"], "object");
        assert!(p["properties"].is_object());
        assert!(p.get("oneOf").is_none());
        assert!(tool.definition.description.len() <= 65536);
        melissa_model_gateway::schema::validate_schema(p).unwrap();
        if let Some(pin) = p["properties"].get("pin") {
            assert_eq!(pin["type"], "object");
            for field in ["skill_id", "semantic_version", "content_digest"] {
                assert_eq!(pin["properties"][field]["type"], "string");
            }
        }
    }
    for (name, args) in [
        (
            "context_script",
            json!({"operation":"common_script","id":"summarize_logs","input":{}}),
        ),
        (
            "context_factory",
            json!({"operation":"shared_template","category":"report","input":{}}),
        ),
    ] {
        let call = ToolCall {
            id: "bad".into(),
            name: name.into(),
            arguments: args.to_string(),
        };
        let wire = d
            .definitions()
            .into_iter()
            .find(|x| x.definition.name == name)
            .unwrap();
        assert!(
            melissa_model_gateway::schema::validate_output(
                &wire.definition.parameters,
                &call.arguments
            )
            .is_ok()
        );
        assert!(
            d.validate_call(&call).is_err(),
            "portable schema never replaces strict host validation"
        );
    }
    let mut wrong = pin;
    wrong.content_digest = cdigest(b"unreviewed pin");
    assert!(
        d.validate_call(&ToolCall {
            id: "pin".into(),
            name: "skill_load".into(),
            arguments: json!({"operation":"skill_load","pin":wrong}).to_string()
        })
        .is_err()
    );
    assert!(
        s.journal()
            .events(TASK)
            .unwrap()
            .iter()
            .all(|e| e.invocation.is_none())
    );
}
