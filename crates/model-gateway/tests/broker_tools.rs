#![cfg(windows)]
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_core_contracts::{InvocationState, TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    container_broker::ContainerBroker,
    container_policy::container_execution_digest,
    control_policy::{ControlGrant, ControlTool},
    policy::*,
    unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey, journal::AttemptState};
use melissa_model_gateway::{
    ErrorKind, ToolCall,
    tools::{BrokerDispatcher, BrokerDispatcherConfig, ToolContext, ToolDispatcher},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const TASK: &str = "task:code04-broker-dispatch";
const RESOURCE: &str = "container:code04-dispatch";
const INVOCATION: &str = "inv:dispatch-main";
const IMAGE: &str = "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";

struct Fixture {
    broker: Arc<Mutex<ContainerBroker>>,
    snapshot: Arc<Snapshot>,
    request: ContainerRequest,
    _dir: tempfile::TempDir,
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn context(suffix: &str) -> ToolContext {
    ToolContext {
        task_id: TASK.into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "run:host-owned".into(),
        request_id: "model-request:host-owned".into(),
        invocation_id: if suffix == "main" {
            INVOCATION.into()
        } else {
            format!("inv:dispatch-{suffix}")
        },
        attempt_id: format!("attempt:dispatch-{suffix}"),
        generation: 1,
    }
}
fn fixture(script: &str, store_config: StoreConfig, rust: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = Arc::new(if rust {
        Snapshot {files:BTreeMap::from([
            ("Cargo.toml".into(),b"[package]\nname=\"code04_real_dispatch\"\nversion=\"0.1.0\"\nedition=\"2024\"\n".to_vec()),
            ("src/lib.rs".into(),b"pub fn answer()->u32{6*7}\n#[cfg(test)]mod tests{#[test]fn behavior(){assert_eq!(super::answer(),42);println!(\"CODE04_DISPATCH_REAL_RUST\");}}\n".to_vec()),
        ])}
    } else {
        Snapshot {
            files: BTreeMap::from([("message.txt".into(), b"owned snapshot".to_vec())]),
        }
    });
    let request = ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: IMAGE.into(),
        executable: "/bin/sh".into(),
        argv: vec!["-c".into(), script.into()],
        cwd: ".".into(),
        env: BTreeMap::new(),
        limits: ContainerLimits {
            wall_time_ms: 60_000,
            cpu_time_ms: 30_000,
            cpu_rate_basis_points: 10000,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            output_bytes: 65536,
            max_processes: 128,
            export_bytes: 32 * 1024 * 1024,
        },
    };
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = TASK.into();
    task.workspace_ref = RESOURCE.into();
    task.input_snapshot_digest = snapshot.digest().unwrap();
    task.selected_profile_ids = vec![
        "melissa.code.implementer".into(),
        "melissa.code.debugger".into(),
    ];
    task.allowed_resource_ids = vec![RESOURCE.into(), "provider:code04-loopback".into()];
    task.authorization_refs = vec![
        "auth:dispatch-exec".into(),
        "auth:dispatch-inspect".into(),
        "auth:dispatch-cancel".into(),
        "auth:code04-loopback".into(),
    ];
    task.allowed_effects = vec![
        "process.execute_scoped".into(),
        "workspace.apply_patch_scoped".into(),
        "process.inspect_owned".into(),
        "process.cancel_owned".into(),
    ];
    task.limits.max_wall_time_ms = 120_000;
    task.limits.max_disk_bytes = 128 * 1024 * 1024;
    task.limits.max_output_bytes = 40 * 1024 * 1024;
    let mut store = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([174; 32]),
        store_config,
    )
    .unwrap();
    store.journal_mut().create_task(&task).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = store.journal().task(TASK).unwrap().record.version;
        store
            .journal_mut()
            .transition_task(TASK, version, next, None)
            .unwrap();
    }
    let now = unix_ms().unwrap();
    let task_digest = authenticated_digest(&task).unwrap();
    let grant = AuthorityGrant {
        authorization_ref: "auth:dispatch-exec".into(),
        task_id: TASK.into(),
        task_digest: task_digest.clone(),
        principal_id: "principal:host".into(),
        profile_id: "melissa.code.implementer".into(),
        resource_id: RESOURCE.into(),
        process_digest: container_execution_digest(&request, &snapshot.digest().unwrap()).unwrap(),
        allow_monitored_disk: false,
        allow_monitored_cpu: true,
        allowed_effects: task.allowed_effects.iter().cloned().collect(),
        not_before_unix_ms: now.saturating_sub(100),
        expires_at_unix_ms: now + 120_000,
    };
    let control_grants = [
        ("auth:dispatch-inspect", ControlTool::Inspect),
        ("auth:dispatch-cancel", ControlTool::Cancel),
    ]
    .into_iter()
    .map(|(reference, tool)| {
        (
            reference.into(),
            ControlGrant {
                authorization_ref: reference.into(),
                task_id: TASK.into(),
                task_digest: task_digest.clone(),
                principal_id: "principal:host".into(),
                profile_id: "melissa.code.debugger".into(),
                resource_id: RESOURCE.into(),
                tool,
                invocation_id: INVOCATION.into(),
                generation: 1,
                not_before_unix_ms: now.saturating_sub(100),
                expires_at_unix_ms: now + 120_000,
            },
        )
    })
    .collect();
    let policy = HostPolicy {
        revision: "policy:code04-tools:1".into(),
        revocation_epoch: 1,
        issuer: "host:code04-tools".into(),
        audience: "executor:code04-tools".into(),
        key_id: "replaced-by-broker".into(),
        max_permit_lifetime_ms: 120_000,
        ceiling: ProcessLimits {
            wall_time_ms: 120_000,
            cpu_time_ms: 60_000,
            cpu_rate_basis_points: 10000,
            cpu_mode: CpuLimitMode::MonitoredTotal,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            disk_mode: DiskLimitMode::Strict,
            output_bytes: 40 * 1024 * 1024,
            max_processes: 128,
            network: NetworkPolicy::Deny,
        },
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: false,
            memory: true,
            disk_quota: true,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: false,
        allow_monitored_cpu: true,
        allowed_env_names: BTreeSet::new(),
        grants: BTreeMap::from([("auth:dispatch-exec".into(), grant)]),
        control_grants,
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    };
    let broker = ContainerBroker::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        RESOURCE.into(),
        policy,
    )
    .unwrap();
    Fixture {
        broker: Arc::new(Mutex::new(broker)),
        snapshot,
        request,
        _dir: dir,
    }
}
fn dispatcher(f: &Fixture) -> BrokerDispatcher {
    BrokerDispatcher::container(
        Arc::clone(&f.broker),
        Arc::clone(&f.snapshot),
        BrokerDispatcherConfig {
            principal_id: "principal:host".into(),
            resource_id: RESOURCE.into(),
            permit_lifetime_ms: 60_000,
            authorization_refs: BTreeMap::from([
                ("process.exec".into(), "auth:dispatch-exec".into()),
                ("process.inspect".into(), "auth:dispatch-inspect".into()),
                ("process.cancel".into(), "auth:dispatch-cancel".into()),
            ]),
        },
    )
    .unwrap()
}
fn call(f: &Fixture) -> ToolCall {
    ToolCall {
        id: "call:exec".into(),
        name: "process_exec".into(),
        arguments: serde_json::to_string(&f.request).unwrap(),
    }
}
fn control(tool: &str) -> ToolCall {
    ToolCall {
        id: format!("call:{tool}"),
        name: format!("process_{tool}"),
        arguments: json!({
        "schema_version":"melissa.process-control/v1","tool":format!("process.{tool}"),
        "task_id":TASK,"resource_id":RESOURCE,"invocation_id":INVOCATION,"generation":1})
        .to_string(),
    }
}

#[test]
fn malformed_or_authority_injected_json_never_creates_an_invocation() {
    let f = fixture("printf never", StoreConfig::default(), false);
    let dispatcher = dispatcher(&f);
    let mut bad = call(&f);
    bad.arguments =
        "{\"schema_version\":\"melissa.container-exec/v1\",\"schema_version\":\"other\"}".into();
    assert_eq!(
        dispatcher.validate_call(&bad).unwrap_err().kind,
        ErrorKind::Invalid
    );
    bad = call(&f);
    let mut value: Value = serde_json::from_str(&bad.arguments).unwrap();
    value["authorization_ref"] = json!("model-cannot-grant");
    bad.arguments = value.to_string();
    assert!(dispatcher.validate_call(&bad).is_err());
    bad = call(&f);
    bad.name = "process.exec".into();
    assert_eq!(
        dispatcher.validate_call(&bad).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    let broker = f.broker.lock().unwrap();
    assert!(broker.store().journal().invocation(INVOCATION).is_err());
    assert_eq!(
        broker.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    broker.store().integrity_check().unwrap();
}

#[test]
fn shape_valid_changed_command_or_profile_cannot_create_its_own_reviewed_grant() {
    let f = fixture("printf authorized", StoreConfig::default(), false);
    let mut dispatcher = dispatcher(&f);
    let before = f
        .broker
        .lock()
        .unwrap()
        .policy_control()
        .snapshot()
        .unwrap()
        .digest()
        .unwrap();
    let mut unauthorized = call(&f);
    let mut value: Value = serde_json::from_str(&unauthorized.arguments).unwrap();
    value["argv"][1] = json!("printf unauthorized");
    unauthorized.arguments = value.to_string();
    dispatcher.validate_call(&unauthorized).unwrap();
    let error = runtime()
        .block_on(dispatcher.execute(
            unauthorized,
            context("main"),
            Arc::new(AtomicBool::new(false)),
        ))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Authorization);
    let mut wrong_profile = context("other-profile");
    wrong_profile.profile_id = "melissa.code.debugger".into();
    let error = runtime()
        .block_on(dispatcher.execute(call(&f), wrong_profile, Arc::new(AtomicBool::new(false))))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Authorization);
    let broker = f.broker.lock().unwrap();
    assert!(broker.store().journal().invocation(INVOCATION).is_err());
    assert_eq!(
        broker
            .policy_control()
            .snapshot()
            .unwrap()
            .digest()
            .unwrap(),
        before
    );
}

#[test]
fn real_rust_build_and_test_crosses_dispatcher_broker_and_encrypted_evidence_then_inspects() {
    let f = fixture(
        "/usr/local/cargo/bin/cargo test --offline --manifest-path Cargo.toml -- --nocapture",
        StoreConfig::default(),
        true,
    );
    let mut dispatcher = dispatcher(&f);
    let definitions = dispatcher.definitions();
    assert_eq!(definitions.len(), 3);
    assert_eq!(definitions[0].canonical_id, "process.exec");
    assert!(!definitions[0].definition.strict);
    assert_eq!(
        definitions[0].definition.parameters["$id"],
        "melissa.container-exec/v1"
    );
    let outcome = runtime()
        .block_on(dispatcher.execute(call(&f), context("main"), Arc::new(AtomicBool::new(false))))
        .unwrap();
    assert!(
        outcome.success && !outcome.cancelled && !outcome.requires_reconciliation,
        "{outcome:?}"
    );
    let content: Value = serde_json::from_str(&outcome.content).unwrap();
    assert_eq!(content["observation"]["status"], "success");
    assert_eq!(content["task_accepted"], false);
    let stdout = content["stdout"]["text"].as_str().unwrap();
    assert!(stdout.contains("CODE04_DISPATCH_REAL_RUST") && stdout.contains("1 passed; 0 failed"));
    assert_eq!(content["stdout"]["preview_truncated"], false);
    {
        let broker = f.broker.lock().unwrap();
        for artifact in &outcome.artifact_refs {
            assert!(broker.store().get_artifact(TASK, artifact).is_ok());
            assert!(broker.store().get_artifact("task:other", artifact).is_err());
        }
        assert_eq!(
            broker
                .store()
                .journal()
                .attempt("attempt:dispatch-main")
                .unwrap()
                .state,
            AttemptState::Succeeded
        );
        assert_eq!(
            broker.store().journal().task(TASK).unwrap().record.state,
            TaskState::Running
        );
        broker.store().integrity_check().unwrap();
    }
    let replay = runtime().block_on(dispatcher.execute(
        call(&f),
        context("main"),
        Arc::new(AtomicBool::new(false)),
    ));
    assert!(replay.is_err());
    let mut inspect_context = context("inspect");
    inspect_context.profile_id = "melissa.code.debugger".into();
    let inspected = runtime()
        .block_on(dispatcher.execute(
            control("inspect"),
            inspect_context,
            Arc::new(AtomicBool::new(false)),
        ))
        .unwrap();
    let inspected: Value = serde_json::from_str(&inspected.content).unwrap();
    assert_eq!(inspected["target"]["state"], "succeeded");
    assert_eq!(inspected["termination_confirmed"], true);
    assert_eq!(inspected["cancellation_requested"], false);
}

#[test]
fn control_wire_name_target_resource_and_host_profile_are_bound() {
    let f = fixture("printf unused", StoreConfig::default(), false);
    let dispatcher = dispatcher(&f);
    let mut mismatched = control("inspect");
    mismatched.name = "process_cancel".into();
    assert_eq!(
        dispatcher.validate_call(&mismatched).unwrap_err().kind,
        ErrorKind::Authorization
    );
    let mut other_resource = control("inspect");
    let mut value: Value = serde_json::from_str(&other_resource.arguments).unwrap();
    value["resource_id"] = json!("unowned");
    other_resource.arguments = value.to_string();
    assert_eq!(
        dispatcher.validate_call(&other_resource).unwrap_err().kind,
        ErrorKind::Authorization
    );
    let definitions = dispatcher.definitions();
    let inspect = definitions
        .iter()
        .find(|binding| binding.canonical_id == "process.inspect")
        .unwrap();
    assert_eq!(
        inspect.definition.parameters["properties"]["invocation_id"]["const"],
        INVOCATION
    );
    assert_eq!(
        inspect.definition.parameters["properties"]["tool"]["const"],
        "process.inspect"
    );
}

#[test]
fn evidence_failure_after_real_execution_returns_unknown_without_a_safe_retry_claim() {
    let f = fixture(
        "printf 'actually-executed'; printf output > result.txt",
        StoreConfig {
            max_blob_bytes: 2048,
            max_cas_bytes: 16 * 1024,
            ..StoreConfig::default()
        },
        false,
    );
    let mut dispatcher = dispatcher(&f);
    let result = runtime()
        .block_on(dispatcher.execute(
            call(&f),
            context("unknown"),
            Arc::new(AtomicBool::new(false)),
        ))
        .unwrap();
    assert!(!result.success && result.requires_reconciliation);
    let content: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(content["automatic_retry_allowed"], false);
    assert_eq!(content["status"], "outcome_unknown");
    let broker = f.broker.lock().unwrap();
    assert_eq!(
        broker
            .store()
            .get_artifact(TASK, "attempt:dispatch-unknown:stdout")
            .unwrap(),
        b"actually-executed"
    );
    assert_eq!(
        broker
            .store()
            .journal()
            .attempt("attempt:dispatch-unknown")
            .unwrap()
            .state,
        AttemptState::OutcomeUnknown
    );
    assert_eq!(
        broker
            .store()
            .journal()
            .invocation("inv:dispatch-unknown")
            .unwrap()
            .state,
        InvocationState::OutcomeUnknown
    );
    assert_ne!(
        broker.store().journal().task(TASK).unwrap().record.state,
        TaskState::Completed
    );
}

#[test]
fn async_runtime_can_signal_cancellation_while_the_real_broker_is_blocking() {
    let f = fixture("sleep 30", StoreConfig::default(), false);
    let mut dispatcher = dispatcher(&f);
    let flag = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&flag);
    let began = Instant::now();
    runtime().block_on(async {
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            signal.store(true, Ordering::Release);
        });
        let outcome = dispatcher
            .execute(call(&f), context("cancel"), flag)
            .await
            .unwrap();
        timer.await.unwrap();
        assert!(
            outcome.cancelled && !outcome.success && !outcome.requires_reconciliation,
            "{outcome:?}"
        );
    });
    assert!(began.elapsed() < Duration::from_secs(20));
}

fn fixture_sse(mut events: Vec<Value>) -> String {
    let mut wire = String::new();
    for (sequence, event) in events.iter_mut().enumerate() {
        event["sequence_number"] = json!(sequence);
        wire.push_str(&format!(
            "event: {}\r\ndata: {}\r\n\r\n",
            event["type"].as_str().unwrap(),
            event
        ));
    }
    wire
}
fn fixture_created(id: &str) -> Value {
    json!({"type":"response.created","response":{"id":id,"model":"local-fixture-model","status":"in_progress","output":[]}})
}
fn fixture_completed(id: &str, item: Value) -> Value {
    json!({"type":"response.completed","response":{"id":id,"model":"local-fixture-model","status":"completed","error":null,"incomplete_details":null,
        "output":[item],"usage":{"input_tokens":20,"output_tokens":10,"total_tokens":30}}})
}
fn tool_stream(arguments: &str) -> String {
    let item = json!({"id":"fc_gateway","type":"function_call","call_id":"call_gateway","name":"process_exec","arguments":arguments,"status":"completed"});
    let mut initial = item.clone();
    initial["arguments"] = json!("");
    initial["status"] = json!("in_progress");
    fixture_sse(vec![
        fixture_created("resp_gateway_tool"),
        json!({"type":"response.output_item.added","output_index":0,"item":initial}),
        json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_gateway","delta":arguments}),
        json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_gateway","arguments":arguments}),
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
        fixture_completed("resp_gateway_tool", item),
    ])
}
fn answer_stream() -> String {
    let text = "Rust fixture executed; this result remains a candidate.";
    let part = json!({"type":"output_text","text":text,"annotations":[],"logprobs":[]});
    let item = json!({"id":"msg_gateway","type":"message","role":"assistant","status":"completed","content":[part]});
    fixture_sse(vec![
        fixture_created("resp_gateway_answer"),
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_gateway","type":"message","role":"assistant","status":"in_progress","content":[]}}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_gateway","content_index":0,"part":{"type":"output_text","text":"","annotations":[],"logprobs":[]}}),
        json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg_gateway","content_index":0,"delta":text}),
        json!({"type":"response.output_text.done","output_index":0,"item_id":"msg_gateway","content_index":0,"text":text}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_gateway","content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
        fixture_completed("resp_gateway_answer", item),
    ])
}

/// A bounded local HTTP fixture. This speaks the provider wire protocol and
/// checks the returned real tool observation; it never contacts a model API.
struct LocalProvider {
    url: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<usize>>,
}

fn fixture_read(
    stream: &mut std::net::TcpStream,
    buffer: &mut [u8],
    served: usize,
    received: usize,
    phase: &str,
    began: Instant,
) -> usize {
    use std::io::Read;
    let remaining = Duration::from_secs(10)
        .checked_sub(began.elapsed())
        .filter(|value| !value.is_zero())
        .unwrap_or_else(|| {
            panic!(
                "local fixture request {} {phase} deadline after {} bytes",
                served + 1,
                received
            )
        });
    stream.set_read_timeout(Some(remaining)).unwrap();
    let read = stream.read(buffer).unwrap_or_else(|error| {
        panic!("local fixture request {} {phase} read failed after {:?}, {} bytes, kind {:?}, OS {:?}: {error}",
            served+1,began.elapsed(),received,error.kind(),error.raw_os_error())
    });
    assert!(
        read > 0,
        "local fixture request {} {phase} EOF after {} bytes",
        served + 1,
        received
    );
    read
}

impl LocalProvider {
    fn new(arguments: String) -> Self {
        use std::{io::Write, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/responses", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let began = Instant::now();
            let mut served = 0;
            while served < 2
                && !stopped.load(Ordering::Acquire)
                && began.elapsed() < Duration::from_secs(90)
            {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("local fixture accept: {error}"),
                };
                // Windows accepted sockets can retain the listener's mode.
                // Reads must wait for delayed or fragmented request bytes.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                let request_began = Instant::now();
                let header_end = loop {
                    let n = fixture_read(
                        &mut stream,
                        &mut buffer,
                        served,
                        bytes.len(),
                        "headers",
                        request_began,
                    );
                    bytes.extend_from_slice(&buffer[..n]);
                    assert!(bytes.len() < 2 * 1024 * 1024);
                    if let Some(index) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                assert!(length < 2 * 1024 * 1024);
                assert!(header_end + length <= 2 * 1024 * 1024);
                while bytes.len() < header_end + length {
                    let n = fixture_read(
                        &mut stream,
                        &mut buffer,
                        served,
                        bytes.len(),
                        "body",
                        request_began,
                    );
                    bytes.extend_from_slice(&buffer[..n]);
                }
                let request: Value =
                    serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                assert_eq!(request["store"], false);
                assert_eq!(request["tools"].as_array().unwrap().len(), 1);
                assert_eq!(request["tools"][0]["name"], "process_exec");
                let body = if served == 0 {
                    tool_stream(&arguments)
                } else {
                    let result = request["input"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|item| item["type"] == "function_call_output")
                        .expect("real tool result must reach the next provider request");
                    let result: Value =
                        serde_json::from_str(result["output"].as_str().unwrap()).unwrap();
                    assert_eq!(result["observation"]["status"], "success");
                    assert!(
                        result["stdout"]["text"]
                            .as_str()
                            .unwrap()
                            .contains("CODE04_DISPATCH_REAL_RUST")
                    );
                    assert_eq!(result["task_accepted"], false);
                    answer_stream()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                served += 1;
            }
            served
        });
        Self {
            url,
            stop,
            thread: Some(handle),
        }
    }
    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap()
    }
}
impl Drop for LocalProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn local_provider_accepts_delayed_fragmented_http_headers_and_body_on_both_turns() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };
    let server = LocalProvider::new("{}".into());
    let address = server
        .url
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let fixture_observation=json!({"observation":{"status":"success"},"stdout":{"text":"CODE04_DISPATCH_REAL_RUST"},"task_accepted":false}).to_string();
    // These are wire-framing fixtures only; no process is executed here.
    let requests = [
        json!({"store":false,"tools":[{"name":"process_exec"}],"input":[]}),
        json!({"store":false,"tools":[{"name":"process_exec"}],"input":[{"type":"function_call_output","output":fixture_observation}]}),
    ];
    for (turn, request) in requests.into_iter().enumerate() {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nonblocking(false).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // Give accept/read time to run before any request byte exists. Without
        // explicitly blocking accepted sockets, Windows returns OS10035 here.
        std::thread::sleep(Duration::from_millis(75));
        let body = request.to_string();
        let headers = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        for chunk in headers.as_bytes().chunks(11) {
            stream.write_all(chunk).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(20));
        for chunk in body.as_bytes().chunks(7) {
            stream.write_all(chunk).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        stream.flush().unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains(if turn == 0 {
            "response.function_call_arguments.done"
        } else {
            "Rust fixture executed; this result remains a candidate."
        }));
    }
    assert_eq!(server.finish(), 2);
}

#[test]
fn local_gateway_provider_protocol_drives_real_rust_broker_and_returns_only_a_candidate() {
    use melissa_model_gateway::{
        DecoderLimits, Protocol,
        agent_loop::{Gateway, GatewayPolicy, RunSpec, RunStatus},
        routing::{
            Capabilities, Measurements, ModelRegistration, PriceSource, RateCard, RouteRequirements,
        },
        transport::{ApiKey, EndpointTrust, ProviderEndpoint},
    };
    let f = fixture(
        "/usr/local/cargo/bin/cargo test --offline --manifest-path Cargo.toml -- --nocapture",
        StoreConfig::default(),
        true,
    );
    let server = LocalProvider::new(serde_json::to_string(&f.request).unwrap());
    let endpoint = ProviderEndpoint::new(
        "fixture:openai".into(),
        "provider:code04-loopback".into(),
        "auth:code04-loopback".into(),
        Protocol::OpenAiResponses,
        EndpointTrust::LoopbackFixture,
        &server.url,
        ApiKey::new("fixture-key-not-a-live-credential".into()).unwrap(),
    )
    .unwrap();
    let registration = ModelRegistration {
        registration_id: "fixture:openai:coding".into(),
        endpoint,
        model_id: "local-fixture-model".into(),
        capabilities: Capabilities {
            tool_calling: true,
            structured_output: true,
            vision: false,
            streaming: true,
        },
        categories: BTreeSet::from(["coding".into()]),
        context_tokens: 4096,
        max_output_tokens: 256,
        timeout_ms: 20_000,
        max_concurrency: 1,
        slots: Arc::new(tokio::sync::Semaphore::new(1)),
        rate_card: Some(RateCard {
            source: PriceSource::Fixture,
            input_micro_usd_per_million: 0,
            output_micro_usd_per_million: 0,
            cached_input_micro_usd_per_million: None,
            cache_creation_micro_usd_per_million: None,
        }),
        measurements: Measurements::default(),
    };
    let store = f.broker.lock().unwrap().store().connect().unwrap();
    let catalog = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut gateway = Gateway::new(
        store,
        catalog,
        vec![registration],
        GatewayPolicy {
            allowed_registrations: BTreeSet::from(["fixture:openai:coding".into()]),
            max_requests: 3,
            max_turns: 3,
            max_tools: 2,
            max_wall_time_ms: 120_000,
            expires_at_unix_ms: unix_ms().unwrap() + 120_000,
            allow_fallback: false,
            max_backoff_ms: 0,
            decoder_limits: DecoderLimits::default(),
        },
        true,
    )
    .unwrap();
    // The implementer profile owns execution. Inspect/cancel remain separate
    // debugger capabilities and are deliberately not declared in this run.
    let mut dispatcher = BrokerDispatcher::container(
        Arc::clone(&f.broker),
        Arc::clone(&f.snapshot),
        BrokerDispatcherConfig {
            principal_id: "principal:host".into(),
            resource_id: RESOURCE.into(),
            authorization_refs: BTreeMap::from([(
                "process.exec".into(),
                "auth:dispatch-exec".into(),
            )]),
            permit_lifetime_ms: 60_000,
        },
    )
    .unwrap();
    let spec = RunSpec {
        run_id: "code04_real_broker_loop".into(),
        task_id: TASK.into(),
        profile_id: "melissa.code.implementer".into(),
        user_message: "Run the exact authorized Rust fixture and report its observed result."
            .into(),
        route: RouteRequirements {
            category: "coding".into(),
            tools: true,
            structured_output: true,
            vision: false,
            minimum_success_ppm: None,
            maximum_p95_ms: None,
        },
        max_output_tokens: 256,
        output_schema: None,
        required_tool_names: BTreeSet::from(["process_exec".into()]),
    };
    let result = runtime()
        .block_on(gateway.run(&spec, &mut dispatcher, Arc::new(AtomicBool::new(false))))
        .unwrap();
    assert_eq!(server.finish(), 2);
    assert_eq!(result.status, RunStatus::FinalCandidate, "{result:?}");
    assert_eq!(result.tool_calls, 1);
    assert_eq!(result.request_ids.len(), 2);
    assert!(!result.task_accepted && !result.requires_reconciliation);
    assert!(
        result
            .answer
            .as_deref()
            .unwrap()
            .contains("remains a candidate")
    );
    let call_hash = blake3::hash(b"call_gateway").to_hex().to_string();
    let invocation = format!("model-tool:code04_real_broker_loop:{}", &call_hash[..24]);
    let attempt = format!("{invocation}:attempt");
    let broker = f.broker.lock().unwrap();
    let stdout = broker
        .store()
        .get_artifact(TASK, &format!("{attempt}:stdout"))
        .unwrap();
    assert!(String::from_utf8_lossy(&stdout).contains("CODE04_DISPATCH_REAL_RUST"));
    assert_eq!(
        broker.store().journal().attempt(&attempt).unwrap().state,
        AttemptState::Succeeded
    );
    assert_eq!(
        gateway.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    for artifact in &result.artifact_refs {
        assert!(gateway.store().get_artifact(TASK, artifact).is_ok());
    }
    gateway.store().integrity_check().unwrap();
}

#[test]
fn native_dispatcher_runs_real_appcontainer_probe_and_rejects_changed_arguments() {
    use melissa_execution_broker::Broker;
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("owned-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let executable = dir.path().join("owned-probe.exe");
    std::fs::copy(
        project.join("target/debug/melissa-executor-probe.exe"),
        &executable,
    )
    .expect("build the real native executor probe before running native broker acceptance");
    let task_id = "task:code04-native-dispatch";
    let resource = "workspace:code04-native-dispatch";
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = task_id.into();
    task.workspace_ref = resource.into();
    task.selected_profile_ids = vec!["melissa.code.implementer".into()];
    task.allowed_resource_ids = vec![resource.into()];
    task.authorization_refs = vec!["auth:native-dispatch".into()];
    task.allowed_effects = vec![
        "process.execute_scoped".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    task.limits.max_disk_bytes = 64 * 1024 * 1024;
    task.limits.max_output_bytes = 1024 * 1024;
    let mut store = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([175; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    store.journal_mut().create_task(&task).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = store.journal().task(task_id).unwrap().record.version;
        store
            .journal_mut()
            .transition_task(task_id, version, next, None)
            .unwrap();
    }
    let limits = ProcessLimits {
        wall_time_ms: 5_000,
        cpu_time_ms: 3_000,
        cpu_rate_basis_points: 10000,
        cpu_mode: CpuLimitMode::MonitoredTotal,
        memory_bytes: 128 * 1024 * 1024,
        disk_bytes: 64 * 1024 * 1024,
        disk_mode: DiskLimitMode::Monitored,
        output_bytes: 65_536,
        max_processes: 8,
        network: NetworkPolicy::Deny,
    };
    let mut ceiling = limits.clone();
    ceiling.wall_time_ms = 60_000;
    ceiling.cpu_time_ms = 60_000;
    ceiling.output_bytes = 1024 * 1024;
    let policy = HostPolicy {
        revision: "policy:code04-native:1".into(),
        revocation_epoch: 1,
        issuer: "host:native-dispatch".into(),
        audience: "executor:native-dispatch".into(),
        key_id: "replaced-session".into(),
        max_permit_lifetime_ms: 60_000,
        ceiling,
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: false,
            memory: true,
            disk_quota: false,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: true,
        allow_monitored_cpu: true,
        allowed_env_names: BTreeSet::from(["MELISSA_VISIBLE".into()]),
        grants: BTreeMap::new(),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    };
    let broker = Broker::new(
        store,
        Catalog::load(&project).unwrap(),
        workspace.clone(),
        resource.into(),
        policy,
    )
    .unwrap();
    let request = ProcessSpec {
        schema_version: "melissa.process-exec/v2".into(),
        executable: executable.to_str().unwrap().into(),
        argv: vec!["ok".into()],
        cwd: ".".into(),
        env: BTreeMap::from([("MELISSA_VISIBLE".into(), "explicit-only".into())]),
        limits,
        effects: task.allowed_effects.clone(),
        worker_type: "generic".into(),
    };
    let pinned = broker.resolve(&request).unwrap();
    let now = unix_ms().unwrap();
    let mut reviewed = broker.policy_control().snapshot().unwrap();
    reviewed.grants.insert(
        "auth:native-dispatch".into(),
        AuthorityGrant {
            authorization_ref: "auth:native-dispatch".into(),
            task_id: task_id.into(),
            task_digest: authenticated_digest(&task).unwrap(),
            principal_id: "principal:host".into(),
            profile_id: "melissa.code.implementer".into(),
            resource_id: resource.into(),
            process_digest: pinned.resolved().resolved_digest().unwrap(),
            allow_monitored_disk: true,
            allow_monitored_cpu: true,
            allowed_effects: task.allowed_effects.iter().cloned().collect(),
            not_before_unix_ms: now.saturating_sub(100),
            expires_at_unix_ms: now + 60_000,
        },
    );
    drop(pinned);
    broker.policy_control().replace(reviewed).unwrap();
    let broker = Arc::new(Mutex::new(broker));
    let mut dispatcher = BrokerDispatcher::native(
        Arc::clone(&broker),
        BrokerDispatcherConfig {
            principal_id: "principal:host".into(),
            resource_id: resource.into(),
            authorization_refs: BTreeMap::from([(
                "process.exec".into(),
                "auth:native-dispatch".into(),
            )]),
            permit_lifetime_ms: 30_000,
        },
    )
    .unwrap();
    assert_eq!(
        dispatcher.definitions()[0].definition.parameters["$id"],
        "melissa.process-exec/v2"
    );
    let call = ToolCall {
        id: "call:native".into(),
        name: "process_exec".into(),
        arguments: serde_json::to_string(&request).unwrap(),
    };
    let mut execution_context = context("native");
    execution_context.task_id = task_id.into();
    let outcome = runtime()
        .block_on(dispatcher.execute(
            call.clone(),
            execution_context,
            Arc::new(AtomicBool::new(false)),
        ))
        .unwrap();
    assert!(
        outcome.success && !outcome.requires_reconciliation,
        "{outcome:?}"
    );
    let content: Value = serde_json::from_str(&outcome.content).unwrap();
    assert_eq!(
        content["stdout"]["text"].as_str().unwrap().trim(),
        "ok:explicit-only"
    );
    assert!(
        content["stderr"]["text"]
            .as_str()
            .unwrap()
            .contains("stderr-ok")
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("inside.txt")).unwrap(),
        "owned workspace"
    );
    {
        let broker = broker.lock().unwrap();
        let report: Value = serde_json::from_slice(
            &broker
                .store()
                .get_artifact(task_id, "attempt:dispatch-native:execution-report")
                .unwrap(),
        )
        .unwrap();
        for flag in [
            "process_was_appcontainer",
            "win32k_system_calls_disabled",
            "tree_confirmed_stopped",
            "profile_removed",
            "acl_restored",
        ] {
            assert_eq!(report["report"][flag], true, "{flag}");
        }
        assert_eq!(
            broker.store().journal().task(task_id).unwrap().record.state,
            TaskState::Running
        );
        for id in &outcome.artifact_refs {
            assert!(broker.store().get_artifact(task_id, id).is_ok());
        }
        broker.store().integrity_check().unwrap();
    }
    let mut changed = call;
    let mut args: Value = serde_json::from_str(&changed.arguments).unwrap();
    args["argv"] = json!(["different"]);
    changed.arguments = args.to_string();
    let mut denied_context = context("native-denied");
    denied_context.task_id = task_id.into();
    let error = runtime()
        .block_on(dispatcher.execute(changed, denied_context, Arc::new(AtomicBool::new(false))))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Authorization);
    assert!(
        broker
            .lock()
            .unwrap()
            .store()
            .journal()
            .invocation("inv:dispatch-native-denied")
            .is_err()
    );
}
