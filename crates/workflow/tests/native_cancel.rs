#![cfg(windows)]
#[path = "../../build-test/tests/support/mod.rs"]
mod support;
use melissa_build_test::{
    RustOperation,
    toolchain::{COMPLETE_IMAGE, PYTHON},
};
use melissa_container_executor::{ContainerRequest, Snapshot};
use melissa_core_contracts::{TaskState, catalog::Catalog};
use melissa_model_gateway::{
    ToolCall,
    tools::{BrokerDispatcher, BrokerDispatcherConfig, ToolContext, ToolDispatcher},
};
use melissa_workflow::{gate::NodeDispatcher, plan::*, scheduler::*};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

#[tokio::test]
async fn workflow_root_cancel_stops_actual_admitted_container_process_tree() {
    let mut fixture = support::Fixture::new(
        "pub fn owned(){}\n",
        RustOperation::Build,
        &[],
        support::limits(),
    );
    let mut request=ContainerRequest{schema_version:"melissa.container-exec/v1".into(),image_id:COMPLETE_IMAGE.into(),executable:PYTHON.into(),argv:vec!["-I".into(),"-S".into(),"-c".into(),"import subprocess,pathlib,time; pathlib.Path('started').write_text('CODE08_WORKER_STARTED'); child=subprocess.Popen(['sleep','30']); time.sleep(30)".into()],cwd:".".into(),env:BTreeMap::new(),limits:support::limits()};
    request.limits.wall_time_ms = 30000;
    let snapshot = Snapshot {
        files: BTreeMap::from([("owned.txt".into(), b"owned source".to_vec())]),
    };
    let _unused_signed = support::permit_for(&mut fixture, &request, &snapshot);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = Catalog::load(&root).unwrap();
    let task = fixture.task.clone();
    let profile = task.selected_profile_ids[0].clone();
    let policy_digest = melissa_workflow::digest(b"native-root-cancel-policy");
    let plan = Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "nativecancel".into(),
        task: task.task_id.clone(),
        revision: 1,
        parent_digest: None,
        workspace_digest: task.input_snapshot_digest.clone(),
        policy_digest: policy_digest.clone(),
        mode: Mode::SingleAgent,
        delegation_reason: None,
        max_parallel: 1,
        max_no_progress: 3,
        nodes: vec![Node {
            id: "worker".into(),
            profile: profile.clone(),
            goal: "Owned actual isolated process cancellation fixture".into(),
            after: BTreeSet::new(),
            bindings: vec![],
            literal_input: json!({}),
            tools: BTreeSet::from(["process.exec".into()]),
            effects: task.allowed_effects.iter().cloned().collect(),
            resources: BTreeSet::from([task.workspace_ref.clone()]),
            authorizations: task.authorization_refs.iter().cloned().collect(),
            claims: vec![Claim {
                resource: task.workspace_ref.clone(),
                path: "/".into(),
                access: Access::Read,
            }],
            output_schema: json!({"type":"object"}),
            skills: vec![],
        }],
        outputs: BTreeSet::from(["worker".into()]),
    };
    let repo = Arc::new(fixture.repo);
    let repo_for_refresh = repo.clone();
    let scheduler = Scheduler::create(
        fixture.broker.store().connect().unwrap(),
        plan,
        &catalog,
        Arc::new(move || {
            Ok(Freshness {
                workspace_digest: repo_for_refresh
                    .snapshot(&AtomicBool::new(false))
                    .unwrap()
                    .digest,
                policy_digest: policy_digest.clone(),
            })
        }),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let owner = Arc::new(Mutex::new(scheduler));
    let packet = owner
        .lock()
        .unwrap()
        .acquire("worker", "host:native", 60000)
        .unwrap();
    let flag = owner.lock().unwrap().flag();
    let backend = BrokerDispatcher::container(
        Arc::new(Mutex::new(fixture.broker)),
        Arc::new(snapshot),
        BrokerDispatcherConfig {
            principal_id: "principal:code06-rust".into(),
            resource_id: task.workspace_ref.clone(),
            authorization_refs: BTreeMap::from([(
                "process.exec".into(),
                "auth:code06-rust".into(),
            )]),
            permit_lifetime_ms: 90000,
        },
    )
    .unwrap();
    let mut dispatcher =
        NodeDispatcher::new(owner.clone(), packet.clone(), Box::new(backend)).unwrap();
    let context = ToolContext {
        task_id: task.task_id.clone(),
        profile_id: profile,
        run_id: packet.lease.run,
        request_id: "native:local:no-model".into(),
        invocation_id: "inv:code08-worker-cancel".into(),
        attempt_id: "attempt:code08-worker-cancel".into(),
        generation: 1,
    };
    let call = ToolCall {
        id: "actual-native".into(),
        name: "process_exec".into(),
        arguments: serde_json::to_string(&request).unwrap(),
    };
    let running = tokio::spawn(async move { dispatcher.execute(call, context, flag).await });
    let mut container = None;
    for _ in 0..500 {
        let bytes = owner.lock().unwrap().store().get_artifact(
            &task.task_id,
            "attempt:code08-worker-cancel:container-identity",
        );
        if let Ok(bytes) = bytes {
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let id = value["container_id"].as_str().unwrap();
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
            let marker = std::process::Command::new("docker")
                .args([
                    "exec",
                    "--user",
                    "65534:65534",
                    id,
                    "/bin/cat",
                    "/work/started",
                ])
                .output()
                .unwrap();
            if marker.status.success() && marker.stdout == b"CODE08_WORKER_STARTED" {
                container = Some(id.to_string());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    if container.is_none() {
        owner.lock().unwrap().cancel().unwrap();
        let _ = running.await;
        panic!("owned worker did not reach actual script marker");
    }
    owner.lock().unwrap().cancel().unwrap();
    let result = running.await.unwrap().unwrap();
    assert!(result.cancelled && !result.requires_reconciliation);
    let mut s = owner.lock().unwrap();
    let report: serde_json::Value = serde_json::from_slice(
        &s.store()
            .get_artifact(
                &task.task_id,
                "attempt:code08-worker-cancel:execution-report",
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["report"]["cleanup_confirmed"], true);
    assert_eq!(report["report"]["tree_confirmed_stopped"], true);
    assert_eq!(report["requires_reconciliation"], false);
    assert!(
        !std::process::Command::new("docker")
            .args(["inspect", &container.unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(s.settle_cancellation().unwrap().cancellation_settled);
    assert_eq!(
        s.store()
            .journal()
            .task(&task.task_id)
            .unwrap()
            .record
            .state,
        TaskState::Cancelled
    );
    s.store().integrity_check().unwrap();
}
