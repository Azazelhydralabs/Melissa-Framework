//! Independent integration checks for restore uncertainty and coordinated files.
use std::{
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use melissa_core_contracts::{InvocationState, TaskState, wire::TaskContractV1};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreConfig, StoreKey,
    journal::{AttemptState, InvocationRequest},
};
use serde_json::json;

fn key() -> StoreKey {
    StoreKey::from_bytes([91; 32])
}

fn contract(id: &str) -> TaskContractV1 {
    let mut contract: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    contract.task_id = id.into();
    contract
}

fn advance(store: &mut LocalStore, task: &str, state: TaskState) {
    let version = store.journal().task(task).unwrap().record.version;
    store.transition_task(task, version, state, None).unwrap();
}

fn request(task: &str, artifact: &str) -> ArtifactRequest {
    ArtifactRequest {
        artifact_id: artifact.into(),
        task_id: task.into(),
        content_type: "application/octet-stream".into(),
        logical_type: "independent-review-fixture".into(),
        schema_version: "fixture/v1".into(),
        retain_until_ms: 0,
        legal_hold: false,
    }
}

#[test]
fn restoring_a_dispatched_backup_records_uncertainty_without_mutating_live_source() {
    let directory = tempfile::tempdir().unwrap();
    let mut source = LocalStore::open(
        &directory.path().join("source"),
        key(),
        StoreConfig::default(),
    )
    .unwrap();
    source
        .journal_mut()
        .create_task(&contract("task:dispatched"))
        .unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        advance(&mut source, "task:dispatched", state);
    }
    let invocation = InvocationRequest {
        invocation_id: "invocation:side-effect".into(),
        task_id: "task:dispatched".into(),
        tool_id: "review.synthetic-operation".into(),
        arguments: json!({"opaque_resource": "fixture"}),
        idempotency_key: Some("request:once".into()),
        generation: 1,
    };
    let version = source
        .journal()
        .task("task:dispatched")
        .unwrap()
        .record
        .version;
    source
        .journal_mut()
        .propose_invocation(&invocation, version)
        .unwrap();
    let version = source
        .journal()
        .task("task:dispatched")
        .unwrap()
        .record
        .version;
    source
        .journal_mut()
        .authorize_invocation(&invocation.invocation_id, version, 0)
        .unwrap();
    let version = source
        .journal()
        .task("task:dispatched")
        .unwrap()
        .record
        .version;
    source
        .journal_mut()
        .begin_attempt(
            &invocation.invocation_id,
            "attempt:possibly-executed",
            version,
            1,
            1,
        )
        .unwrap();
    let original_guard = source
        .journal()
        .attempt_guard("attempt:possibly-executed")
        .unwrap();
    source
        .journal_mut()
        .dispatch_attempt(&original_guard)
        .unwrap();
    let source_version = source
        .journal()
        .task("task:dispatched")
        .unwrap()
        .record
        .version;

    let backup = directory.path().join("backup");
    source.backup(&backup).unwrap();
    let mut restored = LocalStore::restore_backup(
        &backup,
        &directory.path().join("restored"),
        key(),
        StoreConfig::default(),
    )
    .unwrap();
    let task = restored.journal().task("task:dispatched").unwrap();
    assert_eq!(task.record.state, TaskState::OutcomeUnknown);
    assert_eq!(
        task.record.unknown_invocation_id.as_deref(),
        Some(invocation.invocation_id.as_str())
    );
    assert_eq!(
        restored
            .journal()
            .invocation(&invocation.invocation_id)
            .unwrap()
            .state,
        InvocationState::OutcomeUnknown
    );
    assert_eq!(
        restored
            .journal()
            .attempt("attempt:possibly-executed")
            .unwrap()
            .state,
        AttemptState::OutcomeUnknown
    );
    assert_eq!(task.record.version, source_version + 1);
    assert!(
        restored
            .journal_mut()
            .dispatch_attempt(&original_guard)
            .is_err()
    );
    assert!(
        restored
            .transition_task(
                "task:dispatched",
                task.record.version,
                TaskState::Completed,
                None
            )
            .is_err()
    );
    let mut retry = invocation.clone();
    retry.invocation_id = "invocation:blind-retry".into();
    retry.idempotency_key = None;
    assert!(
        restored
            .journal_mut()
            .propose_invocation(&retry, task.record.version)
            .is_err()
    );
    restored.integrity_check().unwrap();

    assert_eq!(
        source
            .journal()
            .task("task:dispatched")
            .unwrap()
            .record
            .version,
        source_version
    );
    assert_eq!(
        source
            .journal()
            .task("task:dispatched")
            .unwrap()
            .record
            .state,
        TaskState::Running
    );
    assert_eq!(
        source
            .journal()
            .invocation(&invocation.invocation_id)
            .unwrap()
            .state,
        InvocationState::Dispatched
    );
    assert_eq!(
        source
            .journal()
            .attempt("attempt:possibly-executed")
            .unwrap()
            .state,
        AttemptState::Dispatched
    );
    source.integrity_check().unwrap();
}

#[test]
fn backup_and_gc_overlap_publication_without_deleting_accepted_shared_content() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStore::open(
        &directory.path().join("source"),
        key(),
        StoreConfig::default(),
    )
    .unwrap();
    store
        .journal_mut()
        .create_task(&contract("task:active"))
        .unwrap();
    store
        .journal_mut()
        .create_task(&contract("task:retired"))
        .unwrap();
    let content = b"shared artifact must survive whichever operation wins";
    store
        .put_artifact(&request("task:retired", "retired:shared"), content)
        .unwrap();
    advance(&mut store, "task:retired", TaskState::Cancelled);
    store
        .release_artifact("task:retired", "retired:shared")
        .unwrap();

    let mut writer = store.connect().unwrap();
    let mut collector = store.connect().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let writer_barrier = Arc::clone(&barrier);
    let writer_thread = thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..20 {
            // Journal writes use SQLite coordination independently from files.
            writer
                .journal_mut()
                .create_task(&contract(&format!("task:journal:{index}")))
                .unwrap();
            writer
                .put_artifact(
                    &request("task:active", &format!("accepted:{index}")),
                    content,
                )
                .unwrap();
        }
    });
    let collector_barrier = Arc::clone(&barrier);
    let collector_thread = thread::spawn(move || {
        collector_barrier.wait();
        for _ in 0..8 {
            let future = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 1_000;
            collector.collect_garbage(future, 0).unwrap();
        }
    });
    barrier.wait();
    for index in 0..3 {
        let backup = directory
            .path()
            .join(format!("backup:{index}").replace(':', "-"));
        store.backup(&backup).unwrap();
        let restored = LocalStore::restore_backup(
            &backup,
            &directory.path().join(format!("restored-{index}")),
            key(),
            StoreConfig::default(),
        )
        .unwrap();
        restored.integrity_check().unwrap();
        assert_eq!(
            restored.journal().task("task:active").unwrap().record.state,
            TaskState::Created
        );
        // A snapshot may precede some publications, but it may never retain a
        // metadata reference whose ciphertext is missing or only half-written.
        for artifact in 0..20 {
            let id = format!("accepted:{artifact}");
            if restored.artifact_metadata("task:active", &id).is_ok() {
                assert_eq!(restored.get_artifact("task:active", &id).unwrap(), content);
            }
        }
    }
    writer_thread.join().unwrap();
    collector_thread.join().unwrap();
    for index in 0..20 {
        assert_eq!(
            store
                .get_artifact("task:active", &format!("accepted:{index}"))
                .unwrap(),
            content
        );
        assert_eq!(
            store
                .journal()
                .task(&format!("task:journal:{index}"))
                .unwrap()
                .record
                .state,
            TaskState::Created
        );
    }
    store.integrity_check().unwrap();
}
