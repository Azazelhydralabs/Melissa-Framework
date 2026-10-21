//! Independent CODE-02 integration checks. These exercise durable host records,
//! not a worker, real external effect, model, or autonomous task acceptance.
use std::{fs, path::Path, process::Command};

use melissa_core_contracts::{
    InvocationState, ReconciliationEvidence, TaskState, wire::TaskContractV1,
};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreConfig, StoreError, StoreKey,
    journal::{AttemptState, InvocationRequest},
};
use serde_json::json;

const TASK: &str = "task:session-crash";
const INVOCATION: &str = "invocation:session-crash";
const ATTEMPT: &str = "attempt:session-crash";
const RESOLUTION: &str = "artifact:synthetic-host-resolution";
const CRASH_ENV: &str = "MELISSA_CODE02_SESSION_RECOVERY_ROOT";

fn key() -> StoreKey {
    StoreKey::from_bytes([23; 32])
}

fn contract() -> TaskContractV1 {
    let mut value: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    value.task_id = TASK.into();
    value.goal = "Host journal fixture only; execute no external operation".into();
    value
}

fn version(store: &LocalStore) -> u64 {
    store.journal().task(TASK).unwrap().record.version
}

fn next(store: &mut LocalStore, state: TaskState) {
    store
        .transition_task(TASK, version(store), state, None)
        .unwrap();
}

fn request(id: &str) -> InvocationRequest {
    InvocationRequest {
        invocation_id: id.into(),
        task_id: TASK.into(),
        tool_id: "test.storage-fixture".into(),
        arguments: json!({"operation": "record-intention-only"}),
        idempotency_key: Some("session-fixture-key".into()),
        generation: 7,
    }
}

#[test]
fn abrupt_session_reopen_requires_owned_authenticated_reconciliation() {
    let dir = tempfile::Builder::new()
        .prefix("melissa-code02-session-recovery-")
        .tempdir()
        .unwrap();
    let root = dir.path().join("store");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_dispatched_session_fixture", "--nocapture"])
        .env(CRASH_ENV, &root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(76),
        "child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // LocalStore::open, rather than a manually called recovery helper, owns
    // exclusive session takeover and records the uncertain outcome.
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    let recovered = store.journal().task(TASK).unwrap();
    assert_eq!(recovered.record.state, TaskState::OutcomeUnknown);
    assert_eq!(
        recovered.record.unknown_invocation_id.as_deref(),
        Some(INVOCATION)
    );
    assert_eq!(
        store.journal().invocation(INVOCATION).unwrap().state,
        InvocationState::OutcomeUnknown
    );
    assert_eq!(
        store.journal().attempt(ATTEMPT).unwrap().state,
        AttemptState::OutcomeUnknown
    );
    assert!(matches!(
        store.transition_task(TASK, recovered.record.version, TaskState::Cancelled, None),
        Err(StoreError::Conflict(_))
    ));
    assert!(
        store
            .journal_mut()
            .propose_invocation(&request("invocation:blind-retry"), recovered.record.version)
            .is_err()
    );
    let guard = store.journal().attempt_guard(ATTEMPT).unwrap();
    assert!(store.journal_mut().dispatch_attempt(&guard).is_err());
    assert_eq!(version(&store), recovered.record.version);

    next(&mut store, TaskState::NeedsReconciliation);
    let metadata = store
        .put_artifact(
            &ArtifactRequest {
                artifact_id: RESOLUTION.into(),
                task_id: TASK.into(),
                content_type: "application/json".into(),
                logical_type: "test.synthetic-host-resolution".into(),
                schema_version: "test/v1".into(),
                retain_until_ms: 0,
                legal_hold: false,
            },
            br#"{"fixture":true,"external_operation_executed":false}"#,
        )
        .unwrap();
    let proof = ReconciliationEvidence {
        task_id: TASK.into(),
        invocation_id: INVOCATION.into(),
        resolution_artifact_ref: RESOLUTION.into(),
        external_effect_resolved: true,
    };
    let task_version = version(&store);
    let invocation_version = store.journal().invocation(INVOCATION).unwrap().version;

    let blob = cas_path(&root, &metadata.digest);
    let original = fs::read(&blob).unwrap();
    let mut damaged = original.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&blob, damaged).unwrap();
    assert!(
        store
            .reconcile_invocation(task_version, invocation_version, &proof)
            .is_err()
    );
    assert_eq!(version(&store), task_version);
    assert_eq!(
        store.journal().invocation(INVOCATION).unwrap().version,
        invocation_version
    );
    fs::write(&blob, original).unwrap();

    let reconciled = store
        .reconcile_invocation(task_version, invocation_version, &proof)
        .unwrap();
    assert_eq!(reconciled.record.state, TaskState::Verifying);
    assert!(reconciled.record.unknown_invocation_id.is_none());
    assert_eq!(
        store.journal().attempt(ATTEMPT).unwrap().state,
        AttemptState::Reconciled
    );
    assert!(
        store
            .transition_task(TASK, reconciled.record.version, TaskState::Completed, None)
            .is_err()
    );
    assert_eq!(
        store
            .journal()
            .events(TASK)
            .unwrap()
            .last()
            .unwrap()
            .reconciliation_evidence
            .as_ref(),
        Some(&proof)
    );
    store.integrity_check().unwrap();
    drop(store);

    let reopened = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    assert_eq!(
        reopened.journal().task(TASK).unwrap().record.state,
        TaskState::Verifying
    );
    assert_eq!(
        reopened.journal().invocation(INVOCATION).unwrap().state,
        InvocationState::Reconciled
    );
    assert_eq!(
        reopened.get_artifact(TASK, RESOLUTION).unwrap(),
        br#"{"fixture":true,"external_operation_executed":false}"#
    );
    reopened.integrity_check().unwrap();
}

fn cas_path(root: &Path, digest: &str) -> std::path::PathBuf {
    root.join("cas/blobs")
        .join(format!("{}.blob", &digest[7..]))
}

#[test]
fn child_dispatched_session_fixture() {
    let Some(root) = std::env::var_os(CRASH_ENV) else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(
        root.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("melissa-code02-session-recovery-")
    );
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    store.journal_mut().create_task(&contract()).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        next(&mut store, state);
    }
    let current = version(&store);
    store
        .journal_mut()
        .propose_invocation(&request(INVOCATION), current)
        .unwrap();
    let current = version(&store);
    store
        .journal_mut()
        .authorize_invocation(INVOCATION, current, 0)
        .unwrap();
    let current = version(&store);
    store
        .journal_mut()
        .begin_attempt(INVOCATION, ATTEMPT, current, 1, 7)
        .unwrap();
    let guard = store.journal().attempt_guard(ATTEMPT).unwrap();
    store.journal_mut().dispatch_attempt(&guard).unwrap();
    // Abrupt termination skips the SQLite connection/session destructors. This
    // records dispatch intent only; no external operation has been executed.
    std::process::exit(76);
}

#[test]
fn linked_sqlite_has_the_official_wal_reset_fix() {
    // SQLite's official WAL documentation lists 3.51.3+ as fixed. This project
    // pins a later bundled release, so older selectively backported branches
    // need not be admitted by this acceptance check.
    assert!(
        rusqlite::version_number() >= 3_051_003,
        "unpatched SQLite runtime {}",
        rusqlite::version()
    );
    println!(
        "SQLite runtime {} ({})",
        rusqlite::version(),
        rusqlite::version_number()
    );
}
