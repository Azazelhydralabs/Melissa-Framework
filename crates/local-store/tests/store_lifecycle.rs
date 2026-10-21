use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use melissa_core_contracts::{CompletionEvidence, TaskState, wire::TaskContractV1};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreConfig, StoreError, StoreKey,
    cas::{Cas, digest_for},
};
use serde_json::json;

fn key() -> StoreKey {
    StoreKey::from_bytes([71; 32])
}
fn contract(id: &str) -> TaskContractV1 {
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = id.into();
    task.goal = "store-secret-fixture-79dbf3".into();
    task
}
fn create(store: &mut LocalStore, id: &str) {
    store.journal_mut().create_task(&contract(id)).unwrap();
}
fn request(task: &str, artifact: &str) -> ArtifactRequest {
    ArtifactRequest {
        artifact_id: artifact.into(),
        task_id: task.into(),
        content_type: "text/plain".into(),
        logical_type: "test.fixture".into(),
        schema_version: "sample/v1".into(),
        retain_until_ms: 0,
        legal_hold: false,
    }
}
fn transition(store: &mut LocalStore, id: &str, state: TaskState) {
    let version = store.journal().task(id).unwrap().record.version;
    store.transition_task(id, version, state, None).unwrap();
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn cas_path(root: &Path, digest: &str) -> std::path::PathBuf {
    root.join("cas/blobs")
        .join(format!("{}.blob", &digest[7..]))
}

#[test]
fn encrypted_artifacts_have_separate_ownership_even_when_content_is_deduplicated() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalStore::open(&dir.path().join("store"), key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    create(&mut store, "task:b");
    let first = store
        .put_artifact(
            &request("task:a", "artifact:a"),
            b"store-secret-fixture-79dbf3",
        )
        .unwrap();
    let second = store
        .put_artifact(
            &request("task:b", "artifact:b"),
            b"store-secret-fixture-79dbf3",
        )
        .unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(
        fs::read_dir(store.root().join("cas/blobs"))
            .unwrap()
            .count(),
        1
    );
    assert!(matches!(
        store.get_artifact("task:a", "artifact:b"),
        Err(StoreError::NotFound(_))
    ));
    assert!(
        store
            .put_artifact(&request("missing", "artifact:c"), b"x")
            .is_err()
    );
    assert!(
        store
            .put_artifact(&request("task:b", "artifact:a"), b"x")
            .is_err()
    );
    assert_eq!(
        store.get_artifact("task:a", "artifact:a").unwrap(),
        b"store-secret-fixture-79dbf3"
    );
    for path in [
        store.root().join("store.sqlite3"),
        store.root().join("store.sqlite3-wal"),
        cas_path(store.root(), &first.digest),
    ] {
        if let Ok(bytes) = fs::read(path) {
            assert!(
                !bytes
                    .windows(27)
                    .any(|part| part == b"store-secret-fixture-79dbf3")
            );
        }
    }
    store.integrity_check().unwrap();
}

#[test]
fn artifact_metadata_is_authenticated_against_index_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    store
        .put_artifact(&request("task:a", "artifact:a"), b"payload")
        .unwrap();
    let conn = rusqlite::Connection::open(root.join("store.sqlite3")).unwrap();
    conn.execute(
        "UPDATE artifacts SET retain_until_ms=123 WHERE artifact_id='artifact:a'",
        [],
    )
    .unwrap();
    assert!(matches!(
        store.get_artifact("task:a", "artifact:a"),
        Err(StoreError::Integrity(_))
    ));
    assert!(store.integrity_check().is_err());
}

#[test]
fn session_lease_prevents_live_takeover_but_shared_connections_can_write() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    assert!(matches!(
        LocalStore::open(&root, key(), StoreConfig::default()),
        Err(StoreError::Busy)
    ));
    let mut second = store.connect().unwrap();
    drop(store);
    second
        .journal_mut()
        .create_task(&contract("task:b"))
        .unwrap();
    assert!(matches!(
        LocalStore::open(&root, key(), StoreConfig::default()),
        Err(StoreError::Busy)
    ));
    drop(second);
    LocalStore::open(&root, key(), StoreConfig::default())
        .unwrap()
        .integrity_check()
        .unwrap();
}

#[test]
fn encrypted_physical_quota_includes_orphans_and_dedup_does_not_double_charge() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let config = StoreConfig {
        max_blob_bytes: 64,
        max_cas_bytes: 128,
        ..StoreConfig::default()
    };
    let mut store = LocalStore::open(&root, key(), config).unwrap();
    create(&mut store, "task:a");
    let raw = Cas::open(&root.join("cas"), key(), 64).unwrap();
    raw.put(&[9; 64]).unwrap();
    assert!(matches!(
        store.put_artifact(&request("task:a", "artifact:a"), b"abcd"),
        Err(StoreError::Quota(_))
    ));
    assert!(store.artifact_metadata("task:a", "artifact:a").is_err());
    assert_eq!(
        store
            .collect_garbage(now() + 1000, 0)
            .unwrap()
            .blobs_removed,
        1
    );
    let first = store
        .put_artifact(&request("task:a", "artifact:a"), &[3; 64])
        .unwrap();
    let second = store
        .put_artifact(&request("task:a", "artifact:b"), &[3; 64])
        .unwrap();
    assert_eq!(first.digest, second.digest);
    assert!(matches!(
        store.put_artifact(&request("task:a", "artifact:c"), b"x"),
        Err(StoreError::Quota(_))
    ));
}

#[test]
fn retention_holds_pins_checkpoints_and_active_tasks_survive_gc() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalStore::open(&dir.path().join("store"), key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    for id in [
        "active",
        "held",
        "pinned",
        "checkpoint",
        "future",
        "disposable",
    ] {
        store
            .put_artifact(&request("task:a", id), id.as_bytes())
            .unwrap();
    }
    assert!(store.release_artifact("task:a", "active").is_err());
    store
        .set_artifact_retention("task:a", "held", 0, true)
        .unwrap();
    store
        .set_artifact_retention("task:a", "future", i64::MAX as u64, false)
        .unwrap();
    store.pin_artifact("task:a", "pinned", "pin:1").unwrap();
    let version = store.journal().task("task:a").unwrap().record.version;
    store
        .append_checkpoint(
            "checkpoint:1",
            "task:a",
            version,
            "checkpoint",
            json!({"continuation":"fixture"}),
        )
        .unwrap();
    transition(&mut store, "task:a", TaskState::Cancelled);
    for id in ["held", "pinned", "checkpoint", "future", "disposable"] {
        store.release_artifact("task:a", id).unwrap();
    }
    let collected = store.collect_garbage(now() + 1000, 0).unwrap();
    assert_eq!(collected.artifacts_removed, 1);
    assert!(store.get_artifact("task:a", "disposable").is_err());
    for id in ["active", "held", "pinned", "checkpoint", "future"] {
        store.get_artifact("task:a", id).unwrap();
    }
    store.unpin_artifact("task:a", "pinned", "pin:1").unwrap();
    store
        .set_artifact_retention("task:a", "held", 0, false)
        .unwrap();
    assert_eq!(
        store
            .collect_garbage(now() + 1000, 0)
            .unwrap()
            .artifacts_removed,
        2
    );
    store.integrity_check().unwrap();
}

#[test]
fn completion_authenticates_cas_and_preserves_final_and_proof_references() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    let final_artifact = store
        .put_artifact(&request("task:a", "final"), b"final fixture")
        .unwrap();
    let raw = store
        .put_artifact(&request("task:a", "raw"), b"raw fixture")
        .unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
        TaskState::Verifying,
    ] {
        transition(&mut store, "task:a", state);
    }
    let version = store.journal().task("task:a").unwrap().record.version;
    store
        .set_final_artifact("task:a", version, "final")
        .unwrap();
    let version = store.journal().task("task:a").unwrap().record.version;
    let proof = CompletionEvidence {
        task_id: "task:a".into(),
        acceptance_digest: contract("task:a").acceptance_contract_digest,
        final_digest: final_artifact.digest.clone(),
        verified_digest: final_artifact.digest.clone(),
        verifier_run_id: "synthetic-host-contract-test".into(),
        protected_checks_passed: true,
        actual_tool_run: true,
        raw_artifact_refs: vec!["raw".into()],
    };
    let raw_path = cas_path(&root, &raw.digest);
    let original = fs::read(&raw_path).unwrap();
    fs::write(&raw_path, b"corrupt").unwrap();
    assert!(
        store
            .transition_task("task:a", version, TaskState::Completed, Some(&proof))
            .is_err()
    );
    assert_eq!(
        store.journal().task("task:a").unwrap().record.state,
        TaskState::Verifying
    );
    fs::write(&raw_path, original).unwrap();
    store
        .transition_task("task:a", version, TaskState::Completed, Some(&proof))
        .unwrap();
    assert!(store.release_artifact("task:a", "final").is_err());
    store.release_artifact("task:a", "raw").unwrap();
    assert_eq!(
        store
            .collect_garbage(now() + 1000, 0)
            .unwrap()
            .artifacts_removed,
        0
    );
    store.get_artifact("task:a", "raw").unwrap();
    drop(store);
    LocalStore::open(&root, key(), StoreConfig::default())
        .unwrap()
        .integrity_check()
        .unwrap();
}

#[test]
fn concurrent_connections_cannot_oversubscribe_cas_quota() {
    let dir = tempfile::tempdir().unwrap();
    let config = StoreConfig {
        max_blob_bytes: 64,
        max_cas_bytes: 128,
        ..StoreConfig::default()
    };
    let mut store = LocalStore::open(&dir.path().join("store"), key(), config).unwrap();
    create(&mut store, "task:a");
    let workers: Vec<_> = (0..8)
        .map(|index| {
            let mut connection = store.connect().unwrap();
            std::thread::spawn(move || {
                connection.put_artifact(
                    &request("task:a", &format!("artifact:{index}")),
                    &[index; 64],
                )
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Quota(_))))
            .count(),
        7
    );
    store.integrity_check().unwrap();
}

#[test]
fn backup_restore_is_consistent_and_never_replaces_existing_targets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    store
        .put_artifact(&request("task:a", "artifact:a"), b"backup fixture")
        .unwrap();
    let version = store.journal().task("task:a").unwrap().record.version;
    store
        .append_checkpoint(
            "checkpoint:1",
            "task:a",
            version,
            "artifact:a",
            json!({"step":1}),
        )
        .unwrap();
    let backup = dir.path().join("backup");
    let manifest = store.backup(&backup).unwrap();
    assert_eq!(manifest.blobs.len(), 1);
    transition(&mut store, "task:a", TaskState::Cancelled);
    let restored = LocalStore::restore_backup(
        &backup,
        &dir.path().join("restored"),
        key(),
        StoreConfig::default(),
    )
    .unwrap();
    assert_eq!(
        restored.journal().task("task:a").unwrap().record.state,
        TaskState::Created
    );
    assert_eq!(
        restored.get_artifact("task:a", "artifact:a").unwrap(),
        b"backup fixture"
    );
    assert_eq!(
        restored
            .journal()
            .checkpoint("checkpoint:1", "task:a")
            .unwrap()
            .data,
        json!({"step":1})
    );
    assert!(LocalStore::restore_backup(&backup, &root, key(), StoreConfig::default()).is_err());
    assert!(store.backup(&backup).is_err());
    assert!(store.backup(&root.join("nested-backup")).is_err());
    assert!(!root.join("nested-backup").exists());
    assert_eq!(
        store.journal().task("task:a").unwrap().record.state,
        TaskState::Cancelled
    );
}

#[test]
fn corrupt_wrong_key_incomplete_or_invalid_config_backups_fail_before_target_creation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalStore::open(&dir.path().join("store"), key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:a");
    let artifact = store
        .put_artifact(&request("task:a", "artifact:a"), b"backup fixture")
        .unwrap();
    let backup = dir.path().join("backup");
    store.backup(&backup).unwrap();
    let target = dir.path().join("restore");
    assert!(
        LocalStore::restore_backup(
            &backup,
            &target,
            StoreKey::from_bytes([8; 32]),
            StoreConfig::default()
        )
        .is_err()
    );
    assert!(!target.exists());
    let invalid = StoreConfig {
        journal: melissa_local_store::journal::JournalLimits {
            max_payload_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(LocalStore::restore_backup(&backup, &target, key(), invalid).is_err());
    assert!(!target.exists());
    let path = cas_path(&backup, &artifact.digest);
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"corrupt").unwrap();
    assert!(LocalStore::restore_backup(&backup, &target, key(), StoreConfig::default()).is_err());
    assert!(!target.exists());
    fs::write(&path, original).unwrap();
    let db = backup.join("store.sqlite3");
    let mut bytes = fs::read(&db).unwrap();
    bytes[100] ^= 1;
    fs::write(&db, bytes).unwrap();
    assert!(LocalStore::restore_backup(&backup, &target, key(), StoreConfig::default()).is_err());
    assert!(!target.exists());
    let incomplete = dir.path().join("incomplete");
    fs::create_dir(&incomplete).unwrap();
    assert!(
        LocalStore::restore_backup(&incomplete, &target, key(), StoreConfig::default()).is_err()
    );
    assert!(!target.exists());
}

#[test]
fn abrupt_crash_after_blob_publication_leaves_only_a_reclaimable_orphan() {
    let dir = tempfile::Builder::new()
        .prefix("melissa-code02-crash-")
        .tempdir()
        .unwrap();
    let root = dir.path().join("store");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_cas_crash_fixture", "--nocapture"])
        .env("MELISSA_CODE02_CRASH_ROOT", &root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(73),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    assert_eq!(
        store.journal().task("task:crash").unwrap().record.state,
        TaskState::Created
    );
    assert!(
        store
            .artifact_metadata("task:crash", "uncommitted")
            .is_err()
    );
    assert!(cas_path(&root, &digest_for(b"published before crash")).exists());
    assert_eq!(
        store
            .collect_garbage(now() + 1000, 0)
            .unwrap()
            .blobs_removed,
        1
    );
    store.integrity_check().unwrap();
}

#[test]
fn child_cas_crash_fixture() {
    let Some(root) = std::env::var_os("MELISSA_CODE02_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(
        root.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("melissa-code02-crash-")
    );
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    create(&mut store, "task:crash");
    let conn = rusqlite::Connection::open(root.join("store.sqlite3")).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    Cas::open(
        &root.join("cas"),
        key(),
        StoreConfig::default().max_blob_bytes,
    )
    .unwrap()
    .put(b"published before crash")
    .unwrap();
    // Abrupt exit deliberately skips both transaction and session destructors.
    std::process::exit(73);
}

#[cfg(windows)]
#[test]
fn unsafe_windows_store_roots_are_rejected_before_any_initialization() {
    let dir = tempfile::tempdir().unwrap();
    for invalid in [
        dir.path().join("NUL"),
        dir.path().join("bad:stream"),
        std::path::PathBuf::from(r"C:drive-relative"),
        std::path::PathBuf::from(r"\\server\share\store"),
    ] {
        assert!(matches!(
            LocalStore::open(&invalid, key(), StoreConfig::default()),
            Err(StoreError::Invalid(_))
        ));
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
