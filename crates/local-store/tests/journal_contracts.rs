use melissa_core_contracts::{
    CompletionEvidence, InvocationState, Module, ReconciliationEvidence, TaskState,
    wire::{TaskContractV1, TaskLimitsV1},
};
use melissa_local_store::{
    StoreError,
    crypto::StoreKey,
    journal::{AttemptState, InvocationRequest, Journal, JournalLimits},
};
use rusqlite::{Connection, params};
use serde_json::json;
use std::{path::Path, process::Command};

fn key() -> StoreKey {
    StoreKey::from_bytes([91; 32])
}
fn contract(id: &str) -> TaskContractV1 {
    TaskContractV1 {
        schema_version: "melissa.task-contract/v1".into(),
        task_id: id.into(),
        module: Module::Code,
        goal: "sensitive-goal-7d9c4e".into(),
        workspace_ref: "workspace:test".into(),
        input_snapshot_digest: "input-1".into(),
        acceptance_contract_digest: "acceptance-1".into(),
        acceptance_criteria: vec!["criterion-1".into()],
        selected_profile_ids: vec!["code.test".into()],
        allowed_resource_ids: vec!["workspace:test".into()],
        allowed_effects: vec!["read".into()],
        authorization_refs: vec![],
        limits: TaskLimitsV1 {
            max_wall_time_ms: 1000,
            max_cost_micro_usd: 100,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_parallel_jobs: 2,
            max_disk_bytes: 1000,
            max_output_bytes: 1000,
        },
        authority_source: "user_task_and_rust_policy".into(),
    }
}
fn open(path: &Path) -> Journal {
    Journal::open(path, key(), JournalLimits::default()).unwrap()
}
fn running(j: &mut Journal, id: &str) {
    j.create_task(&contract(id)).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = j.task(id).unwrap().record.version;
        j.transition_task(id, v, next, None).unwrap();
    }
}
fn request(id: &str, inv: &str, idem: Option<&str>) -> InvocationRequest {
    InvocationRequest {
        invocation_id: inv.into(),
        task_id: id.into(),
        tool_id: "test.tool".into(),
        arguments: json!({"sensitive_argument":"never-log-me-68e1"}),
        idempotency_key: idem.map(str::to_owned),
        generation: 1,
    }
}
fn prepared(j: &mut Journal, id: &str, inv: &str, attempt: &str) {
    let v = j.task(id).unwrap().record.version;
    j.propose_invocation(&request(id, inv, None), v).unwrap();
    let v = j.task(id).unwrap().record.version;
    j.authorize_invocation(inv, v, 0).unwrap();
    let v = j.task(id).unwrap().record.version;
    j.begin_attempt(inv, attempt, v, 1, 1).unwrap();
}
fn fake_artifact(path: &Path, id: &str, task: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO blob_objects VALUES('digest-1',1,49,0)",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO artifacts(artifact_id,task_id,digest,content_type,logical_type,schema_version,created_at_ms,retain_until_ms,legal_hold,payload) VALUES(?1,?2,'digest-1','text/plain','test','v1',0,0,0,x'00')",params![id,task]).unwrap();
}

#[test]
fn create_reopen_replay_and_encrypted_sensitive_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    running(&mut j, "task-a");
    prepared(&mut j, "task-a", "inv-a", "attempt-a");
    assert_eq!(j.replay_task("task-a").unwrap(), j.task("task-a").unwrap());
    j.integrity_check().unwrap();
    drop(j);
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(b"sensitive-goal-7d9c4e".len())
            .any(|w| w == b"sensitive-goal-7d9c4e")
    );
    assert!(
        !raw.windows(b"never-log-me-68e1".len())
            .any(|w| w == b"never-log-me-68e1")
    );
    let j = open(&path);
    assert_eq!(
        j.task("task-a").unwrap().contract.goal,
        "sensitive-goal-7d9c4e"
    );
    assert_eq!(
        j.attempt("attempt-a").unwrap().state,
        AttemptState::Prepared
    );
}
#[test]
fn stale_version_and_duplicate_identity_are_nonmutating() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("journal.db"));
    j.create_task(&contract("a")).unwrap();
    assert!(matches!(
        j.create_task(&contract("a")),
        Err(StoreError::Conflict(_))
    ));
    j.transition_task("a", 0, TaskState::Planned, None).unwrap();
    assert!(matches!(
        j.transition_task("a", 0, TaskState::Queued, None),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(j.events("a").unwrap().len(), 2);
    j.integrity_check().unwrap();
}
#[test]
fn task_update_and_event_insert_roll_back_as_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    j.create_task(&contract("a")).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON events WHEN NEW.sequence=1 BEGIN SELECT RAISE(ABORT,'injected journal fault'); END;").unwrap();
    assert!(j.transition_task("a", 0, TaskState::Planned, None).is_err());
    assert_eq!(j.task("a").unwrap().record.state, TaskState::Created);
    assert_eq!(j.events("a").unwrap().len(), 1);
    conn.execute_batch("DROP TRIGGER injected_failure").unwrap();
    j.integrity_check().unwrap();
}
#[test]
fn invocation_and_attempt_roll_back_on_event_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    running(&mut j, "a");
    let v = j.task("a").unwrap().record.version;
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'injected journal fault'); END;").unwrap();
    assert!(j.propose_invocation(&request("a", "i", None), v).is_err());
    assert!(matches!(j.invocation("i"), Err(StoreError::NotFound(_))));
    assert_eq!(j.task("a").unwrap().record.version, v);
    conn.execute_batch("DROP TRIGGER injected_failure").unwrap();
    j.integrity_check().unwrap();
}
#[test]
fn idempotency_is_per_task_null_keys_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("j.db"));
    running(&mut j, "a");
    running(&mut j, "b");
    let v = j.task("a").unwrap().record.version;
    let first = j
        .propose_invocation(&request("a", "i1", Some("key")), v)
        .unwrap();
    let v = j.task("a").unwrap().record.version;
    let again = j
        .propose_invocation(&request("a", "different-id", Some("key")), v)
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(v, j.task("a").unwrap().record.version);
    let mut changed = request("a", "i2", Some("key"));
    changed.arguments = json!({"different":true});
    assert!(matches!(
        j.propose_invocation(&changed, v),
        Err(StoreError::Conflict(_))
    ));
    for id in ["i3", "i4"] {
        let v = j.task("a").unwrap().record.version;
        j.propose_invocation(&request("a", id, None), v).unwrap();
    }
    let v = j.task("b").unwrap().record.version;
    j.propose_invocation(&request("b", "ib", Some("key")), v)
        .unwrap();
    j.integrity_check().unwrap();
}
#[test]
fn attempt_persists_before_dispatch_and_stale_generation_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("j.db"));
    running(&mut j, "a");
    prepared(&mut j, "a", "i", "attempt");
    let mut guard = j.attempt_guard("attempt").unwrap();
    guard.generation += 1;
    assert!(matches!(
        j.dispatch_attempt(&guard),
        Err(StoreError::Conflict(_))
    ));
    let guard = j.attempt_guard("attempt").unwrap();
    j.dispatch_attempt(&guard).unwrap();
    assert!(matches!(
        j.start_attempt(&guard),
        Err(StoreError::Conflict(_))
    ));
    let guard = j.attempt_guard("attempt").unwrap();
    j.start_attempt(&guard).unwrap();
    assert_eq!(j.invocation("i").unwrap().state, InvocationState::Running);
    j.integrity_check().unwrap();
}
#[test]
fn only_one_active_attempt_and_wrong_task_binding_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("j.db"));
    running(&mut j, "a");
    running(&mut j, "b");
    prepared(&mut j, "a", "i", "attempt");
    let i = j.invocation("i").unwrap();
    let tv = j.task("a").unwrap().record.version;
    assert!(j.begin_attempt("i", "duplicate", tv, i.version, 1).is_err());
    let mut guard = j.attempt_guard("attempt").unwrap();
    guard.task_id = "b".into();
    guard.task_version = j.task("b").unwrap().record.version;
    assert!(j.dispatch_attempt(&guard).is_err());
    assert_eq!(j.attempt("attempt").unwrap().state, AttemptState::Prepared);
}
#[test]
fn open_does_not_recover_another_connections_running_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    prepared(&mut j, "a", "i", "attempt");
    j.dispatch_attempt(&j.attempt_guard("attempt").unwrap())
        .unwrap();
    let other = open(&path);
    assert_eq!(
        other.attempt("attempt").unwrap().state,
        AttemptState::Dispatched
    );
    assert_eq!(other.task("a").unwrap().record.state, TaskState::Running);
}
#[test]
fn recovery_retains_all_unknown_invocations_and_requires_scoped_reconciliation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    running(&mut j, "b");
    for (i, a) in [("i1", "a1"), ("i2", "a2")] {
        prepared(&mut j, "a", i, a);
        j.dispatch_attempt(&j.attempt_guard(a).unwrap()).unwrap();
    }
    fake_artifact(&path, "proof-a", "a");
    fake_artifact(&path, "proof-b", "b");
    assert_eq!(j.recover_interrupted().unwrap(), 2);
    assert_eq!(j.recover_interrupted().unwrap(), 0);
    let task = j.task("a").unwrap();
    assert_eq!(task.record.state, TaskState::OutcomeUnknown);
    let task = j
        .transition_task(
            "a",
            task.record.version,
            TaskState::NeedsReconciliation,
            None,
        )
        .unwrap();
    let marked = task.record.unknown_invocation_id.clone().unwrap();
    let mut proof = ReconciliationEvidence {
        task_id: "a".into(),
        invocation_id: marked.clone(),
        resolution_artifact_ref: "proof-b".into(),
        external_effect_resolved: true,
    };
    assert!(
        j.reconcile_invocation(
            task.record.version,
            j.invocation(&marked).unwrap().version,
            &proof
        )
        .is_err()
    );
    proof.resolution_artifact_ref = "proof-a".into();
    let task = j
        .reconcile_invocation(
            task.record.version,
            j.invocation(&marked).unwrap().version,
            &proof,
        )
        .unwrap();
    assert_eq!(task.record.state, TaskState::NeedsReconciliation);
    assert!(task.record.unknown_invocation_id.is_some());
    assert!(
        j.transition_task("a", task.record.version, TaskState::Cancelled, None)
            .is_err()
    );
    let next = task.record.unknown_invocation_id.clone().unwrap();
    proof.invocation_id = next.clone();
    let task = j
        .reconcile_invocation(
            task.record.version,
            j.invocation(&next).unwrap().version,
            &proof,
        )
        .unwrap();
    assert_eq!(task.record.state, TaskState::Verifying);
    assert!(task.record.unknown_invocation_id.is_none());
    j.integrity_check().unwrap();
}
#[test]
fn terminal_tasks_cannot_hide_inflight_invocations() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("j.db"));
    running(&mut j, "a");
    prepared(&mut j, "a", "i", "attempt");
    let v = j.task("a").unwrap().record.version;
    for state in [TaskState::Cancelled, TaskState::Failed, TaskState::TimedOut] {
        assert!(j.transition_task("a", v, state, None).is_err());
    }
    j.finish_attempt(
        &j.attempt_guard("attempt").unwrap(),
        AttemptState::Cancelled,
        None,
    )
    .unwrap();
    let v = j.task("a").unwrap().record.version;
    j.transition_task("a", v, TaskState::Cancelled, None)
        .unwrap();
}
#[test]
fn successful_attempt_requires_owned_observation_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    running(&mut j, "b");
    prepared(&mut j, "a", "i", "attempt");
    j.dispatch_attempt(&j.attempt_guard("attempt").unwrap())
        .unwrap();
    fake_artifact(&path, "foreign", "b");
    fake_artifact(&path, "owned", "a");
    let g = j.attempt_guard("attempt").unwrap();
    assert!(j.finish_attempt(&g, AttemptState::Succeeded, None).is_err());
    assert!(
        j.finish_attempt(&g, AttemptState::Succeeded, Some("foreign"))
            .is_err()
    );
    j.finish_attempt(&g, AttemptState::Succeeded, Some("owned"))
        .unwrap();
    assert_eq!(
        j.invocation("i").unwrap().result_artifact_id.as_deref(),
        Some("owned")
    );
    j.integrity_check().unwrap();
}
#[test]
fn checkpoint_is_owned_version_bound_and_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    running(&mut j, "b");
    fake_artifact(&path, "artifact", "a");
    let v = j.task("a").unwrap().record.version;
    assert!(
        j.append_checkpoint("c", "a", v - 1, "artifact", json!({}))
            .is_err()
    );
    assert!(
        j.append_checkpoint("c", "b", v, "artifact", json!({}))
            .is_err()
    );
    let cp = j
        .append_checkpoint(
            "c",
            "a",
            v,
            "artifact",
            json!({"continuation":"sensitive-checkpoint"}),
        )
        .unwrap();
    assert!(j.checkpoint("c", "b").is_err());
    drop(j);
    let j = open(&path);
    assert_eq!(cp, j.checkpoint("c", "a").unwrap());
    let conn = Connection::open(path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM artifact_refs WHERE owner_kind='checkpoint' AND owner_id='c'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
#[test]
fn tampering_key_and_payload_and_schema_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    j.create_task(&contract("a")).unwrap();
    drop(j);
    assert!(matches!(
        Journal::open(
            &path,
            StoreKey::from_bytes([92; 32]),
            JournalLimits::default()
        ),
        Err(StoreError::Crypto)
    ));
    let conn = Connection::open(&path).unwrap();
    conn.execute("UPDATE tasks SET state='completed' WHERE task_id='a'", [])
        .unwrap();
    assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
    conn.execute(
        "UPDATE tasks SET state='created', record=x'00' WHERE task_id='a'",
        [],
    )
    .unwrap();
    assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
    let path2 = dir.path().join("foreign.db");
    let j = open(&path2);
    drop(j);
    let conn = Connection::open(&path2).unwrap();
    conn.execute_batch("DROP TRIGGER events_no_delete").unwrap();
    assert!(matches!(
        Journal::open(&path2, key(), JournalLimits::default()),
        Err(StoreError::Integrity(_))
    ));
}
#[test]
fn foreign_partial_and_future_databases_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for (name, sql) in [
        ("foreign.db", "CREATE TABLE other(x);"),
        (
            "partial.db",
            "PRAGMA user_version=1; CREATE TABLE tasks(task_id TEXT);",
        ),
        ("future.db", "PRAGMA user_version=99;"),
    ] {
        let path = dir.path().join(name);
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
    }
}
#[test]
fn payload_event_and_integer_quotas_leave_original_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let limits = JournalLimits {
        max_events_per_task: 2,
        ..JournalLimits::default()
    };
    let mut j = Journal::open(&path, key(), limits).unwrap();
    j.create_task(&contract("a")).unwrap();
    j.transition_task("a", 0, TaskState::Planned, None).unwrap();
    assert!(matches!(
        j.transition_task("a", 1, TaskState::Queued, None),
        Err(StoreError::Quota(_))
    ));
    assert_eq!(j.task("a").unwrap().record.version, 1);
    let mut c = contract("oversize");
    c.goal = "z".repeat(limits.max_payload_bytes + 1);
    assert!(matches!(j.create_task(&c), Err(StoreError::Quota(_))));
    assert!(j.task("oversize").is_err());
    let mut c = contract("overflow");
    c.limits.max_wall_time_ms = u64::MAX;
    assert!(j.create_task(&c).is_err());
    assert!(
        j.transition_task("a", u64::MAX, TaskState::Queued, None)
            .is_err()
    );
    j.integrity_check().unwrap();
}
#[test]
fn concurrent_connections_only_one_optimistic_writer_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut first = open(&path);
    first.create_task(&contract("a")).unwrap();
    let mut second = open(&path);
    first
        .transition_task("a", 0, TaskState::Planned, None)
        .unwrap();
    assert!(matches!(
        second.transition_task("a", 0, TaskState::Cancelled, None),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        second.replay_task("a").unwrap().record.state,
        TaskState::Planned
    );
}
#[test]
fn online_backup_is_consistent_and_non_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let backup = dir.path().join("backup.db");
    let mut j = open(&path);
    running(&mut j, "a");
    prepared(&mut j, "a", "i", "attempt");
    j.backup_to(&backup).unwrap();
    assert!(j.backup_to(&backup).is_err());
    let restored = open(&backup);
    assert_eq!(j.task("a").unwrap(), restored.replay_task("a").unwrap());
}
#[test]
fn process_exit_probe() {
    if let Some(path) = std::env::var_os("MELISSA_JOURNAL_CRASH_TEST_PATH") {
        let mut j = open(Path::new(&path));
        if std::env::var_os("MELISSA_UNCOMMITTED_CRASH_TEST").is_some() {
            j.create_task(&contract("crashed")).unwrap();
            let conn = Connection::open(Path::new(&path)).unwrap();
            conn.execute_batch("BEGIN IMMEDIATE; UPDATE tasks SET state='failed',version=999 WHERE task_id='crashed'").unwrap();
            std::process::exit(74);
        }
        running(&mut j, "crashed");
        prepared(&mut j, "crashed", "crash-inv", "crash-attempt");
        j.dispatch_attempt(&j.attempt_guard("crash-attempt").unwrap())
            .unwrap();
        std::process::exit(73);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.db");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_exit_probe", "--nocapture"])
        .env("MELISSA_JOURNAL_CRASH_TEST_PATH", &path)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(73),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut j = open(&path);
    assert_eq!(
        j.attempt("crash-attempt").unwrap().state,
        AttemptState::Dispatched
    );
    assert_eq!(j.recover_interrupted().unwrap(), 1);
    assert_eq!(
        j.task("crashed").unwrap().record.state,
        TaskState::OutcomeUnknown
    );
    j.integrity_check().unwrap();
}

#[test]
fn completion_and_reconciliation_proof_refs_are_permanent_and_auditable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    fake_artifact(&path, "final", "a");
    fake_artifact(&path, "raw", "a");
    let v = j.task("a").unwrap().record.version;
    let task = j.set_final_artifact("a", v, "final").unwrap();
    let proof = CompletionEvidence {
        task_id: "a".into(),
        acceptance_digest: "acceptance-1".into(),
        final_digest: "digest-1".into(),
        verified_digest: "digest-1".into(),
        verifier_run_id: "trusted-host-001".into(),
        protected_checks_passed: true,
        actual_tool_run: true,
        raw_artifact_refs: vec!["raw".into()],
    };
    assert!(
        j.transition_task("a", task.record.version, TaskState::Verifying, Some(&proof))
            .is_err()
    );
    let task = j
        .transition_task("a", task.record.version, TaskState::Verifying, None)
        .unwrap();
    j.transition_task("a", task.record.version, TaskState::Completed, Some(&proof))
        .unwrap();
    assert_eq!(
        j.events("a").unwrap().last().unwrap().completion_evidence,
        Some(proof)
    );
    j.integrity_check().unwrap();
    let conn = Connection::open(path).unwrap();
    conn.execute(
        "DELETE FROM artifact_refs WHERE owner_kind='completion'",
        [],
    )
    .unwrap();
    assert!(matches!(j.integrity_check(), Err(StoreError::Integrity(_))));
}
#[test]
fn disk_full_rolls_back_domain_and_event_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let limits = JournalLimits {
        max_database_bytes: 256 * 1024,
        max_payload_bytes: 64 * 1024,
        ..JournalLimits::default()
    };
    let mut j = Journal::open(&path, key(), limits).unwrap();
    let mut hit_full = false;
    for number in 0..100 {
        let id = format!("task-{number}");
        let mut c = contract(&id);
        c.goal = "x".repeat(12 * 1024);
        match j.create_task(&c) {
            Ok(_) => {}
            Err(StoreError::Sql(rusqlite::Error::SqliteFailure(error, _)))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                assert!(matches!(j.task(&id), Err(StoreError::NotFound(_))));
                assert!(j.events(&id).unwrap().is_empty());
                hit_full = true;
                break;
            }
            Err(error) => panic!("unexpected quota error: {error}"),
        }
    }
    assert!(hit_full, "test must actually reach SQLite max_page_count");
    j.integrity_check().unwrap();
}
#[test]
fn replay_keeps_one_snapshot_while_another_connection_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let reader = open(&path);
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut j = open(&writer_path);
        for index in 0..40 {
            let id = format!("concurrent-{index}");
            j.create_task(&contract(&id)).unwrap();
            j.transition_task(&id, 0, TaskState::Planned, None).unwrap();
        }
    });
    let mut reads = 0;
    while !writer.is_finished() {
        reader.integrity_check().unwrap();
        reads += 1;
    }
    writer.join().unwrap();
    reader.integrity_check().unwrap();
    assert!(reads > 0);
}
#[test]
fn abrupt_exit_inside_uncommitted_transaction_keeps_previous_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.db");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_exit_probe", "--nocapture"])
        .env("MELISSA_JOURNAL_CRASH_TEST_PATH", &path)
        .env("MELISSA_UNCOMMITTED_CRASH_TEST", "1")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(74),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let j = open(&path);
    assert_eq!(j.task("crashed").unwrap().record.state, TaskState::Created);
    assert_eq!(j.task("crashed").unwrap().record.version, 0);
    assert_eq!(j.events("crashed").unwrap().len(), 1);
}

#[test]
fn other_dispatched_observations_can_finish_while_reconciliation_is_pending() {
    for finish_before_reconciliation in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.db");
        let mut j = open(&path);
        running(&mut j, "a");
        for (inv, attempt) in [("i1", "a1"), ("i2", "a2")] {
            prepared(&mut j, "a", inv, attempt);
            j.dispatch_attempt(&j.attempt_guard(attempt).unwrap())
                .unwrap();
        }
        fake_artifact(&path, "observation", "a");
        fake_artifact(&path, "resolution", "a");
        j.finish_attempt(
            &j.attempt_guard("a1").unwrap(),
            AttemptState::OutcomeUnknown,
            None,
        )
        .unwrap();
        assert!(j.start_attempt(&j.attempt_guard("a2").unwrap()).is_err());
        if finish_before_reconciliation {
            j.finish_attempt(
                &j.attempt_guard("a2").unwrap(),
                AttemptState::Succeeded,
                Some("observation"),
            )
            .unwrap();
        }
        let task = j.task("a").unwrap();
        let task = j
            .transition_task(
                "a",
                task.record.version,
                TaskState::NeedsReconciliation,
                None,
            )
            .unwrap();
        let proof = ReconciliationEvidence {
            task_id: "a".into(),
            invocation_id: "i1".into(),
            resolution_artifact_ref: "resolution".into(),
            external_effect_resolved: true,
        };
        j.reconcile_invocation(
            task.record.version,
            j.invocation("i1").unwrap().version,
            &proof,
        )
        .unwrap();
        if !finish_before_reconciliation {
            j.finish_attempt(
                &j.attempt_guard("a2").unwrap(),
                AttemptState::Succeeded,
                Some("observation"),
            )
            .unwrap();
        }
        assert_eq!(j.task("a").unwrap().record.state, TaskState::Verifying);
        assert_eq!(
            j.invocation("i2").unwrap().state,
            InvocationState::Succeeded
        );
        j.integrity_check().unwrap();
    }
}

#[test]
fn two_live_unknown_outcomes_preserve_first_marker_and_both_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut j = open(&path);
    running(&mut j, "a");
    for (inv, attempt) in [("i1", "a1"), ("i2", "a2")] {
        prepared(&mut j, "a", inv, attempt);
        j.dispatch_attempt(&j.attempt_guard(attempt).unwrap())
            .unwrap();
    }
    j.finish_attempt(
        &j.attempt_guard("a1").unwrap(),
        AttemptState::OutcomeUnknown,
        None,
    )
    .unwrap();
    j.finish_attempt(
        &j.attempt_guard("a2").unwrap(),
        AttemptState::OutcomeUnknown,
        None,
    )
    .unwrap();
    assert_eq!(
        j.task("a").unwrap().record.unknown_invocation_id.as_deref(),
        Some("i1")
    );
    assert_eq!(
        j.invocation("i2").unwrap().state,
        InvocationState::OutcomeUnknown
    );
    j.integrity_check().unwrap();
}
