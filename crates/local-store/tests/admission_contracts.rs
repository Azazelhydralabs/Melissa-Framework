use melissa_core_contracts::{InvocationState, TaskState, wire::TaskContractV1};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreConfig, StoreKey,
    journal::{AdmissionRequest, AttemptState, InvocationRequest, Journal, JournalLimits},
};
use rusqlite::{Connection, params};
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, Barrier},
    thread,
};

fn key() -> StoreKey {
    StoreKey::from_bytes([37; 32])
}
fn open(path: &Path) -> Journal {
    Journal::open(path, key(), JournalLimits::default()).unwrap()
}
fn setup(journal: &mut Journal, id: &str) -> AdmissionRequest {
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = id.into();
    task.limits.max_parallel_jobs = 1;
    journal.create_task(&task).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = journal.task(id).unwrap().record.version;
        journal.transition_task(id, version, next, None).unwrap();
    }
    let inv = journal
        .propose_invocation(
            &InvocationRequest {
                invocation_id: format!("inv:{id}"),
                task_id: id.into(),
                tool_id: "process.exec".into(),
                arguments: json!({"argv":["sensitive-marker-c4a2"],"cwd":"."}),
                idempotency_key: None,
                generation: 7,
            },
            journal.task(id).unwrap().record.version,
        )
        .unwrap();
    AdmissionRequest {
        permit_id: format!("permit:{id}"),
        nonce: format!("nonce:{id}"),
        permit_digest: "verified-permit-digest".into(),
        task_id: id.into(),
        principal_id: "host-principal".into(),
        profile_id: task.selected_profile_ids[0].clone(),
        tool_id: "process.exec".into(),
        resource_id: task.allowed_resource_ids[0].clone(),
        arguments_digest: inv.arguments_digest,
        invocation_id: inv.invocation_id,
        attempt_id: format!("attempt:{id}"),
        generation: 7,
        expected_task_version: journal.task(id).unwrap().record.version,
        expected_invocation_version: inv.version,
        not_before_unix_ms: 100,
        expires_at_unix_ms: 1000,
        consumed_at_unix_ms: 200,
    }
}

#[test]
fn atomic_dispatch_consumes_and_reopens_with_one_coherent_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    let req = setup(&mut j, "a");
    let prior = j.events("a").unwrap().len();
    let attempt = j.admit_dispatch(&req).unwrap();
    assert_eq!(attempt.state, AttemptState::Dispatched);
    assert_eq!(
        j.invocation(&req.invocation_id).unwrap().state,
        InvocationState::Dispatched
    );
    assert_eq!(
        j.task("a").unwrap().record.version,
        req.expected_task_version + 1
    );
    assert_eq!(j.events("a").unwrap().len(), prior + 1);
    assert_eq!(
        j.events("a").unwrap().last().unwrap().kind,
        "execution_admitted"
    );
    assert_eq!(j.permit_admission(&req.permit_id).unwrap(), req);
    j.integrity_check().unwrap();
    drop(j);
    let mut j = open(&path);
    assert!(j.admit_dispatch(&req).is_err());
    assert_eq!(j.recover_interrupted().unwrap(), 1);
    assert_eq!(
        j.attempt(&req.attempt_id).unwrap().state,
        AttemptState::OutcomeUnknown
    );
    assert_eq!(j.task("a").unwrap().record.state, TaskState::OutcomeUnknown);
    j.integrity_check().unwrap();
}

#[test]
fn stale_expired_rebound_and_duplicate_admissions_are_nonmutating() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("journal.db"));
    let req = setup(&mut j, "a");
    let mut mutations = Vec::new();
    let mut x = req.clone();
    x.expected_task_version += 1;
    mutations.push(x);
    let mut x = req.clone();
    x.expected_invocation_version += 1;
    mutations.push(x);
    let mut x = req.clone();
    x.generation += 1;
    mutations.push(x);
    let mut x = req.clone();
    x.arguments_digest = "different".into();
    mutations.push(x);
    let mut x = req.clone();
    x.profile_id = "unselected-profile".into();
    mutations.push(x);
    let mut x = req.clone();
    x.resource_id = "outside:resource".into();
    mutations.push(x);
    let mut x = req.clone();
    x.tool_id = "other.tool".into();
    mutations.push(x);
    let mut x = req.clone();
    x.consumed_at_unix_ms = 99;
    mutations.push(x);
    let mut x = req.clone();
    x.consumed_at_unix_ms = 1000;
    mutations.push(x);
    for changed in mutations {
        assert!(j.admit_dispatch(&changed).is_err());
        assert_eq!(
            j.task("a").unwrap().record.version,
            req.expected_task_version
        );
        assert!(j.attempt(&req.attempt_id).is_err());
        assert!(j.permit_admission(&req.permit_id).is_err());
    }
    j.admit_dispatch(&req).unwrap();
    let version = j.task("a").unwrap().record.version;
    assert!(j.admit_dispatch(&req).is_err());
    assert_eq!(j.task("a").unwrap().record.version, version);
    j.integrity_check().unwrap();
}

#[test]
fn same_nonce_cannot_move_to_another_permit_task_or_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("journal.db"));
    let a = setup(&mut j, "a");
    let mut b = setup(&mut j, "b");
    j.admit_dispatch(&a).unwrap();
    b.nonce = a.nonce;
    assert!(j.admit_dispatch(&b).is_err());
    assert_eq!(
        j.invocation(&b.invocation_id).unwrap().state,
        InvocationState::Proposed
    );
    b.nonce = "fresh-nonce".into();
    j.admit_dispatch(&b).unwrap();
    j.integrity_check().unwrap();
}

#[test]
fn revocation_before_issue_is_durable_and_immutable_and_clock_never_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    let mut req = setup(&mut j, "a");
    j.revoke_permit(&req.permit_id, "sensitive-revocation-reason", 201)
        .unwrap();
    assert!(j.is_permit_revoked(&req.permit_id).unwrap());
    req.consumed_at_unix_ms = 202;
    assert!(j.admit_dispatch(&req).is_err());
    assert!(j.revoke_permit("another", "backwards", 200).is_err());
    j.revoke_permit(&req.permit_id, "sensitive-revocation-reason", 201)
        .unwrap();
    assert!(j.revoke_permit(&req.permit_id, "change", 202).is_err());
    drop(j);
    let mut j = open(&path);
    assert!(j.is_permit_revoked(&req.permit_id).unwrap());
    let mut b = setup(&mut j, "b");
    b.consumed_at_unix_ms = 200;
    assert!(j.admit_dispatch(&b).is_err());
    b.consumed_at_unix_ms = 201;
    j.admit_dispatch(&b).unwrap();
    j.integrity_check().unwrap();
}

#[test]
fn concurrent_connections_consume_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    let req = setup(&mut j, "a");
    drop(j);
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let path = path.clone();
            let req = req.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut j = open(&path);
                barrier.wait();
                j.admit_dispatch(&req).is_ok()
            })
        })
        .collect::<Vec<_>>();
    let successes = handles
        .into_iter()
        .map(|h| usize::from(h.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    open(&path).integrity_check().unwrap();
}

#[test]
fn late_event_quota_failure_rolls_back_nonce_attempt_and_clock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let mut j = open(&path);
    let req = setup(&mut j, "a");
    drop(j);
    let limits = JournalLimits {
        max_events_per_task: req.expected_task_version + 1,
        ..JournalLimits::default()
    };
    let mut j = Journal::open(&path, key(), limits).unwrap();
    assert!(j.admit_dispatch(&req).is_err());
    assert!(j.permit_admission(&req.permit_id).is_err());
    assert!(j.attempt(&req.attempt_id).is_err());
    assert_eq!(
        j.task("a").unwrap().record.version,
        req.expected_task_version
    );
    // An earlier timestamp is accepted after failed admission: no clock was consumed.
    j.revoke_permit("unrelated", "after rollback", 150).unwrap();
    j.integrity_check().unwrap();
}

#[test]
fn real_v1_upgrade_authenticates_before_migration_and_rejects_future_or_corrupt_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    let migration = include_str!("../migrations/0001_initial.sql");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(migration).unwrap();
    conn.execute(
        "INSERT INTO schema_migrations VALUES(1,?1)",
        [blake3::hash(migration.as_bytes()).to_hex().to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO store_metadata VALUES('key_check',?1)",
        [key()
            .seal(
                b"melissa-local-store-authenticated-key-v1",
                b"melissa.local-store/key-check/v1",
            )
            .unwrap()],
    )
    .unwrap();
    drop(conn);
    assert!(
        Journal::open(
            &path,
            StoreKey::from_bytes([0; 32]),
            JournalLimits::default()
        )
        .is_err()
    );
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(conn);
    let mut j = open(&path);
    let req = setup(&mut j, "upgraded");
    j.admit_dispatch(&req).unwrap();
    j.integrity_check().unwrap();
    drop(j);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    conn.execute_batch("PRAGMA user_version=999").unwrap();
    drop(conn);
    assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA user_version=2; DROP TRIGGER permit_admissions_no_update")
        .unwrap();
    drop(conn);
    assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
}

#[test]
fn metadata_tampering_rejected_and_backup_keeps_consumption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let backup = dir.path().join("backup.db");
    let mut j = open(&path);
    let req = setup(&mut j, "a");
    j.admit_dispatch(&req).unwrap();
    j.backup_to(&backup).unwrap();
    let mut copied = open(&backup);
    assert!(copied.admit_dispatch(&req).is_err());
    assert_eq!(copied.permit_admission(&req.permit_id).unwrap(), req);
    drop(copied);
    let conn = Connection::open(&path).unwrap();
    assert!(
        conn.execute(
            "UPDATE permit_admissions SET nonce='other' WHERE permit_id=?1",
            [&req.permit_id]
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "DELETE FROM permit_admissions WHERE permit_id=?1",
            [&req.permit_id]
        )
        .is_err()
    );
    conn.execute("UPDATE execution_clock SET last_seen_ms=?1", params![999])
        .unwrap();
    drop(conn);
    assert!(j.integrity_check().is_err());
    drop(j);
    assert!(Journal::open(&path, key(), JournalLimits::default()).is_err());
}

#[test]
fn task_parallel_allowance_is_checked_in_the_same_admission_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("journal.db"));
    let first = setup(&mut j, "a");
    j.admit_dispatch(&first).unwrap();
    let source = j.invocation(&first.invocation_id).unwrap();
    let second = j
        .propose_invocation(
            &InvocationRequest {
                invocation_id: "inv:second".into(),
                task_id: "a".into(),
                tool_id: source.tool_id,
                arguments: source.arguments,
                idempotency_key: None,
                generation: 7,
            },
            j.task("a").unwrap().record.version,
        )
        .unwrap();
    let mut req = first.clone();
    req.permit_id = "permit:second".into();
    req.nonce = "nonce:second".into();
    req.invocation_id = second.invocation_id;
    req.attempt_id = "attempt:second".into();
    req.expected_task_version = j.task("a").unwrap().record.version;
    req.expected_invocation_version = second.version;
    assert!(j.admit_dispatch(&req).is_err());
    assert!(j.permit_admission(&req.permit_id).is_err());
    assert_eq!(
        j.task("a").unwrap().record.version,
        req.expected_task_version
    );
    assert_eq!(
        j.invocation(&req.invocation_id).unwrap().state,
        InvocationState::Proposed
    );
    j.integrity_check().unwrap();
}

#[test]
fn schema_upgrade_capacity_failure_rolls_back_the_entire_second_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1-full.db");
    let migration = include_str!("../migrations/0001_initial.sql");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(migration).unwrap();
    conn.execute(
        "INSERT INTO schema_migrations VALUES(1,?1)",
        [blake3::hash(migration.as_bytes()).to_hex().to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO store_metadata VALUES('key_check',?1)",
        [key()
            .seal(
                b"melissa-local-store-authenticated-key-v1",
                b"melissa.local-store/key-check/v1",
            )
            .unwrap()],
    )
    .unwrap();
    let pages: u64 = conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let size: u64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap();
    drop(conn);
    let limits = JournalLimits {
        max_database_bytes: pages * size,
        ..JournalLimits::default()
    };
    assert!(Journal::open(&path, key(), limits).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM schema_migrations", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='permit_admissions'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    drop(conn);
    open(&path).integrity_check().unwrap();
}

#[test]
fn preparation_rejection_is_scoped_atomic_and_cannot_cancel_dispatched_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("journal.db"));
    let rejected = setup(&mut j, "rejected");
    assert!(
        j.reject_proposed_invocation(
            &rejected.invocation_id,
            rejected.expected_task_version + 1,
            rejected.expected_invocation_version
        )
        .is_err()
    );
    assert!(
        j.reject_proposed_invocation(
            &rejected.invocation_id,
            rejected.expected_task_version,
            rejected.expected_invocation_version + 1
        )
        .is_err()
    );
    assert_eq!(
        j.task("rejected").unwrap().record.version,
        rejected.expected_task_version
    );
    let cancelled = j
        .reject_proposed_invocation(
            &rejected.invocation_id,
            rejected.expected_task_version,
            rejected.expected_invocation_version,
        )
        .unwrap();
    assert_eq!(cancelled.state, InvocationState::Cancelled);
    assert_eq!(
        j.task("rejected").unwrap().record.version,
        rejected.expected_task_version + 1
    );
    assert!(j.permit_admission(&rejected.permit_id).is_err());
    assert!(j.attempt(&rejected.attempt_id).is_err());
    assert!(j.admit_dispatch(&rejected).is_err());
    let started = setup(&mut j, "started");
    j.admit_dispatch(&started).unwrap();
    let current = j.invocation(&started.invocation_id).unwrap();
    let version = j.task("started").unwrap().record.version;
    assert!(
        j.reject_proposed_invocation(&started.invocation_id, version, current.version)
            .is_err()
    );
    assert_eq!(j.task("started").unwrap().record.version, version);
    assert_eq!(
        j.invocation(&started.invocation_id).unwrap().state,
        InvocationState::Dispatched
    );
    j.integrity_check().unwrap();
}

#[test]
fn inflight_cancellation_requires_an_owned_authenticated_host_observation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalStore::open(&dir.path().join("store"), key(), StoreConfig::default()).unwrap();
    for (task_id, start) in [("dispatched", false), ("running", true)] {
        let request = setup(store.journal_mut(), task_id);
        store.journal_mut().admit_dispatch(&request).unwrap();
        if start {
            let guard = store.journal().attempt_guard(&request.attempt_id).unwrap();
            store.journal_mut().start_attempt(&guard).unwrap();
        }
        let guard = store.journal().attempt_guard(&request.attempt_id).unwrap();
        assert!(
            store
                .finish_attempt(&guard, AttemptState::Cancelled, None)
                .is_err()
        );
        assert!(
            store
                .finish_attempt(&guard, AttemptState::Cancelled, Some("missing-observation"))
                .is_err()
        );
        let artifact = format!("host-cleanup:{task_id}");
        store
            .put_artifact(
                &ArtifactRequest {
                    artifact_id: artifact.clone(),
                    task_id: task_id.into(),
                    content_type: "application/json".into(),
                    logical_type: "test.host_cleanup_observation".into(),
                    schema_version: "test/v1".into(),
                    retain_until_ms: 0,
                    legal_hold: false,
                },
                b"{\"synthetic_host_cleanup_fixture\":true}",
            )
            .unwrap();
        store
            .finish_attempt(&guard, AttemptState::Cancelled, Some(&artifact))
            .unwrap();
        let invocation = store.journal().invocation(&request.invocation_id).unwrap();
        assert_eq!(invocation.state, InvocationState::Cancelled);
        assert!(invocation.active_attempt_id.is_none());
        assert_eq!(
            invocation.result_artifact_id.as_deref(),
            Some(artifact.as_str())
        );
    }
    store.integrity_check().unwrap();
}
