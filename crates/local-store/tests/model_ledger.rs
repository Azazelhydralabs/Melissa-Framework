use std::{
    path::Path,
    sync::{Arc, Barrier},
};

use melissa_core_contracts::{TaskState, wire::TaskContractV1};
use melissa_local_store::{
    LocalStore, StoreConfig, StoreKey,
    journal::{
        Journal, JournalLimits, ModelRequestState, ModelReservation, ModelSettlement, ModelUsage,
    },
};

fn key() -> StoreKey {
    StoreKey::from_bytes([109; 32])
}
fn digest(byte: char) -> String {
    format!("blake3:{}", byte.to_string().repeat(64))
}
fn contract() -> TaskContractV1 {
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = "task:model-ledger".into();
    task.limits.max_input_tokens = 100;
    task.limits.max_output_tokens = 100;
    task.limits.max_cost_micro_usd = 1000;
    task.limits.max_parallel_jobs = 2;
    task
}
fn setup(root: &Path) -> LocalStore {
    let mut store = LocalStore::open(root, key(), StoreConfig::default()).unwrap();
    store.journal_mut().create_task(&contract()).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let version = store
            .journal()
            .task(&contract().task_id)
            .unwrap()
            .record
            .version;
        store
            .transition_task(&contract().task_id, version, state, None)
            .unwrap();
    }
    store
}
fn reserve(id: &str, time: u64) -> ModelReservation {
    ModelReservation {
        schema_version: "melissa.model-reservation/v1".into(),
        request_id: id.into(),
        task_id: contract().task_id,
        profile_id: contract().selected_profile_ids[0].clone(),
        provider_id: "fixture.provider".into(),
        model_id: "fixture.model.secret-name-109".into(),
        request_digest: digest('a'),
        pricing_digest: Some(digest('b')),
        reserved_input_tokens: 40,
        reserved_output_tokens: 30,
        reserved_cost_micro_usd: 300,
        created_at_unix_ms: time,
    }
}
fn version(store: &LocalStore) -> u64 {
    store
        .journal()
        .task(&contract().task_id)
        .unwrap()
        .record
        .version
}
fn settlement(state: ModelRequestState, time: u64) -> ModelSettlement {
    ModelSettlement {
        state,
        usage: ModelUsage {
            input_tokens: Some(20),
            output_tokens: Some(10),
            cached_input_tokens: Some(4),
            cost_micro_usd: Some(80),
        },
        receipt_digest: Some(digest('c')),
        reason: None,
        completed_at_unix_ms: time,
    }
}
fn release(time: u64) -> ModelSettlement {
    ModelSettlement {
        state: ModelRequestState::NeverDispatched,
        usage: ModelUsage {
            input_tokens: Some(0),
            output_tokens: Some(0),
            cached_input_tokens: Some(0),
            cost_micro_usd: Some(0),
        },
        receipt_digest: Some(digest('d')),
        reason: Some("trusted adapter failed before entering transport".into()),
        completed_at_unix_ms: time,
    }
}

#[test]
fn concurrent_connections_atomically_reserve_one_shared_task_budget_without_task_version_races() {
    let dir = tempfile::tempdir().unwrap();
    let store = setup(&dir.path().join("store"));
    let task_version = version(&store);
    let barrier = Arc::new(Barrier::new(2));
    let joins = (0..2)
        .map(|index| {
            let mut connection = store.connect().unwrap();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut request = reserve(&format!("request:parallel:{index}"), 100);
                request.reserved_input_tokens = 70;
                barrier.wait();
                connection
                    .journal_mut()
                    .reserve_model_request(&request, task_version)
            })
        })
        .collect::<Vec<_>>();
    let results = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        store
            .journal()
            .model_budget(&contract().task_id)
            .unwrap()
            .charged_input_tokens,
        70
    );
    assert_eq!(version(&store), task_version);
    store.integrity_check().unwrap();
}

#[test]
fn replay_task_profile_bounds_and_shared_process_clock_fail_before_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let task_version = version(&store);
    store
        .journal_mut()
        .revoke_permit("unrelated:permit", "clock control", 150)
        .unwrap();
    assert!(
        store
            .journal_mut()
            .reserve_model_request(&reserve("old-clock", 149), task_version)
            .is_err()
    );
    for kind in [
        "version",
        "profile",
        "task",
        "digest",
        "overflow",
        "cacheprice",
    ] {
        let mut request = reserve(kind, 200);
        let expected = if kind == "version" {
            task_version + 1
        } else {
            task_version
        };
        match kind {
            "profile" => request.profile_id = "outside:profile".into(),
            "task" => request.task_id = "outside:task".into(),
            "digest" => request.request_digest = "unverified".into(),
            "overflow" => request.reserved_input_tokens = u64::MAX,
            "cacheprice" => request.pricing_digest = Some("unverified".into()),
            _ => {}
        }
        assert!(
            store
                .journal_mut()
                .reserve_model_request(&request, expected)
                .is_err(),
            "{kind}"
        );
        assert!(store.journal().model_request(kind).is_err());
    }
    let request = reserve("once", 200);
    store
        .journal_mut()
        .reserve_model_request(&request, task_version)
        .unwrap();
    assert!(
        store
            .journal_mut()
            .reserve_model_request(&request, task_version)
            .is_err()
    );
    assert!(
        store
            .journal_mut()
            .dispatch_model_request("once", 0, 199)
            .is_err()
    );
    let running = store
        .journal_mut()
        .dispatch_model_request("once", 0, 201)
        .unwrap();
    assert_eq!(running.version, 1);
    assert!(
        store
            .journal_mut()
            .dispatch_model_request("once", 0, 202)
            .is_err()
    );
    assert!(
        store
            .journal_mut()
            .finish_model_request("once", 1, &settlement(ModelRequestState::Succeeded, 200))
            .is_err()
    );
    store
        .journal_mut()
        .finish_model_request("once", 1, &settlement(ModelRequestState::Succeeded, 202))
        .unwrap();
    assert!(
        store
            .journal_mut()
            .finish_model_request("once", 1, &settlement(ModelRequestState::Succeeded, 203))
            .is_err()
    );
    assert!(
        store
            .journal_mut()
            .revoke_permit("late:permit", "backwards", 201)
            .is_err()
    );
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(
        (
            budget.charged_input_tokens,
            budget.charged_output_tokens,
            budget.charged_cost_micro_usd
        ),
        (20, 10, 80)
    );
    assert_eq!(budget.active_requests, 0);
    assert_eq!(version(&store), task_version);
    store.integrity_check().unwrap();
}

#[test]
fn unknown_usage_is_not_zero_and_bounded_fallback_uses_a_fresh_budgeted_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("unknown", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("unknown", 0, 101)
        .unwrap();
    let unknown = store
        .journal_mut()
        .mark_model_request_unknown("unknown", 1, "connection closed after request body", 102)
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(
        (
            budget.charged_input_tokens,
            budget.charged_output_tokens,
            budget.charged_cost_micro_usd
        ),
        (40, 30, 300)
    );
    assert_eq!(
        (
            budget.unknown_requests,
            budget.unknown_cost_requests,
            budget.active_requests
        ),
        (1, 1, 1)
    );
    assert!(
        store
            .journal_mut()
            .dispatch_model_request("unknown", unknown.version, 103)
            .is_err()
    );
    store
        .journal_mut()
        .reserve_model_request(&reserve("fresh-fallback", 103), tv)
        .unwrap();
    assert!(
        store
            .journal_mut()
            .reserve_model_request(&reserve("third", 104), tv)
            .is_err()
    );
    store
        .journal_mut()
        .finish_model_request("fresh-fallback", 0, &release(104))
        .unwrap();
    assert!(
        store
            .journal_mut()
            .finish_model_request(
                "unknown",
                unknown.version,
                &settlement(ModelRequestState::Failed, 105)
            )
            .is_err()
    );
    store
        .journal_mut()
        .reconcile_model_request(
            "unknown",
            unknown.version,
            &settlement(ModelRequestState::Failed, 105),
            "provider-billing:receipt:123",
        )
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(budget.unknown_requests, 0);
    assert_eq!(budget.charged_cost_micro_usd, 80);
    assert_eq!(budget.active_requests, 0);
    store.integrity_check().unwrap();
}

#[test]
fn incomplete_provider_usage_keeps_only_unknown_components_and_explicit_reconciliation_is_audited()
{
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let tv = version(&store);
    let mut request = reserve("partial", 100);
    request.pricing_digest = None;
    let mut unpriced_zero = request.clone();
    unpriced_zero.reserved_cost_micro_usd = 0;
    assert!(
        store
            .journal_mut()
            .reserve_model_request(&unpriced_zero, tv)
            .is_err()
    );
    store
        .journal_mut()
        .reserve_model_request(&request, tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("partial", 0, 101)
        .unwrap();
    let mut result = settlement(ModelRequestState::Succeeded, 102);
    result.usage.cost_micro_usd = None;
    result.usage.cached_input_tokens = None;
    let partial = store
        .journal_mut()
        .finish_model_request("partial", 1, &result)
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(
        (
            budget.charged_input_tokens,
            budget.charged_output_tokens,
            budget.charged_cost_micro_usd
        ),
        (20, 10, 300)
    );
    assert_eq!(
        (budget.known_cost_micro_usd, budget.unknown_cost_requests),
        (0, 1)
    );
    assert_eq!(budget.active_requests, 0);
    store
        .journal_mut()
        .reconcile_model_request(
            "partial",
            partial.version,
            &settlement(ModelRequestState::Succeeded, 103),
            "provider:billing:verified",
        )
        .unwrap();
    assert_eq!(
        store
            .journal()
            .model_budget(&contract().task_id)
            .unwrap()
            .charged_cost_micro_usd,
        80
    );
    assert!(
        store
            .journal_mut()
            .reconcile_model_request(
                "partial",
                partial.version + 1,
                &settlement(ModelRequestState::Succeeded, 104),
                "second:rewrite"
            )
            .is_err()
    );
    store.integrity_check().unwrap();
}

#[test]
fn actual_usage_overrun_is_persisted_and_blocks_further_dispatch_instead_of_discarding_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("overrun", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .reserve_model_request(&reserve("waiting", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("overrun", 0, 101)
        .unwrap();
    let mut usage = settlement(ModelRequestState::Succeeded, 102);
    usage.usage.input_tokens = Some(101);
    store
        .journal_mut()
        .finish_model_request("overrun", 1, &usage)
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert!(budget.budget_exceeded);
    assert_eq!(budget.known_input_tokens, 101);
    assert!(
        store
            .journal_mut()
            .dispatch_model_request("waiting", 0, 103)
            .is_err()
    );
    assert!(
        store
            .journal_mut()
            .reserve_model_request(&reserve("new", 103), tv)
            .is_err()
    );
    assert!(
        store
            .journal_mut()
            .finish_model_request("waiting", 0, &release(103))
            .is_ok()
    );
    store.integrity_check().unwrap();
}

#[test]
fn cancelled_dispatch_without_usage_stays_charged_and_cannot_claim_never_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("cancelled", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("cancelled", 0, 101)
        .unwrap();
    assert!(
        store
            .journal_mut()
            .finish_model_request("cancelled", 1, &release(102))
            .is_err()
    );
    let mut cancelled = settlement(ModelRequestState::Cancelled, 102);
    cancelled.usage = ModelUsage::default();
    store
        .journal_mut()
        .finish_model_request("cancelled", 1, &cancelled)
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(budget.charged_cost_micro_usd, 300);
    assert_eq!(budget.unknown_cost_requests, 1);
    store.integrity_check().unwrap();
}

#[test]
fn exclusive_session_recovery_and_backup_restore_preserve_unknown_reservations_without_replay() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = setup(&root);
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("prepared", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .reserve_model_request(&reserve("running", 101), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("running", 0, 102)
        .unwrap();
    let connection = store.connect().unwrap();
    assert_eq!(
        connection.journal().model_request("running").unwrap().state,
        ModelRequestState::Dispatched
    );
    drop(connection);
    let backup = dir.path().join("backup");
    store.backup(&backup).unwrap();
    drop(store);
    let store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    let records = store.journal().model_requests(&contract().task_id).unwrap();
    assert!(
        records
            .iter()
            .all(|record| record.state == ModelRequestState::OutcomeUnknown)
    );
    assert_eq!(
        store
            .journal()
            .model_budget(&contract().task_id)
            .unwrap()
            .charged_cost_micro_usd,
        600
    );
    assert_eq!(version(&store), tv);
    store.integrity_check().unwrap();
    let restored = LocalStore::restore_backup(
        &backup,
        &dir.path().join("restored"),
        key(),
        StoreConfig::default(),
    )
    .unwrap();
    assert_eq!(
        restored
            .journal()
            .model_budget(&contract().task_id)
            .unwrap()
            .unknown_requests,
        2
    );
    assert!(
        restored
            .journal()
            .model_requests(&contract().task_id)
            .unwrap()
            .iter()
            .all(|record| record.state == ModelRequestState::OutcomeUnknown)
    );
    restored.integrity_check().unwrap();
}

#[test]
fn authenticated_payload_indexes_history_and_migration_checksum_tampering_are_rejected() {
    for mode in ["payload", "index", "event", "checksum", "schema"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let mut store = setup(&root);
        let tv = version(&store);
        store
            .journal_mut()
            .reserve_model_request(&reserve("tamper", 100), tv)
            .unwrap();
        store
            .journal_mut()
            .dispatch_model_request("tamper", 0, 101)
            .unwrap();
        store
            .journal_mut()
            .finish_model_request("tamper", 1, &settlement(ModelRequestState::Succeeded, 102))
            .unwrap();
        drop(store);
        let db = root.join("store.sqlite3");
        let conn = rusqlite::Connection::open(&db).unwrap();
        match mode {
            "payload" => {
                conn.execute_batch("UPDATE model_requests SET payload=zeroblob(length(payload))")
                    .unwrap();
            }
            "index" => {
                conn.execute_batch("UPDATE model_requests SET model_id='spoofed-model'")
                    .unwrap();
            }
            "event" => {
                assert!(
                    conn.execute("DELETE FROM model_request_events WHERE sequence=1", [])
                        .is_err()
                );
                conn.execute_batch("DROP TRIGGER model_request_events_no_delete; DELETE FROM model_request_events WHERE sequence=1; CREATE TRIGGER model_request_events_no_delete BEFORE DELETE ON model_request_events BEGIN SELECT RAISE(ABORT,'model request events are append only'); END;").unwrap();
            }
            "checksum" => {
                conn.execute_batch(
                    "UPDATE schema_migrations SET checksum='forged' WHERE version=4",
                )
                .unwrap();
            }
            _ => {
                conn.execute_batch("DROP INDEX model_requests_task")
                    .unwrap();
            }
        }
        drop(conn);
        assert!(
            LocalStore::open(&root, key(), StoreConfig::default()).is_err(),
            "{mode}"
        );
    }
}

#[test]
fn payload_encryption_and_v3_upgrade_authentication_preserve_prior_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for (version, sql) in [
            (1, include_str!("../migrations/0001_initial.sql")),
            (
                2,
                include_str!("../migrations/0002_execution_admission.sql"),
            ),
            (3, include_str!("../migrations/0003_process_control.sql")),
        ] {
            conn.execute_batch(sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations VALUES(?1,?2)",
                rusqlite::params![version, blake3::hash(sql.as_bytes()).to_hex().to_string()],
            )
            .unwrap();
        }
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
        conn.execute(
            "INSERT INTO execution_clock VALUES(1,0,?1)",
            [key()
                .seal(br#"{"last_seen_ms":0}"#, b"execution-clock:v1")
                .unwrap()],
        )
        .unwrap();
    }
    assert!(
        Journal::open(
            &path,
            StoreKey::from_bytes([0; 32]),
            JournalLimits::default()
        )
        .is_err()
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    drop(conn);
    let quota_path = dir.path().join("capacity-v3.db");
    std::fs::copy(&path, &quota_path).unwrap();
    let quota_conn = rusqlite::Connection::open(&quota_path).unwrap();
    let pages = quota_conn
        .query_row("PRAGMA page_count", [], |row| row.get::<_, u64>(0))
        .unwrap();
    let page_size = quota_conn
        .query_row("PRAGMA page_size", [], |row| row.get::<_, u64>(0))
        .unwrap();
    drop(quota_conn);
    let limits = JournalLimits {
        max_database_bytes: pages * page_size,
        ..Default::default()
    };
    assert!(Journal::open(&quota_path, key(), limits).is_err());
    let quota_conn = rusqlite::Connection::open(&quota_path).unwrap();
    assert_eq!(
        quota_conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        quota_conn
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        quota_conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='model_requests'",
                [],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    drop(quota_conn);
    Journal::open(&path, key(), JournalLimits::default()).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM schema_migrations", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        4
    );
    drop(conn);
    let root = dir.path().join("encrypted");
    let mut store = setup(&root);
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("encrypted", 100), tv)
        .unwrap();
    drop(store);
    let bytes = std::fs::read(root.join("store.sqlite3")).unwrap();
    assert!(
        !bytes
            .windows(b"melissa.model-reservation/v1".len())
            .any(|slice| slice == b"melissa.model-reservation/v1")
    );
    assert!(
        !bytes
            .windows(b"reserved_input_tokens".len())
            .any(|slice| slice == b"reserved_input_tokens")
    );
}

#[test]
fn cached_input_is_a_known_lower_bound_even_when_total_input_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("cache-only", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("cache-only", 0, 101)
        .unwrap();
    let mut result = settlement(ModelRequestState::Succeeded, 102);
    result.usage.input_tokens = None;
    result.usage.cached_input_tokens = Some(120);
    store
        .journal_mut()
        .finish_model_request("cache-only", 1, &result)
        .unwrap();
    let budget = store.journal().model_budget(&contract().task_id).unwrap();
    assert_eq!(budget.charged_input_tokens, 120);
    assert_eq!(budget.unknown_input_requests, 1);
    assert!(budget.budget_exceeded);
    store.integrity_check().unwrap();
}

#[test]
fn late_event_failure_rolls_back_dispatch_record_and_shared_clock_as_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = setup(&root);
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("atomic", 100), tv)
        .unwrap();
    let conn = rusqlite::Connection::open(root.join("store.sqlite3")).unwrap();
    conn.execute_batch("CREATE TRIGGER fixture_model_failure BEFORE INSERT ON model_request_events WHEN NEW.sequence=1 BEGIN SELECT RAISE(ABORT,'injected event failure'); END;").unwrap();
    assert!(
        store
            .journal_mut()
            .dispatch_model_request("atomic", 0, 200)
            .is_err()
    );
    assert_eq!(
        store.journal().model_request("atomic").unwrap().state,
        ModelRequestState::Reserved
    );
    assert_eq!(store.journal().model_request("atomic").unwrap().version, 0);
    conn.execute_batch("DROP TRIGGER fixture_model_failure")
        .unwrap();
    drop(conn);
    store
        .journal_mut()
        .revoke_permit("rollback:clock", "test", 101)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("atomic", 0, 102)
        .unwrap();
    store.integrity_check().unwrap();
}

#[test]
fn child_model_crash_fixture() {
    let Some(path) = std::env::var_os("MELISSA_MODEL_LEDGER_CRASH_ROOT") else {
        return;
    };
    let mut store = setup(Path::new(&path));
    let tv = version(&store);
    store
        .journal_mut()
        .reserve_model_request(&reserve("actual-crash", 100), tv)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("actual-crash", 0, 101)
        .unwrap();
    std::process::exit(91);
}

#[test]
fn actual_host_process_exit_recovers_possible_provider_effect_as_unknown_without_retry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_model_crash_fixture", "--nocapture"])
        .env("MELISSA_MODEL_LEDGER_CRASH_ROOT", &root)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(91));
    let store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    let request = store.journal().model_request("actual-crash").unwrap();
    assert_eq!(request.state, ModelRequestState::OutcomeUnknown);
    assert_eq!(request.version, 2);
    assert_eq!(
        store
            .journal()
            .model_budget(&contract().task_id)
            .unwrap()
            .charged_cost_micro_usd,
        300
    );
    store.integrity_check().unwrap();
}
