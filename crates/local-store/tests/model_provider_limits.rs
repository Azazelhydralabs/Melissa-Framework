use melissa_core_contracts::{TaskState, wire::TaskContractV1};
use melissa_local_store::{
    LocalStore, StoreConfig, StoreError, StoreKey,
    journal::{ModelRequestState, ModelReservation, ModelSettlement, ModelUsage},
};
use std::{
    path::Path,
    sync::{Arc, Barrier},
};

fn key() -> StoreKey {
    StoreKey::from_bytes([117; 32])
}
fn contract(id: &str) -> TaskContractV1 {
    let mut value: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    value.task_id = id.into();
    value.limits.max_input_tokens = 10_000;
    value.limits.max_output_tokens = 10_000;
    value.limits.max_cost_micro_usd = 10_000;
    value.limits.max_parallel_jobs = 8;
    value
}
fn setup(root: &Path) -> LocalStore {
    let mut store = LocalStore::open(root, key(), StoreConfig::default()).unwrap();
    for id in ["task:a", "task:b"] {
        store.journal_mut().create_task(&contract(id)).unwrap();
        for state in [
            TaskState::Planned,
            TaskState::Queued,
            TaskState::Leased,
            TaskState::Running,
        ] {
            let version = version(&store, id);
            store.transition_task(id, version, state, None).unwrap();
        }
    }
    store
}
fn version(store: &LocalStore, task: &str) -> u64 {
    store.journal().task(task).unwrap().record.version
}
fn reservation(task: &str, id: &str, time: u64) -> ModelReservation {
    ModelReservation {
        schema_version: "melissa.model-reservation/v1".into(),
        request_id: id.into(),
        task_id: task.into(),
        profile_id: contract(task).selected_profile_ids[0].clone(),
        provider_id: "provider:shared".into(),
        model_id: "model:shared".into(),
        request_digest: format!("blake3:{}", "a".repeat(64)),
        pricing_digest: Some(format!("blake3:{}", "b".repeat(64))),
        reserved_input_tokens: 100,
        reserved_output_tokens: 100,
        reserved_cost_micro_usd: 100,
        created_at_unix_ms: time,
    }
}
fn settlement(time: u64) -> ModelSettlement {
    ModelSettlement {
        state: ModelRequestState::Failed,
        usage: ModelUsage {
            input_tokens: Some(20),
            output_tokens: Some(10),
            cached_input_tokens: Some(0),
            cost_micro_usd: Some(30),
        },
        receipt_digest: Some(format!("blake3:{}", "c".repeat(64))),
        reason: Some("provider receipt confirmed terminal failure".into()),
        completed_at_unix_ms: time,
    }
}

#[test]
fn provider_limit_is_atomic_across_different_tasks_and_connected_handles() {
    let dir = tempfile::tempdir().unwrap();
    let store = setup(&dir.path().join("store"));
    let barrier = Arc::new(Barrier::new(2));
    let joins = ["task:a", "task:b"]
        .into_iter()
        .enumerate()
        .map(|(index, task)| {
            let mut connected = store.connect().unwrap();
            let barrier = barrier.clone();
            let expected = version(&store, task);
            std::thread::spawn(move || {
                let request = reservation(task, &format!("request:{index}"), 100);
                barrier.wait();
                connected
                    .journal_mut()
                    .reserve_model_request_with_provider_limit(&request, expected, 1)
            })
        })
        .collect::<Vec<_>>();
    let results = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Quota(_))))
            .count(),
        1
    );
    assert_eq!(
        store.journal().model_requests("task:a").unwrap().len()
            + store.journal().model_requests("task:b").unwrap().len(),
        1
    );
    store.integrity_check().unwrap();
}

#[test]
fn unknown_outcome_keeps_provider_slot_until_reconciled_without_blocking_other_models() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("store"));
    let av = version(&store, "task:a");
    let bv = version(&store, "task:b");
    store
        .journal_mut()
        .reserve_model_request_with_provider_limit(&reservation("task:a", "unknown", 100), av, 1)
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("unknown", 0, 101)
        .unwrap();
    let unknown = store
        .journal_mut()
        .mark_model_request_unknown(
            "unknown",
            1,
            "connection dropped with provider outcome unconfirmed",
            102,
        )
        .unwrap();
    let mut connected = store.connect().unwrap();
    assert!(matches!(
        connected
            .journal_mut()
            .reserve_model_request_with_provider_limit(
                &reservation("task:b", "blocked", 103),
                bv,
                1
            ),
        Err(StoreError::Quota(_))
    ));
    assert!(connected.journal().model_request("blocked").is_err());
    let mut other_model = reservation("task:b", "other-model", 103);
    other_model.model_id = "model:other".into();
    connected
        .journal_mut()
        .reserve_model_request_with_provider_limit(&other_model, bv, 1)
        .unwrap();
    let mut other_provider = reservation("task:b", "other-provider", 104);
    other_provider.provider_id = "provider:other".into();
    connected
        .journal_mut()
        .reserve_model_request_with_provider_limit(&other_provider, bv, 1)
        .unwrap();
    store
        .journal_mut()
        .reconcile_model_request(
            "unknown",
            unknown.version,
            &settlement(105),
            "artifact:trusted-provider-terminal-receipt",
        )
        .unwrap();
    connected
        .journal_mut()
        .reserve_model_request_with_provider_limit(
            &reservation("task:b", "after-reconcile", 106),
            bv,
            1,
        )
        .unwrap();
    for invalid in [0, 1025] {
        assert!(matches!(
            connected
                .journal_mut()
                .reserve_model_request_with_provider_limit(
                    &reservation("task:b", "invalid-cap", 107),
                    bv,
                    invalid
                ),
            Err(StoreError::Invalid(_))
        ));
    }
    store.integrity_check().unwrap();
}

#[test]
fn reopened_host_preserves_provider_hold_and_plaintext_index_tampering_cannot_hide_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let mut store = setup(&root);
    let av = version(&store, "task:a");
    store
        .journal_mut()
        .reserve_model_request_with_provider_limit(
            &reservation("task:a", "interrupted", 100),
            av,
            1,
        )
        .unwrap();
    store
        .journal_mut()
        .dispatch_model_request("interrupted", 0, 101)
        .unwrap();
    drop(store);
    let mut store = LocalStore::open(&root, key(), StoreConfig::default()).unwrap();
    let bv = version(&store, "task:b");
    let recovered = store.journal().model_request("interrupted").unwrap();
    assert_eq!(recovered.state, ModelRequestState::OutcomeUnknown);
    let time = recovered.settlement.as_ref().unwrap().completed_at_unix_ms + 1;
    assert!(matches!(
        store
            .journal_mut()
            .reserve_model_request_with_provider_limit(
                &reservation("task:b", "restart-bypass", time),
                bv,
                1
            ),
        Err(StoreError::Quota(_))
    ));
    assert!(store.journal().model_request("restart-bypass").is_err());
    store.integrity_check().unwrap();
    let external = rusqlite::Connection::open(root.join("store.sqlite3")).unwrap();
    external.execute("UPDATE model_requests SET provider_id='hidden-provider', state='succeeded' WHERE request_id='interrupted'",[]).unwrap();
    assert!(matches!(
        store
            .journal_mut()
            .reserve_model_request_with_provider_limit(
                &reservation("task:b", "index-bypass", time),
                bv,
                1
            ),
        Err(StoreError::Integrity(_))
    ));
    assert!(store.journal().model_request("index-bypass").is_err());
}
