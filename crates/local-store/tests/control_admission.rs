use melissa_core_contracts::{TaskState, wire::TaskContractV1};
use melissa_local_store::{
    StoreKey,
    journal::{AdmissionRequest, ControlAdmission, InvocationRequest, Journal, JournalLimits},
};
use serde_json::json;

fn setup(path: &std::path::Path) -> (Journal, AdmissionRequest) {
    let mut j = Journal::open(
        path,
        StoreKey::from_bytes([91; 32]),
        JournalLimits::default(),
    )
    .unwrap();
    let task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    j.create_task(&task).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        j.transition_task(
            &task.task_id,
            j.task(&task.task_id).unwrap().record.version,
            state,
            None,
        )
        .unwrap();
    }
    let inv = j
        .propose_invocation(
            &InvocationRequest {
                invocation_id: "inv:managed".into(),
                task_id: task.task_id.clone(),
                tool_id: "process.exec".into(),
                arguments: json!({"fixture":"not a real process"}),
                idempotency_key: None,
                generation: 7,
            },
            j.task(&task.task_id).unwrap().record.version,
        )
        .unwrap();
    let req = AdmissionRequest {
        permit_id: "permit:exec".into(),
        nonce: "nonce:exec".into(),
        permit_digest: "authenticated-host-fixture".into(),
        task_id: task.task_id.clone(),
        principal_id: "principal:host".into(),
        profile_id: task.selected_profile_ids[0].clone(),
        tool_id: "process.exec".into(),
        resource_id: task.allowed_resource_ids[0].clone(),
        arguments_digest: inv.arguments_digest,
        invocation_id: inv.invocation_id,
        attempt_id: "attempt:managed".into(),
        generation: 7,
        expected_task_version: j.task(&task.task_id).unwrap().record.version,
        expected_invocation_version: inv.version,
        not_before_unix_ms: 100,
        expires_at_unix_ms: 1000,
        consumed_at_unix_ms: 200,
    };
    j.admit_dispatch(&req).unwrap();
    (j, req)
}
fn control(j: &Journal, exec: &AdmissionRequest) -> ControlAdmission {
    ControlAdmission {
        permit_id: "permit:control".into(),
        nonce: "nonce:control".into(),
        permit_digest: "authenticated-control-host-fixture".into(),
        task_id: exec.task_id.clone(),
        principal_id: "principal:host".into(),
        profile_id: exec.profile_id.clone(),
        target_invocation_id: exec.invocation_id.clone(),
        generation: exec.generation,
        resource_id: exec.resource_id.clone(),
        tool_id: "process.inspect".into(),
        arguments_digest: "fixture-control-digest".into(),
        expected_task_version: j.task(&exec.task_id).unwrap().record.version,
        expected_invocation_version: j.invocation(&exec.invocation_id).unwrap().version,
        not_before_unix_ms: 100,
        expires_at_unix_ms: 1000,
        consumed_at_unix_ms: 201,
    }
}
#[test]
fn inspection_and_cancellation_have_a_durable_single_use_control_journal_without_job_slot_or_version_races()
 {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let (mut j, exec) = setup(&path);
    let mut req = control(&j, &exec);
    let prior = j.task(&exec.task_id).unwrap().record.version;
    let record = j.admit_control(&req).unwrap();
    assert_eq!(record.invocation_id, exec.invocation_id);
    assert_eq!(j.task(&exec.task_id).unwrap().record.version, prior);
    assert!(j.admit_control(&req).is_err());
    assert!(
        !j.is_cancel_requested(&exec.task_id, &exec.invocation_id, 7)
            .unwrap()
    );
    req.permit_id = "permit:cancel".into();
    req.nonce = "nonce:cancel".into();
    req.tool_id = "process.cancel".into();
    req.consumed_at_unix_ms = 202;
    j.admit_control(&req).unwrap();
    assert!(
        j.is_cancel_requested(&exec.task_id, &exec.invocation_id, 7)
            .unwrap()
    );
    assert!(
        !j.is_cancel_requested(&exec.task_id, &exec.invocation_id, 8)
            .unwrap()
    );
    j.integrity_check().unwrap();
    drop(j);
    let mut j = Journal::open(
        &path,
        StoreKey::from_bytes([91; 32]),
        JournalLimits::default(),
    )
    .unwrap();
    assert_eq!(j.control_admission("permit:cancel").unwrap(), req);
    assert!(j.admit_control(&req).is_err());
    j.integrity_check().unwrap();
}
#[test]
fn control_scope_clock_revocation_and_cross_tool_nonce_replay_are_nonmutating() {
    let dir = tempfile::tempdir().unwrap();
    let (mut j, exec) = setup(&dir.path().join("journal.db"));
    let req = control(&j, &exec);
    let mut variants = Vec::new();
    for field in [
        "resource",
        "task",
        "generation",
        "version",
        "nonce",
        "time",
        "tool",
    ] {
        let mut x = req.clone();
        match field {
            "resource" => x.resource_id = "outside:workspace".into(),
            "task" => x.task_id = "task:other".into(),
            "generation" => x.generation += 1,
            "version" => x.expected_invocation_version += 1,
            "nonce" => x.nonce = exec.nonce.clone(),
            "time" => x.consumed_at_unix_ms = 199,
            _ => x.tool_id = "process.kill_any".into(),
        };
        variants.push(x);
    }
    for x in variants {
        assert!(j.admit_control(&x).is_err());
        assert!(j.control_admission(&x.permit_id).is_err());
    }
    j.revoke_permit(&req.permit_id, "withdrawn", 201).unwrap();
    assert!(j.admit_control(&req).is_err());
    j.integrity_check().unwrap();
}
#[test]
fn encrypted_control_index_tampering_is_detected_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let (mut j, exec) = setup(&path);
    let req = control(&j, &exec);
    j.admit_control(&req).unwrap();
    drop(j);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch(
        "DROP TRIGGER control_admissions_no_update; UPDATE control_admissions SET generation=99",
    )
    .unwrap();
    drop(c);
    assert!(
        Journal::open(
            &path,
            StoreKey::from_bytes([91; 32]),
            JournalLimits::default()
        )
        .is_err()
    );
}
