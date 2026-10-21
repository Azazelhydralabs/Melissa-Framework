#![allow(dead_code)]
include!("common/gateway.rs");
use melissa_local_store::journal::{ModelSettlement, ModelUsage};
use melissa_workflow::{Kind, plan::*, scheduler::*};

fn reservation(_s: &LocalStore, id: &str, profile: &str) -> ModelReservation {
    ModelReservation {
        schema_version: "melissa.model-reservation/v1".into(),
        request_id: id.into(),
        task_id: TASK.into(),
        profile_id: profile.into(),
        provider_id: "fixture-provider".into(),
        model_id: "fixture-model".into(),
        request_digest: melissa_workflow::digest(id.as_bytes()),
        pricing_digest: None,
        reserved_input_tokens: 600,
        reserved_output_tokens: 128,
        reserved_cost_micro_usd: 90000,
        created_at_unix_ms: melissa_execution_broker::unix_ms().unwrap(),
    }
}
#[test]
fn parallel_experts_share_one_atomic_native_budget() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 1000);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles = [
        ("a", "melissa.code.implementer"),
        ("b", "melissa.code.test-engineer"),
    ]
    .into_iter()
    .map(|(id, profile)| {
        let mut s = s.connect().unwrap();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let v = s.journal().task(TASK).unwrap().record.version;
            let r = reservation(&s, id, profile);
            barrier.wait();
            s.journal_mut().reserve_model_request(&r, v).is_ok()
        })
    })
    .collect::<Vec<_>>();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let budget = s.journal().model_budget(TASK).unwrap();
    assert_eq!(budget.charged_cost_micro_usd, 90000);
    assert_eq!(budget.active_requests, 1);
    assert_eq!(s.journal().model_requests(TASK).unwrap().len(), 1);
}
#[test]
fn unknown_usage_keeps_money_and_blocks_workflow_and_cancel_settlement() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("s"), 100000);
    let task = s.journal().task(TASK).unwrap();
    let r = reservation(&s, "unknown", "melissa.code.implementer");
    let reserved = s
        .journal_mut()
        .reserve_model_request(&r, task.record.version)
        .unwrap();
    let dispatched = s
        .journal_mut()
        .dispatch_model_request(
            "unknown",
            reserved.version,
            melissa_execution_broker::unix_ms().unwrap(),
        )
        .unwrap();
    s.journal_mut()
        .finish_model_request(
            "unknown",
            dispatched.version,
            &ModelSettlement {
                state: ModelRequestState::OutcomeUnknown,
                usage: ModelUsage::default(),
                receipt_digest: None,
                reason: Some("fixture transport loss".into()),
                completed_at_unix_ms: melissa_execution_broker::unix_ms().unwrap(),
            },
        )
        .unwrap();
    let budget = s.journal().model_budget(TASK).unwrap();
    assert_eq!(budget.charged_cost_micro_usd, 90000);
    assert_eq!(budget.unknown_requests, 1);
    let p = Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "blocked".into(),
        task: TASK.into(),
        revision: 1,
        parent_digest: None,
        workspace_digest: task.contract.input_snapshot_digest.clone(),
        policy_digest: melissa_workflow::digest(b"p"),
        mode: Mode::SingleAgent,
        delegation_reason: None,
        max_parallel: 1,
        max_no_progress: 2,
        nodes: vec![Node {
            id: "a".into(),
            profile: "melissa.code.implementer".into(),
            goal: "No effect may dispatch".into(),
            after: BTreeSet::new(),
            bindings: vec![],
            literal_input: json!({}),
            tools: BTreeSet::new(),
            effects: BTreeSet::from(["workspace.read".into()]),
            resources: BTreeSet::from([task.contract.workspace_ref]),
            authorizations: BTreeSet::new(),
            claims: vec![],
            output_schema: json!({"type":"object"}),
            skills: vec![],
        }],
        outputs: BTreeSet::from(["a".into()]),
    };
    let f = Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    };
    let result = Scheduler::create(
        s,
        p,
        &Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        Arc::new(move || Ok(f.clone())),
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(result.err().unwrap().kind, Kind::Uncertain);
}
#[test]
fn budget_cannot_be_reset_by_changing_profile_on_same_task() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("s"), 100000);
    let v = s.journal().task(TASK).unwrap().record.version;
    let a = reservation(&s, "first", "melissa.code.implementer");
    s.journal_mut().reserve_model_request(&a, v).unwrap();
    let b = reservation(&s, "second", "melissa.code.test-engineer");
    assert!(s.journal_mut().reserve_model_request(&b, v).is_err());
    assert_eq!(
        s.journal()
            .model_budget(TASK)
            .unwrap()
            .charged_cost_micro_usd,
        90000
    );
}
