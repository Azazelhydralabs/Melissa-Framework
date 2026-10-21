#![allow(dead_code, unused_imports)]
//! Native loopback transport tests are deterministic fault injection, not AI.
include!("../../workflow/tests/common/gateway.rs");
use melissa_model_gateway::recovery::{RecoveryEvent, RecoveryHook};
use melissa_recovery::{
    Binding, FailureKind, Phase, Policy, RecoverySession,
    session::{Freshness, Refresh},
};
use std::collections::BTreeMap;

fn config(s: &LocalStore, run: &str) -> (Binding, Policy, Refresh) {
    let t = s.journal().task(TASK).unwrap();
    let binding = Binding {
        task: TASK.into(),
        run: run.into(),
        profile: PROFILE.into(),
        initial_source: t.contract.input_snapshot_digest,
        policy: "policy:owned-recovery".into(),
    };
    let b = binding.clone();
    (
        binding,
        Policy {
            max_repairs: 16,
            max_same_failure: 3,
            deadline_ms: melissa_execution_broker::unix_ms().unwrap() + 60_000,
        },
        Arc::new(move || {
            Ok(Freshness {
                source: b.initial_source.clone(),
                policy: b.policy.clone(),
            })
        }),
    )
}
fn event(b: &Binding, kind: FailureKind, id: &str) -> RecoveryEvent {
    RecoveryEvent {
        task: b.task.clone(),
        run: b.run.clone(),
        request: format!("request:{id}"),
        kind,
        calls: vec![ToolCall {
            id: id.into(),
            name: "process_exec".into(),
            arguments: "{\"value\":\"owned\"}".into(),
        }],
        diagnostic: "unchanged actual diagnostic".into(),
        evidence: vec![],
    }
}
#[test]
fn failures_are_durable_and_never_accept_or_reset_the_task() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "failure");
    let initial = s.journal().model_budget(TASK).unwrap();
    let mut h = RecoverySession::create(&mut s, b.clone(), p, r.clone(), BTreeMap::new()).unwrap();
    let directive = h
        .failure(&mut s, event(&b, FailureKind::BuildError, "one"))
        .unwrap();
    assert!(directive.continue_run);
    assert!(directive.feedback.contains("actual diagnostic"));
    drop(h);
    let h = RecoverySession::reopen(&s, b, r, BTreeMap::new()).unwrap();
    let state = h.state(&s).unwrap();
    assert_eq!(state.failures.len(), 1);
    assert_eq!(state.phase, Phase::Repairing);
    assert!(
        s.get_artifact(TASK, &state.failures[0].evidence_artifact)
            .is_ok()
    );
    let after = s.journal().model_budget(TASK).unwrap();
    assert_eq!(after.known_cost_micro_usd, initial.known_cost_micro_usd);
    assert_eq!(
        s.journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}
#[test]
fn new_call_ids_cannot_hide_the_same_failure_loop() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "repeats");
    let mut h = RecoverySession::create(&mut s, b.clone(), p, r, BTreeMap::new()).unwrap();
    assert!(
        h.failure(&mut s, event(&b, FailureKind::StalePatch, "one"))
            .unwrap()
            .continue_run
    );
    assert!(
        h.failure(&mut s, event(&b, FailureKind::StalePatch, "two"))
            .unwrap()
            .continue_run
    );
    assert!(
        !h.failure(&mut s, event(&b, FailureKind::StalePatch, "three"))
            .unwrap()
            .continue_run
    );
    assert_eq!(h.state(&s).unwrap().phase, Phase::Blocked);
    assert!(h.eligibility(&s).is_err());
}
#[test]
fn successful_repeated_reads_also_stop_without_claiming_success() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "readloop");
    let mut h = RecoverySession::create(&mut s, b.clone(), p, r, BTreeMap::new()).unwrap();
    for id in ["one", "two"] {
        assert!(
            h.success(&mut s, event(&b, FailureKind::NoProgress, id))
                .unwrap()
                .is_none()
        );
    }
    assert!(
        !h.success(&mut s, event(&b, FailureKind::NoProgress, "three"))
            .unwrap()
            .unwrap()
            .continue_run
    );
    assert_eq!(h.state(&s).unwrap().phase, Phase::Blocked);
}
#[test]
fn source_progress_changes_fingerprint_but_does_not_erase_history() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, _) = config(&s, "progress");
    let source = Arc::new(Mutex::new(b.initial_source.clone()));
    let owned = source.clone();
    let policy = b.policy.clone();
    let refresh: Refresh = Arc::new(move || {
        Ok(Freshness {
            source: owned.lock().unwrap().clone(),
            policy: policy.clone(),
        })
    });
    let mut h = RecoverySession::create(&mut s, b.clone(), p, refresh, BTreeMap::new()).unwrap();
    for id in ["one", "two"] {
        assert!(
            h.failure(&mut s, event(&b, FailureKind::BuildError, id))
                .unwrap()
                .continue_run
        );
    }
    *source.lock().unwrap() = melissa_recovery::digest(b"new actual source");
    assert!(
        h.failure(&mut s, event(&b, FailureKind::BuildError, "three"))
            .unwrap()
            .continue_run
    );
    assert_eq!(h.state(&s).unwrap().failures.len(), 3);
}
#[test]
fn unknown_effect_and_authority_denial_never_offer_retry() {
    for kind in [FailureKind::UnknownEffect, FailureKind::AuthorityDenied] {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), 100_000);
        let (b, p, r) = config(&s, "hold");
        let mut h =
            RecoverySession::create(&mut s, b.clone(), p, r.clone(), BTreeMap::new()).unwrap();
        assert!(
            !h.failure(&mut s, event(&b, kind, "one"))
                .unwrap()
                .continue_run
        );
        drop(h);
        let h = RecoverySession::reopen(&s, b, r, BTreeMap::new()).unwrap();
        assert!(h.eligibility(&s).is_err());
    }
}
#[test]
fn foreign_task_or_run_cannot_publish_failure() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "scope");
    let mut h = RecoverySession::create(&mut s, b.clone(), p, r, BTreeMap::new()).unwrap();
    let mut e = event(&b, FailureKind::BuildError, "one");
    e.run = "foreign".into();
    assert!(h.failure(&mut s, e).is_err());
    assert_eq!(h.state(&s).unwrap().sequence, 0);
}
#[test]
fn changed_policy_and_cancel_block_recovery() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "cancel");
    let h = RecoverySession::create(&mut s, b.clone(), p, r, BTreeMap::new()).unwrap();
    h.cancel(&mut s).unwrap();
    assert!(h.eligibility(&s).is_err());
    let initial_source = b.initial_source.clone();
    let refresh: Refresh = Arc::new(move || {
        Ok(Freshness {
            source: initial_source.clone(),
            policy: "expanded".into(),
        })
    });
    assert!(RecoverySession::reopen(&s, b, refresh, BTreeMap::new()).is_err());
}
#[tokio::test]
async fn gateway_repairs_bad_arguments_from_feedback_without_executing_rejected_batch() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "args");
    let h = RecoverySession::create(&mut s, b, p, r, BTreeMap::new()).unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[("bad", "process_exec", "{\"value\":42}")])),
        HttpPlan::sse(tool_response(&[(
            "fixed",
            "process_exec",
            "{\"value\":\"owned\"}",
        )])),
        HttpPlan::sse(text_response("done", false, true)),
    ])
    .await;
    let mut g = gateway(s, &http, policy()).with_recovery(Box::new(h));
    let mut tools = FakeTools::default();
    let result = g
        .run(&spec("args"), &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 1);
    assert!(!result.task_accepted);
    assert!(
        serde_json::to_string(&http.bodies.lock().unwrap()[1])
            .unwrap()
            .contains("recovery_required")
    );
    assert_eq!(result.request_ids.len(), 3);
}
#[tokio::test]
async fn gateway_invalid_output_is_reproposed_without_host_json_repair() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "output");
    let h = RecoverySession::create(&mut s, b, p, r, BTreeMap::new()).unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(text_response("{broken", false, true)),
        HttpPlan::sse(text_response("{\"value\":7}", false, true)),
    ])
    .await;
    let mut g = gateway(s, &http, policy()).with_recovery(Box::new(h));
    let mut run = spec("output");
    run.output_schema = Some(
        json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}),
    );
    let result = g
        .run(
            &run,
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(result.answer.as_deref(), Some("{\"value\":7}"));
    assert_eq!(result.request_ids.len(), 2);
    assert!(
        serde_json::to_string(&http.bodies.lock().unwrap()[1])
            .unwrap()
            .contains("{broken")
    );
}
#[tokio::test]
async fn gateway_no_progress_stops_before_an_extra_paid_request() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "loop");
    let h = RecoverySession::create(&mut s, b, p, r, BTreeMap::new()).unwrap();
    let http = http_fixture(
        ["one", "two", "three"]
            .iter()
            .map(|id| HttpPlan::sse(tool_response(&[(id, "process_exec", "{\"value\":0}")])))
            .collect(),
    )
    .await;
    let mut g = gateway(s, &http, policy()).with_recovery(Box::new(h));
    let mut tools = FakeTools::default();
    let result = g
        .run(&spec("loop"), &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::NoAction);
    assert_eq!(http.requests.load(Ordering::SeqCst), 3);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn gateway_unknown_observation_is_terminal_and_not_a_repairable_build_error() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "unknown");
    let h = RecoverySession::create(&mut s, b, p, r, BTreeMap::new()).unwrap();
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "one",
        "process_exec",
        "{\"value\":\"owned\"}",
    )]))])
    .await;
    let mut g = gateway(s, &http, policy()).with_recovery(Box::new(h));
    let mut tools = FakeTools {
        unknown: true,
        ..Default::default()
    };
    let result = g
        .run(
            &spec("unknown"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(result.requires_reconciliation);
    assert_eq!(result.status, RunStatus::NeedsReconciliation);
    assert_eq!(result.request_ids.len(), 1);
}
#[test]
fn unowned_or_unexpired_sweeps_are_denied_before_any_engine_access() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    assert!(melissa_recovery::sweep::sweep_expired_container(&mut s, TASK, "foreign").is_err());
    assert!(
        melissa_container_executor::recovery::remove_expired_owned("short", "sha256:bad").is_err()
    );
}
#[tokio::test]
async fn provider_sent_timeout_retains_charge_and_stops_without_blind_retry() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "timeout");
    let h = RecoverySession::create(&mut s, b.clone(), p, r.clone(), BTreeMap::new()).unwrap();
    let http = http_fixture(vec![HttpPlan {
        status: 200,
        body: text_response("late", false, true),
        delay: Duration::from_secs(6),
    }])
    .await;
    let mut policy = policy();
    policy.max_wall_time_ms = 10_000;
    let mut g = gateway(s, &http, policy).with_recovery(Box::new(h));
    let result = g
        .run(
            &spec("timeout"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::NeedsReconciliation);
    assert_eq!(result.request_ids.len(), 1);
    assert!(result.requires_reconciliation);
    let bgt = g.store().journal().model_budget(TASK).unwrap();
    assert_eq!(bgt.unknown_requests, 1);
    let h = RecoverySession::reopen(g.store(), b, r, BTreeMap::new()).unwrap();
    assert_eq!(
        h.state(g.store()).unwrap().phase,
        Phase::NeedsReconciliation
    );
}
#[tokio::test]
async fn proved_not_sent_connection_failure_is_retried_with_new_ids_and_known_zero_usage() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "not_sent");
    let h = RecoverySession::create(&mut s, b, p, r, BTreeMap::new()).unwrap();
    let http = http_fixture(vec![]).await;
    tokio::task::yield_now().await;
    let mut host_policy = policy();
    host_policy.max_wall_time_ms = 30_000;
    let mut g = gateway(s, &http, host_policy).with_recovery(Box::new(h));
    let result = g
        .run(
            &spec("not_sent"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::ProviderFailed);
    assert_eq!(result.request_ids.len(), 3);
    let records = g.store().journal().model_requests(TASK).unwrap();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| r.state == ModelRequestState::Failed
        && r.settlement.as_ref().unwrap().usage.cost_micro_usd == Some(0)));
    assert_eq!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .unknown_requests,
        0
    );
}
#[tokio::test]
async fn prepared_workflow_recovery_preserves_the_root_task_and_existing_tools() {
    let d = tempfile::tempdir().unwrap();
    let s = store(d.path(), 100_000);
    let (b, p, r) = config(&s, "prepared");
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "bad",
            "process_exec",
            "{\"value\":false}",
        )])),
        HttpPlan::sse(tool_response(&[(
            "fixed",
            "process_exec",
            "{\"value\":\"owned\"}",
        )])),
        HttpPlan::sse(text_response("finished", false, true)),
    ])
    .await;
    let tools = FakeTools::default();
    let executed = tools.executed.clone();
    let prepared = melissa_workflow::runtime::PreparedRun {
        gateway: gateway(s, &http, policy()),
        spec: spec("prepared"),
        dispatcher: Box::new(tools),
    };
    let mut prepared =
        melissa_recovery::integration::enable_prepared_run(prepared, b, p, r, BTreeMap::new())
            .unwrap();
    let result = prepared
        .gateway
        .run(
            &prepared.spec,
            prepared.dispatcher.as_mut(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.task_id, TASK);
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(executed.load(Ordering::SeqCst), 1);
    assert_eq!(result.request_ids.len(), 3);
    assert!(!result.task_accepted);
}
