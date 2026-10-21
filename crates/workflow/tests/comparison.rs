use melissa_core_contracts::wire::TaskLimitsV1;
use melissa_workflow::{comparison::*, digest, plan::Mode};
use std::collections::BTreeSet;
fn trial(case: &str, arm: Arm, passed: bool) -> Trial {
    Trial {
        key: PairKey {
            case_id: case.into(),
            input_content_digest: digest(b"same-input"),
            acceptance_digest: digest(b"same-acceptance"),
            goal_digest: digest(b"same-user-goal"),
            provider: "same-provider".into(),
            model: "same-model".into(),
            model_settings_digest: digest(b"same-full-model-settings"),
            environment_ref: "same-immutable-worker".into(),
            limits: TaskLimitsV1 {
                max_wall_time_ms: 100000,
                max_cost_micro_usd: 1000,
                max_input_tokens: 1000000,
                max_output_tokens: 400000,
                max_parallel_jobs: 3,
                max_disk_bytes: 10000000,
                max_output_bytes: 1000000,
            },
        },
        arm,
        task: format!("task:{case}:{arm:?}"),
        passed,
        critical_failure: false,
        host_interventions: 0,
        wall_time_ms: 100,
        all_requests: 3,
        dispatched_requests: 3,
        conservative_micro_usd: 100,
        known_input_tokens: 100,
        known_output_tokens: 100,
        oracle_evidence_digest: Some(digest(b"host-evidence")),
        native_requests_digest: digest(b"native-request-ledger"),
    }
}
fn pairs() -> Vec<Trial> {
    ["a", "b", "c"]
        .into_iter()
        .flat_map(|id| {
            [
                trial(id, Arm::Single, true),
                trial(id, Arm::Delegated, true),
            ]
        })
        .collect()
}
#[test]
fn simple_task_defaults_to_one_agent_without_admitted_measurement() {
    assert_eq!(
        default_mode(None, &BTreeSet::new()).unwrap(),
        Mode::SingleAgent
    );
}
#[test]
fn same_success_with_more_cost_or_time_keeps_single_agent() {
    let mut t = pairs();
    for v in t.iter_mut().filter(|t| t.arm == Arm::Delegated) {
        v.conservative_micro_usd = 200;
        v.wall_time_ms = 200;
    }
    assert_eq!(
        compare(t).unwrap().recommendation,
        Recommendation::KeepSingle
    );
}
#[test]
fn delegation_quality_gain_requires_host_admission_and_is_suite_scoped() {
    let mut t = pairs();
    t[0].passed = false;
    let c = compare(t).unwrap();
    assert_eq!(
        c.recommendation,
        Recommendation::DelegationMeasuredBetterOnThisSuite
    );
    assert!(!c.general_superiority_claim);
    assert!(!c.held_out);
    assert_eq!(
        default_mode(Some(&c), &BTreeSet::new()).unwrap(),
        Mode::SingleAgent
    );
    let admitted = BTreeSet::from([digest(&serde_json::to_vec(&c).unwrap())]);
    assert_eq!(
        default_mode(Some(&c), &admitted).unwrap(),
        Mode::ConditionalDelegation
    );
}
#[test]
fn different_model_invalidates_comparison() {
    let mut t = pairs();
    t[1].key.model = "other-model".into();
    assert!(compare(t).is_err());
}
#[test]
fn different_source_invalidates_comparison() {
    let mut t = pairs();
    t[1].key.input_content_digest = digest(b"other-source");
    assert!(compare(t).is_err());
}
#[test]
fn different_total_budget_invalidates_comparison() {
    let mut t = pairs();
    t[1].key.limits.max_cost_micro_usd += 1;
    assert!(compare(t).is_err());
}
#[test]
fn different_environment_invalidates_comparison() {
    let mut t = pairs();
    t[1].key.environment_ref = "warmer-sdk".into();
    assert!(compare(t).is_err());
}
#[test]
fn missing_baseline_cannot_be_called_superiority() {
    let mut t = pairs();
    t.remove(0);
    assert!(compare(t).is_err());
}
#[test]
fn failed_arm_cannot_be_silently_replaced_with_another_trial() {
    let mut t = pairs();
    t.push(trial("a", Arm::Single, true));
    assert!(compare(t).is_err());
}
#[test]
fn developer_intervention_excludes_automatic_delegation_recommendation() {
    let mut t = pairs();
    t[0].passed = false;
    t[1].host_interventions = 1;
    assert_eq!(
        compare(t).unwrap().recommendation,
        Recommendation::KeepSingle
    );
}
#[test]
fn critical_failure_blocks_automatic_delegation() {
    let mut t = pairs();
    t[0].passed = false;
    t[1].critical_failure = true;
    assert_eq!(
        compare(t).unwrap().recommendation,
        Recommendation::KeepSingle
    );
}
#[test]
fn tampered_summary_is_rejected_even_with_host_digest() {
    let mut c = compare(pairs()).unwrap();
    c.delegated_passed = 999;
    let admitted = BTreeSet::from([digest(&serde_json::to_vec(&c).unwrap())]);
    assert!(default_mode(Some(&c), &admitted).is_err());
}
#[test]
fn one_pair_does_not_enable_delegation_by_default() {
    let mut t = vec![
        trial("a", Arm::Single, false),
        trial("a", Arm::Delegated, true),
    ];
    t[1].wall_time_ms = 1;
    assert_eq!(
        compare(t).unwrap().recommendation,
        Recommendation::KeepSingle
    );
}
