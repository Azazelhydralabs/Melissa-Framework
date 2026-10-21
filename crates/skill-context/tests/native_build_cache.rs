#![cfg(windows)]
#[path = "../../build-test/tests/support/mod.rs"]
mod support;
use melissa_build_test::RustOperation;
use melissa_skill_context::{Namespace, build_cache::NativeBuildPlan};
#[test]
fn real_cargo_cache_artifacts_reuse_only_with_exact_sources_sdk_policy_and_scope() {
    let mut f = support::Fixture::new(
        "pub fn total(a:i32,b:i32)->i32{a+b}\n",
        RustOperation::Build,
        &[],
        support::limits(),
    );
    let ns = Namespace {
        user: "u".into(),
        project: "native-build".into(),
        engagement: None,
    };
    let expires = melissa_execution_broker::unix_ms().unwrap() + 120000;
    let first = NativeBuildPlan::prepare(
        &f.repo,
        ns.clone(),
        "policy:1",
        expires,
        support::limits(),
        None,
        &support::no(),
    )
    .unwrap();
    let permit = support::permit_for(&mut f, first.request(), first.snapshot());
    let a = first
        .execute(
            &f.repo,
            &mut f.broker,
            &f.task.task_id,
            &permit,
            &support::identity(),
            &support::no(),
        )
        .unwrap();
    assert_eq!(a.observation["cache_seed_reused"], false);
    let second = NativeBuildPlan::prepare(
        &f.repo,
        ns.clone(),
        "policy:1",
        expires,
        support::limits(),
        Some(&a.seed),
        &support::no(),
    )
    .unwrap();
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy
        .grants
        .get_mut("auth:code06-rust")
        .unwrap()
        .process_digest = melissa_execution_broker::container_policy::container_execution_digest(
        second.request(),
        &second.snapshot().digest().unwrap(),
    )
    .unwrap();
    f.broker.policy_control().replace(policy).unwrap();
    let now = melissa_execution_broker::unix_ms().unwrap();
    let permit = f
        .broker
        .issue_permit(
            &f.task.task_id,
            second.request().clone(),
            second.snapshot(),
            melissa_execution_broker::policy::PermitRequest {
                permit_id: "permit:cache-warm".into(),
                nonce: "nonce:cache-warm".into(),
                principal_id: "principal:code06-rust".into(),
                profile_id: f.task.selected_profile_ids[0].clone(),
                resource_id: f.task.workspace_ref.clone(),
                authorization_ref: "auth:code06-rust".into(),
                not_before_unix_ms: now,
                expires_at_unix_ms: now + 90000,
            },
        )
        .unwrap();
    let id = melissa_execution_broker::InvocationIdentity {
        invocation_id: "inv:code07-cache-warm".into(),
        attempt_id: "attempt:code07-cache-warm".into(),
        generation: 1,
        idempotency_key: None,
    };
    let b = second
        .execute(
            &f.repo,
            &mut f.broker,
            &f.task.task_id,
            &permit,
            &id,
            &support::no(),
        )
        .unwrap();
    assert_eq!(b.observation["cache_seed_reused"], true);
    assert!(
        b.observation["native"]["fresh_artifacts"].as_u64().unwrap() > 0,
        "{}",
        b.observation
    );
    assert!(
        NativeBuildPlan::prepare(
            &f.repo,
            ns.clone(),
            "policy:2",
            expires,
            support::limits(),
            Some(&b.seed),
            &support::no()
        )
        .is_err()
    );
    let mut other = ns.clone();
    other.project = "elsewhere".into();
    assert!(
        NativeBuildPlan::prepare(
            &f.repo,
            other,
            "policy:1",
            expires,
            support::limits(),
            Some(&b.seed),
            &support::no()
        )
        .is_err()
    );
    std::fs::write(
        f._dir.path().join("repo/src/lib.rs"),
        "pub fn total(a:i32,b:i32)->i32{a-b}\n",
    )
    .unwrap();
    assert!(
        NativeBuildPlan::prepare(
            &f.repo,
            ns,
            "policy:1",
            expires,
            support::limits(),
            Some(&b.seed),
            &support::no()
        )
        .is_err()
    );
}
