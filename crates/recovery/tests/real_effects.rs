#![cfg(windows)]
#[path = "../../repository/tests/support/mod.rs"]
mod support;
use melissa_local_store::LocalStore;
use melissa_model_gateway::{
    ToolCall,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use melissa_recovery::{
    Binding,
    compensation::{Compensation, CompensationContext, CompensationPlan, Phase},
    session::{Freshness, Refresh},
};
use melissa_repository::{
    ByteEdit, FilePatch, Limits, PatchProposal, Repository,
    tools::{RepositoryDispatcher, RepositoryToolPolicy},
};
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
};

fn context(inv: &str) -> ToolContext {
    ToolContext {
        task_id: "task:code05-closeout".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "owned-comp".into(),
        request_id: "request:owned".into(),
        invocation_id: inv.into(),
        attempt_id: format!("{inv}:attempt"),
        generation: 1,
    }
}
fn proposal(repo: &Repository, content: &[u8], id: &str) -> ToolCall {
    let (version, old) = repo.read("value.txt").unwrap();
    ToolCall {
        id: id.into(),
        name: "fs_patch".into(),
        arguments: serde_json::to_string(&PatchProposal {
            schema_version: "melissa.repository-patch/v1".into(),
            root_identity: repo.root_identity().into(),
            files: vec![FilePatch {
                before: version,
                edits: vec![ByteEdit {
                    start: 0,
                    end: old.len() as u64,
                    expected: old,
                    replacement: content.to_vec(),
                }],
            }],
        })
        .unwrap(),
    }
}
fn dispatcher(
    repo: Repository,
    s: &LocalStore,
    p: melissa_repository::PatchPolicy,
) -> RepositoryDispatcher {
    RepositoryDispatcher::new(
        repo,
        s.connect().unwrap(),
        RepositoryToolPolicy {
            files: p,
            read_repository: true,
            enabled_tools: BTreeSet::from(["fs_patch".into(), "fs_read".into()]),
        },
    )
    .unwrap()
    .with_recovery_observations()
    .unwrap()
}
fn refresh(root: &std::path::Path) -> Refresh {
    let root = root.to_path_buf();
    Arc::new(move || {
        let repo = Repository::open_for_git(&root, Limits::default()).map_err(|e| {
            melissa_model_gateway::GatewayError::new(
                melissa_model_gateway::ErrorKind::Store,
                e.to_string(),
            )
        })?;
        Ok(Freshness {
            source: repo.snapshot(&AtomicBool::new(false)).unwrap().digest,
            policy: "policy:owned".into(),
        })
    })
}
async fn prepared() -> (
    tempfile::TempDir,
    LocalStore,
    RepositoryDispatcher,
    CompensationPlan,
    Refresh,
) {
    let (d, repo, store, policy) = support::fixture(&["value.txt"]);
    std::fs::write(repo.root_path().join("value.txt"), b"original\n").unwrap();
    let r = refresh(repo.root_path());
    let initial = r().unwrap().source;
    let forward = proposal(&repo, b"changed\n", "forward");
    let mut tools = dispatcher(repo, &store, policy);
    let observation = tools
        .execute(
            forward,
            context("forward"),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(observation.success);
    let repo = Repository::open_for_git(&d.path().join("repo"), Limits::default()).unwrap();
    let rollback = proposal(&repo, b"original\n", "rollback");
    let t = store.journal().task("task:code05-closeout").unwrap();
    let forward_artifact = "forward:tool-result".to_string();
    let bytes = store
        .get_artifact(&t.contract.task_id, &forward_artifact)
        .unwrap();
    let plan = CompensationPlan {
        id: "rollback".into(),
        binding: Binding {
            task: t.contract.task_id.clone(),
            run: "owned-comp".into(),
            profile: t.contract.selected_profile_ids[0].clone(),
            initial_source: t.contract.input_snapshot_digest.clone(),
            policy: "policy:owned".into(),
        },
        authorization: "auth:closeout".into(),
        forward_invocation: "forward".into(),
        forward_artifact,
        forward_digest: melissa_recovery::digest(&bytes),
        before_source: r().unwrap().source,
        expected_after_source: initial,
        call: rollback,
        context: CompensationContext {
            request: "request:compensate".into(),
            invocation: "rollback".into(),
            attempt: "rollback:attempt".into(),
            generation: 1,
        },
    };
    // Creating the operation is separate from preparing its exact host plan.
    assert_eq!(
        store.journal().invocation("forward").unwrap().state,
        melissa_core_contracts::InvocationState::Succeeded
    );
    (d, store, tools, plan, r)
}
#[tokio::test]
async fn real_stale_patch_is_known_nonexecuted_then_current_patch_preserves_user_edit() {
    let (d, repo, s, p) = support::fixture(&["value.txt"]);
    std::fs::write(repo.root_path().join("value.txt"), b"old\n").unwrap();
    let stale = proposal(&repo, b"fixed\n", "stale");
    std::fs::write(repo.root_path().join("value.txt"), b"old\nUSER EDIT\n").unwrap();
    let mut tools = dispatcher(repo, &s, p);
    let observed = tools
        .execute(stale, context("stale"), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert!(!observed.success && !observed.requires_reconciliation);
    assert!(observed.content.contains("stale_patch_rejected"));
    assert!(s.journal().invocation("stale").is_err());
    let repo = Repository::open_for_git(&d.path().join("repo"), Limits::default()).unwrap();
    let new = proposal(&repo, b"fixed\nUSER EDIT\n", "current");
    assert!(
        tools
            .execute(new, context("current"), Arc::new(AtomicBool::new(false)))
            .await
            .unwrap()
            .success
    );
    assert_eq!(
        std::fs::read(repo.root_path().join("value.txt")).unwrap(),
        b"fixed\nUSER EDIT\n"
    );
}
#[tokio::test]
async fn real_compensation_is_separately_authorized_and_never_runs_twice() {
    let (d, mut s, mut tools, plan, r) = prepared().await;
    let op = Compensation::create(&mut s, plan.clone(), r).unwrap();
    assert!(matches!(
        melissa_recovery::retry::inspect_retry(&s, "task:code05-closeout", "forward").unwrap(),
        melissa_recovery::retry::RetryDecision::ReuseStoredResult { .. }
    ));
    let result = op
        .execute(&mut s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.phase, Phase::Compensated);
    assert_eq!(
        std::fs::read(d.path().join("repo/value.txt")).unwrap(),
        b"original\n"
    );
    assert!(
        op.execute(&mut s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert_eq!(
        s.journal().invocation("forward").unwrap().state,
        melissa_core_contracts::InvocationState::Succeeded
    );
}
struct Lost {
    inner: RepositoryDispatcher,
    hang: bool,
}
impl ToolDispatcher for Lost {
    fn definitions(&self) -> Vec<BoundTool> {
        self.inner.definitions()
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.inner.validate_call(c)
    }
    fn execute<'a>(
        &'a mut self,
        c: ToolCall,
        t: ToolContext,
        f: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        Box::pin(async move {
            self.inner.execute(c, t, f).await?;
            if self.hang {
                std::future::pending::<()>().await;
            }
            Err(melissa_model_gateway::GatewayError::new(
                melissa_model_gateway::ErrorKind::Transport,
                "injected lost receipt after authentic effect",
            ))
        })
    }
}
#[tokio::test]
async fn compensation_crash_after_effect_is_adopted_from_native_receipt_without_replay() {
    let (_d, mut s, tools, plan, r) = prepared().await;
    let op = Compensation::create(&mut s, plan.clone(), r.clone()).unwrap();
    let mut lost = Lost {
        inner: tools,
        hang: true,
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            op.execute(&mut s, &mut lost, Arc::new(AtomicBool::new(false)))
        )
        .await
        .is_err()
    );
    assert_eq!(op.state(&s).unwrap().phase, Phase::Compensating);
    drop(op);
    let reopened = Compensation::reopen(&s, plan, r).unwrap();
    assert!(
        reopened
            .execute(&mut s, &mut lost, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert_eq!(
        reopened.reconcile_native(&mut s).unwrap().phase,
        Phase::Compensated
    );
}
#[tokio::test]
async fn compensation_missing_authority_fails_before_effect_and_forward_remains_visible() {
    let (d, mut s, _tools, mut plan, r) = prepared().await;
    plan.authorization = "auth:absent".into();
    assert!(Compensation::create(&mut s, plan, r).is_err());
    assert_eq!(
        std::fs::read(d.path().join("repo/value.txt")).unwrap(),
        b"changed\n"
    );
}
#[tokio::test]
async fn a_successful_process_with_wrong_compensation_postimage_is_failed_not_accepted() {
    let (d, mut s, mut tools, mut plan, r) = prepared().await;
    let repo = Repository::open_for_git(&d.path().join("repo"), Limits::default()).unwrap();
    plan.call = proposal(&repo, b"wrong rollback\n", "wrong-rollback");
    let op = Compensation::create(&mut s, plan, r).unwrap();
    assert_eq!(
        op.execute(&mut s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap()
            .phase,
        Phase::Failed
    );
    assert!(
        op.execute(&mut s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(d.path().join("repo/value.txt")).unwrap(),
        b"wrong rollback\n"
    );
}
#[tokio::test]
async fn cancelled_compensation_has_no_new_native_invocation_and_cannot_replay() {
    let (d, mut s, mut tools, plan, r) = prepared().await;
    let op = Compensation::create(&mut s, plan, r).unwrap();
    assert_eq!(
        op.execute(&mut s, &mut tools, Arc::new(AtomicBool::new(true)))
            .await
            .unwrap()
            .phase,
        Phase::Cancelled
    );
    assert!(s.journal().invocation("rollback").is_err());
    assert_eq!(
        std::fs::read(d.path().join("repo/value.txt")).unwrap(),
        b"changed\n"
    );
    assert!(
        op.execute(&mut s, &mut tools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn actual_unknown_patch_effect_is_inspected_and_reconciled_without_executing_again() {
    let (d, repo, mut s, p) = support::fixture(&["value.txt"]);
    std::fs::write(repo.root_path().join("value.txt"), b"old\n").unwrap();
    let call = proposal(&repo, b"new\n", "unknown");
    s.put_artifact(
        &melissa_local_store::ArtifactRequest {
            artifact_id: "unknown:receipt".into(),
            task_id: p.task_id.clone(),
            content_type: "application/json".into(),
            logical_type: "fault_injection".into(),
            schema_version: "v1".into(),
            retain_until_ms: 0,
            legal_hold: false,
        },
        b"injected unavailable receipt slot",
    )
    .unwrap();
    let mut tools = dispatcher(repo, &s, p);
    let outcome = tools
        .execute(call, context("unknown"), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert!(outcome.requires_reconciliation);
    assert_eq!(
        melissa_recovery::retry::inspect_retry(&s, "task:code05-closeout", "unknown").unwrap(),
        melissa_recovery::retry::RetryDecision::ReconciliationRequired
    );
    let repo = Repository::open_for_git(&d.path().join("repo"), Limits::default()).unwrap();
    let resolved = melissa_recovery::reconcile::inspect_patch_effect(
        &mut s,
        &repo,
        "task:code05-closeout",
        "unknown",
    )
    .unwrap();
    assert_eq!(resolved["proof"]["effect_disposition"], "postimage_present");
    assert_eq!(resolved["automatic_replay_allowed"], false);
    assert_eq!(
        s.journal().invocation("unknown").unwrap().state,
        melissa_core_contracts::InvocationState::Reconciled
    );
    assert_eq!(
        std::fs::read(repo.root_path().join("value.txt")).unwrap(),
        b"new\n"
    );
}
#[tokio::test]
async fn unknown_multi_file_patch_in_unsorted_order_reconciles_by_proposal_index() {
    // Proposal order (b.txt, a.txt) differs from the broker's path-sorted write
    // order; preimages must still be found by proposal index.
    let (d, repo, mut s, p) = support::fixture(&["a.txt", "b.txt"]);
    std::fs::write(repo.root_path().join("a.txt"), b"old a\n").unwrap();
    std::fs::write(repo.root_path().join("b.txt"), b"old b\n").unwrap();
    let mut files = vec![];
    for (path, content) in [
        ("b.txt", b"new b\n".as_slice()),
        ("a.txt", b"new a\n".as_slice()),
    ] {
        let (version, old) = repo.read(path).unwrap();
        files.push(FilePatch {
            before: version,
            edits: vec![ByteEdit {
                start: 0,
                end: old.len() as u64,
                expected: old,
                replacement: content.to_vec(),
            }],
        });
    }
    let call = ToolCall {
        id: "unordered".into(),
        name: "fs_patch".into(),
        arguments: serde_json::to_string(&PatchProposal {
            schema_version: "melissa.repository-patch/v1".into(),
            root_identity: repo.root_identity().into(),
            files,
        })
        .unwrap(),
    };
    s.put_artifact(
        &melissa_local_store::ArtifactRequest {
            artifact_id: "unordered:receipt".into(),
            task_id: p.task_id.clone(),
            content_type: "application/json".into(),
            logical_type: "fault_injection".into(),
            schema_version: "v1".into(),
            retain_until_ms: 0,
            legal_hold: false,
        },
        b"injected unavailable receipt slot",
    )
    .unwrap();
    let mut tools = dispatcher(repo, &s, p);
    let outcome = tools
        .execute(call, context("unordered"), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert!(outcome.requires_reconciliation);
    let repo = Repository::open_for_git(&d.path().join("repo"), Limits::default()).unwrap();
    let resolved = melissa_recovery::reconcile::inspect_patch_effect(
        &mut s,
        &repo,
        "task:code05-closeout",
        "unordered",
    )
    .unwrap();
    assert_eq!(resolved["proof"]["effect_disposition"], "postimage_present");
    assert_eq!(
        s.journal().invocation("unordered").unwrap().state,
        melissa_core_contracts::InvocationState::Reconciled
    );
}
