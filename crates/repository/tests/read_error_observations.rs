#![cfg(windows)]
mod support;
use melissa_core_contracts::InvocationState;
use melissa_local_store::ArtifactRequest;
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher, ToolExecution},
};
use melissa_repository::{
    FileMutation, MutationProposal,
    tools::{RepositoryDispatcher, RepositoryToolPolicy},
};
use serde_json::{Value, json};
use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
};

fn context(id: &str) -> ToolContext {
    ToolContext {
        task_id: "task:code05-closeout".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "read-error-check".into(),
        request_id: format!("request:{id}"),
        invocation_id: format!("inv:{id}"),
        attempt_id: format!("attempt:{id}"),
        generation: 1,
    }
}
async fn call(
    d: &mut RepositoryDispatcher,
    name: &str,
    args: Value,
    id: &str,
) -> melissa_model_gateway::Result<ToolExecution> {
    let c = ToolCall {
        id: format!("call:{id}"),
        name: name.into(),
        arguments: args.to_string(),
    };
    d.validate_call(&c)?;
    d.execute(c, context(id), Arc::new(AtomicBool::new(false)))
        .await
}

#[tokio::test]
async fn missing_parent_read_can_be_corrected_after_explicit_mkdir_in_the_same_task() {
    let (_temp, repo, store, policy) = support::fixture(&["scratch"]);
    let root = repo.root_path().to_owned();
    let identity = repo.root_identity().to_string();
    let peer = store.connect().unwrap();
    let mut dispatcher = RepositoryDispatcher::new(
        repo,
        store,
        RepositoryToolPolicy {
            files: policy,
            read_repository: true,
            enabled_tools: ["fs_absent", "fs_mkdir"].map(String::from).into(),
        },
    )
    .unwrap();
    assert!(
        call(
            &mut dispatcher,
            "fs_absent",
            json!({"path":"scratch/note.bin"}),
            "legacy"
        )
        .await
        .is_err()
    );
    let mut dispatcher = dispatcher.with_read_error_observations().unwrap();
    let failure = call(
        &mut dispatcher,
        "fs_absent",
        json!({"path":"scratch/note.bin"}),
        "missing",
    )
    .await
    .unwrap();
    assert!(!failure.success && !failure.requires_reconciliation && !failure.cancelled);
    let content: Value = serde_json::from_str(&failure.content).unwrap();
    assert_eq!(content["status"], "read_input_rejected");
    assert_eq!(content["workspace_write_dispatched"], false);
    assert!(!root.join("scratch").exists());
    assert!(
        peer.journal()
            .task("task:code05-closeout")
            .unwrap()
            .record
            .unknown_invocation_id
            .is_none()
    );
    let absent = call(
        &mut dispatcher,
        "fs_absent",
        json!({"path":"scratch"}),
        "parent",
    )
    .await
    .unwrap();
    let v: Value = serde_json::from_str(&absent.content).unwrap();
    let proposal = MutationProposal {
        schema_version: "melissa.repository-mutation/v2".into(),
        root_identity: identity,
        mutation: FileMutation::CreateDirectory {
            destination: serde_json::from_value(v["result"].clone()).unwrap(),
        },
    };
    assert!(
        call(
            &mut dispatcher,
            "fs_mkdir",
            serde_json::to_value(proposal).unwrap(),
            "mkdir"
        )
        .await
        .unwrap()
        .success
    );
    let after = call(
        &mut dispatcher,
        "fs_absent",
        json!({"path":"scratch/note.bin"}),
        "corrected",
    )
    .await
    .unwrap();
    assert!(after.success);
    assert!(root.join("scratch").is_dir());
    assert!(!root.join("scratch/note.bin").exists());
    assert!(
        peer.journal()
            .task("task:code05-closeout")
            .unwrap()
            .record
            .unknown_invocation_id
            .is_none()
    );
    peer.integrity_check().unwrap();
}

#[tokio::test]
async fn exact_crlf_preview_failure_is_feedback_then_correct_proposal_still_needs_explicit_patch() {
    let (_temp, repo, store, policy) = support::fixture(&["f.txt"]);
    let root = repo.root_path().to_owned();
    fs::write(root.join("f.txt"), b"old\r\n").unwrap();
    let mut dispatcher = RepositoryDispatcher::new(
        repo,
        store,
        RepositoryToolPolicy {
            files: policy,
            read_repository: true,
            enabled_tools: ["code_unified_propose", "fs_patch"]
                .map(String::from)
                .into(),
        },
    )
    .unwrap()
    .with_read_error_observations()
    .unwrap();
    let wrong = "--- a/f.txt\n+++ b/f.txt\n@@ -1 +1 @@\n-old\n+new\n";
    let failure = call(
        &mut dispatcher,
        "code_unified_propose",
        json!({"patch":wrong}),
        "lf",
    )
    .await
    .unwrap();
    assert!(!failure.success && !failure.requires_reconciliation);
    assert_eq!(fs::read(root.join("f.txt")).unwrap(), b"old\r\n");
    let correct = "--- a/f.txt\n+++ b/f.txt\n@@ -1 +1 @@\n-old\r\n+new\r\n";
    let preview = call(
        &mut dispatcher,
        "code_unified_propose",
        json!({"patch":correct}),
        "crlf",
    )
    .await
    .unwrap();
    assert!(preview.success);
    assert_eq!(fs::read(root.join("f.txt")).unwrap(), b"old\r\n");
    let v: Value = serde_json::from_str(&preview.content).unwrap();
    assert_eq!(v["result"]["authorizes_write"], false);
    assert!(
        call(
            &mut dispatcher,
            "fs_patch",
            v["result"]["changes"][0]["proposal"].clone(),
            "apply"
        )
        .await
        .unwrap()
        .success
    );
    assert_eq!(fs::read(root.join("f.txt")).unwrap(), b"new\r\n");
}

#[tokio::test]
async fn read_feedback_mode_keeps_denials_and_post_write_evidence_failure_fail_closed() {
    let (_temp, repo, mut store, policy) = support::fixture(&["new.bin"]);
    let root = repo.root_path().to_owned();
    let identity = repo.root_identity().to_string();
    let dest = repo.absent_path("new.bin").unwrap();
    store
        .put_artifact(
            &ArtifactRequest {
                artifact_id: "inv:create:receipt".into(),
                task_id: "task:code05-closeout".into(),
                content_type: "application/json".into(),
                logical_type: "owned_failure".into(),
                schema_version: "fixture/v1".into(),
                retain_until_ms: 0,
                legal_hold: false,
            },
            b"occupied",
        )
        .unwrap();
    let peer = store.connect().unwrap();
    let mut dispatcher = RepositoryDispatcher::new(
        repo,
        store,
        RepositoryToolPolicy {
            files: policy,
            read_repository: true,
            enabled_tools: ["fs_absent", "fs_create"].map(String::from).into(),
        },
    )
    .unwrap()
    .with_read_error_observations()
    .unwrap();
    let c = ToolCall {
        id: "wrong-profile".into(),
        name: "fs_absent".into(),
        arguments: json!({"path":"new.bin"}).to_string(),
    };
    let mut ctx = context("wrong");
    ctx.profile_id = "melissa.code.repository-analyst".into();
    assert!(
        dispatcher
            .execute(c, ctx, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert!(
        dispatcher
            .validate_call(&ToolCall {
                id: "inject".into(),
                name: "fs_absent".into(),
                arguments: json!({"path":"new.bin","read_error_observations":true}).to_string()
            })
            .is_err()
    );
    let proposal = MutationProposal {
        schema_version: "melissa.repository-mutation/v1".into(),
        root_identity: identity,
        mutation: FileMutation::Create {
            destination: dest,
            bytes: b"real write".to_vec(),
        },
    };
    let outcome = call(
        &mut dispatcher,
        "fs_create",
        serde_json::to_value(proposal).unwrap(),
        "create",
    )
    .await
    .unwrap();
    assert!(!outcome.success && outcome.requires_reconciliation);
    assert_eq!(fs::read(root.join("new.bin")).unwrap(), b"real write");
    assert_eq!(
        peer.journal().invocation("inv:create").unwrap().state,
        InvocationState::OutcomeUnknown
    );
    assert!(dispatcher.definitions().is_empty());
}
