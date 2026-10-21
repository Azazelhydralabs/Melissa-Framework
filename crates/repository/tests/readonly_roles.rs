#![cfg(windows)]
mod support;
use melissa_core_contracts::{InvocationState, TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{
    ArtifactRequest, LocalStore, StoreConfig, StoreKey, journal::InvocationRequest,
};
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use melissa_repository::{
    Limits, Repository,
    analysis::{AnalysisQuery, LspMethod},
    git::GitOperation,
    tools::{RepositoryRead, RepositoryReadDispatcher, RepositoryReadPolicy},
};
use std::{
    fs,
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
fn catalog() -> Catalog {
    Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
}
fn fixture(operation: RepositoryRead) -> (tempfile::TempDir, RepositoryReadDispatcher, LocalStore) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("lib.rs"),
        b"pub fn selected(){}\npub fn caller(){selected();}\n",
    )
    .unwrap();
    if matches!(operation, RepositoryRead::Git(_)) {
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "--all"],
            vec!["commit", "--quiet", "-m", "owned fixture"],
        ] {
            let o = Command::new("C:/Program Files/Git/mingw64/bin/git.exe")
                .env_clear()
                .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "NUL")
                .env("GIT_CONFIG_SYSTEM", "NUL")
                .args([
                    "-c",
                    "core.hooksPath=NUL",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                ])
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        }
    }
    let mut store = LocalStore::open(
        &d.path().join("store"),
        StoreKey::from_bytes([119; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut t: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    t.task_id = "task:readonly-role".into();
    t.workspace_ref = "workspace:readonly".into();
    t.selected_profile_ids = vec!["melissa.code.repository-analyst".into()];
    t.allowed_resource_ids = vec![t.workspace_ref.clone()];
    t.authorization_refs = vec!["auth:readonly".into()];
    t.allowed_effects = vec!["workspace.read".into(), "git.read".into()];
    t.limits.max_disk_bytes = 256 * 1024 * 1024;
    t.limits.max_output_bytes = 32 * 1024 * 1024;
    t.limits.max_wall_time_ms = 120_000;
    store.journal_mut().create_task(&t).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = store.journal().task(&t.task_id).unwrap().record.version;
        store.transition_task(&t.task_id, v, state, None).unwrap();
    }
    let p = RepositoryReadPolicy {
        task_id: t.task_id,
        profile_id: t.selected_profile_ids[0].clone(),
        principal_id: "principal:readonly".into(),
        resource_id: t.workspace_ref,
        authorization_ref: "auth:readonly".into(),
        expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120_000,
        limits: support::limits(),
        operations: vec![operation],
    };
    let peer = store.connect().unwrap();
    let r = Repository::open_for_git(&root, Limits::default()).unwrap();
    let disp = RepositoryReadDispatcher::new(r, store, catalog(), p).unwrap();
    (d, disp, peer)
}
fn refs() -> RepositoryRead {
    RepositoryRead::Analysis(AnalysisQuery::Lsp {
        method: LspMethod::References,
        path: "lib.rs".into(),
        line: 0,
        character: 8,
        include_declaration: false,
        root_modules: vec!["lib.rs".into()],
    })
}
fn context(id: &str) -> ToolContext {
    ToolContext {
        task_id: "task:readonly-role".into(),
        profile_id: "melissa.code.repository-analyst".into(),
        run_id: "run:readonly".into(),
        request_id: format!("request:{id}"),
        invocation_id: format!("inv:{id}"),
        attempt_id: format!("attempt:{id}"),
        generation: 1,
    }
}
fn call(name: &str, op: &RepositoryRead) -> ToolCall {
    ToolCall {
        id: "call:readonly".into(),
        name: name.into(),
        arguments: serde_json::to_string(op).unwrap(),
    }
}
#[tokio::test]
async fn readonly_analyst_runs_real_git_log_and_semantic_lsp_without_raw_process_or_write_authority()
 {
    for (name, op) in [
        (
            "git_log",
            RepositoryRead::Git(GitOperation::Log { max_entries: 2 }),
        ),
        ("code_lsp_references", refs()),
    ] {
        let (d, mut dispatcher, peer) = fixture(op.clone());
        let initial = fs::read(d.path().join("repo/lib.rs")).unwrap();
        let profile = &catalog().profiles["melissa.code.repository-analyst"];
        assert!(!profile.tool_ids.iter().any(|t| t == "process.exec"));
        assert!(
            !peer
                .journal()
                .task("task:readonly-role")
                .unwrap()
                .contract
                .allowed_effects
                .iter()
                .any(|e| e.starts_with("process.") || e.contains("patch"))
        );
        let defs = dispatcher.definitions();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].definition.name, name);
        let c = call(name, &op);
        dispatcher.validate_call(&c).unwrap();
        let result = dispatcher
            .execute(c, context("read"), Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert!(result.success, "{}", result.content);
        assert!(!result.requires_reconciliation);
        let v: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(v["task_accepted"], false);
        if name == "code_lsp_references" {
            assert_eq!(v["locations"].as_array().unwrap().len(), 1);
        } else {
            let bytes: Vec<u8> = serde_json::from_value(v["stdout_bytes"].clone()).unwrap();
            assert!(String::from_utf8_lossy(&bytes).contains("owned fixture"));
        }
        assert_eq!(fs::read(d.path().join("repo/lib.rs")).unwrap(), initial);
        assert_eq!(
            peer.journal().invocation("inv:read").unwrap().state,
            InvocationState::Succeeded
        );
        let proposal: serde_json::Value = serde_json::from_slice(
            &peer
                .get_artifact("task:readonly-role", "inv:read:read-proposal")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(proposal["raw_process_authority"], false);
        let permit = proposal["permit_id"].as_str().unwrap();
        let admitted = peer.journal().permit_admission(permit).unwrap();
        assert_eq!(admitted.principal_id, "principal:readonly");
        assert_eq!(admitted.profile_id, "melissa.code.repository-analyst");
        assert_ne!(admitted.tool_id, "process.exec");
        peer.integrity_check().unwrap();
    }
}
#[tokio::test]
async fn readonly_service_denies_argument_profile_injection_and_respects_shared_active_attempt_quota()
 {
    let (_d, mut dispatcher, mut peer) = fixture(refs());
    let mut c = call("code_lsp_references", &refs());
    c.arguments = r#"{"service":"analysis","operation":{"executable":"/bin/sh"}}"#.into();
    assert!(dispatcher.validate_call(&c).is_err());
    c.name = "process_exec".into();
    assert!(dispatcher.validate_call(&c).is_err());
    let mut ctx = context("wrong-profile");
    ctx.profile_id = "melissa.code.implementer".into();
    assert!(
        dispatcher
            .execute(
                call("code_lsp_references", &refs()),
                ctx,
                Arc::new(AtomicBool::new(false))
            )
            .await
            .is_err()
    );
    let t = "task:readonly-role";
    let v = peer.journal().task(t).unwrap().record.version;
    peer.journal_mut()
        .propose_invocation(
            &InvocationRequest {
                invocation_id: "inv:peer".into(),
                task_id: t.into(),
                tool_id: "git.status".into(),
                arguments: serde_json::json!({"fixture":"prepared peer"}),
                idempotency_key: None,
                generation: 1,
            },
            v,
        )
        .unwrap();
    let v = peer.journal().task(t).unwrap().record.version;
    peer.journal_mut()
        .authorize_invocation("inv:peer", v, 0)
        .unwrap();
    let v = peer.journal().task(t).unwrap().record.version;
    peer.journal_mut()
        .begin_attempt("inv:peer", "attempt:peer", v, 1, 1)
        .unwrap();
    assert!(
        dispatcher
            .execute(
                call("code_lsp_references", &refs()),
                context("quota"),
                Arc::new(AtomicBool::new(false))
            )
            .await
            .is_err()
    );
    assert!(peer.journal().attempt("attempt:quota").is_err());
    assert!(
        peer.get_artifact(t, "attempt:quota:container-identity")
            .is_err()
    );
}
#[tokio::test]
async fn readonly_worker_evidence_failure_is_unknown_and_blocks_further_reads() {
    let (_d, mut dispatcher, mut peer) = fixture(refs());
    peer.put_artifact(
        &ArtifactRequest {
            artifact_id: "inv:unknown:read-worker-report".into(),
            task_id: "task:readonly-role".into(),
            content_type: "application/json".into(),
            logical_type: "owned_fault_fixture".into(),
            schema_version: "fixture/v1".into(),
            retain_until_ms: 0,
            legal_hold: true,
        },
        b"occupied",
    )
    .unwrap();
    let r = dispatcher
        .execute(
            call("code_lsp_references", &refs()),
            context("unknown"),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(r.requires_reconciliation);
    assert!(!r.success);
    assert_eq!(
        peer.journal().invocation("inv:unknown").unwrap().state,
        InvocationState::OutcomeUnknown
    );
    assert!(dispatcher.definitions().is_empty());
}
#[tokio::test]
async fn readonly_worker_cancellation_observes_the_durable_owned_container_identity() {
    let (_d, mut dispatcher, peer) = fixture(refs());
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let job = tokio::spawn(async move {
        dispatcher
            .execute(
                call("code_lsp_references", &refs()),
                context("cancel"),
                signal,
            )
            .await
    });
    let start = std::time::Instant::now();
    loop {
        if peer
            .artifact_metadata("task:readonly-role", "attempt:cancel:container-identity")
            .is_ok()
        {
            break;
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(15));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    cancel.store(true, Ordering::Release);
    let r = job.await.unwrap().unwrap();
    assert!(r.cancelled, "{}", r.content);
    assert!(!r.requires_reconciliation);
    assert_eq!(
        peer.journal().invocation("inv:cancel").unwrap().state,
        InvocationState::Cancelled
    );
    peer.integrity_check().unwrap();
}
