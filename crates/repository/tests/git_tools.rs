//! Actual reviewed agent Git bindings through the existing isolated broker.
#![cfg(windows)]
use melissa_container_executor::ContainerLimits;
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    container_broker::ContainerBroker, container_policy::container_execution_digest, policy::*,
    unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use melissa_repository::{
    Limits, Repository,
    git::{GitOperation, GitPlan},
    tools::{GitDispatcher, GitDispatcherConfig, ReviewedGitTool},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, atomic::AtomicBool},
};
const IMAGE: &str = "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";
fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let o = Command::new("C:/Program Files/Git/mingw64/bin/git.exe")
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .args([
            "--no-optional-locks",
            "-c",
            "core.hooksPath=NUL",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    o.stdout
}
fn fixture() -> (tempfile::TempDir, Repository, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--quiet"]);
    fs::write(root.join("a.txt"), b"committed\n").unwrap();
    fs::write(root.join(".gitignore"), b"ignored.txt\n").unwrap();
    git(&root, &["add", "--", "a.txt", ".gitignore"]);
    git(&root, &["commit", "--quiet", "-m", "initial fixture"]);
    let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();
    fs::write(root.join("a.txt"), b"staged change\n").unwrap();
    git(&root, &["add", "--", "a.txt"]);
    fs::write(root.join("a.txt"), b"user unstaged change\n").unwrap();
    fs::write(root.join("untracked.txt"), b"keep me\n").unwrap();
    fs::write(root.join("ignored.txt"), b"ignored\n").unwrap();
    let repo = Repository::open_for_git(&root, Limits::default()).unwrap();
    (temp, repo, head)
}
fn envelope() -> ContainerLimits {
    ContainerLimits {
        wall_time_ms: 60_000,
        cpu_time_ms: 30_000,
        cpu_rate_basis_points: 10000,
        memory_bytes: 512 * 1024 * 1024,
        disk_bytes: 64 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        max_processes: 128,
        export_bytes: 16 * 1024 * 1024,
    }
}
fn plan(repo: &Repository, op: GitOperation) -> GitPlan {
    let c = AtomicBool::new(false);
    let source = repo.snapshot(&c).unwrap();
    GitPlan::prepare(repo, &source, &op, IMAGE, envelope(), &c).unwrap()
}
fn reviewed_broker(plan: &GitPlan) -> (tempfile::TempDir, ContainerBroker, TaskContractV1) {
    let temp = tempfile::tempdir().unwrap();
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    task.task_id = "task:git-worker".into();
    task.workspace_ref = "workspace:git-worker".into();
    task.input_snapshot_digest = plan.snapshot.digest().unwrap();
    task.selected_profile_ids = vec!["melissa.code.implementer".into()];
    task.allowed_resource_ids = vec![task.workspace_ref.clone()];
    task.authorization_refs = vec!["auth:git-worker".into()];
    task.allowed_effects = vec![
        "process.execute_scoped".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    task.limits.max_wall_time_ms = 120_000;
    task.limits.max_disk_bytes = 128 * 1024 * 1024;
    task.limits.max_output_bytes = 32 * 1024 * 1024;
    let mut store = LocalStore::open(
        &temp.path().join("evidence"),
        StoreKey::from_bytes([74; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    store.journal_mut().create_task(&task).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = store.journal().task(&task.task_id).unwrap().record.version;
        store.transition_task(&task.task_id, v, next, None).unwrap();
    }
    let policy = HostPolicy {
        revision: "policy:git-worker:1".into(),
        revocation_epoch: 1,
        issuer: "host:git-worker".into(),
        audience: "executor:container".into(),
        key_id: "new-session".into(),
        max_permit_lifetime_ms: 120_000,
        ceiling: ProcessLimits {
            wall_time_ms: 120_000,
            cpu_time_ms: 60_000,
            cpu_rate_basis_points: 10000,
            cpu_mode: CpuLimitMode::MonitoredTotal,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            disk_mode: DiskLimitMode::Strict,
            output_bytes: 32 * 1024 * 1024,
            max_processes: 128,
            network: NetworkPolicy::Deny,
        },
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: false,
            memory: true,
            disk_quota: true,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: false,
        allow_monitored_cpu: true,
        allowed_env_names: plan.request.env.keys().cloned().collect(),
        grants: BTreeMap::new(),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    };
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let broker = ContainerBroker::new(
        store,
        Catalog::load(&project).unwrap(),
        task.workspace_ref.clone(),
        policy,
    )
    .unwrap();
    let n = unix_ms().unwrap();
    let mut p = broker.policy_control().snapshot().unwrap();
    p.grants.insert(
        "auth:git-worker".into(),
        AuthorityGrant {
            authorization_ref: "auth:git-worker".into(),
            task_id: task.task_id.clone(),
            task_digest: authenticated_digest(&task).unwrap(),
            principal_id: "principal:host".into(),
            profile_id: task.selected_profile_ids[0].clone(),
            resource_id: task.workspace_ref.clone(),
            process_digest: container_execution_digest(
                &plan.request,
                &plan.snapshot.digest().unwrap(),
            )
            .unwrap(),
            allow_monitored_disk: false,
            allow_monitored_cpu: true,
            allowed_effects: task.allowed_effects.iter().cloned().collect(),
            not_before_unix_ms: n.saturating_sub(100),
            expires_at_unix_ms: n + 120_000,
        },
    );
    broker.policy_control().replace(p).unwrap();
    (temp, broker, task)
}

fn config(task: &TaskContractV1) -> GitDispatcherConfig {
    GitDispatcherConfig {
        task_id: task.task_id.clone(),
        profile_id: task.selected_profile_ids[0].clone(),
        principal_id: "principal:host".into(),
        resource_id: task.workspace_ref.clone(),
        expires_at_ms: unix_ms().unwrap() + 120_000,
    }
}
fn context(task: &TaskContractV1) -> ToolContext {
    ToolContext {
        task_id: task.task_id.clone(),
        profile_id: task.selected_profile_ids[0].clone(),
        run_id: "run:git-tools".into(),
        request_id: "request:git-tools".into(),
        invocation_id: "inv:git-binding".into(),
        attempt_id: "attempt:git-binding".into(),
        generation: 1,
    }
}
fn wire(op: &GitOperation) -> &'static str {
    match op {
        GitOperation::Status => "git_status",
        GitOperation::Diff { .. } => "git_diff",
        GitOperation::Log { .. } => "git_log",
        GitOperation::WorktreeList => "git_worktree_list",
        GitOperation::WorktreeCreate { .. } => "git_worktree_create",
    }
}

#[tokio::test]
async fn actual_reviewed_git_agent_routes_execute_all_supported_operations() {
    let (_t, r, head) = fixture();
    let source_root = r.root_path().to_path_buf();
    let initial = r.snapshot(&AtomicBool::new(false)).unwrap();
    let old_index = fs::read(source_root.join(".git/index")).unwrap();
    drop(r);
    for op in [
        GitOperation::Status,
        GitOperation::Diff { staged: false },
        GitOperation::Diff { staged: true },
        GitOperation::Log { max_entries: 3 },
        GitOperation::WorktreeList,
        GitOperation::WorktreeCreate {
            name: "agent-reviewed".into(),
            commit: head.clone(),
        },
    ] {
        let r = Repository::open_for_git(&source_root, Limits::default()).unwrap();
        let source = r.snapshot(&AtomicBool::new(false)).unwrap();
        let p = plan(&r, op.clone());
        let (_e, b, t) = reviewed_broker(&p);
        let peer = b.store().connect().unwrap();
        let broker = Arc::new(Mutex::new(b));
        let mut dispatcher = GitDispatcher::new(
            r,
            broker,
            config(&t),
            vec![ReviewedGitTool {
                operation: op.clone(),
                source,
                plan: p,
                authorization_ref: "auth:git-worker".into(),
            }],
        )
        .unwrap();
        let defs = dispatcher.definitions();
        assert_eq!(defs.len(), 1);
        melissa_model_gateway::schema::validate_schema(&defs[0].definition.parameters).unwrap();
        let c = ToolCall {
            id: "call:git".into(),
            name: wire(&op).into(),
            arguments: serde_json::to_string(&op).unwrap(),
        };
        dispatcher.validate_call(&c).unwrap();
        let result = dispatcher
            .execute(c, context(&t), Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert!(result.success, "{}", result.content);
        assert!(!result.requires_reconciliation);
        let v: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(v["task_accepted"], false);
        assert!(!result.artifact_refs.is_empty());
        peer.integrity_check().unwrap();
        drop(dispatcher);
        let r = Repository::open_for_git(&source_root, Limits::default()).unwrap();
        assert_eq!(r.snapshot(&AtomicBool::new(false)).unwrap(), initial);
        assert_eq!(fs::read(source_root.join(".git/index")).unwrap(), old_index);
        assert!(!source_root.join(".git/worktrees").exists());
    }
}
#[tokio::test]
async fn git_agent_binding_rejects_unreviewed_arguments_context_and_stale_source() {
    let (_t, r, _) = fixture();
    let root = r.root_path().to_path_buf();
    let source = r.snapshot(&AtomicBool::new(false)).unwrap();
    let p = plan(&r, GitOperation::Status);
    let (_e, b, t) = reviewed_broker(&p);
    let peer = b.store().connect().unwrap();
    let mut d = GitDispatcher::new(
        r,
        Arc::new(Mutex::new(b)),
        config(&t),
        vec![ReviewedGitTool {
            operation: GitOperation::Status,
            source,
            plan: p,
            authorization_ref: "auth:git-worker".into(),
        }],
    )
    .unwrap();
    for args in [
        r#"{"operation":"status","executable":"/bin/sh"}"#,
        r#"{"operation":"log","max_entries":1}"#,
        r#"{"operation":"status","operation":"status"}"#,
    ] {
        assert!(
            d.validate_call(&ToolCall {
                id: "c".into(),
                name: "git_status".into(),
                arguments: args.into()
            })
            .is_err()
        );
    }
    let c = ToolCall {
        id: "c".into(),
        name: "git_status".into(),
        arguments: r#"{"operation":"status"}"#.into(),
    };
    let mut ctx = context(&t);
    ctx.profile_id = "melissa.code.reviewer".into();
    assert!(
        d.execute(c.clone(), ctx, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    fs::write(root.join("a.txt"), b"user changed since review").unwrap();
    assert!(
        d.execute(c, context(&t), Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert!(peer.journal().invocation("inv:git-binding").is_err());
}
