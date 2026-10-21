#![cfg(windows)]
use melissa_container_executor::{ContainerLimits, ContainerReport, TerminationReason};
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker,
    container_policy::container_execution_digest, policy::*, unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_repository::{
    Error, Limits, PatchBroker, PatchPolicy, Repository, archive,
    git::{GitOperation, GitPlan},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
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
fn run(plan: &GitPlan) -> ContainerReport {
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
    let mut broker = ContainerBroker::new(
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
    let permit = broker
        .issue_permit(
            &task.task_id,
            plan.request.clone(),
            &plan.snapshot,
            PermitRequest {
                permit_id: "permit:git-worker".into(),
                nonce: "nonce:git-worker".into(),
                principal_id: "principal:host".into(),
                profile_id: task.selected_profile_ids[0].clone(),
                resource_id: task.workspace_ref.clone(),
                authorization_ref: "auth:git-worker".into(),
                not_before_unix_ms: n,
                expires_at_unix_ms: n + 120_000,
            },
        )
        .unwrap();
    let result = plan
        .execute(
            &mut broker,
            &task.task_id,
            &permit,
            &InvocationIdentity {
                invocation_id: "inv:git-worker".into(),
                attempt_id: "attempt:git-worker".into(),
                generation: 1,
                idempotency_key: None,
            },
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(
        broker
            .store()
            .journal()
            .task(&task.task_id)
            .unwrap()
            .record
            .state,
        TaskState::Running
    );
    assert!(!result.requires_reconciliation);
    let report = result.report.unwrap();
    assert_eq!(report.termination, TerminationReason::Exited);
    assert_eq!(
        report.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    assert!(report.cleanup_confirmed && report.tree_confirmed_stopped && report.policy_verified);
    assert!(!report.output_truncated);
    broker.store().integrity_check().unwrap();
    report
}

#[test]
fn real_isolated_git_status_diff_staged_log_and_source_preservation() {
    let (_temp, repo, head) = fixture();
    let root = repo.root_path();
    let before = git(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    );
    let status = run(&plan(&repo, GitOperation::Status));
    assert_eq!(status.stdout, before);
    let diff = run(&plan(&repo, GitOperation::Diff { staged: false }));
    let text = String::from_utf8(diff.stdout).unwrap();
    assert!(text.contains("-staged change") && text.contains("+user unstaged change"));
    let staged = run(&plan(&repo, GitOperation::Diff { staged: true }));
    let text = String::from_utf8(staged.stdout).unwrap();
    assert!(text.contains("-committed") && text.contains("+staged change"));
    let log = run(&plan(&repo, GitOperation::Log { max_entries: 10 }));
    assert!(log.stdout.starts_with(head.as_bytes()));
    assert!(log.stdout.windows(15).any(|s| s == b"initial fixture"));
    assert_eq!(
        git(
            root,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"]
        ),
        before
    );
    assert_eq!(fs::read(root.join("untracked.txt")).unwrap(), b"keep me\n");
}
#[test]
fn real_git_worktree_is_created_only_in_isolated_worker() {
    let (_temp, repo, head) = fixture();
    let index = fs::read(repo.root_path().join(".git/index")).unwrap();
    let result = run(&plan(
        &repo,
        GitOperation::WorktreeCreate {
            name: "owned-task".into(),
            commit: head.clone(),
        },
    ));
    assert!(String::from_utf8_lossy(&result.stdout).contains(".code05-worktrees/owned-task"));
    assert!(!repo.root_path().join(".code05-worktrees").exists());
    assert!(!repo.root_path().join(".git/worktrees").exists());
    assert_eq!(
        fs::read(repo.root_path().join(".git/index")).unwrap(),
        index
    );
    assert_eq!(
        fs::read(repo.root_path().join("a.txt")).unwrap(),
        b"user unstaged change\n"
    );
}
#[test]
fn unsafe_git_authority_and_external_config_are_not_forwarded() {
    let (_temp, repo, head) = fixture();
    let mut config = fs::read(repo.root_path().join(".git/config")).unwrap();
    config.extend_from_slice(b"\n[include]\n path = /private/secret\n[core]\n fsmonitor = dangerous-command\n[diff]\n external = dangerous-command\n");
    fs::write(repo.root_path().join(".git/config"), config).unwrap();
    let p = plan(&repo, GitOperation::Status);
    let safe = String::from_utf8_lossy(&p.snapshot.files[".git/config"]);
    assert!(!safe.contains("dangerous") && !safe.contains("secret") && !safe.contains("include"));
    let c = AtomicBool::new(false);
    let source = repo.snapshot(&c).unwrap();
    for name in ["../escape", "a/b", "-option", "name;exec"] {
        assert!(
            GitPlan::prepare(
                &repo,
                &source,
                &GitOperation::WorktreeCreate {
                    name: name.into(),
                    commit: head.clone()
                },
                IMAGE,
                envelope(),
                &c
            )
            .is_err()
        );
    }
    assert!(
        GitPlan::prepare(
            &repo,
            &source,
            &GitOperation::WorktreeCreate {
                name: "safe".into(),
                commit: "HEAD;exec".into()
            },
            IMAGE,
            envelope(),
            &c
        )
        .is_err()
    );
    fs::write(
        repo.root_path().join(".git/objects/info/alternates"),
        b"/outside",
    )
    .unwrap();
    assert!(matches!(
        GitPlan::prepare(&repo, &source, &GitOperation::Status, IMAGE, envelope(), &c),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn actual_worker_tar_import_exact_patch_then_real_rust_test_uses_final_snapshot() {
    let (temp, repo, _) = fixture();
    fs::create_dir(repo.root_path().join("src")).unwrap();
    fs::write(
        repo.root_path().join("Cargo.toml"),
        b"[package]\nname=\"code05_owned_chain\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
    )
    .unwrap();
    fs::write(
        repo.root_path().join("src/lib.rs"),
        b"pub fn answer()->u32 { 1 }\n",
    )
    .unwrap();
    let c = AtomicBool::new(false);
    let source = repo.snapshot(&c).unwrap();
    let input = repo.worker_input(&source, &c).unwrap();
    let mut worker = plan(&repo, GitOperation::Status);
    worker.snapshot = input.snapshot;
    worker.request.executable = "/bin/sh".into();
    worker.request.argv=vec!["-c".into(),"printf 'pub fn answer()->u32 { 42 }\\n#[test] fn protected_answer(){assert_eq!(answer(),42);println!(\"CODE05_REAL_FINAL_SOURCE\");}\\n' > src/lib.rs".into()];
    let output = run(&worker);
    assert!(!output.export_truncated);
    let imports = archive::inspect_ustar(&output.archive, repo.limits()).unwrap();
    let selection = repo
        .propose_import(&source, &imports, &["src/lib.rs".into()].into(), &c)
        .unwrap();
    assert!(selection.patch.is_some());
    assert!(!selection.unselected_paths.is_empty());
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    task.task_id = "task:import".into();
    task.workspace_ref = "workspace:import".into();
    task.allowed_resource_ids = vec![task.workspace_ref.clone()];
    task.allowed_effects = vec!["workspace.apply_patch_scoped".into()];
    task.limits.max_disk_bytes = 1024 * 1024;
    task.limits.max_wall_time_ms = 60_000;
    let mut store = LocalStore::open(
        &temp.path().join("patch-evidence"),
        StoreKey::from_bytes([85; 32]),
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
    let policy = PatchPolicy {
        principal_id: "principal:import-fixture".into(),
        task_id: task.task_id.clone(),
        profile_id: task.selected_profile_ids[0].clone(),
        resource_id: task.workspace_ref,
        authorization_ref: task.authorization_refs[0].clone(),
        expires_at_ms: unix_ms().unwrap() + 60_000,
        epoch: 0,
        writable_paths: ["src/lib.rs".into()].into(),
        protected_paths: BTreeSet::new(),
    };
    let receipt = {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let p = b
            .authorize("inv:import", "attempt:import", selection.patch.unwrap())
            .unwrap();
        b.execute(p, &c).unwrap()
    };
    let final_source = repo.snapshot(&c).unwrap();
    let final_input = repo.worker_input(&final_source, &c).unwrap();
    let final_version = repo.read("src/lib.rs").unwrap().0;
    assert_eq!(receipt.files[0].after, final_version);
    assert_eq!(
        format!(
            "blake3:{}",
            blake3::hash(&final_input.snapshot.files["src/lib.rs"]).to_hex()
        ),
        final_version.digest
    );
    worker.snapshot = final_input.snapshot;
    worker.source_snapshot_digest = final_source.digest;
    worker.request.argv = vec![
        "-c".into(),
        "/usr/local/cargo/bin/cargo test --offline --manifest-path Cargo.toml -- --nocapture"
            .into(),
    ];
    let tested = run(&worker);
    assert!(String::from_utf8_lossy(&tested.stdout).contains("CODE05_REAL_FINAL_SOURCE"));
    assert_eq!(
        fs::read(repo.root_path().join("a.txt")).unwrap(),
        b"user unstaged change\n"
    );
    assert!(!repo.root_path().join("target").exists());
    store.integrity_check().unwrap();
}
