#![cfg(windows)]
use melissa_build_test::{Outcome, RustExecution, RustOperation, RustPlan};
use melissa_container_executor::ContainerLimits;
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker,
    container_policy::container_execution_digest, policy::*, unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_repository::{Limits, Repository};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::atomic::AtomicBool,
};

const MANIFEST: &str = "[package]\nname=\"code06_fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n";
const LOCK: &str = "version = 4\n\n[[package]]\nname = \"code06_fixture\"\nversion = \"0.0.0\"\n";
fn no() -> AtomicBool {
    AtomicBool::new(false)
}
fn limits() -> ContainerLimits {
    ContainerLimits {
        wall_time_ms: 90_000,
        cpu_time_ms: 60_000,
        cpu_rate_basis_points: 10_000,
        memory_bytes: 1024 * 1024 * 1024,
        disk_bytes: 128 * 1024 * 1024,
        output_bytes: 4 * 1024 * 1024,
        max_processes: 128,
        export_bytes: 8 * 1024 * 1024,
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    repo: Repository,
    broker: ContainerBroker,
    task: TaskContractV1,
    plan: RustPlan,
}
impl Fixture {
    fn new(
        body: &str,
        op: RustOperation,
        extra: &[(&str, &str)],
        envelope: ContainerLimits,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(root.join("src")).unwrap();
        for (path, value) in [
            ("Cargo.toml", MANIFEST),
            ("Cargo.lock", LOCK),
            ("src/lib.rs", body),
            ("dirty.txt", "preserve this user's work\r\n"),
        ]
        .into_iter()
        .chain(extra.iter().copied())
        {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, value).unwrap();
        }
        let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
        let source = repo.snapshot(&no()).unwrap();
        let plan = RustPlan::prepare(&repo, &source, op, envelope.clone(), &no()).unwrap();
        let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/code01/wire/task-contract-v1.json"
        ))
        .unwrap();
        task.task_id = "task:code06-rust".into();
        task.goal = "Verify the first isolated Rust build/test adapter".into();
        task.workspace_ref = "workspace:code06-rust".into();
        task.input_snapshot_digest = source.digest;
        task.selected_profile_ids = vec!["melissa.code.dependency-build".into()];
        task.allowed_resource_ids = vec![task.workspace_ref.clone()];
        task.authorization_refs = vec!["auth:code06-rust".into()];
        task.allowed_effects = vec![
            "workspace.read".into(),
            "process.execute_scoped".into(),
            "workspace.apply_patch_scoped".into(),
        ];
        task.limits.max_wall_time_ms = 120_000;
        task.limits.max_disk_bytes = 256 * 1024 * 1024;
        task.limits.max_output_bytes = 32 * 1024 * 1024;
        let mut store = LocalStore::open(
            &dir.path().join("evidence"),
            StoreKey::from_bytes([129; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        store.journal_mut().create_task(&task).unwrap();
        for state in [
            TaskState::Planned,
            TaskState::Queued,
            TaskState::Leased,
            TaskState::Running,
        ] {
            let v = store.journal().task(&task.task_id).unwrap().record.version;
            store
                .transition_task(&task.task_id, v, state, None)
                .unwrap();
        }
        let policy = HostPolicy {
            revision: "policy:code06-rust:1".into(),
            revocation_epoch: 1,
            issuer: "host:code06-rust".into(),
            audience: "executor:container".into(),
            key_id: "new-session".into(),
            max_permit_lifetime_ms: 120_000,
            ceiling: ProcessLimits {
                wall_time_ms: 120_000,
                cpu_time_ms: 90_000,
                cpu_rate_basis_points: 10000,
                cpu_mode: CpuLimitMode::MonitoredTotal,
                memory_bytes: 1024 * 1024 * 1024,
                disk_bytes: 256 * 1024 * 1024,
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
            allowed_env_names: BTreeSet::new(),
            grants: BTreeMap::new(),
            control_grants: BTreeMap::new(),
            revoked_authorization_refs: BTreeSet::new(),
            revoked_permit_ids: BTreeSet::new(),
            revoked_nonces: BTreeSet::new(),
        };
        let broker = ContainerBroker::new(
            store,
            Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
            task.workspace_ref.clone(),
            policy,
        )
        .unwrap();
        let mut policy = broker.policy_control().snapshot().unwrap();
        let now = unix_ms().unwrap();
        policy.grants.insert(
            "auth:code06-rust".into(),
            AuthorityGrant {
                authorization_ref: "auth:code06-rust".into(),
                task_id: task.task_id.clone(),
                task_digest: authenticated_digest(&task).unwrap(),
                principal_id: "principal:code06-rust".into(),
                profile_id: task.selected_profile_ids[0].clone(),
                resource_id: task.workspace_ref.clone(),
                process_digest: container_execution_digest(
                    plan.request(),
                    &plan.snapshot().digest().unwrap(),
                )
                .unwrap(),
                allow_monitored_disk: false,
                allow_monitored_cpu: true,
                allowed_effects: task.allowed_effects.iter().cloned().collect(),
                not_before_unix_ms: now.saturating_sub(100),
                expires_at_unix_ms: now + 120_000,
            },
        );
        broker.policy_control().replace(policy).unwrap();
        Self {
            _dir: dir,
            repo,
            broker,
            task,
            plan,
        }
    }
    fn permit(&self) -> melissa_execution_broker::container_policy::SignedContainerPermit {
        let n = unix_ms().unwrap();
        self.broker
            .issue_permit(
                &self.task.task_id,
                self.plan.request().clone(),
                self.plan.snapshot(),
                PermitRequest {
                    permit_id: "permit:code06-rust".into(),
                    nonce: "nonce:code06-rust".into(),
                    principal_id: "principal:code06-rust".into(),
                    profile_id: self.task.selected_profile_ids[0].clone(),
                    resource_id: self.task.workspace_ref.clone(),
                    authorization_ref: "auth:code06-rust".into(),
                    not_before_unix_ms: n,
                    expires_at_unix_ms: n + 90_000,
                },
            )
            .unwrap()
    }
    fn run(&mut self) -> RustExecution {
        let p = self.permit();
        self.plan
            .execute(
                &self.repo,
                &mut self.broker,
                &self.task.task_id,
                &p,
                &identity(),
                &no(),
            )
            .unwrap()
    }
}
fn identity() -> InvocationIdentity {
    InvocationIdentity {
        invocation_id: "inv:code06-rust".into(),
        attempt_id: "attempt:code06-rust".into(),
        generation: 1,
        idempotency_key: None,
    }
}
fn assert_outcome(r: &RustExecution, expected: Outcome) {
    assert_eq!(
        r.report.outcome,
        expected,
        "{}",
        serde_json::to_string_pretty(&r.report).unwrap()
    );
    assert!(!r.report.task_completed && !r.report.protected_acceptance);
    assert!(!r.execution.requires_reconciliation);
}

#[test]
fn actual_rust_metadata_build_and_check_preserve_sources_and_bind_encrypted_raw_logs() {
    for op in [RustOperation::Build, RustOperation::Check] {
        let mut f = Fixture::new("pub fn sum(a:i32,b:i32)->i32 { a+b }\n", op, &[], limits());
        let r = f.run();
        assert_outcome(&r, Outcome::Passed);
        assert!(r.report.host_source_current && r.report.worker_source_unchanged);
        assert!(r.report.rustc_version.as_ref().unwrap().contains("1.98.1"));
        assert_eq!(r.report.raw_logs.len(), 4);
        for log in &r.report.raw_logs {
            assert_eq!(
                f.broker
                    .store()
                    .get_artifact(&f.task.task_id, log.stdout_artifact_id.as_ref().unwrap())
                    .unwrap(),
                log.stdout
            );
            assert_eq!(
                f.broker
                    .store()
                    .get_artifact(&f.task.task_id, log.stderr_artifact_id.as_ref().unwrap())
                    .unwrap(),
                log.stderr
            );
        }
        let saved = f
            .broker
            .store()
            .get_artifact(&f.task.task_id, r.report_artifact_id.as_ref().unwrap())
            .unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(saved["source_snapshot_digest"], f.plan.source().digest);
        assert_eq!(saved["protected_acceptance"], false);
        assert_eq!(
            std::fs::read(f.repo.root_path().join("dirty.txt")).unwrap(),
            b"preserve this user's work\r\n"
        );
        assert!(!f.repo.root_path().join("target").exists());
        assert_eq!(
            f.broker
                .store()
                .journal()
                .task(&f.task.task_id)
                .unwrap()
                .record
                .state,
            TaskState::Running
        );
        f.broker.store().integrity_check().unwrap();
    }
}
#[test]
fn actual_compiler_failure_keeps_first_error_code_file_line_and_full_raw_output() {
    let mut f = Fixture::new(
        "pub fn broken()->u32 {\n    \"not an integer\"\n}\n",
        RustOperation::Check,
        &[],
        limits(),
    );
    let r = f.run();
    assert_outcome(&r, Outcome::Failed);
    let d = r.report.first_error.as_ref().unwrap();
    assert_eq!(d.code.as_deref(), Some("E0308"));
    assert!(
        d.spans
            .iter()
            .any(|s| s.file == "src/lib.rs" && s.line == 2 && s.source_bound)
    );
    let raw = &r.report.raw_logs.last().unwrap().stdout;
    assert!(String::from_utf8_lossy(raw).contains("mismatched types"));
}
#[test]
fn actual_discovery_runs_unit_and_integration_binaries_twice_without_stale_build_cache() {
    let mut f = Fixture::new(
        "pub fn sum(a:i32,b:i32)->i32{a+b}\n#[test] fn unit(){assert_eq!(sum(2,3),5);}\n",
        RustOperation::Test { repetitions: 2 },
        &[(
            "tests/public_api.rs",
            "#[test] fn public_api(){assert_eq!(code06_fixture::sum(3,4),7);}\n",
        )],
        limits(),
    );
    let r = f.run();
    assert_outcome(&r, Outcome::Passed);
    assert_eq!(r.report.discovered_tests, 2);
    assert_eq!(r.report.counts.passed, 4);
    assert_eq!(r.report.test_runs.len(), 4);
    assert_eq!(r.report.worker_reported_artifacts.len(), 2);
    assert!(
        r.report
            .worker_reported_artifacts
            .iter()
            .all(|a| a.worker_reported_sha256.len() == 64)
    );
}
#[test]
fn actual_zero_tests_and_ignored_tests_never_become_passing_test_evidence() {
    for (body, expected) in [
        ("pub fn empty(){}\n", Outcome::NoTests),
        (
            "#[test] #[ignore=\"needs external service\"] fn skipped(){panic!();}\n",
            Outcome::Skipped,
        ),
    ] {
        let mut f = Fixture::new(body, RustOperation::Test { repetitions: 1 }, &[], limits());
        let r = f.run();
        assert_outcome(&r, expected);
        assert_eq!(r.report.counts.passed, 0);
    }
}
#[test]
fn actual_failed_then_passing_repetition_is_flaky_and_preserves_both_results() {
    let body = "#[test] fn stateful(){let p=\".flake-marker\";if !std::path::Path::new(p).exists(){std::fs::write(p,b\"first\").unwrap();panic!(\"first run fails\");}}\n";
    let mut f = Fixture::new(body, RustOperation::Test { repetitions: 2 }, &[], limits());
    let r = f.run();
    assert_outcome(&r, Outcome::Flaky);
    assert_eq!(r.report.counts.failed, 1);
    assert_eq!(r.report.counts.passed, 1);
    assert!(!f.repo.root_path().join(".flake-marker").exists());
}
#[test]
fn actual_missing_components_and_offline_dependencies_are_explicit_failures() {
    for op in [RustOperation::Clippy, RustOperation::FormatCheck] {
        let mut f = Fixture::new("pub fn fine(){}\n", op, &[], limits());
        let r = f.run();
        assert_outcome(&r, Outcome::MissingComponent);
    }
    let manifest = format!("{MANIFEST}\n[dependencies]\nmelissa_never_cached_fixture=\"=0.0.1\"\n");
    let mut f = Fixture::new(
        "pub fn fine(){}\n",
        RustOperation::Build,
        &[("Cargo.toml", &manifest)],
        limits(),
    );
    let r = f.run();
    assert_outcome(&r, Outcome::MissingDependency);
    assert_eq!(r.report.raw_logs.len(), 3);
}
#[test]
fn actual_output_limit_is_incomplete_with_preserved_partial_raw_logs() {
    let mut l = limits();
    l.output_bytes = 32 * 1024;
    let mut f = Fixture::new(
        "#[test] fn noisy(){panic!(\"{}\",\"x\".repeat(100000));}\n",
        RustOperation::Test { repetitions: 1 },
        &[],
        l,
    );
    let r = f.run();
    assert_outcome(&r, Outcome::Incomplete);
    assert!(r.report.truncated);
    assert!(
        r.report
            .raw_logs
            .iter()
            .any(|s| s.stage.starts_with("test:"))
    );
}
#[test]
fn source_and_permit_changes_are_rejected_before_dispatch_and_cancel_never_passes() {
    let mut f = Fixture::new("pub fn fine(){}\n", RustOperation::Build, &[], limits());
    let permit = f.permit();
    std::fs::write(
        f.repo.root_path().join("src/lib.rs"),
        "pub fn user_edited(){}\n",
    )
    .unwrap();
    assert!(
        f.plan
            .execute(
                &f.repo,
                &mut f.broker,
                &f.task.task_id,
                &permit,
                &identity(),
                &no()
            )
            .is_err()
    );
    assert!(
        f.broker
            .store()
            .journal()
            .invocation("inv:code06-rust")
            .is_err()
    );
    let mut f = Fixture::new("pub fn fine(){}\n", RustOperation::Build, &[], limits());
    let mut permit = f.permit();
    permit.binding.request.argv.push("injected".into());
    assert!(
        f.plan
            .execute(
                &f.repo,
                &mut f.broker,
                &f.task.task_id,
                &permit,
                &identity(),
                &no()
            )
            .is_err()
    );
    assert!(
        f.broker
            .store()
            .journal()
            .invocation("inv:code06-rust")
            .is_err()
    );
    let permit = f.permit();
    assert!(
        f.plan
            .execute(
                &f.repo,
                &mut f.broker,
                &f.task.task_id,
                &permit,
                &identity(),
                &AtomicBool::new(true)
            )
            .is_err()
    );
    assert!(
        f.broker
            .store()
            .journal()
            .invocation("inv:code06-rust")
            .is_err()
    );
}
#[test]
fn source_config_toolchain_reserved_paths_and_invalid_repetitions_are_not_commands() {
    for name in [
        ".cargo/config.toml",
        "nested/.cargo/config",
        "rust-toolchain.toml",
        ".melissa-code06/driver.py",
        ".melissa-code06-target/a",
    ] {
        let f = Fixture::new("pub fn fine(){}\n", RustOperation::Build, &[], limits());
        let path = f.repo.root_path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "untrusted").unwrap();
        let source = f.repo.snapshot(&no()).unwrap();
        assert!(
            RustPlan::prepare(&f.repo, &source, RustOperation::Build, limits(), &no()).is_err()
        );
    }
    let f = Fixture::new("pub fn fine(){}\n", RustOperation::Build, &[], limits());
    let source = f.repo.snapshot(&no()).unwrap();
    for repetitions in [0, 17] {
        assert!(
            RustPlan::prepare(
                &f.repo,
                &source,
                RustOperation::Test { repetitions },
                limits(),
                &no()
            )
            .is_err()
        );
    }
    let mut altered = source.clone();
    altered.files[0].digest =
        "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(RustPlan::prepare(&f.repo, &altered, RustOperation::Build, limits(), &no()).is_err());
    assert!(
        serde_json::from_value::<RustOperation>(
            serde_json::json!({"operation":"build","argv":["injected"]})
        )
        .is_err()
    );
    for name in ["build", "check", "clippy", "format_check"] {
        assert!(
            serde_json::from_value::<RustOperation>(
                serde_json::json!({"operation":name,"argv":["injected"]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RustOperation>(serde_json::json!({"operation":name})).is_ok()
        );
    }
    assert!(
        serde_json::from_value::<RustOperation>(
            serde_json::json!({"operation":"test","repetitions":1,"command":"injected"})
        )
        .is_err()
    );
}

#[test]
fn source_changed_after_dispatch_cannot_receive_the_old_builds_passing_result() {
    let mut f = Fixture::new("pub fn original(){}\n", RustOperation::Build, &[], limits());
    let monitor = f.broker.store().connect().unwrap();
    let path = f.repo.root_path().join("src/lib.rs");
    let writer = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while monitor.journal().invocation("inv:code06-rust").is_err() {
            assert!(start.elapsed().as_secs() < 30, "dispatch not observed");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::write(path, "pub fn user_edit_during_build(){}\n").unwrap();
    });
    let r = f.run();
    writer.join().unwrap();
    assert_outcome(&r, Outcome::SourceChanged);
    assert!(!r.report.host_source_current);
    assert!(r.report.worker_source_unchanged);
    assert_eq!(
        std::fs::read(f.repo.root_path().join("src/lib.rs")).unwrap(),
        b"pub fn user_edit_during_build(){}\n"
    );
}

#[test]
fn actual_repeated_failure_stays_failed_and_custom_harness_is_not_accepted() {
    let mut f = Fixture::new(
        "#[test] fn bad(){assert_eq!(2+2,5);}\n",
        RustOperation::Test { repetitions: 2 },
        &[],
        limits(),
    );
    let r = f.run();
    assert_outcome(&r, Outcome::Failed);
    assert_eq!(r.report.counts.failed, 2);
    assert_eq!(r.report.counts.passed, 0);
    let manifest = format!("{MANIFEST}\n[lib]\nharness=false\n");
    let mut f = Fixture::new(
        "pub fn fake(){}\n",
        RustOperation::Test { repetitions: 1 },
        &[("Cargo.toml", &manifest)],
        limits(),
    );
    let r = f.run();
    assert_outcome(&r, Outcome::InvalidOutput);
    assert!(
        r.report
            .protocol_error
            .as_deref()
            .unwrap()
            .contains("custom test harness unsupported")
    );
    assert!(r.report.raw_logs.is_empty());
}

#[test]
fn post_dispatch_evidence_failure_does_not_rerun_or_complete_the_task() {
    let mut f = Fixture::new("pub fn fine(){}\n", RustOperation::Build, &[], limits());
    f.broker
        .store_mut()
        .put_artifact(
            &melissa_local_store::ArtifactRequest {
                artifact_id: "attempt:code06-rust:build-log:0:stdout".into(),
                task_id: f.task.task_id.clone(),
                content_type: "application/octet-stream".into(),
                logical_type: "fixture.preexisting".into(),
                schema_version: "fixture/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            b"preexisting evidence must not be overwritten",
        )
        .unwrap();
    let permit = f.permit();
    let result = f.plan.execute(
        &f.repo,
        &mut f.broker,
        &f.task.task_id,
        &permit,
        &identity(),
        &no(),
    );
    assert!(matches!(
        result,
        Err(melissa_build_test::Error::AfterDispatch(_))
    ));
    assert!(
        f.broker
            .store()
            .journal()
            .invocation("inv:code06-rust")
            .is_ok()
    );
    assert_eq!(
        f.broker
            .store()
            .get_artifact(&f.task.task_id, "attempt:code06-rust:build-log:0:stdout")
            .unwrap(),
        b"preexisting evidence must not be overwritten"
    );
    assert!(
        f.plan
            .execute(
                &f.repo,
                &mut f.broker,
                &f.task.task_id,
                &permit,
                &identity(),
                &no()
            )
            .is_err()
    );
    assert_eq!(
        f.broker
            .store()
            .journal()
            .task(&f.task.task_id)
            .unwrap()
            .record
            .state,
        TaskState::Running
    );
}
