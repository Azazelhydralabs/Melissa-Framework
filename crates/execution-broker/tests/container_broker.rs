#![cfg(windows)]
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_core_contracts::{
    InvocationState, TaskState,
    catalog::Catalog,
    wire::{EffectStatus, ObservationStatus, TaskContractV1},
};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker,
    container_policy::container_execution_digest, policy::*, unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey, journal::AttemptState};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
const IMAGE: &str = "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";
const TASK: &str = "task:container-broker";
const RESOURCE: &str = "container-workspace:fixture";
struct Fixture {
    broker: ContainerBroker,
    request: ContainerRequest,
    snapshot: Snapshot,
    _dir: tempfile::TempDir,
}
fn fixture(script: &str) -> Fixture {
    fixture_with_controls(script, false)
}
fn fixture_with_controls(script: &str, controls: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    let snapshot = Snapshot {
        files: BTreeMap::from([("message.txt".into(), b"owned input".to_vec())]),
    };
    task.task_id = TASK.into();
    task.workspace_ref = RESOURCE.into();
    task.input_snapshot_digest = snapshot.digest().unwrap();
    task.selected_profile_ids = vec!["melissa.code.implementer".into()];
    task.allowed_resource_ids = vec![RESOURCE.into()];
    task.authorization_refs = vec!["auth:container".into()];
    task.allowed_effects = vec![
        "process.execute_scoped".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    if controls {
        task.selected_profile_ids
            .push("melissa.code.debugger".into());
        task.authorization_refs
            .extend(["auth:inspect".into(), "auth:cancel".into()]);
        task.allowed_effects.extend([
            "process.inspect_owned".into(),
            "process.cancel_owned".into(),
        ]);
    }
    task.limits.max_wall_time_ms = 120_000;
    task.limits.max_disk_bytes = 128 * 1024 * 1024;
    task.limits.max_output_bytes = 40 * 1024 * 1024;
    let mut store = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([62; 32]),
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
        let version = store.journal().task(TASK).unwrap().record.version;
        store
            .journal_mut()
            .transition_task(TASK, version, next, None)
            .unwrap();
    }
    let policy = HostPolicy {
        revision: "policy:container:1".into(),
        revocation_epoch: 1,
        issuer: "host:container".into(),
        audience: "executor:container".into(),
        key_id: "replaced-session".into(),
        max_permit_lifetime_ms: 120_000,
        ceiling: ProcessLimits {
            wall_time_ms: 120_000,
            cpu_time_ms: 60_000,
            cpu_rate_basis_points: 10000,
            cpu_mode: CpuLimitMode::MonitoredTotal,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            disk_mode: DiskLimitMode::Strict,
            output_bytes: 40 * 1024 * 1024,
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
        RESOURCE.into(),
        policy,
    )
    .unwrap();
    let request = ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: IMAGE.into(),
        executable: "/bin/sh".into(),
        argv: vec!["-c".into(), script.into()],
        cwd: ".".into(),
        env: BTreeMap::new(),
        limits: ContainerLimits {
            wall_time_ms: 60_000,
            cpu_time_ms: 30_000,
            cpu_rate_basis_points: 10000,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            output_bytes: 65536,
            max_processes: 128,
            export_bytes: 32 * 1024 * 1024,
        },
    };
    Fixture {
        broker,
        request,
        snapshot,
        _dir: dir,
    }
}
fn permit(
    f: &Fixture,
    id: &str,
) -> melissa_execution_broker::container_policy::SignedContainerPermit {
    let now = unix_ms().unwrap();
    let task = f.broker.store().journal().task(TASK).unwrap().contract;
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy.grants.insert(
        "auth:container".into(),
        AuthorityGrant {
            authorization_ref: "auth:container".into(),
            task_id: TASK.into(),
            task_digest: authenticated_digest(&task).unwrap(),
            principal_id: "principal:host".into(),
            profile_id: "melissa.code.implementer".into(),
            resource_id: RESOURCE.into(),
            process_digest: container_execution_digest(&f.request, &f.snapshot.digest().unwrap())
                .unwrap(),
            allow_monitored_disk: false,
            allow_monitored_cpu: true,
            allowed_effects: task.allowed_effects.iter().cloned().collect(),
            not_before_unix_ms: now.saturating_sub(100),
            expires_at_unix_ms: now + 120_000,
        },
    );
    f.broker.policy_control().replace(policy).unwrap();
    f.broker
        .issue_permit(
            TASK,
            f.request.clone(),
            &f.snapshot,
            PermitRequest {
                permit_id: format!("permit:{id}"),
                nonce: format!("nonce:{id}"),
                principal_id: "principal:host".into(),
                profile_id: "melissa.code.implementer".into(),
                resource_id: RESOURCE.into(),
                authorization_ref: "auth:container".into(),
                not_before_unix_ms: now,
                expires_at_unix_ms: now + 120_000,
            },
        )
        .unwrap()
}
fn identity(id: &str) -> InvocationIdentity {
    InvocationIdentity {
        invocation_id: format!("inv:{id}"),
        attempt_id: format!("attempt:{id}"),
        generation: 1,
        idempotency_key: None,
    }
}

#[test]
fn strict_container_runs_through_real_permit_admission_and_owned_archive_observation() {
    let mut f = fixture(
        "test \"$(cat message.txt)\" = 'owned input'; printf 'owned result' > result.txt; printf 'container-ok'",
    );
    let signed = permit(&f, "success");
    let outcome = f
        .broker
        .execute(
            TASK,
            &signed,
            &f.snapshot,
            &identity("success"),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(
        outcome.observation.status,
        ObservationStatus::Success,
        "{outcome:?}"
    );
    assert!(!outcome.requires_reconciliation);
    let report = outcome.report.unwrap();
    assert!(
        report.cleanup_confirmed
            && report.tree_confirmed_stopped
            && report.policy_verified
            && report.disk_limit_hard_enforced
            && report.cpu_rate_hard_enforced
    );
    assert_eq!(report.stdout, b"container-ok");
    assert!(
        report
            .archive
            .windows(b"owned result".len())
            .any(|s| s == b"owned result")
    );
    assert_eq!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:success")
            .unwrap()
            .state,
        AttemptState::Succeeded
    );
    assert_eq!(
        f.broker.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    assert_eq!(outcome.observation.metrics["task_accepted"], false);
    for id in &outcome.observation.artifact_refs {
        assert!(f.broker.store().get_artifact(TASK, id).is_ok());
        assert!(f.broker.store().get_artifact("task:other", id).is_err());
    }
    f.broker.store().integrity_check().unwrap();
    assert!(
        f.broker
            .execute(
                TASK,
                &signed,
                &f.snapshot,
                &identity("replay"),
                &AtomicBool::new(false)
            )
            .is_err()
    );
}
#[test]
fn real_rust_project_builds_and_runs_its_tests_inside_the_hard_capacity_backend() {
    let mut f = fixture(
        "/usr/local/cargo/bin/cargo test --offline --manifest-path Cargo.toml -- --nocapture",
    );
    f.snapshot=Snapshot {files:BTreeMap::from([("Cargo.toml".into(),b"[package]\nname=\"code03_acceptance\"\nversion=\"0.1.0\"\nedition=\"2024\"\n".to_vec()),("src/lib.rs".into(),b"pub fn add(a:u32,b:u32)->u32{a+b}\n#[cfg(test)]mod tests{#[test]fn real_behavior(){assert_eq!(super::add(19,23),42);println!(\"CODE03_REAL_RUST_TEST\");}}\n".to_vec())])};
    let signed = permit(&f, "rust-build-test");
    let outcome = f
        .broker
        .execute(
            TASK,
            &signed,
            &f.snapshot,
            &identity("rust-build-test"),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(
        outcome.observation.status,
        ObservationStatus::Success,
        "{outcome:?}"
    );
    let report = outcome.report.unwrap();
    let stdout = String::from_utf8_lossy(&report.stdout);
    assert!(stdout.contains("CODE03_REAL_RUST_TEST") && stdout.contains("1 passed; 0 failed"));
    assert!(report.cleanup_confirmed && report.disk_limit_hard_enforced);
    f.broker.store().integrity_check().unwrap();
}
#[test]
fn changed_snapshot_and_precancel_do_not_run_container_user_code() {
    let mut f = fixture("echo must-not-run");
    let signed = permit(&f, "changed");
    let mut changed = f.snapshot.clone();
    changed
        .files
        .insert("message.txt".into(), b"tampered".to_vec());
    assert!(
        f.broker
            .execute(
                TASK,
                &signed,
                &changed,
                &identity("changed"),
                &AtomicBool::new(false)
            )
            .is_err()
    );
    assert!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:changed")
            .is_err()
    );
    let signed = permit(&f, "pre-cancel");
    let outcome = f
        .broker
        .execute(
            TASK,
            &signed,
            &f.snapshot,
            &identity("pre-cancel"),
            &AtomicBool::new(true),
        )
        .unwrap();
    assert_eq!(outcome.observation.status, ObservationStatus::Cancelled);
    assert_eq!(outcome.observation.effect_status, EffectStatus::NotStarted);
    assert_eq!(
        outcome.observation.error_category.as_deref(),
        Some("cancelled_before_launch")
    );
    assert!(!outcome.requires_reconciliation);
}

#[test]
fn container_ingress_and_route_registry_are_strict_and_never_fallback() {
    use melissa_execution_broker::{
        container_broker::parse_container_request, routes::process_routes,
    };
    let f = fixture("true");
    let raw = serde_json::to_vec(&f.request).unwrap();
    assert_eq!(parse_container_request(&raw).unwrap(), f.request);
    let raw = String::from_utf8(raw).unwrap();
    let duplicate = raw.replacen("\"image_id\":", "\"image_id\":\"hidden\",\"image_id\":", 1);
    assert!(parse_container_request(duplicate.as_bytes()).is_err());
    let mut invalid = f.request;
    invalid.image_id = "rust:latest".into();
    assert!(parse_container_request(&serde_json::to_vec(&invalid).unwrap()).is_err());
    let routes = process_routes();
    assert_eq!(routes["implicit_backend_fallback"], false);
    assert_eq!(routes["routes"].as_array().unwrap().len(), 4);
}

fn docker(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe");
    command
        .args(["--host", "npipe:////./pipe/dockerDesktopLinuxEngine"])
        .args(args)
        .stdin(Stdio::null());
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000);
    command.output().unwrap()
}

#[test]
fn separately_signed_inspect_and_cancel_reach_the_real_container_watcher_and_persist_receipts() {
    use melissa_execution_broker::{
        control_policy::{ControlGrant, ControlTool, ProcessControlRequest},
        process_control::ProcessControlService,
    };
    const INVOCATION: &str = "inv:container-typed-control";
    const ATTEMPT: &str = "attempt:container-typed-control";
    let mut f = fixture_with_controls(
        "printf CODE03_CONTROL_STARTED > control-started; sleep 30 & sleep 30 & wait",
        true,
    );
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    let task = f.broker.store().journal().task(TASK).unwrap().contract;
    let now = unix_ms().unwrap();
    for (auth, tool) in [
        ("auth:inspect", ControlTool::Inspect),
        ("auth:cancel", ControlTool::Cancel),
    ] {
        policy.control_grants.insert(
            auth.into(),
            ControlGrant {
                authorization_ref: auth.into(),
                task_id: TASK.into(),
                task_digest: authenticated_digest(&task).unwrap(),
                principal_id: "principal:host".into(),
                profile_id: "melissa.code.debugger".into(),
                resource_id: RESOURCE.into(),
                tool,
                invocation_id: INVOCATION.into(),
                generation: 1,
                not_before_unix_ms: now.saturating_sub(100),
                expires_at_unix_ms: now + 120_000,
            },
        );
    }
    f.broker.policy_control().replace(policy).unwrap();
    // The complete policy, including independently granted debugger controls,
    // is installed before issuing the execution permit and never replaced live.
    let execution = permit(&f, "container-typed-control");
    let mut service = f.broker.control_service().unwrap();
    let observer = f.broker.store().connect().unwrap();
    let external_cancel = AtomicBool::new(false);
    fn call(
        service: &mut ProcessControlService,
        tool: ControlTool,
        name: &str,
    ) -> (
        melissa_execution_broker::process_control::ProcessControlOutcome,
        melissa_execution_broker::control_policy::SignedControlPermit,
    ) {
        let now = unix_ms().unwrap();
        let signed = service
            .issue_permit(
                ProcessControlRequest {
                    schema_version: "melissa.process-control/v1".into(),
                    tool,
                    task_id: TASK.into(),
                    invocation_id: INVOCATION.into(),
                    generation: 1,
                    resource_id: RESOURCE.into(),
                },
                PermitRequest {
                    permit_id: format!("permit:container-control:{name}"),
                    nonce: format!("nonce:container-control:{name}"),
                    principal_id: "principal:host".into(),
                    profile_id: "melissa.code.debugger".into(),
                    resource_id: RESOURCE.into(),
                    authorization_ref: if tool == ControlTool::Inspect {
                        "auth:inspect"
                    } else {
                        "auth:cancel"
                    }
                    .into(),
                    not_before_unix_ms: now,
                    expires_at_unix_ms: now + 5000,
                },
            )
            .unwrap();
        let result = service.execute(&signed).unwrap();
        assert!(
            service.execute(&signed).is_err(),
            "a control permit must be durably single-use"
        );
        let receipt = service.stored_receipt(&signed.permit.permit_id).unwrap();
        assert_eq!(receipt.nonce, signed.permit.nonce);
        assert_eq!(
            receipt.permit_digest,
            authenticated_digest(&signed).unwrap()
        );
        assert_eq!(receipt.target_invocation_id, INVOCATION);
        assert_eq!(receipt.generation, 1);
        assert_eq!(receipt.resource_id, RESOURCE);
        (result, signed)
    }
    let (outcome, (container_id, cancel_permit)) = std::thread::scope(|scope| {
        let external_ref = &external_cancel;
        let control = scope.spawn(move || {
            struct CancelOnlyOnTestPanic<'a>(&'a AtomicBool);
            impl Drop for CancelOnlyOnTestPanic<'_> {
                fn drop(&mut self) {
                    if std::thread::panicking() {
                        self.0.store(true, std::sync::atomic::Ordering::Release);
                    }
                }
            }
            let _panic_cleanup = CancelOnlyOnTestPanic(external_ref);
            let deadline = Instant::now() + Duration::from_secs(20);
            let container_id = loop {
                assert!(
                    Instant::now() < deadline,
                    "actual container user workload did not start"
                );
                if let Ok(bytes) =
                    observer.get_artifact(TASK, &format!("{ATTEMPT}:container-identity"))
                {
                    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(record["task_id"], TASK);
                    assert_eq!(record["invocation_id"], INVOCATION);
                    assert_eq!(record["attempt_id"], ATTEMPT);
                    assert_eq!(record["generation"], 1);
                    assert_eq!(record["image_id"], IMAGE);
                    let id = record["container_id"].as_str().unwrap();
                    assert_eq!(id.len(), 64);
                    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
                    let marker = docker(&[
                        "exec",
                        "--user",
                        "65534:65534",
                        id,
                        "/bin/cat",
                        "/work/control-started",
                    ]);
                    let peers = docker(&["top", id, "-eo", "pid,uid,args"]);
                    if marker.status.success()
                        && marker.stdout == b"CODE03_CONTROL_STARTED"
                        && peers.status.success()
                        && String::from_utf8_lossy(&peers.stdout)
                            .lines()
                            .filter(|line| {
                                line.split_whitespace().nth(1) == Some("65534")
                                    && line.contains("sleep 30")
                            })
                            .count()
                            >= 2
                    {
                        break id.to_owned();
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            };
            let inspect = call(&mut service, ControlTool::Inspect, "running").0;
            assert_eq!(inspect.target.state, InvocationState::Running);
            assert!(!inspect.termination_confirmed && !inspect.cancellation_requested);
            let (cancel, signed) = call(&mut service, ControlTool::Cancel, "cancel");
            assert!(cancel.cancellation_requested && !cancel.termination_confirmed);
            (container_id, signed)
        });
        let outcome = f
            .broker
            .execute(
                TASK,
                &execution,
                &f.snapshot,
                &identity("container-typed-control"),
                &external_cancel,
            )
            .unwrap();
        (outcome, control.join().unwrap())
    });
    assert!(
        !external_cancel.load(std::sync::atomic::Ordering::Acquire),
        "the durable control receipt, rather than an external test flag, must stop the worker"
    );
    assert_eq!(
        outcome.observation.status,
        ObservationStatus::Cancelled,
        "{outcome:?}"
    );
    assert_eq!(outcome.observation.effect_status, EffectStatus::Observed);
    assert_eq!(
        outcome.observation.error_category.as_deref(),
        Some("cancelled")
    );
    assert!(!outcome.requires_reconciliation);
    let report = outcome.report.unwrap();
    assert_eq!(report.container_id, container_id);
    assert!(report.cleanup_confirmed && report.tree_confirmed_stopped);
    assert!(!docker(&["inspect", &container_id]).status.success());
    assert_eq!(
        f.broker.store().journal().attempt(ATTEMPT).unwrap().state,
        AttemptState::Cancelled
    );
    // A new service/connection sees the persisted consumption and stop state.
    let mut fresh = f.broker.control_service().unwrap();
    let receipt = fresh
        .stored_receipt(&cancel_permit.permit.permit_id)
        .unwrap();
    assert_eq!(
        receipt.permit_digest,
        authenticated_digest(&cancel_permit).unwrap()
    );
    assert!(fresh.execute(&cancel_permit).is_err());
    let stopped = call(&mut fresh, ControlTool::Inspect, "stopped").0;
    assert!(stopped.termination_confirmed && stopped.cancellation_requested);
    assert_eq!(stopped.target.state, InvocationState::Cancelled);
    assert!(
        f.broker
            .store()
            .get_artifact(TASK, &stopped.artifact_id)
            .is_ok()
    );
    f.broker.store().integrity_check().unwrap();
}
