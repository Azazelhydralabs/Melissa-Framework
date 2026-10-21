#![cfg(windows)]
use melissa_core_contracts::{
    InvocationState, TaskState,
    catalog::Catalog,
    wire::{EffectStatus, ObservationStatus, TaskContractV1},
};
use melissa_execution_broker::{Broker, BrokerError, InvocationIdentity, policy::*, unix_ms};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey, journal::AttemptState};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};
use tempfile::TempDir;

const TASK: &str = "task:broker";
const RESOURCE: &str = "workspace:broker";

struct Fixture {
    broker: Broker,
    spec: ProcessSpec,
    _dir: TempDir,
    workspace: PathBuf,
    executable: PathBuf,
}
fn limits() -> ProcessLimits {
    ProcessLimits {
        wall_time_ms: 5_000,
        cpu_time_ms: 3_000,
        cpu_rate_basis_points: 10000,
        cpu_mode: CpuLimitMode::MonitoredTotal,
        memory_bytes: 128 * 1024 * 1024,
        disk_bytes: 64 * 1024 * 1024,
        disk_mode: DiskLimitMode::Monitored,
        output_bytes: 65_536,
        max_processes: 8,
        network: NetworkPolicy::Deny,
    }
}
fn fixture(mode: &str) -> Fixture {
    fixture_config(mode, StoreConfig::default())
}
fn fixture_config(mode: &str, config: StoreConfig) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let executable = dir.path().join("probe.exe");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // A real isolated PE fixture; copy removes Cargo's shared hard-link identity.
    fs::copy(
        project.join("target/debug/melissa-executor-probe.exe"),
        &executable,
    )
    .expect("build melissa-executor-probe first with scripts/verify-code03.ps1");
    let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/code01/wire/task-contract-v1.json"
    )))
    .unwrap();
    task.task_id = TASK.into();
    task.workspace_ref = RESOURCE.into();
    task.selected_profile_ids = vec![
        "melissa.code.implementer".into(),
        "melissa.code.debugger".into(),
    ];
    task.allowed_resource_ids = vec![RESOURCE.into()];
    task.authorization_refs = vec![
        "auth:broker".into(),
        "auth:inspect".into(),
        "auth:cancel".into(),
    ];
    task.allowed_effects = vec![
        "process.execute_scoped".into(),
        "workspace.apply_patch_scoped".into(),
        "process.inspect_owned".into(),
        "process.cancel_owned".into(),
    ];
    task.limits.max_disk_bytes = 128 * 1024 * 1024;
    task.limits.max_output_bytes = 1_048_576;
    let mut store = LocalStore::open(
        &dir.path().join("store"),
        StoreKey::from_bytes([46; 32]),
        config,
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
    let mut ceiling = limits();
    ceiling.wall_time_ms = 60_000;
    ceiling.cpu_time_ms = 60_000;
    ceiling.output_bytes = 1_048_576;
    let policy = HostPolicy {
        revision: "policy:broker:1".into(),
        revocation_epoch: 1,
        issuer: "host:broker".into(),
        audience: "executor:generic".into(),
        key_id: "host-session-overridden".into(),
        max_permit_lifetime_ms: 60_000,
        ceiling,
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: false,
            memory: true,
            disk_quota: false,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: true,
        allow_monitored_cpu: true,
        allowed_env_names: BTreeSet::from([
            "MELISSA_VISIBLE".into(),
            "MELISSA_TREE_MARKERS".into(),
        ]),
        grants: BTreeMap::new(),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    };
    let broker = Broker::new(
        store,
        Catalog::load(&project).unwrap(),
        workspace.clone(),
        RESOURCE.into(),
        policy,
    )
    .unwrap();
    let spec = ProcessSpec {
        schema_version: "melissa.process-exec/v2".into(),
        executable: executable.to_str().unwrap().into(),
        argv: vec![mode.into()],
        cwd: ".".into(),
        env: BTreeMap::from([("MELISSA_VISIBLE".into(), "explicit-only".into())]),
        limits: limits(),
        effects: vec![
            "process.execute_scoped".into(),
            "workspace.apply_patch_scoped".into(),
        ],
        worker_type: "generic".into(),
    };
    Fixture {
        broker,
        spec,
        _dir: dir,
        workspace,
        executable,
    }
}
fn permit(f: &Fixture, id: &str, lifetime: u64) -> SignedPermit {
    try_permit(f, id, lifetime).unwrap()
}
fn try_permit(f: &Fixture, id: &str, lifetime: u64) -> Result<SignedPermit, BrokerError> {
    let pinned = f.broker.resolve(&f.spec).unwrap();
    let task = &f.broker.store().journal().task(TASK).unwrap().contract;
    let now = unix_ms().unwrap();
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy.grants.insert(
        "auth:broker".into(),
        AuthorityGrant {
            authorization_ref: "auth:broker".into(),
            task_id: TASK.into(),
            task_digest: authenticated_digest(task).unwrap(),
            principal_id: "principal:host".into(),
            profile_id: "melissa.code.implementer".into(),
            resource_id: RESOURCE.into(),
            process_digest: pinned.resolved().resolved_digest().unwrap(),
            allow_monitored_disk: true,
            allow_monitored_cpu: true,
            allowed_effects: f.spec.effects.iter().cloned().collect(),
            not_before_unix_ms: now.saturating_sub(100),
            expires_at_unix_ms: now + 60_000,
        },
    );
    f.broker.policy_control().replace(policy).unwrap();
    f.broker.issue_permit(
        TASK,
        &pinned,
        PermitRequest {
            permit_id: format!("permit:{id}"),
            nonce: format!("nonce:{id}"),
            principal_id: "principal:host".into(),
            profile_id: "melissa.code.implementer".into(),
            resource_id: RESOURCE.into(),
            authorization_ref: "auth:broker".into(),
            not_before_unix_ms: now,
            expires_at_unix_ms: now + lifetime,
        },
    )
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
fn real_process_admission_observation_and_cas_are_one_owned_chain() {
    let mut f = fixture("ok");
    let signed = permit(&f, "success", 30_000);
    let result = f
        .broker
        .execute(TASK, &signed, &identity("success"), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        result.observation.status,
        ObservationStatus::Success,
        "{result:?}"
    );
    assert_eq!(result.observation.effect_status, EffectStatus::Observed);
    let report = result.report.unwrap();
    assert!(
        report.process_was_appcontainer
            && report.win32k_system_calls_disabled
            && report.tree_confirmed_stopped
            && report.profile_removed
            && report.acl_restored
    );
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        "ok:explicit-only"
    );
    assert!(String::from_utf8_lossy(&report.stderr).contains("stderr-ok"));
    assert_eq!(
        fs::read_to_string(f.workspace.join("inside.txt")).unwrap(),
        "owned workspace"
    );
    assert!(!result.requires_reconciliation);
    assert_eq!(result.observation.metrics["task_accepted"], false);
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
        f.broker
            .inspect_invocation(TASK, "inv:success")
            .unwrap()
            .state,
        InvocationState::Succeeded
    );
    assert!(
        f.broker
            .inspect_invocation("task:other", "inv:success")
            .is_err()
    );
    let obs = f
        .broker
        .store()
        .get_artifact(TASK, &result.result_artifact_id)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&obs).unwrap()["status"],
        "success"
    );
    for id in &result.observation.artifact_refs {
        assert!(f.broker.store().get_artifact(TASK, id).is_ok());
        assert!(f.broker.store().get_artifact("task:other", id).is_err());
    }
    assert_eq!(
        f.broker.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    f.broker.store().integrity_check().unwrap();
    assert!(
        f.broker
            .execute(TASK, &signed, &identity("replay"), &AtomicBool::new(false))
            .is_err()
    );
    assert!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:replay")
            .is_err()
    );
    assert_eq!(
        f.broker
            .inspect_invocation(TASK, "inv:replay")
            .unwrap()
            .state,
        InvocationState::Cancelled
    );
}

#[test]
fn exact_nested_cwd_is_used_by_the_real_process() {
    let mut f = fixture("ok");
    fs::create_dir(f.workspace.join("nested")).unwrap();
    f.spec.cwd = "nested".into();
    let signed = permit(&f, "cwd", 30_000);
    let result = f
        .broker
        .execute(TASK, &signed, &identity("cwd"), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        result.observation.status,
        ObservationStatus::Success,
        "{result:?}"
    );
    assert!(f.workspace.join("nested/inside.txt").is_file());
    assert!(!f.workspace.join("inside.txt").exists());
}

#[test]
fn durable_revocation_prevents_launch_and_cleans_proposal() {
    let mut f = fixture("ok");
    let signed = permit(&f, "revoked", 30_000);
    f.broker
        .revoke_permit("permit:revoked", "host withdrew grant")
        .unwrap();
    assert!(
        f.broker
            .execute(TASK, &signed, &identity("revoked"), &AtomicBool::new(false))
            .is_err()
    );
    assert!(!f.workspace.join("inside.txt").exists());
    assert!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:revoked")
            .is_err()
    );
    assert_eq!(
        f.broker
            .inspect_invocation(TASK, "inv:revoked")
            .unwrap()
            .state,
        InvocationState::Cancelled
    );
    f.broker.store().integrity_check().unwrap();
}

#[test]
fn mac_tamper_and_expiry_have_no_process_effect() {
    let mut f = fixture("ok");
    let signed = permit(&f, "tamper", 30_000);
    let mut altered = signed.clone();
    altered.binding.process.spec.argv = vec!["disk".into()];
    assert!(
        f.broker
            .execute(TASK, &altered, &identity("tamper"), &AtomicBool::new(false))
            .is_err()
    );
    let expired = permit(&f, "expired", 20);
    std::thread::sleep(Duration::from_millis(40));
    assert!(
        f.broker
            .execute(
                TASK,
                &expired,
                &identity("expired"),
                &AtomicBool::new(false)
            )
            .is_err()
    );
    assert!(!f.workspace.join("inside.txt").exists());
}

#[test]
fn pinned_image_cannot_be_changed_and_stale_image_cannot_use_old_permit() {
    let mut f = fixture("ok");
    let pinned = f.broker.resolve(&f.spec).unwrap();
    assert!(fs::write(&f.executable, b"changed").is_err());
    assert!(fs::rename(&f.executable, f.executable.with_extension("renamed")).is_err());
    drop(pinned);
    let signed = permit(&f, "stale", 30_000);
    fs::write(&f.executable, b"changed executable").unwrap();
    assert!(
        f.broker
            .execute(TASK, &signed, &identity("stale"), &AtomicBool::new(false))
            .is_err()
    );
    assert!(!f.workspace.join("inside.txt").exists());
}

#[test]
fn ambiguous_paths_and_hardlinks_are_rejected() {
    let f = fixture("ok");
    for cwd in [
        "../escape",
        "nested/../escape",
        "C:\\Windows",
        "file:stream",
        "NUL",
        "a.",
        "a ",
        "CONIN$",
        "COM¹",
    ] {
        let mut spec = f.spec.clone();
        spec.cwd = cwd.into();
        assert!(f.broker.resolve(&spec).is_err(), "accepted {cwd}");
    }
    fs::hard_link(&f.executable, f.executable.with_extension("link.exe")).unwrap();
    assert!(f.broker.resolve(&f.spec).is_err());
}

#[test]
fn untrusted_json_cannot_hide_duplicate_environment_or_permit_fields() {
    use melissa_execution_broker::{parse_process_request, parse_signed_permit};
    let f = fixture("ok");
    assert_eq!(
        HOST_EXECUTION_CONTRACT_VERSION,
        melissa_windows_executor::ENVIRONMENT_CONTRACT
    );
    let raw = serde_json::to_string(&f.spec).unwrap();
    assert_eq!(parse_process_request(raw.as_bytes()).unwrap(), f.spec);
    let duplicate = raw.replace(
        "\"MELISSA_VISIBLE\":\"explicit-only\"",
        "\"MELISSA_VISIBLE\":\"a\",\"MELISSA_VISIBLE\":\"b\"",
    );
    assert_ne!(duplicate, raw);
    assert!(parse_process_request(duplicate.as_bytes()).is_err());
    let mut unknown: serde_json::Value = serde_json::from_str(&raw).unwrap();
    unknown["grant"] = serde_json::json!(true);
    assert!(parse_process_request(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(parse_process_request(&vec![b' '; 512 * 1024 + 1]).is_err());
    let signed = permit(&f, "json", 30_000);
    let raw = serde_json::to_string(&signed).unwrap();
    assert!(parse_signed_permit(raw.as_bytes()).is_ok());
    let duplicate = raw.replacen(
        "\"permit_id\":",
        "\"permit_id\":\"hidden\",\"permit_id\":",
        1,
    );
    assert!(parse_signed_permit(duplicate.as_bytes()).is_err());
    assert!(!f.workspace.join("inside.txt").exists());
}

#[test]
fn policy_rollback_cannot_resurrect_unused_permits() {
    let mut f = fixture("ok");
    let signed = permit(&f, "old-policy", 30_000);
    let control = f.broker.policy_control();
    let original = control.snapshot().unwrap();
    let mut changed = original.clone();
    changed.revision = "policy:changed".into();
    control.replace(changed).unwrap();
    let current = control.snapshot().unwrap();
    assert!(current.revocation_epoch > original.revocation_epoch);
    assert!(control.replace(original.clone()).is_err());
    let mut restored = original;
    restored.revocation_epoch = current.revocation_epoch;
    control.replace(restored).unwrap();
    assert!(
        f.broker
            .execute(
                TASK,
                &signed,
                &identity("old-policy"),
                &AtomicBool::new(false)
            )
            .is_err()
    );
    let mut revoked = control.snapshot().unwrap();
    revoked.revoked_permit_ids.insert("permit:sticky".into());
    control.replace(revoked).unwrap();
    let mut cleared = control.snapshot().unwrap();
    cleared.revoked_permit_ids.clear();
    assert!(control.replace(cleared).is_err());
    assert!(!f.workspace.join("inside.txt").exists());
    let mut exhausted = control.snapshot().unwrap();
    exhausted.revocation_epoch = u64::MAX;
    control.replace(exhausted).unwrap();
    let frozen = control.snapshot().unwrap();
    let mut changed = frozen.clone();
    changed.revision = "cannot-wrap-epoch".into();
    assert!(control.replace(changed).is_err());
    assert_eq!(
        control.snapshot().unwrap().digest().unwrap(),
        frozen.digest().unwrap()
    );
}

#[test]
fn strict_capacity_and_false_capability_claims_fail_closed() {
    let mut f = fixture("ok");
    assert!(try_permit(&f, "supported", 1000).is_ok());
    f.spec.limits.disk_mode = DiskLimitMode::Strict;
    assert!(matches!(
        try_permit(&f, "strict-disk", 1000),
        Err(BrokerError::Policy(PolicyError::Unsupported(_)))
    ));
    f.spec.limits.disk_mode = DiskLimitMode::Monitored;
    f.spec.limits.cpu_mode = CpuLimitMode::StrictTotal;
    assert!(matches!(
        try_permit(&f, "strict-cpu", 1000),
        Err(BrokerError::Policy(PolicyError::Unsupported(_)))
    ));
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy.enforcement.disk_quota = true;
    assert!(f.broker.policy_control().replace(policy).is_err());
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy.enforcement.cpu_time = true;
    assert!(f.broker.policy_control().replace(policy).is_err());
    assert!(!f.workspace.join("inside.txt").exists());
}

#[test]
fn real_timeout_and_output_limit_are_typed_failures_without_task_completion() {
    for (mode, category) in [("sleep", "timeout"), ("burst", "output_limit")] {
        let mut f = fixture(mode);
        f.spec.limits.wall_time_ms = 250;
        f.spec.limits.output_bytes = 4096;
        let signed = permit(&f, mode, 30_000);
        let result = f
            .broker
            .execute(TASK, &signed, &identity(mode), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(result.observation.error_category.as_deref(), Some(category));
        assert_ne!(result.observation.status, ObservationStatus::Success);
        assert!(!result.requires_reconciliation);
        assert_eq!(result.observation.metrics["requires_output_review"], true);
        assert!(result.report.unwrap().tree_confirmed_stopped);
        assert_eq!(
            f.broker.store().journal().task(TASK).unwrap().record.state,
            TaskState::Running
        );
    }
}

#[test]
fn pre_cancel_has_no_launch_and_a_known_cancelled_record() {
    let mut f = fixture("ok");
    let signed = permit(&f, "pre-cancel", 30_000);
    let result = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("pre-cancel"),
            &AtomicBool::new(true),
        )
        .unwrap();
    assert_eq!(result.observation.status, ObservationStatus::Cancelled);
    assert_eq!(result.observation.effect_status, EffectStatus::NotStarted);
    assert!(!result.requires_reconciliation);
    assert!(!f.workspace.join("inside.txt").exists());
    assert_eq!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:pre-cancel")
            .unwrap()
            .state,
        AttemptState::Cancelled
    );
}

#[test]
fn policy_revocation_during_real_execution_stops_and_persists_tree() {
    let mut f = fixture("tree");
    f.spec.env.insert("MELISSA_TREE_MARKERS".into(), "1".into());
    f.spec.limits.wall_time_ms = 10_000;
    let signed = permit(&f, "live-revoke", 30_000);
    let control = f.broker.policy_control();
    let workspace = f.workspace.clone();
    let revoke = std::thread::spawn(move || {
        let pids = wait_for_tree(&workspace);
        let mut policy = control.snapshot().unwrap();
        policy
            .revoked_permit_ids
            .insert("permit:live-revoke".into());
        control.replace(policy).unwrap();
        pids
    });
    let result = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("live-revoke"),
            &AtomicBool::new(false),
        )
        .unwrap();
    let pids = revoke.join().unwrap();
    assert_eq!(result.observation.status, ObservationStatus::Cancelled);
    assert_eq!(
        result.observation.error_category.as_deref(),
        Some("permit_revoked")
    );
    assert!(result.report.unwrap().tree_confirmed_stopped);
    assert_stopped(&pids);
    assert_eq!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:live-revoke")
            .unwrap()
            .state,
        AttemptState::Cancelled
    );
    f.broker.store().integrity_check().unwrap();
}

fn wait_for_tree(workspace: &Path) -> Vec<u32> {
    let start = std::time::Instant::now();
    let names = ["tree-root.pid", "tree-branch.pid", "tree-leaf.pid"];
    loop {
        let pids: Option<Vec<u32>> = names
            .iter()
            .map(|name| {
                fs::read_to_string(workspace.join(name))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            })
            .collect();
        if let Some(pids) = pids {
            return pids;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "real process tree did not signal startup"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn assert_stopped(pids: &[u32]) {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    assert_eq!(pids.len(), 3);
    for pid in pids {
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, *pid) };
        if handle.is_null() {
            assert_eq!(
                unsafe { GetLastError() },
                ERROR_INVALID_PARAMETER,
                "PID inaccessible instead of stopped"
            );
        } else {
            let state = unsafe { WaitForSingleObject(handle, 0) };
            unsafe {
                CloseHandle(handle);
            };
            assert_eq!(state, WAIT_OBJECT_0, "process {pid} survived");
        }
    }
}

#[test]
fn durable_revocation_watcher_stops_an_already_running_process_tree() {
    let mut f = fixture("tree");
    f.spec.env.insert("MELISSA_TREE_MARKERS".into(), "1".into());
    f.spec.limits.wall_time_ms = 10_000;
    let signed = permit(&f, "db-revoke", 30_000);
    let mut revoker = f.broker.store().connect().unwrap();
    let workspace = f.workspace.clone();
    let thread = std::thread::spawn(move || {
        let pids = wait_for_tree(&workspace);
        revoker
            .journal_mut()
            .revoke_permit(
                "permit:db-revoke",
                "host withdrew active permission",
                unix_ms().unwrap(),
            )
            .unwrap();
        pids
    });
    let result = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("db-revoke"),
            &AtomicBool::new(false),
        )
        .unwrap();
    let pids = thread.join().unwrap();
    assert_eq!(result.observation.status, ObservationStatus::Cancelled);
    assert_eq!(
        result.observation.error_category.as_deref(),
        Some("permit_revoked")
    );
    assert_stopped(&pids);
    assert!(result.report.unwrap().tree_confirmed_stopped);
    f.broker.store().integrity_check().unwrap();
}

#[test]
fn permit_expiry_stops_real_processes_and_is_distinct_from_task_timeout() {
    let mut f = fixture("tree");
    f.spec.env.insert("MELISSA_TREE_MARKERS".into(), "1".into());
    f.spec.limits.wall_time_ms = 10_000;
    let signed = permit(&f, "live-expiry", 2_000);
    let workspace = f.workspace.clone();
    let thread = std::thread::spawn(move || wait_for_tree(&workspace));
    let result = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("live-expiry"),
            &AtomicBool::new(false),
        )
        .unwrap();
    let pids = thread.join().unwrap();
    assert_eq!(
        result.observation.error_category.as_deref(),
        Some("permit_expired")
    );
    assert_ne!(result.observation.status, ObservationStatus::Success);
    assert_stopped(&pids);
    assert!(!result.requires_reconciliation);
}

#[test]
fn orphan_cleanup_cannot_be_mistaken_for_successful_completion() {
    let mut f = fixture("orphan");
    let signed = permit(&f, "orphan", 30_000);
    let result = f
        .broker
        .execute(TASK, &signed, &identity("orphan"), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(result.observation.status, ObservationStatus::Failed);
    assert_eq!(
        result.observation.error_category.as_deref(),
        Some("orphan_descendants")
    );
    let report = result.report.unwrap();
    assert!(report.tree_confirmed_stopped && report.descendant_cleanup_required);
    assert_eq!(result.observation.metrics["requires_output_review"], true);
}

#[test]
fn evidence_storage_failure_after_execution_is_not_safe_to_retry() {
    let config = StoreConfig {
        max_blob_bytes: 512,
        max_cas_bytes: 4096,
        ..StoreConfig::default()
    };
    let mut f = fixture_config("ok", config);
    let signed = permit(&f, "store-full", 30_000);
    let error = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("store-full"),
            &AtomicBool::new(false),
        )
        .unwrap_err();
    assert!(matches!(error, BrokerError::AfterDispatch(_)));
    assert!(f.workspace.join("inside.txt").is_file());
    assert_eq!(
        f.broker
            .store()
            .journal()
            .attempt("attempt:store-full")
            .unwrap()
            .state,
        AttemptState::OutcomeUnknown
    );
    assert_ne!(
        f.broker.store().journal().task(TASK).unwrap().record.state,
        TaskState::Completed
    );
}

#[test]
fn new_host_session_rejects_previously_signed_authority() {
    let f = fixture("ok");
    let signed = permit(&f, "session", 30_000);
    let policy = f.broker.policy_control().snapshot().unwrap();
    let store = f.broker.store().connect().unwrap();
    let catalog = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut other =
        Broker::new(store, catalog, f.workspace.clone(), RESOURCE.into(), policy).unwrap();
    assert!(
        other
            .execute(TASK, &signed, &identity("session"), &AtomicBool::new(false))
            .is_err()
    );
    assert!(!f.workspace.join("inside.txt").exists());
}

fn install_controls(f: &Fixture, invocation: &str) {
    use melissa_execution_broker::control_policy::{ControlGrant, ControlTool};
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
                invocation_id: invocation.into(),
                generation: 1,
                not_before_unix_ms: now.saturating_sub(100),
                expires_at_unix_ms: now + 60_000,
            },
        );
    }
    f.broker.policy_control().replace(policy).unwrap();
}
fn control_call(
    service: &mut melissa_execution_broker::process_control::ProcessControlService,
    tool: melissa_execution_broker::control_policy::ControlTool,
    invocation: &str,
    id: &str,
) -> melissa_execution_broker::process_control::ProcessControlOutcome {
    use melissa_execution_broker::control_policy::{ControlTool, ProcessControlRequest};
    let now = unix_ms().unwrap();
    let signed = service
        .issue_permit(
            ProcessControlRequest {
                schema_version: "melissa.process-control/v1".into(),
                tool,
                task_id: TASK.into(),
                invocation_id: invocation.into(),
                generation: 1,
                resource_id: RESOURCE.into(),
            },
            PermitRequest {
                permit_id: format!("permit:control:{id}"),
                nonce: format!("nonce:control:{id}"),
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
                expires_at_unix_ms: now + 5_000,
            },
        )
        .unwrap();
    let outcome = service.execute(&signed).unwrap();
    assert!(service.execute(&signed).is_err());
    outcome
}

#[test]
fn signed_inspect_and_cancel_control_a_running_tree_with_durable_receipts() {
    use melissa_execution_broker::control_policy::{ControlTool, ProcessControlRequest};
    let mut f = fixture("tree");
    f.spec.env.insert("MELISSA_TREE_MARKERS".into(), "1".into());
    f.spec.limits.wall_time_ms = 10_000;
    install_controls(&f, "inv:controlled");
    let signed = permit(&f, "controlled", 30_000);
    let mut service = f.broker.control_service().unwrap();
    let workspace = f.workspace.clone();
    let thread = std::thread::spawn(move || {
        let pids = wait_for_tree(&workspace);
        let status = control_call(
            &mut service,
            ControlTool::Inspect,
            "inv:controlled",
            "inspect-running",
        );
        assert_eq!(status.target.state, InvocationState::Running);
        assert!(!status.termination_confirmed);
        assert!(!status.cancellation_requested);
        let now = unix_ms().unwrap();
        let wrong = ProcessControlRequest {
            schema_version: "melissa.process-control/v1".into(),
            tool: ControlTool::Cancel,
            task_id: TASK.into(),
            invocation_id: "inv:controlled".into(),
            generation: 2,
            resource_id: RESOURCE.into(),
        };
        assert!(
            service
                .issue_permit(
                    wrong,
                    PermitRequest {
                        permit_id: "permit:wrong-generation".into(),
                        nonce: "nonce:wrong-generation".into(),
                        principal_id: "principal:host".into(),
                        profile_id: "melissa.code.debugger".into(),
                        resource_id: RESOURCE.into(),
                        authorization_ref: "auth:cancel".into(),
                        not_before_unix_ms: now,
                        expires_at_unix_ms: now + 1000
                    }
                )
                .is_err()
        );
        let receipt = control_call(
            &mut service,
            ControlTool::Cancel,
            "inv:controlled",
            "cancel-running",
        );
        assert!(receipt.cancellation_requested);
        assert!(!receipt.termination_confirmed);
        assert!(
            service
                .stored_receipt("permit:control:cancel-running")
                .is_ok()
        );
        (pids, service)
    });
    let result = f
        .broker
        .execute(
            TASK,
            &signed,
            &identity("controlled"),
            &AtomicBool::new(false),
        )
        .unwrap();
    let (pids, mut service) = thread.join().unwrap();
    assert_stopped(&pids);
    assert_eq!(result.observation.status, ObservationStatus::Cancelled);
    assert_eq!(
        result.observation.error_category.as_deref(),
        Some("cancelled")
    );
    let status = control_call(
        &mut service,
        ControlTool::Inspect,
        "inv:controlled",
        "inspect-stopped",
    );
    assert!(status.termination_confirmed && status.cancellation_requested);
    assert_eq!(status.target.state, InvocationState::Cancelled);
    assert!(
        f.broker
            .store()
            .get_artifact(TASK, &status.artifact_id)
            .is_ok()
    );
    f.broker.store().integrity_check().unwrap();
}
