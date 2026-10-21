#![allow(dead_code)]
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_execution_broker::{
    container_broker::ContainerBroker, container_policy::container_execution_digest, policy::*,
    unix_ms,
};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_repository::{Limits, PatchPolicy, Repository};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
pub fn task_store(path: &Path, snapshot_digest: Option<String>) -> (LocalStore, TaskContractV1) {
    let mut s = LocalStore::open(
        path,
        StoreKey::from_bytes([112; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut t: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    t.task_id = "task:code05-closeout".into();
    t.workspace_ref = "workspace:closeout".into();
    t.selected_profile_ids = vec!["melissa.code.implementer".into()];
    t.allowed_resource_ids = vec![t.workspace_ref.clone()];
    t.authorization_refs = vec!["auth:closeout".into()];
    t.allowed_effects = vec![
        "workspace.read".into(),
        "workspace.apply_patch_scoped".into(),
        "process.execute_scoped".into(),
    ];
    t.limits.max_disk_bytes = 256 * 1024 * 1024;
    t.limits.max_output_bytes = 32 * 1024 * 1024;
    t.limits.max_wall_time_ms = 120_000;
    if let Some(d) = snapshot_digest {
        t.input_snapshot_digest = d;
    }
    s.journal_mut().create_task(&t).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = s.journal().task(&t.task_id).unwrap().record.version;
        s.transition_task(&t.task_id, v, state, None).unwrap();
    }
    (s, t)
}
pub fn policy(t: &TaskContractV1, paths: &[&str]) -> PatchPolicy {
    PatchPolicy {
        task_id: t.task_id.clone(),
        principal_id: "principal:closeout".into(),
        profile_id: t.selected_profile_ids[0].clone(),
        resource_id: t.workspace_ref.clone(),
        authorization_ref: t.authorization_refs[0].clone(),
        expires_at_ms: unix_ms().unwrap() + 120_000,
        epoch: 0,
        writable_paths: paths.iter().map(|s| s.to_string()).collect(),
        protected_paths: BTreeSet::new(),
    }
}
pub fn fixture(paths: &[&str]) -> (tempfile::TempDir, Repository, LocalStore, PatchPolicy) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let r = Repository::open_for_git(&root, Limits::default()).unwrap();
    let (s, t) = task_store(&d.path().join("store"), None);
    let p = policy(&t, paths);
    (d, r, s, p)
}
pub fn limits() -> ContainerLimits {
    ContainerLimits {
        wall_time_ms: 90_000,
        cpu_time_ms: 60_000,
        cpu_rate_basis_points: 10000,
        memory_bytes: 1024 * 1024 * 1024,
        disk_bytes: 128 * 1024 * 1024,
        output_bytes: 16 * 1024 * 1024,
        max_processes: 128,
        export_bytes: 16 * 1024 * 1024,
    }
}
pub fn container(
    store: LocalStore,
    t: &TaskContractV1,
    request: &ContainerRequest,
    snapshot: &Snapshot,
) -> ContainerBroker {
    let policy = HostPolicy {
        revision: "policy:closeout:1".into(),
        revocation_epoch: 1,
        issuer: "host:closeout".into(),
        audience: "executor:container".into(),
        key_id: "session".into(),
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
        allowed_env_names: request.env.keys().cloned().collect(),
        grants: BTreeMap::new(),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    };
    let b = ContainerBroker::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        t.workspace_ref.clone(),
        policy,
    )
    .unwrap();
    let mut policy = b.policy_control().snapshot().unwrap();
    let n = unix_ms().unwrap();
    policy.grants.insert(
        "auth:closeout".into(),
        AuthorityGrant {
            authorization_ref: "auth:closeout".into(),
            task_id: t.task_id.clone(),
            task_digest: authenticated_digest(t).unwrap(),
            principal_id: "principal:closeout".into(),
            profile_id: t.selected_profile_ids[0].clone(),
            resource_id: t.workspace_ref.clone(),
            process_digest: container_execution_digest(request, &snapshot.digest().unwrap())
                .unwrap(),
            allow_monitored_disk: false,
            allow_monitored_cpu: true,
            allowed_effects: t.allowed_effects.iter().cloned().collect(),
            not_before_unix_ms: n.saturating_sub(100),
            expires_at_unix_ms: n + 120_000,
        },
    );
    b.policy_control().replace(policy).unwrap();
    b
}
