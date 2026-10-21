#![allow(dead_code)]
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
pub fn no() -> AtomicBool {
    AtomicBool::new(false)
}
pub fn limits() -> ContainerLimits {
    ContainerLimits {
        wall_time_ms: 90_000,
        cpu_time_ms: 60_000,
        cpu_rate_basis_points: 10_000,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        disk_bytes: 256 * 1024 * 1024,
        output_bytes: 4 * 1024 * 1024,
        max_processes: 128,
        export_bytes: 8 * 1024 * 1024,
    }
}
pub struct Fixture {
    pub _dir: tempfile::TempDir,
    pub repo: Repository,
    pub broker: ContainerBroker,
    pub task: TaskContractV1,
    pub plan: RustPlan,
}
impl Fixture {
    pub fn new(
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
            "../../../../tests/fixtures/code01/wire/task-contract-v1.json"
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
        task.limits.max_output_bytes = 64 * 1024 * 1024;
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
                memory_bytes: 2 * 1024 * 1024 * 1024,
                disk_bytes: 256 * 1024 * 1024,
                disk_mode: DiskLimitMode::Strict,
                output_bytes: 64 * 1024 * 1024,
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
    pub fn permit(&self) -> melissa_execution_broker::container_policy::SignedContainerPermit {
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
    pub fn run(&mut self) -> RustExecution {
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
pub fn identity() -> InvocationIdentity {
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

pub fn permit_for(
    f: &mut Fixture,
    request: &melissa_container_executor::ContainerRequest,
    snapshot: &melissa_container_executor::Snapshot,
) -> melissa_execution_broker::container_policy::SignedContainerPermit {
    let mut policy = f.broker.policy_control().snapshot().unwrap();
    policy.allowed_env_names = request.env.keys().cloned().collect();
    policy
        .grants
        .get_mut("auth:code06-rust")
        .unwrap()
        .process_digest = container_execution_digest(request, &snapshot.digest().unwrap()).unwrap();
    f.broker.policy_control().replace(policy).unwrap();
    let n = unix_ms().unwrap();
    f.broker
        .issue_permit(
            &f.task.task_id,
            request.clone(),
            snapshot,
            PermitRequest {
                permit_id: "permit:code06-complete".into(),
                nonce: "nonce:code06-complete".into(),
                principal_id: "principal:code06-rust".into(),
                profile_id: f.task.selected_profile_ids[0].clone(),
                resource_id: f.task.workspace_ref.clone(),
                authorization_ref: "auth:code06-rust".into(),
                not_before_unix_ms: n,
                expires_at_unix_ms: n + 90000,
            },
        )
        .unwrap()
}
