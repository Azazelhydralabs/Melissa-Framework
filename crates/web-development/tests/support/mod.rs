#![allow(dead_code)]
use melissa_container_executor::ContainerLimits;
use melissa_core_contracts::{TaskState, catalog::Catalog, wire::TaskContractV1};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_model_gateway::tools::ToolContext;
use melissa_repository::{Limits, Repository};
use melissa_web_development::{
    plan::{App, Database, Registration, WebPlan},
    protocol::{Command, Service},
    session::{Policy, WebSession},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub repo: Arc<Repository>,
    pub store: LocalStore,
    pub catalog: Catalog,
    pub policy: Policy,
    pub registration: Registration,
    pub ctx: ToolContext,
    pub cancelled: Arc<AtomicBool>,
    pub revoked: Arc<AtomicBool>,
}
pub fn limits() -> ContainerLimits {
    ContainerLimits {
        wall_time_ms: 180_000,
        cpu_time_ms: 90_000,
        cpu_rate_basis_points: 10_000,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        disk_bytes: 512 * 1024 * 1024,
        output_bytes: 16 * 1024 * 1024,
        export_bytes: 64 * 1024 * 1024,
        max_processes: 256,
    }
}
impl Fixture {
    pub fn new(service: Service, database: Option<Database>, extra: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        for (path, bytes) in [
            ("app.py", include_str!("../fixtures/app.py")),
            ("index.html", include_str!("../fixtures/index.html")),
            ("schema.sql", include_str!("../fixtures/schema.sql")),
            ("dirty.bin", "KEEP\r\nuser\0work"),
        ]
        .into_iter()
        .chain(extra.iter().copied())
        {
            let target = root.join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
        let repo = Arc::new(Repository::open(&root, Limits::default(), vec![]).unwrap());
        let source = repo.snapshot(&AtomicBool::new(false)).unwrap();
        let profile = match service {
            Service::Browser => "melissa.code.frontend",
            Service::Api => "melissa.code.backend",
            Service::Database => "melissa.code.database",
        };
        let mut task: TaskContractV1 = serde_json::from_slice(include_bytes!(
            "../../../../tests/fixtures/code01/wire/task-contract-v1.json"
        ))
        .unwrap();
        task.task_id = "task:code10-test".into();
        task.workspace_ref = "workspace:code10-test".into();
        task.input_snapshot_digest = source.digest;
        task.selected_profile_ids = vec![profile.into()];
        task.allowed_resource_ids = vec![task.workspace_ref.clone()];
        task.authorization_refs = vec!["authorization:code10-test".into()];
        task.allowed_effects = vec![
            "workspace.read",
            "workspace.apply_patch_scoped",
            "process.execute_scoped",
            "browser.interact_scoped",
            "network.test_scoped",
            "database.local_fixture",
            "evidence.append",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        task.limits.max_wall_time_ms = 240_000;
        task.limits.max_disk_bytes = 512 * 1024 * 1024;
        task.limits.max_output_bytes = 128 * 1024 * 1024;
        let mut store = LocalStore::open(
            &dir.path().join("store"),
            StoreKey::from_bytes([147; 32]),
            StoreConfig {
                max_blob_bytes: 256 * 1024 * 1024,
                max_cas_bytes: 1024 * 1024 * 1024,
                ..StoreConfig::default()
            },
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
        let policy = Policy {
            task_id: task.task_id.clone(),
            profile_id: profile.into(),
            principal_id: "principal:code10-test".into(),
            resource_id: task.workspace_ref,
            authorization_ref: task.authorization_refs[0].clone(),
            expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 240_000,
        };
        let ctx = ToolContext {
            task_id: policy.task_id.clone(),
            profile_id: policy.profile_id.clone(),
            run_id: "run:code10-test".into(),
            request_id: "request:code10-test".into(),
            invocation_id: "invocation:code10-test".into(),
            attempt_id: "attempt:code10-test".into(),
            generation: 1,
        };
        let registration = Registration {
            app: if service == Service::Database {
                None
            } else {
                Some(App::Python {
                    entry: "app.py".into(),
                })
            },
            database,
            seed_path: database.map(|_| "schema.sql".into()),
            migrations: BTreeMap::new(),
            statements: BTreeMap::new(),
            services: BTreeSet::from([service]),
        };
        let catalog = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        Self {
            dir,
            repo,
            store,
            catalog,
            policy,
            registration,
            ctx,
            cancelled: Arc::new(AtomicBool::new(false)),
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn start(&self) -> WebSession {
        let plan = WebPlan::prepare(
            &self.repo,
            &self.repo.snapshot(&self.cancelled).unwrap(),
            self.registration.clone(),
            limits(),
            &self.cancelled,
        )
        .unwrap();
        WebSession::start(
            self.repo.clone(),
            self.store.connect().unwrap(),
            self.catalog.clone(),
            self.policy.clone(),
            plan,
            self.ctx.clone(),
            self.cancelled.clone(),
            self.revoked.clone(),
        )
        .unwrap()
    }
    pub fn root(&self) -> std::path::PathBuf {
        self.dir.path().join("repo")
    }
}
pub fn body(session: &mut WebSession, op: Command) -> serde_json::Value {
    let r = session.command(op).unwrap();
    assert!(r.ok, "{:?}", r.error);
    r.body.unwrap()
}
