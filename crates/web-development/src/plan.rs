use crate::{Error, Result, digest, protocol::Service};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_repository::{Repository, RepositorySnapshot};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::AtomicBool,
};

// Updated only from the separately authenticated image build/SDK manifest.
pub const WEB_IMAGE: &str =
    "sha256:1b4ea48f329dc562d6496635430293b9624f0aecbee77d45b17df443485eb76d";
pub const PRIVATE: &str = ".melissa-code10";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "language", rename_all = "snake_case", deny_unknown_fields)]
pub enum App {
    JavaScript { entry: String },
    TypeScript { entry: String },
    Python { entry: String },
    Static { directory: String },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Database {
    Sqlite,
    Postgres,
}
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Baseline {
    Schema { digest: String },
    After { name: String },
}
/// Trusted Rust host registration; never deserialized from model arguments.
#[derive(Debug, Clone, Serialize)]
pub struct Migration {
    pub source_path: String,
    pub source_digest: String,
    /// Digest of the complete schema SQL before the migration.
    pub baseline: Baseline,
    pub transactional: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Statement {
    pub source_path: String,
    pub source_digest: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    pub app: Option<App>,
    pub database: Option<Database>,
    pub seed_path: Option<String>,
    pub migrations: BTreeMap<String, Migration>,
    pub statements: BTreeMap<String, Statement>,
    pub services: BTreeSet<Service>,
}
pub struct WebPlan {
    pub(crate) request: ContainerRequest,
    pub(crate) snapshot: Snapshot,
    pub(crate) source: RepositorySnapshot,
    pub(crate) registration: Registration,
}
#[derive(Debug, Clone, Serialize)]
pub struct ApiReconciliationRule {
    pub method: crate::protocol::Method,
    pub path: String,
    /// Owned status endpoint, with exactly one {key} placeholder.
    pub status_path: String,
}
fn source_path(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains(['\\', ':', '\0'])
        && s.split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && !p.starts_with(".melissa-"))
}
impl WebPlan {
    pub fn with_api_reconciliation(mut self, rules: Vec<ApiReconciliationRule>) -> Result<Self> {
        if rules.len() > 16
            || rules.iter().any(|r| {
                r.method == crate::protocol::Method::Get
                    || !crate::protocol::local_path(&r.path)
                    || !crate::protocol::local_path(&r.status_path)
                    || r.status_path.matches("{key}").count() != 1
            })
        {
            return Err(Error::Invalid("host API proof registration"));
        }
        let bytes = self
            .snapshot
            .files
            .get_mut(&format!("{PRIVATE}/program.json"))
            .ok_or(Error::Invalid("web program absent"))?;
        let mut program: serde_json::Value = serde_json::from_slice(bytes)?;
        program["api_reconciliation_rules"] = serde_json::to_value(rules)?;
        *bytes = serde_json::to_vec(&program)?;
        Ok(self)
    }
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        registration: Registration,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        let mut snapshot = repo.worker_input(source, cancel)?.snapshot;
        if registration.services.is_empty()
            || registration.services.len() > 3
            || snapshot
                .files
                .keys()
                .any(|p| p.split('/').any(|x| x.starts_with(".melissa-")))
        {
            return Err(Error::Invalid("web registration or reserved source paths"));
        }
        if (registration.services.contains(&Service::Database) && registration.database.is_none())
            || registration
                .services
                .iter()
                .any(|s| matches!(s, Service::Api | Service::Browser))
                && registration.app.is_none()
        {
            return Err(Error::Invalid("registered service dependency absent"));
        }
        if let Some(app) = &registration.app {
            let (path, file) = match app {
                App::JavaScript { entry } | App::TypeScript { entry } | App::Python { entry } => {
                    (entry, true)
                }
                App::Static { directory } => (directory, false),
            };
            if !source_path(path)
                || (file && !snapshot.files.contains_key(path))
                || (!file
                    && !snapshot
                        .files
                        .keys()
                        .any(|p| p.starts_with(&format!("{path}/"))))
            {
                return Err(Error::Invalid("registered application absent from source"));
            }
        }
        if let Some(p) = &registration.seed_path
            && (!source_path(p)
                || !snapshot.files.contains_key(p)
                || registration.database.is_none())
        {
            return Err(Error::Invalid("seed outside captured local fixture"));
        }
        for (name, m) in &registration.migrations {
            if !crate::identifier(name)
                || !source_path(&m.source_path)
                || snapshot
                    .files
                    .get(&m.source_path)
                    .is_none_or(|b| digest(b) != m.source_digest)
            {
                return Err(Error::Invalid("migration source or baseline registration"));
            }
        }
        for name in registration.migrations.keys() {
            let mut seen = BTreeSet::new();
            let mut cursor = name;
            loop {
                if !seen.insert(cursor) {
                    return Err(Error::Invalid("cyclic migration baseline dependency"));
                }
                let m = registration
                    .migrations
                    .get(cursor)
                    .ok_or(Error::Invalid("unknown migration baseline dependency"))?;
                match &m.baseline {
                    Baseline::Schema { digest } => {
                        if !digest.strip_prefix("sha256:").is_some_and(|h| {
                            h.len() == 64
                                && h.bytes()
                                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                        }) {
                            return Err(Error::Invalid("exact migration baseline digest required"));
                        }
                        break;
                    }
                    Baseline::After { name } => cursor = name,
                }
            }
        }
        for (name, s) in &registration.statements {
            if !crate::identifier(name)
                || !source_path(&s.source_path)
                || snapshot
                    .files
                    .get(&s.source_path)
                    .is_none_or(|b| digest(b) != s.source_digest)
            {
                return Err(Error::Invalid("SQL statement source registration"));
            }
        }
        let sources: BTreeMap<_, _> = snapshot
            .files
            .iter()
            .map(|(p, b)| {
                (
                    p.clone(),
                    b.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                )
            })
            .collect();
        let program = serde_json::json!({"schema_version":"melissa.web-program/v1","registration":registration,"source_digest":source.digest,"sources":sources,"response_limit":limits.output_bytes.min(4*1024*1024),"artifact_limit":limits.export_bytes.min(limits.output_bytes/3).min(64*1024*1024),"playwright_version":"1.64.0"});
        for (p, b) in [
            ("program.json", serde_json::to_vec(&program)?),
            ("worker.py", include_bytes!("worker.py").to_vec()),
            ("browser.cjs", include_bytes!("browser.cjs").to_vec()),
            ("sql_runtime.py", include_bytes!("sql_runtime.py").to_vec()),
        ] {
            snapshot.files.insert(format!("{PRIVATE}/{p}"), b);
        }
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: WEB_IMAGE.into(),
            executable: "/opt/melissa-python/bin/python".into(),
            argv: vec!["-I".into(), "-u".into(), format!("{PRIVATE}/worker.py")],
            cwd: ".".into(),
            env: BTreeMap::from([(
                "PLAYWRIGHT_BROWSERS_PATH".into(),
                "/opt/melissa-browsers".into(),
            )]),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("web container contract"))?;
        snapshot
            .validate(request.limits.disk_bytes)
            .map_err(|_| Error::Invalid("web snapshot bound"))?;
        Ok(Self {
            request,
            snapshot,
            source: source.clone(),
            registration,
        })
    }
    pub fn request(&self) -> &ContainerRequest {
        &self.request
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn source(&self) -> &RepositorySnapshot {
        &self.source
    }
}
