//! Real Cargo-aware rust-analyzer / TypeScript / Pyright semantic procedures.
use crate::{
    Error, Result,
    full::{Language, compiler_contract, put, validate_source},
    hex, toolchain,
};
use melissa_container_executor::{
    ContainerLimits, ContainerReport, ContainerRequest, Snapshot, TerminationReason,
};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker, container_policy::SignedContainerPermit,
};
use melissa_local_store::LocalStore;
use melissa_repository::{Repository, RepositorySnapshot, analysis::byte_position, archive};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};
const DRIVER: &str = include_str!("semantic_worker.py");
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticMethod {
    Definition,
    References,
    Symbols,
    Diagnostics,
    Hover,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticQuery {
    pub method: SemanticMethod,
    pub path: String,
    pub line: u32,
    pub character: u32,
}
pub struct SemanticPlan {
    pub(crate) request: ContainerRequest,
    pub(crate) snapshot: Snapshot,
    pub(crate) source: RepositorySnapshot,
    pub(crate) query: SemanticQuery,
    pub(crate) build_scripts: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticLocation {
    pub uri: String,
    pub scope: String,
    pub export_path: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticData {
    pub schema_version: String,
    pub source_digest: String,
    pub result: Value,
    pub locations: Vec<SemanticLocation>,
    pub source_unchanged: bool,
    pub build_scripts_enabled: bool,
    pub error: Option<crate::full::DriverError>,
    pub sdk: Value,
    pub execution_markers: BTreeMap<String, bool>,
}
#[derive(Debug, Serialize)]
pub struct SemanticReport {
    pub schema_version: String,
    pub success: bool,
    pub source_digest: String,
    pub source_current: bool,
    pub locations_authenticated: bool,
    pub result: Option<SemanticData>,
    pub artifact_refs: Vec<String>,
    pub failure: Option<String>,
    pub protected_acceptance: bool,
    pub task_completed: bool,
}
impl SemanticPlan {
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        language: Language,
        query: SemanticQuery,
        build_scripts: bool,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        if build_scripts && language != Language::Rust {
            return Err(Error::Invalid(
                "build-script mode belongs to Rust Cargo only",
            ));
        }
        let mut snapshot = repo.worker_input(source, cancel)?.snapshot;
        validate_source(&snapshot)?;
        let bytes = snapshot
            .files
            .get(&query.path)
            .ok_or(Error::Invalid("semantic source outside snapshot"))?;
        byte_position(bytes, query.line, query.character)?;
        let options = compiler_contract(&snapshot, language)?;
        let sdk = json!({"image":toolchain::COMPLETE_IMAGE,"rust_analyzer":"1.98.1","typescript":toolchain::TYPESCRIPT,"typescript_language_server":toolchain::TS_LSP,"pyright":toolchain::PYRIGHT});
        let payload = json!({"schema_version":"melissa.semantic-program/v1","language":language.wire(),"query":query,"source_digest":source.digest,"sources":snapshot.files.iter().map(|(p,b)|(p.clone(),hex(b))).collect::<BTreeMap<_,_>>(),"compiler_options":options,"build_scripts":build_scripts,"trace_limit":limits.output_bytes,"sdk":sdk});
        snapshot.files.insert(
            ".melissa-code06-semantic/driver.py".into(),
            DRIVER.as_bytes().to_vec(),
        );
        snapshot.files.insert(
            ".melissa-code06-semantic/program.json".into(),
            serde_json::to_vec(&payload)?,
        );
        snapshot
            .validate(limits.disk_bytes)
            .map_err(|_| Error::Invalid("semantic snapshot envelope"))?;
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: toolchain::COMPLETE_IMAGE.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec![
                "-I".into(),
                "-S".into(),
                ".melissa-code06-semantic/driver.py".into(),
            ],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("semantic worker envelope"))?;
        Ok(Self {
            request,
            snapshot,
            source: source.clone(),
            query,
            build_scripts,
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
    pub fn query(&self) -> &SemanticQuery {
        &self.query
    }
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        repo: &Repository,
        broker: &mut ContainerBroker,
        task: &str,
        permit: &SignedContainerPermit,
        identity: &InvocationIdentity,
        cancel: &AtomicBool,
    ) -> Result<SemanticReport> {
        repo.validate_snapshot(&self.source, cancel)?;
        if permit.binding.request != self.request {
            return Err(Error::Invalid("semantic request/permit mismatch"));
        }
        let execution = broker.execute(task, permit, &self.snapshot, identity, cancel)?;
        let Some(worker) = &execution.report else {
            return Err(Error::AfterDispatch(Box::new(Error::Invalid(
                "semantic worker report absent",
            ))));
        };
        self.analyze(
            repo,
            broker.store_mut(),
            task,
            &identity.attempt_id,
            worker,
            &execution.result_artifact_id,
        )
    }
    pub(crate) fn analyze(
        &self,
        repo: &Repository,
        store: &mut LocalStore,
        task: &str,
        attempt: &str,
        worker: &ContainerReport,
        worker_artifact: &str,
    ) -> Result<SemanticReport> {
        let mut report = SemanticReport {
            schema_version: "melissa.semantic-observation/v1".into(),
            success: false,
            source_digest: self.source.digest.clone(),
            source_current: repo
                .validate_snapshot(&self.source, &AtomicBool::new(false))
                .is_ok(),
            locations_authenticated: false,
            result: None,
            artifact_refs: vec![worker_artifact.into()],
            failure: None,
            protected_acceptance: false,
            task_completed: false,
        };
        let valid = worker.input_digest
            == self
                .snapshot
                .digest()
                .map_err(|_| Error::Invalid("semantic input digest"))?
            && worker.image_id == self.request.image_id
            && worker.termination == TerminationReason::Exited
            && worker.exit_code == Some(0)
            && !worker.output_truncated
            && !worker.export_truncated
            && worker.cleanup_confirmed
            && worker.tree_confirmed_stopped
            && worker.policy_verified;
        if valid {
            let parsed = melissa_model_gateway::strict_json(
                std::str::from_utf8(&worker.stdout).unwrap_or(""),
            )
            .map_err(|_| {
                Error::AfterDispatch(Box::new(Error::Invalid("semantic JSON envelope")))
            })?;
            let data: SemanticData = serde_json::from_value(parsed)?;
            let files = archive::inspect_ustar(&worker.archive, repo.limits())?;
            let mut authenticated = data.schema_version == "melissa.semantic-result/v1"
                && data.source_digest == self.source.digest
                && data.build_scripts_enabled == self.build_scripts;
            for (i, location) in data.locations.iter().enumerate() {
                let safe =
                    location.export_path == format!(".melissa-code06-semantic/location-{i}.bin");
                let bytes = files
                    .iter()
                    .find(|f| f.path == location.export_path)
                    .map(|f| &f.bytes);
                let hash = bytes.map(|b| hex(&Sha256::digest(b)));
                authenticated &= safe
                    && hash.as_deref() == Some(&location.sha256)
                    && bytes.is_some_and(|b| b.len() as u64 == location.bytes);
                if location.scope == "workspace" {
                    let uri = decode_file_uri(&location.uri)?;
                    let name = uri
                        .strip_prefix("/work/")
                        .ok_or(Error::Invalid("semantic workspace location"))?;
                    authenticated &= self
                        .snapshot
                        .files
                        .get(name)
                        .is_some_and(|b| hex(&Sha256::digest(b)) == location.sha256);
                } else if location.scope == "sdk" {
                    let path = decode_file_uri(&location.uri)?;
                    authenticated&=["/usr/local/rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/","/opt/melissa-tools/node_modules/typescript/lib/","/opt/melissa-tools/node_modules/@types/","/opt/melissa-tools/node_modules/pyright/dist/typeshed-fallback/","/usr/lib/python3.13/"].iter().any(|p|path.starts_with(p));
                } else {
                    authenticated = false;
                }
                if let Some(bytes) = bytes {
                    let id = format!("{attempt}:semantic-source:{i}");
                    put(
                        store,
                        task,
                        &id,
                        "semantic.source.untrusted",
                        "application/octet-stream",
                        bytes,
                    )?;
                    report.artifact_refs.push(id);
                }
            }
            if let Some(raw) = files
                .iter()
                .find(|f| f.path == ".melissa-code06-semantic/lsp-transcript.ndjson")
            {
                let id = format!("{attempt}:lsp-transcript");
                put(
                    store,
                    task,
                    &id,
                    "semantic.raw-lsp-transcript",
                    "application/x-ndjson",
                    &raw.bytes,
                )?;
                report.artifact_refs.push(id);
            } else {
                authenticated = false;
            }
            report.locations_authenticated = authenticated;
            report.success = authenticated
                && report.source_current
                && data.source_unchanged
                && data.error.is_none();
            if let Some(error) = &data.error {
                report.failure = Some(format!("{}: {}", error.kind, error.message));
            }
            report.result = Some(data);
        } else {
            report.failure = Some("worker source/image/process/output/cleanup mismatch".into());
        }
        let id = format!("{attempt}:semantic-result");
        put(
            store,
            task,
            &id,
            "semantic.normalized-result",
            "application/json",
            &serde_json::to_vec(&report)?,
        )?;
        report.artifact_refs.push(id);
        Ok(report)
    }
}
fn decode_file_uri(uri: &str) -> Result<String> {
    let raw = uri
        .strip_prefix("file://")
        .ok_or(Error::Invalid("semantic URI scheme"))?;
    if !raw.starts_with('/') || raw.contains(['?', '#']) {
        return Err(Error::Invalid("semantic URI authority/query"));
    }
    let mut bytes = Vec::new();
    let source = raw.as_bytes();
    let mut i = 0;
    while i < source.len() {
        if source[i] == b'%' {
            if i + 2 >= source.len() {
                return Err(Error::Invalid("semantic URI escape"));
            }
            bytes.push(
                u8::from_str_radix(
                    std::str::from_utf8(&source[i + 1..i + 3])
                        .map_err(|_| Error::Invalid("semantic URI encoding"))?,
                    16,
                )
                .map_err(|_| Error::Invalid("semantic URI escape"))?,
            );
            i += 3;
        } else {
            bytes.push(source[i]);
            i += 1;
        }
    }
    let path = String::from_utf8(bytes).map_err(|_| Error::Invalid("semantic URI UTF8"))?;
    if path.split('/').any(|s| matches!(s, "." | "..")) || path.contains(['\\', '\0']) {
        return Err(Error::Invalid("semantic URI traversal"));
    }
    Ok(path)
}
