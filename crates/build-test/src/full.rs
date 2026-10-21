//! Versioned, closed SDK procedures. Input syntax never grants authority.
use crate::{Error, Result, hex, toolchain, unhex};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot, TerminationReason};
use melissa_execution_broker::{
    InvocationIdentity,
    container_broker::{ContainerBroker, ContainerExecution},
    container_policy::SignedContainerPermit,
};
use melissa_local_store::{ArtifactRequest, LocalStore};
use melissa_repository::{Repository, RepositorySnapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::AtomicBool,
};

pub const DRIVER: &str = include_str!("full_worker.py");
const PYTEST: &str = include_str!("pytest_runner.py");
const NODE_REPORTER: &str = include_str!("node_reporter.cjs");
pub const PRIVATE: &str = ".melissa-code06-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "typescript")]
    TypeScript,
    Python,
}
impl Language {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Python => "python",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestSuite {
    UnitIntegration,
    Doctest,
    EndToEnd,
    All,
    Custom,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Build {},
    Check {},
    Lint {},
    FormatCheck {},
    Test { suite: TestSuite, repetitions: u16 },
}
impl Operation {
    pub fn repetitions(&self) -> u16 {
        if let Self::Test { repetitions, .. } = self {
            *repetitions
        } else {
            0
        }
    }
}
/// Exact host registration; never deserialized from model arguments.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessRegistration {
    pub id: String,
    pub version: String,
    pub target: String,
    pub source_path: String,
    pub source_digest: String,
}

pub struct ProcedurePlan {
    pub(crate) request: ContainerRequest,
    pub(crate) snapshot: Snapshot,
    pub(crate) source: RepositorySnapshot,
    pub(crate) language: Language,
    pub(crate) operation: Operation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    NoTests,
    Skipped,
    Flaky,
    Unsupported,
    MissingSdk,
    MissingDependency,
    SourceChanged,
    ArtifactMismatch,
    InvalidOutput,
    Incomplete,
    Cancelled,
    TimedOut,
    RequiresReconciliation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStep {
    pub stage: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout_hex: String,
    pub stderr_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub name: String,
    pub bytes_hex: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestIdentity {
    pub group: String,
    pub id: String,
    pub file: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRun {
    pub group: String,
    pub id: String,
    pub repetition: u16,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkDiagnostic {
    pub stage: String,
    pub level: String,
    pub code: Option<String>,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverError {
    pub kind: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema_version: String,
    pub source_digest: String,
    pub steps: Vec<RawStep>,
    pub attachments: Vec<Attachment>,
    pub discovered: Vec<TestIdentity>,
    pub runs: Vec<TestRun>,
    pub diagnostics: Vec<SdkDiagnostic>,
    pub sdk: BTreeMap<String, String>,
    pub source_unchanged: bool,
    pub truncated: bool,
    pub error: Option<DriverError>,
}
#[derive(Debug, Serialize)]
pub struct ProcedureReport {
    pub schema_version: String,
    pub status: Status,
    pub language: Language,
    pub operation: Operation,
    pub source_digest: String,
    pub input_digest: String,
    pub image_id: String,
    pub host_source_current: bool,
    pub developer_output_trusted: bool,
    pub protected_acceptance: bool,
    pub task_completed: bool,
    pub raw_worker_artifact_id: String,
    pub raw_artifact_ids: Vec<String>,
    pub report_artifact_id: Option<String>,
    pub details: Option<Envelope>,
    pub protocol_error: Option<String>,
    pub warnings: Vec<String>,
}
pub struct ProcedureExecution {
    pub execution: ContainerExecution,
    pub report: ProcedureReport,
}

impl ProcedurePlan {
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        language: Language,
        operation: Operation,
        harness: Option<&HarnessRegistration>,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        if matches!(operation,Operation::Test{repetitions,..} if !(1..=16).contains(&repetitions)) {
            return Err(Error::Invalid("explicit test repetitions must be1..16"));
        }
        let mut snapshot = repo.worker_input(source, cancel)?.snapshot;
        validate_source(&snapshot)?;
        let matches = snapshot.files.keys().any(|p| match language {
            Language::Rust => p.ends_with(".rs"),
            Language::Python => p.ends_with(".py"),
            Language::JavaScript => {
                p.ends_with(".js") || p.ends_with(".mjs") || p.ends_with(".cjs")
            }
            Language::TypeScript => p.ends_with(".ts") || p.ends_with(".tsx"),
        });
        if !matches {
            return Err(Error::Invalid("no captured source for selected SDK"));
        }
        if language == Language::Rust
            && (!snapshot.files.contains_key("Cargo.toml")
                || !snapshot.files.contains_key("Cargo.lock"))
        {
            return Err(Error::Invalid(
                "reviewed root Cargo.toml and Cargo.lock required",
            ));
        }
        if let Some(h) = harness {
            if h.id.is_empty()
                || h.version.is_empty()
                || h.target.is_empty()
                || h.target.starts_with('-')
                || h.target.contains(['/', '\\', '\0'])
            {
                return Err(Error::Invalid("invalid host harness registration"));
            }
            let source = snapshot
                .files
                .get(&h.source_path)
                .ok_or(Error::Invalid("harness source absent"))?;
            if digest(source) != h.source_digest {
                return Err(Error::Invalid("host harness source digest mismatch"));
            }
        }
        if matches!(
            operation,
            Operation::Test {
                suite: TestSuite::Custom,
                ..
            }
        ) && (language != Language::Rust || harness.is_none())
        {
            return Err(Error::Invalid(
                "custom Rust harness needs exact host registration",
            ));
        }
        if limits.output_bytes < 64 * 1024 {
            return Err(Error::Invalid("SDK output envelope too small"));
        }
        let compiler_options = compiler_contract(&snapshot, language)?;
        let expected_sdk = expected_sdk(language);
        let payload = json!({"schema_version":"melissa.sdk-program/v1","language":language.wire(),"operation":operation,
            "source_digest":source.digest,"sources":snapshot.files.iter().map(|(p,b)|(p.clone(),hex(b))).collect::<BTreeMap<_,_>>(),
            "expected_sdk":expected_sdk,"compiler_options":compiler_options,"harness":harness,"raw_limit":limits.output_bytes/3});
        for (name, bytes) in [
            ("driver.py", DRIVER.as_bytes().to_vec()),
            ("pytest_runner.py", PYTEST.as_bytes().to_vec()),
            ("node_reporter.cjs", NODE_REPORTER.as_bytes().to_vec()),
            ("program.json", serde_json::to_vec(&payload)?),
        ] {
            snapshot.files.insert(format!("{PRIVATE}/{name}"), bytes);
        }
        snapshot
            .validate(limits.disk_bytes)
            .map_err(|_| Error::Invalid("SDK input exceeds worker envelope"))?;
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: toolchain::COMPLETE_IMAGE.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec!["-I".into(), "-S".into(), format!("{PRIVATE}/driver.py")],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("SDK request invalid"))?;
        Ok(Self {
            request,
            snapshot,
            source: source.clone(),
            language,
            operation,
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
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        repo: &Repository,
        broker: &mut ContainerBroker,
        task: &str,
        permit: &SignedContainerPermit,
        identity: &InvocationIdentity,
        cancel: &AtomicBool,
    ) -> Result<ProcedureExecution> {
        repo.validate_snapshot(&self.source, cancel)?;
        if permit.binding.request != self.request {
            return Err(Error::Invalid("SDK request/permit mismatch"));
        }
        let execution = broker.execute(task, permit, &self.snapshot, identity, cancel)?;
        let report = self.analyze(
            repo,
            broker.store_mut(),
            task,
            &identity.attempt_id,
            execution.report.as_ref(),
            execution.requires_reconciliation,
            &execution.result_artifact_id,
        )?;
        Ok(ProcedureExecution { execution, report })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze(
        &self,
        repo: &Repository,
        store: &mut LocalStore,
        task: &str,
        attempt: &str,
        worker: Option<&melissa_container_executor::ContainerReport>,
        unknown: bool,
        raw_id: &str,
    ) -> Result<ProcedureReport> {
        let current = repo
            .validate_snapshot(&self.source, &AtomicBool::new(false))
            .is_ok();
        let mut report = self.normalize(worker, unknown, raw_id, current);
        if !unknown {
            if let Some(data) = &report.details {
                for (i, step) in data.steps.iter().enumerate() {
                    for (stream, raw) in
                        [("stdout", &step.stdout_hex), ("stderr", &step.stderr_hex)]
                    {
                        let bytes = unhex(raw).ok_or_else(|| {
                            Error::AfterDispatch(Box::new(Error::Invalid("invalid raw SDK bytes")))
                        })?;
                        let id = format!("{attempt}:sdk-log:{i}:{stream}");
                        put(
                            store,
                            task,
                            &id,
                            "sdk.raw-log",
                            "application/octet-stream",
                            &bytes,
                        )?;
                        report.raw_artifact_ids.push(id);
                    }
                }
                for (i, a) in data.attachments.iter().enumerate() {
                    let bytes = unhex(&a.bytes_hex).ok_or_else(|| {
                        Error::AfterDispatch(Box::new(Error::Invalid(
                            "invalid SDK attachment bytes",
                        )))
                    })?;
                    let id = format!("{attempt}:sdk-attachment:{i}");
                    put(
                        store,
                        task,
                        &id,
                        "sdk.raw-report",
                        "application/octet-stream",
                        &bytes,
                    )?;
                    report.raw_artifact_ids.push(id);
                }
            }
            let id = format!("{attempt}:sdk-report");
            report.report_artifact_id = Some(id.clone());
            put(
                store,
                task,
                &id,
                "sdk.normalized-report",
                "application/json",
                &serde_json::to_vec(&report)?,
            )?;
        }
        Ok(report)
    }
    fn normalize(
        &self,
        worker: Option<&melissa_container_executor::ContainerReport>,
        unknown: bool,
        raw_id: &str,
        current: bool,
    ) -> ProcedureReport {
        let mut report=ProcedureReport{schema_version:"melissa.sdk-result/v1".into(),status:Status::InvalidOutput,language:self.language,operation:self.operation.clone(),source_digest:self.source.digest.clone(),input_digest:self.snapshot.digest().unwrap_or_default(),image_id:self.request.image_id.clone(),host_source_current:current,developer_output_trusted:false,protected_acceptance:false,task_completed:false,raw_worker_artifact_id:raw_id.into(),raw_artifact_ids:vec![],report_artifact_id:None,details:None,protocol_error:None,warnings:vec!["SDK/test output remains untrusted developer evidence, not protected acceptance.".into(),"Supported SDK/config/test matrix is versioned; unsupported combinations fail explicitly.".into()]};
        if unknown {
            report.status = Status::RequiresReconciliation;
            return report;
        }
        let Some(worker) = worker else {
            report.status = Status::Incomplete;
            return report;
        };
        if worker.input_digest != report.input_digest || worker.image_id != report.image_id {
            report.status = Status::ArtifactMismatch;
            return report;
        }
        if !worker.cleanup_confirmed || !worker.tree_confirmed_stopped || !worker.policy_verified {
            report.status = Status::RequiresReconciliation;
            return report;
        }
        if worker.termination != TerminationReason::Exited
            || worker.exit_code != Some(0)
            || worker.output_truncated
            || worker.export_truncated
        {
            report.status = match worker.termination {
                TerminationReason::Cancelled => Status::Cancelled,
                TerminationReason::Timeout => Status::TimedOut,
                _ => Status::Incomplete,
            };
            return report;
        }
        let parsed =
            melissa_model_gateway::strict_json(std::str::from_utf8(&worker.stdout).unwrap_or(""));
        let data: Envelope = match parsed.and_then(|v| {
            serde_json::from_value(v)
                .map_err(|_| melissa_model_gateway::GatewayError::invalid("SDK envelope"))
        }) {
            Ok(v) => v,
            Err(_) => {
                report.protocol_error = Some("malformed/incomplete SDK envelope".into());
                return report;
            }
        };
        report.status = match validate_envelope(self, &data, current) {
            Ok(s) => s,
            Err(e) => {
                report.protocol_error = Some(e.into());
                Status::InvalidOutput
            }
        };
        report.details = Some(data);
        report
    }
}
pub(crate) fn put(
    store: &mut LocalStore,
    task: &str,
    id: &str,
    kind: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result {
    store
        .put_artifact(
            &ArtifactRequest {
                artifact_id: id.into(),
                task_id: task.into(),
                content_type: content_type.into(),
                logical_type: kind.into(),
                schema_version: "melissa.code06-evidence/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            bytes,
        )
        .map_err(|e| Error::AfterDispatch(Box::new(Error::Store(e))))?;
    Ok(())
}
pub fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
pub(crate) fn validate_source(snapshot: &Snapshot) -> Result {
    if snapshot.files.keys().any(|p| {
        (p != "tsconfig.json" && p.ends_with("/tsconfig.json"))
            || p.split('/').any(|c| {
                c.starts_with(".melissa-code06")
                    || matches!(
                        c,
                        ".cargo"
                            | "rust-toolchain"
                            | "rust-toolchain.toml"
                            | "pyrightconfig.json"
                            | "jsconfig.json"
                    )
            })
    }) {
        return Err(Error::Invalid(
            "unreviewed source SDK override/reserved adapter path",
        ));
    }
    Ok(())
}
pub(crate) fn compiler_contract(snapshot: &Snapshot, language: Language) -> Result<Value> {
    let mut result = json!({});
    if matches!(language, Language::TypeScript | Language::JavaScript)
        && let Some(bytes) = snapshot.files.get("tsconfig.json")
    {
        let config: Value = serde_json::from_slice(bytes)?;
        let root = config
            .as_object()
            .ok_or(Error::Invalid("tsconfig object required"))?;
        if root.keys().any(|k| k != "compilerOptions") {
            return Err(Error::Invalid(
                "selected Node SDK requires explicit compilerOptions only; extends/files/project references need their own registered contract",
            ));
        }
        let options = config["compilerOptions"]
            .as_object()
            .ok_or(Error::Invalid("compilerOptions object required"))?;
        for (key, value) in options {
            if !matches!(
                key.as_str(),
                "target"
                    | "module"
                    | "moduleResolution"
                    | "strict"
                    | "strictNullChecks"
                    | "esModuleInterop"
                    | "allowSyntheticDefaultImports"
                    | "skipLibCheck"
                    | "resolveJsonModule"
                    | "jsx"
                    | "noUncheckedIndexedAccess"
                    | "exactOptionalPropertyTypes"
            ) {
                return Err(Error::Invalid(
                    "unsupported compiler option requires explicit SDK contract",
                ));
            }
            result[key] = value.clone();
        }
    }
    Ok(result)
}
fn expected_sdk(language: Language) -> BTreeMap<String, String> {
    match language {
        Language::Rust => BTreeMap::from([
            ("rustc".into(), toolchain::RUSTC.into()),
            ("cargo".into(), toolchain::CARGO.into()),
        ]),
        Language::Python => BTreeMap::from([("python".into(), "Python 3.13.5".into())]),
        _ => BTreeMap::from([
            ("node".into(), toolchain::NODE.into()),
            ("typescript".into(), toolchain::TYPESCRIPT.into()),
        ]),
    }
}
fn validate_envelope(
    plan: &ProcedurePlan,
    data: &Envelope,
    current: bool,
) -> std::result::Result<Status, &'static str> {
    if data.schema_version != "melissa.sdk-procedure/v1" || data.source_digest != plan.source.digest
    {
        return Ok(Status::ArtifactMismatch);
    }
    if data.truncated {
        return Ok(Status::Incomplete);
    }
    if !current || !data.source_unchanged {
        return Ok(Status::SourceChanged);
    }
    for step in &data.steps {
        if step.stage.is_empty()
            || !step.executable.starts_with('/')
            || unhex(&step.stdout_hex).is_none()
            || unhex(&step.stderr_hex).is_none()
        {
            return Err("invalid raw command/log envelope");
        }
    }
    for a in &data.attachments {
        if unhex(&a.bytes_hex).is_none() {
            return Err("invalid raw attachment");
        }
    }
    if let Some(error) = &data.error {
        return Ok(match error.kind.as_str() {
            "unsupported" => Status::Unsupported,
            "missing_sdk" => Status::MissingSdk,
            "missing_dependency" => Status::MissingDependency,
            "source_changed" => Status::SourceChanged,
            "artifact_mismatch" => Status::ArtifactMismatch,
            "incomplete" => Status::Incomplete,
            "failed" => Status::Failed,
            _ => Status::InvalidOutput,
        });
    }
    for (key, expected) in expected_sdk(plan.language) {
        let expected = if key == "typescript" {
            format!("Version {expected}")
        } else {
            expected
        };
        if data.sdk.get(&key) != Some(&expected) {
            return Ok(Status::MissingSdk);
        }
    }
    if !matches!(plan.operation, Operation::Test { .. }) {
        if data.steps.iter().any(|s| s.exit_code != 0)
            || !data.runs.is_empty()
            || !data.discovered.is_empty()
        {
            return Err("successful build/check has failed steps or unexpected test reports");
        }
        return Ok(Status::Passed);
    }
    let identities: BTreeSet<_> = data.discovered.iter().map(|t| (&t.group, &t.id)).collect();
    if identities.len() != data.discovered.len() {
        return Err("duplicate test discovery");
    }
    if identities.is_empty() {
        if !data.runs.is_empty() {
            return Err("results without discovery");
        }
        return Ok(Status::NoTests);
    }
    let mut states: BTreeMap<(&String, &String), Vec<&str>> =
        identities.iter().map(|k| (*k, vec![])).collect();
    for repetition in 0..plan.operation.repetitions() {
        let mut seen = BTreeSet::new();
        for run in data.runs.iter().filter(|r| r.repetition == repetition) {
            let key = (&run.group, &run.id);
            if !identities.contains(&key)
                || !seen.insert(key)
                || !matches!(run.status.as_str(), "passed" | "failed" | "skipped")
            {
                return Err("unexpected/duplicate test result");
            }
            states.get_mut(&key).unwrap().push(run.status.as_str());
        }
        if seen != identities {
            return Err("discovered tests not fully executed");
        }
    }
    if data.runs.len() != identities.len() * usize::from(plan.operation.repetitions()) {
        return Err("unexpected repetition/result count");
    }
    if states.values().any(|v| v.iter().any(|s| s != &v[0])) {
        return Ok(Status::Flaky);
    }
    if states.values().any(|v| v.contains(&"failed")) {
        return Ok(Status::Failed);
    }
    if states.values().any(|v| v.contains(&"skipped")) {
        return Ok(Status::Skipped);
    }
    if data.steps.iter().any(|s| s.exit_code != 0) {
        return Ok(Status::Failed);
    }
    Ok(Status::Passed)
}
