//! CODE-06's first Rust host adapter. Developer tool observations are never
//! protected acceptance, task completion, or permission to run more commands.
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_execution_broker::{
    InvocationIdentity,
    container_broker::{ContainerBroker, ContainerExecution},
    container_policy::SignedContainerPermit,
};
use melissa_local_store::ArtifactRequest;
use melissa_repository::{Repository, RepositorySnapshot};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};

pub mod debug;
pub mod full;
pub mod normalize;
pub mod semantic;
mod semantic_service;
pub mod toolchain;
pub mod tools;
pub use normalize::{Diagnostic, DiagnosticSpan, Outcome, RustReport, TestCounts};
pub type Result<T = ()> = std::result::Result<T, Error>;
const DRIVER: &str = include_str!("worker.py");
const CONTRACT: &str = "melissa.rust-build-test/v1";
const CARGO: &str = "/usr/local/cargo/bin/cargo";
const RUSTC: &str = "/usr/local/cargo/bin/rustc";
pub const RUST_IMAGE: &str =
    "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Repository(melissa_repository::Error),
    Broker(melissa_execution_broker::BrokerError),
    Store(melissa_local_store::StoreError),
    Json(serde_json::Error),
    /// An isolated operation has already been admitted. Inspect its durable
    /// records; never automatically rerun on a normalization/evidence failure.
    AfterDispatch(Box<Error>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid(s) => s,
            Self::Repository(_) => "build source validation failed",
            Self::Broker(_) => "build broker operation failed; inspect typed broker state",
            Self::Store(_) => "build evidence persistence failed",
            Self::Json(_) => "invalid build protocol JSON",
            Self::AfterDispatch(_) => "build already dispatched; inspect before any retry",
        })
    }
}
impl std::error::Error for Error {}
impl From<melissa_repository::Error> for Error {
    fn from(e: melissa_repository::Error) -> Self {
        Self::Repository(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<melissa_local_store::StoreError> for Error {
    fn from(e: melissa_local_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<melissa_execution_broker::BrokerError> for Error {
    fn from(e: melissa_execution_broker::BrokerError) -> Self {
        match e {
            melissa_execution_broker::BrokerError::AfterDispatch(e) => {
                Self::AfterDispatch(Box::new(Self::Broker(*e)))
            }
            e => Self::Broker(e),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RustOperation {
    Build,
    Check,
    Clippy,
    FormatCheck,
    /// Repetitions are an explicit host test requirement, not retry on failure.
    Test {
        repetitions: u16,
    },
}
impl<'de> Deserialize<'de> for RustOperation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        // Serde's internally tagged unit variants ignore additional map keys.
        // Explicit empty structs make unknown operation fields fail closed.
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Build {},
            Check {},
            Clippy {},
            FormatCheck {},
            Test { repetitions: u16 },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Build {} => Self::Build,
            Wire::Check {} => Self::Check,
            Wire::Clippy {} => Self::Clippy,
            Wire::FormatCheck {} => Self::FormatCheck,
            Wire::Test { repetitions } => Self::Test { repetitions },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandSpec {
    pub stage: String,
    pub executable: String,
    pub argv: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Program {
    pub schema_version: String,
    pub commands: Vec<CommandSpec>,
    pub repetitions: u16,
    pub raw_limit: u64,
    pub expected_rustc: String,
    pub expected_cargo: String,
    pub sources: BTreeMap<String, String>,
}

/// Fields are private: a parsed model proposal cannot change the executable,
/// helper, source bytes, target path or command sequence after host preparation.
pub struct RustPlan {
    request: ContainerRequest,
    snapshot: Snapshot,
    source: RepositorySnapshot,
    operation: RustOperation,
    commands: Vec<CommandSpec>,
}
pub struct RustExecution {
    pub execution: ContainerExecution,
    pub report: RustReport,
    pub report_artifact_id: Option<String>,
}
impl RustPlan {
    /// Explicit complete worker. Legacy prepare intentionally keeps its original
    /// immutable image and observable missing-component behavior.
    pub fn prepare_complete(
        repo: &Repository,
        source: &RepositorySnapshot,
        operation: RustOperation,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        let mut plan = Self::prepare(repo, source, operation, limits, cancel)?;
        plan.request.image_id = toolchain::COMPLETE_IMAGE.into();
        plan.request
            .validate()
            .map_err(|_| Error::Invalid("complete worker request"))?;
        Ok(plan)
    }
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        operation: RustOperation,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        let repetitions = match operation {
            RustOperation::Test { repetitions } if (1..=16).contains(&repetitions) => repetitions,
            RustOperation::Test { .. } => {
                return Err(Error::Invalid("explicit repetitions must be 1..16"));
            }
            _ => 0,
        };
        let input = repo.worker_input(source, cancel)?;
        let mut snapshot = input.snapshot;
        if !snapshot.files.contains_key("Cargo.toml") || !snapshot.files.contains_key("Cargo.lock")
        {
            return Err(Error::Invalid(
                "root Cargo.toml and reviewed Cargo.lock required",
            ));
        }
        if snapshot.files.keys().any(|p| {
            p.split('/').any(|c| {
                matches!(
                    c,
                    ".cargo"
                        | ".melissa-code06"
                        | ".melissa-code06-target"
                        | "rust-toolchain"
                        | "rust-toolchain.toml"
                )
            })
        }) {
            return Err(Error::Invalid(
                "source toolchain/config override or reserved adapter path",
            ));
        }
        if limits.output_bytes < 16 * 1024 {
            return Err(Error::Invalid(
                "output envelope too small for explicit build protocol",
            ));
        }
        let commands = commands(operation);
        // BLAKE3 is checked by the Rust host. The helper also compares the exact
        // input bytes before and after project code; its claims stay untrusted.
        let sources = snapshot
            .files
            .iter()
            .map(|(p, b)| (p.clone(), hex(b)))
            .collect();
        let program = Program {
            schema_version: CONTRACT.into(),
            commands: commands.clone(),
            repetitions,
            raw_limit: limits.output_bytes / 3,
            expected_rustc: "rustc 1.98.1 (48a229cea 2026-09-01)".into(),
            expected_cargo: "cargo 1.98.1 (797e8a9bc 2026-08-05)".into(),
            sources,
        };
        snapshot.files.insert(
            ".melissa-code06/driver.py".into(),
            DRIVER.as_bytes().to_vec(),
        );
        snapshot.files.insert(
            ".melissa-code06/program.json".into(),
            serde_json::to_vec(&program)?,
        );
        snapshot
            .validate(limits.disk_bytes)
            .map_err(|_| Error::Invalid("build snapshot exceeds worker envelope"))?;
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: RUST_IMAGE.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec!["-I".into(), "-S".into(), ".melissa-code06/driver.py".into()],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("invalid build worker request"))?;
        Ok(Self {
            request,
            snapshot,
            source: source.clone(),
            operation,
            commands,
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
    pub fn operation(&self) -> RustOperation {
        self.operation
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
    ) -> Result<RustExecution> {
        repo.validate_snapshot(&self.source, cancel)?;
        if permit.binding.request != self.request {
            return Err(Error::Invalid(
                "build plan does not match exact signed request",
            ));
        }
        let execution = broker
            .execute(task, permit, &self.snapshot, identity, cancel)
            .map_err(|e| match e {
                melissa_execution_broker::BrokerError::AfterDispatch(e) => {
                    Error::AfterDispatch(Box::new(Error::Broker(*e)))
                }
                e => Error::Broker(e),
            })?;
        let current = repo
            .validate_snapshot(&self.source, &AtomicBool::new(false))
            .is_ok();
        let mut report = normalize::analyze(self, &execution, current);
        // The broker's raw, authenticated execution report is retained even if
        // an additional typed artifact cannot be persisted.
        if !execution.requires_reconciliation {
            for (i, raw) in report.raw_logs.iter_mut().enumerate() {
                for (stream, bytes, id) in [
                    ("stdout", &raw.stdout, &mut raw.stdout_artifact_id),
                    ("stderr", &raw.stderr, &mut raw.stderr_artifact_id),
                ] {
                    let artifact_id = format!("{}:build-log:{i}:{stream}", identity.attempt_id);
                    broker
                        .store_mut()
                        .put_artifact(
                            &ArtifactRequest {
                                artifact_id: artifact_id.clone(),
                                task_id: task.into(),
                                content_type: "application/octet-stream".into(),
                                logical_type: "build.raw-log".into(),
                                schema_version: "melissa.raw-tool-output/v1".into(),
                                retain_until_ms: 0,
                                legal_hold: true,
                            },
                            bytes,
                        )
                        .map_err(|e| Error::AfterDispatch(Box::new(Error::Store(e))))?;
                    *id = Some(artifact_id);
                }
            }
        }
        let report_artifact_id = format!("{}:build-report", identity.attempt_id);
        if !execution.requires_reconciliation {
            let bytes = serde_json::to_vec(&report)
                .map_err(|e| Error::AfterDispatch(Box::new(Error::Json(e))))?;
            broker
                .store_mut()
                .put_artifact(
                    &ArtifactRequest {
                        artifact_id: report_artifact_id.clone(),
                        task_id: task.into(),
                        content_type: "application/json".into(),
                        logical_type: "build.normalized-report".into(),
                        schema_version: CONTRACT.into(),
                        retain_until_ms: 0,
                        legal_hold: true,
                    },
                    &bytes,
                )
                .map_err(|e| Error::AfterDispatch(Box::new(Error::Store(e))))?;
        }
        let report_artifact_id = (!execution.requires_reconciliation).then_some(report_artifact_id);
        Ok(RustExecution {
            execution,
            report,
            report_artifact_id,
        })
    }
}

fn commands(op: RustOperation) -> Vec<CommandSpec> {
    let command = |stage: &str, executable: &str, args: &[&str]| CommandSpec {
        stage: stage.into(),
        executable: executable.into(),
        argv: args.iter().map(|s| s.to_string()).collect(),
    };
    let mut result = vec![
        command("rustc-version", RUSTC, &["--version", "--verbose"]),
        command("cargo-version", CARGO, &["--version"]),
        command(
            "metadata",
            CARGO,
            &["metadata", "--format-version=1", "--locked", "--offline"],
        ),
    ];
    let mut args: Vec<&str> = match op {
        RustOperation::Build => vec!["build"],
        RustOperation::Check => vec!["check"],
        RustOperation::Clippy => vec!["clippy"],
        RustOperation::FormatCheck => vec!["fmt"],
        RustOperation::Test { .. } => vec!["test", "--no-run", "--lib", "--tests"],
    };
    if op == RustOperation::FormatCheck {
        args.extend(["--all", "--", "--check"]);
    } else {
        args.extend([
            "--workspace",
            "--locked",
            "--offline",
            "--target-dir",
            ".melissa-code06-target",
            "--message-format=json",
        ]);
        if op == RustOperation::Clippy {
            args.extend(["--", "-D", "warnings"]);
        }
    }
    result.push(command("primary", CARGO, &args));
    result
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| {
            let digit = |v| match v {
                b'0'..=b'9' => Some(v - b'0'),
                b'a'..=b'f' => Some(v - b'a' + 10),
                _ => None,
            };
            Some(digit(b[0])? * 16 + digit(b[1])?)
        })
        .collect()
}
