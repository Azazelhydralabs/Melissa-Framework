//! Trusted-host Docker executor: immutable Linux image, read-only root and one
//! capacity-bounded tmpfs. No worker receives host mounts or daemon access.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, sync::atomic::AtomicBool};
mod archive;
pub mod recovery;
mod runtime;

pub const EXECUTION_CONTRACT: &str = "linux.docker.readonly-tmpfs/v1";
const MAX_CAPTURE: u64 = 64 * 1024 * 1024;
pub type ExecutorResult<T = ()> = Result<T, ExecutorError>;

#[derive(Debug)]
pub enum ExecutorError {
    CancelledBeforeLaunch,
    Invalid(String),
    Unsupported(String),
    Control(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}
impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancelledBeforeLaunch => f.write_str("cancelled before workload launch"),
            Self::Invalid(s) => write!(f, "invalid container request: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported container execution: {s}"),
            Self::Control(s) => write!(f, "container control failure: {s}"),
            Self::Io(e) => e.fmt(f),
            Self::Json(_) => f.write_str("invalid container control JSON"),
        }
    }
}
impl std::error::Error for ExecutorError {}
impl From<std::io::Error> for ExecutorError {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}
impl From<serde_json::Error> for ExecutorError {
    fn from(v: serde_json::Error) -> Self {
        Self::Json(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerLimits {
    pub wall_time_ms: u64,
    /// Aggregate user+kernel CPU is observed, not an absolute hard lifetime cap.
    pub cpu_time_ms: u64,
    /// 10,000 means one CPU. CFS bandwidth is a hard rate, not a lifetime budget.
    pub cpu_rate_basis_points: u32,
    pub memory_bytes: u64,
    /// Page-aligned allocated tmpfs capacity, including open-unlinked data.
    pub disk_bytes: u64,
    pub output_bytes: u64,
    /// Linux cgroup pids includes threads and the one trusted keeper process.
    pub max_processes: u32,
    pub export_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRequest {
    pub schema_version: String,
    pub image_id: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub limits: ContainerLimits,
}
impl ContainerRequest {
    pub fn validate(&self) -> ExecutorResult {
        let bad = |s: &str| Err(ExecutorError::Invalid(s.into()));
        if self.schema_version != "melissa.container-exec/v1" {
            return bad("unsupported version");
        }
        if !self.image_id.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return bad("immutable image SHA256 ID required");
        }
        if !self.executable.starts_with('/')
            || self.executable.contains(['\0', '\\'])
            || self.executable.split('/').any(|p| p == "..")
        {
            return bad("absolute native Linux executable required");
        }
        if self.cwd != "." {
            archive::safe_name(&self.cwd)?;
        }
        if self.argv.len() > 1024
            || self.argv.iter().any(|v| v.contains('\0'))
            || self.env.len() > 128
        {
            return bad("argument/environment bounds");
        }
        let mut size = self.executable.len() + self.cwd.len();
        for value in &self.argv {
            size = size
                .checked_add(value.len())
                .ok_or_else(|| ExecutorError::Invalid("size overflow".into()))?;
        }
        for (name, value) in &self.env {
            if name.is_empty()
                || !name.is_ascii()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || name.starts_with(|c: char| c.is_ascii_digit())
                || value.contains('\0')
            {
                return bad("invalid environment entry");
            }
            if [
                "HOME",
                "TMPDIR",
                "TMP",
                "TEMP",
                "USER",
                "LOGNAME",
                "CARGO_HOME",
                "CARGO_TARGET_DIR",
            ]
            .contains(&name.as_str())
                || name.starts_with("DOCKER_")
            {
                return bad("reserved environment key");
            }
            size = size
                .checked_add(name.len() + value.len())
                .ok_or_else(|| ExecutorError::Invalid("size overflow".into()))?;
        }
        if size > 64 * 1024 {
            return bad("request text exceeds bound");
        }
        let l = &self.limits;
        if l.wall_time_ms == 0
            || l.wall_time_ms > 1_800_000
            || l.cpu_time_ms == 0
            || l.cpu_time_ms > 1_800_000
            || !(1..=10_000).contains(&l.cpu_rate_basis_points)
        {
            return bad("wall/CPU bounds");
        }
        if l.cpu_rate_basis_points < 10 {
            return Err(ExecutorError::Unsupported("CFS minimum quota cannot enforce less than 10 basis points with a one-second period".into()));
        }
        if l.memory_bytes < 32 * 1024 * 1024
            || l.memory_bytes > 8 * 1024 * 1024 * 1024
            || l.disk_bytes < 4096
            || !l.disk_bytes.is_multiple_of(4096)
            || l.disk_bytes > l.memory_bytes / 2
        {
            return bad("positive page-aligned tmpfs capacity must fit half the memory limit");
        }
        if l.output_bytes > MAX_CAPTURE
            || l.export_bytes > MAX_CAPTURE
            || l.export_bytes < 1024
            || l.max_processes > 4096
        {
            return bad("output/export/pid bounds");
        }
        if l.max_processes < 8 {
            return Err(ExecutorError::Unsupported("Docker OCI exec initialization requires a supported quota of at least eight total cgroup PIDs; the requested quota is never increased".into()));
        }
        Ok(())
    }
    pub fn digest(&self) -> ExecutorResult<String> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(format!(
            "blake3:{}",
            blake3::hash(&serde_json::to_vec(&value)?).to_hex()
        ))
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub files: BTreeMap<String, Vec<u8>>,
}
impl Snapshot {
    pub fn validate(&self, max_bytes: u64) -> ExecutorResult {
        if self.files.len() > 1024 {
            return Err(ExecutorError::Invalid("snapshot file count".into()));
        }
        let mut total = 0u64;
        for (name, data) in &self.files {
            archive::safe_name(name)?;
            if name == ".melissa-runtime" || name.starts_with(".melissa-runtime/") {
                return Err(ExecutorError::Invalid("reserved snapshot path".into()));
            }
            total = total
                .checked_add(data.len() as u64)
                .ok_or_else(|| ExecutorError::Invalid("snapshot size overflow".into()))?;
            if total > max_bytes.min(MAX_CAPTURE) {
                return Err(ExecutorError::Invalid("snapshot byte bound".into()));
            }
            let mut parent = name.as_str();
            while let Some((head, _)) = parent.rsplit_once('/') {
                if self.files.contains_key(head) {
                    return Err(ExecutorError::Invalid(
                        "snapshot file-directory collision".into(),
                    ));
                }
                parent = head;
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> ExecutorResult<String> {
        self.validate(MAX_CAPTURE)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"melissa.container-snapshot/v1\0");
        for (name, data) in &self.files {
            hash.update(&(name.len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            hash.update(&(data.len() as u64).to_le_bytes());
            hash.update(data);
        }
        Ok(format!("blake3:{}", hash.finalize().to_hex()))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Exited,
    Cancelled,
    Timeout,
    CpuLimit,
    OutputLimit,
    ExportLimit,
    OrphanDescendants,
    MonitorFailure,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerReport {
    pub execution_contract: String,
    /// Identity and bytes of the fixed, handle-pinned trusted host client.
    pub docker_client_identity: String,
    pub container_id: String,
    pub image_id: String,
    pub input_digest: String,
    pub termination: TerminationReason,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Raw untrusted tar. The host must never extract it without a separate
    /// bounded path/type validator; archive truncation is explicitly reported.
    pub archive: Vec<u8>,
    pub export_truncated: bool,
    pub output_truncated: bool,
    pub cleanup_confirmed: bool,
    pub tree_confirmed_stopped: bool,
    pub policy_verified: bool,
    pub disk_limit_hard_enforced: bool,
    pub cpu_rate_hard_enforced: bool,
    pub total_cpu_limit_sampled: bool,
    pub total_cpu_time_ms: u64,
    pub cpu_measurement_complete: bool,
    pub memory_usage_at_snapshot_bytes: u64,
    pub elapsed_ms: u64,
    pub orphan_process_ids: Vec<u64>,
    pub effective_environment: BTreeMap<String, String>,
    pub monitor_error: Option<String>,
    pub guest_deadline_guard: bool,
    pub guest_deadline_seconds: u64,
}
pub struct Executor;
/// Host-owned JSON-line pipes for one already authorized isolated process.
/// This does not open another process, container, network route or host mount.
/// The caller must validate application messages and persist them as evidence.
pub struct Conversation {
    pub input: std::sync::mpsc::Receiver<Vec<u8>>,
    pub output: std::sync::mpsc::SyncSender<Vec<u8>>,
}
impl Executor {
    pub fn run(
        request: &ContainerRequest,
        snapshot: &Snapshot,
        cancelled: &AtomicBool,
    ) -> ExecutorResult<ContainerReport> {
        request.validate()?;
        snapshot.validate(request.limits.disk_bytes)?;
        runtime::run(request, snapshot, cancelled, &mut |_| Ok(()))
    }
    /// A trusted host may persist the actual owned resource before any process
    /// starts. Callback failure triggers owned cleanup and prevents launch.
    pub fn run_with_observer(
        request: &ContainerRequest,
        snapshot: &Snapshot,
        cancelled: &AtomicBool,
        observer: &mut dyn FnMut(&str) -> ExecutorResult,
    ) -> ExecutorResult<ContainerReport> {
        request.validate()?;
        snapshot.validate(request.limits.disk_bytes)?;
        runtime::run(request, snapshot, cancelled, observer)
    }
    pub fn run_with_io(
        request: &ContainerRequest,
        snapshot: &Snapshot,
        cancelled: &AtomicBool,
        observer: &mut dyn FnMut(&str) -> ExecutorResult,
        conversation: Option<Conversation>,
    ) -> ExecutorResult<ContainerReport> {
        request.validate()?;
        snapshot.validate(request.limits.disk_bytes)?;
        runtime::run_interactive(request, snapshot, cancelled, observer, conversation)
    }
}
