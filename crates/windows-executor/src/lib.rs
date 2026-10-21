//! Native Windows AppContainer + Job Object execution. No unrestricted fallback.
//!
//! This is a host-only API: arguments, environment and the owned workspace must
//! already be authorized by a broker. AppContainer admits common Windows runtime
//! resources and its private profile as well as explicitly granted files. It is
//! not a claim that every file outside `workspace` is invisible. Disk monitoring
//! is sampled accounting, never a strict filesystem/volume quota.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, path::PathBuf, sync::atomic::AtomicBool};

#[cfg(windows)]
mod fswalk;
#[cfg(windows)]
mod native;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Offline,
    Allowlist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimitMode {
    Strict,
    Monitored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    /// OS hard scheduling-interval rate, 1..=10000 basis points of host CPU.
    pub cpu_rate_basis_points: u16,
    pub memory_bytes: u64,
    pub max_processes: u32,
    pub max_output_bytes: u64,
    pub max_workspace_bytes: u64,
    pub gpu_required: bool,
}

#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub executable: PathBuf,
    /// Exactly `blake3:` followed by 64 lowercase hex characters.
    pub executable_blake3: String,
    /// An owned, staged directory. This API never grants its parent access.
    pub workspace: PathBuf,
    /// Exact current directory, canonically contained in the owned workspace.
    pub current_directory: PathBuf,
    pub arguments: Vec<String>,
    /// Explicit environment only; no inheritance, PATH or credentials. The
    /// executor injects OS-derived SystemRoot. Windows maps LOCALAPPDATA and
    /// TEMP/TMP into the unique AppContainer private profile.
    pub environment: BTreeMap<String, String>,
    pub limits: ExecutionLimits,
    pub network: NetworkMode,
    pub disk_mode: DiskLimitMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Exited,
    Cancelled,
    Timeout,
    OutputLimit,
    CpuLimit,
    MemoryLimit,
    ProcessLimit,
    DiskLimit,
    MonitorFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorReport {
    pub environment_contract: String,
    pub effective_environment: BTreeMap<String, String>,
    pub termination: TerminationReason,
    pub root_process_id: u32,
    pub exit_code: u32,
    pub tree_confirmed_stopped: bool,
    pub process_was_appcontainer: bool,
    pub win32k_system_calls_disabled: bool,
    pub descendant_cleanup_required: bool,
    pub descendant_drain_grace_ms: u64,
    pub natural_job_drain_ms: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
    pub elapsed_ms: u64,
    pub total_cpu_time_ms: u64,
    /// Raw OS PeakJobMemoryUsed. It may exceed the configured limit on this
    /// host and is not clamped or equated to successful probe allocations.
    pub peak_job_committed_memory_bytes: u64,
    /// Unnamed regular-file logical bytes only. ADS, registry, transient and
    /// open-deleted writes are outside this partial sampled measurement.
    pub peak_observed_workspace_and_profile_bytes: u64,
    pub disk_measurement_complete: bool,
    pub disk_overshoot_bytes: u64,
    pub disk_limit_hard_enforced: bool,
    pub total_cpu_limit_sampled: bool,
    pub user_cpu_limit_hard_enforced: bool,
    pub cpu_rate_basis_points: u16,
    pub cpu_rate_hard_enforced: bool,
    pub profile_removed: bool,
    /// Original resource DACL/labels restored and generated file SID grants
    /// revoked. Generated files retain their low integrity label until import.
    pub acl_restored: bool,
}

#[derive(Debug)]
pub enum ExecutorError {
    CancelledBeforeLaunch,
    InvalidRequest(String),
    Unsupported(String),
    Security(String),
    Io(std::io::Error),
}
impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancelledBeforeLaunch => write!(f, "cancelled before sandbox launch"),
            Self::InvalidRequest(s) => write!(f, "invalid request: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Security(s) => write!(f, "security boundary failure: {s}"),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ExecutorError {}
impl From<std::io::Error> for ExecutorError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct Executor;
pub const ENVIRONMENT_CONTRACT: &str = "windows.appcontainer.job.environment/v2";
pub const DESCENDANT_DRAIN_GRACE_MS: u64 = 100;
impl Executor {
    pub fn run(
        request: &ExecuteRequest,
        cancelled: &AtomicBool,
    ) -> Result<ExecutorReport, ExecutorError> {
        validate_request(request)?;
        #[cfg(windows)]
        {
            native::run(request, cancelled)
        }
        #[cfg(not(windows))]
        {
            let _ = cancelled;
            Err(ExecutorError::Unsupported(
                "Windows AppContainer host required".into(),
            ))
        }
    }
}

fn validate_request(r: &ExecuteRequest) -> Result<(), ExecutorError> {
    let bad = |s: &str| Err(ExecutorError::InvalidRequest(s.into()));
    if r.disk_mode == DiskLimitMode::Strict {
        return Err(ExecutorError::Unsupported("strict directory/volume disk quota is unavailable; monitored disk requires explicit host opt-in".into()));
    }
    if r.network != NetworkMode::Offline {
        return Err(ExecutorError::Unsupported(
            "network allowlist executor is unavailable".into(),
        ));
    }
    if r.limits.gpu_required {
        return Err(ExecutorError::Unsupported(
            "GPU isolation/accounting is unavailable".into(),
        ));
    }
    if r.limits.wall_time_ms == 0
        || r.limits.cpu_time_ms == 0
        || r.limits.memory_bytes == 0
        || r.limits.max_processes == 0
        || r.limits.max_workspace_bytes == 0
    {
        return bad("wall/cpu/memory/process/disk limits must be positive");
    }
    if r.limits.memory_bytes > usize::MAX as u64
        || r.limits.cpu_time_ms > (i64::MAX as u64 / 10_000)
        || r.limits.max_output_bytes > 64 * 1024 * 1024
    {
        return bad("resource limit exceeds host implementation bounds");
    }
    if !(1..=10000).contains(&r.limits.cpu_rate_basis_points) {
        return bad("CPU rate must be 1..=10000 basis points");
    }
    let Some(hash) = r.executable_blake3.strip_prefix("blake3:") else {
        return bad("BLAKE3 executable digest required");
    };
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return bad("invalid executable digest");
    }
    if !r.executable.is_absolute()
        || !r.workspace.is_absolute()
        || !r.current_directory.is_absolute()
    {
        return bad("absolute executable and workspace required");
    }
    if r.arguments.len() > 1024 || r.environment.len() > 128 {
        return bad("argument/environment entry limit");
    }
    if r.arguments.iter().any(|s| s.contains('\0'))
        || r.environment
            .iter()
            .any(|(k, v)| k.is_empty() || k.contains(['\0', '=']) || v.contains('\0'))
    {
        return bad("invalid argument/environment characters");
    }
    let mut keys = std::collections::BTreeSet::new();
    if r.environment.keys().any(|k| !keys.insert(k.to_uppercase())) {
        return bad("case-insensitive duplicate environment key");
    }
    if r.environment.keys().any(|key| {
        matches!(
            key.to_uppercase().as_str(),
            "SYSTEMROOT" | "LOCALAPPDATA" | "TEMP" | "TMP"
        )
    }) {
        return bad("reserved native environment key");
    }
    if r.arguments
        .iter()
        .map(|s| s.encode_utf16().count())
        .sum::<usize>()
        > 24_000
        || r.environment
            .iter()
            .map(|(k, v)| k.encode_utf16().count() + v.encode_utf16().count() + 2)
            .sum::<usize>()
            > 30_000
    {
        return bad("argument/environment size limit");
    }
    Ok(())
}
