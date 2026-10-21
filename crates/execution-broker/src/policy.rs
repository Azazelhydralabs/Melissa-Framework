//! Trusted-host admission and authenticated, exact-command permits.
//!
//! Catalog metadata and model/task strings never constitute an authorization.
//! The host supplies reviewed grants, enforcement capabilities, policy and a
//! secret key. This module performs no execution, nonce consumption or path I/O;
//! the broker must re-resolve handles and atomically consume before dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};

use melissa_core_contracts::catalog::Catalog;
use melissa_core_contracts::validation::{ContractError, ContractResult, Validate};
use melissa_core_contracts::wire::{ExecutionPermitV2, TaskContractV1};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAC_DOMAIN: &[u8] = b"melissa.execution-broker.permit-mac/v1\0";
const MAX_COMMAND_BYTES: usize = 64 * 1024;

/// Authenticated native environment contract: inherit no parent environment;
/// reject caller-owned OS/control/credential variables; inject OS-derived
/// SystemRoot plus fresh private-AppContainer LOCALAPPDATA and profile Temp
/// TEMP/TMP. Windows remaps these values at process creation; effective child
/// values are execution evidence. A fresh profile is allocated per run.
pub const HOST_EXECUTION_CONTRACT_VERSION: &str = "windows.appcontainer.job.environment/v2";

pub fn reserved_environment_name(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "SYSTEMROOT"
            | "LOCALAPPDATA"
            | "TEMP"
            | "TMP"
            | "PATH"
            | "PATHEXT"
            | "COMSPEC"
            | "WINDIR"
            | "SYSTEMDRIVE"
            | "USERPROFILE"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "APPDATA"
            | "AWS_ACCESS_KEY_ID"
            | "AWS_SECRET_ACCESS_KEY"
            | "AWS_SESSION_TOKEN"
            | "OPENAI_API_KEY"
            | "ANTHROPIC_API_KEY"
            | "AZURE_OPENAI_API_KEY"
            | "GOOGLE_APPLICATION_CREDENTIALS"
            | "GITHUB_TOKEN"
            | "GH_TOKEN"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Invalid(String),
    Denied(String),
    Unsupported(String),
    Authentication,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid policy input: {message}"),
            Self::Denied(message) => write!(f, "policy denied: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported execution: {message}"),
            Self::Authentication => f.write_str("permit authentication failed"),
        }
    }
}
impl std::error::Error for PolicyError {}
impl From<ContractError> for PolicyError {
    fn from(error: ContractError) -> Self {
        Self::Invalid(error.to_string())
    }
}
pub type PolicyResult<T = ()> = Result<T, PolicyError>;

fn demand(condition: bool, message: &str) -> PolicyResult {
    if condition {
        Ok(())
    } else {
        Err(PolicyError::Denied(message.into()))
    }
}
fn valid(condition: bool, path: &str, message: &str) -> ContractResult {
    if condition {
        Ok(())
    } else {
        Err(ContractError::new(path, message))
    }
}
fn clean(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('\0')
}
fn digest_valid(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimitMode {
    Strict,
    Monitored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuLimitMode {
    StrictTotal,
    MonitoredTotal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLimits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    /// Hard Job Object CPU rate, in 1/100 percent of the applicable CPU capacity.
    pub cpu_rate_basis_points: u16,
    pub cpu_mode: CpuLimitMode,
    pub memory_bytes: u64,
    /// Zero is a zero allowance. In monitored mode writes can precede detection;
    /// only strict mode is a hard quota. Neither mode interprets zero as unlimited.
    pub disk_bytes: u64,
    pub disk_mode: DiskLimitMode,
    /// Shared stdout + stderr maximum, including zero.
    pub output_bytes: u64,
    pub max_processes: u32,
    pub network: NetworkPolicy,
}

impl Validate for ProcessLimits {
    fn validate(&self) -> ContractResult {
        valid(
            self.wall_time_ms > 0,
            "limits.wall_time_ms",
            "must be positive",
        )?;
        valid(
            self.cpu_time_ms > 0,
            "limits.cpu_time_ms",
            "must be positive",
        )?;
        valid(
            (1..=10_000).contains(&self.cpu_rate_basis_points),
            "limits.cpu_rate_basis_points",
            "must be within 1..=10000",
        )?;
        valid(
            self.memory_bytes > 0,
            "limits.memory_bytes",
            "must be positive",
        )?;
        valid(
            self.max_processes > 0,
            "limits.max_processes",
            "must be positive",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
    pub schema_version: String,
    /// An explicit native executable; no PATH search or shell command string.
    pub executable: String,
    pub argv: Vec<String>,
    /// A workspace-relative directory. The resolver supplies the canonical cwd.
    pub cwd: String,
    /// Exact environment: the executor must not inherit its parent's variables.
    pub env: BTreeMap<String, String>,
    pub limits: ProcessLimits,
    pub effects: Vec<String>,
    pub worker_type: String,
}

impl Validate for ProcessSpec {
    fn validate(&self) -> ContractResult {
        valid(
            self.schema_version == "melissa.process-exec/v2",
            "schema_version",
            "unsupported version",
        )?;
        valid(
            clean(&self.executable) && Path::new(&self.executable).is_absolute(),
            "executable",
            "absolute native executable required",
        )?;
        valid(
            !self.executable.starts_with("\\\\") && !self.executable.starts_with("//"),
            "executable",
            "UNC and device executables are unsupported",
        )?;
        let extension = Path::new(&self.executable)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        valid(
            !["cmd", "bat", "ps1", "vbs", "js"].contains(&extension.as_str()),
            "executable",
            "shell/script wrappers require a separate adapter",
        )?;
        valid(
            clean(&self.cwd) && !Path::new(&self.cwd).is_absolute() && !self.cwd.contains(':'),
            "cwd",
            "workspace-relative cwd required",
        )?;
        valid(
            !self.cwd.replace('\\', "/").split('/').any(|p| p == "..")
                && !Path::new(&self.cwd).components().any(|c| {
                    matches!(
                        c,
                        Component::Prefix(_) | Component::ParentDir | Component::RootDir
                    )
                }),
            "cwd",
            "parent/device traversal forbidden",
        )?;
        valid(self.argv.len() <= 1024, "argv", "too many arguments")?;
        valid(
            self.argv.iter().all(|a| !a.contains('\0')),
            "argv",
            "NUL forbidden",
        )?;
        valid(self.env.len() <= 128, "env", "too many environment entries")?;
        let mut names = BTreeSet::new();
        for (name, value) in &self.env {
            valid(
                clean(name)
                    && !name.contains('=')
                    && name.is_ascii()
                    && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    && !name.starts_with(|c: char| c.is_ascii_digit()),
                "env",
                "invalid environment name",
            )?;
            valid(
                names.insert(name.to_ascii_uppercase()),
                "env",
                "case-insensitive duplicate environment name",
            )?;
            valid(
                !reserved_environment_name(name),
                "env",
                "reserved host OS/control/credential environment variable",
            )?;
            valid(!value.contains('\0'), "env", "NUL forbidden")?;
        }
        let bytes = self
            .argv
            .iter()
            .map(String::len)
            .chain(
                self.env
                    .iter()
                    .map(|(k, v)| k.len().saturating_add(v.len())),
            )
            .try_fold(
                self.executable.len().saturating_add(self.cwd.len()),
                |sum, len| sum.checked_add(len),
            );
        valid(
            bytes.is_some_and(|n| n <= MAX_COMMAND_BYTES),
            "process",
            "command payload exceeds bound",
        )?;
        valid(
            self.argv
                .iter()
                .map(|s| s.encode_utf16().count().saturating_add(3))
                .sum::<usize>()
                .saturating_add(self.executable.encode_utf16().count())
                <= 16384,
            "argv",
            "native command line exceeds conservative bound",
        )?;
        valid(
            !self.effects.is_empty()
                && self.effects.len() <= 32
                && self.effects.iter().all(|e| clean(e))
                && self.effects.iter().collect::<BTreeSet<_>>().len() == self.effects.len(),
            "effects",
            "unique nonempty effects required",
        )?;
        valid(
            self.worker_type == "generic",
            "worker_type",
            "only exact generic process route is implemented",
        )?;
        self.limits.validate()?;
        // These are implementation limits of the selected native route, not
        // task-budget defaults. Reject before signing/consuming a permit rather
        // than converting a known-invalid launch into an unknown execution.
        valid(
            self.limits.cpu_time_ms <= i64::MAX as u64 / 10_000,
            "limits.cpu_time_ms",
            "exceeds native Job Object duration representation",
        )?;
        valid(
            self.limits.memory_bytes <= usize::MAX as u64,
            "limits.memory_bytes",
            "exceeds native address-space representation",
        )?;
        valid(
            self.limits.output_bytes <= 64 * 1024 * 1024,
            "limits.output_bytes",
            "exceeds native bounded output capture",
        )?;
        valid(
            self.env
                .iter()
                .map(|(name, value)| {
                    name.encode_utf16()
                        .count()
                        .saturating_add(value.encode_utf16().count())
                        .saturating_add(2)
                })
                .sum::<usize>()
                <= 30_000,
            "env",
            "exceeds native explicit environment representation",
        )
    }
}

/// Produced only after host path/handle validation. Serialized identities and
/// digest are authenticated again; this data alone is not an OS handle guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProcess {
    pub spec: ProcessSpec,
    pub canonical_executable: String,
    pub executable_digest: String,
    pub executable_identity: String,
    pub canonical_cwd: String,
    pub cwd_identity: String,
    pub workspace_identity: String,
}
impl Validate for ResolvedProcess {
    fn validate(&self) -> ContractResult {
        self.spec.validate()?;
        valid(
            Path::new(&self.canonical_executable).is_absolute(),
            "canonical_executable",
            "absolute path required",
        )?;
        valid(
            Path::new(&self.canonical_cwd).is_absolute(),
            "canonical_cwd",
            "absolute path required",
        )?;
        valid(
            digest_valid(&self.executable_digest),
            "executable_digest",
            "BLAKE3 digest required",
        )?;
        for (name, value) in [
            ("canonical_executable", &self.canonical_executable),
            ("canonical_cwd", &self.canonical_cwd),
            ("executable_identity", &self.executable_identity),
            ("cwd_identity", &self.cwd_identity),
            ("workspace_identity", &self.workspace_identity),
        ] {
            valid(clean(value), name, "nonempty identity without NUL required")?;
        }
        Ok(())
    }
}

pub fn authenticated_digest<T: Serialize>(value: &T) -> PolicyResult<String> {
    let bytes = canonical_bytes(value)?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}
fn canonical_bytes<T: Serialize>(value: &T) -> PolicyResult<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| PolicyError::Invalid("serialization failed".into()))?;
    // serde_json's default Map is ordered; conversion also removes Rust struct
    // field-declaration order from the authenticated byte representation.
    serde_json::to_vec(&value).map_err(|_| PolicyError::Invalid("serialization failed".into()))
}
impl ProcessSpec {
    pub fn arguments_digest(&self) -> PolicyResult<String> {
        self.validate()?;
        Ok(blake3::hash(&canonical_bytes(self)?).to_hex().to_string())
    }
}
impl ResolvedProcess {
    pub fn arguments_digest(&self) -> PolicyResult<String> {
        self.validate()?;
        self.spec.arguments_digest()
    }
    pub fn resolved_digest(&self) -> PolicyResult<String> {
        self.validate()?;
        #[derive(Serialize)]
        struct ResolvedBinding<'a> {
            execution_contract: &'static str,
            process: &'a ResolvedProcess,
        }
        authenticated_digest(&ResolvedBinding {
            execution_contract: HOST_EXECUTION_CONTRACT_VERSION,
            process: self,
        })
    }
}

/// Trusted host configuration, never constructed from a model/tool request.
#[derive(Debug, Clone)]
pub struct AuthorityGrant {
    pub authorization_ref: String,
    pub task_id: String,
    pub task_digest: String,
    pub principal_id: String,
    pub profile_id: String,
    pub resource_id: String,
    pub process_digest: String,
    pub allow_monitored_disk: bool,
    pub allow_monitored_cpu: bool,
    pub allowed_effects: BTreeSet<String>,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Claims the selected executor must actually enforce. False is fail-closed;
/// Windows Job Objects alone do not prove filesystem/network/disk isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementCapabilities {
    pub filesystem_isolation: bool,
    pub network_isolation: bool,
    pub cpu_time: bool,
    pub memory: bool,
    pub disk_quota: bool,
    pub process_tree: bool,
    pub output_limit: bool,
}

#[derive(Debug, Clone)]
pub struct HostPolicy {
    pub revision: String,
    pub revocation_epoch: u64,
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub max_permit_lifetime_ms: u64,
    /// Numeric ceilings. Mode authority is exclusively the two explicit
    /// allow_monitored_* booleans plus the reviewed grant's matching opt-in;
    /// the mode values in this ceiling do not select an execution mode.
    pub ceiling: ProcessLimits,
    pub enforcement: EnforcementCapabilities,
    pub allow_monitored_disk: bool,
    pub allow_monitored_cpu: bool,
    pub allowed_env_names: BTreeSet<String>,
    pub grants: BTreeMap<String, AuthorityGrant>,
    pub control_grants: BTreeMap<String, crate::control_policy::ControlGrant>,
    pub revoked_authorization_refs: BTreeSet<String>,
    pub revoked_permit_ids: BTreeSet<String>,
    pub revoked_nonces: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitBinding {
    pub schema_version: String,
    pub key_id: String,
    pub policy_digest: String,
    pub revocation_epoch: u64,
    pub task_digest: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub resolved_digest: String,
    pub process: ResolvedProcess,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPermit {
    pub permit: ExecutionPermitV2,
    pub binding: PermitBinding,
}
impl Validate for SignedPermit {
    fn validate(&self) -> ContractResult {
        self.permit.validate()?;
        valid(
            self.binding.schema_version == "melissa.permit-binding/v1",
            "binding.schema_version",
            "unsupported version",
        )?;
        for (path, value) in [
            ("key_id", &self.binding.key_id),
            ("profile_id", &self.binding.profile_id),
        ] {
            valid(clean(value), path, "nonempty identifier required")?;
        }
        for (path, value) in [
            ("policy_digest", &self.binding.policy_digest),
            ("task_digest", &self.binding.task_digest),
            ("profile_digest", &self.binding.profile_digest),
            ("resolved_digest", &self.binding.resolved_digest),
        ] {
            valid(digest_valid(value), path, "BLAKE3 digest required")?;
        }
        self.binding.process.validate()
    }
}

#[derive(Debug, Clone)]
pub struct PermitRequest {
    pub permit_id: String,
    pub nonce: String,
    pub principal_id: String,
    pub profile_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Independently provisioned MAC key. Debug and serialization never expose it.
pub struct PermitMacKey(Zeroizing<[u8; 32]>);
impl PermitMacKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
impl fmt::Debug for PermitMacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PermitMacKey([REDACTED])")
    }
}
#[derive(Debug)]
pub struct PermitAuthority {
    key: PermitMacKey,
}
impl PermitAuthority {
    pub fn new(key: PermitMacKey) -> Self {
        Self { key }
    }

    pub fn issue(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        process: ResolvedProcess,
        request: PermitRequest,
        policy: &HostPolicy,
        now_unix_ms: u64,
    ) -> PolicyResult<SignedPermit> {
        for value in [
            &request.permit_id,
            &request.nonce,
            &request.principal_id,
            &request.profile_id,
            &request.resource_id,
            &request.authorization_ref,
        ] {
            demand(
                clean(value) && value.len() <= 256,
                "invalid request identifier",
            )?;
        }
        let profile = catalog
            .profiles
            .get(&request.profile_id)
            .ok_or_else(|| PolicyError::Denied("unknown profile".into()))?;
        let mut signed = SignedPermit {
            permit: ExecutionPermitV2 {
                schema_version: "melissa.execution-permit/v2".into(),
                permit_id: request.permit_id,
                task_id: task.task_id.clone(),
                principal_id: request.principal_id,
                tool_id: "process.exec".into(),
                resource_id: request.resource_id,
                arguments_digest: process.arguments_digest()?,
                allowed_effects: process.spec.effects.clone(),
                not_before_unix_ms: request.not_before_unix_ms,
                expires_at_unix_ms: request.expires_at_unix_ms,
                max_invocations: 1,
                max_duration_ms: process.spec.limits.wall_time_ms,
                issuer: policy.issuer.clone(),
                audience: policy.audience.clone(),
                nonce: request.nonce,
                policy_version: policy.revision.clone(),
                authorization_ref: request.authorization_ref,
                signature_or_mac: "pending-authentication".into(),
            },
            binding: PermitBinding {
                schema_version: "melissa.permit-binding/v1".into(),
                key_id: policy.key_id.clone(),
                policy_digest: policy.digest()?,
                revocation_epoch: policy.revocation_epoch,
                task_digest: authenticated_digest(task)?,
                profile_id: request.profile_id,
                profile_digest: authenticated_digest(profile)?,
                resolved_digest: process.resolved_digest()?,
                process,
            },
        };
        self.check(catalog, task, &signed, policy, now_unix_ms)?;
        signed.permit.signature_or_mac = self.mac(&signed)?.to_hex().to_string();
        Ok(signed)
    }

    /// Caller must supply fresh current policy and host clock at consumption.
    /// Authenticity is not one-use consumption: durable broker ledger owns that.
    pub fn verify(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        signed: &SignedPermit,
        current_process: &ResolvedProcess,
        policy: &HostPolicy,
        now_unix_ms: u64,
    ) -> PolicyResult {
        signed.validate()?;
        let supplied = decode_mac(&signed.permit.signature_or_mac)?;
        // blake3::Hash equality uses constant-time comparison (not hex/string ==).
        if supplied != self.mac(signed)? {
            return Err(PolicyError::Authentication);
        }
        demand(
            &signed.binding.process == current_process,
            "resolved process changed after permit issuance",
        )?;
        self.check(catalog, task, signed, policy, now_unix_ms)
    }

    fn mac(&self, signed: &SignedPermit) -> PolicyResult<blake3::Hash> {
        let mut unsigned = signed.clone();
        unsigned.permit.signature_or_mac.clear();
        self.keyed_mac(MAC_DOMAIN, &unsigned)
    }

    pub(crate) fn keyed_mac<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
    ) -> PolicyResult<blake3::Hash> {
        let bytes = canonical_bytes(value)?;
        let mut hasher = blake3::Hasher::new_keyed(&self.key.0);
        hasher.update(domain);
        hasher.update(&bytes);
        Ok(hasher.finalize())
    }

    fn check(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        signed: &SignedPermit,
        policy: &HostPolicy,
        now: u64,
    ) -> PolicyResult {
        signed.validate()?;
        signed.permit.validate_against_task(task)?;
        policy.validate()?;
        let permit = &signed.permit;
        let binding = &signed.binding;
        demand(
            permit.tool_id == "process.exec",
            "unknown or unimplemented exact tool route",
        )?;
        demand(
            catalog.tools.tools.iter().any(|tool| {
                tool.id == permit.tool_id
                    && tool.family == "process"
                    && tool
                        .worker_candidates
                        .contains(&binding.process.spec.worker_type)
            }),
            "exact tool/worker route is absent from catalog",
        )?;
        demand(
            permit.issuer == policy.issuer
                && permit.audience == policy.audience
                && binding.key_id == policy.key_id,
            "issuer/audience/key identity mismatch",
        )?;
        demand(
            permit.policy_version == policy.revision
                && binding.revocation_epoch == policy.revocation_epoch
                && binding.policy_digest == policy.digest()?,
            "policy changed or revoked",
        )?;
        demand(
            !policy
                .revoked_authorization_refs
                .contains(&permit.authorization_ref)
                && !policy.revoked_permit_ids.contains(&permit.permit_id)
                && !policy.revoked_nonces.contains(&permit.nonce),
            "revoked permit or authorization",
        )?;
        demand(
            now >= permit.not_before_unix_ms && now < permit.expires_at_unix_ms,
            "permit is not currently valid",
        )?;
        demand(
            permit
                .expires_at_unix_ms
                .checked_sub(permit.not_before_unix_ms)
                .is_some_and(|n| n <= policy.max_permit_lifetime_ms),
            "permit validity exceeds host maximum",
        )?;
        demand(
            binding.task_digest == authenticated_digest(task)?,
            "task changed",
        )?;
        demand(
            task.selected_profile_ids.contains(&binding.profile_id),
            "profile not selected by task",
        )?;
        let profile = catalog
            .profiles
            .get(&binding.profile_id)
            .ok_or_else(|| PolicyError::Denied("unknown profile".into()))?;
        demand(
            profile.module == task.module
                && binding.profile_digest == authenticated_digest(profile)?,
            "profile changed or module mismatch",
        )?;
        demand(
            profile.tool_ids.contains(&permit.tool_id)
                && profile
                    .authority
                    .capability_ceiling
                    .iter()
                    .any(|c| c == "process.execute_scoped"),
            "profile lacks exact process capability",
        )?;
        demand(
            profile
                .worker_types
                .contains(&binding.process.spec.worker_type)
                && catalog
                    .workers
                    .get(&binding.process.spec.worker_type)
                    .is_some_and(|worker| worker.modules.contains(&task.module)),
            "worker outside selected profile",
        )?;
        demand(
            binding
                .process
                .spec
                .effects
                .iter()
                .all(|e| !profile.authority.forbidden_effects.contains(e)),
            "profile forbids requested effect",
        )?;
        demand(
            binding
                .process
                .spec
                .effects
                .iter()
                .all(|e| profile.authority.capability_ceiling.contains(e)),
            "effect outside profile capability ceiling",
        )?;
        // The implemented route mounts an owned workspace read/write. A caller
        // cannot obtain read-only authority merely by describing read-only argv.
        demand(
            ["process.execute_scoped", "workspace.apply_patch_scoped"]
                .iter()
                .all(|required| binding.process.spec.effects.iter().any(|e| e == required)),
            "read/write process route requires explicit process and scoped workspace-write effects",
        )?;
        demand(
            permit.allowed_effects == binding.process.spec.effects
                && permit.arguments_digest == binding.process.arguments_digest()?
                && binding.resolved_digest == binding.process.resolved_digest()?
                && permit.max_duration_ms == binding.process.spec.limits.wall_time_ms,
            "permit and process binding disagree",
        )?;
        let grant = policy
            .grants
            .get(&permit.authorization_ref)
            .ok_or_else(|| PolicyError::Denied("no trusted host authorization grant".into()))?;
        demand(
            grant.authorization_ref == permit.authorization_ref
                && grant.task_id == task.task_id
                && grant.task_digest == binding.task_digest
                && grant.principal_id == permit.principal_id
                && grant.profile_id == binding.profile_id
                && grant.resource_id == permit.resource_id
                && grant.process_digest == binding.resolved_digest,
            "host authorization scope mismatch",
        )?;
        demand(
            now >= grant.not_before_unix_ms
                && now < grant.expires_at_unix_ms
                && permit.not_before_unix_ms >= grant.not_before_unix_ms
                && permit.expires_at_unix_ms <= grant.expires_at_unix_ms,
            "host authorization expired or narrower",
        )?;
        demand(
            permit
                .allowed_effects
                .iter()
                .all(|e| grant.allowed_effects.contains(e)),
            "effect outside trusted host grant",
        )?;
        let requested = &binding.process.spec.limits;
        demand(
            requested.wall_time_ms <= task.limits.max_wall_time_ms
                && requested.disk_bytes <= task.limits.max_disk_bytes
                && requested.output_bytes <= task.limits.max_output_bytes,
            "process exceeds task budget",
        )?;
        demand(
            requested.wall_time_ms <= policy.ceiling.wall_time_ms
                && requested.cpu_time_ms <= policy.ceiling.cpu_time_ms
                && requested.cpu_rate_basis_points <= policy.ceiling.cpu_rate_basis_points
                && requested.memory_bytes <= policy.ceiling.memory_bytes
                && requested.disk_bytes <= policy.ceiling.disk_bytes
                && requested.output_bytes <= policy.ceiling.output_bytes
                && requested.max_processes <= policy.ceiling.max_processes,
            "process exceeds host resource ceiling",
        )?;
        demand(
            binding.process.spec.env.keys().all(|name| {
                policy
                    .allowed_env_names
                    .contains(&name.to_ascii_uppercase())
            }),
            "environment variable outside host allowlist",
        )?;
        let caps = &policy.enforcement;
        match requested.disk_mode {
            DiskLimitMode::Strict if !caps.disk_quota => {
                return Err(PolicyError::Unsupported(
                    "strict disk quota is not implemented by this executor".into(),
                ));
            }
            DiskLimitMode::Monitored => demand(
                requested.disk_bytes > 0
                    && policy.allow_monitored_disk
                    && grant.allow_monitored_disk,
                "positive monitored disk requires explicit host policy and reviewed grant opt-in",
            )?,
            DiskLimitMode::Strict => {}
        }
        match requested.cpu_mode {
            CpuLimitMode::StrictTotal if !caps.cpu_time => {
                return Err(PolicyError::Unsupported(
                    "strict aggregate CPU quota is not implemented by this executor".into(),
                ));
            }
            CpuLimitMode::MonitoredTotal => demand(
                policy.allow_monitored_cpu && grant.allow_monitored_cpu,
                "monitored CPU requires explicit host policy and reviewed grant opt-in",
            )?,
            CpuLimitMode::StrictTotal => {}
        }
        if !(caps.filesystem_isolation
            && caps.network_isolation
            && caps.memory
            && caps.process_tree
            && caps.output_limit)
        {
            return Err(PolicyError::Unsupported(
                "executor cannot enforce every requested resource and isolation boundary".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn decode_mac(value: &str) -> PolicyResult<blake3::Hash> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(PolicyError::Authentication);
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        bytes[i] = digit(chunk[0]) * 16 + digit(chunk[1]);
    }
    Ok(blake3::Hash::from_bytes(bytes))
}

impl HostPolicy {
    pub(crate) fn validate(&self) -> PolicyResult {
        self.ceiling.validate()?;
        demand(
            [&self.revision, &self.issuer, &self.audience, &self.key_id]
                .iter()
                .all(|s| clean(s)),
            "invalid policy identity",
        )?;
        demand(self.max_permit_lifetime_ms > 0, "invalid permit lifetime")?;
        demand(
            self.allowed_env_names
                .iter()
                .all(|s| clean(s) && *s == s.to_ascii_uppercase()),
            "environment allowlist must use uppercase names",
        )?;
        Ok(())
    }

    /// Includes all mutable admission policy and reviewed grant material.
    pub fn digest(&self) -> PolicyResult<String> {
        #[derive(Serialize)]
        struct Grant<'a> {
            authorization_ref: &'a str,
            task_id: &'a str,
            task_digest: &'a str,
            principal_id: &'a str,
            profile_id: &'a str,
            resource_id: &'a str,
            process_digest: &'a str,
            allow_monitored_disk: bool,
            allow_monitored_cpu: bool,
            allowed_effects: &'a BTreeSet<String>,
            not_before_unix_ms: u64,
            expires_at_unix_ms: u64,
        }
        let grants: BTreeMap<_, _> = self
            .grants
            .iter()
            .map(|(id, g)| {
                (
                    id,
                    Grant {
                        authorization_ref: &g.authorization_ref,
                        task_id: &g.task_id,
                        task_digest: &g.task_digest,
                        principal_id: &g.principal_id,
                        profile_id: &g.profile_id,
                        resource_id: &g.resource_id,
                        process_digest: &g.process_digest,
                        allow_monitored_disk: g.allow_monitored_disk,
                        allow_monitored_cpu: g.allow_monitored_cpu,
                        allowed_effects: &g.allowed_effects,
                        not_before_unix_ms: g.not_before_unix_ms,
                        expires_at_unix_ms: g.expires_at_unix_ms,
                    },
                )
            })
            .collect();
        #[derive(Serialize)]
        struct PolicyIdentity<'a, T> {
            version: &'static str,
            revision: &'a str,
            revocation_epoch: u64,
            issuer: &'a str,
            audience: &'a str,
            key_id: &'a str,
            max_permit_lifetime_ms: u64,
            ceiling: &'a ProcessLimits,
            enforcement: &'a EnforcementCapabilities,
            allow_monitored_disk: bool,
            allow_monitored_cpu: bool,
            allowed_env_names: &'a BTreeSet<String>,
            grants: T,
            control_grants: &'a BTreeMap<String, crate::control_policy::ControlGrant>,
            revoked_authorization_refs: &'a BTreeSet<String>,
            revoked_permit_ids: &'a BTreeSet<String>,
            revoked_nonces: &'a BTreeSet<String>,
        }
        authenticated_digest(&PolicyIdentity {
            version: "melissa.host-policy/v1",
            revision: &self.revision,
            revocation_epoch: self.revocation_epoch,
            issuer: &self.issuer,
            audience: &self.audience,
            key_id: &self.key_id,
            max_permit_lifetime_ms: self.max_permit_lifetime_ms,
            ceiling: &self.ceiling,
            enforcement: &self.enforcement,
            allow_monitored_disk: self.allow_monitored_disk,
            allow_monitored_cpu: self.allow_monitored_cpu,
            allowed_env_names: &self.allowed_env_names,
            grants,
            control_grants: &self.control_grants,
            revoked_authorization_refs: &self.revoked_authorization_refs,
            revoked_permit_ids: &self.revoked_permit_ids,
            revoked_nonces: &self.revoked_nonces,
        })
    }
}
