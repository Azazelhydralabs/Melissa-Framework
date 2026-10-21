//! Authentication for an immutable-image, read-only-root container route with
//! hard allocated tmpfs capacity. Container identities never impersonate native
//! Windows PE handles. Total lifetime CPU is explicitly monitored; hard CPU rate
//! and memory limits remain separate resource contracts.

use crate::policy::{
    HostPolicy, PermitAuthority, PermitRequest, PolicyError, PolicyResult, authenticated_digest,
    decode_mac,
};
use melissa_container_executor::{ContainerRequest, EXECUTION_CONTRACT};
use melissa_core_contracts::{
    catalog::Catalog,
    validation::{ContractError, ContractResult, Validate},
    wire::{ExecutionPermitV2, TaskContractV1},
};
use serde::{Deserialize, Serialize};

const CONTAINER_MAC_DOMAIN: &[u8] = b"melissa.execution-broker.container-permit-mac/v1\0";
const EFFECTS: [&str; 2] = ["process.execute_scoped", "workspace.apply_patch_scoped"];
fn identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn digest(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn valid(condition: bool, path: &str, message: &str) -> ContractResult {
    if condition {
        Ok(())
    } else {
        Err(ContractError::new(path, message))
    }
}
fn demand(condition: bool, message: &str) -> PolicyResult {
    if condition {
        Ok(())
    } else {
        Err(PolicyError::Denied(message.into()))
    }
}
fn request_valid(request: &ContainerRequest) -> PolicyResult {
    request
        .validate()
        .map_err(|e| PolicyError::Invalid(e.to_string()))
}

/// Bind all input content and the selected backend in the reviewed host grant.
/// The caller must compute snapshot_digest from the actual immutable Snapshot.
pub fn container_execution_digest(
    request: &ContainerRequest,
    snapshot_digest: &str,
) -> PolicyResult<String> {
    request_valid(request)?;
    demand(digest(snapshot_digest), "BLAKE3 snapshot digest required")?;
    authenticated_digest(
        &serde_json::json!({"request":request,"snapshot_digest":snapshot_digest,"backend_contract":EXECUTION_CONTRACT}),
    )
}
pub fn container_arguments_digest(request: &ContainerRequest) -> PolicyResult<String> {
    request_valid(request)?;
    let value = serde_json::to_value(request)
        .map_err(|_| PolicyError::Invalid("container request serialization failed".into()))?;
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| PolicyError::Invalid("container request serialization failed".into()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPermitBinding {
    pub schema_version: String,
    pub key_id: String,
    pub policy_digest: String,
    pub revocation_epoch: u64,
    pub task_digest: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub snapshot_digest: String,
    pub execution_digest: String,
    pub request: ContainerRequest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContainerPermit {
    pub permit: ExecutionPermitV2,
    pub binding: ContainerPermitBinding,
}
impl Validate for SignedContainerPermit {
    fn validate(&self) -> ContractResult {
        self.permit.validate()?;
        valid(
            self.binding.schema_version == "melissa.container-permit-binding/v1",
            "binding.schema_version",
            "unsupported container binding version",
        )?;
        for (path, value) in [
            ("key_id", &self.binding.key_id),
            ("profile_id", &self.binding.profile_id),
        ] {
            valid(
                identifier(value),
                path,
                "bounded nonempty identity required",
            )?;
        }
        for (path, value) in [
            ("policy_digest", &self.binding.policy_digest),
            ("task_digest", &self.binding.task_digest),
            ("profile_digest", &self.binding.profile_digest),
            ("snapshot_digest", &self.binding.snapshot_digest),
            ("execution_digest", &self.binding.execution_digest),
        ] {
            valid(digest(value), path, "BLAKE3 digest required")?;
        }
        self.binding
            .request
            .validate()
            .map_err(|e| ContractError::new("binding.request", e.to_string()))
    }
}

impl PermitAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn issue_container(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        container: ContainerRequest,
        snapshot_digest: String,
        request: PermitRequest,
        policy: &HostPolicy,
        now: u64,
    ) -> PolicyResult<SignedContainerPermit> {
        request_valid(&container)?;
        for value in [
            &request.permit_id,
            &request.nonce,
            &request.principal_id,
            &request.profile_id,
            &request.resource_id,
            &request.authorization_ref,
        ] {
            demand(identifier(value), "invalid container permit identifier")?;
        }
        let profile = catalog
            .profiles
            .get(&request.profile_id)
            .ok_or_else(|| PolicyError::Denied("unknown container profile".into()))?;
        let mut signed = SignedContainerPermit {
            permit: ExecutionPermitV2 {
                schema_version: "melissa.execution-permit/v2".into(),
                permit_id: request.permit_id,
                task_id: task.task_id.clone(),
                principal_id: request.principal_id,
                tool_id: "process.exec".into(),
                resource_id: request.resource_id,
                arguments_digest: container_arguments_digest(&container)?,
                allowed_effects: EFFECTS.iter().map(|s| (*s).into()).collect(),
                not_before_unix_ms: request.not_before_unix_ms,
                expires_at_unix_ms: request.expires_at_unix_ms,
                max_invocations: 1,
                max_duration_ms: container.limits.wall_time_ms,
                issuer: policy.issuer.clone(),
                audience: policy.audience.clone(),
                nonce: request.nonce,
                policy_version: policy.revision.clone(),
                authorization_ref: request.authorization_ref,
                signature_or_mac: "pending-authentication".into(),
            },
            binding: ContainerPermitBinding {
                schema_version: "melissa.container-permit-binding/v1".into(),
                key_id: policy.key_id.clone(),
                policy_digest: policy.digest()?,
                revocation_epoch: policy.revocation_epoch,
                task_digest: authenticated_digest(task)?,
                profile_id: request.profile_id,
                profile_digest: authenticated_digest(profile)?,
                execution_digest: container_execution_digest(&container, &snapshot_digest)?,
                snapshot_digest,
                request: container,
            },
        };
        check_container(catalog, task, &signed, policy, now)?;
        signed.permit.signature_or_mac = self.container_mac(&signed)?.to_hex().to_string();
        Ok(signed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_container(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        signed: &SignedContainerPermit,
        current_request: &ContainerRequest,
        current_snapshot_digest: &str,
        policy: &HostPolicy,
        now: u64,
    ) -> PolicyResult {
        signed.validate()?;
        if decode_mac(&signed.permit.signature_or_mac)? != self.container_mac(signed)? {
            return Err(PolicyError::Authentication);
        }
        demand(
            &signed.binding.request == current_request
                && signed.binding.snapshot_digest == current_snapshot_digest,
            "container request or input snapshot changed",
        )?;
        check_container(catalog, task, signed, policy, now)
    }
    fn container_mac(&self, signed: &SignedContainerPermit) -> PolicyResult<blake3::Hash> {
        let mut unsigned = signed.clone();
        unsigned.permit.signature_or_mac.clear();
        self.keyed_mac(CONTAINER_MAC_DOMAIN, &unsigned)
    }
}

fn check_container(
    catalog: &Catalog,
    task: &TaskContractV1,
    signed: &SignedContainerPermit,
    policy: &HostPolicy,
    now: u64,
) -> PolicyResult {
    signed.validate()?;
    signed.permit.validate_against_task(task)?;
    policy.validate()?;
    let permit = &signed.permit;
    let binding = &signed.binding;
    let request = &binding.request;
    demand(
        permit.tool_id == "process.exec"
            && permit.allowed_effects == EFFECTS
            && permit.arguments_digest == container_arguments_digest(request)?
            && binding.execution_digest
                == container_execution_digest(request, &binding.snapshot_digest)?
            && permit.max_duration_ms == request.limits.wall_time_ms,
        "container permit route/arguments/effects disagree",
    )?;
    demand(
        permit.issuer == policy.issuer
            && permit.audience == policy.audience
            && binding.key_id == policy.key_id,
        "container issuer/audience/key identity mismatch",
    )?;
    demand(
        permit.policy_version == policy.revision
            && binding.revocation_epoch == policy.revocation_epoch
            && binding.policy_digest == policy.digest()?,
        "container policy changed",
    )?;
    demand(
        !policy
            .revoked_authorization_refs
            .contains(&permit.authorization_ref)
            && !policy.revoked_permit_ids.contains(&permit.permit_id)
            && !policy.revoked_nonces.contains(&permit.nonce),
        "container permit revoked",
    )?;
    demand(
        now >= permit.not_before_unix_ms && now < permit.expires_at_unix_ms,
        "container permit not currently valid",
    )?;
    demand(
        permit
            .expires_at_unix_ms
            .checked_sub(permit.not_before_unix_ms)
            .is_some_and(|n| n <= policy.max_permit_lifetime_ms),
        "container permit lifetime exceeds host maximum",
    )?;
    demand(
        binding.task_digest == authenticated_digest(task)?
            && task.selected_profile_ids.contains(&binding.profile_id),
        "container task/profile changed or unselected",
    )?;
    let profile = catalog
        .profiles
        .get(&binding.profile_id)
        .ok_or_else(|| PolicyError::Denied("unknown container profile".into()))?;
    demand(
        profile.module == task.module && binding.profile_digest == authenticated_digest(profile)?,
        "container profile changed or module mismatch",
    )?;
    demand(
        profile.tool_ids.iter().any(|s| s == "process.exec")
            && profile.worker_types.iter().any(|s| s == "generic")
            && EFFECTS.iter().all(|e| {
                profile.authority.capability_ceiling.iter().any(|s| s == e)
                    && !profile.authority.forbidden_effects.iter().any(|s| s == e)
            }),
        "container profile lacks exact route/effects",
    )?;
    demand(
        catalog
            .workers
            .get("generic")
            .is_some_and(|w| w.modules.contains(&task.module))
            && catalog.tools.tools.iter().any(|t| {
                t.id == "process.exec"
                    && t.family == "process"
                    && t.worker_candidates.iter().any(|s| s == "generic")
            }),
        "container exact tool/worker route absent",
    )?;
    let grant = policy
        .grants
        .get(&permit.authorization_ref)
        .ok_or_else(|| {
            PolicyError::Denied("no separately reviewed container execution grant".into())
        })?;
    demand(
        grant.authorization_ref == permit.authorization_ref
            && grant.task_id == task.task_id
            && grant.task_digest == binding.task_digest
            && grant.principal_id == permit.principal_id
            && grant.profile_id == binding.profile_id
            && grant.resource_id == permit.resource_id
            && grant.process_digest == binding.execution_digest
            && EFFECTS.iter().all(|s| grant.allowed_effects.contains(*s)),
        "container host grant scope mismatch",
    )?;
    demand(
        now >= grant.not_before_unix_ms
            && now < grant.expires_at_unix_ms
            && permit.not_before_unix_ms >= grant.not_before_unix_ms
            && permit.expires_at_unix_ms <= grant.expires_at_unix_ms,
        "container host grant window mismatch",
    )?;
    demand(
        policy.allow_monitored_cpu && grant.allow_monitored_cpu,
        "container total lifetime CPU monitoring requires explicit host policy and reviewed grant opt-in",
    )?;
    let limits = &request.limits;
    let ceiling = &policy.ceiling;
    let output = limits
        .output_bytes
        .checked_add(limits.export_bytes)
        .ok_or_else(|| PolicyError::Denied("container aggregate output budget overflow".into()))?;
    demand(
        limits.wall_time_ms <= task.limits.max_wall_time_ms
            && limits.disk_bytes <= task.limits.max_disk_bytes
            && output <= task.limits.max_output_bytes,
        "container exceeds task resource budget",
    )?;
    demand(
        limits.wall_time_ms <= ceiling.wall_time_ms
            && limits.cpu_time_ms <= ceiling.cpu_time_ms
            && limits.cpu_rate_basis_points <= u32::from(ceiling.cpu_rate_basis_points)
            && limits.memory_bytes <= ceiling.memory_bytes
            && limits.disk_bytes <= ceiling.disk_bytes
            && output <= ceiling.output_bytes
            && limits.max_processes <= ceiling.max_processes,
        "container exceeds host resource ceiling",
    )?;
    demand(
        request.env.keys().all(|name| {
            policy
                .allowed_env_names
                .contains(&name.to_ascii_uppercase())
                && !crate::policy::reserved_environment_name(name)
        }),
        "container environment exceeds host allowlist",
    )?;
    let enforced = &policy.enforcement;
    if !(enforced.filesystem_isolation
        && enforced.network_isolation
        && enforced.memory
        && enforced.disk_quota
        && enforced.process_tree
        && enforced.output_limit)
    {
        return Err(PolicyError::Unsupported(
            "container backend cannot enforce required strict allocated storage and isolation"
                .into(),
        ));
    }
    Ok(())
}
