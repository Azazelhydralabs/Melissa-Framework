//! Exact, independently granted control of a broker-owned invocation. This
//! module never accepts an arbitrary PID or derives control from an exec permit.
//! The broker resolves ownership/generation and consumes the control nonce in a
//! durable transaction before inspecting or requesting cancellation.

use crate::policy::{
    HostPolicy, PermitAuthority, PermitRequest, PolicyError, PolicyResult, authenticated_digest,
    decode_mac,
};
use melissa_core_contracts::{
    catalog::Catalog,
    validation::{ContractError, ContractResult, Validate},
    wire::{ExecutionPermitV2, TaskContractV1},
};
use serde::{Deserialize, Serialize};

const CONTROL_MAC_DOMAIN: &[u8] = b"melissa.execution-broker.control-permit-mac/v1\0";
const MAX_CONTROL_DURATION_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlTool {
    #[serde(rename = "process.inspect")]
    Inspect,
    #[serde(rename = "process.cancel")]
    Cancel,
}
impl ControlTool {
    pub fn tool_id(self) -> &'static str {
        match self {
            Self::Inspect => "process.inspect",
            Self::Cancel => "process.cancel",
        }
    }
    pub fn effect(self) -> &'static str {
        match self {
            Self::Inspect => "process.inspect_owned",
            Self::Cancel => "process.cancel_owned",
        }
    }
    fn required_capability(self) -> &'static str {
        match self {
            Self::Inspect => "process.execute_scoped",
            Self::Cancel => "process.cancel_owned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessControlRequest {
    pub schema_version: String,
    pub tool: ControlTool,
    pub task_id: String,
    pub invocation_id: String,
    pub generation: u64,
    pub resource_id: String,
}
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
impl Validate for ProcessControlRequest {
    fn validate(&self) -> ContractResult {
        valid(
            self.schema_version == "melissa.process-control/v1",
            "schema_version",
            "unsupported control request version",
        )?;
        for (path, value) in [
            ("task_id", &self.task_id),
            ("invocation_id", &self.invocation_id),
            ("resource_id", &self.resource_id),
        ] {
            valid(
                identifier(value),
                path,
                "bounded nonempty identifier without control characters required",
            )?;
        }
        valid(
            self.invocation_id.len() <= 160,
            "invocation_id",
            "invocation identifier exceeds broker limit",
        )?;
        valid(
            self.generation <= i64::MAX as u64,
            "generation",
            "generation exceeds durable storage representation",
        )
    }
}
impl ProcessControlRequest {
    pub fn arguments_digest(&self) -> PolicyResult<String> {
        self.validate()?;
        let canonical = serde_json::to_value(self)
            .map_err(|_| PolicyError::Invalid("control serialization failed".into()))?;
        let bytes = serde_json::to_vec(&canonical)
            .map_err(|_| PolicyError::Invalid("control serialization failed".into()))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

/// Independently reviewed host authority. Neither the model nor ownership of an
/// execution permit is sufficient to create this trusted-host object.
#[derive(Debug, Clone, Serialize)]
pub struct ControlGrant {
    pub authorization_ref: String,
    pub task_id: String,
    pub task_digest: String,
    pub principal_id: String,
    pub profile_id: String,
    pub resource_id: String,
    pub tool: ControlTool,
    pub invocation_id: String,
    pub generation: u64,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPermitBinding {
    pub schema_version: String,
    pub key_id: String,
    pub policy_digest: String,
    pub revocation_epoch: u64,
    pub task_digest: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub request: ProcessControlRequest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlPermit {
    pub permit: ExecutionPermitV2,
    pub binding: ControlPermitBinding,
}
impl Validate for SignedControlPermit {
    fn validate(&self) -> ContractResult {
        self.permit.validate()?;
        valid(
            self.binding.schema_version == "melissa.control-permit-binding/v1",
            "binding.schema_version",
            "unsupported control binding version",
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
        ] {
            valid(digest(value), path, "BLAKE3 digest required")?;
        }
        self.binding.request.validate()
    }
}

impl PermitAuthority {
    pub fn issue_control(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        control: ProcessControlRequest,
        request: PermitRequest,
        policy: &HostPolicy,
        now: u64,
    ) -> PolicyResult<SignedControlPermit> {
        control.validate()?;
        for value in [
            &request.permit_id,
            &request.nonce,
            &request.principal_id,
            &request.profile_id,
            &request.resource_id,
            &request.authorization_ref,
        ] {
            demand(identifier(value), "invalid control permit identifier")?;
        }
        let profile = catalog
            .profiles
            .get(&request.profile_id)
            .ok_or_else(|| PolicyError::Denied("unknown control profile".into()))?;
        let max_duration = MAX_CONTROL_DURATION_MS
            .min(task.limits.max_wall_time_ms)
            .min(policy.ceiling.wall_time_ms)
            .min(
                request
                    .expires_at_unix_ms
                    .saturating_sub(request.not_before_unix_ms),
            );
        let mut signed = SignedControlPermit {
            permit: ExecutionPermitV2 {
                schema_version: "melissa.execution-permit/v2".into(),
                permit_id: request.permit_id,
                task_id: task.task_id.clone(),
                principal_id: request.principal_id,
                tool_id: control.tool.tool_id().into(),
                resource_id: request.resource_id,
                arguments_digest: control.arguments_digest()?,
                allowed_effects: vec![control.tool.effect().into()],
                not_before_unix_ms: request.not_before_unix_ms,
                expires_at_unix_ms: request.expires_at_unix_ms,
                max_invocations: 1,
                max_duration_ms: max_duration,
                issuer: policy.issuer.clone(),
                audience: policy.audience.clone(),
                nonce: request.nonce,
                policy_version: policy.revision.clone(),
                authorization_ref: request.authorization_ref,
                signature_or_mac: "pending-authentication".into(),
            },
            binding: ControlPermitBinding {
                schema_version: "melissa.control-permit-binding/v1".into(),
                key_id: policy.key_id.clone(),
                policy_digest: policy.digest()?,
                revocation_epoch: policy.revocation_epoch,
                task_digest: authenticated_digest(task)?,
                profile_id: request.profile_id,
                profile_digest: authenticated_digest(profile)?,
                request: control,
            },
        };
        check_control(catalog, task, &signed, policy, now)?;
        signed.permit.signature_or_mac = self.control_mac(&signed)?.to_hex().to_string();
        Ok(signed)
    }

    /// Fresh policy and task must be supplied. This authenticates a request; it
    /// does not verify target ownership, consume a nonce or send a cancel signal.
    pub fn verify_control(
        &self,
        catalog: &Catalog,
        task: &TaskContractV1,
        signed: &SignedControlPermit,
        current_request: &ProcessControlRequest,
        policy: &HostPolicy,
        now: u64,
    ) -> PolicyResult {
        signed.validate()?;
        if decode_mac(&signed.permit.signature_or_mac)? != self.control_mac(signed)? {
            return Err(PolicyError::Authentication);
        }
        demand(
            &signed.binding.request == current_request,
            "managed control target changed",
        )?;
        check_control(catalog, task, signed, policy, now)
    }
    fn control_mac(&self, signed: &SignedControlPermit) -> PolicyResult<blake3::Hash> {
        let mut unsigned = signed.clone();
        unsigned.permit.signature_or_mac.clear();
        self.keyed_mac(CONTROL_MAC_DOMAIN, &unsigned)
    }
}

fn check_control(
    catalog: &Catalog,
    task: &TaskContractV1,
    signed: &SignedControlPermit,
    policy: &HostPolicy,
    now: u64,
) -> PolicyResult {
    signed.validate()?;
    signed.permit.validate_against_task(task)?;
    policy.validate()?;
    let permit = &signed.permit;
    let binding = &signed.binding;
    let control = &binding.request;
    demand(
        control.task_id == task.task_id
            && control.resource_id == permit.resource_id
            && permit.tool_id == control.tool.tool_id()
            && permit.allowed_effects == [control.tool.effect()]
            && permit.arguments_digest == control.arguments_digest()?,
        "control permit target/tool/effects disagree",
    )?;
    demand(
        permit.issuer == policy.issuer
            && permit.audience == policy.audience
            && binding.key_id == policy.key_id,
        "control issuer/audience/key identity mismatch",
    )?;
    demand(
        permit.policy_version == policy.revision
            && binding.revocation_epoch == policy.revocation_epoch
            && binding.policy_digest == policy.digest()?,
        "control policy changed",
    )?;
    demand(
        !policy
            .revoked_authorization_refs
            .contains(&permit.authorization_ref)
            && !policy.revoked_permit_ids.contains(&permit.permit_id)
            && !policy.revoked_nonces.contains(&permit.nonce),
        "control authorization revoked",
    )?;
    demand(
        now >= permit.not_before_unix_ms && now < permit.expires_at_unix_ms,
        "control permit not currently valid",
    )?;
    demand(
        permit
            .expires_at_unix_ms
            .checked_sub(permit.not_before_unix_ms)
            .is_some_and(|n| n <= policy.max_permit_lifetime_ms),
        "control validity exceeds host maximum",
    )?;
    demand(
        permit.max_duration_ms <= MAX_CONTROL_DURATION_MS
            && permit.max_duration_ms <= policy.ceiling.wall_time_ms,
        "control duration exceeds implementation or host maximum",
    )?;
    demand(
        binding.task_digest == authenticated_digest(task)?
            && task.selected_profile_ids.contains(&binding.profile_id),
        "control task/profile changed or unselected",
    )?;
    let profile = catalog
        .profiles
        .get(&binding.profile_id)
        .ok_or_else(|| PolicyError::Denied("unknown control profile".into()))?;
    demand(
        profile.module == task.module && binding.profile_digest == authenticated_digest(profile)?,
        "control profile changed or module mismatch",
    )?;
    demand(
        profile.tool_ids.iter().any(|s| s == control.tool.tool_id())
            && profile
                .authority
                .capability_ceiling
                .iter()
                .any(|s| s == control.tool.required_capability())
            && !profile
                .authority
                .forbidden_effects
                .iter()
                .any(|s| s == control.tool.effect()),
        "profile lacks exact control tool/capability",
    )?;
    demand(
        profile.worker_types.iter().any(|s| s == "generic")
            && catalog
                .workers
                .get("generic")
                .is_some_and(|w| w.modules.contains(&task.module))
            && catalog.tools.tools.iter().any(|t| {
                t.id == control.tool.tool_id()
                    && t.family == "process"
                    && t.worker_candidates.iter().any(|s| s == "generic")
            }),
        "exact managed control route absent from catalog",
    )?;
    let grant = policy
        .control_grants
        .get(&permit.authorization_ref)
        .ok_or_else(|| PolicyError::Denied("no separately reviewed host control grant".into()))?;
    demand(
        grant.authorization_ref == permit.authorization_ref
            && grant.task_id == task.task_id
            && grant.task_digest == binding.task_digest
            && grant.principal_id == permit.principal_id
            && grant.profile_id == binding.profile_id
            && grant.resource_id == control.resource_id
            && grant.tool == control.tool
            && grant.invocation_id == control.invocation_id
            && grant.generation == control.generation,
        "host control grant scope mismatch",
    )?;
    demand(
        now >= grant.not_before_unix_ms
            && now < grant.expires_at_unix_ms
            && permit.not_before_unix_ms >= grant.not_before_unix_ms
            && permit.expires_at_unix_ms <= grant.expires_at_unix_ms,
        "host control grant not valid for permit window",
    )
}
