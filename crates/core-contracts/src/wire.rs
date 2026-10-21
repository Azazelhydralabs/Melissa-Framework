//! Versioned wire contracts. Validation checks data shape and local invariants;
//! it does not authenticate a permit, execute work, or verify an external effect.
//!
//! The existing v1 schemas remain intact. Version 2 explicitly carries the
//! blueprint's per-invocation duration and semantic observation information.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::Module;
use crate::validation::{
    ContractResult, Validate, exact_version, non_blank, require, unique_non_blank,
};

// Required nullable fields are different from optional fields. Without this
// adapter serde accepts a missing Option<T>, silently weakening the v1 schema.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn nullable_non_blank(value: Option<&str>, path: &str) -> ContractResult {
    if let Some(value) = value {
        non_blank(value, path)?;
    }
    Ok(())
}

fn map_keys_non_blank<T>(values: &BTreeMap<String, T>, path: &str) -> ContractResult {
    for key in values.keys() {
        non_blank(key, path)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLimitsV1 {
    pub max_wall_time_ms: u64,
    pub max_cost_micro_usd: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_parallel_jobs: u64,
    pub max_disk_bytes: u64,
    pub max_output_bytes: u64,
}

impl Validate for TaskLimitsV1 {
    fn validate(&self) -> ContractResult {
        require(
            self.max_wall_time_ms > 0,
            "limits.max_wall_time_ms",
            "must be positive",
        )?;
        require(
            self.max_parallel_jobs > 0,
            "limits.max_parallel_jobs",
            "must be positive",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContractV1 {
    pub schema_version: String,
    pub task_id: String,
    pub module: Module,
    pub goal: String,
    pub workspace_ref: String,
    pub input_snapshot_digest: String,
    pub acceptance_contract_digest: String,
    pub acceptance_criteria: Vec<String>,
    pub selected_profile_ids: Vec<String>,
    pub allowed_resource_ids: Vec<String>,
    pub allowed_effects: Vec<String>,
    pub authorization_refs: Vec<String>,
    pub limits: TaskLimitsV1,
    pub authority_source: String,
}

impl Validate for TaskContractV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.task-contract/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("task_id", self.task_id.as_str()),
            ("goal", self.goal.as_str()),
            ("workspace_ref", self.workspace_ref.as_str()),
            ("input_snapshot_digest", self.input_snapshot_digest.as_str()),
            (
                "acceptance_contract_digest",
                self.acceptance_contract_digest.as_str(),
            ),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.acceptance_criteria, "acceptance_criteria", 1)?;
        unique_non_blank(&self.selected_profile_ids, "selected_profile_ids", 1)?;
        unique_non_blank(&self.allowed_resource_ids, "allowed_resource_ids", 1)?;
        unique_non_blank(&self.allowed_effects, "allowed_effects", 1)?;
        unique_non_blank(&self.authorization_refs, "authorization_refs", 0)?;
        require(
            self.authority_source == "user_task_and_rust_policy",
            "authority_source",
            "must be user_task_and_rust_policy",
        )?;
        self.limits.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPermitV1 {
    pub schema_version: String,
    pub permit_id: String,
    pub task_id: String,
    pub principal_id: String,
    pub tool_id: String,
    pub resource_id: String,
    pub arguments_digest: String,
    pub allowed_effects: Vec<String>,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_invocations: u64,
    pub issuer: String,
    pub audience: String,
    pub nonce: String,
    pub policy_version: String,
    pub authorization_ref: String,
    pub signature_or_mac: String,
}

impl ExecutionPermitV1 {
    /// Checks document relationships only. It never authenticates the issuer,
    /// checks revocation, consumes a nonce, or authorizes execution.
    pub fn validate_against_task(&self, task: &TaskContractV1) -> ContractResult {
        self.validate()?;
        task.validate()?;
        require(
            self.task_id == task.task_id,
            "task_id",
            "permit belongs to another task",
        )?;
        require(
            task.allowed_resource_ids.contains(&self.resource_id),
            "resource_id",
            "resource is outside the task's declared scope",
        )?;
        // A task may be valid before execution authority is bound. An empty
        // authorization list grants nothing and cannot bind any permit. Even
        // a matching declared reference still needs broker authentication.
        require(
            task.authorization_refs.contains(&self.authorization_ref),
            "authorization_ref",
            "authorization reference is not declared by the task",
        )?;
        require(
            self.allowed_effects
                .iter()
                .all(|effect| task.allowed_effects.contains(effect)),
            "allowed_effects",
            "permit effects exceed the task's declared scope",
        )
    }
}

impl Validate for ExecutionPermitV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.execution-permit/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("permit_id", self.permit_id.as_str()),
            ("task_id", self.task_id.as_str()),
            ("principal_id", self.principal_id.as_str()),
            ("tool_id", self.tool_id.as_str()),
            ("resource_id", self.resource_id.as_str()),
            ("arguments_digest", self.arguments_digest.as_str()),
            ("issuer", self.issuer.as_str()),
            ("audience", self.audience.as_str()),
            ("nonce", self.nonce.as_str()),
            ("policy_version", self.policy_version.as_str()),
            ("authorization_ref", self.authorization_ref.as_str()),
            ("signature_or_mac", self.signature_or_mac.as_str()),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.allowed_effects, "allowed_effects", 1)?;
        require(
            self.expires_at_unix_ms > self.not_before_unix_ms,
            "expires_at_unix_ms",
            "must be later than not_before_unix_ms",
        )?;
        require(
            self.max_invocations == 1,
            "max_invocations",
            "must be exactly one",
        )
    }
}

/// An explicit v2 instead of silently making duration optional in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPermitV2 {
    pub schema_version: String,
    pub permit_id: String,
    pub task_id: String,
    pub principal_id: String,
    pub tool_id: String,
    pub resource_id: String,
    pub arguments_digest: String,
    pub allowed_effects: Vec<String>,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_invocations: u64,
    pub max_duration_ms: u64,
    pub issuer: String,
    pub audience: String,
    pub nonce: String,
    pub policy_version: String,
    pub authorization_ref: String,
    pub signature_or_mac: String,
}

impl ExecutionPermitV2 {
    fn v1_fields(&self) -> ExecutionPermitV1 {
        ExecutionPermitV1 {
            schema_version: "melissa.execution-permit/v1".into(),
            permit_id: self.permit_id.clone(),
            task_id: self.task_id.clone(),
            principal_id: self.principal_id.clone(),
            tool_id: self.tool_id.clone(),
            resource_id: self.resource_id.clone(),
            arguments_digest: self.arguments_digest.clone(),
            allowed_effects: self.allowed_effects.clone(),
            not_before_unix_ms: self.not_before_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            max_invocations: self.max_invocations,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            nonce: self.nonce.clone(),
            policy_version: self.policy_version.clone(),
            authorization_ref: self.authorization_ref.clone(),
            signature_or_mac: self.signature_or_mac.clone(),
        }
    }

    pub fn validate_against_task(&self, task: &TaskContractV1) -> ContractResult {
        self.validate()?;
        self.v1_fields().validate_against_task(task)?;
        require(
            self.max_duration_ms <= task.limits.max_wall_time_ms,
            "max_duration_ms",
            "invocation duration exceeds the task's declared wall-time limit",
        )
    }
}

impl Validate for ExecutionPermitV2 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.execution-permit/v2",
            "schema_version",
        )?;
        // Reuse v1's semantic rules without accepting v1 as a v2 wire document.
        self.v1_fields().validate()?;
        require(
            self.max_duration_ms > 0,
            "max_duration_ms",
            "must be positive",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Success,
    Failed,
    Cancelled,
    TimedOut,
    Blocked,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    NotStarted,
    Observed,
    NoEffect,
    Unknown,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObservationV1 {
    pub schema_version: String,
    pub task_id: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub tool_id: String,
    pub status: ObservationStatus,
    pub effect_status: EffectStatus,
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub exit_code: Option<i64>,
    pub duration_ms: u64,
    pub truncated: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub error_category: Option<String>,
    pub resource_usage: BTreeMap<String, Value>,
    pub input_digest: String,
    #[serde(deserialize_with = "required_nullable")]
    pub output_digest: Option<String>,
    pub environment_ref: String,
}

impl Validate for ToolObservationV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.tool-observation/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("task_id", self.task_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("attempt_id", self.attempt_id.as_str()),
            ("tool_id", self.tool_id.as_str()),
            ("summary", self.summary.as_str()),
            ("input_digest", self.input_digest.as_str()),
            ("environment_ref", self.environment_ref.as_str()),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.artifact_refs, "artifact_refs", 0)?;
        unique_non_blank(&self.evidence_refs, "evidence_refs", 0)?;
        nullable_non_blank(self.output_digest.as_deref(), "output_digest")?;
        nullable_non_blank(self.error_category.as_deref(), "error_category")?;
        require(
            (self.status == ObservationStatus::OutcomeUnknown)
                == (self.effect_status == EffectStatus::Unknown),
            "effect_status",
            "unknown effect must be reported as outcome_unknown, and vice versa",
        )?;
        if self.status == ObservationStatus::Success {
            require(
                self.error_category.is_none(),
                "error_category",
                "successful observation cannot report an error",
            )?;
            require(
                self.exit_code.is_none_or(|code| code == 0),
                "exit_code",
                "successful observation cannot report a failing process exit",
            )?;
            require(
                self.effect_status != EffectStatus::NotStarted,
                "effect_status",
                "successful operation must have started",
            )?;
        } else {
            require(
                self.error_category.is_some(),
                "error_category",
                "unsuccessful observation needs an error category",
            )?;
        }
        if self.status == ObservationStatus::Blocked {
            require(
                matches!(
                    self.effect_status,
                    EffectStatus::NotStarted | EffectStatus::NoEffect
                ),
                "effect_status",
                "blocked operation cannot claim an observed or reconciled effect",
            )?;
        }
        if self.effect_status == EffectStatus::NotStarted {
            require(
                self.exit_code.is_none(),
                "exit_code",
                "operation that never started cannot report a process exit",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationArtifactV2 {
    pub r#type: String,
    pub uri: String,
}

impl Validate for ObservationArtifactV2 {
    fn validate(&self) -> ContractResult {
        non_blank(&self.r#type, "artifacts.type")?;
        non_blank(&self.uri, "artifacts.uri")
    }
}

/// Semantic metrics such as passed/failed counts are separate from CPU/RAM
/// usage. Metric values retain JSON types, units and nested domain metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObservationV2 {
    pub schema_version: String,
    pub task_id: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub tool_id: String,
    pub status: ObservationStatus,
    pub effect_status: EffectStatus,
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub exit_code: Option<i64>,
    pub duration_ms: u64,
    pub truncated: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub error_category: Option<String>,
    pub resource_usage: BTreeMap<String, Value>,
    pub input_digest: String,
    #[serde(deserialize_with = "required_nullable")]
    pub output_digest: Option<String>,
    pub environment_ref: String,
    pub artifacts: Vec<ObservationArtifactV2>,
    pub metrics: BTreeMap<String, Value>,
    pub warnings: Vec<String>,
}

impl Validate for ToolObservationV2 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.tool-observation/v2",
            "schema_version",
        )?;
        ToolObservationV1 {
            schema_version: "melissa.tool-observation/v1".into(),
            task_id: self.task_id.clone(),
            invocation_id: self.invocation_id.clone(),
            attempt_id: self.attempt_id.clone(),
            tool_id: self.tool_id.clone(),
            status: self.status,
            effect_status: self.effect_status,
            summary: self.summary.clone(),
            artifact_refs: self.artifact_refs.clone(),
            evidence_refs: self.evidence_refs.clone(),
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            truncated: self.truncated,
            error_category: self.error_category.clone(),
            resource_usage: self.resource_usage.clone(),
            input_digest: self.input_digest.clone(),
            output_digest: self.output_digest.clone(),
            environment_ref: self.environment_ref.clone(),
        }
        .validate()?;
        map_keys_non_blank(&self.metrics, "metrics")?;
        unique_non_blank(&self.warnings, "warnings", 0)?;
        let mut uris = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            require(
                uris.insert(&artifact.uri),
                "artifacts",
                "artifact URI must be unique",
            )?;
            require(
                self.artifact_refs.contains(&artifact.uri),
                "artifacts.uri",
                "typed artifact must also appear in artifact_refs",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    NotRun,
    Pending,
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerificationStatus {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceResultV1 {
    pub criterion: String,
    pub passed: bool,
    pub evidence_refs: Vec<String>,
}

impl Validate for AcceptanceResultV1 {
    fn validate(&self) -> ContractResult {
        non_blank(&self.criterion, "acceptance_results.criterion")?;
        unique_non_blank(&self.evidence_refs, "acceptance_results.evidence_refs", 1)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifestV1 {
    pub schema_version: String,
    pub evidence_id: String,
    pub task_id: String,
    pub run_id: String,
    pub input_digest: String,
    pub output_digest: String,
    pub artifact_refs: Vec<String>,
    pub invocation_ids: Vec<String>,
    pub tool_versions: BTreeMap<String, Value>,
    pub environment_ref: String,
    pub verifier_id: String,
    pub verifier_version: String,
    pub protected_acceptance_digest: String,
    pub acceptance_contract_digest: String,
    pub verification_status: EvidenceVerificationStatus,
    pub acceptance_results: Vec<AcceptanceResultV1>,
    pub developer_intervention: bool,
    pub created_at: String,
}

impl EvidenceManifestV1 {
    /// A structurally valid record can retain a developer-assisted pass. It
    /// must never qualify as an autonomous pass. This is not host attestation.
    pub fn is_autonomous_pass(&self) -> bool {
        self.validate().is_ok()
            && self.verification_status == EvidenceVerificationStatus::Passed
            && !self.developer_intervention
    }

    /// Binding to a declared task does not authenticate any referenced artifact.
    pub fn validate_against_task(&self, task: &TaskContractV1) -> ContractResult {
        self.validate()?;
        task.validate()?;
        require(
            self.task_id == task.task_id,
            "task_id",
            "evidence belongs to another task",
        )?;
        require(
            self.acceptance_contract_digest == task.acceptance_contract_digest,
            "acceptance_contract_digest",
            "evidence refers to another acceptance contract",
        )?;
        let actual: BTreeSet<&str> = self
            .acceptance_results
            .iter()
            .map(|result| result.criterion.as_str())
            .collect();
        let expected: BTreeSet<&str> = task
            .acceptance_criteria
            .iter()
            .map(String::as_str)
            .collect();
        require(
            actual == expected,
            "acceptance_results",
            "evidence must account for exactly the declared acceptance criteria",
        )
    }
}

impl Validate for EvidenceManifestV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.evidence-manifest/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("evidence_id", self.evidence_id.as_str()),
            ("task_id", self.task_id.as_str()),
            ("run_id", self.run_id.as_str()),
            ("input_digest", self.input_digest.as_str()),
            ("output_digest", self.output_digest.as_str()),
            ("environment_ref", self.environment_ref.as_str()),
            ("verifier_id", self.verifier_id.as_str()),
            ("verifier_version", self.verifier_version.as_str()),
            (
                "protected_acceptance_digest",
                self.protected_acceptance_digest.as_str(),
            ),
            (
                "acceptance_contract_digest",
                self.acceptance_contract_digest.as_str(),
            ),
            ("created_at", self.created_at.as_str()),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.artifact_refs, "artifact_refs", 1)?;
        unique_non_blank(&self.invocation_ids, "invocation_ids", 1)?;
        require(
            !self.tool_versions.is_empty(),
            "tool_versions",
            "must contain at least one tool",
        )?;
        map_keys_non_blank(&self.tool_versions, "tool_versions")?;
        require(
            !self.acceptance_results.is_empty(),
            "acceptance_results",
            "must contain at least one criterion",
        )?;
        let mut criteria = BTreeSet::new();
        for result in &self.acceptance_results {
            result.validate()?;
            require(
                criteria.insert(&result.criterion),
                "acceptance_results.criterion",
                "criterion must be unique",
            )?;
        }
        let all_passed = self.acceptance_results.iter().all(|result| result.passed);
        if self.verification_status == EvidenceVerificationStatus::Passed {
            require(
                all_passed,
                "verification_status",
                "cannot pass with a failing acceptance criterion",
            )?;
        }
        if self.verification_status == EvidenceVerificationStatus::Failed {
            require(
                !all_passed,
                "verification_status",
                "failed evidence must identify a failing acceptance criterion",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentResultStatus {
    Completed,
    Partial,
    Blocked,
    Failed,
    Inconclusive,
    Cancelled,
    NeedsReconciliation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResultV1 {
    pub schema_version: String,
    pub task_id: String,
    pub run_id: String,
    pub profile_id: String,
    pub status: AgentResultStatus,
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub domain_result: BTreeMap<String, Value>,
    pub open_issues: Vec<String>,
    pub next_actions: Vec<String>,
    pub verification_status: VerificationStatus,
}

impl AgentResultV1 {
    pub fn validate_against_task(&self, task: &TaskContractV1) -> ContractResult {
        self.validate()?;
        task.validate()?;
        require(
            self.task_id == task.task_id,
            "task_id",
            "agent result belongs to another task",
        )?;
        require(
            task.selected_profile_ids.contains(&self.profile_id),
            "profile_id",
            "profile was not selected for this task",
        )
    }
}

impl Validate for AgentResultV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.agent-result/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("task_id", self.task_id.as_str()),
            ("run_id", self.run_id.as_str()),
            ("profile_id", self.profile_id.as_str()),
            ("summary", self.summary.as_str()),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.artifact_refs, "artifact_refs", 0)?;
        unique_non_blank(&self.evidence_refs, "evidence_refs", 0)?;
        unique_non_blank(&self.open_issues, "open_issues", 0)?;
        unique_non_blank(&self.next_actions, "next_actions", 0)?;
        require(
            !self.domain_result.is_empty(),
            "domain_result",
            "must contain at least one domain field",
        )?;
        map_keys_non_blank(&self.domain_result, "domain_result")?;
        if self.status == AgentResultStatus::Completed {
            require(
                self.verification_status == VerificationStatus::Passed,
                "verification_status",
                "completed result requires passed verification",
            )?;
            require(
                !self.evidence_refs.is_empty(),
                "evidence_refs",
                "completed result requires evidence references",
            )?;
        }
        if self.status == AgentResultStatus::NeedsReconciliation {
            require(
                self.verification_status != VerificationStatus::Passed,
                "verification_status",
                "unresolved external effects cannot pass verification",
            )?;
        }
        Ok(())
    }
}

/// Worker limits are bounded values. Empty network_scope denies network use;
/// zero disk/output/GPU allowance is a real zero, never an unlimited sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLimitsV1 {
    pub max_wall_time_ms: u64,
    pub max_cpu_time_ms: u64,
    pub max_memory_bytes: u64,
    pub max_disk_bytes: u64,
    pub max_output_bytes: u64,
    pub max_gpu_vram_bytes: u64,
    pub network_scope: Vec<String>,
}

impl Validate for WorkerLimitsV1 {
    fn validate(&self) -> ContractResult {
        require(
            self.max_wall_time_ms > 0,
            "limits.max_wall_time_ms",
            "must be positive",
        )?;
        require(
            self.max_cpu_time_ms > 0,
            "limits.max_cpu_time_ms",
            "must be positive",
        )?;
        require(
            self.max_memory_bytes > 0,
            "limits.max_memory_bytes",
            "must be positive",
        )?;
        unique_non_blank(&self.network_scope, "limits.network_scope", 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJobV1 {
    pub schema_version: String,
    pub task_id: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub lease_generation: u64,
    pub permit_ref: String,
    pub arguments_digest: String,
    pub input_artifact_refs: Vec<String>,
    pub limits: WorkerLimitsV1,
    pub cancellation_ref: String,
}

impl WorkerJobV1 {
    /// These per-job ceilings do not reserve shared task budgets or enforce
    /// aggregate usage across concurrent jobs. That is scheduler/broker work.
    pub fn validate_against_task(&self, task: &TaskContractV1) -> ContractResult {
        self.validate()?;
        task.validate()?;
        require(
            self.task_id == task.task_id,
            "task_id",
            "worker job belongs to another task",
        )?;
        for (path, actual, maximum) in [
            (
                "limits.max_wall_time_ms",
                self.limits.max_wall_time_ms,
                task.limits.max_wall_time_ms,
            ),
            (
                "limits.max_disk_bytes",
                self.limits.max_disk_bytes,
                task.limits.max_disk_bytes,
            ),
            (
                "limits.max_output_bytes",
                self.limits.max_output_bytes,
                task.limits.max_output_bytes,
            ),
        ] {
            require(
                actual <= maximum,
                path,
                "worker limit exceeds the task allowance",
            )?;
        }
        Ok(())
    }

    pub fn validate_against_permit(&self, permit: &ExecutionPermitV2) -> ContractResult {
        self.validate()?;
        permit.validate()?;
        require(
            self.task_id == permit.task_id,
            "task_id",
            "job and permit belong to different tasks",
        )?;
        require(
            self.permit_ref == permit.permit_id,
            "permit_ref",
            "job refers to a different permit",
        )?;
        require(
            self.arguments_digest == permit.arguments_digest,
            "arguments_digest",
            "job arguments differ from the permitted arguments",
        )?;
        require(
            self.limits.max_wall_time_ms <= permit.max_duration_ms,
            "limits.max_wall_time_ms",
            "worker time limit exceeds the permit duration",
        )
    }
}

impl Validate for WorkerJobV1 {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.worker-job/v1",
            "schema_version",
        )?;
        for (path, value) in [
            ("task_id", self.task_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("attempt_id", self.attempt_id.as_str()),
            ("permit_ref", self.permit_ref.as_str()),
            ("arguments_digest", self.arguments_digest.as_str()),
            ("cancellation_ref", self.cancellation_ref.as_str()),
        ] {
            non_blank(value, path)?;
        }
        require(
            self.lease_generation > 0,
            "lease_generation",
            "must be positive",
        )?;
        unique_non_blank(&self.input_artifact_refs, "input_artifact_refs", 0)?;
        self.limits.validate()
    }
}
