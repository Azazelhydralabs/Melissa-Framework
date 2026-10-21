//! Versioned design contracts. These values never execute packages, authenticate
//! publishers, grant permissions, retrieve context, or schedule workflow nodes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Module;
use crate::validation::{
    ContractError, ContractResult, Validate, exact_version, non_blank, require, unique_non_blank,
};

fn digest(value: &str, path: &str) -> ContractResult {
    let valid = value.split_once(':').is_some_and(|(algorithm, hex)| {
        matches!(algorithm, "blake3" | "sha256")
            && hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    require(
        valid,
        path,
        "expected blake3: or sha256: and 64 lowercase hexadecimal digits",
    )
}

fn semantic_version(value: &str, path: &str) -> ContractResult {
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(v, b)| (v, Some(b)));
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(v, p)| (v, Some(p)));
    let valid_identifiers = |v: &str, numeric_zero_rule: bool| {
        v.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(numeric_zero_rule
                    && part.len() > 1
                    && part.starts_with('0')
                    && part.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    let parts: Vec<_> = core.split('.').collect();
    let valid = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        })
        && prerelease.is_none_or(|v| valid_identifiers(v, true))
        && build.is_none_or(|v| valid_identifiers(v, false));
    require(
        valid,
        path,
        "expected a semantic version, including valid optional prerelease/build identifiers",
    )
}

fn package_path(value: &str, path: &str) -> ContractResult {
    require(
        !value.is_empty()
            && !value.starts_with('/')
            && !value.contains(['\\', ':', '\0', '?', '*', '<', '>', '|', '"'])
            && !value.chars().any(char::is_control)
            && value.split('/').all(|part| {
                let base = part
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                let device = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || (base.len() == 4
                        && (base.starts_with("COM") || base.starts_with("LPT"))
                        && matches!(base.as_bytes()[3], b'1'..=b'9'));
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && !part.ends_with(['.', ' '])
                    && !device
            }),
        path,
        "expected a normalized relative package path without traversal or platform prefixes",
    )
}

/// Limits are declarations. CODE-03/04/08 must intersect and enforce them with
/// task-wide reservations; this type cannot increase task authority or budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLimits {
    pub timeout_seconds: u64,
    pub max_iterations: u32,
    pub max_parallel_tools: u16,
    pub max_cost_micro_usd: u64,
}

impl Validate for RuntimeLimits {
    fn validate(&self) -> ContractResult {
        require(
            self.timeout_seconds > 0,
            "runtime.timeout_seconds",
            "must be positive",
        )?;
        require(
            self.max_iterations > 0,
            "runtime.max_iterations",
            "must be positive",
        )?;
        require(
            self.max_parallel_tools > 0,
            "runtime.max_parallel_tools",
            "must be positive",
        )?;
        // A zero monetary budget is a valid declaration for local/free work;
        // it must never be interpreted as unlimited or unknown provider spend.
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPin {
    pub skill_id: String,
    pub semantic_version: String,
    pub content_digest: String,
}

impl Validate for SkillPin {
    fn validate(&self) -> ContractResult {
        non_blank(&self.skill_id, "skill_id")?;
        semantic_version(&self.semantic_version, "semantic_version")?;
        digest(&self.content_digest, "content_digest")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFileRole {
    Entrypoint,
    Script,
    Reference,
    Asset,
    Schema,
    Evaluation,
    Test,
    Template,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFileRef {
    pub path: String,
    pub content_digest: String,
    pub role: PackageFileRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptReference {
    pub file_path: String,
    pub interpreter_ref: String,
    pub input_schema_ref: String,
    pub output_schema_ref: String,
    pub required_capabilities: Vec<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateReference {
    pub file_path: String,
    pub input_schema_ref: String,
    pub output_schema_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRouting {
    pub intents: Vec<String>,
    pub priority: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherTrust {
    FirstParty,
    ReviewedThirdParty,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequirement {
    pub check: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillEvaluation {
    pub dataset_ref: String,
    pub assertions_ref: String,
    pub min_success_rate: f64,
}

/// Complete source manifest semantics; the publisher's trust assertion and
/// capability requirements are data, never authenticated authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub entrypoint: String,
    pub category: String,
    pub trust_level: PublisherTrust,
    pub routing: SkillRouting,
    pub required_tools: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub prerequisites: Vec<String>,
    pub runtime: RuntimeLimits,
    pub input_schema_ref: String,
    pub output_schema_ref: String,
    pub verification: Vec<VerificationRequirement>,
    pub evaluation: SkillEvaluation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDefinition {
    pub schema_version: String,
    pub id: String,
    pub module: Module,
    pub name_tr: String,
    pub description_tr: String,
    pub use_when: Vec<String>,
    pub manifest: SkillManifest,
    pub files: Vec<PackageFileRef>,
    pub scripts: Vec<ScriptReference>,
    pub templates: Vec<TemplateReference>,
}

impl Validate for SkillDefinition {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.skill-definition/v1",
            "schema_version",
        )?;
        non_blank(&self.id, "id")?;
        non_blank(&self.name_tr, "name_tr")?;
        non_blank(&self.description_tr, "description_tr")?;
        unique_non_blank(&self.use_when, "use_when", 1)?;
        let m = &self.manifest;
        require(
            m.entrypoint == "SKILL.md",
            "manifest.entrypoint",
            "the package entrypoint must be SKILL.md",
        )?;
        non_blank(&m.category, "manifest.category")?;
        unique_non_blank(&m.routing.intents, "manifest.routing.intents", 1)?;
        unique_non_blank(&m.required_tools, "manifest.required_tools", 0)?;
        unique_non_blank(
            &m.required_capabilities,
            "manifest.required_capabilities",
            0,
        )?;
        unique_non_blank(&m.prerequisites, "manifest.prerequisites", 0)?;
        m.runtime.validate()?;
        non_blank(&m.input_schema_ref, "manifest.input_schema_ref")?;
        non_blank(&m.output_schema_ref, "manifest.output_schema_ref")?;
        require(
            !m.verification.is_empty() && m.verification.iter().any(|v| v.required),
            "manifest.verification",
            "at least one required check must be declared",
        )?;
        unique_non_blank(
            &m.verification
                .iter()
                .map(|v| v.check.clone())
                .collect::<Vec<_>>(),
            "manifest.verification",
            1,
        )?;
        require(
            m.evaluation.min_success_rate.is_finite()
                && (0.0..=1.0).contains(&m.evaluation.min_success_rate),
            "manifest.evaluation.min_success_rate",
            "must be finite and between zero and one",
        )?;
        let mut files = BTreeMap::new();
        let mut casefolded_paths = BTreeSet::new();
        for file in &self.files {
            package_path(&file.path, "files.path")?;
            digest(&file.content_digest, "files.content_digest")?;
            require(
                files.insert(file.path.as_str(), file.role).is_none(),
                "files",
                "duplicate package path",
            )?;
            require(
                casefolded_paths.insert(file.path.to_lowercase()),
                "files",
                "package paths must not collide on Windows",
            )?;
        }
        let check_file = |path: &str, role: PackageFileRole| -> ContractResult {
            package_path(path, "package reference")?;
            require(
                files.get(path) == Some(&role),
                path,
                "reference must identify a declared package file with the correct role",
            )
        };
        check_file("SKILL.md", PackageFileRole::Entrypoint)?;
        require(
            self.files
                .iter()
                .filter(|v| v.role == PackageFileRole::Entrypoint)
                .count()
                == 1,
            "files",
            "exactly one entrypoint is allowed",
        )?;
        check_file(&m.input_schema_ref, PackageFileRole::Schema)?;
        check_file(&m.output_schema_ref, PackageFileRole::Schema)?;
        check_file(&m.evaluation.dataset_ref, PackageFileRole::Evaluation)?;
        check_file(&m.evaluation.assertions_ref, PackageFileRole::Evaluation)?;
        unique_non_blank(
            &self
                .scripts
                .iter()
                .map(|v| v.file_path.clone())
                .collect::<Vec<_>>(),
            "scripts",
            0,
        )?;
        for script in &self.scripts {
            check_file(&script.file_path, PackageFileRole::Script)?;
            non_blank(&script.interpreter_ref, "scripts.interpreter_ref")?;
            check_file(&script.input_schema_ref, PackageFileRole::Schema)?;
            check_file(&script.output_schema_ref, PackageFileRole::Schema)?;
            unique_non_blank(
                &script.required_capabilities,
                "scripts.required_capabilities",
                0,
            )?;
            require(
                script
                    .required_capabilities
                    .iter()
                    .all(|v| m.required_capabilities.contains(v)),
                "scripts.required_capabilities",
                "script cannot require undeclared package capabilities",
            )?;
            require(
                script.timeout_seconds > 0 && script.timeout_seconds <= m.runtime.timeout_seconds,
                "scripts.timeout_seconds",
                "must fit package runtime",
            )?;
        }
        unique_non_blank(
            &self
                .templates
                .iter()
                .map(|v| v.file_path.clone())
                .collect::<Vec<_>>(),
            "templates",
            0,
        )?;
        for template in &self.templates {
            check_file(&template.file_path, PackageFileRole::Template)?;
            check_file(&template.input_schema_ref, PackageFileRole::Schema)?;
            check_file(&template.output_schema_ref, PackageFileRole::Schema)?;
        }
        // Every declared executable/helper has an explicit descriptor; hidden
        // helper files cannot escape capability/schema/runtime declarations.
        for file in &self.files {
            if file.role == PackageFileRole::Script {
                require(
                    self.scripts.iter().any(|s| s.file_path == file.path),
                    "files",
                    "script file has no descriptor",
                )?;
            }
            if file.role == PackageFileRole::Template {
                require(
                    self.templates.iter().any(|s| s.file_path == file.path),
                    "files",
                    "template file has no descriptor",
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillReleaseState {
    Draft,
    Tested,
    Evaluated,
    Reviewed,
    SignedRelease,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureReference {
    pub algorithm: String,
    pub key_id: String,
    pub signature_artifact_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillVersion {
    pub schema_version: String,
    pub pin: SkillPin,
    pub definition_digest: String,
    pub publisher_id: String,
    pub state: SkillReleaseState,
    pub required_capabilities: Vec<String>,
    pub evaluation_digest: Option<String>,
    pub review_artifact_ref: Option<String>,
    pub signature: Option<SignatureReference>,
    pub revocation_ref: Option<String>,
    pub rollback_to: Option<SkillPin>,
}

impl Validate for SkillVersion {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.skill-version/v1",
            "schema_version",
        )?;
        self.pin.validate()?;
        digest(&self.definition_digest, "definition_digest")?;
        non_blank(&self.publisher_id, "publisher_id")?;
        unique_non_blank(&self.required_capabilities, "required_capabilities", 0)?;
        if let Some(value) = &self.evaluation_digest {
            digest(value, "evaluation_digest")?;
        }
        if let Some(value) = &self.review_artifact_ref {
            non_blank(value, "review_artifact_ref")?;
        }
        if let Some(value) = &self.revocation_ref {
            non_blank(value, "revocation_ref")?;
        }
        if let Some(signature) = &self.signature {
            non_blank(&signature.algorithm, "signature.algorithm")?;
            non_blank(&signature.key_id, "signature.key_id")?;
            non_blank(
                &signature.signature_artifact_ref,
                "signature.signature_artifact_ref",
            )?;
        }
        if matches!(
            self.state,
            SkillReleaseState::Evaluated
                | SkillReleaseState::Reviewed
                | SkillReleaseState::SignedRelease
        ) {
            require(
                self.evaluation_digest.is_some(),
                "evaluation_digest",
                "evaluated or released versions require evaluation evidence",
            )?;
        }
        if matches!(
            self.state,
            SkillReleaseState::Reviewed | SkillReleaseState::SignedRelease
        ) {
            require(
                self.review_artifact_ref.is_some(),
                "review_artifact_ref",
                "reviewed or released versions require review evidence",
            )?;
        }
        if self.state == SkillReleaseState::SignedRelease {
            require(
                self.signature.is_some(),
                "signature",
                "a signed release requires a signature reference; cryptographic verification is a separate gate",
            )?;
        }
        require(
            (self.state == SkillReleaseState::Revoked) == self.revocation_ref.is_some(),
            "revocation_ref",
            "revoked state must agree with the revocation record",
        )?;
        if let Some(pin) = &self.rollback_to {
            pin.validate()?;
            require(
                pin.skill_id == self.pin.skill_id
                    && pin.semantic_version != self.pin.semantic_version
                    && pin.content_digest != self.pin.content_digest,
                "rollback_to",
                "rollback must identify a different version and digest of the same skill",
            )?;
        }
        Ok(())
    }
}

impl SkillVersion {
    pub fn validate_definition(&self, definition: &SkillDefinition) -> ContractResult {
        self.validate()?;
        definition.validate()?;
        require(
            self.pin.skill_id == definition.id,
            "pin.skill_id",
            "skill version and definition identity differ",
        )?;
        let a: BTreeSet<_> = self.required_capabilities.iter().collect();
        let b: BTreeSet<_> = definition.manifest.required_capabilities.iter().collect();
        require(
            a == b,
            "required_capabilities",
            "version and manifest capability declarations differ",
        )
        // Byte/directory digest recomputation belongs to the CODE-07 package loader.
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSection {
    SystemContract,
    TaskContract,
    RelevantSkills,
    WorkspaceContext,
    Evidence,
    RecentObservations,
    RemainingBudget,
    OutputSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextTrust {
    HostContract,
    UserTask,
    UntrustedData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSourceKind {
    SystemContract,
    TaskContract,
    Skill,
    ToolSchema,
    Repository,
    Evidence,
    Observation,
    Budget,
    OutputSchema,
    Memory,
    Web,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextItem {
    pub id: String,
    pub section: ContextSection,
    pub source_kind: ContextSourceKind,
    pub trust: ContextTrust,
    pub source_ref: String,
    pub source_version: String,
    pub content_digest: String,
    pub namespace: String,
    pub token_count: u64,
    pub full_content: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSkillBinding {
    pub pin: SkillPin,
    pub context_item_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationContract {
    pub checkpoint_ref: String,
    pub task_contract_digest: String,
    pub workspace_snapshot_digest: String,
    pub authorization_ref: String,
    pub cancellation_ref: String,
    pub remaining_budget_ref: String,
    pub open_effect_refs: Vec<String>,
    pub rejected_hypotheses: Vec<String>,
    pub open_issue_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTaskBinding {
    pub module: Module,
    pub goal: String,
    pub workspace_ref: String,
    pub input_snapshot_digest: String,
    pub acceptance_contract_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextContract {
    pub schema_version: String,
    pub id: String,
    pub task_id: String,
    pub task_binding: ContextTaskBinding,
    pub namespace: String,
    pub max_context_tokens: u64,
    pub reserved_output_tokens: u64,
    pub items: Vec<ContextItem>,
    pub selected_skills: Vec<ContextSkillBinding>,
    pub continuation: Option<ContinuationContract>,
}

impl ContextContract {
    /// Compares immutable task fields and declared token ceilings. The host
    /// still authenticates source bytes and the current remaining budget.
    pub fn validate_against_task(&self, task: &crate::wire::TaskContractV1) -> ContractResult {
        self.validate()?;
        task.validate()?;
        require(
            self.task_id == task.task_id,
            "task_id",
            "context belongs to another task",
        )?;
        let binding = &self.task_binding;
        require(
            binding.module == task.module,
            "task_binding.module",
            "context module differs from task",
        )?;
        require(
            binding.goal == task.goal,
            "task_binding.goal",
            "context cannot replace the task goal",
        )?;
        require(
            binding.workspace_ref == task.workspace_ref,
            "task_binding.workspace_ref",
            "context belongs to another workspace",
        )?;
        require(
            binding.input_snapshot_digest == task.input_snapshot_digest,
            "task_binding.input_snapshot_digest",
            "context initial task snapshot differs",
        )?;
        require(
            binding.acceptance_contract_digest == task.acceptance_contract_digest,
            "task_binding.acceptance_contract_digest",
            "context cannot replace acceptance criteria",
        )?;
        let input_tokens = self
            .items
            .iter()
            .try_fold(0_u64, |sum, item| sum.checked_add(item.token_count))
            .ok_or_else(|| ContractError::new("items.token_count", "token total overflow"))?;
        require(
            input_tokens <= task.limits.max_input_tokens,
            "items.token_count",
            "context input exceeds task input-token ceiling",
        )?;
        require(
            self.reserved_output_tokens <= task.limits.max_output_tokens,
            "reserved_output_tokens",
            "output reservation exceeds task output-token ceiling",
        )
    }
}

impl Validate for ContextContract {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.context-contract/v1",
            "schema_version",
        )?;
        non_blank(&self.id, "id")?;
        non_blank(&self.task_id, "task_id")?;
        non_blank(&self.task_binding.goal, "task_binding.goal")?;
        non_blank(
            &self.task_binding.workspace_ref,
            "task_binding.workspace_ref",
        )?;
        digest(
            &self.task_binding.input_snapshot_digest,
            "task_binding.input_snapshot_digest",
        )?;
        digest(
            &self.task_binding.acceptance_contract_digest,
            "task_binding.acceptance_contract_digest",
        )?;
        non_blank(&self.namespace, "namespace")?;
        require(
            self.max_context_tokens > 0,
            "max_context_tokens",
            "must be positive",
        )?;
        let usable = self
            .max_context_tokens
            .checked_sub(self.reserved_output_tokens)
            .ok_or_else(|| {
                ContractError::new(
                    "reserved_output_tokens",
                    "output reservation exceeds context capacity",
                )
            })?;
        let mut total = 0_u64;
        let mut ids = BTreeMap::new();
        let mut sections = BTreeSet::new();
        for item in &self.items {
            non_blank(&item.id, "items.id")?;
            require(
                ids.insert(item.id.as_str(), item).is_none(),
                "items.id",
                "duplicate item id",
            )?;
            non_blank(&item.source_ref, "items.source_ref")?;
            non_blank(&item.source_version, "items.source_version")?;
            digest(&item.content_digest, "items.content_digest")?;
            require(
                item.namespace == self.namespace,
                "items.namespace",
                "context cannot combine different project/engagement namespaces",
            )?;
            require(
                item.token_count > 0,
                "items.token_count",
                "must be positive",
            )?;
            total = total
                .checked_add(item.token_count)
                .ok_or_else(|| ContractError::new("items.token_count", "token total overflow"))?;
            sections.insert(item.section);
            let trusted_source = matches!(
                item.source_kind,
                ContextSourceKind::SystemContract | ContextSourceKind::TaskContract
            );
            require(
                trusted_source || item.trust == ContextTrust::UntrustedData,
                "items.trust",
                "skill, tool, repository and external material cannot become instruction authority",
            )?;
            let required_section = match item.source_kind {
                ContextSourceKind::SystemContract | ContextSourceKind::ToolSchema => {
                    Some(ContextSection::SystemContract)
                }
                ContextSourceKind::TaskContract => Some(ContextSection::TaskContract),
                ContextSourceKind::Skill => Some(ContextSection::RelevantSkills),
                ContextSourceKind::Repository => Some(ContextSection::WorkspaceContext),
                ContextSourceKind::Evidence => Some(ContextSection::Evidence),
                ContextSourceKind::Observation => Some(ContextSection::RecentObservations),
                ContextSourceKind::Budget => Some(ContextSection::RemainingBudget),
                ContextSourceKind::OutputSchema => Some(ContextSection::OutputSchema),
                ContextSourceKind::Memory | ContextSourceKind::Web => None,
            };
            require(
                required_section.is_none_or(|v| v == item.section),
                "items.section",
                "source kind and context section differ",
            )?;
            if item.source_kind == ContextSourceKind::SystemContract {
                require(
                    item.section == ContextSection::SystemContract
                        && item.trust == ContextTrust::HostContract,
                    "items",
                    "system contract requires its section and host trust",
                )?;
            }
            if item.source_kind == ContextSourceKind::TaskContract {
                require(
                    item.section == ContextSection::TaskContract
                        && item.trust == ContextTrust::UserTask,
                    "items",
                    "task contract requires its section and user-task trust",
                )?;
            }
            if matches!(
                item.source_kind,
                ContextSourceKind::SystemContract
                    | ContextSourceKind::TaskContract
                    | ContextSourceKind::Skill
                    | ContextSourceKind::ToolSchema
                    | ContextSourceKind::OutputSchema
            ) {
                require(
                    item.full_content,
                    "items.full_content",
                    "required contracts, selected skills and tool/output schemas cannot be silently truncated",
                )?;
            }
        }
        require(
            total <= usable,
            "items.token_count",
            "context plus output reservation exceeds capacity",
        )?;
        for required in [
            ContextSection::SystemContract,
            ContextSection::TaskContract,
            ContextSection::RemainingBudget,
            ContextSection::OutputSchema,
        ] {
            require(
                sections.contains(&required),
                "items.section",
                "missing required context section",
            )?;
        }
        for required in [
            ContextSourceKind::SystemContract,
            ContextSourceKind::TaskContract,
            ContextSourceKind::Budget,
            ContextSourceKind::OutputSchema,
        ] {
            require(
                self.items
                    .iter()
                    .filter(|i| i.source_kind == required)
                    .count()
                    == 1,
                "items.source_kind",
                "exactly one actual system/task/budget/output contract is required",
            )?;
        }
        let task_item = self
            .items
            .iter()
            .find(|i| i.source_kind == ContextSourceKind::TaskContract)
            .expect("required task checked above");
        require(
            task_item.source_ref == self.task_id,
            "items.source_ref",
            "task contract source must identify this task",
        )?;
        unique_non_blank(
            &self
                .selected_skills
                .iter()
                .map(|v| v.pin.skill_id.clone())
                .collect::<Vec<_>>(),
            "selected_skills",
            0,
        )?;
        for skill in &self.selected_skills {
            skill.pin.validate()?;
            let item = ids.get(skill.context_item_id.as_str()).ok_or_else(|| {
                ContractError::new("selected_skills.context_item_id", "unknown context item")
            })?;
            require(
                item.source_kind == ContextSourceKind::Skill
                    && item.section == ContextSection::RelevantSkills
                    && item.full_content
                    && item.content_digest == skill.pin.content_digest
                    && item.source_ref == skill.pin.skill_id
                    && item.source_version == skill.pin.semantic_version,
                "selected_skills",
                "selected skill must match fully loaded identity, version and digest",
            )?;
        }
        require(
            self.items
                .iter()
                .filter(|i| i.source_kind == ContextSourceKind::Skill)
                .all(|i| {
                    self.selected_skills
                        .iter()
                        .any(|s| s.context_item_id == i.id)
                }),
            "items",
            "skill context item has no selected version binding",
        )?;
        if let Some(c) = &self.continuation {
            for (value, path) in [
                (&c.checkpoint_ref, "continuation.checkpoint_ref"),
                (&c.authorization_ref, "continuation.authorization_ref"),
                (&c.cancellation_ref, "continuation.cancellation_ref"),
                (&c.remaining_budget_ref, "continuation.remaining_budget_ref"),
            ] {
                non_blank(value, path)?;
            }
            digest(&c.task_contract_digest, "continuation.task_contract_digest")?;
            digest(
                &c.workspace_snapshot_digest,
                "continuation.workspace_snapshot_digest",
            )?;
            let task = self
                .items
                .iter()
                .find(|i| i.source_kind == ContextSourceKind::TaskContract)
                .expect("required task checked above");
            require(
                task.content_digest == c.task_contract_digest,
                "continuation.task_contract_digest",
                "continuation cannot replace the task contract",
            )?;
            unique_non_blank(&c.open_effect_refs, "continuation.open_effect_refs", 0)?;
            unique_non_blank(
                &c.rejected_hypotheses,
                "continuation.rejected_hypotheses",
                0,
            )?;
            unique_non_blank(&c.open_issue_refs, "continuation.open_issue_refs", 0)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    Unresolved,
    Bound,
}

/// Sidecar contract, intentionally separate from the existing 62 profile-v1
/// files. Bound means structurally resolved, not executable or live-accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRuntimeBindings {
    pub schema_version: String,
    pub profile_id: String,
    pub profile_schema_version: String,
    pub state: BindingState,
    pub skills: Vec<SkillPin>,
    pub context_contract_ref: Option<String>,
    pub runtime_limits: Option<RuntimeLimits>,
    pub unresolved_reasons: Vec<String>,
}

impl Validate for ProfileRuntimeBindings {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.profile-bindings/v1",
            "schema_version",
        )?;
        exact_version(
            &self.profile_schema_version,
            "melissa.agent-profile/v1",
            "profile_schema_version",
        )?;
        non_blank(&self.profile_id, "profile_id")?;
        unique_non_blank(
            &self
                .skills
                .iter()
                .map(|v| v.skill_id.clone())
                .collect::<Vec<_>>(),
            "skills",
            0,
        )?;
        for pin in &self.skills {
            pin.validate()?;
        }
        if let Some(reference) = &self.context_contract_ref {
            non_blank(reference, "context_contract_ref")?;
        }
        if let Some(limits) = &self.runtime_limits {
            limits.validate()?;
        }
        unique_non_blank(&self.unresolved_reasons, "unresolved_reasons", 0)?;
        match self.state {
            BindingState::Unresolved => require(
                !self.unresolved_reasons.is_empty(),
                "unresolved_reasons",
                "unresolved binding must retain explicit reasons",
            ),
            BindingState::Bound => require(
                self.unresolved_reasons.is_empty()
                    && self.context_contract_ref.is_some()
                    && self.runtime_limits.is_some(),
                "state",
                "bound profile requires context, runtime limits and no unresolved reasons",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedPort {
    pub name: String,
    pub schema_ref: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkflowExecutor {
    Agent(String),
    Tool(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowValueSource {
    WorkflowInput { name: String },
    NodeOutput { node_id: String, output: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputBinding {
    pub input: String,
    pub source: WorkflowValueSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNode {
    pub id: String,
    pub executor: WorkflowExecutor,
    pub depends_on: Vec<String>,
    pub inputs: Vec<TypedPort>,
    pub outputs: Vec<TypedPort>,
    pub bindings: Vec<InputBinding>,
    pub required_capabilities: Vec<String>,
    pub authorization_ref: Option<String>,
    pub timeout_seconds: u64,
    pub compensation_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOutput {
    pub name: String,
    pub schema_ref: String,
    pub source: WorkflowValueSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowFinalAction {
    Fail,
    Block,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowFailurePolicy {
    pub repair_attempts: u32,
    pub no_progress_limit: u32,
    pub final_action: WorkflowFinalAction,
    pub checkpoint_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationSpec {
    pub node_id: String,
    pub compensation_node_id: String,
    pub authorization_ref: String,
    pub reconciliation_policy_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinition {
    pub schema_version: String,
    pub id: String,
    pub semantic_version: String,
    pub inputs: Vec<TypedPort>,
    pub runtime: RuntimeLimits,
    pub nodes: Vec<WorkflowNode>,
    pub outputs: Vec<WorkflowOutput>,
    pub success_all: Vec<String>,
    pub failure: WorkflowFailurePolicy,
    pub compensations: Vec<CompensationSpec>,
}

fn ports(values: &[TypedPort], path: &str) -> ContractResult {
    unique_non_blank(
        &values.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
        path,
        0,
    )?;
    for value in values {
        non_blank(&value.schema_ref, path)?;
    }
    Ok(())
}

impl WorkflowDefinition {
    fn source_port<'a>(&'a self, source: &WorkflowValueSource) -> ContractResult<&'a TypedPort> {
        let port = match source {
            WorkflowValueSource::WorkflowInput { name } => {
                self.inputs.iter().find(|v| v.name == *name)
            }
            WorkflowValueSource::NodeOutput { node_id, output } => self
                .nodes
                .iter()
                .find(|v| v.id == *node_id)
                .and_then(|node| node.outputs.iter().find(|v| v.name == *output)),
        };
        port.ok_or_else(|| ContractError::new("source", "unknown input/node/output reference"))
    }

    /// Catalog existence is checked separately from structural validation.
    /// This does not prove tool implementation, resource reachability, budget
    /// reservation, or authorization; the runtime validator must check those.
    pub fn validate_references(
        &self,
        agent_ids: &BTreeSet<String>,
        tool_ids: &BTreeSet<String>,
    ) -> ContractResult {
        self.validate()?;
        for node in &self.nodes {
            let known = match &node.executor {
                WorkflowExecutor::Agent(id) => agent_ids.contains(id),
                WorkflowExecutor::Tool(id) => tool_ids.contains(id),
            };
            require(known, "nodes.executor", "unknown agent or tool reference")?;
        }
        Ok(())
    }
}

impl Validate for WorkflowDefinition {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.workflow-definition/v1",
            "schema_version",
        )?;
        non_blank(&self.id, "id")?;
        semantic_version(&self.semantic_version, "semantic_version")?;
        ports(&self.inputs, "inputs")?;
        self.runtime.validate()?;
        unique_non_blank(&self.success_all, "success_all", 1)?;
        require(
            !self.nodes.is_empty(),
            "nodes",
            "workflow requires at least one node",
        )?;
        unique_non_blank(
            &self.nodes.iter().map(|v| v.id.clone()).collect::<Vec<_>>(),
            "nodes.id",
            1,
        )?;
        require(
            self.nodes.iter().any(|v| !v.compensation_only),
            "nodes",
            "workflow must include a normal execution node",
        )?;
        let ids: BTreeSet<_> = self.nodes.iter().map(|v| v.id.as_str()).collect();
        for node in &self.nodes {
            match &node.executor {
                WorkflowExecutor::Agent(id) | WorkflowExecutor::Tool(id) => {
                    non_blank(id, "nodes.executor")?
                }
            }
            ports(&node.inputs, "nodes.inputs")?;
            ports(&node.outputs, "nodes.outputs")?;
            unique_non_blank(&node.depends_on, "nodes.depends_on", 0)?;
            unique_non_blank(
                &node.required_capabilities,
                "nodes.required_capabilities",
                0,
            )?;
            if let Some(reference) = &node.authorization_ref {
                non_blank(reference, "nodes.authorization_ref")?;
            }
            require(
                node.required_capabilities.is_empty() || node.authorization_ref.is_some(),
                "nodes.authorization_ref",
                "capability requirements need an authorization reference, not a grant",
            )?;
            require(
                node.timeout_seconds > 0 && node.timeout_seconds <= self.runtime.timeout_seconds,
                "nodes.timeout_seconds",
                "node timeout must fit workflow timeout",
            )?;
            for dep in &node.depends_on {
                require(
                    dep != &node.id && ids.contains(dep.as_str()),
                    "nodes.depends_on",
                    "self or unknown dependency",
                )?;
                let dependency = self
                    .nodes
                    .iter()
                    .find(|v| v.id == *dep)
                    .expect("known dependency");
                require(
                    node.compensation_only || !dependency.compensation_only,
                    "nodes.depends_on",
                    "normal nodes cannot depend on compensation execution",
                )?;
            }
            unique_non_blank(
                &node
                    .bindings
                    .iter()
                    .map(|v| v.input.clone())
                    .collect::<Vec<_>>(),
                "nodes.bindings.input",
                0,
            )?;
            for binding in &node.bindings {
                let target = node
                    .inputs
                    .iter()
                    .find(|v| v.name == binding.input)
                    .ok_or_else(|| {
                        ContractError::new("nodes.bindings.input", "unknown target input")
                    })?;
                let source = self.source_port(&binding.source)?;
                require(
                    target.schema_ref == source.schema_ref,
                    "nodes.bindings",
                    "source and target schema references differ",
                )?;
                require(
                    !target.required || source.required,
                    "nodes.bindings",
                    "required input cannot depend on an optional source without an explicit guard/default",
                )?;
                if let WorkflowValueSource::NodeOutput { node_id, .. } = &binding.source {
                    require(
                        node_id != &node.id && node.depends_on.contains(node_id),
                        "nodes.bindings",
                        "node output binding requires an explicit dependency",
                    )?;
                }
            }
            require(
                node.inputs
                    .iter()
                    .filter(|v| v.required)
                    .all(|v| node.bindings.iter().any(|b| b.input == v.name)),
                "nodes.bindings",
                "required input has no binding",
            )?;
        }
        // Kahn-style elimination without recursion: bounded by catalog size.
        let mut completed = BTreeSet::new();
        loop {
            let previous = completed.len();
            for node in &self.nodes {
                if node
                    .depends_on
                    .iter()
                    .all(|v| completed.contains(v.as_str()))
                {
                    completed.insert(node.id.as_str());
                }
            }
            if previous == completed.len() {
                break;
            }
        }
        require(
            completed.len() == self.nodes.len(),
            "nodes.depends_on",
            "workflow contains a cycle",
        )?;
        unique_non_blank(
            &self
                .outputs
                .iter()
                .map(|v| v.name.clone())
                .collect::<Vec<_>>(),
            "outputs.name",
            1,
        )?;
        for output in &self.outputs {
            non_blank(&output.schema_ref, "outputs.schema_ref")?;
            let source = self.source_port(&output.source)?;
            require(
                output.schema_ref == source.schema_ref,
                "outputs",
                "output schema mismatch",
            )?;
            require(
                source.required,
                "outputs",
                "mandatory workflow output cannot depend on an optional source",
            )?;
            if let WorkflowValueSource::NodeOutput { node_id, .. } = &output.source {
                require(
                    !self
                        .nodes
                        .iter()
                        .find(|v| v.id == *node_id)
                        .expect("source checked")
                        .compensation_only,
                    "outputs",
                    "normal success cannot be sourced from compensation",
                )?;
            }
        }
        let f = &self.failure;
        require(
            f.repair_attempts <= self.runtime.max_iterations,
            "failure.repair_attempts",
            "repair attempts must fit iteration bound",
        )?;
        require(
            (f.repair_attempts == 0 && f.no_progress_limit == 0)
                || (f.repair_attempts > 0
                    && f.no_progress_limit > 0
                    && f.no_progress_limit <= f.repair_attempts),
            "failure.no_progress_limit",
            "repair must have a finite compatible no-progress bound",
        )?;
        let mut compensated = BTreeSet::new();
        let mut handlers = BTreeSet::new();
        for c in &self.compensations {
            let original = self
                .nodes
                .iter()
                .find(|v| v.id == c.node_id)
                .ok_or_else(|| {
                    ContractError::new("compensations.node_id", "unknown target node")
                })?;
            let handler = self
                .nodes
                .iter()
                .find(|v| v.id == c.compensation_node_id)
                .ok_or_else(|| {
                    ContractError::new(
                        "compensations.compensation_node_id",
                        "unknown compensation node",
                    )
                })?;
            require(
                !original.compensation_only
                    && handler.compensation_only
                    && original.id != handler.id,
                "compensations",
                "compensation must target a distinct normal node",
            )?;
            require(
                compensated.insert(&c.node_id) && handlers.insert(&c.compensation_node_id),
                "compensations",
                "duplicate compensation target or handler",
            )?;
            non_blank(&c.authorization_ref, "compensations.authorization_ref")?;
            require(
                handler.authorization_ref.as_ref() == Some(&c.authorization_ref),
                "compensations.authorization_ref",
                "compensation handler and specification authorization references differ",
            )?;
            non_blank(
                &c.reconciliation_policy_ref,
                "compensations.reconciliation_policy_ref",
            )?;
        }
        require(
            self.nodes
                .iter()
                .filter(|v| v.compensation_only)
                .all(|v| handlers.contains(&v.id)),
            "compensations",
            "orphan compensation node",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
    NeedsReconciliation,
}

/// Separate compensation lifecycle preserves the source Compensating concept.
/// A completed compensation does not erase the original external operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationRecord {
    pub schema_version: String,
    pub task_id: String,
    pub original_invocation_id: String,
    pub compensation_node_id: String,
    pub authorization_ref: String,
    pub state: CompensationState,
    pub compensation_invocation_id: Option<String>,
    pub evidence_refs: Vec<String>,
    pub reconciliation_ref: Option<String>,
}

impl Validate for CompensationRecord {
    fn validate(&self) -> ContractResult {
        exact_version(
            &self.schema_version,
            "melissa.compensation-record/v1",
            "schema_version",
        )?;
        for (value, path) in [
            (&self.task_id, "task_id"),
            (&self.original_invocation_id, "original_invocation_id"),
            (&self.compensation_node_id, "compensation_node_id"),
            (&self.authorization_ref, "authorization_ref"),
        ] {
            non_blank(value, path)?;
        }
        unique_non_blank(&self.evidence_refs, "evidence_refs", 0)?;
        if let Some(id) = &self.compensation_invocation_id {
            non_blank(id, "compensation_invocation_id")?;
            require(
                id != &self.original_invocation_id,
                "compensation_invocation_id",
                "compensation is a distinct invocation",
            )?;
        }
        if let Some(reference) = &self.reconciliation_ref {
            non_blank(reference, "reconciliation_ref")?;
        }
        require(
            self.state == CompensationState::Pending || self.compensation_invocation_id.is_some(),
            "compensation_invocation_id",
            "started compensation requires its own invocation",
        )?;
        if self.state == CompensationState::Succeeded {
            require(
                !self.evidence_refs.is_empty(),
                "evidence_refs",
                "successful compensation requires evidence",
            )?;
        }
        let unknown = matches!(
            self.state,
            CompensationState::OutcomeUnknown | CompensationState::NeedsReconciliation
        );
        require(
            !unknown || self.reconciliation_ref.is_some(),
            "reconciliation_ref",
            "unknown compensation effect requires explicit reconciliation",
        )
    }
}
