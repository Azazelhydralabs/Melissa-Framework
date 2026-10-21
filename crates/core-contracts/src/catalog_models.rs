//! Strict definition-catalog records. These records confer no execution authority.
use crate::Module;
use crate::validation::{
    ContractResult, Validate, exact_version, non_blank, require, unique_non_blank,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

macro_rules! record {
    ($name:ident { $($(#[$attribute:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($(#[$attribute])* pub $field: $ty),* }
    };
}
macro_rules! choices {
    ($name:ident { $($variant:ident => $value:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $value)] $variant),* }
    };
}
choices!(ModelClass { Coding=>"coding", Reasoning=>"reasoning", Research=>"research", Review=>"review", Vision=>"vision" });
choices!(ModelCapability { ToolCalling=>"tool_calling", StructuredOutput=>"structured_output", ImageUnderstanding=>"image_understanding" });
choices!(ProviderBinding { TaskPolicy=>"task_policy" });
choices!(FallbackPolicy { CapabilityCheckedOnly=>"capability_checked_only" });
choices!(ApprovalPolicy { TaskScopeAndPolicy=>"task_scope_and_policy" });
choices!(DefinitionStatus { Complete=>"complete" });
// V1 definition records lack adapter/verifier evidence fields. Promotion needs a
// new evidence-aware record contract, not an arbitrary string or inferred claim.
choices!(PendingImplementation { NotImplemented=>"not_implemented" });
choices!(PendingAcceptance { NotRun=>"not_run" });
choices!(Platform { Windows=>"windows", Linux=>"linux", WindowsVm=>"windows-vm" });
choices!(WorkerLifecycle { Registered=>"registered", Ready=>"ready", Leased=>"leased", Running=>"running", Cancelling=>"cancelling", Reconciling=>"reconciling", Finished=>"finished", Quarantined=>"quarantined" });
choices!(ToolExecutionMode { BrokerOrIsolatedWorker=>"broker_or_isolated_worker" });
choices!(ToolPolicyClass { SpecificTargetArgsAndEffects=>"tool_specific_target_args_and_effects_required" });
choices!(InputSchemaStatus { PendingModuleImplementation=>"pending_module_implementation" });
choices!(BacklogStatus { Planned=>"planned", InProgress=>"in_progress", Blocked=>"blocked", Accepted=>"accepted" });
choices!(GateStatus { NotRun=>"not_run", Passed=>"passed", Failed=>"failed", Blocked=>"blocked" });
choices!(CatalogStatus { Defined=>"defined", LocallyVerified=>"locally_verified" });
choices!(ModuleImplementation { NotStarted=>"not_started", InProgress=>"in_progress", Implemented=>"implemented" });
choices!(AcceptanceStatus { NotRun=>"not_run", Passed=>"passed", Failed=>"failed", Blocked=>"blocked", Inconclusive=>"inconclusive" });
choices!(PolicyStatus { DefinitionOnly=>"definition_only" });

record!(Activation { when:Vec<String>, avoid_when:Vec<String> });
record!(ModelPolicy { class:ModelClass, required_capabilities:Vec<ModelCapability>, provider_binding:ProviderBinding, fallback:FallbackPolicy });
record!(ProfileInputs { required:Vec<String>, optional:Vec<String> });
record!(ProfileOutputs { schema_ref:String, required_domain_fields:Vec<String> });
record!(ProfileAuthority { capability_ceiling:Vec<String>, forbidden_effects:Vec<String>, approval_policy:ApprovalPolicy });
record!(ProfileVerification { checks:Vec<String>, independent_verifier_required:bool, completion_rule_tr:String });
record!(ProfileRecovery {
    on_tool_error_tr: String,
    on_no_progress_tr: String,
    on_unknown_effect_tr: String,
    on_budget_exhausted_tr: String
});
record!(Handoff { profile_id:String, when_tr:String, required_evidence:Vec<String> });
record!(EvaluationCase { id:String, scenario_tr:String, expected_checks:Vec<String> });
record!(ProfileImplementation {
    profile_definition: DefinitionStatus,
    runtime: PendingImplementation,
    tool_adapters: PendingImplementation,
    live_acceptance: PendingAcceptance
});
record!(AgentProfile {
    schema_version:String, id:String, module:Module, name_tr:String, purpose_tr:String,
    common_policy_ref:String, activation:Activation, model_policy:ModelPolicy,
    inputs:ProfileInputs, outputs:ProfileOutputs, tool_ids:Vec<String>, worker_types:Vec<String>,
    authority:ProfileAuthority, procedure_tr:Vec<String>, verification:ProfileVerification,
    recovery:ProfileRecovery, handoffs:Vec<Handoff>, evaluation_cases:Vec<EvaluationCase>,
    system_prompt_tr:String, implementation:ProfileImplementation
});
record!(WorkerJobContract { required:Vec<String>, returns:Vec<String> });
record!(WorkerResourcePolicy { authority:String, limits:Vec<String>, unbounded_jobs:bool });
record!(WorkerImplementation {
    definition: DefinitionStatus,
    executor: PendingImplementation,
    local_acceptance: PendingAcceptance,
    live_acceptance: PendingAcceptance
});
record!(WorkerType {
    schema_version:String, id:String, name_tr:String, modules:Vec<Module>, declared_platforms:Vec<Platform>,
    purpose_tr:String, tool_families:Vec<String>, requirements_tr:Vec<String>, isolation_contract_tr:String,
    job_contract:WorkerJobContract, resource_policy:WorkerResourcePolicy, lifecycle:Vec<WorkerLifecycle>,
    acceptance_checks_tr:Vec<String>, implementation:WorkerImplementation
});
record!(ToolDefinition {
    id:String, owner_module:Module, family:String, referenced_by:Vec<String>, worker_candidates:Vec<String>,
    execution_mode:ToolExecutionMode, policy_classification:ToolPolicyClass, input_schema_status:InputSchemaStatus,
    output_envelope_ref:String, adapter_status:PendingImplementation, acceptance_status:PendingAcceptance
});
record!(ToolCatalog { schema_version:String, tools:Vec<ToolDefinition> });
record!(ToolAliases { schema_version:String, aliases:BTreeMap<String,String>, execution:String });
record!(ModuleGate { id:String, requires:Vec<String>, status:GateStatus, evidence_refs:Vec<String> });
record!(ModuleStatus {
    catalog: CatalogStatus,
    implementation: ModuleImplementation,
    local_acceptance: AcceptanceStatus,
    live_acceptance: AcceptanceStatus,
    product_acceptance: AcceptanceStatus
});
record!(ModuleDefinition {
    id:Module, order:u32, profile_count:usize, profile_ids:Vec<String>, implementation_dependencies:Vec<Module>,
    #[serde(deserialize_with="required_nullable")]
    implementation_order_predecessor:Option<Module>, backlog_ids:Vec<String>, gate:ModuleGate, status:ModuleStatus
});
record!(ModuleCatalog { schema_version:String, modules:Vec<ModuleDefinition> });
record!(BacklogItem { id:String, module:Module, title_tr:String, acceptance_tr:String, status:BacklogStatus, evidence_refs:Vec<String>, depends_on_modules:Vec<Module> });
record!(BacklogCatalog { schema_version:String, items:Vec<BacklogItem> });
record!(AgentIndexEntry {
    id: String,
    module: Module,
    name_tr: String,
    path: String
});
record!(AgentIndex { schema_version:String, profiles:Vec<AgentIndexEntry> });
record!(AuthorityPolicy {
    decision_owner: String,
    effective_grant: String,
    delegation: String,
    model_can_authorize: bool,
    approval: String
});
record!(BudgetPolicy {
    scope: String,
    reservation: String,
    limits_source: String,
    unknown_usage: String,
    fixed_universal_turn_limit: bool
});
record!(UntrustedInputPolicy { sources:Vec<String>, rule:String });
record!(EvidencePolicy { completion:String, required_binding:Vec<String> });
record!(RecoveryPolicy { classes:Vec<String>, unknown_effect:String, autonomy:String });
record!(StoragePolicy {
    local: String,
    transactions: String,
    publication: String,
    retention: String
});
record!(ConcurrencyPolicy {
    simple_task_default: String,
    specialists: String,
    catalog_count_is_concurrency: bool
});
record!(RuntimePolicy {
    schema_version:String, id:String, status:PolicyStatus, authority:AuthorityPolicy, budget:BudgetPolicy,
    untrusted_input:UntrustedInputPolicy, evidence:EvidencePolicy, recovery:RecoveryPolicy,
    cancellation:String, storage:StoragePolicy, concurrency:ConcurrencyPolicy, security:Vec<String>
});

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub fn module_name(module: Module) -> &'static str {
    match module {
        Module::Core => "core",
        Module::Code => "code",
        Module::Cyber => "cyber",
        Module::Science => "science",
        Module::Game => "game",
        Module::Repack => "repack",
        Module::Fit => "fit",
        Module::Grid => "grid",
    }
}
pub(crate) fn identifier(value: &str, path: &str) -> ContractResult<()> {
    require(
        !value.is_empty()
            && value.len() <= 200
            && value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
            && !value.starts_with(['.', '-', '_'])
            && !value.ends_with(['.', '-', '_'])
            && !value.contains(".."),
        path,
        "invalid catalog identifier",
    )
}
fn strings(values: &[String], path: &str, min: usize) -> ContractResult<()> {
    unique_non_blank(values, path, min)
}
fn contains(values: &[String], required: &[&str], path: &str) -> ContractResult<()> {
    for value in required {
        require(
            values.iter().any(|v| v == value),
            path,
            &format!("missing required value {value}"),
        )?;
    }
    Ok(())
}
fn distinct<T: PartialEq>(values: &[T], path: &str, min: usize) -> ContractResult<()> {
    require(values.len() >= min, path, "too few values")?;
    for (i, v) in values.iter().enumerate() {
        require(!values[..i].contains(v), path, "duplicate values")?;
    }
    Ok(())
}
impl Validate for AgentProfile {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.agent-profile/v1",
            "profile.schema_version",
        )?;
        identifier(&self.id, "profile.id")?;
        require(
            self.module != Module::Grid,
            "profile.module",
            "grid has no agent namespace in v1",
        )?;
        let prefix = format!("melissa.{}.", module_name(self.module));
        require(
            self.id.starts_with(&prefix) && !self.id[prefix.len()..].contains('.'),
            "profile.id",
            "ID/module mismatch",
        )?;
        non_blank(&self.name_tr, "profile.name_tr")?;
        non_blank(&self.purpose_tr, "profile.purpose_tr")?;
        exact_version(
            &self.common_policy_ref,
            "melissa.runtime-policy/v1",
            "profile.common_policy_ref",
        )?;
        strings(&self.activation.when, "profile.activation.when", 2)?;
        strings(
            &self.activation.avoid_when,
            "profile.activation.avoid_when",
            1,
        )?;
        distinct(
            &self.model_policy.required_capabilities,
            "profile.model_policy.required_capabilities",
            2,
        )?;
        require(
            self.model_policy
                .required_capabilities
                .contains(&ModelCapability::ToolCalling)
                && self
                    .model_policy
                    .required_capabilities
                    .contains(&ModelCapability::StructuredOutput),
            "profile.model_policy",
            "tool calling and structured output required",
        )?;
        strings(&self.inputs.required, "profile.inputs.required", 2)?;
        strings(&self.inputs.optional, "profile.inputs.optional", 0)?;
        contains(
            &self.inputs.required,
            &["task_contract", "workspace_ref"],
            "profile.inputs.required",
        )?;
        require(
            !self
                .inputs
                .optional
                .iter()
                .any(|v| self.inputs.required.contains(v)),
            "profile.inputs",
            "required and optional inputs overlap",
        )?;
        exact_version(
            &self.outputs.schema_ref,
            "melissa.agent-result/v1",
            "profile.outputs.schema_ref",
        )?;
        strings(
            &self.outputs.required_domain_fields,
            "profile.outputs.required_domain_fields",
            1,
        )?;
        strings(&self.tool_ids, "profile.tool_ids", 1)?;
        strings(&self.worker_types, "profile.worker_types", 1)?;
        strings(
            &self.authority.capability_ceiling,
            "profile.authority.capability_ceiling",
            1,
        )?;
        strings(
            &self.authority.forbidden_effects,
            "profile.authority.forbidden_effects",
            2,
        )?;
        contains(
            &self.authority.forbidden_effects,
            &["authority.expand", "unapproved.external_write"],
            "profile.authority.forbidden_effects",
        )?;
        for cap in &self.authority.capability_ceiling {
            require(
                !cap.contains('*')
                    && ![
                        "authority.expand",
                        "policy.override",
                        "protected_verifier.modify",
                        "secrets.exfiltrate",
                    ]
                    .contains(&cap.as_str()),
                "profile.authority.capability_ceiling",
                "unrestricted/self-authorizing capability",
            )?;
            require(
                !self.authority.forbidden_effects.contains(cap),
                "profile.authority",
                "capability is also forbidden",
            )?;
        }
        strings(&self.procedure_tr, "profile.procedure_tr", 5)?;
        strings(&self.verification.checks, "profile.verification.checks", 3)?;
        non_blank(
            &self.verification.completion_rule_tr,
            "profile.verification.completion_rule_tr",
        )?;
        for text in [
            &self.recovery.on_tool_error_tr,
            &self.recovery.on_no_progress_tr,
            &self.recovery.on_unknown_effect_tr,
            &self.recovery.on_budget_exhausted_tr,
        ] {
            non_blank(text, "profile.recovery")?;
        }
        let mut handoff_ids = Vec::new();
        for handoff in &self.handoffs {
            identifier(&handoff.profile_id, "profile.handoffs.profile_id")?;
            non_blank(&handoff.when_tr, "profile.handoffs.when_tr")?;
            strings(
                &handoff.required_evidence,
                "profile.handoffs.required_evidence",
                1,
            )?;
            handoff_ids.push(handoff.profile_id.clone());
        }
        strings(&handoff_ids, "profile.handoffs", 0)?;
        require(
            self.evaluation_cases.len() >= 3,
            "profile.evaluation_cases",
            "at least three evaluation specifications required",
        )?;
        let mut case_ids = Vec::new();
        for case in &self.evaluation_cases {
            identifier(&case.id, "profile.evaluation_cases.id")?;
            non_blank(&case.scenario_tr, "profile.evaluation_cases.scenario_tr")?;
            strings(
                &case.expected_checks,
                "profile.evaluation_cases.expected_checks",
                2,
            )?;
            case_ids.push(case.id.clone());
        }
        strings(&case_ids, "profile.evaluation_cases", 3)?;
        require(
            self.system_prompt_tr.split_whitespace().count() >= 120,
            "profile.system_prompt_tr",
            "role prompt requires at least 120 words (definition completeness, not intelligence evidence)",
        )
    }
}
impl Validate for WorkerType {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.worker-type/v1",
            "worker.schema_version",
        )?;
        identifier(&self.id, "worker.id")?;
        require(
            !self.id.contains('.'),
            "worker.id",
            "worker id cannot contain dots",
        )?;
        non_blank(&self.name_tr, "worker.name_tr")?;
        non_blank(&self.purpose_tr, "worker.purpose_tr")?;
        distinct(&self.modules, "worker.modules", 1)?;
        distinct(&self.declared_platforms, "worker.declared_platforms", 1)?;
        strings(&self.tool_families, "worker.tool_families", 1)?;
        strings(&self.requirements_tr, "worker.requirements_tr", 1)?;
        non_blank(&self.isolation_contract_tr, "worker.isolation_contract_tr")?;
        strings(
            &self.job_contract.required,
            "worker.job_contract.required",
            9,
        )?;
        contains(
            &self.job_contract.required,
            &[
                "task_id",
                "invocation_id",
                "attempt_id",
                "lease_generation",
                "permit_ref",
                "arguments_digest",
                "input_artifact_refs",
                "limits",
                "cancellation_ref",
            ],
            "worker.job_contract.required",
        )?;
        strings(&self.job_contract.returns, "worker.job_contract.returns", 9)?;
        contains(
            &self.job_contract.returns,
            &[
                "status",
                "effect_status",
                "exit_code",
                "artifact_refs",
                "evidence_refs",
                "resource_usage",
                "error_category",
                "cleanup_status",
                "duration_ms",
            ],
            "worker.job_contract.returns",
        )?;
        exact_version(
            &self.resource_policy.authority,
            "task_and_broker",
            "worker.resource_policy.authority",
        )?;
        require(
            !self.resource_policy.unbounded_jobs,
            "worker.resource_policy.unbounded_jobs",
            "unbounded jobs forbidden",
        )?;
        strings(
            &self.resource_policy.limits,
            "worker.resource_policy.limits",
            7,
        )?;
        contains(
            &self.resource_policy.limits,
            &[
                "wall_time",
                "cpu",
                "ram",
                "disk",
                "output_bytes",
                "network_scope",
                "gpu_vram_when_applicable",
            ],
            "worker.resource_policy.limits",
        )?;
        distinct(&self.lifecycle, "worker.lifecycle", 8)?;
        require(
            self.lifecycle.len() == 8,
            "worker.lifecycle",
            "all lifecycle states required",
        )?;
        strings(&self.acceptance_checks_tr, "worker.acceptance_checks_tr", 3)
    }
}
impl Validate for ToolCatalog {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.tool-catalog/v1",
            "tools.schema_version",
        )?;
        require(!self.tools.is_empty(), "tools", "empty tool catalog")?;
        let mut ids = Vec::new();
        for tool in &self.tools {
            identifier(&tool.id, "tools.id")?;
            identifier(&tool.family, "tools.family")?;
            require(
                tool.id.split('.').next() == Some(tool.family.as_str()),
                "tools.family",
                "tool id/family mismatch",
            )?;
            strings(&tool.referenced_by, "tools.referenced_by", 0)?;
            strings(&tool.worker_candidates, "tools.worker_candidates", 0)?;
            exact_version(
                &tool.output_envelope_ref,
                "melissa.tool-observation/v1",
                "tools.output_envelope_ref",
            )?;
            ids.push(tool.id.clone());
        }
        strings(&ids, "tools.ids", 1)
    }
}
impl Validate for ToolAliases {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.tool-aliases/v1",
            "aliases.schema_version",
        )?;
        exact_version(
            &self.execution,
            "resolve_to_canonical_then_schema_and_policy_validate",
            "aliases.execution",
        )?;
        for (alias, target) in &self.aliases {
            identifier(alias, "aliases.key")?;
            identifier(target, "aliases.target")?;
            require(alias != target, "aliases", "self alias")?;
        }
        Ok(())
    }
}
impl Validate for ModuleCatalog {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.module-catalog/v1",
            "modules.schema_version",
        )?;
        require(!self.modules.is_empty(), "modules", "empty module catalog")?;
        let mut ids = Vec::new();
        let mut orders = Vec::new();
        let mut gates = Vec::new();
        for module in &self.modules {
            ids.push(module.id);
            orders.push(module.order);
            gates.push(module.gate.id.clone());
            strings(&module.profile_ids, "modules.profile_ids", 0)?;
            strings(&module.backlog_ids, "modules.backlog_ids", 1)?;
            require(
                module.profile_count == module.profile_ids.len(),
                "modules.profile_count",
                "profile count mismatch",
            )?;
            distinct(
                &module.implementation_dependencies,
                "modules.dependencies",
                0,
            )?;
            strings(&module.gate.requires, "modules.gate.requires", 4)?;
            contains(
                &module.gate.requires,
                &[
                    "all_module_backlog_accepted",
                    "required_previous_module_regression",
                    "local_and_live_evidence_separate",
                    "no_unresolved_false_completion",
                ],
                "modules.gate.requires",
            )?;
            strings(&module.gate.evidence_refs, "modules.gate.evidence_refs", 0)?;
            exact_version(
                &module.gate.id,
                &format!("GATE-{}", module_name(module.id).to_ascii_uppercase()),
                "modules.gate.id",
            )?;
            if module.gate.status == GateStatus::Passed {
                require(
                    !module.gate.evidence_refs.is_empty(),
                    "modules.gate.evidence_refs",
                    "passed gate requires evidence",
                )?;
            }
            if module.status.local_acceptance == AcceptanceStatus::Passed
                || module.status.live_acceptance == AcceptanceStatus::Passed
                || module.status.product_acceptance == AcceptanceStatus::Passed
            {
                require(
                    module.gate.status == GateStatus::Passed,
                    "modules.status",
                    "acceptance promotion requires passed evidence-bearing module gate",
                )?;
            }
            if module.status.product_acceptance == AcceptanceStatus::Passed {
                require(
                    module.status.live_acceptance == AcceptanceStatus::Passed
                        && module.status.local_acceptance == AcceptanceStatus::Passed,
                    "modules.status",
                    "product acceptance requires local and live acceptance",
                )?;
            }
            if module.status.live_acceptance == AcceptanceStatus::Passed {
                require(
                    module.status.local_acceptance == AcceptanceStatus::Passed,
                    "modules.status",
                    "live acceptance requires local acceptance",
                )?;
            }
        }
        distinct(&ids, "modules.ids", 1)?;
        distinct(&orders, "modules.order", 1)?;
        strings(&gates, "modules.gate.ids", 1)
    }
}
impl Validate for BacklogCatalog {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.backlog/v1",
            "backlog.schema_version",
        )?;
        let mut ids = Vec::new();
        for item in &self.items {
            let prefix = format!("{}-", module_name(item.module).to_ascii_uppercase());
            require(
                item.id.starts_with(&prefix)
                    && item.id[prefix.len()..].len() >= 2
                    && item.id[prefix.len()..].bytes().all(|v| v.is_ascii_digit()),
                "backlog.id",
                "backlog ID/module mismatch",
            )?;
            non_blank(&item.title_tr, "backlog.title_tr")?;
            non_blank(&item.acceptance_tr, "backlog.acceptance_tr")?;
            strings(&item.evidence_refs, "backlog.evidence_refs", 0)?;
            distinct(&item.depends_on_modules, "backlog.depends_on_modules", 0)?;
            if item.status == BacklogStatus::Accepted {
                require(
                    !item.evidence_refs.is_empty(),
                    "backlog.evidence_refs",
                    "accepted work requires evidence refs",
                )?;
            }
            ids.push(item.id.clone());
        }
        strings(&ids, "backlog.ids", 1)
    }
}
impl Validate for AgentIndex {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.agent-index/v1",
            "index.schema_version",
        )?;
        let mut ids = Vec::new();
        let mut paths = Vec::new();
        for item in &self.profiles {
            identifier(&item.id, "index.id")?;
            non_blank(&item.name_tr, "index.name_tr")?;
            non_blank(&item.path, "index.path")?;
            ids.push(item.id.clone());
            paths.push(item.path.clone());
        }
        strings(&ids, "index.ids", 1)?;
        strings(&paths, "index.paths", 1)
    }
}
impl Validate for RuntimePolicy {
    fn validate(&self) -> ContractResult<()> {
        exact_version(
            &self.schema_version,
            "melissa.runtime-policy/v1",
            "policy.schema_version",
        )?;
        exact_version(&self.id, "melissa.runtime-policy/v1", "policy.id")?;
        exact_version(
            &self.authority.decision_owner,
            "rust_policy_and_broker",
            "policy.authority.decision_owner",
        )?;
        exact_version(
            &self.authority.effective_grant,
            "intersection(task_grant, profile_ceiling, policy, valid_execution_permit)",
            "policy.authority.effective_grant",
        )?;
        exact_version(
            &self.authority.delegation,
            "attenuation_only",
            "policy.authority.delegation",
        )?;
        require(
            !self.authority.model_can_authorize,
            "policy.authority.model_can_authorize",
            "model must not authorize",
        )?;
        non_blank(&self.authority.approval, "policy.authority.approval")?;
        for (actual, expected, path) in [
            (
                &self.budget.scope,
                "entire_task_tree",
                "policy.budget.scope",
            ),
            (
                &self.budget.reservation,
                "atomic_before_parallel_dispatch",
                "policy.budget.reservation",
            ),
            (
                &self.budget.limits_source,
                "task_contract",
                "policy.budget.limits_source",
            ),
            (
                &self.budget.unknown_usage,
                "record_unknown_never_zero",
                "policy.budget.unknown_usage",
            ),
            (
                &self.storage.local,
                "sqlite_and_blake3_cas",
                "policy.storage.local",
            ),
            (
                &self.storage.transactions,
                "state_and_event_atomic",
                "policy.storage.transactions",
            ),
            (
                &self.storage.publication,
                "atomic_artifact_publish_and_recovery",
                "policy.storage.publication",
            ),
            (
                &self.storage.retention,
                "workspace_owned_with_quota_and_secure_gc",
                "policy.storage.retention",
            ),
            (
                &self.concurrency.simple_task_default,
                "one_active_agent",
                "policy.concurrency.simple_task_default",
            ),
            (
                &self.concurrency.specialists,
                "optional_by_task_and_shared_budget",
                "policy.concurrency.specialists",
            ),
        ] {
            exact_version(actual, expected, path)?;
        }
        require(
            !self.budget.fixed_universal_turn_limit,
            "policy.budget.fixed_universal_turn_limit",
            "universal turn limit is not task budget",
        )?;
        require(
            !self.concurrency.catalog_count_is_concurrency,
            "policy.concurrency.catalog_count_is_concurrency",
            "catalog count is not concurrency",
        )?;
        strings(
            &self.untrusted_input.sources,
            "policy.untrusted_input.sources",
            6,
        )?;
        contains(
            &self.untrusted_input.sources,
            &[
                "web",
                "tool_result",
                "artifact",
                "repository",
                "third_party_skill",
                "model_memory_proposal",
            ],
            "policy.untrusted_input.sources",
        )?;
        non_blank(&self.untrusted_input.rule, "policy.untrusted_input.rule")?;
        non_blank(&self.evidence.completion, "policy.evidence.completion")?;
        strings(
            &self.evidence.required_binding,
            "policy.evidence.required_binding",
            8,
        )?;
        contains(
            &self.evidence.required_binding,
            &[
                "task_id",
                "run_id",
                "input_digest",
                "output_digest",
                "tool_version",
                "environment_ref",
                "verifier_version",
                "acceptance_refs",
            ],
            "policy.evidence.required_binding",
        )?;
        strings(&self.recovery.classes, "policy.recovery.classes", 10)?;
        contains(
            &self.recovery.classes,
            &[
                "schema_error",
                "stale_input",
                "dependency_missing",
                "permission_denied",
                "provider_transient",
                "timeout",
                "cancelled",
                "budget_exhausted",
                "no_progress",
                "outcome_unknown",
            ],
            "policy.recovery.classes",
        )?;
        non_blank(
            &self.recovery.unknown_effect,
            "policy.recovery.unknown_effect",
        )?;
        non_blank(&self.recovery.autonomy, "policy.recovery.autonomy")?;
        non_blank(&self.cancellation, "policy.cancellation")?;
        strings(&self.security, "policy.security", 6)?;
        contains(
            &self.security,
            &[
                "expected_hash_scoped_patch",
                "protected_verifier",
                "actual_worker_filesystem_network_process_isolation",
                "fresh_ui_reference_and_input_scope",
                "source_redaction_and_content_telemetry_opt_in",
                "license_and_dependency_attestation",
            ],
            "policy.security",
        )
    }
}
