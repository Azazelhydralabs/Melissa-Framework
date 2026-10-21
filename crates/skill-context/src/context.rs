//! Lossless selected skill payloads and source-labelled context packing.
use crate::{
    Error, Namespace, Result, digest,
    package::{Registry, SkillPolicy},
    require,
};
use melissa_core_contracts::{design::SkillPin, validation::Validate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    SystemContract,
    TaskContract,
    RelevantSkills,
    WorkspaceContext,
    Evidence,
    RecentObservations,
    RemainingBudget,
    OutputSchema,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub id: String,
    pub namespace: Namespace,
    pub section: Section,
    pub source_ref: String,
    pub version: String,
    pub source_digest: String,
    pub payload_digest: String,
    pub payload: Vec<u8>,
    pub required: bool,
    pub authority: String,
}
impl Item {
    /// Host-only input factory; retrieved data must use untrusted_data.
    pub fn new(
        id: &str,
        namespace: Namespace,
        section: Section,
        bytes: Vec<u8>,
        source_ref: &str,
        version: &str,
        required: bool,
    ) -> Self {
        let d = digest(&bytes);
        Self {
            id: id.into(),
            namespace,
            section,
            source_ref: source_ref.into(),
            version: version.into(),
            source_digest: d.clone(),
            payload_digest: d,
            payload: bytes,
            required,
            authority: "untrusted_data".into(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct PackRequest {
    pub task_id: String,
    pub namespace: Namespace,
    pub task_contract_digest: String,
    pub workspace_digest: String,
    pub model_capacity: u64,
    pub reserved_output: u64,
    pub items: Vec<Item>,
    pub current_sources: BTreeMap<String, (String, String)>,
    pub skills: Vec<SkillPin>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub schema_version: String,
    pub task_id: String,
    pub namespace: Namespace,
    pub task_contract_digest: String,
    pub workspace_digest: String,
    pub policy_epoch: String,
    pub model_capacity: u64,
    pub reserved_output: u64,
    pub conservative_input_units: u64,
    pub counting_method: String,
    pub skills: Vec<SkillPin>,
    pub items: Vec<Item>,
    pub omitted_item_refs: Vec<String>,
}
pub fn pack(mut request: PackRequest, registry: &Registry, policy: &SkillPolicy) -> Result<Pack> {
    request.namespace.validate()?;
    require(!request.task_id.trim().is_empty(), "empty context task")?;
    require(
        request
            .items
            .iter()
            .all(|i| i.section != Section::RelevantSkills),
        "skill material must come from the pinned registry",
    )?;
    let mut skill_ids = BTreeSet::new();
    for pin in &request.skills {
        pin.validate()?;
        require(skill_ids.insert(&pin.skill_id), "duplicate selected skill")?;
        let p = registry.load(pin, policy)?;
        let mut i = Item::new(
            &format!("skill:{}", pin.skill_id),
            request.namespace.clone(),
            Section::RelevantSkills,
            serde_json::to_vec(&p.material()?)?,
            &pin.skill_id,
            &pin.semantic_version,
            true,
        );
        i.source_digest = pin.content_digest.clone();
        request.items.push(i);
    }
    let usable = request
        .model_capacity
        .checked_sub(request.reserved_output)
        .ok_or_else(|| Error("output reservation exceeds model capacity".into()))?;
    let mut ids = BTreeSet::new();
    let mut sections = BTreeMap::new();
    for i in &request.items {
        require(
            ids.insert(i.id.clone())
                && !i.source_ref.trim().is_empty()
                && !i.version.trim().is_empty()
                && i.namespace == request.namespace
                && !i.payload.is_empty()
                && digest(&i.payload) == i.payload_digest,
            "duplicate item, wrong namespace or invalid context payload",
        )?;
        if matches!(
            i.section,
            Section::WorkspaceContext | Section::Evidence | Section::RecentObservations
        ) {
            require(
                i.source_digest == i.payload_digest
                    && request
                        .current_sources
                        .get(&i.source_ref)
                        .is_some_and(|(v, d)| v == &i.version && d == &i.source_digest),
                "stale or unauthenticated context source",
            )?;
        }
        let authority = match i.section {
            Section::SystemContract => "host_contract",
            Section::TaskContract => "user_task",
            _ => "untrusted_data",
        };
        require(i.authority == authority, "context authority mismatch")?;
        if matches!(
            i.section,
            Section::SystemContract
                | Section::TaskContract
                | Section::RemainingBudget
                | Section::OutputSchema
        ) {
            require(
                i.required && sections.insert(i.section, 1).is_none(),
                "mandatory contract missing, duplicated or optional",
            )?;
        }
        if i.section == Section::TaskContract {
            require(
                i.source_ref == request.task_id
                    && i.source_digest == request.task_contract_digest
                    && i.source_digest == i.payload_digest,
                "task contract changed",
            )?;
        }
        if i.section == Section::RelevantSkills {
            require(
                request.skills.iter().any(|p| {
                    p.skill_id == i.source_ref
                        && p.semantic_version == i.version
                        && p.content_digest == i.source_digest
                }) && i.required,
                "unbound or partial skill",
            )?;
        }
    }
    require(
        sections.len() == 4,
        "required system/task/budget/output sections missing",
    )?;
    // Count the complete serialized envelope, including JSON escaping/metadata.
    // UTF8 bytes are a conservative transport unit, NOT measured model tokens.
    request
        .items
        .sort_by_key(|i| (!i.required, priority(i.section)));
    let mut result = Pack {
        schema_version: "melissa.context-pack/v1".into(),
        task_id: request.task_id,
        namespace: request.namespace,
        task_contract_digest: request.task_contract_digest,
        workspace_digest: request.workspace_digest,
        policy_epoch: policy.epoch.clone(),
        model_capacity: request.model_capacity,
        reserved_output: request.reserved_output,
        conservative_input_units: 0,
        counting_method: "serialized_UTF8_bytes_upper_bound_not_token_measurement".into(),
        skills: request.skills,
        items: Vec::new(),
        omitted_item_refs: Vec::new(),
    };
    for i in request.items {
        result.items.push(i.clone());
        let n = serde_json::to_vec(&result)?.len() as u64 + 20;
        if n > usable {
            result.items.pop();
            require(
                !i.required,
                "required context does not fit; no truncation allowed",
            )?;
            result.omitted_item_refs.push(i.source_ref);
        }
    }
    result.conservative_input_units = serde_json::to_vec(&result)?.len() as u64 + 20;
    require(
        result.conservative_input_units <= usable,
        "context metadata does not fit; explicit repack required",
    )?;
    Ok(result)
}
fn priority(s: Section) -> u8 {
    match s {
        Section::SystemContract
        | Section::TaskContract
        | Section::RemainingBudget
        | Section::OutputSchema => 0,
        Section::Evidence | Section::RecentObservations => 1,
        Section::WorkspaceContext => 2,
        Section::RelevantSkills => 3,
    }
}
