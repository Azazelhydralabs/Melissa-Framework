//! Strict typed DAG and attenuation-only declarations. Actual tool backends
//! must still supply CODE-03/C05 permits and path policies; a claim is a lock,
//! never filesystem authority.
use crate::{Kind, Result, digest, error, require};
use melissa_core_contracts::{
    catalog::Catalog, design::SkillPin, validation::Validate, wire::TaskContractV1,
};
use melissa_model_gateway::{schema, strict_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    SingleAgent,
    ConditionalDelegation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub resource: String,
    pub path: String,
    pub access: Access,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub from: String,
    pub pointer: String,
    pub input: String,
    pub schema: Value,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub profile: String,
    pub goal: String,
    pub after: BTreeSet<String>,
    pub bindings: Vec<Binding>,
    pub literal_input: Value,
    pub tools: BTreeSet<String>,
    pub effects: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub authorizations: BTreeSet<String>,
    pub claims: Vec<Claim>,
    pub output_schema: Value,
    pub skills: Vec<SkillPin>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: String,
    pub id: String,
    pub task: String,
    pub revision: u64,
    pub parent_digest: Option<String>,
    pub workspace_digest: String,
    pub policy_digest: String,
    pub mode: Mode,
    pub delegation_reason: Option<String>,
    pub max_parallel: u16,
    pub max_no_progress: u32,
    pub nodes: Vec<Node>,
    pub outputs: BTreeSet<String>,
}
pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
pub fn hash(s: &str) -> bool {
    s.strip_prefix("blake3:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}
pub fn path(s: &str) -> bool {
    s == "/"
        || (!s.is_empty()
            && s.len() <= 2048
            && !s.contains(['\\', ':', '\0', '*', '?', '<', '>', '|', '"'])
            && !s.chars().any(char::is_control)
            && s.split('/').all(|p| {
                let stem = p.split('.').next().unwrap_or_default().to_uppercase();
                !p.is_empty()
                    && !matches!(p, "." | "..")
                    && !p.ends_with(['.', ' '])
                    && !matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    )
                    && !["COM", "LPT"].iter().any(|v| {
                        stem.strip_prefix(v).is_some_and(|n| {
                            matches!(
                                n,
                                "1" | "2"
                                    | "3"
                                    | "4"
                                    | "5"
                                    | "6"
                                    | "7"
                                    | "8"
                                    | "9"
                                    | "¹"
                                    | "²"
                                    | "³"
                            )
                        })
                    })
            }))
}
pub fn conflicts(a: &Claim, b: &Claim) -> bool {
    if a.resource != b.resource || (a.access == Access::Read && b.access == Access::Read) {
        return false;
    }
    let x = a.path.to_uppercase();
    let y = b.path.to_uppercase();
    x == "/"
        || y == "/"
        || x == y
        || x.strip_prefix(&y).is_some_and(|p| p.starts_with('/'))
        || y.strip_prefix(&x).is_some_and(|p| p.starts_with('/'))
}
impl Plan {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(serde_json::from_value(strict_json(text)?)?)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    pub fn validate(&self, task: &TaskContractV1, catalog: &Catalog) -> Result<()> {
        task.validate()
            .map_err(|_| error(Kind::Invalid, "invalid parent task"))?;
        require(
            self.schema_version == "melissa.workflow-plan/v1"
                && identifier(&self.id)
                && self.task == task.task_id
                && self.revision > 0,
            Kind::Invalid,
            "plan identity/version/task mismatch",
        )?;
        require(
            hash(&self.workspace_digest)
                && hash(&self.policy_digest)
                && (self.revision == 1) == self.parent_digest.is_none()
                && self.parent_digest.as_ref().is_none_or(|s| hash(s)),
            Kind::Invalid,
            "plan revision/freshness digest mismatch",
        )?;
        require(
            !self.nodes.is_empty()
                && self.nodes.len() <= 128
                && self.max_parallel > 0
                && u64::from(self.max_parallel) <= task.limits.max_parallel_jobs
                && self.max_no_progress > 0,
            Kind::Invalid,
            "plan node/concurrency/progress bounds",
        )?;
        if self.mode == Mode::SingleAgent {
            require(
                self.nodes.len() == 1 && self.max_parallel == 1 && self.delegation_reason.is_none(),
                Kind::Invalid,
                "single-agent default cannot hide delegated work",
            )?;
        } else {
            require(
                self.delegation_reason
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty()),
                Kind::Invalid,
                "delegation needs an explicit task reason",
            )?;
        }
        let mut ids = BTreeMap::new();
        for n in &self.nodes {
            require(
                identifier(&n.id)
                    && !n.goal.trim().is_empty()
                    && n.goal.len() <= 256 * 1024
                    && ids.insert(n.id.clone(), n).is_none(),
                Kind::Invalid,
                "duplicate/invalid node identity or empty goal",
            )?;
            let p = catalog
                .profiles
                .get(&n.profile)
                .ok_or_else(|| error(Kind::Authority, "unknown node profile"))?;
            require(
                task.selected_profile_ids.contains(&n.profile),
                Kind::Authority,
                "profile outside parent task",
            )?;
            require(
                !n.effects.is_empty()
                    && n.effects.iter().all(|e| {
                        task.allowed_effects.contains(e)
                            && p.authority.capability_ceiling.contains(e)
                            && !p.authority.forbidden_effects.contains(e)
                    }),
                Kind::Authority,
                "node effects exceed parent/profile authority",
            )?;
            require(
                !n.resources.is_empty()
                    && n.resources
                        .iter()
                        .all(|r| task.allowed_resource_ids.contains(r))
                    && n.authorizations
                        .iter()
                        .all(|r| task.authorization_refs.contains(r)),
                Kind::Authority,
                "node resource/authorization amplification",
            )?;
            require(
                n.tools.iter().all(|t| {
                    p.tool_ids.contains(t) && catalog.tools.tools.iter().any(|c| &c.id == t)
                }),
                Kind::Authority,
                "unknown or role-inappropriate tool",
            )?;
            let mut seen = BTreeSet::new();
            for c in &n.claims {
                require(
                    n.resources.contains(&c.resource)
                        && path(&c.path)
                        && seen.insert((c.resource.clone(), c.path.to_uppercase())),
                    Kind::Invalid,
                    "invalid/aliased/duplicate resource claim",
                )?;
                if c.access == Access::Write {
                    require(
                        n.effects.contains("workspace.apply_patch_scoped"),
                        Kind::Authority,
                        "write ownership requires existing scoped mutation authority",
                    )?;
                }
            }
            schema::validate_schema(&n.output_schema)?;
            let mut inputs = BTreeSet::new();
            for b in &n.bindings {
                require(
                    n.after.contains(&b.from)
                        && identifier(&b.input)
                        && inputs.insert(&b.input)
                        && (b.pointer.is_empty() || b.pointer.starts_with('/')),
                    Kind::Invalid,
                    "invalid output binding/dependency/input",
                )?;
                schema::validate_schema(&b.schema)?;
            }
            let mut skills = BTreeSet::new();
            for pin in &n.skills {
                pin.validate()
                    .map_err(|_| error(Kind::Invalid, "invalid skill pin"))?;
                require(
                    skills.insert(&pin.skill_id),
                    Kind::Invalid,
                    "duplicate selected skill",
                )?;
            }
        }
        require(
            !self.outputs.is_empty() && self.outputs.iter().all(|id| ids.contains_key(id)),
            Kind::Invalid,
            "unknown/missing final output node",
        )?;
        for n in &self.nodes {
            require(
                n.after.iter().all(|id| id != &n.id && ids.contains_key(id)),
                Kind::Invalid,
                "self/unknown dependency",
            )?;
        }
        let mut done = BTreeSet::new();
        loop {
            let previous = done.len();
            for n in &self.nodes {
                if n.after.is_subset(&done) {
                    done.insert(n.id.clone());
                }
            }
            if done.len() == previous {
                break;
            }
        }
        require(
            done.len() == self.nodes.len(),
            Kind::Invalid,
            "cyclic workflow",
        )?;
        // Every node must contribute to a declared output, not hidden spend.
        let mut needed = self.outputs.clone();
        loop {
            let before = needed.len();
            for id in needed.clone() {
                needed.extend(ids[&id].after.iter().cloned());
            }
            if needed.len() == before {
                break;
            }
        }
        require(
            needed.len() == self.nodes.len(),
            Kind::Invalid,
            "orphan node does not contribute to output",
        )
    }
}
