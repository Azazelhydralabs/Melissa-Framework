//! Authenticated immutable checkpoints, project memory proposals and cache keys.
//! All methods are trusted-host APIs. Stored references cannot renew authority.
use crate::{
    Namespace, Result,
    context::Pack,
    digest, json,
    package::{Registry, SkillPolicy},
    require,
    retrieval::{SearchScope, Source},
};
use melissa_core_contracts::design::SkillPin;
use melissa_local_store::cas::Cas;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub fn save<T: Serialize>(cas: &Cas, record: &T) -> Result<String> {
    let bytes = serde_json::to_vec(record)?;
    let blob = cas.put(&bytes)?;
    Ok(format!("blake3:{}", blob.digest))
}
pub fn restore<T: serde::de::DeserializeOwned>(cas: &Cas, reference: &str) -> Result<T> {
    let raw = reference
        .strip_prefix("blake3:")
        .ok_or_else(|| crate::Error("invalid checkpoint digest".into()))?;
    json(&cas.get(raw)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema_version: String,
    pub pack: Pack,
    pub authorization_ref: String,
    pub cancellation_ref: String,
    pub remaining_cost_micro_usd: u64,
    pub consumed_model_requests: u64,
    pub open_effect_refs: Vec<String>,
    pub rejected_hypotheses: Vec<String>,
    pub open_issue_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}
/// Independently refreshed from the host task, policy and durable budget ledger.
pub struct ResumeState {
    pub namespace: Namespace,
    pub task_id: String,
    pub task_contract_digest: String,
    pub workspace_digest: String,
    pub authorization_ref: String,
    pub cancellation_ref: String,
    pub cancelled: bool,
    pub authorization_active: bool,
    pub remaining_cost_micro_usd: u64,
    pub consumed_model_requests: u64,
    pub skills: Vec<SkillPin>,
}
impl Checkpoint {
    /// Returns a candidate for the existing gateway/broker, never starts work
    /// or replays tool calls. Native provider continuation remains CODE-04's job.
    pub fn validate_resume(
        &self,
        current: &ResumeState,
        registry: &Registry,
        policy: &SkillPolicy,
    ) -> Result<()> {
        require(
            self.schema_version == "melissa.context-checkpoint/v1"
                && self.pack.schema_version == "melissa.context-pack/v1"
                && !current.cancelled
                && current.authorization_active
                && self.open_effect_refs.is_empty(),
            "checkpoint cancelled, unauthorized or needs reconciliation",
        )?;
        require(
            current.namespace == self.pack.namespace
                && current.task_id == self.pack.task_id
                && current.task_contract_digest == self.pack.task_contract_digest
                && current.workspace_digest == self.pack.workspace_digest
                && current.authorization_ref == self.authorization_ref
                && !self.authorization_ref.trim().is_empty()
                && current.cancellation_ref == self.cancellation_ref
                && !self.cancellation_ref.trim().is_empty(),
            "checkpoint scope, source or authority changed; re-observe",
        )?;
        require(
            self.pack.policy_epoch == policy.epoch
                && current.remaining_cost_micro_usd <= self.remaining_cost_micro_usd
                && current.consumed_model_requests >= self.consumed_model_requests
                && current.skills == self.pack.skills,
            "checkpoint policy/skill changed or budget reset",
        )?;
        for pin in &current.skills {
            registry.load(pin, policy)?;
        }
        for i in &self.pack.items {
            require(
                digest(&i.payload) == i.payload_digest,
                "checkpoint payload changed",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    Proposed,
    Accepted,
    Rejected,
    Stale,
    Deleted,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub id: String,
    pub namespace: Namespace,
    pub key: String,
    pub claim: String,
    pub sources: Vec<Source>,
    pub status: MemoryStatus,
    pub review_evidence_ref: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBook {
    records: BTreeMap<String, Memory>,
}
impl MemoryBook {
    pub fn propose(
        &mut self,
        id: &str,
        namespace: Namespace,
        key: &str,
        claim: &str,
        sources: Vec<Source>,
    ) -> Result<String> {
        namespace.validate()?;
        require(
            !id.trim().is_empty()
                && !key.trim().is_empty()
                && !claim.trim().is_empty()
                && claim.len() <= 65536
                && !self.records.contains_key(id)
                && !sources.is_empty(),
            "invalid or duplicate memory proposal",
        )?;
        for s in &sources {
            s.validate()?;
            require(s.namespace == namespace, "memory source namespace mismatch")?;
        }
        let record = Memory {
            id: id.into(),
            namespace,
            key: key.into(),
            claim: claim.into(),
            sources,
            status: MemoryStatus::Proposed,
            review_evidence_ref: None,
        };
        let hash = digest(&serde_json::to_vec(&record)?);
        self.records.insert(id.into(), record);
        Ok(hash)
    }
    /// Host review decision only; semantic truth is the reviewer's responsibility.
    /// A model proposal cannot invoke this transition through a model tool.
    pub fn review(
        &mut self,
        id: &str,
        expected: &str,
        scope: &SearchScope,
        accept: bool,
        evidence_ref: &str,
        supersedes: &BTreeSet<String>,
    ) -> Result<()> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| crate::Error("memory not found".into()))?;
        require(
            record.status == MemoryStatus::Proposed
                && digest(&serde_json::to_vec(record)?) == expected
                && record.namespace == scope.namespace
                && !evidence_ref.trim().is_empty()
                && record.sources.iter().all(|s| scope.allows(s)),
            "stale/unreviewable memory proposal",
        )?;
        let conflicts: BTreeSet<_> = self
            .records
            .values()
            .filter(|r| {
                r.id != id
                    && r.namespace == record.namespace
                    && r.key == record.key
                    && r.status == MemoryStatus::Accepted
            })
            .map(|r| r.id.clone())
            .collect();
        require(
            !accept || &conflicts == supersedes,
            "memory conflict requires explicit full supersession",
        )?;
        if accept {
            for prior in supersedes {
                self.records
                    .get_mut(prior)
                    .expect("conflict set checked")
                    .status = MemoryStatus::Stale;
            }
        }
        let r = self.records.get_mut(id).expect("checked");
        r.status = if accept {
            MemoryStatus::Accepted
        } else {
            MemoryStatus::Rejected
        };
        r.review_evidence_ref = Some(evidence_ref.into());
        Ok(())
    }
    pub fn search(&self, scope: &SearchScope, query: &str) -> Vec<&Memory> {
        self.records
            .values()
            .filter(|r| {
                r.namespace == scope.namespace
                    && r.status == MemoryStatus::Accepted
                    && r.sources.iter().all(|s| scope.allows(s))
                    && (r.key.contains(query) || r.claim.contains(query))
            })
            .collect()
    }
    pub fn delete(&mut self, scope: &Namespace, id: &str) -> Result<()> {
        let r = self
            .records
            .get_mut(id)
            .ok_or_else(|| crate::Error("memory not found".into()))?;
        require(&r.namespace == scope, "memory deletion scope mismatch")?;
        r.status = MemoryStatus::Deleted;
        r.claim.clear();
        r.sources.clear();
        r.review_evidence_ref = None;
        Ok(())
    }
    pub fn invalidate_source(&mut self, scope: &Namespace, source_id: &str) {
        for r in self
            .records
            .values_mut()
            .filter(|r| &r.namespace == scope && r.sources.iter().any(|s| s.id == source_id))
        {
            if matches!(r.status, MemoryStatus::Accepted | MemoryStatus::Proposed) {
                r.status = MemoryStatus::Stale;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    Prompt,
    Retrieval,
    Parse,
    Build,
    ToolResult,
    Artifact,
    SkillEvaluation,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKey {
    pub kind: CacheKind,
    pub namespace: Namespace,
    pub input_digest: String,
    pub source_digest: String,
    pub skill_digest: String,
    pub provider_model: String,
    pub prompt_digest: String,
    pub tool_version: String,
    pub verifier_version: String,
    pub environment_digest: String,
    pub policy_epoch: String,
}
impl CacheKey {
    fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        require(
            [
                &self.input_digest,
                &self.source_digest,
                &self.skill_digest,
                &self.provider_model,
                &self.prompt_digest,
                &self.tool_version,
                &self.verifier_version,
                &self.environment_digest,
                &self.policy_epoch,
            ]
            .iter()
            .all(|s| !s.trim().is_empty()),
            "cache dependency missing",
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(&serde_json::to_vec(self)?))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEntry {
    key: CacheKey,
    created_ms: u64,
    expires_ms: u64,
    bytes: Vec<u8>,
    digest: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    entries: BTreeMap<String, CacheEntry>,
}
/// Fresh host decision, deliberately not serialized with the cached data.
pub struct CacheAdmission {
    pub authorized_now: bool,
    pub deterministic_readonly: bool,
    pub cancelled: bool,
}
impl Cache {
    pub fn put(
        &mut self,
        key: CacheKey,
        bytes: Vec<u8>,
        now: u64,
        expires: u64,
        admission: &CacheAdmission,
    ) -> Result<()> {
        require(
            admission.authorized_now
                && admission.deterministic_readonly
                && !admission.cancelled
                && expires > now,
            "unsafe cache insertion",
        )?;
        let d = digest(&bytes);
        self.entries.insert(
            key.digest()?,
            CacheEntry {
                key,
                created_ms: now,
                expires_ms: expires,
                bytes,
                digest: d,
            },
        );
        Ok(())
    }
    pub fn get(
        &self,
        key: &CacheKey,
        now: u64,
        admission: &CacheAdmission,
    ) -> Result<Option<&[u8]>> {
        require(
            admission.authorized_now && admission.deterministic_readonly && !admission.cancelled,
            "cache access denied",
        )?;
        let Some(e) = self.entries.get(&key.digest()?) else {
            return Ok(None);
        };
        require(
            e.key == *key && digest(&e.bytes) == e.digest,
            "cache integrity mismatch",
        )?;
        Ok((e.created_ms <= now && now < e.expires_ms).then_some(e.bytes.as_slice()))
    }
    pub fn invalidate_source(&mut self, scope: &Namespace, digest: &str) {
        self.entries
            .retain(|_, e| &e.key.namespace != scope || e.key.source_digest != digest);
    }
}
