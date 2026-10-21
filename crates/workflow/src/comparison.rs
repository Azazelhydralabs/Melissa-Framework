//! Host-only paired evaluation. All requests (including failures) are charged
//! from the native ledger. An oracle is trusted ONLY for the exact snapshot
//! selected by the independent host, never a digest selected by model output.
use crate::{Kind, Result, digest, error, plan::Mode, require};
use melissa_core_contracts::wire::{ObservationStatus, TaskLimitsV1, ToolObservationV2};
use melissa_local_store::{LocalStore, journal::ModelRequestState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arm {
    Single,
    Delegated,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairKey {
    pub case_id: String,
    pub input_content_digest: String,
    pub acceptance_digest: String,
    pub goal_digest: String,
    pub provider: String,
    pub model: String,
    pub model_settings_digest: String,
    pub environment_ref: String,
    pub limits: TaskLimitsV1,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedOracle {
    pub observation_artifact_id: String,
    pub exact_snapshot_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    pub key: PairKey,
    pub arm: Arm,
    pub task: String,
    pub passed: bool,
    pub critical_failure: bool,
    pub host_interventions: u32,
    pub wall_time_ms: u64,
    pub all_requests: usize,
    pub dispatched_requests: usize,
    pub conservative_micro_usd: u64,
    pub known_input_tokens: u64,
    pub known_output_tokens: u64,
    pub oracle_evidence_digest: Option<String>,
    pub native_requests_digest: String,
}
pub fn settings(request: &Value) -> Result<String> {
    let b = &request["body"];
    require(
        request["configured_context_tokens"].is_u64()
            && request["configured_max_output_tokens"].is_u64(),
        Kind::Invalid,
        "native model capacity metadata missing",
    )?;
    Ok(digest(&serde_json::to_vec(
        &json!({"model":b["model"],"context":request["configured_context_tokens"],"output":request["configured_max_output_tokens"],"max_output_tokens":b["max_output_tokens"],"reasoning":b["reasoning"],"temperature":b["temperature"],"top_p":b["top_p"],"protocol":request["protocol"],"endpoint":request["endpoint"],"output_mode":request["configured_output_mode"]}),
    )?))
}
pub struct AuditSpec {
    pub key: PairKey,
    pub arm: Arm,
    pub oracle: Option<ProtectedOracle>,
    pub wall_time_ms: u64,
    pub host_interventions: u32,
    pub critical_failure: bool,
}
pub fn audit_trial(store: &LocalStore, task: &str, spec: AuditSpec) -> Result<Trial> {
    let AuditSpec {
        key,
        arm,
        oracle,
        wall_time_ms,
        host_interventions,
        critical_failure,
    } = spec;
    let parent = store.journal().task(task)?;
    require(
        parent.contract.limits == key.limits
            && parent.contract.acceptance_contract_digest == key.acceptance_digest
            && digest(parent.contract.goal.as_bytes()) == key.goal_digest,
        Kind::Invalid,
        "paired task goal/acceptance/total budget differs",
    )?;
    let budget = store.journal().model_budget(task)?;
    require(
        budget.active_requests == 0
            && budget.unknown_requests == 0
            && budget.unknown_input_requests == 0
            && budget.unknown_output_requests == 0
            && budget.unknown_cost_requests == 0
            && parent.record.unknown_invocation_id.is_none(),
        Kind::Uncertain,
        "unsettled trial cannot enter comparison",
    )?;
    let input: melissa_container_executor::Snapshot = serde_json::from_slice(
        &store.get_artifact(task, &format!("workflow-comparison-input:{task}"))?,
    )?;
    input
        .validate(parent.contract.limits.max_disk_bytes)
        .map_err(|_| error(Kind::Invalid, "comparison source capture invalid"))?;
    require(
        input
            .digest()
            .map_err(|_| error(Kind::Invalid, "comparison source digest invalid"))?
            == key.input_content_digest,
        Kind::Invalid,
        "comparison initial source bytes changed",
    )?;
    let requests = store.journal().model_requests(task)?;
    require(
        !requests.is_empty(),
        Kind::Invalid,
        "real native model requests required",
    )?;
    for r in &requests {
        require(
            r.reservation.provider_id == key.provider && r.reservation.model_id == key.model,
            Kind::Invalid,
            "comparison changed model/provider",
        )?;
        let raw = store.get_artifact(task, &format!("{}:request", r.reservation.request_id))?;
        let request: Value = serde_json::from_slice(&raw)?;
        require(
            digest(&raw) == r.reservation.request_digest
                && settings(&request)? == key.model_settings_digest,
            Kind::Invalid,
            "comparison changed native request/capacity/sampling",
        )?;
        require(
            !matches!(
                r.state,
                ModelRequestState::Reserved
                    | ModelRequestState::Dispatched
                    | ModelRequestState::OutcomeUnknown
            ),
            Kind::Uncertain,
            "unknown model receipt in trial",
        )?;
    }
    let mut passed = false;
    let mut oracle_digest = None;
    if let Some(oracle) = oracle {
        let bytes = store.get_artifact(task, &oracle.observation_artifact_id)?;
        let observation: ToolObservationV2 = serde_json::from_slice(&bytes)?;
        require(
            observation.task_id == task
                && observation.tool_id == "process.exec"
                && !observation.truncated,
            Kind::Invalid,
            "protected oracle is not an owned native C03 execution",
        )?;
        let mut report = None;
        let mut stdout = None;
        for artifact in &observation.artifacts {
            let bytes = store.get_artifact(task, &artifact.uri)?;
            if artifact.r#type == "process.execution_report" {
                report = Some(serde_json::from_slice::<Value>(&bytes)?);
            }
            if artifact.r#type == "process.stdout" {
                stdout = Some(bytes);
            }
        }
        let report =
            report.ok_or_else(|| error(Kind::Invalid, "protected native report missing"))?;
        let native = &report["report"];
        require(
            native["input_digest"] == oracle.exact_snapshot_digest
                && native["image_id"] == key.environment_ref
                && report["requires_reconciliation"] == false
                && native["cleanup_confirmed"] == true
                && native["tree_confirmed_stopped"] == true
                && native["policy_verified"] == true
                && native["output_truncated"] == false
                && native["export_truncated"] == false,
            Kind::Uncertain,
            "oracle environment/input/containment mismatch",
        )?;
        passed = observation.status == ObservationStatus::Success
            && native["exit_code"] == 0
            && stdout
                .as_deref()
                .is_some_and(|v| String::from_utf8_lossy(v).contains("CODE08_PROTECTED_ORACLE_OK"));
        oracle_digest = Some(digest(&bytes));
    }
    Ok(Trial {
        key,
        arm,
        task: task.into(),
        passed,
        critical_failure,
        host_interventions,
        wall_time_ms,
        all_requests: requests.len(),
        dispatched_requests: requests
            .iter()
            .filter(|r| r.dispatched_at_unix_ms.is_some())
            .count(),
        conservative_micro_usd: budget.charged_cost_micro_usd,
        known_input_tokens: budget.known_input_tokens,
        known_output_tokens: budget.known_output_tokens,
        oracle_evidence_digest: oracle_digest,
        native_requests_digest: digest(&serde_json::to_vec(&requests)?),
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    KeepSingle,
    DelegationMeasuredBetterOnThisSuite,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub schema_version: String,
    pub pairs: usize,
    pub single_passed: usize,
    pub delegated_passed: usize,
    pub single_cost: u64,
    pub delegated_cost: u64,
    pub single_wall_ms: u64,
    pub delegated_wall_ms: u64,
    pub recommendation: Recommendation,
    pub trials: Vec<Trial>,
    pub general_superiority_claim: bool,
    pub held_out: bool,
}
pub fn compare(trials: Vec<Trial>) -> Result<Comparison> {
    let mut pairs = BTreeMap::<String, (Option<&Trial>, Option<&Trial>)>::new();
    for t in &trials {
        let pair = pairs.entry(t.key.case_id.clone()).or_default();
        let target = if t.arm == Arm::Single {
            &mut pair.0
        } else {
            &mut pair.1
        };
        require(
            target.is_none(),
            Kind::Invalid,
            "duplicate trial arm; failed attempts may not be silently replaced",
        )?;
        *target = Some(t);
    }
    require(!pairs.is_empty(), Kind::Invalid, "empty comparison")?;
    let (mut sp, mut dp, mut sc, mut dc, mut st, mut dt) = (0usize, 0usize, 0u64, 0u64, 0u64, 0u64);
    let mut critical = false;
    let mut interventions = false;
    let mut tasks = BTreeSet::new();
    for (single, delegated) in pairs.values() {
        let s = single.ok_or_else(|| error(Kind::Invalid, "missing single-agent baseline"))?;
        let d = delegated.ok_or_else(|| error(Kind::Invalid, "missing delegated arm"))?;
        require(
            s.key == d.key
                && s.task != d.task
                && tasks.insert(s.task.clone())
                && tasks.insert(d.task.clone()),
            Kind::Invalid,
            "paired inputs/model/configuration/budget/environment differ",
        )?;
        sp += usize::from(s.passed);
        dp += usize::from(d.passed);
        sc = sc
            .checked_add(s.conservative_micro_usd)
            .ok_or_else(|| error(Kind::Invalid, "cost overflow"))?;
        dc = dc
            .checked_add(d.conservative_micro_usd)
            .ok_or_else(|| error(Kind::Invalid, "cost overflow"))?;
        st = st.saturating_add(s.wall_time_ms);
        dt = dt.saturating_add(d.wall_time_ms);
        critical |= d.critical_failure;
        interventions |= s.host_interventions > 0 || d.host_interventions > 0;
    }
    // Three paired development fixtures can establish only an observed suite
    // result. They are not a statistical guarantee on unknown future tasks.
    let better = pairs.len() >= 3
        && !critical
        && !interventions
        && (dp > sp || (dp == sp && dp == pairs.len() && dc <= sc && dt < st));
    Ok(Comparison {
        schema_version: "melissa.workflow-comparison/v1".into(),
        pairs: pairs.len(),
        single_passed: sp,
        delegated_passed: dp,
        single_cost: sc,
        delegated_cost: dc,
        single_wall_ms: st,
        delegated_wall_ms: dt,
        recommendation: if better {
            Recommendation::DelegationMeasuredBetterOnThisSuite
        } else {
            Recommendation::KeepSingle
        },
        trials,
        general_superiority_claim: false,
        held_out: false,
    })
}
pub fn default_mode(
    comparison: Option<&Comparison>,
    host_admitted_digests: &BTreeSet<String>,
) -> Result<Mode> {
    if let Some(c) = comparison {
        let actual = compare(c.trials.clone())?;
        require(
            serde_json::to_value(&actual)? == serde_json::to_value(c)?,
            Kind::Invalid,
            "comparison summary differs from actual trial records",
        )?;
        if c.recommendation == Recommendation::DelegationMeasuredBetterOnThisSuite
            && host_admitted_digests.contains(&digest(&serde_json::to_vec(c)?))
        {
            return Ok(Mode::ConditionalDelegation);
        }
    }
    Ok(Mode::SingleAgent)
}
