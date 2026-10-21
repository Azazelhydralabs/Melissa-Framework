use melissa_core_contracts::validation::Validate;
use melissa_core_contracts::wire::{
    AgentResultV1, EvidenceManifestV1, ExecutionPermitV1, ExecutionPermitV2, TaskContractV1,
    ToolObservationV1, ToolObservationV2, WorkerJobV1,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn checked<T: DeserializeOwned + Validate>(value: Value) -> Result<T, String> {
    let parsed: T = serde_json::from_value(value).map_err(|error| error.to_string())?;
    parsed.validate().map_err(|error| error.to_string())?;
    Ok(parsed)
}

fn round_trip<T: DeserializeOwned + Serialize + Validate>(value: Value) {
    let parsed: T = checked(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

fn task() -> Value {
    json!({
        "schema_version": "melissa.task-contract/v1", "task_id": "task:code:1", "module": "code",
        "goal": "Repair the boundary failure and preserve unrelated changes.",
        "workspace_ref": "workspace:owned-project", "input_snapshot_digest": "blake3:input",
        "acceptance_contract_digest": "blake3:acceptance", "acceptance_criteria": ["protected boundary regression passes"],
        "selected_profile_ids": ["melissa.code.debugger"], "allowed_resource_ids": ["workspace:owned-project"],
        "allowed_effects": ["workspace.read", "workspace.write"], "authorization_refs": [],
        "limits": {"max_wall_time_ms": 60000, "max_cost_micro_usd": 0, "max_input_tokens": 0,
            "max_output_tokens": 0, "max_parallel_jobs": 1, "max_disk_bytes": 0, "max_output_bytes": 0},
        "authority_source": "user_task_and_rust_policy"
    })
}

fn permit() -> Value {
    json!({
        "schema_version": "melissa.execution-permit/v1", "permit_id": "permit:one", "task_id": "task:code:1",
        "principal_id": "principal:worker", "tool_id": "code.test", "resource_id": "workspace:owned-project",
        "arguments_digest": "blake3:canonical-arguments", "allowed_effects": ["process.execute"],
        "not_before_unix_ms": 1000, "expires_at_unix_ms": 2000, "max_invocations": 1,
        "issuer": "local-policy", "audience": "worker:generic", "nonce": "nonce:unique",
        "policy_version": "policy:1", "authorization_ref": "authorization:user-task", "signature_or_mac": "unverified-test-placeholder"
    })
}

fn observation() -> Value {
    json!({
        "schema_version": "melissa.tool-observation/v1", "task_id": "task:code:1", "invocation_id": "invocation:1",
        "attempt_id": "attempt:1", "tool_id": "code.test", "status": "success", "effect_status": "observed",
        "summary": "The protected regression ran.", "artifact_refs": ["cas:raw-log"], "evidence_refs": [],
        "exit_code": 0, "duration_ms": 100, "truncated": false, "error_category": null,
        "resource_usage": {"cpu_ms": 10, "peak_memory_bytes": 1000}, "input_digest": "blake3:final-source",
        "output_digest": "blake3:raw-log", "environment_ref": "environment:pinned-toolchain"
    })
}

fn evidence() -> Value {
    json!({
        "schema_version": "melissa.evidence-manifest/v1", "evidence_id": "evidence:1", "task_id": "task:code:1",
        "run_id": "run:1", "input_digest": "blake3:final-source", "output_digest": "blake3:test-results",
        "artifact_refs": ["cas:raw-log"], "invocation_ids": ["invocation:1"],
        "tool_versions": {"cargo": {"version": "pinned", "binary_digest": "blake3:tool"}},
        "environment_ref": "environment:pinned-toolchain", "verifier_id": "verifier:protected",
        "verifier_version": "verifier:1", "protected_acceptance_digest": "blake3:protected-tests",
        "acceptance_contract_digest": "blake3:acceptance", "verification_status": "passed",
        "acceptance_results": [{"criterion": "protected boundary regression passes", "passed": true, "evidence_refs": ["cas:raw-log"]}],
        "developer_intervention": false, "created_at": "2026-10-17T10:00:00+03:00"
    })
}

fn agent_result() -> Value {
    json!({
        "schema_version": "melissa.agent-result/v1", "task_id": "task:code:1", "run_id": "run:1",
        "profile_id": "melissa.code.debugger", "status": "completed", "summary": "Boundary failure corrected.",
        "artifact_refs": ["cas:patch"], "evidence_refs": ["evidence:1"], "domain_result": {"root_cause": "off-by-one"},
        "open_issues": [], "next_actions": [], "verification_status": "passed"
    })
}

fn worker_job() -> Value {
    json!({
        "schema_version": "melissa.worker-job/v1", "task_id": "task:code:1", "invocation_id": "invocation:1",
        "attempt_id": "attempt:1", "lease_generation": 1, "permit_ref": "permit:one",
        "arguments_digest": "blake3:canonical-arguments", "input_artifact_refs": ["cas:source"],
        "limits": {"max_wall_time_ms": 1000, "max_cpu_time_ms": 500, "max_memory_bytes": 1048576,
            "max_disk_bytes": 0, "max_output_bytes": 0, "max_gpu_vram_bytes": 0, "network_scope": []},
        "cancellation_ref": "cancellation:1"
    })
}

#[test]
fn v1_wire_documents_round_trip_without_dropping_open_domain_data() {
    round_trip::<TaskContractV1>(task());
    round_trip::<ExecutionPermitV1>(permit());
    round_trip::<ToolObservationV1>(observation());
    round_trip::<EvidenceManifestV1>(evidence());
    round_trip::<AgentResultV1>(agent_result());
    round_trip::<WorkerJobV1>(worker_job());
}

#[test]
fn task_budgets_distinguish_zero_allowance_from_invalid_unbounded_work() {
    checked::<TaskContractV1>(task()).unwrap();
    for field in ["max_wall_time_ms", "max_parallel_jobs"] {
        let mut invalid = task();
        invalid["limits"][field] = json!(0);
        assert!(
            checked::<TaskContractV1>(invalid)
                .unwrap_err()
                .contains(field)
        );
    }
    let mut negative = task();
    negative["limits"]["max_cost_micro_usd"] = json!(-1);
    assert!(checked::<TaskContractV1>(negative).is_err());
    let mut overflow = task();
    overflow["limits"]["max_wall_time_ms"] = json!(1e30);
    assert!(checked::<TaskContractV1>(overflow).is_err());
}

#[test]
fn task_rejects_blank_and_duplicate_scope_references_and_self_authority() {
    for field in [
        "acceptance_criteria",
        "selected_profile_ids",
        "allowed_resource_ids",
        "allowed_effects",
        "authorization_refs",
    ] {
        let mut blank = task();
        blank[field] = json!([" \t"]);
        assert!(
            checked::<TaskContractV1>(blank)
                .unwrap_err()
                .contains(field)
        );
        let mut duplicate = task();
        duplicate[field] = json!(["same", "same"]);
        assert!(
            checked::<TaskContractV1>(duplicate)
                .unwrap_err()
                .contains(field)
        );
    }
    let mut invalid = task();
    invalid["authority_source"] = json!("model_system_prompt");
    assert!(
        checked::<TaskContractV1>(invalid)
            .unwrap_err()
            .contains("authority_source")
    );
}

#[test]
fn strict_wire_fields_and_versions_do_not_silently_accept_future_authority() {
    let mut unknown = task();
    unknown["unlimited_authority"] = json!(true);
    assert!(
        checked::<TaskContractV1>(unknown)
            .unwrap_err()
            .contains("unlimited_authority")
    );
    let mut nested_unknown = task();
    nested_unknown["limits"]["ignore_limits"] = json!(true);
    assert!(
        checked::<TaskContractV1>(nested_unknown)
            .unwrap_err()
            .contains("ignore_limits")
    );
    let mut future = task();
    future["schema_version"] = json!("melissa.task-contract/v2");
    assert!(
        checked::<TaskContractV1>(future)
            .unwrap_err()
            .contains("schema_version")
    );
    let mut unknown_enum = task();
    unknown_enum["module"] = json!("god_mode");
    assert!(checked::<TaskContractV1>(unknown_enum).is_err());
    let raw = serde_json::to_string(&task()).unwrap();
    let duplicate = raw.replacen("{", "{\"task_id\":\"foreign-task\",", 1);
    assert!(
        serde_json::from_str::<TaskContractV1>(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate field")
    );
}

#[test]
fn permit_rejects_reusable_empty_or_inverted_grants_without_authenticating_them() {
    for invocations in [0, 2, u64::MAX] {
        let mut invalid = permit();
        invalid["max_invocations"] = json!(invocations);
        assert!(
            checked::<ExecutionPermitV1>(invalid)
                .unwrap_err()
                .contains("max_invocations")
        );
    }
    for expiry in [0, 1000] {
        let mut invalid = permit();
        invalid["expires_at_unix_ms"] = json!(expiry);
        assert!(
            checked::<ExecutionPermitV1>(invalid)
                .unwrap_err()
                .contains("expires_at_unix_ms")
        );
    }
    for field in [
        "arguments_digest",
        "authorization_ref",
        "signature_or_mac",
        "nonce",
    ] {
        let mut invalid = permit();
        invalid[field] = json!(" ");
        assert!(
            checked::<ExecutionPermitV1>(invalid)
                .unwrap_err()
                .contains(field)
        );
    }
    // The placeholder passes shape validation only. Real signature, replay,
    // revocation and runtime-clock enforcement belong to CODE-03.
    checked::<ExecutionPermitV1>(permit()).unwrap();
}

#[test]
fn permit_v2_requires_duration_and_never_upgrades_v1_implicitly() {
    let mut value = permit();
    value["schema_version"] = json!("melissa.execution-permit/v2");
    assert!(
        checked::<ExecutionPermitV2>(value.clone())
            .unwrap_err()
            .contains("max_duration_ms")
    );
    value["max_duration_ms"] = json!(600);
    round_trip::<ExecutionPermitV2>(value.clone());
    assert!(checked::<ExecutionPermitV1>(value.clone()).is_err());
    value["max_duration_ms"] = json!(0);
    assert!(
        checked::<ExecutionPermitV2>(value)
            .unwrap_err()
            .contains("max_duration_ms")
    );
}

#[test]
fn nullable_observation_fields_are_required_even_when_their_value_is_null() {
    let mut valid = observation();
    for field in ["exit_code", "error_category", "output_digest"] {
        valid[field] = Value::Null;
    }
    round_trip::<ToolObservationV1>(valid.clone());
    for field in ["exit_code", "error_category", "output_digest"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            checked::<ToolObservationV1>(missing)
                .unwrap_err()
                .contains(field)
        );
    }
}

#[test]
fn successful_tool_observations_cannot_hide_process_errors_or_unknown_effects() {
    for (field, value) in [
        ("exit_code", json!(1)),
        ("error_category", json!("process_failure")),
        ("effect_status", json!("unknown")),
        ("effect_status", json!("not_started")),
    ] {
        let mut invalid = observation();
        invalid[field] = value;
        assert!(
            checked::<ToolObservationV1>(invalid)
                .unwrap_err()
                .contains(field)
        );
    }
    let mut duplicate = observation();
    duplicate["artifact_refs"] = json!(["cas:log", "cas:log"]);
    assert!(
        checked::<ToolObservationV1>(duplicate)
            .unwrap_err()
            .contains("artifact_refs")
    );
}

#[test]
fn uncertain_effects_remain_distinct_from_failed_or_blocked_operations() {
    let mut unknown = observation();
    unknown["status"] = json!("outcome_unknown");
    unknown["effect_status"] = json!("unknown");
    unknown["error_category"] = json!("transport_lost_after_dispatch");
    unknown["exit_code"] = Value::Null;
    unknown["output_digest"] = Value::Null;
    round_trip::<ToolObservationV1>(unknown.clone());
    unknown["effect_status"] = json!("observed");
    assert!(
        checked::<ToolObservationV1>(unknown)
            .unwrap_err()
            .contains("effect_status")
    );
    let mut blocked = observation();
    blocked["status"] = json!("blocked");
    blocked["error_category"] = json!("expired_permit");
    assert!(checked::<ToolObservationV1>(blocked.clone()).is_err());
    blocked["effect_status"] = json!("not_started");
    blocked["exit_code"] = Value::Null;
    round_trip::<ToolObservationV1>(blocked);
}

#[test]
fn semantic_metrics_warnings_and_typed_artifacts_survive_v2_round_trip() {
    let mut value = observation();
    value["schema_version"] = json!("melissa.tool-observation/v2");
    value["artifacts"] = json!([{"type": "junit", "uri": "cas:raw-log"}]);
    value["metrics"] =
        json!({"passed": 18, "failed": 0, "coverage": {"value": 91.5, "unit": "percent"}});
    value["warnings"] = json!(["One optional platform suite was unavailable."]);
    round_trip::<ToolObservationV2>(value.clone());
    assert!(checked::<ToolObservationV1>(value.clone()).is_err());
    let mut bad_uri = value.clone();
    bad_uri["artifacts"][0]["uri"] = json!("cas:unlisted-artifact");
    assert!(
        checked::<ToolObservationV2>(bad_uri)
            .unwrap_err()
            .contains("artifacts.uri")
    );
    let mut unknown_artifact_field = value.clone();
    unknown_artifact_field["artifacts"][0]["trusted"] = json!(true);
    assert!(
        checked::<ToolObservationV2>(unknown_artifact_field)
            .unwrap_err()
            .contains("trusted")
    );
    value.as_object_mut().unwrap().remove("metrics");
    assert!(
        checked::<ToolObservationV2>(value)
            .unwrap_err()
            .contains("metrics")
    );
}

#[test]
fn evidence_cannot_claim_pass_with_failure_or_duplicate_criteria() {
    let mut false_pass = evidence();
    false_pass["acceptance_results"][0]["passed"] = json!(false);
    assert!(
        checked::<EvidenceManifestV1>(false_pass.clone())
            .unwrap_err()
            .contains("verification_status")
    );
    false_pass["verification_status"] = json!("failed");
    round_trip::<EvidenceManifestV1>(false_pass);
    let mut duplicate = evidence();
    let result = duplicate["acceptance_results"][0].clone();
    duplicate["acceptance_results"]
        .as_array_mut()
        .unwrap()
        .push(result);
    assert!(
        checked::<EvidenceManifestV1>(duplicate)
            .unwrap_err()
            .contains("acceptance_results.criterion")
    );
    let mut empty = evidence();
    empty["acceptance_results"] = json!([]);
    assert!(
        checked::<EvidenceManifestV1>(empty)
            .unwrap_err()
            .contains("acceptance_results")
    );
}

#[test]
fn developer_assisted_measurement_is_recorded_but_is_never_an_autonomous_pass() {
    let autonomous = checked::<EvidenceManifestV1>(evidence()).unwrap();
    assert!(autonomous.is_autonomous_pass());
    let mut assisted = evidence();
    assisted["developer_intervention"] = json!(true);
    let parsed = checked::<EvidenceManifestV1>(assisted.clone()).unwrap();
    assert!(!parsed.is_autonomous_pass());
    assert_eq!(serde_json::to_value(parsed).unwrap(), assisted);
    let mut inconclusive = evidence();
    inconclusive["verification_status"] = json!("inconclusive");
    assert!(
        !checked::<EvidenceManifestV1>(inconclusive)
            .unwrap()
            .is_autonomous_pass()
    );
}

#[test]
fn completed_agent_work_requires_verification_and_an_evidence_reference() {
    for verification in ["not_run", "pending", "failed", "inconclusive"] {
        let mut invalid = agent_result();
        invalid["verification_status"] = json!(verification);
        assert!(
            checked::<AgentResultV1>(invalid)
                .unwrap_err()
                .contains("verification_status")
        );
    }
    let mut no_evidence = agent_result();
    no_evidence["evidence_refs"] = json!([]);
    assert!(
        checked::<AgentResultV1>(no_evidence)
            .unwrap_err()
            .contains("evidence_refs")
    );
    let mut unresolved = agent_result();
    unresolved["status"] = json!("needs_reconciliation");
    assert!(checked::<AgentResultV1>(unresolved.clone()).is_err());
    unresolved["verification_status"] = json!("inconclusive");
    round_trip::<AgentResultV1>(unresolved);
}

#[test]
fn worker_jobs_have_positive_execution_bounds_and_preserve_zero_permissions() {
    round_trip::<WorkerJobV1>(worker_job());
    for field in ["max_wall_time_ms", "max_cpu_time_ms", "max_memory_bytes"] {
        let mut invalid = worker_job();
        invalid["limits"][field] = json!(0);
        assert!(checked::<WorkerJobV1>(invalid).unwrap_err().contains(field));
    }
    let mut unfenced = worker_job();
    unfenced["lease_generation"] = json!(0);
    assert!(
        checked::<WorkerJobV1>(unfenced)
            .unwrap_err()
            .contains("lease_generation")
    );
    let mut duplicate = worker_job();
    duplicate["input_artifact_refs"] = json!(["cas:source", "cas:source"]);
    assert!(
        checked::<WorkerJobV1>(duplicate)
            .unwrap_err()
            .contains("input_artifact_refs")
    );
}

#[test]
fn valid_shapes_cannot_cross_task_resource_or_effect_boundaries() {
    let mut task_value = task();
    task_value["allowed_effects"] = json!(["workspace.read", "process.execute"]);
    task_value["authorization_refs"] = json!(["authorization:user-task"]);
    let task = checked::<TaskContractV1>(task_value).unwrap();
    let parsed = checked::<ExecutionPermitV1>(permit()).unwrap();
    parsed.validate_against_task(&task).unwrap();
    for field in ["task_id", "resource_id", "allowed_effects"] {
        let mut foreign = permit();
        foreign[field] = if field == "allowed_effects" {
            json!(["process.execute", "network.external_write"])
        } else {
            json!("foreign-scope")
        };
        let parsed = checked::<ExecutionPermitV1>(foreign).unwrap();
        assert!(
            parsed
                .validate_against_task(&task)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
    }
    let mut long_permit = permit();
    long_permit["schema_version"] = json!("melissa.execution-permit/v2");
    long_permit["max_duration_ms"] = json!(60001);
    let parsed = checked::<ExecutionPermitV2>(long_permit).unwrap();
    assert!(
        parsed
            .validate_against_task(&task)
            .unwrap_err()
            .to_string()
            .contains("max_duration_ms")
    );
}

#[test]
fn independently_valid_worker_job_cannot_substitute_permit_or_arguments() {
    let mut value = permit();
    value["schema_version"] = json!("melissa.execution-permit/v2");
    value["max_duration_ms"] = json!(1000);
    let permit = checked::<ExecutionPermitV2>(value).unwrap();
    checked::<WorkerJobV1>(worker_job())
        .unwrap()
        .validate_against_permit(&permit)
        .unwrap();
    for field in ["task_id", "permit_ref", "arguments_digest"] {
        let mut value = worker_job();
        value[field] = json!("substituted");
        let job = checked::<WorkerJobV1>(value).unwrap();
        assert!(
            job.validate_against_permit(&permit)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
    }
    let mut excessive = worker_job();
    excessive["limits"]["max_wall_time_ms"] = json!(1001);
    assert!(
        checked::<WorkerJobV1>(excessive)
            .unwrap()
            .validate_against_permit(&permit)
            .is_err()
    );
}

#[test]
fn evidence_binds_all_declared_criteria_without_reusing_foreign_acceptance() {
    let task = checked::<TaskContractV1>(task()).unwrap();
    checked::<EvidenceManifestV1>(evidence())
        .unwrap()
        .validate_against_task(&task)
        .unwrap();
    for field in ["task_id", "acceptance_contract_digest"] {
        let mut foreign = evidence();
        foreign[field] = json!("foreign");
        assert!(
            checked::<EvidenceManifestV1>(foreign)
                .unwrap()
                .validate_against_task(&task)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
    }
    let mut omitted = evidence();
    omitted["acceptance_results"][0]["criterion"] = json!("an easier unrelated check");
    assert!(
        checked::<EvidenceManifestV1>(omitted)
            .unwrap()
            .validate_against_task(&task)
            .unwrap_err()
            .to_string()
            .contains("acceptance_results")
    );
    let mut unselected = agent_result();
    unselected["profile_id"] = json!("melissa.cyber.reverse-engineering");
    assert!(
        checked::<AgentResultV1>(unselected)
            .unwrap()
            .validate_against_task(&task)
            .unwrap_err()
            .to_string()
            .contains("profile_id")
    );
}

#[test]
fn explicit_task_authorizations_cannot_be_substituted() {
    let mut task_value = task();
    task_value["allowed_effects"] = json!(["process.execute"]);
    task_value["authorization_refs"] = json!(["authorization:user-task"]);
    let task = checked::<TaskContractV1>(task_value).unwrap();
    checked::<ExecutionPermitV1>(permit())
        .unwrap()
        .validate_against_task(&task)
        .unwrap();
    let mut foreign = permit();
    foreign["authorization_ref"] = json!("authorization:another-task");
    assert!(
        checked::<ExecutionPermitV1>(foreign)
            .unwrap()
            .validate_against_task(&task)
            .unwrap_err()
            .to_string()
            .contains("authorization_ref")
    );
    let mut unbound = task.clone();
    unbound.authorization_refs.clear();
    unbound.validate().unwrap();
    assert!(
        checked::<ExecutionPermitV1>(permit())
            .unwrap()
            .validate_against_task(&unbound)
            .is_err()
    );
}

#[test]
fn worker_job_cannot_turn_zero_task_disk_or_output_allowance_into_unbounded_work() {
    let task = checked::<TaskContractV1>(task()).unwrap();
    checked::<WorkerJobV1>(worker_job())
        .unwrap()
        .validate_against_task(&task)
        .unwrap();
    for (field, too_large) in [
        ("max_wall_time_ms", 60001),
        ("max_disk_bytes", 1),
        ("max_output_bytes", 1),
    ] {
        let mut value = worker_job();
        value["limits"][field] = json!(too_large);
        assert!(
            checked::<WorkerJobV1>(value)
                .unwrap()
                .validate_against_task(&task)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
    }
    let mut foreign = worker_job();
    foreign["task_id"] = json!("task:foreign");
    assert!(
        checked::<WorkerJobV1>(foreign)
            .unwrap()
            .validate_against_task(&task)
            .unwrap_err()
            .to_string()
            .contains("task_id")
    );
}
