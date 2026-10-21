use std::collections::BTreeSet;

use melissa_core_contracts::design::*;
use melissa_core_contracts::validation::Validate;
use serde_json::{Value, json};

fn hash() -> String {
    format!("blake3:{}", "a".repeat(64))
}
fn limits() -> Value {
    json!({"timeout_seconds":600,"max_iterations":8,"max_parallel_tools":2,"max_cost_micro_usd":2_000_000})
}
fn pin() -> Value {
    json!({"skill_id":"melissa.code.debug","semantic_version":"1.2.0","content_digest":hash()})
}

fn skill() -> Value {
    let files = [
        ("SKILL.md", "entrypoint"),
        ("schemas/input.json", "schema"),
        ("schemas/output.json", "schema"),
        ("evals/cases.jsonl", "evaluation"),
        ("evals/assertions.json", "evaluation"),
        ("scripts/classify.py", "script"),
        ("references/debug.md", "reference"),
        ("assets/report.md", "template"),
        ("tests/parser.py", "test"),
    ]
    .into_iter()
    .map(|(path, role)| json!({"path":path,"content_digest":hash(),"role":role}))
    .collect::<Vec<_>>();
    json!({"schema_version":"melissa.skill-definition/v1","id":"melissa.code.debug","module":"code",
        "name_tr":"Debug","description_tr":"Reproduce and classify a compiler failure","use_when":["Build fails"],
        "manifest":{"entrypoint":"SKILL.md","category":"coding","trust_level":"first_party",
            "routing":{"intents":["compiler_error"],"priority":80},"required_tools":["code.build","fs.read"],
            "required_capabilities":["workspace.read"],"prerequisites":["Rust toolchain"],"runtime":limits(),
            "input_schema_ref":"schemas/input.json","output_schema_ref":"schemas/output.json",
            "verification":[{"check":"Actual build and regression","required":true}],
            "evaluation":{"dataset_ref":"evals/cases.jsonl","assertions_ref":"evals/assertions.json","min_success_rate":0.85}},
        "files":files,"scripts":[{"file_path":"scripts/classify.py","interpreter_ref":"python/3",
            "input_schema_ref":"schemas/input.json","output_schema_ref":"schemas/output.json",
            "required_capabilities":["workspace.read"],"timeout_seconds":30}],
        "templates":[{"file_path":"assets/report.md","input_schema_ref":"schemas/input.json","output_schema_ref":"schemas/output.json"}]})
}

fn context() -> Value {
    let entries = [
        (
            "system",
            "system_contract",
            "system_contract",
            "host_contract",
        ),
        ("task", "task_contract", "task_contract", "user_task"),
        ("budget", "remaining_budget", "budget", "untrusted_data"),
        ("output", "output_schema", "output_schema", "untrusted_data"),
        ("skill", "relevant_skills", "skill", "untrusted_data"),
    ];
    let mut items: Vec<_> = entries.into_iter().map(|(id,section,kind,trust)| json!({"id":id,"section":section,
        "source_kind":kind,"trust":trust,"source_ref":id,"source_version":"1.0.0","content_digest":hash(),
        "namespace":"project-a","token_count":100,"full_content":true})).collect();
    items[4]["source_ref"] = json!("melissa.code.debug");
    items[4]["source_version"] = json!("1.2.0");
    items[1]["source_ref"] = json!("task-1");
    json!({"schema_version":"melissa.context-contract/v1","id":"context-1","task_id":"task-1","namespace":"project-a",
        "task_binding":{"module":"code","goal":"Repair the sample regression","workspace_ref":"workspace-1","input_snapshot_digest":hash(),"acceptance_contract_digest":hash()},
        "max_context_tokens":2000,"reserved_output_tokens":500,"items":items,
        "selected_skills":[{"pin":pin(),"context_item_id":"skill"}],
        "continuation":{"checkpoint_ref":"checkpoint-1","task_contract_digest":hash(),"workspace_snapshot_digest":hash(),
            "authorization_ref":"auth-1","cancellation_ref":"cancel-1","remaining_budget_ref":"budget-1",
            "open_effect_refs":["unknown-invocation-1"],"rejected_hypotheses":["Not an import failure"],"open_issue_refs":["error-1"]}})
}

fn workflow() -> Value {
    json!({"schema_version":"melissa.workflow-definition/v1","id":"repair","semantic_version":"1.0.0",
        "inputs":[{"name":"workspace","schema_ref":"workspace/v1","required":true}],"runtime":limits(),
        "nodes":[
            {"id":"inspect","executor":{"kind":"agent","id":"melissa.code.repository-analyst"},"depends_on":[],
                "inputs":[{"name":"workspace","schema_ref":"workspace/v1","required":true}],
                "outputs":[{"name":"diagnostics","schema_ref":"diagnostics/v1","required":true}],
                "bindings":[{"input":"workspace","source":{"kind":"workflow_input","name":"workspace"}}],
                "required_capabilities":["workspace.read"],"authorization_ref":"auth-1","timeout_seconds":60,"compensation_only":false},
            {"id":"build","executor":{"kind":"tool","id":"code.build"},"depends_on":["inspect"],
                "inputs":[{"name":"diagnostics","schema_ref":"diagnostics/v1","required":true}],
                "outputs":[{"name":"result","schema_ref":"build-result/v1","required":true}],
                "bindings":[{"input":"diagnostics","source":{"kind":"node_output","node_id":"inspect","output":"diagnostics"}}],
                "required_capabilities":["process.execute_scoped"],"authorization_ref":"auth-1","timeout_seconds":120,"compensation_only":false}],
        "outputs":[{"name":"build_result","schema_ref":"build-result/v1","source":{"kind":"node_output","node_id":"build","output":"result"}}],
        "success_all":["Actual build passes","Independent acceptance passes"],
        "failure":{"repair_attempts":3,"no_progress_limit":2,"final_action":"review","checkpoint_required":true},"compensations":[]})
}

fn validate_skill(value: Value) -> bool {
    serde_json::from_value::<SkillDefinition>(value).is_ok_and(|v| v.validate().is_ok())
}
fn validate_context(value: Value) -> bool {
    serde_json::from_value::<ContextContract>(value).is_ok_and(|v| v.validate().is_ok())
}
fn validate_workflow(value: Value) -> bool {
    serde_json::from_value::<WorkflowDefinition>(value).is_ok_and(|v| v.validate().is_ok())
}

#[test]
fn full_skill_manifest_round_trips_without_running_helpers() {
    let original = skill();
    let parsed: SkillDefinition = serde_json::from_value(original.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), original);
}

#[test]
fn package_escape_missing_schema_and_undeclared_script_capability_are_rejected() {
    let mut traversal = skill();
    traversal["files"][6]["path"] = json!("../outside.md");
    assert!(!validate_skill(traversal));
    let mut wrong_role = skill();
    wrong_role["manifest"]["output_schema_ref"] = json!("references/debug.md");
    assert!(!validate_skill(wrong_role));
    let mut escalation = skill();
    escalation["scripts"][0]["required_capabilities"] = json!(["authority.expand"]);
    assert!(!validate_skill(escalation));
    let mut hidden = skill();
    hidden["scripts"] = json!([]);
    assert!(!validate_skill(hidden));
    for invalid in [
        "references/CON.txt",
        "references/report. ",
        "references\\report.md",
        "C:/outside.md",
        "references/a?.md",
        "references/a*.md",
        "references/a<.md",
        "references/a>.md",
        "references/a|.md",
        "references/a\".md",
    ] {
        let mut value = skill();
        value["files"][6]["path"] = json!(invalid);
        assert!(!validate_skill(value), "accepted {invalid}");
    }
    let mut collision = skill();
    collision["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path":"references/DEBUG.md","content_digest":hash(),"role":"reference"}));
    assert!(!validate_skill(collision));
}

#[test]
fn skill_versions_need_real_evidence_references_and_match_definition_capabilities() {
    let definition: SkillDefinition = serde_json::from_value(skill()).unwrap();
    let mut version: SkillVersion = serde_json::from_value(json!({"schema_version":"melissa.skill-version/v1","pin":pin(),
        "definition_digest":hash(),"publisher_id":"melissa","state":"signed_release","required_capabilities":["workspace.read"],
        "evaluation_digest":hash(),"review_artifact_ref":"review-1","signature":{"algorithm":"ed25519","key_id":"key-1","signature_artifact_ref":"sig-1"},
        "revocation_ref":null,"rollback_to":null})).unwrap();
    version.validate_definition(&definition).unwrap();
    version.signature = None;
    assert!(version.validate().is_err());
    version.state = SkillReleaseState::Reviewed;
    version.required_capabilities.push("workspace.write".into());
    assert!(version.validate_definition(&definition).is_err());
}

#[test]
fn unknown_versions_and_unknown_nested_fields_fail_closed() {
    let mut s = skill();
    s["schema_version"] = json!("melissa.skill-definition/v2");
    assert!(!validate_skill(s));
    let mut s = skill();
    s["manifest"]["silently_skip_verification"] = json!(true);
    assert!(!validate_skill(s));
    let mut w = workflow();
    w["nodes"][0]["executor"]["permission"] = json!("all");
    assert!(!validate_workflow(w));
    let mut c = context();
    c["schema_version"] = json!("melissa.context-contract/v2");
    assert!(!validate_context(c));
}

#[test]
fn semantic_versions_are_pinned_and_malformed_versions_are_rejected() {
    let mut binding: SkillPin = serde_json::from_value(pin()).unwrap();
    for valid in ["1.2.3", "1.2.3-rc.1+build.001"] {
        binding.semantic_version = valid.into();
        binding.validate().unwrap();
    }
    for invalid in [
        "latest",
        "01.2.3",
        "1.2",
        "1.2.3-01",
        "1.2.3+",
        "1.2.3-rc..1",
    ] {
        binding.semantic_version = invalid.into();
        assert!(binding.validate().is_err(), "accepted {invalid}");
    }
}

#[test]
fn context_preserves_selected_skill_and_continuation_information() {
    let parsed: ContextContract = serde_json::from_value(context()).unwrap();
    parsed.validate().unwrap();
    let restored: ContextContract =
        serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(
        restored.continuation.unwrap().open_effect_refs,
        vec!["unknown-invocation-1"]
    );
}

#[test]
fn context_rejects_instruction_promotion_namespace_mix_and_truncated_skills() {
    let mut c = context();
    c["items"][4]["trust"] = json!("host_contract");
    assert!(!validate_context(c));
    let mut c = context();
    c["items"][4]["namespace"] = json!("another-engagement");
    assert!(!validate_context(c));
    let mut c = context();
    c["items"][4]["full_content"] = json!(false);
    assert!(!validate_context(c));
    let mut c = context();
    c["selected_skills"][0]["pin"]["semantic_version"] = json!("1.3.0");
    assert!(!validate_context(c));
    let mut c = context();
    c["continuation"]["task_contract_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
    assert!(!validate_context(c));
    let mut c = context();
    c["items"][1]["source_ref"] = json!("different-task");
    assert!(!validate_context(c));
    let mut c = context();
    let mut duplicate = c["items"][1].clone();
    duplicate["id"] = json!("task-duplicate");
    c["items"].as_array_mut().unwrap().push(duplicate);
    assert!(!validate_context(c));
    let mut c = context();
    c["items"][2]["source_kind"] = json!("web");
    assert!(!validate_context(c));
}

#[test]
fn context_budget_and_overflow_fail_before_execution() {
    let mut c = context();
    c["max_context_tokens"] = json!(900);
    c["reserved_output_tokens"] = json!(500);
    assert!(!validate_context(c));
    let mut c = context();
    c["items"][0]["token_count"] = json!(u64::MAX);
    assert!(!validate_context(c));
    let mut c = context();
    c["reserved_output_tokens"] = json!(u64::MAX);
    assert!(!validate_context(c));
}

#[test]
fn unresolved_profile_binding_cannot_silently_become_ready() {
    let mut binding: ProfileRuntimeBindings = serde_json::from_value(json!({"schema_version":"melissa.profile-bindings/v1",
        "profile_id":"melissa.code.debugger","profile_schema_version":"melissa.agent-profile/v1","state":"unresolved",
        "skills":[],"context_contract_ref":null,"runtime_limits":null,"unresolved_reasons":["CODE-07 skill package and context binding pending"]})).unwrap();
    binding.validate().unwrap();
    binding.state = BindingState::Bound;
    assert!(binding.validate().is_err());
    binding.unresolved_reasons.clear();
    binding.context_contract_ref = Some("context-code/v1".into());
    binding.runtime_limits = Some(serde_json::from_value(limits()).unwrap());
    binding.validate().unwrap();
}

#[test]
fn typed_dag_resolves_known_executors() {
    let w: WorkflowDefinition = serde_json::from_value(workflow()).unwrap();
    w.validate_references(
        &BTreeSet::from(["melissa.code.repository-analyst".into()]),
        &BTreeSet::from(["code.build".into()]),
    )
    .unwrap();
    assert!(
        w.validate_references(&BTreeSet::new(), &BTreeSet::from(["code.build".into()]))
            .is_err()
    );
    assert!(
        w.validate_references(
            &BTreeSet::from(["melissa.code.repository-analyst".into()]),
            &BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn dag_rejects_cycles_missing_dependencies_and_self_dependencies() {
    let mut w = workflow();
    w["nodes"][0]["depends_on"] = json!(["build"]);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["depends_on"] = json!(["missing"]);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][0]["depends_on"] = json!(["inspect"]);
    assert!(!validate_workflow(w));
}

#[test]
fn dag_rejects_mismatched_duplicate_and_unordered_bindings() {
    let mut w = workflow();
    w["nodes"][1]["inputs"][0]["schema_ref"] = json!("wrong/v1");
    assert!(!validate_workflow(w));
    let mut w = workflow();
    let repeated = w["nodes"][1]["bindings"][0].clone();
    w["nodes"][1]["bindings"]
        .as_array_mut()
        .unwrap()
        .push(repeated);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["depends_on"] = json!([]);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["bindings"] = json!([]);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["outputs"][0]["source"]["output"] = json!("missing");
    assert!(!validate_workflow(w));
}

#[test]
fn required_bindings_and_workflow_outputs_cannot_be_sourced_from_optional_values() {
    let mut w = workflow();
    w["inputs"][0]["required"] = json!(false);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][0]["outputs"][0]["required"] = json!(false);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["outputs"][0]["required"] = json!(false);
    assert!(!validate_workflow(w));
    // An optional input may still consume an optional source; it cannot be
    // used to satisfy a required output without a guard/default in a future version.
    let mut w = workflow();
    w["inputs"][0]["required"] = json!(false);
    w["nodes"][0]["inputs"][0]["required"] = json!(false);
    assert!(validate_workflow(w));
}

#[test]
fn context_is_bound_to_actual_task_goal_acceptance_workspace_and_token_ceilings() {
    let c: ContextContract = serde_json::from_value(context()).unwrap();
    let task_json = json!({"schema_version":"melissa.task-contract/v1","task_id":"task-1","module":"code",
        "goal":"Repair the sample regression","workspace_ref":"workspace-1","input_snapshot_digest":hash(),"acceptance_contract_digest":hash(),
        "acceptance_criteria":["The regression passes"],"selected_profile_ids":["melissa.code.debugger"],
        "allowed_resource_ids":["workspace-1"],"allowed_effects":["workspace.read"],"authorization_refs":[],
        "limits":{"max_wall_time_ms":600000,"max_cost_micro_usd":0,"max_input_tokens":1000,"max_output_tokens":500,
            "max_parallel_jobs":1,"max_disk_bytes":0,"max_output_bytes":0},"authority_source":"user_task_and_rust_policy"});
    let task = serde_json::from_value(task_json.clone()).unwrap();
    c.validate_against_task(&task).unwrap();
    for (field, value) in [
        ("task_id", json!("another-task")),
        ("module", json!("science")),
        ("goal", json!("Replace all tests")),
        ("workspace_ref", json!("other-workspace")),
        (
            "input_snapshot_digest",
            json!(format!("sha256:{}", "b".repeat(64))),
        ),
        (
            "acceptance_contract_digest",
            json!(format!("sha256:{}", "c".repeat(64))),
        ),
    ] {
        let mut changed = task_json.clone();
        changed[field] = value;
        assert!(
            c.validate_against_task(&serde_json::from_value(changed).unwrap())
                .is_err(),
            "accepted mismatched {field}"
        );
    }
    let mut changed = task_json.clone();
    changed["limits"]["max_input_tokens"] = json!(499);
    assert!(
        c.validate_against_task(&serde_json::from_value(changed).unwrap())
            .is_err()
    );
    let mut changed = task_json;
    changed["limits"]["max_output_tokens"] = json!(499);
    assert!(
        c.validate_against_task(&serde_json::from_value(changed).unwrap())
            .is_err()
    );
}

#[test]
fn repair_loops_and_node_limits_are_bounded() {
    let mut w = workflow();
    w["failure"]["repair_attempts"] = json!(9);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["failure"]["no_progress_limit"] = json!(0);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["timeout_seconds"] = json!(601);
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["nodes"][1]["authorization_ref"] = Value::Null;
    assert!(!validate_workflow(w));
    let mut w = workflow();
    w["failure"]["repair_attempts"] = json!(0);
    w["failure"]["no_progress_limit"] = json!(0);
    assert!(validate_workflow(w));
}

fn compensated_workflow() -> Value {
    let mut w = workflow();
    w["nodes"].as_array_mut().unwrap().push(json!({"id":"undo","executor":{"kind":"tool","id":"fs.patch"},
        "depends_on":["build"],"inputs":[],"outputs":[],"bindings":[],"required_capabilities":["workspace.write"],
        "authorization_ref":"auth-undo","timeout_seconds":60,"compensation_only":true}));
    w["compensations"] = json!([{"node_id":"build","compensation_node_id":"undo","authorization_ref":"auth-undo","reconciliation_policy_ref":"reconcile/v1"}]);
    w
}

#[test]
fn compensation_has_distinct_authorization_and_cannot_produce_normal_success() {
    assert!(validate_workflow(compensated_workflow()));
    let mut w = compensated_workflow();
    w["compensations"][0]["authorization_ref"] = json!("auth-original");
    assert!(!validate_workflow(w));
    let mut w = compensated_workflow();
    w["compensations"][0]["node_id"] = json!("missing");
    assert!(!validate_workflow(w));
    let mut w = compensated_workflow();
    w["compensations"] = json!([]);
    assert!(!validate_workflow(w));
    let mut w = compensated_workflow();
    w["nodes"][1]["depends_on"] = json!(["inspect", "undo"]);
    assert!(!validate_workflow(w));
}

#[test]
fn unknown_compensation_effect_requires_reconciliation_and_distinct_invocation() {
    let mut record: CompensationRecord = serde_json::from_value(json!({"schema_version":"melissa.compensation-record/v1",
        "task_id":"task-1","original_invocation_id":"original-1","compensation_node_id":"undo","authorization_ref":"auth-undo",
        "state":"outcome_unknown","compensation_invocation_id":"undo-1","evidence_refs":[],"reconciliation_ref":"reconciliation-1"})).unwrap();
    record.validate().unwrap();
    record.reconciliation_ref = None;
    assert!(record.validate().is_err());
    record.state = CompensationState::Succeeded;
    assert!(record.validate().is_err());
    record.evidence_refs.push("raw-tool-run".into());
    record.validate().unwrap();
    record.compensation_invocation_id = Some("original-1".into());
    assert!(record.validate().is_err());
}
