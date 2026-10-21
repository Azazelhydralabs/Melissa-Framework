//! Static examples must pass both the typed Rust reader and JSON Schema checks.
//! These examples do not represent actual tool runs, evidence, or permission.
use melissa_core_contracts::design::{
    ContextContract, ProfileRuntimeBindings, SkillDefinition, SkillVersion, WorkflowDefinition,
};
use melissa_core_contracts::json::parse_contract;
use melissa_core_contracts::validation::Validate;
use melissa_core_contracts::wire::{
    AgentResultV1, EvidenceManifestV1, ExecutionPermitV1, ExecutionPermitV2, TaskContractV1,
    ToolObservationV1, ToolObservationV2, WorkerJobV1,
};
use serde::{Serialize, de::DeserializeOwned};

fn checked<T: DeserializeOwned + Serialize + Validate>(bytes: &[u8]) -> T {
    let parsed: T = parse_contract(bytes, 256 * 1024).unwrap();
    let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), original);
    parsed
}

macro_rules! fixture {
    ($name:ident, $ty:ty, $file:literal) => {
        #[test]
        fn $name() {
            checked::<$ty>(include_bytes!(concat!(
                "../../../tests/fixtures/code01/",
                $file
            )));
        }
    };
}

fixture!(task_v1, TaskContractV1, "wire/task-contract-v1.json");
fixture!(
    permit_v1,
    ExecutionPermitV1,
    "wire/execution-permit-v1.json"
);
fixture!(
    permit_v2,
    ExecutionPermitV2,
    "wire/execution-permit-v2.json"
);
fixture!(
    observation_v1,
    ToolObservationV1,
    "wire/tool-observation-v1.json"
);
fixture!(
    observation_v2,
    ToolObservationV2,
    "wire/tool-observation-v2.json"
);
fixture!(
    evidence_v1,
    EvidenceManifestV1,
    "wire/evidence-manifest-v1.json"
);
fixture!(agent_result_v1, AgentResultV1, "wire/agent-result-v1.json");
fixture!(worker_job_v1, WorkerJobV1, "wire/worker-job-v1.json");
fixture!(
    skill_definition_v1,
    SkillDefinition,
    "design/skill-definition-v1.json"
);
fixture!(
    skill_version_v1,
    SkillVersion,
    "design/skill-version-v1.json"
);
fixture!(
    workflow_v1,
    WorkflowDefinition,
    "design/workflow-definition-v1.json"
);
fixture!(
    context_v1,
    ContextContract,
    "design/context-contract-v1.json"
);
fixture!(
    profile_bindings_v1,
    ProfileRuntimeBindings,
    "design/profile-bindings-v1.json"
);

#[test]
fn static_wire_fixtures_bind_to_one_task_without_granting_authority() {
    let task: TaskContractV1 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ));
    let permit_v1: ExecutionPermitV1 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/execution-permit-v1.json"
    ));
    let permit_v2: ExecutionPermitV2 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/execution-permit-v2.json"
    ));
    let job: WorkerJobV1 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/worker-job-v1.json"
    ));
    let evidence: EvidenceManifestV1 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/evidence-manifest-v1.json"
    ));
    let result: AgentResultV1 = checked(include_bytes!(
        "../../../tests/fixtures/code01/wire/agent-result-v1.json"
    ));
    permit_v1.validate_against_task(&task).unwrap();
    permit_v2.validate_against_task(&task).unwrap();
    job.validate_against_permit(&permit_v2).unwrap();
    job.validate_against_task(&task).unwrap();
    evidence.validate_against_task(&task).unwrap();
    result.validate_against_task(&task).unwrap();
}

#[test]
fn static_skill_version_pins_its_definition() {
    let definition: SkillDefinition = checked(include_bytes!(
        "../../../tests/fixtures/code01/design/skill-definition-v1.json"
    ));
    let version: SkillVersion = checked(include_bytes!(
        "../../../tests/fixtures/code01/design/skill-version-v1.json"
    ));
    version.validate_definition(&definition).unwrap();
}
