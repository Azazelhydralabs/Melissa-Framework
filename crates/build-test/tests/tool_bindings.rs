#![cfg(windows)]
mod support;
use melissa_build_test::{
    RustOperation,
    full::{Language, Operation},
    semantic::{SemanticMethod, SemanticQuery},
    tools::{CodeDispatcher, CodeOperation, CodeToolPolicy},
};
use melissa_core_contracts::{TaskState, catalog::Catalog};
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
fn setup(
    profile: &str,
    op: CodeOperation,
    process: bool,
) -> (
    tempfile::TempDir,
    CodeDispatcher,
    melissa_local_store::LocalStore,
) {
    try_setup(profile, op, process).unwrap()
}
fn try_setup(
    profile: &str,
    op: CodeOperation,
    process: bool,
) -> melissa_build_test::Result<(
    tempfile::TempDir,
    CodeDispatcher,
    melissa_local_store::LocalStore,
)> {
    let f = support::Fixture::new(
        "pub fn answer()->u32{42}\n",
        RustOperation::Build,
        &[
            ("src/calc.py", "def same() -> int:\n    return 42\n"),
            ("src/main.py", "from calc import same\nvalue=same()\n"),
        ],
        support::limits(),
    );
    let mut t = f.task.clone();
    t.task_id = "task:code06-bound".into();
    t.selected_profile_ids = vec![profile.into()];
    t.allowed_effects = vec!["workspace.read".into()];
    if process {
        t.allowed_effects.extend([
            "process.execute_scoped".into(),
            "workspace.apply_patch_scoped".into(),
        ]);
    }
    let mut store = f.broker.store().connect().unwrap();
    store.journal_mut().create_task(&t).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = store.journal().task(&t.task_id).unwrap().record.version;
        store.transition_task(&t.task_id, v, state, None).unwrap();
    }
    let monitor = store.connect().unwrap();
    let policy = CodeToolPolicy {
        task_id: t.task_id,
        profile_id: profile.into(),
        principal_id: "principal:code06-rust".into(),
        resource_id: t.workspace_ref,
        authorization_ref: "auth:code06-rust".into(),
        expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
        limits: support::limits(),
        operations: BTreeMap::from([("code_fixture".into(), op)]),
        process_policy: process.then(|| f.broker.policy_control().snapshot().unwrap()),
    };
    let d = CodeDispatcher::new(
        f.repo,
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        policy,
    )?;
    Ok((f._dir, d, monitor))
}
fn context(profile: &str, n: u32) -> ToolContext {
    ToolContext {
        task_id: "task:code06-bound".into(),
        profile_id: profile.into(),
        run_id: "run:code06".into(),
        request_id: format!("request:code06:{n}"),
        invocation_id: format!("inv:code06:{n}"),
        attempt_id: format!("attempt:code06:{n}"),
        generation: 1,
    }
}
fn call(d: &CodeDispatcher, n: u32) -> ToolCall {
    let definition = d.definitions().remove(0);
    let value = literal(&definition.definition.parameters);
    ToolCall {
        id: format!("call:{n}"),
        name: definition.definition.name,
        arguments: value.to_string(),
    }
}
fn literal(schema: &serde_json::Value) -> serde_json::Value {
    if let Some(v) = schema.get("const") {
        return v.clone();
    }
    serde_json::Value::Object(
        schema["properties"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), literal(v)))
            .collect(),
    )
}
#[tokio::test]
async fn real_bound_build_uses_atomic_broker_and_refuses_model_command_injection_and_replay() {
    let (_temp, mut d, s) = setup(
        "melissa.code.dependency-build",
        CodeOperation::Procedure {
            language: Language::Rust,
            operation: Operation::Build {},
            harness: None,
        },
        true,
    );
    let c = call(&d, 1);
    let mut injected = c.clone();
    injected.arguments = injected.arguments.replace(
        "\"harness\":null",
        "\"harness\":null,\"executable\":\"/bin/sh\"",
    );
    assert!(d.validate_call(&injected).is_err());
    let r = d
        .execute(
            c.clone(),
            context("melissa.code.dependency-build", 1),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(r.success && !r.requires_reconciliation, "{}", r.content);
    assert_eq!(
        s.journal().attempt("attempt:code06:1").unwrap().state,
        melissa_local_store::journal::AttemptState::Succeeded
    );
    assert!(
        d.execute(
            c,
            context("melissa.code.dependency-build", 1),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn real_readonly_analyst_semantic_service_never_acquires_process_authority() {
    let (_temp, mut d, s) = setup(
        "melissa.code.repository-analyst",
        CodeOperation::Semantic {
            language: Language::Python,
            query: SemanticQuery {
                method: SemanticMethod::Definition,
                path: "src/main.py".into(),
                line: 1,
                character: 8,
            },
            build_scripts: false,
        },
        false,
    );
    assert_eq!(d.definitions()[0].canonical_id, "code.references");
    let c = call(&d, 1);
    let mut wrong = context("melissa.code.implementer", 1);
    assert!(
        d.execute(c.clone(), wrong.clone(), Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    wrong = context("melissa.code.repository-analyst", 1);
    wrong.task_id = "task:other".into();
    assert!(
        d.execute(c.clone(), wrong, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    let r = d
        .execute(
            c,
            context("melissa.code.repository-analyst", 1),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(r.success && !r.requires_reconciliation, "{}", r.content);
    assert!(r.content.contains("calc.py"));
    let inv = s.journal().invocation("inv:code06:1").unwrap();
    assert_eq!(inv.tool_id, "code.references");
    assert!(
        !s.journal()
            .task("task:code06-bound")
            .unwrap()
            .contract
            .allowed_effects
            .iter()
            .any(|x| x == "process.execute_scoped")
    );
}
#[test]
fn role_and_task_intersections_deny_build_lint_scripts_and_revoked_scope() {
    assert!(
        try_setup(
            "melissa.code.repository-analyst",
            CodeOperation::Procedure {
                language: Language::Rust,
                operation: Operation::Build {},
                harness: None
            },
            false
        )
        .is_err()
    );
    assert!(
        try_setup(
            "melissa.code.dependency-build",
            CodeOperation::Procedure {
                language: Language::Rust,
                operation: Operation::Lint {},
                harness: None
            },
            true
        )
        .is_err()
    );
    assert!(
        try_setup(
            "melissa.code.repository-analyst",
            CodeOperation::Semantic {
                language: Language::Rust,
                query: SemanticQuery {
                    method: SemanticMethod::Definition,
                    path: "src/lib.rs".into(),
                    line: 0,
                    character: 8
                },
                build_scripts: true
            },
            false
        )
        .is_err()
    );
    let (_temp, d, _s) = setup(
        "melissa.code.frontend",
        CodeOperation::Procedure {
            language: Language::JavaScript,
            operation: Operation::Lint {},
            harness: None,
        },
        true,
    );
    assert_eq!(d.definitions()[0].canonical_id, "code.lint");
    d.revoke();
    assert!(d.definitions().is_empty());
}
#[tokio::test]
async fn real_debug_model_binding_keeps_one_admitted_session_and_closes_with_binary_evidence() {
    let (_temp, mut d, s) = setup(
        "melissa.code.debugger",
        CodeOperation::Debug {
            language: Language::Python,
            entry: "src/main.py".into(),
            breakpoints: vec![melissa_build_test::debug::Breakpoint {
                path: "src/main.py".into(),
                line: 2,
            }],
            expected_binary_sha256: None,
        },
        true,
    );
    let definitions = d.definitions();
    assert!(
        definitions
            .iter()
            .any(|t| t.definition.name == "code_debug_command")
    );
    for t in &definitions {
        melissa_model_gateway::schema::validate_schema(&t.definition.parameters).unwrap();
    }
    let result = d
        .execute(
            call(&d, 1),
            context("melissa.code.debugger", 1),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(result.success, "{}", result.content);
    let v: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    let id = v["session_id"].as_str().unwrap();
    assert!(matches!(
        s.journal().attempt("attempt:code06:1").unwrap().state,
        melissa_local_store::journal::AttemptState::Dispatched
            | melissa_local_store::journal::AttemptState::Running
    ));
    for (n, command) in [(2, "inspect"), (3, "close")] {
        let op = if command == "inspect" {
            serde_json::json!({"command":command,"count":20})
        } else {
            serde_json::json!({"command":command})
        };
        let call = ToolCall {
            id: format!("call:{n}"),
            name: "code_debug_command".into(),
            arguments: serde_json::json!({"session_id":id,"operation":op}).to_string(),
        };
        let r = d
            .execute(
                call,
                context("melissa.code.debugger", n),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert!(r.success && !r.requires_reconciliation, "{}", r.content);
        if command == "close" {
            assert!(r.content.contains("\"binary_bytes_authenticated\":true"));
        }
    }
    assert_eq!(
        s.journal().attempt("attempt:code06:1").unwrap().state,
        melissa_local_store::journal::AttemptState::Succeeded
    );
}
#[tokio::test]
async fn real_result_pages_are_lossless_and_cannot_read_foreign_artifacts() {
    let (_temp, mut d, s) = setup(
        "melissa.code.dependency-build",
        CodeOperation::Procedure {
            language: Language::Rust,
            operation: Operation::Build {},
            harness: None,
        },
        true,
    );
    let r = d
        .execute(
            call(&d, 1),
            context("melissa.code.dependency-build", 1),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(r.success);
    let id = "inv:code06:1:semantic-service-result";
    let original = s.get_artifact("task:code06-bound", id).unwrap();
    let mut joined = Vec::new();
    let mut offset = 0;
    for n in 2..200 {
        let c = ToolCall {
            id: format!("call:{n}"),
            name: "code_result_page".into(),
            arguments: serde_json::json!({"artifact_id":id,"offset":offset,"max_bytes":5120})
                .to_string(),
        };
        let r = d
            .execute(
                c,
                context("melissa.code.dependency-build", n),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert!(r.success && !r.requires_reconciliation);
        let v: serde_json::Value = serde_json::from_str(&r.content).unwrap();
        let raw = v["data_hex"].as_str().unwrap();
        let (pairs, remainder) = raw.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        joined.extend(
            pairs
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()),
        );
        offset = v["next_offset"].as_u64().unwrap();
        if v["complete"] == true {
            break;
        }
    }
    assert_eq!(joined, original);
    for (artifact, offset) in [("other-task:secret", 0), (id, u64::MAX)] {
        let c = ToolCall {
            id: "call:denied".into(),
            name: "code_result_page".into(),
            arguments: serde_json::json!({"artifact_id":artifact,"offset":offset,"max_bytes":1024})
                .to_string(),
        };
        assert!(
            d.execute(
                c,
                context("melissa.code.dependency-build", 201),
                Arc::new(AtomicBool::new(false))
            )
            .await
            .is_err()
        );
    }
}
#[tokio::test]
async fn evidence_fault_before_dispatch_is_known_and_after_real_worker_requires_reconciliation() {
    for after in [false, true] {
        let (_temp, mut d, mut s) = setup(
            "melissa.code.dependency-build",
            CodeOperation::Procedure {
                language: Language::Rust,
                operation: Operation::Build {},
                harness: None,
            },
            true,
        );
        let id = if after {
            "attempt:code06:1:semantic-worker-report"
        } else {
            "inv:code06:1:semantic-input"
        };
        s.put_artifact(
            &melissa_local_store::ArtifactRequest {
                artifact_id: id.into(),
                task_id: "task:code06-bound".into(),
                content_type: "application/json".into(),
                logical_type: "protected.fault-fixture".into(),
                schema_version: "fixture/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            b"{}",
        )
        .unwrap();
        let r = d
            .execute(
                call(&d, 1),
                context("melissa.code.dependency-build", 1),
                Arc::new(AtomicBool::new(false)),
            )
            .await;
        if after {
            let r = r.unwrap();
            assert!(!r.success && r.requires_reconciliation);
            assert_eq!(
                s.journal().attempt("attempt:code06:1").unwrap().state,
                melissa_local_store::journal::AttemptState::OutcomeUnknown
            );
            assert!(
                s.journal()
                    .task("task:code06-bound")
                    .unwrap()
                    .record
                    .unknown_invocation_id
                    .is_some()
            );
            assert!(
                d.definitions()
                    .iter()
                    .all(|t| t.definition.name == "code_result_page")
            );
        } else {
            assert!(r.is_err());
            assert!(s.journal().attempt("attempt:code06:1").is_err());
            assert!(
                s.journal()
                    .task("task:code06-bound")
                    .unwrap()
                    .record
                    .unknown_invocation_id
                    .is_none()
            );
        }
    }
}
#[tokio::test]
async fn host_revocation_cancels_owned_debug_worker_and_settles_its_only_parent_attempt() {
    let (_temp, mut d, s) = setup(
        "melissa.code.debugger",
        CodeOperation::Debug {
            language: Language::Python,
            entry: "src/main.py".into(),
            breakpoints: vec![melissa_build_test::debug::Breakpoint {
                path: "src/main.py".into(),
                line: 2,
            }],
            expected_binary_sha256: None,
        },
        true,
    );
    let handle = d.revocation_handle();
    let r = d
        .execute(
            call(&d, 1),
            context("melissa.code.debugger", 1),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(r.success, "{}", r.content);
    handle.revoke();
    drop(d);
    assert_eq!(
        s.journal().attempt("attempt:code06:1").unwrap().state,
        melissa_local_store::journal::AttemptState::Cancelled
    );
    assert!(
        s.journal()
            .task("task:code06-bound")
            .unwrap()
            .record
            .unknown_invocation_id
            .is_none()
    );
}
