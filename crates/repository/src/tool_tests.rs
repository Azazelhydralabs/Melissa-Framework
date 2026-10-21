use super::*;
use crate::{ByteEdit, FileMutation, FilePatch, Limits};
use melissa_core_contracts::wire::TaskContractV1;
use melissa_local_store::{StoreConfig, StoreKey};
use std::fs;

fn fixture() -> (tempfile::TempDir, RepositoryDispatcher, LocalStore) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("lib.rs"), b"pub fn original() {}\r\n").unwrap();
    fs::write(root.join("dirty.txt"), b"preserve dirty\0\xff").unwrap();
    let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
    let mut store = LocalStore::open(
        &temp.path().join("store"),
        StoreKey::from_bytes([89; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut t: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    t.task_id = "task:repository-tools".into();
    t.selected_profile_ids = vec!["melissa.code.implementer".into()];
    t.allowed_effects = vec![
        "workspace.read".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    t.limits.max_disk_bytes = 16 * 1024 * 1024;
    t.limits.max_output_bytes = 16 * 1024 * 1024;
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
    let files = PatchPolicy {
        task_id: t.task_id,
        profile_id: t.selected_profile_ids[0].clone(),
        resource_id: t.workspace_ref,
        authorization_ref: t.authorization_refs[0].clone(),
        principal_id: "principal:repository-tools".into(),
        expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 60_000,
        epoch: 0,
        writable_paths: ["lib.rs", "new.bin", "moved.bin"].map(String::from).into(),
        protected_paths: ["dirty.txt".into()].into(),
    };
    let peer = store.connect().unwrap();
    let dispatcher = RepositoryDispatcher::new(
        repo,
        store,
        RepositoryToolPolicy {
            files,
            read_repository: true,
            enabled_tools: ROUTES.iter().map(|r| r.0.to_string()).collect(),
        },
    )
    .unwrap();
    (temp, dispatcher, peer)
}
fn context(tag: &str) -> ToolContext {
    ToolContext {
        task_id: "task:repository-tools".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "run:tools".into(),
        request_id: format!("request:{tag}"),
        invocation_id: format!("inv:{tag}"),
        attempt_id: format!("attempt:{tag}"),
        generation: 1,
    }
}
fn call(name: &str, args: Value) -> ToolCall {
    ToolCall {
        id: format!("call:{name}"),
        name: name.into(),
        arguments: args.to_string(),
    }
}
fn mutation(d: &RepositoryDispatcher, m: FileMutation) -> Value {
    let h = d.host.lock().unwrap();
    json!(MutationProposal {
        schema_version: "melissa.repository-mutation/v1".into(),
        root_identity: h.repo.root_identity().into(),
        mutation: m
    })
}
async fn invoke(d: &mut dyn ToolDispatcher, name: &str, args: Value, tag: &str) -> ToolExecution {
    let c = call(name, args);
    d.validate_call(&c).unwrap();
    d.execute(c, context(tag), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap()
}

#[tokio::test]
async fn real_agent_tool_chain_reads_creates_patches_moves_and_deletes() {
    let (temp, mut d, peer) = fixture();
    let read = invoke(&mut d, "fs_read", json!({"path":"dirty.txt"}), "read").await;
    let v: Value = serde_json::from_str(&read.content).unwrap();
    assert_eq!(
        v["result"]["bytes"],
        json!(b"preserve dirty\0\xff".to_vec())
    );
    let a = invoke(&mut d, "fs_absent", json!({"path":"new.bin"}), "absent").await;
    let absent = serde_json::from_value(
        serde_json::from_str::<Value>(&a.content).unwrap()["result"].clone(),
    )
    .unwrap();
    let args = mutation(
        &d,
        FileMutation::Create {
            destination: absent,
            bytes: b"old\r\n\0\xff".to_vec(),
        },
    );
    assert!(invoke(&mut d, "fs_create", args, "create").await.success);
    let version = d.host.lock().unwrap().repo.read("new.bin").unwrap().0;
    let patch = {
        let h = d.host.lock().unwrap();
        json!(PatchProposal {
            schema_version: "melissa.repository-patch/v1".into(),
            root_identity: h.repo.root_identity().into(),
            files: vec![FilePatch {
                before: version,
                edits: vec![ByteEdit {
                    start: 0,
                    end: 3,
                    expected: b"old".to_vec(),
                    replacement: b"new".to_vec()
                }]
            }]
        })
    };
    assert!(invoke(&mut d, "fs_patch", patch, "patch").await.success);
    let (before, dest) = {
        let h = d.host.lock().unwrap();
        (
            h.repo.read("new.bin").unwrap().0,
            h.repo.absent_path("moved.bin").unwrap(),
        )
    };
    let args = mutation(
        &d,
        FileMutation::Move {
            before,
            destination: dest,
        },
    );
    assert!(invoke(&mut d, "fs_move", args, "move").await.success);
    assert_eq!(
        fs::read(temp.path().join("repo/moved.bin")).unwrap(),
        b"new\r\n\0\xff"
    );
    let before = d.host.lock().unwrap().repo.read("moved.bin").unwrap().0;
    let args = mutation(&d, FileMutation::Delete { before });
    assert!(invoke(&mut d, "fs_delete", args, "delete").await.success);
    assert!(!temp.path().join("repo/new.bin").exists());
    assert!(!temp.path().join("repo/moved.bin").exists());
    assert_eq!(
        fs::read(temp.path().join("repo/dirty.txt")).unwrap(),
        b"preserve dirty\0\xff"
    );
    let binding: Value = serde_json::from_slice(
        &peer
            .get_artifact("task:repository-tools", "inv:create:tool-binding")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(binding["wire_name"], "fs_create");
    assert_eq!(binding["canonical_tool"], "fs.patch");
    assert_eq!(binding["profile"], "melissa.code.implementer");
    for tag in ["create", "patch", "move", "delete"] {
        assert_eq!(
            peer.journal()
                .invocation(&format!("inv:{tag}"))
                .unwrap()
                .state,
            melissa_core_contracts::InvocationState::Succeeded
        );
    }
    assert_eq!(
        peer.journal()
            .task("task:repository-tools")
            .unwrap()
            .record
            .state,
        TaskState::Running
    );
    peer.integrity_check().unwrap();
}
#[tokio::test]
async fn repository_read_search_and_rust_ast_bindings_return_source_evidence() {
    let (_temp, mut d, _peer) = fixture();
    for (name, args) in [
        ("fs_list", json!({})),
        ("fs_hash", json!({"path":"lib.rs"})),
        ("fs_search", json!({"bytes":b"original".to_vec()})),
        ("code_symbols", json!({})),
        ("code_references", json!({"name":"original"})),
    ] {
        let r = invoke(&mut d, name, args, name).await;
        assert!(r.success);
        assert!(r.artifact_refs.iter().any(|s| s.ends_with(":tool-result")));
        let v: Value = serde_json::from_str(&r.content).unwrap();
        assert_eq!(v["task_accepted"], false);
        if name == "code_references" {
            assert_eq!(v["result"]["resolution"], "syntax_only_not_semantic_lsp");
        }
    }
}
#[test]
fn every_repository_function_schema_is_valid_and_maps_to_existing_catalog_capability() {
    let (_t, d, _p) = fixture();
    let catalog = melissa_core_contracts::catalog::Catalog::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
    )
    .unwrap();
    for t in d.definitions() {
        melissa_model_gateway::schema::validate_schema(&t.definition.parameters).unwrap();
        assert!(catalog.tools.tools.iter().any(|x| x.id == t.canonical_id));
    }
}
#[tokio::test]
async fn injected_principal_grants_paths_or_wrong_tool_variant_are_rejected() {
    let (_t, mut d, peer) = fixture();
    for args in [
        json!({"path":"lib.rs","principal_id":"forged"}),
        json!({"path":"../outside"}),
        json!({"path":"lib.rs","authorization_ref":"forged"}),
    ] {
        assert!(d.validate_call(&call("fs_read", args)).is_err());
    }
    let dest = d.host.lock().unwrap().repo.absent_path("new.bin").unwrap();
    let args = mutation(
        &d,
        FileMutation::Create {
            destination: dest,
            bytes: vec![1],
        },
    );
    assert!(d.validate_call(&call("fs_delete", args)).is_err());
    let c = ToolCall {
        id: "call:dup".into(),
        name: "fs_read".into(),
        arguments: r#"{"path":"lib.rs","path":"dirty.txt"}"#.into(),
    };
    assert!(d.validate_call(&c).is_err());
    let mut c = context("wrong-task");
    c.task_id = "task:other".into();
    assert!(
        d.execute(
            call("fs_read", json!({"path":"lib.rs"})),
            c,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert!(
        peer.get_artifact("task:repository-tools", "inv:wrong-task:tool-binding")
            .is_err()
    );
}
#[test]
fn host_route_and_read_scopes_filter_exposure_and_cannot_be_overridden_by_json() {
    let (_t, d, _p) = fixture();
    {
        let mut h = d.host.lock().unwrap();
        h.policy.enabled_tools = ["fs_read".into()].into();
    }
    assert_eq!(d.definitions().len(), 1);
    assert!(d.validate_call(&call("fs_create", json!({}))).is_err());
    d.host.lock().unwrap().policy.read_repository = false;
    assert!(d.definitions().is_empty());
    assert!(
        d.validate_call(&call("fs_read", json!({"path":"lib.rs"})))
            .is_err()
    );
}
#[tokio::test]
async fn typed_diff_and_patch_proposal_are_read_only_and_snapshot_is_callable() {
    let (t, mut d, peer) = fixture();
    let original = d.host.lock().unwrap().repo.read("lib.rs").unwrap();
    let p = {
        let h = d.host.lock().unwrap();
        json!(PatchProposal {
            schema_version: "melissa.repository-patch/v1".into(),
            root_identity: h.repo.root_identity().into(),
            files: vec![FilePatch {
                before: original.0.clone(),
                edits: vec![ByteEdit {
                    start: 0,
                    end: 3,
                    expected: b"pub".to_vec(),
                    replacement: b"pub(crate)".to_vec()
                }]
            }]
        })
    };
    for name in ["fs_diff", "code_patch_propose"] {
        let r = invoke(&mut d, name, p.clone(), name).await;
        let v: Value = serde_json::from_str(&r.content).unwrap();
        assert_eq!(v["result"]["applied"], false);
        assert_eq!(v["result"]["authorizes_write"], false);
        assert!(peer.journal().invocation(&format!("inv:{name}")).is_err());
    }
    assert!(
        invoke(&mut d, "fs_snapshot", json!({}), "snapshot")
            .await
            .success
    );
    assert_eq!(fs::read(t.path().join("repo/lib.rs")).unwrap(), original.1);
}
#[test]
fn host_can_revoke_all_repository_agent_functions() {
    let (_t, d, _p) = fixture();
    assert!(!d.definitions().is_empty());
    d.revoke().unwrap();
    assert!(d.definitions().is_empty());
    assert!(
        d.validate_call(&call("fs_read", json!({"path":"lib.rs"})))
            .is_err()
    );
}
#[tokio::test]
async fn task_profile_context_and_one_use_invocation_survive_agent_binding() {
    let (_t, mut d, _p) = fixture();
    let dest = d.host.lock().unwrap().repo.absent_path("new.bin").unwrap();
    let args = mutation(
        &d,
        FileMutation::Create {
            destination: dest,
            bytes: vec![7],
        },
    );
    let mut ctx = context("create");
    ctx.profile_id = "melissa.code.reviewer".into();
    assert!(
        d.execute(
            call("fs_create", args.clone()),
            ctx,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert!(
        invoke(&mut d, "fs_create", args.clone(), "create")
            .await
            .success
    );
    assert!(
        d.execute(
            call("fs_create", args),
            context("create"),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert_eq!(d.host.lock().unwrap().repo.read("new.bin").unwrap().1, [7]);
}
#[tokio::test]
async fn receipt_evidence_failure_after_real_create_returns_unknown_and_blocks_retry() {
    let (t, mut d, peer) = fixture();
    {
        d.host
            .lock()
            .unwrap()
            .put("inv:create:receipt", "collision-fixture", b"occupied")
            .unwrap();
    }
    let dest = d.host.lock().unwrap().repo.absent_path("new.bin").unwrap();
    let args = mutation(
        &d,
        FileMutation::Create {
            destination: dest,
            bytes: b"created".to_vec(),
        },
    );
    let r = invoke(&mut d, "fs_create", args, "create").await;
    assert!(!r.success);
    assert!(r.requires_reconciliation);
    assert_eq!(fs::read(t.path().join("repo/new.bin")).unwrap(), b"created");
    assert_eq!(
        peer.journal().invocation("inv:create").unwrap().state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
    );
    assert!(d.definitions().is_empty());
}
#[tokio::test]
async fn cancelled_agent_call_never_creates_a_file() {
    let (t, mut d, _p) = fixture();
    let dest = d.host.lock().unwrap().repo.absent_path("new.bin").unwrap();
    let args = mutation(
        &d,
        FileMutation::Create {
            destination: dest,
            bytes: vec![7],
        },
    );
    let r = d
        .execute(
            call("fs_create", args),
            context("cancel"),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
    assert!(r.cancelled);
    assert!(!r.requires_reconciliation);
    assert!(!t.path().join("repo/new.bin").exists());
}
#[tokio::test]
async fn router_keeps_exact_bindings_and_rejects_duplicate_function_names() {
    let (_t, d, _p) = fixture();
    assert!(ToolRouter::new(vec![Box::new(d.clone()), Box::new(d.clone())]).is_err());
    let mut router = ToolRouter::new(vec![Box::new(d)]).unwrap();
    assert!(
        invoke(&mut router, "fs_hash", json!({"path":"lib.rs"}), "router")
            .await
            .success
    );
    assert!(
        router
            .validate_call(&call("process_exec", json!({})))
            .is_err()
    );
}
