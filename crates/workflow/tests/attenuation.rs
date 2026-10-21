#![allow(dead_code)]
include!("common/gateway.rs");
use melissa_workflow::{gate::*, plan::*, scheduler::*};

fn setup(
    tools: &[&str],
    effects: &[&str],
    claims: Vec<Claim>,
) -> (tempfile::TempDir, SharedScheduler, WorkPacket) {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("s"), 1000000);
    let task = store.journal().task(TASK).unwrap().contract;
    let p = Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "attenuation".into(),
        task: TASK.into(),
        revision: 1,
        parent_digest: None,
        workspace_digest: task.input_snapshot_digest.clone(),
        policy_digest: melissa_workflow::digest(b"p"),
        mode: Mode::SingleAgent,
        delegation_reason: None,
        max_parallel: 1,
        max_no_progress: 3,
        nodes: vec![Node {
            id: "worker".into(),
            profile: "melissa.code.implementer".into(),
            goal: "Scoped local fixture".into(),
            after: BTreeSet::new(),
            bindings: vec![],
            literal_input: json!({}),
            tools: tools.iter().map(|s| s.to_string()).collect(),
            effects: effects.iter().map(|s| s.to_string()).collect(),
            resources: BTreeSet::from([task.workspace_ref.clone()]),
            authorizations: task.authorization_refs.iter().cloned().collect(),
            claims,
            output_schema: json!({"type":"object"}),
            skills: vec![],
        }],
        outputs: BTreeSet::from(["worker".into()]),
    };
    let f = Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    };
    let c = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut s = Scheduler::create(
        store,
        p,
        &c,
        Arc::new(move || Ok(f.clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let packet = s.acquire("worker", "host:fixture", 30000).unwrap();
    (dir, Arc::new(Mutex::new(s)), packet)
}
fn claim(p: &str, access: Access) -> Claim {
    Claim {
        resource: "fixture:workspace:owned".into(),
        path: p.into(),
        access,
    }
}
struct Tool {
    canonical: &'static str,
    wire: &'static str,
    executed: Arc<AtomicUsize>,
}
impl ToolDispatcher for Tool {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: self.canonical.into(),
            definition: ToolDefinition {
                name: self.wire.into(),
                description: "Local hostile binding fixture".into(),
                parameters: json!({"type":"object"}),
                strict: false,
            },
        }]
    }
    fn validate_call(&self, _: &ToolCall) -> Result<()> {
        Ok(())
    }
    fn execute<'a>(
        &'a mut self,
        _: ToolCall,
        _: ToolContext,
        _: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            self.executed.fetch_add(1, Ordering::SeqCst);
            Ok(ToolExecution {
                content: "{}".into(),
                success: true,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: vec![],
            })
        })
    }
}
fn tool(canonical: &'static str, wire: &'static str) -> Box<dyn ToolDispatcher> {
    Box::new(Tool {
        canonical,
        wire,
        executed: Arc::new(AtomicUsize::new(0)),
    })
}
fn call(wire: &str, args: Value) -> ToolCall {
    ToolCall {
        id: "call:owned".into(),
        name: wire.into(),
        arguments: args.to_string(),
    }
}
#[test]
fn process_tool_cannot_borrow_parent_effects_from_readonly_node() {
    let (_d, s, p) = setup(
        &["process.exec"],
        &["workspace.read"],
        vec![claim("/", Access::Read)],
    );
    assert!(NodeDispatcher::new(s, p, tool("process.exec", "process_exec")).is_err());
}
#[test]
fn unregistered_effect_binding_is_fail_closed() {
    let (_d, s, p) = setup(&["evidence.attach"], &["evidence.append"], vec![]);
    assert!(NodeDispatcher::new(s, p, tool("unknown.canonical", "unknown_wire")).is_err());
}
#[test]
fn different_canonical_tool_is_not_silently_added() {
    let (_d, s, p) = setup(
        &["fs.read"],
        &["workspace.read"],
        vec![claim("/", Access::Read)],
    );
    assert!(NodeDispatcher::new(s, p, tool("fs.search", "fs_search")).is_err());
}
#[test]
fn read_cannot_escape_declared_ownership() {
    let (_d, s, p) = setup(
        &["fs.read"],
        &["workspace.read"],
        vec![claim("src/a.py", Access::Read)],
    );
    let d = NodeDispatcher::new(s, p, tool("fs.read", "fs_read")).unwrap();
    assert!(
        d.validate_call(&call("fs_read", json!({"path":"src/a.py"})))
            .is_ok()
    );
    assert!(
        d.validate_call(&call("fs_read", json!({"path":"src/b.py"})))
            .is_err()
    );
    assert!(
        d.validate_call(&call("fs_read", json!({"path":"src/../secret"})))
            .is_err()
    );
}
#[test]
fn broad_search_requires_whole_repository_lock() {
    let (_d, s, p) = setup(
        &["fs.search"],
        &["workspace.read"],
        vec![claim("src/a.py", Access::Read)],
    );
    let d = NodeDispatcher::new(s, p, tool("fs.search", "context_search")).unwrap();
    assert!(
        d.validate_call(&call("context_search", json!({"query":"x"})))
            .is_err()
    );
}
#[test]
fn patch_targets_require_write_ownership_for_every_file() {
    let (_d, s, p) = setup(
        &["fs.patch"],
        &["workspace.apply_patch_scoped"],
        vec![claim("src/a.py", Access::Write)],
    );
    let d = NodeDispatcher::new(s, p, tool("fs.patch", "fs_patch")).unwrap();
    let mut args = json!({"files":[{"before":{"path":"src/a.py"}}]});
    assert!(d.validate_call(&call("fs_patch", args.clone())).is_ok());
    args["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"before":{"path":"src/b.py"}}));
    assert!(d.validate_call(&call("fs_patch", args)).is_err());
}
#[test]
fn move_requires_both_source_and_destination() {
    let (_d, s, p) = setup(
        &["fs.patch"],
        &["workspace.apply_patch_scoped"],
        vec![claim("src", Access::Write)],
    );
    let d = NodeDispatcher::new(s, p, tool("fs.patch", "fs_move")).unwrap();
    assert!(
        d.validate_call(&call(
            "fs_move",
            json!({"mutation":{"before":{"path":"src/a"},"destination":{"path":"src/b"}}})
        ))
        .is_ok()
    );
    assert!(
        d.validate_call(&call(
            "fs_move",
            json!({"mutation":{"before":{"path":"src/a"},"destination":{"path":"secret/b"}}})
        ))
        .is_err()
    );
}
#[test]
fn readonly_claim_cannot_be_used_for_mutation() {
    let (_d, s, p) = setup(
        &["fs.patch"],
        &["workspace.apply_patch_scoped"],
        vec![claim("/", Access::Read)],
    );
    let d = NodeDispatcher::new(s, p, tool("fs.patch", "fs_delete")).unwrap();
    assert!(
        d.validate_call(&call(
            "fs_delete",
            json!({"mutation":{"before":{"path":"a.py"}}})
        ))
        .is_err()
    );
}
#[tokio::test]
async fn execution_rechecks_node_context_before_inner_backend() {
    let (_d, s, p) = setup(
        &["fs.read"],
        &["workspace.read"],
        vec![claim("/", Access::Read)],
    );
    let count = Arc::new(AtomicUsize::new(0));
    let mut d = NodeDispatcher::new(
        s,
        p,
        Box::new(Tool {
            canonical: "fs.read",
            wire: "fs_read",
            executed: count.clone(),
        }),
    )
    .unwrap();
    let wrong = ToolContext {
        task_id: TASK.into(),
        profile_id: PROFILE.into(),
        run_id: "wrong".into(),
        request_id: "r".into(),
        invocation_id: "i".into(),
        attempt_id: "a".into(),
        generation: 1,
    };
    assert!(
        d.execute(
            call("fs_read", json!({"path":"a.py"})),
            wrong,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}
