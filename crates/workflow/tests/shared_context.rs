#![allow(dead_code, unused_imports)]
//! Two native C04 role runs share the REAL C07 state/ledger; loopback only.
include!("common/gateway.rs");
use melissa_repository::{Limits, Repository};
use melissa_skill_context::{
    Namespace,
    package::{Registry, SkillPolicy},
    runtime::{ContextDispatcher, ContextRuntime, RuntimeGrant},
};

fn context(store: LocalStore, repo: Arc<Repository>, profile: &str) -> ContextDispatcher {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = Catalog::load(&root).unwrap();
    let p = &catalog.profiles[profile];
    let workspace = store.journal().task(TASK).unwrap().contract.workspace_ref;
    let policy = SkillPolicy {
        epoch: "code08-shared-context".into(),
        reviewed: BTreeSet::new(),
        publishers: BTreeSet::new(),
        revoked: BTreeSet::new(),
        tools: p.tool_ids.iter().cloned().collect(),
        capabilities: p.authority.capability_ceiling.iter().cloned().collect(),
        allow_helpers: false,
    };
    ContextDispatcher::new(
        ContextRuntime::open(
            repo,
            store,
            catalog,
            RuntimeGrant {
                task_id: TASK.into(),
                profile_id: profile.into(),
                principal_id: "principal:shared-context".into(),
                resource_id: workspace,
                authorization_ref: AUTH.into(),
                namespace: Namespace {
                    user: "user:owned-context".into(),
                    project: TASK.into(),
                    engagement: None,
                },
                expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
                policy_epoch: policy.epoch.clone(),
                enabled: BTreeSet::from(["context_search".into()]),
                skill_policy: policy,
                pins: vec![],
            },
            Registry::default(),
            &[],
        )
        .unwrap(),
    )
}
#[tokio::test]
async fn parallel_native_roles_reload_one_shared_c07_context_without_lost_checkpoint_or_error() {
    let dir = tempfile::tempdir().unwrap();
    let repo_dir = dir.path().join("repo");
    std::fs::create_dir(&repo_dir).unwrap();
    std::fs::write(
        repo_dir.join("source.py"),
        b"def observed_source_marker():\n    return 819\n",
    )
    .unwrap();
    let repo = Arc::new(Repository::open(&repo_dir, Limits::default(), vec![]).unwrap());
    let store = store(&dir.path().join("store"), 1000000);
    let args =
        json!({"operation":"search","query":"observed_source_marker","limit":8,"symbols":[]})
            .to_string();
    let a = http_fixture(vec![
        HttpPlan::sse(tool_response(&[("search_a", "context_search", &args)])),
        HttpPlan::sse(text_response("candidate A", false, true)),
    ])
    .await;
    let b = http_fixture(vec![
        HttpPlan {
            status: 200,
            body: tool_response(&[("search_b", "context_search", &args)]),
            delay: Duration::from_millis(250),
        },
        HttpPlan::sse(text_response("candidate B", false, true)),
    ])
    .await;
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let make = |profile: &'static str| {
        let store = Arc::new(Mutex::new(store.connect().unwrap()));
        let repo = repo.clone();
        melissa_workflow::serial_tools::ReloadingDispatcher::new(
            TASK.into(),
            profile.into(),
            gate.clone(),
            Arc::new(move || {
                Ok(Box::new(context(
                    store.lock().unwrap().connect().unwrap(),
                    repo.clone(),
                    profile,
                )))
            }),
        )
        .unwrap()
    };
    let mut da = make("melissa.code.repository-analyst");
    let mut db = make("melissa.code.implementer");
    let mut ga = gateway(store.connect().unwrap(), &a, policy());
    let mut gb = gateway(store.connect().unwrap(), &b, policy());
    let mut sa = spec("shared_context_a");
    sa.profile_id = "melissa.code.repository-analyst".into();
    sa.route.tools = true;
    sa.required_tool_names = BTreeSet::from(["context_search".into()]);
    let mut sb = spec("shared_context_b");
    sb.profile_id = "melissa.code.implementer".into();
    sb.route.tools = true;
    sb.required_tool_names = BTreeSet::from(["context_search".into()]);
    let (ra, rb) = tokio::join!(
        ga.run(&sa, &mut da, Arc::new(AtomicBool::new(false))),
        gb.run(&sb, &mut db, Arc::new(AtomicBool::new(false)))
    );
    for r in [ra.unwrap(), rb.unwrap()] {
        assert_eq!(r.status, RunStatus::FinalCandidate);
        assert_eq!(r.request_ids.len(), 2);
        assert_eq!(r.tool_calls, 1);
        assert!(!r.requires_reconciliation && !r.task_accepted);
    }
    for http in [&a, &b] {
        let bodies = http.bodies.lock().unwrap();
        let outputs = bodies[1]["input"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["type"] == "function_call_output")
            .collect::<Vec<_>>();
        assert_eq!(outputs.len(), 1);
        let raw = outputs[0]["output"].as_str().unwrap();
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_ne!(v["is_error"], true, "{raw}");
        assert!(raw.contains("observed_source_marker"), "{raw}");
    }
    for n in 0..2 {
        store
            .journal()
            .checkpoint(&format!("context-state:{TASK}:{n}"), TASK)
            .unwrap();
    }
    assert_eq!(store.journal().model_requests(TASK).unwrap().len(), 4);
    assert_eq!(
        store.journal().model_budget(TASK).unwrap().unknown_requests,
        0
    );
    store.integrity_check().unwrap();
}
