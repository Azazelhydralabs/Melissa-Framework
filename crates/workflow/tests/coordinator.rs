#![allow(dead_code)]
include!("common/gateway.rs");
use melissa_workflow::{plan::*, runtime::*, scheduler::*};
struct NoTools;
impl ToolDispatcher for NoTools {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![]
    }
    fn validate_call(&self, _: &ToolCall) -> Result<()> {
        Err(GatewayError::invalid("none"))
    }
    fn execute<'a>(
        &'a mut self,
        _: ToolCall,
        _: ToolContext,
        _: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async { Err(GatewayError::invalid("none")) })
    }
}
fn setup() -> (tempfile::TempDir, Arc<Mutex<Scheduler>>) {
    let d = tempfile::tempdir().unwrap();
    let store = store(&d.path().join("s"), 1000000);
    let task = store.journal().task(TASK).unwrap().contract;
    let mut previous = None;
    let nodes=[("analysis","melissa.code.repository-analyst"),("implementation","melissa.code.implementer"),("tests","melissa.code.test-engineer")].into_iter().map(|(id,profile)|{
        let after=previous.iter().cloned().collect();let bindings=previous.iter().map(|from:&String|Binding{from:from.clone(),pointer:"/value".into(),input:"prior".into(),schema:json!({"type":"integer"})}).collect();previous=Some(id.to_string());
        Node{id:id.into(),profile:profile.into(),goal:format!("Perform bounded stage {id}"),after,bindings,literal_input:json!({}),tools:BTreeSet::new(),effects:BTreeSet::from(["workspace.read".into()]),resources:BTreeSet::from([task.workspace_ref.clone()]),authorizations:BTreeSet::new(),claims:vec![],output_schema:json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}),skills:vec![]}
    }).collect();
    let p = Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "cooperation".into(),
        task: TASK.into(),
        revision: 1,
        parent_digest: None,
        workspace_digest: task.input_snapshot_digest.clone(),
        policy_digest: melissa_workflow::digest(b"policy"),
        mode: Mode::ConditionalDelegation,
        delegation_reason: Some(
            "local integration evaluation of three existing role profiles".into(),
        ),
        max_parallel: 2,
        max_no_progress: 3,
        nodes,
        outputs: BTreeSet::from(["tests".into()]),
    };
    let fresh = Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    };
    let catalog = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let scheduler = Scheduler::create(
        store,
        p,
        &catalog,
        Arc::new(move || Ok(fresh.clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    (d, Arc::new(Mutex::new(scheduler)))
}
async fn driver(
    owner: Arc<Mutex<Scheduler>>,
    responses: Vec<HttpPlan>,
) -> (Runtime, Arc<HttpFixture>) {
    let http = Arc::new(http_fixture(responses).await);
    let s = owner.clone();
    let server = http.clone();
    let runtime = Runtime {
        scheduler: owner,
        lease_ms: 30000,
        factory: Arc::new(move |packet| {
            let store = s.lock().unwrap().store().connect().unwrap();
            let mut sp = spec(&packet.lease.run);
            sp.profile_id = packet.node.profile.clone();
            sp.user_message = serde_json::to_string(packet).unwrap();
            sp.output_schema = Some(packet.node.output_schema.clone());
            Ok(PreparedRun {
                gateway: gateway(store, &server, policy()),
                spec: sp,
                dispatcher: Box::new(NoTools),
            })
        }),
    };
    (runtime, http)
}
#[tokio::test]
async fn coordinator_native_task_spawn_routes_three_real_profile_runs_and_handoffs() {
    let (_d, owner) = setup();
    let (rt, nodes) = driver(
        owner.clone(),
        vec![
            HttpPlan::sse(text_response(r#"{"value":1}"#, false, true)),
            HttpPlan::sse(text_response(r#"{"value":2}"#, false, true)),
            HttpPlan::sse(text_response(r#"{"value":3}"#, false, true)),
        ],
    )
    .await;
    let main = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "a",
            "task_spawn",
            r#"{"node":"analysis"}"#,
        )])),
        HttpPlan::sse(tool_response(&[(
            "b",
            "task_spawn",
            r#"{"node":"implementation"}"#,
        )])),
        HttpPlan::sse(tool_response(&[("c", "task_spawn", r#"{"node":"tests"}"#)])),
        HttpPlan::sse(text_response(
            "Candidate awaiting independent checks",
            false,
            true,
        )),
    ])
    .await;
    let catalog = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut tools =
        CoordinatorDispatcher::new(rt, "melissa.core.coordinator".into(), &catalog).unwrap();
    let store = owner.lock().unwrap().store().connect().unwrap();
    let mut g = gateway(store, &main, policy());
    let mut sp = spec("coordinator_native");
    sp.profile_id = "melissa.core.coordinator".into();
    sp.required_tool_names.insert("task_spawn".into());
    let result = g
        .run(&sp, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert!(!result.task_accepted);
    let s = owner.lock().unwrap();
    assert_eq!(s.outputs().unwrap()["tests"]["value"], 3);
    let requests = s.store().journal().model_requests(TASK).unwrap();
    assert_eq!(requests.len(), 7);
    let profiles = requests
        .iter()
        .map(|r| r.reservation.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(profiles.len(), 4);
    assert_eq!(
        s.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .known_input_tokens,
        84
    );
    assert_eq!(
        s.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    assert_eq!(nodes.requests.load(Ordering::SeqCst), 3);
    let bodies = nodes.bodies.lock().unwrap();
    let handoff: Value = serde_json::from_str(
        bodies[2]["input"][0]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(handoff["bound_inputs"]["prior"], 2);
}
#[tokio::test]
async fn invalid_spawn_cannot_create_an_unapproved_expert() {
    let (_d, owner) = setup();
    let (rt, http) = driver(owner, vec![]).await;
    let c = Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let tools = CoordinatorDispatcher::new(rt, "melissa.core.coordinator".into(), &c).unwrap();
    let call = ToolCall {
        id: "bad".into(),
        name: "task_spawn".into(),
        arguments: r#"{"node":"unapproved","budget":999999999}"#.into(),
    };
    assert!(tools.validate_call(&call).is_err());
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn coordinator_cancel_stops_an_active_native_provider_and_keeps_unknown_hold() {
    let (_d, owner) = setup();
    let (rt, http) = driver(
        owner.clone(),
        vec![HttpPlan {
            status: 200,
            body: text_response(r#"{"value":1}"#, false, true),
            delay: Duration::from_secs(2),
        }],
    )
    .await;
    let worker = rt.clone();
    let running = tokio::spawn(async move { worker.run("analysis").await });
    for _ in 0..200 {
        if http.requests.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    rt.cancel().unwrap();
    let _result = running.await.unwrap();
    let mut s = owner.lock().unwrap();
    assert!(s.state().unwrap().cancel_requested);
    assert!(!s.state().unwrap().cancellation_settled);
    assert_eq!(
        s.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .unknown_requests,
        1
    );
    assert!(s.settle_cancellation().is_err());
    assert!(s.acquire("implementation", "another", 10000).is_err());
    assert_eq!(
        s.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}
