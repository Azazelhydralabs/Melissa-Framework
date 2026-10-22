#![allow(dead_code, unused_imports)]
//! A concurrent NeedsReconciliation must not be overwritten by complete_native.
include!("common/gateway.rs");
use melissa_workflow::{plan::*, scheduler::*};
struct NoTools;
impl ToolDispatcher for NoTools {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![]
    }
    fn validate_call(&self, _: &ToolCall) -> Result<()> {
        Err(GatewayError::invalid("no"))
    }
    fn execute<'a>(
        &'a mut self,
        _: ToolCall,
        _: ToolContext,
        _: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async { Err(GatewayError::invalid("no")) })
    }
}
fn catalog() -> Catalog {
    Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
}
#[tokio::test]
async fn complete_native_does_not_overwrite_concurrent_needs_reconciliation() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 1_000_000);
    let p = Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "flow".into(),
        task: TASK.into(),
        revision: 1,
        parent_digest: None,
        workspace_digest: st
            .journal()
            .task(TASK)
            .unwrap()
            .contract
            .input_snapshot_digest,
        policy_digest: melissa_workflow::digest(b"current-policy"),
        mode: Mode::SingleAgent,
        delegation_reason: None,
        max_parallel: 1,
        max_no_progress: 2,
        nodes: vec![Node {
            id: "a".into(),
            profile: "melissa.code.implementer".into(),
            goal: "g".into(),
            after: BTreeSet::new(),
            bindings: vec![],
            literal_input: json!({}),
            tools: BTreeSet::new(),
            effects: BTreeSet::from(["workspace.read".into()]),
            resources: BTreeSet::from(["fixture:workspace:owned".into()]),
            authorizations: BTreeSet::from(["fixture:authorization:user-task".into()]),
            claims: vec![],
            output_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}),
            skills: vec![],
        }],
        outputs: BTreeSet::from(["a".into()]),
    };
    let fresh = Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    };
    let other = Arc::new(Mutex::new(Some(st.connect().unwrap())));
    let armed: Arc<Mutex<Option<Lease>>> = Arc::new(Mutex::new(None));
    let (o2, a2, f2) = (other.clone(), armed.clone(), fresh.clone());
    let refresh: Refresh = Arc::new(move || {
        if let Some(lease) = a2.lock().unwrap().take() {
            let f3 = f2.clone();
            let mut second = Scheduler::open(
                o2.lock().unwrap().take().unwrap(),
                TASK.into(),
                "flow".into(),
                Arc::new(move || Ok(f3.clone())),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            second
                .mark_uncertain(&lease, "concurrent worker reported unknown effect")
                .unwrap();
        }
        Ok(f2.clone())
    });
    let mut s =
        Scheduler::create(st, p, &catalog(), refresh, Arc::new(AtomicBool::new(false))).unwrap();
    let packet = s.acquire("a", "worker", 30000).unwrap();
    let http = http_fixture(vec![HttpPlan::sse(text_response(
        r#"{"value":7}"#,
        false,
        true,
    ))])
    .await;
    let mut g = gateway(s.store().connect().unwrap(), &http, policy());
    let mut sp = spec(&packet.lease.run);
    sp.profile_id = packet.node.profile.clone();
    sp.output_schema = Some(packet.node.output_schema.clone());
    let _ = g
        .run(&sp, &mut NoTools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    *armed.lock().unwrap() = Some(packet.lease.clone());
    let res = s.complete_native(&packet.lease);
    assert!(
        res.is_err(),
        "complete_native overwrote a concurrently committed NeedsReconciliation"
    );
    assert_eq!(
        s.state().unwrap().slots["a"].phase,
        Phase::NeedsReconciliation
    );
}
