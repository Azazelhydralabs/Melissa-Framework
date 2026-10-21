#![allow(dead_code)]
include!("common/gateway.rs");
use melissa_workflow::{Kind, gate::*, plan::*, runtime::*, scheduler::*};
struct NoTools;
impl ToolDispatcher for NoTools {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![]
    }
    fn validate_call(&self, _: &ToolCall) -> Result<()> {
        Err(GatewayError::invalid("no tools declared"))
    }
    fn execute<'a>(
        &'a mut self,
        _: ToolCall,
        _: ToolContext,
        _: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async { Err(GatewayError::invalid("no tools declared")) })
    }
}

fn catalog() -> Catalog {
    Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
}
fn node(id: &str) -> Node {
    Node {
        id: id.into(),
        profile: "melissa.code.implementer".into(),
        goal: format!("Observe and implement {id}; return a candidate"),
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
    }
}
fn plan(s: &LocalStore) -> Plan {
    Plan {
        schema_version: "melissa.workflow-plan/v1".into(),
        id: "flow".into(),
        task: TASK.into(),
        revision: 1,
        parent_digest: None,
        workspace_digest: s
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
        nodes: vec![node("a")],
        outputs: BTreeSet::from(["a".into()]),
    }
}
fn parallel(s: &LocalStore) -> Plan {
    let mut p = plan(s);
    p.nodes.push(node("b"));
    p.outputs.insert("b".into());
    p.mode = Mode::ConditionalDelegation;
    p.delegation_reason = Some("independent source analysis".into());
    p.max_parallel = 2;
    p
}
fn create(s: LocalStore, p: Plan) -> Scheduler {
    let fresh = Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    };
    Scheduler::create(
        s,
        p,
        &catalog(),
        Arc::new(move || Ok(fresh.clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}
fn setup() -> (tempfile::TempDir, Scheduler) {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("store"), 1_000_000);
    let p = plan(&s);
    (d, create(s, p))
}
fn invalid(mutate: impl FnOnce(&mut Plan)) {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("store"), 1_000_000);
    let mut p = plan(&s);
    mutate(&mut p);
    assert!(
        p.validate(&s.journal().task(TASK).unwrap().contract, &catalog())
            .is_err()
    );
}
fn claim(path: &str, access: Access) -> Claim {
    Claim {
        resource: "fixture:workspace:owned".into(),
        path: path.into(),
        access,
    }
}
fn normal_runtime(owner: SharedScheduler, http: Arc<HttpFixture>) -> Runtime {
    let s = owner.clone();
    Runtime {
        scheduler: owner,
        lease_ms: 30000,
        factory: Arc::new(move |packet| {
            let store = s.lock().unwrap().store().connect().unwrap();
            let mut sp = spec(&packet.lease.run);
            sp.profile_id = packet.node.profile.clone();
            sp.user_message = serde_json::to_string(packet).unwrap();
            sp.output_schema = Some(packet.node.output_schema.clone());
            Ok(PreparedRun {
                gateway: gateway(store, &http, policy()),
                spec: sp,
                dispatcher: Box::new(NoTools),
            })
        }),
    }
}

#[test]
fn valid_plan_has_typed_dependency_binding() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 100000);
    let mut p = parallel(&s);
    p.nodes[1].after.insert("a".into());
    p.nodes[1].bindings.push(Binding {
        from: "a".into(),
        pointer: "/value".into(),
        input: "analysis".into(),
        schema: json!({"type":"integer"}),
    });
    p.outputs.remove("a");
    assert!(
        p.validate(&s.journal().task(TASK).unwrap().contract, &catalog())
            .is_ok()
    );
}
#[test]
fn rejects_cycle() {
    invalid(|p| {
        p.mode = Mode::ConditionalDelegation;
        p.delegation_reason = Some("cycle".into());
        p.nodes.push(node("b"));
        p.nodes[0].after.insert("b".into());
        p.nodes[1].after.insert("a".into());
    });
}
#[test]
fn rejects_unknown_profile() {
    invalid(|p| p.nodes[0].profile = "fake.expert".into());
}
#[test]
fn known_profile_must_still_be_selected_by_parent() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 100000);
    let p = plan(&st);
    let mut task = st.journal().task(TASK).unwrap().contract;
    task.selected_profile_ids = vec!["melissa.code.reviewer".into()];
    assert_eq!(
        p.validate(&task, &catalog()).unwrap_err().kind,
        Kind::Authority
    );
}
#[test]
fn rejects_unknown_tool() {
    invalid(|p| {
        p.nodes[0].tools.insert("madeup.tool".into());
    });
}
#[test]
fn rejects_role_inappropriate_tool() {
    invalid(|p| {
        p.nodes[0].profile = "melissa.code.reviewer".into();
        p.nodes[0].tools.insert("fs.patch".into());
    });
}
#[test]
fn rejects_parent_effect_amplification() {
    invalid(|p| {
        p.nodes[0].effects.insert("network.unrestricted".into());
    });
}
#[test]
fn rejects_profile_effect_amplification() {
    invalid(|p| {
        p.nodes[0].profile = "melissa.code.reviewer".into();
        p.nodes[0]
            .effects
            .insert("workspace.apply_patch_scoped".into());
    });
}
#[test]
fn rejects_resource_amplification() {
    invalid(|p| {
        p.nodes[0].resources.insert("another:workspace".into());
    });
}
#[test]
fn rejects_authorization_amplification() {
    invalid(|p| {
        p.nodes[0].authorizations.insert("new:approval".into());
    });
}
#[test]
fn rejects_duplicate_node_identity() {
    invalid(|p| p.nodes.push(p.nodes[0].clone()));
}
#[test]
fn rejects_missing_output_node() {
    invalid(|p| {
        p.outputs.insert("missing".into());
    });
}
#[test]
fn rejects_hidden_orphan_spend() {
    invalid(|p| {
        p.mode = Mode::ConditionalDelegation;
        p.delegation_reason = Some("hidden".into());
        p.nodes.push(node("orphan"));
    });
}
#[test]
fn rejects_delegation_without_reason() {
    invalid(|p| {
        p.mode = Mode::ConditionalDelegation;
    });
}
#[test]
fn rejects_parallel_single_agent() {
    invalid(|p| p.max_parallel = 2);
}
#[test]
fn rejects_parent_parallel_limit() {
    invalid(|p| p.max_parallel = 5);
}
#[test]
fn rejects_external_schema_before_any_provider() {
    invalid(|p| p.nodes[0].output_schema = json!({"$ref":"https://invalid.example/secret"}));
}
#[test]
fn rejects_bad_output_binding() {
    invalid(|p| {
        p.nodes[0].bindings.push(Binding {
            from: "x".into(),
            pointer: "bad".into(),
            input: "x".into(),
            schema: json!({}),
        })
    });
}
#[test]
fn rejects_malformed_output_schema() {
    invalid(|p| p.nodes[0].output_schema = json!({"type":"notatype"}));
}
#[test]
fn rejects_write_lock_without_mutation_grant() {
    invalid(|p| p.nodes[0].claims.push(claim("a.py", Access::Write)));
}
#[test]
fn path_claims_reject_aliases_and_traversal() {
    for s in [
        "../x",
        "a/../b",
        "C:/x",
        "a\\b",
        "NUL.txt",
        "a.",
        "a//b",
        "LPT\u{00b9}.log",
        "x/",
        "",
    ] {
        assert!(!path(s), "{s}");
    }
}
#[test]
fn duplicate_json_keys_cannot_collapse_plan_fields() {
    assert!(Plan::parse(r#"{"id":"a","id":"b"}"#).is_err());
}
#[test]
fn unknown_plan_fields_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 10000);
    let mut v = serde_json::to_value(plan(&s)).unwrap();
    v["grant_unlimited"] = json!(true);
    assert!(Plan::parse(&v.to_string()).is_err());
}
#[test]
fn file_prefix_and_case_ownership_is_conservative() {
    assert!(conflicts(
        &claim("src", Access::Write),
        &claim("SRC/a.py", Access::Read)
    ));
    assert!(!conflicts(
        &claim("src", Access::Write),
        &claim("src2/a.py", Access::Read)
    ));
    assert!(conflicts(
        &claim("/", Access::Write),
        &claim("a.py", Access::Read)
    ));
}
#[test]
fn one_durable_lease_prevents_duplicate_dispatch() {
    let (_d, mut s) = setup();
    let packet = s.acquire("a", "worker:one", 10000).unwrap();
    assert!(s.acquire("a", "worker:two", 10000).is_err());
    assert!(s.check(&packet.lease).is_ok());
}
#[test]
fn forged_run_or_generation_is_rejected() {
    let (_d, mut s) = setup();
    let p = s.acquire("a", "worker:one", 10000).unwrap();
    let mut wrong = p.lease.clone();
    wrong.generation += 1;
    assert_eq!(s.check(&wrong).unwrap_err().kind, Kind::Stale);
    wrong = p.lease.clone();
    wrong.run.push('x');
    assert!(s.check(&wrong).is_err());
}
#[test]
fn result_without_owned_native_gateway_artifact_is_rejected() {
    let (_d, mut s) = setup();
    let p = s.acquire("a", "worker:one", 10000).unwrap();
    assert!(s.complete_native(&p.lease).is_err());
    assert_eq!(s.state().unwrap().slots["a"].phase, Phase::Leased);
}
#[test]
fn expired_lease_is_not_replayed_or_automatically_reassigned() {
    let (_d, mut s) = setup();
    let p = s.acquire("a", "worker:one", 1).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    assert!(s.check(&p.lease).is_err());
    assert!(s.acquire("a", "worker:two", 10000).is_err());
}
#[test]
fn parallel_readers_share_resource() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 10000);
    let mut p = parallel(&s);
    for n in &mut p.nodes {
        n.claims.push(claim("src", Access::Read));
    }
    let mut s = create(s, p);
    s.acquire("a", "worker:a", 10000).unwrap();
    s.acquire("b", "worker:b", 10000).unwrap();
}
#[test]
fn parallel_writer_conflicts_with_reader() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 10000);
    let mut p = parallel(&s);
    p.nodes[0]
        .effects
        .insert("workspace.apply_patch_scoped".into());
    p.nodes[0].claims.push(claim("src", Access::Write));
    p.nodes[1].claims.push(claim("SRC/x.py", Access::Read));
    let mut s = create(s, p);
    s.acquire("a", "worker:a", 10000).unwrap();
    assert_eq!(
        s.acquire("b", "worker:b", 10000).unwrap_err().kind,
        Kind::Conflict
    );
}
#[test]
fn independent_writers_can_run_in_parallel() {
    let d = tempfile::tempdir().unwrap();
    let s = store(&d.path().join("s"), 10000);
    let mut p = parallel(&s);
    for (n, path) in p.nodes.iter_mut().zip(["a.py", "b.py"]) {
        n.effects.insert("workspace.apply_patch_scoped".into());
        n.claims.push(claim(path, Access::Write));
    }
    let mut s = create(s, p);
    s.acquire("a", "worker:a", 10000).unwrap();
    s.acquire("b", "worker:b", 10000).unwrap();
}
#[test]
fn active_node_blocks_plan_replacement() {
    let (_d, mut s) = setup();
    s.acquire("a", "worker:a", 10000).unwrap();
    let mut p = s.state().unwrap().plan;
    p.parent_digest = Some(p.digest().unwrap());
    p.revision = 2;
    assert!(s.revise(p, &catalog()).is_err());
}
#[test]
fn quiescent_plan_revision_preserves_task_ledger() {
    let (_d, mut s) = setup();
    let mut p = s.state().unwrap().plan;
    p.parent_digest = Some(p.digest().unwrap());
    p.revision = 2;
    p.nodes[0].goal = "Revised goal".into();
    s.revise(p, &catalog()).unwrap();
    assert_eq!(s.state().unwrap().plan.revision, 2);
    assert_eq!(
        s.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}
#[test]
fn no_progress_stops_admission_until_explicit_revision() {
    let (_d, mut s) = setup();
    s.no_progress("no useful evidence").unwrap();
    s.no_progress("same observations").unwrap();
    assert!(s.acquire("a", "worker:a", 10000).is_err());
}
#[test]
fn plan_revision_cannot_restart_the_shared_wall_clock() {
    let (_d, mut s) = setup();
    let old = s.state().unwrap();
    let mut p = old.plan.clone();
    p.parent_digest = Some(p.digest().unwrap());
    p.revision = 2;
    s.revise(p, &catalog()).unwrap();
    let next = s.state().unwrap();
    assert_eq!(old.started_at_ms, next.started_at_ms);
    assert_eq!(old.deadline_ms, next.deadline_ms);
}
#[test]
fn root_cancellation_is_durable_and_not_task_success() {
    let (_d, mut s) = setup();
    s.acquire("a", "worker:a", 10000).unwrap();
    s.cancel().unwrap();
    assert!(s.flag().load(Ordering::Acquire));
    assert_eq!(
        s.store().journal().task(TASK).unwrap().record.state,
        TaskState::Cancelled
    );
    assert!(s.acquire("a", "worker:b", 10000).is_err());
    assert!(s.outputs().is_err());
    assert!(s.settle_cancellation().unwrap().cancellation_settled);
}
#[test]
fn current_policy_and_source_are_rechecked() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 10000);
    let p = plan(&st);
    let f = Arc::new(Mutex::new(Freshness {
        workspace_digest: p.workspace_digest.clone(),
        policy_digest: p.policy_digest.clone(),
    }));
    let refresh = f.clone();
    let mut s = Scheduler::create(
        st,
        p,
        &catalog(),
        Arc::new(move || Ok(refresh.lock().unwrap().clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let packet = s.acquire("a", "worker:a", 10000).unwrap();
    f.lock().unwrap().policy_digest = melissa_workflow::digest(b"revoked");
    assert_eq!(s.check(&packet.lease).unwrap_err().kind, Kind::Stale);
}
#[test]
fn checkpoint_can_be_reopened_after_real_store_close() {
    let (d, s) = setup();
    let fresh = Freshness {
        workspace_digest: s.state().unwrap().plan.workspace_digest,
        policy_digest: melissa_workflow::digest(b"current-policy"),
    };
    drop(s);
    let st = LocalStore::open(
        &d.path().join("store"),
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut reopened = Scheduler::open(
        st,
        TASK.into(),
        "flow".into(),
        Arc::new(move || Ok(fresh.clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    reopened
        .acquire("a", "worker:after-restart", 10000)
        .unwrap();
}
#[test]
fn concurrent_scheduler_connections_return_only_one_lease() {
    let (_d, s) = setup();
    let store1 = s.store().connect().unwrap();
    let store2 = s.store().connect().unwrap();
    let fresh = Freshness {
        workspace_digest: s.state().unwrap().plan.workspace_digest,
        policy_digest: melissa_workflow::digest(b"current-policy"),
    };
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles = [store1, store2]
        .into_iter()
        .map(|store| {
            let f = fresh.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let mut s = Scheduler::open(
                    store,
                    TASK.into(),
                    "flow".into(),
                    Arc::new(move || Ok(f.clone())),
                    Arc::new(AtomicBool::new(false)),
                )
                .unwrap();
                b.wait();
                s.acquire("a", "worker:concurrent", 10000).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[tokio::test]
async fn native_gateway_candidate_binds_dependency_and_same_task_budget() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 100000);
    let mut p = parallel(&st);
    p.nodes[1].after.insert("a".into());
    p.nodes[1].bindings.push(Binding {
        from: "a".into(),
        pointer: "/value".into(),
        input: "prior".into(),
        schema: json!({"type":"integer"}),
    });
    p.outputs.remove("a");
    let scheduler = Arc::new(Mutex::new(create(st, p)));
    let http = Arc::new(
        http_fixture(vec![
            HttpPlan::sse(text_response(r#"{"value":7}"#, false, true)),
            HttpPlan::sse(text_response(r#"{"value":8}"#, false, true)),
        ])
        .await,
    );
    let owner = scheduler.clone();
    let server = http.clone();
    let rt = Runtime {
        scheduler: scheduler.clone(),
        lease_ms: 10000,
        factory: Arc::new(move |packet| {
            let store = owner.lock().unwrap().store().connect().unwrap();
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
    rt.run("a").await.unwrap();
    let b = rt.run("b").await.unwrap();
    assert_eq!(b.slots["b"].output.as_ref().unwrap()["value"], 8);
    let s = scheduler.lock().unwrap();
    assert_eq!(s.outputs().unwrap()["b"]["value"], 8);
    assert_eq!(s.store().journal().model_requests(TASK).unwrap().len(), 2);
    assert_eq!(
        s.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .known_input_tokens,
        24
    );
    assert_eq!(
        s.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
    let request = &http.bodies.lock().unwrap()[1];
    let prompt = request["input"][0]["content"][0]["text"].as_str().unwrap();
    let handoff: Value = serde_json::from_str(prompt).unwrap();
    assert_eq!(handoff["bound_inputs"]["prior"], 7);
    assert_eq!(handoff["shared_budget"]["known_input_tokens"], 12);
}

#[tokio::test]
async fn two_native_agent_runs_can_hold_distinct_leases_and_shared_reservations_concurrently() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 100000);
    let p = parallel(&st);
    let owner = Arc::new(Mutex::new(create(st, p)));
    let http = Arc::new(
        http_fixture(vec![
            HttpPlan {
                status: 200,
                body: text_response(r#"{"value":1}"#, false, true),
                delay: Duration::from_millis(300),
            },
            HttpPlan::sse(text_response(r#"{"value":2}"#, false, true)),
        ])
        .await,
    );
    let rt = normal_runtime(owner.clone(), http);
    let a = rt.clone();
    let b = rt.clone();
    let first = tokio::spawn(async move { a.run("a").await });
    let second = tokio::spawn(async move { b.run("b").await });
    let mut observed = false;
    for _ in 0..100 {
        if owner
            .lock()
            .unwrap()
            .store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .active_requests
            == 2
        {
            observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        observed,
        "actual native reservations were not simultaneously active"
    );
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    assert_eq!(owner.lock().unwrap().outputs().unwrap().len(), 2);
}

#[tokio::test]
async fn completed_node_rejects_duplicate_result_and_contract_rewrite() {
    let (_d, s) = setup();
    let owner = Arc::new(Mutex::new(s));
    let http = Arc::new(
        http_fixture(vec![HttpPlan::sse(text_response(
            r#"{"value":7}"#,
            false,
            true,
        ))])
        .await,
    );
    let rt = normal_runtime(owner.clone(), http);
    rt.run("a").await.unwrap();
    let mut s = owner.lock().unwrap();
    let state = s.state().unwrap();
    let old = state.slots["a"].lease.clone().unwrap();
    assert!(s.complete_native(&old).is_err());
    let mut p = state.plan;
    p.parent_digest = Some(p.digest().unwrap());
    p.revision += 1;
    p.nodes[0].goal = "Rewrite completed work".into();
    assert!(s.revise(p, &catalog()).is_err());
}
#[tokio::test]
async fn missing_dependency_pointer_blocks_next_provider_call() {
    let d = tempfile::tempdir().unwrap();
    let st = store(&d.path().join("s"), 100000);
    let mut p = parallel(&st);
    p.nodes[1].after.insert("a".into());
    p.nodes[1].bindings.push(Binding {
        from: "a".into(),
        pointer: "/missing".into(),
        input: "x".into(),
        schema: json!({"type":"integer"}),
    });
    p.outputs.remove("a");
    let owner = Arc::new(Mutex::new(create(st, p)));
    let http = Arc::new(
        http_fixture(vec![HttpPlan::sse(text_response(
            r#"{"value":1}"#,
            false,
            true,
        ))])
        .await,
    );
    let rt = normal_runtime(owner.clone(), http.clone());
    rt.run("a").await.unwrap();
    assert!(rt.run("b").await.is_err());
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        owner.lock().unwrap().state().unwrap().slots["b"].phase,
        Phase::Pending
    );
}
#[tokio::test]
async fn invalid_native_output_is_a_failed_node_not_workflow_success() {
    let (_d, s) = setup();
    let owner = Arc::new(Mutex::new(s));
    let http = Arc::new(
        http_fixture(vec![HttpPlan::sse(text_response(
            r#"{"value":"wrong type"}"#,
            false,
            true,
        ))])
        .await,
    );
    let rt = normal_runtime(owner.clone(), http);
    let state = rt.run("a").await.unwrap();
    assert_eq!(state.slots["a"].phase, Phase::Failed);
    assert!(owner.lock().unwrap().outputs().is_err());
}
#[tokio::test]
async fn pending_checkpoint_is_not_a_safe_resume_even_with_zero_provider_dispatch() {
    use melissa_model_gateway::continuation::{
        ContinuationStore, Phase as TurnPhase, TurnCheckpoint,
    };
    use melissa_workflow::continuation::WorkflowContinuation;
    struct StopBeforeDispatch(WorkflowContinuation);
    impl ContinuationStore for StopBeforeDispatch {
        fn begin(
            &mut self,
            s: &mut LocalStore,
            b: &str,
            t: &str,
            r: &str,
        ) -> Result<Option<TurnCheckpoint>> {
            self.0.begin(s, b, t, r)
        }
        fn publish(&mut self, s: &mut LocalStore, c: &TurnCheckpoint) -> Result<()> {
            self.0.publish(s, c)?;
            if c.phase == TurnPhase::InferencePending {
                Err(GatewayError::new(
                    ErrorKind::Store,
                    "intentional local pre-dispatch stop",
                ))
            } else {
                Ok(())
            }
        }
    }
    let (_d, s) = setup();
    let owner = Arc::new(Mutex::new(s));
    let packet = owner
        .lock()
        .unwrap()
        .acquire("a", "host:checkpoint", 30000)
        .unwrap();
    let server = http_fixture(vec![]).await;
    let mut policy1 = policy();
    policy1.expires_at_unix_ms = packet.lease.expires_at_ms;
    let mut sp = spec(&packet.lease.run);
    sp.profile_id = packet.node.profile.clone();
    sp.user_message = serde_json::to_string(&packet).unwrap();
    sp.output_schema = Some(packet.node.output_schema.clone());
    let st = owner.lock().unwrap().store().connect().unwrap();
    let mut g = gateway(st, &server, policy1.clone()).with_continuation(Box::new(
        StopBeforeDispatch(WorkflowContinuation::new(owner.clone(), packet.clone())),
    ));
    assert!(
        g.run(&sp, &mut NoTools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    let st = owner.lock().unwrap().store().connect().unwrap();
    let mut g = gateway(st, &server, policy1)
        .with_continuation(Box::new(WorkflowContinuation::new(owner.clone(), packet)));
    assert!(
        g.run(&sp, &mut NoTools, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    assert!(
        owner
            .lock()
            .unwrap()
            .store()
            .journal()
            .model_requests(TASK)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn shared_root_continuation_survives_store_close_and_other_node_charges_without_replaying_read()
 {
    use melissa_model_gateway::continuation::{
        ContinuationStore, Phase as TurnPhase, TurnCheckpoint,
    };
    use melissa_workflow::continuation::WorkflowContinuation;
    struct StopAtSafe(WorkflowContinuation);
    impl ContinuationStore for StopAtSafe {
        fn begin(
            &mut self,
            s: &mut LocalStore,
            b: &str,
            t: &str,
            r: &str,
        ) -> Result<Option<TurnCheckpoint>> {
            self.0.begin(s, b, t, r)
        }
        fn publish(&mut self, s: &mut LocalStore, c: &TurnCheckpoint) -> Result<()> {
            self.0.publish(s, c)?;
            if c.phase == TurnPhase::Safe && c.result.request_ids.len() == 1 {
                Err(GatewayError::new(
                    ErrorKind::Store,
                    "controlled host exit boundary after durable safe checkpoint",
                ))
            } else {
                Ok(())
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("repo");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("owned.txt"), b"original payload").unwrap();
    let repo = Arc::new(
        melissa_repository::Repository::open(
            &source,
            melissa_repository::Limits::default(),
            vec![],
        )
        .unwrap(),
    );
    let st = store(&dir.path().join("s"), 100000);
    let mut p = parallel(&st);
    p.nodes[0].tools.insert("fs.read".into());
    p.nodes[0].claims.push(claim("/", Access::Read));
    let owner = Arc::new(Mutex::new(create(st, p)));
    let http = Arc::new(
        http_fixture(vec![
            HttpPlan::sse(tool_response(&[(
                "read",
                "fs_read",
                r#"{"path":"owned.txt"}"#,
            )])),
            HttpPlan::sse(text_response(r#"{"value":2}"#, false, true)),
            HttpPlan::sse(text_response(r#"{"value":3}"#, false, true)),
        ])
        .await,
    );
    fn factory(
        owner: SharedScheduler,
        http: Arc<HttpFixture>,
        repo: Arc<melissa_repository::Repository>,
    ) -> Factory {
        Arc::new(move |packet| {
            let store = owner.lock().unwrap().store().connect().unwrap();
            let mut sp = spec(&packet.lease.run);
            sp.profile_id = packet.node.profile.clone();
            sp.user_message = serde_json::to_string(packet).unwrap();
            sp.output_schema = Some(packet.node.output_schema.clone());
            let tools: Box<dyn ToolDispatcher> = if packet.node.id == "a" {
                sp.required_tool_names.insert("fs_read".into());
                Box::new(
                    melissa_repository::tools::RepositoryDispatcher::new(
                        melissa_repository::Repository::open(
                            repo.root_path(),
                            melissa_repository::Limits::default(),
                            vec![],
                        )
                        .unwrap(),
                        store.connect().unwrap(),
                        melissa_repository::tools::RepositoryToolPolicy {
                            files: melissa_repository::PatchPolicy {
                                task_id: TASK.into(),
                                principal_id: "principal:fixture".into(),
                                profile_id: packet.node.profile.clone(),
                                resource_id: packet.parent_task.workspace_ref.clone(),
                                authorization_ref: "fixture:authorization:user-task".into(),
                                expires_at_ms: packet.lease.expires_at_ms,
                                epoch: 1,
                                writable_paths: BTreeSet::new(),
                                protected_paths: BTreeSet::new(),
                            },
                            read_repository: true,
                            enabled_tools: BTreeSet::from(["fs_read".into()]),
                        },
                    )
                    .unwrap(),
                )
            } else {
                Box::new(NoTools)
            };
            Ok(PreparedRun {
                gateway: {
                    let mut p = policy();
                    p.expires_at_unix_ms = packet.lease.expires_at_ms;
                    gateway(store, &http, p)
                }
                .with_continuation(Box::new(WorkflowContinuation::new(
                    owner.clone(),
                    packet.clone(),
                ))),
                spec: sp,
                dispatcher: tools,
            })
        })
    }
    let rt = Runtime {
        scheduler: owner.clone(),
        factory: factory(owner.clone(), http.clone(), repo.clone()),
        lease_ms: 30000,
    };
    let packet = owner
        .lock()
        .unwrap()
        .acquire("a", "host:before-close", 30000)
        .unwrap();
    let mut prepared = (rt.factory)(&packet).unwrap();
    let bytes = serde_json::to_vec(&packet).unwrap();
    prepared
        .gateway
        .store_mut()
        .put_artifact(
            &melissa_local_store::ArtifactRequest {
                artifact_id: format!("workflow-handoff:{}", packet.lease.run),
                task_id: TASK.into(),
                content_type: "application/json".into(),
                logical_type: "workflow.handoff".into(),
                schema_version: packet.schema_version.clone(),
                retain_until_ms: 0,
                legal_hold: false,
            },
            &bytes,
        )
        .unwrap();
    prepared.gateway =
        prepared
            .gateway
            .with_continuation(Box::new(StopAtSafe(WorkflowContinuation::new(
                owner.clone(),
                packet.clone(),
            ))));
    let mut tools =
        NodeDispatcher::new(owner.clone(), packet.clone(), prepared.dispatcher).unwrap();
    let flag = owner.lock().unwrap().flag();
    assert!(
        prepared
            .gateway
            .run(&prepared.spec, &mut tools, flag)
            .await
            .is_err()
    );
    drop(tools);
    drop(prepared.gateway);
    rt.run("b").await.unwrap();
    assert_eq!(
        owner
            .lock()
            .unwrap()
            .store()
            .journal()
            .model_requests(TASK)
            .unwrap()
            .len(),
        2
    );
    let read_ref = format!(
        "model-tool:{}:{}:tool-result",
        packet.lease.run,
        &blake3::hash(b"read").to_hex()[..24]
    );
    let before = owner
        .lock()
        .unwrap()
        .store()
        .get_artifact(TASK, &read_ref)
        .unwrap();
    let read: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(read["result"]["bytes"], json!(b"original payload"));
    let fresh = Freshness {
        workspace_digest: owner.lock().unwrap().state().unwrap().plan.workspace_digest,
        policy_digest: melissa_workflow::digest(b"current-policy"),
    };
    drop(rt);
    drop(owner);
    let reopened = LocalStore::open(
        &dir.path().join("s"),
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let owner = Arc::new(Mutex::new(
        Scheduler::open(
            reopened,
            TASK.into(),
            "flow".into(),
            Arc::new(move || Ok(fresh.clone())),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap(),
    ));
    let rt = Runtime {
        scheduler: owner.clone(),
        factory: factory(owner.clone(), http.clone(), repo),
        lease_ms: 30000,
    };
    rt.resume("a").await.unwrap();
    {
        let s = owner.lock().unwrap();
        assert_eq!(s.outputs().unwrap()["a"]["value"], 3);
        assert_eq!(s.store().journal().model_requests(TASK).unwrap().len(), 3);
        assert_eq!(
            s.store()
                .journal()
                .model_budget(TASK)
                .unwrap()
                .known_input_tokens,
            36
        );
        let after = s.store().get_artifact(TASK, &read_ref).unwrap();
        assert_eq!(before, after);
        let run: Value = serde_json::from_slice(
            &s.store()
                .get_artifact(TASK, &format!("model-run:{}:result", packet.lease.run))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(run["tool_calls"], 1);
        assert_eq!(http.requests.load(Ordering::SeqCst), 3);
    }
    assert!(rt.resume("a").await.is_err());
}

#[test]
fn actual_process_exit_preserves_checkpoint_and_fences_abandoned_lease() {
    const PROBE: &str = "CODE08_OWNED_PROCESS_EXIT_PROBE";
    if let Some(root) = std::env::var_os(PROBE) {
        let st = store(Path::new(&root), 100000);
        let p = parallel(&st);
        let mut s = create(st, p);
        s.acquire("a", "host:before-real-exit", 30000).unwrap();
        std::process::exit(0);
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("s");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "actual_process_exit_preserves_checkpoint_and_fences_abandoned_lease",
            "--nocapture",
        ])
        .env(PROBE, &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let st = LocalStore::open(
        &root,
        StoreKey::from_bytes([117; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let fresh = Freshness {
        workspace_digest: st
            .journal()
            .task(TASK)
            .unwrap()
            .contract
            .input_snapshot_digest,
        policy_digest: melissa_workflow::digest(b"current-policy"),
    };
    let mut s = Scheduler::open(
        st,
        TASK.into(),
        "flow".into(),
        Arc::new(move || Ok(fresh.clone())),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(s.state().unwrap().slots["a"].phase, Phase::Leased);
    assert!(s.acquire("a", "host:replay", 10000).is_err());
    s.acquire("b", "host:next-independent-node", 10000).unwrap();
    assert_eq!(
        s.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .charged_cost_micro_usd,
        0
    );
    s.store().integrity_check().unwrap();
}
