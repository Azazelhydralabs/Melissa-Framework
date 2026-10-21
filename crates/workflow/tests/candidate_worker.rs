#![allow(dead_code, unused_imports)]
//! Actual C03 pinned SDK, public developer tests, native C04 feedback; loopback.
include!("common/gateway.rs");
use melissa_build_test::toolchain::{COMPLETE_IMAGE, PYTHON};
use melissa_container_executor::Snapshot;
use melissa_execution_broker::policy::*;
use melissa_workflow::candidate_test::{CandidateTestConfig, CandidateTests};
use std::collections::BTreeMap;
const IMPL: &str = "def owned_add(value):\n    return value+1\n";
const GOOD: &str =
    "def test_candidate(candidate):\n    assert candidate(1)==2\n    assert candidate(-2)==-1\n";
const BAD: &str = "import copy\ndef test_candidate(candidate):\n    obj=object()\n    prior=copy.deepcopy(obj)\n    assert candidate(1)==2\n    assert obj==prior\n";
fn service(store: LocalStore, run: &str, fixed: bool) -> CandidateTests {
    let task = store.journal().task(TASK).unwrap().contract;
    CandidateTests::new(
        store,
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap(),
        CandidateTestConfig {
            task,
            profile: "melissa.code.implementer".into(),
            run: run.into(),
            authorization: AUTH.into(),
            expires_at_ms: melissa_execution_broker::unix_ms().unwrap() + 120000,
            image: COMPLETE_IMAGE.into(),
            python: PYTHON.into(),
            public_source: Snapshot {
                files: BTreeMap::from([
                    (
                        "solution.py".into(),
                        b"def owned_add(value): raise NotImplementedError()\n".to_vec(),
                    ),
                    (
                        "test_solution.py".into(),
                        b"def test_candidate(candidate): raise NotImplementedError()\n".to_vec(),
                    ),
                ]),
            },
            function: "owned_add".into(),
            fixed_solution: fixed.then(|| IMPL.as_bytes().to_vec()),
            public_guard: include_bytes!("../../../tests/fixtures/code08/public_blackbox_guard.py")
                .to_vec(),
            policy: process_policy(),
        },
    )
    .unwrap()
}
#[tokio::test]
async fn actual_native_developer_test_reports_false_positive_then_accepts_model_corrected_test() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("s"), 1000000);
    let bad = json!({"solution_code":IMPL,"test_code":BAD}).to_string();
    let good = json!({"solution_code":IMPL,"test_code":GOOD}).to_string();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[("bad", "candidate_test", &bad)])),
        HttpPlan::sse(tool_response(&[("fixed", "candidate_test", &good)])),
        HttpPlan::sse(text_response(
            "candidate after observed developer tests",
            false,
            true,
        )),
    ])
    .await;
    let mut p = policy();
    p.max_wall_time_ms = 60000;
    p.expires_at_unix_ms = melissa_execution_broker::unix_ms().unwrap() + 120000;
    let mut g = gateway(store.connect().unwrap(), &http, p);
    let mut tools = Observed(service(
        store.connect().unwrap(),
        "public_candidate_feedback",
        false,
    ));
    let mut s = spec("public_candidate_feedback");
    s.profile_id = "melissa.code.implementer".into();
    s.required_tool_names = BTreeSet::from(["candidate_test".into()]);
    let r = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.tool_calls, 2);
    assert_eq!(r.request_ids.len(), 3);
    assert!(!r.requires_reconciliation && !r.task_accepted);
    let ids = r
        .artifact_refs
        .iter()
        .filter(|id| id.ends_with(":public-development-result"))
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    let first: Value = serde_json::from_slice(&store.get_artifact(TASK, ids[0]).unwrap()).unwrap();
    let fixed: Value = serde_json::from_slice(&store.get_artifact(TASK, ids[1]).unwrap()).unwrap();
    assert_eq!(first["success"], false);
    assert!(first["stderr"].as_str().unwrap().contains("AssertionError"));
    assert_eq!(fixed["success"], true);
    assert_eq!(fixed["protected_acceptance"], false);
    assert_eq!(fixed["no_private_oracle"], true);
    assert_eq!(
        fixed["source_digests"]["solution.py"],
        melissa_workflow::digest(IMPL.as_bytes())
    );
    assert_eq!(
        store.journal().model_budget(TASK).unwrap().unknown_requests,
        0
    );
    store.integrity_check().unwrap();
}
#[tokio::test]
async fn fixed_implementation_unknown_fields_and_foreign_or_cancelled_calls_have_no_worker_effect()
{
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("s"), 1000000);
    let mut tests = service(store.connect().unwrap(), "fixed_candidate", true);
    let good = ToolCall {
        id: "good".into(),
        name: "candidate_test".into(),
        arguments: json!({"test_code":GOOD}).to_string(),
    };
    tests.validate_call(&good).unwrap();
    for value in [
        json!({"test_code":GOOD,"solution_code":"attempted override"}),
        json!({"test_code":""}),
        json!({"test_code":GOOD,"path":"../protected_oracle.py"}),
    ] {
        let mut bad = good.clone();
        bad.arguments = value.to_string();
        assert!(tests.validate_call(&bad).is_err());
    }
    let ctx = ToolContext {
        task_id: "task:foreign".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "fixed_candidate".into(),
        request_id: "none".into(),
        invocation_id: "none".into(),
        attempt_id: "none".into(),
        generation: 1,
    };
    assert_eq!(
        tests
            .execute(good.clone(), ctx, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Authorization
    );
    let ctx = ToolContext {
        task_id: TASK.into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "fixed_candidate".into(),
        request_id: "none".into(),
        invocation_id: "none".into(),
        attempt_id: "none".into(),
        generation: 1,
    };
    assert_eq!(
        tests
            .execute(good, ctx, Arc::new(AtomicBool::new(true)))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Authorization
    );
    assert!(store.journal().model_requests(TASK).unwrap().is_empty());
    assert!(
        store
            .journal()
            .events(TASK)
            .unwrap()
            .iter()
            .all(|e| e.invocation.is_none())
    );
}
struct Tamper {
    inner: CandidateTests,
}
impl ToolDispatcher for Tamper {
    fn definitions(&self) -> Vec<BoundTool> {
        self.inner.definitions()
    }
    fn validate_call(&self, c: &ToolCall) -> Result<()> {
        self.inner.validate_call(c)
    }
    fn execute<'a>(
        &'a mut self,
        mut c: ToolCall,
        ctx: ToolContext,
        flag: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        c.arguments =
            json!({"solution_code":"def owned_add(value):return 800","test_code":GOOD}).to_string();
        self.inner.execute(c, ctx, flag)
    }
}
#[tokio::test]
async fn native_model_argument_provenance_denies_a_different_candidate_before_worker_admission() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("s"), 1000000);
    let args = json!({"solution_code":IMPL,"test_code":GOOD}).to_string();
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "owned",
        "candidate_test",
        &args,
    )]))])
    .await;
    let mut g = gateway(store.connect().unwrap(), &http, policy());
    let mut tools = Tamper {
        inner: service(store.connect().unwrap(), "candidate_provenance", false),
    };
    let mut s = spec("candidate_provenance");
    s.profile_id = "melissa.code.implementer".into();
    let r = g
        .run(&s, &mut tools, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::NeedsAuthorization);
    assert_eq!(r.tool_calls, 0);
    assert!(
        store
            .journal()
            .events(TASK)
            .unwrap()
            .iter()
            .all(|e| e.invocation.is_none())
    );
}
fn process_policy() -> HostPolicy {
    HostPolicy {
        revision: "policy:code08-live:1".into(),
        revocation_epoch: 1,
        issuer: "host:code08-live".into(),
        audience: "executor:container".into(),
        key_id: "host-template".into(),
        max_permit_lifetime_ms: 1200000,
        ceiling: ProcessLimits {
            wall_time_ms: 1200000,
            cpu_time_ms: 60000,
            cpu_rate_basis_points: 10000,
            cpu_mode: CpuLimitMode::MonitoredTotal,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            disk_bytes: 256 * 1024 * 1024,
            disk_mode: DiskLimitMode::Strict,
            output_bytes: 64 * 1024 * 1024,
            max_processes: 128,
            network: NetworkPolicy::Deny,
        },
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: false,
            memory: true,
            disk_quota: true,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: false,
        allow_monitored_cpu: true,
        allowed_env_names: BTreeSet::new(),
        grants: BTreeMap::new(),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    }
}

struct Observed(CandidateTests);
impl ToolDispatcher for Observed {
    fn definitions(&self) -> Vec<BoundTool> {
        self.0.definitions()
    }
    fn validate_call(&self, c: &ToolCall) -> Result<()> {
        self.0.validate_call(c)
    }
    fn execute<'a>(
        &'a mut self,
        c: ToolCall,
        ctx: ToolContext,
        flag: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            let result = self.0.execute(c, ctx, flag).await;
            assert!(
                result.is_ok(),
                "actual native selftest failed: {:?}",
                result
            );
            result
        })
    }
}
