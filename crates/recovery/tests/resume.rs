#![allow(dead_code, unused_imports)]
include!("../../workflow/tests/common/gateway.rs");
use melissa_model_gateway::continuation::{ContinuationStore, Phase, TurnCheckpoint};
use melissa_recovery::{
    Binding, Policy, RecoverySession,
    continuation::RecoveryContinuation,
    session::{Freshness, Refresh},
};
use std::collections::BTreeMap;
struct Crash {
    inner: RecoveryContinuation,
    at: Phase,
}
impl ContinuationStore for Crash {
    fn begin(
        &mut self,
        s: &mut LocalStore,
        b: &str,
        t: &str,
        r: &str,
    ) -> Result<Option<TurnCheckpoint>> {
        self.inner.begin(s, b, t, r)
    }
    fn publish(&mut self, s: &mut LocalStore, c: &TurnCheckpoint) -> Result<()> {
        self.inner.publish(s, c)?;
        if c.phase == self.at && (self.at != Phase::Safe || c.next_turn == 1) {
            return Err(GatewayError::new(
                ErrorKind::Store,
                "injected controller loss after durable boundary",
            ));
        }
        Ok(())
    }
}
fn setup(s: &mut LocalStore, run: &str) -> (Binding, Refresh, RecoverySession) {
    let b = Binding {
        task: TASK.into(),
        run: run.into(),
        profile: PROFILE.into(),
        initial_source: s
            .journal()
            .task(TASK)
            .unwrap()
            .contract
            .input_snapshot_digest,
        policy: "policy:resume".into(),
    };
    let x = b.clone();
    let r: Refresh = Arc::new(move || {
        Ok(Freshness {
            source: x.initial_source.clone(),
            policy: x.policy.clone(),
        })
    });
    let h = RecoverySession::create(
        s,
        b.clone(),
        Policy {
            max_repairs: 16,
            max_same_failure: 3,
            deadline_ms: melissa_execution_broker::unix_ms().unwrap() + 60_000,
        },
        r.clone(),
        BTreeMap::new(),
    )
    .unwrap();
    (b, r, h)
}
#[tokio::test]
async fn safe_restart_carries_exact_native_history_and_charges_without_reexecuting_tool() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, r, h) = setup(&mut s, "resume");
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "one",
            "process_exec",
            "{\"value\":\"owned\"}",
        )])),
        HttpPlan::sse(text_response("finished", false, true)),
    ])
    .await;
    let policy = policy();
    let mut g = gateway(s, &http, policy.clone())
        .with_recovery(Box::new(h))
        .with_continuation(Box::new(Crash {
            inner: RecoveryContinuation::new(b.clone(), r.clone()),
            at: Phase::Safe,
        }));
    let mut tools = FakeTools::default();
    assert!(
        g.run(
            &spec("resume"),
            &mut tools,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert_eq!(tools.executed.load(Ordering::SeqCst), 1);
    let s = g.store().connect().unwrap();
    let before = s.journal().model_budget(TASK).unwrap().known_cost_micro_usd;
    drop(g);
    let h = RecoverySession::reopen(&s, b.clone(), r.clone(), BTreeMap::new()).unwrap();
    let mut g = gateway(s, &http, policy)
        .with_recovery(Box::new(h))
        .with_continuation(Box::new(RecoveryContinuation::new(b, r)));
    let result = g
        .run(
            &spec("resume"),
            &mut tools,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(result.status, RunStatus::FinalCandidate);
    assert_eq!(result.request_ids.len(), 2);
    assert_eq!(tools.executed.load(Ordering::SeqCst), 1);
    assert!(
        g.store()
            .journal()
            .model_budget(TASK)
            .unwrap()
            .known_cost_micro_usd
            >= before
    );
    assert!(
        serde_json::to_string(&http.bodies.lock().unwrap()[1])
            .unwrap()
            .contains("observed")
    );
}
#[tokio::test]
async fn pending_inference_checkpoint_cannot_be_replayed_after_restart() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(d.path(), 100_000);
    let (b, r, h) = setup(&mut s, "pending");
    let http = http_fixture(vec![]).await;
    let policy = policy();
    let mut g = gateway(s, &http, policy.clone())
        .with_recovery(Box::new(h))
        .with_continuation(Box::new(Crash {
            inner: RecoveryContinuation::new(b.clone(), r.clone()),
            at: Phase::InferencePending,
        }));
    assert!(
        g.run(
            &spec("pending"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    let s = g.store().connect().unwrap();
    drop(g);
    let h = RecoverySession::reopen(&s, b.clone(), r.clone(), BTreeMap::new()).unwrap();
    let mut g = gateway(s, &http, policy)
        .with_recovery(Box::new(h))
        .with_continuation(Box::new(RecoveryContinuation::new(b, r)));
    assert!(
        g.run(
            &spec("pending"),
            &mut FakeTools::default(),
            Arc::new(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}
