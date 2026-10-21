mod support;
use melissa_local_store::LocalStore;
use melissa_model_gateway::{recovery::*, tools::ToolDispatcher, *};
use melissa_repository::{Limits, Repository};
use melissa_web_development::{
    plan::Database, progress::WebProgress, protocol::Service, tools::WebDispatcher,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, atomic::AtomicBool},
};
use support::*;
struct LoopGuard {
    seen: BTreeMap<String, u32>,
    captured: Arc<Mutex<Vec<String>>>,
}
impl RecoveryHook for LoopGuard {
    fn binding_digest(&self, _: &LocalStore) -> Result<String> {
        Ok("owned-inner-policy".into())
    }
    fn failure(&mut self, _: &mut LocalStore, _: RecoveryEvent) -> Result<RecoveryDirective> {
        unreachable!()
    }
    fn classify_observation(
        &self,
        _: &ToolCall,
        _: &melissa_model_gateway::tools::ToolExecution,
    ) -> FailureKind {
        FailureKind::ToolFailure
    }
    fn success(
        &mut self,
        _: &mut LocalStore,
        event: RecoveryEvent,
    ) -> Result<Option<RecoveryDirective>> {
        let args = event.calls[0].arguments.clone();
        self.captured.lock().unwrap().push(args.clone());
        let count = self.seen.entry(args).or_default();
        *count += 1;
        Ok((*count >= 4).then(|| RecoveryDirective {
            continue_run: false,
            feedback: "unchanged native web state".into(),
        }))
    }
}
#[tokio::test]
async fn actual_ui_state_changes_are_progress_but_identical_native_observations_still_stop() {
    let mut f = Fixture::new(Service::Browser, Some(Database::Sqlite), &[]);
    let mut d = WebDispatcher::new(
        Repository::open(&f.root(), Limits::default(), vec![]).unwrap(),
        f.store.connect().unwrap(),
        f.catalog.clone(),
        f.policy.clone(),
        f.registration.clone(),
        limits(),
    )
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let call = |id: &str, session: serde_json::Value, operation: serde_json::Value| ToolCall {
        id: id.into(),
        name: "web_session".into(),
        arguments: json!({"session_id":session,"operation":operation}).to_string(),
    };
    let start = d
        .execute(
            call("start", json!(null), json!({"command":"start"})),
            f.ctx.clone(),
            cancel.clone(),
        )
        .await
        .unwrap();
    let id: serde_json::Value =
        serde_json::from_str::<serde_json::Value>(&start.content).unwrap()["session_id"].clone();
    d.execute(
        call(
            "navigate",
            id.clone(),
            json!({"command":"navigate","page":"main","path":"/"}),
        ),
        f.ctx.clone(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let captured = Arc::new(Mutex::new(vec![]));
    let mut hook = WebProgress::new(
        Box::new(LoopGuard {
            seen: BTreeMap::new(),
            captured: captured.clone(),
        }),
        BTreeSet::from(["web_session".into()]),
    )
    .unwrap();
    let original = call(
        "inspect",
        id.clone(),
        json!({"command":"inspect","page":"main"}),
    );
    for index in 0..6 {
        if index == 2 {
            d.execute(
                call(
                    "fill",
                    id.clone(),
                    json!({"command":"fill","page":"main","selector":"#user","value":"alice"}),
                ),
                f.ctx.clone(),
                cancel.clone(),
            )
            .await
            .unwrap();
        }
        let result = d
            .execute(original.clone(), f.ctx.clone(), cancel.clone())
            .await
            .unwrap();
        assert!(result.success);
        let event = RecoveryEvent {
            task: f.ctx.task_id.clone(),
            run: f.ctx.run_id.clone(),
            request: format!("owned-{index}"),
            kind: FailureKind::NoProgress,
            calls: vec![original.clone()],
            diagnostic: "native observation".into(),
            evidence: result.artifact_refs,
        };
        let stopped = hook.success(&mut f.store, event).unwrap();
        assert_eq!(stopped.is_some(), index == 5);
    }
    {
        let history = captured.lock().unwrap();
        assert_eq!(history[0], history[1]);
        assert_ne!(history[1], history[2]);
        assert_eq!(history[2], history[5]);
    }
    assert!(
        d.execute(
            call("close", id, json!({"command":"close"})),
            f.ctx.clone(),
            cancel
        )
        .await
        .unwrap()
        .success
    );
}
