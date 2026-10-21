mod support;
use melissa_model_gateway::{ToolCall, tools::ToolDispatcher};
use melissa_repository::{Limits, Repository};
use melissa_web_development::{plan::Database, protocol::Service, tools::WebDispatcher};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicBool};
use support::*;
fn call(value: Value) -> ToolCall {
    ToolCall {
        id: "call:web-test".into(),
        name: "web_session".into(),
        arguments: value.to_string(),
    }
}
#[tokio::test]
async fn actual_gateway_dispatcher_binds_handle_to_run_and_closes_native_attempt() {
    let f = Fixture::new(Service::Database, Some(Database::Sqlite), &[]);
    let repo = Repository::open(&f.root(), Limits::default(), vec![]).unwrap();
    let mut d = WebDispatcher::new(
        repo,
        f.store.connect().unwrap(),
        f.catalog.clone(),
        f.policy.clone(),
        f.registration.clone(),
        limits(),
    )
    .unwrap();
    assert_eq!(d.definitions()[0].canonical_id, "data.profile");
    let no = Arc::new(AtomicBool::new(false));
    let start = call(json!({"session_id":null,"operation":{"command":"start"}}));
    d.validate_call(&start).unwrap();
    let r = d.execute(start, f.ctx.clone(), no.clone()).await.unwrap();
    assert!(r.success && !r.requires_reconciliation);
    let v: Value = serde_json::from_str(&r.content).unwrap();
    let handle = v["session_id"].as_str().unwrap();
    let foreign = call(
        json!({"session_id":"web:foreign","operation":{"command":"profile","connection":"read"}}),
    );
    assert!(d.validate_call(&foreign).is_err());
    let request = call(
        json!({"session_id":handle,"operation":{"command":"query","connection":"read","sql":"SELECT COUNT(*) FROM notes","parameters":[]}}),
    );
    let mut ctx = f.ctx.clone();
    ctx.run_id = "run:foreign".into();
    assert!(d.execute(request.clone(), ctx, no.clone()).await.is_err());
    let r = d.execute(request, f.ctx.clone(), no.clone()).await.unwrap();
    assert!(r.success);
    let v: Value = serde_json::from_str(&r.content).unwrap();
    assert_eq!(v["reply"]["body"]["rows"], json!([[0]]));
    let close = call(json!({"session_id":handle,"operation":{"command":"close"}}));
    let r = d.execute(close.clone(), f.ctx.clone(), no).await.unwrap();
    assert!(r.success && !r.requires_reconciliation);
    assert!(d.validate_call(&close).is_err());
    assert_eq!(
        f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
        melissa_local_store::journal::AttemptState::Succeeded
    );
}

#[tokio::test]
async fn actual_adapter_death_is_durable_unknown_before_gateway_can_retry() {
    let source=include_str!("fixtures/app.py").replace("    def do_GET(self):\n","    def do_GET(self):\n        if self.path=='/disconnect':os.kill(os.getppid(),9);return\n");
    let f = Fixture::new(Service::Api, None, &[("app.py", &source)]);
    let repo = Repository::open(&f.root(), Limits::default(), vec![]).unwrap();
    let mut d = WebDispatcher::new(
        repo,
        f.store.connect().unwrap(),
        f.catalog.clone(),
        f.policy.clone(),
        f.registration.clone(),
        limits(),
    )
    .unwrap();
    let no = Arc::new(AtomicBool::new(false));
    let result = d
        .execute(
            call(json!({"session_id":null,"operation":{"command":"start"}})),
            f.ctx.clone(),
            no.clone(),
        )
        .await
        .unwrap();
    assert!(result.success);
    let value: Value = serde_json::from_str(&result.content).unwrap();
    let handle = value["session_id"].as_str().unwrap();
    let request = call(
        json!({"session_id":handle,"operation":{"command":"api","request":{"session":"client","method":"get","path":"/disconnect","headers":{},"body":null,"timeout_ms":2000}}}),
    );
    let result = d.execute(request, f.ctx.clone(), no).await.unwrap();
    assert!(!result.success && result.requires_reconciliation);
    assert_eq!(
        serde_json::from_str::<Value>(&result.content).unwrap()["cleanup_confirmed"],
        true
    );
    assert_eq!(
        f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
        melissa_local_store::journal::AttemptState::OutcomeUnknown
    );
    assert_eq!(
        f.store
            .journal()
            .task(&f.ctx.task_id)
            .unwrap()
            .record
            .unknown_invocation_id,
        Some(f.ctx.invocation_id.clone())
    );
    assert!(
        d.validate_call(&call(
            json!({"session_id":null,"operation":{"command":"start"}})
        ))
        .is_err()
    );
}
