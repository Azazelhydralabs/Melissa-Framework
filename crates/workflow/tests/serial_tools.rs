use melissa_model_gateway::{
    ErrorKind, GatewayError, Result, ToolCall, ToolDefinition,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use melissa_workflow::serial_tools::*;
use serde_json::json;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
struct Effect {
    changed: bool,
    calls: Arc<AtomicUsize>,
}
impl ToolDispatcher for Effect {
    fn definitions(&self) -> Vec<BoundTool> {
        vec![BoundTool {
            canonical_id: "fs.read".into(),
            definition: ToolDefinition {
                name: "owned".into(),
                description: if self.changed {
                    "changed authority declaration"
                } else {
                    "owned original declaration"
                }
                .into(),
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(GatewayError::new(
                ErrorKind::Tool,
                "effect occurred; never retry automatically",
            ))
        })
    }
}
fn call() -> ToolCall {
    ToolCall {
        id: "owned_call".into(),
        name: "owned".into(),
        arguments: "{}".into(),
    }
}
fn ctx() -> ToolContext {
    ToolContext {
        task_id: "task:serial".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "serial_test".into(),
        request_id: "native:test".into(),
        invocation_id: "inv:test".into(),
        attempt_id: "attempt:test".into(),
        generation: 1,
    }
}
fn fixture(
    gate: SharedToolGate,
) -> (
    ReloadingDispatcher,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let changed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let opens = Arc::new(AtomicUsize::new(0));
    let c = changed.clone();
    let n = calls.clone();
    let o = opens.clone();
    let factory: ReloadFactory = Arc::new(move || {
        o.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Effect {
            changed: c.load(Ordering::Acquire),
            calls: n.clone(),
        }))
    });
    (
        ReloadingDispatcher::new(
            "task:serial".into(),
            "melissa.code.implementer".into(),
            gate,
            factory,
        )
        .unwrap(),
        changed,
        calls,
        opens,
    )
}
#[tokio::test]
async fn changed_fresh_tool_declaration_is_denied_before_any_effect() {
    let (mut d, changed, calls, _) = fixture(Arc::new(tokio::sync::Mutex::new(())));
    changed.store(true, Ordering::Release);
    let e = d
        .execute(call(), ctx(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Authorization);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn cancelled_queue_does_not_wait_for_writer_or_prepare_another_effect() {
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let held = gate.lock().await;
    let (mut d, _, calls, opens) = fixture(gate.clone());
    let flag = Arc::new(AtomicBool::new(false));
    let c = flag.clone();
    let work = tokio::spawn(async move { d.execute(call(), ctx(), c).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    flag.store(true, Ordering::Release);
    let e = tokio::time::timeout(Duration::from_millis(200), work)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Cancelled);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    drop(held);
}
#[tokio::test]
async fn effect_error_is_never_replayed_and_foreign_root_or_profile_never_executes() {
    let (mut d, _, calls, _) = fixture(Arc::new(tokio::sync::Mutex::new(())));
    for foreign in ["task", "profile"] {
        let mut c = ctx();
        if foreign == "task" {
            c.task_id = "task:foreign".into()
        } else {
            c.profile_id = "melissa.code.test-engineer".into()
        }
        assert_eq!(
            d.execute(call(), c, Arc::new(AtomicBool::new(false)))
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Authorization
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        d.execute(call(), ctx(), Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Tool
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
