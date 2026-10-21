#![allow(dead_code, unused_imports)]
//! Native loopback protocol/regression; no live service or private oracle.
include!("../../workflow/tests/common/gateway.rs");
fn output() -> Value {
    json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false})
}
struct Sink {
    effects: Arc<Mutex<Vec<String>>>,
    provide: bool,
    cancel_on_submit: bool,
}
impl Sink {
    fn new() -> Self {
        Self {
            effects: Arc::new(Mutex::new(Vec::new())),
            provide: true,
            cancel_on_submit: false,
        }
    }
}
impl ToolDispatcher for Sink {
    fn definitions(&self) -> Vec<BoundTool> {
        let mut d = vec![BoundTool {
            canonical_id: "fs.read".into(),
            definition: ToolDefinition {
                name: "source".into(),
                description: "owned observed source".into(),
                parameters: json!({"type":"object","properties":{},"additionalProperties":false}),
                strict: false,
            },
        }];
        if self.provide {
            d.push(BoundTool {
                canonical_id: "evidence.attach".into(),
                definition: ToolDefinition {
                    name: "submit_result".into(),
                    description: "data-only candidate submission".into(),
                    parameters: json!({"type":"object"}),
                    strict: false,
                },
            });
        }
        d
    }
    fn validate_call(&self, _: &ToolCall) -> Result<()> {
        Ok(())
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        _: ToolContext,
        flag: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecution>> + Send + 'a>> {
        Box::pin(async move {
            self.effects.lock().unwrap().push(call.name.clone());
            if self.cancel_on_submit && call.name == "submit_result" {
                flag.store(true, Ordering::Release);
            }
            Ok(ToolExecution {
                content: json!({"candidate_received":true,"task_accepted":false}).to_string(),
                success: true,
                cancelled: false,
                requires_reconciliation: false,
                artifact_refs: vec![],
            })
        })
    }
}
fn typed(run: &str) -> RunSpec {
    let mut s = spec(run);
    s.output_schema = Some(output());
    s
}
#[tokio::test]
async fn typed_submission_finishes_after_one_owned_call_preserving_original_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let args = "{ \"value\": 19 }";
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "submit",
        "submit_result",
        args,
    )]))])
    .await;
    let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy())
        .with_candidate_submission_tool("submit_result")
        .unwrap();
    let mut sink = Sink::new();
    let r = gateway
        .run(
            &typed("typed_submission"),
            &mut sink,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.answer.as_deref(), Some(args));
    assert_eq!(r.request_ids.len(), 1);
    assert_eq!(r.tool_calls, 1);
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert!(!r.task_accepted && !r.requires_reconciliation);
    assert_eq!(
        gateway.store().journal().task(TASK).unwrap().record.state,
        TaskState::Running
    );
}
#[tokio::test]
async fn legacy_default_never_turns_a_tool_call_into_a_final_answer() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "submit",
            "submit_result",
            "{\"value\":1}",
        )])),
        HttpPlan::sse(text_response("{\"value\":2}", false, true)),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy());
    let mut sink = Sink::new();
    let r = gateway
        .run(
            &typed("legacy_submission"),
            &mut sink,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.answer.as_deref(), Some("{\"value\":2}"));
    assert_eq!(r.request_ids.len(), 2);
}
#[tokio::test]
async fn prior_success_and_exact_output_schema_are_enforced_before_submission_effects() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[(
            "early",
            "submit_result",
            "{\"value\":1}",
        )])),
        HttpPlan::sse(tool_response(&[("source", "source", "{}")])),
        HttpPlan::sse(tool_response(&[(
            "bad",
            "submit_result",
            "{\"value\":1,\"extra\":true}",
        )])),
        HttpPlan::sse(tool_response(&[("good", "submit_result", "{\"value\":3}")])),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy())
        .with_candidate_submission_tool("submit_result")
        .unwrap();
    let mut sink = Sink::new();
    let mut s = typed("typed_requirements");
    s.required_tool_names = BTreeSet::from(["source".into(), "submit_result".into()]);
    let r = gateway
        .run(&s, &mut sink, Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(r.request_ids.len(), 4);
    assert_eq!(
        *sink.effects.lock().unwrap(),
        vec!["source", "submit_result"]
    );
    assert_eq!(r.answer.as_deref(), Some("{\"value\":3}"));
}
#[tokio::test]
async fn a_submission_batch_cannot_execute_any_peer_effect() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![
        HttpPlan::sse(tool_response(&[
            ("submit", "submit_result", "{\"value\":1}"),
            ("peer", "source", "{}"),
        ])),
        HttpPlan::sse(tool_response(&[("good", "submit_result", "{\"value\":2}")])),
    ])
    .await;
    let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy())
        .with_candidate_submission_tool("submit_result")
        .unwrap();
    let mut sink = Sink::new();
    let r = gateway
        .run(
            &typed("typed_batch"),
            &mut sink,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::FinalCandidate);
    assert_eq!(*sink.effects.lock().unwrap(), vec!["submit_result"]);
    assert_eq!(r.request_ids.len(), 2);
}
#[tokio::test]
async fn missing_schema_or_tool_never_dispatches_and_opt_in_text_cannot_finalize() {
    for mode in ["schema", "tool", "text"] {
        let dir = tempfile::tempdir().unwrap();
        let http = http_fixture(vec![HttpPlan::sse(text_response(
            "{\"value\":1}",
            false,
            true,
        ))])
        .await;
        let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy())
            .with_candidate_submission_tool("submit_result")
            .unwrap();
        let mut sink = Sink::new();
        let mut s = typed("typed_missing");
        if mode == "schema" {
            s.output_schema = None;
        }
        if mode == "tool" {
            sink.provide = false;
        }
        let r = gateway
            .run(&s, &mut sink, Arc::new(AtomicBool::new(false)))
            .await;
        if mode == "text" {
            assert_eq!(r.unwrap().status, RunStatus::NoAction);
            assert_eq!(http.requests.load(Ordering::SeqCst), 1);
        } else {
            assert!(r.is_err());
            assert_eq!(http.requests.load(Ordering::SeqCst), 0);
        }
        assert!(sink.effects.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn cancellation_after_submission_observation_never_accepts_a_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let http = http_fixture(vec![HttpPlan::sse(tool_response(&[(
        "submit",
        "submit_result",
        "{\"value\":1}",
    )]))])
    .await;
    let mut gateway = gateway(store(&dir.path().join("s"), 1000000), &http, policy())
        .with_candidate_submission_tool("submit_result")
        .unwrap();
    let mut sink = Sink::new();
    sink.cancel_on_submit = true;
    let r = gateway
        .run(
            &typed("typed_cancel"),
            &mut sink,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(r.status, RunStatus::Cancelled);
    assert!(r.answer.is_none());
    assert!(!r.task_accepted);
}
