mod support;
use melissa_model_gateway::{ToolCall, tools::ToolDispatcher};
use melissa_repository::{Limits, Repository};
use melissa_web_development::{plan::*, protocol::*, tools::WebDispatcher};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::AtomicBool},
};
use support::*;
const APP: &str = r#"from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,time
receipt=None;writes=0
class A(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def send(self,obj):
  raw=json.dumps(obj).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers()
  try:self.wfile.write(raw)
  except BrokenPipeError:pass
 def do_POST(self):
  global receipt,writes
  body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));writes+=1;receipt={'state':'committed','operation':{'method':'post','path':self.path,'idempotency_key':self.headers['Idempotency-Key'],'request_body':body}}
  time.sleep(.3);self.send({'saved':True})
 def do_GET(self):self.send(receipt)
ThreadingHTTPServer(('127.0.0.1',37641),A).serve_forever()
"#;
fn call(id: &str, session: Option<&str>, operation: Value) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "web_session".into(),
        arguments: json!({"session_id":session,"operation":operation}).to_string(),
    }
}
#[tokio::test]
async fn unresolved_api_write_is_durable_unknown_before_any_next_gateway_turn() {
    let f = Fixture::new(Service::Api, None, &[("app.py", APP)]);
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
    let started = d
        .execute(
            call("start", None, json!({"command":"start"})),
            f.ctx.clone(),
            cancel.clone(),
        )
        .await
        .unwrap();
    let start: Value = serde_json::from_str(&started.content).unwrap();
    let id = start["session_id"].as_str().unwrap();
    let r=d.execute(call("lost",Some(id),json!({"command":"api","request":{"session":"client","method":"post","path":"/save","headers":{"idempotency-key":"owned"},"body":{"value":1},"timeout_ms":50}})),f.ctx.clone(),cancel).await.unwrap();
    assert!(!r.success && r.requires_reconciliation);
    assert_eq!(
        f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
        melissa_local_store::journal::AttemptState::OutcomeUnknown
    );
    assert!(
        d.validate_call(&call("new", None, json!({"command":"start"})))
            .is_err()
    );
}
#[tokio::test]
async fn host_registered_api_proof_runs_inside_same_tool_call_without_another_model_turn() {
    let f = Fixture::new(Service::Api, None, &[("app.py", APP)]);
    let mut d = WebDispatcher::new(
        Repository::open(&f.root(), Limits::default(), vec![]).unwrap(),
        f.store.connect().unwrap(),
        f.catalog.clone(),
        f.policy.clone(),
        f.registration.clone(),
        limits(),
    )
    .unwrap()
    .with_api_reconciliation(vec![ApiReconciliationRule {
        method: Method::Post,
        path: "/save".into(),
        status_path: "/status/{key}".into(),
    }])
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let started = d
        .execute(
            call("start", None, json!({"command":"start"})),
            f.ctx.clone(),
            cancel.clone(),
        )
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&started.content).unwrap();
    let id = v["session_id"].as_str().unwrap();
    let r=d.execute(call("lost",Some(id),json!({"command":"api","request":{"session":"client","method":"post","path":"/save","headers":{"idempotency-key":"owned"},"body":{"value":1},"timeout_ms":50}})),f.ctx.clone(),cancel.clone()).await.unwrap();
    assert!(r.success && !r.requires_reconciliation);
    let v: Value = serde_json::from_str(&r.content).unwrap();
    assert_eq!(v["reply"]["body"]["effect"], "outcome_unknown");
    assert_eq!(v["reconciliation"]["body"]["reconciled"], true);
    assert_eq!(v["reconciliation"]["body"]["automatic_retry"], false);
    let close = d
        .execute(
            call("close", Some(id), json!({"command":"close"})),
            f.ctx.clone(),
            cancel,
        )
        .await
        .unwrap();
    assert!(close.success && !close.requires_reconciliation);
}
#[test]
fn actual_postgres_connection_death_holds_uncertain_writes_and_forbids_replay() {
    let sql = "SELECT pg_terminate_backend(pg_backend_pid())";
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Postgres),
        &[
            ("kill.sql", sql),
            (
                "write.sql",
                "INSERT INTO notes(tenant,text) VALUES('alice','unsafe replay')",
            ),
        ],
    );
    f.registration.statements = BTreeMap::from([
        (
            "kill".into(),
            Statement {
                source_path: "kill.sql".into(),
                source_digest: melissa_web_development::digest(sql.as_bytes()),
            },
        ),
        (
            "write".into(),
            Statement {
                source_path: "write.sql".into(),
                source_digest: melissa_web_development::digest(
                    b"INSERT INTO notes(tenant,text) VALUES('alice','unsafe replay')",
                ),
            },
        ),
    ]);
    let mut s = f.start();
    assert!(
        !s.command(Command::Execute {
            connection: "writer".into(),
            statement: "kill".into(),
            parameters: vec![]
        })
        .unwrap()
        .ok
    );
    assert!(
        s.command(Command::Execute {
            connection: "newwriter".into(),
            statement: "write".into(),
            parameters: vec![]
        })
        .is_err()
    );
    let outcome = s.finish().unwrap();
    assert!(outcome.requires_reconciliation && outcome.cleanup_confirmed);
}
