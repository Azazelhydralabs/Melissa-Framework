mod support;
use melissa_web_development::{plan::*, protocol::*, session::*};
use serde_json::json;
use std::collections::BTreeMap;
use support::*;
#[test]
fn foreign_commit_proof_and_oversized_write_response_never_clear_unknown_effects() {
    let app = r#"from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,time
class A(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def send(self,data):
  raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers()
  try:self.wfile.write(raw)
  except BrokenPipeError:pass
 def do_POST(self):
  self.rfile.read(int(self.headers['Content-Length']))
  if self.path=='/oversized':return self.send({'committed':True,'payload':'x'*1100000})
  time.sleep(.3);self.send({'committed':True})
 def do_GET(self):self.send({'state':'committed','operation':{'method':'post','path':'/another-operation','idempotency_key':'owned','request_body':{'value':1}}})
ThreadingHTTPServer(('127.0.0.1',37641),A).serve_forever()
"#;
    for path in ["/save", "/oversized"] {
        let f = Fixture::new(Service::Api, None, &[("app.py", app)]);
        let plan = WebPlan::prepare(
            &f.repo,
            &f.repo.snapshot(&f.cancelled).unwrap(),
            f.registration.clone(),
            limits(),
            &f.cancelled,
        )
        .unwrap()
        .with_api_reconciliation(vec![ApiReconciliationRule {
            method: Method::Post,
            path: path.into(),
            status_path: "/status/{key}".into(),
        }])
        .unwrap();
        let mut s = WebSession::start(
            f.repo.clone(),
            f.store.connect().unwrap(),
            f.catalog.clone(),
            f.policy.clone(),
            plan,
            f.ctx.clone(),
            f.cancelled.clone(),
            f.revoked.clone(),
        )
        .unwrap();
        let request = ApiRequest {
            session: "client".into(),
            method: Method::Post,
            path: path.into(),
            headers: BTreeMap::from([("idempotency-key".into(), "owned".into())]),
            body: Some(json!({"value":1})),
            timeout_ms: if path == "/save" { 50 } else { 3000 },
        };
        let reply = s
            .command(Command::Api {
                request: request.clone(),
            })
            .unwrap();
        assert_eq!(reply.body.unwrap()["effect"], "outcome_unknown");
        assert!(
            !s.command(Command::ReconcileApi {
                sequence: reply.seq
            })
            .unwrap()
            .ok
        );
        assert!(s.command(Command::Api { request }).is_err());
        let outcome = s.finish().unwrap();
        assert!(
            outcome.requires_reconciliation
                && outcome.application_outcome_unknown
                && outcome.cleanup_confirmed
        );
        assert_eq!(
            f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
            melissa_local_store::journal::AttemptState::OutcomeUnknown
        );
    }
}
