mod support;
use melissa_web_development::{plan::*, protocol::*, session::WebSession};
use serde_json::{Value, json};
use support::*;

fn pinned(f: &mut Fixture, name: &str, path: &str, sql: &str) {
    std::fs::write(f.root().join(path), sql).unwrap();
    f.registration.statements.insert(
        name.into(),
        Statement {
            source_path: path.into(),
            source_digest: melissa_web_development::digest(sql.as_bytes()),
        },
    );
}
fn execute(statement: &str) -> SqlStep {
    SqlStep::Execute {
        statement: statement.into(),
        parameters: vec![],
    }
}
fn parallel(s: &mut WebSession, scripts: Vec<SqlScript>) -> Value {
    body(s, Command::SqlParallel { scripts })
}
fn script(name: &str, steps: Vec<SqlStep>) -> SqlScript {
    SqlScript {
        connection: name.into(),
        mode: TransactionMode::Serializable,
        steps,
    }
}
#[test]
fn sqlite_and_postgres_cursor_pages_and_query_plans_preserve_all_values() {
    for db in [Database::Sqlite, Database::Postgres] {
        let seed = if matches!(db, Database::Sqlite) {
            "CREATE TABLE page_items(id INTEGER PRIMARY KEY,label TEXT NOT NULL); WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2105) INSERT INTO page_items SELECT x,'item-'||x FROM n;"
        } else {
            "CREATE TABLE page_items(id INTEGER PRIMARY KEY,label TEXT NOT NULL); INSERT INTO page_items SELECT x,'item-'||x FROM generate_series(1,2105) AS x;"
        };
        let f = Fixture::new(Service::Database, Some(db), &[("schema.sql", seed)]);
        let mut s = f.start();
        let plan = body(
            &mut s,
            Command::QueryPlan {
                connection: "plan".into(),
                sql: "SELECT label FROM page_items WHERE id=42".into(),
                parameters: vec![],
            },
        );
        assert!(!plan["rows"].as_array().unwrap().is_empty());
        let mut page = body(
            &mut s,
            Command::Cursor {
                connection: "pages".into(),
                sql: "SELECT id,label FROM page_items ORDER BY id".into(),
                parameters: vec![],
                limit: 700,
            },
        );
        let cursor = page["cursor"].as_str().unwrap().to_owned();
        let mut actual = vec![];
        loop {
            assert_eq!(page["offset"].as_u64().unwrap(), actual.len() as u64);
            actual.extend(page["rows"].as_array().unwrap().clone());
            if page["has_more"] == false {
                break;
            }
            page = body(
                &mut s,
                Command::Fetch {
                    cursor: cursor.clone(),
                    limit: 700,
                },
            );
        }
        assert_eq!(actual.len(), 2105);
        for (i, row) in actual.iter().enumerate() {
            assert_eq!(*row, json!([i + 1, format!("item-{}", i + 1)]));
        }
        assert!(!s.command(Command::Fetch { cursor, limit: 1 }).unwrap().ok);
        assert!(
            !s.command(Command::QueryPlan {
                connection: "plan".into(),
                sql: "DELETE FROM page_items".into(),
                parameters: vec![]
            })
            .unwrap()
            .ok
        );
        assert!(!s.finish().unwrap().requires_reconciliation);
    }
}
#[test]
fn postgres_read_only_transaction_is_the_actual_query_session() {
    let mut f = Fixture::new(Service::Database, Some(Database::Postgres), &[]);
    pinned(
        &mut f,
        "write",
        "write.sql",
        "INSERT INTO notes(tenant,text) VALUES('alice','denied')",
    );
    let mut s = f.start();
    body(
        &mut s,
        Command::Begin {
            connection: "readonly".into(),
            mode: TransactionMode::ReadOnly,
        },
    );
    let q = || Command::Query {
        connection: "readonly".into(),
        sql: "SELECT transaction_timestamp()::text,current_setting('transaction_read_only')".into(),
        parameters: vec![],
    };
    let a = body(&mut s, q());
    std::thread::sleep(std::time::Duration::from_millis(20));
    let b = body(&mut s, q());
    assert_eq!(a["rows"], b["rows"]);
    assert_eq!(a["rows"][0][1], "on");
    assert!(
        !s.command(Command::Execute {
            connection: "readonly".into(),
            statement: "write".into(),
            parameters: vec![]
        })
        .unwrap()
        .ok
    );
    body(
        &mut s,
        Command::Rollback {
            connection: "readonly".into(),
        },
    );
    assert!(!s.finish().unwrap().requires_reconciliation);
}
#[test]
fn postgres_serializable_prevents_real_write_skew_and_never_blindly_retries() {
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Postgres),
        &[(
            "schema.sql",
            "CREATE TABLE balances(id INTEGER PRIMARY KEY,n INTEGER NOT NULL); INSERT INTO balances VALUES(1,0),(2,0);",
        )],
    );
    pinned(&mut f, "read", "read.sql", "SELECT SUM(n) FROM balances");
    pinned(
        &mut f,
        "one",
        "one.sql",
        "UPDATE balances SET n=n+1 WHERE id=1",
    );
    pinned(
        &mut f,
        "two",
        "two.sql",
        "UPDATE balances SET n=n+1 WHERE id=2",
    );
    let mut s = f.start();
    let result = parallel(
        &mut s,
        vec![
            script(
                "first",
                vec![
                    execute("read"),
                    SqlStep::Barrier {},
                    execute("one"),
                    SqlStep::Commit {},
                ],
            ),
            script(
                "second",
                vec![
                    execute("read"),
                    SqlStep::Barrier {},
                    execute("two"),
                    SqlStep::Commit {},
                ],
            ),
        ],
    );
    let rs = result["results"].as_array().unwrap();
    assert_eq!(rs.iter().filter(|r| r["ok"] == true).count(), 1, "{result}");
    assert!(rs.iter().any(|r| r["sqlstate"] == "40001"), "{result}");
    assert!(rs.iter().all(|r| r["automatic_retry"] == false));
    assert_eq!(
        body(
            &mut s,
            Command::Query {
                connection: "check".into(),
                sql: "SELECT SUM(n) FROM balances".into(),
                parameters: vec![]
            }
        )["rows"],
        json!([[1]])
    );
    assert!(!s.finish().unwrap().requires_reconciliation);
}
#[test]
fn postgres_real_deadlock_and_sqlite_writer_lock_are_classified_without_replay() {
    for db in [Database::Postgres, Database::Sqlite] {
        let mut f = Fixture::new(
            Service::Database,
            Some(db),
            &[(
                "schema.sql",
                "CREATE TABLE locks(id INTEGER PRIMARY KEY,n INTEGER NOT NULL); INSERT INTO locks VALUES(1,0),(2,0);",
            )],
        );
        pinned(
            &mut f,
            "one",
            "one.sql",
            "UPDATE locks SET n=n+1 WHERE id=1",
        );
        pinned(
            &mut f,
            "two",
            "two.sql",
            "UPDATE locks SET n=n+1 WHERE id=2",
        );
        let mut s = f.start();
        let mut scripts = vec![
            script(
                "first",
                vec![
                    execute("one"),
                    SqlStep::Barrier {},
                    execute("two"),
                    SqlStep::Commit {},
                ],
            ),
            script(
                "second",
                vec![
                    execute("two"),
                    SqlStep::Barrier {},
                    execute("one"),
                    SqlStep::Commit {},
                ],
            ),
        ];
        if matches!(db, Database::Sqlite) {
            for s in &mut scripts {
                s.mode = TransactionMode::Immediate;
            }
        }
        let result = parallel(&mut s, scripts);
        let rs = result["results"].as_array().unwrap();
        assert!(
            rs.iter().any(|r| if matches!(db, Database::Postgres) {
                r["sqlstate"] == "40P01"
            } else {
                r["sqlite_errorcode"] == 5
            }),
            "{result}"
        );
        let expected = if matches!(db, Database::Postgres) {
            json!([[1, 1], [2, 1]])
        } else {
            json!([[1, 0], [2, 0]])
        };
        assert_eq!(
            body(
                &mut s,
                Command::Query {
                    connection: "check".into(),
                    sql: "SELECT id,n FROM locks ORDER BY id".into(),
                    parameters: vec![]
                }
            )["rows"],
            expected
        );
        assert!(!s.finish().unwrap().requires_reconciliation);
    }
}
#[test]
fn postgres_quoted_procedural_seed_and_comment_hidden_migration_control() {
    let seed = "CREATE TABLE samples(id INT PRIMARY KEY,label TEXT); /* outer /* inner ; */ ; */ INSERT INTO samples VALUES(1,'a;b'); DO $body$ BEGIN INSERT INTO samples VALUES(2,'x;y'); END $body$; CREATE FUNCTION sample_label() RETURNS TEXT LANGUAGE sql AS $$ SELECT 'z;q'::text; $$;";
    let f = Fixture::new(
        Service::Database,
        Some(Database::Postgres),
        &[("schema.sql", seed)],
    );
    let mut s = f.start();
    assert_eq!(
        body(
            &mut s,
            Command::Query {
                connection: "read".into(),
                sql: "SELECT id,label FROM samples ORDER BY id".into(),
                parameters: vec![]
            }
        )["rows"],
        json!([[1, "a;b"], [2, "x;y"]])
    );
    assert_eq!(
        body(
            &mut s,
            Command::Query {
                connection: "read".into(),
                sql: "SELECT sample_label()".into(),
                parameters: vec![]
            }
        )["rows"],
        json!([["z;q"]])
    );
    assert!(!s.finish().unwrap().requires_reconciliation);
}
#[test]
fn exact_api_commit_proof_clears_pending_effect_without_replaying_the_write() {
    let app = r#"from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,time
receipt=None;writes=0
class A(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def send(self,data):
  raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_POST(self):
  global receipt,writes
  payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])));writes+=1
  receipt={'operation':{'method':'post','path':self.path,'idempotency_key':self.headers['Idempotency-Key'],'request_body':payload},'state':'committed'}
  time.sleep(.4)
  try:self.send({'saved':True})
  except BrokenPipeError:pass
 def do_GET(self):self.send(receipt if self.path.startswith('/status/') else {'writes':writes})
ThreadingHTTPServer(('127.0.0.1',37641),A).serve_forever()
"#;
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
        path: "/save".into(),
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
        session: "alice".into(),
        method: Method::Post,
        path: "/save".into(),
        headers: std::collections::BTreeMap::from([(
            "idempotency-key".into(),
            "exact-owned-1".into(),
        )]),
        body: Some(json!({"text":"hello"})),
        timeout_ms: 50,
    };
    let reply = s
        .command(Command::Api {
            request: request.clone(),
        })
        .unwrap();
    let sequence = reply.seq;
    assert_eq!(reply.body.unwrap()["effect"], "outcome_unknown");
    assert!(s.command(Command::Api { request }).is_err());
    assert!(
        s.command(Command::ReconcileApi {
            sequence: sequence + 10
        })
        .is_err()
    );
    assert_eq!(
        body(&mut s, Command::ReconcileApi { sequence })["reconciled"],
        true
    );
    let read = body(
        &mut s,
        Command::Api {
            request: ApiRequest {
                session: "alice".into(),
                method: Method::Get,
                path: "/count".into(),
                headers: Default::default(),
                body: None,
                timeout_ms: 1000,
            },
        },
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&hex(read["body_hex"].as_str().unwrap())).unwrap()["writes"],
        1
    );
    let out = s.finish().unwrap();
    assert!(
        !out.requires_reconciliation && !out.application_outcome_unknown,
        "{out:?}"
    );
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sqlite_relational_legacy_values_survive_forward_down_and_failed_data_migration() {
    let seed = "CREATE TABLE parent(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE); CREATE TABLE child(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL REFERENCES parent(id),cents INTEGER NOT NULL CHECK(cents>=0)); INSERT INTO parent VALUES(1,'Ada'),(2,'Deniz'); INSERT INTO child VALUES(1,1,1205),(2,2,0),(3,1,999);";
    let up = "ALTER TABLE child ADD COLUMN label TEXT NOT NULL DEFAULT 'legacy';";
    let fail = "UPDATE child SET cents=cents+100; INSERT INTO child VALUES(9,999,1,'invalid');";
    let down = "ALTER TABLE child DROP COLUMN label;";
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Sqlite),
        &[
            ("schema.sql", seed),
            ("up.sql", up),
            ("fail.sql", fail),
            ("down.sql", down),
        ],
    );
    let mut probe = f.start();
    let baseline = body(
        &mut probe,
        Command::Profile {
            connection: "meta".into(),
        },
    )["schema_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(probe.finish().unwrap().success);
    f.ctx.invocation_id.push_str("-next");
    f.ctx.attempt_id.push_str("-next");
    f.ctx.request_id.push_str("-next");
    for (name, path, sql, base) in [
        (
            "up",
            "up.sql",
            up,
            Baseline::Schema {
                digest: baseline.clone(),
            },
        ),
        (
            "failure",
            "fail.sql",
            fail,
            Baseline::After { name: "up".into() },
        ),
        (
            "down",
            "down.sql",
            down,
            Baseline::After {
                name: "failure".into(),
            },
        ),
    ] {
        f.registration.migrations.insert(
            name.into(),
            Migration {
                source_path: path.into(),
                source_digest: melissa_web_development::digest(sql.as_bytes()),
                baseline: base,
                transactional: true,
            },
        );
    }
    let mut s = f.start();
    let q = || {
        Command::Query{connection:"check".into(),sql:"SELECT c.id,p.name,c.cents FROM child c JOIN parent p ON p.id=c.parent_id ORDER BY c.id".into(),parameters:vec![]}
    };
    let original = body(&mut s, q())["rows"].clone();
    assert_eq!(
        original,
        json!([[1, "Ada", 1205], [2, "Deniz", 0], [3, "Ada", 999]])
    );
    body(&mut s, Command::Migration { name: "up".into() });
    let failed = body(
        &mut s,
        Command::Migration {
            name: "failure".into(),
        },
    );
    assert_eq!(failed["failed"], true);
    assert_eq!(failed["rolled_back"], true);
    assert_eq!(body(&mut s, q())["rows"], original);
    assert_eq!(
        body(
            &mut s,
            Command::Migration {
                name: "down".into()
            }
        )["after"],
        baseline
    );
    assert_eq!(body(&mut s, q())["rows"], original);
    assert_eq!(
        body(
            &mut s,
            Command::Profile {
                connection: "meta".into()
            }
        )["foreign_keys"]["rows"],
        json!([])
    );
    assert!(s.finish().unwrap().success);
}
