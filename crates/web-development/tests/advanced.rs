mod support;
use melissa_web_development::{
    plan::{App, Baseline, Database, Migration, WebPlan},
    protocol::*,
    session::WebSession,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use support::*;

fn registered(sql: &str, baseline: Baseline, transactional: bool, path: &str) -> Migration {
    Migration {
        source_path: path.into(),
        source_digest: melissa_web_development::digest(sql.as_bytes()),
        baseline,
        transactional,
    }
}
fn next(f: &mut Fixture) {
    f.ctx.invocation_id.push('x');
    f.ctx.attempt_id.push('x');
    f.ctx.request_id.push('x');
}
fn baseline(f: &mut Fixture) -> String {
    let mut s = f.start();
    let result = body(
        &mut s,
        Command::Profile {
            connection: "read".into(),
        },
    )["schema_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!s.finish().unwrap().requires_reconciliation);
    next(f);
    result
}
#[test]
fn sqlite_forward_backwards_atomic_failure_and_wrong_baseline() {
    let up = "ALTER TABLE notes ADD COLUMN tag TEXT NOT NULL DEFAULT 'legacy';";
    let down = "ALTER TABLE notes DROP COLUMN tag;";
    let fail = "ALTER TABLE notes ADD COLUMN temporary TEXT; INSERT INTO absent_table VALUES(1);";
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Sqlite),
        &[("up.sql", up), ("down.sql", down), ("fail.sql", fail)],
    );
    let initial = baseline(&mut f);
    f.registration.migrations.insert(
        "wrong".into(),
        registered(
            up,
            Baseline::Schema {
                digest: format!("sha256:{}", "f".repeat(64)),
            },
            true,
            "up.sql",
        ),
    );
    f.registration.migrations.insert(
        "up".into(),
        registered(
            up,
            Baseline::Schema {
                digest: initial.clone(),
            },
            true,
            "up.sql",
        ),
    );
    f.registration.migrations.insert(
        "down".into(),
        registered(
            down,
            Baseline::After { name: "up".into() },
            true,
            "down.sql",
        ),
    );
    f.registration.migrations.insert(
        "failure".into(),
        registered(
            fail,
            Baseline::After {
                name: "down".into(),
            },
            true,
            "fail.sql",
        ),
    );
    let mut s = f.start();
    assert!(
        !s.command(Command::Migration {
            name: "wrong".into()
        })
        .unwrap()
        .ok
    );
    let up = body(&mut s, Command::Migration { name: "up".into() });
    assert_eq!(up["applied"], 1);
    assert_ne!(up["after"], initial);
    assert_eq!(
        body(
            &mut s,
            Command::Query {
                connection: "read".into(),
                sql: "SELECT tag FROM notes".into(),
                parameters: vec![]
            }
        )["columns"],
        json!(["tag"])
    );
    assert_eq!(
        body(
            &mut s,
            Command::Migration {
                name: "down".into()
            }
        )["after"],
        initial
    );
    let failed = body(
        &mut s,
        Command::Migration {
            name: "failure".into(),
        },
    );
    assert_eq!(failed["failed"], true);
    assert_eq!(failed["rolled_back"], true);
    assert_eq!(failed["after"], initial);
    assert!(!s.finish().unwrap().requires_reconciliation);
}
#[test]
fn nontransactional_partial_migration_requires_observation_and_registered_forward_recovery() {
    let partial = "ALTER TABLE notes ADD COLUMN tag TEXT; INSERT INTO absent_table VALUES(1);";
    let recover = "ALTER TABLE notes DROP COLUMN tag;";
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Sqlite),
        &[("partial.sql", partial), ("recover.sql", recover)],
    );
    let initial = baseline(&mut f);
    f.registration.migrations.insert(
        "partial".into(),
        registered(
            partial,
            Baseline::Schema {
                digest: initial.clone(),
            },
            false,
            "partial.sql",
        ),
    );
    f.registration.migrations.insert(
        "recover".into(),
        registered(
            recover,
            Baseline::After {
                name: "partial".into(),
            },
            true,
            "recover.sql",
        ),
    );
    let mut s = f.start();
    let failed = body(
        &mut s,
        Command::Migration {
            name: "partial".into(),
        },
    );
    assert_eq!(failed["requires_reconciliation"], true);
    assert_eq!(failed["applied_before_error"], 1);
    assert_ne!(failed["after"], initial);
    let observed = body(
        &mut s,
        Command::Profile {
            connection: "observe".into(),
        },
    );
    assert_eq!(observed["schema_digest"], failed["after"]);
    assert_eq!(
        body(
            &mut s,
            Command::Migration {
                name: "recover".into()
            }
        )["after"],
        initial
    );
    assert!(!s.finish().unwrap().requires_reconciliation);
}
#[test]
fn postgres_real_engine_constraints_and_readonly_role() {
    let schema = "CREATE TABLE accounts(id INTEGER PRIMARY KEY,balance INTEGER NOT NULL CHECK(balance>=0)); INSERT INTO accounts VALUES(1,100),(2,200);";
    let f = Fixture::new(
        Service::Database,
        Some(Database::Postgres),
        &[("schema.sql", schema)],
    );
    let mut s = f.start();
    assert!(s.last_reply().unwrap().ok, "{:?}", s.last_reply());
    let result = body(
        &mut s,
        Command::Query {
            connection: "read".into(),
            sql: "SELECT id,balance FROM accounts ORDER BY id".into(),
            parameters: vec![],
        },
    );
    assert_eq!(result["rows"], json!([[1, 100], [2, 200]]));
    for sql in [
        "DELETE FROM accounts",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_write_file('/work/escape','x',false)",
    ] {
        assert!(
            !s.command(Command::Query {
                connection: "deny".into(),
                sql: sql.into(),
                parameters: vec![]
            })
            .unwrap()
            .ok
        );
    }
    let profile = body(
        &mut s,
        Command::Profile {
            connection: "inspect".into(),
        },
    );
    assert!(
        profile["schema_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let out = s.finish().unwrap();
    assert!(
        out.cleanup_confirmed && !out.requires_reconciliation,
        "{:?}",
        out.executor_error
    );
}
#[test]
fn source_change_and_revocation_stop_existing_session() {
    let f = Fixture::new(Service::Database, Some(Database::Sqlite), &[]);
    let mut s = f.start();
    std::fs::write(f.root().join("dirty.bin"), b"new user edit").unwrap();
    assert!(
        s.command(Command::Profile {
            connection: "read".into()
        })
        .is_err()
    );
    let out = s.finish().unwrap();
    assert!(out.cleanup_confirmed);
    assert!(!out.source_current);
    assert!(out.requires_reconciliation);
    let f = Fixture::new(Service::Database, Some(Database::Sqlite), &[]);
    let mut s = f.start();
    f.revoked.store(true, Ordering::Release);
    assert!(
        s.command(Command::Profile {
            connection: "read".into()
        })
        .is_err()
    );
    assert!(s.finish().unwrap().cleanup_confirmed);
}
#[test]
fn wrong_role_resource_and_cancel_are_rejected_before_native_dispatch() {
    let f = Fixture::new(Service::Browser, None, &[]);
    let mut policy = f.policy.clone();
    policy.profile_id = "melissa.code.backend".into();
    let source = f.repo.snapshot(&AtomicBool::new(false)).unwrap();
    let plan = WebPlan::prepare(
        &f.repo,
        &source,
        f.registration.clone(),
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        WebSession::start(
            f.repo.clone(),
            f.store.connect().unwrap(),
            f.catalog.clone(),
            policy,
            plan,
            f.ctx.clone(),
            Arc::new(AtomicBool::new(false)),
            f.revoked.clone()
        )
        .is_err()
    );
    assert!(f.store.journal().attempt(&f.ctx.attempt_id).is_err());
    let mut policy = f.policy.clone();
    policy.resource_id = "workspace:foreign".into();
    let plan = WebPlan::prepare(
        &f.repo,
        &source,
        f.registration.clone(),
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        WebSession::start(
            f.repo.clone(),
            f.store.connect().unwrap(),
            f.catalog.clone(),
            policy,
            plan,
            f.ctx.clone(),
            Arc::new(AtomicBool::new(false)),
            f.revoked.clone()
        )
        .is_err()
    );
    assert!(f.store.journal().attempt(&f.ctx.attempt_id).is_err());
    let plan = WebPlan::prepare(
        &f.repo,
        &source,
        f.registration.clone(),
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        WebSession::start(
            f.repo.clone(),
            f.store.connect().unwrap(),
            f.catalog.clone(),
            f.policy.clone(),
            plan,
            f.ctx.clone(),
            Arc::new(AtomicBool::new(true)),
            f.revoked.clone()
        )
        .is_err()
    );
    assert!(f.store.journal().attempt(&f.ctx.attempt_id).is_err());
}
#[test]
fn javascript_and_typescript_run_real_local_api() {
    let js = "const http=require('node:http'); http.createServer((q,r)=>{r.setHeader('content-type','application/json');r.end(JSON.stringify({method:q.method,ok:true}));}).listen(Number(process.env.PORT),'127.0.0.1');";
    let typed_js=js.replace("(q,r)=>","(q:{method:string},r:{setHeader:(key:string,value:string)=>void,end:(text:string)=>void})=>");
    let ts = format!(
        "declare const require:any; declare const process:any; const marker:number=7; {typed_js}"
    );
    for (entry, source, app) in [
        (
            "app.cjs",
            js.to_string(),
            App::JavaScript {
                entry: "app.cjs".into(),
            },
        ),
        (
            "app.ts",
            ts,
            App::TypeScript {
                entry: "app.ts".into(),
            },
        ),
    ] {
        let mut f = Fixture::new(Service::Api, None, &[(entry, &source)]);
        f.registration.app = Some(app);
        let mut s = f.start();
        assert!(s.last_reply().unwrap().ok, "{:?}", s.last_reply());
        let request = ApiRequest {
            session: "client".into(),
            method: Method::Get,
            path: "/".into(),
            headers: BTreeMap::new(),
            body: None,
            timeout_ms: 2000,
        };
        assert_eq!(body(&mut s, Command::Api { request })["status"], 200);
        assert!(!s.finish().unwrap().requires_reconciliation);
    }
}
