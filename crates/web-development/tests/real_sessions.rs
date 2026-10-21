mod support;
use melissa_web_development::plan::{Database, Statement};
use melissa_web_development::protocol::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use support::*;
fn api(session: &str, method: Method, path: &str, data: Option<Value>) -> ApiRequest {
    ApiRequest {
        session: session.into(),
        method,
        path: path.into(),
        body: data,
        headers: BTreeMap::new(),
        timeout_ms: 2000,
    }
}
#[test]
fn real_browser_keyboard_responsive_screenshot_and_backend_persistence() {
    let f = Fixture::new(Service::Browser, Some(Database::Sqlite), &[]);
    let mut s = f.start();
    assert!(s.last_reply().unwrap().ok);
    body(
        &mut s,
        Command::Navigate {
            page: "main".into(),
            path: "/".into(),
        },
    );
    body(
        &mut s,
        Command::Fill {
            page: "main".into(),
            selector: "#user".into(),
            value: "alice".into(),
        },
    );
    body(
        &mut s,
        Command::Press {
            page: "main".into(),
            selector: "#user".into(),
            key: "Enter".into(),
        },
    );
    body(
        &mut s,
        Command::Wait {
            page: "main".into(),
            selector: "#notes:not([hidden])".into(),
            state: "visible".into(),
            timeout_ms: 5000,
        },
    );
    let before = body(
        &mut s,
        Command::Inspect {
            page: "main".into(),
        },
    );
    assert!(before["dom"].as_str().unwrap().contains("No notes yet"));
    body(
        &mut s,
        Command::Wait {
            page: "main".into(),
            selector: "#login".into(),
            state: "hidden".into(),
            timeout_ms: 1000,
        },
    );
    assert!(
        !before["aria"].as_str().unwrap().contains("Sign in"),
        "the login form must be hidden in the rendered accessibility tree"
    );
    assert_eq!(before["layout"]["focus"], "text");
    body(
        &mut s,
        Command::Fill {
            page: "main".into(),
            selector: "#text".into(),
            value: "persisted from keyboard".into(),
        },
    );
    body(
        &mut s,
        Command::Press {
            page: "main".into(),
            selector: "#text".into(),
            key: "Enter".into(),
        },
    );
    body(
        &mut s,
        Command::Wait {
            page: "main".into(),
            selector: "#items li".into(),
            state: "visible".into(),
            timeout_ms: 5000,
        },
    );
    for width in [360, 1440] {
        body(
            &mut s,
            Command::Viewport {
                page: "main".into(),
                width,
                height: 800,
            },
        );
        let r = body(
            &mut s,
            Command::Inspect {
                page: "main".into(),
            },
        );
        assert!(r["layout"]["scrollWidth"].as_u64().unwrap() <= width as u64);
        assert!(
            r["aria"]
                .as_str()
                .unwrap()
                .contains("persisted from keyboard")
        );
    }
    let png = body(
        &mut s,
        Command::Screenshot {
            page: "main".into(),
        },
    );
    assert!(
        png["png_hex"]
            .as_str()
            .unwrap()
            .starts_with("89504e470d0a1a0a")
    );
    // Reload performs a new server/database read rather than retaining DOM state.
    body(
        &mut s,
        Command::Navigate {
            page: "main".into(),
            path: "/".into(),
        },
    );
    body(
        &mut s,
        Command::Fill {
            page: "main".into(),
            selector: "#user".into(),
            value: "alice".into(),
        },
    );
    body(
        &mut s,
        Command::Click {
            page: "main".into(),
            selector: "#sign-in".into(),
        },
    );
    body(
        &mut s,
        Command::Wait {
            page: "main".into(),
            selector: "#items li".into(),
            state: "visible".into(),
            timeout_ms: 5000,
        },
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "main".into()
            }
        )["dom"]
            .as_str()
            .unwrap()
            .contains("persisted from keyboard")
    );
    let out = s.finish().unwrap();
    let wire = String::from_utf8_lossy(&out.worker.as_ref().unwrap().stdout);
    assert!(
        wire.lines()
            .filter_map(|s| serde_json::from_str::<Value>(s).ok())
            .any(|v| v["parts"].as_u64().is_some_and(|n| n > 1)),
        "actual trace must cross the legacy 64KiB transport frame boundary"
    );
    assert!(out.cleanup_confirmed && !out.requires_reconciliation && out.source_current);
    assert!(!out.task_completed && !out.protected_acceptance);
    assert_eq!(
        std::fs::read(f.root().join("dirty.bin")).unwrap(),
        b"KEEP\r\nuser\0work"
    );
    assert_eq!(
        f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
        melissa_local_store::journal::AttemptState::Succeeded
    );
}

#[test]
fn concurrent_idempotency_invalid_input_and_unknown_write_no_replay() {
    let f = Fixture::new(Service::Api, Some(Database::Sqlite), &[]);
    let mut s = f.start();
    let requests = (0..8)
        .map(|i| {
            let mut r = api(
                &format!("client{i}"),
                Method::Post,
                "/api/notes",
                Some(json!({"text":"concurrent"})),
            );
            r.headers
                .insert("authorization".into(), "Bearer alice".into());
            r.headers.insert("idempotency-key".into(), "one-key".into());
            r
        })
        .collect();
    let responses = body(&mut s, Command::ApiConcurrent { requests });
    let responses = responses["responses"].as_array().unwrap();
    assert_eq!(responses.iter().filter(|r| r["status"] == 201).count(), 1);
    assert_eq!(responses.iter().filter(|r| r["status"] == 200).count(), 7);
    let mut invalid = api(
        "invalid",
        Method::Post,
        "/api/notes",
        Some(json!({"text":""})),
    );
    invalid
        .headers
        .insert("authorization".into(), "Bearer alice".into());
    invalid
        .headers
        .insert("idempotency-key".into(), "invalid".into());
    assert_eq!(
        body(&mut s, Command::Api { request: invalid })["status"],
        422
    );
    let mut lost = api(
        "lost",
        Method::Post,
        "/api/notes?lose_response=1",
        Some(json!({"text":"committed before response loss"})),
    );
    lost.headers
        .insert("authorization".into(), "Bearer alice".into());
    lost.headers
        .insert("idempotency-key".into(), "lost-key".into());
    lost.timeout_ms = 100;
    let result = body(
        &mut s,
        Command::Api {
            request: lost.clone(),
        },
    );
    assert_eq!(result["effect"], "outcome_unknown");
    assert_eq!(result["automatic_retry"], false);
    assert!(
        s.command(Command::Api { request: lost }).is_err(),
        "a model cannot blindly replay an unknown write"
    );
    let mut read = api("observe", Method::Get, "/api/notes", None);
    read.headers
        .insert("authorization".into(), "Bearer alice".into());
    let observed = body(&mut s, Command::Api { request: read });
    assert_eq!(observed["status"], 200);
    let hex = observed["body_hex"].as_str().unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let data: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["items"].as_array().unwrap().len(), 2);
    assert!(
        data["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["text"] == "committed before response loss")
    );
    let result = s.finish().unwrap();
    assert!(
        result.cleanup_confirmed
            && result.application_outcome_unknown
            && result.requires_reconciliation
    );
    assert_eq!(
        f.store.journal().attempt(&f.ctx.attempt_id).unwrap().state,
        melissa_local_store::journal::AttemptState::OutcomeUnknown
    );
}
#[test]
fn real_api_cookies_validation_tenant_and_idempotency() {
    let f = Fixture::new(Service::Api, Some(Database::Sqlite), &[]);
    let mut s = f.start();
    let r = body(
        &mut s,
        Command::Api {
            request: api("anon", Method::Get, "/api/notes", None),
        },
    );
    assert_eq!(r["status"], 401);
    for who in ["alice", "bob"] {
        assert_eq!(
            body(
                &mut s,
                Command::Api {
                    request: api(who, Method::Post, "/login", Some(json!({"user":who})))
                }
            )["status"],
            200
        );
    }
    let mut request = api(
        "alice",
        Method::Post,
        "/api/notes",
        Some(json!({"text":"one record"})),
    );
    request
        .headers
        .insert("idempotency-key".into(), "same-key".into());
    assert_eq!(
        body(
            &mut s,
            Command::Api {
                request: request.clone()
            }
        )["status"],
        201
    );
    assert_eq!(body(&mut s, Command::Api { request })["status"], 200);
    let alice = body(
        &mut s,
        Command::Api {
            request: api("alice", Method::Get, "/api/notes", None),
        },
    );
    let bob = body(
        &mut s,
        Command::Api {
            request: api("bob", Method::Get, "/api/notes", None),
        },
    );
    let decode = |v: &Value| {
        let h = v["body_hex"].as_str().unwrap();
        let b = (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        serde_json::from_slice::<Value>(&b).unwrap()
    };
    assert_eq!(decode(&alice)["items"].as_array().unwrap().len(), 1);
    assert_eq!(decode(&bob)["items"], json!([]));
    let out = s.finish().unwrap();
    assert!(out.cleanup_confirmed && !out.requires_reconciliation);
}
#[test]
fn real_sqlite_readonly_queries_constraints_and_transaction_rollback() {
    let sql = "INSERT INTO notes(tenant,text) VALUES(?,?)";
    let mut f = Fixture::new(
        Service::Database,
        Some(Database::Sqlite),
        &[("insert.sql", sql)],
    );
    f.registration.statements.insert(
        "insert".into(),
        Statement {
            source_path: "insert.sql".into(),
            source_digest: melissa_web_development::digest(sql.as_bytes()),
        },
    );
    let mut s = f.start();
    let denied = s
        .command(Command::Query {
            connection: "read".into(),
            sql: "ATTACH DATABASE '/tmp/foreign' AS other".into(),
            parameters: vec![],
        })
        .unwrap();
    assert!(!denied.ok);
    body(
        &mut s,
        Command::Begin {
            connection: "write".into(),
            mode: TransactionMode::Immediate,
        },
    );
    body(
        &mut s,
        Command::Execute {
            connection: "write".into(),
            statement: "insert".into(),
            parameters: vec![json!("alice"), json!("rolled back")],
        },
    );
    body(
        &mut s,
        Command::Rollback {
            connection: "write".into(),
        },
    );
    assert_eq!(
        body(
            &mut s,
            Command::Query {
                connection: "read".into(),
                sql: "SELECT COUNT(*) FROM notes".into(),
                parameters: vec![]
            }
        )["rows"],
        json!([[0]])
    );
    let invalid = s
        .command(Command::Execute {
            connection: "write".into(),
            statement: "insert".into(),
            parameters: vec![json!("alice"), json!("")],
        })
        .unwrap();
    assert!(!invalid.ok);
    let profile = body(
        &mut s,
        Command::Profile {
            connection: "read".into(),
        },
    );
    assert_eq!(profile["integrity"]["rows"], json!([["ok"]]));
    assert_eq!(profile["foreign_keys"]["rows"], json!([]));
    assert!(!s.finish().unwrap().requires_reconciliation);
}
