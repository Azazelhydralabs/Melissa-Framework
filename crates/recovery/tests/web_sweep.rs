#![cfg(windows)]
#[path = "../../web-development/tests/support/mod.rs"]
mod support;
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use melissa_web_development::{plan::*, protocol::*, session::*};
use serde_json::{Value, json};
use std::{
    process::Command as ProcessCommand,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[test]
fn actual_web_controller_death_restarts_only_owned_cleanup_and_keeps_unknown_fenced() {
    const ENV: &str = "MELISSA_CODE10_OWNED_CRASH";
    if let Some(path) = std::env::var_os(ENV) {
        let root = std::path::PathBuf::from(path);
        let mut f = support::Fixture::new(Service::Database, Some(Database::Postgres), &[]);
        // Transfer the actual temporary owned source/store into the parent's
        // explicitly named fixture directory before any session admission.
        fn copy(a: &std::path::Path, b: &std::path::Path) {
            std::fs::create_dir(b).unwrap();
            for e in std::fs::read_dir(a).unwrap() {
                let e = e.unwrap();
                assert!(!e.file_type().unwrap().is_symlink());
                if e.file_type().unwrap().is_dir() {
                    copy(&e.path(), &b.join(e.file_name()));
                } else {
                    std::fs::copy(e.path(), b.join(e.file_name())).unwrap();
                }
            }
        }
        let original_root = f.root();
        drop(f.store);
        copy(&f.dir.path().join("store"), &root.join("store"));
        copy(&original_root, &root.join("repo"));
        f.store = LocalStore::open(
            &root.join("store"),
            StoreKey::from_bytes([147; 32]),
            StoreConfig {
                max_blob_bytes: 256 * 1024 * 1024,
                max_cas_bytes: 1024 * 1024 * 1024,
                ..StoreConfig::default()
            },
        )
        .unwrap();
        f.repo = std::sync::Arc::new(
            melissa_repository::Repository::open(
                &root.join("repo"),
                melissa_repository::Limits::default(),
                vec![],
            )
            .unwrap(),
        );
        f.policy.expires_at_ms = melissa_execution_broker::unix_ms().unwrap() + 20_000;
        let plan = WebPlan::prepare(
            &f.repo,
            &f.repo.snapshot(&AtomicBool::new(false)).unwrap(),
            f.registration.clone(),
            support::limits(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut session = WebSession::start(
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
        support::body(
            &mut session,
            Command::Begin {
                connection: "owned".into(),
                mode: TransactionMode::Serializable,
            },
        );
        let identity = f
            .store
            .get_artifact(
                &f.ctx.task_id,
                &format!("{}:web-container-identity", f.ctx.attempt_id),
            )
            .unwrap();
        let expires = f
            .store
            .journal()
            .managed_execution(&f.ctx.invocation_id)
            .unwrap()
            .expires_at_unix_ms;
        std::fs::write(root.join("witness.json"),json!({"identity":serde_json::from_slice::<Value>(&identity).unwrap(),"expires":expires}).to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(45));
        panic!("parent failed to kill its owned child");
    }
    let d = tempfile::tempdir().unwrap();
    let mut cmd = ProcessCommand::new(std::env::current_exe().unwrap());
    use std::os::windows::process::CommandExt;
    let log = std::fs::File::create(d.path().join("child.log")).unwrap();
    cmd.args([
        "--exact",
        "actual_web_controller_death_restarts_only_owned_cleanup_and_keeps_unknown_fenced",
        "--nocapture",
    ])
    .env(ENV, d.path())
    .stdout(log.try_clone().unwrap())
    .stderr(log)
    .creation_flags(0x08000000);
    let mut child = cmd.spawn().unwrap();
    let start = Instant::now();
    while !d.path().join("witness.json").exists() && start.elapsed() < Duration::from_secs(18) {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    if !d.path().join("witness.json").exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "owned child never produced real web witness: {}",
            std::fs::read_to_string(d.path().join("child.log")).unwrap()
        );
    }
    let witness: Value =
        serde_json::from_slice(&std::fs::read(d.path().join("witness.json")).unwrap()).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let mut s = LocalStore::open(
        &d.path().join("store"),
        StoreKey::from_bytes([147; 32]),
        StoreConfig {
            max_blob_bytes: 256 * 1024 * 1024,
            max_cas_bytes: 1024 * 1024 * 1024,
            ..StoreConfig::default()
        },
    )
    .unwrap();
    let task = "task:code10-test";
    let inv = "invocation:code10-test";
    assert_eq!(
        s.journal().invocation(inv).unwrap().state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
    );
    assert!(melissa_recovery::sweep::sweep_expired_container(&mut s, "foreign", inv).is_err());
    assert!(melissa_recovery::sweep::sweep_expired_container(&mut s, task, inv).is_err());
    let initial = melissa_recovery::sweep::recover_on_restart(&mut s, task).unwrap();
    assert!(
        initial
            .to_string()
            .contains("waiting_for_original_lease_expiry")
    );
    while melissa_execution_broker::unix_ms().unwrap() < witness["expires"].as_u64().unwrap() {
        std::thread::sleep(Duration::from_millis(40));
    }
    let report = melissa_recovery::sweep::recover_on_restart(&mut s, task).unwrap();
    assert_eq!(report["results"][0]["invocation_reconciled"], false);
    assert_eq!(
        report["results"][0]["cleanup_does_not_prove_program_outcome"],
        true
    );
    assert_eq!(
        s.journal().invocation(inv).unwrap().state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
    );
    assert!(
        s.journal()
            .task(task)
            .unwrap()
            .record
            .unknown_invocation_id
            .is_some()
    );
    let repeated = melissa_recovery::sweep::recover_on_restart(&mut s, task).unwrap();
    assert_eq!(repeated["results"][0]["invocation_reconciled"], false);
}
