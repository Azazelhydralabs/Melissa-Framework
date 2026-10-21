#![cfg(windows)]
#[path = "../../repository/tests/support/mod.rs"]
mod support;
use melissa_container_executor::{ContainerRequest, Snapshot};
use melissa_execution_broker::{InvocationIdentity, policy::PermitRequest, unix_ms};
use melissa_local_store::{LocalStore, StoreConfig, StoreKey};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
const TASK: &str = "task:code05-closeout";
const IMAGE: &str = "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";
fn crash_case(semantic: bool) {
    const ENV: &str = "MELISSA_CODE09_CRASH_STORE";
    if let Some(root) = std::env::var_os(ENV) {
        println!("child: opening owned store");
        let root = std::path::PathBuf::from(root);
        let s = LocalStore::open(
            &root.join("store"),
            StoreKey::from_bytes([112; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        let t = s.journal().task(TASK).unwrap().contract;
        let mut limits = support::limits();
        limits.wall_time_ms = 30_000;
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: IMAGE.into(),
            executable: "/bin/sh".into(),
            argv: vec!["-c".into(), "sleep 30".into()],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        let mut broker = support::container(s, &t, &request, &Snapshot::default());
        println!("child: broker prepared");
        let expires = unix_ms().unwrap() + 12_000;
        let signed = broker
            .issue_permit(
                TASK,
                request,
                &Snapshot::default(),
                PermitRequest {
                    permit_id: "permit:code09-crash".into(),
                    nonce: "nonce:code09-crash".into(),
                    principal_id: "principal:closeout".into(),
                    profile_id: t.selected_profile_ids[0].clone(),
                    resource_id: t.workspace_ref.clone(),
                    authorization_ref: "auth:closeout".into(),
                    not_before_unix_ms: unix_ms().unwrap(),
                    expires_at_unix_ms: expires,
                },
            )
            .unwrap();
        let monitor = broker.store().connect().unwrap();
        println!("child: permit prepared");
        let sdk = if semantic {
            let repo_root = root.join("code-repo");
            std::fs::create_dir_all(repo_root.join("src")).unwrap();
            std::fs::write(
                repo_root.join("Cargo.toml"),
                "[package]\nname=\"code09_crash\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
            )
            .unwrap();
            std::fs::write(
                repo_root.join("Cargo.lock"),
                "version=4\n[[package]]\nname=\"code09_crash\"\nversion=\"0.1.0\"\n",
            )
            .unwrap();
            std::fs::write(repo_root.join("src/lib.rs"),"#[test] fn owned_sleep(){std::thread::sleep(std::time::Duration::from_secs(30));}\n").unwrap();
            let mut limits = support::limits();
            limits.output_bytes = 1024 * 1024;
            limits.export_bytes = 4 * 1024 * 1024;
            Some(
                melissa_build_test::tools::CodeDispatcher::new(
                    melissa_repository::Repository::open(
                        &repo_root,
                        melissa_repository::Limits::default(),
                        vec![],
                    )
                    .unwrap(),
                    monitor.connect().unwrap(),
                    melissa_core_contracts::catalog::Catalog::load(
                        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
                    )
                    .unwrap(),
                    melissa_build_test::tools::CodeToolPolicy {
                        task_id: TASK.into(),
                        profile_id: t.selected_profile_ids[0].clone(),
                        principal_id: "principal:closeout".into(),
                        resource_id: t.workspace_ref.clone(),
                        authorization_ref: "auth:closeout".into(),
                        expires_at_ms: expires,
                        limits,
                        operations: BTreeMap::from([(
                            "code_tests".into(),
                            melissa_build_test::tools::CodeOperation::Procedure {
                                language: melissa_build_test::full::Language::Rust,
                                operation: melissa_build_test::full::Operation::Test {
                                    suite: melissa_build_test::full::TestSuite::UnitIntegration,
                                    repetitions: 1,
                                },
                                harness: None,
                            },
                        )]),
                        process_policy: Some(broker.policy_control().snapshot().unwrap()),
                    },
                )
                .unwrap(),
            )
        } else {
            None
        };
        let worker = std::thread::spawn(move || -> Result<(), String> {
            if let Some(mut sdk) = sdk {
                use melissa_model_gateway::tools::ToolDispatcher;
                let operation = melissa_build_test::tools::CodeOperation::Procedure {
                    language: melissa_build_test::full::Language::Rust,
                    operation: melissa_build_test::full::Operation::Test {
                        suite: melissa_build_test::full::TestSuite::UnitIntegration,
                        repetitions: 1,
                    },
                    harness: None,
                };
                return tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(sdk.execute(
                        melissa_model_gateway::ToolCall {
                            id: "crash".into(),
                            name: "code_tests".into(),
                            arguments: serde_json::to_string(&operation).unwrap(),
                        },
                        melissa_model_gateway::tools::ToolContext {
                            task_id: TASK.into(),
                            profile_id: t.selected_profile_ids[0].clone(),
                            run_id: "crash".into(),
                            request_id: "host:crash".into(),
                            invocation_id: "inv:crash".into(),
                            attempt_id: "attempt:crash".into(),
                            generation: 1,
                        },
                        std::sync::Arc::new(AtomicBool::new(false)),
                    ))
                    .map(|_| ())
                    .map_err(|e| e.to_string());
            }
            broker
                .execute(
                    TASK,
                    &signed,
                    &Snapshot::default(),
                    &InvocationIdentity {
                        invocation_id: "inv:crash".into(),
                        attempt_id: "attempt:crash".into(),
                        generation: 1,
                        idempotency_key: None,
                    },
                    &AtomicBool::new(false),
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            if let Ok(bytes) = monitor.get_artifact(TASK, "attempt:crash:container-identity") {
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                std::fs::write(
                    root.join("witness.json"),
                    json!({"container_id":value["container_id"],"expires":expires}).to_string(),
                )
                .unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        println!("child: identity wait ended");
        let outcome = worker.join();
        std::fs::write(
            root.join("child-outcome.txt"),
            match outcome {
                Ok(Ok(_)) => "known terminal result",
                Ok(Err(_)) => "broker error",
                Err(_) => "worker panic",
            },
        )
        .unwrap();
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let (s, _) = support::task_store(&d.path().join("store"), None);
    drop(s);
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact",if semantic{"actual_code06_procedure_crash_is_cleaned_on_continuation_startup"}else{"actual_controller_death_is_swept_by_product_code_without_replaying_or_accepting_unknown_work"},"--nocapture"]).env(ENV,d.path()).stdout(Stdio::null()).stderr(Stdio::null());
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000);
    let child_log = std::fs::File::create(d.path().join("child.log")).unwrap();
    cmd.stdout(child_log.try_clone().unwrap()).stderr(child_log);
    let mut child = cmd.spawn().unwrap();
    let start = Instant::now();
    let mut witness = None;
    let mut last_top = String::new();
    let docker_config = d.path().join("docker-config");
    std::fs::create_dir(&docker_config).unwrap();
    while start.elapsed() < Duration::from_secs(20) {
        if let Ok(bytes) = std::fs::read(d.path().join("witness.json")) {
            let w: Value = serde_json::from_slice(&bytes).unwrap();
            let mut c = Command::new(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe");
            c.env_clear();
            if let Some(v) = std::env::var_os("SystemRoot") {
                c.env("SystemRoot", v);
            }
            c.arg("--config").arg(&docker_config);
            c.args([
                "--host",
                "npipe:////./pipe/dockerDesktopLinuxEngine",
                "top",
                w["container_id"].as_str().unwrap(),
                "-eo",
                "pid,uid,args",
            ])
            .creation_flags(0x08000000);
            let out = c.output().unwrap();
            if last_top.len() < 12_000 {
                last_top.push_str(&format!(
                    "witness={w}; top stdout={}; stderr={}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            if String::from_utf8_lossy(&out.stdout).lines().any(|l| {
                l.split_whitespace().nth(1) == Some("65534")
                    && if semantic {
                        l.contains("python")
                            || l.contains("rustc")
                            || l.contains(".melissa-code06-target")
                    } else {
                        l.contains("sleep 30")
                    }
            }) {
                witness = Some(w);
                break;
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let w = match witness {
        Some(w) => w,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let log = std::fs::read_to_string(d.path().join("child.log")).unwrap_or_default();
            let outcome =
                std::fs::read_to_string(d.path().join("child-outcome.txt")).unwrap_or_default();
            panic!(
                "owned workload did not start; fixture must fail, never skip; {log}; {outcome}; {last_top}"
            );
        }
    };
    child.kill().unwrap();
    child.wait().unwrap();
    let mut s = LocalStore::open(
        &d.path().join("store"),
        StoreKey::from_bytes([112; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    assert_eq!(
        s.journal().invocation("inv:crash").unwrap().state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
    );
    assert!(
        melissa_recovery::sweep::sweep_expired_container(&mut s, "foreign", "inv:crash").is_err()
    );
    assert!(melissa_recovery::sweep::sweep_expired_container(&mut s, TASK, "inv:crash").is_err());
    while unix_ms().unwrap() < w["expires"].as_u64().unwrap() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let source = s
        .journal()
        .task(TASK)
        .unwrap()
        .contract
        .input_snapshot_digest;
    let binding = melissa_recovery::Binding {
        task: TASK.into(),
        run: "restart".into(),
        profile: "melissa.code.implementer".into(),
        initial_source: source.clone(),
        policy: "policy:restart".into(),
    };
    let refresh: melissa_recovery::session::Refresh = std::sync::Arc::new(move || {
        Ok(melissa_recovery::session::Freshness {
            source: source.clone(),
            policy: "policy:restart".into(),
        })
    });
    let mut continuation =
        melissa_recovery::continuation::RecoveryContinuation::new(binding, refresh);
    assert!(
        melissa_model_gateway::continuation::ContinuationStore::begin(
            &mut continuation,
            &mut s,
            "native:restart",
            TASK,
            "restart"
        )
        .is_err()
    );
    assert_eq!(
        s.journal().invocation("inv:crash").unwrap().state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
    );
    let again =
        melissa_recovery::sweep::sweep_expired_container(&mut s, TASK, "inv:crash").unwrap();
    assert_eq!(again["native_report"]["already_absent"], true);
    assert_eq!(again["native_report"]["invocation_outcome_known"], false);
}

#[test]
fn actual_controller_death_is_swept_by_product_code_without_replaying_or_accepting_unknown_work() {
    crash_case(false)
}
#[test]
fn actual_code06_procedure_crash_is_cleaned_on_continuation_startup() {
    crash_case(true)
}
