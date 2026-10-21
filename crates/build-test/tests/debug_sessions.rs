#![cfg(windows)]
mod support;
use melissa_build_test::{
    RustOperation,
    debug::{Breakpoint, DebugCommand, DebugPlan, DebugSession, DebugState, Reference},
    full::Language,
};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
fn session(
    language: Language,
    path: &str,
    body: &str,
    line: u64,
    expected: Option<String>,
) -> (tempfile::TempDir, DebugSession) {
    let mut limits = support::limits();
    limits.export_bytes = 32 * 1024 * 1024;
    let mut f = support::Fixture::new(
        "pub fn fixture(){}\n",
        RustOperation::Build,
        &[(path, body)],
        limits.clone(),
    );
    let source = f.repo.snapshot(&support::no()).unwrap();
    let p = DebugPlan::prepare(
        &f.repo,
        &source,
        language,
        path.into(),
        vec![Breakpoint {
            path: path.into(),
            line,
        }],
        expected,
        limits,
        &support::no(),
    )
    .unwrap();
    let permit = support::permit_for(&mut f, p.request(), p.snapshot());
    let s = p
        .start(
            Arc::new(f.repo),
            Arc::new(Mutex::new(f.broker)),
            f.task.task_id,
            permit,
            support::identity(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
    (f._dir, s)
}
fn exercise(language: Language, path: &str, body: &str) {
    let (_temp, mut s) = session(language, path, body, 2, None);
    if s.state() != DebugState::Stopped {
        let last = s.last_reply().cloned();
        let outcome = s.finish().unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../reports/debug-faults/{stamp}-{}",
            language.wire()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("reply.json"),
            serde_json::to_vec_pretty(&last).unwrap(),
        )
        .unwrap();
        if let Some(report) = outcome.execution.report {
            std::fs::write(dir.join("archive.tar"), &report.archive).unwrap();
            let files = melissa_repository::archive::inspect_ustar(
                &report.archive,
                &melissa_repository::Limits::default(),
            )
            .unwrap();
            for (i, file) in files
                .iter()
                .filter(|f| f.path.starts_with(".melissa-code06-debug/"))
                .enumerate()
            {
                if file.path.ends_with("dap-transcript.ndjson")
                    || file.path.ends_with(".stderr")
                    || file.path.ends_with("server.stdout")
                {
                    std::fs::write(
                        dir.join(format!(
                            "{i}-{}",
                            std::path::Path::new(&file.path)
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                        )),
                        &file.bytes,
                    )
                    .unwrap();
                }
            }
        }
        panic!(
            "real debugger startup failed; preserved at {:?}: {:?}",
            dir, last
        );
    }
    assert_eq!(s.state(), DebugState::Stopped, "{:?}", s.last_reply());
    let stack = s.command(DebugCommand::Stack {}).unwrap();
    assert!(stack.ok, "{:?}", stack);
    let frame: Reference =
        serde_json::from_value(stack.body.as_ref().unwrap()["stackFrames"][0]["handle"].clone())
            .unwrap();
    let scopes = s
        .command(DebugCommand::Scopes {
            frame: frame.clone(),
        })
        .unwrap();
    assert!(scopes.ok, "{:?}", scopes);
    let next = s.command(DebugCommand::Next {}).unwrap();
    assert!(next.ok, "{:?}", next);
    assert!(s.epoch() > frame.epoch);
    assert!(s.command(DebugCommand::Scopes { frame }).is_err());
    let values = s.command(DebugCommand::Inspect { count: 30 }).unwrap();
    assert!(values.ok, "{:?}", values);
    let text = values.body.unwrap().to_string();
    assert!(text.contains("total") && text.contains('5'), "{text}");
    let running = s.command(DebugCommand::Continue {}).unwrap();
    assert!(running.ok, "{:?}", running);
    let done = s.command(DebugCommand::Wait { timeout_ms: 10000 }).unwrap();
    assert!(done.ok, "{:?}", done);
    assert_eq!(s.state(), DebugState::Exited, "{:?}", done);
    let closed = s.command(DebugCommand::Close {}).unwrap();
    assert!(closed.ok, "{:?}", closed);
    let outcome = s.finish().unwrap();
    assert!(
        outcome.success,
        "debug finish failed; {:?}",
        outcome.execution.report
    );
    assert!(outcome.binary_bytes_authenticated && outcome.host_source_current);
    assert!(!outcome.execution.requires_reconciliation);
    assert!(
        outcome
            .artifact_refs
            .iter()
            .any(|a| a.ends_with(":dap-transcript"))
    );
}
#[test]
fn real_python_dap_breakpoint_frames_scopes_variables_step_continue_and_stop_identity() {
    exercise(
        Language::Python,
        "src/main.py",
        "def add(a: int, b: int) -> int:\n    total = a + b\n    return total\nresult = add(2, 3)\nprint(result)\n",
    );
}
#[test]
fn real_rust_lldb_dap_binds_binary_symbols_and_actual_local_variables() {
    exercise(
        Language::Rust,
        "src/main.rs",
        "fn add(a:i32,b:i32)->i32 {\n    let total = a+b;\n    std::hint::black_box(total);\n    total\n}\nfn main(){\n    let result=add(2,3);\n    println!(\"{}\",result);\n}\n",
    );
}
#[test]
fn real_node_dap_binds_javascript_breakpoints_and_variables() {
    exercise(
        Language::JavaScript,
        "src/main.js",
        "function add(a,b){\n    const total=a+b;\n    return total;\n}\nconst result=add(2,3);\nconsole.log(result);\n",
    );
}
#[test]
fn real_typescript_dap_uses_compiled_artifact_and_original_source_map() {
    exercise(
        Language::TypeScript,
        "src/main.ts",
        "function add(a:number,b:number):number {\n    const total=a+b;\n    return total;\n}\nconst result=add(2,3);\nconsole.log(result);\n",
    );
}
#[test]
fn wrong_expected_debug_binary_hash_is_rejected_before_adapter_start() {
    let (_temp, s) = session(
        Language::Python,
        "src/main.py",
        "x=1\nprint(x)\n",
        2,
        Some("a".repeat(64)),
    );
    let reply = s.last_reply().unwrap();
    assert!(!reply.ok);
    assert_eq!(reply.error.as_ref().unwrap().kind, "artifact_mismatch");
    let outcome = s.finish().unwrap();
    assert!(!outcome.success);
}
#[test]
fn actual_python_step_in_out_breakpoint_replacement_pause_and_foreign_handle_denial() {
    let (_temp, mut s) = session(
        Language::Python,
        "src/main.py",
        "def add(a, b):\n    total = a + b\n    return total\n\nresult = add(2, 3)\nwhile True:\n    result += 1\n",
        5,
        None,
    );
    assert_eq!(s.state(), DebugState::Stopped, "{:?}", s.last_reply());
    assert!(s.command(DebugCommand::Start {}).is_err());
    assert!(s.command(DebugCommand::Pause {}).is_err());
    let entered = s.command(DebugCommand::StepIn {}).unwrap();
    assert!(entered.ok, "{:?}", entered);
    let stack = s.command(DebugCommand::Stack {}).unwrap();
    let body = stack.body.unwrap();
    assert!(body.to_string().contains("add"));
    let mut frame: Reference =
        serde_json::from_value(body["stackFrames"][0]["handle"].clone()).unwrap();
    frame.session_id = "debug:other".into();
    assert!(s.command(DebugCommand::Scopes { frame }).is_err());
    let left = s.command(DebugCommand::StepOut {}).unwrap();
    assert!(left.ok, "{:?}", left);
    assert!(
        s.command(DebugCommand::Breakpoints {
            breakpoints: vec![]
        })
        .unwrap()
        .ok
    );
    assert!(s.command(DebugCommand::Continue {}).unwrap().ok);
    assert_eq!(s.state(), DebugState::Running);
    let paused = s.command(DebugCommand::Pause {}).unwrap();
    assert!(paused.ok, "{:?}", paused);
    assert_eq!(s.state(), DebugState::Stopped);
    assert!(s.command(DebugCommand::Close {}).unwrap().ok);
    assert!(s.command(DebugCommand::Stack {}).is_err());
    assert!(s.finish().unwrap().success);
}
#[test]
fn real_debug_source_change_and_cancellation_cannot_accept_old_result() {
    for changed in [false, true] {
        let (temp, mut s) = session(Language::Python, "src/main.py", "x=1\nprint(x)\n", 2, None);
        assert_eq!(s.state(), DebugState::Stopped);
        if changed {
            std::fs::write(temp.path().join("repo/src/main.py"), "x=2\nprint(x)\n").unwrap();
        } else {
            s.cancellation()
                .store(true, std::sync::atomic::Ordering::Release);
        }
        assert!(s.command(DebugCommand::Stack {}).is_err());
        let r = s.finish().unwrap();
        assert!(!r.success);
        assert!(!r.execution.requires_reconciliation);
        assert!(r.execution.report.unwrap().cleanup_confirmed);
    }
}
#[test]
fn actual_adapter_crash_is_recorded_without_forging_a_successful_session() {
    let source = "import os, signal\nfrom pathlib import Path\nready = 1\nfor entry in Path('/proc').iterdir():\n    if entry.name.isdigit():\n        try:\n            raw = (entry / 'cmdline').read_bytes()\n            if b'debugpy.adapter' in raw:\n                os.kill(int(entry.name), signal.SIGKILL)\n        except (ProcessLookupError, FileNotFoundError, PermissionError):\n            pass\nprint('adapter killed')\n";
    let (_temp, mut s) = session(Language::Python, "src/main.py", source, 3, None);
    assert_eq!(s.state(), DebugState::Stopped);
    let resumed = s.command(DebugCommand::Continue {});
    if resumed.as_ref().is_ok_and(|r| r.ok) {
        let wait = s.command(DebugCommand::Wait { timeout_ms: 10000 });
        assert!(wait.is_err() || !wait.unwrap().ok);
    }
    let r = s.finish().unwrap();
    assert!(!r.success);
    assert!(r.execution.report.unwrap().cleanup_confirmed);
}
#[test]
fn actual_rust_without_debug_symbols_fails_source_breakpoint_contract() {
    let mut f = support::Fixture::new(
        "pub fn fixture(){}\n",
        RustOperation::Build,
        &[
            (
                "Cargo.toml",
                "[package]\nname=\"code06_fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[profile.dev]\ndebug=0\nstrip=\"symbols\"\n",
            ),
            (
                "src/main.rs",
                "fn main(){\n let x=42;\n println!(\"{}\",x);\n}\n",
            ),
        ],
        support::limits(),
    );
    let source = f.repo.snapshot(&support::no()).unwrap();
    let plan = DebugPlan::prepare(
        &f.repo,
        &source,
        Language::Rust,
        "src/main.rs".into(),
        vec![Breakpoint {
            path: "src/main.rs".into(),
            line: 2,
        }],
        None,
        support::limits(),
        &support::no(),
    )
    .unwrap();
    let permit = support::permit_for(&mut f, plan.request(), plan.snapshot());
    let s = plan
        .start(
            Arc::new(f.repo),
            Arc::new(Mutex::new(f.broker)),
            f.task.task_id,
            permit,
            support::identity(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
    assert!(!s.last_reply().unwrap().ok);
    assert!(!s.finish().unwrap().success);
}
#[test]
fn native_breakpoint_ids_never_become_frame_handles_and_only_actual_stack_issues_frames() {
    let (_temp, mut session) = session(
        Language::Python,
        "src/main.py",
        "def add(a, b):\n    total = a + b\n    return total\nprint(add(2, 3))\n",
        2,
        None,
    );
    assert_eq!(session.state(), DebugState::Stopped);
    let start = session.last_reply().unwrap().clone();
    let point = &start.body.as_ref().unwrap()["breakpoints"][0];
    assert!(
        point.get("handle").is_none(),
        "a breakpoint is not a Frame: {point}"
    );
    let forged = Reference {
        session_id: session.id().into(),
        epoch: session.epoch(),
        kind: melissa_build_test::debug::ReferenceKind::Frame,
        id: point["id"].as_i64().unwrap(),
    };
    assert!(
        session
            .command(DebugCommand::Scopes { frame: forged })
            .is_err()
    );
    assert_eq!(
        session.last_reply().unwrap().seq,
        start.seq,
        "unissued reference must fail before another wire request"
    );
    let stack = session.command(DebugCommand::Stack {}).unwrap();
    assert!(stack.ok);
    let frame: Reference =
        serde_json::from_value(stack.body.unwrap()["stackFrames"][0]["handle"].clone()).unwrap();
    assert!(session.command(DebugCommand::Scopes { frame }).unwrap().ok);
    assert!(session.command(DebugCommand::Next {}).unwrap().ok);
    let values = session
        .command(DebugCommand::Inspect { count: 20 })
        .unwrap();
    assert!(
        values.body.unwrap()["values"]["variables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["name"] == "total" && v["value"] == "5")
    );
    assert!(session.command(DebugCommand::Close {}).unwrap().ok);
    assert!(session.finish().unwrap().success);
}
