#![cfg(windows)]
mod support;
use melissa_build_test::{RustOperation, toolchain::COMPLETE_IMAGE};
use melissa_container_executor::{ContainerRequest, Conversation, Snapshot, TerminationReason};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

fn run(
    script: &str,
    cancel: bool,
) -> melissa_execution_broker::container_broker::ContainerExecution {
    let mut f = support::Fixture::new(
        "pub fn fixture(){}\n",
        RustOperation::Build,
        &[],
        support::limits(),
    );
    let request = ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: COMPLETE_IMAGE.into(),
        executable: "/usr/bin/python3".into(),
        argv: vec![
            "-I".into(),
            "-S".into(),
            "-u".into(),
            "-c".into(),
            script.into(),
        ],
        cwd: ".".into(),
        env: BTreeMap::new(),
        limits: support::limits(),
    };
    let snapshot = Snapshot::default();
    let permit = support::permit_for(&mut f, &request, &snapshot);
    let (input, receiver) = mpsc::channel();
    let (output, answers) = mpsc::sync_channel(4);
    let signal = Arc::new(AtomicBool::new(false));
    let worker_signal = signal.clone();
    let worker = std::thread::spawn(move || {
        let _keep = f._dir;
        f.broker
            .execute_conversation(
                &f.task.task_id,
                &permit,
                &snapshot,
                &support::identity(),
                &worker_signal,
                Conversation {
                    input: receiver,
                    output,
                },
            )
            .unwrap()
    });
    if cancel {
        input.send(b"{\"seq\":1}\n".to_vec()).unwrap();
        let line = answers.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&line).unwrap()["seq"],
            1
        );
        signal.store(true, Ordering::Release);
        // Keep the sender alive while joining: cancellation must wake the pipe
        // writer without relying on caller EOF or an input-thread leak.
        let result = worker.join().unwrap();
        drop(input);
        return result;
    }
    if script.contains("OVERSIZED_FRAME") {
        let result = worker.join().unwrap();
        drop(input);
        return result;
    }
    for seq in 1..=3 {
        input
            .send(format!("{{\"seq\":{seq}}}\n").into_bytes())
            .unwrap();
        let answer = answers.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&answer).unwrap()["seq"],
            seq
        );
    }
    drop(input);
    worker.join().unwrap()
}
const ECHO: &str = "import sys,json\nfor line in sys.stdin:\n value=json.loads(line);print(json.dumps(value),flush=True)\n";
#[test]
fn real_admitted_worker_exchanges_multiple_messages_then_closes_without_orphans() {
    let r = run(ECHO, false);
    assert!(!r.requires_reconciliation);
    let report = r.report.unwrap();
    assert_eq!(report.termination, TerminationReason::Exited);
    assert_eq!(report.exit_code, Some(0));
    assert!(report.cleanup_confirmed && report.tree_confirmed_stopped);
    assert_eq!(
        report
            .stdout
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count(),
        3
    );
}
#[test]
fn real_interactive_cancel_joins_writer_even_when_input_sender_remains_alive() {
    let r = run(ECHO, true);
    assert!(!r.requires_reconciliation);
    let report = r.report.unwrap();
    assert_eq!(report.termination, TerminationReason::Cancelled);
    assert!(report.cleanup_confirmed && report.tree_confirmed_stopped);
}
#[test]
fn oversized_interactive_frame_preserves_unknown_and_never_reports_success() {
    let r = run("# OVERSIZED_FRAME\nprint('x'*70000,flush=True)\n", false);
    assert!(r.requires_reconciliation);
    assert_ne!(
        r.observation.status,
        melissa_core_contracts::wire::ObservationStatus::Success
    );
}
