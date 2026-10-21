//! Fixed package helper service under the already consumed CODE-03 admission.
//! No host mounts, network, model-selected image/command/env or extra authority.
use crate::{Error, Result, package::Package, runtime::put};
use melissa_container_executor::{
    ContainerLimits, ContainerRequest, Executor, ExecutorError, Snapshot, TerminationReason,
};
use melissa_local_store::{LocalStore, journal::AdmissionRequest};
use melissa_model_gateway::tools::ToolContext;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[allow(clippy::too_many_arguments)] // One already admitted request and its immutable inputs.
pub fn helper(
    store: &mut LocalStore,
    ctx: &ToolContext,
    package: &Package,
    path: &str,
    input: &Value,
    cancel: &Arc<AtomicBool>,
    revoked: &Arc<AtomicBool>,
    admit: &AdmissionRequest,
) -> Result<Value> {
    let input = serde_json::to_vec(input)?;
    let input_digest = package.validate_script_input(path, &input)?;
    let descriptor = package
        .definition()
        .scripts
        .iter()
        .find(|s| s.file_path == path)
        .ok_or_else(|| Error("unregistered helper".into()))?;
    let task_limits = store.journal().task(&ctx.task_id)?.contract.limits;
    let request=ContainerRequest{schema_version:"melissa.container-exec/v1".into(),image_id:melissa_build_test::toolchain::COMPLETE_IMAGE.into(),executable:melissa_build_test::toolchain::PYTHON.into(),argv:vec!["-I".into(),"-S".into(),"-u".into(),"-c".into(),"import io,sys,runpy,pathlib;sys.stdin=io.StringIO(pathlib.Path('input.json').read_text(encoding='utf-8'));runpy.run_path('helper.py',run_name='__main__')".into()],cwd:".".into(),env:BTreeMap::new(),limits:ContainerLimits{wall_time_ms:(descriptor.timeout_seconds*1000).min(admit.expires_at_unix_ms.saturating_sub(admit.consumed_at_unix_ms)),cpu_time_ms:30000,cpu_rate_basis_points:10000,memory_bytes:512*1024*1024,disk_bytes:task_limits.max_disk_bytes.min(128*1024*1024),output_bytes:task_limits.max_output_bytes.min(8*1024*1024),max_processes:32,export_bytes:task_limits.max_output_bytes.min(8*1024*1024)}};
    request.validate().map_err(|e| Error(e.to_string()))?;
    let snapshot = Snapshot {
        files: BTreeMap::from([
            ("helper.py".into(), package.file(path)?.to_vec()),
            ("input.json".into(), input),
        ]),
    };
    let input_id = format!("{}:helper-input", ctx.attempt_id);
    put(
        store,
        &ctx.task_id,
        &input_id,
        "skill.helper-input",
        &serde_json::to_vec(
            &json!({"request":request,"snapshot":snapshot,"pin":package.version().pin,"input_digest":input_digest,"admission":admit}),
        )?,
    )?;
    let monitor = store.connect()?;
    let signal = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let r = revoked.clone();
    let done = stop.clone();
    let s = signal.clone();
    let a = admit.clone();
    let wall = request.limits.wall_time_ms;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let watcher = std::thread::spawn(move || {
        let mut ready = Some(ready_tx);
        let start = Instant::now();
        while !done.load(Ordering::Acquire) {
            let now = melissa_execution_broker::unix_ms();
            let task = monitor.journal().task(&a.task_id);
            if c.load(Ordering::Acquire)
                || r.load(Ordering::Acquire)
                || start.elapsed().as_millis() >= u128::from(wall)
                || now.is_err()
                || now.is_ok_and(|n| n < a.not_before_unix_ms || n >= a.expires_at_unix_ms)
                || !matches!(
                    monitor.journal().is_cancel_requested(
                        &a.task_id,
                        &a.invocation_id,
                        a.generation
                    ),
                    Ok(false)
                )
                || task.as_ref().map_or(true, |t| {
                    t.record.state != melissa_core_contracts::TaskState::Running
                        || t.record.unknown_invocation_id.is_some()
                })
                || !matches!(monitor.journal().is_permit_revoked(&a.permit_id), Ok(false))
            {
                s.store(true, Ordering::Release);
            }
            if let Some(tx) = ready.take() {
                let _ = tx.send(());
            }
            if s.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let ready = ready_rx.recv_timeout(Duration::from_secs(2)).is_ok();
    let execution = if ready && !signal.load(Ordering::Acquire) {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(||Executor::run_with_observer(&request,&snapshot,&signal,&mut |container|{
        put(store,&ctx.task_id,&format!("{}:helper-container",ctx.attempt_id),"skill.helper-container",&serde_json::to_vec(&json!({"container_id":container,"permit":admit.permit_id,"image":request.image_id})).map_err(|e|ExecutorError::Control(e.to_string()))?).map_err(|e|ExecutorError::Control(e.to_string()))
    }))).map_err(|_|Error("helper executor panic; inspect admitted attempt".into()))
    } else {
        Ok(Err(ExecutorError::CancelledBeforeLaunch))
    };
    stop.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| Error("helper monitor failed".into()))?;
    let execution = execution?;
    if matches!(execution, Err(ExecutorError::CancelledBeforeLaunch)) {
        return Ok(json!({"success":false,"cancelled":true,"known_zero_launch":true}));
    }
    let report = execution.map_err(|e| Error(format!("admitted helper executor failed: {e}")))?;
    let raw = format!("{}:helper-raw", ctx.attempt_id);
    put(
        store,
        &ctx.task_id,
        &raw,
        "skill.helper-raw",
        &serde_json::to_vec(&report)?,
    )?;
    crate::require(
        report.cleanup_confirmed
            && report.tree_confirmed_stopped
            && report.policy_verified
            && report.monitor_error.is_none(),
        "helper worker state needs reconciliation",
    )?;
    let schema: Value = crate::json(package.file(&descriptor.output_schema_ref)?)?;
    let parsed = std::str::from_utf8(&report.stdout)
        .ok()
        .and_then(|text| melissa_model_gateway::schema::validate_output(&schema, text).ok());
    let success = report.exit_code == Some(0)
        && report.termination == TerminationReason::Exited
        && !report.output_truncated
        && !report.export_truncated
        && parsed.is_some();
    Ok(
        json!({"success":success,"observation":parsed,"exit_code":report.exit_code,"cancelled":report.termination==TerminationReason::Cancelled,"raw_artifact":raw,"input_digest":input_digest,"pin":package.version().pin,"protected_acceptance":false,"task_completed":false}),
    )
}
