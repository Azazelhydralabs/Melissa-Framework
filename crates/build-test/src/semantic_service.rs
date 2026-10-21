//! Least privilege finite semantic service: no process.exec grant is created.
use crate::{
    Error, Result,
    full::{ProcedurePlan, Status, digest, put},
    semantic::SemanticPlan,
    tools::{CodeOperation, Host, denied, token},
};
use melissa_container_executor::{Executor, ExecutorError, TerminationReason};
use melissa_core_contracts::TaskState;
use melissa_execution_broker::unix_ms;
use melissa_local_store::journal::{AdmissionRequest, AttemptState, InvocationRequest};
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolExecution},
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub(crate) enum Plan<'a> {
    Semantic(&'a SemanticPlan),
    Procedure(&'a ProcedurePlan),
}
impl Plan<'_> {
    fn request(&self) -> &melissa_container_executor::ContainerRequest {
        match self {
            Self::Semantic(p) => p.request(),
            Self::Procedure(p) => p.request(),
        }
    }
    fn snapshot(&self) -> &melissa_container_executor::Snapshot {
        match self {
            Self::Semantic(p) => p.snapshot(),
            Self::Procedure(p) => p.snapshot(),
        }
    }
    fn source(&self) -> &melissa_repository::RepositorySnapshot {
        match self {
            Self::Semantic(p) => p.source(),
            Self::Procedure(p) => p.source(),
        }
    }
}
fn before(r: Result) -> Result {
    r.map_err(|e| match e {
        Error::AfterDispatch(inner) => *inner,
        other => other,
    })
}
pub(crate) fn execute(
    host: &mut Host,
    op: &CodeOperation,
    plan: Plan<'_>,
    call: &ToolCall,
    ctx: &ToolContext,
    cancel: Arc<AtomicBool>,
) -> Result<ToolExecution> {
    host.authority(op)?;
    host.repo.validate_snapshot(plan.source(), &cancel)?;
    let p = &host.policy;
    let issued = unix_ms()?;
    let expires = issued
        .checked_add(p.limits.wall_time_ms)
        .ok_or_else(denied)?
        .min(p.expires_at_ms);
    let token = token()?;
    let permit = format!("permit:code06-semantic:{token}");
    let input_id = format!("{}:semantic-input", ctx.invocation_id);
    let proposal_id = format!("{}:semantic-proposal", ctx.invocation_id);
    before(put(
        &mut host.store,
        &ctx.task_id,
        &input_id,
        "semantic.input",
        "application/json",
        &serde_json::to_vec(plan.snapshot())?,
    ))?;
    let policy_digest = p
        .process_policy
        .as_ref()
        .map(|p| p.digest())
        .transpose()
        .map_err(melissa_execution_broker::BrokerError::from)?;
    let metadata = json!({"schema_version":"melissa.semantic-dispatch/v1","operation":op,"request":plan.request(),"snapshot_digest":plan.snapshot().digest().map_err(|_|denied())?,"source_digest":plan.source().digest,"root_identity":host.repo.root_identity(),"task_id":ctx.task_id,"profile_id":ctx.profile_id,"principal_id":p.principal_id,"resource_id":p.resource_id,"authorization_ref":p.authorization_ref,"input_artifact_id":input_id,"wire_call_id":call.id,"arguments_digest":digest(call.arguments.as_bytes()),"run_id":ctx.run_id,"request_id":ctx.request_id,"permit_id":permit,"expires_at_ms":expires,"raw_process_authority":false,"process_policy_digest":policy_digest});
    let encoded = serde_json::to_vec(&metadata)?;
    before(put(
        &mut host.store,
        &ctx.task_id,
        &proposal_id,
        "semantic.proposal",
        "application/json",
        &encoded,
    ))?;
    host.authority(op)?;
    if cancel.load(Ordering::Acquire) {
        return Err(denied());
    }
    let task = host.store.journal().task(&ctx.task_id)?;
    let proposed=host.store.journal_mut().propose_invocation(&InvocationRequest{invocation_id:ctx.invocation_id.clone(),task_id:ctx.task_id.clone(),tool_id:op.canonical().into(),arguments:json!({"proposal_artifact_id":proposal_id,"proposal_digest":digest(&encoded),"permit_id":permit,"resource_id":p.resource_id,"authorization_ref":p.authorization_ref}),idempotency_key:None,generation:1},task.record.version)?;
    let admission = AdmissionRequest {
        permit_id: permit.clone(),
        nonce: format!("nonce:code06-semantic:{token}"),
        permit_digest: digest(&encoded),
        task_id: ctx.task_id.clone(),
        principal_id: p.principal_id.clone(),
        profile_id: ctx.profile_id.clone(),
        tool_id: op.canonical().into(),
        resource_id: p.resource_id.clone(),
        arguments_digest: proposed.arguments_digest,
        invocation_id: ctx.invocation_id.clone(),
        attempt_id: ctx.attempt_id.clone(),
        generation: 1,
        expected_task_version: host.store.journal().task(&ctx.task_id)?.record.version,
        expected_invocation_version: proposed.version,
        not_before_unix_ms: issued,
        expires_at_unix_ms: expires,
        consumed_at_unix_ms: unix_ms()?,
    };
    if let Err(e) = host.store.journal_mut().admit_dispatch(&admission) {
        if let Ok(g) = host.store.journal().attempt_guard(&ctx.attempt_id) {
            let _ = host
                .store
                .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
            return Err(Error::AfterDispatch(Box::new(e.into())));
        }
        if let Ok(t) = host.store.journal().task(&ctx.task_id) {
            let _ = host.store.journal_mut().reject_proposed_invocation(
                &ctx.invocation_id,
                t.record.version,
                proposed.version,
            );
        }
        return Err(e.into());
    }
    let effect = (|| -> Result<ToolExecution> {
        let monitor = host.store.connect()?;
        let signal = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let s = signal.clone();
        let done = stop.clone();
        let revoked = host.revoked.clone();
        let task_id = ctx.task_id.clone();
        let inv = ctx.invocation_id.clone();
        let permit_id = permit.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let wall = plan.request().limits.wall_time_ms;
        let watcher = std::thread::spawn(move || {
            let start = Instant::now();
            let mut ready = Some(tx);
            while !done.load(Ordering::Acquire) {
                let now = unix_ms();
                let t = monitor.journal().task(&task_id);
                let invalid = cancel.load(Ordering::Acquire)
                    || revoked.load(Ordering::Acquire)
                    || start.elapsed().as_millis() >= u128::from(wall)
                    || now.as_ref().map_or(true, |n| *n < issued || *n >= expires)
                    || !matches!(monitor.journal().is_permit_revoked(&permit_id), Ok(false))
                    || !matches!(
                        monitor.journal().is_cancel_requested(&task_id, &inv, 1),
                        Ok(false)
                    )
                    || t.as_ref().map_or(true, |t| {
                        t.record.state != TaskState::Running
                            || t.record.unknown_invocation_id.is_some()
                    });
                if invalid {
                    s.store(true, Ordering::Release);
                }
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
                if invalid {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let run = if ready && !signal.load(Ordering::Acquire) {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(||Executor::run_with_observer(plan.request(),plan.snapshot(),&signal,&mut|id|{
            put(&mut host.store,&ctx.task_id,&format!("{}:container-identity",ctx.attempt_id),"semantic.container-identity","application/json",&serde_json::to_vec(&json!({"container_id":id,"task_id":ctx.task_id,"invocation_id":ctx.invocation_id,"attempt_id":ctx.attempt_id,"permit_digest":admission.permit_digest,"image":plan.request().image_id})).map_err(|e|ExecutorError::Control(e.to_string()))?).map_err(|e|ExecutorError::Control(e.to_string()))
        }))).unwrap_or_else(|_|Err(ExecutorError::Control("semantic executor unwound".into())))
        } else {
            Err(ExecutorError::CancelledBeforeLaunch)
        };
        stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(denied());
        }
        let result_id = format!("{}:semantic-service-result", ctx.invocation_id);
        if matches!(run, Err(ExecutorError::CancelledBeforeLaunch)) {
            let content =
                json!({"status":"cancelled_before_launch","task_completed":false}).to_string();
            put(
                &mut host.store,
                &ctx.task_id,
                &result_id,
                "semantic.service-result",
                "application/json",
                content.as_bytes(),
            )?;
            let g = host.store.journal().attempt_guard(&ctx.attempt_id)?;
            host.store
                .finish_attempt(&g, AttemptState::Cancelled, Some(&result_id))?;
            return Ok(ToolExecution {
                content,
                success: false,
                cancelled: true,
                requires_reconciliation: false,
                artifact_refs: vec![input_id.clone(), proposal_id.clone(), result_id],
            });
        }
        let report = run.map_err(|_| denied())?;
        let raw_id = format!("{}:semantic-worker-report", ctx.attempt_id);
        put(
            &mut host.store,
            &ctx.task_id,
            &raw_id,
            "semantic.worker-report",
            "application/json",
            &serde_json::to_vec(&report)?,
        )?;
        if !report.cleanup_confirmed
            || !report.tree_confirmed_stopped
            || !report.policy_verified
            || report.monitor_error.is_some()
        {
            return Err(denied());
        }
        let (success, content, mut refs) = match plan {
            Plan::Semantic(p) => {
                let r = p.analyze(
                    &host.repo,
                    &mut host.store,
                    &ctx.task_id,
                    &ctx.attempt_id,
                    &report,
                    &raw_id,
                )?;
                (r.success, serde_json::to_string(&r)?, r.artifact_refs)
            }
            Plan::Procedure(p) => {
                let r = p.analyze(
                    &host.repo,
                    &mut host.store,
                    &ctx.task_id,
                    &ctx.attempt_id,
                    Some(&report),
                    false,
                    &raw_id,
                )?;
                let mut ids = r.raw_artifact_ids.clone();
                if let Some(id) = &r.report_artifact_id {
                    ids.push(id.clone());
                }
                (r.status == Status::Passed, serde_json::to_string(&r)?, ids)
            }
        };
        let cancelled = report.termination == TerminationReason::Cancelled;
        put(
            &mut host.store,
            &ctx.task_id,
            &result_id,
            "semantic.service-result",
            "application/json",
            content.as_bytes(),
        )?;
        let g = host.store.journal().attempt_guard(&ctx.attempt_id)?;
        host.store.finish_attempt(
            &g,
            if success {
                AttemptState::Succeeded
            } else if cancelled {
                AttemptState::Cancelled
            } else {
                AttemptState::Failed
            },
            Some(&result_id),
        )?;
        refs.extend([raw_id, input_id.clone(), proposal_id.clone(), result_id]);
        let content = if content.len() > 768 * 1024 {
            json!({"delivery":"paged_result","artifact_id":refs.last(),"digest":digest(content.as_bytes()),"total_bytes":content.len(),"next_offset":0,"complete":false,"task_completed":false}).to_string()
        } else {
            content
        };
        Ok(ToolExecution {
            content,
            success,
            cancelled,
            requires_reconciliation: false,
            artifact_refs: refs,
        })
    })();
    match effect {
        Ok(r) => Ok(r),
        Err(e) => {
            if let Ok(g) = host.store.journal().attempt_guard(&ctx.attempt_id) {
                let _ = host
                    .store
                    .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
            }
            Err(Error::AfterDispatch(Box::new(e)))
        }
    }
}
