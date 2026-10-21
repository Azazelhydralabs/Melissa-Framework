use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use melissa_core_contracts::{
    catalog::Catalog,
    validation::Validate,
    wire::{EffectStatus, ObservationArtifactV2, ObservationStatus, ToolObservationV2},
};
use melissa_local_store::{
    ArtifactRequest, LocalStore,
    journal::{AdmissionRequest, AttemptState, InvocationRecord, InvocationRequest},
};
use melissa_windows_executor::{
    ExecuteRequest, ExecutionLimits, Executor, ExecutorReport, TerminationReason,
};
use serde::Serialize;
use serde_json::json;

use crate::{
    BrokerError, BrokerResult,
    paths::PinnedProcess,
    policy::{
        self, HostPolicy, PermitAuthority, PermitMacKey, PermitRequest, ProcessSpec, SignedPermit,
    },
};

#[derive(Clone)]
pub struct PolicyControl {
    pub(crate) state: Arc<RwLock<HostPolicy>>,
    pub(crate) container_backend: bool,
}
impl PolicyControl {
    pub fn snapshot(&self) -> BrokerResult<HostPolicy> {
        self.state
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| BrokerError::Denied("policy lock poisoned".into()))
    }
    /// Trusted host configuration only. Changes invalidate old permits and
    /// stop affected active runs through the broker's revocation watcher.
    pub fn replace(&self, mut policy: HostPolicy) -> BrokerResult<()> {
        if self.container_backend {
            validate_container_enforcement(&policy)?;
        } else {
            validate_enforcement(&policy)?;
        }
        let mut current = self
            .state
            .write()
            .map_err(|_| BrokerError::Denied("policy lock poisoned".into()))?;
        if policy.key_id != current.key_id
            || policy.issuer != current.issuer
            || policy.audience != current.audience
        {
            return Err(BrokerError::Denied(
                "session issuer/key/audience cannot change in place".into(),
            ));
        }
        if policy.revocation_epoch < current.revocation_epoch
            || !policy
                .revoked_authorization_refs
                .is_superset(&current.revoked_authorization_refs)
            || !policy
                .revoked_permit_ids
                .is_superset(&current.revoked_permit_ids)
            || !policy.revoked_nonces.is_superset(&current.revoked_nonces)
        {
            return Err(BrokerError::Denied(
                "policy revocation cannot be rolled back within a host session".into(),
            ));
        }
        if policy.revocation_epoch == current.revocation_epoch
            && policy.digest()? != current.digest()?
        {
            policy.revocation_epoch = current
                .revocation_epoch
                .checked_add(1)
                .ok_or_else(|| BrokerError::Denied("policy epoch exhausted".into()))?;
        }
        *current = policy;
        Ok(())
    }
}

pub struct Broker {
    store: LocalStore,
    catalog: Arc<Catalog>,
    workspace: PathBuf,
    resource_id: String,
    authority: Arc<PermitAuthority>,
    policy: PolicyControl,
}

#[derive(Debug, Clone)]
pub struct InvocationIdentity {
    pub invocation_id: String,
    pub attempt_id: String,
    pub generation: u64,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BrokerExecution {
    pub observation: ToolObservationV2,
    pub report: Option<ExecutorReport>,
    pub result_artifact_id: String,
    pub requires_reconciliation: bool,
}

impl Broker {
    /// `workspace` is an owned staging directory. Original repositories and
    /// application installations must not be mounted writable by this API.
    pub fn new(
        store: LocalStore,
        catalog: Catalog,
        workspace: PathBuf,
        resource_id: String,
        mut policy: HostPolicy,
    ) -> BrokerResult<Self> {
        validate_enforcement(&policy)?;
        if !workspace.is_absolute() || resource_id.trim().is_empty() {
            return Err(BrokerError::Invalid(
                "absolute owned workspace and resource ID required".into(),
            ));
        }
        let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *secret)
            .map_err(|_| BrokerError::Denied("host entropy unavailable".into()))?;
        let mut identity = [0_u8; 16];
        getrandom::fill(&mut identity)
            .map_err(|_| BrokerError::Denied("host entropy unavailable".into()))?;
        policy.key_id = format!(
            "broker-session:{}",
            identity
                .iter()
                .map(|value| format!("{value:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            store,
            catalog: Arc::new(catalog),
            workspace,
            resource_id,
            authority: Arc::new(PermitAuthority::new(PermitMacKey::from_bytes(*secret))),
            policy: PolicyControl {
                state: Arc::new(RwLock::new(policy)),
                container_backend: false,
            },
        })
    }

    pub fn policy_control(&self) -> PolicyControl {
        self.policy.clone()
    }
    pub fn control_service(&self) -> BrokerResult<crate::process_control::ProcessControlService> {
        Ok(crate::process_control::ProcessControlService::new(
            self.store.connect()?,
            Arc::clone(&self.catalog),
            Arc::clone(&self.authority),
            self.policy.clone(),
            self.resource_id.clone(),
        ))
    }
    pub fn store(&self) -> &LocalStore {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut LocalStore {
        &mut self.store
    }
    pub fn resolve(&self, spec: &ProcessSpec) -> BrokerResult<PinnedProcess> {
        PinnedProcess::resolve(spec, &self.workspace)
    }

    pub fn issue_permit(
        &self,
        task_id: &str,
        pinned: &PinnedProcess,
        request: PermitRequest,
    ) -> BrokerResult<SignedPermit> {
        if request.resource_id != self.resource_id {
            return Err(BrokerError::Denied(
                "resource is not this broker's staged workspace".into(),
            ));
        }
        let current = pinned.revalidate(&self.workspace)?;
        let task = self.store.journal().task(task_id)?;
        let policy = self.policy.snapshot()?;
        Ok(self.authority.issue(
            &self.catalog,
            &task.contract,
            current.resolved().clone(),
            request,
            &policy,
            unix_ms()?,
        )?)
    }

    /// Fresh current policy, handles, expiry and durable consumption precede
    /// OS launch. Model tool JSON supplies none of this host authority.
    pub fn execute(
        &mut self,
        task_id: &str,
        signed: &SignedPermit,
        identity: &InvocationIdentity,
        cancelled: &AtomicBool,
    ) -> BrokerResult<BrokerExecution> {
        for value in [&identity.invocation_id, &identity.attempt_id] {
            if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
                return Err(BrokerError::Invalid(
                    "bounded invocation and attempt identifiers required".into(),
                ));
            }
        }
        if signed.permit.resource_id != self.resource_id || signed.permit.task_id != task_id {
            return Err(BrokerError::Denied(
                "permit outside broker task/workspace".into(),
            ));
        }
        let pinned = self.resolve(&signed.binding.process.spec)?;
        let _rechecked = pinned.revalidate(&self.workspace)?;
        let monitor_store = self.store.connect()?;
        let policy_guard = self
            .policy
            .state
            .read()
            .map_err(|_| BrokerError::Denied("policy lock poisoned".into()))?;
        let task = self.store.journal().task(task_id)?;
        self.authority.verify(
            &self.catalog,
            &task.contract,
            signed,
            pinned.resolved(),
            &policy_guard,
            unix_ms()?,
        )?;
        let permit_digest = policy::authenticated_digest(signed)?;
        let proposed = self.store.journal_mut().propose_invocation(
            &InvocationRequest {
                invocation_id: identity.invocation_id.clone(),
                task_id: task_id.into(),
                tool_id: "process.exec".into(),
                arguments: serde_json::to_value(&pinned.resolved().spec)?,
                idempotency_key: identity.idempotency_key.clone(),
                generation: identity.generation,
            },
            task.record.version,
        )?;
        let prepared =
            (|| -> BrokerResult<_> { Ok((self.store.journal().task(task_id)?, unix_ms()?)) })();
        let (after_proposal, now) = match prepared {
            Ok(value) => value,
            Err(error) => {
                reject_preparation(&mut self.store, &proposed);
                return Err(error);
            }
        };
        // Recheck under the same policy read guard immediately before the
        // atomic admission; durable revocation is checked inside its transaction.
        if let Err(error) = self.authority.verify(
            &self.catalog,
            &after_proposal.contract,
            signed,
            pinned.resolved(),
            &policy_guard,
            now,
        ) {
            reject_preparation(&mut self.store, &proposed);
            return Err(error.into());
        }
        let admission = AdmissionRequest {
            permit_id: signed.permit.permit_id.clone(),
            nonce: signed.permit.nonce.clone(),
            permit_digest,
            task_id: task_id.into(),
            principal_id: signed.permit.principal_id.clone(),
            profile_id: signed.binding.profile_id.clone(),
            tool_id: signed.permit.tool_id.clone(),
            resource_id: self.resource_id.clone(),
            arguments_digest: signed.permit.arguments_digest.clone(),
            invocation_id: identity.invocation_id.clone(),
            attempt_id: identity.attempt_id.clone(),
            generation: identity.generation,
            expected_task_version: after_proposal.record.version,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: signed.permit.not_before_unix_ms,
            expires_at_unix_ms: signed.permit.expires_at_unix_ms,
            consumed_at_unix_ms: now,
        };
        if let Err(error) = self.store.journal_mut().admit_dispatch(&admission) {
            reject_preparation(&mut self.store, &proposed);
            return Err(error.into());
        }
        drop(policy_guard);
        let attempt_guard = match self.store.journal().attempt_guard(&identity.attempt_id) {
            Ok(guard) => guard,
            Err(error) => {
                mark_unknown(&mut self.store, &identity.attempt_id);
                return Err(BrokerError::AfterDispatch(Box::new(error.into())));
            }
        };
        if let Err(error) = self.store.journal_mut().start_attempt(&attempt_guard) {
            mark_unknown(&mut self.store, &identity.attempt_id);
            return Err(BrokerError::AfterDispatch(Box::new(error.into())));
        }
        let limits = &pinned.resolved().spec.limits;
        let dispatch_time = match unix_ms() {
            Ok(now) => now,
            Err(error) => {
                mark_unknown(&mut self.store, &identity.attempt_id);
                return Err(BrokerError::AfterDispatch(Box::new(error)));
            }
        };
        let remaining = signed
            .permit
            .expires_at_unix_ms
            .saturating_sub(dispatch_time);
        let request = ExecuteRequest {
            executable: PathBuf::from(&pinned.resolved().canonical_executable),
            executable_blake3: pinned.resolved().executable_digest.clone(),
            workspace: self.workspace.clone(),
            current_directory: PathBuf::from(&pinned.resolved().canonical_cwd),
            arguments: pinned.resolved().spec.argv.clone(),
            environment: pinned.resolved().spec.env.clone(),
            limits: ExecutionLimits {
                wall_time_ms: limits.wall_time_ms.min(remaining.max(1)),
                cpu_time_ms: limits.cpu_time_ms,
                cpu_rate_basis_points: limits.cpu_rate_basis_points,
                memory_bytes: limits.memory_bytes,
                max_processes: limits.max_processes,
                max_output_bytes: limits.output_bytes,
                max_workspace_bytes: limits.disk_bytes,
                gpu_required: false,
            },
            network: melissa_windows_executor::NetworkMode::Offline,
            disk_mode: match limits.disk_mode {
                policy::DiskLimitMode::Strict => melissa_windows_executor::DiskLimitMode::Strict,
                policy::DiskLimitMode::Monitored => {
                    melissa_windows_executor::DiskLimitMode::Monitored
                }
            },
        };
        let combined = Arc::new(AtomicBool::new(
            cancelled.load(Ordering::Acquire) || remaining == 0,
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let control_reason = Arc::new(AtomicU8::new(0));
        let policy = self.policy.clone();
        let bound_policy = signed.binding.policy_digest.clone();
        let permit_id = signed.permit.permit_id.clone();
        let managed_task = task_id.to_owned();
        let managed_invocation = identity.invocation_id.clone();
        let managed_generation = identity.generation;
        let expires = signed.permit.expires_at_unix_ms;
        let result = std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let signal = Arc::clone(&combined);
            let done = Arc::clone(&stop);
            let reason = Arc::clone(&control_reason);
            let watcher = scope.spawn(move || {
                let mut previous = now;
                let mut ready = Some(ready_tx);
                while !done.load(Ordering::Acquire) {
                    let current = unix_ms();
                    let cause = if cancelled.load(Ordering::Acquire) {
                        1
                    } else if current.as_ref().is_ok_and(|value| *value < previous) {
                        5
                    } else if current.as_ref().is_ok_and(|value| *value >= expires) {
                        2
                    } else if policy
                        .snapshot()
                        .and_then(|p| p.digest().map_err(BrokerError::from))
                        .map_or(true, |digest| digest != bound_policy)
                    {
                        3
                    } else {
                        match monitor_store.journal().is_permit_revoked(&permit_id) {
                            Ok(false) => match monitor_store.journal().is_cancel_requested(
                                &managed_task,
                                &managed_invocation,
                                managed_generation,
                            ) {
                                Ok(true) => 1,
                                Ok(false) => 0,
                                Err(_) => 4,
                            },
                            Ok(true) => 3,
                            Err(_) => 4,
                        }
                    };
                    let cause = if let Ok(time) = current {
                        previous = time;
                        cause
                    } else {
                        4
                    };
                    if cause != 0 {
                        reason.store(cause, Ordering::Release);
                        signal.store(true, Ordering::Release);
                    }
                    if let Some(ready) = ready.take()
                        && ready.send(()).is_err()
                    {
                        reason.store(4, Ordering::Release);
                        signal.store(true, Ordering::Release);
                        break;
                    }
                    if cause != 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            let executed = if await_initial_control_check(&ready_rx, &combined, &control_reason) {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Executor::run(&request, &combined)
                }))
            } else {
                Ok(Err(
                    melissa_windows_executor::ExecutorError::CancelledBeforeLaunch,
                ))
            };
            stop.store(true, Ordering::Release);
            if watcher.join().is_err() {
                control_reason.store(4, Ordering::Release);
            }
            match executed {
                Ok(result) => result,
                Err(_) => Err(melissa_windows_executor::ExecutorError::Security(
                    "executor unwound; durable dispatch requires reconciliation".into(),
                )),
            }
        });
        // Keep all original and revalidated filesystem handles alive until the
        // Job is empty and native cleanup has finished.
        let mut final_control = control_reason.load(Ordering::Acquire);
        if final_control == 0
            && result
                .as_ref()
                .is_ok_and(|r| r.termination == TerminationReason::Timeout)
        {
            match unix_ms() {
                Ok(now) if now >= expires => final_control = 2,
                Err(_) => final_control = 4,
                _ => {}
            }
        }
        let saved = self.persist_outcome(task_id, signed, identity, result, final_control);
        if saved.is_err() {
            mark_unknown(&mut self.store, &identity.attempt_id);
        }
        saved.map_err(|error| BrokerError::AfterDispatch(Box::new(error)))
    }

    pub fn inspect_invocation(
        &self,
        task_id: &str,
        invocation_id: &str,
    ) -> BrokerResult<InvocationRecord> {
        let record = self.store.journal().invocation(invocation_id)?;
        if record.task_id != task_id {
            return Err(BrokerError::Denied(
                "managed invocation belongs to another task".into(),
            ));
        }
        Ok(record)
    }

    pub fn revoke_permit(&mut self, permit_id: &str, reason: &str) -> BrokerResult<()> {
        self.store
            .journal_mut()
            .revoke_permit(permit_id, reason, unix_ms()?)?;
        Ok(())
    }

    fn persist_outcome(
        &mut self,
        task_id: &str,
        signed: &SignedPermit,
        identity: &InvocationIdentity,
        result: Result<ExecutorReport, melissa_windows_executor::ExecutorError>,
        control: u8,
    ) -> BrokerResult<BrokerExecution> {
        let not_started = matches!(
            result,
            Err(melissa_windows_executor::ExecutorError::CancelledBeforeLaunch)
        );
        let (report, error) = match result {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let uncertain = (!not_started
            && report.as_ref().is_none_or(|r| {
                !r.tree_confirmed_stopped
                    || !r.process_was_appcontainer
                    || !r.win32k_system_calls_disabled
                    || !r.cpu_rate_hard_enforced
                    || r.environment_contract != policy::HOST_EXECUTION_CONTRACT_VERSION
                    || !r.profile_removed
                    || !r.acl_restored
                    || r.termination == TerminationReason::MonitorFailure
            }))
            || matches!(control, 4 | 5);
        let success = !uncertain
            && control == 0
            && report.as_ref().is_some_and(|r| {
                r.termination == TerminationReason::Exited
                    && r.exit_code == 0
                    && !r.output_truncated
                    && !r.descendant_cleanup_required
            });
        let cancelled = control != 0
            || report
                .as_ref()
                .is_some_and(|r| r.termination == TerminationReason::Cancelled);
        let (status, effect, attempt_state) = if uncertain {
            (
                ObservationStatus::OutcomeUnknown,
                EffectStatus::Unknown,
                AttemptState::OutcomeUnknown,
            )
        } else if not_started {
            (
                ObservationStatus::Cancelled,
                EffectStatus::NotStarted,
                AttemptState::Cancelled,
            )
        } else if success {
            (
                ObservationStatus::Success,
                EffectStatus::Observed,
                AttemptState::Succeeded,
            )
        } else if cancelled {
            (
                ObservationStatus::Cancelled,
                EffectStatus::Observed,
                AttemptState::Cancelled,
            )
        } else if report
            .as_ref()
            .is_some_and(|r| r.termination == TerminationReason::Timeout)
        {
            (
                ObservationStatus::TimedOut,
                EffectStatus::Observed,
                AttemptState::Failed,
            )
        } else {
            (
                ObservationStatus::Failed,
                EffectStatus::Observed,
                AttemptState::Failed,
            )
        };
        let mut artifacts = Vec::new();
        let mut typed = Vec::new();
        if let Some(report) = &report {
            for (suffix, data) in [
                ("stdout", report.stdout.as_slice()),
                ("stderr", report.stderr.as_slice()),
            ] {
                let id = format!("{}:{suffix}", identity.attempt_id);
                self.store.put_artifact(
                    &artifact_request(
                        task_id,
                        &id,
                        "application/octet-stream",
                        "process.raw_output",
                    ),
                    data,
                )?;
                self.store
                    .pin_artifact(task_id, &id, &identity.attempt_id)?;
                typed.push(ObservationArtifactV2 {
                    r#type: format!("process.{suffix}"),
                    uri: id.clone(),
                });
                artifacts.push(id);
            }
        }
        let report_id = format!("{}:execution-report", identity.attempt_id);
        let mut report_metadata = serde_json::to_value(&report)?;
        if let Some(object) = report_metadata.as_object_mut() {
            object.remove("stdout");
            object.remove("stderr");
        }
        let payload = serde_json::to_vec(
            &json!({"schema_version":"melissa.broker-execution-report/v1","permit_digest":policy::authenticated_digest(signed)?,"report":report_metadata,"raw_output_refs":artifacts,"error":error,"control_reason":control,"outcome_uncertain":uncertain,"requires_output_review":!success,"task_accepted":false}),
        )?;
        self.store.put_artifact(
            &artifact_request(
                task_id,
                &report_id,
                "application/json",
                "process.execution_report",
            ),
            &payload,
        )?;
        self.store
            .pin_artifact(task_id, &report_id, &identity.attempt_id)?;
        artifacts.push(report_id.clone());
        typed.push(ObservationArtifactV2 {
            r#type: "process.execution_report".into(),
            uri: report_id.clone(),
        });
        let mut usage = BTreeMap::new();
        usage.insert(
            "duration_known".into(),
            json!(report.is_some() || not_started),
        );
        if let Some(r) = &report {
            usage.insert(
                "cpu_rate_basis_points".into(),
                json!(r.cpu_rate_basis_points),
            );
            usage.insert("cpu_rate_denominator".into(), json!("host_processors"));
            usage.insert(
                "cpu_rate_hard_enforced".into(),
                json!(r.cpu_rate_hard_enforced),
            );
            usage.insert("total_cpu_time_ms".into(), json!(r.total_cpu_time_ms));
            usage.insert(
                "peak_job_committed_memory_bytes".into(),
                json!(r.peak_job_committed_memory_bytes),
            );
            usage.insert(
                "peak_observed_workspace_and_profile_bytes".into(),
                json!(r.peak_observed_workspace_and_profile_bytes),
            );
            usage.insert("disk_overshoot_bytes".into(), json!(r.disk_overshoot_bytes));
        }
        let observation=ToolObservationV2 {
            schema_version:"melissa.tool-observation/v2".into(),task_id:task_id.into(),invocation_id:identity.invocation_id.clone(),attempt_id:identity.attempt_id.clone(),tool_id:"process.exec".into(),
            status,effect_status:effect,summary:if success{"Isolated process exited successfully; task acceptance remains separate."}else if uncertain{"Execution requires reconciliation; durable dispatch is retained."}else{"Isolated process stopped without successful completion; partial staged outputs may remain."}.into(),
            artifact_refs:artifacts,evidence_refs:Vec::new(),exit_code:report.as_ref().map(|r|i64::from(r.exit_code)),duration_ms:report.as_ref().map_or(0,|r|r.elapsed_ms),truncated:report.as_ref().is_some_and(|r|r.output_truncated),
            error_category:(!success).then(||failure_category(control,report.as_ref(),uncertain,not_started).into()),
            resource_usage:usage,input_digest:signed.permit.arguments_digest.clone(),output_digest:Some(melissa_local_store::cas::digest_for(&payload)),environment_ref:policy::HOST_EXECUTION_CONTRACT_VERSION.into(),
            artifacts:typed,metrics:BTreeMap::from([("process_success".into(),json!(success)),("task_accepted".into(),json!(false)),("requires_output_review".into(),json!(!success))]),
            warnings:vec!["Disk accounting and total CPU are sampled under explicit host opt-in; strict quotas are unsupported.".into(),"AppContainer permits common Windows runtime resources and its private profile; this is an owned staged workspace, not a writable original repository.".into()],
        };
        observation
            .validate()
            .map_err(|error| BrokerError::Invalid(error.to_string()))?;
        let observation_id = format!("{}:observation", identity.attempt_id);
        self.store.put_artifact(
            &artifact_request(
                task_id,
                &observation_id,
                "application/json",
                "tool.observation",
            ),
            &serde_json::to_vec(&observation)?,
        )?;
        let guard = self.store.journal().attempt_guard(&identity.attempt_id)?;
        self.store
            .finish_attempt(&guard, attempt_state, Some(&observation_id))?;
        Ok(BrokerExecution {
            observation,
            report,
            result_artifact_id: observation_id,
            requires_reconciliation: uncertain,
        })
    }
}

fn failure_category(
    control: u8,
    report: Option<&ExecutorReport>,
    uncertain: bool,
    not_started: bool,
) -> &'static str {
    match control {
        1 => return "cancelled",
        2 => return "permit_expired",
        3 => return "permit_revoked",
        4 => return "monitor_failure",
        5 => return "clock_rollback",
        _ => {}
    }
    if uncertain {
        return "outcome_unknown";
    }
    if not_started {
        return "cancelled_before_launch";
    }
    match report.map(|r| r.termination) {
        Some(TerminationReason::Cancelled) => "cancelled",
        Some(TerminationReason::Timeout) => "timeout",
        Some(TerminationReason::OutputLimit) => "output_limit",
        Some(TerminationReason::CpuLimit) => "cpu_limit",
        Some(TerminationReason::MemoryLimit) => "memory_limit",
        Some(TerminationReason::ProcessLimit) => "process_limit",
        Some(TerminationReason::DiskLimit) => "disk_limit",
        Some(TerminationReason::MonitorFailure) => "monitor_failure",
        Some(TerminationReason::Exited)
            if report.is_some_and(|r| r.descendant_cleanup_required) =>
        {
            "orphan_descendants"
        }
        _ => "process_exit_nonzero",
    }
}

fn artifact_request(task: &str, id: &str, mime: &str, logical: &str) -> ArtifactRequest {
    ArtifactRequest {
        artifact_id: id.into(),
        task_id: task.into(),
        content_type: mime.into(),
        logical_type: logical.into(),
        schema_version: "melissa.broker-artifact/v1".into(),
        retain_until_ms: 0,
        legal_hold: false,
    }
}

/// A durable dispatch does not authorize launch until the monitor has completed
/// its first fresh policy/revocation/cancellation read. A disconnected or stalled
/// monitor is an unknown control outcome and must never start user code.
pub(crate) fn await_initial_control_check(
    ready: &std::sync::mpsc::Receiver<()>,
    cancelled: &AtomicBool,
    reason: &AtomicU8,
) -> bool {
    if ready.recv_timeout(Duration::from_secs(5)).is_err() {
        reason.store(4, Ordering::Release);
        cancelled.store(true, Ordering::Release);
        return false;
    }
    !cancelled.load(Ordering::Acquire)
}

pub(crate) fn reject_preparation(store: &mut LocalStore, proposed: &InvocationRecord) {
    if let (Ok(task), Ok(invocation)) = (
        store.journal().task(&proposed.task_id),
        store.journal().invocation(&proposed.invocation_id),
    ) {
        let _ = store.journal_mut().reject_proposed_invocation(
            &invocation.invocation_id,
            task.record.version,
            invocation.version,
        );
    }
}
pub(crate) fn mark_unknown(store: &mut LocalStore, attempt: &str) {
    if let Ok(guard) = store.journal().attempt_guard(attempt) {
        let _ = store
            .journal_mut()
            .finish_attempt(&guard, AttemptState::OutcomeUnknown, None);
    }
}
fn validate_enforcement(policy: &HostPolicy) -> BrokerResult<()> {
    if !cfg!(windows) {
        return Err(BrokerError::Denied(
            "native Windows executor required".into(),
        ));
    }
    if policy.enforcement.disk_quota || policy.enforcement.cpu_time {
        return Err(BrokerError::Denied(
            "this native backend cannot prove hard disk or strict total CPU quotas".into(),
        ));
    }
    policy
        .ceiling
        .validate()
        .map_err(|error| BrokerError::Invalid(error.to_string()))?;
    Ok(())
}
pub(crate) fn validate_container_enforcement(policy: &HostPolicy) -> BrokerResult<()> {
    if policy.enforcement.cpu_time || !policy.enforcement.disk_quota {
        return Err(BrokerError::Denied("container backend requires truthful hard allocated disk and monitored lifetime CPU capabilities".into()));
    }
    policy
        .ceiling
        .validate()
        .map_err(|error| BrokerError::Invalid(error.to_string()))?;
    Ok(())
}
pub fn unix_ms() -> BrokerResult<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerError::Denied("host clock precedes epoch".into()))?
            .as_millis(),
    )
    .map_err(|_| BrokerError::Denied("host clock exceeds supported range".into()))
}

pub fn process_tool_schema() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../schemas/process-exec-v2.schema.json"))
        .expect("committed process schema is valid JSON")
}

pub fn environment_support() -> serde_json::Value {
    json!({"schema_version":"melissa.execution-support/v1","platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"native_backend":"windows_appcontainer_job","network":"offline_only","strict_disk_capacity":false,"strict_total_cpu":false,"sampled_modes_require_explicit_host_and_grant_opt_in":true,"real_ai_test":"not_run"})
}

#[cfg(test)]
mod startup_control_tests {
    use super::*;
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};

    #[test]
    fn launch_waits_for_the_initial_control_read_and_obeys_its_cancellation() {
        let cancelled = AtomicBool::new(false);
        let reason = AtomicU8::new(0);
        let (ready_tx, ready_rx) = sync_channel(1);
        let (entered_tx, entered_rx) = sync_channel(1);
        let (launched_tx, launched_rx) = sync_channel(1);
        std::thread::scope(|scope| {
            let cancellation = &cancelled;
            let control_reason = &reason;
            let launcher = scope.spawn(move || {
                entered_tx.send(()).unwrap();
                let launch = await_initial_control_check(&ready_rx, cancellation, control_reason);
                launched_tx.send(launch).unwrap();
            });
            entered_rx.recv().unwrap();
            // Deliberately hold the first monitor result. The launch decision
            // must remain blocked even when the monitor has not been scheduled.
            assert_eq!(
                launched_rx.recv_timeout(Duration::from_millis(50)),
                Err(RecvTimeoutError::Timeout)
            );
            reason.store(1, Ordering::Release);
            cancelled.store(true, Ordering::Release);
            ready_tx.send(()).unwrap();
            assert!(!launched_rx.recv().unwrap());
            launcher.join().unwrap();
        });
        assert_eq!(reason.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_monitor_that_panics_before_its_first_read_cannot_authorize_launch() {
        let cancelled = AtomicBool::new(false);
        let reason = AtomicU8::new(0);
        let (ready_tx, ready_rx) = sync_channel::<()>(1);
        let monitor = std::thread::spawn(move || {
            let _owned_sender = ready_tx;
            panic!("injected initial control monitor failure");
        });
        assert!(!await_initial_control_check(&ready_rx, &cancelled, &reason));
        assert!(monitor.join().is_err());
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(reason.load(Ordering::Acquire), 4);
    }
}
