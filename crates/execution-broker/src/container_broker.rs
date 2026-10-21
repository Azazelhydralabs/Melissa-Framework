//! Explicit Linux container backend on a Windows host. Never a native fallback.
use crate::{
    BrokerError, BrokerResult, InvocationIdentity, PolicyControl,
    container_policy::SignedContainerPermit,
    policy::{HostPolicy, PermitAuthority, PermitMacKey, PermitRequest, authenticated_digest},
    process_control::ProcessControlService,
    unix_ms,
};
use melissa_container_executor::{
    ContainerReport, ContainerRequest, Executor, Snapshot, TerminationReason,
};
use melissa_core_contracts::{
    catalog::Catalog,
    validation::Validate,
    wire::{EffectStatus, ObservationArtifactV2, ObservationStatus, ToolObservationV2},
};
use melissa_local_store::{
    ArtifactRequest, LocalStore,
    journal::{AdmissionRequest, AttemptState, InvocationRequest},
};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};

pub struct ContainerBroker {
    store: LocalStore,
    catalog: Arc<Catalog>,
    resource_id: String,
    authority: Arc<PermitAuthority>,
    policy: PolicyControl,
}
#[derive(Debug, Serialize)]
pub struct ContainerExecution {
    pub observation: ToolObservationV2,
    pub report: Option<ContainerReport>,
    pub result_artifact_id: String,
    pub requires_reconciliation: bool,
}
impl ContainerBroker {
    pub fn new(
        store: LocalStore,
        catalog: Catalog,
        resource_id: String,
        mut policy: HostPolicy,
    ) -> BrokerResult<Self> {
        crate::broker::validate_container_enforcement(&policy)?;
        if resource_id.trim().is_empty() {
            return Err(BrokerError::Invalid(
                "container resource identity required".into(),
            ));
        }
        let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *secret)
            .map_err(|_| BrokerError::Denied("host entropy unavailable".into()))?;
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id)
            .map_err(|_| BrokerError::Denied("host entropy unavailable".into()))?;
        policy.key_id = format!(
            "container-session:{}",
            id.iter().map(|v| format!("{v:02x}")).collect::<String>()
        );
        Ok(Self {
            store,
            catalog: Arc::new(catalog),
            resource_id,
            authority: Arc::new(PermitAuthority::new(PermitMacKey::from_bytes(*secret))),
            policy: PolicyControl {
                state: Arc::new(RwLock::new(policy)),
                container_backend: true,
            },
        })
    }
    pub fn store(&self) -> &LocalStore {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut LocalStore {
        &mut self.store
    }
    pub fn policy_control(&self) -> PolicyControl {
        self.policy.clone()
    }
    pub fn control_service(&self) -> BrokerResult<ProcessControlService> {
        Ok(ProcessControlService::new(
            self.store.connect()?,
            Arc::clone(&self.catalog),
            Arc::clone(&self.authority),
            self.policy.clone(),
            self.resource_id.clone(),
        ))
    }
    pub fn issue_permit(
        &self,
        task_id: &str,
        request: ContainerRequest,
        snapshot: &Snapshot,
        permit: PermitRequest,
    ) -> BrokerResult<SignedContainerPermit> {
        if permit.resource_id != self.resource_id {
            return Err(BrokerError::Denied(
                "container permit outside resource".into(),
            ));
        }
        snapshot.validate(request.limits.disk_bytes)?;
        let task = self.store.journal().task(task_id)?;
        Ok(self.authority.issue_container(
            &self.catalog,
            &task.contract,
            request,
            snapshot.digest()?,
            permit,
            &self.policy.snapshot()?,
            unix_ms()?,
        )?)
    }
    pub fn execute(
        &mut self,
        task_id: &str,
        signed: &SignedContainerPermit,
        snapshot: &Snapshot,
        identity: &InvocationIdentity,
        cancelled: &AtomicBool,
    ) -> BrokerResult<ContainerExecution> {
        self.execute_inner(task_id, signed, snapshot, identity, cancelled, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn execute_conversation(
        &mut self,
        task_id: &str,
        signed: &SignedContainerPermit,
        snapshot: &Snapshot,
        identity: &InvocationIdentity,
        cancelled: &AtomicBool,
        conversation: melissa_container_executor::Conversation,
    ) -> BrokerResult<ContainerExecution> {
        self.execute_inner(
            task_id,
            signed,
            snapshot,
            identity,
            cancelled,
            Some(conversation),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn execute_inner(
        &mut self,
        task_id: &str,
        signed: &SignedContainerPermit,
        snapshot: &Snapshot,
        identity: &InvocationIdentity,
        cancelled: &AtomicBool,
        conversation: Option<melissa_container_executor::Conversation>,
    ) -> BrokerResult<ContainerExecution> {
        if signed.permit.task_id != task_id || signed.permit.resource_id != self.resource_id {
            return Err(BrokerError::Denied(
                "container permit outside task/resource".into(),
            ));
        }
        for id in [&identity.invocation_id, &identity.attempt_id] {
            if id.is_empty() || id.len() > 160 || id.chars().any(char::is_control) {
                return Err(BrokerError::Invalid(
                    "bounded invocation identity required".into(),
                ));
            }
        }
        let request = &signed.binding.request;
        snapshot.validate(request.limits.disk_bytes)?;
        let snapshot_digest = snapshot.digest()?;
        let monitor = self.store.connect()?;
        let policy = self
            .policy
            .state
            .read()
            .map_err(|_| BrokerError::Denied("policy lock poisoned".into()))?;
        let task = self.store.journal().task(task_id)?;
        self.authority.verify_container(
            &self.catalog,
            &task.contract,
            signed,
            request,
            &snapshot_digest,
            &policy,
            unix_ms()?,
        )?;
        let permit_digest = authenticated_digest(signed)?;
        let proposed = self.store.journal_mut().propose_invocation(
            &InvocationRequest {
                invocation_id: identity.invocation_id.clone(),
                task_id: task_id.into(),
                tool_id: "process.exec".into(),
                arguments: serde_json::to_value(request)?,
                idempotency_key: identity.idempotency_key.clone(),
                generation: identity.generation,
            },
            task.record.version,
        )?;
        let prepared =
            (|| -> BrokerResult<_> { Ok((self.store.journal().task(task_id)?, unix_ms()?)) })();
        let (task, now) = match prepared {
            Ok(value) => value,
            Err(error) => {
                crate::broker::reject_preparation(&mut self.store, &proposed);
                return Err(error);
            }
        };
        if let Err(error) = self.authority.verify_container(
            &self.catalog,
            &task.contract,
            signed,
            request,
            &snapshot_digest,
            &policy,
            now,
        ) {
            crate::broker::reject_preparation(&mut self.store, &proposed);
            return Err(error.into());
        }
        let admitted = self.store.journal_mut().admit_dispatch(&AdmissionRequest {
            permit_id: signed.permit.permit_id.clone(),
            nonce: signed.permit.nonce.clone(),
            permit_digest,
            task_id: task_id.into(),
            principal_id: signed.permit.principal_id.clone(),
            profile_id: signed.binding.profile_id.clone(),
            tool_id: "process.exec".into(),
            resource_id: self.resource_id.clone(),
            arguments_digest: signed.permit.arguments_digest.clone(),
            invocation_id: identity.invocation_id.clone(),
            attempt_id: identity.attempt_id.clone(),
            generation: identity.generation,
            expected_task_version: task.record.version,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: signed.permit.not_before_unix_ms,
            expires_at_unix_ms: signed.permit.expires_at_unix_ms,
            consumed_at_unix_ms: now,
        });
        if let Err(error) = admitted {
            crate::broker::reject_preparation(&mut self.store, &proposed);
            return Err(error.into());
        }
        drop(policy);
        let outcome = (|| -> BrokerResult<ContainerExecution> {
            let guard = self.store.journal().attempt_guard(&identity.attempt_id)?;
            self.store.journal_mut().start_attempt(&guard)?;
            let expires = signed.permit.expires_at_unix_ms;
            let remaining = expires.saturating_sub(unix_ms()?);
            let mut applied = request.clone();
            applied.limits.wall_time_ms = applied.limits.wall_time_ms.min(remaining.max(1));
            let signal = AtomicBool::new(cancelled.load(Ordering::Acquire) || remaining == 0);
            let stop = AtomicBool::new(false);
            let reason = AtomicU8::new(0);
            let bound_policy = signed.binding.policy_digest.clone();
            let policy = self.policy.clone();
            let permit_id = signed.permit.permit_id.clone();
            let result = std::thread::scope(|scope| {
                let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                let signal_ref = &signal;
                let stop_ref = &stop;
                let reason_ref = &reason;
                let watcher = scope.spawn(move || {
                    let mut previous = now;
                    let mut ready = Some(ready_tx);
                    while !stop_ref.load(Ordering::Acquire) {
                        let current = unix_ms();
                        let cause = if cancelled.load(Ordering::Acquire) {
                            1
                        } else if current.as_ref().is_ok_and(|v| *v < previous) {
                            5
                        } else if current.as_ref().is_ok_and(|v| *v >= expires) {
                            2
                        } else if policy
                            .snapshot()
                            .and_then(|p| p.digest().map_err(BrokerError::from))
                            .map_or(true, |v| v != bound_policy)
                        {
                            3
                        } else {
                            match monitor.journal().is_permit_revoked(&permit_id) {
                                Ok(true) => 3,
                                Err(_) => 4,
                                Ok(false) => match monitor.journal().is_cancel_requested(
                                    task_id,
                                    &identity.invocation_id,
                                    identity.generation,
                                ) {
                                    Ok(true) => 1,
                                    Ok(false) => 0,
                                    Err(_) => 4,
                                },
                            }
                        };
                        let cause = if let Ok(current) = current {
                            previous = current;
                            cause
                        } else {
                            4
                        };
                        if cause != 0 {
                            reason_ref.store(cause, Ordering::Release);
                            signal_ref.store(true, Ordering::Release);
                        }
                        if let Some(ready) = ready.take()
                            && ready.send(()).is_err()
                        {
                            reason_ref.store(4, Ordering::Release);
                            signal_ref.store(true, Ordering::Release);
                            break;
                        }
                        if cause != 0 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                });
                let result = if crate::broker::await_initial_control_check(
                    &ready_rx, &signal, &reason,
                ) {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        Executor::run_with_io(
                            &applied,
                            snapshot,
                            &signal,
                            &mut |container_id| {
                                let id = format!("{}:container-identity", identity.attempt_id);
                                let payload = serde_json::to_vec(
                                    &json!({"schema_version":"melissa.container-identity/v1","container_id":container_id,"image_id":signed.binding.request.image_id,"task_id":task_id,"invocation_id":identity.invocation_id,"attempt_id":identity.attempt_id,"generation":identity.generation,"permit_digest":authenticated_digest(signed).map_err(|e|melissa_container_executor::ExecutorError::Control(e.to_string()))?,"snapshot_digest":signed.binding.snapshot_digest,"execution_contract":melissa_container_executor::EXECUTION_CONTRACT}),
                                )?;
                                self.put(
                                    task_id,
                                    &id,
                                    "application/json",
                                    "process.container_identity",
                                    &payload,
                                    &identity.attempt_id,
                                )
                                .map_err(|e| {
                                    melissa_container_executor::ExecutorError::Control(
                                        e.to_string(),
                                    )
                                })
                            },
                            conversation,
                        )
                    }))
                } else {
                    Ok(Err(
                        melissa_container_executor::ExecutorError::CancelledBeforeLaunch,
                    ))
                };
                stop.store(true, Ordering::Release);
                if watcher.join().is_err() {
                    reason.store(4, Ordering::Release);
                }
                match result {
                    Ok(result) => result,
                    Err(_) => Err(melissa_container_executor::ExecutorError::Control(
                        "executor unwound after durable dispatch".into(),
                    )),
                }
            });
            let mut cause = reason.load(Ordering::Acquire);
            if cause == 0
                && result
                    .as_ref()
                    .is_ok_and(|r| r.termination == TerminationReason::Timeout)
                && unix_ms()? >= expires
            {
                cause = 2;
            }
            self.persist(task_id, signed, identity, result, cause)
        })();
        if outcome.is_err() {
            crate::broker::mark_unknown(&mut self.store, &identity.attempt_id);
        }
        outcome.map_err(|error| BrokerError::AfterDispatch(Box::new(error)))
    }
    fn persist(
        &mut self,
        task_id: &str,
        signed: &SignedContainerPermit,
        identity: &InvocationIdentity,
        result: Result<ContainerReport, melissa_container_executor::ExecutorError>,
        control: u8,
    ) -> BrokerResult<ContainerExecution> {
        let not_started = matches!(
            result,
            Err(melissa_container_executor::ExecutorError::CancelledBeforeLaunch)
        );
        let (report, error) = match result {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let uncertain = matches!(control, 4 | 5)
            || (!not_started
                && report.as_ref().is_none_or(|r| {
                    !r.cleanup_confirmed
                        || !r.tree_confirmed_stopped
                        || !r.policy_verified
                        || !r.disk_limit_hard_enforced
                        || !r.cpu_rate_hard_enforced
                        || r.termination == TerminationReason::MonitorFailure
                }));
        let success = !uncertain
            && control == 0
            && report.as_ref().is_some_and(|r| {
                r.termination == TerminationReason::Exited
                    && r.exit_code == Some(0)
                    && !r.output_truncated
                    && !r.export_truncated
                    && r.orphan_process_ids.is_empty()
            });
        let cancelled = control != 0
            || report
                .as_ref()
                .is_some_and(|r| r.termination == TerminationReason::Cancelled);
        let (status, effect, state) = if uncertain {
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
        let mut refs = Vec::new();
        let mut artifacts = Vec::new();
        if let Some(r) = &report {
            let id = format!("{}:container-identity", identity.attempt_id);
            let value: serde_json::Value =
                serde_json::from_slice(&self.store.get_artifact(task_id, &id)?)?;
            if value["container_id"] != r.container_id
                || value["image_id"] != r.image_id
                || value["snapshot_digest"] != signed.binding.snapshot_digest
                || r.input_digest != signed.binding.snapshot_digest
                || r.execution_contract != melissa_container_executor::EXECUTION_CONTRACT
            {
                return Err(BrokerError::Denied(
                    "container outcome identity differs from prelaunch durable record".into(),
                ));
            }
            refs.push(id.clone());
            artifacts.push(ObservationArtifactV2 {
                r#type: "process.container_identity".into(),
                uri: id,
            });
        }
        if let Some(r) = &report {
            for (suffix, bytes, mime) in [
                ("stdout", r.stdout.as_slice(), "application/octet-stream"),
                ("stderr", r.stderr.as_slice(), "application/octet-stream"),
                (
                    "workspace-archive",
                    r.archive.as_slice(),
                    "application/x-tar",
                ),
            ] {
                let id = format!("{}:{suffix}", identity.attempt_id);
                self.put(
                    task_id,
                    &id,
                    mime,
                    &format!("process.{suffix}"),
                    bytes,
                    &identity.attempt_id,
                )?;
                refs.push(id.clone());
                artifacts.push(ObservationArtifactV2 {
                    r#type: format!("process.{suffix}"),
                    uri: id,
                });
            }
        }
        let mut metadata = serde_json::to_value(&report)?;
        if let Some(object) = metadata.as_object_mut() {
            object.remove("stdout");
            object.remove("stderr");
            object.remove("archive");
        }
        let report_id = format!("{}:execution-report", identity.attempt_id);
        let payload = serde_json::to_vec(
            &json!({"schema_version":"melissa.container-execution-report/v1","permit_digest":authenticated_digest(signed)?,"report":metadata,"raw_refs":refs,"error":error,"control_reason":control,"requires_reconciliation":uncertain,"requires_output_review":!success,"task_accepted":false}),
        )?;
        self.put(
            task_id,
            &report_id,
            "application/json",
            "process.execution_report",
            &payload,
            &identity.attempt_id,
        )?;
        refs.push(report_id.clone());
        artifacts.push(ObservationArtifactV2 {
            r#type: "process.execution_report".into(),
            uri: report_id,
        });
        let mut usage = BTreeMap::from([
            ("duration_known".into(), json!(report.is_some())),
            (
                "disk_limit_hard_enforced".into(),
                json!(report.as_ref().is_some_and(|r| r.disk_limit_hard_enforced)),
            ),
            (
                "cpu_rate_hard_enforced".into(),
                json!(report.as_ref().is_some_and(|r| r.cpu_rate_hard_enforced)),
            ),
        ]);
        if let Some(r) = &report {
            usage.insert("total_cpu_time_ms".into(), json!(r.total_cpu_time_ms));
            usage.insert(
                "cpu_measurement_complete".into(),
                json!(r.cpu_measurement_complete),
            );
            usage.insert(
                "memory_usage_at_snapshot_bytes".into(),
                json!(r.memory_usage_at_snapshot_bytes),
            );
        }
        let observation=ToolObservationV2{schema_version:"melissa.tool-observation/v2".into(),task_id:task_id.into(),invocation_id:identity.invocation_id.clone(),attempt_id:identity.attempt_id.clone(),tool_id:"process.exec".into(),status,effect_status:effect,summary:if success{"Isolated container command completed; independent task acceptance remains separate."}else if uncertain{"Container execution requires reconciliation; durable dispatch is retained."}else{"Container command stopped without success; partial archived output requires review."}.into(),artifact_refs:refs,evidence_refs:Vec::new(),exit_code:report.as_ref().and_then(|r|r.exit_code.map(i64::from)),duration_ms:report.as_ref().map_or(0,|r|r.elapsed_ms),truncated:report.as_ref().is_some_and(|r|r.output_truncated||r.export_truncated),error_category:(!success).then(||if not_started&&matches!(control,0|1){"cancelled_before_launch".into()}else{container_category(control,report.as_ref(),uncertain).into()}),resource_usage:usage,input_digest:signed.permit.arguments_digest.clone(),output_digest:Some(melissa_local_store::cas::digest_for(&payload)),environment_ref:melissa_container_executor::EXECUTION_CONTRACT.into(),artifacts,metrics:BTreeMap::from([("process_success".into(),json!(success)),("task_accepted".into(),json!(false)),("requires_output_review".into(),json!(!success))]),warnings:vec!["Hard disk capacity is allocated tmpfs storage; aggregate logical file length and export limits are distinct.".into(),"CPU rate is an OS bandwidth cap; aggregate lifetime CPU is monitored with explicit host/grant opt-in.".into(),"The tar archive is untrusted and is never extracted/imported by this broker.".into()]};
        observation
            .validate()
            .map_err(|e| BrokerError::Invalid(e.to_string()))?;
        let id = format!("{}:observation", identity.attempt_id);
        self.put(
            task_id,
            &id,
            "application/json",
            "tool.observation",
            &serde_json::to_vec(&observation)?,
            &identity.attempt_id,
        )?;
        let guard = self.store.journal().attempt_guard(&identity.attempt_id)?;
        self.store.finish_attempt(&guard, state, Some(&id))?;
        Ok(ContainerExecution {
            observation,
            report,
            result_artifact_id: id,
            requires_reconciliation: uncertain,
        })
    }
    fn put(
        &mut self,
        task: &str,
        id: &str,
        mime: &str,
        logical: &str,
        bytes: &[u8],
        pin: &str,
    ) -> BrokerResult<()> {
        self.store.put_artifact(
            &ArtifactRequest {
                artifact_id: id.into(),
                task_id: task.into(),
                content_type: mime.into(),
                logical_type: logical.into(),
                schema_version: "melissa.container-artifact/v1".into(),
                retain_until_ms: 0,
                legal_hold: false,
            },
            bytes,
        )?;
        self.store.pin_artifact(task, id, pin)?;
        Ok(())
    }
}
fn container_category(
    control: u8,
    report: Option<&ContainerReport>,
    uncertain: bool,
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
    match report.map(|r| r.termination) {
        Some(TerminationReason::Timeout) => "timeout",
        Some(TerminationReason::CpuLimit) => "cpu_limit",
        Some(TerminationReason::OutputLimit) => "output_limit",
        Some(TerminationReason::ExportLimit) => "export_limit",
        Some(TerminationReason::OrphanDescendants) => "orphan_descendants",
        Some(TerminationReason::Cancelled) => "cancelled",
        _ => "process_exit_nonzero",
    }
}

pub fn parse_container_permit(bytes: &[u8]) -> BrokerResult<SignedContainerPermit> {
    melissa_core_contracts::json::parse_contract(bytes, 512 * 1024)
        .map_err(|e| BrokerError::Invalid(e.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(transparent)]
struct ParsedContainer(ContainerRequest);
impl Validate for ParsedContainer {
    fn validate(&self) -> melissa_core_contracts::validation::ContractResult {
        self.0
            .validate()
            .map_err(|e| melissa_core_contracts::validation::ContractError::new("$", e.to_string()))
    }
}
pub fn parse_container_request(bytes: &[u8]) -> BrokerResult<ContainerRequest> {
    melissa_core_contracts::json::parse_contract::<ParsedContainer>(bytes, 512 * 1024)
        .map(|value| value.0)
        .map_err(|e| BrokerError::Invalid(e.to_string()))
}

pub fn container_tool_schema() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../schemas/container-exec.schema.json"))
        .expect("committed container schema is valid")
}
