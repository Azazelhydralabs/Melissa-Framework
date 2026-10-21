//! Initial pure domain guards, not a worker sandbox or a complete runtime.
//!
//! Evidence must be supplied by a trusted host verifier. Deserializing a model
//! response into these types does not authenticate evidence or authorize work.

use serde::{Deserialize, Serialize};

pub mod catalog;
pub mod catalog_models;
pub mod design;
pub mod json;
pub mod validation;
pub mod wire;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Core,
    Code,
    Cyber,
    Science,
    Game,
    Repack,
    Fit,
    Grid,
}

impl Module {
    pub const ALL: [Self; 8] = [
        Self::Core,
        Self::Code,
        Self::Cyber,
        Self::Science,
        Self::Game,
        Self::Repack,
        Self::Fit,
        Self::Grid,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Code => "code",
            Self::Cyber => "cyber",
            Self::Science => "science",
            Self::Game => "game",
            Self::Repack => "repack",
            Self::Fit => "fit",
            Self::Grid => "grid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Created,
    Planned,
    AwaitingApproval,
    Queued,
    Leased,
    Running,
    Verifying,
    Repairing,
    OutcomeUnknown,
    NeedsReconciliation,
    Blocked,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationState {
    Proposed,
    Authorized,
    Dispatched,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
    NeedsReconciliation,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionEvidence {
    pub task_id: String,
    pub acceptance_digest: String,
    pub final_digest: String,
    pub verified_digest: String,
    pub verifier_run_id: String,
    pub protected_checks_passed: bool,
    pub actual_tool_run: bool,
    pub raw_artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationEvidence {
    pub task_id: String,
    pub invocation_id: String,
    pub resolution_artifact_ref: String,
    pub external_effect_resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    IllegalTransition,
    MissingHostEvidence,
    UnverifiedFinalArtifact,
    FailedAcceptance,
    MissingRawArtifacts,
    VersionConflict,
    VersionExhausted,
    EvidenceScopeMismatch,
    UnresolvedExternalEffect,
    InvalidRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    pub task_id: String,
    pub module: Module,
    pub state: TaskState,
    pub version: u64,
    pub acceptance_digest: String,
    pub final_artifact_digest: Option<String>,
    pub unknown_invocation_id: Option<String>,
}

impl TaskRecord {
    /// Pure transition validation. A future storage adapter must atomically
    /// compare/version-update this record and append the matching event.
    pub fn transition(
        &mut self,
        expected_version: u64,
        next: TaskState,
        host_evidence: Option<&CompletionEvidence>,
    ) -> Result<(), TransitionError> {
        if self.version != expected_version {
            return Err(TransitionError::VersionConflict);
        }
        use crate::validation::Validate;
        self.validate()
            .map_err(|_| TransitionError::InvalidRecord)?;
        if self.unknown_invocation_id.is_some()
            && !matches!(
                self.state,
                TaskState::OutcomeUnknown | TaskState::NeedsReconciliation
            )
            && next != TaskState::OutcomeUnknown
        {
            return Err(TransitionError::UnresolvedExternalEffect);
        }
        use TaskState::*;
        let allowed = match self.state {
            Created => matches!(next, Planned | Cancelled),
            Planned => matches!(next, AwaitingApproval | Queued | Blocked | Cancelled),
            AwaitingApproval => matches!(next, Queued | Blocked | Cancelled),
            Queued => matches!(next, Leased | Blocked | Cancelled),
            Leased => matches!(next, Running | Queued | Cancelled | TimedOut),
            Running => matches!(
                next,
                Verifying | Repairing | OutcomeUnknown | Blocked | Failed | Cancelled | TimedOut
            ),
            Verifying => matches!(
                next,
                Completed | Repairing | OutcomeUnknown | Blocked | Failed | Cancelled
            ),
            Repairing => matches!(next, Queued | Running | Blocked | Failed | Cancelled),
            OutcomeUnknown => next == NeedsReconciliation,
            // Only record_reconciliation can leave this state. Routing through
            // Blocked must never erase an unresolved external effect.
            NeedsReconciliation => false,
            Blocked => matches!(next, Planned | Queued | Failed | Cancelled),
            Completed | Failed | Cancelled | TimedOut => false,
        };
        if !allowed {
            return Err(TransitionError::IllegalTransition);
        }
        if next == OutcomeUnknown
            && self
                .unknown_invocation_id
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(TransitionError::UnresolvedExternalEffect);
        }
        if next == Completed {
            let proof = host_evidence.ok_or(TransitionError::MissingHostEvidence)?;
            if proof.task_id != self.task_id
                || proof.acceptance_digest.trim().is_empty()
                || proof.acceptance_digest != self.acceptance_digest
            {
                return Err(TransitionError::EvidenceScopeMismatch);
            }
            if proof.task_id.trim().is_empty()
                || proof.final_digest.trim().is_empty()
                || proof.final_digest != proof.verified_digest
                || proof.verifier_run_id.trim().is_empty()
                || self.final_artifact_digest.as_ref() != Some(&proof.final_digest)
            {
                return Err(TransitionError::UnverifiedFinalArtifact);
            }
            if !proof.protected_checks_passed || !proof.actual_tool_run {
                return Err(TransitionError::FailedAcceptance);
            }
            if proof.raw_artifact_refs.is_empty()
                || proof
                    .raw_artifact_refs
                    .iter()
                    .any(|value| value.trim().is_empty())
            {
                return Err(TransitionError::MissingRawArtifacts);
            }
        }
        let new_version = self
            .version
            .checked_add(1)
            .ok_or(TransitionError::VersionExhausted)?;
        self.state = next;
        self.version = new_version;
        Ok(())
    }

    /// Records trusted host reconciliation; schema-valid model text is not
    /// reconciliation proof. Signature/store authentication is a later adapter.
    pub fn record_reconciliation(
        &mut self,
        expected_version: u64,
        proof: &ReconciliationEvidence,
    ) -> Result<(), TransitionError> {
        if self.version != expected_version {
            return Err(TransitionError::VersionConflict);
        }
        use crate::validation::Validate;
        self.validate()
            .map_err(|_| TransitionError::InvalidRecord)?;
        if self.state != TaskState::NeedsReconciliation {
            return Err(TransitionError::IllegalTransition);
        }
        if proof.task_id != self.task_id
            || self.unknown_invocation_id.as_ref() != Some(&proof.invocation_id)
        {
            return Err(TransitionError::EvidenceScopeMismatch);
        }
        if !proof.external_effect_resolved
            || proof.invocation_id.trim().is_empty()
            || proof.resolution_artifact_ref.trim().is_empty()
        {
            return Err(TransitionError::UnresolvedExternalEffect);
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(TransitionError::VersionExhausted)?;
        self.state = TaskState::Verifying;
        self.version = next_version;
        self.unknown_invocation_id = None;
        Ok(())
    }
}

impl validation::Validate for TaskRecord {
    fn validate(&self) -> validation::ContractResult<()> {
        use validation::{non_blank, require};
        non_blank(&self.task_id, "task_id")?;
        non_blank(&self.acceptance_digest, "acceptance_digest")?;
        if let Some(digest) = &self.final_artifact_digest {
            non_blank(digest, "final_artifact_digest")?;
        }
        if let Some(invocation) = &self.unknown_invocation_id {
            non_blank(invocation, "unknown_invocation_id")?;
            require(
                matches!(
                    self.state,
                    TaskState::Running
                        | TaskState::Verifying
                        | TaskState::OutcomeUnknown
                        | TaskState::NeedsReconciliation
                ),
                "unknown_invocation_id",
                "unresolved effect cannot be hidden in an unrelated state",
            )?;
        }
        if matches!(
            self.state,
            TaskState::OutcomeUnknown | TaskState::NeedsReconciliation
        ) {
            require(
                self.unknown_invocation_id.is_some(),
                "unknown_invocation_id",
                "reconciliation requires an invocation identity",
            )?;
        }
        if self.state == TaskState::Completed {
            require(
                self.final_artifact_digest.is_some(),
                "final_artifact_digest",
                "completed task needs a final artifact identity",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: TaskState) -> TaskRecord {
        TaskRecord {
            task_id: "task-code-001".into(),
            module: Module::Code,
            state,
            version: 4,
            acceptance_digest: "blake3:acceptance-contract-v1".into(),
            final_artifact_digest: Some("blake3:final-source".into()),
            unknown_invocation_id: matches!(
                state,
                TaskState::OutcomeUnknown | TaskState::NeedsReconciliation
            )
            .then(|| "invocation-001".into()),
        }
    }

    fn proof() -> CompletionEvidence {
        CompletionEvidence {
            task_id: "task-code-001".into(),
            acceptance_digest: "blake3:acceptance-contract-v1".into(),
            final_digest: "blake3:final-source".into(),
            verified_digest: "blake3:final-source".into(),
            verifier_run_id: "protected-verifier-001".into(),
            protected_checks_passed: true,
            actual_tool_run: true,
            raw_artifact_refs: vec!["artifact:test-log".into()],
        }
    }

    #[test]
    fn cannot_complete_from_a_model_running_state() {
        let mut task = record(TaskState::Running);
        assert_eq!(
            task.transition(4, TaskState::Completed, Some(&proof())),
            Err(TransitionError::IllegalTransition)
        );
        assert_eq!(task.version, 4);
    }

    #[test]
    fn cannot_complete_without_host_evidence() {
        let mut task = record(TaskState::Verifying);
        assert_eq!(
            task.transition(4, TaskState::Completed, None),
            Err(TransitionError::MissingHostEvidence)
        );
        assert_eq!(task.state, TaskState::Verifying);
    }

    #[test]
    fn stale_test_evidence_cannot_accept_changed_code() {
        let mut task = record(TaskState::Verifying);
        let mut stale = proof();
        stale.verified_digest = "blake3:old-source".into();
        assert_eq!(
            task.transition(4, TaskState::Completed, Some(&stale)),
            Err(TransitionError::UnverifiedFinalArtifact)
        );
    }

    #[test]
    fn skipped_or_failed_checks_do_not_become_success() {
        for (passed, ran) in [(false, true), (true, false), (false, false)] {
            let mut task = record(TaskState::Verifying);
            let mut invalid = proof();
            invalid.protected_checks_passed = passed;
            invalid.actual_tool_run = ran;
            assert_eq!(
                task.transition(4, TaskState::Completed, Some(&invalid)),
                Err(TransitionError::FailedAcceptance)
            );
        }
    }

    #[test]
    fn unknown_effect_cannot_retry_or_finish_without_reconciliation() {
        for next in [TaskState::Running, TaskState::Completed, TaskState::Failed] {
            let mut task = record(TaskState::OutcomeUnknown);
            assert_eq!(
                task.transition(4, next, Some(&proof())),
                Err(TransitionError::IllegalTransition)
            );
        }
        let mut task = record(TaskState::OutcomeUnknown);
        task.transition(4, TaskState::NeedsReconciliation, None)
            .unwrap();
        task.record_reconciliation(
            5,
            &ReconciliationEvidence {
                task_id: "task-code-001".into(),
                invocation_id: "invocation-001".into(),
                resolution_artifact_ref: "artifact:observed-external-state".into(),
                external_effect_resolved: true,
            },
        )
        .unwrap();
        task.transition(6, TaskState::Completed, Some(&proof()))
            .unwrap();
    }

    #[test]
    fn stale_version_does_not_mutate_task() {
        let mut task = record(TaskState::Running);
        let before = task.clone();
        assert_eq!(
            task.transition(3, TaskState::Verifying, None),
            Err(TransitionError::VersionConflict)
        );
        assert_eq!(task, before);
    }

    #[test]
    fn terminal_state_cannot_restart() {
        for state in [
            TaskState::Completed,
            TaskState::Failed,
            TaskState::Cancelled,
            TaskState::TimedOut,
        ] {
            assert!(state.is_terminal());
            let mut task = record(state);
            assert_eq!(
                task.transition(4, TaskState::Queued, None),
                Err(TransitionError::IllegalTransition)
            );
        }
    }

    #[test]
    fn counter_exhaustion_does_not_change_state() {
        let mut task = record(TaskState::Running);
        task.version = u64::MAX;
        assert_eq!(
            task.transition(u64::MAX, TaskState::Verifying, None),
            Err(TransitionError::VersionExhausted)
        );
        assert_eq!(task.state, TaskState::Running);
    }

    #[test]
    fn empty_artifact_reference_cannot_support_acceptance() {
        let mut task = record(TaskState::Verifying);
        let mut invalid = proof();
        invalid.raw_artifact_refs = vec![String::new()];
        assert_eq!(
            task.transition(4, TaskState::Completed, Some(&invalid)),
            Err(TransitionError::MissingRawArtifacts)
        );
    }

    #[test]
    fn valid_protected_acceptance_advances_once() {
        let mut task = record(TaskState::Verifying);
        task.transition(4, TaskState::Completed, Some(&proof()))
            .unwrap();
        assert_eq!((task.state, task.version), (TaskState::Completed, 5));
    }

    #[test]
    fn completion_proof_cannot_move_between_tasks_or_acceptance_contracts() {
        for field in ["task", "acceptance"] {
            let mut task = record(TaskState::Verifying);
            let mut foreign = proof();
            if field == "task" {
                foreign.task_id = "another-task".into();
            } else {
                foreign.acceptance_digest = "other-acceptance".into();
            }
            assert_eq!(
                task.transition(4, TaskState::Completed, Some(&foreign)),
                Err(TransitionError::EvidenceScopeMismatch)
            );
        }
    }

    #[test]
    fn evidence_must_match_the_records_final_artifact() {
        let mut task = record(TaskState::Verifying);
        task.final_artifact_digest = Some("blake3:changed-after-test".into());
        assert_eq!(
            task.transition(4, TaskState::Completed, Some(&proof())),
            Err(TransitionError::UnverifiedFinalArtifact)
        );
    }

    #[test]
    fn reconciliation_cannot_escape_through_blocked_or_queue() {
        for next in [
            TaskState::Blocked,
            TaskState::Queued,
            TaskState::Running,
            TaskState::Verifying,
            TaskState::Cancelled,
        ] {
            let mut task = record(TaskState::NeedsReconciliation);
            assert_eq!(
                task.transition(4, next, None),
                Err(TransitionError::IllegalTransition)
            );
        }
    }

    #[test]
    fn unresolved_or_foreign_reconciliation_does_not_mutate_state() {
        let mut task = record(TaskState::NeedsReconciliation);
        let mut unresolved = ReconciliationEvidence {
            task_id: "task-code-001".into(),
            invocation_id: "invocation-001".into(),
            resolution_artifact_ref: "artifact:observed-external-state".into(),
            external_effect_resolved: false,
        };
        assert_eq!(
            task.record_reconciliation(4, &unresolved),
            Err(TransitionError::UnresolvedExternalEffect)
        );
        unresolved.external_effect_resolved = true;
        unresolved.task_id = "other-task".into();
        assert_eq!(
            task.record_reconciliation(4, &unresolved),
            Err(TransitionError::EvidenceScopeMismatch)
        );
        unresolved.task_id = "task-code-001".into();
        unresolved.invocation_id = "different-invocation".into();
        assert_eq!(
            task.record_reconciliation(4, &unresolved),
            Err(TransitionError::EvidenceScopeMismatch)
        );
        assert_eq!(
            (task.state, task.version),
            (TaskState::NeedsReconciliation, 4)
        );
    }

    #[test]
    fn pending_unknown_effect_blocks_all_shortcuts_until_explicit_reconciliation() {
        for state in [TaskState::Running, TaskState::Verifying] {
            for next in [
                TaskState::Completed,
                TaskState::Failed,
                TaskState::Cancelled,
                TaskState::TimedOut,
                TaskState::Repairing,
                TaskState::Blocked,
            ] {
                let mut task = record(state);
                task.unknown_invocation_id = Some("invocation-001".into());
                let before = task.clone();
                assert_eq!(
                    task.transition(4, next, Some(&proof())),
                    Err(TransitionError::UnresolvedExternalEffect)
                );
                assert_eq!(task, before);
            }
            let mut task = record(state);
            task.unknown_invocation_id = Some("invocation-001".into());
            task.transition(4, TaskState::OutcomeUnknown, None).unwrap();
            task.transition(5, TaskState::NeedsReconciliation, None)
                .unwrap();
            assert_eq!(
                task.unknown_invocation_id.as_deref(),
                Some("invocation-001")
            );
        }
    }

    #[test]
    fn malformed_stored_record_cannot_advance() {
        let mut invalid_records = vec![];
        let mut task = record(TaskState::Created);
        task.task_id = " \t".into();
        invalid_records.push(task);
        let mut task = record(TaskState::Created);
        task.acceptance_digest = " ".into();
        invalid_records.push(task);
        let mut task = record(TaskState::Created);
        task.unknown_invocation_id = Some("invocation-001".into());
        invalid_records.push(task);
        let mut task = record(TaskState::OutcomeUnknown);
        task.unknown_invocation_id = None;
        invalid_records.push(task);
        let mut task = record(TaskState::Running);
        task.unknown_invocation_id = Some(" \r\n".into());
        invalid_records.push(task);
        for mut task in invalid_records {
            let before = task.clone();
            assert_eq!(
                task.transition(4, TaskState::Planned, None),
                Err(TransitionError::InvalidRecord)
            );
            assert_eq!(task, before);
        }
    }

    #[test]
    fn whitespace_is_not_a_verifier_or_raw_artifact_reference() {
        for (field, expected) in [
            ("verifier", TransitionError::UnverifiedFinalArtifact),
            ("artifact", TransitionError::MissingRawArtifacts),
        ] {
            let mut task = record(TaskState::Verifying);
            let before = task.clone();
            let mut invalid = proof();
            if field == "verifier" {
                invalid.verifier_run_id = " \n".into();
            } else {
                invalid.raw_artifact_refs = vec!["\t".into()];
            }
            assert_eq!(
                task.transition(4, TaskState::Completed, Some(&invalid)),
                Err(expected)
            );
            assert_eq!(task, before);
        }
    }

    #[test]
    fn blank_resolution_and_exhausted_version_preserve_unknown_effect() {
        let proof = ReconciliationEvidence {
            task_id: "task-code-001".into(),
            invocation_id: "invocation-001".into(),
            resolution_artifact_ref: " \t".into(),
            external_effect_resolved: true,
        };
        let mut task = record(TaskState::NeedsReconciliation);
        let before = task.clone();
        assert_eq!(
            task.record_reconciliation(4, &proof),
            Err(TransitionError::UnresolvedExternalEffect)
        );
        assert_eq!(task, before);
        let mut valid = proof;
        valid.resolution_artifact_ref = "artifact:resolution".into();
        task.version = u64::MAX;
        let before = task.clone();
        assert_eq!(
            task.record_reconciliation(u64::MAX, &valid),
            Err(TransitionError::VersionExhausted)
        );
        assert_eq!(task, before);
    }
}
