//! Exact existing-file patch admission. This host API is not deserializable
//! authority and does not claim an atomic filesystem/SQLite transaction.
use crate::{
    Error, FileVersion, PatchProposal, Repository, Result, check_cancel, digest,
    patch::apply_bytes, paths,
};
use melissa_core_contracts::TaskState;
use melissa_local_store::{
    ArtifactRequest, LocalStore,
    journal::{AdmissionRequest, AttemptState, InvocationRequest},
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// Trusted host configuration; never take this from model arguments.
#[derive(Debug, Clone)]
pub struct PatchPolicy {
    pub task_id: String,
    pub principal_id: String,
    pub profile_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub expires_at_ms: u64,
    pub epoch: u64,
    pub writable_paths: BTreeSet<String>,
    pub protected_paths: BTreeSet<String>,
}
/// Opaque, move-only, process/session-local capability. No serde or Clone.
pub struct AuthorizedPatch {
    session: [u8; 32],
    epoch: u64,
    task_version: u64,
    issued_at_ms: u64,
    issued_at: Instant,
    invocation_id: String,
    attempt_id: String,
    permit_id: String,
    nonce: String,
    proposal: PatchProposal,
    proposal_digest: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct AppliedFile {
    pub before: FileVersion,
    pub after: FileVersion,
    pub preimage_artifact_id: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct PatchReceipt {
    pub schema_version: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub permit_id: String,
    pub proposal_digest: String,
    pub root_identity: String,
    pub files: Vec<AppliedFile>,
    pub task_accepted: bool,
    pub multi_file_atomic: bool,
    pub durability: String,
}

pub struct PatchBroker<'a> {
    repo: &'a Repository,
    store: &'a mut LocalStore,
    policy: PatchPolicy,
    session: [u8; 32],
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Denied("host clock"))?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Denied("host clock overflow"))
}
pub(crate) fn identifier(s: &str) -> Result {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
    {
        return Err(Error::Invalid("invalid invocation identifier"));
    }
    Ok(())
}
impl<'a> PatchBroker<'a> {
    pub fn new(
        repo: &'a Repository,
        store: &'a mut LocalStore,
        policy: PatchPolicy,
    ) -> Result<Self> {
        for text in [
            &policy.task_id,
            &policy.principal_id,
            &policy.profile_id,
            &policy.resource_id,
            &policy.authorization_ref,
        ] {
            identifier(text)?;
        }
        if policy.writable_paths.is_empty() || policy.writable_paths.len() > repo.limits().max_files
        {
            return Err(Error::Invalid("explicit writable file set required"));
        }
        for p in policy.writable_paths.iter().chain(&policy.protected_paths) {
            repo.check_path(p)?;
        }
        let mut session = [0; 32];
        getrandom::fill(&mut session).map_err(|_| Error::Denied("host session entropy"))?;
        Ok(Self {
            repo,
            store,
            policy,
            session,
        })
    }
    pub fn revoke(&mut self) -> Result {
        self.policy.epoch = self
            .policy
            .epoch
            .checked_add(1)
            .ok_or(Error::Denied("policy epoch exhausted"))?;
        Ok(())
    }
    fn check_policy(&self, proposal: &PatchProposal) -> Result {
        proposal.validate(self.repo.limits())?;
        if proposal.root_identity != self.repo.root_identity() {
            return Err(Error::Denied("workspace identity"));
        }
        let paths: Vec<_> = proposal
            .files
            .iter()
            .map(|f| f.before.path.as_str())
            .collect();
        self.check_authority(&paths)?;
        let total = proposal.files.iter().try_fold(0u64, |n, f| {
            n.checked_add(f.before.bytes)
                .ok_or(Error::Quota("task byte overflow"))
        })?;
        if total
            > self
                .store
                .journal()
                .task(&self.policy.task_id)?
                .contract
                .limits
                .max_disk_bytes
        {
            return Err(Error::Quota("task patch bytes"));
        }
        Ok(())
    }
    fn check_authority(&self, targets: &[&str]) -> Result {
        if now()? >= self.policy.expires_at_ms {
            return Err(Error::Denied("repository policy expired"));
        }
        for path in targets {
            self.repo.check_path(path)?;
            if !self.policy.writable_paths.contains(*path) {
                return Err(Error::Denied("file outside exact host write set"));
            }
            if path.split('/').any(|s| s.eq_ignore_ascii_case("AGENTS.md"))
                || self
                    .policy
                    .protected_paths
                    .iter()
                    .any(|p| paths::beneath(path, p))
            {
                return Err(Error::Denied("protected file"));
            }
        }
        let task = self.store.journal().task(&self.policy.task_id)?;
        if task.record.state != TaskState::Running
            || task.record.unknown_invocation_id.is_some()
            || task.contract.workspace_ref != self.policy.resource_id
            || !task
                .contract
                .allowed_resource_ids
                .contains(&self.policy.resource_id)
            || !task
                .contract
                .authorization_refs
                .contains(&self.policy.authorization_ref)
            || !task
                .contract
                .selected_profile_ids
                .contains(&self.policy.profile_id)
            || !task
                .contract
                .allowed_effects
                .iter()
                .any(|e| e == "workspace.apply_patch_scoped")
        {
            return Err(Error::Denied(
                "task authority does not intersect host patch grant",
            ));
        }
        Ok(())
    }
    pub fn authorize(
        &self,
        invocation_id: &str,
        attempt_id: &str,
        proposal: PatchProposal,
    ) -> Result<AuthorizedPatch> {
        identifier(invocation_id)?;
        identifier(attempt_id)?;
        self.check_policy(&proposal)?;
        let version = self
            .store
            .journal()
            .task(&self.policy.task_id)?
            .record
            .version;
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::Denied("patch capability entropy"))?;
        let token = entropy
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Ok(AuthorizedPatch {
            session: self.session,
            epoch: self.policy.epoch,
            task_version: version,
            issued_at_ms: now()?,
            issued_at: Instant::now(),
            invocation_id: invocation_id.into(),
            attempt_id: attempt_id.into(),
            permit_id: format!("permit:repository:{token}"),
            nonce: format!("nonce:repository:{token}"),
            proposal_digest: proposal.digest()?,
            proposal,
        })
    }
    fn put(&mut self, id: &str, logical: &str, bytes: &[u8]) -> Result {
        self.store.put_artifact(
            &ArtifactRequest {
                artifact_id: id.into(),
                task_id: self.policy.task_id.clone(),
                content_type: "application/octet-stream".into(),
                logical_type: logical.into(),
                schema_version: "melissa.repository-evidence/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            bytes,
        )?;
        Ok(())
    }
    pub fn execute(
        &mut self,
        permit: AuthorizedPatch,
        cancel: &AtomicBool,
    ) -> Result<PatchReceipt> {
        self.execute_inner(permit, cancel, |_| Ok(()))
    }
    fn execute_inner(
        &mut self,
        permit: AuthorizedPatch,
        cancel: &AtomicBool,
        mut after_write: impl FnMut(usize) -> Result,
    ) -> Result<PatchReceipt> {
        check_cancel(cancel)?;
        self.check_policy(&permit.proposal)?;
        let task = self.store.journal().task(&self.policy.task_id)?;
        if permit.session != self.session
            || permit.epoch != self.policy.epoch
            || task.record.version != permit.task_version
            || now()? < permit.issued_at_ms
            || permit.issued_at.elapsed().as_millis()
                > u128::from(task.contract.limits.max_wall_time_ms)
            || permit.proposal_digest != permit.proposal.digest()?
        {
            return Err(Error::Denied("stale or foreign patch capability"));
        }
        // Writes run in path order (lock ordering), but preimage/receipt ids keep
        // the proposal index: reconciliation looks them up by proposal order.
        let mut files: Vec<_> = permit.proposal.files.iter().enumerate().collect();
        files.sort_by_key(|(_, p)| paths::key(&p.before.path));
        let mut locked = Vec::new();
        let mut total = 0u64;
        // Acquire and verify EVERY exclusive target before the first write.
        for (index, patch) in files {
            check_cancel(cancel)?;
            let mut file = self.repo.lock(&patch.before.path, true)?;
            let (current, before) = self.repo.read_locked(&mut file, &patch.before.path)?;
            if current != patch.before {
                return Err(Error::Stale("file identity or content changed"));
            }
            let after = apply_bytes(&before, patch, self.repo.limits())?;
            total = total
                .checked_add(after.len() as u64)
                .ok_or(Error::Quota("task output overflow"))?;
            if total > task.contract.limits.max_disk_bytes {
                return Err(Error::Quota("task output bytes"));
            }
            locked.push((index, file, current, before, after));
        }
        for (index, _, _, before, _) in &locked {
            self.put(
                &format!("{}:preimage:{index}", permit.invocation_id),
                "repository_preimage",
                before,
            )?;
        }
        let predicted_files: Vec<_> = locked
            .iter()
            .map(|(index, _, before, _, after)| AppliedFile {
                before: before.clone(),
                after: FileVersion {
                    path: before.path.clone(),
                    identity: before.identity.clone(),
                    digest: digest(after),
                    bytes: after.len() as u64,
                },
                preimage_artifact_id: format!("{}:preimage:{index}", permit.invocation_id),
            })
            .collect();
        // Bound the result before committing dispatch, rather than discovering
        // an unaffordable receipt after a filesystem effect.
        let predicted_receipt=PatchReceipt {schema_version:"melissa.repository-patch-receipt/v1".into(),invocation_id:permit.invocation_id.clone(),attempt_id:permit.attempt_id.clone(),permit_id:permit.permit_id.clone(),proposal_digest:permit.proposal_digest.clone(),root_identity:self.repo.root_identity().into(),files:predicted_files,task_accepted:false,multi_file_atomic:false,durability:"sync_all_per_file_plus_encrypted_dispatch_and_receipt; crash_requires_reconciliation".into()};
        if serde_json::to_vec(&predicted_receipt)?.len() as u64
            > task.contract.limits.max_output_bytes
        {
            return Err(Error::Quota("task patch receipt bytes"));
        }
        self.put(
            &format!("{}:proposal", permit.invocation_id),
            "repository_patch_proposal",
            &serde_json::to_vec(&permit.proposal)?,
        )?;
        check_cancel(cancel)?;
        self.check_policy(&permit.proposal)?;
        let version = self
            .store
            .journal()
            .task(&self.policy.task_id)?
            .record
            .version;
        if version != permit.task_version {
            return Err(Error::Stale("task changed during patch preparation"));
        }
        let proposed=self.store.journal_mut().propose_invocation(&InvocationRequest {invocation_id:permit.invocation_id.clone(),task_id:self.policy.task_id.clone(),tool_id:"fs.patch".into(),arguments:serde_json::json!({"schema_version":"melissa.repository-dispatch/v1","proposal_digest":permit.proposal_digest,"root_identity":self.repo.root_identity(),"policy_epoch":self.policy.epoch,"authorization_ref":self.policy.authorization_ref,"principal_id":self.policy.principal_id,"profile_id":self.policy.profile_id,"permit_id":permit.permit_id,"proposal_artifact_id":format!("{}:proposal",permit.invocation_id)}),idempotency_key:None,generation:1},version)?;
        let version = self
            .store
            .journal()
            .task(&self.policy.task_id)?
            .record
            .version;
        if let Err(e) = check_cancel(cancel) {
            self.store.journal_mut().reject_proposed_invocation(
                &permit.invocation_id,
                version,
                proposed.version,
            )?;
            return Err(e);
        }
        let expires = permit
            .issued_at_ms
            .checked_add(task.contract.limits.max_wall_time_ms)
            .ok_or(Error::Invalid("patch deadline overflow"))?
            .min(self.policy.expires_at_ms);
        let admission = AdmissionRequest {
            permit_id: permit.permit_id.clone(),
            nonce: permit.nonce.clone(),
            permit_digest: digest(&serde_json::to_vec(
                &serde_json::json!({"proposal":permit.proposal_digest,"root":self.repo.root_identity(),"principal":self.policy.principal_id,"profile":self.policy.profile_id,"authorization":self.policy.authorization_ref,"policy_epoch":self.policy.epoch,"permit_id":permit.permit_id,"nonce":permit.nonce,"expires":expires}),
            )?),
            task_id: self.policy.task_id.clone(),
            principal_id: self.policy.principal_id.clone(),
            profile_id: self.policy.profile_id.clone(),
            tool_id: "fs.patch".into(),
            resource_id: self.policy.resource_id.clone(),
            arguments_digest: proposed.arguments_digest,
            invocation_id: permit.invocation_id.clone(),
            attempt_id: permit.attempt_id.clone(),
            generation: 1,
            expected_task_version: version,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: permit.issued_at_ms,
            expires_at_unix_ms: expires,
            consumed_at_unix_ms: now()?,
        };
        if let Err(error) = self.store.journal_mut().admit_dispatch(&admission) {
            if let Ok(attempt) = self.store.journal().attempt(&permit.attempt_id)
                && attempt.invocation_id == permit.invocation_id
                && attempt.task_id == self.policy.task_id
            {
                if let Ok(g) = self.store.journal().attempt_guard(&permit.attempt_id) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                return Err(Error::AfterDispatch(Box::new(Error::Store(error))));
            }
            if let Ok(current) = self.store.journal().task(&self.policy.task_id) {
                let _ = self.store.journal_mut().reject_proposed_invocation(
                    &permit.invocation_id,
                    current.record.version,
                    proposed.version,
                );
            }
            return Err(error.into());
        }
        let effect = (|| -> Result<PatchReceipt> {
            let mut applied = Vec::new();
            for (i, (index, file, before, _, after)) in locked.iter_mut().enumerate() {
                check_cancel(cancel)?;
                self.check_policy(&permit.proposal)?;
                if self.store.journal().is_permit_revoked(&permit.permit_id)? {
                    return Err(Error::Denied("patch permit durably revoked"));
                }
                if now()? >= self.policy.expires_at_ms
                    || permit.issued_at.elapsed().as_millis()
                        > u128::from(task.contract.limits.max_wall_time_ms)
                {
                    return Err(Error::Denied("patch deadline during dispatch"));
                }
                file.file.seek(SeekFrom::Start(0))?;
                file.file.write_all(after)?;
                file.file.set_len(after.len() as u64)?;
                file.file.sync_all()?;
                file.file.seek(SeekFrom::Start(0))?;
                let mut observed = Vec::new();
                Read::by_ref(&mut file.file)
                    .take(self.repo.limits().max_file_bytes + 1)
                    .read_to_end(&mut observed)?;
                if observed != *after {
                    return Err(Error::Stale("post-write verification"));
                }
                applied.push(AppliedFile {
                    before: before.clone(),
                    after: FileVersion {
                        path: before.path.clone(),
                        identity: before.identity.clone(),
                        digest: digest(&observed),
                        bytes: observed.len() as u64,
                    },
                    preimage_artifact_id: format!("{}:preimage:{index}", permit.invocation_id),
                });
                after_write(i)?;
            }
            let receipt=PatchReceipt {schema_version:"melissa.repository-patch-receipt/v1".into(),invocation_id:permit.invocation_id.clone(),attempt_id:permit.attempt_id.clone(),permit_id:permit.permit_id.clone(),proposal_digest:permit.proposal_digest.clone(),root_identity:self.repo.root_identity().into(),files:applied,task_accepted:false,multi_file_atomic:false,durability:"sync_all_per_file_plus_encrypted_dispatch_and_receipt; crash_requires_reconciliation".into()};
            let receipt_id = format!("{}:receipt", permit.invocation_id);
            self.put(
                &receipt_id,
                "repository_patch_receipt",
                &serde_json::to_vec(&receipt)?,
            )?;
            let guard = self.store.journal().attempt_guard(&permit.attempt_id)?;
            self.store
                .finish_attempt(&guard, AttemptState::Succeeded, Some(&receipt_id))?;
            Ok(receipt)
        })();
        match effect {
            Ok(receipt) => Ok(receipt),
            Err(e) => {
                if let Ok(g) = self.store.journal().attempt_guard(&permit.attempt_id) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                Err(Error::AfterDispatch(Box::new(e)))
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests;

#[path = "mutations.rs"]
mod mutations;
pub use mutations::{
    AbsentPath, AuthorizedMutation, FileMutation, MutationProposal, MutationReceipt,
};
