//! File namespace changes: single-file create/delete/move, never recursive.
//! Existing parents are explicit identity-bound prerequisites, not mkdir grants.
use super::*;
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsentPath {
    pub path: String,
    pub parent_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileMutation {
    Create {
        destination: AbsentPath,
        bytes: Vec<u8>,
    },
    Delete {
        before: FileVersion,
    },
    Move {
        before: FileVersion,
        destination: AbsentPath,
    },
    CreateDirectory {
        destination: AbsentPath,
    },
    DeleteDirectory {
        before: FileVersion,
    },
    MoveDirectory {
        before: FileVersion,
        destination: AbsentPath,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationProposal {
    pub schema_version: String,
    pub root_identity: String,
    pub mutation: FileMutation,
}
impl MutationProposal {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        melissa_core_contracts::json::parse_contract(bytes, 32 * 1024 * 1024)
            .map_err(|_| Error::Invalid("bounded duplicate-free mutation JSON required"))
    }
    pub fn tool_id(&self) -> &'static str {
        match self.mutation {
            FileMutation::Create { .. } => "fs.create",
            FileMutation::Delete { .. } => "fs.delete",
            FileMutation::Move { .. } => "fs.move",
            FileMutation::CreateDirectory { .. } => "fs.mkdir",
            FileMutation::DeleteDirectory { .. } => "fs.rmdir",
            FileMutation::MoveDirectory { .. } => "fs.movedir",
        }
    }
    fn paths(&self) -> Vec<&str> {
        match &self.mutation {
            FileMutation::Create { destination, .. }
            | FileMutation::CreateDirectory { destination } => vec![&destination.path],
            FileMutation::Delete { before } | FileMutation::DeleteDirectory { before } => {
                vec![&before.path]
            }
            FileMutation::Move {
                before,
                destination,
            }
            | FileMutation::MoveDirectory {
                before,
                destination,
            } => vec![&before.path, &destination.path],
        }
    }
    fn bytes(&self) -> u64 {
        match &self.mutation {
            FileMutation::Create { bytes, .. } => bytes.len() as u64,
            FileMutation::Delete { before } | FileMutation::Move { before, .. } => before.bytes,
            _ => 0,
        }
    }
    fn validate(&self, limits: &crate::Limits) -> Result {
        let directory = self.tool_id().starts_with("fs.mk")
            || matches!(
                &self.mutation,
                FileMutation::DeleteDirectory { .. } | FileMutation::MoveDirectory { .. }
            );
        let version = if directory {
            "melissa.repository-mutation/v2"
        } else {
            "melissa.repository-mutation/v1"
        };
        if self.schema_version != version
            || self.root_identity.is_empty()
            || self.root_identity.len() > 128
        {
            return Err(Error::Invalid("mutation schema/root"));
        }
        for p in self.paths() {
            paths::relative(p)?;
        }
        if let FileMutation::DeleteDirectory { before } | FileMutation::MoveDirectory { before, .. } =
            &self.mutation
            && (before.bytes != 0
                || before.digest != digest(b"melissa.empty-directory/v1")
                || before.identity.is_empty()
                || before.identity.len() > 128)
        {
            return Err(Error::Invalid("exact empty directory version required"));
        }
        if directory
            && let FileMutation::CreateDirectory { destination }
            | FileMutation::MoveDirectory { destination, .. } = &self.mutation
            && (destination.parent_identity.is_empty() || destination.parent_identity.len() > 128)
        {
            return Err(Error::Invalid("directory parent identity"));
        }
        if let FileMutation::MoveDirectory {
            before,
            destination,
        } = &self.mutation
            && (paths::beneath(&destination.path, &before.path)
                || paths::beneath(&before.path, &destination.path))
        {
            return Err(Error::Invalid("overlapping directory move"));
        }
        if self.bytes() > limits.max_file_bytes || self.bytes() > limits.max_total_bytes {
            return Err(Error::Quota("mutation bytes"));
        }
        if let FileMutation::Delete { before } | FileMutation::Move { before, .. } = &self.mutation
            && (before.identity.is_empty()
                || before.identity.len() > 128
                || !before.digest.strip_prefix("blake3:").is_some_and(|d| {
                    d.len() == 64
                        && d.bytes()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                }))
        {
            return Err(Error::Invalid("mutation preimage"));
        }
        if let FileMutation::Create { destination, .. } | FileMutation::Move { destination, .. } =
            &self.mutation
            && (destination.parent_identity.is_empty() || destination.parent_identity.len() > 128)
        {
            return Err(Error::Invalid("destination parent identity"));
        }
        if let FileMutation::Move {
            before,
            destination,
        } = &self.mutation
            && paths::key(&before.path) == paths::key(&destination.path)
        {
            return Err(Error::Invalid("same or case-alias move"));
        }
        Ok(())
    }
}
impl melissa_core_contracts::validation::Validate for MutationProposal {
    fn validate(&self) -> melissa_core_contracts::validation::ContractResult {
        self.validate(&crate::Limits {
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            ..Default::default()
        })
        .map_err(|e| melissa_core_contracts::validation::ContractError::new("$", e.to_string()))
    }
}

fn path(repo: &Repository, p: &str) -> PathBuf {
    repo.root_path().join(p.replace('/', "\\"))
}
fn absent(parent: &paths::Pinned, target: &std::path::Path, limit: usize) -> Result {
    match fs::symlink_metadata(target) {
        Ok(_) => return Err(Error::Stale("destination already exists")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::Invalid("destination name"))?;
    for (i, entry) in fs::read_dir(&parent.canonical)?.enumerate() {
        if i >= limit {
            return Err(Error::Quota("destination sibling count"));
        }
        let entry = entry?;
        if paths::key(&entry.file_name().to_string_lossy()) == paths::key(name) {
            return Err(Error::Stale("destination case alias exists"));
        }
    }
    Ok(())
}
impl Repository {
    pub fn empty_directory_version(&self, p: &str) -> Result<FileVersion> {
        self.check_path(p)?;
        let pinned = paths::pin(&path(self, p), true, false)?;
        empty_directory(&pinned, p)
    }
    fn destination_parent(&self, p: &str) -> Result<paths::Pinned> {
        self.check_path(p)?;
        let target = path(self, p);
        let parent = paths::pin(
            target
                .parent()
                .ok_or(Error::Invalid("destination parent"))?,
            true,
            false,
        )?;
        absent(&parent, &target, self.limits().max_files)?;
        Ok(parent)
    }
    /// An observation only. CREATE_NEW/no-replace rename rechecks absence at
    /// the actual effect; neither this token nor model JSON grants authority.
    pub fn absent_path(&self, p: &str) -> Result<AbsentPath> {
        let parent = self.destination_parent(p)?;
        Ok(AbsentPath {
            path: p.into(),
            parent_identity: parent.identity,
        })
    }
}

fn empty_directory(pin: &paths::Pinned, path: &str) -> Result<FileVersion> {
    if fs::read_dir(&pin.canonical)?.next().transpose()?.is_some() {
        return Err(Error::Denied(
            "directory must be empty; move files with explicit per-file grants",
        ));
    }
    Ok(FileVersion {
        path: path.into(),
        identity: pin.identity.clone(),
        digest: digest(b"melissa.empty-directory/v1"),
        bytes: 0,
    })
}

/// Host-produced, move-only session capability; deliberately no serde/Clone.
pub struct AuthorizedMutation {
    session: [u8; 32],
    epoch: u64,
    task_version: u64,
    issued: u64,
    started: Instant,
    invocation: String,
    attempt: String,
    permit: String,
    nonce: String,
    proposal: MutationProposal,
    digest: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct MutationReceipt {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_kind: Option<String>,
    pub invocation_id: String,
    pub attempt_id: String,
    pub permit_id: String,
    pub proposal_digest: String,
    pub root_identity: String,
    pub tool_id: String,
    pub before: Option<FileVersion>,
    pub after: Option<FileVersion>,
    pub absent_paths: Vec<String>,
    pub preimage_artifact_id: Option<String>,
    pub task_accepted: bool,
    pub atomic_tree_snapshot: bool,
    pub durability: String,
}
impl PatchBroker<'_> {
    fn check_mutation(&self, p: &MutationProposal) -> Result {
        p.validate(self.repo.limits())?;
        if p.root_identity != self.repo.root_identity() {
            return Err(Error::Denied("mutation root identity"));
        }
        self.check_authority(&p.paths())?;
        if p.bytes()
            > self
                .store
                .journal()
                .task(&self.policy.task_id)?
                .contract
                .limits
                .max_disk_bytes
        {
            return Err(Error::Quota("task mutation bytes"));
        }
        Ok(())
    }
    pub fn authorize_mutation(
        &self,
        invocation: &str,
        attempt: &str,
        proposal: MutationProposal,
    ) -> Result<AuthorizedMutation> {
        identifier(invocation)?;
        identifier(attempt)?;
        self.check_mutation(&proposal)?;
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::Denied("mutation entropy"))?;
        let token = blake3::hash(&entropy).to_hex().to_string();
        Ok(AuthorizedMutation {
            session: self.session,
            epoch: self.policy.epoch,
            task_version: self
                .store
                .journal()
                .task(&self.policy.task_id)?
                .record
                .version,
            issued: now()?,
            started: Instant::now(),
            invocation: invocation.into(),
            attempt: attempt.into(),
            permit: format!("permit:repository:{token}"),
            nonce: format!("nonce:repository:{token}"),
            digest: digest(&serde_json::to_vec(&proposal)?),
            proposal,
        })
    }
    pub fn execute_mutation(
        &mut self,
        permit: AuthorizedMutation,
        cancel: &AtomicBool,
    ) -> Result<MutationReceipt> {
        self.mutate_inner(permit, cancel, |_| Ok(()))
    }
    fn mutate_inner(
        &mut self,
        p: AuthorizedMutation,
        cancel: &AtomicBool,
        mut hook: impl FnMut(bool) -> Result,
    ) -> Result<MutationReceipt> {
        check_cancel(cancel)?;
        self.check_mutation(&p.proposal)?;
        let task = self.store.journal().task(&self.policy.task_id)?;
        if p.session != self.session
            || p.epoch != self.policy.epoch
            || p.task_version != task.record.version
            || now()? < p.issued
            || p.started.elapsed().as_millis() > u128::from(task.contract.limits.max_wall_time_ms)
            || digest(&serde_json::to_vec(&p.proposal)?) != p.digest
        {
            return Err(Error::Denied("stale or foreign mutation capability"));
        }
        let (before, dest) = match &p.proposal.mutation {
            FileMutation::Create { destination, .. }
            | FileMutation::CreateDirectory { destination } => (None, Some(destination)),
            FileMutation::Delete { before } | FileMutation::DeleteDirectory { before } => {
                (Some(before), None)
            }
            FileMutation::Move {
                before,
                destination,
            }
            | FileMutation::MoveDirectory {
                before,
                destination,
            } => (Some(before), Some(destination)),
        };
        // Hold source and destination ancestors through the final receipt.
        let parent = dest
            .map(|d| self.repo.destination_parent(&d.path))
            .transpose()?;
        if let (Some(d), Some(parent)) = (dest, &parent)
            && d.parent_identity != parent.identity
        {
            return Err(Error::Stale("destination parent replaced"));
        }
        let directory = matches!(
            &p.proposal.mutation,
            FileMutation::CreateDirectory { .. }
                | FileMutation::DeleteDirectory { .. }
                | FileMutation::MoveDirectory { .. }
        );
        let mut source = before
            .map(|f| {
                if directory {
                    paths::pin_delete_directory(&path(self.repo, &f.path))
                } else {
                    paths::pin_delete(&path(self.repo, &f.path))
                }
            })
            .transpose()?;
        let source_parent = before
            .map(|f| {
                paths::pin(
                    path(self.repo, &f.path)
                        .parent()
                        .ok_or(Error::Invalid("source parent"))?,
                    true,
                    false,
                )
            })
            .transpose()?;
        let mut preimage = None;
        if let (Some(before), Some(source)) = (before, source.as_mut()) {
            let (actual, bytes) = if directory {
                (
                    empty_directory(source, &before.path)?,
                    serde_json::to_vec(before)?,
                )
            } else {
                self.repo.read_locked(source, &before.path)?
            };
            if actual != *before {
                return Err(Error::Stale("mutation source changed"));
            }
            let id = format!("{}:preimage", p.invocation);
            self.put(&id, "repository_preimage", &bytes)?;
            preimage = Some(id);
        }
        let proposal_id = format!("{}:proposal", p.invocation);
        self.put(
            &proposal_id,
            "repository_mutation_proposal",
            &serde_json::to_vec(&p.proposal)?,
        )?;
        // Conservative bound before dispatch, including evidence identifiers.
        if 4096
            + p.proposal
                .paths()
                .iter()
                .map(|p| p.len() as u64)
                .sum::<u64>()
                * 4
            > task.contract.limits.max_output_bytes
        {
            return Err(Error::Quota("mutation receipt budget"));
        }
        check_cancel(cancel)?;
        self.check_mutation(&p.proposal)?;
        if self
            .store
            .journal()
            .task(&self.policy.task_id)?
            .record
            .version
            != p.task_version
        {
            return Err(Error::Stale("task changed before mutation"));
        }
        let proposed=self.store.journal_mut().propose_invocation(&InvocationRequest{
            invocation_id:p.invocation.clone(),task_id:self.policy.task_id.clone(),tool_id:p.proposal.tool_id().into(),
            arguments:serde_json::json!({"schema_version":"melissa.repository-mutation-dispatch/v1","proposal_digest":p.digest,"root_identity":self.repo.root_identity(),"authorization_ref":self.policy.authorization_ref,"principal_id":self.policy.principal_id,"profile_id":self.policy.profile_id,"policy_epoch":self.policy.epoch,"permit_id":p.permit,"proposal_artifact_id":proposal_id}),idempotency_key:None,generation:1},p.task_version)?;
        let version = self
            .store
            .journal()
            .task(&self.policy.task_id)?
            .record
            .version;
        let expires = p
            .issued
            .checked_add(task.contract.limits.max_wall_time_ms)
            .ok_or(Error::Invalid("mutation deadline"))?
            .min(self.policy.expires_at_ms);
        let admission = AdmissionRequest {
            permit_id: p.permit.clone(),
            nonce: p.nonce.clone(),
            permit_digest: digest(&serde_json::to_vec(
                &serde_json::json!({"proposal":p.digest,"principal":self.policy.principal_id,"profile":self.policy.profile_id,"resource":self.policy.resource_id,"authorization":self.policy.authorization_ref,"epoch":p.epoch,"nonce":p.nonce,"expires":expires}),
            )?),
            task_id: self.policy.task_id.clone(),
            principal_id: self.policy.principal_id.clone(),
            profile_id: self.policy.profile_id.clone(),
            tool_id: p.proposal.tool_id().into(),
            resource_id: self.policy.resource_id.clone(),
            arguments_digest: proposed.arguments_digest,
            invocation_id: p.invocation.clone(),
            attempt_id: p.attempt.clone(),
            generation: 1,
            expected_task_version: version,
            expected_invocation_version: proposed.version,
            not_before_unix_ms: p.issued,
            expires_at_unix_ms: expires,
            consumed_at_unix_ms: now()?,
        };
        let admission_result = check_cancel(cancel).and_then(|()| {
            self.store
                .journal_mut()
                .admit_dispatch(&admission)
                .map(|_| ())
                .map_err(Error::from)
        });
        if let Err(e) = admission_result {
            if let Ok(a) = self.store.journal().attempt(&p.attempt)
                && a.invocation_id == p.invocation
                && a.task_id == self.policy.task_id
            {
                if let Ok(g) = self.store.journal().attempt_guard(&p.attempt) {
                    let _ = self
                        .store
                        .finish_attempt(&g, AttemptState::OutcomeUnknown, None);
                }
                return Err(Error::AfterDispatch(Box::new(e)));
            }
            if let Ok(t) = self.store.journal().task(&self.policy.task_id) {
                let _ = self.store.journal_mut().reject_proposed_invocation(
                    &p.invocation,
                    t.record.version,
                    proposed.version,
                );
            }
            return Err(e);
        }
        let effect = (|| -> Result<MutationReceipt> {
            hook(false)?;
            check_cancel(cancel)?;
            self.check_mutation(&p.proposal)?;
            if self.store.journal().is_permit_revoked(&p.permit)?
                || now()? >= expires
                || p.started.elapsed().as_millis()
                    > u128::from(task.contract.limits.max_wall_time_ms)
            {
                return Err(Error::Denied("mutation revoked/expired"));
            }
            let mut after = None;
            let mut absent_paths = vec![];
            match &p.proposal.mutation {
                FileMutation::CreateDirectory { destination } => {
                    let parent = parent.as_ref().ok_or(Error::Invalid("directory parent"))?;
                    let name = destination
                        .path
                        .rsplit('/')
                        .next()
                        .ok_or(Error::Invalid("directory name"))?;
                    let created = paths::create_directory(parent, name)?;
                    hook(true)?;
                    after = Some(empty_directory(&created, &destination.path)?);
                }
                FileMutation::DeleteDirectory { before } => {
                    let held = source.take().ok_or(Error::Invalid("directory source"))?;
                    if empty_directory(&held, &before.path)? != *before {
                        return Err(Error::Stale("directory changed before delete"));
                    }
                    paths::delete(held)?;
                    hook(true)?;
                    absent(
                        source_parent
                            .as_ref()
                            .ok_or(Error::Invalid("directory parent"))?,
                        &path(self.repo, &before.path),
                        self.repo.limits().max_files,
                    )?;
                    absent_paths.push(before.path.clone());
                }
                FileMutation::MoveDirectory {
                    before,
                    destination,
                } => {
                    let held = source.as_mut().ok_or(Error::Invalid("directory source"))?;
                    if empty_directory(held, &before.path)? != *before {
                        return Err(Error::Stale("directory changed before move"));
                    }
                    paths::move_no_replace(held, &path(self.repo, &destination.path))?;
                    held.canonical = path(self.repo, &destination.path);
                    hook(true)?;
                    after = Some(empty_directory(held, &destination.path)?);
                    absent(
                        source_parent
                            .as_ref()
                            .ok_or(Error::Invalid("directory parent"))?,
                        &path(self.repo, &before.path),
                        self.repo.limits().max_files,
                    )?;
                    absent_paths.push(before.path.clone());
                }
                FileMutation::Create { destination, bytes } => {
                    let mut created = paths::create_new(&path(self.repo, &destination.path))?;
                    hook(true)?;
                    check_cancel(cancel)?;
                    if self.store.journal().is_permit_revoked(&p.permit)? {
                        return Err(Error::Denied("create revoked after namespace effect"));
                    }
                    created.file.write_all(bytes)?;
                    created.file.sync_all()?;
                    let (version, actual) =
                        self.repo.read_locked(&mut created, &destination.path)?;
                    if actual != *bytes {
                        return Err(Error::Stale("create read-back"));
                    }
                    after = Some(version);
                }
                FileMutation::Delete { before } => {
                    paths::delete(source.take().ok_or(Error::Invalid("delete source"))?)?;
                    hook(true)?;
                    absent(
                        source_parent
                            .as_ref()
                            .ok_or(Error::Invalid("delete parent"))?,
                        &path(self.repo, &before.path),
                        self.repo.limits().max_files,
                    )?;
                    absent_paths.push(before.path.clone());
                }
                FileMutation::Move {
                    before,
                    destination,
                } => {
                    let source = source.as_mut().ok_or(Error::Invalid("move source"))?;
                    paths::move_no_replace(source, &path(self.repo, &destination.path))?;
                    hook(true)?;
                    let (version, _) = self.repo.read_locked(source, &destination.path)?;
                    if version.identity != before.identity || version.digest != before.digest {
                        return Err(Error::Stale("move read-back"));
                    }
                    after = Some(version);
                    match fs::symlink_metadata(path(self.repo, &before.path)) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e.into()),
                        Ok(_) => return Err(Error::Stale("move source path reused")),
                    }
                    absent_paths.push(before.path.clone());
                }
            }
            check_cancel(cancel)?;
            self.check_mutation(&p.proposal)?;
            if self.store.journal().is_permit_revoked(&p.permit)? || now()? >= expires {
                return Err(Error::Denied("mutation authority changed after effect"));
            }
            let receipt=MutationReceipt{schema_version:if directory {"melissa.repository-mutation-receipt/v2"}else{"melissa.repository-mutation-receipt/v1"}.into(),namespace_kind:directory.then(||"empty_directory".into()),invocation_id:p.invocation.clone(),attempt_id:p.attempt.clone(),permit_id:p.permit.clone(),proposal_digest:p.digest.clone(),root_identity:self.repo.root_identity().into(),tool_id:p.proposal.tool_id().into(),before:before.cloned(),after,absent_paths,preimage_artifact_id:preimage,task_accepted:false,atomic_tree_snapshot:false,durability:"encrypted_dispatch_and_preimages; file_data_sync; namespace_crash_requires_reconciliation".into()};
            let receipt_id = format!("{}:receipt", p.invocation);
            self.put(
                &receipt_id,
                "repository_mutation_receipt",
                &serde_json::to_vec(&receipt)?,
            )?;
            let g = self.store.journal().attempt_guard(&p.attempt)?;
            self.store
                .finish_attempt(&g, AttemptState::Succeeded, Some(&receipt_id))?;
            Ok(receipt)
        })();
        match effect {
            Ok(r) => Ok(r),
            Err(e) => {
                if let Ok(g) = self.store.journal().attempt_guard(&p.attempt) {
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
#[path = "mutation_tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "directory_tests.rs"]
mod directory_tests;
