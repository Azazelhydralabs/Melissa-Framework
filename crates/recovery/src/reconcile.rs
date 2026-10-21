//! Read actual files against the authentic admitted patch/preimages. A full
//! preimage or postimage can be resolved; mixed/foreign/partial effects remain
//! unknown. Non-idempotent operations without such proof remain blocked.
use crate::{Result, checked, digest, session::put, store_error};
use melissa_local_store::LocalStore;
use melissa_model_gateway::ErrorKind;
use melissa_repository::{PatchProposal, Repository};
use serde_json::{Value, json};

pub fn inspect_patch_effect(
    store: &mut LocalStore,
    repo: &Repository,
    task: &str,
    invocation: &str,
) -> Result<Value> {
    let owned = store
        .journal()
        .invocation(invocation)
        .map_err(store_error)?;
    checked(
        owned.task_id == task
            && owned.tool_id == "fs.patch"
            && owned.arguments["schema_version"] == "melissa.repository-dispatch/v1",
        ErrorKind::Authorization,
        "reconciliation requires authentic owned patch dispatch",
    )?;
    let artifact = owned.arguments["proposal_artifact_id"]
        .as_str()
        .ok_or_else(|| store_error("proposal reference"))?;
    let bytes = store.get_artifact(task, artifact).map_err(store_error)?;
    checked(
        owned.arguments["proposal_digest"] == digest(&bytes),
        ErrorKind::Store,
        "admitted patch proposal digest mismatch",
    )?;
    let proposal = PatchProposal::parse(&bytes).map_err(store_error)?;
    checked(
        proposal.root_identity == repo.root_identity()
            && owned.arguments["root_identity"] == repo.root_identity(),
        ErrorKind::Authorization,
        "reconciliation repository identity changed",
    )?;
    let mut all_before = true;
    let mut all_after = true;
    let mut files = vec![];
    for (i, file) in proposal.files.iter().enumerate() {
        let before = store
            .get_artifact(task, &format!("{invocation}:preimage:{i}"))
            .map_err(store_error)?;
        checked(
            digest(&before) == file.before.digest && before.len() as u64 == file.before.bytes,
            ErrorKind::Store,
            "reconciliation preimage changed",
        )?;
        let mut after = before.clone();
        for edit in file.edits.iter().rev() {
            let start = usize::try_from(edit.start).map_err(store_error)?;
            let end = usize::try_from(edit.end).map_err(store_error)?;
            checked(
                end <= after.len() && start <= end && after[start..end] == edit.expected,
                ErrorKind::Store,
                "admitted patch preimage does not match",
            )?;
            after.splice(start..end, edit.replacement.clone());
        }
        let (actual, content) = repo.read(&file.before.path).map_err(store_error)?;
        checked(
            actual.identity == file.before.identity,
            ErrorKind::Authorization,
            "reconciliation file identity replaced",
        )?;
        all_before &= content == before;
        all_after &= content == after;
        files.push(json!({"path":file.before.path,"actual_version":actual,"before_digest":digest(&before),"after_digest":digest(&after)}));
    }
    checked(
        all_before || all_after,
        ErrorKind::Store,
        "mixed/partial/foreign file effects remain unresolved",
    )?;
    let disposition = if all_after {
        "postimage_present"
    } else {
        "preimage_present"
    };
    let proof = json!({"schema_version":"melissa.patch-reconciliation/v1","task_id":task,"invocation_id":invocation,"proposal_digest":digest(&bytes),"effect_disposition":disposition,"files":files,"task_accepted":false});
    let bytes = serde_json::to_vec(&proof).map_err(store_error)?;
    let id = format!("patch-reconciliation:{invocation}:{}", digest(&bytes));
    put(store, task, &id, "recovery.patch_reconciliation", &bytes)?;
    let current = store
        .journal()
        .invocation(invocation)
        .map_err(store_error)?;
    if matches!(
        current.state,
        melissa_core_contracts::InvocationState::OutcomeUnknown
            | melissa_core_contracts::InvocationState::NeedsReconciliation
    ) {
        let mut t = store.journal().task(task).map_err(store_error)?;
        if t.record.state == melissa_core_contracts::TaskState::OutcomeUnknown {
            t = store
                .transition_task(
                    task,
                    t.record.version,
                    melissa_core_contracts::TaskState::NeedsReconciliation,
                    None,
                )
                .map_err(store_error)?;
        }
        store
            .journal_mut()
            .reconcile_invocation(
                t.record.version,
                current.version,
                &melissa_core_contracts::ReconciliationEvidence {
                    task_id: task.into(),
                    invocation_id: invocation.into(),
                    resolution_artifact_ref: id.clone(),
                    external_effect_resolved: true,
                },
            )
            .map_err(store_error)?;
    }
    Ok(json!({"artifact_id":id,"proof":proof,"automatic_replay_allowed":false}))
}
