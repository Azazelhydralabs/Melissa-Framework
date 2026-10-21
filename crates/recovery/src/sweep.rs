//! Restart sweep uses only authenticated native admissions and their pinned
//! prelaunch identity. Removal never pretends an unknown program succeeded.
use crate::{Result, checked, digest, now, session::put, store_error};
use melissa_local_store::LocalStore;
use melissa_model_gateway::ErrorKind;
use serde_json::{Value, json};
fn identity_id(store: &LocalStore, task: &str, attempt: &str) -> Result<String> {
    let standard = format!("{attempt}:container-identity");
    match store.artifact_metadata(task, &standard) {
        Ok(_) => Ok(standard),
        Err(melissa_local_store::StoreError::NotFound(_)) => {
            Ok(format!("{attempt}:web-container-identity"))
        }
        Err(e) => Err(store_error(e)),
    }
}

/// Called by native continuation startup. Scan only this task's authentic
/// journal; no daemon-wide name/prefix search and no unknown effect replay.
pub fn recover_on_restart(store: &mut LocalStore, task: &str) -> Result<Value> {
    let mut latest = std::collections::BTreeMap::new();
    for e in store.journal().events(task).map_err(store_error)? {
        if let Some(i) = e.invocation {
            latest.insert(i.invocation_id.clone(), i);
        }
    }
    let mut results = vec![];
    for (id, inv) in latest {
        if !matches!(
            inv.state,
            melissa_core_contracts::InvocationState::OutcomeUnknown
                | melissa_core_contracts::InvocationState::NeedsReconciliation
        ) {
            continue;
        }
        let admission = store
            .journal()
            .managed_execution(&id)
            .map_err(store_error)?;
        let identity = identity_id(store, task, &admission.attempt_id)?;
        match store.artifact_metadata(task, &identity) {
            Ok(_) => {}
            Err(melissa_local_store::StoreError::NotFound(_)) => {
                results.push(json!({"invocation":id,"cleanup":"no_durable_container_identity","outcome":"still_unknown","replay":false}));
                continue;
            }
            Err(e) => return Err(store_error(e)),
        }
        if now()? < admission.expires_at_unix_ms {
            results.push(json!({"invocation":id,"cleanup":"waiting_for_original_lease_expiry","outcome":"still_unknown","replay":false}));
            continue;
        }
        results.push(sweep_expired_container(store, task, &id)?);
    }
    let report = json!({"schema_version":"melissa.recovery-startup/v1","task":task,"results":results,"task_accepted":false,"unknown_outcomes_not_cleared":true});
    if !report["results"].as_array().expect("host array").is_empty() {
        let bytes = serde_json::to_vec(&report).map_err(store_error)?;
        put(
            store,
            task,
            &format!("recovery-startup:{task}:{}", digest(&bytes)),
            "recovery.startup",
            &bytes,
        )?;
    }
    Ok(report)
}

pub fn sweep_expired_container(
    store: &mut LocalStore,
    task: &str,
    invocation: &str,
) -> Result<Value> {
    let owned = store
        .journal()
        .invocation(invocation)
        .map_err(store_error)?;
    let admission = store
        .journal()
        .managed_execution(invocation)
        .map_err(store_error)?;
    checked(
        owned.task_id == task
            && admission.task_id == task
            && admission.invocation_id == invocation
            && owned.generation == admission.generation
            && now()? >= admission.expires_at_unix_ms,
        ErrorKind::Authorization,
        "only exact expired owned admissions may be swept",
    )?;
    let id = identity_id(store, task, &admission.attempt_id)?;
    let metadata = store.artifact_metadata(task, &id).map_err(store_error)?;
    let bytes = store.get_artifact(task, &id).map_err(store_error)?;
    let record: Value = serde_json::from_slice(&bytes).map_err(store_error)?;
    let broker_identity = metadata.logical_type == "process.container_identity"
        && record["schema_version"] == "melissa.container-identity/v1"
        && record["generation"] == admission.generation
        && record["image_id"] == owned.arguments["image_id"]
        && record["execution_contract"] == melissa_container_executor::EXECUTION_CONTRACT;
    // CODE-06 journal arguments contain an authenticated proposal reference,
    // not the proposal body. Resolve and bind the exact original CAS bytes.
    let sdk_proposal = if metadata.logical_type == "semantic.container-identity" {
        let proposal_id = owned.arguments["proposal_artifact_id"]
            .as_str()
            .ok_or_else(|| store_error("missing semantic proposal reference"))?;
        let proposal_metadata = store
            .artifact_metadata(task, proposal_id)
            .map_err(store_error)?;
        let encoded = store.get_artifact(task, proposal_id).map_err(store_error)?;
        checked(
            proposal_id == format!("{invocation}:semantic-proposal")
                && proposal_metadata.logical_type == "semantic.proposal"
                && owned.arguments["proposal_digest"] == digest(&encoded)
                && digest(&encoded) == admission.permit_digest,
            ErrorKind::Authorization,
            "semantic sweep proposal not bound to native admission",
        )?;
        serde_json::from_slice::<Value>(&encoded).map_err(store_error)?
    } else {
        Value::Null
    };
    let sdk_identity = metadata.logical_type == "semantic.container-identity"
        && sdk_proposal["schema_version"] == "melissa.semantic-dispatch/v1"
        && sdk_proposal["task_id"] == task
        && sdk_proposal["permit_id"] == admission.permit_id
        && owned.arguments["permit_id"] == admission.permit_id
        && sdk_proposal["profile_id"] == admission.profile_id
        && sdk_proposal["principal_id"] == admission.principal_id
        && sdk_proposal["resource_id"] == admission.resource_id
        && sdk_proposal["expires_at_ms"] == admission.expires_at_unix_ms
        && record["image"] == sdk_proposal["request"]["image_id"]
        && matches!(
            owned.tool_id.as_str(),
            "code.tests"
                | "code.build"
                | "code.diagnostics"
                | "code.lint"
                | "code.symbols"
                | "code.references"
        );
    let web_identity = if metadata.logical_type == "web.container-identity" {
        let proposal_id = owned.arguments["proposal_artifact_id"]
            .as_str()
            .ok_or_else(|| store_error("web proposal absent"))?;
        let bytes = store.get_artifact(task, proposal_id).map_err(store_error)?;
        let proposal: Value = serde_json::from_slice(&bytes).map_err(store_error)?;
        let meta = store
            .artifact_metadata(task, proposal_id)
            .map_err(store_error)?;
        proposal_id == format!("{invocation}:web-proposal")
            && meta.logical_type == "web.proposal"
            && owned.arguments["proposal_digest"] == digest(&bytes)
            && digest(&bytes) == admission.permit_digest
            && proposal["schema_version"] == "melissa.web-dispatch/v1"
            && proposal["policy"]["task_id"] == task
            && proposal["policy"]["profile_id"] == admission.profile_id
            && proposal["policy"]["principal_id"] == admission.principal_id
            && proposal["policy"]["resource_id"] == admission.resource_id
            && proposal["expires_at_ms"] == admission.expires_at_unix_ms
            && proposal["permit_id"] == admission.permit_id
            && owned.arguments["permit_id"] == admission.permit_id
            && record["image"] == proposal["request"]["image_id"]
            && matches!(
                owned.tool_id.as_str(),
                "browser.navigate" | "code.tests" | "data.profile"
            )
    } else {
        false
    };
    checked(
        (broker_identity || sdk_identity || web_identity)
            && record["task_id"] == task
            && record["invocation_id"] == invocation
            && record["attempt_id"] == admission.attempt_id
            && record["permit_digest"] == admission.permit_digest
            && owned.tool_id == admission.tool_id,
        ErrorKind::Authorization,
        "sweep identity not bound to native admission",
    )?;
    let container = record["container_id"]
        .as_str()
        .ok_or_else(|| store_error("container identity"))?;
    let image = if sdk_identity || web_identity {
        &record["image"]
    } else {
        &record["image_id"]
    }
    .as_str()
    .ok_or_else(|| store_error("image identity"))?;
    let intent = json!({"schema_version":"melissa.recovery-sweep-intent/v1","task":task,"invocation":invocation,"generation":owned.generation,"identity_digest":digest(&bytes),"admission_digest":digest(&serde_json::to_vec(&admission).map_err(store_error)?),"never_reexecute":true});
    let intent_bytes = serde_json::to_vec(&intent).map_err(store_error)?;
    let intent_id = format!(
        "recovery-sweep-intent:{}:{}",
        admission.attempt_id,
        digest(&intent_bytes)
    );
    put(
        store,
        task,
        &intent_id,
        "recovery.sweep_intent",
        &intent_bytes,
    )?;
    let report = melissa_container_executor::recovery::remove_expired_owned(container, image)
        .map_err(store_error)?;
    let result = json!({"schema_version":"melissa.recovery-sweep-result/v1","intent_artifact":intent_id,"native_report":report,"task_accepted":false,"invocation_reconciled":false,"cleanup_does_not_prove_program_outcome":true});
    let bytes = serde_json::to_vec(&result).map_err(store_error)?;
    put(
        store,
        task,
        &format!(
            "recovery-sweep-receipt:{}:{}",
            admission.attempt_id,
            digest(&bytes)
        ),
        "recovery.sweep_result",
        &bytes,
    )?;
    Ok(result)
}
