//! Bind recovery to the existing CODE-08 PreparedRun. Preserve its complete
//! handoff, selected skills, dispatcher, workflow continuation and root ledger.
use crate::{
    Binding, FailureKind, Policy, RecoverySession, Result, checked, session::Refresh, store_error,
};
use melissa_model_gateway::ErrorKind;
use melissa_workflow::runtime::PreparedRun;
use std::collections::BTreeMap;

pub fn enable_prepared_run(
    mut prepared: PreparedRun,
    binding: Binding,
    policy: Policy,
    refresh: Refresh,
    classifiers: BTreeMap<String, FailureKind>,
) -> Result<PreparedRun> {
    checked(
        prepared.spec.task_id == binding.task
            && prepared.spec.run_id == binding.run
            && prepared.spec.profile_id == binding.profile,
        ErrorKind::Authorization,
        "recovery cannot change prepared workflow scope",
    )?;
    let definitions = prepared.dispatcher.definitions();
    checked(
        classifiers
            .keys()
            .all(|name| definitions.iter().any(|d| d.definition.name == *name)),
        ErrorKind::Invalid,
        "recovery classifier refers to an unbound tool",
    )?;
    let cp = format!("recovery:{}:{}:0", binding.task, binding.run);
    let session = match prepared
        .gateway
        .store()
        .journal()
        .checkpoint(&cp, &binding.task)
    {
        Ok(_) => {
            let session =
                RecoverySession::reopen(prepared.gateway.store(), binding, refresh, classifiers)?;
            checked(
                session.state(prepared.gateway.store())?.policy == policy,
                ErrorKind::Authorization,
                "prepared recovery policy changed on resume",
            )?;
            session.eligibility(prepared.gateway.store())?;
            session
        }
        Err(melissa_local_store::StoreError::NotFound(_)) => RecoverySession::create(
            prepared.gateway.store_mut(),
            binding,
            policy,
            refresh,
            classifiers,
        )?,
        Err(e) => return Err(store_error(e)),
    };
    prepared.gateway = prepared.gateway.with_recovery(Box::new(session));
    Ok(prepared)
}
