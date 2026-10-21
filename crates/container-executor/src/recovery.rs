//! Exact owned-resource cleanup for a trusted host after a verified expired
//! admission. This low-level API confers no task authority; use the broker-bound
//! CODE-09 sweeper rather than accepting container IDs from model arguments.
use crate::ExecutorResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub container_id: String,
    pub image_id: String,
    pub docker_client_identity: String,
    pub removed: bool,
    pub already_absent: bool,
    pub previously_running: bool,
    pub invocation_outcome_known: bool,
}
pub fn remove_expired_owned(container_id: &str, image_id: &str) -> ExecutorResult<RecoveryReport> {
    crate::runtime::recover_owned(container_id, image_id)
}
