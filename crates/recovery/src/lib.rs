//! CODE-09: durable, task-bound recovery. Decisions and model repairs are not
//! grants, independent acceptance, or permission to replay uncertain effects.
pub mod compensation;
pub mod continuation;
pub mod integration;
pub mod reconcile;
pub mod retry;
pub mod session;
pub mod sweep;
pub use melissa_model_gateway::recovery::FailureKind;
pub use session::{Binding, Phase, Policy, RecoverySession, State};

use melissa_model_gateway::{ErrorKind, GatewayError};
pub type Result<T> = melissa_model_gateway::Result<T>;
fn fail(kind: ErrorKind, message: &str) -> GatewayError {
    GatewayError::new(kind, message)
}
fn checked(ok: bool, kind: ErrorKind, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(fail(kind, message)) }
}
fn store_error(_: impl std::fmt::Display) -> GatewayError {
    fail(
        ErrorKind::Store,
        "recovery evidence unavailable; inspect before replay",
    )
}
pub fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes))
}
fn now() -> Result<u64> {
    melissa_execution_broker::unix_ms().map_err(store_error)
}
