//! CODE-08 task-scoped scheduling. Plans and model candidates do not grant
//! authority or constitute protected product acceptance. All agent runs use
//! ONE existing native task ID and its atomic CODE-04 reservation ledger.
pub mod candidate_test;
pub mod comparison;
pub mod continuation;
pub mod gate;
pub mod plan;
pub mod runtime;
pub mod scheduler;
pub mod serial_tools;

use serde::{Deserialize, Serialize};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Invalid,
    Authority,
    Conflict,
    Stale,
    Cancelled,
    Uncertain,
    Budget,
    Store,
}
#[derive(Debug)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}
impl std::error::Error for Error {}
impl From<melissa_local_store::StoreError> for Error {
    fn from(_: melissa_local_store::StoreError) -> Self {
        error(
            Kind::Store,
            "durable workflow evidence failed; inspect before retry",
        )
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        error(Kind::Invalid, "invalid workflow serialization")
    }
}
impl From<melissa_model_gateway::GatewayError> for Error {
    fn from(e: melissa_model_gateway::GatewayError) -> Self {
        error(Kind::Invalid, &e.message)
    }
}
pub(crate) fn error(kind: Kind, message: &str) -> Error {
    Error {
        kind,
        message: message.into(),
    }
}
pub(crate) fn require(ok: bool, kind: Kind, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error(kind, message))
    }
}
pub fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes))
}
pub fn now() -> Result<u64> {
    melissa_execution_broker::unix_ms().map_err(|_| error(Kind::Store, "host clock unavailable"))
}
