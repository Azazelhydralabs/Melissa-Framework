//! Local persistence for CODE-02. These APIs are a trusted-host boundary, not
//! model-callable tools, an executor, a secret provisioner, or an outcome oracle.
use std::fmt;

mod artifacts;
mod backup;
pub mod cas;
pub mod crypto;
pub mod journal;
mod service;

pub use artifacts::{ArtifactMetadata, ArtifactRequest, GarbageCollection};
pub use backup::{BackupBlob, BackupManifest};
pub use crypto::StoreKey;
pub use service::{LocalStore, StoreConfig};

pub type StoreResult<T = ()> = Result<T, StoreError>;

#[derive(Debug)]
pub enum StoreError {
    Invalid(String),
    Integrity(String),
    Conflict(String),
    NotFound(String),
    Quota(String),
    Busy,
    Crypto,
    Unsupported(String),
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid store request: {message}"),
            Self::Integrity(message) => write!(f, "store integrity failure: {message}"),
            Self::Conflict(message) => write!(f, "store version or identity conflict: {message}"),
            Self::NotFound(message) => write!(f, "store record not found: {message}"),
            Self::Quota(message) => write!(f, "store quota exceeded: {message}"),
            Self::Busy => f.write_str("store instance is already open in another session"),
            Self::Crypto => f.write_str("encrypted store authentication failed"),
            Self::Unsupported(message) => write!(f, "unsupported store format: {message}"),
            Self::Io(error) => write!(f, "store I/O failure: {error}"),
            Self::Sql(error) => write!(f, "store SQLite failure: {error}"),
            Self::Json(_) => f.write_str("invalid stored JSON payload"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sql(value)
    }
}
impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<melissa_core_contracts::validation::ContractError> for StoreError {
    fn from(value: melissa_core_contracts::validation::ContractError) -> Self {
        Self::Invalid(value.to_string())
    }
}
