//! CODE-05 repository capabilities for trusted Rust hosts.
//!
//! A parsed proposal is untrusted data. Only the host's PatchBroker can mutate
//! files, after task/policy checks, exclusive handle validation, encrypted
//! preimages and durable dispatch. Gateway bindings are opt-in host routes.
use std::fmt;

pub mod analysis;
pub mod archive;
pub mod broker;
pub mod discovery;
pub mod git;
pub mod patch;
mod paths;
pub mod polyglot;
pub mod snapshot;
pub mod symbols;
pub mod tools;
pub mod unified;

pub use broker::{AbsentPath, AuthorizedMutation, FileMutation, MutationProposal, MutationReceipt};
pub use broker::{AuthorizedPatch, PatchBroker, PatchPolicy, PatchReceipt};
pub use patch::{ByteEdit, FilePatch, PatchProposal};
pub use snapshot::{FileVersion, Limits, Repository, RepositorySnapshot, SearchHit, SearchResult};

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Denied(&'static str),
    Stale(&'static str),
    Quota(&'static str),
    Cancelled,
    Unsupported(&'static str),
    Io(std::io::Error),
    Store(melissa_local_store::StoreError),
    Broker(melissa_execution_broker::BrokerError),
    Json(serde_json::Error),
    /// Dispatch already committed. Inspect the durable invocation; do not retry.
    AfterDispatch(Box<Error>),
}
pub type Result<T = ()> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid repository request: {s}"),
            Self::Denied(s) => write!(f, "repository policy denied: {s}"),
            Self::Stale(s) => write!(f, "repository observation is stale: {s}"),
            Self::Quota(s) => write!(f, "repository resource limit: {s}"),
            Self::Cancelled => f.write_str("repository operation cancelled"),
            Self::Unsupported(s) => write!(f, "unsupported repository operation: {s}"),
            Self::Io(e) => write!(f, "repository I/O failure (kind {:?})", e.kind()),
            Self::Store(_) => f.write_str("repository durable evidence operation failed"),
            Self::Broker(_) => f.write_str(
                "repository execution broker operation failed; inspect its typed outcome",
            ),
            Self::Json(_) => f.write_str("invalid repository JSON"),
            Self::AfterDispatch(_) => {
                f.write_str("repository effect requires inspection or reconciliation before retry")
            }
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<melissa_local_store::StoreError> for Error {
    fn from(e: melissa_local_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
pub(crate) fn check_cancel(cancel: &std::sync::atomic::AtomicBool) -> Result {
    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
