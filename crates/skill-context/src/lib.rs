//! Host-side CODE-07 package, context and persistence primitives.
//! Package text and model memory proposals are data, never execution authority.
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod assembly;
pub mod build_cache;
pub mod context;
pub mod durable;
pub mod package;
pub mod release;
pub mod retrieval;
pub mod runtime;
pub mod scripts;
pub mod state;
mod worker_service;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid CODE-07 JSON".into())
    }
}
impl From<melissa_local_store::StoreError> for Error {
    fn from(e: melissa_local_store::StoreError) -> Self {
        Self(e.to_string())
    }
}
impl From<melissa_core_contracts::validation::ContractError> for Error {
    fn from(e: melissa_core_contracts::validation::ContractError) -> Self {
        Self(e.to_string())
    }
}
pub(crate) fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
pub fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
pub(crate) fn json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Strict<T>(T);
    impl<T> melissa_core_contracts::validation::Validate for Strict<T> {
        fn validate(&self) -> melissa_core_contracts::validation::ContractResult {
            Ok(())
        }
    }
    Ok(melissa_core_contracts::json::parse_contract::<Strict<T>>(bytes, 16 * 1024 * 1024)?.0)
}

/// Exact project/user/engagement boundary. None does not mean wildcard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub user: String,
    pub project: String,
    pub engagement: Option<String>,
}
impl Namespace {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.user.trim().is_empty()
                && !self.project.trim().is_empty()
                && self
                    .engagement
                    .as_ref()
                    .is_none_or(|x| !x.trim().is_empty()),
            "empty namespace",
        )
    }
}
