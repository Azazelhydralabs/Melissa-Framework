//! CODE-03 host broker. No provider loop or model-supplied authorization.
use std::fmt;

mod broker;
pub mod container_broker;
pub mod container_policy;
pub mod control_policy;
pub mod paths;
pub mod policy;
pub mod process_control;
pub mod routes;
pub use broker::{
    Broker, BrokerExecution, InvocationIdentity, PolicyControl, environment_support,
    process_tool_schema, unix_ms,
};

#[derive(Debug)]
pub enum BrokerError {
    Invalid(String),
    Denied(String),
    Policy(policy::PolicyError),
    StaleTarget(String),
    Store(melissa_local_store::StoreError),
    Executor(melissa_windows_executor::ExecutorError),
    Container(melissa_container_executor::ExecutorError),
    Io(std::io::Error),
    Json(serde_json::Error),
    AfterDispatch(Box<BrokerError>),
}
pub type BrokerResult<T = ()> = Result<T, BrokerError>;

/// Untrusted tool JSON enters through the bounded duplicate-rejecting reader.
/// Successful parsing grants no authority and does not access the filesystem.
pub fn parse_process_request(bytes: &[u8]) -> BrokerResult<policy::ProcessSpec> {
    melissa_core_contracts::json::parse_contract(bytes, 512 * 1024)
        .map_err(|error| BrokerError::Invalid(error.to_string()))
}

pub fn parse_signed_permit(bytes: &[u8]) -> BrokerResult<policy::SignedPermit> {
    melissa_core_contracts::json::parse_contract(bytes, 512 * 1024)
        .map_err(|error| BrokerError::Invalid(error.to_string()))
}
impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid broker request: {message}"),
            Self::Denied(message) => write!(f, "broker denied: {message}"),
            Self::Policy(error) => error.fmt(f),
            Self::StaleTarget(message) => write!(f, "broker target changed: {message}"),
            Self::Store(error) => error.fmt(f),
            Self::Executor(error) => error.fmt(f),
            Self::Container(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Json(_) => f.write_str("invalid broker JSON"),
            Self::AfterDispatch(error) => write!(
                f,
                "dispatch was durable; inspect or reconcile before retry: {error}"
            ),
        }
    }
}
impl std::error::Error for BrokerError {}
impl From<melissa_local_store::StoreError> for BrokerError {
    fn from(error: melissa_local_store::StoreError) -> Self {
        Self::Store(error)
    }
}
impl From<melissa_windows_executor::ExecutorError> for BrokerError {
    fn from(error: melissa_windows_executor::ExecutorError) -> Self {
        Self::Executor(error)
    }
}
impl From<std::io::Error> for BrokerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for BrokerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<policy::PolicyError> for BrokerError {
    fn from(error: policy::PolicyError) -> Self {
        Self::Policy(error)
    }
}
impl From<melissa_container_executor::ExecutorError> for BrokerError {
    fn from(error: melissa_container_executor::ExecutorError) -> Self {
        Self::Container(error)
    }
}
