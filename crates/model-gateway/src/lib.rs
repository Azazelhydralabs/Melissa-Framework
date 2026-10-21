//! CODE-04 provider-independent, host-controlled model generation. Model output
//! never creates tool authority or constitutes independent task acceptance.
pub mod agent_loop;
pub mod anthropic;
pub mod continuation;
pub mod openai;
pub mod output_capabilities;
pub mod recovery;
pub mod routing;
pub mod schema;
pub mod sse;
pub mod tools;
pub mod transport;
mod types;
pub mod vision;
pub use sse::SseEvent;
pub use types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Invalid,
    Protocol,
    Unsupported,
    Cancelled,
    Timeout,
    Transport,
    Authentication,
    RateLimited,
    ProviderUnavailable,
    Refused,
    Incomplete,
    Budget,
    Store,
    Tool,
    Authorization,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError {
    pub kind: ErrorKind,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, GatewayError>;
impl GatewayError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, message)
    }
}
impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}
impl std::error::Error for GatewayError {}

/// Every provider envelope and every final tool argument uses the same bounded
/// recursive duplicate-key rejecting reader as the task/broker contracts.
pub fn strict_json(text: &str) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(transparent)]
    struct Json(serde_json::Value);
    impl melissa_core_contracts::validation::Validate for Json {
        fn validate(&self) -> melissa_core_contracts::validation::ContractResult {
            Ok(())
        }
    }
    melissa_core_contracts::json::parse_contract::<Json>(text.as_bytes(), 8 * 1024 * 1024)
        .map(|v| v.0)
        .map_err(|_| GatewayError::protocol("invalid, duplicate, deeply nested or oversized JSON"))
}
