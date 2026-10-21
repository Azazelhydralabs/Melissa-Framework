//! Source-bound, host-authorized development browser/API/database sessions.
//! Worker replies are developer observations, never protected acceptance.
pub mod plan;
pub mod progress;
pub mod protocol;
pub mod session;
pub mod tools;

pub type Result<T = ()> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Store(melissa_local_store::StoreError),
    Repository(melissa_repository::Error),
    Json(serde_json::Error),
    AfterDispatch(Box<Error>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid(s) => s,
            Self::Store(_) => "web development evidence persistence failed",
            Self::Repository(_) => "web development source verification failed",
            Self::Json(_) => "invalid web development protocol",
            Self::AfterDispatch(_) => "web operation already admitted; inspect before retry",
        })
    }
}
impl std::error::Error for Error {}
impl From<melissa_local_store::StoreError> for Error {
    fn from(e: melissa_local_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<melissa_repository::Error> for Error {
    fn from(e: melissa_repository::Error) -> Self {
        Self::Repository(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
pub fn digest(b: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(b).to_hex())
}
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control)
}
pub(crate) fn put(
    store: &mut melissa_local_store::LocalStore,
    task: &str,
    id: &str,
    kind: &str,
    bytes: &[u8],
) -> Result {
    store.put_artifact(
        &melissa_local_store::ArtifactRequest {
            artifact_id: id.into(),
            task_id: task.into(),
            content_type: "application/json".into(),
            logical_type: kind.into(),
            schema_version: "melissa.web-evidence/v1".into(),
            retain_until_ms: 0,
            legal_hold: true,
        },
        bytes,
    )?;
    Ok(())
}
