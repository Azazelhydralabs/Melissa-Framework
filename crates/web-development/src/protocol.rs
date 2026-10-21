use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Browser,
    Api,
    Database,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRequest {
    pub session: String,
    pub method: Method,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Value>,
    pub timeout_ms: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionMode {
    ReadOnly,
    Immediate,
    Serializable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Read a cursor page from its original read-only transaction/snapshot.
    Cursor {
        connection: String,
        sql: String,
        parameters: Vec<Value>,
        limit: u32,
    },
    Fetch {
        cursor: String,
        limit: u32,
    },
    QueryPlan {
        connection: String,
        sql: String,
        parameters: Vec<Value>,
    },
    SqlParallel {
        scripts: Vec<SqlScript>,
    },
    /// Status route is selected by a trusted host rule, never by this command.
    ReconcileApi {
        sequence: u64,
    },
    Start {},
    Navigate {
        page: String,
        path: String,
    },
    Inspect {
        page: String,
    },
    Fill {
        page: String,
        selector: String,
        value: String,
    },
    Click {
        page: String,
        selector: String,
    },
    Press {
        page: String,
        selector: String,
        key: String,
    },
    Wait {
        page: String,
        selector: String,
        state: String,
        timeout_ms: u32,
    },
    Viewport {
        page: String,
        width: u32,
        height: u32,
    },
    Screenshot {
        page: String,
    },
    Api {
        request: ApiRequest,
    },
    ApiConcurrent {
        requests: Vec<ApiRequest>,
    },
    Query {
        connection: String,
        sql: String,
        parameters: Vec<Value>,
    },
    Execute {
        connection: String,
        statement: String,
        parameters: Vec<Value>,
    },
    Profile {
        connection: String,
    },
    Begin {
        connection: String,
        mode: TransactionMode,
    },
    Commit {
        connection: String,
    },
    Rollback {
        connection: String,
    },
    /// Name selects an exact host-registered source script and expected baseline.
    Migration {
        name: String,
    },
    Close {},
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlScript {
    pub connection: String,
    pub mode: TransactionMode,
    pub steps: Vec<SqlStep>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlStep {
    Query {
        sql: String,
        parameters: Vec<Value>,
    },
    Execute {
        statement: String,
        parameters: Vec<Value>,
    },
    Barrier {},
    Commit {},
    Rollback {},
}
pub fn local_path(s: &str) -> bool {
    s.starts_with('/')
        && !s.starts_with("//")
        && !s.contains(['\\', '\0', '\r', '\n'])
        && s.len() <= 4096
        && !s.contains('#')
}
fn handle(s: &str) -> bool {
    !s.is_empty()
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
impl ApiRequest {
    pub fn validate(&self) -> Result {
        if !handle(&self.session)
            || !local_path(&self.path)
            || !(1..=30_000).contains(&self.timeout_ms)
            || self.headers.len() > 16
            || self.headers.iter().any(|(k, v)| {
                ![
                    "content-type",
                    "authorization",
                    "idempotency-key",
                    "x-test-tenant",
                ]
                .contains(&k.as_str())
                    || v.len() > 4096
                    || v.contains(['\r', '\n', '\0'])
            })
            || serde_json::to_vec(&self.body)?.len() > 64 * 1024
        {
            return Err(Error::Invalid("local API request envelope denied"));
        }
        Ok(())
    }
}
impl Command {
    pub fn service(&self) -> Option<Service> {
        match self {
            Self::Start {} | Self::Close {} => None,
            Self::Api { .. } | Self::ApiConcurrent { .. } | Self::ReconcileApi { .. } => {
                Some(Service::Api)
            }
            Self::Cursor { .. }
            | Self::Fetch { .. }
            | Self::QueryPlan { .. }
            | Self::SqlParallel { .. }
            | Self::Query { .. }
            | Self::Execute { .. }
            | Self::Profile { .. }
            | Self::Begin { .. }
            | Self::Commit { .. }
            | Self::Rollback { .. }
            | Self::Migration { .. } => Some(Service::Database),
            _ => Some(Service::Browser),
        }
    }
    pub fn canonical(&self) -> Option<&'static str> {
        Some(match self {
            Self::Start {} | Self::Close {} => return None,
            Self::Navigate { .. } => "browser.navigate",
            Self::Inspect { .. } => "browser.inspect",
            Self::Screenshot { .. } => "browser.screenshot",
            Self::Api { .. } | Self::ApiConcurrent { .. } | Self::ReconcileApi { .. } => {
                "code.tests"
            }
            Self::Query { .. }
            | Self::Cursor { .. }
            | Self::Fetch { .. }
            | Self::QueryPlan { .. } => "data.query",
            Self::Profile { .. } => "data.profile",
            Self::SqlParallel { .. }
            | Self::Execute { .. }
            | Self::Begin { .. }
            | Self::Commit { .. }
            | Self::Rollback { .. }
            | Self::Migration { .. } => "process.exec",
            _ => "browser.interact",
        })
    }
    pub fn validate(&self) -> Result {
        match self {
            Self::Cursor {
                connection,
                sql,
                parameters,
                limit,
            } => {
                Self::Query {
                    connection: connection.clone(),
                    sql: sql.clone(),
                    parameters: parameters.clone(),
                }
                .validate()?;
                if !(1..=1000).contains(limit) {
                    return Err(Error::Invalid("cursor page size"));
                }
            }
            Self::QueryPlan {
                connection,
                sql,
                parameters,
            } => Self::Query {
                connection: connection.clone(),
                sql: sql.clone(),
                parameters: parameters.clone(),
            }
            .validate()?,
            Self::Fetch { cursor, limit } if !handle(cursor) || !(1..=1000).contains(limit) => {
                return Err(Error::Invalid("cursor handle/page size"));
            }
            Self::SqlParallel { scripts } => {
                let mut names = std::collections::BTreeSet::new();
                if !(2..=4).contains(&scripts.len()) {
                    return Err(Error::Invalid("parallel SQL count"));
                }
                let barriers = scripts[0]
                    .steps
                    .iter()
                    .filter(|s| matches!(s, SqlStep::Barrier {}))
                    .count();
                for script in scripts {
                    if !handle(&script.connection)
                        || !names.insert(&script.connection)
                        || script.steps.is_empty()
                        || script.steps.len() > 16
                        || barriers
                            != script
                                .steps
                                .iter()
                                .filter(|s| matches!(s, SqlStep::Barrier {}))
                                .count()
                    {
                        return Err(Error::Invalid("parallel SQL script envelope"));
                    }
                    for step in &script.steps {
                        match step {
                            SqlStep::Query { sql, parameters } => {
                                if script.mode != TransactionMode::ReadOnly {
                                    return Err(Error::Invalid(
                                        "writable transactional reads require a pinned statement",
                                    ));
                                }
                                Self::Query {
                                    connection: script.connection.clone(),
                                    sql: sql.clone(),
                                    parameters: parameters.clone(),
                                }
                                .validate()?;
                            }
                            SqlStep::Execute {
                                statement,
                                parameters,
                            } => Self::Execute {
                                connection: script.connection.clone(),
                                statement: statement.clone(),
                                parameters: parameters.clone(),
                            }
                            .validate()?,
                            _ => (),
                        }
                    }
                }
            }
            Self::ReconcileApi { sequence } if *sequence == 0 => {
                return Err(Error::Invalid("API reconciliation sequence"));
            }
            Self::Navigate { page, path } if !handle(page) || !local_path(path) => {
                return Err(Error::Invalid("browser target outside local application"));
            }
            Self::Inspect { page } | Self::Screenshot { page } | Self::Viewport { page, .. }
                if !handle(page) =>
            {
                return Err(Error::Invalid("invalid page handle"));
            }
            Self::Fill { page, selector, .. }
            | Self::Click { page, selector }
            | Self::Press { page, selector, .. }
            | Self::Wait { page, selector, .. }
                if !handle(page)
                    || selector.is_empty()
                    || selector.len() > 4096
                    || selector.contains('\0') =>
            {
                return Err(Error::Invalid("browser locator envelope"));
            }
            Self::Query {
                connection,
                sql,
                parameters,
            } if !handle(connection)
                || sql.is_empty()
                || sql.len() > 64 * 1024
                || sql.contains('\0')
                || parameters.len() > 128
                || parameters.iter().any(|v| v.is_array() || v.is_object()) =>
            {
                return Err(Error::Invalid("query envelope"));
            }
            Self::Profile { connection }
            | Self::Begin { connection, .. }
            | Self::Commit { connection }
            | Self::Rollback { connection }
                if !handle(connection) =>
            {
                return Err(Error::Invalid("invalid connection handle"));
            }
            Self::Migration { name } if !handle(name) => {
                return Err(Error::Invalid("invalid migration registration"));
            }
            Self::Execute {
                connection,
                statement,
                parameters,
            } if !handle(connection)
                || !handle(statement)
                || parameters.len() > 128
                || parameters.iter().any(|v| v.is_array() || v.is_object()) =>
            {
                return Err(Error::Invalid("registered SQL statement envelope"));
            }
            Self::Api { request } => request.validate()?,
            Self::ApiConcurrent { requests } => {
                if requests.is_empty() || requests.len() > 16 {
                    return Err(Error::Invalid("concurrent API envelope"));
                }
                for r in requests {
                    r.validate()?;
                }
            }
            _ => (),
        }
        if matches!(self, Self::Viewport{width,height,..} if !(240..=4096).contains(width)||!(240..=4096).contains(height))
            || matches!(self,Self::Wait{state,timeout_ms,..} if !["visible","hidden","attached","detached"].contains(&state.as_str())||!(1..=30_000).contains(timeout_ms))
            || matches!(self,Self::Fill{value,..} if value.len()>64*1024||value.contains('\0'))
            || matches!(self,Self::Press{key,..} if key.len()>128||key.contains(['\0','\r','\n']))
        {
            return Err(Error::Invalid("browser operation bounds"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub schema_version: String,
    pub seq: u64,
    pub source_digest: String,
    pub ok: bool,
    pub body: Option<Value>,
    pub error: Option<Value>,
    pub closed: bool,
    pub task_completed: bool,
}
