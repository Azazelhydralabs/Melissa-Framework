//! Transactional host journal. Records and events are encrypted; identifiers,
//! states, versions, workspace references and CAS metadata remain plaintext.
//! Dispatch is a recorded intention, never proof of an external outcome.
use crate::{StoreError, StoreResult, crypto::StoreKey};
use melissa_core_contracts::{
    CompletionEvidence, InvocationState, ReconciliationEvidence, TaskRecord, TaskState,
    validation::Validate, wire::TaskContractV1,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MIGRATION: &str = include_str!("../migrations/0001_initial.sql");
const ADMISSION_MIGRATION: &str = include_str!("../migrations/0002_execution_admission.sql");
const CONTROL_MIGRATION: &str = include_str!("../migrations/0003_process_control.sql");
const MODEL_MIGRATION: &str = include_str!("../migrations/0004_model_ledger.sql");
#[path = "model_ledger.rs"]
mod model_ledger;
pub use model_ledger::{
    ModelBudgetSnapshot, ModelRequestRecord, ModelRequestState, ModelReservation, ModelSettlement,
    ModelUsage,
};
#[path = "control_admission.rs"]
mod control_admission;
pub use control_admission::ControlAdmission;
#[path = "admission.rs"]
mod admission;
pub use admission::{AdmissionRequest, PermitRevocation};
const KEY_AAD: &[u8] = b"melissa.local-store/key-check/v1";
const KEY_PLAIN: &[u8] = b"melissa-local-store-authenticated-key-v1";

#[derive(Debug, Clone, Copy)]
pub struct JournalLimits {
    pub max_database_bytes: u64,
    pub max_payload_bytes: usize,
    pub max_events_per_task: u64,
    pub busy_timeout_ms: u64,
}
impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_database_bytes: 256 * 1024 * 1024,
            max_payload_bytes: 1024 * 1024,
            max_events_per_task: 100_000,
            busy_timeout_ms: 1000,
        }
    }
}
impl JournalLimits {
    pub fn validate(&self) -> StoreResult {
        if self.max_database_bytes < 65536
            || self.max_database_bytes > i64::MAX as u64
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > i32::MAX as usize - 128
            || self.max_events_per_task == 0
            || self.max_events_per_task > i64::MAX as u64
            || self.busy_timeout_ms > 60_000
        {
            return Err(StoreError::Invalid("invalid journal limits".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTask {
    pub contract: TaskContractV1,
    pub record: TaskRecord,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    pub invocation_id: String,
    pub task_id: String,
    pub tool_id: String,
    pub arguments: Value,
    pub idempotency_key: Option<String>,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRecord {
    pub invocation_id: String,
    pub task_id: String,
    pub tool_id: String,
    pub arguments: Value,
    pub arguments_digest: String,
    pub idempotency_key: Option<String>,
    pub generation: u64,
    pub state: InvocationState,
    pub version: u64,
    pub active_attempt_id: Option<String>,
    pub result_artifact_id: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Prepared,
    Dispatched,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
    Reconciled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub attempt_id: String,
    pub invocation_id: String,
    pub task_id: String,
    pub number: u64,
    pub generation: u64,
    pub state: AttemptState,
    pub version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptGuard {
    pub task_id: String,
    pub task_version: u64,
    pub invocation_id: String,
    pub invocation_version: u64,
    pub attempt_id: String,
    pub attempt_version: u64,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEvent {
    pub task_id: String,
    pub sequence: u64,
    pub kind: String,
    pub created_at_ms: u64,
    pub task: StoredTask,
    pub invocation: Option<InvocationRecord>,
    pub attempt: Option<AttemptRecord>,
    pub completion_evidence: Option<CompletionEvidence>,
    pub reconciliation_evidence: Option<ReconciliationEvidence>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub checkpoint_id: String,
    pub task_id: String,
    pub task_version: u64,
    pub artifact_id: String,
    pub created_at_ms: u64,
    pub data: Value,
}

pub struct Journal {
    pub(crate) conn: Connection,
    pub(crate) key: StoreKey,
    limits: JournalLimits,
}
impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

pub(crate) fn integer(value: u64) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::Invalid("integer exceeds SQLite range".into()))
}
fn nonblank(value: &str) -> StoreResult {
    if value.trim().is_empty() {
        Err(StoreError::Invalid("blank identifier".into()))
    } else {
        Ok(())
    }
}
fn now() -> StoreResult<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::Invalid("clock before epoch".into()))?
            .as_millis(),
    )
    .map_err(|_| StoreError::Invalid("clock overflow".into()))
}
fn label<T: Serialize>(value: &T) -> StoreResult<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StoreError::Invalid("state must be a string".into()))
}
pub(crate) fn encode<T: Serialize>(
    key: &StoreKey,
    context: &str,
    value: &T,
    max: usize,
) -> StoreResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > max {
        return Err(StoreError::Quota("payload byte limit".into()));
    }
    key.seal(&bytes, context.as_bytes())
}
pub(crate) fn decode<T: DeserializeOwned>(
    key: &StoreKey,
    context: &str,
    bytes: &[u8],
    max: usize,
) -> StoreResult<T> {
    if bytes.len() > max.saturating_add(128) {
        return Err(StoreError::Quota("encrypted payload byte limit".into()));
    }
    let plain = key.open(bytes, context.as_bytes())?;
    if plain.len() > max {
        return Err(StoreError::Quota("payload byte limit".into()));
    }
    Ok(serde_json::from_slice(&plain)?)
}

impl Journal {
    pub fn open(path: &Path, key: StoreKey, limits: JournalLimits) -> StoreResult<Self> {
        limits.validate()?;
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_millis(limits.busy_timeout_ms))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA synchronous=FULL;")?;
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        // Apply capacity before any migration DDL so an upgrade cannot commit
        // a larger schema and only then discover that it exceeds this host quota.
        let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let pages = limits.max_database_bytes / page_size;
        let current: u64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        if current > pages {
            return Err(StoreError::Quota(
                "database already exceeds byte limit".into(),
            ));
        }
        let _: u64 = conn.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let table_count: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        let checksum = blake3::hash(MIGRATION.as_bytes()).to_hex().to_string();
        if version == 0 && table_count == 0 {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES(1,?1)",
                [&checksum],
            )?;
            tx.execute(
                "INSERT INTO store_metadata(name,value) VALUES('key_check',?1)",
                [key.seal(KEY_PLAIN, KEY_AAD)?],
            )?;
            tx.commit()?;
        } else if ![1, 2, 3, 4].contains(&version) {
            return Err(StoreError::Unsupported("journal schema version".into()));
        }
        let actual: String = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StoreError::Integrity("missing schema migration".into()))?;
        let count: i64 =
            conn.query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))?;
        let current_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if actual != checksum || count != current_version {
            return Err(StoreError::Integrity("migration checksum mismatch".into()));
        }
        validate_schema(&conn, current_version)?;
        let envelope: Vec<u8> = conn
            .query_row(
                "SELECT value FROM store_metadata WHERE name='key_check'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StoreError::Integrity("missing key check".into()))?;
        if key.open(&envelope, KEY_AAD)? != KEY_PLAIN {
            return Err(StoreError::Crypto);
        }
        let admission_checksum = blake3::hash(ADMISSION_MIGRATION.as_bytes())
            .to_hex()
            .to_string();
        if current_version == 1 {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(ADMISSION_MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES(2,?1)",
                [&admission_checksum],
            )?;
            admission::initialize(&tx, &key, limits)?;
            tx.commit()?;
        } else {
            let actual: String = conn
                .query_row(
                    "SELECT checksum FROM schema_migrations WHERE version=2",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| StoreError::Integrity("missing admission migration".into()))?;
            if actual != admission_checksum {
                return Err(StoreError::Integrity(
                    "admission migration checksum mismatch".into(),
                ));
            }
        }
        let control_checksum = blake3::hash(CONTROL_MIGRATION.as_bytes())
            .to_hex()
            .to_string();
        let upgraded: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if upgraded == 2 {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(CONTROL_MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES(3,?1)",
                [&control_checksum],
            )?;
            tx.commit()?;
        } else {
            let actual: String = conn.query_row(
                "SELECT checksum FROM schema_migrations WHERE version=3",
                [],
                |r| r.get(0),
            )?;
            if actual != control_checksum {
                return Err(StoreError::Integrity(
                    "control migration checksum mismatch".into(),
                ));
            }
        }
        let model_checksum = blake3::hash(MODEL_MIGRATION.as_bytes())
            .to_hex()
            .to_string();
        let upgraded: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if upgraded == 3 {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(MODEL_MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES(4,?1)",
                [&model_checksum],
            )?;
            tx.commit()?;
        } else {
            let actual: String = conn.query_row(
                "SELECT checksum FROM schema_migrations WHERE version=4",
                [],
                |r| r.get(0),
            )?;
            if actual != model_checksum {
                return Err(StoreError::Integrity(
                    "model ledger migration checksum mismatch".into(),
                ));
            }
        }
        validate_schema(&conn, 4)?;
        conn.execute_batch("PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=1048576;")?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (limits.max_payload_bytes + 128).min(i32::MAX as usize) as i32,
        )?;
        let journal = Self { conn, key, limits };
        journal.integrity_check()?;
        Ok(journal)
    }
    pub fn create_task(&mut self, contract: &TaskContractV1) -> StoreResult<StoredTask> {
        contract.validate()?;
        for value in [
            contract.limits.max_wall_time_ms,
            contract.limits.max_cost_micro_usd,
            contract.limits.max_input_tokens,
            contract.limits.max_output_tokens,
            contract.limits.max_parallel_jobs,
            contract.limits.max_disk_bytes,
            contract.limits.max_output_bytes,
        ] {
            integer(value)?;
        }
        let task = StoredTask {
            contract: contract.clone(),
            record: TaskRecord {
                task_id: contract.task_id.clone(),
                module: contract.module,
                state: TaskState::Created,
                version: 0,
                acceptance_digest: contract.acceptance_contract_digest.clone(),
                final_artifact_digest: None,
                unknown_invocation_id: None,
            },
        };
        let contract_blob = encode(
            &self.key,
            &format!("contract:{}", contract.task_id),
            contract,
            self.limits.max_payload_bytes,
        )?;
        let record = encode(
            &self.key,
            &format!("task:{}", contract.task_id),
            &task.record,
            self.limits.max_payload_bytes,
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .query_row(
                "SELECT 1 FROM tasks WHERE task_id=?1",
                [&contract.task_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::Conflict("task identity already exists".into()));
        }
        tx.execute("INSERT INTO tasks(task_id,workspace_ref,state,version,contract,record) VALUES(?1,?2,'created',0,?3,?4)",params![contract.task_id,contract.workspace_ref,contract_blob,record])?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "task_created",
            None,
            None,
        )?;
        tx.commit()?;
        Ok(task)
    }
    pub fn task(&self, task_id: &str) -> StoreResult<StoredTask> {
        load_task(&self.conn, &self.key, self.limits, task_id)
    }
    pub fn transition_task(
        &mut self,
        task_id: &str,
        expected_version: u64,
        next: TaskState,
        evidence: Option<&CompletionEvidence>,
    ) -> StoreResult<StoredTask> {
        integer(expected_version)?;
        if evidence.is_some() && next != TaskState::Completed {
            return Err(StoreError::Invalid(
                "completion evidence is accepted only for completion".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut task = load_task(&tx, &self.key, self.limits, task_id)?;
        if next != TaskState::OutcomeUnknown && next != TaskState::NeedsReconciliation {
            ensure_no_inflight(&tx, task_id)?;
        }
        if let Some(proof) = evidence {
            for id in &proof.raw_artifact_refs {
                artifact_owned(&tx, task_id, id)?;
            }
        }
        task.record
            .transition(expected_version, next, evidence)
            .map_err(|e| StoreError::Conflict(format!("task transition rejected: {e:?}")))?;
        save_task(&tx, &self.key, self.limits, &task, expected_version)?;
        if next == TaskState::Completed {
            for id in &evidence
                .expect("core guard requires proof")
                .raw_artifact_refs
            {
                add_reference(&tx, task_id, "completion", task_id, id)?;
            }
        }
        append_event_with_proof(
            &tx,
            &self.key,
            self.limits,
            &task,
            "task_transition",
            None,
            None,
            evidence.cloned(),
            None,
        )?;
        tx.commit()?;
        Ok(task)
    }
    pub fn set_final_artifact(
        &mut self,
        task_id: &str,
        expected_version: u64,
        artifact_id: &str,
    ) -> StoreResult<StoredTask> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut task = load_task(&tx, &self.key, self.limits, task_id)?;
        check_task_version(&task, expected_version)?;
        if task.record.state.is_terminal() {
            return Err(StoreError::Conflict("terminal task is immutable".into()));
        }
        let digest = artifact_owned(&tx, task_id, artifact_id)?;
        task.record.final_artifact_digest = Some(digest);
        bump(&mut task)?;
        tx.execute(
            "DELETE FROM artifact_refs WHERE owner_kind='task_final' AND owner_id=?1",
            [task_id],
        )?;
        add_reference(&tx, task_id, "task_final", task_id, artifact_id)?;
        save_task(&tx, &self.key, self.limits, &task, expected_version)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "final_artifact_selected",
            None,
            None,
        )?;
        tx.commit()?;
        Ok(task)
    }
    pub fn propose_invocation(
        &mut self,
        request: &InvocationRequest,
        expected_task_version: u64,
    ) -> StoreResult<InvocationRecord> {
        for text in [&request.invocation_id, &request.task_id, &request.tool_id] {
            nonblank(text)?;
        }
        if let Some(key) = &request.idempotency_key {
            nonblank(key)?;
        }
        integer(request.generation)?;
        let arguments_digest = blake3::hash(&serde_json::to_vec(&request.arguments)?)
            .to_hex()
            .to_string();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut task = load_task(&tx, &self.key, self.limits, &request.task_id)?;
        check_task_version(&task, expected_task_version)?;
        if task.record.state != TaskState::Running || task.record.unknown_invocation_id.is_some() {
            return Err(StoreError::Conflict(
                "invocation requires a running reconciled task".into(),
            ));
        }
        if let Some(key) = &request.idempotency_key {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT invocation_id FROM invocations WHERE task_id=?1 AND idempotency_key=?2",
                    params![request.task_id, key],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                let existing = load_invocation(&tx, &self.key, self.limits, &id)?;
                if existing.tool_id != request.tool_id
                    || existing.arguments_digest != arguments_digest
                    || existing.generation != request.generation
                {
                    return Err(StoreError::Conflict(
                        "idempotency key has different request".into(),
                    ));
                }
                return Ok(existing);
            }
        }
        let invocation = InvocationRecord {
            invocation_id: request.invocation_id.clone(),
            task_id: request.task_id.clone(),
            tool_id: request.tool_id.clone(),
            arguments: request.arguments.clone(),
            arguments_digest,
            idempotency_key: request.idempotency_key.clone(),
            generation: request.generation,
            state: InvocationState::Proposed,
            version: 0,
            active_attempt_id: None,
            result_artifact_id: None,
        };
        if tx
            .query_row(
                "SELECT 1 FROM invocations WHERE invocation_id=?1",
                [&request.invocation_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::Conflict("invocation identity exists".into()));
        }
        insert_invocation(&tx, &self.key, self.limits, &invocation)?;
        bump(&mut task)?;
        save_task(&tx, &self.key, self.limits, &task, expected_task_version)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "invocation_proposed",
            Some(invocation.clone()),
            None,
        )?;
        tx.commit()?;
        Ok(invocation)
    }
    pub fn invocation(&self, invocation_id: &str) -> StoreResult<InvocationRecord> {
        load_invocation(&self.conn, &self.key, self.limits, invocation_id)
    }
    pub fn authorize_invocation(
        &mut self,
        invocation_id: &str,
        expected_task_version: u64,
        expected_invocation_version: u64,
    ) -> StoreResult<InvocationRecord> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut invocation = load_invocation(&tx, &self.key, self.limits, invocation_id)?;
        let mut task = load_task(&tx, &self.key, self.limits, &invocation.task_id)?;
        check_task_version(&task, expected_task_version)?;
        if invocation.version != expected_invocation_version
            || invocation.state != InvocationState::Proposed
            || task.record.state != TaskState::Running
        {
            return Err(StoreError::Conflict(
                "invocation authorization state/version".into(),
            ));
        }
        invocation.state = InvocationState::Authorized;
        invocation.version = increment(invocation.version)?;
        save_invocation(
            &tx,
            &self.key,
            self.limits,
            &invocation,
            expected_invocation_version,
        )?;
        bump(&mut task)?;
        save_task(&tx, &self.key, self.limits, &task, expected_task_version)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "invocation_authorized",
            Some(invocation.clone()),
            None,
        )?;
        tx.commit()?;
        Ok(invocation)
    }
    pub fn begin_attempt(
        &mut self,
        invocation_id: &str,
        attempt_id: &str,
        expected_task_version: u64,
        expected_invocation_version: u64,
        generation: u64,
    ) -> StoreResult<AttemptRecord> {
        nonblank(attempt_id)?;
        integer(generation)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut invocation = load_invocation(&tx, &self.key, self.limits, invocation_id)?;
        let mut task = load_task(&tx, &self.key, self.limits, &invocation.task_id)?;
        check_task_version(&task, expected_task_version)?;
        if invocation.version != expected_invocation_version
            || invocation.generation != generation
            || invocation.state != InvocationState::Authorized
            || invocation.active_attempt_id.is_some()
            || task.record.state != TaskState::Running
            || task.record.unknown_invocation_id.is_some()
        {
            return Err(StoreError::Conflict(
                "attempt identity/state/version/generation".into(),
            ));
        }
        let last: u64 = tx.query_row(
            "SELECT coalesce(max(number),0) FROM attempts WHERE invocation_id=?1",
            [invocation_id],
            |r| r.get(0),
        )?;
        let attempt = AttemptRecord {
            attempt_id: attempt_id.into(),
            invocation_id: invocation_id.into(),
            task_id: invocation.task_id.clone(),
            number: increment(last)?,
            generation,
            state: AttemptState::Prepared,
            version: 0,
        };
        let payload = encode(
            &self.key,
            &format!("attempt:{attempt_id}"),
            &attempt,
            self.limits.max_payload_bytes,
        )?;
        tx.execute("INSERT INTO attempts(attempt_id,invocation_id,task_id,number,generation,state,version,payload) VALUES(?1,?2,?3,?4,?5,'prepared',0,?6)",params![attempt_id,invocation_id,invocation.task_id,integer(attempt.number)?,integer(generation)?,payload])?;
        invocation.active_attempt_id = Some(attempt_id.into());
        invocation.version = increment(invocation.version)?;
        save_invocation(
            &tx,
            &self.key,
            self.limits,
            &invocation,
            expected_invocation_version,
        )?;
        bump(&mut task)?;
        save_task(&tx, &self.key, self.limits, &task, expected_task_version)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "attempt_prepared",
            Some(invocation),
            Some(attempt.clone()),
        )?;
        tx.commit()?;
        Ok(attempt)
    }
    pub fn attempt(&self, attempt_id: &str) -> StoreResult<AttemptRecord> {
        load_attempt(&self.conn, &self.key, self.limits, attempt_id)
    }
    pub fn attempt_guard(&self, attempt_id: &str) -> StoreResult<AttemptGuard> {
        let tx = self.conn.unchecked_transaction()?;
        let attempt = load_attempt(&tx, &self.key, self.limits, attempt_id)?;
        let invocation = load_invocation(&tx, &self.key, self.limits, &attempt.invocation_id)?;
        let task = load_task(&tx, &self.key, self.limits, &attempt.task_id)?;
        let guard = AttemptGuard {
            task_id: attempt.task_id,
            task_version: task.record.version,
            invocation_id: attempt.invocation_id,
            invocation_version: invocation.version,
            attempt_id: attempt.attempt_id,
            attempt_version: attempt.version,
            generation: attempt.generation,
        };
        tx.commit()?;
        Ok(guard)
    }
    pub fn dispatch_attempt(&mut self, guard: &AttemptGuard) -> StoreResult<AttemptRecord> {
        self.change_attempt(guard, AttemptState::Dispatched, None)
    }
    pub fn start_attempt(&mut self, guard: &AttemptGuard) -> StoreResult<AttemptRecord> {
        self.change_attempt(guard, AttemptState::Running, None)
    }
    pub fn finish_attempt(
        &mut self,
        guard: &AttemptGuard,
        state: AttemptState,
        result_artifact_id: Option<&str>,
    ) -> StoreResult<AttemptRecord> {
        if !matches!(
            state,
            AttemptState::Succeeded
                | AttemptState::Failed
                | AttemptState::Cancelled
                | AttemptState::OutcomeUnknown
        ) {
            return Err(StoreError::Invalid("invalid attempt outcome".into()));
        }
        self.change_attempt(guard, state, result_artifact_id)
    }
    fn change_attempt(
        &mut self,
        guard: &AttemptGuard,
        next: AttemptState,
        result_artifact_id: Option<&str>,
    ) -> StoreResult<AttemptRecord> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut attempt = load_attempt(&tx, &self.key, self.limits, &guard.attempt_id)?;
        let mut invocation = load_invocation(&tx, &self.key, self.limits, &guard.invocation_id)?;
        let mut task = load_task(&tx, &self.key, self.limits, &guard.task_id)?;
        check_task_version(&task, guard.task_version)?;
        if attempt.task_id != guard.task_id
            || attempt.invocation_id != guard.invocation_id
            || invocation.task_id != guard.task_id
            || attempt.version != guard.attempt_version
            || invocation.version != guard.invocation_version
            || attempt.generation != guard.generation
            || invocation.generation != guard.generation
            || invocation.active_attempt_id.as_deref() != Some(&guard.attempt_id)
            || !matches!(
                task.record.state,
                TaskState::Running
                    | TaskState::Verifying
                    | TaskState::OutcomeUnknown
                    | TaskState::NeedsReconciliation
            )
        {
            return Err(StoreError::Conflict("attempt guard mismatch".into()));
        }
        if matches!(next, AttemptState::Dispatched | AttemptState::Running)
            && task.record.state != TaskState::Running
        {
            return Err(StoreError::Conflict(
                "new dispatch/start is blocked while reconciliation is pending".into(),
            ));
        }
        let allowed = match attempt.state {
            AttemptState::Prepared => {
                matches!(next, AttemptState::Dispatched | AttemptState::Cancelled)
            }
            AttemptState::Dispatched => matches!(
                next,
                AttemptState::Running
                    | AttemptState::Succeeded
                    | AttemptState::Failed
                    | AttemptState::Cancelled
                    | AttemptState::OutcomeUnknown
            ),
            AttemptState::Running => matches!(
                next,
                AttemptState::Succeeded
                    | AttemptState::Failed
                    | AttemptState::Cancelled
                    | AttemptState::OutcomeUnknown
            ),
            _ => false,
        };
        if !allowed {
            return Err(StoreError::Conflict("invalid attempt transition".into()));
        }
        if next == AttemptState::Succeeded && result_artifact_id.is_none() {
            return Err(StoreError::Invalid(
                "successful attempt requires a stored observation artifact".into(),
            ));
        }
        if next == AttemptState::Cancelled
            && matches!(
                attempt.state,
                AttemptState::Dispatched | AttemptState::Running
            )
            && result_artifact_id.is_none()
        {
            return Err(StoreError::Invalid(
                "inflight cancellation requires a stored trusted-host cleanup observation".into(),
            ));
        }
        if let Some(id) = result_artifact_id {
            artifact_owned(&tx, &guard.task_id, id)?;
            add_reference(&tx, &guard.task_id, "invocation", &guard.invocation_id, id)?;
            invocation.result_artifact_id = Some(id.into());
        }
        attempt.state = next;
        attempt.version = increment(attempt.version)?;
        invocation.state = match next {
            AttemptState::Prepared => InvocationState::Authorized,
            AttemptState::Dispatched => InvocationState::Dispatched,
            AttemptState::Running => InvocationState::Running,
            AttemptState::Succeeded => InvocationState::Succeeded,
            AttemptState::Failed => InvocationState::Failed,
            AttemptState::Cancelled => InvocationState::Cancelled,
            AttemptState::OutcomeUnknown => InvocationState::OutcomeUnknown,
            AttemptState::Reconciled => InvocationState::Reconciled,
        };
        if matches!(
            next,
            AttemptState::Succeeded | AttemptState::Failed | AttemptState::Cancelled
        ) {
            invocation.active_attempt_id = None;
        }
        invocation.version = increment(invocation.version)?;
        if next == AttemptState::OutcomeUnknown {
            if task.record.unknown_invocation_id.is_none() {
                task.record.unknown_invocation_id = Some(invocation.invocation_id.clone());
                task.record
                    .transition(task.record.version, TaskState::OutcomeUnknown, None)
                    .map_err(|e| StoreError::Conflict(format!("unknown transition: {e:?}")))?;
            } else {
                bump(&mut task)?;
            }
        } else {
            bump(&mut task)?;
        }
        save_attempt(&tx, &self.key, self.limits, &attempt, guard.attempt_version)?;
        save_invocation(
            &tx,
            &self.key,
            self.limits,
            &invocation,
            guard.invocation_version,
        )?;
        save_task(&tx, &self.key, self.limits, &task, guard.task_version)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "attempt_transition",
            Some(invocation),
            Some(attempt.clone()),
        )?;
        tx.commit()?;
        Ok(attempt)
    }
    /// Call only after exclusive ownership/takeover. Opening another connection
    /// does not imply that another executor crashed.
    pub fn recover_interrupted(&mut self) -> StoreResult<usize> {
        let ids = {
            let mut s=self.conn.prepare("SELECT attempt_id FROM attempts WHERE state IN ('dispatched','running') ORDER BY task_id,attempt_id")?;
            s.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut recovered = 0;
        for id in ids {
            let mut attempt = load_attempt(&tx, &self.key, self.limits, &id)?;
            if !matches!(
                attempt.state,
                AttemptState::Dispatched | AttemptState::Running
            ) {
                continue;
            }
            let mut invocation =
                load_invocation(&tx, &self.key, self.limits, &attempt.invocation_id)?;
            let mut task = load_task(&tx, &self.key, self.limits, &attempt.task_id)?;
            let tv = task.record.version;
            let iv = invocation.version;
            let av = attempt.version;
            if !matches!(
                task.record.state,
                TaskState::Running
                    | TaskState::Verifying
                    | TaskState::OutcomeUnknown
                    | TaskState::NeedsReconciliation
            ) {
                return Err(StoreError::Integrity(
                    "inflight invocation in unrelated task state".into(),
                ));
            }
            attempt.state = AttemptState::OutcomeUnknown;
            attempt.version = increment(av)?;
            invocation.state = InvocationState::OutcomeUnknown;
            invocation.version = increment(iv)?;
            if task.record.unknown_invocation_id.is_none() {
                task.record.unknown_invocation_id = Some(invocation.invocation_id.clone());
                task.record.state = TaskState::OutcomeUnknown;
            }
            bump(&mut task)?;
            save_attempt(&tx, &self.key, self.limits, &attempt, av)?;
            save_invocation(&tx, &self.key, self.limits, &invocation, iv)?;
            save_task(&tx, &self.key, self.limits, &task, tv)?;
            append_event(
                &tx,
                &self.key,
                self.limits,
                &task,
                "interrupted_outcome_unknown",
                Some(invocation),
                Some(attempt),
            )?;
            recovered += 1;
        }
        tx.commit()?;
        Ok(recovered)
    }
    /// A matching trusted-host report resolves uncertainty; it does not imply
    /// that the external operation succeeded, and does not authorize a retry.
    pub fn reconcile_invocation(
        &mut self,
        expected_task_version: u64,
        expected_invocation_version: u64,
        proof: &ReconciliationEvidence,
    ) -> StoreResult<StoredTask> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut task = load_task(&tx, &self.key, self.limits, &proof.task_id)?;
        check_task_version(&task, expected_task_version)?;
        let mut invocation = load_invocation(&tx, &self.key, self.limits, &proof.invocation_id)?;
        if invocation.task_id != proof.task_id
            || invocation.version != expected_invocation_version
            || !matches!(
                invocation.state,
                InvocationState::OutcomeUnknown | InvocationState::NeedsReconciliation
            )
            || !proof.external_effect_resolved
            || task.record.state != TaskState::NeedsReconciliation
        {
            return Err(StoreError::Conflict(
                "reconciliation identity/state/version".into(),
            ));
        }
        artifact_owned(&tx, &proof.task_id, &proof.resolution_artifact_ref)?;
        add_reference(
            &tx,
            &proof.task_id,
            "reconciliation",
            &proof.invocation_id,
            &proof.resolution_artifact_ref,
        )?;
        let id = invocation.active_attempt_id.clone().ok_or_else(|| {
            StoreError::Integrity("unknown invocation lacks an active attempt".into())
        })?;
        let mut attempt = load_attempt(&tx, &self.key, self.limits, &id)?;
        if attempt.state != AttemptState::OutcomeUnknown {
            return Err(StoreError::Integrity(
                "unknown invocation attempt mismatch".into(),
            ));
        }
        let av = attempt.version;
        attempt.state = AttemptState::Reconciled;
        attempt.version = increment(av)?;
        invocation.state = InvocationState::Reconciled;
        invocation.version = increment(invocation.version)?;
        invocation.active_attempt_id = None;
        // The singular domain marker identifies the next unresolved operation;
        // the database query below preserves all additional unknown operations.
        if task.record.unknown_invocation_id.as_deref() != Some(&proof.invocation_id) {
            return Err(StoreError::Conflict(
                "reconcile the marked invocation first".into(),
            ));
        }
        task.record
            .record_reconciliation(expected_task_version, proof)
            .map_err(|e| StoreError::Conflict(format!("host reconciliation rejected: {e:?}")))?;
        save_attempt(&tx, &self.key, self.limits, &attempt, av)?;
        save_invocation(
            &tx,
            &self.key,
            self.limits,
            &invocation,
            expected_invocation_version,
        )?;
        let next:Option<String>=tx.query_row("SELECT invocation_id FROM invocations WHERE task_id=?1 AND state IN ('outcome_unknown','needs_reconciliation') ORDER BY invocation_id LIMIT 1",[&proof.task_id],|r|r.get(0)).optional()?;
        if let Some(id) = next {
            task.record.state = TaskState::NeedsReconciliation;
            task.record.unknown_invocation_id = Some(id);
        }
        save_task(&tx, &self.key, self.limits, &task, expected_task_version)?;
        append_event_with_proof(
            &tx,
            &self.key,
            self.limits,
            &task,
            "invocation_reconciled",
            Some(invocation),
            Some(attempt),
            None,
            Some(proof.clone()),
        )?;
        tx.commit()?;
        Ok(task)
    }
    pub fn append_checkpoint(
        &mut self,
        checkpoint_id: &str,
        task_id: &str,
        expected_task_version: u64,
        artifact_id: &str,
        data: Value,
    ) -> StoreResult<Checkpoint> {
        nonblank(checkpoint_id)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = load_task(&tx, &self.key, self.limits, task_id)?;
        check_task_version(&task, expected_task_version)?;
        artifact_owned(&tx, task_id, artifact_id)?;
        let checkpoint = Checkpoint {
            checkpoint_id: checkpoint_id.into(),
            task_id: task_id.into(),
            task_version: expected_task_version,
            artifact_id: artifact_id.into(),
            created_at_ms: now()?,
            data,
        };
        let payload = encode(
            &self.key,
            &format!("checkpoint:{checkpoint_id}"),
            &checkpoint,
            self.limits.max_payload_bytes,
        )?;
        tx.execute("INSERT INTO checkpoints(checkpoint_id,task_id,task_version,artifact_id,created_at_ms,payload) VALUES(?1,?2,?3,?4,?5,?6)",params![checkpoint_id,task_id,integer(expected_task_version)?,artifact_id,integer(checkpoint.created_at_ms)?,payload])?;
        add_reference(&tx, task_id, "checkpoint", checkpoint_id, artifact_id)?;
        tx.commit()?;
        Ok(checkpoint)
    }
    pub fn checkpoint(&self, checkpoint_id: &str, task_id: &str) -> StoreResult<Checkpoint> {
        let tx = self.conn.unchecked_transaction()?;
        let row:Option<(String,u64,String,u64,Vec<u8>)>=tx.query_row("SELECT task_id,task_version,artifact_id,created_at_ms,payload FROM checkpoints WHERE checkpoint_id=?1",[checkpoint_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (owner, version, artifact, created, payload) =
            row.ok_or_else(|| StoreError::NotFound("checkpoint".into()))?;
        if owner != task_id {
            return Err(StoreError::Conflict(
                "checkpoint belongs to a different task".into(),
            ));
        }
        let cp: Checkpoint = decode(
            &self.key,
            &format!("checkpoint:{checkpoint_id}"),
            &payload,
            self.limits.max_payload_bytes,
        )?;
        if cp.checkpoint_id != checkpoint_id
            || cp.task_id != owner
            || cp.task_version != version
            || cp.artifact_id != artifact
            || cp.created_at_ms != created
        {
            return Err(StoreError::Integrity("checkpoint metadata mismatch".into()));
        }
        if load_task(&tx, &self.key, self.limits, task_id)?
            .record
            .version
            < version
        {
            return Err(StoreError::Integrity(
                "checkpoint version is in the future".into(),
            ));
        }
        artifact_owned(&tx, task_id, &artifact)?;
        require_reference(&tx, task_id, "checkpoint", checkpoint_id, &artifact)?;
        tx.commit()?;
        Ok(cp)
    }
    pub fn events(&self, task_id: &str) -> StoreResult<Vec<JournalEvent>> {
        self.events_on(&self.conn, task_id)
    }
    fn events_on(&self, conn: &Connection, task_id: &str) -> StoreResult<Vec<JournalEvent>> {
        let mut s=conn.prepare("SELECT sequence,kind,created_at_ms,payload FROM events WHERE task_id=?1 ORDER BY sequence")?;
        let rows = s.query_map([task_id], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (sequence, kind, time, payload) = row?;
            if result.len() as u64 >= self.limits.max_events_per_task {
                return Err(StoreError::Quota("event count".into()));
            }
            let event: JournalEvent = decode(
                &self.key,
                &format!("event:{task_id}:{sequence}"),
                &payload,
                self.limits.max_payload_bytes,
            )?;
            if event.task_id != task_id
                || event.sequence != sequence
                || event.task.record.version != sequence
                || event.kind != kind
                || event.created_at_ms != time
            {
                return Err(StoreError::Integrity("event metadata mismatch".into()));
            }
            result.push(event);
        }
        Ok(result)
    }
    pub fn replay_task(&self, task_id: &str) -> StoreResult<StoredTask> {
        let tx = self.conn.unchecked_transaction()?;
        let task = self.replay_task_on(&tx, task_id)?;
        tx.commit()?;
        Ok(task)
    }
    fn replay_task_on(&self, conn: &Connection, task_id: &str) -> StoreResult<StoredTask> {
        let events = self.events_on(conn, task_id)?;
        let mut invocations = BTreeMap::new();
        let mut attempts = BTreeMap::new();
        let mut previous: Option<StoredTask> = None;
        for (index, event) in events.iter().enumerate() {
            if event.sequence != index as u64
                || event.task.contract.task_id != task_id
                || event.task.record.task_id != task_id
            {
                return Err(StoreError::Integrity(
                    "event sequence or task mismatch".into(),
                ));
            }
            if let Some(prior) = &previous {
                if event.task.contract != prior.contract {
                    return Err(StoreError::Integrity(
                        "immutable task contract changed in journal".into(),
                    ));
                }
                if event.kind == "task_transition" {
                    let mut replayed = prior.record.clone();
                    replayed
                        .transition(
                            prior.record.version,
                            event.task.record.state,
                            event.completion_evidence.as_ref(),
                        )
                        .map_err(|_| {
                            StoreError::Integrity(
                                "task transition proof or state rejected during replay".into(),
                            )
                        })?;
                    if replayed != event.task.record {
                        return Err(StoreError::Integrity(
                            "task transition replay mismatch".into(),
                        ));
                    }
                    if let Some(proof) = &event.completion_evidence {
                        for artifact in &proof.raw_artifact_refs {
                            artifact_owned(conn, task_id, artifact)?;
                            require_reference(conn, task_id, "completion", task_id, artifact)?;
                        }
                    }
                }
                if event.kind == "invocation_reconciled" {
                    let proof = event.reconciliation_evidence.as_ref().ok_or_else(|| {
                        StoreError::Integrity("missing host reconciliation evidence".into())
                    })?;
                    let mut replayed = prior.record.clone();
                    replayed
                        .record_reconciliation(prior.record.version, proof)
                        .map_err(|_| {
                            StoreError::Integrity(
                                "reconciliation proof rejected during replay".into(),
                            )
                        })?;
                    if event.task.record.version != replayed.version
                        || event.task.record.final_artifact_digest != replayed.final_artifact_digest
                        || !matches!(
                            event.task.record.state,
                            TaskState::Verifying | TaskState::NeedsReconciliation
                        )
                    {
                        return Err(StoreError::Integrity(
                            "reconciliation replay mismatch".into(),
                        ));
                    }
                    artifact_owned(conn, task_id, &proof.resolution_artifact_ref)?;
                    require_reference(
                        conn,
                        task_id,
                        "reconciliation",
                        &proof.invocation_id,
                        &proof.resolution_artifact_ref,
                    )?;
                }
            } else if event.kind != "task_created" || event.task.record.state != TaskState::Created
            {
                return Err(StoreError::Integrity(
                    "journal must begin with task creation".into(),
                ));
            }
            event
                .task
                .record
                .validate()
                .map_err(|_| StoreError::Integrity("invalid task event".into()))?;
            if let Some(invocation) = &event.invocation {
                if invocation.task_id != task_id {
                    return Err(StoreError::Integrity("invocation event scope".into()));
                }
                invocations.insert(invocation.invocation_id.clone(), invocation.clone());
            }
            if let Some(attempt) = &event.attempt {
                if attempt.task_id != task_id {
                    return Err(StoreError::Integrity("attempt event scope".into()));
                }
                attempts.insert(attempt.attempt_id.clone(), attempt.clone());
            }
            previous = Some(event.task.clone());
        }
        let task =
            previous.ok_or_else(|| StoreError::NotFound("task has no journal events".into()))?;
        if task != load_task(conn, &self.key, self.limits, task_id)? {
            return Err(StoreError::Integrity(
                "task snapshot disagrees with replay".into(),
            ));
        }
        for (id, record) in &invocations {
            if *record != load_invocation(conn, &self.key, self.limits, id)? {
                return Err(StoreError::Integrity(
                    "invocation snapshot disagrees with replay".into(),
                ));
            }
            if let Some(artifact) = &record.result_artifact_id {
                require_reference(conn, task_id, "invocation", id, artifact)?;
            }
        }
        for (id, record) in &attempts {
            if *record != load_attempt(conn, &self.key, self.limits, id)? {
                return Err(StoreError::Integrity(
                    "attempt snapshot disagrees with replay".into(),
                ));
            }
        }
        let ic: u64 = conn.query_row(
            "SELECT count(*) FROM invocations WHERE task_id=?1",
            [task_id],
            |r| r.get(0),
        )?;
        let ac: u64 = conn.query_row(
            "SELECT count(*) FROM attempts WHERE task_id=?1",
            [task_id],
            |r| r.get(0),
        )?;
        if ic != invocations.len() as u64 || ac != attempts.len() as u64 {
            return Err(StoreError::Integrity(
                "unjournaled invocation or attempt".into(),
            ));
        }
        if let Some(digest) = &task.record.final_artifact_digest {
            let count:i64=conn.query_row("SELECT count(*) FROM artifact_refs r JOIN artifacts a ON a.artifact_id=r.artifact_id WHERE r.owner_kind='task_final' AND r.owner_id=?1 AND r.owner_task_id=?1 AND a.task_id=?1 AND a.digest=?2",params![task_id,digest],|r|r.get(0))?;
            if count != 1 {
                return Err(StoreError::Integrity(
                    "final artifact reference missing or ambiguous".into(),
                ));
            }
        }
        Ok(task)
    }
    pub fn integrity_check(&self) -> StoreResult {
        let tx = self.conn.unchecked_transaction()?;
        let status: String = tx.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if status != "ok" {
            return Err(StoreError::Integrity("SQLite quick check failed".into()));
        }
        let violation: Option<i64> = tx
            .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if violation.is_some() {
            return Err(StoreError::Integrity(
                "SQLite foreign key check failed".into(),
            ));
        }
        let tasks = {
            let mut s = tx.prepare("SELECT task_id FROM tasks ORDER BY task_id")?;
            s.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for task in tasks {
            self.replay_task_on(&tx, &task)?;
        }
        let checkpoint_ids = {
            let mut s=tx.prepare("SELECT checkpoint_id,task_id,task_version,artifact_id,created_at_ms,payload FROM checkpoints ORDER BY checkpoint_id")?;
            s.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        for (id, task, version, artifact, time, payload) in checkpoint_ids {
            let checkpoint: Checkpoint = decode(
                &self.key,
                &format!("checkpoint:{id}"),
                &payload,
                self.limits.max_payload_bytes,
            )?;
            if checkpoint.checkpoint_id != id
                || checkpoint.task_id != task
                || checkpoint.task_version != version
                || checkpoint.artifact_id != artifact
                || checkpoint.created_at_ms != time
            {
                return Err(StoreError::Integrity("checkpoint metadata mismatch".into()));
            }
            if load_task(&tx, &self.key, self.limits, &task)?
                .record
                .version
                < version
            {
                return Err(StoreError::Integrity(
                    "checkpoint version is in the future".into(),
                ));
            }
            artifact_owned(&tx, &task, &artifact)?;
            require_reference(&tx, &task, "checkpoint", &id, &artifact)?;
        }
        admission::integrity(&tx, &self.key, self.limits)?;
        control_admission::integrity(&tx, &self.key, self.limits)?;
        model_ledger::integrity(&tx, &self.key, self.limits)?;
        tx.commit()?;
        Ok(())
    }
    pub fn backup_to(&self, path: &Path) -> StoreResult {
        if path.exists() {
            return Err(StoreError::Conflict("backup destination exists".into()));
        }
        let mut destination = Connection::open(path)?;
        let backup = rusqlite::backup::Backup::new(&self.conn, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(5), None)?;
        drop(backup);
        let status: String = destination.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if status != "ok" {
            return Err(StoreError::Integrity("backup quick check".into()));
        }
        destination.close().map_err(|(_, e)| StoreError::Sql(e))?;
        Ok(())
    }
}

fn increment(value: u64) -> StoreResult<u64> {
    let next = value
        .checked_add(1)
        .ok_or_else(|| StoreError::Conflict("version exhausted".into()))?;
    integer(next)?;
    Ok(next)
}
fn bump(task: &mut StoredTask) -> StoreResult {
    task.record.version = increment(task.record.version)?;
    Ok(())
}
fn check_task_version(task: &StoredTask, expected: u64) -> StoreResult {
    integer(expected)?;
    if task.record.version != expected {
        return Err(StoreError::Conflict("stale task version".into()));
    }
    Ok(())
}
fn load_task(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<StoredTask> {
    type Row = (String, String, u64, Vec<u8>, Vec<u8>);
    let row: Option<Row> = conn
        .query_row(
            "SELECT workspace_ref,state,version,contract,record FROM tasks WHERE task_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (workspace, state, version, contract, record) =
        row.ok_or_else(|| StoreError::NotFound("task".into()))?;
    let contract: TaskContractV1 = decode(
        key,
        &format!("contract:{id}"),
        &contract,
        limits.max_payload_bytes,
    )?;
    let record: TaskRecord = decode(
        key,
        &format!("task:{id}"),
        &record,
        limits.max_payload_bytes,
    )?;
    contract
        .validate()
        .map_err(|_| StoreError::Integrity("invalid stored task contract".into()))?;
    record
        .validate()
        .map_err(|_| StoreError::Integrity("invalid stored task record".into()))?;
    if contract.task_id != id
        || record.task_id != id
        || contract.workspace_ref != workspace
        || record.version != version
        || label(&record.state)? != state
        || record.module != contract.module
        || record.acceptance_digest != contract.acceptance_contract_digest
    {
        return Err(StoreError::Integrity(
            "task metadata or immutable contract mismatch".into(),
        ));
    }
    Ok(StoredTask { contract, record })
}
fn save_task(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    task: &StoredTask,
    expected: u64,
) -> StoreResult {
    task.record.validate()?;
    let payload = encode(
        key,
        &format!("task:{}", task.record.task_id),
        &task.record,
        limits.max_payload_bytes,
    )?;
    let changed = conn.execute(
        "UPDATE tasks SET state=?1,version=?2,record=?3 WHERE task_id=?4 AND version=?5",
        params![
            label(&task.record.state)?,
            integer(task.record.version)?,
            payload,
            task.record.task_id,
            integer(expected)?
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict("task version changed".into()));
    }
    Ok(())
}
fn append_event(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    task: &StoredTask,
    kind: &str,
    invocation: Option<InvocationRecord>,
    attempt: Option<AttemptRecord>,
) -> StoreResult {
    append_event_with_proof(
        conn, key, limits, task, kind, invocation, attempt, None, None,
    )
}
#[allow(clippy::too_many_arguments)]
fn append_event_with_proof(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    task: &StoredTask,
    kind: &str,
    invocation: Option<InvocationRecord>,
    attempt: Option<AttemptRecord>,
    completion_evidence: Option<CompletionEvidence>,
    reconciliation_evidence: Option<ReconciliationEvidence>,
) -> StoreResult {
    if task.record.version >= limits.max_events_per_task {
        return Err(StoreError::Quota("event count per task".into()));
    }
    let event = JournalEvent {
        task_id: task.record.task_id.clone(),
        sequence: task.record.version,
        kind: kind.into(),
        created_at_ms: now()?,
        task: task.clone(),
        invocation,
        attempt,
        completion_evidence,
        reconciliation_evidence,
    };
    let payload = encode(
        key,
        &format!("event:{}:{}", event.task_id, event.sequence),
        &event,
        limits.max_payload_bytes,
    )?;
    conn.execute(
        "INSERT INTO events(task_id,sequence,kind,created_at_ms,payload) VALUES(?1,?2,?3,?4,?5)",
        params![
            event.task_id,
            integer(event.sequence)?,
            event.kind,
            integer(event.created_at_ms)?,
            payload
        ],
    )?;
    Ok(())
}
fn load_invocation(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<InvocationRecord> {
    type Row = (
        String,
        String,
        String,
        Option<String>,
        String,
        u64,
        u64,
        Option<String>,
        Option<String>,
        Vec<u8>,
    );
    let row:Option<Row>=conn.query_row("SELECT task_id,tool_id,arguments_digest,idempotency_key,state,version,generation,active_attempt_id,result_artifact_id,payload FROM invocations WHERE invocation_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).optional()?;
    let (task, tool, digest, idempotency, state, version, generation, active, result, payload) =
        row.ok_or_else(|| StoreError::NotFound("invocation".into()))?;
    let record: InvocationRecord = decode(
        key,
        &format!("invocation:{id}"),
        &payload,
        limits.max_payload_bytes,
    )?;
    if record.invocation_id != id
        || record.task_id != task
        || record.tool_id != tool
        || record.arguments_digest != digest
        || record.idempotency_key != idempotency
        || label(&record.state)? != state
        || record.version != version
        || record.generation != generation
        || record.active_attempt_id != active
        || record.result_artifact_id != result
        || blake3::hash(&serde_json::to_vec(&record.arguments)?)
            .to_hex()
            .as_str()
            != digest
    {
        return Err(StoreError::Integrity("invocation metadata mismatch".into()));
    }
    Ok(record)
}
fn insert_invocation(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    record: &InvocationRecord,
) -> StoreResult {
    let payload = encode(
        key,
        &format!("invocation:{}", record.invocation_id),
        record,
        limits.max_payload_bytes,
    )?;
    conn.execute("INSERT INTO invocations(invocation_id,task_id,tool_id,arguments_digest,idempotency_key,state,version,generation,active_attempt_id,result_artifact_id,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![record.invocation_id,record.task_id,record.tool_id,record.arguments_digest,record.idempotency_key,label(&record.state)?,integer(record.version)?,integer(record.generation)?,record.active_attempt_id,record.result_artifact_id,payload])?;
    Ok(())
}
fn save_invocation(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    record: &InvocationRecord,
    expected: u64,
) -> StoreResult {
    let payload = encode(
        key,
        &format!("invocation:{}", record.invocation_id),
        record,
        limits.max_payload_bytes,
    )?;
    let changed=conn.execute("UPDATE invocations SET state=?1,version=?2,active_attempt_id=?3,result_artifact_id=?4,payload=?5 WHERE invocation_id=?6 AND version=?7",params![label(&record.state)?,integer(record.version)?,record.active_attempt_id,record.result_artifact_id,payload,record.invocation_id,integer(expected)?])?;
    if changed != 1 {
        return Err(StoreError::Conflict("invocation version changed".into()));
    }
    Ok(())
}
fn load_attempt(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<AttemptRecord> {
    type Row = (String, String, u64, u64, String, u64, Vec<u8>);
    let row:Option<Row>=conn.query_row("SELECT invocation_id,task_id,number,generation,state,version,payload FROM attempts WHERE attempt_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
    let (invocation, task, number, generation, state, version, payload) =
        row.ok_or_else(|| StoreError::NotFound("attempt".into()))?;
    let record: AttemptRecord = decode(
        key,
        &format!("attempt:{id}"),
        &payload,
        limits.max_payload_bytes,
    )?;
    if record.attempt_id != id
        || record.invocation_id != invocation
        || record.task_id != task
        || record.number != number
        || record.generation != generation
        || label(&record.state)? != state
        || record.version != version
    {
        return Err(StoreError::Integrity("attempt metadata mismatch".into()));
    }
    Ok(record)
}
fn save_attempt(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    record: &AttemptRecord,
    expected: u64,
) -> StoreResult {
    let payload = encode(
        key,
        &format!("attempt:{}", record.attempt_id),
        record,
        limits.max_payload_bytes,
    )?;
    let changed = conn.execute(
        "UPDATE attempts SET state=?1,version=?2,payload=?3 WHERE attempt_id=?4 AND version=?5",
        params![
            label(&record.state)?,
            integer(record.version)?,
            payload,
            record.attempt_id,
            integer(expected)?
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict("attempt version changed".into()));
    }
    Ok(())
}
fn ensure_no_inflight(conn: &Connection, task: &str) -> StoreResult {
    model_ledger::ensure_no_unresolved(conn, task)?;
    let count:i64=conn.query_row("SELECT count(*) FROM invocations WHERE task_id=?1 AND (active_attempt_id IS NOT NULL OR state IN ('dispatched','running','outcome_unknown','needs_reconciliation'))",[task],|r|r.get(0))?;
    if count != 0 {
        return Err(StoreError::Conflict(
            "task has unresolved or inflight invocations".into(),
        ));
    }
    Ok(())
}
pub(crate) fn artifact_owned(conn: &Connection, task: &str, artifact: &str) -> StoreResult<String> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT task_id,digest FROM artifacts WHERE artifact_id=?1",
            [artifact],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (owner, digest) = row.ok_or_else(|| StoreError::NotFound("artifact".into()))?;
    if owner != task {
        return Err(StoreError::Conflict(
            "artifact belongs to a different task".into(),
        ));
    }
    Ok(digest)
}
pub(crate) fn add_reference(
    conn: &Connection,
    task: &str,
    kind: &str,
    owner: &str,
    artifact: &str,
) -> StoreResult {
    artifact_owned(conn, task, artifact)?;
    conn.execute("INSERT OR IGNORE INTO artifact_refs(owner_task_id,owner_kind,owner_id,artifact_id) VALUES(?1,?2,?3,?4)",params![task,kind,owner,artifact])?;
    Ok(())
}
fn require_reference(
    conn: &Connection,
    task: &str,
    kind: &str,
    owner: &str,
    artifact: &str,
) -> StoreResult {
    let found:Option<i64>=conn.query_row("SELECT 1 FROM artifact_refs WHERE owner_task_id=?1 AND owner_kind=?2 AND owner_id=?3 AND artifact_id=?4",params![task,kind,owner,artifact],|r|r.get(0)).optional()?;
    if found.is_none() {
        return Err(StoreError::Integrity(
            "permanent journal artifact reference is missing".into(),
        ));
    }
    Ok(())
}

fn validate_schema(conn: &Connection, version: i64) -> StoreResult {
    fn definitions(conn: &Connection) -> StoreResult<Vec<(String, String, String)>> {
        let mut statement=conn.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
        Ok(statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(MIGRATION)?;
    if version >= 2 {
        expected.execute_batch(ADMISSION_MIGRATION)?;
    }
    if version >= 3 {
        expected.execute_batch(CONTROL_MIGRATION)?;
    }
    if version >= 4 {
        expected.execute_batch(MODEL_MIGRATION)?;
    }
    if definitions(conn)? != definitions(&expected)? {
        return Err(StoreError::Integrity(
            "missing, modified or foreign schema object".into(),
        ));
    }
    Ok(())
}
