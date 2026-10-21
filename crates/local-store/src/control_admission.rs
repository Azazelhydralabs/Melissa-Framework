//! Authenticated managed process control, never arbitrary PID authority.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlAdmission {
    pub permit_id: String,
    pub nonce: String,
    pub permit_digest: String,
    pub task_id: String,
    pub principal_id: String,
    pub profile_id: String,
    pub target_invocation_id: String,
    pub generation: u64,
    pub resource_id: String,
    pub tool_id: String,
    pub arguments_digest: String,
    pub expected_task_version: u64,
    pub expected_invocation_version: u64,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub consumed_at_unix_ms: u64,
}
impl ControlAdmission {
    fn validate(&self) -> StoreResult {
        for value in [
            &self.permit_id,
            &self.nonce,
            &self.permit_digest,
            &self.task_id,
            &self.principal_id,
            &self.profile_id,
            &self.target_invocation_id,
            &self.resource_id,
            &self.arguments_digest,
        ] {
            if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(StoreError::Invalid(
                    "bounded control identity required".into(),
                ));
            }
        }
        if !matches!(self.tool_id.as_str(), "process.inspect" | "process.cancel") {
            return Err(StoreError::Invalid("unknown managed control tool".into()));
        }
        for value in [
            self.generation,
            self.expected_task_version,
            self.expected_invocation_version,
            self.not_before_unix_ms,
            self.expires_at_unix_ms,
            self.consumed_at_unix_ms,
        ] {
            integer(value)?;
        }
        if self.not_before_unix_ms >= self.expires_at_unix_ms {
            return Err(StoreError::Invalid("control validity window".into()));
        }
        Ok(())
    }
}

fn load(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<ControlAdmission> {
    type Row = (String, String, String, u64, String, String, u64, Vec<u8>);
    let row:Option<Row>=conn.query_row("SELECT nonce,task_id,target_invocation_id,generation,tool_id,resource_id,consumed_at_ms,payload FROM control_admissions WHERE permit_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let (nonce, task, target, generation, tool, resource, time, payload) =
        row.ok_or_else(|| StoreError::NotFound("control admission".into()))?;
    let value: ControlAdmission = decode(
        key,
        &format!("control-admission:{id}"),
        &payload,
        limits.max_payload_bytes,
    )?;
    value.validate()?;
    if value.permit_id != id
        || value.nonce != nonce
        || value.task_id != task
        || value.target_invocation_id != target
        || value.generation != generation
        || value.tool_id != tool
        || value.resource_id != resource
        || value.consumed_at_unix_ms != time
    {
        return Err(StoreError::Integrity(
            "control index binding mismatch".into(),
        ));
    }
    Ok(value)
}

impl Journal {
    pub fn managed_execution(&self, invocation_id: &str) -> StoreResult<AdmissionRequest> {
        let id: String = self
            .conn
            .query_row(
                "SELECT permit_id FROM permit_admissions WHERE invocation_id=?1",
                [invocation_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound("managed execution admission".into()))?;
        admission::load_admission(&self.conn, &self.key, self.limits, &id)
    }
    /// The transaction consumes a control nonce and persists cancellation intent
    /// without using a process-job slot or claiming termination has happened.
    pub fn admit_control(&mut self, request: &ControlAdmission) -> StoreResult<InvocationRecord> {
        request.validate()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if request.consumed_at_unix_ms < admission::read_clock(&tx, &self.key, self.limits)?
            || request.consumed_at_unix_ms < request.not_before_unix_ms
            || request.consumed_at_unix_ms >= request.expires_at_unix_ms
        {
            return Err(StoreError::Conflict(
                "control clock or expiry rejected".into(),
            ));
        }
        if admission::load_revocation(&tx, &self.key, self.limits, &request.permit_id)?.is_some() {
            return Err(StoreError::Conflict("control permit revoked".into()));
        }
        let used:Option<i64>=tx.query_row("SELECT 1 FROM permit_admissions WHERE permit_id=?1 OR nonce=?2 UNION ALL SELECT 1 FROM control_admissions WHERE permit_id=?1 OR nonce=?2 LIMIT 1",params![request.permit_id,request.nonce],|r|r.get(0)).optional()?;
        if used.is_some() {
            return Err(StoreError::Conflict("permit or nonce consumed".into()));
        }
        let task = load_task(&tx, &self.key, self.limits, &request.task_id)?;
        check_task_version(&task, request.expected_task_version)?;
        let target = load_invocation(&tx, &self.key, self.limits, &request.target_invocation_id)?;
        let execution_id: String = tx
            .query_row(
                "SELECT permit_id FROM permit_admissions WHERE invocation_id=?1",
                [&request.target_invocation_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound("control target is not broker managed".into()))?;
        let execution = admission::load_admission(&tx, &self.key, self.limits, &execution_id)?;
        if target.task_id != request.task_id
            || target.generation != request.generation
            || target.version != request.expected_invocation_version
            || execution.resource_id != request.resource_id
            || execution.task_id != request.task_id
            || execution.generation != request.generation
            || !task
                .contract
                .selected_profile_ids
                .contains(&request.profile_id)
            || !task
                .contract
                .allowed_resource_ids
                .contains(&request.resource_id)
        {
            return Err(StoreError::Conflict(
                "managed control scope/version mismatch".into(),
            ));
        }
        let payload = encode(
            &self.key,
            &format!("control-admission:{}", request.permit_id),
            request,
            self.limits.max_payload_bytes,
        )?;
        tx.execute("INSERT INTO control_admissions(permit_id,nonce,task_id,target_invocation_id,generation,tool_id,resource_id,consumed_at_ms,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![request.permit_id,request.nonce,request.task_id,request.target_invocation_id,integer(request.generation)?,request.tool_id,request.resource_id,integer(request.consumed_at_unix_ms)?,payload])?;
        admission::advance_clock(&tx, &self.key, self.limits, request.consumed_at_unix_ms)?;
        // Control has its own immutable audit journal. An inspection must not
        // change task/attempt versions and race a legitimate executor commit.
        tx.commit()?;
        Ok(target)
    }
    pub fn control_admission(&self, id: &str) -> StoreResult<ControlAdmission> {
        load(&self.conn, &self.key, self.limits, id)
    }
    pub fn is_cancel_requested(
        &self,
        task: &str,
        invocation: &str,
        generation: u64,
    ) -> StoreResult<bool> {
        let ids = {
            let mut query=self.conn.prepare("SELECT permit_id FROM control_admissions WHERE task_id=?1 AND target_invocation_id=?2 AND generation=?3 AND tool_id='process.cancel'")?;
            query
                .query_map(params![task, invocation, integer(generation)?], |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let requested = !ids.is_empty();
        for id in ids {
            let record = load(&self.conn, &self.key, self.limits, &id)?;
            if record.task_id != task
                || record.target_invocation_id != invocation
                || record.generation != generation
                || record.tool_id != "process.cancel"
            {
                return Err(StoreError::Integrity("cancel request mismatch".into()));
            }
        }
        Ok(requested)
    }
}

pub(super) fn integrity(conn: &Connection, key: &StoreKey, limits: JournalLimits) -> StoreResult {
    let ids = {
        let mut query =
            conn.prepare("SELECT permit_id FROM control_admissions ORDER BY permit_id")?;
        query
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let cross:u64=conn.query_row("SELECT count(*) FROM control_admissions c JOIN permit_admissions p ON p.permit_id=c.permit_id OR p.nonce=c.nonce",[],|r|r.get(0))?;
    if cross != 0 {
        return Err(StoreError::Integrity("cross-tool nonce replay".into()));
    }
    for id in ids {
        let record = load(conn, key, limits, &id)?;
        let target = load_invocation(conn, key, limits, &record.target_invocation_id)?;
        let original: String = conn.query_row(
            "SELECT permit_id FROM permit_admissions WHERE invocation_id=?1",
            [&record.target_invocation_id],
            |r| r.get(0),
        )?;
        let execution = admission::load_admission(conn, key, limits, &original)?;
        if target.task_id != record.task_id
            || target.generation != record.generation
            || execution.resource_id != record.resource_id
            || record.consumed_at_unix_ms < record.not_before_unix_ms
            || record.consumed_at_unix_ms >= record.expires_at_unix_ms
        {
            return Err(StoreError::Integrity(
                "control target binding mismatch".into(),
            ));
        }
        let task = load_task(conn, key, limits, &record.task_id)?;
        if task.record.version < record.expected_task_version
            || target.version < record.expected_invocation_version
            || !task
                .contract
                .selected_profile_ids
                .contains(&record.profile_id)
            || !task
                .contract
                .allowed_resource_ids
                .contains(&record.resource_id)
        {
            return Err(StoreError::Integrity(
                "control historical version or authority mismatch".into(),
            ));
        }
    }
    Ok(())
}
