//! Trusted-host durable admission. Signature and policy verification belong to
//! the broker; this transaction binds its verified decision to one dispatch.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    pub permit_id: String,
    pub nonce: String,
    pub permit_digest: String,
    pub task_id: String,
    pub principal_id: String,
    pub profile_id: String,
    pub tool_id: String,
    pub resource_id: String,
    /// Exact digest stored by Journal::propose_invocation (lowercase raw hex).
    pub arguments_digest: String,
    pub invocation_id: String,
    pub attempt_id: String,
    pub generation: u64,
    pub expected_task_version: u64,
    pub expected_invocation_version: u64,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    /// Obtained from the trusted host clock, never from a model tool argument.
    pub consumed_at_unix_ms: u64,
}

impl AdmissionRequest {
    fn validate(&self) -> StoreResult {
        for value in [
            &self.permit_id,
            &self.nonce,
            &self.permit_digest,
            &self.task_id,
            &self.principal_id,
            &self.profile_id,
            &self.tool_id,
            &self.resource_id,
            &self.arguments_digest,
            &self.invocation_id,
            &self.attempt_id,
        ] {
            nonblank(value)?;
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
            return Err(StoreError::Invalid("invalid permit validity window".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitRevocation {
    pub permit_id: String,
    pub reason: String,
    pub revoked_at_unix_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionClock {
    last_seen_ms: u64,
}

fn initialize_clock(conn: &Connection, key: &StoreKey, limits: JournalLimits) -> StoreResult {
    let payload = encode(
        key,
        "execution-clock:v1",
        &ExecutionClock { last_seen_ms: 0 },
        limits.max_payload_bytes,
    )?;
    conn.execute(
        "INSERT INTO execution_clock(singleton,last_seen_ms,payload) VALUES(1,0,?1)",
        [payload],
    )?;
    Ok(())
}

pub(super) fn read_clock(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
) -> StoreResult<u64> {
    let row: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT last_seen_ms,payload FROM execution_clock WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (time, payload) =
        row.ok_or_else(|| StoreError::Integrity("missing execution clock".into()))?;
    let clock: ExecutionClock = decode(
        key,
        "execution-clock:v1",
        &payload,
        limits.max_payload_bytes,
    )?;
    let recorded: u64 = conn.query_row("SELECT max(coalesce((SELECT max(consumed_at_ms) FROM permit_admissions),0),coalesce((SELECT max(revoked_at_ms) FROM permit_revocations),0),coalesce((SELECT max(consumed_at_ms) FROM control_admissions),0),coalesce((SELECT max(created_at_ms) FROM model_request_events),0))",[],|r|r.get(0))?;
    if clock.last_seen_ms != time || time != recorded {
        return Err(StoreError::Integrity(
            "execution clock metadata mismatch".into(),
        ));
    }
    Ok(time)
}

pub(super) fn advance_clock(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    time: u64,
) -> StoreResult {
    let payload = encode(
        key,
        "execution-clock:v1",
        &ExecutionClock { last_seen_ms: time },
        limits.max_payload_bytes,
    )?;
    if conn.execute(
        "UPDATE execution_clock SET last_seen_ms=?1,payload=?2 WHERE singleton=1",
        params![integer(time)?, payload],
    )? != 1
    {
        return Err(StoreError::Integrity("missing execution clock".into()));
    }
    Ok(())
}

pub(super) fn load_revocation(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<Option<PermitRevocation>> {
    let row: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT revoked_at_ms,payload FROM permit_revocations WHERE permit_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(time, payload)| {
        let record: PermitRevocation = decode(
            key,
            &format!("permit-revocation:{id}"),
            &payload,
            limits.max_payload_bytes,
        )?;
        nonblank(&record.permit_id)?;
        nonblank(&record.reason)?;
        if record.permit_id != id || record.revoked_at_unix_ms != time {
            return Err(StoreError::Integrity("revocation metadata mismatch".into()));
        }
        Ok(record)
    })
    .transpose()
}

pub(super) fn load_admission(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<AdmissionRequest> {
    type Row = (String, String, String, String, String, String, u64, Vec<u8>);
    let row:Option<Row>=conn.query_row("SELECT nonce,invocation_id,attempt_id,task_id,arguments_digest,permit_digest,consumed_at_ms,payload FROM permit_admissions WHERE permit_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let (nonce, inv, attempt, task, args, digest, time, payload) =
        row.ok_or_else(|| StoreError::NotFound("permit admission".into()))?;
    let record: AdmissionRequest = decode(
        key,
        &format!("permit-admission:{id}"),
        &payload,
        limits.max_payload_bytes,
    )?;
    record.validate()?;
    if record.permit_id != id
        || record.nonce != nonce
        || record.invocation_id != inv
        || record.attempt_id != attempt
        || record.task_id != task
        || record.arguments_digest != args
        || record.permit_digest != digest
        || record.consumed_at_unix_ms != time
    {
        return Err(StoreError::Integrity("admission metadata mismatch".into()));
    }
    Ok(record)
}

impl Journal {
    /// Discards preparation after an admission denial. This cannot cancel any
    /// dispatched attempt and does not claim that an external action occurred.
    pub fn reject_proposed_invocation(
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
            || invocation.active_attempt_id.is_some()
            || task.record.state.is_terminal()
        {
            return Err(StoreError::Conflict(
                "only an unstarted proposed invocation may be rejected".into(),
            ));
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM attempts WHERE invocation_id=?1",
            [invocation_id],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(StoreError::Integrity(
                "proposed invocation has execution attempts".into(),
            ));
        }
        invocation.state = InvocationState::Cancelled;
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
            "invocation_preparation_rejected",
            Some(invocation.clone()),
            None,
        )?;
        tx.commit()?;
        Ok(invocation)
    }

    /// Atomically consumes a verified one-use permit and records dispatch intent.
    /// No OS effect has happened yet. Crash after commit is outcome-unknown.
    pub fn admit_dispatch(&mut self, request: &AdmissionRequest) -> StoreResult<AttemptRecord> {
        request.validate()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last = read_clock(&tx, &self.key, self.limits)?;
        if request.consumed_at_unix_ms < last {
            return Err(StoreError::Conflict("trusted clock moved backwards".into()));
        }
        if request.consumed_at_unix_ms < request.not_before_unix_ms
            || request.consumed_at_unix_ms >= request.expires_at_unix_ms
        {
            return Err(StoreError::Conflict(
                "permit outside validity window".into(),
            ));
        }
        if load_revocation(&tx, &self.key, self.limits, &request.permit_id)?.is_some() {
            return Err(StoreError::Conflict("permit is revoked".into()));
        }
        let duplicate:Option<i64>=tx.query_row("SELECT 1 FROM permit_admissions WHERE permit_id=?1 OR nonce=?2 OR invocation_id=?3 OR attempt_id=?4 UNION ALL SELECT 1 FROM control_admissions WHERE permit_id=?1 OR nonce=?2 LIMIT 1",params![request.permit_id,request.nonce,request.invocation_id,request.attempt_id],|r|r.get(0)).optional()?;
        if duplicate.is_some() {
            return Err(StoreError::Conflict(
                "permit or dispatch identity already consumed".into(),
            ));
        }
        let mut task = load_task(&tx, &self.key, self.limits, &request.task_id)?;
        check_task_version(&task, request.expected_task_version)?;
        let mut invocation = load_invocation(&tx, &self.key, self.limits, &request.invocation_id)?;
        if task.record.state != TaskState::Running
            || task.record.unknown_invocation_id.is_some()
            || invocation.task_id != request.task_id
            || invocation.tool_id != request.tool_id
            || invocation.arguments_digest != request.arguments_digest
            || invocation.generation != request.generation
            || invocation.version != request.expected_invocation_version
            || invocation.state != InvocationState::Proposed
            || invocation.active_attempt_id.is_some()
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
                "admission task/profile/resource/invocation binding mismatch".into(),
            ));
        }
        let prior: u64 = tx.query_row(
            "SELECT count(*) FROM attempts WHERE invocation_id=?1",
            [&request.invocation_id],
            |r| r.get(0),
        )?;
        if prior != 0 {
            return Err(StoreError::Conflict(
                "proposed invocation already has attempts".into(),
            ));
        }
        let active:u64=tx.query_row("SELECT count(*) FROM attempts WHERE task_id=?1 AND state IN ('prepared','dispatched','running','outcome_unknown')",[&request.task_id],|r|r.get(0))?;
        if active >= task.contract.limits.max_parallel_jobs {
            return Err(StoreError::Quota("task parallel dispatch allowance".into()));
        }
        let attempt = AttemptRecord {
            attempt_id: request.attempt_id.clone(),
            invocation_id: request.invocation_id.clone(),
            task_id: request.task_id.clone(),
            number: 1,
            generation: request.generation,
            state: AttemptState::Dispatched,
            version: 0,
        };
        let payload = encode(
            &self.key,
            &format!("attempt:{}", attempt.attempt_id),
            &attempt,
            self.limits.max_payload_bytes,
        )?;
        tx.execute("INSERT INTO attempts(attempt_id,invocation_id,task_id,number,generation,state,version,payload) VALUES(?1,?2,?3,1,?4,'dispatched',0,?5)",params![attempt.attempt_id,attempt.invocation_id,attempt.task_id,integer(attempt.generation)?,payload])?;
        invocation.state = InvocationState::Dispatched;
        invocation.active_attempt_id = Some(attempt.attempt_id.clone());
        invocation.version = increment(invocation.version)?;
        save_invocation(
            &tx,
            &self.key,
            self.limits,
            &invocation,
            request.expected_invocation_version,
        )?;
        bump(&mut task)?;
        save_task(
            &tx,
            &self.key,
            self.limits,
            &task,
            request.expected_task_version,
        )?;
        let payload = encode(
            &self.key,
            &format!("permit-admission:{}", request.permit_id),
            request,
            self.limits.max_payload_bytes,
        )?;
        tx.execute("INSERT INTO permit_admissions(permit_id,nonce,invocation_id,attempt_id,task_id,arguments_digest,permit_digest,consumed_at_ms,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![request.permit_id,request.nonce,request.invocation_id,request.attempt_id,request.task_id,request.arguments_digest,request.permit_digest,integer(request.consumed_at_unix_ms)?,payload])?;
        advance_clock(&tx, &self.key, self.limits, request.consumed_at_unix_ms)?;
        append_event(
            &tx,
            &self.key,
            self.limits,
            &task,
            "execution_admitted",
            Some(invocation),
            Some(attempt.clone()),
        )?;
        tx.commit()?;
        Ok(attempt)
    }
    pub fn permit_admission(&self, permit_id: &str) -> StoreResult<AdmissionRequest> {
        load_admission(&self.conn, &self.key, self.limits, permit_id)
    }
    pub fn is_permit_revoked(&self, permit_id: &str) -> StoreResult<bool> {
        Ok(load_revocation(&self.conn, &self.key, self.limits, permit_id)?.is_some())
    }
    /// Trusted host revocation is immutable and may precede permit issuance.
    pub fn revoke_permit(
        &mut self,
        permit_id: &str,
        reason: &str,
        revoked_at_unix_ms: u64,
    ) -> StoreResult {
        nonblank(permit_id)?;
        nonblank(reason)?;
        integer(revoked_at_unix_ms)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last = read_clock(&tx, &self.key, self.limits)?;
        if revoked_at_unix_ms < last {
            return Err(StoreError::Conflict("trusted clock moved backwards".into()));
        }
        let record = PermitRevocation {
            permit_id: permit_id.into(),
            reason: reason.into(),
            revoked_at_unix_ms,
        };
        if let Some(existing) = load_revocation(&tx, &self.key, self.limits, permit_id)? {
            if existing == record {
                return Ok(());
            }
            return Err(StoreError::Conflict("revocation is immutable".into()));
        }
        let payload = encode(
            &self.key,
            &format!("permit-revocation:{permit_id}"),
            &record,
            self.limits.max_payload_bytes,
        )?;
        tx.execute(
            "INSERT INTO permit_revocations(permit_id,revoked_at_ms,payload) VALUES(?1,?2,?3)",
            params![permit_id, integer(revoked_at_unix_ms)?, payload],
        )?;
        advance_clock(&tx, &self.key, self.limits, revoked_at_unix_ms)?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn initialize(conn: &Connection, key: &StoreKey, limits: JournalLimits) -> StoreResult {
    initialize_clock(conn, key, limits)
}

pub(super) fn integrity(conn: &Connection, key: &StoreKey, limits: JournalLimits) -> StoreResult {
    read_clock(conn, key, limits)?;
    let mut rows = conn.prepare("SELECT permit_id FROM permit_admissions ORDER BY permit_id")?;
    let ids = rows
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let events: u64 = conn.query_row(
        "SELECT count(*) FROM events WHERE kind='execution_admitted'",
        [],
        |r| r.get(0),
    )?;
    if events != ids.len() as u64 {
        return Err(StoreError::Integrity(
            "admission/event count mismatch".into(),
        ));
    }
    for id in ids {
        let record = load_admission(conn, key, limits, &id)?;
        let invocation = load_invocation(conn, key, limits, &record.invocation_id)?;
        let attempt = load_attempt(conn, key, limits, &record.attempt_id)?;
        let task = load_task(conn, key, limits, &record.task_id)?;
        if invocation.task_id != record.task_id
            || invocation.tool_id != record.tool_id
            || invocation.arguments_digest != record.arguments_digest
            || invocation.generation != record.generation
            || invocation.version <= record.expected_invocation_version
            || attempt.task_id != record.task_id
            || attempt.invocation_id != record.invocation_id
            || attempt.generation != record.generation
            || attempt.state == AttemptState::Prepared
            || task.record.version <= record.expected_task_version
            || !task
                .contract
                .selected_profile_ids
                .contains(&record.profile_id)
            || !task
                .contract
                .allowed_resource_ids
                .contains(&record.resource_id)
            || record.consumed_at_unix_ms < record.not_before_unix_ms
            || record.consumed_at_unix_ms >= record.expires_at_unix_ms
        {
            return Err(StoreError::Integrity(
                "admission record binding mismatch".into(),
            ));
        }
        let sequence = increment(record.expected_task_version)?;
        let payload:Vec<u8>=conn.query_row("SELECT payload FROM events WHERE task_id=?1 AND sequence=?2 AND kind='execution_admitted'",params![record.task_id,integer(sequence)?],|r|r.get(0)).map_err(|_|StoreError::Integrity("admission event missing".into()))?;
        let event: JournalEvent = decode(
            key,
            &format!("event:{}:{sequence}", record.task_id),
            &payload,
            limits.max_payload_bytes,
        )?;
        let ev_inv = event
            .invocation
            .ok_or_else(|| StoreError::Integrity("admission invocation snapshot missing".into()))?;
        let ev_attempt = event
            .attempt
            .ok_or_else(|| StoreError::Integrity("admission attempt snapshot missing".into()))?;
        if ev_inv.invocation_id != record.invocation_id
            || ev_inv.arguments_digest != record.arguments_digest
            || ev_inv.state != InvocationState::Dispatched
            || ev_inv.version != increment(record.expected_invocation_version)?
            || ev_inv.active_attempt_id.as_deref() != Some(&record.attempt_id)
            || ev_attempt.attempt_id != record.attempt_id
            || ev_attempt.state != AttemptState::Dispatched
            || ev_attempt.version != 0
        {
            return Err(StoreError::Integrity(
                "admission event binding mismatch".into(),
            ));
        }
    }
    let mut rows = conn.prepare("SELECT permit_id FROM permit_revocations ORDER BY permit_id")?;
    for id in rows.query_map([], |r| r.get::<_, String>(0))? {
        load_revocation(conn, key, limits, &id?)?;
    }
    Ok(())
}
