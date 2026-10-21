//! Durable model accounting at the trusted-host boundary. A reservation is not
//! a provider call, tool invocation, authorization, or evidence of task success.
//! Unknown usage keeps its reservation and interrupted requests are never retried.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReservation {
    pub schema_version: String,
    pub request_id: String,
    pub task_id: String,
    pub profile_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub request_digest: String,
    pub pricing_digest: Option<String>,
    pub reserved_input_tokens: u64,
    pub reserved_output_tokens: u64,
    pub reserved_cost_micro_usd: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    /// Input includes cached input; cached_input_tokens is a subset, not an
    /// additional quantity to charge against the task input-token ceiling.
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub cost_micro_usd: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRequestState {
    Reserved,
    Dispatched,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
    NeverDispatched,
}

impl ModelRequestState {
    fn unresolved(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Dispatched | Self::OutcomeUnknown
        )
    }
    fn settlement(self) -> bool {
        !matches!(self, Self::Reserved | Self::Dispatched)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSettlement {
    pub state: ModelRequestState,
    pub usage: ModelUsage,
    pub receipt_digest: Option<String>,
    pub reason: Option<String>,
    pub completed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequestRecord {
    pub schema_version: String,
    pub reservation: ModelReservation,
    pub state: ModelRequestState,
    pub version: u64,
    pub dispatched_at_unix_ms: Option<u64>,
    pub settlement: Option<ModelSettlement>,
    pub reconciliation_evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBudgetSnapshot {
    pub task_id: String,
    pub charged_input_tokens: u64,
    pub charged_output_tokens: u64,
    pub charged_cost_micro_usd: u64,
    pub known_input_tokens: u64,
    pub known_output_tokens: u64,
    pub known_cost_micro_usd: u64,
    pub unknown_input_requests: u64,
    pub unknown_output_requests: u64,
    pub unknown_cost_requests: u64,
    pub active_requests: u64,
    pub unknown_requests: u64,
    pub budget_exceeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelEvent {
    kind: String,
    created_at_unix_ms: u64,
    record: ModelRequestRecord,
}

fn bounded(value: &str) -> StoreResult {
    if value.trim().is_empty() || value.len() > 1024 || value.contains('\0') {
        return Err(StoreError::Invalid(
            "invalid model ledger identifier".into(),
        ));
    }
    Ok(())
}
fn digest(value: &str) -> StoreResult {
    if value.len() != 71
        || !value.starts_with("blake3:")
        || !value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(StoreError::Invalid(
            "noncanonical model ledger digest".into(),
        ));
    }
    Ok(())
}
fn validate_reservation(value: &ModelReservation) -> StoreResult {
    if value.schema_version != "melissa.model-reservation/v1" {
        return Err(StoreError::Unsupported("model reservation version".into()));
    }
    for id in [
        &value.request_id,
        &value.task_id,
        &value.profile_id,
        &value.provider_id,
        &value.model_id,
    ] {
        bounded(id)?;
    }
    digest(&value.request_digest)?;
    if let Some(price) = &value.pricing_digest {
        digest(price)?;
    }
    for number in [
        value.reserved_input_tokens,
        value.reserved_output_tokens,
        value.reserved_cost_micro_usd,
        value.created_at_unix_ms,
    ] {
        integer(number)?;
    }
    if value.pricing_digest.is_none() && value.reserved_cost_micro_usd == 0 {
        return Err(StoreError::Invalid(
            "unpriced model requires a nonzero conservative cost reservation".into(),
        ));
    }
    Ok(())
}
fn validate_usage(usage: &ModelUsage) -> StoreResult {
    for number in [
        usage.input_tokens,
        usage.output_tokens,
        usage.cached_input_tokens,
        usage.cost_micro_usd,
    ]
    .into_iter()
    .flatten()
    {
        integer(number)?;
    }
    if matches!((usage.input_tokens, usage.cached_input_tokens), (Some(input), Some(cache)) if cache > input)
    {
        return Err(StoreError::Invalid(
            "cached tokens exceed input tokens".into(),
        ));
    }
    Ok(())
}
fn validate_settlement(value: &ModelSettlement) -> StoreResult {
    if !value.state.settlement() {
        return Err(StoreError::Invalid(
            "model settlement state is not terminal".into(),
        ));
    }
    validate_usage(&value.usage)?;
    integer(value.completed_at_unix_ms)?;
    if let Some(receipt) = &value.receipt_digest {
        digest(receipt)?;
    }
    if let Some(reason) = &value.reason {
        bounded(reason)?;
    }
    if value.state == ModelRequestState::OutcomeUnknown && value.reason.is_none() {
        return Err(StoreError::Invalid(
            "unknown outcome requires a reason".into(),
        ));
    }
    if value.state == ModelRequestState::NeverDispatched
        && (value.receipt_digest.is_none()
            || value.reason.is_none()
            || value.usage
                != (ModelUsage {
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    cached_input_tokens: Some(0),
                    cost_micro_usd: Some(0),
                }))
    {
        return Err(StoreError::Invalid(
            "never-dispatched release requires explicit proof and known zero usage".into(),
        ));
    }
    Ok(())
}
fn validate_record(record: &ModelRequestRecord) -> StoreResult {
    validate_reservation(&record.reservation)?;
    integer(record.version)?;
    if record.schema_version != "melissa.model-request/v1" {
        return Err(StoreError::Unsupported(
            "model request record version".into(),
        ));
    }
    if let Some(time) = record.dispatched_at_unix_ms {
        integer(time)?;
        if time < record.reservation.created_at_unix_ms {
            return Err(StoreError::Integrity(
                "model dispatch predates reservation".into(),
            ));
        }
    }
    if let Some(proof) = &record.reconciliation_evidence_ref {
        bounded(proof)?;
    }
    match &record.settlement {
        Some(settlement) => {
            validate_settlement(settlement)?;
            if settlement.state != record.state
                || settlement.completed_at_unix_ms
                    < record
                        .dispatched_at_unix_ms
                        .unwrap_or(record.reservation.created_at_unix_ms)
            {
                return Err(StoreError::Integrity(
                    "invalid model settlement binding".into(),
                ));
            }
        }
        None if record.state.settlement() => {
            return Err(StoreError::Integrity("missing model settlement".into()));
        }
        None => {}
    }
    if record.state == ModelRequestState::Reserved
        && (record.version != 0 || record.dispatched_at_unix_ms.is_some())
        || record.state == ModelRequestState::Dispatched && record.dispatched_at_unix_ms.is_none()
        || record.state == ModelRequestState::NeverDispatched
            && record.dispatched_at_unix_ms.is_some()
    {
        return Err(StoreError::Integrity(
            "model state and dispatch disagree".into(),
        ));
    }
    Ok(())
}

fn load(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    id: &str,
) -> StoreResult<ModelRequestRecord> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        u64,
        u64,
        Vec<u8>,
    );
    let row: Option<Row> = conn.query_row("SELECT task_id,profile_id,provider_id,model_id,request_digest,state,version,created_at_ms,payload FROM model_requests WHERE request_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
    let (task, profile, provider, model, request_digest, state, version, created, payload) =
        row.ok_or_else(|| StoreError::NotFound("model request".into()))?;
    let record: ModelRequestRecord = decode(
        key,
        &format!("model-request:{id}"),
        &payload,
        limits.max_payload_bytes,
    )?;
    validate_record(&record)?;
    let reservation = &record.reservation;
    if reservation.request_id != id
        || reservation.task_id != task
        || reservation.profile_id != profile
        || reservation.provider_id != provider
        || reservation.model_id != model
        || reservation.request_digest != request_digest
        || label(&record.state)? != state
        || record.version != version
        || reservation.created_at_unix_ms != created
    {
        return Err(StoreError::Integrity("model request index mismatch".into()));
    }
    let owner = load_task(conn, key, limits, &task)?;
    if !owner.contract.selected_profile_ids.contains(&profile) {
        return Err(StoreError::Integrity(
            "model profile outside task scope".into(),
        ));
    }
    Ok(record)
}

fn records(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    task: &str,
) -> StoreResult<Vec<ModelRequestRecord>> {
    let mut statement =
        conn.prepare("SELECT request_id FROM model_requests WHERE task_id=?1 ORDER BY request_id")?;
    let ids = statement
        .query_map([task], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() as u64 > limits.max_events_per_task {
        return Err(StoreError::Quota("model request count per task".into()));
    }
    ids.iter().map(|id| load(conn, key, limits, id)).collect()
}

fn add(total: &mut u64, value: u64) -> StoreResult {
    *total = total
        .checked_add(value)
        .ok_or_else(|| StoreError::Quota("model accounting overflow".into()))?;
    Ok(())
}
fn budget(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    task: &str,
) -> StoreResult<ModelBudgetSnapshot> {
    let owner = load_task(conn, key, limits, task)?;
    let mut result = ModelBudgetSnapshot {
        task_id: task.into(),
        ..Default::default()
    };
    for record in records(conn, key, limits, task)? {
        let usage = record
            .settlement
            .as_ref()
            .map(|settlement| &settlement.usage);
        let values = [
            (
                usage.and_then(|value| value.input_tokens),
                record.reservation.reserved_input_tokens.max(
                    usage
                        .and_then(|value| value.cached_input_tokens)
                        .unwrap_or(0),
                ),
            ),
            (
                usage.and_then(|value| value.output_tokens),
                record.reservation.reserved_output_tokens,
            ),
            (
                usage.and_then(|value| value.cost_micro_usd),
                record.reservation.reserved_cost_micro_usd,
            ),
        ];
        for (index, (known, reserved)) in values.into_iter().enumerate() {
            let (charged_total, known_total, unknown_total) = match index {
                0 => (
                    &mut result.charged_input_tokens,
                    &mut result.known_input_tokens,
                    &mut result.unknown_input_requests,
                ),
                1 => (
                    &mut result.charged_output_tokens,
                    &mut result.known_output_tokens,
                    &mut result.unknown_output_requests,
                ),
                _ => (
                    &mut result.charged_cost_micro_usd,
                    &mut result.known_cost_micro_usd,
                    &mut result.unknown_cost_requests,
                ),
            };
            add(charged_total, known.unwrap_or(reserved))?;
            if let Some(known) = known {
                add(known_total, known)?;
            } else {
                add(unknown_total, 1)?;
            }
        }
        if record.state.unresolved() {
            add(&mut result.active_requests, 1)?;
        }
        if record.state == ModelRequestState::OutcomeUnknown {
            add(&mut result.unknown_requests, 1)?;
        }
    }
    result.budget_exceeded = result.charged_input_tokens > owner.contract.limits.max_input_tokens
        || result.charged_output_tokens > owner.contract.limits.max_output_tokens
        || result.charged_cost_micro_usd > owner.contract.limits.max_cost_micro_usd;
    Ok(result)
}

fn clock(conn: &Connection, key: &StoreKey, limits: JournalLimits, time: u64) -> StoreResult {
    integer(time)?;
    if time < admission::read_clock(conn, key, limits)? {
        return Err(StoreError::Conflict(
            "model ledger clock moved backwards".into(),
        ));
    }
    Ok(())
}
fn event(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    record: &ModelRequestRecord,
    kind: &str,
    time: u64,
) -> StoreResult {
    if record.version >= limits.max_events_per_task {
        return Err(StoreError::Quota("model request event limit".into()));
    }
    let value = ModelEvent {
        kind: kind.into(),
        created_at_unix_ms: time,
        record: record.clone(),
    };
    let payload = encode(
        key,
        &format!(
            "model-event:{}:{}",
            record.reservation.request_id, record.version
        ),
        &value,
        limits.max_payload_bytes,
    )?;
    conn.execute("INSERT INTO model_request_events(request_id,sequence,kind,created_at_ms,payload) VALUES(?1,?2,?3,?4,?5)", params![record.reservation.request_id,integer(record.version)?,kind,integer(time)?,payload])?;
    admission::advance_clock(conn, key, limits, time)
}
fn save(
    conn: &Connection,
    key: &StoreKey,
    limits: JournalLimits,
    record: &ModelRequestRecord,
    expected: u64,
    kind: &str,
    time: u64,
) -> StoreResult {
    validate_record(record)?;
    let payload = encode(
        key,
        &format!("model-request:{}", record.reservation.request_id),
        record,
        limits.max_payload_bytes,
    )?;
    if conn.execute("UPDATE model_requests SET state=?1,version=?2,payload=?3 WHERE request_id=?4 AND version=?5",params![label(&record.state)?,integer(record.version)?,payload,record.reservation.request_id,integer(expected)?])? != 1 {
        return Err(StoreError::Conflict("stale model request version".into()));
    }
    event(conn, key, limits, record, kind, time)
}
fn active_task(task: &StoredTask) -> StoreResult {
    if !matches!(
        task.record.state,
        TaskState::Running | TaskState::Repairing | TaskState::Verifying
    ) {
        return Err(StoreError::Conflict(
            "task is not active for model requests".into(),
        ));
    }
    Ok(())
}

impl Journal {
    pub fn reserve_model_request(
        &mut self,
        reservation: &ModelReservation,
        expected_task_version: u64,
    ) -> StoreResult<ModelRequestRecord> {
        self.reserve_model_request_inner(reservation, expected_task_version, None)
    }

    /// The gateway uses this additive entry point to enforce a host-configured
    /// provider/model concurrency ceiling across tasks, connections and host
    /// restarts. Unknown outcomes retain their slot until explicit reconciliation.
    /// The original reservation API retains its task-budget-only contract.
    pub fn reserve_model_request_with_provider_limit(
        &mut self,
        reservation: &ModelReservation,
        expected_task_version: u64,
        maximum_active: u32,
    ) -> StoreResult<ModelRequestRecord> {
        if maximum_active == 0 || maximum_active > 1024 {
            return Err(StoreError::Invalid(
                "provider concurrency limit bounds".into(),
            ));
        }
        self.reserve_model_request_inner(reservation, expected_task_version, Some(maximum_active))
    }

    fn reserve_model_request_inner(
        &mut self,
        reservation: &ModelReservation,
        expected_task_version: u64,
        maximum_active: Option<u32>,
    ) -> StoreResult<ModelRequestRecord> {
        validate_reservation(reservation)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner = load_task(&tx, &self.key, self.limits, &reservation.task_id)?;
        check_task_version(&owner, expected_task_version)?;
        active_task(&owner)?;
        if !owner
            .contract
            .selected_profile_ids
            .contains(&reservation.profile_id)
        {
            return Err(StoreError::Conflict(
                "model profile outside task scope".into(),
            ));
        }
        clock(&tx, &self.key, self.limits, reservation.created_at_unix_ms)?;
        if let Some(maximum_active) = maximum_active {
            // Authenticate current rows before using plaintext SQL indexes for
            // capacity. Filtering first by mutable provider/model/state indexes
            // could otherwise hide an unresolved encrypted reservation. This
            // initial local implementation scans the bounded store; it does not
            // add or silently rewrite a historical migration/index contract.
            let ids = {
                let mut statement =
                    tx.prepare("SELECT request_id FROM model_requests ORDER BY request_id")?;
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let mut active = 0u32;
            for id in ids {
                let record = load(&tx, &self.key, self.limits, &id)?;
                if record.reservation.provider_id == reservation.provider_id
                    && record.reservation.model_id == reservation.model_id
                    && record.state.unresolved()
                {
                    active = active.checked_add(1).ok_or_else(|| {
                        StoreError::Quota("provider concurrency count overflow".into())
                    })?;
                }
            }
            if active >= maximum_active {
                return Err(StoreError::Quota(
                    "provider/model concurrent request limit".into(),
                ));
            }
        }
        let current = budget(&tx, &self.key, self.limits, &reservation.task_id)?;
        if current.active_requests >= owner.contract.limits.max_parallel_jobs {
            return Err(StoreError::Quota("concurrent model request limit".into()));
        }
        for (used, requested, max) in [
            (
                current.charged_input_tokens,
                reservation.reserved_input_tokens,
                owner.contract.limits.max_input_tokens,
            ),
            (
                current.charged_output_tokens,
                reservation.reserved_output_tokens,
                owner.contract.limits.max_output_tokens,
            ),
            (
                current.charged_cost_micro_usd,
                reservation.reserved_cost_micro_usd,
                owner.contract.limits.max_cost_micro_usd,
            ),
        ] {
            if used.checked_add(requested).is_none_or(|value| value > max) {
                return Err(StoreError::Quota("task model budget exhausted".into()));
            }
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM model_requests WHERE task_id=?1",
            [&reservation.task_id],
            |r| r.get(0),
        )?;
        if count >= self.limits.max_events_per_task {
            return Err(StoreError::Quota("model request count per task".into()));
        }
        let record = ModelRequestRecord {
            schema_version: "melissa.model-request/v1".into(),
            reservation: reservation.clone(),
            state: ModelRequestState::Reserved,
            version: 0,
            dispatched_at_unix_ms: None,
            settlement: None,
            reconciliation_evidence_ref: None,
        };
        let payload = encode(
            &self.key,
            &format!("model-request:{}", reservation.request_id),
            &record,
            self.limits.max_payload_bytes,
        )?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM model_requests WHERE request_id=?1)",
            [&reservation.request_id],
            |r| r.get(0),
        )?;
        if exists {
            return Err(StoreError::Conflict(
                "model request ID already consumed".into(),
            ));
        }
        tx.execute("INSERT INTO model_requests(request_id,task_id,profile_id,provider_id,model_id,request_digest,state,version,created_at_ms,payload) VALUES(?1,?2,?3,?4,?5,?6,'reserved',0,?7,?8)",params![reservation.request_id,reservation.task_id,reservation.profile_id,reservation.provider_id,reservation.model_id,reservation.request_digest,integer(reservation.created_at_unix_ms)?,payload])?;
        event(
            &tx,
            &self.key,
            self.limits,
            &record,
            "reserved",
            reservation.created_at_unix_ms,
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn dispatch_model_request(
        &mut self,
        id: &str,
        expected_version: u64,
        time: u64,
    ) -> StoreResult<ModelRequestRecord> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, &self.key, self.limits, id)?;
        if record.version != expected_version || record.state != ModelRequestState::Reserved {
            return Err(StoreError::Conflict(
                "model request is not reserved at expected version".into(),
            ));
        }
        active_task(&load_task(
            &tx,
            &self.key,
            self.limits,
            &record.reservation.task_id,
        )?)?;
        clock(&tx, &self.key, self.limits, time)?;
        let current = budget(&tx, &self.key, self.limits, &record.reservation.task_id)?;
        if current.budget_exceeded {
            return Err(StoreError::Conflict(
                "model dispatch blocked by unresolved outcome or budget".into(),
            ));
        }
        record.state = ModelRequestState::Dispatched;
        record.version = increment(record.version)?;
        record.dispatched_at_unix_ms = Some(time);
        save(
            &tx,
            &self.key,
            self.limits,
            &record,
            expected_version,
            "dispatched",
            time,
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn finish_model_request(
        &mut self,
        id: &str,
        expected_version: u64,
        settlement: &ModelSettlement,
    ) -> StoreResult<ModelRequestRecord> {
        self.settle_model(id, expected_version, settlement, None)
    }

    fn settle_model(
        &mut self,
        id: &str,
        expected_version: u64,
        settlement: &ModelSettlement,
        evidence: Option<&str>,
    ) -> StoreResult<ModelRequestRecord> {
        validate_settlement(settlement)?;
        if let Some(proof) = evidence {
            bounded(proof)?;
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, &self.key, self.limits, id)?;
        if record.version != expected_version {
            return Err(StoreError::Conflict("stale model request version".into()));
        }
        if evidence.is_some() {
            let partial = record.settlement.as_ref().is_some_and(|value| {
                value.usage.input_tokens.is_none()
                    || value.usage.output_tokens.is_none()
                    || value.usage.cost_micro_usd.is_none()
            });
            if record.state != ModelRequestState::OutcomeUnknown && !partial {
                return Err(StoreError::Conflict(
                    "model request does not require reconciliation".into(),
                ));
            }
            if settlement.state == ModelRequestState::OutcomeUnknown {
                return Err(StoreError::Invalid(
                    "reconciliation must resolve the outcome".into(),
                ));
            }
        } else if record.state != ModelRequestState::Dispatched
            && !(record.state == ModelRequestState::Reserved
                && matches!(
                    settlement.state,
                    ModelRequestState::NeverDispatched | ModelRequestState::OutcomeUnknown
                ))
        {
            return Err(StoreError::Conflict(
                "model request cannot be settled from current state".into(),
            ));
        }
        if settlement.state == ModelRequestState::NeverDispatched
            && record.dispatched_at_unix_ms.is_some()
        {
            return Err(StoreError::Conflict(
                "dispatched model request cannot claim no dispatch".into(),
            ));
        }
        clock(&tx, &self.key, self.limits, settlement.completed_at_unix_ms)?;
        record.state = settlement.state;
        record.version = increment(record.version)?;
        record.settlement = Some(settlement.clone());
        record.reconciliation_evidence_ref = evidence.map(str::to_owned);
        let kind = if evidence.is_some() {
            "reconciled"
        } else if settlement.state == ModelRequestState::OutcomeUnknown {
            "unknown"
        } else {
            "settled"
        };
        // Actual provider usage is evidence: an overrun is persisted, never
        // discarded because it exceeded the earlier reservation.
        save(
            &tx,
            &self.key,
            self.limits,
            &record,
            expected_version,
            kind,
            settlement.completed_at_unix_ms,
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn mark_model_request_unknown(
        &mut self,
        id: &str,
        expected_version: u64,
        reason: &str,
        time: u64,
    ) -> StoreResult<ModelRequestRecord> {
        self.finish_model_request(
            id,
            expected_version,
            &ModelSettlement {
                state: ModelRequestState::OutcomeUnknown,
                usage: ModelUsage::default(),
                receipt_digest: None,
                reason: Some(reason.into()),
                completed_at_unix_ms: time,
            },
        )
    }

    pub fn reconcile_model_request(
        &mut self,
        id: &str,
        expected_version: u64,
        settlement: &ModelSettlement,
        evidence_ref: &str,
    ) -> StoreResult<ModelRequestRecord> {
        self.settle_model(id, expected_version, settlement, Some(evidence_ref))
    }

    pub fn model_request(&self, id: &str) -> StoreResult<ModelRequestRecord> {
        load(&self.conn, &self.key, self.limits, id)
    }
    pub fn model_requests(&self, task: &str) -> StoreResult<Vec<ModelRequestRecord>> {
        load_task(&self.conn, &self.key, self.limits, task)?;
        records(&self.conn, &self.key, self.limits, task)
    }
    pub fn model_budget(&self, task: &str) -> StoreResult<ModelBudgetSnapshot> {
        budget(&self.conn, &self.key, self.limits, task)
    }

    /// Only LocalStore's new exclusive host session invokes this automatically.
    /// `connect` never converts another live connection's work to unknown.
    pub fn recover_interrupted_model_requests(&mut self) -> StoreResult<usize> {
        let ids = {
            let mut statement = self.conn.prepare("SELECT request_id FROM model_requests WHERE state IN ('reserved','dispatched') ORDER BY task_id,request_id")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let time = now()?.max(admission::read_clock(&tx, &self.key, self.limits)?);
        let mut recovered = 0;
        for id in ids {
            let mut record = load(&tx, &self.key, self.limits, &id)?;
            if !matches!(
                record.state,
                ModelRequestState::Reserved | ModelRequestState::Dispatched
            ) {
                continue;
            }
            let version = record.version;
            record.version = increment(version)?;
            record.state = ModelRequestState::OutcomeUnknown;
            record.settlement = Some(ModelSettlement {
                state: ModelRequestState::OutcomeUnknown,
                usage: ModelUsage::default(),
                receipt_digest: None,
                reason: Some("host session interrupted; no automatic release or retry".into()),
                completed_at_unix_ms: time,
            });
            save(
                &tx,
                &self.key,
                self.limits,
                &record,
                version,
                "recovered_unknown",
                time,
            )?;
            recovered += 1;
        }
        tx.commit()?;
        Ok(recovered)
    }
}

pub(super) fn ensure_no_unresolved(conn: &Connection, task: &str) -> StoreResult {
    let count: u64 = conn.query_row("SELECT count(*) FROM model_requests WHERE task_id=?1 AND state IN ('reserved','dispatched','outcome_unknown')", [task], |row| row.get(0))?;
    if count != 0 {
        return Err(StoreError::Conflict(
            "task has unresolved model requests".into(),
        ));
    }
    Ok(())
}

pub(super) fn integrity(conn: &Connection, key: &StoreKey, limits: JournalLimits) -> StoreResult {
    let ids = {
        let mut statement =
            conn.prepare("SELECT request_id FROM model_requests ORDER BY request_id")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let last_clock = admission::read_clock(conn, key, limits)?;
    for id in ids {
        let current = load(conn, key, limits, &id)?;
        let mut statement = conn.prepare("SELECT sequence,kind,created_at_ms,payload FROM model_request_events WHERE request_id=?1 ORDER BY sequence")?;
        let rows = statement
            .query_map([&id], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() as u64 != current.version + 1
            || rows.len() as u64 > limits.max_events_per_task
        {
            return Err(StoreError::Integrity(
                "model event sequence incomplete".into(),
            ));
        }
        let mut previous: Option<ModelEvent> = None;
        for (sequence, kind, time, payload) in rows {
            let event: ModelEvent = decode(
                key,
                &format!("model-event:{id}:{sequence}"),
                &payload,
                limits.max_payload_bytes,
            )?;
            validate_record(&event.record)?;
            if event.kind != kind
                || event.created_at_unix_ms != time
                || event.record.reservation != current.reservation
                || event.record.version != sequence
                || time > last_clock
            {
                return Err(StoreError::Integrity(
                    "model event metadata mismatch".into(),
                ));
            }
            if let Some(prior) = &previous {
                if sequence != prior.record.version + 1 || time < prior.created_at_unix_ms {
                    return Err(StoreError::Integrity("model history order mismatch".into()));
                }
                let valid = match kind.as_str() {
                    "dispatched" => {
                        prior.record.state == ModelRequestState::Reserved
                            && event.record.state == ModelRequestState::Dispatched
                            && event.record.dispatched_at_unix_ms == Some(time)
                    }
                    "settled" => {
                        prior.record.state == ModelRequestState::Dispatched
                            && event.record.state.settlement()
                            && event.record.state != ModelRequestState::OutcomeUnknown
                            || prior.record.state == ModelRequestState::Reserved
                                && event.record.state == ModelRequestState::NeverDispatched
                    }
                    "unknown" | "recovered_unknown" => {
                        matches!(
                            prior.record.state,
                            ModelRequestState::Reserved | ModelRequestState::Dispatched
                        ) && event.record.state == ModelRequestState::OutcomeUnknown
                    }
                    "reconciled" => {
                        event.record.reconciliation_evidence_ref.is_some()
                            && event.record.state.settlement()
                            && event.record.state != ModelRequestState::OutcomeUnknown
                    }
                    _ => false,
                };
                if !valid
                    || (kind != "dispatched"
                        && event.record.dispatched_at_unix_ms != prior.record.dispatched_at_unix_ms)
                {
                    return Err(StoreError::Integrity(
                        "invalid model history transition".into(),
                    ));
                }
                if let Some(settlement) = &event.record.settlement
                    && settlement.completed_at_unix_ms != time
                {
                    return Err(StoreError::Integrity(
                        "model history settlement clock mismatch".into(),
                    ));
                }
            } else if sequence != 0
                || kind != "reserved"
                || event.record.state != ModelRequestState::Reserved
                || time != current.reservation.created_at_unix_ms
            {
                return Err(StoreError::Integrity(
                    "model history has no reservation root".into(),
                ));
            }
            previous = Some(event);
        }
        if previous.as_ref().map(|value| &value.record) != Some(&current) {
            return Err(StoreError::Integrity(
                "model current record differs from history".into(),
            ));
        }
    }
    Ok(())
}
