//! Stateful, task/source/permit-bound DAP actor. Commands are input to one
//! already admitted private process; they cannot choose adapters or attach PIDs.
use crate::{
    Error, Result,
    full::{Language, put, validate_source},
    hex, toolchain,
};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Conversation, Snapshot};
use melissa_execution_broker::{
    InvocationIdentity, PolicyControl,
    container_broker::{ContainerBroker, ContainerExecution},
    container_policy::SignedContainerPermit,
    unix_ms,
};
use melissa_local_store::LocalStore;
use melissa_repository::{Repository, RepositorySnapshot, archive};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
const DRIVER: &str = include_str!("debug_worker.py");
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Breakpoint {
    pub path: String,
    pub line: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Frame,
    Variables,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub session_id: String,
    pub epoch: u64,
    pub kind: ReferenceKind,
    pub id: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum DebugCommand {
    Start {},
    Stack {},
    Inspect {
        count: u16,
    },
    Scopes {
        frame: Reference,
    },
    Variables {
        reference: Reference,
        start: u32,
        count: u16,
    },
    Next {},
    StepIn {},
    StepOut {},
    Continue {},
    Pause {},
    Wait {
        timeout_ms: u32,
    },
    Breakpoints {
        breakpoints: Vec<Breakpoint>,
    },
    Close {},
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugState {
    New,
    Stopped,
    Running,
    Exited,
    Closed,
    Crashed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugReply {
    pub seq: u64,
    pub ok: bool,
    pub body: Option<Value>,
    pub error: Option<crate::full::DriverError>,
    pub source_digest: String,
    pub state: DebugState,
    pub epoch: u64,
}
pub struct DebugPlan {
    request: ContainerRequest,
    snapshot: Snapshot,
    source: RepositorySnapshot,
    language: Language,
    entry: String,
}
impl DebugPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        language: Language,
        entry: String,
        breakpoints: Vec<Breakpoint>,
        expected_binary_sha256: Option<String>,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        let mut snapshot = repo.worker_input(source, cancel)?.snapshot;
        validate_source(&snapshot)?;
        if !snapshot.files.contains_key(&entry) {
            return Err(Error::Invalid("debug entry absent from captured source"));
        }
        validate_breakpoints(&snapshot, &breakpoints)?;
        if breakpoints.is_empty() {
            return Err(Error::Invalid(
                "at least one source breakpoint required for this debug contract",
            ));
        }
        if expected_binary_sha256.as_ref().is_some_and(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(Error::Invalid(
                "expected debug binary SHA256 required in lowercase hex",
            ));
        }
        let options = crate::full::compiler_contract(&snapshot, language)?;
        let program = json!({"schema_version":"melissa.debug-program/v1","language":language.wire(),"entry":entry,"breakpoints":breakpoints,"expected_binary_sha256":expected_binary_sha256,"source_digest":source.digest,"sources":snapshot.files.iter().map(|(p,b)|(p.clone(),hex(b))).collect::<BTreeMap<_,_>>(),"compiler_options":options,"trace_limit":limits.output_bytes});
        snapshot.files.insert(
            ".melissa-code06-debug/program.json".into(),
            serde_json::to_vec(&program)?,
        );
        snapshot.files.insert(
            ".melissa-code06-debug/driver.py".into(),
            DRIVER.as_bytes().to_vec(),
        );
        snapshot
            .validate(limits.disk_bytes)
            .map_err(|_| Error::Invalid("debug snapshot envelope"))?;
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: toolchain::COMPLETE_IMAGE.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec![
                "-I".into(),
                "-S".into(),
                "-u".into(),
                ".melissa-code06-debug/driver.py".into(),
            ],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("debug request envelope"))?;
        Ok(Self {
            request,
            snapshot,
            source: source.clone(),
            language,
            entry,
        })
    }
    pub fn request(&self) -> &ContainerRequest {
        &self.request
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn source(&self) -> &RepositorySnapshot {
        &self.source
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        self,
        repo: Arc<Repository>,
        broker: Arc<Mutex<ContainerBroker>>,
        task: String,
        permit: SignedContainerPermit,
        identity: InvocationIdentity,
        cancel: Arc<AtomicBool>,
    ) -> Result<DebugSession> {
        repo.validate_snapshot(&self.source, &cancel)?;
        if permit.binding.request != self.request {
            return Err(Error::Invalid("debug request/permit mismatch"));
        }
        let (store, policy) = {
            let b = broker
                .lock()
                .map_err(|_| Error::Invalid("debug broker lock poisoned"))?;
            (b.store().connect()?, b.policy_control())
        };
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::Invalid("session entropy unavailable"))?;
        let session_id = format!("debug:{}", blake3::hash(&entropy).to_hex());
        let (input, receiver) = mpsc::channel();
        let (output, answers) = mpsc::sync_channel(8);
        let signal = cancel.clone();
        let t = task.clone();
        let attempt = identity.attempt_id.clone();
        let inv = identity.invocation_id.clone();
        let snapshot = self.snapshot.clone();
        let p = permit.clone();
        let worker = thread::spawn(move || {
            let mut b = broker.lock().map_err(|_| {
                melissa_execution_broker::BrokerError::Denied("debug broker lock poisoned".into())
            })?;
            b.execute_conversation(
                &t,
                &p,
                &snapshot,
                &identity,
                &signal,
                Conversation {
                    input: receiver,
                    output,
                },
            )
        });
        let mut session = DebugSession {
            repo,
            plan: self,
            store,
            policy,
            task,
            attempt,
            inv,
            permit,
            session_id,
            input: Some(input),
            answers,
            worker: Some(worker),
            cancel,
            sequence: 0,
            epoch: 0,
            state: DebugState::New,
            issued: BTreeSet::new(),
            last: None,
            failed: false,
            raw_artifact_ids: vec![],
            binary: None,
        };
        session.await_admission()?;
        session.command(DebugCommand::Start {})?;
        Ok(session)
    }
}
fn validate_breakpoints(snapshot: &Snapshot, points: &[Breakpoint]) -> Result {
    if points.len() > 128 {
        return Err(Error::Invalid("breakpoint envelope"));
    }
    let mut seen = BTreeSet::new();
    for p in points {
        let bytes = snapshot
            .files
            .get(&p.path)
            .ok_or(Error::Invalid("breakpoint outside captured source"))?;
        if p.line == 0
            || p.line > bytes.split(|b| *b == b'\n').count() as u64
            || !seen.insert((&p.path, p.line))
        {
            return Err(Error::Invalid("invalid or duplicate breakpoint line"));
        }
    }
    Ok(())
}
pub struct DebugSession {
    repo: Arc<Repository>,
    plan: DebugPlan,
    store: LocalStore,
    policy: PolicyControl,
    task: String,
    attempt: String,
    inv: String,
    permit: SignedContainerPermit,
    session_id: String,
    input: Option<mpsc::Sender<Vec<u8>>>,
    answers: mpsc::Receiver<Vec<u8>>,
    worker: Option<thread::JoinHandle<melissa_execution_broker::BrokerResult<ContainerExecution>>>,
    cancel: Arc<AtomicBool>,
    sequence: u64,
    epoch: u64,
    state: DebugState,
    issued: BTreeSet<(ReferenceKind, i64)>,
    last: Option<DebugReply>,
    failed: bool,
    raw_artifact_ids: Vec<String>,
    binary: Option<Value>,
}
pub struct DebugOutcome {
    pub execution: ContainerExecution,
    pub success: bool,
    pub session_id: String,
    pub language: Language,
    pub source_digest: String,
    pub host_source_current: bool,
    pub binary_bytes_authenticated: bool,
    pub artifact_refs: Vec<String>,
}
impl DebugSession {
    fn await_admission(&mut self) -> Result {
        loop {
            if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
                let result = self
                    .worker
                    .take()
                    .ok_or(Error::Invalid("debug startup worker missing"))?
                    .join()
                    .map_err(|_| {
                        Error::AfterDispatch(Box::new(Error::Invalid(
                            "debug startup worker unwound",
                        )))
                    })?;
                let error = match result {
                    Err(e) => Error::from(e),
                    Ok(e) => {
                        if e.requires_reconciliation {
                            Error::AfterDispatch(Box::new(Error::Invalid(
                                "debug worker requires reconciliation before protocol start",
                            )))
                        } else {
                            Error::Invalid("debug worker stopped before protocol start")
                        }
                    }
                };
                let admitted = self.store.journal().attempt(&self.attempt).is_ok();
                if !admitted
                    && !matches!(error, Error::AfterDispatch(_))
                    && let Ok(inv) = self.store.journal().invocation(&self.inv)
                    && inv.state == melissa_core_contracts::InvocationState::Proposed
                {
                    let task = self.store.journal().task(&self.task)?;
                    self.store.journal_mut().reject_proposed_invocation(
                        &self.inv,
                        task.record.version,
                        inv.version,
                    )?;
                }
                let id = format!("{}:debug-start-error", self.attempt);
                put(
                    &mut self.store,
                    &self.task,
                    &id,
                    "debug.start-error",
                    "application/json",
                    &serde_json::to_vec(
                        &json!({"error":format!("{error:?}"),"admitted":admitted,"protocol_start_sent":false,"automatic_retry_allowed":false}),
                    )?,
                )?;
                return Err(error);
            }
            match self.store.journal().attempt(&self.attempt) {
                Ok(a)
                    if matches!(
                        a.state,
                        melissa_local_store::journal::AttemptState::Dispatched
                            | melissa_local_store::journal::AttemptState::Running
                    ) =>
                {
                    return Ok(());
                }
                Ok(_) => (),
                Err(melissa_local_store::StoreError::NotFound(_)) => (),
                Err(e) => return Err(Error::AfterDispatch(Box::new(e.into()))),
            }
            if self.cancel.load(Ordering::Acquire)
                || unix_ms()? >= self.permit.permit.expires_at_unix_ms
            {
                self.cancel.store(true, Ordering::Release);
                return Err(Error::AfterDispatch(Box::new(Error::Invalid(
                    "debug startup cancelled or permit expired",
                ))));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn id(&self) -> &str {
        &self.session_id
    }
    pub fn state(&self) -> DebugState {
        self.state
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn last_reply(&self) -> Option<&DebugReply> {
        self.last.as_ref()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }
    fn authority(&self) -> Result {
        if self.cancel.load(Ordering::Acquire) {
            return Err(Error::Invalid("debug session cancelled"));
        }
        self.repo
            .validate_snapshot(&self.plan.source, &self.cancel)?;
        let now = unix_ms()?;
        let task = self.store.journal().task(&self.task)?;
        let policy = self.policy.snapshot()?;
        if now >= self.permit.permit.expires_at_unix_ms
            || now < self.permit.permit.not_before_unix_ms
            || task.record.state != melissa_core_contracts::TaskState::Running
            || task.record.unknown_invocation_id.is_some()
            || self
                .store
                .journal()
                .is_permit_revoked(&self.permit.permit.permit_id)?
            || self
                .store
                .journal()
                .is_cancel_requested(&self.task, &self.inv, 1)?
            || policy
                .digest()
                .map_err(melissa_execution_broker::BrokerError::from)?
                != self.permit.binding.policy_digest
        {
            return Err(Error::Invalid(
                "debug task/permit/revocation/source is no longer current",
            ));
        }
        Ok(())
    }
    fn reference(&self, r: &Reference, kind: ReferenceKind) -> Result<i64> {
        if r.session_id != self.session_id
            || r.epoch != self.epoch
            || r.kind != kind
            || !self.issued.contains(&(kind, r.id))
        {
            return Err(Error::Invalid("foreign, stale or unissued debug reference"));
        }
        Ok(r.id)
    }
    fn native(&self, command: &DebugCommand) -> Result<Value> {
        if matches!(self.state, DebugState::Closed | DebugState::Crashed) {
            return Err(Error::Invalid("debug session is no longer actionable"));
        }
        if matches!(command, DebugCommand::Start {}) && self.state != DebugState::New {
            return Err(Error::Invalid("debug session already started"));
        }
        if matches!(command, DebugCommand::Pause {} | DebugCommand::Wait { .. })
            && self.state != DebugState::Running
        {
            return Err(Error::Invalid("debug wait/pause requires running state"));
        }
        let stopped = matches!(
            command,
            DebugCommand::Stack {}
                | DebugCommand::Inspect { .. }
                | DebugCommand::Scopes { .. }
                | DebugCommand::Variables { .. }
                | DebugCommand::Next {}
                | DebugCommand::StepIn {}
                | DebugCommand::StepOut {}
                | DebugCommand::Continue {}
        );
        if stopped && self.state != DebugState::Stopped {
            return Err(Error::Invalid("debug operation requires stopped state"));
        }
        match command {
            DebugCommand::Scopes { frame } => {
                Ok(json!({"command":"scopes","frame":self.reference(frame,ReferenceKind::Frame)?}))
            }
            DebugCommand::Variables {
                reference,
                start,
                count,
            } => {
                if *count == 0 || *count > 100 {
                    return Err(Error::Invalid("explicit variable page must be1..100"));
                }
                Ok(
                    json!({"command":"variables","reference":self.reference(reference,ReferenceKind::Variables)?,"start":start,"count":count}),
                )
            }
            DebugCommand::Inspect { count } if *count == 0 || *count > 100 => {
                Err(Error::Invalid("inspect page must be1..100"))
            }
            DebugCommand::Wait { timeout_ms } if *timeout_ms == 0 || *timeout_ms > 30000 => {
                Err(Error::Invalid("explicit wait must be1..30000ms"))
            }
            DebugCommand::Breakpoints { breakpoints } => {
                validate_breakpoints(&self.plan.snapshot, breakpoints)?;
                Ok(serde_json::to_value(command)?)
            }
            _ => Ok(serde_json::to_value(command)?),
        }
    }
    pub fn command(&mut self, command: DebugCommand) -> Result<DebugReply> {
        self.authority()?;
        let operation = self.native(&command)?;
        self.sequence += 1;
        let request = json!({"seq":self.sequence,"epoch":self.epoch,"operation":operation});
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        if bytes.len() > 64 * 1024 {
            return Err(Error::Invalid("debug command frame envelope"));
        }
        let id = format!("{}:debug-request:{}", self.attempt, self.sequence);
        put(
            &mut self.store,
            &self.task,
            &id,
            "debug.request",
            "application/json",
            &bytes,
        )?;
        self.raw_artifact_ids.push(id);
        let effect = (|| -> Result<DebugReply> {
            self.input
                .as_ref()
                .ok_or(Error::Invalid("debug stream closed"))?
                .send(bytes)
                .map_err(|_| Error::Invalid("debug process input closed"))?;
            let budget = if matches!(command, DebugCommand::Start {}) {
                Duration::from_millis(
                    self.permit
                        .permit
                        .expires_at_unix_ms
                        .saturating_sub(unix_ms()?),
                )
            } else {
                Duration::from_secs(35)
            };
            let raw = receive_until(&self.answers, &self.cancel, Instant::now() + budget, || {
                self.worker.as_ref().is_some_and(|w| w.is_finished())
            })?;
            let value = melissa_model_gateway::strict_json(
                std::str::from_utf8(&raw).map_err(|_| Error::Invalid("debug response encoding"))?,
            )
            .map_err(|_| Error::Invalid("debug response JSON"))?;
            let mut reply: DebugReply = serde_json::from_value(value)?;
            if reply.seq != self.sequence
                || reply.source_digest != self.plan.source.digest
                || reply.epoch < self.epoch
            {
                return Err(Error::Invalid(
                    "debug sequence/source/stop identity mismatch",
                ));
            }
            if reply.epoch != self.epoch {
                self.issued.clear();
            }
            self.epoch = reply.epoch;
            self.state = reply.state;
            if !reply.ok {
                self.failed = true;
            }
            if let Some(body) = &mut reply.body {
                if matches!(command, DebugCommand::Start {}) {
                    self.binary = body.get("binary").cloned();
                }
                self.decorate(body);
            }
            self.authority()?;
            let id = format!("{}:debug-reply:{}", self.attempt, self.sequence);
            put(
                &mut self.store,
                &self.task,
                &id,
                "debug.reply",
                "application/json",
                &serde_json::to_vec(&reply)?,
            )?;
            self.raw_artifact_ids.push(id);
            Ok(reply)
        })();
        match effect {
            Ok(reply) => {
                self.last = Some(reply.clone());
                Ok(reply)
            }
            Err(e) => {
                self.failed = true;
                self.cancel.store(true, Ordering::Release);
                Err(Error::AfterDispatch(Box::new(e)))
            }
        }
    }
    fn decorate(&mut self, body: &mut Value) {
        fn visit(
            value: &mut Value,
            session: &str,
            epoch: u64,
            issued: &mut BTreeSet<(ReferenceKind, i64)>,
            frame_position: bool,
        ) {
            if let Some(object) = value.as_object_mut() {
                let kind = if object.contains_key("scopes") || object.contains_key("variables") {
                    None
                } else if frame_position && object.contains_key("line") && object.contains_key("id")
                {
                    Some((ReferenceKind::Frame, "id"))
                } else if object
                    .get("variablesReference")
                    .and_then(Value::as_i64)
                    .is_some_and(|id| id > 0)
                {
                    Some((ReferenceKind::Variables, "variablesReference"))
                } else {
                    None
                };
                if let Some((kind, key)) = kind
                    && let Some(id) = object.get(key).and_then(Value::as_i64)
                {
                    issued.insert((kind, id));
                    object.insert(
                        "handle".into(),
                        json!({"session_id":session,"epoch":epoch,"kind":kind,"id":id}),
                    );
                }
                for (key, child) in object.iter_mut() {
                    visit(
                        child,
                        session,
                        epoch,
                        issued,
                        matches!(key.as_str(), "stackFrames" | "frame"),
                    );
                }
            } else if let Some(array) = value.as_array_mut() {
                for child in array {
                    visit(child, session, epoch, issued, frame_position);
                }
            }
        }
        visit(body, &self.session_id, self.epoch, &mut self.issued, false);
    }
    pub fn finish(mut self) -> Result<DebugOutcome> {
        if !matches!(self.state, DebugState::Closed | DebugState::Crashed)
            && !self.cancel.load(Ordering::Acquire)
        {
            let _ = self.command(DebugCommand::Close {});
        }
        self.input.take();
        if self.state != DebugState::Closed {
            self.cancel.store(true, Ordering::Release);
        }
        let execution = self
            .worker
            .take()
            .ok_or(Error::Invalid("debug worker already joined"))?
            .join()
            .map_err(|_| {
                Error::AfterDispatch(Box::new(Error::Invalid("debug host worker unwound")))
            })??;
        let current = self
            .repo
            .validate_snapshot(&self.plan.source, &AtomicBool::new(false))
            .is_ok();
        let mut authenticated = false;
        let mut success = !self.failed
            && self.state == DebugState::Closed
            && current
            && !execution.requires_reconciliation;
        if let Some(worker) = &execution.report {
            success &= worker.termination == melissa_container_executor::TerminationReason::Exited
                && worker.exit_code == Some(0)
                && !worker.output_truncated
                && !worker.export_truncated
                && worker.cleanup_confirmed;
            if !worker.export_truncated {
                let files = archive::inspect_ustar(&worker.archive, self.repo.limits())?;
                if let Some(identity) = &self.binary
                    && let Some(data) = files
                        .iter()
                        .find(|f| f.path == ".melissa-code06-debug/debug-artifact.bin")
                {
                    let sha = hex(&Sha256::digest(&data.bytes));
                    authenticated = identity["sha256"].as_str() == Some(sha.as_str())
                        && identity["bytes"].as_u64() == Some(data.bytes.len() as u64);
                    let id = format!("{}:debug-executable", self.attempt);
                    put(
                        &mut self.store,
                        &self.task,
                        &id,
                        "debug.executable.untrusted",
                        "application/octet-stream",
                        &data.bytes,
                    )?;
                    self.raw_artifact_ids.push(id);
                }
                if let Some(raw) = files
                    .iter()
                    .find(|f| f.path == ".melissa-code06-debug/dap-transcript.ndjson")
                {
                    let id = format!("{}:dap-transcript", self.attempt);
                    put(
                        &mut self.store,
                        &self.task,
                        &id,
                        "debug.raw-dap-transcript",
                        "application/x-ndjson",
                        &raw.bytes,
                    )?;
                    self.raw_artifact_ids.push(id);
                } else {
                    success = false;
                }
            }
        }
        success &= authenticated;
        let id = format!("{}:debug-result", self.attempt);
        let result = json!({"schema_version":"melissa.debug-result/v1","success":success,"session_id":self.session_id,"language":self.plan.language,"entry":self.plan.entry,"source_digest":self.plan.source.digest,"host_source_current":current,"binary_bytes_authenticated":authenticated,"protected_acceptance":false,"task_completed":false,"raw_worker_artifact_id":execution.result_artifact_id,"artifacts":self.raw_artifact_ids});
        put(
            &mut self.store,
            &self.task,
            &id,
            "debug.normalized-result",
            "application/json",
            &serde_json::to_vec(&result)?,
        )?;
        self.raw_artifact_ids.push(id);
        Ok(DebugOutcome {
            execution,
            success,
            session_id: self.session_id.clone(),
            language: self.plan.language,
            source_digest: self.plan.source.digest.clone(),
            host_source_current: current,
            binary_bytes_authenticated: authenticated,
            artifact_refs: self.raw_artifact_ids.clone(),
        })
    }
}
impl Drop for DebugSession {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.cancel.store(true, Ordering::Release);
            self.input.take();
            let _ = worker.join();
        }
    }
}
fn receive_until(
    receiver: &mpsc::Receiver<Vec<u8>>,
    cancel: &AtomicBool,
    deadline: Instant,
    finished: impl Fn() -> bool,
) -> Result<Vec<u8>> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Invalid("debug response wait cancelled"));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Invalid(
                "debug response deadline; inspect admitted parent",
            ));
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(bytes) => return Ok(bytes),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::Invalid(
                    "debug process output closed; inspect parent",
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if finished() {
                    return Err(Error::Invalid("debug parent ended without a reply"));
                }
            }
        }
    }
}
#[cfg(test)]
mod startup_transport_tests {
    use super::*;
    #[test]
    fn delayed_start_reply_uses_its_signed_lifetime_while_deadline_and_cancel_still_stop_wait() {
        let (tx, rx) = mpsc::channel();
        let cancel = AtomicBool::new(false);
        let began = Instant::now();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            tx.send(b"real queued reply".to_vec()).unwrap();
        });
        let got = receive_until(
            &rx,
            &cancel,
            Instant::now() + Duration::from_secs(2),
            || false,
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(got, b"real queued reply");
        assert!(began.elapsed() >= Duration::from_millis(60));
        let (_tx, rx) = mpsc::channel();
        assert!(
            receive_until(
                &rx,
                &cancel,
                Instant::now() + Duration::from_millis(5),
                || false
            )
            .is_err()
        );
        cancel.store(true, Ordering::Release);
        let began = Instant::now();
        assert!(
            receive_until(
                &rx,
                &cancel,
                Instant::now() + Duration::from_secs(60),
                || false
            )
            .is_err()
        );
        assert!(began.elapsed() < Duration::from_millis(100));
    }
}
