//! Opt-in Gateway ToolDispatcher implementation. The host chooses the root,
//! task, profile, grants and routes. Wire arguments contain observations only.
use crate::{
    Error, MutationProposal, PatchBroker, PatchPolicy, PatchProposal, Repository, check_cancel,
    digest, symbols::SyntaxIndex,
};
use melissa_core_contracts::TaskState;
use melissa_local_store::{ArtifactRequest, LocalStore};
use melissa_model_gateway::{
    ErrorKind, GatewayError, ToolCall, ToolDefinition,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

/// Trusted host configuration; never deserialize this from a function call.
#[derive(Clone)]
pub struct RepositoryToolPolicy {
    pub files: PatchPolicy,
    /// Explicit authority to read this entire selected repository.
    pub read_repository: bool,
    /// Exact wire function names, e.g. fs_read or fs_create.
    pub enabled_tools: BTreeSet<String>,
}
struct Host {
    repo: Repository,
    store: LocalStore,
    policy: RepositoryToolPolicy,
    read_error_observations: bool,
    recovery_observations: bool,
}
#[derive(Clone)]
pub struct RepositoryDispatcher {
    host: Arc<Mutex<Host>>,
}

#[path = "git_tools.rs"]
mod git_bindings;
pub use git_bindings::{GitDispatcher, GitDispatcherConfig, ReviewedGitTool};
#[path = "analysis_tools.rs"]
mod analysis_bindings;
pub use analysis_bindings::{AnalysisDispatcher, ReviewedAnalysisTool};
#[path = "read_tools.rs"]
mod read_bindings;
pub use read_bindings::{RepositoryRead, RepositoryReadDispatcher, RepositoryReadPolicy};

const ROUTES: &[(&str, &str, &str)] = &[
    (
        "fs_read_page",
        "fs.read",
        "Read a byte page from an exact current file version. Continue with next_offset until complete; no silent truncation.",
    ),
    (
        "fs_artifact_page",
        "fs.read",
        "Read a digest-bound page of this task's repository tool-result artifact. Other artifact types and tasks are denied.",
    ),
    (
        "fs_discover",
        "fs.snapshot",
        "Discover source, generated, ignored and filtered files with pinned ignore/glob rules and package manifests.",
    ),
    (
        "code_polyglot_symbols",
        "code.symbols",
        "Index real Rust, Python, JavaScript, TypeScript and TSX grammars; syntax and unsupported files stay explicit.",
    ),
    (
        "code_unified_propose",
        "code.patch_propose",
        "Convert Git/unified text into untrusted proposals. line_endings defaults to exact (hunk bytes must match). Explicit preserve_source accepts text LF/CRLF transport for existing same-path edits and preserves uniform observed source EOL; mixed source EOL is refused. No fuzzy content/line match. Does not authorize or apply changes.",
    ),
    (
        "fs_directory",
        "fs.read",
        "Observe the identity and version of an empty directory. Nonempty directories require explicit per-file operations.",
    ),
    (
        "fs_mkdir",
        "fs.patch",
        "Create one empty directory in an existing pinned parent; no implicit recursive creation or replacement.",
    ),
    (
        "fs_rmdir",
        "fs.patch",
        "Remove one exact empty directory. Nonempty directories and recursive deletion are rejected.",
    ),
    (
        "fs_movedir",
        "fs.patch",
        "Rename one exact empty directory without replacing a target. Move files with separate version-bound fs_move calls.",
    ),
    (
        "fs_list",
        "fs.list",
        "List the bounded repository snapshot with exact file versions. The tree snapshot is not atomic.",
    ),
    (
        "fs_snapshot",
        "fs.snapshot",
        "Capture a bounded source snapshot with exact file versions. The tree snapshot is not atomic.",
    ),
    (
        "fs_read",
        "fs.read",
        "Read exact bytes and file identity. Byte arrays preserve binary content and CRLF.",
    ),
    (
        "fs_hash",
        "fs.hash",
        "Observe the exact file identity, BLAKE3 digest and byte count.",
    ),
    (
        "fs_absent",
        "fs.read",
        "Observe an absent file destination and its existing parent identity. This grants no write permission.",
    ),
    (
        "fs_search",
        "fs.search",
        "Search literal bytes in a current snapshot. Results include source hashes and explicit truncation.",
    ),
    (
        "code_symbols",
        "code.symbols",
        "Parse Rust Tree-sitter symbols. Other languages are reported as skipped.",
    ),
    (
        "code_references",
        "code.references",
        "Return syntactic Rust identifier occurrences only; this does not resolve semantic LSP references.",
    ),
    (
        "fs_diff",
        "fs.diff",
        "Dry-run an exact typed byte patch against current identities. Returns byte changes without writing or granting authority.",
    ),
    (
        "code_patch_propose",
        "code.patch_propose",
        "Validate and preview an exact typed byte patch proposal. This cannot authorize or apply changes.",
    ),
    (
        "fs_patch",
        "fs.patch",
        "Apply an exact existing-file typed byte patch after host/task admission. Unknown outcomes require reconciliation.",
    ),
    (
        "fs_create",
        "fs.patch",
        "Create one regular file with exact bytes in an existing identity-bound parent. Never replaces an existing target.",
    ),
    (
        "fs_delete",
        "fs.patch",
        "Delete one exact identity/hash-bound regular file. Encrypted preimage is retained. No recursive deletion.",
    ),
    (
        "fs_move",
        "fs.patch",
        "Move one exact identity/hash-bound regular file within this repository. Never replaces a destination.",
    ),
];
fn route(name: &str) -> Option<(&'static str, &'static str)> {
    ROUTES.iter().find(|r| r.0 == name).map(|r| (r.1, r.2))
}
fn write_route(id: &str) -> bool {
    matches!(id, "fs.patch" | "fs.create" | "fs.delete" | "fs.move")
}
fn err(e: Error) -> GatewayError {
    let kind = match e {
        Error::Invalid(_) | Error::Json(_) => ErrorKind::Invalid,
        Error::Denied(_) | Error::Stale(_) => ErrorKind::Authorization,
        Error::Cancelled => ErrorKind::Cancelled,
        Error::Store(_) => ErrorKind::Store,
        _ => ErrorKind::Tool,
    };
    GatewayError::new(kind, e.to_string())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArg {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArg {
    bytes: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameArg {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPageArg {
    before: crate::FileVersion,
    offset: u64,
    max_bytes: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPageArg {
    artifact_id: String,
    digest: String,
    offset: u64,
    max_bytes: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnifiedArg {
    patch: String,
    #[serde(default)]
    line_endings: crate::unified::UnifiedLineEndings,
}
enum Parsed {
    ReadPage(ReadPageArg),
    ArtifactPage(ArtifactPageArg),
    Discover(crate::discovery::DiscoveryOptions),
    Polyglot,
    Unified(UnifiedArg),
    List,
    Read(String),
    Hash(String),
    Absent(String),
    Directory(String),
    Search(Vec<u8>),
    Symbols,
    References(String),
    Preview(PatchProposal),
    Patch(PatchProposal),
    Mutation(MutationProposal),
}
fn decode<T: serde::de::DeserializeOwned>(v: Value) -> melissa_model_gateway::Result<T> {
    serde_json::from_value(v)
        .map_err(|_| GatewayError::invalid("exact tool argument fields required"))
}
fn parse(call: &ToolCall) -> melissa_model_gateway::Result<Parsed> {
    if call.id.is_empty()
        || call.id.len() > 256
        || call.id.chars().any(char::is_control)
        || call.arguments.len() > 32 * 1024 * 1024
    {
        return Err(GatewayError::invalid("repository tool bounds"));
    }
    let v = melissa_model_gateway::strict_json(&call.arguments)?;
    let p = match call.name.as_str() {
        "fs_read_page" => Parsed::ReadPage(decode(v)?),
        "fs_artifact_page" => Parsed::ArtifactPage(decode(v)?),
        "fs_discover" => Parsed::Discover(decode(v)?),
        "code_polyglot_symbols" => {
            decode::<Empty>(v)?;
            Parsed::Polyglot
        }
        "code_unified_propose" => Parsed::Unified(decode::<UnifiedArg>(v)?),
        "fs_list" | "fs_snapshot" => {
            decode::<Empty>(v)?;
            Parsed::List
        }
        "fs_read" => Parsed::Read(decode::<PathArg>(v)?.path),
        "fs_hash" => Parsed::Hash(decode::<PathArg>(v)?.path),
        "fs_directory" => Parsed::Directory(decode::<PathArg>(v)?.path),
        "fs_absent" => Parsed::Absent(decode::<PathArg>(v)?.path),
        "fs_search" => {
            let p = decode::<SearchArg>(v)?;
            if p.bytes.is_empty() || p.bytes.len() > 64 * 1024 {
                return Err(GatewayError::invalid("search byte bounds"));
            }
            Parsed::Search(p.bytes)
        }
        "code_symbols" => {
            decode::<Empty>(v)?;
            Parsed::Symbols
        }
        "code_references" => {
            let p = decode::<NameArg>(v)?;
            if p.name.is_empty() || p.name.len() > 1024 {
                return Err(GatewayError::invalid("identifier bounds"));
            }
            Parsed::References(p.name)
        }
        "fs_patch" => Parsed::Patch(PatchProposal::parse(call.arguments.as_bytes()).map_err(err)?),
        "fs_diff" | "code_patch_propose" => {
            Parsed::Preview(PatchProposal::parse(call.arguments.as_bytes()).map_err(err)?)
        }
        "fs_create" | "fs_delete" | "fs_move" | "fs_mkdir" | "fs_rmdir" | "fs_movedir" => {
            let p = MutationProposal::parse(call.arguments.as_bytes()).map_err(err)?;
            if p.tool_id().replace('.', "_") != call.name {
                return Err(GatewayError::invalid(
                    "function and mutation operation differ",
                ));
            }
            Parsed::Mutation(p)
        }
        _ => return Err(GatewayError::unsupported("unbound repository function")),
    };
    if let Parsed::Read(p) | Parsed::Hash(p) | Parsed::Absent(p) = &p {
        crate::paths::relative(p).map_err(err)?;
    }
    Ok(p)
}
impl Host {
    fn authority(&self, wire: &str) -> crate::Result {
        let canonical = route(wire).ok_or(Error::Invalid("repository route"))?.0;
        if !self.policy.enabled_tools.contains(wire) {
            return Err(Error::Denied("tool not enabled by host"));
        }
        let p = &self.policy.files;
        let t = self.store.journal().task(&p.task_id)?;
        if t.record.state != TaskState::Running
            || t.record.unknown_invocation_id.is_some()
            || t.contract.workspace_ref != p.resource_id
            || !t.contract.allowed_resource_ids.contains(&p.resource_id)
            || !t.contract.selected_profile_ids.contains(&p.profile_id)
            || !t.contract.authorization_refs.contains(&p.authorization_ref)
            || melissa_execution_broker::unix_ms().map_err(Error::Broker)? >= p.expires_at_ms
        {
            return Err(Error::Denied("repository tool task/host authority"));
        }
        let effect = if write_route(canonical) {
            "workspace.apply_patch_scoped"
        } else {
            "workspace.read"
        };
        if !t.contract.allowed_effects.iter().any(|e| e == effect)
            || (!write_route(canonical) && !self.policy.read_repository)
        {
            return Err(Error::Denied("repository tool effect scope"));
        }
        Ok(())
    }
    fn put(&mut self, id: &str, logical: &str, bytes: &[u8]) -> crate::Result {
        self.store.put_artifact(
            &ArtifactRequest {
                artifact_id: id.into(),
                task_id: self.policy.files.task_id.clone(),
                content_type: "application/json".into(),
                logical_type: logical.into(),
                schema_version: "melissa.repository-tool-evidence/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            bytes,
        )?;
        Ok(())
    }
    fn execute(
        &mut self,
        call: ToolCall,
        c: ToolContext,
        cancel: &AtomicBool,
    ) -> crate::Result<ToolExecution> {
        let canonical = route(&call.name)
            .ok_or(Error::Invalid("repository route"))?
            .0;
        self.authority(&call.name)?;
        if c.task_id != self.policy.files.task_id
            || c.profile_id != self.policy.files.profile_id
            || c.generation != 1
            || [&c.run_id, &c.request_id, &c.invocation_id, &c.attempt_id]
                .iter()
                .any(|s| {
                    s.is_empty()
                        || s.len() > 128
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
                })
        {
            return Err(Error::Denied("tool context differs from host binding"));
        }
        check_cancel(cancel)?;
        let parsed = parse(&call).map_err(|_| Error::Invalid("repository tool arguments"))?;
        let binding_id = format!("{}:tool-binding", c.invocation_id);
        self.put(&binding_id,"repository_tool_binding",&serde_json::to_vec(&json!({"task":c.task_id,"profile":c.profile_id,"run":c.run_id,"request":c.request_id,"invocation":c.invocation_id,"attempt":c.attempt_id,"generation":c.generation,"wire_call_id":call.id,"wire_name":call.name,"canonical_tool":canonical,"arguments_digest":digest(call.arguments.as_bytes()),"root_identity":self.repo.root_identity()}))?)?;
        let mut artifacts = vec![binding_id];
        let value = match parsed {
            Parsed::ReadPage(p) => {
                let (v, bytes) = self.repo.read(&p.before.path)?;
                if v != p.before {
                    return Err(Error::Stale("file page version"));
                }
                page(&bytes, p.offset, p.max_bytes, json!({"version":v}))?
            }
            Parsed::ArtifactPage(p) => {
                let metadata = self
                    .store
                    .artifact_metadata(&self.policy.files.task_id, &p.artifact_id)?;
                if metadata.logical_type != "repository_tool_result"
                    || metadata.schema_version != "melissa.repository-tool-evidence/v1"
                {
                    return Err(Error::Denied("artifact is not a repository tool result"));
                }
                let bytes = self
                    .store
                    .get_artifact(&self.policy.files.task_id, &p.artifact_id)?;
                if digest(&bytes) != p.digest {
                    return Err(Error::Stale("artifact page digest"));
                }
                page(
                    &bytes,
                    p.offset,
                    p.max_bytes,
                    json!({"artifact_id":p.artifact_id,"digest":p.digest}),
                )?
            }
            Parsed::Discover(p) => serde_json::to_value(self.repo.discover(&p, cancel)?)?,
            Parsed::Polyglot => {
                let s = self.repo.snapshot(cancel)?;
                serde_json::to_value(crate::polyglot::PolyglotIndex::build(
                    &self.repo, &s, cancel,
                )?)?
            }
            Parsed::Unified(p) => {
                let s = self.repo.snapshot(cancel)?;
                serde_json::to_value(self.repo.propose_unified_with_line_endings(
                    &s,
                    p.patch.as_bytes(),
                    p.line_endings,
                    cancel,
                )?)?
            }
            Parsed::Patch(p) => {
                let mut b =
                    PatchBroker::new(&self.repo, &mut self.store, self.policy.files.clone())?;
                let permit = b.authorize(&c.invocation_id, &c.attempt_id, p)?;
                let r = b.execute(permit, cancel)?;
                artifacts.push(format!("{}:receipt", c.invocation_id));
                artifacts.extend(r.files.iter().map(|f| f.preimage_artifact_id.clone()));
                serde_json::to_value(r)?
            }
            Parsed::Mutation(p) => {
                let mut b =
                    PatchBroker::new(&self.repo, &mut self.store, self.policy.files.clone())?;
                let permit = b.authorize_mutation(&c.invocation_id, &c.attempt_id, p)?;
                let r = b.execute_mutation(permit, cancel)?;
                artifacts.push(format!("{}:receipt", c.invocation_id));
                if let Some(id) = &r.preimage_artifact_id {
                    artifacts.push(id.clone());
                }
                serde_json::to_value(r)?
            }
            Parsed::Preview(p) => {
                p.validate(self.repo.limits())?;
                if p.root_identity != self.repo.root_identity() {
                    return Err(Error::Denied("preview root identity"));
                }
                let mut changes = vec![];
                for f in &p.files {
                    check_cancel(cancel)?;
                    let (version, before) = self.repo.read(&f.before.path)?;
                    if version != f.before {
                        return Err(Error::Stale("preview source changed"));
                    }
                    let after = crate::patch::apply_bytes(&before, f, self.repo.limits())?;
                    changes.push(json!({"before":version,"after_digest":digest(&after),"after_bytes":after.len(),"edits":f.edits}));
                }
                json!({"proposal":p,"changes":changes,"applied":false,"authorizes_write":false})
            }
            Parsed::Read(p) => {
                let (version, bytes) = self.repo.read(&p)?;
                json!({"version":version,"bytes":bytes,"encoding":"byte_array"})
            }
            Parsed::Hash(p) => {
                let (version, _) = self.repo.read(&p)?;
                serde_json::to_value(version)?
            }
            Parsed::Absent(p) => serde_json::to_value(self.repo.absent_path(&p)?)?,
            Parsed::Directory(p) => serde_json::to_value(self.repo.empty_directory_version(&p)?)?,
            Parsed::List => serde_json::to_value(self.repo.snapshot(cancel)?)?,
            Parsed::Search(bytes) => {
                let s = self.repo.snapshot(cancel)?;
                serde_json::to_value(self.repo.search(&s, &bytes, cancel)?)?
            }
            Parsed::Symbols => {
                let s = self.repo.snapshot(cancel)?;
                serde_json::to_value(SyntaxIndex::build(
                    &self.repo,
                    &s,
                    cancel,
                    Duration::from_secs(60),
                )?)?
            }
            Parsed::References(name) => {
                let s = self.repo.snapshot(cancel)?;
                let i = SyntaxIndex::build(&self.repo, &s, cancel, Duration::from_secs(60))?;
                json!({"resolution":"syntax_only_not_semantic_lsp","references":i.references(&self.repo,&s,&name,cancel)?,"snapshot_digest":s.digest})
            }
        };
        check_cancel(cancel).map_err(|e| {
            if write_route(canonical) {
                Error::AfterDispatch(Box::new(e))
            } else {
                e
            }
        })?;
        let content=json!({"schema_version":"melissa.repository-tool-result/v1","tool_id":canonical,"task_id":c.task_id,"invocation_id":c.invocation_id,"result":value,"task_accepted":false,"requires_reconciliation":false}).to_string();
        let max = self
            .store
            .journal()
            .task(&self.policy.files.task_id)?
            .contract
            .limits
            .max_output_bytes;
        if content.len() as u64 > max {
            return Err(if write_route(canonical) {
                Error::AfterDispatch(Box::new(Error::Quota("tool result bytes")))
            } else {
                Error::Quota("tool result bytes")
            });
        }
        let id = format!("{}:tool-result", c.invocation_id);
        // A write already has its durable broker receipt. Failure to deliver or
        // persist the gateway envelope is conservatively not retryable.
        if let Err(e) = self.put(&id, "repository_tool_result", content.as_bytes()) {
            return Err(if write_route(canonical) {
                Error::AfterDispatch(Box::new(e))
            } else {
                e
            });
        }
        artifacts.push(id);
        let content = if content.len() > 768 * 1024 {
            json!({"schema_version":"melissa.repository-paged-result/v1","delivery":"paged_result","artifact_id":artifacts.last(),"digest":digest(content.as_bytes()),"total_bytes":content.len(),"next_offset":0,"task_accepted":false,"complete":false}).to_string()
        } else {
            content
        };
        Ok(ToolExecution {
            content,
            success: true,
            cancelled: false,
            requires_reconciliation: false,
            artifact_refs: artifacts,
        })
    }
}
fn page(bytes: &[u8], offset: u64, max: u32, mut context: Value) -> crate::Result<Value> {
    if max == 0 || max > 64 * 1024 || offset > bytes.len() as u64 {
        return Err(Error::Invalid("page bounds"));
    }
    let start = offset as usize;
    let end = start.saturating_add(max as usize).min(bytes.len());
    context["bytes"] = json!(&bytes[start..end]);
    context["offset"] = json!(offset);
    context["total_bytes"] = json!(bytes.len());
    context["next_offset"] = if end < bytes.len() {
        json!(end)
    } else {
        Value::Null
    };
    context["complete"] = json!(end == bytes.len());
    context["encoding"] = json!("byte_array");
    Ok(context)
}
impl RepositoryDispatcher {
    /// Host-side withdrawal for subsequent calls and outstanding capabilities.
    /// In-flight cancellation uses the separately shared cancellation flag or
    /// the durable permit revocation journal; no model can invoke this method.
    pub fn revoke(&self) -> crate::Result {
        let mut h = self
            .host
            .lock()
            .map_err(|_| Error::Denied("repository host unavailable"))?;
        h.policy.files.epoch = h
            .policy
            .files
            .epoch
            .checked_add(1)
            .ok_or(Error::Denied("repository epoch exhausted"))?;
        h.policy.enabled_tools.clear();
        Ok(())
    }
    pub fn new(
        repo: Repository,
        store: LocalStore,
        policy: RepositoryToolPolicy,
    ) -> crate::Result<Self> {
        if policy.enabled_tools.is_empty()
            || policy
                .enabled_tools
                .iter()
                .any(|id| !ROUTES.iter().any(|r| r.0 == id))
        {
            return Err(Error::Invalid(
                "explicit supported repository routes required",
            ));
        }
        // Validate host identifiers and path sets through the shared broker.
        let mut store = store;
        if policy
            .enabled_tools
            .iter()
            .any(|wire| route(wire).is_some_and(|r| write_route(r.0)))
        {
            PatchBroker::new(&repo, &mut store, policy.files.clone())?;
        } else {
            for id in [
                &policy.files.task_id,
                &policy.files.principal_id,
                &policy.files.profile_id,
                &policy.files.resource_id,
                &policy.files.authorization_ref,
            ] {
                crate::broker::identifier(id)?;
            }
            for path in policy
                .files
                .writable_paths
                .iter()
                .chain(&policy.files.protected_paths)
            {
                repo.check_path(path)?;
            }
        }
        Ok(Self {
            host: Arc::new(Mutex::new(Host {
                repo,
                store,
                policy,
                read_error_observations: false,
                recovery_observations: false,
            })),
        })
    }

    /// CODE-09 opt-in: a stale pre-dispatch patch becomes a known failed
    /// observation. AfterDispatch, policy denials and storage faults stay closed.
    pub fn with_recovery_observations(self) -> crate::Result<Self> {
        self.host
            .lock()
            .map_err(|_| Error::Denied("repository host lock poisoned"))?
            .recovery_observations = true;
        Ok(self)
    }
    /// Host-only opt-in: known write-free read/input failures become failed
    /// observations so the existing agent loop may re-observe and correct its
    /// request. Policy denials, persistence faults, writes and Unknown stay
    /// fail-closed. Legacy callers retain the original Err behavior.
    pub fn with_read_error_observations(self) -> crate::Result<Self> {
        {
            let mut host = self
                .host
                .lock()
                .map_err(|_| Error::Denied("repository host lock poisoned"))?;
            host.read_error_observations = true;
        }
        Ok(self)
    }
}

fn known_read_input_error(error: &Error) -> bool {
    match error {
        Error::Invalid(_) | Error::Stale(_) | Error::Quota(_) | Error::Unsupported(_) => true,
        Error::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::AlreadyExists
                | std::io::ErrorKind::InvalidInput
        ),
        // Never turn authority, durable evidence, cancellation, dispatch or
        // unknown failures into ordinary model-visible retries.
        _ => false,
    }
}
impl ToolDispatcher for RepositoryDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        let Ok(h) = self.host.lock() else {
            return vec![];
        };
        ROUTES
            .iter()
            .filter(|r| h.authority(r.0).is_ok())
            .map(|r| BoundTool {
                canonical_id: r.1.into(),
                definition: ToolDefinition {
                    name: r.0.into(),
                    description: r.2.into(),
                    parameters: schema(r.0),
                    strict: false,
                },
            })
            .collect()
    }
    fn validate_call(&self, call: &ToolCall) -> melissa_model_gateway::Result<()> {
        let _id = route(&call.name)
            .ok_or_else(|| GatewayError::unsupported("unbound repository route"))?
            .0;
        self.host
            .lock()
            .map_err(|_| GatewayError::new(ErrorKind::Tool, "repository host unavailable"))?
            .authority(&call.name)
            .map_err(err)?;
        parse(call).map(|_| ())
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        let host = self.host.clone();
        let recover_stale = self.host.lock().is_ok_and(|h| h.recovery_observations);
        let recover_read = self.host.lock().is_ok_and(|h| h.read_error_observations)
            && route(&call.name).is_some_and(|(id, _)| !write_route(id));
        Box::pin(async move {
            let joined = tokio::task::spawn_blocking(move || {
                host.lock()
                    .map_err(|_| Error::Denied("repository host lock poisoned"))?
                    .execute(call, context, &cancelled)
            })
            .await;
            match joined {
                Ok(Ok(r))=>Ok(r),
                Ok(Err(Error::AfterDispatch(_)))|Err(_)=>Ok(ToolExecution{content:json!({"status":"outcome_unknown","requires_reconciliation":true,"automatic_retry_allowed":false,"task_accepted":false}).to_string(),success:false,cancelled:false,requires_reconciliation:true,artifact_refs:vec![]}),
                Ok(Err(Error::Cancelled))=>Ok(ToolExecution{content:json!({"status":"cancelled_before_effect","task_accepted":false}).to_string(),success:false,cancelled:true,requires_reconciliation:false,artifact_refs:vec![]}),
                Ok(Err(e @ Error::Stale(_))) if recover_stale=>Ok(ToolExecution{content:json!({"status":"stale_patch_rejected","message":e.to_string(),"workspace_write_dispatched":false,"requires_reconciliation":false,"task_accepted":false}).to_string(),success:false,cancelled:false,requires_reconciliation:false,artifact_refs:vec![]}),
                Ok(Err(e)) if recover_read && known_read_input_error(&e)=>Ok(ToolExecution{content:json!({"status":"read_input_rejected","message":e.to_string(),"workspace_write_dispatched":false,"requires_reconciliation":false,"remediation":"Re-observe existing parents and exact current file versions. Create a parent only with an existing explicit write grant; use exact source bytes and line endings for a new proposal. Do not invent identities or change authorization.","task_accepted":false}).to_string(),success:false,cancelled:false,requires_reconciliation:false,artifact_refs:vec![]}),
                Ok(Err(e))=>Err(err(e)),
            }
        })
    }
}

fn object(props: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":props,"required":required,"additionalProperties":false})
}
fn schema(id: &str) -> Value {
    let path = json!({"type":"string","minLength":1,"maxLength":2048});
    let version = object(
        json!({"path":path,"identity":{"type":"string"},"digest":{"type":"string"},"bytes":{"type":"integer","minimum":0}}),
        &["path", "identity", "digest", "bytes"],
    );
    let dest = object(
        json!({"path":path,"parent_identity":{"type":"string"}}),
        &["path", "parent_identity"],
    );
    let bytes = json!({"type":"array","items":{"type":"integer","minimum":0,"maximum":255}});
    match id {
        "fs_read_page" => object(
            json!({"before":version,"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":65536}}),
            &["before", "offset", "max_bytes"],
        ),
        "fs_artifact_page" => object(
            json!({"artifact_id":{"type":"string"},"digest":{"type":"string"},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":65536}}),
            &["artifact_id", "digest", "offset", "max_bytes"],
        ),
        "fs_discover" => object(
            json!({"include_globs":{"type":"array","items":{"type":"string"}},"generated_globs":{"type":"array","items":{"type":"string"}},"respect_ignore":{"type":"boolean"}}),
            &["include_globs", "generated_globs", "respect_ignore"],
        ),
        "code_unified_propose" => object(
            json!({"patch":{"type":"string"},"line_endings":{"type":"string","enum":["exact","preserve_source"]}}),
            &["patch"],
        ),
        "fs_read" | "fs_hash" | "fs_absent" | "fs_directory" => {
            object(json!({"path":path}), &["path"])
        }
        "fs_mkdir" | "fs_rmdir" | "fs_movedir" => {
            let op = match id {
                "fs_mkdir" => object(
                    json!({"operation":{"const":"create_directory"},"destination":dest}),
                    &["operation", "destination"],
                ),
                "fs_rmdir" => object(
                    json!({"operation":{"const":"delete_directory"},"before":version}),
                    &["operation", "before"],
                ),
                _ => object(
                    json!({"operation":{"const":"move_directory"},"before":version,"destination":dest}),
                    &["operation", "before", "destination"],
                ),
            };
            object(
                json!({"schema_version":{"const":"melissa.repository-mutation/v2"},"root_identity":{"type":"string"},"mutation":op}),
                &["schema_version", "root_identity", "mutation"],
            )
        }
        "fs_search" => object(json!({"bytes":bytes}), &["bytes"]),
        "code_references" => object(
            json!({"name":{"type":"string","minLength":1,"maxLength":1024}}),
            &["name"],
        ),
        "fs_patch" | "fs_diff" | "code_patch_propose" => {
            let edit = object(
                json!({"start":{"type":"integer","minimum":0},"end":{"type":"integer","minimum":0},"expected":bytes,"replacement":bytes}),
                &["start", "end", "expected", "replacement"],
            );
            object(
                json!({"schema_version":{"const":"melissa.repository-patch/v1"},"root_identity":{"type":"string"},"files":{"type":"array","minItems":1,"items":object(json!({"before":version,"edits":{"type":"array","minItems":1,"items":edit}}),&["before","edits"])}}),
                &["schema_version", "root_identity", "files"],
            )
        }
        "fs_create" | "fs_delete" | "fs_move" => {
            let mutation = match id {
                "fs_create" => object(
                    json!({"operation":{"const":"create"},"destination":dest,"bytes":bytes}),
                    &["operation", "destination", "bytes"],
                ),
                "fs_delete" => object(
                    json!({"operation":{"const":"delete"},"before":version}),
                    &["operation", "before"],
                ),
                _ => object(
                    json!({"operation":{"const":"move"},"before":version,"destination":dest}),
                    &["operation", "before", "destination"],
                ),
            };
            object(
                json!({"schema_version":{"const":"melissa.repository-mutation/v1"},"root_identity":{"type":"string"},"mutation":mutation}),
                &["schema_version", "root_identity", "mutation"],
            )
        }
        _ => object(json!({}), &[]),
    }
}

/// Routes repository, process and reviewed adapters through the same Gateway
/// loop. Duplicate function names fail closed; execution never falls back/retries.
pub struct ToolRouter {
    children: Vec<Box<dyn ToolDispatcher>>,
    routes: BTreeMap<String, usize>,
}
impl ToolRouter {
    pub fn new(children: Vec<Box<dyn ToolDispatcher>>) -> melissa_model_gateway::Result<Self> {
        let mut routes = BTreeMap::new();
        for (i, child) in children.iter().enumerate() {
            for t in child.definitions() {
                if routes.insert(t.definition.name, i).is_some() {
                    return Err(GatewayError::invalid("duplicate tool route"));
                }
            }
        }
        Ok(Self { children, routes })
    }
}
impl ToolDispatcher for ToolRouter {
    fn definitions(&self) -> Vec<BoundTool> {
        self.children
            .iter()
            .flat_map(|c| c.definitions())
            .filter(|t| self.routes.contains_key(&t.definition.name))
            .collect()
    }
    fn validate_call(&self, c: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.children[*self
            .routes
            .get(&c.name)
            .ok_or_else(|| GatewayError::unsupported("unbound router function"))?]
        .validate_call(c)
    }
    fn execute<'a>(
        &'a mut self,
        c: ToolCall,
        ctx: ToolContext,
        cancel: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        let Some(&i) = self.routes.get(&c.name) else {
            return Box::pin(async { Err(GatewayError::unsupported("unbound router function")) });
        };
        self.children[i].execute(c, ctx, cancel)
    }
}

#[cfg(all(test, windows))]
#[path = "tool_tests.rs"]
mod tests;
