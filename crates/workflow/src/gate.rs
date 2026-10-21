//! The node gate rejects every tool not present in the exact host-validated
//! handoff. Inner backends retain their ordinary permit/path enforcement.
use crate::plan::{Access, path};
use crate::{
    Kind, Result, error, require,
    scheduler::{Scheduler, WorkPacket},
};
use melissa_model_gateway::{
    ErrorKind, GatewayError, ToolCall,
    tools::{BoundTool, ToolContext, ToolDispatcher, ToolExecution},
};
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

pub type SharedScheduler = Arc<Mutex<Scheduler>>;
pub(crate) fn lock(s: &SharedScheduler) -> Result<std::sync::MutexGuard<'_, Scheduler>> {
    s.lock()
        .map_err(|_| error(Kind::Store, "workflow owner lock poisoned"))
}
fn gateway(e: crate::Error) -> GatewayError {
    GatewayError::new(ErrorKind::Authorization, e.to_string())
}
fn effects(canonical: &str) -> Option<&'static [&'static str]> {
    Some(match canonical {
        "fs.read" | "fs.search" | "fs.hash" | "fs.snapshot" | "fs.diff" | "code.symbols"
        | "code.references" => &["workspace.read"],
        "code.patch_propose" => &["workspace.read", "workspace.propose_patch"],
        "fs.patch" => &["workspace.apply_patch_scoped"],
        "git.status" | "git.diff" => &["git.read"],
        "git.worktree" => &[
            "workspace.create_worktree_scoped",
            "workspace.apply_patch_scoped",
        ],
        "process.exec" | "code.build" | "code.tests" | "code.lint" | "code.diagnostics" => {
            &["process.execute_scoped", "workspace.apply_patch_scoped"]
        }
        "artifact.read" => &["artifact.read"],
        "evidence.attach" => &["evidence.append"],
        "memory.search" => &["workspace.read"],
        "memory.propose" => &["memory.propose"],
        _ => return None,
    })
}
pub struct NodeDispatcher {
    pub(crate) scheduler: SharedScheduler,
    packet: WorkPacket,
    inner: Box<dyn ToolDispatcher>,
}
impl NodeDispatcher {
    pub fn new(
        scheduler: SharedScheduler,
        packet: WorkPacket,
        inner: Box<dyn ToolDispatcher>,
    ) -> Result<Self> {
        lock(&scheduler)?.check(&packet.lease)?;
        let mut names = BTreeSet::new();
        for d in inner.definitions() {
            require(
                packet.node.tools.contains(&d.canonical_id) && names.insert(d.definition.name),
                Kind::Authority,
                "dispatcher exposes a tool outside exact node grant",
            )?;
            let needed = effects(&d.canonical_id).ok_or_else(|| {
                error(
                    Kind::Authority,
                    "no reviewed workflow effect binding for tool",
                )
            })?;
            require(
                needed
                    .iter()
                    .all(|e| packet.node.effects.iter().any(|v| v == e)),
                Kind::Authority,
                "tool effects exceed attenuated node authority",
            )?;
        }
        Ok(Self {
            scheduler,
            packet,
            inner,
        })
    }
    fn check(&self) -> Result<()> {
        lock(&self.scheduler)?.check(&self.packet.lease)
    }
    fn scope(&self, call: &ToolCall) -> Result<()> {
        let def = self
            .inner
            .definitions()
            .into_iter()
            .find(|d| d.definition.name == call.name)
            .ok_or_else(|| error(Kind::Authority, "wire tool not bound"))?;
        let args = melissa_model_gateway::strict_json(&call.arguments)?;
        if def.canonical_id == "process.exec" && call.name == "process_exec" {
            let remaining = self
                .packet
                .lease
                .expires_at_ms
                .saturating_sub(crate::now()?);
            require(
                args["limits"]["wall_time_ms"]
                    .as_u64()
                    .is_some_and(|v| v > 0 && v <= remaining),
                Kind::Authority,
                "native process duration exceeds remaining node lease",
            )?;
        }
        let covers = |target: &str, write: bool| -> bool {
            path(target)
                && self.packet.node.claims.iter().any(|c| {
                    c.resource == self.packet.parent_task.workspace_ref
                        && (!write || c.access == Access::Write)
                        && {
                            let p = c.path.to_uppercase();
                            let t = target.to_uppercase();
                            p == "/"
                                || p == t
                                || t.strip_prefix(&p).is_some_and(|s| s.starts_with('/'))
                        }
                })
        };
        if def.canonical_id == "fs.patch" {
            let mut paths = vec![];
            match call.name.as_str() {
                "fs_patch" => {
                    for f in args["files"]
                        .as_array()
                        .ok_or_else(|| error(Kind::Invalid, "missing patch files"))?
                    {
                        paths.push(
                            f["before"]["path"]
                                .as_str()
                                .ok_or_else(|| error(Kind::Invalid, "patch target missing"))?,
                        );
                    }
                }
                "fs_create" | "fs_delete" | "fs_move" | "fs_mkdir" | "fs_rmdir" | "fs_movedir" => {
                    for key in ["before", "destination"] {
                        if let Some(p) = args["mutation"][key]["path"].as_str() {
                            paths.push(p);
                        }
                    }
                }
                _ => {
                    return Err(error(
                        Kind::Authority,
                        "mutation wire format has no reviewed ownership binding",
                    ));
                }
            }
            require(
                !paths.is_empty() && paths.iter().all(|p| covers(p, true)),
                Kind::Authority,
                "mutation target outside node write ownership",
            )?;
        } else if matches!(
            call.name.as_str(),
            "fs_read" | "fs_hash" | "fs_absent" | "fs_directory" | "fs_read_page"
        ) {
            let p = args["path"]
                .as_str()
                .or_else(|| args["before"]["path"].as_str())
                .ok_or_else(|| error(Kind::Invalid, "read path missing"))?;
            require(
                covers(p, false),
                Kind::Authority,
                "read target outside node ownership",
            )?;
        } else if !matches!(
            def.canonical_id.as_str(),
            "artifact.read" | "evidence.attach" | "memory.search" | "memory.propose"
        ) {
            // Search/index/process/helper adapters can observe a whole captured
            // repository. Require a whole-workspace lock unless an exact-path
            // binding is explicitly implemented above. Inner grants still apply.
            require(
                covers("/", def.canonical_id == "git.worktree"),
                Kind::Authority,
                "repository-wide adapter requires whole-workspace ownership",
            )?;
        }
        Ok(())
    }
}
impl ToolDispatcher for NodeDispatcher {
    fn definitions(&self) -> Vec<BoundTool> {
        self.inner.definitions()
    }
    fn validate_call(&self, call: &ToolCall) -> melissa_model_gateway::Result<()> {
        self.check().map_err(gateway)?;
        self.scope(call).map_err(gateway)?;
        self.inner.validate_call(call)
    }
    fn execute<'a>(
        &'a mut self,
        call: ToolCall,
        context: ToolContext,
        cancelled: Arc<AtomicBool>,
    ) -> Pin<Box<dyn Future<Output = melissa_model_gateway::Result<ToolExecution>> + Send + 'a>>
    {
        Box::pin(async move {
            self.check().map_err(gateway)?;
            self.scope(&call).map_err(gateway)?;
            require(
                context.task_id == self.packet.parent_task.task_id
                    && context.profile_id == self.packet.node.profile
                    && context.run_id == self.packet.lease.run,
                Kind::Authority,
                "tool context differs from leased node",
            )
            .map_err(gateway)?;
            self.inner.execute(call, context, cancelled).await
        })
    }
}
