//! Opt-in durable turn boundary. Default Gateway::run has no persistence hook.
//! Native provider messages remain lossless; pending inference/tools never replay.
use crate::{Message, Result, agent_loop::RunResult};
use melissa_local_store::LocalStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Safe,
    InferencePending,
    ToolsPending,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCheckpoint {
    pub schema_version: String,
    pub binding_digest: String,
    pub phase: Phase,
    pub next_turn: u32,
    pub messages: Vec<Message>,
    pub seen_calls: BTreeSet<String>,
    pub successful: BTreeSet<String>,
    pub selected_model: Option<usize>,
    pub result: RunResult,
}
/// The implementing trusted host owns source/policy freshness, encrypted
/// artifact/checkpoint publication and current budget/Unknown/cancel checks.
pub trait ContinuationStore: Send {
    fn begin(
        &mut self,
        store: &mut LocalStore,
        binding: &str,
        task: &str,
        run: &str,
    ) -> Result<Option<TurnCheckpoint>>;
    fn publish(&mut self, store: &mut LocalStore, state: &TurnCheckpoint) -> Result<()>;
}
