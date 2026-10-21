//! Optional native web progress adapter. UI/API state may change while source
//! stays identical. Exact same observed state still participates in loop stops.
use melissa_local_store::LocalStore;
use melissa_model_gateway::{
    ErrorKind, GatewayError, Result, ToolCall,
    recovery::{FailureKind, RecoveryDirective, RecoveryEvent, RecoveryHook},
    strict_json,
    tools::ToolExecution,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
pub struct WebProgress {
    inner: Box<dyn RecoveryHook>,
    wires: BTreeSet<String>,
}
fn semantic(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("events");
            map.remove("trace_hex");
            if let Some(artifact) = map
                .get_mut("binary_artifact")
                .and_then(Value::as_object_mut)
            {
                if artifact.get("kind").and_then(Value::as_str) == Some("trace") {
                    map.remove("binary_artifact");
                } else {
                    artifact.remove("id");
                }
            }
            if let Some(headers) = map.get_mut("headers").and_then(Value::as_object_mut) {
                headers.retain(|k, _| {
                    !matches!(
                        k.to_ascii_lowercase().as_str(),
                        "date" | "server" | "connection"
                    )
                });
            }
            for v in map.values_mut() {
                semantic(v);
            }
        }
        Value::Array(a) => {
            for v in a {
                semantic(v);
            }
        }
        _ => (),
    }
}
impl WebProgress {
    pub fn new(inner: Box<dyn RecoveryHook>, wires: BTreeSet<String>) -> Result<Self> {
        if wires.is_empty()
            || wires.len() > 8
            || wires
                .iter()
                .any(|w| !melissa_model_gateway::valid_tool_name(w))
        {
            return Err(GatewayError::invalid("web progress host wires"));
        }
        Ok(Self { inner, wires })
    }
}
impl RecoveryHook for WebProgress {
    fn binding_digest(&self, store: &LocalStore) -> Result<String> {
        Ok(crate::digest(&serde_json::to_vec(&json!({"inner":self.inner.binding_digest(store)?,"web_progress":"native-semantic-observation/v2","wires":self.wires})).map_err(|_|GatewayError::invalid("web progress binding"))?))
    }
    fn failure(
        &mut self,
        store: &mut LocalStore,
        event: RecoveryEvent,
    ) -> Result<RecoveryDirective> {
        self.inner.failure(store, event)
    }
    fn classify_observation(&self, call: &ToolCall, observation: &ToolExecution) -> FailureKind {
        self.inner.classify_observation(call, observation)
    }
    fn success(
        &mut self,
        store: &mut LocalStore,
        mut event: RecoveryEvent,
    ) -> Result<Option<RecoveryDirective>> {
        if event.calls.iter().any(|c| self.wires.contains(&c.name)) {
            let mut observed = None;
            for id in event.evidence.iter().rev() {
                let meta = store.artifact_metadata(&event.task, id).map_err(|_| {
                    GatewayError::new(ErrorKind::Store, "web progress task artifact")
                })?;
                if meta.logical_type != "web.reply" {
                    continue;
                }
                let bytes = store.get_artifact(&event.task, id).map_err(|_| {
                    GatewayError::new(ErrorKind::Store, "web progress native reply")
                })?;
                let reply: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| GatewayError::invalid("web progress native JSON"))?;
                let mut state =
                    json!({"ok":reply["ok"],"body":reply["body"],"closed":reply["closed"]});
                semantic(&mut state);
                observed = Some(crate::digest(
                    &serde_json::to_vec(&state)
                        .map_err(|_| GatewayError::invalid("web state encoding"))?,
                ));
                break;
            }
            let observed = observed.ok_or_else(|| {
                GatewayError::new(ErrorKind::Store, "web progress lacks native observation")
            })?;
            for call in &mut event.calls {
                if !self.wires.contains(&call.name) {
                    continue;
                }
                let args = strict_json(&call.arguments)?;
                let operation = match args["operation_json"].as_str() {
                    Some(raw) => strict_json(raw)?,
                    None => args["operation"].clone(),
                };
                // Fingerprint input only; the original model call/proposal is
                // unchanged in Gateway/native receipts and is never dispatched.
                call.arguments=json!({"session_id":args["session_id"],"operation":operation,"native_observed_state_digest":observed}).to_string();
            }
        }
        self.inner.success(store, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_ids_and_traces_do_not_fake_progress_but_image_content_does() {
        let image =
            |id, sha| json!({"binary_artifact":{"id":id,"kind":"png","bytes":600000,"sha256":sha}});
        let mut first = image("a1", "same");
        let mut repeat = image("a2", "same");
        let mut changed = image("a3", "different");
        semantic(&mut first);
        semantic(&mut repeat);
        semantic(&mut changed);
        assert_eq!(first, repeat);
        assert_ne!(first, changed);
        let mut close = json!({"closed":true,"binary_artifact":{"id":"a4","kind":"trace","bytes":1000000,"sha256":"random-timestamps"}});
        semantic(&mut close);
        assert_eq!(close, json!({"closed":true}));
    }
}
