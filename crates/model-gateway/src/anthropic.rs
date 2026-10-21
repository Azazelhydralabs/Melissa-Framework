//! Claude Messages wire adapter. A complete terminal message is the only place
//! where client tool requests become available to the caller.
//!
//! Thinking and redacted blocks are retained solely in the provider-owned
//! continuation. They are never appended to normalized text or error messages.

use crate::{
    DecoderLimits, ErrorKind, GatewayError, Message, ModelResponse, Protocol, RequestLimits,
    Result, SseEvent, StopReason, ToolCall, TurnRequest, Usage, strict_json, valid_tool_name,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn build_request(request: &TurnRequest) -> Result<Value> {
    build_request_with_limits(request, RequestLimits::default())
}
pub fn build_request_with_limits(request: &TurnRequest, limits: RequestLimits) -> Result<Value> {
    request.validate_with_limits(limits)?;
    if request.model.is_empty() || request.max_output_tokens == 0 {
        return Err(GatewayError::invalid(
            "invalid Claude model or output limit",
        ));
    }
    let mut messages = Vec::new();
    let mut pending = BTreeSet::new();
    let mut results = Vec::new();
    for message in &request.messages {
        match message {
            Message::UserImages { text, images } => {
                flush_results(&mut messages, &mut results, &pending)?;
                let mut parts = vec![json!({"type":"text","text":text})];
                parts.extend(images.iter().map(|i| json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":i.base64()}})));
                messages.push(json!({"role":"user","content":parts}));
            }
            Message::ToolImages {
                call_id,
                content,
                is_error,
                images,
            } => {
                if !pending.remove(call_id) {
                    return Err(GatewayError::invalid("unmatched image tool result"));
                }
                let mut parts = vec![json!({"type":"text","text":content})];
                parts.extend(images.iter().map(|i| json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":i.base64()}})));
                results.push(json!({"type":"tool_result","tool_use_id":call_id,"content":parts,"is_error":is_error}));
            }
            Message::ToolResult {
                call_id,
                content,
                is_error,
            } => {
                if !pending.remove(call_id) {
                    return Err(GatewayError::invalid(
                        "Claude tool result has no unique pending client call",
                    ));
                }
                results.push(json!({
                    "type": "tool_result", "tool_use_id": call_id,
                    "content": content, "is_error": is_error,
                }));
            }
            Message::User { text } => {
                flush_results(&mut messages, &mut results, &pending)?;
                messages.push(json!({"role":"user", "content":text}));
            }
            Message::Assistant { response } => {
                flush_results(&mut messages, &mut results, &pending)?;
                if response.protocol != Protocol::AnthropicMessages {
                    return Err(GatewayError::unsupported(
                        "Claude history requires its own provider continuation",
                    ));
                }
                if response.requested_model != request.model {
                    return Err(GatewayError::unsupported(
                        "Claude continuation cannot silently change configured model",
                    ));
                }
                if !matches!(response.stop, StopReason::EndTurn | StopReason::ToolCalls)
                    || response.continuation.is_empty()
                {
                    return Err(GatewayError::invalid(
                        "incomplete or refused Claude response cannot be replayed",
                    ));
                }
                validate_continuation(response)?;
                if response.stop == StopReason::ToolCalls {
                    for call in &response.calls {
                        if !pending.insert(call.id.clone()) {
                            return Err(GatewayError::invalid("duplicate Claude client call ID"));
                        }
                    }
                } else if !response.calls.is_empty() {
                    return Err(GatewayError::invalid(
                        "Claude non-tool terminal cannot carry executable calls",
                    ));
                }
                messages.push(json!({"role":"assistant", "content":response.continuation}));
            }
        }
    }
    flush_results(&mut messages, &mut results, &pending)?;
    if messages.is_empty() {
        return Err(GatewayError::invalid(
            "Claude request requires message history",
        ));
    }
    let mut body = json!({
        "model":request.model, "max_tokens":request.max_output_tokens,
        "stream":true, "messages":messages,
    });
    if !request.system_prompt.is_empty() {
        body["system"] = Value::String(request.system_prompt.clone());
    }
    if !request.tools.is_empty() {
        let mut names = BTreeSet::new();
        let mut strict_count = 0usize;
        let mut tools = Vec::new();
        for tool in &request.tools {
            if tool.name.is_empty() || !names.insert(&tool.name) || !tool.parameters.is_object() {
                return Err(GatewayError::invalid(
                    "invalid or duplicate Claude client tool",
                ));
            }
            strict_count += usize::from(tool.strict);
            tools.push(json!({
                "name":tool.name, "description":tool.description,
                "input_schema":tool.parameters, "strict":tool.strict,
            }));
        }
        if strict_count > 20 {
            return Err(GatewayError::unsupported(
                "Claude strict tool count exceeds 20",
            ));
        }
        body["tools"] = Value::Array(tools);
    }
    if let Some(schema) = &request.output_schema {
        if !schema.is_object() {
            return Err(GatewayError::invalid(
                "Claude output schema must be an object",
            ));
        }
        body["output_config"] = json!({"format":{"type":"json_schema", "schema":schema}});
    }
    Ok(body)
}

fn flush_results(
    messages: &mut Vec<Value>,
    results: &mut Vec<Value>,
    pending: &BTreeSet<String>,
) -> Result<()> {
    if !pending.is_empty() {
        return Err(GatewayError::invalid(
            "Claude client call results are incomplete",
        ));
    }
    if !results.is_empty() {
        messages.push(json!({"role":"user", "content":std::mem::take(results)}));
    }
    Ok(())
}

fn validate_continuation(response: &ModelResponse) -> Result<()> {
    // Only replayable end-turn/tool-call responses reach this function. The
    // decoder assigns refusal metadata solely to non-replayable refusal stops.
    if response.refusal.is_some() {
        return Err(GatewayError::invalid(
            "Claude continuation contradicts normalized refusal",
        ));
    }
    // Compare exact UTF-8 concatenation without allocating a second large text
    // buffer. Thinking, signatures and redacted blocks remain opaque.
    let mut remaining_text = response.text.as_str();
    let mut calls = Vec::new();
    for block in &response.continuation {
        match string(block, "type")? {
            "text" => {
                remaining_text = remaining_text
                    .strip_prefix(string(block, "text")?)
                    .ok_or_else(|| {
                        GatewayError::invalid("Claude continuation disagrees with normalized text")
                    })?;
            }
            "thinking" => {
                string(block, "thinking")?;
                if string(block, "signature")?.is_empty() {
                    return Err(GatewayError::invalid(
                        "Claude thinking signature is missing",
                    ));
                }
            }
            "redacted_thinking" => {
                string(block, "data")?;
            }
            "tool_use" => {
                validate_client_origin(block)?;
                if !block.get("input").is_some_and(Value::is_object) {
                    return Err(GatewayError::invalid(
                        "Claude continuation tool input is not an object",
                    ));
                }
                calls.push((
                    string(block, "id")?,
                    string(block, "name")?,
                    &block["input"],
                ));
            }
            _ => {
                return Err(GatewayError::unsupported(
                    "unsupported Claude continuation block",
                ));
            }
        }
    }
    if !remaining_text.is_empty() {
        return Err(GatewayError::invalid(
            "Claude continuation disagrees with normalized text",
        ));
    }
    if response.stop != StopReason::ToolCalls {
        if !calls.is_empty() {
            return Err(GatewayError::invalid(
                "incomplete Claude tool blocks cannot be replayed",
            ));
        }
        return Ok(());
    }
    if calls.is_empty() || calls.len() != response.calls.len() {
        return Err(GatewayError::invalid(
            "Claude continuation client call mismatch",
        ));
    }
    for ((id, name, input), call) in calls.into_iter().zip(&response.calls) {
        let arguments = strict_json(&call.arguments)
            .map_err(|_| GatewayError::invalid("Claude continuation arguments are invalid JSON"))?;
        if id != call.id || name != call.name || *input != arguments {
            return Err(GatewayError::invalid(
                "Claude continuation client call mismatch",
            ));
        }
    }
    Ok(())
}

struct ActiveBlock {
    index: usize,
    raw: Value,
    input_json: String,
    saw_input_delta: bool,
    saw_signature: bool,
}

pub struct AnthropicDecoder {
    requested_model: String,
    limits: DecoderLimits,
    total_bytes: usize,
    output_bytes: usize,
    model: Option<String>,
    response_id: Option<String>,
    blocks: Vec<Value>,
    active: Option<ActiveBlock>,
    stop: Option<String>,
    finalizing: bool,
    terminal: bool,
    failed: bool,
    usage: Usage,
    output_final_known: bool,
}

impl AnthropicDecoder {
    pub fn new(requested_model: &str, limits: DecoderLimits) -> Self {
        Self {
            requested_model: requested_model.into(),
            limits,
            total_bytes: 0,
            output_bytes: 0,
            model: None,
            response_id: None,
            blocks: Vec::new(),
            active: None,
            stop: None,
            finalizing: false,
            terminal: false,
            failed: false,
            usage: Usage::default(),
            output_final_known: false,
        }
    }

    pub fn push(&mut self, event: &SseEvent) -> Result<()> {
        if self.failed {
            return Err(GatewayError::protocol(
                "Claude decoder is permanently failed",
            ));
        }
        let result = self.push_inner(event);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn push_inner(&mut self, event: &SseEvent) -> Result<()> {
        if self.terminal {
            return Err(GatewayError::protocol(
                "Claude event after terminal message",
            ));
        }
        let bytes = event
            .data
            .len()
            .checked_add(event.event.as_ref().map_or(0, String::len))
            .ok_or_else(|| GatewayError::protocol("Claude event size overflow"))?;
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| GatewayError::protocol("Claude stream size overflow"))?;
        if bytes > self.limits.max_event_bytes || self.total_bytes > self.limits.max_total_bytes {
            return Err(GatewayError::protocol("Claude stream byte limit exceeded"));
        }
        let value = strict_json(&event.data)
            .map_err(|_| GatewayError::protocol("invalid Claude event JSON"))?;
        let kind = string(&value, "type")?;
        if event.event.as_deref() != Some(kind) {
            return Err(GatewayError::protocol("Claude SSE event type mismatch"));
        }
        match kind {
            "ping" => Ok(()),
            "error" => {
                let kind = match string(&value["error"], "type")? {
                    "authentication_error" | "permission_error" => ErrorKind::Authentication,
                    "rate_limit_error" => ErrorKind::RateLimited,
                    "overloaded_error" | "api_error" => ErrorKind::ProviderUnavailable,
                    "timeout_error" => ErrorKind::Timeout,
                    "invalid_request_error" | "request_too_large" => ErrorKind::Invalid,
                    _ => ErrorKind::Protocol,
                };
                Err(GatewayError::new(kind, "Claude upstream streaming error"))
            }
            "message_start" => self.message_start(&value),
            "content_block_start" => self.block_start(&value),
            "content_block_delta" => self.block_delta(&value),
            "content_block_stop" => self.block_stop(&value),
            "message_delta" => self.message_delta(&value),
            "message_stop" => {
                if self.response_id.is_none()
                    || self.active.is_some()
                    || !self.finalizing
                    || self.stop.is_none()
                {
                    return Err(GatewayError::protocol(
                        "Claude terminal before complete message",
                    ));
                }
                self.terminal = true;
                Ok(())
            }
            // The provider documents additive unknown event types. They cannot
            // open/modify/complete a known block or authorize a tool request.
            _ => Ok(()),
        }
    }

    fn message_start(&mut self, event: &Value) -> Result<()> {
        if self.response_id.is_some() {
            return Err(GatewayError::protocol("duplicate Claude message start"));
        }
        let message = &event["message"];
        if string(message, "type")? != "message"
            || string(message, "role")? != "assistant"
            || !message
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !message.get("stop_reason").is_some_and(Value::is_null)
        {
            return Err(GatewayError::protocol("invalid Claude initial message"));
        }
        let id = bounded_identity(message, "id")?;
        let model = bounded_identity(message, "model")?;
        self.response_id = Some(id.into());
        self.model = Some(model.into());
        if let Some(usage) = message.get("usage") {
            self.update_usage(usage)?;
        }
        Ok(())
    }

    fn block_start(&mut self, event: &Value) -> Result<()> {
        if self.response_id.is_none() || self.active.is_some() || self.finalizing {
            return Err(GatewayError::protocol(
                "Claude content start outside open message",
            ));
        }
        let index = index(event)?;
        if index != self.blocks.len() || index >= self.limits.max_items {
            return Err(GatewayError::protocol(
                "Claude content block index is invalid",
            ));
        }
        let raw = event
            .get("content_block")
            .filter(|value| value.is_object())
            .ok_or_else(|| GatewayError::protocol("Claude content block is missing"))?
            .clone();
        let kind = string(&raw, "type")?;
        let mut saw_signature = false;
        match kind {
            "text" => self.add_output_bytes(string(&raw, "text")?.len())?,
            "thinking" => {
                self.add_output_bytes(string(&raw, "thinking")?.len())?;
                self.add_output_bytes(string(&raw, "signature")?.len())?;
                saw_signature = !string(&raw, "signature")?.is_empty();
            }
            "redacted_thinking" => self.add_output_bytes(string(&raw, "data")?.len())?,
            "tool_use" => {
                validate_client_origin(&raw)?;
                bounded_identity(&raw, "id")?;
                if !valid_tool_name(bounded_identity(&raw, "name")?) {
                    return Err(GatewayError::protocol(
                        "invalid Claude client tool wire name",
                    ));
                }
                if !raw.get("input").is_some_and(Value::is_object) {
                    return Err(GatewayError::protocol(
                        "Claude client input must be an object",
                    ));
                }
                let count = self
                    .blocks
                    .iter()
                    .filter(|block| block["type"] == "tool_use")
                    .count();
                if count >= self.limits.max_tool_calls {
                    return Err(GatewayError::protocol("Claude client call count exceeded"));
                }
                let id = string(&raw, "id")?;
                if self
                    .blocks
                    .iter()
                    .any(|block| block["type"] == "tool_use" && block["id"] == id)
                {
                    return Err(GatewayError::protocol("duplicate Claude client call ID"));
                }
                let input_bytes = serde_json::to_vec(&raw["input"])
                    .map_err(|_| GatewayError::protocol("invalid Claude input"))?
                    .len();
                if input_bytes > self.limits.max_argument_bytes {
                    return Err(GatewayError::protocol(
                        "Claude client input byte limit exceeded",
                    ));
                }
                self.add_output_bytes(input_bytes)?;
            }
            _ => {
                return Err(GatewayError::unsupported(
                    "unsupported Claude content block; hosted tools are disabled",
                ));
            }
        }
        self.active = Some(ActiveBlock {
            index,
            raw,
            input_json: String::new(),
            saw_input_delta: false,
            saw_signature,
        });
        Ok(())
    }

    fn block_delta(&mut self, event: &Value) -> Result<()> {
        let expected_index = index(event)?;
        let delta = &event["delta"];
        let kind = string(delta, "type")?;
        let delta_text = match kind {
            "text_delta" => string(delta, "text")?,
            "input_json_delta" => string(delta, "partial_json")?,
            "thinking_delta" => string(delta, "thinking")?,
            "signature_delta" => string(delta, "signature")?,
            _ => {
                return Err(GatewayError::unsupported(
                    "unsupported Claude content delta",
                ));
            }
        };
        self.add_output_bytes(delta_text.len())?;
        let active = self
            .active
            .as_mut()
            .filter(|block| block.index == expected_index)
            .ok_or_else(|| {
                GatewayError::protocol("Claude delta has no matching open content block")
            })?;
        match (string(&active.raw, "type")?, kind) {
            ("text", "text_delta") => append_string(&mut active.raw, "text", delta_text),
            ("tool_use", "input_json_delta") => {
                if !active.raw["input"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
                {
                    return Err(GatewayError::protocol(
                        "ambiguous Claude initial and streamed client input",
                    ));
                }
                let length = active
                    .input_json
                    .len()
                    .checked_add(delta_text.len())
                    .ok_or_else(|| GatewayError::protocol("Claude client input size overflow"))?;
                if length > self.limits.max_argument_bytes {
                    return Err(GatewayError::protocol(
                        "Claude client input byte limit exceeded",
                    ));
                }
                active.saw_input_delta = true;
                active.input_json.push_str(delta_text);
                Ok(())
            }
            ("thinking", "thinking_delta") if !active.saw_signature => {
                append_string(&mut active.raw, "thinking", delta_text)
            }
            ("thinking", "signature_delta") => {
                active.saw_signature = true;
                append_string(&mut active.raw, "signature", delta_text)
            }
            _ => Err(GatewayError::protocol(
                "Claude delta does not match content block type",
            )),
        }
    }

    fn block_stop(&mut self, event: &Value) -> Result<()> {
        let expected_index = index(event)?;
        let active = self
            .active
            .take()
            .filter(|block| block.index == expected_index)
            .ok_or_else(|| {
                GatewayError::protocol("Claude stop has no matching open content block")
            })?;
        let mut raw = active.raw;
        if raw["type"] == "tool_use" && active.saw_input_delta {
            // Invalid/truncated arguments are retained only as a private marker
            // until the terminal stop reason is known. Never expose them early.
            raw["input"] = Value::String(active.input_json);
        }
        self.blocks.push(raw);
        Ok(())
    }

    fn message_delta(&mut self, event: &Value) -> Result<()> {
        if self.response_id.is_none() || self.active.is_some() {
            return Err(GatewayError::protocol(
                "Claude message delta before content completion",
            ));
        }
        let delta = event
            .get("delta")
            .filter(|value| value.is_object())
            .ok_or_else(|| GatewayError::protocol("Claude message delta is missing"))?;
        if let Some(reason) = delta.get("stop_reason").filter(|value| !value.is_null()) {
            let reason = reason
                .as_str()
                .filter(|reason| !reason.is_empty())
                .ok_or_else(|| GatewayError::protocol("invalid Claude terminal stop reason"))?;
            if self
                .stop
                .as_deref()
                .is_some_and(|previous| previous != reason)
            {
                return Err(GatewayError::protocol(
                    "Claude terminal stop reason changed",
                ));
            }
            self.stop = Some(reason.into());
        }
        if let Some(usage) = event.get("usage") {
            self.update_usage(usage)?;
        }
        self.output_final_known = event
            .get("usage")
            .is_some_and(|usage| usage.get("output_tokens").is_some());
        self.finalizing = true;
        Ok(())
    }

    fn update_usage(&mut self, value: &Value) -> Result<()> {
        if !value.is_object() {
            return Err(GatewayError::protocol("Claude usage is not an object"));
        }
        // Keep the three independent input components until all are observed.
        // Anthropic input_tokens excludes cache reads and cache writes.
        update_counter(value, "input_tokens", &mut self.usage.input_tokens)?;
        update_counter(value, "output_tokens", &mut self.usage.output_tokens)?;
        update_counter(
            value,
            "cache_read_input_tokens",
            &mut self.usage.cached_input_tokens,
        )?;
        update_counter(
            value,
            "cache_creation_input_tokens",
            &mut self.usage.cache_creation_input_tokens,
        )?;
        if let Some(details) = value.get("output_tokens_details") {
            if !details.is_object() {
                return Err(GatewayError::protocol(
                    "Claude output token details is not an object",
                ));
            }
            update_counter(
                details,
                "thinking_tokens",
                &mut self.usage.reasoning_output_tokens,
            )?;
        }
        if self
            .usage
            .reasoning_output_tokens
            .zip(self.usage.output_tokens)
            .is_some_and(|(reasoning, output)| reasoning > output)
        {
            return Err(GatewayError::protocol(
                "Claude thinking usage exceeds total output usage",
            ));
        }
        Ok(())
    }

    fn add_output_bytes(&mut self, bytes: usize) -> Result<()> {
        self.output_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| GatewayError::protocol("Claude output size overflow"))?;
        if self.output_bytes > self.limits.max_output_bytes {
            return Err(GatewayError::protocol("Claude output byte limit exceeded"));
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<ModelResponse> {
        if self.failed || !self.terminal {
            return Err(GatewayError::protocol(
                "Claude stream did not finish a complete message",
            ));
        }
        let stop = match self.stop.as_deref() {
            Some("end_turn" | "stop_sequence") => StopReason::EndTurn,
            Some("tool_use") => StopReason::ToolCalls,
            Some("refusal") => StopReason::Refusal,
            Some("max_tokens") => StopReason::MaxTokens,
            Some("model_context_window_exceeded") => StopReason::Incomplete,
            Some("pause_turn") => {
                return Err(GatewayError::unsupported(
                    "Claude hosted tool continuation is disabled",
                ));
            }
            _ => {
                return Err(GatewayError::unsupported(
                    "unsupported Claude terminal stop reason",
                ));
            }
        };
        let mut text = String::new();
        let mut calls = Vec::new();
        let mut continuation_valid = true;
        let mut tool_block_count = 0usize;
        for block in &mut self.blocks {
            match string(block, "type")? {
                "text" => text.push_str(string(block, "text")?),
                "thinking" => {
                    if string(block, "signature")?.is_empty() {
                        continuation_valid = false;
                        if matches!(stop, StopReason::EndTurn | StopReason::ToolCalls) {
                            return Err(GatewayError::protocol(
                                "Claude thinking block has no replay signature",
                            ));
                        }
                    }
                }
                "tool_use" => {
                    tool_block_count += 1;
                    let parsed = if let Some(raw) = block["input"].as_str() {
                        strict_json(raw).ok().filter(Value::is_object)
                    } else {
                        block.get("input").cloned().filter(Value::is_object)
                    };
                    match parsed {
                        Some(arguments) => {
                            block["input"] = arguments;
                            if stop == StopReason::ToolCalls {
                                calls.push(ToolCall {
                                    id: string(block, "id")?.into(),
                                    name: string(block, "name")?.into(),
                                    arguments: serde_json::to_string(&block["input"]).map_err(
                                        |_| GatewayError::protocol("invalid Claude client input"),
                                    )?,
                                });
                            }
                        }
                        None => {
                            continuation_valid = false;
                            if stop == StopReason::ToolCalls {
                                return Err(GatewayError::protocol(
                                    "Claude client arguments are not complete object JSON",
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if stop == StopReason::ToolCalls && calls.is_empty() {
            return Err(GatewayError::protocol(
                "Claude tool terminal has no client calls",
            ));
        }
        if stop == StopReason::EndTurn && tool_block_count != 0 {
            return Err(GatewayError::protocol(
                "Claude client call and terminal reason disagree",
            ));
        }
        self.usage.input_tokens = match (
            self.usage.input_tokens,
            self.usage.cached_input_tokens,
            self.usage.cache_creation_input_tokens,
        ) {
            (Some(input), Some(read), Some(write)) => Some(
                input
                    .checked_add(read)
                    .and_then(|sum| sum.checked_add(write))
                    .ok_or_else(|| GatewayError::protocol("Claude input token count overflow"))?,
            ),
            _ => None,
        };
        if !self.output_final_known {
            self.usage.output_tokens = None;
            self.usage.reasoning_output_tokens = None;
        }
        // Refused/truncated generations are not suitable tool continuations.
        let continuation =
            if continuation_valid && matches!(stop, StopReason::EndTurn | StopReason::ToolCalls) {
                self.blocks
            } else {
                Vec::new()
            };
        Ok(ModelResponse {
            protocol: Protocol::AnthropicMessages,
            requested_model: self.requested_model,
            model: self
                .model
                .ok_or_else(|| GatewayError::protocol("Claude model is missing"))?,
            response_id: self
                .response_id
                .ok_or_else(|| GatewayError::protocol("Claude response ID is missing"))?,
            text,
            calls,
            stop,
            usage: self.usage,
            continuation,
            refusal: (stop == StopReason::Refusal).then(|| "Provider refused the request".into()),
        })
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::protocol("Claude event string field is missing or invalid"))
}

fn bounded_identity<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let value = string(value, key)?;
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(GatewayError::protocol(
            "Claude identity is empty, oversized or contains control characters",
        ));
    }
    Ok(value)
}

fn validate_client_origin(block: &Value) -> Result<()> {
    if block
        .get("toolset_name")
        .is_some_and(|value| !value.is_null())
        || block
            .get("caller")
            .is_some_and(|caller| caller.get("type").and_then(Value::as_str) != Some("direct"))
    {
        return Err(GatewayError::unsupported(
            "Claude hosted or toolset caller is disabled",
        ));
    }
    Ok(())
}

fn index(value: &Value) -> Result<usize> {
    value
        .get("index")
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| GatewayError::protocol("Claude content block index is missing or invalid"))
}

fn append_string(value: &mut Value, key: &str, text: &str) -> Result<()> {
    match value.get_mut(key) {
        Some(Value::String(field)) => {
            field.push_str(text);
            Ok(())
        }
        _ => Err(GatewayError::protocol("Claude content string is missing")),
    }
}

fn update_counter(value: &Value, key: &str, counter: &mut Option<u64>) -> Result<()> {
    if let Some(next) = value.get(key) {
        let next = next
            .as_u64()
            .ok_or_else(|| GatewayError::protocol("Claude usage must be an unsigned integer"))?;
        if counter.is_some_and(|previous| next < previous) {
            return Err(GatewayError::protocol(
                "Claude cumulative usage moved backwards",
            ));
        }
        *counter = Some(next);
    }
    Ok(())
}
