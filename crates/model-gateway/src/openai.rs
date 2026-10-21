//! OpenAI Responses wire protocol. Deltas are provisional; only a complete,
//! internally consistent response can expose a function call to the host.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::{
    DecoderLimits, GatewayError, Message, ModelResponse, Protocol, RequestLimits, Result, SseEvent,
    StopReason, ToolCall, TurnRequest, Usage,
};

pub fn build_request(request: &TurnRequest) -> Result<Value> {
    build_request_with_limits(request, RequestLimits::default())
}
pub fn build_request_with_limits(request: &TurnRequest, limits: RequestLimits) -> Result<Value> {
    request.validate_with_limits(limits)?;
    if request.model.trim().is_empty() || request.max_output_tokens == 0 {
        return Err(GatewayError::invalid(
            "model and positive output limit are required",
        ));
    }
    let mut names = BTreeSet::new();
    let mut tools = Vec::with_capacity(request.tools.len());
    for tool in &request.tools {
        if !wire_name(&tool.name) || !names.insert(&tool.name) {
            return Err(GatewayError::invalid("duplicate or invalid function name"));
        }
        if !tool.parameters.is_object() {
            return Err(GatewayError::invalid(
                "function parameters must be an object schema",
            ));
        }
        if tool.strict {
            strict_objects(&tool.parameters)?;
        }
        tools.push(json!({"type":"function", "name":tool.name,
            "description":tool.description,"parameters":tool.parameters,"strict":tool.strict}));
    }
    let mut input = Vec::new();
    let mut pending = BTreeSet::<String>::new();
    let mut seen_calls = BTreeSet::new();
    for message in &request.messages {
        match message {
            Message::UserImages { text, images } => {
                if !pending.is_empty() {
                    return Err(GatewayError::invalid("image user before tool results"));
                }
                let mut parts = vec![json!({"type":"input_text","text":text})];
                parts.extend(images.iter().map(
                    |i| json!({"type":"input_image","image_url":i.data_url(),"detail":"original"}),
                ));
                input.push(json!({"role":"user","content":parts}));
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
                let mut parts = vec![
                    json!({"type":"input_text","text":if *is_error {json!({"is_error":true,"content":content}).to_string()} else {content.clone()}}),
                ];
                parts.extend(images.iter().map(
                    |i| json!({"type":"input_image","image_url":i.data_url(),"detail":"original"}),
                ));
                input.push(json!({"type":"function_call_output","call_id":call_id,"output":parts}));
            }
            Message::User { text } => {
                if !pending.is_empty() {
                    return Err(GatewayError::invalid(
                        "tool results must precede a new user turn",
                    ));
                }
                input.push(json!({"role":"user","content":[{"type":"input_text","text":text}]}));
            }
            Message::Assistant { response } => {
                if response.protocol != Protocol::OpenAiResponses
                    || response.requested_model != request.model
                {
                    return Err(GatewayError::unsupported(
                        "native continuation belongs to another protocol or model",
                    ));
                }
                if !pending.is_empty() || response.continuation.is_empty() {
                    return Err(GatewayError::invalid("incomplete assistant continuation"));
                }
                if !matches!(
                    response.stop,
                    StopReason::EndTurn | StopReason::ToolCalls | StopReason::Refusal
                ) {
                    return Err(GatewayError::invalid(
                        "an incomplete response cannot be replayed",
                    ));
                }
                validate_history_response(response)?;
                for call in &response.calls {
                    if !seen_calls.insert(call.id.clone()) || !pending.insert(call.id.clone()) {
                        return Err(GatewayError::invalid("repeated call identifier in history"));
                    }
                }
                for item in &response.continuation {
                    match string(item, "type")? {
                        "message" | "reasoning" | "function_call" => input.push(item.clone()),
                        _ => {
                            return Err(GatewayError::unsupported("unsupported continuation item"));
                        }
                    }
                }
            }
            Message::ToolResult {
                call_id,
                content,
                is_error,
            } => {
                if !pending.remove(call_id) {
                    return Err(GatewayError::invalid(
                        "tool result has no unique pending call",
                    ));
                }
                let output = if *is_error {
                    json!({"is_error":true,"content":content}).to_string()
                } else {
                    content.clone()
                };
                input
                    .push(json!({"type":"function_call_output","call_id":call_id,"output":output}));
            }
        }
    }
    if input.is_empty() || !pending.is_empty() {
        return Err(GatewayError::invalid(
            "request input or matching tool result is missing",
        ));
    }
    let mut body = json!({"model":request.model,"instructions":request.system_prompt,
        "input":input,"tools":tools,"max_output_tokens":request.max_output_tokens,
        "stream":true,"store":false,"parallel_tool_calls":false,
        "include":["reasoning.encrypted_content"]});
    if let Some(schema) = &request.output_schema {
        if !schema.is_object() || schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(GatewayError::invalid(
                "structured output requires a root object schema",
            ));
        }
        strict_objects(schema)?;
        body["text"] = json!({"format":{"type":"json_schema","name":"melissa_output","strict":true,"schema":schema}});
    }
    Ok(body)
}

fn wire_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn strict_objects(schema: &Value) -> Result<()> {
    match schema {
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some("object")
                || map
                    .get("type")
                    .and_then(Value::as_array)
                    .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("object")))
                || map.contains_key("properties")
            {
                let properties = map
                    .get("properties")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        GatewayError::invalid("strict object schema requires properties")
                    })?;
                let required = map
                    .get("required")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        GatewayError::invalid("strict object schema requires every property")
                    })?;
                let required_count = required.len();
                let required: Option<BTreeSet<&str>> = required.iter().map(Value::as_str).collect();
                let required = required
                    .ok_or_else(|| GatewayError::invalid("required must contain property names"))?;
                if map.get("additionalProperties") != Some(&Value::Bool(false))
                    || required.len() != properties.len()
                    || required.len() != required_count
                    || !properties.keys().all(|key| required.contains(key.as_str()))
                {
                    return Err(GatewayError::invalid(
                        "strict objects require all properties and additionalProperties=false",
                    ));
                }
            }
            for keyword in ["properties", "$defs", "definitions", "patternProperties"] {
                if let Some(children) = map.get(keyword).and_then(Value::as_object) {
                    for child in children.values() {
                        strict_objects(child)?;
                    }
                }
            }
            for keyword in ["items", "additionalProperties", "not", "if", "then", "else"] {
                if let Some(child) = map.get(keyword).filter(|child| child.is_object()) {
                    strict_objects(child)?;
                }
            }
            for keyword in ["anyOf", "allOf", "oneOf", "prefixItems"] {
                if let Some(children) = map.get(keyword).and_then(Value::as_array) {
                    for child in children {
                        strict_objects(child)?;
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                strict_objects(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_history_response(response: &ModelResponse) -> Result<()> {
    let mut calls = Vec::new();
    let mut text = String::new();
    let mut refusal = String::new();
    let mut refused = false;
    let mut ids = BTreeSet::new();
    let mut call_ids = BTreeSet::new();
    for item in &response.continuation {
        if !ids.insert(nonempty(item, "id")?)
            || item
                .get("status")
                .is_some_and(|status| status.as_str() != Some("completed"))
        {
            return Err(GatewayError::invalid(
                "invalid native history item identity or status",
            ));
        }
        match string(item, "type")? {
            "function_call" => {
                let call = ToolCall {
                    id: nonempty(item, "call_id")?.to_owned(),
                    name: nonempty(item, "name")?.to_owned(),
                    arguments: string(item, "arguments")?.to_owned(),
                };
                if !wire_name(&call.name)
                    || !call_ids.insert(call.id.clone())
                    || !crate::strict_json(&call.arguments)?.is_object()
                {
                    return Err(GatewayError::invalid(
                        "invalid native history function call",
                    ));
                }
                calls.push(call);
            }
            "message" => {
                if string(item, "role")? != "assistant" {
                    return Err(GatewayError::invalid(
                        "native history message has another role",
                    ));
                }
                for part in array(item, "content")? {
                    match string(part, "type")? {
                        "output_text" => text.push_str(string(part, "text")?),
                        "refusal" => {
                            refused = true;
                            refusal.push_str(string(part, "refusal")?);
                        }
                        _ => {
                            return Err(GatewayError::unsupported(
                                "unsupported native history content",
                            ));
                        }
                    }
                }
            }
            "reasoning" => {
                if item
                    .get("encrypted_content")
                    .is_some_and(|value| !value.is_string() && !value.is_null())
                {
                    return Err(GatewayError::invalid("invalid encrypted native history"));
                }
            }
            _ => return Err(GatewayError::unsupported("unsupported native history item")),
        }
    }
    let expected_stop = if refused {
        StopReason::Refusal
    } else if calls.is_empty() {
        StopReason::EndTurn
    } else {
        StopReason::ToolCalls
    };
    if calls != response.calls
        || text != response.text
        || response.refusal.as_deref()
            != if refused {
                Some(refusal.as_str())
            } else {
                None
            }
        || response.stop != expected_stop
        || (refused && !calls.is_empty())
    {
        return Err(GatewayError::invalid(
            "native continuation disagrees with normalized history",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Part {
    kind: String,
    text: String,
    text_done: bool,
    done: Option<Value>,
    annotations: Vec<Value>,
}

enum ItemKind {
    Function {
        call_id: String,
        name: String,
        arguments: String,
        arguments_done: bool,
    },
    Message {
        parts: BTreeMap<usize, Part>,
    },
    Reasoning {
        summaries: BTreeMap<usize, Part>,
        contents: BTreeMap<usize, Part>,
    },
}

struct Item {
    id: String,
    kind: ItemKind,
    done: Option<Value>,
}

pub struct OpenAiDecoder {
    requested_model: String,
    limits: DecoderLimits,
    total: usize,
    output_bytes: usize,
    sequence: Option<u64>,
    response_id: Option<String>,
    model: Option<String>,
    items: BTreeMap<usize, Item>,
    item_ids: BTreeSet<String>,
    call_ids: BTreeSet<String>,
    terminal: Option<ModelResponse>,
    poisoned: bool,
}

impl OpenAiDecoder {
    pub fn new(requested_model: &str, limits: DecoderLimits) -> Self {
        Self {
            requested_model: requested_model.to_owned(),
            limits,
            total: 0,
            output_bytes: 0,
            sequence: None,
            response_id: None,
            model: None,
            items: BTreeMap::new(),
            item_ids: BTreeSet::new(),
            call_ids: BTreeSet::new(),
            terminal: None,
            poisoned: false,
        }
    }

    pub fn push(&mut self, event: &SseEvent) -> Result<()> {
        if self.poisoned {
            return Err(GatewayError::protocol("decoder is already invalid"));
        }
        let result = self.push_inner(event);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn push_inner(&mut self, event: &SseEvent) -> Result<()> {
        if self.terminal.is_some() {
            return protocol("event after terminal response");
        }
        if event.data.len() > self.limits.max_event_bytes {
            return protocol("event byte limit exceeded");
        }
        self.total = self
            .total
            .checked_add(event.data.len())
            .ok_or_else(|| GatewayError::protocol("stream byte overflow"))?;
        if self.total > self.limits.max_total_bytes {
            return protocol("stream byte limit exceeded");
        }
        let value = crate::strict_json(&event.data)?;
        let kind = string(&value, "type")?;
        if event.event.as_deref().is_some_and(|name| name != kind) {
            return protocol("SSE event name disagrees with JSON type");
        }
        let sequence = integer(&value, "sequence_number")?;
        if self.sequence.is_some_and(|previous| sequence <= previous) {
            return protocol("repeated or unordered sequence number");
        }
        self.sequence = Some(sequence);
        if let Some(id) = value.get("response_id")
            && id.as_str() != self.response_id.as_deref()
        {
            return protocol("event belongs to a different response");
        }
        match kind {
            "response.created" => self.created(&value),
            "response.in_progress" => self.in_progress(&value),
            "response.output_item.added" => self.add_item(&value),
            "response.output_item.done" => self.done_item(&value),
            "response.content_part.added" => self.add_part(&value, false),
            "response.content_part.done" => self.done_part(&value, false),
            "response.output_text.delta" | "response.refusal.delta" => {
                self.text_event(&value, false, false)
            }
            "response.output_text.done" | "response.refusal.done" => {
                self.text_event(&value, true, false)
            }
            "response.output_text.annotation.added" => self.annotation(&value),
            "response.function_call_arguments.delta" => self.arguments(&value, false),
            "response.function_call_arguments.done" => self.arguments(&value, true),
            "response.reasoning_summary_part.added" => self.add_part(&value, true),
            "response.reasoning_summary_part.done" => self.done_part(&value, true),
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                self.text_event(&value, false, true)
            }
            "response.reasoning_summary_text.done" | "response.reasoning_text.done" => {
                self.text_event(&value, true, true)
            }
            "response.completed" | "response.failed" | "response.incomplete" => {
                self.complete(&value, kind)
            }
            "error" => self.error(&value),
            _ => Err(GatewayError::unsupported(
                "unsupported Responses event kind",
            )),
        }
    }

    fn created(&mut self, event: &Value) -> Result<()> {
        if self.response_id.is_some() {
            return protocol("repeated response.created");
        }
        let response = object_field(event, "response")?;
        if string(response, "status")? != "in_progress" || !array(response, "output")?.is_empty() {
            return protocol("invalid initial response state");
        }
        self.response_id = Some(nonempty(response, "id")?.to_owned());
        self.model = Some(nonempty(response, "model")?.to_owned());
        Ok(())
    }

    fn response_matches(&self, response: &Value) -> Result<()> {
        if Some(string(response, "id")?) != self.response_id.as_deref()
            || Some(string(response, "model")?) != self.model.as_deref()
        {
            return protocol("response identity or model changed");
        }
        Ok(())
    }

    fn in_progress(&self, event: &Value) -> Result<()> {
        let response = object_field(event, "response")?;
        self.response_matches(response)?;
        if string(response, "status")? != "in_progress" {
            return protocol("invalid progress response status");
        }
        Ok(())
    }

    fn add_item(&mut self, event: &Value) -> Result<()> {
        self.require_started()?;
        let index = index(event, "output_index")?;
        if index != self.items.len() || index >= self.limits.max_items {
            return protocol("duplicate, sparse, or excessive output index");
        }
        let value = object_field(event, "item")?;
        let id = nonempty(value, "id")?.to_owned();
        if !self.item_ids.insert(id.clone()) {
            return protocol("duplicate output item identifier");
        }
        let kind = match string(value, "type")? {
            "function_call" => {
                let call_id = nonempty(value, "call_id")?.to_owned();
                let name = nonempty(value, "name")?.to_owned();
                if !wire_name(&name)
                    || !self.call_ids.insert(call_id.clone())
                    || self.call_ids.len() > self.limits.max_tool_calls
                {
                    return protocol("invalid or duplicate function call");
                }
                let arguments = string(value, "arguments")?.to_owned();
                if arguments.len() > self.limits.max_argument_bytes {
                    return protocol("function argument limit exceeded");
                }
                ItemKind::Function {
                    call_id,
                    name,
                    arguments,
                    arguments_done: false,
                }
            }
            "message" => {
                if string(value, "role")? != "assistant" || !array(value, "content")?.is_empty() {
                    return protocol("invalid initial assistant message");
                }
                ItemKind::Message {
                    parts: BTreeMap::new(),
                }
            }
            "reasoning" => ItemKind::Reasoning {
                summaries: BTreeMap::new(),
                contents: BTreeMap::new(),
            },
            _ => {
                return Err(GatewayError::unsupported(
                    "hosted and freeform tools are not supported",
                ));
            }
        };
        if let Some(status) = value.get("status")
            && status.as_str() != Some("in_progress")
        {
            return protocol("new output item is not in progress");
        }
        self.items.insert(
            index,
            Item {
                id,
                kind,
                done: None,
            },
        );
        Ok(())
    }

    fn item_mut(&mut self, event: &Value) -> Result<&mut Item> {
        let item = self
            .items
            .get_mut(&index(event, "output_index")?)
            .ok_or_else(|| GatewayError::protocol("event references an unknown output item"))?;
        if item.done.is_some() || nonempty(event, "item_id")? != item.id {
            return protocol("event references a completed or different item");
        }
        Ok(item)
    }

    fn arguments(&mut self, event: &Value, done: bool) -> Result<()> {
        let limit = self.limits.max_argument_bytes;
        let item = self.item_mut(event)?;
        let ItemKind::Function {
            arguments,
            arguments_done,
            ..
        } = &mut item.kind
        else {
            return protocol("argument event is not for a function");
        };
        if *arguments_done {
            return protocol("arguments already finalized");
        }
        if done {
            if string(event, "arguments")? != arguments {
                return protocol("final arguments disagree with deltas");
            }
            *arguments_done = true;
        } else {
            append(arguments, string(event, "delta")?, limit)?;
        }
        Ok(())
    }

    fn add_part(&mut self, event: &Value, summary: bool) -> Result<()> {
        let limit = self.limits.max_items;
        let part_index = index(
            event,
            if summary {
                "summary_index"
            } else {
                "content_index"
            },
        )?;
        let raw = object_field(event, "part")?;
        let kind = string(raw, "type")?;
        let field = match kind {
            "output_text" | "summary_text" | "reasoning_text" => "text",
            "refusal" => "refusal",
            _ => return Err(GatewayError::unsupported("unsupported output content")),
        };
        if !string(raw, field)?.is_empty() {
            return protocol("content part starts with nonempty text");
        }
        let item = self.item_mut(event)?;
        let parts = match (&mut item.kind, summary, kind) {
            (ItemKind::Message { parts }, false, "output_text" | "refusal") => parts,
            (ItemKind::Reasoning { summaries, .. }, true, "summary_text") => summaries,
            (ItemKind::Reasoning { contents, .. }, false, "reasoning_text") => contents,
            _ => return protocol("content part kind disagrees with output item"),
        };
        if part_index != parts.len() || part_index >= limit {
            return protocol("duplicate, sparse, or excessive content index");
        }
        parts.insert(
            part_index,
            Part {
                kind: kind.to_owned(),
                ..Part::default()
            },
        );
        Ok(())
    }

    fn text_event(&mut self, event: &Value, done: bool, reasoning: bool) -> Result<()> {
        let event_type = string(event, "type")?;
        let summary = event_type.starts_with("response.reasoning_summary");
        let refusal = event_type.starts_with("response.refusal");
        let part_index = index(
            event,
            if summary {
                "summary_index"
            } else {
                "content_index"
            },
        )?;
        let text = string(
            event,
            if done {
                if refusal { "refusal" } else { "text" }
            } else {
                "delta"
            },
        )?;
        let limit = self.limits.max_output_bytes;
        let item_limit = self.limits.max_items;
        if !done {
            self.output_bytes = self
                .output_bytes
                .checked_add(text.len())
                .ok_or_else(|| GatewayError::protocol("output byte overflow"))?;
            if self.output_bytes > limit {
                return protocol("output text byte limit exceeded");
            }
        }
        let item = self.item_mut(event)?;
        let parts = match (&mut item.kind, reasoning, summary) {
            (ItemKind::Message { parts }, false, false) => parts,
            (ItemKind::Reasoning { summaries, .. }, true, true) => summaries,
            (ItemKind::Reasoning { contents, .. }, true, false) => contents,
            _ => return protocol("text event kind disagrees with item"),
        };
        // Reasoning text streams have no content_part.added event in the API.
        if reasoning && !summary && !parts.contains_key(&part_index) {
            if part_index != parts.len() || part_index >= item_limit {
                return protocol("invalid reasoning content index");
            }
            parts.insert(
                part_index,
                Part {
                    kind: "reasoning_text".to_owned(),
                    ..Part::default()
                },
            );
        }
        let part = parts
            .get_mut(&part_index)
            .ok_or_else(|| GatewayError::protocol("text references an unknown content part"))?;
        let expected = if reasoning {
            if summary {
                "summary_text"
            } else {
                "reasoning_text"
            }
        } else if refusal {
            "refusal"
        } else {
            "output_text"
        };
        if part.kind != expected || part.text_done || part.done.is_some() {
            return protocol("text kind changed or content already finalized");
        }
        if done {
            if text != part.text {
                return protocol("final text disagrees with deltas");
            }
            part.text_done = true;
        } else {
            append(&mut part.text, text, limit)?;
        }
        Ok(())
    }

    fn done_part(&mut self, event: &Value, summary: bool) -> Result<()> {
        let part_index = index(
            event,
            if summary {
                "summary_index"
            } else {
                "content_index"
            },
        )?;
        let raw = object_field(event, "part")?;
        let item = self.item_mut(event)?;
        let parts = match (&mut item.kind, summary) {
            (ItemKind::Message { parts }, false) => parts,
            (ItemKind::Reasoning { summaries, .. }, true) => summaries,
            (ItemKind::Reasoning { contents, .. }, false) => contents,
            _ => return protocol("content completion has wrong item kind"),
        };
        let part = parts
            .get_mut(&part_index)
            .ok_or_else(|| GatewayError::protocol("content completion before start"))?;
        if part.done.is_some()
            || !part.text_done
            || string(raw, "type")? != part.kind
            || string(
                raw,
                if part.kind == "refusal" {
                    "refusal"
                } else {
                    "text"
                },
            )? != part.text
        {
            return protocol("content completion disagrees with text");
        }
        if !part.annotations.is_empty() && array(raw, "annotations")? != &part.annotations {
            return protocol("annotations disagree with completion");
        }
        part.done = Some(raw.clone());
        Ok(())
    }

    fn annotation(&mut self, event: &Value) -> Result<()> {
        let annotation_index = index(event, "annotation_index")?;
        let part_index = index(event, "content_index")?;
        let item = self.item_mut(event)?;
        let ItemKind::Message { parts } = &mut item.kind else {
            return protocol("annotation on non-message item");
        };
        let part = parts
            .get_mut(&part_index)
            .ok_or_else(|| GatewayError::protocol("annotation before content"))?;
        if part.kind != "output_text"
            || part.done.is_some()
            || annotation_index != part.annotations.len()
        {
            return protocol("invalid annotation index or lifecycle");
        }
        part.annotations.push(
            event
                .get("annotation")
                .ok_or_else(|| GatewayError::protocol("missing annotation"))?
                .clone(),
        );
        Ok(())
    }

    fn done_item(&mut self, event: &Value) -> Result<()> {
        let raw = object_field(event, "item")?;
        let item = self
            .items
            .get_mut(&index(event, "output_index")?)
            .ok_or_else(|| GatewayError::protocol("item completion before start"))?;
        if item.done.is_some() || string(raw, "id")? != item.id {
            return protocol("duplicate or mismatched item completion");
        }
        if raw
            .get("status")
            .is_some_and(|s| !matches!(s.as_str(), Some("completed" | "incomplete")))
        {
            return protocol("output item did not finish");
        }
        match &item.kind {
            ItemKind::Function {
                call_id,
                name,
                arguments,
                arguments_done,
            } => {
                if !arguments_done
                    || string(raw, "type")? != "function_call"
                    || string(raw, "call_id")? != call_id
                    || string(raw, "name")? != name
                    || string(raw, "arguments")? != arguments
                {
                    return protocol("function item completion disagrees with stream");
                }
            }
            ItemKind::Message { parts } => {
                if string(raw, "type")? != "message" || string(raw, "role")? != "assistant" {
                    return protocol("message identity changed");
                }
                compare_parts(array(raw, "content")?, parts, true)?;
            }
            ItemKind::Reasoning {
                summaries,
                contents,
            } => {
                if string(raw, "type")? != "reasoning" {
                    return protocol("reasoning identity changed");
                }
                if !summaries.is_empty() {
                    compare_parts(array(raw, "summary")?, summaries, true)?;
                }
                if !contents.is_empty() {
                    compare_parts(array(raw, "content")?, contents, false)?;
                }
                if raw
                    .get("encrypted_content")
                    .is_some_and(|v| !v.is_string() && !v.is_null())
                {
                    return protocol("invalid encrypted continuation");
                }
            }
        }
        item.done = Some(raw.clone());
        Ok(())
    }

    fn complete(&mut self, event: &Value, event_type: &str) -> Result<()> {
        let response = object_field(event, "response")?;
        self.response_matches(response)?;
        let status = string(response, "status")?;
        let expected = match event_type {
            "response.completed" => "completed",
            "response.failed" => "failed",
            _ => "incomplete",
        };
        if status != expected {
            return protocol("terminal response status mismatch");
        }
        let usage = usage(response.get("usage"))?;
        let mut text = String::new();
        let mut refusal = String::new();
        let mut refused = false;
        let mut calls = Vec::new();
        let mut continuation = Vec::new();
        let stop = if status == "completed" {
            if response.get("error").is_some_and(|v| !v.is_null())
                || response
                    .get("incomplete_details")
                    .is_some_and(|v| !v.is_null())
            {
                return protocol("completed response contains failure details");
            }
            let output = array(response, "output")?;
            if output.len() != self.items.len() {
                return protocol("terminal output count disagrees with stream");
            }
            for (index, raw) in output.iter().enumerate() {
                let item = self
                    .items
                    .get(&index)
                    .ok_or_else(|| GatewayError::protocol("missing output item"))?;
                if item.done.as_ref() != Some(raw) {
                    return protocol("terminal output snapshot disagrees with completed item");
                }
                if raw
                    .get("status")
                    .is_some_and(|s| s.as_str() != Some("completed"))
                {
                    return protocol("completed response contains incomplete output");
                }
                match &item.kind {
                    ItemKind::Function {
                        call_id,
                        name,
                        arguments,
                        ..
                    } => {
                        if !crate::strict_json(arguments)?.is_object() {
                            return protocol("function arguments must be a JSON object");
                        }
                        calls.push(ToolCall {
                            id: call_id.clone(),
                            name: name.clone(),
                            arguments: arguments.clone(),
                        });
                    }
                    ItemKind::Message { parts } => {
                        for part in parts.values() {
                            if part.kind == "refusal" {
                                refused = true;
                                refusal.push_str(&part.text);
                            } else {
                                text.push_str(&part.text);
                            }
                        }
                    }
                    ItemKind::Reasoning { .. } => {}
                }
                continuation.push(raw.clone());
            }
            if refused {
                if !calls.is_empty() {
                    return protocol("response mixes refusal and function calls");
                }
                StopReason::Refusal
            } else if calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolCalls
            }
        } else if status == "failed" {
            StopReason::Error
        } else {
            match response
                .get("incomplete_details")
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str)
            {
                Some("max_output_tokens") => StopReason::MaxTokens,
                _ => StopReason::Incomplete,
            }
        };
        self.terminal = Some(ModelResponse {
            protocol: Protocol::OpenAiResponses,
            requested_model: self.requested_model.clone(),
            model: self.model.clone().unwrap_or_default(),
            response_id: self.response_id.clone().unwrap_or_default(),
            text,
            calls,
            stop,
            usage,
            continuation,
            refusal: if refused { Some(refusal) } else { None },
        });
        Ok(())
    }

    fn error(&mut self, _event: &Value) -> Result<()> {
        // The provider error message may contain input data or credentials. It
        // is deliberately not copied into an error, response, or diagnostic.
        self.require_started()?;
        self.terminal = Some(ModelResponse {
            protocol: Protocol::OpenAiResponses,
            requested_model: self.requested_model.clone(),
            model: self.model.clone().unwrap_or_default(),
            response_id: self.response_id.clone().unwrap_or_default(),
            text: String::new(),
            calls: Vec::new(),
            stop: StopReason::Error,
            usage: Usage::default(),
            continuation: Vec::new(),
            refusal: None,
        });
        Ok(())
    }

    fn require_started(&self) -> Result<()> {
        if self.response_id.is_none() {
            return protocol("event before response.created");
        }
        Ok(())
    }

    pub fn finish(self) -> Result<ModelResponse> {
        if self.poisoned {
            return protocol("invalid provider stream");
        }
        self.terminal
            .ok_or_else(|| GatewayError::protocol("provider stream ended before terminal response"))
    }
}

fn compare_parts(
    raw: &[Value],
    parts: &BTreeMap<usize, Part>,
    require_part_done: bool,
) -> Result<()> {
    if raw.len() != parts.len() {
        return protocol("content count disagrees with stream");
    }
    for (index, value) in raw.iter().enumerate() {
        let part = parts
            .get(&index)
            .ok_or_else(|| GatewayError::protocol("missing content index"))?;
        if !part.text_done
            || string(value, "type")? != part.kind
            || string(
                value,
                if part.kind == "refusal" {
                    "refusal"
                } else {
                    "text"
                },
            )? != part.text
            || (require_part_done && part.done.as_ref() != Some(value))
        {
            return protocol("output content disagrees with finalized part");
        }
    }
    Ok(())
}

fn usage(raw: Option<&Value>) -> Result<Usage> {
    let Some(raw) = raw.filter(|value| !value.is_null()) else {
        return Ok(Usage::default());
    };
    if !raw.is_object() {
        return protocol("invalid usage record");
    }
    let input = optional_integer(raw, "input_tokens")?;
    let output = optional_integer(raw, "output_tokens")?;
    if let (Some(input), Some(output), Some(total)) =
        (input, output, optional_integer(raw, "total_tokens")?)
        && input.checked_add(output) != Some(total)
    {
        return protocol("inconsistent token usage total");
    }
    let input_details = raw.get("input_tokens_details").filter(|v| !v.is_null());
    let output_details = raw.get("output_tokens_details").filter(|v| !v.is_null());
    let cached = input_details
        .map(|v| optional_integer(v, "cached_tokens"))
        .transpose()?
        .flatten();
    let created = input_details
        .map(|v| optional_integer(v, "cache_write_tokens"))
        .transpose()?
        .flatten();
    let reasoning = output_details
        .map(|v| optional_integer(v, "reasoning_tokens"))
        .transpose()?
        .flatten();
    if cached
        .zip(input)
        .is_some_and(|(cached, total)| cached > total)
        || created
            .zip(input)
            .is_some_and(|(cached, total)| cached > total)
        || reasoning
            .zip(output)
            .is_some_and(|(reasoning, total)| reasoning > total)
    {
        return protocol("usage detail exceeds parent count");
    }
    if let (Some(cached), Some(created), Some(input)) = (cached, created, input)
        && cached.checked_add(created).is_none_or(|sum| sum > input)
    {
        return protocol("cache usage exceeds total input count");
    }
    Ok(Usage {
        input_tokens: input,
        output_tokens: output,
        cached_input_tokens: cached,
        cache_creation_input_tokens: created,
        reasoning_output_tokens: reasoning,
    })
}

fn append(target: &mut String, delta: &str, limit: usize) -> Result<()> {
    if target
        .len()
        .checked_add(delta.len())
        .is_none_or(|n| n > limit)
    {
        return protocol("buffer limit exceeded");
    }
    target.push_str(delta);
    Ok(())
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::protocol("required string field is missing or invalid"))
}
fn nonempty<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let result = string(value, field)?;
    if result.is_empty() {
        return protocol("required identifier is empty");
    }
    Ok(result)
}
fn object_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .filter(|v| v.is_object())
        .ok_or_else(|| GatewayError::protocol("required object field is missing or invalid"))
}
fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| GatewayError::protocol("required array field is missing or invalid"))
}
fn integer(value: &Value, field: &str) -> Result<u64> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        GatewayError::protocol("required unsigned integer field is missing or invalid")
    })
}
fn optional_integer(value: &Value, field: &str) -> Result<Option<u64>> {
    if !value.is_object() {
        return protocol("usage details are not an object");
    }
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| GatewayError::protocol("invalid token count")),
    }
}
fn index(value: &Value, field: &str) -> Result<usize> {
    usize::try_from(integer(value, field)?)
        .map_err(|_| GatewayError::protocol("index cannot fit host range"))
}
fn protocol<T>(message: &str) -> Result<T> {
    Err(GatewayError::protocol(message))
}
