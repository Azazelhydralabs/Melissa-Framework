use crate::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    OpenAiResponses,
    AnthropicMessages,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolCalls,
    Refusal,
    MaxTokens,
    Incomplete,
    Cancelled,
    Error,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    /// Total billed input, including cached input, when fully known.
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub cache_creation_input_tokens: Option<u64>,
    /// A subset of output tokens, never an additional charge.
    pub reasoning_output_tokens: Option<u64>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}
impl std::fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCall")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("arguments", &"[redacted]")
            .finish()
    }
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    pub protocol: Protocol,
    pub requested_model: String,
    pub model: String,
    pub response_id: String,
    pub text: String,
    pub calls: Vec<ToolCall>,
    pub stop: StopReason,
    pub usage: Usage,
    /// Provider-owned continuation items. Opaque reasoning/signature data is
    /// replayed only to its originating protocol, and never logged via Debug.
    pub continuation: Vec<Value>,
    pub refusal: Option<String>,
}
impl std::fmt::Debug for ModelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelResponse")
            .field("protocol", &self.protocol)
            .field("requested_model", &self.requested_model)
            .field("model", &self.model)
            .field("response_id", &self.response_id)
            .field("stop", &self.stop)
            .field("usage", &self.usage)
            .field("call_count", &self.calls.len())
            .field("content", &"[redacted]")
            .finish()
    }
}
// Transcript message/individual input bounds are independent of the explicit
// trusted-host history byte policy. Provider continuation is never shortened.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    UserImages {
        text: String,
        images: Vec<crate::vision::InlinePng>,
    },
    ToolImages {
        call_id: String,
        content: String,
        is_error: bool,
        images: Vec<crate::vision::InlinePng>,
    },
    User {
        text: String,
    },
    Assistant {
        response: ModelResponse,
    },
    ToolResult {
        call_id: String,
        content: String,
        is_error: bool,
    },
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserImages { text, images } => f
                .debug_struct("UserImages")
                .field("text_bytes", &text.len())
                .field("images", &images.len())
                .finish(),
            Self::ToolImages { images, .. } => f
                .debug_struct("ToolImages")
                .field("images", &images.len())
                .finish(),
            Self::User { text } => f.debug_struct("User").field("bytes", &text.len()).finish(),
            Self::Assistant { response } => response.fmt(f),
            Self::ToolResult { is_error, .. } => f
                .debug_struct("ToolResult")
                .field("is_error", is_error)
                .field("content", &"[redacted]")
                .finish(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
    pub strict: bool,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    pub model: String,
    pub system_prompt: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDefinition>,
    pub max_output_tokens: u64,
    pub output_schema: Option<Value>,
}
impl std::fmt::Debug for TurnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnRequest")
            .field("model", &self.model)
            .field("messages", &self.messages.len())
            .field(
                "tools",
                &self
                    .tools
                    .iter()
                    .map(|t| t.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("max_output_tokens", &self.max_output_tokens)
            .field("content", &"[redacted]")
            .finish()
    }
}
pub fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
impl TurnRequest {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_limits(RequestLimits::default())
    }
    pub fn validate_with_limits(&self, limits: RequestLimits) -> Result<()> {
        limits.validate()?;
        if self.model.trim().is_empty()
            || self.model.len() > 256
            || self.model.chars().any(char::is_control)
            || self.system_prompt.len() > 1024 * 1024
            || self.messages.is_empty()
            || self.messages.len() > 256
            || self.tools.len() > 64
            || self.max_output_tokens == 0
            || self.max_output_tokens > 1_000_000
        {
            return Err(GatewayError::invalid("request identity or bounds"));
        }
        let mut names = BTreeSet::new();
        for t in &self.tools {
            if !valid_tool_name(&t.name)
                || !names.insert(&t.name)
                || t.description.len() > 64 * 1024
                || !t.parameters.is_object()
            {
                return Err(GatewayError::invalid("tool declaration"));
            }
        }
        let mut pending = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for m in &self.messages {
            match m {
                Message::User { text } | Message::UserImages { text, .. } => {
                    if !pending.is_empty() || text.len() > 1024 * 1024 {
                        return Err(GatewayError::invalid(
                            "unanswered tool calls or user input size",
                        ));
                    }
                }
                Message::Assistant { response } => {
                    if !pending.is_empty() || response.calls.len() > 16 {
                        return Err(GatewayError::invalid("assistant history ordering"));
                    }
                    for c in &response.calls {
                        if c.id.trim().is_empty()
                            || c.id.len() > 256
                            || !valid_tool_name(&c.name)
                            || !seen.insert(c.id.clone())
                            || !pending.insert(c.id.clone())
                        {
                            return Err(GatewayError::invalid(
                                "duplicate or invalid history call identity",
                            ));
                        }
                    }
                }
                Message::ToolResult {
                    call_id, content, ..
                }
                | Message::ToolImages {
                    call_id, content, ..
                } => {
                    if !pending.remove(call_id) || content.len() > 1024 * 1024 {
                        return Err(GatewayError::invalid("unmatched tool result"));
                    }
                }
            }
            if let Message::UserImages { images, .. } | Message::ToolImages { images, .. } = m {
                if images.is_empty() || images.len() > 8 {
                    return Err(GatewayError::invalid("image message capacity"));
                }
                for image in images {
                    image.validate()?;
                }
            }
        }
        if !pending.is_empty() {
            return Err(GatewayError::invalid("missing tool result"));
        }
        // Count without allocating another complete, potentially oversized
        // transcript. The writer rejects before accepting any bytes over quota.
        serde_json::to_writer(&mut HistoryByteLimit(limits.max_history_bytes), self)
            .map_err(|_| GatewayError::invalid("request total bytes"))?;
        Ok(())
    }
}
/// Selected only by the trusted host, never from model/tool-generated JSON.
/// Existing callers retain the2MiB default. This is a bounded in-memory policy,
/// not a token/context estimate, provider maximum guarantee or disk spool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub max_history_bytes: usize,
}
impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_history_bytes: 2 * 1024 * 1024,
        }
    }
}
impl RequestLimits {
    pub const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
    pub fn validate(&self) -> Result<()> {
        if self.max_history_bytes == 0 || self.max_history_bytes > Self::MAX_HISTORY_BYTES {
            return Err(GatewayError::invalid(
                "request history resource policy bounds",
            ));
        }
        Ok(())
    }
}
struct HistoryByteLimit(usize);
impl std::io::Write for HistoryByteLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(std::io::Error::other("request history byte limit"));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[derive(Debug, Clone, Copy)]
pub struct DecoderLimits {
    pub max_event_bytes: usize,
    pub max_total_bytes: usize,
    pub max_output_bytes: usize,
    pub max_tool_calls: usize,
    pub max_argument_bytes: usize,
    pub max_items: usize,
}
impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_event_bytes: 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_output_bytes: 256 * 1024,
            max_tool_calls: 16,
            max_argument_bytes: 256 * 1024,
            max_items: 128,
        }
    }
}
impl DecoderLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_event_bytes == 0
            || self.max_event_bytes > 8 * 1024 * 1024
            || self.max_total_bytes < self.max_event_bytes
            || self.max_total_bytes > 256 * 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 8 * 1024 * 1024
            || self.max_argument_bytes == 0
            || self.max_argument_bytes > 1024 * 1024
            || self.max_tool_calls == 0
            || self.max_tool_calls > 64
            || self.max_items == 0
            || self.max_items > 4096
        {
            return Err(GatewayError::invalid("decoder resource policy bounds"));
        }
        Ok(())
    }
}
