use crate::{
    DecoderLimits, ErrorKind, GatewayError, ModelResponse, Protocol, RequestLimits, Result,
    TurnRequest,
    output_capabilities::{OutputCapabilityRegistration, OutputCapabilityRegistry, OutputMode},
    sse::SseParser,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ApiKey(Zeroizing<String>);
impl ApiKey {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 8192 || !value.bytes().all(|v| v.is_ascii_graphic()) {
            return Err(GatewayError::invalid("invalid credential shape"));
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn from_env(name: &str) -> Result<Self> {
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(GatewayError::invalid("invalid credential variable"));
        }
        Self::new(std::env::var(name).map_err(|_| {
            GatewayError::new(
                ErrorKind::Authentication,
                "configured credential unavailable",
            )
        })?)
    }
}
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey([redacted])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTrust {
    RemoteHttps,
    LoopbackFixture,
}
/// Request extensions are selected by the host, never by model-generated JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderRequestPolicy {
    Standard,
    ReviewedSingleAttempt,
}
#[derive(Clone)]
pub struct ProviderEndpoint {
    pub provider_id: String,
    pub resource_id: String,
    pub authorization_ref: String,
    pub protocol: Protocol,
    pub trust: EndpointTrust,
    pub url: Url,
    key: ApiKey,
    request_policy: ProviderRequestPolicy,
    reviewed_origin: Option<String>,
}
impl std::fmt::Debug for ProviderEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderEndpoint")
            .field("provider_id", &self.provider_id)
            .field("protocol", &self.protocol)
            .field("trust", &self.trust)
            .field("request_policy", &self.request_policy)
            .field("credential", &"[redacted]")
            .finish()
    }
}
impl ProviderEndpoint {
    pub fn validate(&self) -> Result<()> {
        let _ = Self::new(
            self.provider_id.clone(),
            self.resource_id.clone(),
            self.authorization_ref.clone(),
            self.protocol,
            self.trust,
            self.url.as_str(),
            self.key.clone(),
        )?;
        self.validate_request_policy()?;
        Ok(())
    }
    /// Bound The reviewed gateway's internal waterfall to one generation dispatch.
    /// This opt-in does not change the gateway host's separate retry policy.
    pub fn with_single_attempt_origin(mut self, reviewed_origin: &str) -> Result<Self> {
        let origin = Url::parse(reviewed_origin)
            .map_err(|_| GatewayError::invalid("reviewed origin URL"))?;
        if origin.scheme() != "https"
            || origin.path() != "/"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.host_str().is_none()
        {
            return Err(GatewayError::invalid(
                "reviewed origin must be an exact credential-free HTTPS origin",
            ));
        }
        self.reviewed_origin = Some(origin.origin().ascii_serialization());
        self.request_policy = ProviderRequestPolicy::ReviewedSingleAttempt;
        self.validate()?;
        Ok(self)
    }
    fn validate_request_policy(&self) -> Result<()> {
        if self.request_policy == ProviderRequestPolicy::ReviewedSingleAttempt
            && (self.trust != EndpointTrust::RemoteHttps
                || self.protocol != Protocol::OpenAiResponses
                || self.url.scheme() != "https"
                || self.reviewed_origin.as_deref()
                    != Some(self.url.origin().ascii_serialization().as_str())
                || self.url.port_or_known_default() != Some(443)
                || !matches!(self.url.path(), "/v1/responses" | "/api/v1/responses"))
        {
            return Err(GatewayError::invalid(
                "Request policy requires its exact host-reviewed HTTPS Responses origin",
            ));
        }
        Ok(())
    }
    pub fn new(
        provider_id: String,
        resource_id: String,
        authorization_ref: String,
        protocol: Protocol,
        trust: EndpointTrust,
        endpoint: &str,
        key: ApiKey,
    ) -> Result<Self> {
        let url =
            Url::parse(endpoint).map_err(|_| GatewayError::invalid("invalid provider URL"))?;
        if [&provider_id, &resource_id, &authorization_ref]
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > 256 || v.chars().any(char::is_control))
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            return Err(GatewayError::invalid("provider scope or URL components"));
        }
        match trust {
            EndpointTrust::RemoteHttps => {
                if url.scheme() != "https" {
                    return Err(GatewayError::invalid(
                        "remote providers require verified HTTPS",
                    ));
                }
            }
            EndpointTrust::LoopbackFixture => {
                if url.scheme() != "http"
                    || !url
                        .host_str()
                        .and_then(|v| v.parse::<std::net::IpAddr>().ok())
                        .is_some_and(|ip| ip.is_loopback())
                {
                    return Err(GatewayError::invalid(
                        "fixture requires an explicit loopback IP URL",
                    ));
                }
            }
        }
        Ok(Self {
            provider_id,
            resource_id,
            authorization_ref,
            protocol,
            trust,
            url,
            key,
            request_policy: ProviderRequestPolicy::Standard,
            reviewed_origin: None,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    NotSent,
    PossiblySent,
    ResponseReceived,
}
#[derive(Clone)]
pub struct AttemptOutcome {
    pub response: Option<ModelResponse>,
    pub error: Option<GatewayError>,
    pub delivery: Delivery,
    pub http_status: Option<u16>,
    /// Only the provider's bounded request identifier, never arbitrary headers.
    pub provider_request_id: Option<String>,
    pub elapsed_ms: u64,
    pub response_bytes: u64,
    pub retry_after_ms: Option<u64>,
    /// Original bounded response bytes. The legacy field/artifact name also
    /// carries HTTP error JSON; a non-success status is never an SSE response.
    pub raw_sse: Vec<u8>,
}
impl std::fmt::Debug for AttemptOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptOutcome")
            .field("response", &self.response)
            .field("error", &self.error)
            .field("delivery", &self.delivery)
            .field("http_status", &self.http_status)
            .field("response_bytes", &self.response_bytes)
            .field("raw_sse", &"[redacted]")
            .finish()
    }
}
pub struct HttpTransport {
    client: reqwest::Client,
    pub local_only: bool,
    request_limits: RequestLimits,
    json_object_output: bool,
    output_capabilities: OutputCapabilityRegistry,
}
impl HttpTransport {
    pub fn new(local_only: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| {
                GatewayError::new(ErrorKind::Transport, "HTTP client initialization failed")
            })?;
        Ok(Self {
            client,
            local_only,
            request_limits: RequestLimits::default(),
            json_object_output: false,
            output_capabilities: OutputCapabilityRegistry::default(),
        })
    }
    pub fn with_request_limits(mut self, limits: RequestLimits) -> Result<Self> {
        limits.validate()?;
        self.request_limits = limits;
        Ok(self)
    }
    /// Explicit JSON-object transport for providers without native JSON-schema.
    /// The Gateway retains strict schema validation. Never selected as fallback.
    pub fn with_json_object_output(mut self) -> Self {
        self.json_object_output = true;
        self
    }
    pub fn with_output_capabilities(
        mut self,
        records: Vec<OutputCapabilityRegistration>,
    ) -> Result<Self> {
        self.output_capabilities = OutputCapabilityRegistry::new(records)?;
        Ok(self)
    }
    pub fn request_limits(&self) -> RequestLimits {
        self.request_limits
    }
    /// Audit evidence and the actual send use this identical host-selected policy.
    pub fn request_body(
        &self,
        endpoint: &ProviderEndpoint,
        request: &TurnRequest,
    ) -> Result<Value> {
        if request.output_schema.is_some() {
            self.output_capabilities.check_wire(
                endpoint,
                &request.model,
                if self.json_object_output {
                    OutputMode::JsonObject
                } else {
                    OutputMode::NativeJsonSchema
                },
            )?;
        }
        if self.json_object_output
            && let Some(schema) = &request.output_schema
        {
            if endpoint.protocol != Protocol::OpenAiResponses {
                return Err(GatewayError::unsupported(
                    "JSON-object mode requires Responses",
                ));
            }
            crate::schema::validate_schema(schema)?;
            if schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(GatewayError::invalid(
                    "JSON-object mode requires object schema",
                ));
            }
            let mut json_request = request.clone();
            json_request.output_schema = None;
            let mut body = Self::body_with_limits(endpoint, &json_request, self.request_limits)?;
            body["text"] = serde_json::json!({"format":{"type":"json_object"}});
            return Ok(body);
        }
        Self::body_with_limits(endpoint, request, self.request_limits)
    }
    pub fn body(endpoint: &ProviderEndpoint, request: &TurnRequest) -> Result<Value> {
        Self::body_with_limits(endpoint, request, RequestLimits::default())
    }
    pub fn body_with_limits(
        endpoint: &ProviderEndpoint,
        request: &TurnRequest,
        limits: RequestLimits,
    ) -> Result<Value> {
        endpoint.validate()?;
        let mut body = match endpoint.protocol {
            Protocol::OpenAiResponses => crate::openai::build_request_with_limits(request, limits),
            Protocol::AnthropicMessages => {
                crate::anthropic::build_request_with_limits(request, limits)
            }
        }?;
        if endpoint.request_policy == ProviderRequestPolicy::ReviewedSingleAttempt {
            body["gateway"] = serde_json::json!({
                "retry": {
                    "max_attempts_per_route": 1,
                    "max_total_attempts": 1,
                    "backoff": {"type": "none"}
                },
                "routing": {"allow_fallbacks": false}
            });
        }
        Ok(body)
    }
    pub async fn generate(
        &self,
        endpoint: &ProviderEndpoint,
        request: &TurnRequest,
        timeout_ms: u64,
        limits: DecoderLimits,
        cancelled: Arc<AtomicBool>,
    ) -> AttemptOutcome {
        let begin = Instant::now();
        let mut delivery = Delivery::NotSent;
        let mut status = None;
        let mut provider_request_id = None;
        let mut bytes = 0u64;
        let mut retry_after = None;
        let mut raw_sse = Vec::new();
        let result = async {
            if cancelled.load(Ordering::Acquire) {
                return Err(GatewayError::new(
                    ErrorKind::Cancelled,
                    "cancelled before provider request",
                ));
            }
            if timeout_ms == 0 || timeout_ms > 1_800_000 {
                return Err(GatewayError::invalid("provider timeout bounds"));
            }
            endpoint.validate()?;
            limits.validate()?;
            if self.local_only && endpoint.trust != EndpointTrust::LoopbackFixture {
                return Err(GatewayError::unsupported(
                    "local-only gateway cannot contact a remote provider",
                ));
            }
            let body = self.request_body(endpoint, request)?;
            let mut send = self
                .client
                .post(endpoint.url.clone())
                .header("accept", "text/event-stream")
                .json(&body)
                .timeout(Duration::from_millis(timeout_ms));
            send = match endpoint.protocol {
                Protocol::OpenAiResponses => send.bearer_auth(endpoint.key.0.as_str()),
                Protocol::AnthropicMessages => send
                    .header("x-api-key", endpoint.key.0.as_str())
                    .header("anthropic-version", "2023-06-01"),
            };
            delivery = Delivery::PossiblySent;
            let response = match send.send().await {
                Ok(v) => v,
                Err(e) => {
                    if e.is_connect() || e.is_builder() {
                        delivery = Delivery::NotSent;
                    }
                    return Err(GatewayError::new(
                        if e.is_timeout() {
                            ErrorKind::Timeout
                        } else {
                            ErrorKind::Transport
                        },
                        "provider request failed; raw transport details redacted",
                    ));
                }
            };
            delivery = Delivery::ResponseReceived;
            status = Some(response.status().as_u16());
            provider_request_id = ["x-request-id", "request-id"].into_iter().find_map(|name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| {
                        !v.is_empty()
                            && v.len() <= 256
                            && v.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
                    })
                    .map(str::to_owned)
            });
            retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .and_then(|v| v.checked_mul(1000))
                .map(|v| v.min(30_000));
            if !response.status().is_success() {
                // The reviewed gateway's documented HTTP refusal envelope is distinct
                // from a successful SSE refusal. Never infer this from prose,
                // assume zero billing, or turn it into a replayable response.
                if response.status().as_u16() == 400
                    && response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| {
                            v.split(';')
                                .next()
                                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
                        })
                {
                    let bound = limits.max_total_bytes.min(64 * 1024);
                    if response.content_length().is_some_and(|n| n > bound as u64) {
                        return Err(GatewayError::protocol(
                            "provider error envelope exceeds bound",
                        ));
                    }
                    let mut stream = response.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.map_err(|error| {
                            GatewayError::new(
                                if error.is_timeout() {
                                    ErrorKind::Timeout
                                } else {
                                    ErrorKind::Transport
                                },
                                "provider error body interrupted; details redacted",
                            )
                        })?;
                        bytes = bytes
                            .checked_add(chunk.len() as u64)
                            .ok_or_else(|| GatewayError::protocol("response byte overflow"))?;
                        let take = chunk.len().min(bound.saturating_sub(raw_sse.len()));
                        raw_sse.extend_from_slice(&chunk[..take]);
                        if bytes > bound as u64 {
                            return Err(GatewayError::protocol(
                                "provider error envelope exceeds bound",
                            ));
                        }
                    }
                    let envelope = std::str::from_utf8(&raw_sse)
                        .ok()
                        .and_then(|text| crate::strict_json(text).ok());
                    let refused = envelope.as_ref().is_some_and(|value| {
                        value.pointer("/error/code").and_then(Value::as_str) == Some("refusal")
                            && value.pointer("/error/type").and_then(Value::as_str)
                                == Some("invalid_request_error")
                            && value
                                .pointer("/error/refusal_reason")
                                .and_then(Value::as_str)
                                .is_some_and(|reason| {
                                    matches!(
                                        reason,
                                        "cyber_policy"
                                            | "cbrn"
                                            | "content_policy"
                                            | "recitation"
                                            | "data_inspection"
                                            | "unspecified"
                                    )
                                })
                    });
                    return Err(GatewayError::new(
                        if refused {
                            ErrorKind::Refused
                        } else {
                            ErrorKind::Protocol
                        },
                        "provider rejected request; body and credentials redacted",
                    ));
                }
                return Err(GatewayError::new(
                    match response.status().as_u16() {
                        401 | 403 => ErrorKind::Authentication,
                        429 => ErrorKind::RateLimited,
                        500..=599 => ErrorKind::ProviderUnavailable,
                        300..=399 => ErrorKind::Unsupported,
                        _ => ErrorKind::Protocol,
                    },
                    "provider rejected request; body and credentials redacted",
                ));
            }
            if response
                .content_length()
                .is_some_and(|n| n > limits.max_total_bytes as u64)
            {
                return Err(GatewayError::protocol(
                    "provider response Content-Length exceeds bound",
                ));
            }
            if !response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
                })
            {
                return Err(GatewayError::protocol("provider response is not SSE"));
            }
            let mut parser = SseParser::new(limits);
            let mut openai = crate::openai::OpenAiDecoder::new(&request.model, limits);
            let mut anthropic = crate::anthropic::AnthropicDecoder::new(&request.model, limits);
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                if cancelled.load(Ordering::Acquire) {
                    return Err(GatewayError::new(
                        ErrorKind::Cancelled,
                        "provider stream cancelled",
                    ));
                }
                let chunk = chunk.map_err(|e| {
                    GatewayError::new(
                        if e.is_timeout() {
                            ErrorKind::Timeout
                        } else {
                            ErrorKind::Transport
                        },
                        "provider stream interrupted",
                    )
                })?;
                bytes = bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| GatewayError::protocol("response byte overflow"))?;
                let take = chunk
                    .len()
                    .min(limits.max_total_bytes.saturating_sub(raw_sse.len()));
                raw_sse.extend_from_slice(&chunk[..take]);
                for piece in chunk.chunks(16 * 1024) {
                    for event in parser.feed(piece)? {
                        match endpoint.protocol {
                            Protocol::OpenAiResponses => openai.push(&event)?,
                            Protocol::AnthropicMessages => anthropic.push(&event)?,
                        }
                    }
                }
            }
            parser.finish()?;
            match endpoint.protocol {
                Protocol::OpenAiResponses => openai.finish(),
                Protocol::AnthropicMessages => anthropic.finish(),
            }
        };
        let waited = async {
            tokio::select! {result=result=>result,_=wait_cancelled(&cancelled)=>Err(GatewayError::new(ErrorKind::Cancelled,"provider request cancelled")),}
        };
        let result =
            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), waited).await {
                Ok(v) => v,
                Err(_) => Err(GatewayError::new(
                    ErrorKind::Timeout,
                    "provider request deadline expired",
                )),
            };
        let (response, error) = match result {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        AttemptOutcome {
            response,
            error,
            delivery,
            http_status: status,
            provider_request_id,
            elapsed_ms: begin.elapsed().as_millis().min(u64::MAX as u128) as u64,
            response_bytes: bytes,
            retry_after_ms: retry_after,
            raw_sse,
        }
    }
}
pub async fn wait_cancelled(flag: &AtomicBool) {
    while !flag.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
