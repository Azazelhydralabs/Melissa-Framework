//! Actual loopback HTTP fixtures. These tests never use a live model service.
use melissa_model_gateway::routing::{
    Capabilities, Measurements, ModelRegistration, PriceSource, RateCard, RouteRequirements,
    select_routes,
};
use melissa_model_gateway::transport::{
    ApiKey, Delivery, EndpointTrust, HttpTransport, ProviderEndpoint,
};
use melissa_model_gateway::{DecoderLimits, ErrorKind, Message, Protocol, StopReason, TurnRequest};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};

struct Captured {
    headers: String,
    body: Value,
}
struct Fixture {
    url: String,
    captured: oneshot::Receiver<Captured>,
    task: JoinHandle<()>,
}
struct Plan {
    status: u16,
    content_type: &'static str,
    extra_headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunked: bool,
    fragment: usize,
    before_headers: Duration,
    before_body: Duration,
}
impl Plan {
    fn sse(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "text/event-stream; charset=utf-8",
            extra_headers: vec![],
            body,
            chunked: false,
            fragment: usize::MAX,
            before_headers: Duration::ZERO,
            before_body: Duration::ZERO,
        }
    }
}

async fn fixture(plan: Plan) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, captured) = oneshot::channel();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut bytes = Vec::new();
        let mut temporary = [0u8; 4096];
        let header_end = loop {
            let count = socket.read(&mut temporary).await.unwrap();
            if count == 0 {
                return;
            }
            bytes.extend_from_slice(&temporary[..count]);
            if let Some(index) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(bytes.len() <= 64 * 1024);
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(length <= 2 * 1024 * 1024);
        while bytes.len() - header_end < length {
            let count = socket.read(&mut temporary).await.unwrap();
            if count == 0 {
                return;
            }
            bytes.extend_from_slice(&temporary[..count]);
        }
        let body = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
        let _ = sender.send(Captured { headers, body });
        tokio::time::sleep(plan.before_headers).await;
        let mut header = format!(
            "HTTP/1.1 {} Fixture\r\nContent-Type: {}\r\nConnection: close\r\n",
            plan.status, plan.content_type
        );
        if plan.chunked {
            header.push_str("Transfer-Encoding: chunked\r\n");
        } else {
            header.push_str(&format!("Content-Length: {}\r\n", plan.body.len()));
        }
        for (name, value) in &plan.extra_headers {
            header.push_str(&format!("{name}: {value}\r\n"));
        }
        header.push_str("\r\n");
        for part in header.as_bytes().chunks(plan.fragment.max(1)) {
            if socket.write_all(part).await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(plan.before_body).await;
        for part in plan.body.chunks(plan.fragment.max(1)) {
            if plan.chunked
                && socket
                    .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await
                    .is_err()
            {
                return;
            }
            if socket.write_all(part).await.is_err() {
                return;
            }
            if plan.chunked && socket.write_all(b"\r\n").await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
        if plan.chunked {
            let _ = socket.write_all(b"0\r\n\r\n").await;
        }
        let _ = socket.shutdown().await;
    });
    Fixture {
        url: format!("http://{address}/v1/messages"),
        captured,
        task,
    }
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "configured-fixture-model".into(),
        system_prompt: "host instruction".into(),
        messages: vec![Message::User {
            text: "local fixture request".into(),
        }],
        tools: vec![],
        max_output_tokens: 128,
        output_schema: None,
    }
}
fn endpoint(protocol: Protocol, url: &str) -> ProviderEndpoint {
    ProviderEndpoint::new(
        "fixture-provider".into(),
        "fixture-resource".into(),
        "fixture-authorization".into(),
        protocol,
        EndpointTrust::LoopbackFixture,
        url,
        ApiKey::new("LOCAL_FIXTURE_CREDENTIAL".into()).unwrap(),
    )
    .unwrap()
}
fn anthropic_events() -> Vec<Value> {
    vec![
        json!({"type":"message_start","message":{"type":"message","role":"assistant","id":"msg_fixture","model":"served-fixture","content":[],"stop_reason":null,"usage":{"input_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ş😀"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),
        json!({"type":"message_stop"}),
    ]
}
fn openai_events() -> Vec<Value> {
    let part = json!({"type":"output_text","text":"ş😀","annotations":[],"logprobs":[]});
    let item = json!({"type":"message","id":"msg_fixture","role":"assistant","status":"completed","content":[part]});
    let mut values = vec![
        json!({"type":"response.created","response":{"id":"resp_fixture","model":"served-fixture","status":"in_progress","output":[]}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_fixture","role":"assistant","status":"in_progress","content":[]}}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_fixture","content_index":0,"part":{"type":"output_text","text":"","annotations":[],"logprobs":[]}}),
        json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg_fixture","content_index":0,"delta":"ş😀"}),
        json!({"type":"response.output_text.done","output_index":0,"item_id":"msg_fixture","content_index":0,"text":"ş😀"}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_fixture","content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
        json!({"type":"response.completed","response":{"id":"resp_fixture","model":"served-fixture","status":"completed","error":null,"incomplete_details":null,"output":[item],"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}}),
    ];
    for (index, value) in values.iter_mut().enumerate() {
        value["sequence_number"] = json!(index);
    }
    values
}
fn wire(events: &[Value]) -> Vec<u8> {
    let mut text = String::new();
    for value in events {
        text.push_str(&format!(
            "event: {}\r\ndata: {}\r\n\r\n",
            value["type"].as_str().unwrap(),
            value
        ));
    }
    text.into_bytes()
}
async fn generate(
    endpoint: &ProviderEndpoint,
    timeout: u64,
    limits: DecoderLimits,
    cancel: Arc<AtomicBool>,
) -> melissa_model_gateway::transport::AttemptOutcome {
    HttpTransport::new(true)
        .unwrap()
        .generate(endpoint, &request(), timeout, limits, cancel)
        .await
}

#[tokio::test]
async fn both_actual_http_protocols_preserve_fragmented_unicode_and_authentication_scope() {
    for (protocol, events) in [
        (Protocol::AnthropicMessages, anthropic_events()),
        (Protocol::OpenAiResponses, openai_events()),
    ] {
        let mut plan = Plan::sse(wire(&events));
        plan.fragment = 3;
        plan.chunked = true;
        let fixture = fixture(plan).await;
        let endpoint = endpoint(protocol, &fixture.url);
        let result = generate(
            &endpoint,
            3000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(
            result.error.is_none(),
            "sanitized result: {:?}",
            result.error
        );
        let response = result.response.unwrap();
        assert_eq!(response.text, "ş😀");
        assert_eq!(response.stop, StopReason::EndTurn);
        assert_eq!(result.delivery, Delivery::ResponseReceived);
        assert_eq!(result.http_status, Some(200));
        assert!(result.response_bytes > 0);
        let captured = fixture.captured.await.unwrap();
        let lower = captured.headers.to_ascii_lowercase();
        match protocol {
            Protocol::AnthropicMessages => {
                assert!(lower.contains("x-api-key: local_fixture_credential"));
                assert!(lower.contains("anthropic-version: 2023-06-01"));
                assert!(!lower.contains("authorization:"));
            }
            Protocol::OpenAiResponses => {
                assert!(lower.contains("authorization: bearer local_fixture_credential"));
                assert!(!lower.contains("x-api-key:"));
            }
        }
        assert_eq!(captured.body["model"], "configured-fixture-model");
        assert_eq!(captured.body["stream"], true);
        assert!(!format!("{endpoint:?}").contains("LOCAL_FIXTURE_CREDENTIAL"));
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn broken_json_truncated_sse_and_missing_terminal_never_yield_a_response() {
    let mut truncated = anthropic_events();
    truncated.pop();
    for body in [
        b"event: message_start\ndata: {broken}\n\n".to_vec(),
        b"event: message_stop\ndata: {}".to_vec(),
        wire(&truncated),
    ] {
        let fixture = fixture(Plan::sse(body)).await;
        let result = generate(
            &endpoint(Protocol::AnthropicMessages, &fixture.url),
            1000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(result.response.is_none());
        assert_eq!(result.error.unwrap().kind, ErrorKind::Protocol);
        assert_eq!(result.delivery, Delivery::ResponseReceived);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn complete_argument_fragment_without_message_terminal_is_never_a_callable_response() {
    let values = vec![
        anthropic_events()[0].clone(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_partial","name":"process_exec","input":{}}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"argv\":[\"test\"]}"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":10}}),
    ];
    let fixture = fixture(Plan::sse(wire(&values))).await;
    let result = generate(
        &endpoint(Protocol::AnthropicMessages, &fixture.url),
        1000,
        DecoderLimits::default(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert!(result.response.is_none());
    assert_eq!(result.error.unwrap().kind, ErrorKind::Protocol);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn content_type_and_body_size_are_checked_before_protocol_results_are_exposed() {
    for (content_type, maximum) in [
        ("application/json", 8 * 1024 * 1024),
        ("text/event-stream", 10),
    ] {
        let mut plan = Plan::sse(wire(&anthropic_events()));
        plan.content_type = content_type;
        let fixture = fixture(plan).await;
        let result = generate(
            &endpoint(Protocol::AnthropicMessages, &fixture.url),
            1000,
            DecoderLimits {
                max_total_bytes: maximum,
                max_event_bytes: maximum.min(1024 * 1024),
                ..DecoderLimits::default()
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(result.response.is_none());
        assert_eq!(result.error.unwrap().kind, ErrorKind::Protocol);
        fixture.task.await.unwrap();
    }
    let mut plan = Plan::sse(vec![b' '; 2048]);
    plan.chunked = true;
    plan.fragment = 64;
    let fixture = fixture(plan).await;
    let result = generate(
        &endpoint(Protocol::AnthropicMessages, &fixture.url),
        1000,
        DecoderLimits {
            max_total_bytes: 1024,
            max_event_bytes: 1024,
            ..DecoderLimits::default()
        },
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert!(result.response.is_none());
    assert_eq!(result.error.unwrap().kind, ErrorKind::Protocol);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn http_refusal_envelopes_require_exact_code_type_reason_and_complete_bounded_json() {
    let valid = json!({"error":{"message":"PRIVATE_REFUSAL_PROSE","type":"invalid_request_error","code":"refusal","refusal_reason":"content_policy"}});
    for protocol in [Protocol::OpenAiResponses, Protocol::AnthropicMessages] {
        for reason in [
            "cyber_policy",
            "cbrn",
            "content_policy",
            "recitation",
            "data_inspection",
            "unspecified",
        ] {
            let mut value = valid.clone();
            value["error"]["refusal_reason"] = json!(reason);
            let body = serde_json::to_vec(&value).unwrap();
            let mut plan = Plan::sse(body.clone());
            plan.status = 400;
            plan.content_type = "Application/JSON; charset=utf-8";
            plan.fragment = 7;
            plan.chunked = true;
            let http = fixture(plan).await;
            let outcome = generate(
                &endpoint(protocol, &http.url),
                5000,
                DecoderLimits::default(),
                Arc::new(AtomicBool::new(false)),
            )
            .await;
            assert_eq!(outcome.error.as_ref().unwrap().kind, ErrorKind::Refused);
            assert!(outcome.response.is_none());
            assert_eq!(outcome.delivery, Delivery::ResponseReceived);
            assert_eq!(outcome.raw_sse, body);
            assert_eq!(outcome.response_bytes, body.len() as u64);
            assert!(!format!("{outcome:?}").contains("PRIVATE_REFUSAL_PROSE"));
            http.task.await.unwrap();
        }
    }
    let mut negatives = Vec::new();
    for (field, value) in [
        ("code", json!("invalid_parameter")),
        ("type", json!("server_error")),
        ("refusal_reason", json!("future_unknown")),
        ("refusal_reason", Value::Null),
    ] {
        let mut bad = valid.clone();
        bad["error"][field] = value;
        negatives.push(serde_json::to_vec(&bad).unwrap());
    }
    negatives.push(br#"{"error":{"code":"other","code":"refusal","type":"invalid_request_error","refusal_reason":"content_policy"}}"#.to_vec());
    negatives.push(br#"{"error":{"code":"refusal","type":"invalid_request_error","refusal_reason":"content_policy"}"#.to_vec());
    negatives.push(br#"{"message":"refusal content_policy PRIVATE_REFUSAL_PROSE"}"#.to_vec());
    negatives.push([serde_json::to_vec(&valid).unwrap(), b" trailing".to_vec()].concat());
    for body in negatives {
        let mut plan = Plan::sse(body);
        plan.status = 400;
        plan.content_type = "application/json";
        let http = fixture(plan).await;
        let outcome = generate(
            &endpoint(Protocol::OpenAiResponses, &http.url),
            5000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(outcome.error.as_ref().unwrap().kind, ErrorKind::Protocol);
        assert!(outcome.response.is_none());
        assert!(!format!("{outcome:?}").contains("PRIVATE_REFUSAL_PROSE"));
        http.task.await.unwrap();
    }
}

#[tokio::test]
async fn http_error_json_keeps_body_quotas_timeout_and_cancellation() {
    for chunked in [false, true] {
        let mut plan = Plan::sse(vec![b'x'; 65537]);
        plan.status = 400;
        plan.content_type = "application/json";
        plan.chunked = chunked;
        let http = fixture(plan).await;
        let outcome = generate(
            &endpoint(Protocol::OpenAiResponses, &http.url),
            5000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(outcome.error.as_ref().unwrap().kind, ErrorKind::Protocol);
        assert!(outcome.response.is_none() && outcome.raw_sse.len() <= 65536);
        http.task.await.unwrap();
    }
    for cancel in [false, true] {
        let mut plan = Plan::sse(br#"{"error":{"code":"refusal","type":"invalid_request_error","refusal_reason":"unspecified"}}"#.to_vec());
        plan.status = 400;
        plan.content_type = "application/json";
        plan.before_body = Duration::from_secs(5);
        let http = fixture(plan).await;
        let flag = Arc::new(AtomicBool::new(false));
        let captured = http.captured;
        let cancelled = Arc::clone(&flag);
        let signal = tokio::spawn(async move {
            captured.await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            if cancel {
                cancelled.store(true, Ordering::Release);
            }
        });
        let outcome = generate(
            &endpoint(Protocol::OpenAiResponses, &http.url),
            if cancel { 5000 } else { 300 },
            DecoderLimits::default(),
            flag,
        )
        .await;
        assert_eq!(
            outcome.error.as_ref().unwrap().kind,
            if cancel {
                ErrorKind::Cancelled
            } else {
                ErrorKind::Timeout
            }
        );
        assert!(outcome.response.is_none());
        assert_ne!(outcome.delivery, Delivery::NotSent);
        signal.await.unwrap();
        http.task.abort();
    }
}

#[tokio::test]
async fn http_rejections_are_typed_retry_after_is_bounded_and_error_bodies_are_redacted() {
    for (status, expected) in [
        (401, ErrorKind::Authentication),
        (403, ErrorKind::Authentication),
        (429, ErrorKind::RateLimited),
        (500, ErrorKind::ProviderUnavailable),
        (529, ErrorKind::ProviderUnavailable),
        (400, ErrorKind::Protocol),
    ] {
        let mut plan = Plan::sse(b"PRIVATE_PROVIDER_BODY".to_vec());
        plan.status = status;
        plan.extra_headers
            .push(("Retry-After".into(), "9999999".into()));
        let fixture = fixture(plan).await;
        let result = generate(
            &endpoint(Protocol::AnthropicMessages, &fixture.url),
            1000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(result.http_status, Some(status));
        assert_eq!(result.retry_after_ms, Some(30_000));
        let error = result.error.unwrap();
        assert_eq!(error.kind, expected);
        assert!(!error.to_string().contains("PRIVATE_PROVIDER_BODY"));
        assert!(result.response.is_none());
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn provider_request_id_headers_are_bounded_and_never_appear_in_debug_or_raw_auth_headers() {
    for name in ["x-request-id", "request-id"] {
        for (value, accepted) in [
            ("req_PRIVATE_PROVIDER_ID:fixture/1".to_owned(), true),
            ("r".repeat(256), true),
            ("r".repeat(257), false),
            ("req invalid whitespace".to_owned(), false),
            ("req@invalid-character".to_owned(), false),
        ] {
            let mut plan = Plan::sse(wire(&anthropic_events()));
            plan.extra_headers.push((name.into(), value.clone()));
            plan.extra_headers.push((
                "Authorization".into(),
                "Bearer PRIVATE_RESPONSE_AUTH_HEADER".into(),
            ));
            let fixture = fixture(plan).await;
            let result = generate(
                &endpoint(Protocol::AnthropicMessages, &fixture.url),
                1000,
                DecoderLimits::default(),
                Arc::new(AtomicBool::new(false)),
            )
            .await;
            assert!(result.error.is_none());
            assert_eq!(
                result.provider_request_id.as_deref(),
                accepted.then_some(value.as_str())
            );
            let debug = format!("{result:?}");
            assert!(!debug.contains(&value));
            assert!(!debug.contains("PRIVATE_RESPONSE_AUTH_HEADER"));
            assert!(!debug.contains("LOCAL_FIXTURE_CREDENTIAL"));
            fixture.task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_credentials_do_not_reach_the_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let mut plan = Plan::sse(Vec::new());
    plan.status = 307;
    plan.extra_headers.push((
        "Location".into(),
        format!("http://{address}/credential-sink"),
    ));
    let fixture = fixture(plan).await;
    let result = generate(
        &endpoint(Protocol::OpenAiResponses, &fixture.url),
        1000,
        DecoderLimits::default(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(result.error.unwrap().kind, ErrorKind::Unsupported);
    assert_eq!(result.http_status, Some(307));
    assert!(
        tokio::time::timeout(Duration::from_millis(60), target.accept())
            .await
            .is_err()
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn cancellation_interrupts_stalled_headers_and_stalled_body() {
    for stalled_headers in [true, false] {
        let mut plan = Plan::sse(wire(&anthropic_events()));
        if stalled_headers {
            plan.before_headers = Duration::from_secs(2);
        } else {
            plan.before_body = Duration::from_secs(2);
        }
        let fixture = fixture(plan).await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            flag.store(true, Ordering::Release);
        });
        let result = generate(
            &endpoint(Protocol::AnthropicMessages, &fixture.url),
            1000,
            DecoderLimits::default(),
            cancelled,
        )
        .await;
        assert_eq!(result.error.unwrap().kind, ErrorKind::Cancelled);
        assert!(result.elapsed_ms < 700);
        assert!(result.response.is_none());
        fixture.task.abort();
    }
}

#[tokio::test]
async fn absolute_deadline_covers_waiting_for_headers_and_body() {
    for stalled_headers in [true, false] {
        let mut plan = Plan::sse(wire(&anthropic_events()));
        if stalled_headers {
            plan.before_headers = Duration::from_secs(2);
        } else {
            plan.before_body = Duration::from_secs(2);
        }
        let fixture = fixture(plan).await;
        let result = generate(
            &endpoint(Protocol::AnthropicMessages, &fixture.url),
            60,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(result.error.unwrap().kind, ErrorKind::Timeout);
        assert!(result.elapsed_ms < 700);
        assert!(result.response.is_none());
        fixture.task.abort();
    }
}

#[tokio::test]
async fn pre_cancel_invalid_request_and_remote_endpoint_are_not_sent() {
    let fixture = fixture(Plan::sse(wire(&anthropic_events()))).await;
    let endpoint = endpoint(Protocol::AnthropicMessages, &fixture.url);
    let result = generate(
        &endpoint,
        1000,
        DecoderLimits::default(),
        Arc::new(AtomicBool::new(true)),
    )
    .await;
    assert_eq!(result.delivery, Delivery::NotSent);
    assert_eq!(result.error.unwrap().kind, ErrorKind::Cancelled);
    let mut invalid = request();
    invalid.model.clear();
    let result = HttpTransport::new(true)
        .unwrap()
        .generate(
            &endpoint,
            &invalid,
            1000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
    assert_eq!(result.delivery, Delivery::NotSent);
    assert_eq!(result.error.unwrap().kind, ErrorKind::Invalid);
    let remote = ProviderEndpoint::new(
        "remote".into(),
        "resource".into(),
        "auth".into(),
        Protocol::AnthropicMessages,
        EndpointTrust::RemoteHttps,
        "https://example.invalid/v1/messages",
        ApiKey::new("LOCAL_FIXTURE_CREDENTIAL".into()).unwrap(),
    )
    .unwrap();
    let result = generate(
        &remote,
        1000,
        DecoderLimits::default(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert_eq!(result.delivery, Delivery::NotSent);
    assert_eq!(result.error.unwrap().kind, ErrorKind::Unsupported);
    fixture.task.abort();
}

#[tokio::test]
async fn mutable_endpoint_configuration_is_revalidated_before_any_request() {
    let mut endpoint = endpoint(
        Protocol::AnthropicMessages,
        "http://127.0.0.1:1/v1/messages",
    );
    for url in [
        "https://example.invalid/v1/messages",
        "http://127.0.0.1:1/v1/messages?injected=true",
    ] {
        endpoint.url = url::Url::parse(url).unwrap();
        let result = generate(
            &endpoint,
            1000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(result.delivery, Delivery::NotSent);
        assert_eq!(result.error.unwrap().kind, ErrorKind::Invalid);
    }
}

#[test]
fn endpoint_credentials_query_fragment_scheme_and_dns_fixture_alias_are_rejected() {
    for url in [
        "http://user:password@127.0.0.1:1/x",
        "http://127.0.0.1:1/x?credential=x",
        "http://127.0.0.1:1/x#fragment",
        "https://127.0.0.1:1/x",
        "http://localhost:1/x",
        "http://192.0.2.1:1/x",
    ] {
        assert!(
            ProviderEndpoint::new(
                "p".into(),
                "r".into(),
                "a".into(),
                Protocol::AnthropicMessages,
                EndpointTrust::LoopbackFixture,
                url,
                ApiKey::new("local".into()).unwrap()
            )
            .is_err()
        );
    }
    assert!(ApiKey::new("header\r\ninjection".into()).is_err());
    assert!(
        !format!(
            "{:?}",
            ApiKey::new("LOCAL_FIXTURE_CREDENTIAL".into()).unwrap()
        )
        .contains("LOCAL_FIXTURE_CREDENTIAL")
    );
}

#[test]
fn environment_proxies_are_ignored_without_mutating_the_parallel_test_environment() {
    const CHILD: &str = "MELISSA_FIXTURE_PROXY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let fixture = fixture(Plan::sse(wire(&anthropic_events()))).await;
            let result = generate(
                &endpoint(Protocol::AnthropicMessages, &fixture.url),
                1000,
                DecoderLimits::default(),
                Arc::new(AtomicBool::new(false)),
            )
            .await;
            assert!(result.error.is_none());
            assert_eq!(result.response.unwrap().text, "ş😀");
            fixture.task.await.unwrap();
        });
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "environment_proxies_are_ignored_without_mutating_the_parallel_test_environment",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "proxy isolation child failed without emitting captured credentials"
    );
}

fn rate(source: PriceSource) -> RateCard {
    RateCard {
        source,
        input_micro_usd_per_million: 1_000_000,
        output_micro_usd_per_million: 2_000_000,
        cached_input_micro_usd_per_million: Some(100_000),
        cache_creation_micro_usd_per_million: Some(1_250_000),
    }
}
fn model(id: &str) -> ModelRegistration {
    ModelRegistration {
        registration_id: id.into(),
        endpoint: endpoint(
            Protocol::AnthropicMessages,
            "http://127.0.0.1:1/v1/messages",
        ),
        model_id: id.into(),
        capabilities: Capabilities {
            tool_calling: true,
            structured_output: true,
            vision: false,
            streaming: true,
        },
        categories: BTreeSet::from(["code".into()]),
        context_tokens: 4096,
        max_output_tokens: 256,
        timeout_ms: 1000,
        max_concurrency: 2,
        rate_card: Some(rate(PriceSource::Fixture)),
        measurements: Measurements::default(),
        slots: Arc::new(Semaphore::new(2)),
    }
}
fn requirements() -> RouteRequirements {
    RouteRequirements {
        category: "code".into(),
        tools: true,
        structured_output: true,
        vision: false,
        minimum_success_ppm: None,
        maximum_p95_ms: None,
    }
}

#[test]
fn routing_filters_authority_capability_category_and_unmeasured_quality() {
    let mut good = model("good");
    good.measurements.task_success_ppm = Some(950_000);
    good.measurements.p95_latency_ms = Some(100);
    let mut incapable = model("incapable");
    incapable.capabilities.tool_calling = false;
    let unknown = model("unknown");
    let mut unauthorized = model("unauthorized");
    unauthorized.measurements.task_success_ppm = Some(1_000_000);
    let models = vec![unknown, incapable, good, unauthorized];
    let allowed = BTreeSet::from(["unknown".into(), "incapable".into(), "good".into()]);
    let mut wanted = requirements();
    wanted.minimum_success_ppm = Some(900_000);
    wanted.maximum_p95_ms = Some(200);
    assert_eq!(select_routes(&models, &wanted, &allowed).unwrap(), vec![2]);
    wanted.category = "science".into();
    assert!(select_routes(&models, &wanted, &allowed).is_err());
    wanted = requirements();
    wanted.vision = true;
    assert!(select_routes(&models, &wanted, &allowed).is_err());
    assert_eq!(models[0].measurements, Measurements::default());
}

#[test]
fn routing_ties_are_stable_and_duplicate_registration_or_impossible_measurements_fail() {
    let models = vec![model("b"), model("a")];
    let allowed = BTreeSet::from(["a".into(), "b".into()]);
    assert_eq!(
        select_routes(&models, &requirements(), &allowed).unwrap(),
        vec![1, 0]
    );
    assert!(select_routes(&[model("a"), model("a")], &requirements(), &allowed).is_err());
    let mut invalid = model("a");
    invalid.measurements.availability_ppm = Some(1_000_001);
    assert!(invalid.validate().is_err());
    invalid = model("a");
    invalid.slots = Arc::new(Semaphore::new(3));
    assert!(invalid.validate().is_err());
}

#[test]
fn fixture_prices_cannot_be_promoted_to_remote_and_unknown_usage_is_not_free() {
    let remote = ProviderEndpoint::new(
        "remote".into(),
        "resource".into(),
        "auth".into(),
        Protocol::AnthropicMessages,
        EndpointTrust::RemoteHttps,
        "https://example.invalid/v1/messages",
        ApiKey::new("local".into()).unwrap(),
    )
    .unwrap();
    assert!(rate(PriceSource::Fixture).validate(&remote).is_err());
    let verified = rate(PriceSource::VerifiedHostRateCard {
        source_url: "https://provider.example.invalid/pricing".into(),
        checked_at_unix_ms: 1,
    });
    verified.validate(&remote).unwrap();
    assert_eq!(
        verified.usage_upper_bound(&Default::default()).unwrap(),
        None
    );
    assert_eq!(verified.upper_bound(100, 10).unwrap(), 145);
    assert_ne!(verified.digest(), rate(PriceSource::Fixture).digest());
}
