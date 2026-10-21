//! Real decoder-to-replay integrity checks. Synthetic events; no HTTP or model.
use melissa_model_gateway::{
    DecoderLimits, ErrorKind, Message, ModelResponse, RequestLimits, SseEvent, StopReason,
    ToolDefinition, TurnRequest,
    anthropic::{AnthropicDecoder, build_request, build_request_with_limits},
};
use serde_json::{Value, json};

const MODEL: &str = "owned-claude-history";

fn decoded(blocks: Vec<Value>, reason: &str) -> ModelResponse {
    let mut values = vec![json!({"type":"message_start","message":{
        "id":"msg_owned_history","type":"message","role":"assistant","model":MODEL,
        "content":[],"stop_reason":null,"usage":{"input_tokens":3,"output_tokens":1}
    }})];
    for (index, block) in blocks.into_iter().enumerate() {
        values.push(json!({"type":"content_block_start","index":index,"content_block":block}));
        values.push(json!({"type":"content_block_stop","index":index}));
    }
    values.extend([
        json!({"type":"message_delta","delta":{"stop_reason":reason},"usage":{"output_tokens":12}}),
        json!({"type":"message_stop"}),
    ]);
    let mut decoder = AnthropicDecoder::new(MODEL, DecoderLimits::default());
    for value in values {
        decoder
            .push(&SseEvent {
                event: Some(value["type"].as_str().unwrap().into()),
                data: value.to_string(),
            })
            .unwrap();
    }
    decoder.finish().unwrap()
}

fn replay(response: ModelResponse) -> TurnRequest {
    TurnRequest {
        model: MODEL.into(),
        system_prompt: "Trusted owned fixture".into(),
        messages: vec![
            Message::User {
                text: "owned".into(),
            },
            Message::Assistant { response },
        ],
        tools: vec![ToolDefinition {
            name: "process_exec".into(),
            description: "Owned declaration only".into(),
            parameters: json!({"type":"object","properties":{},"additionalProperties":false}),
            strict: false,
        }],
        max_output_tokens: 393216,
        output_schema: None,
    }
}

fn visible_text(body: &Value) -> String {
    body["messages"][1]["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["type"] == "text")
        .map(|b| b["text"].as_str().unwrap())
        .collect()
}

fn multi_text() -> ModelResponse {
    decoded(
        vec![
            json!({"type":"text","text":"Merhaba ş🦀"}),
            json!({"type":"thinking","thinking":"PRIVATE_REASONING","signature":"opaque_signed_ş🦀"}),
            json!({"type":"redacted_thinking","data":"opaque_redacted_ownership"}),
            json!({"type":"text","text":"\nİkinci parça"}),
        ],
        "end_turn",
    )
}

#[test]
fn multi_text_and_opaque_blocks_replay_exactly_under_both_history_policies() {
    let response = multi_text();
    assert_eq!(response.text, "Merhaba ş🦀\nİkinci parça");
    let expected_blocks = response.continuation.clone();
    let expected_text = response.text.clone();
    let request = replay(response);
    for body in [
        build_request(&request).unwrap(),
        build_request_with_limits(
            &request,
            RequestLimits {
                max_history_bytes: 48 * 1024 * 1024,
            },
        )
        .unwrap(),
    ] {
        assert_eq!(body["messages"][1]["content"], json!(expected_blocks));
        assert_eq!(visible_text(&body), expected_text);
        assert_eq!(
            body["messages"][1]["content"][1]["signature"],
            "opaque_signed_ş🦀"
        );
        assert_eq!(
            body["messages"][1]["content"][2]["data"],
            "opaque_redacted_ownership"
        );
    }
}

#[test]
fn serialized_normalized_text_and_native_text_cannot_disagree_on_replay() {
    for variant in ["normalized", "native", "reordered", "prefix"] {
        let mut response = multi_text();
        match variant {
            "normalized" => response.text.push_str(" forged"),
            "native" => response.continuation[0]["text"] = json!("forged"),
            "reordered" => response.continuation.swap(0, 3),
            _ => response.text.insert_str(0, "forged "),
        }
        // Exercise the public persisted/host-supplied ModelResponse boundary.
        let response: ModelResponse =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
        let normalized = response.text.clone();
        let request = replay(response);
        let built = build_request(&request);
        if let Ok(body) = &built {
            eprintln!(
                "PARITY_BASELINE_ACCEPTED {}",
                json!({
                "variant":variant,"normalized_text":normalized,"wire_text":visible_text(body),
                "scope":"host_replay_integrity_not_model_authority_or_live_call"})
            );
        }
        let error = built.expect_err("normalized/native disagreement must be rejected");
        assert_eq!(error.kind, ErrorKind::Invalid);
        assert!(
            build_request_with_limits(
                &request,
                RequestLimits {
                    max_history_bytes: 48 * 1024 * 1024
                }
            )
            .is_err()
        );
    }
}

#[test]
fn reasoning_is_never_merged_into_normalized_visible_text() {
    let response = decoded(
        vec![
            json!({"type":"thinking","thinking":"PRIVATE_REASONING","signature":"opaque"}),
            json!({"type":"redacted_thinking","data":"opaque_redacted"}),
        ],
        "end_turn",
    );
    assert!(response.text.is_empty());
    let body = build_request(&replay(response.clone())).unwrap();
    assert!(visible_text(&body).is_empty());
    let mut forged = response;
    forged.text = "PRIVATE_REASONING".into();
    assert!(build_request(&replay(forged)).is_err());
}

#[test]
fn contradictory_normalized_refusal_and_actual_refusals_are_not_replayable() {
    let actual = decoded(
        vec![json!({"type":"text","text":"owned refusal fixture"})],
        "refusal",
    );
    assert_eq!(actual.stop, StopReason::Refusal);
    assert!(actual.refusal.is_some());
    assert!(actual.continuation.is_empty());
    assert!(build_request(&replay(actual)).is_err());
    let mut forged = multi_text();
    forged.refusal = Some("contradictory normalized refusal".into());
    assert!(build_request(&replay(forged)).is_err());
}

#[test]
fn tool_observation_ordering_and_native_call_identity_remain_enforced() {
    let response = decoded(
        vec![
            json!({"type":"text","text":"owned tool request"}),
            json!({"type":"thinking","thinking":"private","signature":"opaque_signature"}),
            json!({"type":"tool_use","id":"toolu_owned","name":"process_exec","input":{}}),
        ],
        "tool_use",
    );
    let expected = response.continuation.clone();
    let mut request = replay(response);
    request.messages.push(Message::ToolResult {
        call_id: "toolu_owned".into(),
        content: "owned observation 🦀".into(),
        is_error: false,
    });
    let body = build_request(&request).unwrap();
    assert_eq!(body["messages"][1]["content"], json!(expected));
    assert_eq!(
        body["messages"][2]["content"][0]["tool_use_id"],
        "toolu_owned"
    );
    assert_eq!(
        body["messages"][2]["content"][0]["content"],
        "owned observation 🦀"
    );
    let mut missing = request.clone();
    missing.messages.pop();
    assert!(build_request(&missing).is_err());
    let mut interleaved = request.clone();
    interleaved.messages.insert(
        2,
        Message::User {
            text: "out of order".into(),
        },
    );
    assert!(build_request(&interleaved).is_err());
    let Message::Assistant { response } = &mut request.messages[1] else {
        unreachable!()
    };
    response.calls[0].arguments = "{\"forged\":true}".into();
    assert!(build_request(&request).is_err());
}
