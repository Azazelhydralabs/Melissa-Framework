use melissa_model_gateway::anthropic::{AnthropicDecoder, build_request};
use melissa_model_gateway::{
    DecoderLimits, ErrorKind, Message, ModelResponse, Protocol, SseEvent, StopReason,
    ToolDefinition, TurnRequest,
};
use serde_json::{Value, json};

fn event(value: Value) -> SseEvent {
    SseEvent {
        event: Some(value["type"].as_str().unwrap().into()),
        data: value.to_string(),
    }
}

fn start() -> Value {
    json!({"type":"message_start","message":{
        "id":"msg_local_fixture", "type":"message", "role":"assistant",
        "model":"served-claude-snapshot", "content":[], "stop_reason":null,
        "usage":{"input_tokens":12,"cache_read_input_tokens":5,"cache_creation_input_tokens":3,"output_tokens":1}
    }})
}

fn terminal(reason: &str, output: u64) -> Vec<Value> {
    vec![
        json!({"type":"message_delta","delta":{"stop_reason":reason},"usage":{"output_tokens":output}}),
        json!({"type":"message_stop"}),
    ]
}

fn block(index: usize, value: Value) -> Vec<Value> {
    vec![
        json!({"type":"content_block_start","index":index,"content_block":value}),
        json!({"type":"content_block_stop","index":index}),
    ]
}

fn tool_stream(arguments: &[&str], reason: &str) -> Vec<Value> {
    let mut events = vec![
        start(),
        json!({"type":"content_block_start","index":0,
        "content_block":{"type":"tool_use","id":"toolu_local_1","name":"process_exec","input":{}}}),
    ];
    for partial in arguments {
        events.push(json!({"type":"content_block_delta","index":0,
            "delta":{"type":"input_json_delta","partial_json":partial}}));
    }
    events.push(json!({"type":"content_block_stop","index":0}));
    events.extend(terminal(reason, 23));
    events
}

fn decode(values: Vec<Value>) -> melissa_model_gateway::Result<ModelResponse> {
    let mut decoder = AnthropicDecoder::new("configured-claude", DecoderLimits::default());
    for value in values {
        decoder.push(&event(value))?;
    }
    decoder.finish()
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "configured-claude".into(),
        system_prompt: "Trusted host instruction".into(),
        messages: vec![Message::User {
            text: "Run the selected build".into(),
        }],
        tools: vec![ToolDefinition {
            name: "process_exec".into(),
            description: "Bounded host process request".into(),
            parameters: json!({"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}}},"required":["argv"],"additionalProperties":false}),
            strict: true,
        }],
        max_output_tokens: 256,
        output_schema: None,
    }
}

#[test]
fn text_stream_is_terminal_gated_and_records_requested_and_served_model() {
    let mut values = vec![
        start(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
    ];
    for text in ["Merhaba ", "dostum", " 🦀"] {
        values.push(json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}}));
        values.push(json!({"type":"ping"}));
    }
    values.push(json!({"type":"content_block_stop","index":0}));
    values.extend(terminal("end_turn", 17));
    let response = decode(values).unwrap();
    assert_eq!(response.text, "Merhaba dostum 🦀");
    assert_eq!(response.stop, StopReason::EndTurn);
    assert_eq!(response.requested_model, "configured-claude");
    assert_eq!(response.model, "served-claude-snapshot");
    assert_eq!(response.response_id, "msg_local_fixture");
    assert_eq!(response.usage.input_tokens, Some(20));
    assert_eq!(response.usage.output_tokens, Some(17));
    assert_eq!(response.continuation[0]["text"], response.text);
}

#[test]
fn every_incomplete_tool_stream_prefix_fails_without_a_callable_response() {
    let values = tool_stream(&["{\"argv\":[", "\"test\"]}"], "tool_use");
    for length in 0..values.len() {
        assert!(
            decode(values[..length].to_vec()).is_err(),
            "prefix {length}"
        );
    }
    let response = decode(values).unwrap();
    assert_eq!(response.stop, StopReason::ToolCalls);
    assert_eq!(response.calls.len(), 1);
    assert_eq!(response.calls[0].name, "process_exec");
    assert_eq!(
        serde_json::from_str::<Value>(&response.calls[0].arguments).unwrap(),
        json!({"argv":["test"]})
    );
}

#[test]
fn parallel_client_calls_preserve_order_and_keep_unique_identity() {
    let mut values = vec![start()];
    for (index, id) in ["toolu_a", "toolu_b"].iter().enumerate() {
        values.extend(block(
            index,
            json!({"type":"tool_use","id":id,"name":"process_exec","input":{"argv":[id]}}),
        ));
    }
    values.extend(terminal("tool_use", 30));
    let response = decode(values).unwrap();
    assert_eq!(
        response
            .calls
            .iter()
            .map(|call| call.id.as_str())
            .collect::<Vec<_>>(),
        vec!["toolu_a", "toolu_b"]
    );
}

#[test]
fn nested_duplicate_invalid_scalar_and_trailing_arguments_are_never_calls() {
    for arguments in [
        "{\"x\":{\"y\":1,\"y\":2}}",
        "{\"argv\":[}",
        "[]",
        "null",
        "true",
        "{} {}",
    ] {
        assert!(
            decode(tool_stream(&[arguments], "tool_use")).is_err(),
            "{arguments}"
        );
    }
}

#[test]
fn max_tokens_and_refusal_retain_usage_but_never_partial_or_complete_calls() {
    for reason in ["max_tokens", "model_context_window_exceeded", "refusal"] {
        for arguments in ["{\"argv\":[", "{\"argv\":[\"test\"]}"] {
            let response = decode(tool_stream(&[arguments], reason)).unwrap();
            assert!(response.calls.is_empty());
            assert!(response.continuation.is_empty());
            assert_eq!(response.usage.output_tokens, Some(23));
            assert_eq!(response.usage.input_tokens, Some(20));
            if reason == "refusal" {
                assert_eq!(response.stop, StopReason::Refusal);
                assert!(response.refusal.is_some());
            }
        }
    }
}

#[test]
fn tool_stop_reason_and_content_must_agree() {
    assert!(decode(tool_stream(&["{}"], "end_turn")).is_err());
    let mut values = vec![start()];
    values.extend(block(0, json!({"type":"text","text":"No tool"})));
    values.extend(terminal("tool_use", 9));
    assert!(decode(values).is_err());
}

#[test]
fn cumulative_output_usage_is_replaced_instead_of_summed() {
    let mut values = vec![start()];
    values.extend(block(0, json!({"type":"text","text":"done"})));
    values.push(
        json!({"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":8}}),
    );
    values.push(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":11,"output_tokens_details":{"thinking_tokens":6}}}));
    values.push(json!({"type":"message_stop"}));
    let response = decode(values).unwrap();
    assert_eq!(response.usage.output_tokens, Some(11));
    assert_eq!(response.usage.reasoning_output_tokens, Some(6));
    assert_eq!(response.usage.cached_input_tokens, Some(5));
    assert_eq!(response.usage.cache_creation_input_tokens, Some(3));
}

#[test]
fn missing_usage_and_missing_cache_components_remain_unknown_not_zero() {
    for remove in [
        "usage",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "input_tokens",
    ] {
        let mut first = start();
        if remove == "usage" {
            first["message"].as_object_mut().unwrap().remove(remove);
        } else {
            first["message"]["usage"]
                .as_object_mut()
                .unwrap()
                .remove(remove);
        }
        let mut values = vec![first];
        values.extend(block(0, json!({"type":"text","text":"done"})));
        values.extend(terminal("end_turn", 11));
        let response = decode(values).unwrap();
        assert_eq!(response.usage.input_tokens, None, "{remove}");
        assert_eq!(response.usage.output_tokens, Some(11));
    }
}

#[test]
fn invalid_decreasing_overflowing_or_excess_reasoning_usage_is_rejected() {
    for usage in [
        json!({"output_tokens":0}),
        json!({"output_tokens":-1}),
        json!({"output_tokens":1.5}),
        json!({"output_tokens":2,"output_tokens_details":{"thinking_tokens":3}}),
    ] {
        let values = vec![
            start(),
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":usage}),
            json!({"type":"message_stop"}),
        ];
        assert!(decode(values).is_err());
    }
    let mut first = start();
    first["message"]["usage"]["input_tokens"] = json!(u64::MAX);
    assert!(
        decode(vec![
            first,
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}}),
            json!({"type":"message_stop"})
        ])
        .is_err()
    );
}

#[test]
fn opaque_thinking_and_redacted_blocks_replay_without_becoming_visible_text() {
    let mut values = vec![
        start(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"PRIVATE_THINKING_FIXTURE"}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"opaque_signature"}}),
        json!({"type":"content_block_stop","index":0}),
    ];
    values.extend(block(
        1,
        json!({"type":"redacted_thinking","data":"opaque_redacted"}),
    ));
    values.extend(block(
        2,
        json!({"type":"tool_use","id":"toolu_a","name":"process_exec","input":{}}),
    ));
    values.extend(terminal("tool_use", 50));
    let response = decode(values).unwrap();
    assert!(response.text.is_empty());
    assert!(!format!("{response:?}").contains("PRIVATE_THINKING_FIXTURE"));
    let continuation = response.continuation.clone();
    let mut request = request();
    request.messages.push(Message::Assistant { response });
    request.messages.push(Message::ToolResult {
        call_id: "toolu_a".into(),
        content: "tool observation".into(),
        is_error: false,
    });
    let body = build_request(&request).unwrap();
    assert_eq!(body["messages"][1]["content"], json!(continuation));
    assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
    assert_eq!(
        body["messages"][2]["content"][0]["content"],
        "tool observation"
    );
}

#[test]
fn unsigned_thinking_and_thinking_after_signature_fail_closed() {
    let mut values = vec![start()];
    values.extend(block(
        0,
        json!({"type":"thinking","thinking":"private","signature":""}),
    ));
    values.extend(terminal("end_turn", 5));
    assert!(decode(values).is_err());
    assert!(decode(vec![start(),json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":"signed"}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"changed"}})]).is_err());
}

#[test]
fn wrong_or_repeated_block_index_and_cross_type_delta_fail() {
    let wrongs = vec![
        vec![
            json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
        ],
        vec![
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}),
        ],
        vec![
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"x"}}),
        ],
        vec![
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}),
        ],
        block(0, json!({"type":"text","text":"x"}))
            .into_iter()
            .chain(block(0, json!({"type":"text","text":"y"})))
            .collect(),
    ];
    for wrong in wrongs {
        let mut values = vec![start()];
        values.extend(wrong);
        assert!(decode(values).is_err());
    }
}

#[test]
fn duplicate_client_ids_and_ambiguous_initial_json_are_rejected() {
    let mut values = vec![start()];
    values.extend(block(
        0,
        json!({"type":"tool_use","id":"same","name":"process_exec","input":{}}),
    ));
    values.extend(block(
        1,
        json!({"type":"tool_use","id":"same","name":"process_exec","input":{}}),
    ));
    assert!(decode(values).is_err());
    assert!(decode(vec![start(),json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a","name":"process_exec","input":{"x":1}}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":2}"}})]).is_err());
}

#[test]
fn repeated_start_wrong_role_and_nonempty_initial_content_fail() {
    assert!(decode(vec![start(), start()]).is_err());
    for field in ["role", "content", "id", "model", "type", "stop_reason"] {
        let mut first = start();
        first["message"][field] = match field {
            "role" => json!("user"),
            "content" => json!([{"type":"text","text":"x"}]),
            "stop_reason" => json!("end_turn"),
            _ => json!(""),
        };
        assert!(decode(vec![first]).is_err(), "{field}");
    }
}

#[test]
fn envelope_event_mismatch_duplicate_json_and_events_after_terminal_fail() {
    let mut decoder = AnthropicDecoder::new("configured-claude", DecoderLimits::default());
    assert!(
        decoder
            .push(&SseEvent {
                event: Some("ping".into()),
                data: "{\"type\":\"message_start\"}".into()
            })
            .is_err()
    );
    assert!(decoder.push(&event(start())).is_err());
    let mut decoder = AnthropicDecoder::new("configured-claude", DecoderLimits::default());
    assert!(
        decoder
            .push(&SseEvent {
                event: Some("ping".into()),
                data: "{\"type\":\"ping\",\"type\":\"message_stop\"}".into()
            })
            .is_err()
    );
    let mut values = vec![start()];
    values.extend(terminal("end_turn", 1));
    values.push(json!({"type":"ping"}));
    assert!(decode(values).is_err());
}

#[test]
fn harmless_additive_unknown_events_do_not_authorize_any_tools() {
    let mut values = vec![
        json!({"type":"ping"}),
        start(),
        json!({"type":"future_provider_notice","payload":{"tool_use":{"id":"fake"}}}),
    ];
    values.extend(block(0, json!({"type":"text","text":"done"})));
    values.extend(terminal("end_turn", 8));
    let response = decode(values).unwrap();
    assert!(response.calls.is_empty());
    assert_eq!(response.text, "done");
}

#[test]
fn hosted_content_server_pause_and_unknown_stop_reason_are_unsupported() {
    for kind in [
        "server_tool_use",
        "web_search_tool_result",
        "image",
        "future_action",
    ] {
        let result = decode(vec![
            start(),
            json!({"type":"content_block_start","index":0,"content_block":{"type":kind}}),
        ]);
        assert_eq!(result.unwrap_err().kind, ErrorKind::Unsupported);
    }
    for reason in ["pause_turn", "future_stop"] {
        let mut values = vec![start()];
        values.extend(terminal(reason, 1));
        assert_eq!(decode(values).unwrap_err().kind, ErrorKind::Unsupported);
    }
}

#[test]
fn upstream_stream_errors_are_typed_and_never_expose_provider_message_content() {
    for (kind, expected) in [
        ("overloaded_error", ErrorKind::ProviderUnavailable),
        ("rate_limit_error", ErrorKind::RateLimited),
        ("authentication_error", ErrorKind::Authentication),
        ("timeout_error", ErrorKind::Timeout),
        ("future_error", ErrorKind::Protocol),
    ] {
        let result = decode(vec![
            start(),
            json!({"type":"error","error":{"type":kind,"message":"PRIVATE_PROVIDER_MESSAGE"}}),
        ])
        .unwrap_err();
        assert_eq!(result.kind, expected);
        assert!(!result.to_string().contains("PRIVATE_PROVIDER_MESSAGE"));
    }
}

#[test]
fn byte_argument_item_and_call_limits_fail_before_exposing_calls() {
    let values = tool_stream(&["{\"argv\":[\"test\"]}"], "tool_use");
    for limits in [
        DecoderLimits {
            max_event_bytes: 10,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_total_bytes: 10,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_output_bytes: 2,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_argument_bytes: 2,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_items: 0,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_tool_calls: 0,
            ..DecoderLimits::default()
        },
    ] {
        let mut decoder = AnthropicDecoder::new("configured-claude", limits);
        let mut failed = false;
        for value in &values {
            if decoder.push(&event(value.clone())).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(decoder.finish().is_err());
    }
}

#[test]
fn builder_uses_current_structured_output_and_custom_tool_wire_shape() {
    let mut request = request();
    request.output_schema =
        Some(json!({"type":"object","properties":{},"additionalProperties":false}));
    let body = build_request(&request).unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["model"], "configured-claude");
    assert_eq!(body["max_tokens"], 256);
    assert_eq!(body["tools"][0]["strict"], true);
    assert_eq!(
        body["tools"][0]["input_schema"],
        request.tools[0].parameters
    );
    assert!(body["tools"][0].get("type").is_none());
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    assert!(body.get("output_format").is_none());
}

#[test]
fn all_parallel_results_are_grouped_immediately_after_exact_assistant_content() {
    let mut values = vec![start()];
    for (index, id) in ["a", "b"].iter().enumerate() {
        values.extend(block(
            index,
            json!({"type":"tool_use","id":id,"name":"process_exec","input":{}}),
        ));
    }
    values.extend(terminal("tool_use", 20));
    let response = decode(values).unwrap();
    let mut request = request();
    request.messages.push(Message::Assistant { response });
    request.messages.push(Message::ToolResult {
        call_id: "b".into(),
        content: "untrusted tool data".into(),
        is_error: true,
    });
    request.messages.push(Message::ToolResult {
        call_id: "a".into(),
        content: "done".into(),
        is_error: false,
    });
    let body = build_request(&request).unwrap();
    assert_eq!(body["messages"].as_array().unwrap().len(), 3);
    assert_eq!(body["messages"][2]["content"].as_array().unwrap().len(), 2);
    assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "b");
    assert_eq!(body["messages"][2]["content"][0]["is_error"], true);
    assert_eq!(body["system"], request.system_prompt);
}

#[test]
fn unmatched_missing_duplicate_or_interleaved_tool_results_are_rejected() {
    for wrong in 0..4 {
        let response = decode(tool_stream(&["{}"], "tool_use")).unwrap();
        let mut request = request();
        request.messages.push(Message::Assistant { response });
        if wrong == 0 {
            request.messages.push(Message::ToolResult {
                call_id: "wrong".into(),
                content: "x".into(),
                is_error: false,
            });
        }
        if wrong == 2 {
            request.messages.push(Message::User {
                text: "interleaved".into(),
            });
        }
        if wrong == 3 {
            for _ in 0..2 {
                request.messages.push(Message::ToolResult {
                    call_id: "toolu_local_1".into(),
                    content: "x".into(),
                    is_error: false,
                });
            }
        }
        assert!(build_request(&request).is_err(), "case {wrong}");
    }
}

#[test]
fn foreign_model_protocol_tampered_call_and_refused_continuation_are_rejected() {
    for wrong in 0..5 {
        let mut response = decode(tool_stream(&["{}"], "tool_use")).unwrap();
        match wrong {
            0 => response.protocol = Protocol::OpenAiResponses,
            1 => response.requested_model = "another-model".into(),
            2 => response.calls[0].arguments = "{\"changed\":true}".into(),
            3 => response.continuation[0]["type"] = json!("server_tool_use"),
            _ => response.stop = StopReason::Refusal,
        }
        let mut request = request();
        request.messages.push(Message::Assistant { response });
        request.messages.push(Message::ToolResult {
            call_id: "toolu_local_1".into(),
            content: "x".into(),
            is_error: false,
        });
        assert!(build_request(&request).is_err(), "case {wrong}");
    }
}

#[test]
fn strict_tool_count_is_explicit_and_host_can_select_non_strict_tools() {
    let mut request = request();
    for index in 1..21 {
        let mut tool = request.tools[0].clone();
        tool.name = format!("tool_{index}");
        request.tools.push(tool);
    }
    assert_eq!(
        build_request(&request).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    request.tools[20].strict = false;
    assert!(build_request(&request).is_ok());
}

#[test]
fn message_delta_cannot_reopen_content_or_change_its_terminal_reason() {
    let mut values = vec![start()];
    values.push(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}));
    let mut changed = values.clone();
    changed.push(json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}));
    assert!(decode(changed).is_err());
    values.extend(block(0, json!({"type":"text","text":"late"})));
    assert!(decode(values).is_err());
}

#[test]
fn initial_output_estimate_without_final_usage_does_not_become_a_final_bill() {
    let mut values = vec![start()];
    values.extend(block(0, json!({"type":"text","text":"done"})));
    values.push(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}}));
    values.push(json!({"type":"message_stop"}));
    let response = decode(values).unwrap();
    assert_eq!(response.usage.input_tokens, Some(20));
    assert_eq!(response.usage.output_tokens, None);
}

#[test]
fn signatures_and_initial_tool_input_share_the_output_byte_ceiling() {
    for content in [
        json!({"type":"thinking","thinking":"","signature":"0123456789"}),
        json!({"type":"tool_use","id":"a","name":"process_exec","input":{"x":"0123456789"}}),
    ] {
        let mut decoder = AnthropicDecoder::new(
            "configured-claude",
            DecoderLimits {
                max_output_bytes: 8,
                ..DecoderLimits::default()
            },
        );
        decoder.push(&event(start())).unwrap();
        assert!(
            decoder
                .push(&event(
                    json!({"type":"content_block_start","index":0,"content_block":content})
                ))
                .is_err()
        );
        assert!(decoder.finish().is_err());
    }
}

#[test]
fn hosted_caller_toolsets_and_invalid_wire_names_cannot_disguise_client_tools() {
    for extra in [
        json!({"caller":{"type":"code_execution_20250522"}}),
        json!({"toolset_name":"browser"}),
        json!({"name":"process.exec"}),
    ] {
        let mut content = json!({"type":"tool_use","id":"a","name":"process_exec","input":{}});
        for (key, value) in extra.as_object().unwrap() {
            content[key] = value.clone();
        }
        assert!(
            decode(vec![
                start(),
                json!({"type":"content_block_start","index":0,"content_block":content})
            ])
            .is_err()
        );
    }
}
