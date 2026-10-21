use melissa_model_gateway::{
    DecoderLimits, Message, Protocol, SseEvent, StopReason, ToolDefinition, TurnRequest,
    openai::{OpenAiDecoder, build_request},
    sse::SseParser,
};
use serde_json::{Value, json};

fn fixture_request() -> TurnRequest {
    TurnRequest {
        model: "configured-model-alias".into(),
        system_prompt: "host system instructions".into(),
        messages: vec![Message::User {
            text: "test request".into(),
        }],
        tools: vec![ToolDefinition {
            name: "process_exec".into(),
            description: "run an authorized job".into(),
            parameters: json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}),
            strict: true,
        }],
        max_output_tokens: 1024,
        output_schema: None,
    }
}
fn created() -> Value {
    json!({"type":"response.created","response":{"id":"resp_1","model":"resolved-snapshot","status":"in_progress","output":[]}})
}
fn completed(output: Vec<Value>) -> Value {
    json!({"type":"response.completed","response":{"id":"resp_1","model":"resolved-snapshot","status":"completed","error":null,"incomplete_details":null,"output":output,"usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16,"input_tokens_details":{"cached_tokens":3},"output_tokens_details":{"reasoning_tokens":1}}}})
}
fn call_item(id: &str, call_id: &str, args: &str) -> Value {
    json!({"id":id,"type":"function_call","call_id":call_id,"name":"process_exec","arguments":args,"status":"completed"})
}
fn call_events() -> Vec<Value> {
    let item = call_item("fc_1", "call_1", "{\"value\":\"ş😀\"}");
    let mut initial = item.clone();
    initial["arguments"] = json!("");
    initial["status"] = json!("in_progress");
    vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":initial}),
        json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":"{\"value\":"}),
        json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":"\"ş😀\"}"}),
        json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_1","arguments":item["arguments"]}),
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
        completed(vec![item]),
    ]
}
fn text_events(refusal: bool) -> Vec<Value> {
    let kind = if refusal { "refusal" } else { "output_text" };
    let field = if refusal { "refusal" } else { "text" };
    let event_prefix = if refusal {
        "response.refusal"
    } else {
        "response.output_text"
    };
    let mut part = json!({"type":kind,field:"hello ş😀"});
    if !refusal {
        part["annotations"] = json!([]);
        part["logprobs"] = json!([]);
    }
    let mut initial_part = part.clone();
    initial_part[field] = json!("");
    let item = json!({"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[part]});
    let mut initial_item = item.clone();
    initial_item["content"] = json!([]);
    initial_item["status"] = json!("in_progress");
    vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":initial_item}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg_1","content_index":0,"part":initial_part}),
        json!({"type":format!("{event_prefix}.delta"),"output_index":0,"item_id":"msg_1","content_index":0,"delta":"hello ş😀"}),
        json!({"type":format!("{event_prefix}.done"),"output_index":0,"item_id":"msg_1","content_index":0,field:"hello ş😀"}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg_1","content_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
        completed(vec![item]),
    ]
}
fn number(events: &mut [Value]) {
    for (i, event) in events.iter_mut().enumerate() {
        event["sequence_number"] = json!(i);
    }
}
fn decode(
    mut events: Vec<Value>,
) -> melissa_model_gateway::Result<melissa_model_gateway::ModelResponse> {
    number(&mut events);
    let mut decoder = OpenAiDecoder::new("configured-model-alias", DecoderLimits::default());
    for event in events {
        decoder.push(&SseEvent {
            event: None,
            data: event.to_string(),
        })?;
    }
    decoder.finish()
}

#[test]
fn real_responses_shape_reassembles_tool_arguments_and_keeps_alias_distinct() {
    let response = decode(call_events()).unwrap();
    assert_eq!(response.protocol, Protocol::OpenAiResponses);
    assert_eq!(response.stop, StopReason::ToolCalls);
    assert_eq!(response.requested_model, "configured-model-alias");
    assert_eq!(response.model, "resolved-snapshot");
    assert_eq!(response.calls.len(), 1);
    assert_eq!(response.calls[0].arguments, "{\"value\":\"ş😀\"}");
    assert_eq!(response.usage.input_tokens, Some(12));
    assert_eq!(response.usage.cached_input_tokens, Some(3));
    assert_eq!(response.usage.reasoning_output_tokens, Some(1));
    assert_eq!(response.continuation.len(), 1);
}

#[test]
fn arbitrary_network_splits_reassemble_unicode_and_never_dispatch_early() {
    let mut events = call_events();
    number(&mut events);
    let wire = events
        .iter()
        .map(|e| {
            format!(
                "event: {}\r\ndata: {}\r\n\r\n",
                e["type"].as_str().unwrap(),
                e
            )
        })
        .collect::<String>();
    for chunk_size in [1, 2, 3, 7, 31, 127] {
        let mut parser = SseParser::new(DecoderLimits::default());
        let mut decoder = OpenAiDecoder::new("configured-model-alias", DecoderLimits::default());
        for chunk in wire.as_bytes().chunks(chunk_size) {
            for event in parser.feed(chunk).unwrap() {
                decoder.push(&event).unwrap();
            }
        }
        parser.finish().unwrap();
        assert_eq!(decoder.finish().unwrap().calls.len(), 1);
    }
    let mut partial = call_events();
    partial.pop();
    assert!(decode(partial).is_err());
}

#[test]
fn output_text_and_refusal_have_distinct_terminal_states() {
    let text = decode(text_events(false)).unwrap();
    assert_eq!(text.text, "hello ş😀");
    assert_eq!(text.stop, StopReason::EndTurn);
    let refusal = decode(text_events(true)).unwrap();
    assert_eq!(refusal.stop, StopReason::Refusal);
    assert!(refusal.calls.is_empty());
    assert_eq!(refusal.refusal.as_deref(), Some("hello ş😀"));
    assert!(refusal.text.is_empty());
}

#[test]
fn incomplete_and_failed_responses_discard_even_completed_function_calls() {
    for (kind, status, expected) in [
        ("response.incomplete", "incomplete", StopReason::MaxTokens),
        ("response.failed", "failed", StopReason::Error),
    ] {
        let mut events = call_events();
        let last = events.last_mut().unwrap();
        last["type"] = json!(kind);
        last["response"]["status"] = json!(status);
        last["response"]["incomplete_details"] = json!({"reason":"max_output_tokens"});
        let response = decode(events).unwrap();
        assert_eq!(response.stop, expected);
        assert!(response.calls.is_empty());
        assert!(response.continuation.is_empty());
    }
}

#[test]
fn null_and_missing_usage_are_unknown_not_zero() {
    for usage in [Value::Null, json!({})] {
        let mut events = call_events();
        events.last_mut().unwrap()["response"]["usage"] = usage;
        let response = decode(events).unwrap();
        assert_eq!(response.usage.input_tokens, None);
        assert_eq!(response.usage.output_tokens, None);
    }
}

#[test]
fn malformed_usage_counts_cannot_become_accounting_evidence() {
    for usage in [
        json!({"input_tokens":-1}),
        json!({"output_tokens":"3"}),
        json!({"input_tokens":1,"output_tokens":2,"total_tokens":4}),
        json!({"input_tokens":1,"input_tokens_details":{"cached_tokens":2}}),
        json!({"input_tokens":3,"input_tokens_details":{"cached_tokens":2,"cache_write_tokens":2}}),
        json!({"output_tokens":1,"output_tokens_details":{"reasoning_tokens":2}}),
    ] {
        let mut events = call_events();
        events.last_mut().unwrap()["response"]["usage"] = usage;
        assert!(decode(events).is_err());
    }
}

#[test]
fn each_snapshot_must_agree_with_the_entire_stream() {
    for position in [4, 5, 6] {
        let mut events = call_events();
        match position {
            4 => events[4]["arguments"] = json!("{}"),
            5 => events[5]["item"]["arguments"] = json!("{}"),
            _ => events[6]["response"]["output"][0]["arguments"] = json!("{}"),
        }
        assert!(decode(events).is_err());
    }
    let mut events = text_events(false);
    events[4]["text"] = json!("different");
    assert!(decode(events).is_err());
    let mut events = text_events(false);
    events[5]["part"]["text"] = json!("different");
    assert!(decode(events).is_err());
}

#[test]
fn changed_item_call_and_response_identities_are_rejected() {
    for (position, field, value) in [
        (2, "item_id", json!("other")),
        (2, "output_index", json!(1)),
        (2, "response_id", json!("other")),
    ] {
        let mut events = call_events();
        events[position][field] = value;
        assert!(decode(events).is_err());
    }
    let mut events = call_events();
    events[5]["item"]["call_id"] = json!("other");
    assert!(decode(events).is_err());
    let mut events = call_events();
    events[6]["response"]["id"] = json!("other");
    assert!(decode(events).is_err());
    let mut events = call_events();
    events[6]["response"]["model"] = json!("other-model");
    assert!(decode(events).is_err());
}

#[test]
fn unordered_repeated_sequence_and_sse_type_mismatch_poison_the_decoder() {
    let mut events = call_events();
    number(&mut events);
    events[2]["sequence_number"] = json!(1);
    let mut decoder = OpenAiDecoder::new("configured-model-alias", DecoderLimits::default());
    decoder
        .push(&SseEvent {
            event: None,
            data: events[0].to_string(),
        })
        .unwrap();
    decoder
        .push(&SseEvent {
            event: None,
            data: events[1].to_string(),
        })
        .unwrap();
    assert!(
        decoder
            .push(&SseEvent {
                event: None,
                data: events[2].to_string()
            })
            .is_err()
    );
    assert!(decoder.finish().is_err());
    let mut decoder = OpenAiDecoder::new("configured-model-alias", DecoderLimits::default());
    assert!(
        decoder
            .push(&SseEvent {
                event: Some("wrong.event".into()),
                data: events[0].to_string()
            })
            .is_err()
    );
}

#[test]
fn duplicate_envelope_and_argument_keys_are_rejected_recursively() {
    let mut decoder = OpenAiDecoder::new("configured-model-alias", DecoderLimits::default());
    assert!(
        decoder
            .push(&SseEvent {
                event: None,
                data: "{\"type\":\"response.created\",\"type\":\"error\",\"sequence_number\":0}"
                    .into()
            })
            .is_err()
    );
    let args = "{\"x\":{\"same\":1,\"same\":2}}";
    let mut events = call_events();
    events[2]["delta"] = json!(args);
    events.remove(3);
    events[3]["arguments"] = json!(args);
    events[4]["item"]["arguments"] = json!(args);
    events[5]["response"]["output"][0]["arguments"] = json!(args);
    assert!(decode(events).is_err());
}

#[test]
fn hosted_tools_freeform_calls_and_unknown_events_fail_closed() {
    for kind in [
        "web_search_call",
        "code_interpreter_call",
        "custom_tool_call",
        "computer_call",
    ] {
        let mut events = call_events();
        events[1]["item"]["type"] = json!(kind);
        assert!(decode(events).is_err());
    }
    let mut events = call_events();
    events[2]["type"] = json!("response.new_unrecognized.delta");
    assert!(decode(events).is_err());
}

#[test]
fn all_buffer_bounds_are_enforced_before_a_call_is_exposed() {
    let events = call_events();
    for limits in [
        DecoderLimits {
            max_event_bytes: 32,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_total_bytes: 32,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_tool_calls: 0,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_argument_bytes: 4,
            ..DecoderLimits::default()
        },
        DecoderLimits {
            max_items: 0,
            ..DecoderLimits::default()
        },
    ] {
        let mut decoder = OpenAiDecoder::new("configured-model-alias", limits);
        let mut numbered = events.clone();
        number(&mut numbered);
        assert!(numbered.iter().any(|event| {
            decoder
                .push(&SseEvent {
                    event: None,
                    data: event.to_string(),
                })
                .is_err()
        }));
        assert!(decoder.finish().is_err());
    }
    let mut events = text_events(false);
    number(&mut events);
    let mut decoder = OpenAiDecoder::new(
        "configured-model-alias",
        DecoderLimits {
            max_output_bytes: 3,
            ..DecoderLimits::default()
        },
    );
    assert!(events.iter().any(|event| {
        decoder
            .push(&SseEvent {
                event: None,
                data: event.to_string(),
            })
            .is_err()
    }));
}

#[test]
fn repeated_terminals_and_events_after_completion_are_invalid() {
    let mut events = call_events();
    events.push(events.last().unwrap().clone());
    assert!(decode(events).is_err());
}

#[test]
fn provider_error_messages_are_not_copied_to_diagnostics_or_responses() {
    let response = decode(vec![
        created(),
        json!({"type":"error","code":"failure","message":"SECRET-KEY-RAW-INPUT","param":null}),
    ])
    .unwrap();
    assert_eq!(response.stop, StopReason::Error);
    assert!(response.calls.is_empty());
    assert!(!format!("{response:?}").contains("SECRET"));
    assert!(!serde_json::to_string(&response).unwrap().contains("SECRET"));
}

#[test]
fn final_encrypted_reasoning_is_preserved_opaque_and_replayed_with_tool_outputs() {
    let mut events = call_events();
    let reasoning = json!({"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"FINAL-OPAQUE-SECRET","status":"completed"});
    let mut initial = reasoning.clone();
    initial["encrypted_content"] = json!("PARTIAL-DO-NOT-REPLAY");
    initial["status"] = json!("in_progress");
    for event in events.iter_mut().skip(1) {
        if event.get("output_index").is_some() {
            event["output_index"] = json!(1);
        }
    }
    events.insert(
        1,
        json!({"type":"response.output_item.added","output_index":0,"item":initial}),
    );
    events.insert(
        2,
        json!({"type":"response.output_item.done","output_index":0,"item":reasoning}),
    );
    events.last_mut().unwrap()["response"]["output"] = json!([
        reasoning,
        call_item("fc_1", "call_1", "{\"value\":\"ş😀\"}")
    ]);
    let response = decode(events).unwrap();
    assert!(response.text.is_empty());
    assert_eq!(
        response.continuation[0]["encrypted_content"],
        "FINAL-OPAQUE-SECRET"
    );
    assert!(!format!("{response:?}").contains("OPAQUE"));
    let mut request = fixture_request();
    request.messages.push(Message::Assistant { response });
    request.messages.push(Message::ToolResult {
        call_id: "call_1".into(),
        content: "actual host result".into(),
        is_error: false,
    });
    let wire = build_request(&request).unwrap();
    assert_eq!(wire["input"][1]["encrypted_content"], "FINAL-OPAQUE-SECRET");
    assert_eq!(wire["input"][3]["call_id"], "call_1");
    assert_eq!(wire["input"][3]["output"], "actual host result");
    assert!(!wire.to_string().contains("PARTIAL-DO-NOT-REPLAY"));
}

#[test]
fn request_builder_has_only_explicit_functions_and_stateless_streaming() {
    let wire = build_request(&fixture_request()).unwrap();
    assert_eq!(wire["stream"], true);
    assert_eq!(wire["store"], false);
    assert_eq!(wire["parallel_tool_calls"], false);
    assert_eq!(wire["tools"][0]["type"], "function");
    assert_eq!(wire["tools"][0]["strict"], true);
    assert_eq!(wire["instructions"], "host system instructions");
    assert_eq!(wire["model"], "configured-model-alias");
    assert!(wire.get("previous_response_id").is_none());
}

#[test]
fn strict_schema_is_explicit_and_dynamic_parameter_schema_can_be_nonstrict() {
    let mut request = fixture_request();
    request.tools[0].parameters = json!({"type":"object","additionalProperties":{"type":"string"}});
    assert!(build_request(&request).is_err());
    request.tools[0].strict = false;
    assert_eq!(
        build_request(&request).unwrap()["tools"][0]["strict"],
        false
    );
    request.output_schema = Some(
        json!({"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}),
    );
    assert_eq!(
        build_request(&request).unwrap()["text"]["format"]["type"],
        "json_schema"
    );
}

#[test]
fn wrong_protocol_or_model_continuation_and_unmatched_tool_results_are_rejected() {
    let mut response = decode(call_events()).unwrap();
    response.protocol = Protocol::AnthropicMessages;
    let mut request = fixture_request();
    request.messages.push(Message::Assistant { response });
    request.messages.push(Message::ToolResult {
        call_id: "call_1".into(),
        content: "x".into(),
        is_error: false,
    });
    assert!(build_request(&request).is_err());
    let Message::Assistant { response } = &mut request.messages[1] else {
        panic!()
    };
    response.protocol = Protocol::OpenAiResponses;
    response.requested_model = "different".into();
    assert!(build_request(&request).is_err());
    let mut request = fixture_request();
    request.messages.push(Message::ToolResult {
        call_id: "nonexistent".into(),
        content: "x".into(),
        is_error: false,
    });
    assert!(build_request(&request).is_err());
}

#[test]
fn error_tool_result_is_preserved_without_inventing_an_openai_is_error_field() {
    let response = decode(call_events()).unwrap();
    let mut request = fixture_request();
    request.messages.push(Message::Assistant { response });
    request.messages.push(Message::ToolResult {
        call_id: "call_1".into(),
        content: "permission denied".into(),
        is_error: true,
    });
    let wire = build_request(&request).unwrap();
    let output = wire["input"][2]["output"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(output).unwrap()["is_error"],
        true
    );
    assert!(wire["input"][2].get("is_error").is_none());
}

#[test]
fn parallel_items_can_interleave_but_keep_unique_calls_and_output_order() {
    let a = call_item("fc_a", "call_a", "{\"value\":\"a\"}");
    let b = call_item("fc_b", "call_b", "{\"value\":\"b\"}");
    let mut initial_a = a.clone();
    initial_a["arguments"] = json!("");
    initial_a["status"] = json!("in_progress");
    let mut initial_b = b.clone();
    initial_b["arguments"] = json!("");
    initial_b["status"] = json!("in_progress");
    let events = vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":initial_a}),
        json!({"type":"response.output_item.added","output_index":1,"item":initial_b}),
        json!({"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_b","delta":b["arguments"]}),
        json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_a","delta":a["arguments"]}),
        json!({"type":"response.function_call_arguments.done","output_index":1,"item_id":"fc_b","arguments":b["arguments"]}),
        json!({"type":"response.output_item.done","output_index":1,"item":b}),
        json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_a","arguments":a["arguments"]}),
        json!({"type":"response.output_item.done","output_index":0,"item":a}),
        completed(vec![a, b]),
    ];
    let response = decode(events.clone()).unwrap();
    assert_eq!(
        response
            .calls
            .iter()
            .map(|call| call.id.as_str())
            .collect::<Vec<_>>(),
        ["call_a", "call_b"]
    );
    let mut duplicate = events;
    duplicate[2]["item"]["call_id"] = json!("call_a");
    assert!(decode(duplicate).is_err());
}

#[test]
fn reasoning_summary_deltas_are_not_answer_text_and_final_native_items_are_kept() {
    let part = json!({"type":"summary_text","text":"private provider summary"});
    let final_item = json!({"id":"rs_1","type":"reasoning","status":"completed","summary":[part],"encrypted_content":"opaque"});
    let events = vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"rs_1","type":"reasoning","status":"in_progress","summary":[]}}),
        json!({"type":"response.reasoning_summary_part.added","output_index":0,"item_id":"rs_1","summary_index":0,"part":{"type":"summary_text","text":""}}),
        json!({"type":"response.reasoning_summary_text.delta","output_index":0,"item_id":"rs_1","summary_index":0,"delta":"private provider summary"}),
        json!({"type":"response.reasoning_summary_text.done","output_index":0,"item_id":"rs_1","summary_index":0,"text":"private provider summary"}),
        json!({"type":"response.reasoning_summary_part.done","output_index":0,"item_id":"rs_1","summary_index":0,"part":part}),
        json!({"type":"response.output_item.done","output_index":0,"item":final_item}),
        completed(vec![final_item]),
    ];
    let response = decode(events.clone()).unwrap();
    assert!(response.text.is_empty());
    assert_eq!(response.continuation[0]["summary"][0], part);
    assert!(!format!("{response:?}").contains("private provider summary"));
    let mut conflicting = events;
    conflicting[6]["item"]["summary"][0]["text"] = json!("changed");
    assert!(decode(conflicting).is_err());
}

#[test]
fn reasoning_text_without_part_added_is_bounded_and_provider_owned() {
    let final_item = json!({"id":"rs_1","type":"reasoning","status":"completed","summary":[],"content":[{"type":"reasoning_text","text":"provider private text"}],"encrypted_content":"opaque"});
    let events = vec![
        created(),
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"rs_1","type":"reasoning","status":"in_progress","summary":[]}}),
        json!({"type":"response.reasoning_text.delta","output_index":0,"item_id":"rs_1","content_index":0,"delta":"provider private text"}),
        json!({"type":"response.reasoning_text.done","output_index":0,"item_id":"rs_1","content_index":0,"text":"provider private text"}),
        json!({"type":"response.output_item.done","output_index":0,"item":final_item}),
        completed(vec![final_item]),
    ];
    let response = decode(events).unwrap();
    assert!(response.text.is_empty());
    assert_eq!(response.stop, StopReason::EndTurn);
}

#[test]
fn explicit_incomplete_function_items_do_not_require_complete_argument_json() {
    let mut events = call_events();
    events[2]["delta"] = json!("{\"unfinished\":");
    events.remove(3);
    events[3]["arguments"] = json!("{\"unfinished\":");
    events[4]["item"]["arguments"] = json!("{\"unfinished\":");
    events[4]["item"]["status"] = json!("incomplete");
    events[5]["type"] = json!("response.incomplete");
    events[5]["response"]["status"] = json!("incomplete");
    events[5]["response"]["incomplete_details"] = json!({"reason":"max_output_tokens"});
    let response = decode(events).unwrap();
    assert_eq!(response.stop, StopReason::MaxTokens);
    assert!(response.calls.is_empty());
    assert!(response.continuation.is_empty());
}

#[test]
fn native_history_cannot_hide_calls_or_conflict_with_normalized_fields() {
    for change in ["hidden_call", "name", "arguments", "text", "status"] {
        let mut response = decode(call_events()).unwrap();
        match change {
            "hidden_call" => {
                let mut hidden = response.continuation[0].clone();
                hidden["id"] = json!("fc_hidden");
                hidden["call_id"] = json!("call_hidden");
                response.continuation.push(hidden);
            }
            "name" => response.continuation[0]["name"] = json!("other_tool"),
            "arguments" => response.continuation[0]["arguments"] = json!("{}"),
            "text" => response.text = "invented output".into(),
            _ => response.continuation[0]["status"] = json!("incomplete"),
        }
        let mut request = fixture_request();
        request.messages.push(Message::Assistant { response });
        request.messages.push(Message::ToolResult {
            call_id: "call_1".into(),
            content: "host result".into(),
            is_error: false,
        });
        assert!(build_request(&request).is_err(), "{change}");
    }
}

#[test]
fn strict_schema_validation_distinguishes_schema_nodes_from_property_names_and_literals() {
    let mut request = fixture_request();
    request.tools[0].parameters = json!({"type":"object","properties":{"properties":{"type":"string"},"type":{"type":"string","enum":["object"]}},"required":["properties","type"],"additionalProperties":false});
    assert!(build_request(&request).is_ok());
    request.tools[0].parameters["required"] = json!(["properties", "type", "type"]);
    assert!(build_request(&request).is_err());
    request.tools[0].parameters = json!({"type":"object","properties":{"optional":{"type":["object","null"],"properties":{"x":{"type":"string"}},"required":["x"]}},"required":["optional"],"additionalProperties":false});
    assert!(build_request(&request).is_err());
}

#[test]
fn function_calls_need_done_events_and_completed_item_statuses() {
    let mut events = call_events();
    events.remove(4);
    assert!(decode(events).is_err());
    let mut events = call_events();
    events[5]["item"]["status"] = json!("incomplete");
    events[6]["response"]["output"][0]["status"] = json!("incomplete");
    assert!(decode(events).is_err());
    let mut events = call_events();
    events.remove(5);
    assert!(decode(events).is_err());
}
