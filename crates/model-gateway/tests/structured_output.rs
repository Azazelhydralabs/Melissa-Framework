use melissa_model_gateway::{
    ErrorKind,
    schema::{
        MAX_JSON_DEPTH, MAX_OUTPUT_BYTES, MAX_SCHEMA_BYTES, validate_output, validate_schema,
    },
    strict_json,
};
use serde_json::{Value, json};

fn object_schema() -> Value {
    json!({"type":"object","required":["name","count"],"properties":{"name":{"type":"string","minLength":1},"count":{"type":"integer","minimum":1}},"additionalProperties":false})
}

#[test]
fn exact_object_unicode_and_numbers_validate_without_type_coercion() {
    let schema = object_schema();
    let value = validate_output(&schema, r#"{"name":"Çağrı 日本語 🦀","count":2}"#).unwrap();
    assert_eq!(value["name"], "Çağrı 日本語 🦀");
    for text in [
        r#"{"name":"x"}"#,
        r#"{"name":"x","count":"2"}"#,
        r#"{"name":"x","count":0}"#,
        r#"{"name":"","count":2}"#,
        r#"{"name":"x","count":2,"extra":true}"#,
        r#"{"name":"x","count":2.5}"#,
        "null",
        "[]",
    ] {
        let error = validate_output(&schema, text).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Protocol);
    }
}

#[test]
fn anyof_enum_nullable_scalars_and_boolean_schemas_keep_json_schema_semantics() {
    let schema =
        json!({"anyOf":[{"type":"integer","minimum":5},{"enum":["approved","denied",null]}]});
    for text in ["5", "9", r#""approved""#, r#""denied""#, "null"] {
        validate_output(&schema, text).unwrap();
    }
    for text in ["4", "true", r#""unknown""#, "{}"] {
        assert!(validate_output(&schema, text).is_err());
    }
    validate_schema(&json!(true)).unwrap();
    validate_schema(&json!(false)).unwrap();
    assert!(validate_output(&json!(true), "null").is_ok());
    assert!(validate_output(&json!(false), "null").is_err());
}

#[test]
fn nested_arrays_combinators_and_conditional_constraints_are_enforced() {
    let schema = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object","required":["mode","items"],
        "properties":{
            "mode":{"enum":["one","many"]},
            "items":{"type":"array","items":{"type":"integer"},"uniqueItems":true,"minItems":1,"maxItems":3}
        },
        "if":{"properties":{"mode":{"const":"one"}}},
        "then":{"properties":{"items":{"maxItems":1}}},
        "else":{"properties":{"items":{"minItems":2}}},
        "unevaluatedProperties":false
    });
    validate_output(&schema, r#"{"mode":"one","items":[1]}"#).unwrap();
    validate_output(&schema, r#"{"mode":"many","items":[1,2]}"#).unwrap();
    for text in [
        r#"{"mode":"one","items":[1,2]}"#,
        r#"{"mode":"many","items":[1]}"#,
        r#"{"mode":"many","items":[1,1]}"#,
        r#"{"mode":"many","items":[1,"x"]}"#,
        r#"{"mode":"one","items":[1],"unknown":0}"#,
    ] {
        assert!(validate_output(&schema, text).is_err());
    }
}

#[test]
fn inline_refs_json_pointer_escaping_and_recursive_tree_schemas_work_offline() {
    let schema = json!({"$defs":{"a/b~c":{"type":"integer","minimum":3}},"type":"object","properties":{"x":{"$ref":"#/$defs/a~1b~0c"}},"required":["x"],"additionalProperties":false});
    validate_output(&schema, r#"{"x":3}"#).unwrap();
    assert!(validate_output(&schema, r#"{"x":2}"#).is_err());
    let recursive = json!({"$defs":{"node":{"type":"object","properties":{"value":{"type":"integer"},"child":{"$ref":"#/$defs/node"}},"required":["value"],"additionalProperties":false}},"$ref":"#/$defs/node"});
    validate_output(&recursive, r#"{"value":1,"child":{"value":2}}"#).unwrap();
    assert!(validate_output(&recursive, r#"{"value":1,"child":{"value":"wrong"}}"#).is_err());
    assert!(validate_schema(&json!({"$ref":"#/$defs/missing"})).is_err());
}

#[test]
fn external_http_file_relative_dynamic_and_recursive_refs_are_rejected_before_resolution() {
    for reference in [
        "https://example.invalid/schema.json",
        "http://127.0.0.1:9/secret",
        "file:///C:/private/schema.json",
        "other.json#/$defs/item",
        "//server/share/schema.json",
        "",
    ] {
        for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
            let mut schema = serde_json::Map::new();
            schema.insert(keyword.into(), json!(reference));
            let error = validate_schema(&Value::Object(schema)).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Unsupported);
            assert!(!error.to_string().contains(reference) || reference.is_empty());
        }
    }
    for schema in [
        json!({"properties":{"x":{"$ref":"file:///private"}}}),
        json!({"$defs":{"x":{"$ref":"https://example.invalid"}}}),
        json!({"allOf":[{"$ref":"external.json"}]}),
        json!({"items":{"$dynamicRef":"external.json#node"}}),
        json!({"if":{"$ref":"external.json"},"then":true}),
        json!({"dependentSchemas":{"x":{"$ref":"external.json"}}}),
        json!({"dependencies":{"x":{"$ref":"external.json"}}}),
    ] {
        assert!(validate_schema(&schema).is_err());
    }
}

#[test]
fn rejection_makes_no_http_connection_even_when_a_live_loopback_listener_exists() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let uri = format!("http://{}/schema.json", listener.local_addr().unwrap());
    assert!(validate_schema(&json!({"$ref":uri})).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn property_names_and_constant_data_are_not_mistaken_for_schema_reference_keywords() {
    let schema = json!({
        "type":"object",
        "properties":{
            "$ref":{"type":"string"},
            "$dynamicRef":{"type":"integer"},
            "properties":{"const":{"$ref":"https://ordinary-instance-data.invalid"}},
            "enum":{"enum":[{"$ref":"file:///ordinary-data"}]}
        },
        "required":["$ref","$dynamicRef","properties","enum"],
        "additionalProperties":false
    });
    let text = r#"{"$ref":"a regular field","$dynamicRef":3,"properties":{"$ref":"https://ordinary-instance-data.invalid"},"enum":{"$ref":"file:///ordinary-data"}}"#;
    validate_schema(&schema).unwrap();
    validate_output(&schema, text).unwrap();
}

#[test]
fn invalid_meta_schemas_and_custom_dialects_fail_with_redacted_errors() {
    for schema in [
        json!(null),
        json!(3),
        json!({"type":"private-schema-value-719"}),
        json!({"required":"private-schema-value-719"}),
        json!({"properties":{"secret-property-719":{"minimum":"secret"}}}),
        json!({"$ref":3}),
        json!({"$schema":"https://private-schema-value-719.invalid/dialect"}),
    ] {
        let error = validate_schema(&schema).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Invalid);
        assert!(!format!("{error:?}").contains("private-schema-value-719"));
        assert!(!format!("{error:?}").contains("secret-property-719"));
    }
    let error = validate_output(
        &object_schema(),
        r#"{"name":"private-model-output-719","count":"secret"}"#,
    )
    .unwrap_err();
    assert!(!format!("{error:?}").contains("private-model-output-719"));
}

#[test]
fn duplicate_keys_nested_duplicates_and_escaped_aliases_never_become_valid_output() {
    for text in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"a":1,"a":2}}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"[{"a":1,"a":2}]"#,
    ] {
        assert!(validate_output(&json!(true), text).is_err());
    }
    assert!(strict_json(r#"{"type":"object","type":"string"}"#).is_err());
}

#[test]
fn blank_fenced_partial_trailing_nonfinite_and_comment_outputs_are_rejected() {
    for text in [
        "",
        "  \n\t",
        "```json\n{}\n```",
        "{} explanation",
        "{}{}",
        "{\"a\":",
        "NaN",
        "Infinity",
        "/*comment*/{}",
        "{\"a\":1,}",
    ] {
        assert!(validate_output(&json!(true), text).is_err(), "{text}");
    }
    assert_eq!(validate_output(&json!(true), " \n{}\t").unwrap(), json!({}));
}

#[test]
fn serialized_bytes_depth_and_node_budgets_are_enforced_for_schema_and_model_output() {
    assert!(
        validate_output(
            &json!(true),
            &format!("\"{}\"", "a".repeat(MAX_OUTPUT_BYTES))
        )
        .is_err()
    );
    assert!(validate_schema(&json!({"description":"a".repeat(MAX_SCHEMA_BYTES)})).is_err());
    let mut deep = json!(null);
    for _ in 0..MAX_JSON_DEPTH + 1 {
        deep = json!([deep]);
    }
    assert!(validate_output(&json!(true), &serde_json::to_string(&deep).unwrap()).is_err());
    assert!(validate_schema(&json!({"const":deep})).is_err());
    let wide = format!("[{}]", vec!["0"; 32 * 1024 + 1].join(","));
    assert!(wide.len() < MAX_OUTPUT_BYTES);
    assert!(validate_output(&json!(true), &wide).is_err());
}

#[test]
fn formats_patterns_and_draft_seven_tuple_validation_are_checked_locally() {
    let schema = json!({"type":"object","required":["email","code"],"properties":{"email":{"type":"string","format":"email"},"code":{"type":"string","pattern":"^[A-Z]{2}[0-9]{2}$"}},"additionalProperties":false});
    validate_output(&schema, r#"{"email":"test@example.com","code":"AB12"}"#).unwrap();
    for text in [
        r#"{"email":"invalid email","code":"AB12"}"#,
        r#"{"email":"test@example.com","code":"bad"}"#,
    ] {
        assert!(validate_output(&schema, text).is_err());
    }
    assert!(
        validate_schema(&json!({"type":"string","format":"unimplemented-private-format"})).is_err()
    );
    let draft7 = json!({"$schema":"http://json-schema.org/draft-07/schema#","type":"array","items":[{"type":"integer"},{"type":"string"}],"additionalItems":false,"minItems":2});
    validate_output(&draft7, r#"[2,"yes"]"#).unwrap();
    for text in [r#"["wrong","yes"]"#, r#"[2,"yes",3]"#] {
        assert!(validate_output(&draft7, text).is_err());
    }
}
