use melissa_core_contracts::json::{parse_contract, read_contract};
use melissa_core_contracts::validation::{ContractResult, Validate, non_blank};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    name: String,
    payload: BTreeMap<String, Value>,
    counter: u64,
}

impl Validate for Sample {
    fn validate(&self) -> ContractResult<()> {
        non_blank(&self.name, "name")
    }
}

fn parse(bytes: &[u8]) -> ContractResult<Sample> {
    parse_contract(bytes, 4096)
}

#[test]
fn actual_json_and_unicode_are_preserved_without_coercing_numbers() {
    let bytes = br#"{"name":"\u0130stanbul","payload":{"nested":[true,null,3]},"counter":18446744073709551615}"#;
    let sample = parse(bytes).unwrap();
    assert_eq!(sample.name, "İstanbul");
    assert_eq!(sample.counter, u64::MAX);
    assert_eq!(sample.payload["nested"][2], 3);
}

#[test]
fn duplicate_keys_are_rejected_even_in_open_nested_payloads() {
    for bytes in [
        br#"{"name":"a","name":"b","payload":{},"counter":1}"#.as_slice(),
        br#"{"name":"a","payload":{"n":{"x":1,"x":2}},"counter":1}"#,
        br#"{"name":"a","payload":{"n":[{"x":1,"\u0078":2}]},"counter":1}"#,
    ] {
        let error = parse(bytes).unwrap_err();
        assert!(error.message.contains("duplicate"), "{error}");
    }
}

#[test]
fn multiple_documents_or_trailing_garbage_never_form_a_contract() {
    for suffix in [" {}", " null", " trailing"] {
        let json = format!(r#"{{"name":"a","payload":{{}},"counter":1}}{suffix}"#);
        assert!(parse(json.as_bytes()).is_err());
    }
}

#[test]
fn unknown_fields_missing_required_null_and_wrong_numbers_are_rejected() {
    for bytes in [
        br#"{"name":"a","payload":{},"counter":1,"extra":true}"#.as_slice(),
        br#"{"name":"a","counter":1}"#,
        br#"{"name":"a","payload":null,"counter":1}"#,
        br#"{"name":"a","payload":{},"counter":-1}"#,
        br#"{"name":"a","payload":{},"counter":1.5}"#,
        br#"{"name":"a","payload":{},"counter":18446744073709551616}"#,
    ] {
        assert!(parse(bytes).is_err());
    }
}

#[test]
fn semantic_validation_is_required_after_shape_validation() {
    let error = parse(br#"{"name":" \n ","payload":{},"counter":1}"#).unwrap_err();
    assert_eq!(error.path, "name");
}

#[test]
fn configured_byte_limit_is_inclusive_and_zero_limit_is_invalid() {
    let json = br#"{"name":"a","payload":{},"counter":1}"#;
    assert!(parse_contract::<Sample>(json, json.len()).is_ok());
    assert!(parse_contract::<Sample>(json, json.len() - 1).is_err());
    assert!(parse_contract::<Sample>(json, 0).is_err());
}

#[test]
fn malformed_utf8_json_or_excessive_nesting_is_rejected() {
    assert!(parse(b"\xff").is_err());
    assert!(parse(b"{broken").is_err());
    let nested = format!(
        r#"{{"name":"a","payload":{{"n":{}{}}},"counter":1}}"#,
        "[".repeat(150),
        "]".repeat(150)
    );
    assert!(parse(nested.as_bytes()).is_err());
}

struct OwnedFixture(PathBuf);
impl OwnedFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "melissa-code01-json-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for OwnedFixture {
    fn drop(&mut self) {
        // Created by this test with a unique path; never enumerate or prune any
        // parent, workspace, source document or unrelated temporary directory.
        let _ = std::fs::remove_file(self.0.join("sample.json"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[test]
fn bounded_file_reader_reports_invalid_contract_without_consuming_a_huge_file() {
    let fixture = OwnedFixture::new();
    let path = fixture.0.join("sample.json");
    std::fs::write(&path, br#"{"name":"a","payload":{},"counter":1}"#).unwrap();
    assert!(read_contract::<Sample>(&path, 4096).is_ok());
    assert!(read_contract::<Sample>(&path, 8).is_err());
    assert!(read_contract::<Sample>(&fixture.0.join("missing.json"), 4096).is_err());
}
