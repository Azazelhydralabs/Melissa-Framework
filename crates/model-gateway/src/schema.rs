//! Host-side JSON Schema validation. Provider "strict" declarations do not
//! replace this check. No schema can fetch files, network URLs, or credentials.
use std::{error::Error, io::Write};

use jsonschema::{PatternOptions, Retrieve, Uri, Validator};
use serde_json::Value;

use crate::{GatewayError, Result, strict_json};

pub const MAX_SCHEMA_BYTES: usize = 256 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 32 * 1024;

struct RejectRetrieval;
impl Retrieve for RejectRetrieval {
    fn retrieve(
        &self,
        _uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn Error + Send + Sync>> {
        Err("external schema retrieval is disabled".into())
    }
}

/// Counts serialized bytes without allocating an oversized copy. Values first
/// pass the iterative depth/node walk so serde cannot recurse through an
/// arbitrarily deep Value supplied by the trusted host.
struct ByteLimit(usize);
impl Write for ByteLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(std::io::Error::other("JSON byte limit"));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json(value: &Value, max_bytes: usize) -> Result<()> {
    let mut pending = vec![(value, 0usize)];
    let mut count = 1usize;
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(GatewayError::invalid("JSON depth bound exceeded"));
        }
        let children: Box<dyn Iterator<Item = &Value> + '_> = match value {
            Value::Object(values) => Box::new(values.values()),
            Value::Array(values) => Box::new(values.iter()),
            _ => continue,
        };
        for child in children {
            count += 1;
            if count > MAX_JSON_NODES {
                return Err(GatewayError::invalid("JSON node bound exceeded"));
            }
            pending.push((child, depth + 1));
        }
    }
    serde_json::to_writer(&mut ByteLimit(max_bytes), value)
        .map_err(|_| GatewayError::invalid("JSON byte bound exceeded"))
}

/// Visit actual schema positions, not every JSON object. A property called
/// "$ref", or the same spelling inside enum/const/example data, is ordinary
/// instance data and must not be mistaken for a reference keyword.
fn inline_references_only(schema: &Value) -> Result<()> {
    let mut pending = vec![schema];
    while let Some(node) = pending.pop() {
        let Some(object) = node.as_object() else {
            continue;
        };
        for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
            if let Some(reference) = object.get(keyword) {
                let Some(reference) = reference.as_str() else {
                    return Err(GatewayError::invalid("schema reference must be a string"));
                };
                if !reference.starts_with('#') {
                    return Err(GatewayError::unsupported(
                        "only inline schema references are supported",
                    ));
                }
            }
        }
        for keyword in [
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
            "dependentSchemas",
        ] {
            if let Some(children) = object.get(keyword).and_then(Value::as_object) {
                pending.extend(children.values());
            }
        }
        if let Some(children) = object.get("dependencies").and_then(Value::as_object) {
            pending.extend(
                children
                    .values()
                    .filter(|value| value.is_object() || value.is_boolean()),
            );
        }
        for keyword in [
            "additionalProperties",
            "unevaluatedProperties",
            "additionalItems",
            "unevaluatedItems",
            "contains",
            "propertyNames",
            "not",
            "if",
            "then",
            "else",
            "contentSchema",
        ] {
            if let Some(child) = object.get(keyword) {
                pending.push(child);
            }
        }
        for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(children) = object.get(keyword).and_then(Value::as_array) {
                pending.extend(children);
            }
        }
        if let Some(items) = object.get("items") {
            if let Some(children) = items.as_array() {
                pending.extend(children);
            } else {
                pending.push(items);
            }
        }
    }
    Ok(())
}

fn compile(schema: &Value) -> Result<Validator> {
    bounded_json(schema, MAX_SCHEMA_BYTES)?;
    inline_references_only(schema)?;
    // Library compilation validates the schema against its declared supported
    // draft's meta-schema. Bundled standard meta-schemas need no retrieval.
    // The rejecting retriever is an independent backstop for resolution paths,
    // including nested resource IDs, custom dialects and unresolved fragments.
    jsonschema::options()
        .with_retriever(RejectRetrieval)
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .with_pattern_options(
            PatternOptions::fancy_regex()
                .backtrack_limit(100_000)
                .size_limit(1024 * 1024)
                .dfa_size_limit(1024 * 1024),
        )
        .build(schema)
        .map_err(|_| GatewayError::invalid("schema is invalid, unresolved or unsupported"))
}

/// Validate a host-supplied schema before any provider/network dispatch.
/// Raw schema JSON must enter through `strict_json` before becoming a Value;
/// duplicate keys cannot be recovered after a caller has already collapsed them.
pub fn validate_schema(schema: &Value) -> Result<()> {
    compile(schema).map(|_| ())
}

/// Accept exactly one bounded, duplicate-free JSON value satisfying the full
/// host schema. No markdown fence, explanation, partial JSON or type coercion.
/// Returned errors intentionally omit provider data, schema paths and values.
pub fn validate_output(schema: &Value, text: &str) -> Result<Value> {
    validate_output_with_limit(schema, text, MAX_OUTPUT_BYTES)
}
/// A final answer may use the trusted host's decoder output byte allowance.
/// Tool arguments retain `validate_output` and its original256KiB bound.
/// Schema size, duplicate rejection, depth, nodes and retrieval policy stay fixed.
pub fn validate_output_with_limit(schema: &Value, text: &str, max_bytes: usize) -> Result<Value> {
    if max_bytes == 0 || max_bytes > 8 * 1024 * 1024 {
        return Err(GatewayError::invalid(
            "structured output resource policy bounds",
        ));
    }
    let validator = compile(schema)?;
    if text.len() > max_bytes || text.trim().is_empty() {
        return Err(GatewayError::protocol(
            "structured output is empty or oversized",
        ));
    }
    let value = strict_json(text)
        .map_err(|_| GatewayError::protocol("structured output is not strict JSON"))?;
    bounded_json(&value, max_bytes)
        .map_err(|_| GatewayError::protocol("structured output exceeds JSON bounds"))?;
    if !validator.is_valid(&value) {
        return Err(GatewayError::protocol(
            "structured output does not satisfy its schema",
        ));
    }
    Ok(value)
}
