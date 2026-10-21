//! Bounded, duplicate-rejecting JSON ingestion shared by catalog and wire types.
//!
//! Nested duplicate keys are rejected before conversion to serde_json::Value,
//! including keys inside deliberately open domain payloads. The serde_json
//! parser retains its default nesting limit. This reader is not a filesystem
//! authorization boundary; the real broker and OS isolation are later stages.

use crate::validation::{ContractError, ContractResult, Validate, require};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.into())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let StrictValue(value) = object.next_value::<StrictValue>()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

pub fn parse_contract<T: DeserializeOwned + Validate>(
    bytes: &[u8],
    max_bytes: usize,
) -> ContractResult<T> {
    require(max_bytes > 0, "$", "JSON byte limit must be positive")?;
    require(bytes.len() <= max_bytes, "$", "JSON byte limit exceeded")?;
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut parser)
        .map_err(|error| ContractError::new("$", format!("invalid JSON: {error}")))?;
    parser
        .end()
        .map_err(|error| ContractError::new("$", format!("trailing JSON data: {error}")))?;
    let result: T = serde_json::from_value(value)
        .map_err(|error| ContractError::new("$", format!("invalid contract shape: {error}")))?;
    result.validate()?;
    Ok(result)
}

pub fn read_contract<T: DeserializeOwned + Validate>(
    path: &Path,
    max_bytes: usize,
) -> ContractResult<T> {
    require(max_bytes > 0, "$", "JSON byte limit must be positive")?;
    let maximum = u64::try_from(max_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| ContractError::new("$", "JSON byte limit is too large"))?;
    let file = File::open(path).map_err(|error| {
        ContractError::new(path.display().to_string(), format!("read: {error}"))
    })?;
    let mut bytes = Vec::new();
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ContractError::new(path.display().to_string(), format!("read: {error}"))
        })?;
    parse_contract(&bytes, max_bytes).map_err(|error| error.at(&path.display().to_string()))
}
