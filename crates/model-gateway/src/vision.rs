//! Explicit host opt-in. Images are inline PNG bytes, never remote URLs/files.
use crate::{GatewayError, Result, tools::ToolExecution};
use melissa_local_store::LocalStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlinePng {
    bytes: Vec<u8>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use melissa_local_store::{ArtifactRequest, StoreConfig, StoreKey};
    use serde_json::json;
    #[test]
    fn binary_png_requires_native_receipt_matching_reply_source_and_bytes() {
        let d = tempfile::tempdir().unwrap();
        let mut store = LocalStore::open(
            &d.path().join("store"),
            StoreKey::from_bytes([159; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        let task: melissa_core_contracts::wire::TaskContractV1 = serde_json::from_slice(
            include_bytes!("../../../tests/fixtures/code01/wire/task-contract-v1.json"),
        )
        .unwrap();
        store.journal_mut().create_task(&task).unwrap();
        let bytes = include_bytes!("../tests/fixtures/browser-fixture.png");
        let descriptor = json!({"id":"a1","kind":"png","bytes":bytes.len(),"sha256":"verified-by-native-receiver"});
        let reply = json!({"seq":3,"ok":true,"source_digest":"source-current","body":{"binary_artifact":descriptor,"content_type":"image/png"}});
        let receipt = json!({"artifact_id":"binary","web_reply_artifact_id":"reply","descriptor":descriptor,"source_digest":"source-current","seq":3,"blake3":format!("blake3:{}",blake3::hash(bytes))});
        for (id, kind, content_type, data) in [
            ("binary", "web.png", "image/png", bytes.to_vec()),
            (
                "reply",
                "web.reply",
                "application/json",
                serde_json::to_vec(&reply).unwrap(),
            ),
            (
                "receipt",
                "web.binary-receipt",
                "application/json",
                serde_json::to_vec(&receipt).unwrap(),
            ),
        ] {
            store
                .put_artifact(
                    &ArtifactRequest {
                        artifact_id: id.into(),
                        task_id: task.task_id.clone(),
                        content_type: content_type.into(),
                        logical_type: kind.into(),
                        schema_version: "v1".into(),
                        retain_until_ms: 0,
                        legal_hold: false,
                    },
                    &data,
                )
                .unwrap();
        }
        let p = VisionPolicy {
            initial_images: vec![],
            screenshot_tools: BTreeSet::from(["web_session".into()]),
        };
        let mut result = ToolExecution {
            content: json!({"reply":reply}).to_string(),
            success: true,
            cancelled: false,
            requires_reconciliation: false,
            artifact_refs: vec!["binary".into(), "receipt".into(), "reply".into()],
        };
        assert_eq!(
            p.tool_images(&store, &task.task_id, "web_session", &result)
                .unwrap()
                .len(),
            1
        );
        result.artifact_refs.retain(|id| id != "receipt");
        assert!(
            p.tool_images(&store, &task.task_id, "web_session", &result)
                .is_err()
        );
        assert!(
            p.tool_images(&store, "foreign-task", "web_session", &result)
                .is_err()
        );
    }
    #[test]
    fn forged_screenshot_or_foreign_task_cannot_become_an_image_message() {
        let d = tempfile::tempdir().unwrap();
        let mut store = LocalStore::open(
            &d.path().join("store"),
            StoreKey::from_bytes([158; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        let task: melissa_core_contracts::wire::TaskContractV1 = serde_json::from_slice(
            include_bytes!("../../../tests/fixtures/code01/wire/task-contract-v1.json"),
        )
        .unwrap();
        store.journal_mut().create_task(&task).unwrap();
        let bytes = include_bytes!("../tests/fixtures/browser-fixture.png");
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let reply = json!({"ok":true,"body":{"content_type":"image/png","png_hex":hex},"seq":1,"source_digest":"owned-source"});
        store
            .put_artifact(
                &ArtifactRequest {
                    artifact_id: "owned-image".into(),
                    task_id: task.task_id.clone(),
                    content_type: "application/json".into(),
                    logical_type: "web.reply".into(),
                    schema_version: "v1".into(),
                    retain_until_ms: 0,
                    legal_hold: false,
                },
                &serde_json::to_vec(&reply).unwrap(),
            )
            .unwrap();
        let policy = VisionPolicy {
            initial_images: vec![],
            screenshot_tools: BTreeSet::from(["web_session".into()]),
        };
        let mut result = ToolExecution {
            content: json!({"reply":reply}).to_string(),
            success: true,
            cancelled: false,
            requires_reconciliation: false,
            artifact_refs: vec!["owned-image".into()],
        };
        assert_eq!(
            policy
                .tool_images(&store, &task.task_id, "web_session", &result)
                .unwrap()
                .len(),
            1
        );
        assert!(
            policy
                .tool_images(&store, "foreign-task", "web_session", &result)
                .is_err()
        );
        let mut forged = reply;
        forged["seq"] = json!(2);
        result.content = json!({"reply":forged}).to_string();
        assert!(
            policy
                .tool_images(&store, &task.task_id, "web_session", &result)
                .is_err()
        );
        assert!(
            policy
                .tool_images(&store, &task.task_id, "unregistered", &result)
                .unwrap()
                .is_empty()
        );
    }
}
impl std::fmt::Debug for InlinePng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlinePng")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}
impl InlinePng {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let image = Self { bytes };
        image.validate()?;
        Ok(image)
    }
    pub fn validate(&self) -> Result<()> {
        let b = &self.bytes;
        if b.len() < 45
            || b.len() > 4 * 1024 * 1024
            || !b.starts_with(b"\x89PNG\r\n\x1a\n")
            || &b[12..16] != b"IHDR"
            || !b.windows(4).any(|s| s == b"IEND")
        {
            return Err(GatewayError::invalid("inline PNG envelope"));
        }
        let w = u32::from_be_bytes(b[16..20].try_into().expect("checked length"));
        let h = u32::from_be_bytes(b[20..24].try_into().expect("checked length"));
        if w == 0 || h == 0 || u64::from(w) * u64::from(h) > 32_000_000 {
            return Err(GatewayError::invalid("inline PNG dimensions"));
        }
        Ok(())
    }
    pub fn base64(&self) -> String {
        const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::with_capacity(self.bytes.len().div_ceil(3) * 4);
        for b in self.bytes.chunks(3) {
            let n = (u32::from(b[0]) << 16)
                | (u32::from(*b.get(1).unwrap_or(&0)) << 8)
                | u32::from(*b.get(2).unwrap_or(&0));
            s.push(C[((n >> 18) & 63) as usize] as char);
            s.push(C[((n >> 12) & 63) as usize] as char);
            s.push(if b.len() > 1 {
                C[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            s.push(if b.len() > 2 {
                C[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        s
    }
    pub fn data_url(&self) -> String {
        format!("data:image/png;base64,{}", self.base64())
    }
}
/// Host-selected image tools. Model arguments cannot enable vision or select a
/// file. Native CAS task ownership and exact tool reply bytes are prerequisites.
#[derive(Debug, Clone, Serialize)]
pub struct VisionPolicy {
    pub initial_images: Vec<InlinePng>,
    pub screenshot_tools: BTreeSet<String>,
}
impl VisionPolicy {
    pub(crate) fn model_text(content: &str, images: &[InlinePng]) -> Result<String> {
        let mut value = crate::strict_json(content)?;
        if let Some(body) = value["reply"]["body"].as_object_mut() {
            body.remove("png_hex");
            body.insert("image_delivery".into(),serde_json::json!({"kind":"original_inline_png","digests":images.iter().map(|i|format!("blake3:{}",blake3::hash(&i.bytes))).collect::<Vec<_>>(),"raw_bytes":"exact task-owned native web.reply or linked web.png CAS artifact"}));
        }
        Ok(value.to_string())
    }
    pub fn validate(&self) -> Result<()> {
        if self.initial_images.len() > 8 || self.screenshot_tools.len() > 8 {
            return Err(GatewayError::invalid("vision policy capacity"));
        }
        for image in &self.initial_images {
            image.validate()?;
        }
        for name in &self.screenshot_tools {
            if !crate::valid_tool_name(name) {
                return Err(GatewayError::invalid("vision tool name"));
            }
        }
        Ok(())
    }
    pub(crate) fn tool_images(
        &self,
        store: &LocalStore,
        task: &str,
        name: &str,
        result: &ToolExecution,
    ) -> Result<Vec<InlinePng>> {
        if !self.screenshot_tools.contains(name) || !result.success {
            return Ok(vec![]);
        }
        let value = crate::strict_json(&result.content)?;
        let reply = &value["reply"];
        let hex = reply["body"]["png_hex"].as_str();
        if hex.is_none() && reply["body"]["binary_artifact"]["kind"] != "png" {
            return Ok(vec![]);
        }
        let mut authenticated = None;
        for id in result.artifact_refs.iter().rev() {
            let meta = store
                .artifact_metadata(task, id)
                .map_err(|_| GatewayError::invalid("vision task artifact ownership"))?;
            if meta.logical_type != "web.reply" {
                continue;
            }
            let raw = store
                .get_artifact(task, id)
                .map_err(|_| GatewayError::invalid("vision native CAS read"))?;
            if crate::strict_json(
                std::str::from_utf8(&raw).map_err(|_| GatewayError::invalid("vision CAS UTF8"))?,
            )? == *reply
            {
                authenticated = Some(id.clone());
                break;
            }
        }
        if authenticated.is_none()
            || reply["ok"] != true
            || reply["body"]["content_type"] != "image/png"
            || hex.is_some_and(|h| h.len() > 8 * 1024 * 1024 || h.len() % 2 != 0)
        {
            return Err(GatewayError::invalid(
                "vision screenshot not bound to native reply",
            ));
        }
        if hex.is_none() {
            let descriptor = &reply["body"]["binary_artifact"];
            if descriptor["bytes"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 4 * 1024 * 1024)
            {
                return Err(GatewayError::invalid("native PNG image envelope"));
            }
            for id in result.artifact_refs.iter().rev() {
                let meta = store
                    .artifact_metadata(task, id)
                    .map_err(|_| GatewayError::invalid("binary image task ownership"))?;
                if meta.logical_type != "web.binary-receipt" {
                    continue;
                }
                let receipt: serde_json::Value = serde_json::from_slice(
                    &store
                        .get_artifact(task, id)
                        .map_err(|_| GatewayError::invalid("binary image receipt"))?,
                )
                .map_err(|_| GatewayError::invalid("binary image receipt JSON"))?;
                if receipt["web_reply_artifact_id"]
                    != *authenticated.as_ref().expect("authenticated")
                    || receipt["descriptor"] != *descriptor
                    || receipt["source_digest"] != reply["source_digest"]
                    || receipt["seq"] != reply["seq"]
                {
                    continue;
                }
                let binary_id = receipt["artifact_id"]
                    .as_str()
                    .ok_or_else(|| GatewayError::invalid("binary image ID"))?;
                let metadata = store
                    .artifact_metadata(task, binary_id)
                    .map_err(|_| GatewayError::invalid("binary image metadata"))?;
                let raw = store
                    .get_artifact(task, binary_id)
                    .map_err(|_| GatewayError::invalid("binary image CAS"))?;
                if metadata.logical_type != "web.png"
                    || metadata.content_type != "image/png"
                    || receipt["blake3"] != format!("blake3:{}", blake3::hash(&raw))
                    || descriptor["bytes"] != raw.len() as u64
                {
                    return Err(GatewayError::invalid("binary image native digest mismatch"));
                }
                return Ok(vec![InlinePng::new(raw)?]);
            }
            return Err(GatewayError::invalid(
                "binary image lacks exact native receipt",
            ));
        }
        let hex = hex.expect("checked inline image");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for p in hex.as_bytes().as_chunks::<2>().0 {
            let digit = |c: u8| -> Result<u8> {
                match c {
                    b'0'..=b'9' => Ok(c - b'0'),
                    b'a'..=b'f' => Ok(c - b'a' + 10),
                    _ => Err(GatewayError::invalid("PNG hex")),
                }
            };
            bytes.push(digit(p[0])? * 16 + digit(p[1])?);
        }
        Ok(vec![InlinePng::new(bytes)?])
    }
}
