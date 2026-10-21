//! Large PNG/ZIP bytes use bounded acknowledged frames, separately from JSON.
use super::*;
use sha2::{Digest, Sha256};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    id: String,
    kind: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    schema_version: String,
    seq: u64,
    artifact_id: String,
    offset: u64,
    total_bytes: u64,
    data_hex: String,
}
impl WebSession {
    pub(super) fn receive_binary(&mut self, reply: &Reply, deadline: Instant) -> Result<()> {
        let Some(value) = reply.body.as_ref().and_then(|b| b.get("binary_artifact")) else {
            return Ok(());
        };
        let meta: Descriptor = serde_json::from_value(value.clone())?;
        let limit = self
            .plan
            .request
            .limits
            .export_bytes
            .min(self.plan.request.limits.output_bytes / 3)
            .min(64 * 1024 * 1024);
        if meta.bytes == 0
            || meta.bytes > limit
            || meta.id.len() > 10
            || !meta
                .id
                .strip_prefix('a')
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || !["png", "trace"].contains(&meta.kind.as_str())
            || (meta.kind == "trace" && !reply.closed)
            || (meta.kind == "png"
                && reply
                    .body
                    .as_ref()
                    .is_none_or(|b| b["content_type"] != "image/png"))
        {
            return Err(Error::Invalid(
                "binary artifact descriptor outside host envelope",
            ));
        }
        let mut bytes = Vec::with_capacity(meta.bytes as usize);
        while (bytes.len() as u64) < meta.bytes {
            if self.cancel.load(Ordering::Acquire)
                || self.revoked.load(Ordering::Acquire)
                || Instant::now() >= deadline
            {
                return Err(Error::Invalid("binary artifact interrupted"));
            }
            let raw = match self.answers.recv_timeout(Duration::from_millis(40)) {
                Ok(b) => b,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => return Err(Error::Invalid("binary artifact pipe closed")),
            };
            let frame = melissa_model_gateway::strict_json(
                std::str::from_utf8(&raw).map_err(|_| Error::Invalid("binary frame encoding"))?,
            )
            .map_err(|_| Error::Invalid("binary frame JSON"))?;
            let part: Part = serde_json::from_value(frame)?;
            let remaining = (meta.bytes - bytes.len() as u64).min(24576) as usize;
            if part.schema_version != "melissa.web-binary/v1"
                || part.seq != reply.seq
                || part.artifact_id != meta.id
                || part.offset != bytes.len() as u64
                || part.total_bytes != meta.bytes
                || part.data_hex.len() != remaining * 2
            {
                return Err(Error::Invalid("binary frame source/sequence/size mismatch"));
            }
            for pair in part.data_hex.as_bytes().as_chunks::<2>().0 {
                let digit = |b: u8| -> Result<u8> {
                    match b {
                        b'0'..=b'9' => Ok(b - b'0'),
                        b'a'..=b'f' => Ok(b - b'a' + 10),
                        _ => Err(Error::Invalid("binary frame hex")),
                    }
                };
                bytes.push(digit(pair[0])? * 16 + digit(pair[1])?);
            }
            let mut ack =
                serde_json::to_vec(&json!({"artifact_ack":reply.seq,"offset":part.offset}))?;
            ack.push(b'\n');
            self.input
                .as_ref()
                .ok_or(Error::Invalid("binary input closed"))?
                .send(ack)
                .map_err(|_| Error::Invalid("binary ACK send failed"))?;
        }
        if format!("sha256:{:x}", Sha256::digest(&bytes)) != meta.sha256 {
            return Err(Error::Invalid("binary artifact SHA256 mismatch"));
        }
        let id = format!(
            "{}:web-binary:{}:{}",
            self.context.attempt_id, reply.seq, meta.kind
        );
        self.store.put_artifact(
            &melissa_local_store::ArtifactRequest {
                artifact_id: id.clone(),
                task_id: self.context.task_id.clone(),
                content_type: if meta.kind == "png" {
                    "image/png"
                } else {
                    "application/zip"
                }
                .into(),
                logical_type: format!("web.{}", meta.kind),
                schema_version: "melissa.web-binary/v1".into(),
                retain_until_ms: 0,
                legal_hold: true,
            },
            &bytes,
        )?;
        self.artifacts.push(id.clone());
        let receipt = format!("{id}:receipt");
        put(
            &mut self.store,
            &self.context.task_id,
            &receipt,
            "web.binary-receipt",
            &serde_json::to_vec(
                &json!({"schema_version":"melissa.web-binary-receipt/v1","artifact_id":id,"web_reply_artifact_id":format!("{}:web-reply:{}",self.context.attempt_id,reply.seq),"seq":reply.seq,"descriptor":value,"source_digest":reply.source_digest,"blake3":digest(&bytes)}),
            )?,
        )?;
        self.artifacts.push(receipt);
        Ok(())
    }
}
