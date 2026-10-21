use std::{collections::BTreeMap, fs, time::UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    StoreError, StoreResult,
    cas::{digest_for, validate_digest},
    crypto::stored_len_for_plain,
    journal::{decode, encode, integer},
    service::{LocalStore, unix_ms},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub artifact_id: String,
    pub task_id: String,
    pub digest_algorithm: String,
    pub digest: String,
    pub content_type: String,
    pub logical_type: String,
    pub schema_version: String,
    pub plain_bytes: u64,
    pub stored_bytes: u64,
    pub created_at_ms: u64,
    pub retain_until_ms: u64,
    pub legal_hold: bool,
}

#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub artifact_id: String,
    pub task_id: String,
    pub content_type: String,
    pub logical_type: String,
    pub schema_version: String,
    pub retain_until_ms: u64,
    pub legal_hold: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct GarbageCollection {
    pub artifacts_removed: u64,
    pub blobs_removed: u64,
    pub stored_bytes_removed: u64,
    pub staging_files_removed: u64,
    pub staging_bytes_removed: u64,
}

impl LocalStore {
    pub fn put_artifact(
        &mut self,
        request: &ArtifactRequest,
        bytes: &[u8],
    ) -> StoreResult<ArtifactMetadata> {
        request.validate()?;
        if bytes.len() as u64 > self.instance.config.max_blob_bytes {
            return Err(StoreError::Quota("per-blob plaintext limit".into()));
        }
        // Separate connection lets a file guard and an IMMEDIATE transaction
        // coexist without borrowing the public journal mutably.
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM tasks WHERE task_id=?1)",
            [&request.task_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound("artifact producer task".into()));
        }
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE artifact_id=?1)",
            [&request.artifact_id],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(StoreError::Conflict(
                "artifact identity already exists".into(),
            ));
        }
        let digest = digest_for(bytes);
        let inventory = self.cas.list()?;
        let used = inventory.iter().try_fold(0_u64, |sum, blob| {
            sum.checked_add(blob.stored_bytes)
                .ok_or_else(|| StoreError::Integrity("CAS inventory byte overflow".into()))
        })?;
        let additional = if inventory.iter().any(|blob| blob.digest == digest) {
            0
        } else {
            stored_len_for_plain(bytes.len() as u64)?
        };
        if used
            .checked_add(additional)
            .is_none_or(|total| total > self.instance.config.max_cas_bytes)
        {
            return Err(StoreError::Quota(
                "encrypted published CAS bytes, including orphans".into(),
            ));
        }
        // Blob publication precedes metadata commit. A crash may leave an
        // unreferenced blob; it cannot commit a reference to a partial blob.
        let blob = self.cas.put(bytes)?;
        let now = unix_ms()?;
        let metadata = ArtifactMetadata {
            artifact_id: request.artifact_id.clone(),
            task_id: request.task_id.clone(),
            digest_algorithm: "blake3".into(),
            digest: blob.digest.clone(),
            content_type: request.content_type.clone(),
            logical_type: request.logical_type.clone(),
            schema_version: request.schema_version.clone(),
            plain_bytes: blob.plain_bytes,
            stored_bytes: blob.stored_bytes,
            created_at_ms: now,
            retain_until_ms: request.retain_until_ms,
            legal_hold: request.legal_hold,
        };
        let payload = encode(
            &self.instance.key,
            &artifact_context(&metadata.task_id, &metadata.artifact_id),
            &metadata,
            64 * 1024,
        )?;
        tx.execute("INSERT INTO blob_objects(digest,plain_bytes,stored_bytes,created_at_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(digest) DO NOTHING",
            params![blob.digest, integer(blob.plain_bytes)?, integer(blob.stored_bytes)?, integer(now)?])?;
        tx.execute("INSERT INTO artifacts(artifact_id,task_id,digest,content_type,logical_type,schema_version,created_at_ms,retain_until_ms,legal_hold,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![metadata.artifact_id,metadata.task_id,metadata.digest,metadata.content_type,metadata.logical_type,metadata.schema_version,integer(now)?,integer(metadata.retain_until_ms)?,metadata.legal_hold,payload])?;
        tx.execute("INSERT INTO artifact_refs(owner_task_id,owner_kind,owner_id,artifact_id) VALUES(?1,'task',?1,?2)", params![metadata.task_id,metadata.artifact_id])?;
        tx.commit()?;
        Ok(metadata)
    }

    pub fn artifact_metadata(
        &self,
        task_id: &str,
        artifact_id: &str,
    ) -> StoreResult<ArtifactMetadata> {
        artifact_on(&self.journal.conn, &self.instance.key, task_id, artifact_id)
    }

    pub fn get_artifact(&self, task_id: &str, artifact_id: &str) -> StoreResult<Vec<u8>> {
        let _guard = self.file_guard()?;
        let metadata = self.artifact_metadata(task_id, artifact_id)?;
        let content = self.cas.get(&metadata.digest)?;
        if content.len() as u64 != metadata.plain_bytes {
            return Err(StoreError::Integrity(
                "artifact size differs from authenticated metadata".into(),
            ));
        }
        Ok(content)
    }

    pub fn set_artifact_retention(
        &mut self,
        task_id: &str,
        artifact_id: &str,
        retain_until_ms: u64,
        legal_hold: bool,
    ) -> StoreResult<()> {
        integer(retain_until_ms)?;
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut metadata = artifact_on(&tx, &self.instance.key, task_id, artifact_id)?;
        metadata.retain_until_ms = retain_until_ms;
        metadata.legal_hold = legal_hold;
        let payload = encode(
            &self.instance.key,
            &artifact_context(task_id, artifact_id),
            &metadata,
            64 * 1024,
        )?;
        tx.execute(
            "UPDATE artifacts SET retain_until_ms=?1,legal_hold=?2,payload=?3 WHERE artifact_id=?4",
            params![integer(retain_until_ms)?, legal_hold, payload, artifact_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Release only the automatic owner pin of a terminal task. Final/evidence,
    /// checkpoint and invocation references remain live and cannot be erased by
    /// this retention action.
    pub fn release_artifact(&mut self, task_id: &str, artifact_id: &str) -> StoreResult<()> {
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = artifact_on(&tx, &self.instance.key, task_id, artifact_id)?;
        let task = self.journal.task(task_id)?;
        if !task.record.state.is_terminal() {
            return Err(StoreError::Conflict(
                "active task artifact must remain referenced".into(),
            ));
        }
        if task.record.final_artifact_digest.as_deref() == Some(&metadata.digest) {
            return Err(StoreError::Conflict(
                "task final artifact remains live".into(),
            ));
        }
        tx.execute("DELETE FROM artifact_refs WHERE owner_task_id=?1 AND owner_kind='task' AND owner_id=?1 AND artifact_id=?2",params![task_id,artifact_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn pin_artifact(
        &mut self,
        task_id: &str,
        artifact_id: &str,
        pin_id: &str,
    ) -> StoreResult<()> {
        text(pin_id, "pin ID", 256)?;
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        artifact_on(&tx, &self.instance.key, task_id, artifact_id)?;
        tx.execute("INSERT INTO artifact_refs(owner_task_id,owner_kind,owner_id,artifact_id) VALUES(?1,'pin',?2,?3) ON CONFLICT DO NOTHING",params![task_id,pin_id,artifact_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn unpin_artifact(
        &mut self,
        task_id: &str,
        artifact_id: &str,
        pin_id: &str,
    ) -> StoreResult<()> {
        text(pin_id, "pin ID", 256)?;
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        artifact_on(&tx, &self.instance.key, task_id, artifact_id)?;
        tx.execute("DELETE FROM artifact_refs WHERE owner_task_id=?1 AND owner_kind='pin' AND owner_id=?2 AND artifact_id=?3",params![task_id,pin_id,artifact_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn collect_garbage(
        &mut self,
        now_ms: u64,
        orphan_grace_ms: u64,
    ) -> StoreResult<GarbageCollection> {
        integer(now_ms)?;
        let cutoff = now_ms.saturating_sub(orphan_grace_ms);
        let _guard = self.file_guard()?;
        let mut connection = self.connect()?;
        let tx = connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut removed = GarbageCollection::default();
        // Authenticated journal proofs must still have their permanent reference
        // indexes before any deletion is considered.
        self.journal.integrity_check()?;
        let candidates = {
            let mut statement = tx.prepare("SELECT task_id,artifact_id FROM artifacts WHERE legal_hold=0 AND retain_until_ms<=?1 AND NOT EXISTS(SELECT 1 FROM artifact_refs r WHERE r.artifact_id=artifacts.artifact_id) AND NOT EXISTS(SELECT 1 FROM checkpoints c WHERE c.artifact_id=artifacts.artifact_id) AND NOT EXISTS(SELECT 1 FROM invocations i WHERE i.result_artifact_id=artifacts.artifact_id)")?;
            statement
                .query_map([integer(now_ms)?], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (task_id, artifact_id) in candidates {
            let metadata = artifact_on(&tx, &self.instance.key, &task_id, &artifact_id)?;
            let task = self.journal.task(&task_id)?;
            if !task.record.state.is_terminal()
                || task.record.final_artifact_digest.as_deref() == Some(&metadata.digest)
            {
                continue;
            }
            tx.execute("DELETE FROM artifacts WHERE artifact_id=?1", [&artifact_id])?;
            removed.artifacts_removed += 1;
        }
        tx.execute("DELETE FROM blob_objects WHERE NOT EXISTS(SELECT 1 FROM artifacts a WHERE a.digest=blob_objects.digest)",[])?;
        let registered = {
            let mut statement = tx.prepare("SELECT digest FROM blob_objects")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        };
        // Commit reference removals before unlinking. If unlink/host crashes,
        // only an orphan remains. File coordination prevents republishing the
        // same digest during the commit-to-unlink interval.
        tx.commit()?;
        for blob in self.cas.list()? {
            if registered.contains(&blob.digest) {
                continue;
            }
            let modified = fs::metadata(self.cas.blob_path(&blob.digest)?)?
                .modified()?
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError::Integrity("blob timestamp precedes epoch".into()))?
                .as_millis();
            if modified > u128::from(cutoff) {
                continue;
            }
            self.cas.remove(&blob.digest)?;
            removed.blobs_removed += 1;
            removed.stored_bytes_removed = removed
                .stored_bytes_removed
                .checked_add(blob.stored_bytes)
                .ok_or_else(|| StoreError::Integrity("GC byte overflow".into()))?;
        }
        let staging = self.cas.sweep_staging(cutoff)?;
        removed.staging_files_removed = staging.removed_files;
        removed.staging_bytes_removed = staging.removed_bytes;
        Ok(removed)
    }

    pub(crate) fn check_artifact_integrity(&self) -> StoreResult<()> {
        let inventory: BTreeMap<_, _> = self
            .cas
            .list()?
            .into_iter()
            .map(|blob| (blob.digest.clone(), blob))
            .collect();
        let mut statement = self
            .journal
            .conn
            .prepare("SELECT digest,plain_bytes,stored_bytes FROM blob_objects")?;
        let entries = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for entry in entries {
            let (digest, plain, stored) = entry?;
            let blob = inventory
                .get(&digest)
                .ok_or_else(|| StoreError::Integrity("registered CAS object is missing".into()))?;
            if i64::try_from(blob.plain_bytes).ok() != Some(plain)
                || i64::try_from(blob.stored_bytes).ok() != Some(stored)
            {
                return Err(StoreError::Integrity(
                    "registered CAS length mismatch".into(),
                ));
            }
        }
        let mut statement = self
            .journal
            .conn
            .prepare("SELECT task_id,artifact_id FROM artifacts")?;
        let entries = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for entry in entries {
            let (task, artifact) = entry?;
            artifact_on(&self.journal.conn, &self.instance.key, &task, &artifact)?;
        }
        Ok(())
    }
}

impl ArtifactRequest {
    fn validate(&self) -> StoreResult<()> {
        text(&self.artifact_id, "artifact ID", 256)?;
        text(&self.task_id, "task ID", 256)?;
        text(&self.content_type, "content type", 256)?;
        if !self.content_type.contains('/') {
            return Err(StoreError::Invalid(
                "artifact content type must include MIME type/subtype".into(),
            ));
        }
        text(&self.logical_type, "logical type", 256)?;
        text(&self.schema_version, "artifact schema version", 256)?;
        integer(self.retain_until_ms)?;
        Ok(())
    }
}

pub(crate) fn text(value: &str, field: &str, maximum: usize) -> StoreResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(StoreError::Invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn artifact_context(task_id: &str, artifact_id: &str) -> String {
    // Length-prefix each arbitrary ID; delimiters inside IDs cannot alias AAD.
    format!(
        "artifact/v1/{}:{task_id}/{}:{artifact_id}",
        task_id.len(),
        artifact_id.len()
    )
}

fn artifact_on(
    conn: &Connection,
    key: &crate::crypto::StoreKey,
    task_id: &str,
    artifact_id: &str,
) -> StoreResult<ArtifactMetadata> {
    type Indexed = (
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        bool,
        Vec<u8>,
        i64,
        i64,
    );
    let indexed: Option<Indexed> = conn.query_row("SELECT a.task_id,a.digest,a.content_type,a.logical_type,a.schema_version,a.created_at_ms,a.retain_until_ms,a.legal_hold,a.payload,b.plain_bytes,b.stored_bytes FROM artifacts a JOIN blob_objects b ON b.digest=a.digest WHERE a.artifact_id=?1",[artifact_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?))).optional()?;
    let (owner, digest, mime, logical, version, created, retain, hold, payload, plain, stored) =
        indexed.ok_or_else(|| StoreError::NotFound("artifact".into()))?;
    if owner != task_id {
        return Err(StoreError::NotFound("artifact in this task scope".into()));
    }
    let metadata: ArtifactMetadata = decode(
        key,
        &artifact_context(task_id, artifact_id),
        &payload,
        64 * 1024,
    )?;
    validate_digest(&metadata.digest)?;
    if metadata.artifact_id != artifact_id
        || metadata.task_id != owner
        || metadata.digest_algorithm != "blake3"
        || metadata.digest != digest
        || metadata.content_type != mime
        || metadata.logical_type != logical
        || metadata.schema_version != version
        || i64::try_from(metadata.created_at_ms).ok() != Some(created)
        || i64::try_from(metadata.retain_until_ms).ok() != Some(retain)
        || metadata.legal_hold != hold
        || i64::try_from(metadata.plain_bytes).ok() != Some(plain)
        || i64::try_from(metadata.stored_bytes).ok() != Some(stored)
        || stored_len_for_plain(metadata.plain_bytes)? != metadata.stored_bytes
    {
        return Err(StoreError::Integrity(
            "artifact authenticated metadata differs from indexes".into(),
        ));
    }
    Ok(metadata)
}
