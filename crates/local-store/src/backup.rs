use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use melissa_core_contracts::{
    json::parse_contract,
    validation::{ContractResult, Validate, require},
};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};

use crate::{
    LocalStore, StoreConfig, StoreError, StoreKey, StoreResult,
    cas::{BlobInfo, Cas, validate_digest},
    crypto::ENVELOPE_OVERHEAD,
    service::{clean_absolute, ensure_directory, reject_link_if_exists, unix_ms},
};

const MANIFEST_AAD: &[u8] = b"melissa.local-store.backup-manifest/v1";
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_BACKUP_BLOBS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBlob {
    pub content: BlobInfo,
    pub ciphertext_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub schema_version: String,
    pub created_at_ms: u64,
    pub database_digest: String,
    pub database_bytes: u64,
    pub blobs: Vec<BackupBlob>,
}

impl Validate for BackupManifest {
    fn validate(&self) -> ContractResult<()> {
        require(
            self.schema_version == "melissa.local-store-backup/v1",
            "schema_version",
            "unsupported backup version",
        )?;
        require(
            self.database_bytes > 0,
            "database_bytes",
            "empty database snapshot",
        )?;
        require(
            self.blobs.len() <= MAX_BACKUP_BLOBS,
            "blobs",
            "too many backup blobs",
        )?;
        require(
            validate_digest(&self.database_digest).is_ok(),
            "database_digest",
            "invalid digest",
        )?;
        let mut seen = std::collections::BTreeSet::new();
        for blob in &self.blobs {
            require(
                validate_digest(&blob.content.digest).is_ok()
                    && validate_digest(&blob.ciphertext_digest).is_ok(),
                "blobs.digest",
                "invalid blob digest",
            )?;
            require(
                seen.insert(&blob.content.digest),
                "blobs",
                "duplicate content identity",
            )?;
            require(
                blob.content.plain_bytes.checked_add(ENVELOPE_OVERHEAD)
                    == Some(blob.content.stored_bytes),
                "blobs.size",
                "invalid encrypted blob length",
            )?;
        }
        Ok(())
    }
}

impl LocalStore {
    /// Export to a new directory. A manifest published last is the commit
    /// marker; interrupted exports remain incomplete and cannot be restored.
    /// The live store is never moved or replaced.
    pub fn backup(&self, destination: &Path) -> StoreResult<BackupManifest> {
        let destination = clean_absolute(destination)?;
        disjoint(&destination, self.root())?;
        fresh_parent(&destination)?;
        let _guard = self.file_guard()?;
        // Block every SQLite writer, including direct Journal handles, while
        // online backup and its CAS inventory are captured from one state.
        let mut guard_connection = self.connect()?;
        let _write_lock = guard_connection
            .journal
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.journal.integrity_check()?;
        self.check_artifact_integrity()?;
        fs::create_dir(&destination)?;
        let database = destination.join("store.sqlite3");
        self.journal.backup_to(&database)?;
        // Windows FlushFileBuffers requires a writable handle.
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)?
            .sync_all()?;
        let (database_digest, database_bytes) =
            file_digest(&database, self.instance.config.journal.max_database_bytes)?;
        let backup_cas = Cas::open(
            &destination.join("cas"),
            self.instance.key.clone(),
            self.instance.config.max_blob_bytes,
        )?;
        let registered = {
            let mut statement = self
                .journal
                .conn
                .prepare("SELECT digest FROM blob_objects ORDER BY digest")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        };
        if registered.len() > MAX_BACKUP_BLOBS {
            return Err(StoreError::Quota("backup blob count".into()));
        }
        let mut blobs = Vec::new();
        for blob in self.cas.list()? {
            if !registered.contains(&blob.digest) {
                continue;
            }
            let source = self.cas.blob_path(&blob.digest)?;
            let target = backup_cas.blob_path(&blob.digest)?;
            copy_new(&source, &target, blob.stored_bytes)?;
            let (ciphertext_digest, size) = file_digest(&target, blob.stored_bytes)?;
            if size != blob.stored_bytes
                || backup_cas.get(&blob.digest)?.len() as u64 != blob.plain_bytes
            {
                return Err(StoreError::Integrity("exported CAS object mismatch".into()));
            }
            blobs.push(BackupBlob {
                content: blob,
                ciphertext_digest,
            });
        }
        if blobs.len() != registered.len() {
            return Err(StoreError::Integrity(
                "backup missed a registered CAS object".into(),
            ));
        }
        let manifest = BackupManifest {
            schema_version: "melissa.local-store-backup/v1".into(),
            created_at_ms: unix_ms()?,
            database_digest,
            database_bytes,
            blobs,
        };
        manifest.validate()?;
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&manifest)?);
        if plaintext.len() > MAX_MANIFEST_BYTES {
            return Err(StoreError::Quota("backup manifest".into()));
        }
        let envelope = self.instance.key.seal(&plaintext, MANIFEST_AAD)?;
        write_new(&destination.join("manifest.enc"), &envelope)?;
        Ok(manifest)
    }

    /// Validate an authenticated backup and restore only into a new directory.
    /// Existing destinations are rejected, including empty ones. Startup marks
    /// any possibly executed attempts unknown; it never replays their effects.
    pub fn restore_backup(
        source: &Path,
        destination: &Path,
        key: StoreKey,
        config: StoreConfig,
    ) -> StoreResult<Self> {
        config.validate()?;
        let source = clean_absolute(source)?;
        let destination = clean_absolute(destination)?;
        disjoint(&source, &destination)?;
        for ancestor in source.ancestors() {
            reject_link_if_exists(ancestor)?;
        }
        fresh_parent(&destination)?;
        let manifest_path = source.join("manifest.enc");
        let envelope = read_bounded(
            &manifest_path,
            MAX_MANIFEST_BYTES as u64 + ENVELOPE_OVERHEAD,
        )?;
        let plaintext = zeroize::Zeroizing::new(key.open(&envelope, MANIFEST_AAD)?);
        let manifest: BackupManifest = parse_contract(&plaintext, MAX_MANIFEST_BYTES)?;
        if manifest.database_bytes > config.journal.max_database_bytes {
            return Err(StoreError::Quota(
                "restored database exceeds configured limit".into(),
            ));
        }
        let total = manifest.blobs.iter().try_fold(0_u64, |sum, blob| {
            sum.checked_add(blob.content.stored_bytes)
                .ok_or_else(|| StoreError::Quota("backup size overflow".into()))
        })?;
        if total > config.max_cas_bytes
            || manifest
                .blobs
                .iter()
                .any(|blob| blob.content.plain_bytes > config.max_blob_bytes)
        {
            return Err(StoreError::Quota(
                "restored CAS exceeds configured limits".into(),
            ));
        }
        let (digest, size) = file_digest(&source.join("store.sqlite3"), manifest.database_bytes)?;
        if digest != manifest.database_digest || size != manifest.database_bytes {
            return Err(StoreError::Integrity(
                "backup database digest mismatch".into(),
            ));
        }
        // Backup CAS directories were created by the exporter. Require them to
        // exist so validation cannot initialize an incomplete input backup.
        for relative in ["cas", "cas/blobs", "cas/staging"] {
            let path = source.join(relative);
            reject_link_if_exists(&path)?;
            if !fs::metadata(&path)?.is_dir() {
                return Err(StoreError::Integrity("backup CAS layout".into()));
            }
        }
        let backup_cas = Cas::open(&source.join("cas"), key.clone(), config.max_blob_bytes)?;
        let inventory = backup_cas.list()?;
        if inventory.len() != manifest.blobs.len() {
            return Err(StoreError::Integrity(
                "backup CAS inventory mismatch".into(),
            ));
        }
        for blob in &manifest.blobs {
            let (digest, size) = file_digest(
                &backup_cas.blob_path(&blob.content.digest)?,
                blob.content.stored_bytes,
            )?;
            if digest != blob.ciphertext_digest
                || size != blob.content.stored_bytes
                || !inventory.iter().any(|actual| actual == &blob.content)
            {
                return Err(StoreError::Integrity(
                    "backup CAS digest/size mismatch".into(),
                ));
            }
        }
        // All source bytes are verified before allocating a destination. The
        // final open rechecks copied ciphertext, schema, FK and journal replay.
        fs::create_dir(&destination)?;
        copy_new(
            &source.join("store.sqlite3"),
            &destination.join("store.sqlite3"),
            manifest.database_bytes,
        )?;
        let restored_cas = Cas::open(&destination.join("cas"), key.clone(), config.max_blob_bytes)?;
        for blob in &manifest.blobs {
            let target = restored_cas.blob_path(&blob.content.digest)?;
            copy_new(
                &backup_cas.blob_path(&blob.content.digest)?,
                &target,
                blob.content.stored_bytes,
            )?;
            let (digest, size) = file_digest(&target, blob.content.stored_bytes)?;
            if digest != blob.ciphertext_digest || size != blob.content.stored_bytes {
                return Err(StoreError::Integrity(
                    "restored CAS ciphertext differs from backup manifest".into(),
                ));
            }
        }
        let (digest, size) =
            file_digest(&destination.join("store.sqlite3"), manifest.database_bytes)?;
        if digest != manifest.database_digest || size != manifest.database_bytes {
            return Err(StoreError::Integrity(
                "restored database differs from backup".into(),
            ));
        }
        Self::open(&destination, key, config)
    }
}

fn disjoint(left: &Path, right: &Path) -> StoreResult<()> {
    let (left, right) = (identity_path(left)?, identity_path(right)?);
    #[cfg(windows)]
    let (left, right) = (
        PathBuf::from(left.to_string_lossy().to_lowercase()),
        PathBuf::from(right.to_string_lossy().to_lowercase()),
    );
    if left.starts_with(&right) || right.starts_with(&left) {
        return Err(StoreError::Invalid(
            "backup/store paths must be disjoint".into(),
        ));
    }
    Ok(())
}

fn identity_path(path: &Path) -> StoreResult<PathBuf> {
    // Resolve existing ancestors before comparing identities. Windows 8.3 names
    // and casing aliases must not hide a destination inside the live store.
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| StoreError::Invalid("path has no existing ancestor".into()))?
                        .to_owned(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| StoreError::Invalid("path has no parent".into()))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    for parent in ancestor.ancestors() {
        reject_link_if_exists(parent)?;
    }
    let mut identity = fs::canonicalize(ancestor)?;
    for part in suffix.into_iter().rev() {
        identity.push(part);
    }
    Ok(identity)
}

fn fresh_parent(path: &Path) -> StoreResult<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(StoreError::Conflict("destination already exists".into()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::Invalid("destination has no parent".into()))?;
    ensure_directory(parent)
}

fn read_bounded(path: &Path, maximum: u64) -> StoreResult<Vec<u8>> {
    reject_link_if_exists(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(StoreError::Quota("backup file exceeds limit".into()));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(
            maximum
                .checked_add(1)
                .ok_or_else(|| StoreError::Invalid("backup bound overflow".into()))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(StoreError::Integrity(
            "backup file changed or is incomplete".into(),
        ));
    }
    Ok(bytes)
}

fn file_digest(path: &Path, maximum: u64) -> StoreResult<(String, u64)> {
    reject_link_if_exists(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(StoreError::Quota("backup file size".into()));
    }
    let mut reader = File::open(path)?.take(
        maximum
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("backup bound overflow".into()))?,
    );
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total = total
            .checked_add(size as u64)
            .ok_or_else(|| StoreError::Quota("backup byte overflow".into()))?;
        if total > maximum {
            return Err(StoreError::Quota("backup file grew past limit".into()));
        }
        hasher.update(&buffer[..size]);
    }
    if total != metadata.len() {
        return Err(StoreError::Integrity("backup file changed".into()));
    }
    Ok((format!("blake3:{}", hasher.finalize().to_hex()), total))
}

fn write_new(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn copy_new(source: &Path, destination: &Path, maximum: u64) -> StoreResult<()> {
    reject_link_if_exists(source)?;
    let mut reader = File::open(source)?.take(
        maximum
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("backup copy bound overflow".into()))?,
    );
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let copied = std::io::copy(&mut reader, &mut writer)?;
    if copied != maximum {
        return Err(StoreError::Integrity(
            "backup copy is partial or changed".into(),
        ));
    }
    writer.sync_all()?;
    Ok(())
}
