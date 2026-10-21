//! Encrypted content-addressed files. The service owns authorization, quotas,
//! references and GC serialization; direct CAS access is a trusted-host API.
use std::{
    fs::{self, File, Metadata},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    StoreError, StoreResult,
    crypto::{ENVELOPE_OVERHEAD, StoreKey, stored_len_for_plain},
};

const STAGE_PREFIX: &str = "cas-stage-";
const STAGE_SUFFIX: &str = ".tmp";
const MAX_SCAN_ENTRIES: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobInfo {
    pub digest: String,
    pub plain_bytes: u64,
    pub stored_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingSweep {
    pub removed_files: u64,
    pub removed_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Cas {
    root: PathBuf,
    key: StoreKey,
    max_blob_bytes: u64,
}

impl Cas {
    pub fn open(root: &Path, key: StoreKey, max_blob_bytes: u64) -> StoreResult<Self> {
        let max_stored = stored_len_for_plain(max_blob_bytes)?;
        if max_stored >= usize::MAX as u64 {
            return Err(StoreError::Invalid(
                "blob limit exceeds address space".into(),
            ));
        }
        let root = absolute_clean_path(root)?;
        ensure_directory(&root)?;
        ensure_directory(&root.join("blobs"))?;
        ensure_directory(&root.join("staging"))?;
        Ok(Self {
            root,
            key,
            max_blob_bytes,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(&self, plaintext: &[u8]) -> StoreResult<BlobInfo> {
        self.validate_directories()?;
        if plaintext.len() as u64 > self.max_blob_bytes {
            return Err(StoreError::Quota(
                "blob exceeds configured byte limit".into(),
            ));
        }
        let digest = digest_for(plaintext);
        let path = self.blob_path(&digest)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => return self.verified_info(&digest),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let envelope = self.key.seal(plaintext, &blob_aad(&digest))?;
        let mut staged = tempfile::Builder::new()
            .prefix(STAGE_PREFIX)
            .suffix(STAGE_SUFFIX)
            .tempfile_in(self.root.join("staging"))?;
        staged.write_all(&envelope)?;
        staged.as_file().sync_all()?;
        self.validate_directories()?;
        match staged.persist_noclobber(&path) {
            Ok(published) => {
                published.sync_all()?;
                sync_directory(&self.root.join("blobs"))?;
                self.verified_info(&digest)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent successful writer may win; verify its complete
                // ciphertext instead of assuming an existing name is healthy.
                self.verified_info(&digest)
            }
            Err(error) => Err(error.error.into()),
        }
    }

    pub fn get(&self, digest: &str) -> StoreResult<Vec<u8>> {
        self.validate_directories()?;
        let path = self.blob_path(digest)?;
        let metadata = regular_metadata(&path).map_err(|error| match error {
            StoreError::Io(value) if value.kind() == std::io::ErrorKind::NotFound => {
                StoreError::NotFound("CAS blob".into())
            }
            other => other,
        })?;
        let max_stored = stored_len_for_plain(self.max_blob_bytes)?;
        if metadata.len() < ENVELOPE_OVERHEAD || metadata.len() > max_stored {
            return Err(StoreError::Integrity(
                "CAS blob size is outside limits".into(),
            ));
        }
        let file = File::open(&path)?;
        validate_regular(&file.metadata()?)?;
        let mut bytes = Vec::new();
        file.take(max_stored + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > max_stored {
            return Err(StoreError::Integrity(
                "CAS blob changed or exceeds limits".into(),
            ));
        }
        let mut plaintext = Zeroizing::new(self.key.open(&bytes, &blob_aad(digest))?);
        if plaintext.len() as u64 > self.max_blob_bytes || digest_for(&plaintext) != digest {
            return Err(StoreError::Integrity(
                "CAS plaintext digest mismatch".into(),
            ));
        }
        Ok(std::mem::take(&mut *plaintext))
    }

    /// Full verification is intentional: a directory name alone is not a valid
    /// blob inventory or quota-accounting record.
    pub fn list(&self) -> StoreResult<Vec<BlobInfo>> {
        self.validate_directories()?;
        let mut result = Vec::new();
        for (index, entry) in fs::read_dir(self.root.join("blobs"))?.enumerate() {
            if index >= MAX_SCAN_ENTRIES {
                return Err(StoreError::Quota("CAS inventory scan limit".into()));
            }
            let entry = entry?;
            regular_metadata(&entry.path())?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| StoreError::Integrity("non-UTF8 CAS filename".into()))?;
            let hex = name
                .strip_suffix(".blob")
                .ok_or_else(|| StoreError::Integrity("unexpected CAS file".into()))?;
            let digest = format!("blake3:{hex}");
            validate_digest(&digest)
                .map_err(|_| StoreError::Integrity("unexpected CAS filename".into()))?;
            result.push(self.verified_info(&digest)?);
        }
        result.sort_unstable_by(|left, right| left.digest.cmp(&right.digest));
        Ok(result)
    }

    /// The owner must prove this blob is unreferenced and serialize GC against
    /// publication/reference commits before calling this primitive.
    pub fn remove(&self, digest: &str) -> StoreResult<()> {
        self.validate_directories()?;
        let path = self.blob_path(digest)?;
        regular_metadata(&path)?;
        fs::remove_file(path)?;
        sync_directory(&self.root.join("blobs"))
    }

    /// Remove only this implementation's old staging files. Call only while
    /// publication is excluded by the owner's session/transaction guard.
    pub fn sweep_staging(&self, older_than_unix_ms: u64) -> StoreResult<StagingSweep> {
        self.validate_directories()?;
        let mut sweep = StagingSweep::default();
        for (index, entry) in fs::read_dir(self.root.join("staging"))?.enumerate() {
            if index >= MAX_SCAN_ENTRIES {
                return Err(StoreError::Quota("CAS staging scan limit".into()));
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(unique) = name
                .strip_prefix(STAGE_PREFIX)
                .and_then(|name| name.strip_suffix(STAGE_SUFFIX))
            else {
                continue;
            };
            if unique.is_empty() || !unique.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                continue;
            }
            let metadata = regular_metadata(&entry.path())?;
            let modified = metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError::Integrity("staging timestamp precedes epoch".into()))?
                .as_millis();
            if modified >= u128::from(older_than_unix_ms) {
                continue;
            }
            fs::remove_file(entry.path())?;
            sweep.removed_files += 1;
            sweep.removed_bytes = sweep
                .removed_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| StoreError::Integrity("staging byte count overflow".into()))?;
        }
        if sweep.removed_files > 0 {
            sync_directory(&self.root.join("staging"))?;
        }
        Ok(sweep)
    }

    pub(crate) fn blob_path(&self, digest: &str) -> StoreResult<PathBuf> {
        validate_digest(digest)?;
        Ok(self
            .root
            .join("blobs")
            .join(format!("{}.blob", &digest[7..])))
    }

    fn verified_info(&self, digest: &str) -> StoreResult<BlobInfo> {
        let plaintext = Zeroizing::new(self.get(digest)?);
        let stored_bytes = regular_metadata(&self.blob_path(digest)?)?.len();
        if stored_bytes != stored_len_for_plain(plaintext.len() as u64)? {
            return Err(StoreError::Integrity("CAS envelope length mismatch".into()));
        }
        Ok(BlobInfo {
            digest: digest.into(),
            plain_bytes: plaintext.len() as u64,
            stored_bytes,
        })
    }

    fn validate_directories(&self) -> StoreResult<()> {
        validate_ancestry(&self.root)?;
        validate_directory(&self.root.join("blobs"))?;
        validate_directory(&self.root.join("staging"))
    }
}

pub fn digest_for(plaintext: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(plaintext).to_hex())
}

pub fn validate_digest(digest: &str) -> StoreResult<()> {
    let Some(hex) = digest.strip_prefix("blake3:") else {
        return Err(StoreError::Invalid(
            "expected canonical BLAKE3 digest".into(),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::Invalid(
            "expected canonical BLAKE3 digest".into(),
        ));
    }
    Ok(())
}

fn blob_aad(digest: &str) -> Vec<u8> {
    format!("melissa.cas.blob.v1\0{digest}").into_bytes()
}

pub(crate) fn absolute_clean_path(path: &Path) -> StoreResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::Invalid("empty CAS path".into()));
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(StoreError::Invalid("CAS path contains traversal".into()));
    }
    #[cfg(windows)]
    for part in path.components() {
        use std::path::Prefix;
        match part {
            Component::Prefix(prefix)
                if !matches!(prefix.kind(), Prefix::Disk(_)) || !path.is_absolute() =>
            {
                return Err(StoreError::Invalid(
                    "CAS path requires a local drive".into(),
                ));
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                let stem = name.split('.').next().unwrap_or_default().to_uppercase();
                let device = matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|prefix| {
                    stem.strip_prefix(prefix).is_some_and(|suffix| {
                        matches!(
                            suffix,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                });
                if device
                    || name.ends_with(['.', ' '])
                    || name
                        .chars()
                        .any(|value| value <= '\u{1f}' || "<>:\"|?*".contains(value))
                {
                    return Err(StoreError::Invalid(
                        "unsafe Windows CAS path component".into(),
                    ));
                }
            }
            _ => {}
        }
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        if path.has_root() {
            return Err(StoreError::Invalid(
                "CAS path is not fully qualified".into(),
            ));
        }
        std::env::current_dir()?.join(path)
    };
    if !absolute.is_absolute() {
        return Err(StoreError::Invalid(
            "CAS path is not fully qualified".into(),
        ));
    }
    Ok(absolute)
}

pub(crate) fn ensure_directory(path: &Path) -> StoreResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_ancestry(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| StoreError::Invalid("CAS root missing".into()))?;
            ensure_directory(parent)?;
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            validate_ancestry(path)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_ancestry(path: &Path) -> StoreResult<()> {
    for ancestor in path.ancestors() {
        validate_directory(ancestor)?;
    }
    Ok(())
}

fn validate_directory(path: &Path) -> StoreResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(StoreError::Invalid(
            "CAS directory is linked or not a directory".into(),
        ));
    }
    Ok(())
}

fn regular_metadata(path: &Path) -> StoreResult<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    validate_regular(&metadata)?;
    Ok(metadata)
}

fn validate_regular(metadata: &Metadata) -> StoreResult<()> {
    if is_link_or_reparse(metadata) || !metadata.is_file() {
        return Err(StoreError::Integrity(
            "CAS entry is linked or not a regular file".into(),
        ));
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn sync_directory(path: &Path) -> StoreResult<()> {
    // std cannot open directory handles for FlushFileBuffers on Windows.
    // The file itself is synced; directory durability remains an OS/filesystem
    // property, and recovery verifies inventory rather than claiming power-loss
    // atomicity on every filesystem.
    #[cfg(not(windows))]
    File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}
