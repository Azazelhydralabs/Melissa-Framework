use crate::{Error, FileVersion, Limits, Result, digest, paths};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteEdit {
    pub start: u64,
    pub end: u64,
    pub expected: Vec<u8>,
    pub replacement: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePatch {
    pub before: FileVersion,
    pub edits: Vec<ByteEdit>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProposal {
    pub schema_version: String,
    pub root_identity: String,
    pub files: Vec<FilePatch>,
}

impl melissa_core_contracts::validation::Validate for PatchProposal {
    fn validate(&self) -> melissa_core_contracts::validation::ContractResult {
        let maximum = Limits {
            max_files: 100_000,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            max_patch_files: 1024,
            max_edits: 100_000,
            max_search_hits: 100_000,
        };
        self.validate(&maximum)
            .map_err(|e| melissa_core_contracts::validation::ContractError::new("$", e.to_string()))
    }
}

impl PatchProposal {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        melissa_core_contracts::json::parse_contract(bytes, 32 * 1024 * 1024)
            .map_err(|_| Error::Invalid("bounded duplicate-free patch JSON required"))
    }
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    pub fn validate(&self, limits: &Limits) -> Result {
        limits.validate()?;
        if self.schema_version != "melissa.repository-patch/v1"
            || self.root_identity.is_empty()
            || self.files.is_empty()
            || self.files.len() > limits.max_patch_files
        {
            return Err(Error::Invalid("patch schema or file count"));
        }
        let mut seen = BTreeSet::new();
        let mut count = 0;
        let mut total = 0u64;
        for file in &self.files {
            paths::relative(&file.before.path)?;
            if !seen.insert(paths::key(&file.before.path)) {
                return Err(Error::Invalid("duplicate or case-alias patch target"));
            }
            if file.before.identity.is_empty()
                || !valid_digest(&file.before.digest)
                || file.before.bytes > limits.max_file_bytes
                || file.edits.is_empty()
            {
                return Err(Error::Invalid("invalid patch preimage"));
            }
            let mut end = 0;
            let mut output = file.before.bytes;
            for (i, edit) in file.edits.iter().enumerate() {
                count += 1;
                if count > limits.max_edits {
                    return Err(Error::Quota("edit count"));
                }
                if edit.start > edit.end
                    || edit.end > file.before.bytes
                    || (i > 0 && edit.start <= end)
                    || edit.end - edit.start != edit.expected.len() as u64
                    || edit.expected == edit.replacement
                {
                    return Err(Error::Invalid(
                        "unordered, overlapping, ambiguous or empty edit",
                    ));
                }
                end = edit.end;
                output = output
                    .checked_sub(edit.end - edit.start)
                    .and_then(|n| n.checked_add(edit.replacement.len() as u64))
                    .ok_or(Error::Quota("patch size overflow"))?;
                if output > limits.max_file_bytes {
                    return Err(Error::Quota("patch result bytes"));
                }
            }
            total = total
                .checked_add(file.before.bytes.max(output))
                .ok_or(Error::Quota("patch total overflow"))?;
            if total > limits.max_total_bytes {
                return Err(Error::Quota("patch total bytes"));
            }
        }
        Ok(())
    }
}
fn valid_digest(s: &str) -> bool {
    s.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportProposal {
    pub patch: Option<PatchProposal>,
    pub unselected_paths: Vec<String>,
    pub unchanged_paths: Vec<String>,
}
impl crate::Repository {
    /// Explicit host-selected regular files only. A proposal grants no write
    /// permission and is revalidated again by PatchBroker at dispatch.
    pub fn propose_import(
        &self,
        source: &crate::RepositorySnapshot,
        files: &[crate::archive::ImportedFile],
        selected: &BTreeSet<String>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<ImportProposal> {
        self.validate_snapshot(source, cancel)?;
        if selected.is_empty() || selected.len() > self.limits().max_patch_files {
            return Err(Error::Invalid("explicit import file selection required"));
        }
        let mut seen = BTreeSet::new();
        let mut matched = BTreeSet::new();
        let mut proposed = Vec::new();
        let mut unchanged = Vec::new();
        let mut unselected = Vec::new();
        for f in files {
            crate::check_cancel(cancel)?;
            paths::relative(&f.path)?;
            if !seen.insert(paths::key(&f.path)) {
                return Err(Error::Invalid("duplicate import target"));
            }
            if !selected.contains(&f.path) {
                unselected.push(f.path.clone());
                continue;
            }
            matched.insert(f.path.clone());
            let observed =
                source
                    .files
                    .iter()
                    .find(|v| v.path == f.path)
                    .ok_or(Error::Unsupported(
                        "new-file import needs a separate create contract",
                    ))?;
            let (current, before) = self.read(&f.path)?;
            if current != *observed {
                return Err(Error::Stale("worker import preimage changed"));
            }
            if f.bytes.len() as u64 > self.limits().max_file_bytes {
                return Err(Error::Quota("import file bytes"));
            }
            if f.bytes == before {
                unchanged.push(f.path.clone());
                continue;
            }
            proposed.push(FilePatch {
                before: current,
                edits: vec![ByteEdit {
                    start: 0,
                    end: before.len() as u64,
                    expected: before,
                    replacement: f.bytes.clone(),
                }],
            });
        }
        if selected.iter().any(|p| !matched.contains(p)) {
            return Err(Error::Invalid(
                "selected worker output missing or differently cased",
            ));
        }
        let patch = if proposed.is_empty() {
            None
        } else {
            let p = PatchProposal {
                schema_version: "melissa.repository-patch/v1".into(),
                root_identity: self.root_identity().into(),
                files: proposed,
            };
            p.validate(self.limits())?;
            Some(p)
        };
        Ok(ImportProposal {
            patch,
            unselected_paths: unselected,
            unchanged_paths: unchanged,
        })
    }
}

pub(crate) fn apply_bytes(before: &[u8], patch: &FilePatch, limits: &Limits) -> Result<Vec<u8>> {
    if before.len() as u64 != patch.before.bytes || digest(before) != patch.before.digest {
        return Err(Error::Stale("patch preimage digest"));
    }
    let mut after = Vec::new();
    let mut last = 0;
    for edit in &patch.edits {
        let start = usize::try_from(edit.start).map_err(|_| Error::Invalid("edit offset"))?;
        let end = usize::try_from(edit.end).map_err(|_| Error::Invalid("edit offset"))?;
        if before.get(start..end) != Some(edit.expected.as_slice()) {
            return Err(Error::Stale("edit preimage bytes"));
        }
        after.extend_from_slice(&before[last..start]);
        after.extend_from_slice(&edit.replacement);
        last = end;
        if after.len() as u64 > limits.max_file_bytes {
            return Err(Error::Quota("patch output bytes"));
        }
    }
    after.extend_from_slice(&before[last..]);
    if after.len() as u64 > limits.max_file_bytes {
        return Err(Error::Quota("patch output bytes"));
    }
    Ok(after)
}
