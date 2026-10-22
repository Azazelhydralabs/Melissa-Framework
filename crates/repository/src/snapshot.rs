use crate::{
    Error, Result, check_cancel, digest,
    paths::{self, Pinned},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_patch_files: usize,
    pub max_edits: usize,
    pub max_search_hits: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_patch_files: 128,
            max_edits: 4096,
            max_search_hits: 1000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result {
        if self.max_files == 0
            || self.max_files > 100_000
            || self.max_file_bytes == 0
            || self.max_file_bytes > 64 * 1024 * 1024
            || self.max_total_bytes < self.max_file_bytes
            || self.max_total_bytes > 1024 * 1024 * 1024
            || self.max_patch_files == 0
            || self.max_patch_files > 1024
            || self.max_edits == 0
            || self.max_edits > 100_000
            || self.max_search_hits == 0
            || self.max_search_hits > 100_000
        {
            return Err(Error::Invalid("invalid host resource envelope"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileVersion {
    pub path: String,
    pub identity: String,
    pub digest: String,
    pub bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySnapshot {
    pub schema_version: String,
    pub root_identity: String,
    pub files: Vec<FileVersion>,
    pub digest: String,
    pub total_bytes: u64,
    pub atomic_tree_snapshot: bool,
    pub excluded_prefixes: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub path: String,
    pub digest: String,
    pub byte_offset: usize,
    pub line: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub truncated: bool,
    pub snapshot_digest: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct WorkerInput {
    pub source_snapshot_digest: String,
    pub snapshot: melissa_container_executor::Snapshot,
}

pub struct Repository {
    pub(crate) root: Pinned,
    pub(crate) limits: Limits,
    excluded: Vec<String>,
}
impl Repository {
    /// Host-selected workspace. Does not run Git, build scripts, hooks or tools.
    pub fn open(root: &Path, limits: Limits, excluded_prefixes: Vec<String>) -> Result<Self> {
        limits.validate()?;
        for p in &excluded_prefixes {
            paths::relative(p)?;
        }
        let mut excluded = vec![
            ".git".into(),
            "target".into(),
            "node_modules".into(),
            ".venv".into(),
        ];
        excluded.extend(excluded_prefixes);
        Ok(Self {
            root: paths::pin(root, true, false)?,
            limits,
            excluded,
        })
    }
    pub fn root_path(&self) -> &Path {
        &self.root.canonical
    }
    /// Exact bounded worktree capture for Git: no generated/ignored exclusions.
    /// A repository that exceeds the selected envelope fails instead of
    /// reporting missing tracked files as deleted.
    pub fn open_for_git(root: &Path, limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            root: paths::pin(root, true, false)?,
            limits,
            excluded: vec![".git".into()],
        })
    }
    pub fn root_identity(&self) -> &str {
        &self.root.identity
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub(crate) fn check_path(&self, path: &str) -> Result {
        paths::relative(path)?;
        // Git internals are never source files, including nested repositories.
        if path.split('/').any(|s| s.eq_ignore_ascii_case(".git")) {
            return Err(Error::Denied("Git metadata is outside file capability"));
        }
        Ok(())
    }
    pub(crate) fn lock(&self, path: &str, write: bool) -> Result<Pinned> {
        self.check_path(path)?;
        paths::pin(
            &self.root.canonical.join(path.replace('/', "\\")),
            false,
            write,
        )
    }
    pub(crate) fn read_locked(
        &self,
        pin: &mut Pinned,
        path: &str,
    ) -> Result<(FileVersion, Vec<u8>)> {
        if pin.file.metadata()?.len() > self.limits.max_file_bytes {
            return Err(Error::Quota("file bytes"));
        }
        pin.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        pin.file
            .by_ref()
            .take(self.limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.limits.max_file_bytes {
            return Err(Error::Quota("file bytes"));
        }
        let version = FileVersion {
            path: path.into(),
            identity: pin.identity.clone(),
            digest: digest(&bytes),
            bytes: bytes.len() as u64,
        };
        Ok((version, bytes))
    }
    pub fn read(&self, path: &str) -> Result<(FileVersion, Vec<u8>)> {
        let mut file = self.lock(path, false)?;
        self.read_locked(&mut file, path)
    }
    pub fn snapshot(&self, cancel: &AtomicBool) -> Result<RepositorySnapshot> {
        let mut files = Vec::new();
        let mut total = 0;
        let mut seen = BTreeSet::new();
        let mut entries = 0;
        self.visit("", &mut files, &mut total, &mut seen, &mut entries, cancel)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let seal = digest(&serde_json::to_vec(&(
            self.root_identity(),
            &files,
            &self.excluded,
        ))?);
        Ok(RepositorySnapshot {
            schema_version: "melissa.repository-snapshot/v1".into(),
            root_identity: self.root.identity.clone(),
            files,
            digest: seal,
            total_bytes: total,
            atomic_tree_snapshot: false,
            excluded_prefixes: self.excluded.clone(),
        })
    }
    fn visit(
        &self,
        relative: &str,
        files: &mut Vec<FileVersion>,
        total: &mut u64,
        seen: &mut BTreeSet<String>,
        entries: &mut usize,
        cancel: &AtomicBool,
    ) -> Result {
        check_cancel(cancel)?;
        let path: PathBuf = if relative.is_empty() {
            self.root.canonical.clone()
        } else {
            self.root.canonical.join(relative.replace('/', "\\"))
        };
        let _guard = paths::pin(&path, true, false)?;
        for entry in fs::read_dir(path)? {
            check_cancel(cancel)?;
            *entries += 1;
            if *entries > self.limits.max_files {
                return Err(Error::Quota("directory and file entry count"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("non-Unicode entry"))?;
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            paths::relative(&child)?;
            if self.excluded.iter().any(|p| paths::beneath(&child, p))
                || child.split('/').any(|s| s.eq_ignore_ascii_case(".git"))
            {
                continue;
            }
            if !seen.insert(paths::key(&child)) {
                return Err(Error::Denied("case-colliding paths"));
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                self.visit(&child, files, total, seen, entries, cancel)?;
            } else {
                let (version, _) = self.read(&child)?;
                *total = total
                    .checked_add(version.bytes)
                    .ok_or(Error::Quota("byte overflow"))?;
                if *total > self.limits.max_total_bytes {
                    return Err(Error::Quota("snapshot bytes"));
                }
                files.push(version);
            }
        }
        Ok(())
    }
    pub fn validate_snapshot(&self, snapshot: &RepositorySnapshot, cancel: &AtomicBool) -> Result {
        let current = self.snapshot(cancel)?;
        if current != *snapshot {
            return Err(Error::Stale(
                "repository snapshot changed or its envelope was altered",
            ));
        }
        Ok(())
    }
    pub fn worker_input(
        &self,
        source: &RepositorySnapshot,
        cancel: &AtomicBool,
    ) -> Result<WorkerInput> {
        self.validate_snapshot(source, cancel)?;
        let mut files = std::collections::BTreeMap::new();
        for f in &source.files {
            check_cancel(cancel)?;
            let (current, bytes) = self.read(&f.path)?;
            if current != *f {
                return Err(Error::Stale("worker snapshot source changed"));
            }
            files.insert(f.path.clone(), bytes);
        }
        let snapshot = melissa_container_executor::Snapshot { files };
        snapshot
            .validate(self.limits.max_total_bytes)
            .map_err(|_| Error::Quota("worker input format or bytes"))?;
        self.validate_snapshot(source, cancel)?;
        Ok(WorkerInput {
            source_snapshot_digest: source.digest.clone(),
            snapshot,
        })
    }
    /// Byte-literal search; matches carry the exact file and snapshot digest.
    pub fn search(
        &self,
        snapshot: &RepositorySnapshot,
        needle: &[u8],
        cancel: &AtomicBool,
    ) -> Result<SearchResult> {
        if needle.is_empty() || needle.len() > 64 * 1024 {
            return Err(Error::Invalid("invalid search needle"));
        }
        self.validate_snapshot(snapshot, cancel)?;
        let mut hits = Vec::new();
        let mut truncated = false;
        // Linear-time substring search; comparing every window cost
        // file size x needle length (up to 64 KiB) with no cancel point.
        let finder = memchr::memmem::Finder::new(needle);
        for observed in &snapshot.files {
            check_cancel(cancel)?;
            let (version, bytes) = self.read(&observed.path)?;
            if version != *observed {
                return Err(Error::Stale("search file changed"));
            }
            let (mut start, mut line, mut counted) = (0, 1, 0);
            // Restart one byte past each hit so overlapping matches are kept.
            while let Some(found) = finder.find(&bytes[start..]) {
                check_cancel(cancel)?;
                let pos = start + found;
                if hits.len() == self.limits.max_search_hits {
                    truncated = true;
                    break;
                }
                line += memchr::memchr_iter(b'\n', &bytes[counted..pos]).count();
                counted = pos;
                hits.push(SearchHit {
                    path: version.path.clone(),
                    digest: version.digest.clone(),
                    byte_offset: pos,
                    line,
                });
                start = pos + 1;
            }
            if truncated {
                break;
            }
        }
        Ok(SearchResult {
            hits,
            truncated,
            snapshot_digest: snapshot.digest.clone(),
        })
    }
}
