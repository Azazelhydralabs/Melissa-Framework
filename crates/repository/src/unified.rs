//! Exact Git/unified text patches -> untrusted typed broker proposals.
//! No fuzzy context, external patch command, mode changes or binary decoding.
use crate::{
    ByteEdit, Error, FileMutation, FilePatch, FileVersion, MutationProposal, PatchProposal,
    Repository, RepositorySnapshot, Result, check_cancel, digest, paths,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::atomic::AtomicBool};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "proposal", rename_all = "snake_case")]
pub enum ProposedChange {
    Patch(PatchProposal),
    Mutation(MutationProposal),
}
/// Text EOL interpretation is explicit, never inferred after an exact failure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedLineEndings {
    #[default]
    Exact,
    PreserveSource,
}
#[derive(Debug, Clone, Serialize)]
pub struct UnifiedProposal {
    pub schema_version: String,
    pub source_snapshot_digest: String,
    pub line_endings: UnifiedLineEndings,
    pub changes: Vec<ProposedChange>,
    pub authorizes_write: bool,
    pub multi_file_atomic: bool,
}
#[derive(Default)]
struct Block {
    old: Option<String>,
    new: Option<String>,
    rename_old: Option<String>,
    rename_new: Option<String>,
    hunks: Vec<Hunk>,
    empty_path: Option<String>,
    new_file: bool,
    deleted_file: bool,
}
struct Hunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    rows: Vec<(u8, Vec<u8>)>,
}
fn filename(bytes: &[u8], prefix: bool) -> Result<Option<String>> {
    let raw = if bytes.starts_with(b"\"") {
        let mut out = vec![];
        let mut i = 1;
        loop {
            let c = *bytes
                .get(i)
                .ok_or(Error::Invalid("unterminated quoted Git path"))?;
            i += 1;
            if c == b'"' {
                if bytes[i..].iter().any(|c| !matches!(c, b'\t' | b' ')) {
                    return Err(Error::Invalid("quoted path trailing bytes"));
                }
                break;
            }
            if c != b'\\' {
                out.push(c);
                continue;
            }
            let esc = *bytes.get(i).ok_or(Error::Invalid("Git path escape"))?;
            i += 1;
            match esc {
                b'\\' | b'"' => out.push(esc),
                b'0'..=b'3' => {
                    let a = *bytes.get(i).ok_or(Error::Invalid("octal path"))?;
                    let b = *bytes.get(i + 1).ok_or(Error::Invalid("octal path"))?;
                    if !(b'0'..=b'7').contains(&a) || !(b'0'..=b'7').contains(&b) {
                        return Err(Error::Invalid("octal path"));
                    }
                    out.push((esc - b'0') * 64 + (a - b'0') * 8 + b - b'0');
                    i += 2;
                }
                _ => return Err(Error::Invalid("unsupported Git path escape")),
            }
        }
        out
    } else {
        bytes
            .split(|c| *c == b'\t')
            .next()
            .unwrap_or_default()
            .to_vec()
    };
    let s = String::from_utf8(raw).map_err(|_| Error::Invalid("UTF-8 patch path"))?;
    if s == "/dev/null" {
        return Ok(None);
    }
    let s = if prefix {
        s.strip_prefix("a/")
            .or_else(|| s.strip_prefix("b/"))
            .ok_or(Error::Invalid("a/ or b/ unified prefix required"))?
            .to_string()
    } else {
        s
    };
    paths::relative(&s)?;
    Ok(Some(s))
}
fn range(s: &str, prefix: char) -> Result<(usize, usize)> {
    let s = s
        .strip_prefix(prefix)
        .ok_or(Error::Invalid("hunk range sign"))?;
    let mut p = s.split(',');
    let start = p
        .next()
        .unwrap_or_default()
        .parse()
        .map_err(|_| Error::Invalid("hunk line number"))?;
    let count = p
        .next()
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| Error::Invalid("hunk line count"))?
        .unwrap_or(1);
    if p.next().is_some() {
        return Err(Error::Invalid("hunk range"));
    }
    Ok((start, count))
}
fn identical_git_path(line: &[u8]) -> Result<Option<String>> {
    if line.starts_with(b"\"") {
        let mut escaped = false;
        for i in 1..line.len() {
            let c = line[i];
            if c == b'"' && !escaped {
                let a = filename(&line[..=i], true)?;
                let rest = line.get(i + 2..).ok_or(Error::Invalid("Git path pair"))?;
                let b = filename(rest, true)?;
                return Ok(if a == b { a } else { None });
            }
            escaped = c == b'\\' && !escaped;
        }
        return Err(Error::Invalid("Git quoted path pair"));
    }
    for i in 0..line.len().saturating_sub(2) {
        if line.get(i..i + 3) == Some(b" b/") {
            let a = filename(&line[..i], true)?;
            let b = filename(&line[i + 1..], true)?;
            if a == b {
                return Ok(a);
            }
        }
    }
    Ok(None)
}
fn header(line: &[u8]) -> Result<Hunk> {
    let text = std::str::from_utf8(line).map_err(|_| Error::Invalid("hunk header UTF-8"))?;
    let mut t = text.split(' ');
    if t.next() != Some("@@") {
        return Err(Error::Invalid("hunk marker"));
    }
    let (os, oc) = range(t.next().ok_or(Error::Invalid("old range"))?, '-')?;
    let (ns, nc) = range(t.next().ok_or(Error::Invalid("new range"))?, '+')?;
    if t.next() != Some("@@") {
        return Err(Error::Invalid("hunk end marker"));
    }
    Ok(Hunk {
        old_start: os,
        old_count: oc,
        new_start: ns,
        new_count: nc,
        rows: vec![],
    })
}
fn text_line(bytes: &[u8]) -> (&[u8], bool) {
    if let Some(b) = bytes.strip_suffix(b"\n") {
        (b.strip_suffix(b"\r").unwrap_or(b), true)
    } else {
        (bytes, false)
    }
}
fn source_eol(before: &[u8]) -> Result<&'static [u8]> {
    let mut eol: Option<&[u8]> = None;
    for line in before.split_inclusive(|b| *b == b'\n') {
        let (content, terminated) = text_line(line);
        if content.contains(&b'\r') {
            return Err(Error::Unsupported("preserve_source rejects bare CR"));
        }
        if terminated {
            let next: &[u8] = if line.ends_with(b"\r\n") {
                b"\r\n"
            } else {
                b"\n"
            };
            if eol.is_some_and(|previous| previous != next) {
                return Err(Error::Unsupported(
                    "preserve_source rejects mixed source EOL",
                ));
            }
            eol = Some(next);
        }
    }
    eol.ok_or(Error::Unsupported(
        "preserve_source requires an observed source EOL; use exact mode",
    ))
}
fn apply(before: &[u8], hunks: &[Hunk], mode: UnifiedLineEndings) -> Result<Vec<u8>> {
    let eol = if mode == UnifiedLineEndings::PreserveSource {
        Some(source_eol(before)?)
    } else {
        None
    };
    let lines: Vec<_> = before.split_inclusive(|c| *c == b'\n').collect();
    let mut pos = 0;
    let mut out = vec![];
    let mut out_lines = 0;
    for h in hunks {
        let start = if h.old_count == 0 {
            h.old_start
        } else {
            h.old_start
                .checked_sub(1)
                .ok_or(Error::Invalid("old hunk zero"))?
        };
        if start < pos || start > lines.len() {
            return Err(Error::Invalid("overlapping/outside hunk"));
        }
        for line in &lines[pos..start] {
            out.extend_from_slice(line);
            out_lines += 1;
        }
        pos = start;
        let new_start = if h.new_count == 0 {
            h.new_start
        } else {
            h.new_start
                .checked_sub(1)
                .ok_or(Error::Invalid("new hunk zero"))?
        };
        if new_start != out_lines {
            return Err(Error::Invalid("new hunk coordinate"));
        }
        let (mut old, mut new) = (0, 0);
        for (kind, bytes) in &h.rows {
            match kind {
                b' ' | b'-' => {
                    let matches = lines.get(pos).is_some_and(|line| {
                        if eol.is_some() {
                            text_line(line) == text_line(bytes)
                        } else {
                            *line == bytes.as_slice()
                        }
                    });
                    if !matches {
                        return Err(Error::Stale("exact unified context does not match"));
                    }
                    pos += 1;
                    old += 1;
                }
                b'+' => (),
                _ => return Err(Error::Invalid("hunk row")),
            }
            if *kind != b'-' {
                if let Some(eol) = eol {
                    let (content, terminated) = text_line(bytes);
                    if content.contains(&b'\r') {
                        return Err(Error::Unsupported(
                            "preserve_source rejects bare CR in patch",
                        ));
                    }
                    out.extend_from_slice(content);
                    if terminated {
                        out.extend_from_slice(eol);
                    }
                } else {
                    out.extend_from_slice(bytes);
                }
                out_lines += 1;
                new += 1;
            }
        }
        if old != h.old_count || new != h.new_count {
            return Err(Error::Invalid("hunk row counts"));
        }
    }
    for line in &lines[pos..] {
        out.extend_from_slice(line);
    }
    Ok(out)
}
impl Repository {
    pub fn propose_unified(
        &self,
        source: &RepositorySnapshot,
        patch: &[u8],
        cancel: &AtomicBool,
    ) -> Result<UnifiedProposal> {
        self.propose_unified_with_line_endings(source, patch, UnifiedLineEndings::Exact, cancel)
    }
    /// Explicit text transport adapter: preserve a uniform observed source EOL.
    /// Existing same-path files only; no implicit creation, rename, fuzz or write.
    pub fn propose_unified_with_line_endings(
        &self,
        source: &RepositorySnapshot,
        patch: &[u8],
        line_endings: UnifiedLineEndings,
        cancel: &AtomicBool,
    ) -> Result<UnifiedProposal> {
        self.validate_snapshot(source, cancel)?;
        if patch.is_empty() || patch.len() > 32 * 1024 * 1024 || patch.contains(&0) {
            return Err(Error::Invalid("bounded text unified patch required"));
        }
        let lines: Vec<_> = patch.split_inclusive(|c| *c == b'\n').collect();
        let mut blocks = vec![];
        let mut b = Block::default();
        let mut i = 0;
        while i < lines.len() {
            check_cancel(cancel)?;
            let line = lines[i];
            let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
            if let Some(pair) = trimmed.strip_prefix(b"diff --git ") {
                if b.old.is_some()
                    || b.new.is_some()
                    || b.rename_old.is_some()
                    || b.new_file
                    || b.deleted_file
                {
                    blocks.push(b);
                    b = Block::default();
                }
                b.empty_path = identical_git_path(pair)?;
            } else if let Some(s) = trimmed.strip_prefix(b"--- ") {
                if b.old.is_some() || b.new.is_some() || !b.hunks.is_empty() {
                    blocks.push(b);
                    b = Block::default();
                }
                b.old = filename(s, true)?;
                i += 1;
                let next = lines.get(i).ok_or(Error::Invalid("missing +++ header"))?;
                let next = next.strip_suffix(b"\n").unwrap_or(next);
                b.new = filename(
                    next.strip_prefix(b"+++ ")
                        .ok_or(Error::Invalid("missing +++ header"))?,
                    true,
                )?;
            } else if trimmed.starts_with(b"@@ ") {
                let mut h = header(trimmed)?;
                i += 1;
                let (mut old, mut new) = (0, 0);
                while i < lines.len() {
                    let row = lines[i];
                    if row.starts_with(b"\\ No newline at end of file") {
                        let (_, last) = h
                            .rows
                            .last_mut()
                            .ok_or(Error::Invalid("orphan no-newline marker"))?;
                        if last.pop() != Some(b'\n') {
                            return Err(Error::Invalid("repeated no-newline marker"));
                        }
                        i += 1;
                        continue;
                    }
                    if old == h.old_count && new == h.new_count {
                        break;
                    }
                    let kind = *row.first().ok_or(Error::Invalid("empty hunk row"))?;
                    if !matches!(kind, b' ' | b'+' | b'-') {
                        return Err(Error::Invalid("missing hunk rows"));
                    }
                    if kind != b'+' {
                        old += 1;
                    }
                    if kind != b'-' {
                        new += 1;
                    }
                    if old > h.old_count || new > h.new_count {
                        return Err(Error::Invalid("excess hunk rows"));
                    }
                    h.rows.push((kind, row[1..].to_vec()));
                    i += 1;
                }
                b.hunks.push(h);
                continue;
            } else if let Some(s) = trimmed.strip_prefix(b"rename from ") {
                b.rename_old = filename(s, false)?;
            } else if let Some(s) = trimmed.strip_prefix(b"rename to ") {
                b.rename_new = filename(s, false)?;
            } else if trimmed == b"new file mode 100644" {
                b.new_file = true;
            } else if trimmed == b"deleted file mode 100644" {
                b.deleted_file = true;
            } else if trimmed.starts_with(b"index ") || trimmed.starts_with(b"similarity index ") {
            } else {
                return Err(Error::Unsupported(
                    "unsupported patch metadata/binary/mode change",
                ));
            }
            i += 1;
        }
        if b.old.is_some()
            || b.new.is_some()
            || b.rename_old.is_some()
            || b.new_file
            || b.deleted_file
        {
            blocks.push(b);
        }
        if blocks.is_empty() || blocks.len() > self.limits().max_patch_files {
            return Err(Error::Quota("unified file count"));
        }
        let mut changes = vec![];
        let mut touched = BTreeSet::new();
        for b in blocks {
            check_cancel(cancel)?;
            let old = if b.new_file {
                None
            } else {
                b.old.or(b.rename_old).or_else(|| b.empty_path.clone())
            };
            let new = if b.deleted_file {
                None
            } else {
                b.new.or(b.rename_new).or(b.empty_path)
            };
            if line_endings == UnifiedLineEndings::PreserveSource && (old.is_none() || old != new) {
                return Err(Error::Unsupported(
                    "preserve_source supports existing same-path edits only",
                ));
            }
            let source_path = old
                .as_ref()
                .or(new.as_ref())
                .ok_or(Error::Invalid("two null patch paths"))?;
            self.check_path(source_path)?;
            if !touched.insert(paths::key(source_path)) {
                return Err(Error::Invalid("duplicate patch source"));
            }
            let before = old.as_ref().map(|p| self.read(p)).transpose()?;
            if let Some((v, _)) = &before
                && !source.files.contains(v)
            {
                return Err(Error::Stale("patch source missing from supplied snapshot"));
            }
            let bytes = before
                .as_ref()
                .map(|(_, b)| b.as_slice())
                .unwrap_or_default();
            let after = apply(bytes, &b.hunks, line_endings)?;
            if after.len() as u64 > self.limits().max_file_bytes {
                return Err(Error::Quota("unified result bytes"));
            }
            let mutation = |m| {
                ProposedChange::Mutation(MutationProposal {
                    schema_version: "melissa.repository-mutation/v1".into(),
                    root_identity: self.root_identity().into(),
                    mutation: m,
                })
            };
            match (old, new, before) {
                (None, Some(p), None) => {
                    changes.push(mutation(FileMutation::Create {
                        destination: self.absent_path(&p)?,
                        bytes: after,
                    }));
                }
                (Some(_), None, Some((v, _))) => {
                    if !after.is_empty() {
                        return Err(Error::Invalid("delete patch retains content"));
                    }
                    changes.push(mutation(FileMutation::Delete { before: v }));
                }
                (Some(old), Some(new), Some((v, before))) => {
                    let moved = old != new;
                    let mut final_version = v.clone();
                    if after != before {
                        final_version = FileVersion {
                            digest: digest(&after),
                            bytes: after.len() as u64,
                            ..v.clone()
                        };
                        changes.push(ProposedChange::Patch(PatchProposal {
                            schema_version: "melissa.repository-patch/v1".into(),
                            root_identity: self.root_identity().into(),
                            files: vec![FilePatch {
                                before: v,
                                edits: vec![ByteEdit {
                                    start: 0,
                                    end: before.len() as u64,
                                    expected: before,
                                    replacement: after,
                                }],
                            }],
                        }));
                    }
                    if moved {
                        if !touched.insert(paths::key(&new)) {
                            return Err(Error::Invalid("patch rename collision"));
                        }
                        changes.push(mutation(FileMutation::Move {
                            before: final_version,
                            destination: self.absent_path(&new)?,
                        }));
                    }
                }
                _ => return Err(Error::Invalid("unified path shape")),
            }
        }
        Ok(UnifiedProposal {
            schema_version: "melissa.unified-proposal/v1".into(),
            source_snapshot_digest: source.digest.clone(),
            line_endings,
            changes,
            authorizes_write: false,
            multi_file_atomic: false,
        })
    }
}
