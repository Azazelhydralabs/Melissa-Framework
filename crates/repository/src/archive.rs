//! A quarantined tar reader, NEVER an archive extractor. Files returned here
//! are still untrusted proposals; they require normal expected-version patches.
use crate::{Error, Limits, Result, paths};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct ImportedFile {
    pub path: String,
    pub bytes: Vec<u8>,
    pub trusted: bool,
}
fn text(b: &[u8]) -> Result<&str> {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    if b[end..].iter().any(|c| *c != 0) {
        return Err(Error::Invalid("tar field contains trailing data"));
    }
    std::str::from_utf8(&b[..end]).map_err(|_| Error::Invalid("tar path UTF-8"))
}
fn octal(b: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(b)
        .map_err(|_| Error::Invalid("tar octal field"))?
        .trim_matches([' ', '\0']);
    if s.is_empty() || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(Error::Invalid("tar binary or invalid octal field"));
    }
    u64::from_str_radix(s, 8).map_err(|_| Error::Invalid("tar octal overflow"))
}
pub fn inspect_ustar(bytes: &[u8], limits: &Limits) -> Result<Vec<ImportedFile>> {
    limits.validate()?;
    let ceiling = limits
        .max_total_bytes
        .checked_add((limits.max_files as u64).saturating_mul(2048))
        .ok_or(Error::Quota("archive bytes"))?;
    if bytes.len() as u64 > ceiling || !bytes.len().is_multiple_of(512) {
        return Err(Error::Quota("archive size or alignment"));
    }
    let mut result = Vec::new();
    let mut pos = 0;
    let mut total = 0u64;
    let mut seen = BTreeSet::new();
    let mut regular = BTreeSet::new();
    let mut entries = 0;
    while pos + 512 <= bytes.len() {
        let h = &bytes[pos..pos + 512];
        pos += 512;
        if h.iter().all(|b| *b == 0) {
            if pos + 512 > bytes.len() || bytes[pos..].iter().any(|b| *b != 0) {
                return Err(Error::Invalid("tar terminal blocks"));
            }
            return Ok(result);
        }
        entries += 1;
        if entries > limits.max_files {
            return Err(Error::Quota("tar entry count"));
        }
        if !((&h[257..263] == b"ustar\0" && &h[263..265] == b"00")
            || (&h[257..263] == b"ustar " && &h[263..265] == b" \0"))
        {
            return Err(Error::Unsupported(
                "only ordinary POSIX/GNU ustar is supported",
            ));
        }
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if octal(&h[148..156])? != sum {
            return Err(Error::Invalid("tar checksum"));
        }
        if !text(&h[157..257])?.is_empty() {
            return Err(Error::Denied("tar link target"));
        }
        let name = text(&h[..100])?;
        let prefix = if &h[257..263] == b"ustar\0" {
            text(&h[345..500])?
        } else {
            ""
        };
        let name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let name = name.strip_prefix("./").unwrap_or(&name).to_string();
        let directory = h[156] == b'5';
        let name = if directory {
            name.strip_suffix('/').unwrap_or(&name).to_string()
        } else {
            name
        };
        if directory && (name == "." || name.is_empty()) {
            if octal(&h[124..136])? != 0 {
                return Err(Error::Invalid("nonempty tar root"));
            }
            continue;
        }
        paths::relative(&name)?;
        if name.split('/').any(|s| s.eq_ignore_ascii_case(".git")) {
            return Err(Error::Denied("Git metadata in archive"));
        }
        if !seen.insert(paths::key(&name)) {
            return Err(Error::Denied("duplicate or case-alias tar entry"));
        }
        let mut parent = name.as_str();
        while let Some((head, _)) = parent.rsplit_once('/') {
            if regular.contains(&paths::key(head)) {
                return Err(Error::Denied("tar file-directory collision"));
            }
            parent = head;
        }
        let len = octal(&h[124..136])?;
        if directory {
            if len != 0 {
                return Err(Error::Invalid("nonempty tar directory"));
            }
            continue;
        }
        if !matches!(h[156], 0 | b'0') {
            return Err(Error::Denied(
                "links, devices, PAX, sparse and extension records are not imported",
            ));
        }
        // `seen` is ordered, so any entry beneath `name/` sorts first at or
        // after that prefix: one range lookup instead of a scan per file.
        let below = format!("{}/", paths::key(&name));
        if seen
            .range(below.clone()..)
            .next()
            .is_some_and(|p| p.starts_with(&below))
        {
            return Err(Error::Denied("tar ancestor collision"));
        }
        regular.insert(paths::key(&name));
        total = total
            .checked_add(len)
            .ok_or(Error::Quota("tar length overflow"))?;
        if len > limits.max_file_bytes || total > limits.max_total_bytes {
            return Err(Error::Quota("tar payload bytes"));
        }
        let len = usize::try_from(len).map_err(|_| Error::Quota("tar length"))?;
        let end = pos
            .checked_add(len)
            .ok_or(Error::Invalid("tar length overflow"))?;
        let padded = end
            .checked_add(511)
            .map(|n| n / 512 * 512)
            .ok_or(Error::Invalid("tar padding overflow"))?;
        if padded > bytes.len() {
            return Err(Error::Invalid("truncated tar payload"));
        }
        if bytes[end..padded].iter().any(|b| *b != 0) {
            return Err(Error::Invalid("nonzero tar padding"));
        }
        result.push(ImportedFile {
            path: name,
            bytes: bytes[pos..end].to_vec(),
            trusted: false,
        });
        pos = padded;
    }
    Err(Error::Invalid("missing tar termination"))
}
