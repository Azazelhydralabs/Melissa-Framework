//! Exact, isolated real ripgrep and Rust LSP plans. Rust owns every path,
//! source binding, execution grant and returned-location validation.
use crate::{
    Error, FileVersion, Repository, RepositorySnapshot, Result, check_cancel, digest,
    discovery::DiscoveryOptions, paths,
};
use melissa_container_executor::{ContainerLimits, ContainerReport, ContainerRequest, Snapshot};
use melissa_execution_broker::{
    InvocationIdentity,
    container_broker::{ContainerBroker, ContainerExecution},
    container_policy::SignedContainerPermit,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};

pub const TOOLING_IMAGE: &str =
    "sha256:e74995d2b94a4435b9670882922c18eabc98c0685cc6ca547b68b027a3466d68";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisQuery {
    Ripgrep {
        needle: String,
        discovery: DiscoveryOptions,
    },
    Lsp {
        method: LspMethod,
        path: String,
        line: u32,
        character: u32,
        include_declaration: bool,
        root_modules: Vec<String>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LspMethod {
    #[serde(rename = "textDocument/references")]
    References,
    #[serde(rename = "textDocument/definition")]
    Definition,
    #[serde(rename = "textDocument/documentSymbol")]
    DocumentSymbol,
}
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisPlan {
    pub request: ContainerRequest,
    pub snapshot: Snapshot,
    pub source: RepositorySnapshot,
    pub query: AnalysisQuery,
}
#[derive(Debug, Clone, Serialize)]
pub struct SourceLocation {
    pub version: FileVersion,
    pub line: u32,
    pub utf16_character: u32,
    pub end_line: u32,
    pub end_utf16_character: u32,
    pub start_byte: usize,
    pub end_byte: usize,
    pub column_encoding: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisResult {
    pub schema_version: String,
    pub source_snapshot_digest: String,
    pub engine: String,
    pub locations: Vec<SourceLocation>,
    pub raw: Value,
    pub task_accepted: bool,
}

/// Validate UTF-16 positions, including the middle of a surrogate pair.
pub fn byte_position(bytes: &[u8], line: u32, character: u32) -> Result<usize> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid("LSP source UTF-8"))?;
    let mut offset = 0;
    let mut rows = text.split_inclusive('\n');
    for _ in 0..line {
        let row = rows
            .next()
            .ok_or(Error::Invalid("LSP line outside source"))?;
        offset += row.len();
    }
    let row = rows.next().unwrap_or("");
    if offset == bytes.len() && line > 0 && !text.ends_with('\n') {
        return Err(Error::Invalid("LSP line outside source"));
    }
    let content = row
        .strip_suffix('\n')
        .unwrap_or(row)
        .strip_suffix('\r')
        .unwrap_or(row.strip_suffix('\n').unwrap_or(row));
    let mut units = 0;
    for (byte, c) in content.char_indices() {
        if units == character {
            return Ok(offset + byte);
        }
        units += c.len_utf16() as u32;
        if units > character {
            return Err(Error::Invalid("LSP surrogate midpoint"));
        }
    }
    if units == character {
        Ok(offset + content.len())
    } else {
        Err(Error::Invalid("LSP column outside source"))
    }
}
fn snapshot(files: BTreeMap<String, Vec<u8>>) -> Result<Snapshot> {
    let s = Snapshot { files };
    s.validate(64 * 1024 * 1024)
        .map_err(|_| Error::Quota("analysis worker snapshot envelope"))?;
    Ok(s)
}
impl AnalysisPlan {
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        query: AnalysisQuery,
        image: &str,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        if image != TOOLING_IMAGE {
            return Err(Error::Denied(
                "analysis tooling image has not passed this adapter version gate",
            ));
        }
        repo.validate_snapshot(source, cancel)?;
        let mut files = BTreeMap::new();
        for f in &source.files {
            check_cancel(cancel)?;
            if paths::beneath(&f.path, ".melissa-analysis") {
                return Err(Error::Denied("reserved analysis source path"));
            }
            let (v, bytes) = repo.read(&f.path)?;
            if v != *f {
                return Err(Error::Stale("analysis source changed"));
            }
            files.insert(f.path.clone(), bytes);
        }
        let (script, payload) = match &query {
            AnalysisQuery::Ripgrep { needle, discovery } => {
                if needle.is_empty()
                    || needle.len() > 64 * 1024
                    || needle.contains(['\n', '\r', '\0'])
                {
                    return Err(Error::Invalid("ripgrep single-line literal"));
                }
                let d = repo.discover(discovery, cancel)?;
                if d.snapshot != *source {
                    return Err(Error::Stale("discovery analysis binding"));
                }
                files.retain(|path, _| {
                    d.files
                        .iter()
                        .any(|f| f.version.path == *path && f.classification == "source")
                });
                (include_str!("ripgrep_driver.py"), json!({"needle":needle}))
            }
            AnalysisQuery::Lsp {
                method,
                path,
                line,
                character,
                include_declaration,
                root_modules,
            } => {
                repo.check_path(path)?;
                if root_modules.is_empty() || root_modules.len() > 128 {
                    return Err(Error::Invalid("LSP root modules"));
                }
                let bytes = files
                    .get(path)
                    .ok_or(Error::Invalid("LSP query path not captured"))?;
                byte_position(bytes, *line, *character)?;
                for root in root_modules {
                    repo.check_path(root)?;
                    if !root.ends_with(".rs") || !files.contains_key(root) {
                        return Err(Error::Invalid("captured Rust root module required"));
                    }
                }
                let documents: Vec<_> = files
                    .keys()
                    .filter(|p| p.ends_with(".rs"))
                    .cloned()
                    .collect();
                // Source-owned Cargo, rust-analyzer and Python startup
                // configuration cannot change this analysis-only route.
                files.retain(|p, _| p.ends_with(".rs"));
                (
                    include_str!("lsp_driver.py"),
                    json!({"root_modules":root_modules,"documents":documents,"query":{"method":method,"path":path,"line":line,"character":character,"include_declaration":include_declaration}}),
                )
            }
        };
        files.insert(
            ".melissa-analysis/driver.py".into(),
            script.as_bytes().to_vec(),
        );
        files.insert(
            ".melissa-analysis/request.json".into(),
            serde_json::to_vec(&payload)?,
        );
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: image.into(),
            executable: "/usr/bin/python3".into(),
            argv: vec![
                "-I".into(),
                "-S".into(),
                ".melissa-analysis/driver.py".into(),
            ],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("analysis worker request"))?;
        Ok(Self {
            request,
            snapshot: snapshot(files)?,
            source: source.clone(),
            query,
        })
    }
    pub fn execute(
        &self,
        repo: &Repository,
        broker: &mut ContainerBroker,
        task: &str,
        permit: &SignedContainerPermit,
        identity: &InvocationIdentity,
        cancel: &AtomicBool,
    ) -> Result<ContainerExecution> {
        repo.validate_snapshot(&self.source, cancel)?;
        if permit.binding.request != self.request {
            return Err(Error::Denied("analysis permit exact request"));
        }
        broker
            .execute(task, permit, &self.snapshot, identity, cancel)
            .map_err(|e| match e {
                melissa_execution_broker::BrokerError::AfterDispatch(e) => {
                    Error::AfterDispatch(Box::new(Error::Broker(*e)))
                }
                e => Error::Broker(e),
            })
    }
    fn location(&self, repo: &Repository, uri: &str, range: &Value) -> Result<SourceLocation> {
        let encoded = uri
            .strip_prefix("file:///work/")
            .ok_or(Error::Denied("LSP result outside source workspace"))?;
        let mut decoded = vec![];
        let mut iter = encoded.as_bytes().iter();
        while let Some(&c) = iter.next() {
            if c == b'%' {
                let h = *iter.next().ok_or(Error::Invalid("URI escape"))?;
                let l = *iter.next().ok_or(Error::Invalid("URI escape"))?;
                let hex = |b: u8| {
                    (b as char)
                        .to_digit(16)
                        .map(|x| x as u8)
                        .ok_or(Error::Invalid("URI hex"))
                };
                decoded.push(hex(h)? * 16 + hex(l)?);
            } else {
                decoded.push(c);
            }
        }
        let path = String::from_utf8(decoded).map_err(|_| Error::Invalid("URI UTF-8"))?;
        repo.check_path(&path)?;
        let version = self
            .source
            .files
            .iter()
            .find(|f| f.path == path)
            .ok_or(Error::Denied("LSP result is not a source file"))?;
        let (actual, bytes) = repo.read(&path)?;
        if actual != *version {
            return Err(Error::Stale("LSP result source changed"));
        }
        let n = |v: &Value| {
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(Error::Invalid("LSP position integer"))
        };
        let line = n(&range["start"]["line"])?;
        let ch = n(&range["start"]["character"])?;
        let end_line = n(&range["end"]["line"])?;
        let end_ch = n(&range["end"]["character"])?;
        let start = byte_position(&bytes, line, ch)?;
        let end = byte_position(&bytes, end_line, end_ch)?;
        if end < start {
            return Err(Error::Invalid("LSP reversed range"));
        }
        Ok(SourceLocation {
            version: version.clone(),
            line,
            utf16_character: ch,
            end_line,
            end_utf16_character: end_ch,
            start_byte: start,
            end_byte: end,
            column_encoding: "utf-16".into(),
        })
    }
    pub fn decode(
        &self,
        repo: &Repository,
        report: &ContainerReport,
        cancel: &AtomicBool,
    ) -> Result<AnalysisResult> {
        if report.exit_code != Some(0)
            || !matches!(
                report.termination,
                melissa_container_executor::TerminationReason::Exited
            )
            || report.output_truncated
            || !report.cleanup_confirmed
            || !report.tree_confirmed_stopped
            || !report.policy_verified
            || report.input_digest
                != self
                    .snapshot
                    .digest()
                    .map_err(|_| Error::Invalid("analysis input digest"))?
            || report.image_id != self.request.image_id
        {
            return Err(Error::Invalid(
                "analysis process/evidence did not complete successfully",
            ));
        }
        repo.validate_snapshot(&self.source, cancel)?;
        let raw = melissa_model_gateway::strict_json(
            std::str::from_utf8(&report.stdout)
                .map_err(|_| Error::Invalid("analysis stdout UTF-8"))?,
        )
        .map_err(|_| Error::Invalid("analysis result JSON"))?;
        let mut locations = vec![];
        let engine = match &self.query {
            AnalysisQuery::Lsp { method, .. } => {
                if raw["schema_version"] != "melissa.lsp-worker-result/v1"
                    || raw["position_encoding"] != "utf-16"
                {
                    return Err(Error::Invalid("LSP result contract/encoding"));
                }
                let request: Value = serde_json::from_slice(
                    self.snapshot
                        .files
                        .get(".melissa-analysis/request.json")
                        .ok_or(Error::Invalid("analysis request evidence"))?,
                )?;
                if raw["query"] != request["query"]
                    || raw["server_info"]["name"] != "rust-analyzer"
                    || !raw["server_info"]["version"]
                        .as_str()
                        .is_some_and(|v| v.starts_with("1.98.1 "))
                    || raw["ready_status"]["quiescent"] != true
                    || raw["ready_status"]["health"] != "ok"
                {
                    return Err(Error::Invalid("LSP query/version/readiness evidence"));
                }
                if let Some(items) = raw["result"].as_array() {
                    for item in items {
                        check_cancel(cancel)?;
                        match method {
                            LspMethod::DocumentSymbol => {
                                let uri = match &self.query {
                                    AnalysisQuery::Lsp { path, .. } => {
                                        format!("file:///work/{path}")
                                    }
                                    _ => unreachable!(),
                                };
                                let mut pending = vec![item];
                                while let Some(symbol) = pending.pop() {
                                    if symbol["selectionRange"].is_object() {
                                        locations.push(self.location(
                                            repo,
                                            &uri,
                                            &symbol["selectionRange"],
                                        )?);
                                    } else {
                                        locations.push(
                                            self.location(
                                                repo,
                                                symbol["location"]["uri"]
                                                    .as_str()
                                                    .ok_or(Error::Invalid("LSP symbol URI"))?,
                                                &symbol["location"]["range"],
                                            )?,
                                        );
                                    }
                                    if let Some(c) = symbol["children"].as_array() {
                                        pending.extend(c);
                                    }
                                }
                            }
                            _ => {
                                let (uri, range) = if item["targetUri"].is_string() {
                                    (&item["targetUri"], &item["targetSelectionRange"])
                                } else {
                                    (&item["uri"], &item["range"])
                                };
                                locations.push(self.location(
                                    repo,
                                    uri.as_str().ok_or(Error::Invalid("LSP URI"))?,
                                    range,
                                )?);
                            }
                        }
                    }
                } else if !raw["result"].is_null() {
                    let item = &raw["result"];
                    locations.push(self.location(
                        repo,
                        item["uri"].as_str().ok_or(Error::Invalid("LSP URI"))?,
                        &item["range"],
                    )?);
                }
                "rust-analyzer/1.98.1; semantic LSP"
            }
            AnalysisQuery::Ripgrep { needle, .. } => {
                if raw["schema_version"] != "melissa.ripgrep-worker-result/v1" {
                    return Err(Error::Invalid("ripgrep result contract"));
                }
                for event in raw["events"]
                    .as_array()
                    .ok_or(Error::Invalid("ripgrep events"))?
                {
                    check_cancel(cancel)?;
                    if event["type"] != "match" {
                        continue;
                    }
                    let data = &event["data"];
                    let p = data["path"]["text"]
                        .as_str()
                        .ok_or(Error::Invalid("ripgrep UTF-8 path"))?
                        .strip_prefix("./")
                        .unwrap_or(data["path"]["text"].as_str().unwrap());
                    repo.check_path(p)?;
                    let version = self
                        .source
                        .files
                        .iter()
                        .find(|f| f.path == p)
                        .ok_or(Error::Denied("ripgrep result outside source"))?;
                    let (v, bytes) = repo.read(p)?;
                    if v != *version {
                        return Err(Error::Stale("ripgrep result source"));
                    }
                    let absolute = data["absolute_offset"]
                        .as_u64()
                        .ok_or(Error::Invalid("ripgrep offset"))?
                        as usize;
                    for sub in data["submatches"]
                        .as_array()
                        .ok_or(Error::Invalid("ripgrep submatches"))?
                    {
                        let offset = |k: &str| {
                            sub[k]
                                .as_u64()
                                .and_then(|n| usize::try_from(n).ok())
                                .and_then(|n| absolute.checked_add(n))
                                .ok_or(Error::Invalid("ripgrep byte range"))
                        };
                        let start = offset("start")?;
                        let end = offset("end")?;
                        if bytes.get(start..end) != Some(needle.as_bytes()) {
                            return Err(Error::Invalid(
                                "ripgrep match not authenticated by source bytes",
                            ));
                        }
                        let line = bytes[..start].iter().filter(|c| **c == b'\n').count() as u32;
                        let line_start = bytes[..start]
                            .iter()
                            .rposition(|c| *c == b'\n')
                            .map(|x| x + 1)
                            .unwrap_or(0);
                        let ch = std::str::from_utf8(&bytes[line_start..start])
                            .map(|s| s.encode_utf16().count() as u32)
                            .unwrap_or((start - line_start) as u32);
                        locations.push(SourceLocation {
                            version: version.clone(),
                            line,
                            utf16_character: ch,
                            end_line: line,
                            end_utf16_character: ch + needle.encode_utf16().count() as u32,
                            start_byte: start,
                            end_byte: end,
                            column_encoding: if std::str::from_utf8(&bytes[line_start..start])
                                .is_ok()
                            {
                                "utf-16"
                            } else {
                                "bytes"
                            }
                            .into(),
                        });
                    }
                }
                "ripgrep/15.2.0; exact source-byte verified literal"
            }
        };
        Ok(AnalysisResult {
            schema_version: "melissa.repository-analysis-result/v1".into(),
            source_snapshot_digest: self.source.digest.clone(),
            engine: engine.into(),
            locations,
            raw,
            task_accepted: false,
        })
    }
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}
