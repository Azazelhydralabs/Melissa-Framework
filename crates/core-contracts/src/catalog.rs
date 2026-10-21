//! Read-only definition loading and reference validation, not a tool broker.
//!
//! Paths are bounded and links/reparse points are rejected while loading. This
//! does not provide an OS sandbox or race-free handles against hostile writers.
use crate::catalog_models::*;
use crate::json::parse_contract;
use crate::validation::{ContractError, ContractResult, Validate, require};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct CatalogLimits {
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_files: usize,
    pub max_entries: usize,
}
impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_files: 4096,
            max_entries: 4096,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Catalog {
    pub profiles: BTreeMap<String, AgentProfile>,
    pub workers: BTreeMap<String, WorkerType>,
    pub tools: ToolCatalog,
    pub aliases: ToolAliases,
    pub modules: ModuleCatalog,
    pub backlog: BacklogCatalog,
    pub policy: RuntimePolicy,
    pub index: AgentIndex,
}
/// Missing bindings are reported, never synthesized from tool families or names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionReadiness {
    pub evidence_level: String,
    pub executable: bool,
    pub missing_runtime_bindings: Vec<String>,
    pub missing_skill_packages: Vec<String>,
    pub missing_exact_tool_routes: Vec<String>,
    pub pending_input_schemas: Vec<String>,
    pub missing_worker_executors: Vec<String>,
    pub source_interface_mappings_pending: Vec<String>,
}

impl Catalog {
    /// Load a project root containing `catalog/`. Additional planning catalogs
    /// are not interpreted as executable profiles or skills by this loader.
    pub fn load(root: &Path) -> ContractResult<Self> {
        Self::load_with_limits(root, CatalogLimits::default())
    }
    pub fn load_with_limits(root: &Path, limits: CatalogLimits) -> ContractResult<Self> {
        require(
            limits.max_file_bytes > 0
                && limits.max_total_bytes > 0
                && limits.max_files > 0
                && limits.max_entries > 0,
            "catalog.limits",
            "all limits must be positive",
        )?;
        // Refuse a linked root or any linked ancestor before canonicalization.
        check_ancestors(root)?;
        let root = fs::canonicalize(root).map_err(|e| io_error(root, e))?;
        let mut reader = CatalogReader {
            root,
            limits,
            files: 0,
            bytes: 0,
        };
        let tools = reader.read("catalog/tools.json")?;
        let aliases = reader.read("catalog/tool-aliases.json")?;
        let modules = reader.read("catalog/modules.json")?;
        let backlog = reader.read("catalog/backlog.json")?;
        let policy = reader.read("catalog/runtime-policy.json")?;
        let index: AgentIndex = reader.read("catalog/agent-index.json")?;
        let mut profiles = BTreeMap::new();
        let agents_dir = reader.directory("catalog/agents")?;
        for module_dir in reader.entries(&agents_dir)? {
            let meta = checked_metadata(&module_dir)?;
            require(
                meta.is_dir(),
                "catalog/agents",
                "only module directories are permitted",
            )?;
            let directory_name = module_dir
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(|| ContractError::new("catalog/agents", "non-UTF8 module name"))?;
            identifier(directory_name, "catalog/agents/module")?;
            for file in reader.entries(&module_dir)? {
                require(
                    checked_metadata(&file)?.is_file(),
                    "catalog/agents",
                    "profile entries must be regular files",
                )?;
                require(
                    file.extension().and_then(|v| v.to_str()) == Some("json"),
                    "catalog/agents",
                    "profile entries must be JSON files",
                )?;
                let relative = reader.relative(&file)?;
                let profile: AgentProfile = reader.read(&relative)?;
                require(
                    module_name(profile.module) == directory_name,
                    "profile.module",
                    "profile directory/module mismatch",
                )?;
                let expected = format!(
                    "catalog/agents/{}/{}.json",
                    module_name(profile.module),
                    profile.id.rsplit('.').next().unwrap_or_default()
                );
                require(
                    relative == expected,
                    "profile.path",
                    "profile filename/ID mismatch",
                )?;
                let id = profile.id.clone();
                require(
                    profiles.insert(id, profile).is_none(),
                    "profiles",
                    "duplicate profile ID",
                )?;
            }
        }
        let mut workers = BTreeMap::new();
        let workers_dir = reader.directory("catalog/workers")?;
        for file in reader.entries(&workers_dir)? {
            require(
                checked_metadata(&file)?.is_file(),
                "catalog/workers",
                "worker entries must be regular files",
            )?;
            require(
                file.extension().and_then(|v| v.to_str()) == Some("json"),
                "catalog/workers",
                "worker entries must be JSON files",
            )?;
            let relative = reader.relative(&file)?;
            let worker: WorkerType = reader.read(&relative)?;
            require(
                relative == format!("catalog/workers/{}.json", worker.id),
                "worker.path",
                "worker filename/ID mismatch",
            )?;
            let id = worker.id.clone();
            require(
                workers.insert(id, worker).is_none(),
                "workers",
                "duplicate worker ID",
            )?;
        }
        let catalog = Self {
            profiles,
            workers,
            tools,
            aliases,
            modules,
            backlog,
            policy,
            index,
        };
        for (kind, len) in [
            ("profiles", catalog.profiles.len()),
            ("workers", catalog.workers.len()),
            ("tools", catalog.tools.tools.len()),
            ("aliases", catalog.aliases.aliases.len()),
            ("modules", catalog.modules.modules.len()),
            ("backlog", catalog.backlog.items.len()),
            ("index", catalog.index.profiles.len()),
        ] {
            require(
                len <= limits.max_entries,
                kind,
                "catalog entry limit exceeded",
            )?;
        }
        catalog.validate()?;
        // Evidence references are local definition evidence only. Existence does
        // not authenticate a verifier, prove content, or promote product state.
        for item in &catalog.backlog.items {
            if item.status == BacklogStatus::Accepted {
                for reference in &item.evidence_refs {
                    reader.evidence(reference)?;
                }
            }
        }
        for module in &catalog.modules.modules {
            if module.gate.status == GateStatus::Passed {
                for reference in &module.gate.evidence_refs {
                    reader.evidence(reference)?;
                }
            }
        }
        Ok(catalog)
    }
    pub fn resolve_tool_alias<'a>(&'a self, id: &'a str) -> ContractResult<&'a str> {
        let mut current = id;
        let mut seen = BTreeSet::new();
        while let Some(next) = self.aliases.aliases.get(current) {
            require(seen.insert(current), "aliases", "alias cycle")?;
            current = next;
        }
        require(
            self.tools.tools.iter().any(|tool| tool.id == current),
            "aliases",
            "alias target is not a canonical tool",
        )?;
        Ok(current)
    }
    pub fn readiness(&self) -> DefinitionReadiness {
        DefinitionReadiness {
            evidence_level: "definition_catalog_only".into(),
            executable: false,
            missing_runtime_bindings: self.profiles.keys().cloned().collect(),
            missing_skill_packages: self.profiles.keys().cloned().collect(),
            missing_exact_tool_routes: self
                .tools
                .tools
                .iter()
                .map(|tool| tool.id.clone())
                .collect(),
            pending_input_schemas: self
                .tools
                .tools
                .iter()
                .map(|tool| tool.id.clone())
                .collect(),
            missing_worker_executors: self.workers.keys().cloned().collect(),
            source_interface_mappings_pending: [
                "memory.search",
                "memory.propose",
                "science.cad.inspect",
                "game.physics.simulate",
            ]
            .iter()
            .filter(|id| !self.tools.tools.iter().any(|tool| tool.id == **id))
            .map(|id| (*id).into())
            .collect(),
        }
    }
}

impl Validate for Catalog {
    fn validate(&self) -> ContractResult<()> {
        self.tools.validate()?;
        self.aliases.validate()?;
        self.modules.validate()?;
        self.backlog.validate()?;
        self.policy.validate()?;
        self.index.validate()?;
        require(
            !self.profiles.is_empty(),
            "profiles",
            "empty profile catalog",
        )?;
        require(!self.workers.is_empty(), "workers", "empty worker catalog")?;
        let modules: BTreeMap<_, _> = self
            .modules
            .modules
            .iter()
            .map(|module| (module_name(module.id), module))
            .collect();
        // Modules are a finite domain enum; require every registered domain while
        // allowing profile/tool/backlog growth within each domain.
        for name in [
            "core", "code", "cyber", "science", "game", "repack", "fit", "grid",
        ] {
            require(
                modules.contains_key(name),
                "modules",
                "missing required module",
            )?;
        }
        let tool_ids: BTreeSet<_> = self
            .tools
            .tools
            .iter()
            .map(|tool| tool.id.as_str())
            .collect();
        let mut tool_users: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut cases = BTreeSet::new();
        for (id, profile) in &self.profiles {
            profile.validate()?;
            require(id == &profile.id, "profiles", "profile map key/ID mismatch")?;
            require(
                modules.contains_key(module_name(profile.module)),
                "profile.module",
                "unknown module",
            )?;
            for tool in &profile.tool_ids {
                require(
                    tool_ids.contains(tool.as_str()),
                    "profile.tool_ids",
                    "unknown/noncanonical tool",
                )?;
                tool_users.entry(tool).or_default().insert(id);
            }
            for worker in &profile.worker_types {
                require(
                    self.workers.contains_key(worker),
                    "profile.worker_types",
                    "unknown worker",
                )?;
            }
            for handoff in &profile.handoffs {
                require(
                    handoff.profile_id != *id && self.profiles.contains_key(&handoff.profile_id),
                    "profile.handoffs",
                    "unknown/self handoff",
                )?;
            }
            for case in &profile.evaluation_cases {
                require(
                    cases.insert(case.id.as_str()),
                    "profile.evaluation_cases",
                    "duplicate global evaluation case ID",
                )?;
            }
            if [
                "melissa.core.independent-qa",
                "melissa.code.reviewer",
                "melissa.cyber.finding-verifier",
                "melissa.science.verifier",
            ]
            .contains(&id.as_str())
            {
                require(
                    !profile.tool_ids.iter().any(|tool| {
                        ["fs.patch", "workspace.patch.apply", "code.patch_propose"]
                            .contains(&tool.as_str())
                    }),
                    "profile.tool_ids",
                    "protected reviewer cannot modify source",
                )?;
            }
            if id == "melissa.cyber.remediation" {
                require(
                    !profile.tool_ids.iter().any(|tool| tool == "fs.patch"),
                    "profile.tool_ids",
                    "Cyber remediation is not a Code write grant",
                )?;
            }
        }
        for (id, worker) in &self.workers {
            worker.validate()?;
            require(id == &worker.id, "workers", "worker map key/ID mismatch")?;
            for module in &worker.modules {
                require(
                    modules.contains_key(module_name(*module)),
                    "worker.modules",
                    "unknown module",
                )?;
            }
        }
        for tool in &self.tools.tools {
            require(
                modules.contains_key(module_name(tool.owner_module)),
                "tools.owner_module",
                "unknown module",
            )?;
            let actual = tool_users
                .get(tool.id.as_str())
                .cloned()
                .unwrap_or_default();
            let declared: BTreeSet<_> = tool.referenced_by.iter().map(String::as_str).collect();
            require(
                actual == declared,
                "tools.referenced_by",
                "stale, foreign or missing profile references",
            )?;
            for worker in &tool.worker_candidates {
                require(
                    self.workers.contains_key(worker),
                    "tools.worker_candidates",
                    "unknown worker candidate",
                )?;
            }
        }
        for alias in self.aliases.aliases.keys() {
            require(
                !tool_ids.contains(alias.as_str()),
                "aliases",
                "alias shadows canonical tool",
            )?;
            self.resolve_tool_alias(alias)?;
        }
        let index_ids: BTreeSet<_> = self
            .index
            .profiles
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        let profile_ids: BTreeSet<_> = self.profiles.keys().map(String::as_str).collect();
        require(
            index_ids == profile_ids,
            "index",
            "profile index incomplete or foreign",
        )?;
        for item in &self.index.profiles {
            let profile = &self.profiles[&item.id];
            let expected = format!(
                "catalog/agents/{}/{}.json",
                module_name(profile.module),
                profile.id.rsplit('.').next().unwrap_or_default()
            );
            require(
                item.module == profile.module
                    && item.name_tr == profile.name_tr
                    && item.path == expected,
                "index",
                "ID/path/module/name association mismatch",
            )?;
        }
        for module in &self.modules.modules {
            let actual_profiles: BTreeSet<_> = self
                .profiles
                .values()
                .filter(|p| p.module == module.id)
                .map(|p| p.id.as_str())
                .collect();
            let declared_profiles: BTreeSet<_> =
                module.profile_ids.iter().map(String::as_str).collect();
            require(
                actual_profiles == declared_profiles,
                "modules.profile_ids",
                "missing or foreign module profiles",
            )?;
            let actual_backlog: BTreeSet<_> = self
                .backlog
                .items
                .iter()
                .filter(|item| item.module == module.id)
                .map(|item| item.id.as_str())
                .collect();
            let declared_backlog: BTreeSet<_> =
                module.backlog_ids.iter().map(String::as_str).collect();
            require(
                actual_backlog == declared_backlog,
                "modules.backlog_ids",
                "missing or foreign module backlog",
            )?;
            for dep in &module.implementation_dependencies {
                let dependency = modules.get(module_name(*dep)).ok_or_else(|| {
                    ContractError::new("modules.dependencies", "unknown module dependency")
                })?;
                require(
                    dependency.order < module.order,
                    "modules.dependencies",
                    "dependency must precede module (cycle or invalid order)",
                )?;
            }
            if module.order == 0 {
                require(
                    module.implementation_order_predecessor.is_none(),
                    "modules.predecessor",
                    "first module cannot have predecessor",
                )?;
            } else {
                let predecessor = module
                    .implementation_order_predecessor
                    .and_then(|id| modules.get(module_name(id)))
                    .ok_or_else(|| {
                        ContractError::new("modules.predecessor", "missing predecessor")
                    })?;
                require(
                    predecessor.order.checked_add(1) == Some(module.order),
                    "modules.predecessor",
                    "predecessor/order mismatch",
                )?;
            }
            if module.gate.status == GateStatus::Passed {
                require(
                    self.backlog
                        .items
                        .iter()
                        .filter(|item| item.module == module.id)
                        .all(|item| item.status == BacklogStatus::Accepted),
                    "modules.gate",
                    "gate passed with incomplete module work",
                )?;
                for dep in module
                    .implementation_dependencies
                    .iter()
                    .copied()
                    .chain(module.implementation_order_predecessor)
                {
                    require(
                        modules[module_name(dep)].gate.status == GateStatus::Passed,
                        "modules.gate",
                        "gate passed before prerequisite acceptance",
                    )?;
                }
            }
        }
        for item in &self.backlog.items {
            let module = modules
                .get(module_name(item.module))
                .ok_or_else(|| ContractError::new("backlog.module", "unknown module"))?;
            for dep in &item.depends_on_modules {
                let dependency = modules.get(module_name(*dep)).ok_or_else(|| {
                    ContractError::new("backlog.depends_on_modules", "unknown dependency")
                })?;
                require(
                    dependency.order < module.order,
                    "backlog.depends_on_modules",
                    "backlog module dependency must precede module",
                )?;
            }
        }
        Ok(())
    }
}

struct CatalogReader {
    root: PathBuf,
    limits: CatalogLimits,
    files: usize,
    bytes: usize,
}
impl CatalogReader {
    fn path(&self, relative: &str) -> ContractResult<PathBuf> {
        safe_relative_path(relative)?;
        let mut path = self.root.clone();
        for component in Path::new(relative).components() {
            path.push(component);
            checked_metadata(&path)?;
        }
        Ok(path)
    }
    fn directory(&self, relative: &str) -> ContractResult<PathBuf> {
        let path = self.path(relative)?;
        require(
            checked_metadata(&path)?.is_dir(),
            relative,
            "expected directory",
        )?;
        Ok(path)
    }
    fn relative(&self, path: &Path) -> ContractResult<String> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| ContractError::new("catalog.path", "path escapes root"))?;
        let text = relative
            .to_str()
            .ok_or_else(|| ContractError::new("catalog.path", "non-UTF8 path"))?
            .replace('\\', "/");
        safe_relative_path(&text)?;
        Ok(text)
    }
    fn entries(&mut self, path: &Path) -> ContractResult<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| io_error(path, e))? {
            let entry = entry.map_err(|e| io_error(path, e))?;
            require(
                entries.len() < self.limits.max_files,
                "catalog.directory",
                "directory entry limit exceeded",
            )?;
            checked_metadata(&entry.path())?;
            entries.push(entry.path());
        }
        entries.sort();
        Ok(entries)
    }
    fn read<T: DeserializeOwned + Validate>(&mut self, relative: &str) -> ContractResult<T> {
        let path = self.path(relative)?;
        let meta = checked_metadata(&path)?;
        require(meta.is_file(), relative, "expected regular file")?;
        let metadata_bytes = usize::try_from(meta.len())
            .map_err(|_| ContractError::new(relative, "file too large"))?;
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| ContractError::new(relative, "file count overflow"))?;
        require(
            self.files <= self.limits.max_files,
            relative,
            "catalog file limit exceeded",
        )?;
        let remaining = self
            .limits
            .max_total_bytes
            .checked_sub(self.bytes)
            .ok_or_else(|| ContractError::new(relative, "catalog total byte limit exceeded"))?;
        let maximum = self.limits.max_file_bytes.min(remaining);
        require(
            metadata_bytes <= maximum,
            relative,
            "catalog file or remaining total byte limit exceeded",
        )?;
        let file = File::open(&path).map_err(|error| io_error(&path, error))?;
        // Charge the bytes actually read. A growing/replaced file cannot bypass
        // the aggregate budget through a stale metadata length.
        let bytes = bounded_bytes(file, maximum).map_err(|error| error.at(relative))?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ContractError::new(relative, "byte count overflow"))?;
        parse_contract(&bytes, maximum).map_err(|error| error.at(relative))
    }
    fn evidence(&self, reference: &str) -> ContractResult<()> {
        let path = self.path(reference)?;
        require(
            checked_metadata(&path)?.is_file(),
            reference,
            "evidence ref must identify an existing regular project file",
        )
    }
}
fn bounded_bytes(reader: impl Read, maximum: usize) -> ContractResult<Vec<u8>> {
    require(maximum > 0, "catalog.read", "no remaining byte budget")?;
    let probe_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ContractError::new("catalog.read", "byte limit overflow"))?;
    let mut bytes = Vec::new();
    reader
        .take(probe_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| ContractError::new("catalog.read", error.to_string()))?;
    require(
        bytes.len() <= maximum,
        "catalog.read",
        "file exceeded per-file or remaining aggregate byte limit while reading",
    )?;
    Ok(bytes)
}
fn io_error(path: &Path, error: std::io::Error) -> ContractError {
    ContractError::new(path.display().to_string(), error.to_string())
}
fn checked_metadata(path: &Path) -> ContractResult<fs::Metadata> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    require(
        !meta.file_type().is_symlink(),
        &path.display().to_string(),
        "symbolic links forbidden in catalog",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        require(
            meta.file_attributes() & 0x400 == 0,
            &path.display().to_string(),
            "reparse points forbidden in catalog",
        )?;
    }
    Ok(meta)
}
fn check_ancestors(path: &Path) -> ContractResult<()> {
    for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        checked_metadata(ancestor)?;
    }
    Ok(())
}
/// Portable repository-relative path syntax, including Windows reserved names.
pub fn safe_relative_path(value: &str) -> ContractResult<()> {
    require(
        !value.is_empty()
            && value.len() <= 1024
            && !value.contains('\\')
            && !value.contains(':')
            && !value.contains('\0'),
        "catalog.path",
        "invalid relative path",
    )?;
    for part in value.split('/') {
        require(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>\"|?*".contains(c)),
            "catalog.path",
            "invalid relative path component",
        )?;
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        require(
            ![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9",
            ]
            .contains(&stem.as_str()),
            "catalog.path",
            "reserved path component",
        )?;
    }
    require(
        Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "catalog.path",
        "path must be project-relative",
    )
}

#[cfg(test)]
mod resource_tests {
    use super::bounded_bytes;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_enforces_remaining_budget_from_actual_bytes() {
        let remaining_total = 16;
        let per_file = 128;
        assert_eq!(
            bounded_bytes(Cursor::new(vec![b'x'; 16]), per_file.min(remaining_total))
                .unwrap()
                .len(),
            16
        );
        assert!(bounded_bytes(Cursor::new(vec![b'x'; 17]), per_file.min(remaining_total)).is_err());
    }

    #[test]
    fn bounded_reader_refuses_zero_budget_and_overflowing_probe() {
        assert!(bounded_bytes(Cursor::new(Vec::<u8>::new()), 0).is_err());
        if let Ok(overflowing_probe) = usize::try_from(u64::MAX) {
            assert!(bounded_bytes(Cursor::new(Vec::<u8>::new()), overflowing_probe).is_err());
        }
    }
}
