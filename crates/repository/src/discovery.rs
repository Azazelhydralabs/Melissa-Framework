//! Pinned source capture + real ignore/globset matchers. Ambient home/system
//! Git configuration is deliberately outside repository discovery authority.
use crate::{Error, FileVersion, Repository, RepositorySnapshot, Result, check_cancel, paths};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::atomic::AtomicBool};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryOptions {
    pub include_globs: Vec<String>,
    pub generated_globs: Vec<String>,
    pub respect_ignore: bool,
}
impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            include_globs: vec!["**".into()],
            generated_globs: vec![
                "**/target/**".into(),
                "**/node_modules/**".into(),
                "**/__pycache__/**".into(),
                "**/*.generated.*".into(),
            ],
            respect_ignore: true,
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredFile {
    pub version: FileVersion,
    pub classification: String,
    pub language: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Discovery {
    pub schema_version: String,
    pub snapshot: RepositorySnapshot,
    pub files: Vec<DiscoveredFile>,
    pub manifests: Vec<String>,
    pub ignore_inputs: Vec<FileVersion>,
    pub configuration_scope: String,
}
fn globs(list: &[String]) -> Result<globset::GlobSet> {
    if list.len() > 256 || list.iter().any(|s| s.len() > 2048) {
        return Err(Error::Quota("glob rules"));
    }
    let mut b = globset::GlobSetBuilder::new();
    for s in list {
        b.add(
            globset::GlobBuilder::new(s)
                .literal_separator(true)
                .backslash_escape(true)
                .build()
                .map_err(|_| Error::Invalid("glob syntax"))?,
        );
    }
    b.build().map_err(|_| Error::Invalid("globset build"))
}
impl Repository {
    pub fn discover(&self, options: &DiscoveryOptions, cancel: &AtomicBool) -> Result<Discovery> {
        let snapshot = self.snapshot(cancel)?;
        let include = globs(&options.include_globs)?;
        let generated = globs(&options.generated_globs)?;
        let mut ignores = vec![];
        let mut ignore_inputs = vec![];
        if options.respect_ignore {
            for f in &snapshot.files {
                let name = f.path.rsplit('/').next().unwrap_or_default();
                if !matches!(name, ".gitignore" | ".ignore") {
                    continue;
                }
                check_cancel(cancel)?;
                let parent = Path::new(&f.path).parent().unwrap_or(Path::new(""));
                let root = self.root_path().join(parent);
                let mut builder = ignore::gitignore::GitignoreBuilder::new(&root);
                let (v, bytes) = self.read(&f.path)?;
                if v != *f {
                    return Err(Error::Stale("ignore source changed"));
                }
                let text =
                    std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("ignore UTF-8"))?;
                for line in text.lines() {
                    builder
                        .add_line(Some(self.root_path().join(&f.path)), line)
                        .map_err(|_| Error::Invalid("ignore rule syntax"))?;
                }
                ignores.push((
                    parent.to_string_lossy().replace('\\', "/"),
                    name == ".ignore",
                    builder
                        .build()
                        .map_err(|_| Error::Invalid("ignore matcher"))?,
                ));
                ignore_inputs.push(v);
            }
        }
        ignores.sort_by_key(|(p, local, _)| (*local, p.split('/').count()));
        let mut files = vec![];
        let mut manifests = vec![];
        for f in &snapshot.files {
            check_cancel(cancel)?;
            let mut ignored = false;
            // An excluded parent cannot be re-included by a nested ignore
            // file. Evaluate each parent before considering its children.
            let mut candidate = String::new();
            let components: Vec<_> = f.path.split('/').collect();
            for (i, part) in components.iter().enumerate() {
                if !candidate.is_empty() {
                    candidate.push('/');
                }
                candidate.push_str(part);
                let is_dir = i + 1 < components.len();
                let mut this = false;
                for (parent, _, matcher) in &ignores {
                    if parent.is_empty() || paths::beneath(&candidate, parent) {
                        let m = matcher.matched(self.root_path().join(&candidate), is_dir);
                        if m.is_ignore() {
                            this = true;
                        } else if m.is_whitelist() {
                            this = false;
                        }
                    }
                }
                if this {
                    ignored = true;
                    break;
                }
            }
            let class = if generated.is_match(&f.path) {
                "generated"
            } else if ignored {
                "ignored"
            } else if !include.is_match(&f.path) {
                "filtered"
            } else {
                "source"
            };
            let name = f.path.rsplit('/').next().unwrap_or_default();
            if class == "source"
                && matches!(
                    name,
                    "Cargo.toml"
                        | "package.json"
                        | "pyproject.toml"
                        | "requirements.txt"
                        | "rust-toolchain.toml"
                        | "tsconfig.json"
                )
            {
                manifests.push(f.path.clone());
            }
            files.push(DiscoveredFile {
                version: f.clone(),
                classification: class.into(),
                language: language(&f.path).map(String::from),
            });
        }
        self.validate_snapshot(&snapshot, cancel)?;
        Ok(Discovery{schema_version:"melissa.repository-discovery/v1".into(),snapshot,files,manifests,ignore_inputs,configuration_scope:"pinned .gitignore/.ignore hierarchy and host globs; no ambient global/system Git configuration; excluded prefixes stay explicit".into()})
    }
}
pub(crate) fn language(path: &str) -> Option<&'static str> {
    match path.rsplit('.').next()? {
        "rs" => Some("rust"),
        "py" => Some("python"),
        "ts" | "mts" | "cts" => Some("typescript"),
        "tsx" => Some("tsx"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        _ => None,
    }
}
