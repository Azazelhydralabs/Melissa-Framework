//! Git runs only on a bounded private snapshot through CODE-03's exact
//! ContainerBroker. The original repository is never mounted or passed to Git.
//! Host Git configuration, credential helpers, hooks and filters are not used.
use crate::{Error, Repository, RepositorySnapshot, Result, check_cancel, digest, paths};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot};
use melissa_execution_broker::{
    InvocationIdentity,
    container_broker::{ContainerBroker, ContainerExecution},
    container_policy::SignedContainerPermit,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Read, path::Path, sync::atomic::AtomicBool};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitOperation {
    Status,
    Diff {
        staged: bool,
    },
    Log {
        max_entries: u16,
    },
    WorktreeList,
    /// Destination is inside this task's private Linux workspace. The source
    /// remains untouched. The resulting worktree is quarantined worker output.
    WorktreeCreate {
        name: String,
        commit: String,
    },
}
#[derive(Debug, Clone, Serialize)]
pub struct GitPlan {
    pub request: ContainerRequest,
    pub snapshot: Snapshot,
    pub source_snapshot_digest: String,
    pub metadata_digest: String,
    pub atomic_source_snapshot: bool,
    pub configuration_scope: String,
}
impl GitPlan {
    pub fn prepare(
        repo: &Repository,
        source: &RepositorySnapshot,
        operation: &GitOperation,
        image_id: &str,
        limits: ContainerLimits,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        if source.excluded_prefixes != [".git"] {
            return Err(Error::Denied(
                "Git requires an exact capture without generated-file exclusions",
            ));
        }
        repo.validate_snapshot(source, cancel)?;
        let mut files = BTreeMap::new();
        let mut total = 0u64;
        for f in &source.files {
            check_cancel(cancel)?;
            if paths::beneath(&f.path, ".code05-worktrees") {
                return Err(Error::Denied("reserved private worktree destination"));
            }
            let (version, bytes) = repo.read(&f.path)?;
            if version != *f {
                return Err(Error::Stale("Git source changed"));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or(Error::Quota("Git source size"))?;
            files.insert(f.path.clone(), bytes);
        }
        let git = repo.root_path().join(".git");
        let _guard = paths::pin(&git, true, false)?;
        for unsupported in [
            "commondir",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            if fs::symlink_metadata(git.join(unsupported)).is_ok() {
                return Err(Error::Unsupported(
                    "linked-worktree metadata or external object stores require explicit separate support",
                ));
            }
        }
        let mut metadata = BTreeMap::new();
        let mut count = source.files.len();
        capture_metadata(
            repo,
            &git,
            "",
            &mut metadata,
            &mut total,
            &mut count,
            cancel,
        )?;
        if !metadata.contains_key("HEAD") {
            return Err(Error::Invalid("Git HEAD missing"));
        }
        let before_metadata = digest(&serde_json::to_vec(&metadata)?);
        // Reread the captured metadata to catch ordinary concurrent ref/index
        // edits. This is deliberately not advertised as an atomic tree freeze.
        let mut again = BTreeMap::new();
        let mut check_total = source.total_bytes;
        let mut check_count = source.files.len();
        capture_metadata(
            repo,
            &git,
            "",
            &mut again,
            &mut check_total,
            &mut check_count,
            cancel,
        )?;
        if metadata != again {
            return Err(Error::Stale("Git metadata changed while captured"));
        }
        let config = metadata.remove("config").unwrap_or_default();
        let safe = sanitized_config(&config)?;
        metadata.insert("config".into(), safe);
        for (name, bytes) in metadata {
            files.insert(format!(".git/{name}"), bytes);
        }
        repo.validate_snapshot(source, cancel)?;
        let snapshot = Snapshot { files };
        snapshot
            .validate(repo.limits().max_total_bytes)
            .map_err(|_| Error::Quota("container snapshot format or resource bounds"))?;
        let mut argv = vec![
            "--no-pager".into(),
            "--no-optional-locks".into(),
            "--literal-pathspecs".into(),
            "-c".into(),
            "core.fsmonitor=false".into(),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "credential.helper=".into(),
        ];
        let mut executable = "/usr/bin/git".to_string();
        match operation {
            GitOperation::Status => argv.extend([
                "status".into(),
                "--porcelain=v1".into(),
                "-z".into(),
                "--untracked-files=all".into(),
                "--ignore-submodules=all".into(),
            ]),
            GitOperation::Diff { staged } => {
                argv.extend([
                    "diff".into(),
                    "--no-ext-diff".into(),
                    "--no-textconv".into(),
                    "--no-color".into(),
                    "--no-renames".into(),
                    "--ignore-submodules=all".into(),
                    "--src-prefix=a/".into(),
                    "--dst-prefix=b/".into(),
                ]);
                if *staged {
                    argv.push("--cached".into());
                }
                argv.push("--".into());
            }
            GitOperation::Log { max_entries } => {
                if *max_entries == 0 || *max_entries > 1000 {
                    return Err(Error::Invalid("Git log count"));
                }
                argv.extend([
                    "log".into(),
                    "--no-show-signature".into(),
                    "--format=%H%x00%P%x00%s%x00".into(),
                    format!("--max-count={max_entries}"),
                    "--".into(),
                ]);
            }
            GitOperation::WorktreeList => argv.extend([
                "worktree".into(),
                "list".into(),
                "--porcelain".into(),
                "-z".into(),
            ]),
            GitOperation::WorktreeCreate { name, commit } => {
                if name.is_empty()
                    || !name.as_bytes()[0].is_ascii_alphanumeric()
                    || name.len() > 48
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    || !matches!(commit.len(), 40 | 64)
                    || !commit.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(Error::Invalid("worktree name or exact commit object id"));
                }
                executable = "/bin/sh".into();
                argv=vec!["-c".into(),concat!("set -eu\n","mkdir -p .code05-worktrees\n","dest=.code05-worktrees/$1\n","/usr/bin/git -c core.hooksPath=/dev/null worktree add --detach --no-checkout -- \"$dest\" \"$2\"\n","/usr/bin/git -C \"$dest\" -c core.hooksPath=/dev/null read-tree HEAD\n","/usr/bin/git -C \"$dest\" -c core.hooksPath=/dev/null checkout-index --all\n","/usr/bin/git worktree list --porcelain -z\n").into(),"melissa-git-worktree".into(),name.clone(),commit.clone()];
            }
        }
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: image_id.into(),
            executable,
            argv,
            cwd: ".".into(),
            env: BTreeMap::from([
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
                ("GIT_CONFIG_SYSTEM".into(), "/dev/null".into()),
                ("GIT_ATTR_NOSYSTEM".into(), "1".into()),
                ("GIT_NO_REPLACE_OBJECTS".into(), "1".into()),
                ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
                ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ]),
            limits,
        };
        request
            .validate()
            .map_err(|_| Error::Invalid("Git container request"))?;
        Ok(Self {request,snapshot,source_snapshot_digest:source.digest.clone(),metadata_digest:before_metadata,atomic_source_snapshot:false,configuration_scope:"safe core/object-format whitelist; no global/system/includes, credentials, external diff, hooks or configured filters; not full original-machine Git semantics".into()})
    }
    pub fn execute(
        &self,
        broker: &mut ContainerBroker,
        task: &str,
        permit: &SignedContainerPermit,
        identity: &InvocationIdentity,
        cancel: &AtomicBool,
    ) -> Result<ContainerExecution> {
        if permit.binding.request != self.request {
            return Err(Error::Denied(
                "Git plan does not match exact container permit",
            ));
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
}

fn capture_metadata(
    repo: &Repository,
    root: &Path,
    rel: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
    count: &mut usize,
    cancel: &AtomicBool,
) -> Result {
    let path = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel.replace('/', "\\"))
    };
    let _guard = paths::pin(&path, true, false)?;
    for entry in fs::read_dir(path)? {
        check_cancel(cancel)?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::Invalid("Git metadata Unicode"))?;
        let name = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        paths::relative(&name)?;
        // Never copy executable hooks, reflogs, nested worktrees or credentials.
        if !(matches!(
            name.as_str(),
            "HEAD" | "index" | "config" | "packed-refs" | "shallow" | "info"
        ) || name.starts_with("sharedindex.")
            || paths::beneath(&name, "objects")
            || paths::beneath(&name, "refs")
            || name == "info/exclude")
        {
            continue;
        }
        *count += 1;
        if *count > repo.limits().max_files {
            return Err(Error::Quota("Git metadata entries"));
        }
        if entry.file_type()?.is_dir() {
            capture_metadata(repo, root, &name, files, total, count, cancel)?;
        } else {
            let pin = paths::pin(&entry.path(), false, false)?;
            let mut bytes = Vec::new();
            pin.file
                .take(repo.limits().max_file_bytes + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > repo.limits().max_file_bytes {
                return Err(Error::Quota("Git metadata file bytes"));
            }
            *total = total
                .checked_add(bytes.len() as u64)
                .ok_or(Error::Quota("Git metadata byte overflow"))?;
            if *total > repo.limits().max_total_bytes {
                return Err(Error::Quota("Git combined bytes"));
            }
            files.insert(name, bytes);
        }
    }
    Ok(())
}
fn sanitized_config(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Unsupported("non-UTF8 Git config"))?;
    let mut section = String::new();
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_ascii_lowercase();
        let valid = match (section.as_str(), key.as_str()) {
            ("[core]", "autocrlf") => matches!(value.as_str(), "true" | "false" | "input"),
            ("[core]", "eol") => matches!(value.as_str(), "lf" | "crlf" | "native"),
            ("[core]", "filemode" | "ignorecase" | "symlinks") => {
                matches!(value.as_str(), "true" | "false")
            }
            ("[extensions]", "objectformat") => matches!(value.as_str(), "sha1" | "sha256"),
            _ => continue,
        };
        if !valid {
            return Err(Error::Unsupported(
                "Git core option outside safe configuration grammar",
            ));
        }
        entries.insert((section.clone(), key), value);
    }
    let sha256 = entries
        .get(&("[extensions]".into(), "objectformat".into()))
        .is_some_and(|v| v == "sha256");
    let mut result = format!(
        "[core]\nrepositoryformatversion = {}\nbare = false\nfsmonitor = false\nhooksPath = /dev/null\n",
        if sha256 { 1 } else { 0 }
    );
    for ((section, key), value) in entries {
        result.push_str(&format!("{section}\n{key} = {value}\n"));
    }
    Ok(result.into_bytes())
}
