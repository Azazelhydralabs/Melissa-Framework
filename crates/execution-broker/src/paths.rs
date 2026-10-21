//! Handle-pinned path resolution for one owned staged workspace.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use crate::{
    BrokerError, BrokerResult,
    policy::{ProcessSpec, ResolvedProcess},
};
use melissa_core_contracts::{catalog::safe_relative_path, validation::Validate};

const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

pub struct PinnedProcess {
    resolved: ResolvedProcess,
    _guards: Vec<File>,
}

impl PinnedProcess {
    pub fn resolve(spec: &ProcessSpec, workspace: &Path) -> BrokerResult<Self> {
        spec.validate()
            .map_err(|error| BrokerError::Invalid(error.to_string()))?;
        #[cfg(not(windows))]
        {
            let _ = workspace;
            return Err(BrokerError::Denied(
                "native Windows resolver required".into(),
            ));
        }
        #[cfg(windows)]
        {
            validate_absolute(workspace)?;
            validate_absolute(Path::new(&spec.executable))?;
            if spec.cwd != "." {
                safe_relative_path(&spec.cwd.replace('\\', "/"))
                    .map_err(|error| BrokerError::Invalid(error.to_string()))?;
            }
            let mut guards = Vec::new();
            let (canonical_workspace, workspace_identity) =
                pin_directory_chain(workspace, &mut guards)?;
            let cwd = if spec.cwd == "." {
                workspace.to_path_buf()
            } else {
                workspace.join(spec.cwd.replace('/', "\\"))
            };
            let (canonical_cwd, cwd_identity) = pin_directory_chain(&cwd, &mut guards)?;
            if !within(&canonical_cwd, &canonical_workspace) {
                return Err(BrokerError::Denied(
                    "cwd is outside the staged workspace".into(),
                ));
            }
            let executable = Path::new(&spec.executable);
            if let Some(parent) = executable.parent() {
                pin_directory_chain(parent, &mut guards)?;
            }
            let mut executable_file = open_pinned(executable, false)?;
            let (canonical_executable, executable_identity, links) =
                file_identity(&executable_file)?;
            if links != 1 {
                return Err(BrokerError::Denied(
                    "hard-linked executables require a separate verified staging copy".into(),
                ));
            }
            let executable_digest = hash_executable(&mut executable_file)?;
            guards.push(executable_file);
            let resolved = ResolvedProcess {
                spec: spec.clone(),
                canonical_executable: unicode_path(&canonical_executable)?,
                executable_digest,
                executable_identity,
                canonical_cwd: unicode_path(&canonical_cwd)?,
                cwd_identity,
                workspace_identity: format!(
                    "{}:{}",
                    unicode_path(&canonical_workspace)?,
                    workspace_identity
                ),
            };
            resolved
                .validate()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?;
            Ok(Self {
                resolved,
                _guards: guards,
            })
        }
    }

    pub fn resolved(&self) -> &ResolvedProcess {
        &self.resolved
    }

    /// Re-resolve while retaining the original handles. A changed file ID,
    /// digest, workspace/cwd, environment or argv cannot reuse the old permit.
    pub fn revalidate(&self, workspace: &Path) -> BrokerResult<Self> {
        let current = Self::resolve(&self.resolved.spec, workspace)?;
        if current.resolved != self.resolved {
            return Err(BrokerError::StaleTarget(
                "resolved process identity changed".into(),
            ));
        }
        Ok(current)
    }
}

#[cfg(windows)]
fn validate_absolute(path: &Path) -> BrokerResult<()> {
    use std::path::Prefix;
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(BrokerError::Invalid(
            "absolute local drive path required".into(),
        ));
    }
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if !matches!(prefix.kind(), Prefix::Disk(_)) => {
                return Err(BrokerError::Denied(
                    "UNC/device/verbatim paths are unsupported".into(),
                ));
            }
            Component::ParentDir | Component::CurDir => {
                return Err(BrokerError::Denied("path traversal is forbidden".into()));
            }
            Component::Normal(name) => {
                let text = name
                    .to_str()
                    .ok_or_else(|| BrokerError::Invalid("invalid Unicode path".into()))?;
                safe_relative_path(text)
                    .map_err(|error| BrokerError::Invalid(error.to_string()))?;
                let stem = text.split('.').next().unwrap_or_default().to_uppercase();
                if matches!(stem.as_str(), "CONIN$" | "CONOUT$")
                    || ["COM", "LPT"].iter().any(|prefix| {
                        stem.strip_prefix(prefix)
                            .is_some_and(|suffix| matches!(suffix, "¹" | "²" | "³"))
                    })
                {
                    return Err(BrokerError::Denied("reserved Windows path".into()));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(windows)]
fn pin_directory_chain(path: &Path, guards: &mut Vec<File>) -> BrokerResult<(PathBuf, String)> {
    validate_absolute(path)?;
    let mut paths: Vec<_> = path.ancestors().collect();
    paths.reverse();
    let mut final_identity = None;
    for ancestor in paths {
        let file = open_pinned(ancestor, true)?;
        let (canonical, identity, _) = file_identity(&file)?;
        final_identity = Some((canonical, identity));
        guards.push(file);
    }
    final_identity.ok_or_else(|| BrokerError::Invalid("empty directory chain".into()))
}

#[cfg(windows)]
fn open_pinned(path: &Path, directory: bool) -> BrokerResult<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
    };
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_attributes() & 0x400 != 0
        || metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(BrokerError::Denied("reparse or wrong-kind target".into()));
    }
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ).custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    if directory {
        options.access_mode(FILE_READ_ATTRIBUTES);
    }
    let file = options.open(path)?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(BrokerError::StaleTarget(
            "target became a reparse point".into(),
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn file_identity(file: &File) -> BrokerResult<(PathBuf, String, u32)> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        },
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if information.dwFileAttributes & 0x400 != 0 {
        return Err(BrokerError::Denied("linked target handle".into()));
    }
    let mut buffer = vec![0_u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as HANDLE,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(BrokerError::Denied(
            "canonical handle path unavailable".into(),
        ));
    }
    let text = std::ffi::OsString::from_wide(&buffer[..length as usize])
        .into_string()
        .map_err(|_| BrokerError::Invalid("invalid Unicode target".into()))?;
    let text = text
        .strip_prefix(r"\\?\")
        .ok_or_else(|| BrokerError::Denied("non-DOS handle path".into()))?;
    if text.starts_with("UNC\\") {
        return Err(BrokerError::Denied("network target is unsupported".into()));
    }
    let canonical = PathBuf::from(text);
    validate_absolute(&canonical)?;
    let identity = format!(
        "volume:{:08x}/file:{:08x}{:08x}",
        information.dwVolumeSerialNumber, information.nFileIndexHigh, information.nFileIndexLow
    );
    Ok((canonical, identity, information.nNumberOfLinks))
}

#[cfg(windows)]
fn unicode_path(path: &Path) -> BrokerResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| BrokerError::Invalid("invalid Unicode target".into()))
}

#[cfg(windows)]
fn hash_executable(file: &mut File) -> BrokerResult<String> {
    if file.metadata()?.len() > MAX_EXECUTABLE_BYTES {
        return Err(BrokerError::Denied(
            "executable exceeds verified image limit".into(),
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bounded = file.take(MAX_EXECUTABLE_BYTES + 1);
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 65536];
    let mut total = 0_u64;
    loop {
        let size = bounded.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(BrokerError::Denied("executable grew past limit".into()));
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("blake3:{}", hash.finalize().to_hex()))
}

#[cfg(windows)]
fn within(path: &Path, root: &Path) -> bool {
    PathBuf::from(path.to_string_lossy().to_lowercase())
        .starts_with(PathBuf::from(root.to_string_lossy().to_lowercase()))
}
