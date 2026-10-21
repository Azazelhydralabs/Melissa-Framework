//! Windows share restrictions retain ancestors and targets through I/O.
//! Pathname prechecks alone are never used as the filesystem boundary.
use crate::{Error, Result};
use std::{
    fs::{File, OpenOptions},
    path::{Component, Path, PathBuf},
};

pub(crate) fn relative(path: &str) -> Result {
    if path.is_empty()
        || path.len() > 2048
        || path.contains(['\\', ':', '\0'])
        || path.split('/').count() > 64
    {
        return Err(Error::Invalid(
            "canonical slash-separated relative path required",
        ));
    }
    for part in path.split('/') {
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|c| c.is_control() || "<>\"|?*".contains(c))
        {
            return Err(Error::Invalid("unsafe path component"));
        }
        let stem = part.split('.').next().unwrap_or_default().to_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|p| {
            stem.strip_prefix(p).is_some_and(|x| {
                matches!(
                    x,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            return Err(Error::Invalid("reserved device path"));
        }
    }
    Ok(())
}

/// Conservative collision/denial checks only; never use this as a write grant.
pub(crate) fn key(s: &str) -> String {
    s.to_uppercase()
}
pub(crate) fn beneath(path: &str, prefix: &str) -> bool {
    let p = key(path);
    let r = key(prefix);
    p == r || p.strip_prefix(&r).is_some_and(|x| x.starts_with('/'))
}

pub(crate) struct Pinned {
    pub file: File,
    pub identity: String,
    pub canonical: PathBuf,
    pub _ancestors: Vec<File>,
}

#[cfg(windows)]
fn absolute(path: &Path) -> Result {
    use std::path::Prefix;
    if !path.is_absolute() {
        return Err(Error::Invalid("absolute local drive path required"));
    }
    for c in path.components() {
        match c {
            Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_)) => (),
            Component::Prefix(_) | Component::ParentDir | Component::CurDir => {
                return Err(Error::Denied("device, network or traversal root"));
            }
            Component::Normal(s) => {
                relative(s.to_str().ok_or(Error::Invalid("non-Unicode path"))?)?
            }
            _ => (),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_mode(
    path: &Path,
    dir: bool,
    write: bool,
    delete: bool,
    create: bool,
) -> Result<(File, String, PathBuf)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(write)
        .create_new(create)
        .share_mode(if dir {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else if write {
            0
        } else {
            FILE_SHARE_READ
        })
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT | if dir { FILE_FLAG_BACKUP_SEMANTICS } else { 0 },
        );
    if dir {
        opts.access_mode(
            FILE_READ_ATTRIBUTES
                | FILE_LIST_DIRECTORY
                | if delete { DELETE | SYNCHRONIZE } else { 0 },
        );
    } else if delete {
        opts.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE);
    }
    let file = opts.open(path)?;
    inspect(file, path, dir)
}

#[cfg(windows)]
fn inspect(file: File, path: &Path, dir: bool) -> Result<(File, String, PathBuf)> {
    use std::os::windows::{ffi::OsStringExt, fs::MetadataExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::*;
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || meta.is_dir() != dir
        || (!dir && !meta.is_file())
    {
        return Err(Error::Denied("reparse or wrong-kind file"));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if !dir && info.nNumberOfLinks != 1 {
        return Err(Error::Denied("hard-linked files are not supported"));
    }
    let mut buf = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(file.as_raw_handle(), buf.as_mut_ptr(), buf.len() as u32, 0)
    } as usize;
    if count == 0 || count >= buf.len() {
        return Err(Error::Denied("handle path unavailable"));
    }
    let name = std::ffi::OsString::from_wide(&buf[..count])
        .into_string()
        .map_err(|_| Error::Invalid("non-Unicode handle path"))?;
    let name = name
        .strip_prefix(r"\\?\")
        .ok_or(Error::Denied("non-local handle path"))?;
    let canonical = PathBuf::from(name);
    absolute(&canonical)?;
    if key(&canonical.to_string_lossy()) != key(&path.to_string_lossy()) {
        return Err(Error::Denied("handle target alias"));
    }
    let identity = format!(
        "{:08x}:{:08x}{:08x}",
        info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
    );
    Ok((file, identity, canonical))
}

pub(crate) fn pin(path: &Path, dir: bool, write: bool) -> Result<Pinned> {
    pin_mode(path, dir, write, false)
}

pub(crate) fn pin_delete(path: &Path) -> Result<Pinned> {
    pin_mode(path, false, true, true)
}

pub(crate) fn pin_delete_directory(path: &Path) -> Result<Pinned> {
    pin_mode(path, true, false, true)
}

/// Relative FILE_CREATE returns the new directory handle in the same system
/// call. There is no create-by-name followed by an unprotected reopen gap.
pub(crate) fn create_directory(parent: &Pinned, name: &str) -> Result<Pinned> {
    relative(name)?;
    if name.contains('/') {
        return Err(Error::Invalid("one directory component required"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        };
        use windows_sys::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
                },
            },
            Win32::{
                Foundation::{RtlNtStatusToDosError, UNICODE_STRING},
                Storage::FileSystem::*,
                System::IO::IO_STATUS_BLOCK,
            },
        };
        let mut wide: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
        let mut text = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.file.as_raw_handle(),
            ObjectName: &mut text,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut handle = std::ptr::null_mut();
        let mut io = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
                &attrs,
                &mut io,
                std::ptr::null(),
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            return Err(std::io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            )
            .into());
        }
        let f = unsafe { File::from_raw_handle(handle) };
        let (file, identity, canonical) = inspect(f, &parent.canonical.join(name), true)?;
        Ok(Pinned {
            file,
            identity,
            canonical,
            _ancestors: vec![],
        })
    }
    #[cfg(not(windows))]
    {
        let _ = parent;
        Err(Error::Unsupported("Windows directory create required"))
    }
}

fn pin_mode(path: &Path, dir: bool, write: bool, delete: bool) -> Result<Pinned> {
    #[cfg(not(windows))]
    {
        let _ = (path, dir, write, delete);
        Err(Error::Unsupported(
            "Windows handle-pinned filesystem required",
        ))
    }
    #[cfg(windows)]
    {
        absolute(path)?;
        let parent = path
            .parent()
            .ok_or(Error::Invalid("drive root is not a workspace"))?;
        let mut chain: Vec<_> = parent.ancestors().collect();
        chain.reverse();
        let mut guards = Vec::new();
        for p in chain {
            let (f, _, actual) = open_mode(p, true, false, false, false)?;
            if key(&actual.to_string_lossy()) != key(&p.to_string_lossy()) {
                return Err(Error::Denied("ancestor alias is not canonical"));
            }
            guards.push(f);
        }
        let (file, identity, canonical) = open_mode(path, dir, write, delete, false)?;
        if key(&canonical.to_string_lossy()) != key(&path.to_string_lossy()) {
            return Err(Error::Denied("target alias is not canonical"));
        }
        Ok(Pinned {
            file,
            identity,
            canonical,
            _ancestors: guards,
        })
    }
}

/// All destination ancestors stay pinned by the caller. CREATE_NEW is the
/// final absence check: a concurrently appearing file is never overwritten.
pub(crate) fn create_new(path: &Path) -> Result<Pinned> {
    #[cfg(windows)]
    {
        let (file, identity, canonical) = open_mode(path, false, true, false, true)?;
        Ok(Pinned {
            file,
            identity,
            canonical,
            _ancestors: vec![],
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::Unsupported("Windows create required"))
    }
}

/// Rename the exact held source object, without replacement. Destination
/// ancestors must stay pinned throughout this call and postcondition checks.
pub(crate) fn move_no_replace(source: &Pinned, destination: &Path) -> Result {
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::*;
        absolute(destination)?;
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let size = offset + (name.len() + 1) * 2;
        // u64 allocation supplies alignment for HANDLE and the union.
        let mut buffer = vec![0u64; size.div_ceil(8)];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = (name.len() * 2) as u32;
            // The flexible UTF-16 tail belongs to the aligned allocation.
            let tail = buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>();
            std::ptr::copy_nonoverlapping(name.as_ptr(), tail, name.len());
            if SetFileInformationByHandle(
                source.file.as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                size as u32,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (source, destination);
        Err(Error::Unsupported("Windows move required"))
    }
}

/// Consumes the exclusive source handle so successful deletion is finalized
/// before callers inspect absence. No recursive or pathname deletion exists.
pub(crate) fn delete(source: Pinned) -> Result {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let mut info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                source.file.as_raw_handle(),
                FileDispositionInfo,
                (&mut info as *mut FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        drop(source);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = source;
        Err(Error::Unsupported("Windows delete required"))
    }
}
