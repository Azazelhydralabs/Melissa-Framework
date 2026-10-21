//! No-reparse, handle-relative traversal. Read-only monitoring never denies
//! rename/delete and never resolves a directory entry by an unpinned pathname.
use crate::ExecutorError;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem as nt},
    Win32::{Foundation::*, Storage::FileSystem::*, System::IO::IO_STATUS_BLOCK},
};

pub(crate) struct Entry {
    pub file: File,
    pub path: PathBuf,
    pub directory: bool,
}
pub(crate) struct Snapshot {
    pub entries: Vec<Entry>,
    pub bytes: u64,
    _root: File,
}
fn error(context: &str, status: NTSTATUS) -> ExecutorError {
    ExecutorError::Security(format!("{context}: NTSTATUS {status:#x}"))
}
pub(crate) fn path_of(file: &File) -> Result<PathBuf, ExecutorError> {
    let mut buffer = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if count == 0 || count as usize >= buffer.len() {
        return Err(ExecutorError::Io(std::io::Error::last_os_error()));
    }
    buffer.truncate(count as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}
pub(crate) fn scan(
    root: &Path,
    cleanup: bool,
    allow_hard_links: bool,
) -> Result<Snapshot, ExecutorError> {
    let root_file = OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    check(&root_file, allow_hard_links)?;
    if !root_file.metadata()?.is_dir() {
        return Err(ExecutorError::Security(
            "scan root must be directory".into(),
        ));
    }
    let mut entries = Vec::new();
    let mut bytes = 0;
    visit(
        &root_file,
        &mut entries,
        &mut bytes,
        0,
        cleanup,
        allow_hard_links,
    )?;
    Ok(Snapshot {
        entries,
        bytes,
        _root: root_file,
    })
}
fn check(file: &File, allow_hard_links: bool) -> Result<(), ExecutorError> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ExecutorError::Security(
            "reparse scan object rejected".into(),
        ));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if !allow_hard_links && !metadata.is_dir() && info.nNumberOfLinks != 1 {
        return Err(ExecutorError::Security(
            "hard-linked initial resource rejected".into(),
        ));
    }
    Ok(())
}
pub(crate) fn all_links_inside(file: &File, roots: &[PathBuf]) -> Result<(), ExecutorError> {
    let path = path_of(file)?;
    if !roots.iter().any(|root| path.starts_with(root)) {
        return Err(ExecutorError::Security(
            "cleanup object left owned roots".into(),
        ));
    }
    if file.metadata()?.is_dir() {
        return Ok(());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.nNumberOfLinks == 1 {
        return Ok(());
    }
    if info.nNumberOfLinks == 0 || info.nNumberOfLinks > 4096 {
        return Err(ExecutorError::Security(
            "cleanup hardlink count bound".into(),
        ));
    }
    let Some(std::path::Component::Prefix(prefix)) = path.components().next() else {
        return Err(ExecutorError::Security(
            "cleanup volume prefix missing".into(),
        ));
    };
    use std::os::windows::ffi::OsStrExt;
    let source: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut name = vec![0u16; 32768];
    let mut length = name.len() as u32;
    let raw = unsafe { FindFirstFileNameW(source.as_ptr(), 0, &mut length, name.as_mut_ptr()) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Find(HANDLE);
    impl Drop for Find {
        fn drop(&mut self) {
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let find = Find(raw);
    let mut seen = 0;
    loop {
        let count = name
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| ExecutorError::Security("unterminated hardlink name".into()))?;
        let mut absolute = prefix.as_os_str().to_os_string();
        absolute.push(OsString::from_wide(&name[..count]));
        let absolute = PathBuf::from(absolute);
        if !roots.iter().any(|root| absolute.starts_with(root)) {
            return Err(ExecutorError::Security(
                "hardlink extends outside owned roots".into(),
            ));
        }
        seen += 1;
        if seen > 4096 {
            return Err(ExecutorError::Security("hardlink enumeration bound".into()));
        }
        name.fill(0);
        length = name.len() as u32;
        if unsafe { FindNextFileNameW(find.0, &mut length, name.as_mut_ptr()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_HANDLE_EOF {
                return Err(std::io::Error::from_raw_os_error(error as i32).into());
            }
            break;
        }
    }
    if seen != info.nNumberOfLinks {
        return Err(ExecutorError::Security(
            "hardlink membership changed during cleanup".into(),
        ));
    }
    Ok(())
}
fn open_relative(
    parent: &File,
    name: &[u16],
    directory: bool,
    cleanup: bool,
) -> Result<File, ExecutorError> {
    if name.is_empty() || name.len() > 255 || name.iter().any(|c| matches!(*c, 0 | 47 | 58 | 92)) {
        return Err(ExecutorError::Security(
            "invalid directory entry component".into(),
        ));
    }
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_DONT_REPARSE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    let desired = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if directory { FILE_LIST_DIRECTORY } else { 0 }
        | if cleanup { READ_CONTROL | WRITE_DAC } else { 0 };
    let result = unsafe {
        nt::NtCreateFile(
            &mut raw,
            desired,
            &attributes,
            &mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nt::FILE_OPEN,
            nt::FILE_OPEN_REPARSE_POINT | nt::FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if !cleanup && result == STATUS_DELETE_PENDING {
        // RtlNtStatusToDosError(STATUS_DELETE_PENDING) is ACCESS_DENIED on Windows.
        // Preserve the native deletion distinction for read-only sampling only;
        // the existing walker handles this typed pending/deleted condition.
        return Err(std::io::Error::from_raw_os_error(ERROR_DELETE_PENDING as i32).into());
    }
    if result < 0 {
        return Err(ExecutorError::Io(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        )));
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn visit(
    parent: &File,
    entries: &mut Vec<Entry>,
    bytes: &mut u64,
    depth: usize,
    cleanup: bool,
    allow_links: bool,
) -> Result<(), ExecutorError> {
    if depth > 64 {
        return Err(ExecutorError::Security("scan depth bound".into()));
    }
    let mut storage = vec![0usize; 65536 / size_of::<usize>()];
    let mut restart = true;
    loop {
        let mut io = IO_STATUS_BLOCK::default();
        let status = unsafe {
            nt::NtQueryDirectoryFile(
                parent.as_raw_handle(),
                null_mut(),
                None,
                null(),
                &mut io,
                storage.as_mut_ptr().cast(),
                65536,
                nt::FileNamesInformation,
                false,
                null(),
                restart,
            )
        };
        restart = false;
        if status == STATUS_NO_MORE_FILES {
            return Ok(());
        }
        if status < 0 {
            if matches!(
                unsafe { RtlNtStatusToDosError(status) },
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_DELETE_PENDING
            ) {
                return Ok(());
            }
            return Err(error("handle-relative directory enumeration", status));
        }
        let available = io.Information;
        if available == 0 || available > 65536 {
            return Err(ExecutorError::Security(
                "invalid directory response length".into(),
            ));
        }
        let raw = storage.as_ptr().cast::<u8>();
        let mut offset = 0;
        loop {
            let fixed = offset_of!(nt::FILE_NAMES_INFORMATION, FileName);
            if offset + size_of::<nt::FILE_NAMES_INFORMATION>() > storage.len() * size_of::<usize>()
                || offset + fixed > available
            {
                return Err(ExecutorError::Security("truncated directory entry".into()));
            }
            let record = unsafe { &*raw.add(offset).cast::<nt::FILE_NAMES_INFORMATION>() };
            let length = record.FileNameLength as usize;
            if !length.is_multiple_of(2) || offset + fixed + length > available {
                return Err(ExecutorError::Security(
                    "invalid directory name length".into(),
                ));
            }
            let next = record.NextEntryOffset as usize;
            if next != 0 && (next < fixed || !next.is_multiple_of(4) || offset + next >= available)
            {
                return Err(ExecutorError::Security(
                    "invalid directory next offset".into(),
                ));
            }
            let name = unsafe {
                std::slice::from_raw_parts(raw.add(offset + fixed).cast::<u16>(), length / 2)
            };
            if name != [46] && name != [46, 46] {
                if entries.len() >= 4096 {
                    return Err(ExecutorError::Security("scan entry bound".into()));
                }
                let file = match open_relative(parent, name, false, cleanup) {
                    Err(ExecutorError::Io(e)) if matches!(e.raw_os_error(), Some(2 | 3 | 303)) => {
                        None
                    }
                    Err(e) => return Err(e),
                    Ok(file) => Some(file),
                };
                if let Some(mut file) = file {
                    check(&file, allow_links)?;
                    let directory = file.metadata()?.is_dir();
                    if directory {
                        file = match open_relative(parent, name, true, cleanup) {
                            Err(ExecutorError::Io(error))
                                if matches!(error.raw_os_error(), Some(2 | 3 | 303)) =>
                            {
                                if record.NextEntryOffset == 0 {
                                    break;
                                }
                                offset += record.NextEntryOffset as usize;
                                continue;
                            }
                            result => result?,
                        };
                        check(&file, allow_links)?;
                        if !file.metadata()?.is_dir() {
                            return Err(ExecutorError::Security(
                                "directory entry changed kind".into(),
                            ));
                        }
                    }
                    let path = match path_of(&file) {
                        Err(ExecutorError::Io(error))
                            if matches!(error.raw_os_error(), Some(2 | 3 | 303)) =>
                        {
                            if record.NextEntryOffset == 0 {
                                break;
                            }
                            offset += record.NextEntryOffset as usize;
                            continue;
                        }
                        result => result?,
                    };
                    if !directory {
                        *bytes = bytes.checked_add(file.metadata()?.len()).ok_or_else(|| {
                            ExecutorError::Security("sample byte overflow".into())
                        })?;
                    }
                    if directory {
                        visit(&file, entries, bytes, depth + 1, cleanup, allow_links)?;
                    }
                    entries.push(Entry {
                        file,
                        path,
                        directory,
                    });
                }
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            let next = record.NextEntryOffset as usize;
            if next < fixed || !next.is_multiple_of(4) || offset + next >= available {
                return Err(ExecutorError::Security(
                    "invalid directory next offset".into(),
                ));
            }
            offset += next;
        }
    }
}
#[cfg(test)]
#[path = "fswalk_monitor_tests.rs"]
mod monitor_tests;
