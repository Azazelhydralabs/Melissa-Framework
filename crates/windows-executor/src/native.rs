use crate::*;
use std::{
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{IO::*, JobObjects::*, Pipes::*, SystemServices::*, Threading::*},
};

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
fn last(context: &str) -> ExecutorError {
    ExecutorError::Security(format!("{context}: {}", std::io::Error::last_os_error()))
}
fn bool_ok(value: i32, context: &str) -> Result<(), ExecutorError> {
    if value == 0 {
        Err(last(context))
    } else {
        Ok(())
    }
}

struct Handle(HANDLE);
impl Handle {
    fn new(h: HANDLE, context: &str) -> Result<Self, ExecutorError> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            Err(last(context))
        } else {
            Ok(Self(h))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct Profile {
    name: Vec<u16>,
    sid: PSID,
    folder: PathBuf,
    removed: bool,
}
impl Profile {
    fn create() -> Result<Self, ExecutorError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| ExecutorError::Security(format!("secure job identity: {e}")))?;
        let name = wide(format!(
            "Melissa.Code03.{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let mut sid = null_mut();
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if status < 0 {
            return Err(ExecutorError::Unsupported(format!(
                "CreateAppContainerProfile HRESULT {status:#x}; no fallback"
            )));
        }
        let mut value = Self {
            name,
            sid,
            folder: PathBuf::new(),
            removed: false,
        };
        let mut sid_text = null_mut();
        bool_ok(
            unsafe { ConvertSidToStringSidW(sid, &mut sid_text) },
            "ConvertSidToStringSidW",
        )?;
        let _sid_text = Local(sid_text.cast());
        let mut folder = null_mut();
        let status = unsafe { GetAppContainerFolderPath(sid_text, &mut folder) };
        if status < 0 {
            return Err(ExecutorError::Security(format!(
                "AppContainer folder HRESULT {status:#x}"
            )));
        }
        // GetAppContainerFolderPath allocates with CoTaskMemAlloc.
        let mut len = 0;
        unsafe {
            while *folder.add(len) != 0 {
                len += 1;
            }
        }
        value.folder = PathBuf::from(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(folder, len)
        }));
        unsafe {
            windows_sys::Win32::System::Com::CoTaskMemFree(folder.cast());
        }
        Ok(value)
    }
    fn remove(&mut self) -> bool {
        if self.removed {
            return true;
        }
        self.removed = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) } >= 0;
        self.removed
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        self.remove();
        unsafe {
            FreeSid(self.sid);
        }
    }
}

/// ACL snapshots bind original file objects, even when owned staging renames
/// them. Only authority anchors and the selected executable deny deletion.
struct AclGuard {
    file: Option<File>,
    volume_hint: Option<File>,
    file_id: u64,
    owned_roots: Vec<PathBuf>,
    id_reopen_verified: bool,
    descriptor: Local,
    old_dacl: *mut ACL,
    writable: bool,
    restored: bool,
}
impl AclGuard {
    fn grant(
        path: &Path,
        sid: PSID,
        writable: bool,
        directory: bool,
    ) -> Result<Self, ExecutorError> {
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | if writable { WRITE_OWNER } else { 0 })
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let h = file.as_raw_handle();
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        bool_ok(
            unsafe { GetFileInformationByHandle(h, &mut info) },
            "file identity",
        )?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (!writable && !directory && info.nNumberOfLinks != 1)
        {
            return Err(ExecutorError::Security(
                "linked/reparse sandbox resource rejected".into(),
            ));
        }
        let mut old_dacl = null_mut();
        let mut old_sacl = null_mut();
        let mut descriptor = null_mut();
        let result = unsafe {
            GetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut old_dacl,
                &mut old_sacl,
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(ExecutorError::Security(format!(
                "read resource ACL: {result}"
            )));
        }
        let mut guard = Self {
            file: Some(file),
            volume_hint: None,
            file_id: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            owned_roots: Vec::new(),
            id_reopen_verified: false,
            descriptor: Local(descriptor),
            old_dacl,
            writable,
            restored: false,
        };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: if writable {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            } else {
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            },
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: if directory {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
            },
        };
        let mut new_acl = null_mut();
        let status = unsafe { SetEntriesInAclW(1, &entry, old_dacl, &mut new_acl) };
        if status != 0 {
            return Err(ExecutorError::Security(format!(
                "build resource ACL: {status}"
            )));
        }
        let _new_acl = Local(new_acl.cast());
        let status = unsafe {
            SetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_acl,
                null(),
            )
        };
        if status != 0 {
            return Err(ExecutorError::Security(format!(
                "grant resource ACL: {status}"
            )));
        }
        if writable {
            let label = wide("S:(ML;OICI;NW;;;LW)");
            let mut sd = null_mut();
            bool_ok(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        label.as_ptr(),
                        1,
                        &mut sd,
                        null_mut(),
                    )
                },
                "low integrity descriptor",
            )?;
            let _sd = Local(sd);
            let mut present = 0;
            let mut defaulted = 0;
            let mut sacl = null_mut();
            bool_ok(
                unsafe { GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted) },
                "low integrity SACL",
            )?;
            let status = unsafe {
                SetSecurityInfo(
                    h,
                    SE_FILE_OBJECT,
                    LABEL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null(),
                    sacl,
                )
            };
            if status != 0 {
                return Err(ExecutorError::Security(format!(
                    "label writable resource: {status}"
                )));
            }
        }
        // Keep ownership of the original security descriptor through restore.
        guard.restored = false;
        Ok(guard)
    }
    fn restore(&mut self) -> bool {
        if self.restored {
            return true;
        }
        let reopened;
        let file = if let Some(file) = &self.file {
            file
        } else {
            let Some(hint) = &self.volume_hint else {
                return false;
            };
            let id = FILE_ID_DESCRIPTOR {
                dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
                Type: FileIdType,
                Anonymous: FILE_ID_DESCRIPTOR_0 {
                    FileId: self.file_id as i64,
                },
            };
            let raw = unsafe {
                OpenFileById(
                    hint.as_raw_handle(),
                    &id,
                    FILE_READ_ATTRIBUTES
                        | READ_CONTROL
                        | WRITE_DAC
                        | if self.writable { WRITE_OWNER } else { 0 },
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                if matches!(
                    unsafe { GetLastError() },
                    ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND
                ) || (self.id_reopen_verified
                    && unsafe { GetLastError() } == ERROR_INVALID_PARAMETER)
                {
                    self.restored = true;
                    return true;
                }
                return false;
            }
            reopened = unsafe { File::from_raw_handle(raw) };
            &reopened
        };
        let mut standard = FILE_STANDARD_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } == 0
        {
            return false;
        }
        // A verified original file ID may remain open after its final name was
        // removed. NTFS can then expose an internal $Deleted path outside the
        // owned roots. Zero links proves there is no remaining named object to
        // mutate; do not apply any ACL through this now-unlinked handle.
        if standard.NumberOfLinks == 0 {
            self.restored = true;
            return true;
        }
        if self.file.is_none() && crate::fswalk::all_links_inside(file, &self.owned_roots).is_err()
        {
            return false;
        }
        // Pending deletion alone never bypasses ownership/hardlink checks.
        if standard.DeletePending {
            self.restored = true;
            return true;
        }
        self.restored = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.old_dacl,
                null(),
            )
        } == 0;
        if self.writable {
            self.restored = unsafe {
                SetKernelObjectSecurity(
                    file.as_raw_handle(),
                    LABEL_SECURITY_INFORMATION,
                    self.descriptor.0,
                )
            } != 0
                && self.restored;
        }
        self.restored
    }
    fn release_runtime_lock(
        &mut self,
        hint: &File,
        roots: &[PathBuf],
    ) -> Result<(), ExecutorError> {
        // Verify this filesystem accepts the exact ID/access/options before
        // releasing the original handle. This also distinguishes unsupported
        // ID reopening from stale IDs after an authorized deletion.
        let id = FILE_ID_DESCRIPTOR {
            dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: self.file_id as i64,
            },
        };
        let verification = Handle::new(
            unsafe {
                OpenFileById(
                    hint.as_raw_handle(),
                    &id,
                    FILE_READ_ATTRIBUTES
                        | READ_CONTROL
                        | WRITE_DAC
                        | if self.writable { WRITE_OWNER } else { 0 },
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                )
            },
            "verify filesystem ID reopen support",
        )?;
        let mut identity = BY_HANDLE_FILE_INFORMATION::default();
        bool_ok(
            unsafe { GetFileInformationByHandle(verification.0, &mut identity) },
            "verify reopened ID identity",
        )?;
        if (((identity.nFileIndexHigh as u64) << 32) | identity.nFileIndexLow as u64)
            != self.file_id
        {
            return Err(ExecutorError::Security(
                "filesystem ID reopen returned a different object".into(),
            ));
        }
        self.id_reopen_verified = true;
        self.volume_hint = Some(hint.try_clone()?);
        self.owned_roots = roots.to_vec();
        self.file.take();
        Ok(())
    }
}
impl Drop for AclGuard {
    fn drop(&mut self) {
        let _ = &self.descriptor;
        self.restore();
    }
}

fn inspect_path(path: &Path, directory: bool) -> Result<PathBuf, ExecutorError> {
    for part in path.ancestors() {
        let m = fs::symlink_metadata(part)?;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ExecutorError::Security(
                "reparse path component rejected".into(),
            ));
        }
    }
    let m = fs::metadata(path)?;
    if m.is_dir() != directory || (!directory && !m.is_file()) {
        return Err(ExecutorError::InvalidRequest(
            "unexpected executable/workspace kind".into(),
        ));
    }
    Ok(fs::canonicalize(path)?)
}

fn pin_ancestors(path: &Path, directory: bool, pins: &mut Vec<File>) -> Result<(), ExecutorError> {
    let mut ancestors: Vec<_> = path.ancestors().skip(usize::from(!directory)).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ExecutorError::Security(
                "linked/reparse ancestor rejected".into(),
            ));
        }
        pins.push(file);
    }
    Ok(())
}
fn collect_paths(root: &Path, paths: &mut Vec<(PathBuf, bool)>) -> Result<(), ExecutorError> {
    let allowed = [fs::canonicalize(root)?];
    for entry in crate::fswalk::scan(root, false, true)?.entries {
        crate::fswalk::all_links_inside(&entry.file, &allowed)?;
        paths.push((entry.path, entry.directory));
    }
    Ok(())
}
fn sampled_bytes(root: &Path) -> Result<u64, ExecutorError> {
    Ok(crate::fswalk::scan(root, false, true)?.bytes)
}

fn remove_generated_sid_grants(root: &Path, sid: PSID, owned_roots: &[PathBuf]) -> bool {
    let Ok(snapshot) = crate::fswalk::scan(root, true, true) else {
        return false;
    };
    let mut restored = true;
    for object in &snapshot.entries {
        let result = (|| -> Result<(), ExecutorError> {
            crate::fswalk::all_links_inside(&object.file, owned_roots)?;
            let file = &object.file;
            let mut dacl = null_mut();
            let mut sd = null_mut();
            let status = unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut dacl,
                    null_mut(),
                    &mut sd,
                )
            };
            if status != 0 {
                return Err(ExecutorError::Security(format!(
                    "generated resource ACL: {status}"
                )));
            }
            let _sd = Local(sd);
            let entry = EXPLICIT_ACCESS_W {
                grfAccessPermissions: 0,
                grfAccessMode: REVOKE_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: sid.cast(),
                },
            };
            let mut clean_acl = null_mut();
            let status = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut clean_acl) };
            if status != 0 {
                return Err(ExecutorError::Security(format!(
                    "revoke generated resource ACL: {status}"
                )));
            }
            let _clean_acl = Local(clean_acl.cast());
            let status = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    clean_acl,
                    null(),
                )
            };
            if status != 0 {
                return Err(ExecutorError::Security(format!(
                    "restore generated resource ACL: {status}"
                )));
            }
            Ok(())
        })();
        restored = result.is_ok() && restored;
    }
    restored
}

fn quoted(s: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in s.chars() {
        if ch == '\\' {
            slashes += 1;
        } else {
            if ch == '\"' {
                result.push_str(&"\\".repeat(slashes * 2 + 1));
            } else {
                result.push_str(&"\\".repeat(slashes));
            }
            slashes = 0;
            result.push(ch);
        }
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    result
}
struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new() -> Result<Self, ExecutorError> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 3, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(last("attribute list sizing"));
        }
        let mut value = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        bool_ok(
            unsafe { InitializeProcThreadAttributeList(value.ptr(), 3, 0, &mut bytes) },
            "attribute list initialization",
        )?;
        value.initialized = true;
        Ok(value)
    }
    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn set<T>(&mut self, key: u32, value: *const T, count: usize) -> Result<(), ExecutorError> {
        bool_ok(
            unsafe {
                UpdateProcThreadAttribute(
                    self.ptr(),
                    0,
                    key as usize,
                    value.cast(),
                    size_of::<T>() * count,
                    null_mut(),
                    null(),
                )
            },
            "launch security attributes",
        )
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr());
            }
        }
    }
}
fn pipe() -> Result<(Handle, Handle), ExecutorError> {
    let mut read = null_mut();
    let mut write = null_mut();
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    bool_ok(
        unsafe { CreatePipe(&mut read, &mut write, &attrs, 0) },
        "CreatePipe",
    )?;
    Ok((
        Handle::new(read, "read pipe")?,
        Handle::new(write, "write pipe")?,
    ))
}
#[derive(Default)]
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    failed: bool,
}
fn reader(
    handle: Handle,
    stderr: bool,
    shared: Arc<Mutex<Output>>,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    // Ownership of only this read handle moves into the reader thread.
    let raw = handle.0 as usize;
    std::mem::forget(handle);
    thread::spawn(move || {
        let mut file = unsafe { File::from_raw_handle(raw as HANDLE) };
        let mut buf = [0u8; 8192];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let Ok(mut out) = shared.lock() else {
                        return;
                    };
                    let available = limit.saturating_sub(out.stdout.len() + out.stderr.len());
                    let take = n.min(available);
                    if stderr {
                        out.stderr.extend_from_slice(&buf[..take]);
                    } else {
                        out.stdout.extend_from_slice(&buf[..take]);
                    }
                    if take < n {
                        out.truncated = true;
                        exceeded.store(true, Ordering::Release);
                    }
                }
                Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => break,
                Err(_) => {
                    if let Ok(mut out) = shared.lock() {
                        out.failed = true;
                    }
                    break;
                }
            }
        }
    })
}
fn job_query<T: Default>(job: HANDLE, class: JOBOBJECTINFOCLASS) -> Result<T, ExecutorError> {
    let mut v = T::default();
    bool_ok(
        unsafe {
            QueryInformationJobObject(
                job,
                class,
                (&mut v as *mut T).cast(),
                size_of::<T>() as u32,
                null_mut(),
            )
        },
        "query Job Object",
    )?;
    Ok(v)
}
fn job_set<T>(job: HANDLE, class: JOBOBJECTINFOCLASS, v: &T) -> Result<(), ExecutorError> {
    bool_ok(
        unsafe {
            SetInformationJobObject(job, class, (v as *const T).cast(), size_of::<T>() as u32)
        },
        "configure Job Object",
    )
}

fn job_has_live_descendants(job: HANDLE, root_pid: u32) -> Result<bool, ExecutorError> {
    // Root signaling and accounting snapshots are not atomic. The accounting
    // snapshot taken before root exit can still count the root itself. Query a
    // fresh process list and verify actual non-root live members instead.
    let offset = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
    let mut slots = 16usize;
    loop {
        let bytes = offset + slots * size_of::<usize>();
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let value = storage
            .as_mut_ptr()
            .cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        let result = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                value.cast(),
                bytes as u32,
                null_mut(),
            )
        };
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_MORE_DATA && slots < 4096 {
                slots = (slots * 2)
                    .max(unsafe { (*value).NumberOfAssignedProcesses } as usize)
                    .min(4096);
                continue;
            }
            return Err(ExecutorError::Security(format!(
                "fresh Job process list: {error}"
            )));
        }
        let count = unsafe { (*value).NumberOfProcessIdsInList } as usize;
        let assigned = unsafe { (*value).NumberOfAssignedProcesses } as usize;
        if count < assigned {
            if slots >= 4096 {
                return Err(ExecutorError::Security(
                    "Job process list exceeds verification bound".into(),
                ));
            }
            slots = (slots * 2).max(assigned).min(4096);
            continue;
        }
        if count > slots {
            return Err(ExecutorError::Security(
                "invalid Job process-list length".into(),
            ));
        }
        let pids = unsafe {
            std::slice::from_raw_parts(
                storage.as_ptr().cast::<u8>().add(offset).cast::<usize>(),
                count,
            )
        };
        for &pid in pids {
            if pid == 0 || pid == root_pid as usize {
                continue;
            }
            let pid: u32 = pid
                .try_into()
                .map_err(|_| ExecutorError::Security("invalid Job process identifier".into()))?;
            let raw = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            if raw.is_null() {
                let error = unsafe { GetLastError() };
                if error == ERROR_INVALID_PARAMETER {
                    continue;
                }
                return Err(ExecutorError::Security(format!(
                    "verify descendant process: {error}"
                )));
            }
            let process = Handle::new(raw, "descendant process")?;
            let mut member = 0;
            bool_ok(
                unsafe { IsProcessInJob(process.0, job, &mut member) },
                "verify descendant Job membership",
            )?;
            match unsafe { WaitForSingleObject(process.0, 0) } {
                WAIT_OBJECT_0 => continue,
                WAIT_TIMEOUT if member != 0 => return Ok(true),
                WAIT_TIMEOUT => continue, // PID was reused by a process outside this Job.
                _ => return Err(last("verify descendant liveness")),
            }
        }
        return Ok(false);
    }
}
struct Running {
    job: Handle,
    process: Handle,
    thread: Handle,
}
impl Drop for Running {
    fn drop(&mut self) {
        unsafe {
            TerminateJobObject(self.job.0, 0xE0000001);
            WaitForSingleObject(self.process.0, 5000);
        }
    }
}

pub(crate) fn run(
    r: &ExecuteRequest,
    cancelled: &AtomicBool,
) -> Result<ExecutorReport, ExecutorError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ExecutorError::CancelledBeforeLaunch);
    }
    let mut ancestor_pins = Vec::new();
    pin_ancestors(&r.workspace, true, &mut ancestor_pins)?;
    pin_ancestors(&r.current_directory, true, &mut ancestor_pins)?;
    pin_ancestors(&r.executable, false, &mut ancestor_pins)?;
    let workspace = inspect_path(&r.workspace, true)?;
    let current_directory = inspect_path(&r.current_directory, true)?;
    if !current_directory.starts_with(&workspace) {
        return Err(ExecutorError::Security(
            "current directory is outside staged workspace".into(),
        ));
    }
    let executable = inspect_path(&r.executable, false)?;
    let mut binary = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&executable)?;
    let mut binary_info = BY_HANDLE_FILE_INFORMATION::default();
    bool_ok(
        unsafe { GetFileInformationByHandle(binary.as_raw_handle(), &mut binary_info) },
        "selected binary identity",
    )?;
    if binary_info.nNumberOfLinks != 1 {
        return Err(ExecutorError::Security(
            "selected executable must have a single immutable name".into(),
        ));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = binary.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    if format!("blake3:{}", hasher.finalize().to_hex()) != r.executable_blake3 {
        return Err(ExecutorError::Security("executable digest changed".into()));
    }
    binary.seek(SeekFrom::Start(0))?;
    let mut profile = Profile::create()?;
    let profile_directory_pin = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&profile.folder)?;
    let owned_roots = [workspace.clone(), fs::canonicalize(&profile.folder)?];
    let mut paths = vec![(workspace.clone(), true)];
    collect_paths(&workspace, &mut paths)?;
    // Pin and grant files first, then directory ACL inheritance. This avoids
    // taking a child snapshot after parent inheritance has already changed it.
    paths.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    let mut acls = Vec::new();
    for (path, isdir) in &paths {
        acls.push(AclGuard::grant(path, profile.sid, true, *isdir)?);
    }
    if !executable.starts_with(&workspace) {
        acls.push(AclGuard::grant(&executable, profile.sid, false, false)?);
    }
    let workspace_hint = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&workspace)?;
    let restore_roots = [
        workspace.clone(),
        owned_roots[1].clone(),
        executable.clone(),
    ];
    for acl in &mut acls {
        if acl.writable {
            acl.release_runtime_lock(&workspace_hint, &restore_roots)?;
        }
    }
    let job = Handle::new(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObjectW",
    )?;
    let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            PerJobUserTimeLimit: (r.limits.cpu_time_ms * 10_000) as i64,
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_JOB_TIME
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            ActiveProcessLimit: r.limits.max_processes,
            ..Default::default()
        },
        JobMemoryLimit: r.limits.memory_bytes as usize,
        ..Default::default()
    };
    job_set(job.0, JobObjectExtendedLimitInformation, &limits)?;
    let cpu_rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
            CpuRate: r.limits.cpu_rate_basis_points as u32,
        },
    };
    job_set(job.0, JobObjectCpuRateControlInformation, &cpu_rate)?;
    let observed_rate = job_query::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>(
        job.0,
        JobObjectCpuRateControlInformation,
    )?;
    if observed_rate.ControlFlags != cpu_rate.ControlFlags
        || unsafe { observed_rate.Anonymous.CpuRate } != r.limits.cpu_rate_basis_points as u32
    {
        return Err(ExecutorError::Security(
            "OS CPU rate cap differs from authorized value".into(),
        ));
    }
    job_set(
        job.0,
        JobObjectBasicUIRestrictions,
        &JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        },
    )?;
    let port = Handle::new(
        unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) },
        "Job completion port",
    )?;
    job_set(
        job.0,
        JobObjectAssociateCompletionPortInformation,
        &JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: std::ptr::dangling_mut::<c_void>(),
            CompletionPort: port.0,
        },
    )?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let (stdin_read, stdin_write) = pipe()?;
    bool_ok(
        unsafe { SetHandleInformation(stdout_read.0, HANDLE_FLAG_INHERIT, 0) },
        "stdout parent noninheritance",
    )?;
    bool_ok(
        unsafe { SetHandleInformation(stderr_read.0, HANDLE_FLAG_INHERIT, 0) },
        "stderr parent noninheritance",
    )?;
    drop(stdin_write); // Child reads EOF; no broker/user input is inherited.
    let inherited = [stdin_read.0, stdout_write.0, stderr_write.0];
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attributes = Attributes::new()?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited.as_ptr(),
        inherited.len(),
    )?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &capabilities,
        1,
    )?;
    // WinBase.h 10.0.26100.0, also documented by UpdateProcThreadAttribute.
    let mitigation: u64 = 1u64 << 28;
    attributes.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation, 1)?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read.0;
    startup.StartupInfo.hStdOutput = stdout_write.0;
    startup.StartupInfo.hStdError = stderr_write.0;
    startup.lpAttributeList = attributes.ptr();
    let mut command = quoted(&executable.to_string_lossy());
    for arg in &r.arguments {
        command.push(' ');
        command.push_str(&quoted(arg));
    }
    let mut command = wide(command);
    if command.len() > 32767 {
        return Err(ExecutorError::InvalidRequest(
            "encoded command line too long".into(),
        ));
    }
    let mut windows_dir = vec![0u16; 32768];
    let size = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
            windows_dir.as_mut_ptr(),
            windows_dir.len() as u32,
        )
    };
    if size == 0 || size as usize >= windows_dir.len() {
        return Err(last("OS-derived SystemRoot"));
    }
    windows_dir.truncate(size as usize);
    let mut local_app_data = null_mut();
    let status = unsafe {
        windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData,
            0,
            null_mut(),
            &mut local_app_data,
        )
    };
    if status < 0 {
        return Err(ExecutorError::Security(format!(
            "OS known folder HRESULT {status:#x}"
        )));
    }
    let mut len = 0;
    unsafe {
        while *local_app_data.add(len) != 0 {
            len += 1;
        }
    }
    let local_app_data_value =
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(local_app_data, len) });
    unsafe {
        windows_sys::Win32::System::Com::CoTaskMemFree(local_app_data.cast());
    }
    let mut env = r.environment.clone();
    env.retain(|k, _| {
        !matches!(
            k.to_uppercase().as_str(),
            "SYSTEMROOT" | "LOCALAPPDATA" | "TEMP" | "TMP"
        )
    });
    env.insert("SystemRoot".into(), String::from_utf16_lossy(&windows_dir));
    env.insert(
        "LOCALAPPDATA".into(),
        profile.folder.to_string_lossy().into(),
    );
    env.insert(
        "TEMP".into(),
        profile.folder.join("Temp").to_string_lossy().into(),
    );
    env.insert(
        "TMP".into(),
        profile.folder.join("Temp").to_string_lossy().into(),
    );
    // CreateProcessW applies its AppContainer mapping to the supplied base
    // LOCALAPPDATA and replaces TEMP/TMP. Supplying the already mapped folder
    // would incorrectly append Packages/<profile>/AC a second time.
    let mut launch_env = env.clone();
    launch_env.insert("LOCALAPPDATA".into(), local_app_data_value);
    let mut environment: Vec<u16> = Vec::new();
    let mut ordered: Vec<_> = launch_env.iter().collect();
    ordered.sort_by_key(|(k, _)| k.to_uppercase());
    for (k, v) in ordered {
        environment.extend(format!("{k}={v}").encode_utf16());
        environment.push(0);
    }
    environment.push(0);
    let app = wide(&executable);
    let cwd = wide(&current_directory);
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    bool_ok(
        unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        },
        "AppContainer suspended CreateProcessW; no fallback",
    )?;
    let process = Handle::new(info.hProcess, "process handle")?;
    let mainthread = Handle::new(info.hThread, "thread handle")?;
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        unsafe {
            TerminateProcess(process.0, 0xE0000001);
            WaitForSingleObject(process.0, 5000);
        }
        return Err(last("assign suspended AppContainer to Job Object"));
    }
    let running = Running {
        job,
        process,
        thread: mainthread,
    };
    let mut token = null_mut();
    bool_ok(
        unsafe { OpenProcessToken(running.process.0, TOKEN_QUERY, &mut token) },
        "query AppContainer token",
    )?;
    let token = Handle::new(token, "token")?;
    let mut is_ac = 0u32;
    let mut returned = 0;
    bool_ok(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenIsAppContainer,
                (&mut is_ac as *mut u32).cast(),
                4,
                &mut returned,
            )
        },
        "verify AppContainer token",
    )?;
    if is_ac != 1 {
        return Err(ExecutorError::Security(
            "OS did not create AppContainer token".into(),
        ));
    }
    drop(stdout_write);
    let mut token_buffer = [0usize; 128];
    bool_ok(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenAppContainerSid,
                token_buffer.as_mut_ptr().cast(),
                size_of_val(&token_buffer) as u32,
                &mut returned,
            )
        },
        "verify exact AppContainer SID",
    )?;
    let actual_sid = unsafe {
        (*(token_buffer
            .as_ptr()
            .cast::<TOKEN_APPCONTAINER_INFORMATION>()))
        .TokenAppContainer
    };
    if unsafe { EqualSid(actual_sid, profile.sid) } == 0 {
        return Err(ExecutorError::Security(
            "OS AppContainer identity mismatch".into(),
        ));
    }
    bool_ok(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenCapabilities,
                token_buffer.as_mut_ptr().cast(),
                size_of_val(&token_buffer) as u32,
                &mut returned,
            )
        },
        "verify zero network capabilities",
    )?;
    if unsafe { *(token_buffer.as_ptr().cast::<u32>()) } != 0 {
        return Err(ExecutorError::Security(
            "unexpected AppContainer capability grant".into(),
        ));
    }
    let mut system_call_policy = 0u32;
    bool_ok(
        unsafe {
            GetProcessMitigationPolicy(
                running.process.0,
                ProcessSystemCallDisablePolicy,
                (&mut system_call_policy as *mut u32).cast(),
                size_of::<u32>(),
            )
        },
        "verify Win32k disable policy",
    )?;
    if system_call_policy & 1 == 0 {
        return Err(ExecutorError::Security(
            "Win32k system calls were not disabled".into(),
        ));
    }
    drop(stderr_write);
    drop(stdin_read);
    let output = Arc::new(Mutex::new(Output::default()));
    let exceeded = Arc::new(AtomicBool::new(false));
    let outreader = reader(
        stdout_read,
        false,
        output.clone(),
        r.limits.max_output_bytes as usize,
        exceeded.clone(),
    );
    let errreader = reader(
        stderr_read,
        true,
        output.clone(),
        r.limits.max_output_bytes as usize,
        exceeded.clone(),
    );
    let started = Instant::now();
    if !cancelled.load(Ordering::Acquire) && unsafe { ResumeThread(running.thread.0) } == u32::MAX {
        return Err(last("resume sandbox process"));
    }
    let mut reason = None;
    let mut peak_disk = 0;
    let mut scan_at = Instant::now() - Duration::from_secs(1);
    let mut tree_stopped = false;
    let mut descendant_cleanup_required = false;
    let mut root_exit_observed_at: Option<Instant> = None;
    loop {
        let mut msg = 0;
        let mut key = 0;
        let mut overlapped = null_mut();
        while unsafe { GetQueuedCompletionStatus(port.0, &mut msg, &mut key, &mut overlapped, 0) }
            != 0
        {
            let why = match msg {
                JOB_OBJECT_MSG_END_OF_JOB_TIME => Some(TerminationReason::CpuLimit),
                JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT => Some(TerminationReason::ProcessLimit),
                JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT => {
                    Some(TerminationReason::MemoryLimit)
                }
                _ => None,
            };
            if reason.is_none() {
                reason = why;
            }
        }
        let accounting = match job_query::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(
            running.job.0,
            JobObjectBasicAccountingInformation,
        ) {
            Ok(v) => v,
            Err(_) => {
                reason = Some(TerminationReason::MonitorFailure);
                break;
            }
        };
        let cpu = (accounting.TotalUserTime.max(0) as u64)
            .saturating_add(accounting.TotalKernelTime.max(0) as u64)
            / 10_000;
        if reason.is_none() {
            reason = if cancelled.load(Ordering::Acquire) {
                Some(TerminationReason::Cancelled)
            } else if exceeded.load(Ordering::Acquire) {
                Some(TerminationReason::OutputLimit)
            } else if started.elapsed().as_millis() >= r.limits.wall_time_ms as u128 {
                Some(TerminationReason::Timeout)
            } else if cpu >= r.limits.cpu_time_ms {
                Some(TerminationReason::CpuLimit)
            } else {
                None
            };
        }
        if scan_at.elapsed() >= Duration::from_millis(25) {
            scan_at = Instant::now();
            match sampled_bytes(&workspace).and_then(|v| {
                sampled_bytes(&profile.folder).and_then(|p| {
                    v.checked_add(p)
                        .ok_or_else(|| ExecutorError::Security("sampled disk overflow".into()))
                })
            }) {
                Ok(bytes) => {
                    peak_disk = peak_disk.max(bytes);
                    if reason.is_none() && bytes > r.limits.max_workspace_bytes {
                        reason = Some(TerminationReason::DiskLimit);
                    }
                }
                Err(_) => {
                    if reason.is_none() {
                        reason = Some(TerminationReason::MonitorFailure);
                    }
                }
            }
        }
        if accounting.ActiveProcesses == 0 {
            tree_stopped = true;
            break;
        }
        if reason.is_some() {
            break;
        }
        // A finished parent never leaves detached descendants running.
        if unsafe { WaitForSingleObject(running.process.0, 0) } == WAIT_OBJECT_0 {
            let root_exit = root_exit_observed_at.get_or_insert_with(Instant::now);
            match job_has_live_descendants(running.job.0, info.dwProcessId) {
                Ok(true)
                    if root_exit.elapsed() < Duration::from_millis(DESCENDANT_DRAIN_GRACE_MS) =>
                {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Ok(live) => {
                    descendant_cleanup_required = live;
                    reason = Some(TerminationReason::Exited);
                }
                Err(_) => reason = Some(TerminationReason::MonitorFailure),
            }
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let natural_job_drain_ms = root_exit_observed_at.map_or(0, |exit| {
        exit.elapsed().as_millis().min(u64::MAX as u128) as u64
    });
    if !tree_stopped {
        bool_ok(
            unsafe { TerminateJobObject(running.job.0, 0xE0000001) },
            "terminate entire sandbox Job",
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if job_query::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(
                running.job.0,
                JobObjectBasicAccountingInformation,
            )?
            .ActiveProcesses
                == 0
            {
                tree_stopped = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    if !tree_stopped {
        return Err(ExecutorError::Security(
            "Job tree termination not confirmed".into(),
        ));
    }
    if unsafe { WaitForSingleObject(running.process.0, 5000) } != WAIT_OBJECT_0 {
        return Err(last("root process exit wait"));
    }
    let mut exit = 0;
    bool_ok(
        unsafe { GetExitCodeProcess(running.process.0, &mut exit) },
        "root exit code",
    )?;
    outreader
        .join()
        .map_err(|_| ExecutorError::Security("stdout reader panicked".into()))?;
    errreader
        .join()
        .map_err(|_| ExecutorError::Security("stderr reader panicked".into()))?;
    let accounting = job_query::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(
        running.job.0,
        JobObjectBasicAccountingInformation,
    )?;
    let total_cpu_time_ms = (accounting.TotalUserTime.max(0) as u64)
        .saturating_add(accounting.TotalKernelTime.max(0) as u64)
        / 10_000;
    // The root can exit after the last monitor sample but before its signaled
    // state is observed. Final Job accounting includes that last CPU burst;
    // successful exit must not erase an exhausted aggregate CPU allowance.
    reason = finalize_cpu_reason(reason, total_cpu_time_ms, r.limits.cpu_time_ms);
    let memory = job_query::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(
        running.job.0,
        JobObjectExtendedLimitInformation,
    )?;
    // Include retained writes made between the last sample and root exit.
    // Transient/deleted files and other disk consumers remain unmeasured.
    match sampled_bytes(&workspace).and_then(|bytes| {
        sampled_bytes(&profile.folder).and_then(|profile_bytes| {
            bytes
                .checked_add(profile_bytes)
                .ok_or_else(|| ExecutorError::Security("sampled disk overflow".into()))
        })
    }) {
        Ok(bytes) => {
            peak_disk = peak_disk.max(bytes);
            if bytes > r.limits.max_workspace_bytes
                && matches!(reason, None | Some(TerminationReason::Exited))
            {
                reason = Some(TerminationReason::DiskLimit);
            }
        }
        Err(_) => reason = Some(TerminationReason::MonitorFailure),
    }
    let mut output = output
        .lock()
        .map_err(|_| ExecutorError::Security("output reader state poisoned".into()))?;
    if output.failed {
        reason = Some(TerminationReason::MonitorFailure);
    } else if output.truncated && matches!(reason, None | Some(TerminationReason::Exited)) {
        reason = Some(TerminationReason::OutputLimit);
    }
    let mut restored = remove_generated_sid_grants(&workspace, profile.sid, &owned_roots);
    for acl in acls.iter_mut().rev() {
        restored = acl.restore() && restored;
    }
    drop(acls);
    drop(running);
    drop(token);
    drop(binary);
    drop(profile_directory_pin);
    let removed = profile.remove();
    Ok(ExecutorReport {
        environment_contract: ENVIRONMENT_CONTRACT.into(),
        effective_environment: env,
        termination: reason.unwrap_or(TerminationReason::Exited),
        root_process_id: info.dwProcessId,
        exit_code: exit,
        tree_confirmed_stopped: tree_stopped,
        process_was_appcontainer: true,
        win32k_system_calls_disabled: true,
        descendant_cleanup_required,
        descendant_drain_grace_ms: DESCENDANT_DRAIN_GRACE_MS,
        natural_job_drain_ms,
        stdout: std::mem::take(&mut output.stdout),
        stderr: std::mem::take(&mut output.stderr),
        output_truncated: output.truncated,
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        total_cpu_time_ms,
        peak_job_committed_memory_bytes: memory.PeakJobMemoryUsed as u64,
        peak_observed_workspace_and_profile_bytes: peak_disk,
        disk_measurement_complete: false,
        disk_overshoot_bytes: peak_disk.saturating_sub(r.limits.max_workspace_bytes),
        disk_limit_hard_enforced: false,
        total_cpu_limit_sampled: true,
        user_cpu_limit_hard_enforced: true,
        cpu_rate_basis_points: r.limits.cpu_rate_basis_points,
        cpu_rate_hard_enforced: true,
        profile_removed: removed,
        acl_restored: restored,
    })
}

fn finalize_cpu_reason(
    reason: Option<TerminationReason>,
    total_cpu_time_ms: u64,
    cpu_budget_ms: u64,
) -> Option<TerminationReason> {
    if total_cpu_time_ms >= cpu_budget_ms
        && matches!(reason, None | Some(TerminationReason::Exited))
    {
        Some(TerminationReason::CpuLimit)
    } else {
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_argv_quoting() {
        assert_eq!(quoted(""), "\"\"");
        assert_eq!(quoted("a b"), "\"a b\"");
        assert_eq!(quoted("x\\"), "\"x\\\\\"");
        assert_eq!(quoted("x\"y"), "\"x\\\"y\"");
    }
    #[test]
    fn final_cpu_accounting_overrides_a_late_success_without_hiding_other_failures() {
        for reason in [None, Some(TerminationReason::Exited)] {
            assert_eq!(
                finalize_cpu_reason(reason, 25, 25),
                Some(TerminationReason::CpuLimit)
            );
            assert_eq!(finalize_cpu_reason(reason, 24, 25), reason);
        }
        for reason in [
            TerminationReason::Cancelled,
            TerminationReason::Timeout,
            TerminationReason::OutputLimit,
            TerminationReason::MemoryLimit,
            TerminationReason::MonitorFailure,
        ] {
            assert_eq!(finalize_cpu_reason(Some(reason), 26, 25), Some(reason));
        }
    }
}
