//! Real Windows filesystem regressions for native-status monitor classification.
use super::*;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Security::{Authorization::*, *};

fn parent_handle(path: &Path) -> File {
    OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap()
}

#[test]
fn native_delete_pending_is_skipped_only_by_read_only_monitor() {
    assert_eq!(unsafe { RtlNtStatusToDosError(STATUS_DELETE_PENDING) }, 5);
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("counted.txt"), b"counted").unwrap();
    let parent = parent_handle(temp.path());
    for directory in [false, true] {
        let path = temp
            .path()
            .join(if directory { "directory" } else { "file" });
        if directory {
            std::fs::create_dir(&path).unwrap();
        } else {
            std::fs::write(&path, b"owned").unwrap();
        }
        let held = OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .unwrap();
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    held.as_raw_handle(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        let mut standard = FILE_STANDARD_INFO::default();
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    held.as_raw_handle(),
                    FileStandardInfo,
                    (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                    size_of::<FILE_STANDARD_INFO>() as u32,
                )
            },
            0
        );
        assert!(standard.DeletePending);
        assert_eq!(standard.NumberOfLinks, 0);
        let name: Vec<u16> = path.file_name().unwrap().encode_wide().collect();
        let read_only = open_relative(&parent, &name, directory, false);
        assert!(
            matches!(read_only, Err(ExecutorError::Io(ref e))
            if e.raw_os_error() == Some(ERROR_DELETE_PENDING as i32)),
            "{read_only:?}"
        );
        let cleanup = open_relative(&parent, &name, directory, true);
        assert!(
            matches!(cleanup, Err(ExecutorError::Io(ref e))
            if e.raw_os_error() == Some(5)),
            "cleanup must remain fail-closed: {cleanup:?}"
        );
        let snapshot = scan(temp.path(), false, true).unwrap();
        assert_eq!(snapshot.bytes, 7, "live files must still be accounted");
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].path.file_name().unwrap(), "counted.txt");
        drop(held);
    }
}

struct RestoreDacl {
    file: File,
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
}

impl Drop for RestoreDacl {
    fn drop(&mut self) {
        let result = unsafe {
            SetSecurityInfo(
                self.file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.dacl,
                null(),
            )
        };
        unsafe {
            LocalFree(self.descriptor);
        }
        assert_eq!(result, 0, "restore owned test DACL");
    }
}

#[test]
fn persistent_acl_denial_remains_error_five_and_restores_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("denied");
    std::fs::write(&path, b"owned").unwrap();
    let parent = parent_handle(temp.path());
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path)
        .unwrap();
    let mut descriptor = null_mut();
    let mut dacl = null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let restore = RestoreDacl {
        file,
        descriptor,
        dacl,
    };
    // Deny SYNCHRONIZE, which the actual walker requests, on this owned file.
    // READ_ATTRIBUTES alone can be granted through the parent directory by NTFS.
    let sddl: Vec<u16> = "D:P(D;;0x100000;;;WD)(A;;FA;;;WD)\0"
        .encode_utf16()
        .collect();
    let mut denied_sd = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut denied_sd,
                null_mut(),
            )
        },
        0
    );
    let mut denied_dacl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    assert_ne!(
        unsafe {
            GetSecurityDescriptorDacl(denied_sd, &mut present, &mut denied_dacl, &mut defaulted)
        },
        0
    );
    let applied = unsafe {
        SetSecurityInfo(
            restore.file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            denied_dacl,
            null(),
        )
    };
    unsafe {
        LocalFree(denied_sd);
    }
    assert_eq!(applied, 0);
    let name: Vec<u16> = "denied".encode_utf16().collect();
    for _ in 0..3 {
        for cleanup in [false, true] {
            let result = open_relative(&parent, &name, false, cleanup);
            assert!(
                matches!(result, Err(ExecutorError::Io(ref e))
                if e.raw_os_error() == Some(5)),
                "{result:?}"
            );
        }
        assert!(
            matches!(scan(temp.path(), false, true), Err(ExecutorError::Io(ref e))
            if e.raw_os_error() == Some(5))
        );
    }
    drop(restore);
    assert_eq!(scan(temp.path(), false, true).unwrap().bytes, 5);
}

#[test]
fn outside_hardlink_membership_is_still_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let owned = temp.path().join("owned");
    std::fs::create_dir(&owned).unwrap();
    let path = owned.join("file");
    std::fs::write(&path, b"owned").unwrap();
    std::fs::hard_link(&path, temp.path().join("outside-alias")).unwrap();
    let file = File::open(&path).unwrap();
    let root = path_of(&parent_handle(&owned)).unwrap();
    assert!(matches!(
        all_links_inside(&file, &[root]),
        Err(ExecutorError::Security(_))
    ));
}

#[test]
fn reparse_directory_entry_is_still_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let owned = temp.path().join("owned");
    let target = temp.path().join("outside-target");
    std::fs::create_dir(&owned).unwrap();
    std::fs::create_dir(&target).unwrap();
    let junction = owned.join("junction");
    let creation = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(creation.status.success(), "junction creation: {creation:?}");
    assert!(matches!(
        scan(&owned, false, true),
        Err(ExecutorError::Security(_))
    ));
}
