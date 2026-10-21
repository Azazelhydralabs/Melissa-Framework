//! Real AppContainer regressions for cleanup of unlinked original objects.
#![cfg(windows)]
use melissa_windows_executor::*;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    mem::size_of,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr::null_mut,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::*,
};

fn request(root: &Path, mode: &str) -> ExecuteRequest {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let executable = root.join("probe.exe");
    fs::copy(env!("CARGO_BIN_EXE_melissa-executor-probe"), &executable).unwrap();
    ExecuteRequest {
        executable_blake3: format!("blake3:{}", blake3::hash(&fs::read(&executable).unwrap())),
        executable,
        current_directory: workspace.clone(),
        workspace,
        arguments: vec![mode.into()],
        environment: BTreeMap::from([("MELISSA_VISIBLE".into(), "explicit-value".into())]),
        limits: ExecutionLimits {
            wall_time_ms: 10_000,
            cpu_time_ms: 10_000,
            cpu_rate_basis_points: 10000,
            memory_bytes: 128 * 1024 * 1024,
            max_processes: 5,
            max_output_bytes: 64 * 1024,
            max_workspace_bytes: 32 * 1024 * 1024,
            gpu_required: false,
        },
        network: NetworkMode::Offline,
        disk_mode: DiskLimitMode::Monitored,
    }
}

fn security_descriptor(path: &Path) -> String {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sd = null_mut();
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        },
        0
    );
    let mut value = null_mut();
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                1,
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                &mut value,
                null_mut(),
            )
        },
        0
    );
    let mut len = 0;
    unsafe {
        while *value.add(len) != 0 {
            len += 1;
        }
    }
    let descriptor = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) });
    unsafe {
        LocalFree(sd);
        LocalFree(value.cast());
    }
    descriptor
}

#[test]
fn zero_link_delete_pending_original_needs_no_acl_mutation_and_cleanup_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), "staging-ops");
    for name in ["original.txt", "delete.txt", "replace.txt"] {
        fs::write(request.workspace.join(name), name).unwrap();
    }
    for name in ["original-dir", "delete-dir"] {
        fs::create_dir(request.workspace.join(name)).unwrap();
        fs::write(
            request.workspace.join(name).join("existing.txt"),
            "existing",
        )
        .unwrap();
    }
    // The reader permits deletion and keeps the actual original object alive
    // until Executor::run has returned. No delay assumption controls the race.
    let held = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(request.workspace.join("delete.txt"))
        .unwrap();
    let report = Executor::run(&request, &AtomicBool::new(false)).unwrap();
    let mut final_standard = FILE_STANDARD_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                held.as_raw_handle(),
                FileStandardInfo,
                (&mut final_standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        },
        0
    );
    assert!(final_standard.DeletePending);
    assert_eq!(final_standard.NumberOfLinks, 0);
    assert_eq!(report.termination, TerminationReason::Exited, "{report:?}");
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(String::from_utf8_lossy(&report.stdout), "staging-ops-ok\n");
    assert!(report.tree_confirmed_stopped && report.profile_removed);
    assert!(report.acl_restored, "{report:?}");
    drop(held);
}

#[test]
fn preexisting_outside_hardlink_is_rejected_without_acl_changes() {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), "ok");
    let initial = request.workspace.join("existing.txt");
    let outside = root.path().join("outside-alias.txt");
    fs::write(&initial, "owned fixture").unwrap();
    fs::hard_link(&initial, &outside).unwrap();
    let before = security_descriptor(&outside);
    assert!(matches!(
        Executor::run(&request, &AtomicBool::new(false)),
        Err(ExecutorError::Security(_))
    ));
    assert_eq!(security_descriptor(&outside), before);
    assert!(!request.workspace.join("inside.txt").exists());
}

#[test]
fn nonzero_link_reopened_original_outside_owned_roots_still_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let mut request = request(root.path(), "cpu");
    request.limits.wall_time_ms = 1200;
    let initial = request.workspace.join("existing.txt");
    let outside = root.path().join("outside-alias.txt");
    fs::write(&initial, "owned fixture").unwrap();
    let workspace = request.workspace.clone();
    let observed = Arc::new(AtomicBool::new(false));
    let ready = Arc::clone(&observed);
    let outside_for_host = outside.clone();
    let mutation = std::thread::spawn(move || {
        let began = Instant::now();
        while began.elapsed() < Duration::from_secs(10) {
            // The workspace root is granted last, after all original object
            // snapshots. This is a trusted host mutation of an owned fixture.
            if security_descriptor(&workspace).contains("S-1-15-2-") {
                fs::hard_link(&initial, &outside_for_host).unwrap();
                fs::remove_file(&initial).unwrap();
                ready.store(true, Ordering::Release);
                return security_descriptor(&outside_for_host);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("sandbox ACL grant was not observed within bound");
    });
    let outcome = Executor::run(&request, &AtomicBool::new(false));
    let before_cleanup = mutation.join().unwrap();
    let report = outcome.unwrap();
    assert!(observed.load(Ordering::Acquire));
    let outside_handle = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&outside)
        .unwrap();
    let mut outside_standard = FILE_STANDARD_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                outside_handle.as_raw_handle(),
                FileStandardInfo,
                (&mut outside_standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        },
        0
    );
    assert!(outside_standard.NumberOfLinks > 0);
    assert!(report.tree_confirmed_stopped && report.profile_removed);
    assert!(
        !report.acl_restored,
        "outside alias must not be restored: {report:?}"
    );
    assert_eq!(security_descriptor(&outside), before_cleanup);
}
