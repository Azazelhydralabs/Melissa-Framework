#![cfg(windows)]
use melissa_windows_executor::*;
use std::{
    collections::BTreeMap,
    fs,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    request: ExecuteRequest,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = root.path().join("probe.exe");
        fs::copy(env!("CARGO_BIN_EXE_melissa-executor-probe"), &executable).unwrap();
        let executable_blake3 = format!(
            "blake3:{}",
            blake3::hash(&fs::read(&executable).unwrap()).to_hex()
        );
        Self {
            root,
            request: ExecuteRequest {
                executable,
                executable_blake3,
                current_directory: workspace.clone(),
                workspace,
                arguments: vec![mode.into()],
                environment: BTreeMap::from([("MELISSA_VISIBLE".into(), "explicit-value".into())]),
                limits: ExecutionLimits {
                    wall_time_ms: 5000,
                    cpu_time_ms: 3000,
                    cpu_rate_basis_points: 10000,
                    memory_bytes: 128 * 1024 * 1024,
                    max_processes: 5,
                    max_output_bytes: 64 * 1024,
                    max_workspace_bytes: 32 * 1024 * 1024,
                    gpu_required: false,
                },
                network: NetworkMode::Offline,
                disk_mode: DiskLimitMode::Monitored,
            },
        }
    }
    fn run(&self) -> ExecutorReport {
        Executor::run(&self.request, &AtomicBool::new(false)).unwrap_or_else(|e| {
            panic!("actual AppContainer launch failed, no fallback allowed: {e}")
        })
    }
}
fn clean(report: &ExecutorReport) {
    assert!(report.tree_confirmed_stopped, "{report:?}");
    assert!(report.process_was_appcontainer);
    assert!(report.win32k_system_calls_disabled);
    assert!(report.profile_removed, "private profile cleanup failed");
    assert!(
        report.acl_restored,
        "resource ACL restore failed: {report:?}; stderr={}",
        String::from_utf8_lossy(&report.stderr)
    );
    assert!(!report.disk_limit_hard_enforced);
}
#[test]
fn actual_workspace_stdin_env_and_output() {
    let fixture = Fixture::new("ok");
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.termination, TerminationReason::Exited);
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(
        fs::read_to_string(fixture.request.workspace.join("inside.txt")).unwrap(),
        "owned workspace"
    );
    assert_eq!(
        String::from_utf8(report.stdout).unwrap(),
        "ok:explicit-value\n"
    );
    assert_eq!(String::from_utf8(report.stderr).unwrap(), "stderr-ok\n");
}
#[test]
fn parallel_short_lived_successes_are_not_misclassified_as_orphans() {
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    for _ in 0..6 {
                        let fixture = Fixture::new("ok");
                        let report = fixture.run();
                        clean(&report);
                        assert_eq!(report.termination, TerminationReason::Exited, "{report:?}");
                        assert_eq!(report.exit_code, 0, "{report:?}");
                        assert!(
                            !report.descendant_cleanup_required,
                            "exited root alone is not a descendant: {report:?}"
                        );
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
}
#[test]
fn private_outside_file_denies_read_and_write() {
    let mut fixture = Fixture::new("outside");
    let sentinel = fixture.root.path().join("private-sentinel.txt");
    fs::write(&sentinel, "unchanged private data").unwrap();
    fixture
        .request
        .arguments
        .push(sentinel.to_string_lossy().into());
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(
        String::from_utf8(report.stdout).unwrap(),
        "read_denied=true\nwrite_denied=true\n"
    );
    assert_eq!(
        fs::read_to_string(sentinel).unwrap(),
        "unchanged private data"
    );
}
#[test]
fn real_loopback_connection_is_blocked_by_os() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_connection =
        TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_millis(700))
            .unwrap();
    let accepted = listener.accept().unwrap();
    drop(accepted);
    drop(host_connection);
    listener.set_nonblocking(true).unwrap();
    let mut fixture = Fixture::new("network");
    fixture
        .request
        .arguments
        .push(listener.local_addr().unwrap().to_string());
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    let out = String::from_utf8(report.stdout).unwrap();
    assert!(
        out.contains("PermissionDenied:10013") || out.contains("TimedOut:0"),
        "AppContainer WFP loopback may drop rather than reject: {out}"
    );
    assert!(
        listener.accept().is_err(),
        "host control worked, sandbox must not reach listener"
    );
}
#[test]
fn foreign_host_process_cannot_be_opened_for_memory_or_thread_access() {
    let mut fixture = Fixture::new("foreign");
    fixture
        .request
        .arguments
        .push(std::process::id().to_string());
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(
        String::from_utf8(report.stdout).unwrap(),
        "foreign_denied=true\n"
    );
}
#[test]
fn output_is_bounded_across_both_streams_and_process_is_killed() {
    let mut fixture = Fixture::new("flood");
    fixture.request.limits.max_output_bytes = 8192;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::OutputLimit,
        "{report:?}"
    );
    assert_eq!(report.stdout.len() + report.stderr.len(), 8192);
    assert!(report.output_truncated);
}
#[test]
fn timeout_kills_actual_child_and_grandchild() {
    let mut fixture = Fixture::new("tree");
    fixture.request.limits.wall_time_ms = 700;
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.termination, TerminationReason::Timeout, "{report:?}");
    assert_all_processes_gone(&report, 3);
}
#[test]
fn cancellation_kills_actual_child_and_grandchild() {
    let fixture = Fixture::new("tree");
    let cancel = AtomicBool::new(false);
    let report = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(700));
            cancel.store(true, Ordering::Release);
        });
        Executor::run(&fixture.request, &cancel).unwrap()
    });
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::Cancelled,
        "{report:?}"
    );
    assert_all_processes_gone(&report, 3);
}
#[test]
fn parent_exit_also_kills_descendants() {
    let fixture = Fixture::new("orphan");
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.termination, TerminationReason::Exited);
    assert!(report.descendant_cleanup_required);
    assert_all_processes_gone(&report, 1);
}
#[test]
fn precancel_does_not_create_profile_or_run_program() {
    let fixture = Fixture::new("ok");
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(true)),
        Err(ExecutorError::CancelledBeforeLaunch)
    ));
    assert!(!fixture.request.workspace.join("inside.txt").exists());
}
#[test]
fn finite_output_burst_cannot_be_reported_as_successful_exit() {
    let mut fixture = Fixture::new("burst");
    fixture.request.limits.max_output_bytes = 8192;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::OutputLimit,
        "{report:?}"
    );
    assert!(report.output_truncated);
    assert_eq!(report.stdout.len() + report.stderr.len(), 8192);
}
#[test]
fn process_count_limit_rejects_real_child_creation() {
    let mut fixture = Fixture::new("tree");
    fixture.request.limits.max_processes = 1;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::ProcessLimit,
        "{report:?}"
    );
}
#[test]
fn current_directory_is_exact_and_scoped() {
    let mut fixture = Fixture::new("ok");
    let nested = fixture.request.workspace.join("nested");
    fs::create_dir(&nested).unwrap();
    fixture.request.current_directory = nested.clone();
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert!(nested.join("inside.txt").exists());
    assert!(!fixture.request.workspace.join("inside.txt").exists());
    fixture.request.current_directory = fixture.root.path().to_path_buf();
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Security(_))
    ));
}
#[test]
fn staged_files_can_be_renamed_deleted_replaced_and_hardlinked_during_monitoring() {
    let mut fixture = Fixture::new("staging-ops");
    fixture.request.limits.wall_time_ms = 10000;
    for name in ["original.txt", "delete.txt", "replace.txt"] {
        fs::write(fixture.request.workspace.join(name), name).unwrap();
    }
    for name in ["original-dir", "delete-dir"] {
        fs::create_dir(fixture.request.workspace.join(name)).unwrap();
        fs::write(
            fixture.request.workspace.join(name).join("existing.txt"),
            "existing",
        )
        .unwrap();
    }
    let before = security_descriptor(&fixture.request.workspace.join("original.txt"));
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.termination, TerminationReason::Exited, "{report:?}");
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(String::from_utf8_lossy(&report.stdout), "staging-ops-ok\n");
    assert_eq!(
        fs::read_to_string(fixture.request.workspace.join("replace.txt")).unwrap(),
        "replacement"
    );
    assert!(!fixture.request.workspace.join("delete.txt").exists());
    assert!(!fixture.request.workspace.join("delete-dir").exists());
    let renamed = security_descriptor(&fixture.request.workspace.join("renamed.txt"));
    assert_eq!(
        renamed.trim_end_matches("S:NO_ACCESS_CONTROL"),
        before.trim_end_matches("S:NO_ACCESS_CONTROL")
    );
    assert!(
        !security_descriptor(&fixture.request.workspace.join("alias.txt")).contains("S-1-15-2-")
    );
    // A later invocation must accept only the proven owned aliases left by
    // the first invocation, rather than rejecting all hard links wholesale.
    fixture.request.arguments = vec!["ok".into()];
    let second = fixture.run();
    clean(&second);
    assert_eq!(second.exit_code, 0, "{second:?}");
}
#[test]
fn os_hard_cpu_rate_is_verified_and_reduces_actual_cpu_usage() {
    let mut baseline = Fixture::new("cpu");
    baseline.request.limits.cpu_time_ms = 10000;
    baseline.request.limits.wall_time_ms = 1000;
    let unrestricted = baseline.run();
    clean(&unrestricted);
    assert_eq!(
        unrestricted.termination,
        TerminationReason::Timeout,
        "{unrestricted:?}"
    );
    assert!(
        unrestricted.total_cpu_time_ms > 100,
        "host must provide a meaningful CPU control sample: {unrestricted:?}"
    );
    let mut limited = Fixture::new("cpu");
    limited.request.limits.cpu_time_ms = 10000;
    limited.request.limits.wall_time_ms = 1000;
    limited.request.limits.cpu_rate_basis_points = 1;
    let capped = limited.run();
    clean(&capped);
    assert_eq!(capped.termination, TerminationReason::Timeout, "{capped:?}");
    assert!(capped.cpu_rate_hard_enforced);
    assert_eq!(capped.cpu_rate_basis_points, 1);
    assert!(
        capped.total_cpu_time_ms < unrestricted.total_cpu_time_ms / 2 + 32,
        "OS-quantized capped CPU must be below uncapped control: {capped:?}, baseline={unrestricted:?}"
    );
}
#[test]
fn hard_linked_executable_is_rejected_before_launch() {
    let fixture = Fixture::new("ok");
    fs::hard_link(
        &fixture.request.executable,
        fixture.root.path().join("binary-link.exe"),
    )
    .unwrap();
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Security(_))
    ));
    assert!(!fixture.request.workspace.join("inside.txt").exists());
}
#[test]
fn win32k_foreground_window_probe_is_blocked() {
    let fixture = Fixture::new("ui-attempt");
    let report = fixture.run();
    clean(&report);
    assert!(
        String::from_utf8_lossy(&report.stdout).contains("before-ui-attempt"),
        "{report:?}"
    );
    assert_ne!(report.exit_code, 7, "sandbox read host foreground window");
    assert!(
        report.exit_code != 0
            || String::from_utf8_lossy(&report.stdout).contains("ui-library-blocked=true")
            || String::from_utf8_lossy(&report.stdout).contains("foreign_window=0"),
        "{report:?}"
    );
}
#[test]
fn original_acls_are_restored_and_generated_sid_grants_removed() {
    let fixture = Fixture::new("ok");
    let existing = fixture.request.workspace.join("existing.txt");
    fs::write(&existing, "before").unwrap();
    let paths = [
        &fixture.request.executable,
        &fixture.request.workspace,
        &existing,
    ];
    let before: Vec<_> = paths.iter().map(|path| security_descriptor(path)).collect();
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    for (path, before) in paths.iter().zip(before) {
        assert_eq!(
            security_descriptor(path).trim_end_matches("S:NO_ACCESS_CONTROL"),
            before.trim_end_matches("S:NO_ACCESS_CONTROL"),
            "original ACL/label changed: {}",
            path.display()
        );
    }
    let generated = security_descriptor(&fixture.request.workspace.join("inside.txt"));
    assert!(
        !generated.contains("S-1-15-2-"),
        "orphan job package SID on generated file: {generated}"
    );
}
#[test]
fn effective_environment_is_exact_and_privately_derived() {
    let mut fixture = Fixture::new("environment");
    let report = fixture.run();
    clean(&report);
    assert_eq!(report.exit_code, 0, "{report:?}");
    assert_eq!(report.environment_contract, ENVIRONMENT_CONTRACT);
    let actual: BTreeMap<String, String> = String::from_utf8(report.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').unwrap();
            (key.into(), value.into())
        })
        .collect();
    assert_eq!(actual, report.effective_environment);
    assert!(
        actual["LOCALAPPDATA"]
            .to_lowercase()
            .contains("melissa.code03.")
    );
    assert!(
        !std::path::Path::new(&actual["LOCALAPPDATA"]).exists(),
        "private profile not deleted"
    );
    assert_eq!(
        std::path::Path::new(&actual["TEMP"]),
        std::path::Path::new(&actual["LOCALAPPDATA"]).join("Temp")
    );
    fixture
        .request
        .environment
        .insert("tmp".into(), "caller override".into());
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::InvalidRequest(_))
    ));
}
fn security_descriptor(path: &std::path::Path) -> String {
    use std::{os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
        },
    };
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sd = null_mut();
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
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
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) });
    unsafe {
        LocalFree(sd);
        LocalFree(value.cast());
    }
    text
}
#[test]
fn finite_cpu_work_cannot_succeed_after_exhausting_its_aggregate_budget() {
    let baseline = Fixture::new("cpu-finite");
    let completed = baseline.run();
    clean(&completed);
    assert_eq!(completed.termination, TerminationReason::Exited);
    assert_eq!(completed.exit_code, 0);
    assert_eq!(completed.stdout, b"finite-cpu-complete\n");
    assert!(completed.total_cpu_time_ms >= 100);

    let mut limited = Fixture::new("cpu-finite");
    limited.request.limits.cpu_time_ms = 50;
    let stopped = limited.run();
    clean(&stopped);
    assert_eq!(
        stopped.termination,
        TerminationReason::CpuLimit,
        "{stopped:?}"
    );
    assert!(stopped.total_cpu_time_ms >= limited.request.limits.cpu_time_ms);
}

#[test]
fn cpu_job_is_measured_and_terminated() {
    let mut fixture = Fixture::new("cpu");
    fixture.request.limits.cpu_time_ms = 150;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::CpuLimit,
        "{report:?}"
    );
    assert!(report.total_cpu_time_ms >= 100);
    assert!(report.user_cpu_limit_hard_enforced);
    assert!(report.total_cpu_limit_sampled);
}
#[test]
fn committed_memory_job_limit_is_enforced() {
    let mut fixture = Fixture::new("memory");
    fixture.request.limits.memory_bytes = 48 * 1024 * 1024;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::MemoryLimit,
        "{report:?}"
    );
    let stdout = String::from_utf8_lossy(&report.stdout);
    let successful = stdout
        .lines()
        .filter_map(|line| {
            line.strip_prefix("allocated=")
                .and_then(|s| s.parse::<u64>().ok())
        })
        .max()
        .unwrap();
    assert!(
        successful < fixture.request.limits.memory_bytes,
        "successful committed allocations exceeded limit: {report:?}"
    );
    assert!(successful >= 16 * 1024 * 1024);
    assert!(report.peak_job_committed_memory_bytes >= successful);
}
#[test]
fn disk_monitor_reports_overshoot_without_hard_quota_claim() {
    let mut fixture = Fixture::new("disk");
    fixture.request.limits.max_workspace_bytes = 2 * 1024 * 1024;
    let report = fixture.run();
    clean(&report);
    assert_eq!(
        report.termination,
        TerminationReason::DiskLimit,
        "{report:?}"
    );
    assert!(report.disk_overshoot_bytes > 0);
    assert!(
        report.peak_observed_workspace_and_profile_bytes
            > fixture.request.limits.max_workspace_bytes
    );
}
#[test]
fn unsupported_modes_fail_before_any_launch_or_fs_access() {
    let mut fixture = Fixture::new("ok");
    fixture.request.workspace = PathBuf::from("C:\\missing-executor-workspace");
    fixture.request.disk_mode = DiskLimitMode::Strict;
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Unsupported(_))
    ));
    fixture.request.disk_mode = DiskLimitMode::Monitored;
    fixture.request.network = NetworkMode::Allowlist;
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Unsupported(_))
    ));
    fixture.request.network = NetworkMode::Offline;
    fixture.request.limits.gpu_required = true;
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Unsupported(_))
    ));
}
#[test]
fn exact_executable_digest_is_rechecked() {
    let mut fixture = Fixture::new("ok");
    fixture.request.executable_blake3 = format!("blake3:{}", "0".repeat(64));
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::Security(_))
    ));
    assert!(!fixture.request.workspace.join("inside.txt").exists());
}
#[test]
fn ambiguous_environment_and_zero_limits_rejected() {
    let mut fixture = Fixture::new("ok");
    fixture
        .request
        .environment
        .insert("melissa_visible".into(), "ambiguous".into());
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::InvalidRequest(_))
    ));
    fixture.request.environment.clear();
    fixture.request.limits.wall_time_ms = 0;
    assert!(matches!(
        Executor::run(&fixture.request, &AtomicBool::new(false)),
        Err(ExecutorError::InvalidRequest(_))
    ));
}
fn assert_all_processes_gone(report: &ExecutorReport, minimum: usize) {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    let text = String::from_utf8_lossy(&report.stdout);
    let pids: Vec<u32> = text
        .lines()
        .filter_map(|line| line.strip_prefix("pid=").and_then(|id| id.parse().ok()))
        .collect();
    assert!(
        pids.len() >= minimum,
        "expected real descendants: {text}; {report:?}"
    );
    for pid in pids {
        let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if !h.is_null() {
            assert_eq!(
                unsafe { WaitForSingleObject(h, 0) },
                WAIT_OBJECT_0,
                "descendant {pid} survives"
            );
            unsafe {
                CloseHandle(h);
            }
        } else {
            assert_eq!(
                unsafe { GetLastError() },
                ERROR_INVALID_PARAMETER,
                "could not prove descendant {pid} is gone"
            );
        }
    }
}
