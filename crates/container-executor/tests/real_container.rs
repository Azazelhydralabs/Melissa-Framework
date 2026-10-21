#![cfg(windows)]
use melissa_container_executor::*;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const IMAGE: &str = "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4";
fn make_request(script: &str) -> ContainerRequest {
    ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: IMAGE.into(),
        executable: "/bin/sh".into(),
        argv: vec!["-c".into(), script.into()],
        cwd: ".".into(),
        env: BTreeMap::new(),
        limits: ContainerLimits {
            wall_time_ms: 15000,
            cpu_time_ms: 10000,
            cpu_rate_basis_points: 10000,
            memory_bytes: 256 * 1024 * 1024,
            disk_bytes: 16 * 1024 * 1024,
            output_bytes: 65536,
            max_processes: 128,
            export_bytes: 32 * 1024 * 1024,
        },
    }
}
#[test]
fn real_readonly_root_tmpfs_input_output_and_cleanup() {
    let snapshot = Snapshot {
        files: BTreeMap::from([("input.txt".into(), b"actual injected bytes".to_vec())]),
    };
    let mut request = make_request(
        "test \"$MELISSA_WORKLOAD_ENV\" = 'actual workload value' || exit 93; cat input.txt; printf result > result.txt; printf stderr >&2",
    );
    request.env.insert(
        "MELISSA_WORKLOAD_ENV".into(),
        "actual workload value".into(),
    );
    let report = Executor::run(&request, &snapshot, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        report.termination,
        TerminationReason::Exited,
        "monitor={:?}, exit={:?}, stdout={:?}, stderr={:?}",
        report.monitor_error,
        report.exit_code,
        String::from_utf8_lossy(&report.stdout),
        String::from_utf8_lossy(&report.stderr)
    );
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.stdout, b"actual injected bytes");
    assert_eq!(report.stderr, b"stderr");
    assert_eq!(
        report
            .effective_environment
            .get("MELISSA_WORKLOAD_ENV")
            .map(String::as_str),
        Some("actual workload value")
    );
    assert!(
        report.cleanup_confirmed
            && report.tree_confirmed_stopped
            && report.policy_verified
            && report.disk_limit_hard_enforced
            && report.cpu_rate_hard_enforced
            && report.cpu_measurement_complete
    );
    assert!(!report.export_truncated);
    assert!(report.archive.windows(6).any(|b| b == b"result"));
    assert_eq!(report.input_digest, snapshot.digest().unwrap());
}

#[test]
fn actual_rust_compiler_and_two_tests_run_inside_the_limited_worker() {
    let source=b"#[test]fn arithmetic(){assert_eq!(2+3,5);} #[test]fn bytes(){assert_eq!(b\"ok\".len(),2);}".to_vec();
    let snapshot = Snapshot {
        files: BTreeMap::from([("tests.rs".into(), source)]),
    };
    let mut request = make_request(
        "/usr/local/cargo/bin/rustc --test tests.rs -o tests-bin && ./tests-bin --test-threads=1",
    );
    request.limits.wall_time_ms = 30000;
    request.limits.cpu_time_ms = 20000;
    request.limits.memory_bytes = 512 * 1024 * 1024;
    request.limits.disk_bytes = 128 * 1024 * 1024;
    let report = Executor::run(&request, &snapshot, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        report.termination,
        TerminationReason::Exited,
        "{:?}; {}",
        report.monitor_error,
        String::from_utf8_lossy(&report.stderr)
    );
    assert_eq!(report.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&report.stdout).contains("2 passed"));
    assert!(report.archive.windows(9).any(|b| b == b"tests-bin"));
    assert!(report.cleanup_confirmed && !report.export_truncated);
}

#[test]
fn strict_allocated_capacity_counts_open_deleted_and_colon_named_data() {
    for target in ["deleted", "colon:stream"] {
        let script = if target == "deleted" {
            "exec 3>deleted; rm deleted; dd if=/dev/zero bs=4096 count=1536 status=none >&3; dd if=/dev/zero of=second bs=4096 count=1536 status=none; code=$?; printf 'write_status=%s\\n' \"$code\"; test \"$code\" -ne 0"
        } else {
            "dd if=/dev/zero of='colon:stream' bs=4096 count=1536 status=none; dd if=/dev/zero of=second bs=4096 count=1536 status=none; code=$?; printf 'write_status=%s\\n' \"$code\"; test \"$code\" -ne 0"
        };
        let mut request = make_request(script);
        request.limits.disk_bytes = 8 * 1024 * 1024;
        let report =
            Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
        assert_eq!(
            report.exit_code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&report.stderr)
        );
        assert!(String::from_utf8_lossy(&report.stderr).contains("No space left on device"));
        assert!(report.disk_limit_hard_enforced && report.cleanup_confirmed);
    }
}

#[test]
fn readonly_outside_network_and_daemon_are_unreachable() {
    let script = "test ! -e /var/run/docker.sock && test ! -e /dev/shm; ! touch /tmp/escape; ! touch /dev/escape; ! touch /etc/escape; ! /bin/bash -c 'echo probe >/dev/tcp/1.1.1.1/80'; test $(id -u) = 65534; echo boundaries-ok";
    let report = Executor::run(
        &make_request(script),
        &Snapshot::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(report.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&report.stdout).contains("boundaries-ok"));
    assert!(report.cleanup_confirmed && report.policy_verified);
}

#[test]
fn actual_memory_overflow_is_kernel_rejected_and_accounted() {
    let mut request = make_request(
        "perl -e '$x=\"a\"x(400*1024*1024); sleep 10'; code=$?; cat /sys/fs/cgroup/memory.events; exit \"$code\"",
    );
    request.limits.memory_bytes = 128 * 1024 * 1024;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_ne!(report.exit_code, Some(0));
    assert!(
        String::from_utf8_lossy(&report.stdout).contains("oom_kill 1"),
        "{} {}",
        String::from_utf8_lossy(&report.stdout),
        String::from_utf8_lossy(&report.stderr)
    );
    assert!(report.cleanup_confirmed);
}

#[test]
fn kernel_pid_limit_is_enforced_and_worker_cannot_reset_the_keeper_deadline() {
    let mut request = make_request(
        "if kill -USR1 1 2>/dev/null; then exit 99; fi; perl -e 'my @kids; for(1..32) { my $p=fork(); if(!defined $p) { print \"fork-denied\\n\"; last; } if($p==0) { sleep 30; exit; } push @kids,$p; } kill 9,@kids; while(wait()>0) {}'; cat /sys/fs/cgroup/pids.events",
    );
    request.limits.max_processes = 8;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::Exited);
    assert_eq!(report.exit_code, Some(0));
    let output = String::from_utf8_lossy(&report.stdout);
    assert!(output.contains("fork-denied"), "{output}");
    assert!(
        output.lines().any(|line| line
            .strip_prefix("max ")
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0)),
        "{output}"
    );
    assert!(report.cleanup_confirmed && report.guest_deadline_guard);
}

#[test]
fn unsupported_pid_minima_are_rejected_before_engine_use_without_raising_the_quota() {
    let mut request = make_request("printf minimum-four-pids");
    for unsupported in [0, 4, 7] {
        request.limits.max_processes = unsupported;
        assert!(matches!(
            request.validate(),
            Err(ExecutorError::Unsupported(_))
        ));
        assert!(matches!(
            Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)),
            Err(ExecutorError::Unsupported(_))
        ));
        assert_eq!(request.limits.max_processes, unsupported);
    }
}

#[test]
fn protected_pid_one_reaps_real_orphaned_grandchildren_within_the_same_quota() {
    let mut request = make_request("unused");
    request.executable = "/usr/bin/perl".into();
    request.argv = vec!["-e".into(), "for(1..64){my $p=fork(); die \"parent fork denied\" unless defined $p; if($p==0){my $g=fork(); exit 91 unless defined $g; if($g==0){exit 0} exit 0} waitpid($p,0); die \"child fork denied\" if $?; select undef,undef,undef,0.01} print \"orphan-reaping-ok\\n\"".into()];
    request.limits.max_processes = 16;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::Exited, "{report:?}");
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.stdout, b"orphan-reaping-ok\n");
    assert!(report.cleanup_confirmed && !report.export_truncated);
}

#[test]
fn a_full_pid_cgroup_uses_exact_owned_force_cleanup_without_export_or_success() {
    let mut request = make_request("unused");
    request.executable = "/usr/bin/perl".into();
    request.argv = vec!["-e".into(), "$|=1; my @kids; for(1..128){my $p=fork();last unless defined $p;if($p==0){sleep 30;exit 0}push @kids,$p} print \"pid-cgroup-full\\n\"; sleep 30".into()];
    request.limits.max_processes = 8;
    let identity = Mutex::new(None::<String>);
    let cancel = AtomicBool::new(false);
    let observed = AtomicBool::new(false);
    let report = std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if let Some(id) = identity.lock().unwrap().clone() {
                    let top = docker(&["top", &id, "-eo", "pid,uid,args"]);
                    if top.status.success()
                        && String::from_utf8_lossy(&top.stdout)
                            .lines()
                            .filter(|line| line.split_whitespace().nth(1) == Some("65534"))
                            .count()
                            >= 7
                    {
                        observed.store(true, Ordering::Release);
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            cancel.store(true, Ordering::Release);
        });
        Executor::run_with_observer(&request, &Snapshot::default(), &cancel, &mut |id| {
            *identity.lock().unwrap() = Some(id.into());
            Ok(())
        })
        .unwrap()
    });
    assert!(
        observed.load(Ordering::Acquire),
        "seven real workload PIDs plus keeper must fill the unchanged eight-PID quota"
    );
    assert!(matches!(
        report.termination,
        TerminationReason::Cancelled | TerminationReason::MonitorFailure
    ));
    assert!(report.cleanup_confirmed && report.tree_confirmed_stopped);
    if report.termination == TerminationReason::MonitorFailure {
        assert!(
            report
                .monitor_error
                .as_deref()
                .is_some_and(|error| error.contains("namespace stop helper unavailable"))
        );
        assert!(report.archive.is_empty() && report.export_truncated);
        assert!(!report.cpu_measurement_complete);
    }
    assert!(!docker(&["inspect", &report.container_id]).status.success());
}

#[test]
fn total_cpu_is_measured_and_stopped_under_an_actual_hard_rate() {
    let mut request = make_request("while :; do :; done");
    request.limits.cpu_time_ms = 200;
    request.limits.cpu_rate_basis_points = 5000;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::CpuLimit);
    assert!(
        report.total_cpu_time_ms >= 200
            && report.cpu_rate_hard_enforced
            && report.total_cpu_limit_sampled
            && report.cpu_measurement_complete
            && report.cleanup_confirmed
    );
    assert!(report.archive.len() <= 64 * 1024 * 1024);
}

#[test]
fn finite_zero_exit_command_cannot_succeed_above_the_final_observed_cpu_budget() {
    let mut request = make_request("unused");
    request.executable = "/usr/bin/printf".into();
    request.argv = vec!["finite-zero-exit".into()];
    request.limits.cpu_time_ms = 1;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.stdout, b"finite-zero-exit");
    assert_eq!(report.termination, TerminationReason::CpuLimit);
    assert!(report.total_cpu_time_ms >= 1 && report.cpu_measurement_complete);
    assert!(report.cleanup_confirmed);
}

#[test]
fn output_export_and_symlink_fifo_archives_are_bounded_without_host_extraction() {
    let mut request = make_request("yes x");
    request.limits.output_bytes = 4096;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::OutputLimit);
    assert_eq!(report.stdout.len() + report.stderr.len(), 4096);
    assert!(report.output_truncated && report.cleanup_confirmed);
    let mut request =
        make_request("ln -s /dev/zero evil-link; mkfifo evil-fifo; printf content > output");
    request.limits.export_bytes = 65536;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.exit_code, Some(0));
    assert!(
        !report.export_truncated
            && report.archive.windows(9).any(|v| v == b"evil-link")
            && report.cleanup_confirmed
    );
    let mut request = make_request("dd if=/dev/zero of=export-data bs=4096 count=100 status=none");
    request.limits.export_bytes = 2048;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::ExportLimit);
    assert!(report.export_truncated && report.archive.len() <= 2048 && report.cleanup_confirmed);
}

fn docker(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe");
    command
        .args(["--host", "npipe:////./pipe/dockerDesktopLinuxEngine"])
        .args(args)
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.output().unwrap()
}

#[test]
fn cancellation_waits_for_actual_workload_and_removes_the_whole_container() {
    let cancel = AtomicBool::new(false);
    let observed = AtomicBool::new(false);
    let witness = Mutex::new(String::new());
    let identity = Arc::new(Mutex::new(None::<String>));
    let request = make_request("sleep 30 & sleep 30 & wait");
    let report = std::thread::scope(|scope| {
        let shared = identity.clone();
        scope.spawn(|| {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(15) {
                if let Some(id) = identity.lock().unwrap().clone() {
                    let output = docker(&["top", &id, "-eo", "pid,uid,args"]);
                    let text = String::from_utf8_lossy(&output.stdout);
                    *witness.lock().unwrap() = format!(
                        "stdout={} stderr={}",
                        text,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if text.lines().any(|l| {
                        l.split_whitespace().nth(1) == Some("65534") && l.contains("sleep 30")
                    }) {
                        observed.store(true, Ordering::Release);
                        cancel.store(true, Ordering::Release);
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            cancel.store(true, Ordering::Release);
        });
        Executor::run_with_observer(&request, &Snapshot::default(), &cancel, &mut |id| {
            *shared.lock().unwrap() = Some(id.into());
            Ok(())
        })
        .unwrap()
    });
    assert!(
        observed.load(Ordering::Acquire),
        "{}",
        witness.lock().unwrap()
    );
    assert_eq!(report.termination, TerminationReason::Cancelled);
    assert!(report.tree_confirmed_stopped && report.cleanup_confirmed);
    assert!(!docker(&["inspect", &report.container_id]).status.success());
}

#[test]
fn cancelling_one_uid_does_not_signal_another_jobs_pid_namespace() {
    let cancel = AtomicBool::new(false);
    let victim_id = Mutex::new(None::<String>);
    let survivor_id = Mutex::new(None::<String>);
    let (victim, survivor, both_observed, survivor_still_running) = std::thread::scope(|scope| {
        let victim = scope.spawn(|| {
            Executor::run_with_observer(
                &make_request("sleep 30 & sleep 30 & wait"),
                &Snapshot::default(),
                &cancel,
                &mut |id| {
                    *victim_id.lock().unwrap() = Some(id.into());
                    Ok(())
                },
            )
        });
        let survivor = scope.spawn(|| {
            Executor::run_with_observer(
                &make_request("sleep 8; printf survivor-remained-alive"),
                &Snapshot::default(),
                &AtomicBool::new(false),
                &mut |id| {
                    *survivor_id.lock().unwrap() = Some(id.into());
                    Ok(())
                },
            )
        });
        let start = Instant::now();
        let mut both_observed = false;
        while start.elapsed() < Duration::from_secs(15) {
            let ids = [
                victim_id.lock().unwrap().clone(),
                survivor_id.lock().unwrap().clone(),
            ];
            if ids.iter().all(|id| {
                id.as_ref().is_some_and(|id| {
                    let output = docker(&["top", id, "-eo", "pid,uid,args"]);
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).lines().any(|line| {
                            line.split_whitespace().nth(1) == Some("65534")
                                && line.contains("sleep ")
                        })
                })
            }) {
                both_observed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        cancel.store(true, Ordering::Release);
        let victim = victim.join().unwrap().unwrap();
        let running = survivor_id.lock().unwrap().as_ref().is_some_and(|id| {
            let output = docker(&["inspect", "--format", "{{.State.Running}}", id]);
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
        });
        (
            victim,
            survivor.join().unwrap().unwrap(),
            both_observed,
            running,
        )
    });
    assert!(
        both_observed,
        "both separate real UID65534 workloads must start"
    );
    assert_eq!(victim.termination, TerminationReason::Cancelled);
    assert!(victim.cleanup_confirmed && survivor_still_running);
    assert_eq!(survivor.termination, TerminationReason::Exited);
    assert_eq!(survivor.exit_code, Some(0));
    assert_eq!(survivor.stdout, b"survivor-remained-alive");
    assert!(survivor.cleanup_confirmed);
    assert_ne!(victim.container_id, survivor.container_id);
}

#[test]
fn timeout_and_orphaned_descendants_never_succeed() {
    let mut request = make_request("sleep 30");
    request.limits.wall_time_ms = 800;
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::Timeout);
    assert!(report.cleanup_confirmed);
    let request = make_request("sleep 30 >/dev/null 2>&1 & exit 0");
    let report = Executor::run(&request, &Snapshot::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.termination, TerminationReason::OrphanDescendants);
    assert!(!report.orphan_process_ids.is_empty());
    assert!(report.cleanup_confirmed);
}

#[test]
fn guest_deadline_survives_abrupt_controller_death() {
    const VAR: &str = "MELISSA_CONTAINER_CRASH_WITNESS";
    if let Some(path) = std::env::var_os(VAR) {
        let mut request = make_request("sleep 30");
        request.limits.wall_time_ms = 2000;
        // This would kill the protected Perl keeper immediately if caller
        // interpreter options leaked into create or trusted helper execution.
        request
            .env
            .insert("PERL5OPT".into(), "-MMelissaForbiddenKeeperModule".into());
        let _ = Executor::run_with_observer(
            &request,
            &Snapshot::default(),
            &AtomicBool::new(false),
            &mut |id| {
                std::fs::write(&path, id)?;
                Ok(())
            },
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("container-id.txt");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "guest_deadline_survives_abrupt_controller_death",
            "--nocapture",
        ])
        .env(VAR, &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    let mut id = None;
    while start.elapsed() < Duration::from_secs(15) {
        if let Ok(value) = std::fs::read_to_string(&path) {
            let output = docker(&["top", &value, "-eo", "pid,uid,args"]);
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|l| l.split_whitespace().nth(1) == Some("65534") && l.contains("sleep 30"))
            {
                id = Some(value);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let id = id.expect("real workload never started");
    child.kill().unwrap();
    child.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(7);
    let mut stopped = false;
    while Instant::now() < deadline {
        let out = docker(&["inspect", "--format", "{{.State.Running}}", &id]);
        if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "false" {
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    // Only this exact observed test-created container is removed.
    let removed = docker(&["rm", "--force", &id]);
    assert!(removed.status.success());
    assert!(
        stopped,
        "guest deadline did not stop namespace after host death"
    );
}

#[test]
fn unsafe_inputs_and_unsupported_sub_minimum_rate_fail_before_any_engine_use() {
    let mut request = make_request("true");
    request.limits.cpu_rate_basis_points = 1;
    assert!(matches!(
        request.validate(),
        Err(ExecutorError::Unsupported(_))
    ));
    for path in ["../escape", "/absolute", "a/../b", "a\\b", "a:stream"] {
        let snapshot = Snapshot {
            files: BTreeMap::from([(path.into(), vec![1])]),
        };
        assert!(snapshot.digest().is_err());
    }
    let snapshot = Snapshot {
        files: BTreeMap::from([("a".into(), vec![1]), ("a/b".into(), vec![2])]),
    };
    assert!(snapshot.validate(100).is_err());
    let first = Snapshot {
        files: BTreeMap::from([("b".into(), vec![2]), ("a".into(), vec![1])]),
    };
    let second = Snapshot {
        files: BTreeMap::from([("a".into(), vec![1]), ("b".into(), vec![2])]),
    };
    assert_eq!(first.digest().unwrap(), second.digest().unwrap());
}
