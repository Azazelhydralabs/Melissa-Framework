#![cfg(windows)]
//! Negative native compatibility evidence. Real Rust compile/test acceptance
//! belongs to the separately verified Linux container backend on this host.
use melissa_windows_executor::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
};

fn host_output(command: &mut Command) -> String {
    let output = command
        .output()
        .expect("required host development tool is unavailable");
    assert!(
        output.status.success(),
        "host discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
fn copy_files(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let metadata = entry.metadata().unwrap();
        if metadata.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
}
fn run(executable: &Path, workspace: &Path, arguments: Vec<String>) -> ExecutorReport {
    let request = ExecuteRequest {
        executable: executable.to_path_buf(),
        executable_blake3: format!(
            "blake3:{}",
            blake3::hash(&fs::read(executable).unwrap()).to_hex()
        ),
        workspace: workspace.to_path_buf(),
        current_directory: workspace.to_path_buf(),
        arguments,
        environment: BTreeMap::new(),
        limits: ExecutionLimits {
            wall_time_ms: 60000,
            cpu_time_ms: 45000,
            cpu_rate_basis_points: 10000,
            memory_bytes: 1024 * 1024 * 1024,
            max_processes: 16,
            max_output_bytes: 1024 * 1024,
            max_workspace_bytes: 2 * 1024 * 1024 * 1024,
            gpu_required: false,
        },
        network: NetworkMode::Offline,
        disk_mode: DiskLimitMode::Monitored,
    };
    let report = Executor::run(&request, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        report.termination,
        TerminationReason::Exited,
        "{report:?}; stderr={}",
        String::from_utf8_lossy(&report.stderr)
    );
    assert!(
        report.tree_confirmed_stopped
            && report.process_was_appcontainer
            && report.win32k_system_calls_disabled
            && report.acl_restored
            && report.profile_removed
            && !report.descendant_cleanup_required,
        "{report:?}"
    );
    report
}
#[test]
fn native_rustc_gui_runtime_dependency_is_rejected_without_weaker_fallback() {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let sysroot = PathBuf::from(host_output(
        Command::new("rustc").args(["--print", "sysroot"]),
    ));
    let target = "x86_64-pc-windows-msvc";
    let runtime = workspace.join("toolchain");
    let bin = runtime.join("bin");
    fs::create_dir_all(&bin).unwrap();
    for entry in fs::read_dir(sysroot.join("bin")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "rustc.exe" || entry.path().extension().is_some_and(|x| x == "dll")
        {
            fs::copy(entry.path(), bin.join(entry.file_name())).unwrap();
        }
    }
    copy_files(
        &sysroot.join("lib").join("rustlib").join(target).join("lib"),
        &runtime.join("lib").join("rustlib").join(target).join("lib"),
    );
    let vswhere =
        Path::new("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe");
    let linkers = host_output(Command::new(vswhere).args([
        "-latest",
        "-products",
        "*",
        "-find",
        "VC\\Tools\\MSVC\\**\\bin\\Hostx64\\x64\\link.exe",
    ]));
    let linker = PathBuf::from(
        linkers
            .lines()
            .next()
            .expect("MSVC linker must be installed"),
    );
    let msvc = linker.ancestors().nth(4).unwrap().join("lib").join("x64");
    let sdk_root = Path::new("C:\\Program Files (x86)\\Windows Kits\\10\\Lib");
    let mut sdk_versions: Vec<_> = fs::read_dir(sdk_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("um\\x64\\kernel32.lib").is_file())
        .collect();
    sdk_versions.sort();
    let sdk = sdk_versions
        .last()
        .expect("Windows SDK libraries must be installed");
    let source = workspace.join("sample.rs");
    fs::write(
        &source,
        "fn add(a:u32,b:u32)->u32{a+b}\n#[test]fn arithmetic(){assert_eq!(add(2,3),5);}\n",
    )
    .unwrap();
    let compiler = bin.join("rustc.exe");
    // Trusted compiler metadata control only: no user program is compiled or
    // executed outside containment. The identical staged compiler works here.
    let host_version = host_output(Command::new(&compiler).arg("--version"));
    let driver = fs::read_dir(&bin)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rustc_driver")
                && path.extension().is_some_and(|extension| extension == "dll")
        })
        .unwrap();
    let dumpbin = linker.parent().unwrap().join("dumpbin.exe");
    let imports = host_output(Command::new(dumpbin).arg("/dependents").arg(&driver));
    assert!(
        imports.to_lowercase().contains("shell32.dll"),
        "compiler GUI runtime dependency changed; refresh compatibility acceptance"
    );
    let output = workspace.join("sample-tests.exe");
    let args = vec![
        "--test".into(),
        source.to_string_lossy().into(),
        "--edition=2024".into(),
        "--sysroot".into(),
        runtime.to_string_lossy().into(),
        "-C".into(),
        format!("linker={}", linker.display()),
        "-C".into(),
        format!("link-arg=/LIBPATH:{}", msvc.display()),
        "-C".into(),
        format!("link-arg=/LIBPATH:{}", sdk.join("um\\x64").display()),
        "-C".into(),
        format!("link-arg=/LIBPATH:{}", sdk.join("ucrt\\x64").display()),
        "-o".into(),
        output.to_string_lossy().into(),
    ];
    let report = run(&compiler, &workspace, args);
    assert_eq!(
        report.exit_code, 0xC0000142,
        "native Rustc compatibility changed; verify real compilation and update backend contract rather than weakening isolation: {report:?}"
    );
    assert!(!output.exists());
    if let Some(path) = std::env::var_os("MELISSA_NATIVE_COMPAT_REPORT") {
        let evidence = serde_json::json!({"schema_version":"melissa.native-rustc-compatibility/v1","outcome":"unsupported_by_mandatory_win32k_disabled_native_backend","real_compile_test_acceptance":false,"fallback_used":false,"host_version_control":host_version,"driver_imports":imports,"expected_native_exit_hex":"0xC0000142","compiler_blake3":format!("blake3:{}",blake3::hash(&fs::read(compiler).unwrap()).to_hex()),"driver_blake3":format!("blake3:{}",blake3::hash(&fs::read(driver).unwrap()).to_hex()),"native_report":report});
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}
