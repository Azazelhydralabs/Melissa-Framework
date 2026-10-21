//! Deliberately small adversarial child fixture; not a product command runner.
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("ok");
    match mode {
        "ok" => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin).unwrap();
            assert!(stdin.is_empty());
            fs::write("inside.txt", "owned workspace").unwrap();
            println!(
                "ok:{}",
                std::env::var("MELISSA_VISIBLE").unwrap_or_default()
            );
            eprintln!("stderr-ok");
            assert!(std::env::var_os("MELISSA_HOST_SECRET").is_none());
            assert!(std::env::var_os("PATH").is_none());
        }
        "environment" => {
            let temp = std::path::PathBuf::from(std::env::var_os("TEMP").unwrap());
            fs::write(temp.join("private-temp-probe.txt"), "private scratch").unwrap();
            for (key, value) in std::env::vars() {
                println!("{key}={value}");
            }
        }
        "staging-ops" => {
            fs::rename("original.txt", "renamed.txt").unwrap();
            fs::remove_file("delete.txt").unwrap();
            fs::write("replacement.tmp", "replacement").unwrap();
            fs::rename("replacement.tmp", "replace.txt").unwrap();
            fs::rename("original-dir", "renamed-dir").unwrap();
            fs::remove_dir_all("delete-dir").unwrap();
            fs::hard_link("renamed.txt", "alias.txt").unwrap();
            for _ in 0..200 {
                fs::write("spin.tmp", "new").unwrap();
                fs::rename("spin.tmp", "spin.current").unwrap();
                fs::remove_file("spin.current").unwrap();
                fs::create_dir("spin-dir").unwrap();
                fs::write("spin-dir/file", "x").unwrap();
                fs::rename("spin-dir", "spin-renamed-dir").unwrap();
                fs::remove_dir_all("spin-renamed-dir").unwrap();
            }
            println!("staging-ops-ok");
        }
        "outside" => {
            let p = &args[2];
            println!("read_denied={}", fs::read(p).is_err());
            println!("write_denied={}", fs::write(p, "escaped").is_err());
        }
        "network" => {
            let address: SocketAddr = args[2].parse().unwrap();
            let error =
                TcpStream::connect_timeout(&address, Duration::from_millis(700)).unwrap_err();
            println!(
                "network_error={:?}:{}",
                error.kind(),
                error.raw_os_error().unwrap_or(0)
            );
        }
        "foreign" => {
            #[cfg(windows)]
            {
                use windows_sys::Win32::{
                    Foundation::CloseHandle,
                    System::Threading::{
                        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_VM_WRITE,
                    },
                };
                let h = unsafe {
                    OpenProcess(
                        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                        0,
                        args[2].parse().unwrap(),
                    )
                };
                println!("foreign_denied={}", h.is_null());
                if !h.is_null() {
                    unsafe {
                        CloseHandle(h);
                    }
                }
            }
        }
        "flood" => {
            let chunk = vec![b'x'; 8192];
            loop {
                let _ = std::io::stdout().write_all(&chunk);
                let _ = std::io::stderr().write_all(&chunk);
            }
        }
        "burst" => {
            std::io::stdout()
                .write_all(&vec![b'x'; 128 * 1024])
                .unwrap();
            std::io::stderr()
                .write_all(&vec![b'e'; 128 * 1024])
                .unwrap();
        }
        "ui-attempt" => {
            #[cfg(windows)]
            {
                use windows_sys::Win32::{
                    Foundation::FreeLibrary,
                    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
                };
                println!("before-ui-attempt");
                std::io::stdout().flush().unwrap();
                let dll: Vec<u16> = "user32.dll\0".encode_utf16().collect();
                let module = unsafe { LoadLibraryW(dll.as_ptr()) };
                if module.is_null() {
                    println!("ui-library-blocked=true");
                    return;
                }
                let function =
                    unsafe { GetProcAddress(module, c"GetForegroundWindow".as_ptr().cast()) };
                if let Some(function) = function {
                    let get_window: unsafe extern "system" fn() -> isize = function;
                    let window = unsafe { get_window() };
                    println!("foreign_window={window}");
                    if window != 0 {
                        std::process::exit(7);
                    }
                }
                unsafe {
                    FreeLibrary(module);
                }
            }
        }
        "sleep" => {
            tree_marker("tree-leaf.pid");
            println!("pid={}", std::process::id());
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
        "tree" => {
            tree_marker("tree-root.pid");
            println!("pid={}", std::process::id());
            std::io::stdout().flush().unwrap();
            let mut child = detached_child("branch");
            let _ = child.wait();
        }
        "branch" => {
            tree_marker("tree-branch.pid");
            println!("pid={}", std::process::id());
            std::io::stdout().flush().unwrap();
            let mut child = detached_child("sleep");
            let _ = child.wait();
        }
        "orphan" => {
            // Deliberately orphan a child to verify that the executor kills
            // descendants when their parent exits; this fixture must not wait.
            #[allow(clippy::zombie_processes)]
            let _child = detached_child("sleep");
            std::thread::sleep(Duration::from_millis(100));
        }
        "cpu" => loop {
            std::hint::black_box((0..1000).sum::<u64>());
        },
        "cpu-finite" => {
            #[cfg(windows)]
            {
                use windows_sys::Win32::{
                    Foundation::FILETIME,
                    System::Threading::{GetCurrentProcess, GetProcessTimes},
                };
                loop {
                    for _ in 0..1000 {
                        std::hint::black_box((0..1000).sum::<u64>());
                    }
                    let mut creation = FILETIME::default();
                    let mut exit = FILETIME::default();
                    let mut kernel = FILETIME::default();
                    let mut user = FILETIME::default();
                    assert_ne!(
                        unsafe {
                            GetProcessTimes(
                                GetCurrentProcess(),
                                &mut creation,
                                &mut exit,
                                &mut kernel,
                                &mut user,
                            )
                        },
                        0
                    );
                    let ticks = |time: FILETIME| {
                        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
                    };
                    if ticks(kernel).saturating_add(ticks(user)) >= 1_500_000 {
                        break;
                    }
                }
                println!("finite-cpu-complete");
            }
        }
        "memory" => {
            #[cfg(windows)]
            {
                use windows_sys::Win32::System::Memory::{
                    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
                };
                let mut allocated = 0u64;
                loop {
                    let memory = unsafe {
                        VirtualAlloc(
                            std::ptr::null(),
                            4 * 1024 * 1024,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE,
                        )
                    };
                    if memory.is_null() {
                        println!("allocation_denied=true");
                        std::io::stdout().flush().unwrap();
                        std::thread::sleep(Duration::from_secs(2));
                        break;
                    }
                    allocated += 4 * 1024 * 1024;
                    println!("allocated={allocated}");
                    std::io::stdout().flush().unwrap();
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        "disk" => {
            let mut file = fs::File::create("disk.bin").unwrap();
            let chunk = vec![1u8; 1024 * 1024];
            loop {
                file.write_all(&chunk).unwrap();
                file.flush().unwrap();
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        _ => panic!("unknown probe"),
    }
}
fn tree_marker(name: &str) {
    if std::env::var("MELISSA_TREE_MARKERS").as_deref() == Ok("1") {
        fs::write(name, std::process::id().to_string()).unwrap();
    }
}
fn detached_child(mode: &str) -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(mode)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Ordinary std::process::Command: no special console/creation flags.
    command.spawn().unwrap()
}
