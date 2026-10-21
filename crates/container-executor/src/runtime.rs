use crate::*;
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

const ENGINE: &str = "npipe:////./pipe/dockerDesktopLinuxEngine";
include!("runtime_recovery.rs");
const CONTROL_LIMIT: usize = 1024 * 1024;
// A single, non-root PID1 both reaps adopted children and owns the independent
// deadline. A shell plus a bootstrap sleep needlessly occupied two PID slots
// and could starve OCI exec initialization at small, correctly enforced quotas.
const KEEPER: &str = "use POSIX qw(WNOHANG); $SIG{USR1}=sub{alarm $ARGV[0]}; $SIG{ALRM}=sub{exit 0}; $SIG{CHLD}=sub{while(waitpid(-1,WNOHANG)>0){}}; alarm 180; while(1){sleep 180}";
const ATTEST: &str = "while IFS= read -r line; do case \"$line\" in Uid:*|CapEff:*|NoNewPrivs:*|Seccomp:*) printf '%s\\n' \"$line\";; esac; done < /proc/self/status; for file in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max; do IFS= read -r value < \"$file\"; printf '%s\\n' \"$value\"; done; while IFS= read -r line; do case \"$line\" in 'Max file size '*) printf '%s\\n' \"$line\";; esac; done < /proc/self/limits; exec /usr/bin/stat -f -c '%S %b' /work";
fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|v| v.to_string()).collect()
}
fn fail(s: &str) -> ExecutorError {
    ExecutorError::Control(s.into())
}
#[derive(Default)]
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    failed: bool,
}
struct Capture {
    child: Child,
    out: Arc<Mutex<Output>>,
    readers: Vec<thread::JoinHandle<()>>,
    writer: Option<thread::JoinHandle<()>>,
    _held_input: Option<std::process::ChildStdin>,
    writer_stop: Option<Arc<AtomicBool>>,
}
impl Capture {
    fn spawn(command: Command, input: Option<Vec<u8>>, limit: usize) -> ExecutorResult<Self> {
        Self::spawn_with_input(command, input, limit, false)
    }
    fn spawn_with_input(
        command: Command,
        input: Option<Vec<u8>>,
        limit: usize,
        hold_input: bool,
    ) -> ExecutorResult<Self> {
        Self::spawn_protocol(command, input, limit, hold_input, None)
    }
    fn spawn_protocol(
        mut command: Command,
        input: Option<Vec<u8>>,
        limit: usize,
        hold_input: bool,
        conversation: Option<Conversation>,
    ) -> ExecutorResult<Self> {
        command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let out = Arc::new(Mutex::new(Output::default()));
        let mut readers = Vec::new();
        let response_pipe = conversation.as_ref().map(|c| c.output.clone());
        for (mut stream, is_stderr) in [
            (
                Box::new(child.stdout.take().expect("piped stdout")) as Box<dyn Read + Send>,
                false,
            ),
            (
                Box::new(child.stderr.take().expect("piped stderr")) as Box<dyn Read + Send>,
                true,
            ),
        ] {
            let shared = out.clone();
            let response_pipe = if is_stderr {
                None
            } else {
                response_pipe.clone()
            };
            readers.push(thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut frame = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            if response_pipe.is_some()
                                && !frame.is_empty()
                                && let Ok(mut o) = shared.lock()
                            {
                                o.failed = true;
                            }
                            break;
                        }
                        Ok(n) => {
                            let Ok(mut o) = shared.lock() else { return };
                            let available = limit.saturating_sub(o.stdout.len() + o.stderr.len());
                            let take = n.min(available);
                            if is_stderr {
                                o.stderr.extend_from_slice(&buf[..take]);
                            } else {
                                o.stdout.extend_from_slice(&buf[..take]);
                            }
                            o.truncated |= take < n;
                            drop(o);
                            if let Some(pipe) = &response_pipe {
                                for byte in &buf[..n] {
                                    frame.push(*byte);
                                    if frame.len() > 64 * 1024 {
                                        if let Ok(mut o) = shared.lock() {
                                            o.failed = true;
                                        }
                                        return;
                                    }
                                    if *byte == b'\n'
                                        && pipe.try_send(std::mem::take(&mut frame)).is_err()
                                    {
                                        if let Ok(mut o) = shared.lock() {
                                            o.failed = true;
                                        }
                                        return;
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            if let Ok(mut o) = shared.lock() {
                                o.failed = true;
                            }
                            break;
                        }
                    }
                }
            }));
        }
        let mut held_input = None;
        let mut writer_stop = None;
        let writer = if let Some(conversation) = conversation {
            let mut stdin = child.stdin.take().expect("piped conversation input");
            let stop = Arc::new(AtomicBool::new(false));
            writer_stop = Some(stop.clone());
            let shared = out.clone();
            Some(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match conversation.input.recv_timeout(Duration::from_millis(20)) {
                        Ok(bytes) => {
                            if bytes.len() > 64 * 1024
                                || !bytes.ends_with(b"\n")
                                || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n')
                                || std::str::from_utf8(&bytes).is_err()
                                || stdin.write_all(&bytes).and_then(|_| stdin.flush()).is_err()
                            {
                                if let Ok(mut o) = shared.lock() {
                                    o.failed = true;
                                }
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (),
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }))
        } else if hold_input {
            if let Some(bytes) = input {
                let mut stdin = child.stdin.take().expect("piped input");
                stdin.write_all(&bytes)?;
                stdin.flush()?;
                held_input = Some(stdin);
            }
            None
        } else {
            input.map(|bytes| {
                let mut stdin = child.stdin.take().expect("piped input");
                thread::spawn(move || {
                    let _ = stdin.write_all(&bytes);
                })
            })
        };
        Ok(Self {
            child,
            out,
            readers,
            writer,
            _held_input: held_input,
            writer_stop,
        })
    }
    fn truncated(&self) -> bool {
        self.out.lock().map_or(true, |v| v.truncated || v.failed)
    }
    fn finish(mut self, kill: bool) -> ExecutorResult<(Option<i32>, Output)> {
        if let Some(stop) = &self.writer_stop {
            stop.store(true, Ordering::Release);
        }
        if kill {
            let _ = self.child.kill();
        }
        let status = self.child.wait()?;
        if let Some(writer) = self.writer.take() {
            writer
                .join()
                .map_err(|_| fail("control input thread failed"))?;
        }
        for reader in self.readers.drain(..) {
            reader
                .join()
                .map_err(|_| fail("control output thread failed"))?;
        }
        let mut out = self
            .out
            .lock()
            .map_err(|_| fail("control output lock failed"))?;
        Ok((status.code(), std::mem::take(&mut *out)))
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(stop) = &self.writer_stop {
            stop.store(true, Ordering::Release);
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Docker {
    _config: tempfile::TempDir,
    _pin: File,
    _ancestors: Vec<File>,
    client_identity: String,
    executable: PathBuf,
}
#[cfg(windows)]
fn pin_client(executable: &std::path::Path) -> ExecutorResult<(File, Vec<File>, String)> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::*;
    let mut ancestors = Vec::new();
    // Pin from the drive root downwards. No path component can be renamed or
    // replaced while subsequent checks and CreateProcess use this fixed path.
    for path in executable
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(fail(
                "Docker client path has a reparse or non-directory ancestor",
            ));
        }
        ancestors.push(file);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(executable)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
        || file.metadata()?.len() > 128 * 1024 * 1024
    {
        return Err(fail(
            "Docker client must be a bounded, unlinked regular installation file",
        ));
    }
    let mut resolved = [0u16; 32768];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
            0,
        )
    };
    if len == 0 || len as usize >= resolved.len() {
        return Err(fail("Docker client final handle path unavailable"));
    }
    let actual = String::from_utf16(&resolved[..len as usize])
        .map_err(|_| fail("Docker client path encoding"))?;
    let expected = format!(r"\\?\{}", executable.display());
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(fail(
            "Docker client final handle path differs from trusted installation path",
        ));
    }
    let mut hash = blake3::Hasher::new();
    let mut bytes = [0u8; 65536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    let identity = format!(
        "windows-file:{:08x}:{:08x}{:08x}:blake3:{}",
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
        hash.finalize().to_hex()
    );
    Ok((file, ancestors, identity))
}
impl Docker {
    fn new() -> ExecutorResult<Self> {
        if !cfg!(windows) {
            return Err(ExecutorError::Unsupported(
                "this backend currently pins the Windows Docker Desktop Linux engine".into(),
            ));
        }
        let executable = PathBuf::from(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe");
        #[cfg(windows)]
        let (pin, ancestors, client_identity) = pin_client(&executable)?;
        #[cfg(not(windows))]
        let (pin, ancestors, client_identity) = (
            OpenOptions::new().read(true).open(&executable)?,
            Vec::new(),
            String::new(),
        );
        Ok(Self {
            _config: tempfile::tempdir()?,
            _pin: pin,
            _ancestors: ancestors,
            client_identity,
            executable,
        })
    }
    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.executable);
        command.env_clear();
        // The executable and endpoint are host-selected, never model fields.
        if let Some(value) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", value);
        }
        command
            .arg("--config")
            .arg(self._config.path())
            .arg("--host")
            .arg(ENGINE)
            .args(args);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command
    }
    fn capture(
        &self,
        args: &[String],
        input: Option<Vec<u8>>,
        limit: usize,
        timeout: Duration,
    ) -> ExecutorResult<(Option<i32>, Output)> {
        let mut process = Capture::spawn(self.command(args), input, limit)?;
        let begin = Instant::now();
        loop {
            if process.child.try_wait()?.is_some() {
                return process.finish(false);
            }
            if begin.elapsed() > timeout || process.truncated() {
                return process.finish(true);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn checked(
        &self,
        args: &[String],
        input: Option<Vec<u8>>,
        limit: usize,
    ) -> ExecutorResult<Vec<u8>> {
        let (status, out) = self.capture(args, input, limit, Duration::from_secs(30))?;
        if status != Some(0) || out.truncated || out.failed {
            return Err(ExecutorError::Control(format!(
                "bounded Docker {} command failed (exit={status:?}, truncated={}, reader_failed={}, stdout={:?}, stderr={:?})",
                args.first().map_or("unknown", String::as_str),
                out.truncated,
                out.failed,
                String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(2048)]),
                String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2048)])
            )));
        }
        Ok(out.stdout)
    }
    fn inspect(&self, id: &str) -> ExecutorResult<Value> {
        let bytes = self.checked(&strings(&["inspect", id]), None, CONTROL_LIMIT)?;
        let values: Vec<Value> = serde_json::from_slice(&bytes)?;
        values
            .into_iter()
            .next()
            .ok_or_else(|| fail("missing inspected object"))
    }
    fn get(&self, path: &str) -> ExecutorResult<(u16, Value)> {
        let request = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
            .into_bytes();
        let mut process = Capture::spawn_with_input(
            self.command(&strings(&["system", "dial-stdio"])),
            Some(request),
            CONTROL_LIMIT,
            true,
        )?;
        let begin = Instant::now();
        let (status, out) = loop {
            if process.child.try_wait()?.is_some() {
                break process.finish(false)?;
            }
            if begin.elapsed() > Duration::from_secs(5) || process.truncated() {
                break process.finish(true)?;
            }
            thread::sleep(Duration::from_millis(5));
        };
        if status != Some(0) || out.truncated || out.failed {
            return Err(fail("bounded Docker engine transport failed"));
        }
        let (status, body) = http_body(&out.stdout)?;
        Ok((
            status,
            if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body)?
            },
        ))
    }
    fn exec(
        &self,
        stage: &str,
        id: &str,
        program: &[String],
        input: Option<Vec<u8>>,
        limit: usize,
    ) -> ExecutorResult<Vec<u8>> {
        let mut args = strings(&["exec", "--user", "65534:65534"]);
        if input.is_some() {
            args.push("--interactive".into());
        }
        args.push(id.into());
        args.extend_from_slice(program);
        self.checked(&args, input, limit)
            .map_err(|error| ExecutorError::Control(format!("sandbox {stage}: {error}")))
    }
}

fn http_body(bytes: &[u8]) -> ExecutorResult<(u16, Vec<u8>)> {
    let split = bytes
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or_else(|| fail("missing engine HTTP header"))?;
    if split > 32768 {
        return Err(fail("engine HTTP header limit"));
    }
    let head =
        std::str::from_utf8(&bytes[..split]).map_err(|_| fail("invalid engine HTTP header"))?;
    let status = head
        .lines()
        .next()
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| fail("invalid engine HTTP status"))?;
    let raw = &bytes[split + 4..];
    if head.lines().any(|line| {
        line.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    }) {
        let mut body = Vec::new();
        let mut remaining = raw;
        loop {
            let end = remaining
                .windows(2)
                .position(|v| v == b"\r\n")
                .ok_or_else(|| fail("invalid HTTP chunk"))?;
            let hex = std::str::from_utf8(&remaining[..end])
                .map_err(|_| fail("invalid HTTP chunk length"))?
                .split(';')
                .next()
                .unwrap_or("");
            let count =
                usize::from_str_radix(hex, 16).map_err(|_| fail("invalid HTTP chunk length"))?;
            remaining = &remaining[end + 2..];
            if count == 0 {
                break;
            }
            if count > remaining.len().saturating_sub(2) || &remaining[count..count + 2] != b"\r\n"
            {
                return Err(fail("truncated HTTP chunk"));
            }
            body.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count + 2..];
        }
        Ok((status, body))
    } else {
        Ok((status, raw.to_vec()))
    }
}

struct Container<'a> {
    docker: &'a Docker,
    id: String,
    name: String,
    nonce: String,
    image: String,
    cleaned: bool,
}
impl Container<'_> {
    fn cleanup(&mut self) -> bool {
        if self.cleaned {
            return true;
        }
        let lookup = if self.id.is_empty() {
            &self.name
        } else {
            &self.id
        };
        match self.docker.get(&format!("/containers/{lookup}/json")) {
            Ok((404, _)) => {
                self.cleaned = true;
                return true;
            }
            Ok((200, value)) => {
                if value
                    .pointer("/Config/Labels/melissa.code03.nonce")
                    .and_then(Value::as_str)
                    != Some(&self.nonce)
                    || value.get("Image").and_then(Value::as_str) != Some(&self.image)
                {
                    return false;
                }
            }
            _ => return false,
        }
        if self
            .docker
            .checked(&strings(&["rm", "--force", lookup]), None, CONTROL_LIMIT)
            .is_err()
        {
            return false;
        }
        self.cleaned = matches!(
            self.docker.get(&format!("/containers/{lookup}/json")),
            Ok((404, _))
        );
        self.cleaned
    }
}
impl Drop for Container<'_> {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn runtime_policy(value: &Value, request: &ContainerRequest, nonce: &str) -> ExecutorResult {
    let h = &value["HostConfig"];
    let l = &request.limits;
    let empty = |v: &Value| {
        v.is_null()
            || v.as_array().is_some_and(Vec::is_empty)
            || v.as_object().is_some_and(serde_json::Map::is_empty)
    };
    let yes = h["ReadonlyRootfs"] == true
        && h["Privileged"] == false
        && h["NetworkMode"] == "none"
        && h["IpcMode"] == "none"
        && h["LogConfig"]["Type"] == "none"
        && h["Memory"].as_u64() == Some(l.memory_bytes)
        && h["MemorySwap"].as_u64() == Some(l.memory_bytes)
        && h["PidsLimit"].as_u64() == Some(u64::from(l.max_processes))
        && h["CpuPeriod"].as_u64() == Some(1_000_000)
        && h["CpuQuota"].as_u64() == Some(u64::from(l.cpu_rate_basis_points) * 100)
        && h["Ulimits"].as_array().is_some_and(|v| {
            v.iter().any(|limit| {
                limit["Name"] == "fsize"
                    && limit["Soft"].as_u64() == Some(l.disk_bytes)
                    && limit["Hard"].as_u64() == Some(l.disk_bytes)
            })
        })
        && empty(&h["Binds"])
        && empty(&h["Devices"])
        && empty(&h["CapAdd"])
        && h["PidMode"] != "host"
        && value["Config"]["User"] == "65533:65533"
        && value["Config"]["Labels"]["melissa.code03.nonce"] == nonce
        && value["Image"] == request.image_id
        && h["CapDrop"].as_array().is_some_and(|v| {
            v.iter()
                .any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case("all")))
        })
        && h["SecurityOpt"].as_array().is_some_and(|v| {
            v.iter().any(|s| {
                s.as_str()
                    .is_some_and(|s| s.starts_with("no-new-privileges"))
            })
        })
        && h["Tmpfs"]
            .as_object()
            .is_some_and(|v| v.len() == 1 && v.contains_key("/work"))
        && value["Mounts"].as_array().is_some_and(|v| {
            v.iter()
                .all(|m| m["Type"] == "tmpfs" && m["Destination"] == "/work")
        });
    if !yes {
        return Err(fail(
            "actual container host configuration violates the immutable isolation policy",
        ));
    }
    Ok(())
}

fn stats(docker: &Docker, id: &str) -> ExecutorResult<(u64, u64)> {
    let (status, value) = docker.get(&format!(
        "/containers/{id}/stats?stream=false&one-shot=true"
    ))?;
    if status != 200 {
        return Err(fail("container stats unavailable"));
    }
    let cpu = value
        .pointer("/cpu_stats/cpu_usage/total_usage")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("aggregate CPU accounting missing"))?
        / 1_000_000;
    let memory = value
        .pointer("/memory_stats/usage")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("memory accounting missing"))?;
    Ok((cpu, memory))
}
fn environment(request: &ContainerRequest) -> BTreeMap<String, String> {
    let mut env = request.env.clone();
    env.extend(controlled_environment());
    env
}
fn controlled_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (key, value) in [
        ("HOME", "/work/.melissa-runtime/home"),
        ("TMPDIR", "/work/.melissa-runtime/tmp"),
        ("TMP", "/work/.melissa-runtime/tmp"),
        ("TEMP", "/work/.melissa-runtime/tmp"),
        ("USER", "65534"),
        ("LOGNAME", "65534"),
        ("CARGO_HOME", "/work/.melissa-runtime/cargo"),
        ("CARGO_TARGET_DIR", "/work/target"),
    ] {
        env.insert(key.into(), value.into());
    }
    env
}
fn workload_environment_flags(args: &mut Vec<String>, request: &ContainerRequest) {
    for (key, value) in &request.env {
        args.extend(strings(&["--env", &format!("{key}={value}")]));
    }
}

fn active_pids(docker: &Docker, id: &str, keeper: u64) -> ExecutorResult<Vec<u64>> {
    let top = docker.checked(
        &strings(&["top", id, "-eo", "pid,stat"]),
        None,
        CONTROL_LIMIT,
    )?;
    let text = String::from_utf8(top).map_err(|_| fail("invalid process listing"))?;
    let mut active = Vec::new();
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let pid = fields
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| fail("invalid process identity"))?;
        let state = fields.next().ok_or_else(|| fail("missing process state"))?;
        // Zombies have already exited and cannot write or execute. Namespace
        // removal reaps them; they are not evidence of a surviving worker.
        if pid != keeper && !state.starts_with('Z') {
            active.push(pid);
        }
    }
    Ok(active)
}

pub(crate) fn run(
    request: &ContainerRequest,
    snapshot: &Snapshot,
    cancelled: &AtomicBool,
    observer: &mut dyn FnMut(&str) -> ExecutorResult,
) -> ExecutorResult<ContainerReport> {
    run_interactive(request, snapshot, cancelled, observer, None)
}
pub(crate) fn run_interactive(
    request: &ContainerRequest,
    snapshot: &Snapshot,
    cancelled: &AtomicBool,
    observer: &mut dyn FnMut(&str) -> ExecutorResult,
    conversation: Option<Conversation>,
) -> ExecutorResult<ContainerReport> {
    if request.limits.cpu_rate_basis_points < 10 {
        return Err(ExecutorError::Unsupported(
            "CFS minimum quota cannot enforce less than 10 basis points with a one-second period"
                .into(),
        ));
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(ExecutorError::CancelledBeforeLaunch);
    }
    let docker = Docker::new()?;
    let (status, info) = docker.get("/info")?;
    if status != 200
        || info["OSType"] != "linux"
        || !info["SecurityOptions"].as_array().is_some_and(|v| {
            v.iter()
                .any(|v| v.as_str().is_some_and(|s| s.contains("seccomp")))
        })
    {
        return Err(ExecutorError::Unsupported(
            "local Linux engine with seccomp required".into(),
        ));
    }
    let bytes = docker.checked(
        &strings(&["image", "inspect", &request.image_id]),
        None,
        CONTROL_LIMIT,
    )?;
    let images: Vec<Value> = serde_json::from_slice(&bytes)?;
    let image = images
        .first()
        .ok_or_else(|| fail("image unavailable; pulling is forbidden"))?;
    if image["Id"] != request.image_id
        || !(image["Config"]["Volumes"].is_null()
            || image["Config"]["Volumes"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty))
    {
        return Err(fail(
            "image identity or writable volume declaration rejected",
        ));
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| fail("host entropy unavailable"))?;
    let nonce = random
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let name = format!("melissa-code03-{nonce}");
    let mut container = Container {
        docker: &docker,
        id: String::new(),
        name: name.clone(),
        nonce: nonce.clone(),
        image: request.image_id.clone(),
        cleaned: false,
    };
    let l = &request.limits;
    let tmpfs = format!(
        "/work:rw,exec,nosuid,nodev,size={},nr_inodes=8192,uid=65534,gid=65534,mode=0700",
        l.disk_bytes
    );
    let mut args = strings(&[
        "create",
        "--pull",
        "never",
        "--name",
        &name,
        "--label",
        &format!("melissa.code03.nonce={nonce}"),
        "--label",
        &format!("melissa.code03.contract={EXECUTION_CONTRACT}"),
        "--read-only",
        "--network",
        "none",
        "--ipc",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        "65533:65533",
        "--log-driver",
        "none",
        "--no-healthcheck",
        "--stop-timeout",
        "0",
        "--ulimit",
        &format!("fsize={0}:{0}", l.disk_bytes),
        "--memory",
        &l.memory_bytes.to_string(),
        "--memory-swap",
        &l.memory_bytes.to_string(),
        "--pids-limit",
        &l.max_processes.to_string(),
        "--cpu-period",
        "1000000",
        "--cpu-quota",
        &(u64::from(l.cpu_rate_basis_points) * 100).to_string(),
        "--tmpfs",
        &tmpfs,
        "--entrypoint",
        "/usr/bin/perl",
    ]);
    // The protected keeper and all trusted preparation/export helpers receive
    // only host-fixed values plus immutable image defaults. Interpreter/loader
    // options from the caller belong exclusively to the UID65534 workload.
    for (key, value) in controlled_environment() {
        args.extend(strings(&["--env", &format!("{key}={value}")]));
    }
    let guest_deadline_seconds = l.wall_time_ms.div_ceil(1000) + 1;
    args.extend(strings(&[
        &request.image_id,
        "-e",
        KEEPER,
        "--",
        &guest_deadline_seconds.to_string(),
    ]));
    let id = String::from_utf8(docker.checked(&args, None, CONTROL_LIMIT)?)
        .map_err(|_| fail("non-UTF8 container identity"))?;
    let id = id.trim();
    if id.len() != 64 || !id.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(fail("invalid created container identity"));
    }
    container.id = id.into();
    runtime_policy(&docker.inspect(id)?, request, &nonce)?;
    observer(id)?;
    docker.checked(&strings(&["start", id]), None, CONTROL_LIMIT)?;
    runtime_policy(&docker.inspect(id)?, request, &nonce)?;
    // No host source mount: only a deterministic regular-file archive enters
    // tmpfs, with all names and bytes validated before the engine sees them.
    docker.exec(
        "snapshot injection",
        id,
        &strings(&[
            "/bin/tar",
            "--extract",
            "--file",
            "-",
            "--directory",
            "/work",
            "--no-same-owner",
            "--no-same-permissions",
        ]),
        Some(archive::pack(snapshot)?),
        CONTROL_LIMIT,
    )?;
    docker.exec(
        "private directory preparation",
        id,
        &strings(&[
            "/bin/mkdir",
            "-p",
            "/work/.melissa-runtime/home",
            "/work/.melissa-runtime/tmp",
            "/work/.melissa-runtime/cargo",
        ]),
        None,
        CONTROL_LIMIT,
    )?;
    let actual = docker.exec(
        "kernel limit attestation",
        id,
        &strings(&["/bin/sh", "-c", ATTEST]),
        None,
        CONTROL_LIMIT,
    )?;
    let text = String::from_utf8(actual).map_err(|_| fail("invalid cgroup attestation"))?;
    let lines = text.lines().collect::<Vec<_>>();
    let exact_status = |line: &str, name: &str, expected: &str| {
        let mut fields = line.split_whitespace();
        fields.next() == Some(name) && fields.next() == Some(expected) && fields.next().is_none()
    };
    if lines.len() != 10
        || lines[0].split_whitespace().collect::<Vec<_>>()
            != ["Uid:", "65534", "65534", "65534", "65534"]
        || !exact_status(lines[1], "CapEff:", "0000000000000000")
        || !exact_status(lines[2], "NoNewPrivs:", "1")
        || !exact_status(lines[3], "Seccomp:", "2")
        || lines[4] != l.memory_bytes.to_string()
        || lines[5] != "0"
        || lines[6] != l.max_processes.to_string()
        || lines[7] != format!("{} 1000000", u64::from(l.cpu_rate_basis_points) * 100)
        || lines[8].split_whitespace().collect::<Vec<_>>()
            != [
                "Max",
                "file",
                "size",
                &l.disk_bytes.to_string(),
                &l.disk_bytes.to_string(),
                "bytes",
            ]
    {
        return Err(fail(
            "actual worker UID/capabilities/no-new-privileges/cgroup limits failed attestation",
        ));
    }
    let capacity = lines[9]
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| fail("tmpfs capacity attestation"))?;
    if capacity.len() != 2
        || capacity[0]
            .checked_mul(capacity[1])
            .is_none_or(|v| v == 0 || v > l.disk_bytes)
    {
        return Err(fail("tmpfs exceeds requested capacity"));
    }
    // Probe trusted defaults only: caller loader variables can execute code
    // even in /usr/bin/env, before the last workload cancellation guard.
    let environment_bytes = docker.exec(
        "fixed environment attestation",
        id,
        &strings(&["/usr/bin/env", "-0"]),
        None,
        CONTROL_LIMIT,
    )?;
    let mut effective_environment = BTreeMap::new();
    for part in environment_bytes
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
    {
        let text = std::str::from_utf8(part).map_err(|_| fail("environment encoding"))?;
        let (key, value) = text
            .split_once('=')
            .ok_or_else(|| fail("environment entry"))?;
        effective_environment.insert(key.into(), value.into());
    }
    effective_environment.extend(request.env.clone());
    for (key, value) in environment(request) {
        if effective_environment.get(&key) != Some(&value) {
            return Err(fail("effective worker environment mapping mismatch"));
        }
    }
    if cancelled.load(Ordering::Acquire) {
        if !container.cleanup() {
            return Err(fail("prelaunch cancellation cleanup is unconfirmed"));
        }
        return Err(ExecutorError::CancelledBeforeLaunch);
    }
    docker.checked(
        &strings(&["kill", "--signal", "USR1", id]),
        None,
        CONTROL_LIMIT,
    )?;
    let mut args = strings(&["exec", "--user", "65534:65534"]);
    if conversation.is_some() {
        args.push("--interactive".into());
    }
    workload_environment_flags(&mut args, request);
    args.extend(strings(&[
        id,
        "/bin/sh",
        "-c",
        "cd \"$1\" && shift && exec \"$@\"",
        "melissa-entry",
        &if request.cwd == "." {
            "/work".into()
        } else {
            format!("/work/{}", request.cwd)
        },
    ]));
    args.push(request.executable.clone());
    args.extend(request.argv.clone());
    // The keeper signal is a blocking host-control operation. Recheck after
    // it so permit expiry/cancellation during that call cannot launch work.
    if cancelled.load(Ordering::Acquire) {
        if !container.cleanup() {
            return Err(fail("prelaunch cancellation cleanup is unconfirmed"));
        }
        return Err(ExecutorError::CancelledBeforeLaunch);
    }
    let mut worker = if conversation.is_some() {
        Capture::spawn_protocol(
            docker.command(&args),
            Some(vec![]),
            l.output_bytes as usize,
            true,
            conversation,
        )?
    } else {
        Capture::spawn(docker.command(&args), None, l.output_bytes as usize)?
    };
    let begin = Instant::now();
    let mut reason = None;
    let mut cpu = 0;
    let mut memory = 0;
    let mut monitor_error = None;
    let mut sample = Instant::now() - Duration::from_secs(1);
    loop {
        if worker.child.try_wait()?.is_some() {
            break;
        }
        if cancelled.load(Ordering::Acquire) {
            reason = Some(TerminationReason::Cancelled);
            break;
        }
        if worker.truncated() {
            reason = Some(TerminationReason::OutputLimit);
            break;
        }
        if begin.elapsed().as_millis() >= l.wall_time_ms as u128 {
            reason = Some(TerminationReason::Timeout);
            break;
        }
        if sample.elapsed() >= Duration::from_millis(100) {
            sample = Instant::now();
            match stats(&docker, id) {
                Ok((c, m)) => {
                    cpu = c;
                    memory = m;
                    if cpu >= l.cpu_time_ms {
                        reason = Some(TerminationReason::CpuLimit);
                        break;
                    }
                }
                Err(error) => {
                    monitor_error = Some(error.to_string());
                    reason = Some(TerminationReason::MonitorFailure);
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    // No namespace freeze: that would also freeze the independent PID1
    // deadline and could leave a paused container after a host crash. A trusted
    // same-UID helper kills every workload peer, never the distinct keeper.
    // Linux kill(-1) excludes the calling process; no CAP_KILL is granted.
    let inspect = docker.inspect(id)?;
    let keeper = inspect
        .pointer("/State/Pid")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("keeper PID missing"))?;
    let mut namespace_stopped = inspect["State"]["Running"] == false;
    let mut orphan_process_ids = Vec::new();
    if !namespace_stopped {
        match active_pids(&docker, id, keeper) {
            Ok(pids) => orphan_process_ids = pids,
            Err(error) => {
                namespace_stopped = docker.inspect(id)?["State"]["Running"] == false;
                if !namespace_stopped {
                    return Err(error);
                }
            }
        }
    }
    if namespace_stopped && reason.is_none() {
        reason = Some(
            if begin.elapsed().as_millis() >= u128::from(l.wall_time_ms) {
                TerminationReason::Timeout
            } else {
                TerminationReason::MonitorFailure
            },
        );
        monitor_error = Some("protected namespace stopped before final accounting/export".into());
    }
    if reason.is_none() && !orphan_process_ids.is_empty() {
        reason = Some(TerminationReason::OrphanDescendants);
    }
    let stop_error = if namespace_stopped {
        None
    } else {
        docker
            .exec(
                "workload namespace stop",
                id,
                &strings(&["/bin/sh", "-c", "kill -KILL -1 2>/dev/null || :"]),
                None,
                CONTROL_LIMIT,
            )
            .err()
    };
    let mut stop_failed = false;
    if let Some(error) = stop_error {
        // A full, correctly enforced PID cgroup may have no slot for OCI exec.
        // Never enlarge it or retry the helper. The owned engine-level remove
        // below kills the namespace without entering it; no export is safe.
        namespace_stopped = docker.inspect(id)?["State"]["Running"] == false;
        if namespace_stopped && begin.elapsed().as_millis() >= u128::from(l.wall_time_ms) {
            if reason.is_none() {
                reason = Some(TerminationReason::Timeout);
            }
        } else {
            stop_failed = true;
            monitor_error = Some(format!(
                "namespace stop helper unavailable; exact owned force cleanup without export: {error}"
            ));
            reason = Some(TerminationReason::MonitorFailure);
        }
    }
    let (exit_code, out) = worker.finish(reason.is_some())?;
    let mut measurement_complete = false;
    if !namespace_stopped {
        match stats(&docker, id) {
            Ok((c, m)) => {
                cpu = c;
                memory = m;
                measurement_complete = !stop_failed;
            }
            Err(error) => {
                namespace_stopped = docker.inspect(id)?["State"]["Running"] == false;
                if namespace_stopped && begin.elapsed().as_millis() >= u128::from(l.wall_time_ms) {
                    if reason.is_none() {
                        reason = Some(TerminationReason::Timeout);
                    }
                } else {
                    monitor_error = Some(error.to_string());
                    reason = Some(TerminationReason::MonitorFailure);
                }
            }
        }
    }
    if !stop_failed && !namespace_stopped {
        match active_pids(&docker, id, keeper) {
            Ok(pids) if !pids.is_empty() => {
                return Err(fail("workload peers remained after namespace cancellation"));
            }
            Ok(_) => {}
            Err(error) => {
                namespace_stopped = docker.inspect(id)?["State"]["Running"] == false;
                if !namespace_stopped {
                    return Err(error);
                }
            }
        }
    }
    if namespace_stopped {
        measurement_complete = false;
    }
    // A finite burst can exit between samples. A final observed over-budget
    // total/deadline must never become Exited merely because try_wait won.
    if reason.is_none() && measurement_complete && cpu >= l.cpu_time_ms {
        reason = Some(TerminationReason::CpuLimit);
    }
    if reason.is_none() && begin.elapsed().as_millis() >= u128::from(l.wall_time_ms) {
        reason = Some(TerminationReason::Timeout);
    }
    if out.failed {
        reason = Some(TerminationReason::MonitorFailure);
    } else if out.truncated && reason.is_none() {
        reason = Some(TerminationReason::OutputLimit);
    }
    // The only remaining process is the protected keeper. A bounded
    // unprivileged tar now sees tmpfs without any workload writer present.
    let (export_status, export) = if stop_failed || namespace_stopped {
        (None, Output::default())
    } else {
        docker.capture(
            &strings(&[
                "exec",
                "--user",
                "65534:65534",
                id,
                "/bin/tar",
                "--create",
                "--file",
                "-",
                "--directory",
                "/work",
                ".",
            ]),
            None,
            l.export_bytes as usize,
            Duration::from_secs(30),
        )?
    };
    let export_truncated = stop_failed
        || namespace_stopped
        || export.truncated
        || export.failed
        || export_status != Some(0);
    if export_truncated && reason.is_none() {
        reason = Some(TerminationReason::ExportLimit);
    }
    let cleanup_confirmed = container.cleanup();
    Ok(ContainerReport {
        execution_contract: EXECUTION_CONTRACT.into(),
        docker_client_identity: docker.client_identity.clone(),
        container_id: id.into(),
        image_id: request.image_id.clone(),
        input_digest: snapshot.digest()?,
        termination: reason.unwrap_or(TerminationReason::Exited),
        exit_code,
        stdout: out.stdout,
        stderr: out.stderr,
        archive: export.stdout,
        export_truncated,
        output_truncated: out.truncated,
        cleanup_confirmed,
        tree_confirmed_stopped: cleanup_confirmed,
        policy_verified: true,
        disk_limit_hard_enforced: true,
        cpu_rate_hard_enforced: true,
        total_cpu_limit_sampled: true,
        total_cpu_time_ms: cpu,
        cpu_measurement_complete: measurement_complete,
        memory_usage_at_snapshot_bytes: memory,
        elapsed_ms: begin.elapsed().as_millis().min(u64::MAX as u128) as u64,
        orphan_process_ids,
        effective_environment,
        monitor_error,
        guest_deadline_guard: true,
        guest_deadline_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_http_chunk_parser() {
        let (status, body) =
            http_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
                .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{}");
        assert!(
            http_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{}\r\n").is_err()
        );
    }
}
