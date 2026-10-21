"""One persistent DAP conversation inside the existing isolated worker.

No attach-to-host, evaluate, shell, environment, arbitrary adapter or runInTerminal
request is accepted. Native frame/reference IDs expire on every resume.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = Path.cwd().resolve()
PRIVATE = ROOT / ".melissa-code06-debug"
TARGET = ROOT / ".melissa-code06-target"
P = json.loads((PRIVATE / "program.json").read_bytes())
NODE = "/opt/node/bin/node"
PY = "/opt/melissa-python/bin/python"
trace = (PRIVATE / "dap-transcript.ndjson").open("wb")
trace_lock = threading.Lock()
trace_bytes = 0
owned = []


class DebugError(Exception):
    def __init__(self, kind, message):
        self.kind = kind
        super().__init__(message)


def record(direction, data):
    global trace_bytes
    raw = (json.dumps({"direction": direction, "message": data}, ensure_ascii=True) + "\n").encode()
    with trace_lock:
        trace_bytes += len(raw)
        if trace_bytes > P["trace_limit"]:
            raise DebugError("resource_limit", "raw DAP transcript exceeded envelope")
        trace.write(raw)
        trace.flush()


def same_source():
    return all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
               and (ROOT / name).read_bytes().hex() == value for name, value in P["sources"].items())


def process(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE):
    child = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=(PRIVATE / f"adapter-{len(owned)}.stderr").open("wb"), start_new_session=True)
    owned.append(child)
    return child


class Dap:
    def __init__(self, reader, writer, child=None, on_child=None):
        self.reader, self.writer, self.child = reader, writer, child
        self.on_child = on_child
        self.sequence = 0
        self.responses = {}
        self.events = []
        self.messages = queue.Queue(maxsize=512)
        self.failure = None
        self.capabilities = {}
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        try:
            while True:
                line = self.reader.readline(8193)
                if not line:
                    raise DebugError("adapter_crash", "DAP stream closed")
                if len(line) > 8192 or not line.endswith(b"\r\n"):
                    raise DebugError("invalid_protocol", "invalid DAP header")
                match = re.fullmatch(b"Content-Length: ([0-9]+)\r\n", line, re.I)
                if not match or self.reader.read(2) != b"\r\n":
                    raise DebugError("invalid_protocol", "unexpected DAP header")
                length = int(match[1])
                if length <= 0 or length > 4 * 1024 * 1024:
                    raise DebugError("resource_limit", "DAP frame length")
                payload = bytearray()
                while len(payload) < length:
                    chunk = self.reader.read(length - len(payload))
                    if not chunk:
                        raise DebugError("adapter_crash", "incomplete DAP payload")
                    payload.extend(chunk)
                message = json.loads(payload)
                record("adapter", message)
                self.messages.put(message, timeout=1)
        except Exception as exc:
            self.failure = exc

    def send(self, message):
        self.sequence += 1
        message["seq"] = self.sequence
        record("client", message)
        raw = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode()
        self.writer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        self.writer.flush()
        return self.sequence

    def pump(self, deadline):
        while True:
            if time.monotonic() > deadline:
                raise DebugError("timeout", "DAP operation deadline")
            try:
                msg = self.messages.get(timeout=0.05)
                break
            except queue.Empty:
                if self.failure:
                    raise self.failure
        if msg.get("type") == "response":
            self.responses[msg["request_seq"]] = msg
        elif msg.get("type") == "event":
            self.events.append(msg)
        elif msg.get("type") == "request":
            supported = msg.get("command") == "startDebugging" and self.on_child is not None
            self.send({"type": "response", "request_seq": msg["seq"], "command": msg["command"], "success": supported,
                       "message": "terminal/evaluate/external process requests are not authorized" if not supported else ""})
            if supported:
                self.on_child(msg["arguments"])
        else:
            raise DebugError("invalid_protocol", "unknown DAP message type")

    def response(self, sequence, timeout=20):
        deadline = time.monotonic() + timeout
        while sequence not in self.responses:
            self.pump(deadline)
        msg = self.responses.pop(sequence)
        if not msg.get("success"):
            raise DebugError("adapter_error", str(msg.get("message", msg.get("body", {}))))
        return msg.get("body", {})

    def request(self, command, arguments=None):
        return self.response(self.send({"type": "request", "command": command, "arguments": arguments or {}}))

    def event(self, names, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            for i, msg in enumerate(self.events):
                if msg.get("event") in names:
                    return self.events.pop(i)
            self.pump(deadline)

    def initialize(self, adapter):
        self.capabilities = self.request("initialize", {"clientID": "melissa", "adapterID": adapter,
            "pathFormat": "path", "linesStartAt1": True, "columnsStartAt1": True,
            "supportsVariableType": True, "supportsVariablePaging": True,
            "supportsRunInTerminalRequest": False, "supportsStartDebuggingRequest": self.on_child is not None})


class Session:
    def __init__(self):
        self.state = "new"
        self.epoch = 0
        self.thread = None
        self.frames = set()
        self.references = set()
        self.dap = None
        self.root_dap = None
        self.server_port = None
        self.breakpoints = P["breakpoints"]
        self.binary = None
        self.js_launch = None
        self.point_cache = {}

    def clear(self):
        self.epoch += 1
        self.frames.clear()
        self.references.clear()

    def check_file(self, path):
        if path not in P["sources"] or path.startswith(".melissa-"):
            raise DebugError("invalid_input", "debug source outside captured snapshot")
        return str(ROOT / path)

    def breakpoints_for(self, dap, configure=True):
        results = []
        grouped = {}
        for bp in self.breakpoints:
            grouped.setdefault(bp["path"], []).append({"line": bp["line"]})
        for path, values in grouped.items():
            body = dap.request("setBreakpoints", {"source": {"path": self.check_file(path)}, "breakpoints": values})
            points = body.get("breakpoints", [])
            # DAP permits unresolved breakpoints before modules/source maps
            # load. Acceptance still requires the actual source stop and a
            # verified response after launch, never the pending initial flag.
            if len(points) != len(values):
                raise DebugError("symbol_mismatch", "breakpoint not verified against this build/source")
            results.extend(points)
        self.point_cache[id(dap)] = results
        if configure and dap.capabilities.get("supportsConfigurationDoneRequest"):
            dap.request("configurationDone")
        return results if configure else self.verified_points(dap)

    def verified_points(self, dap):
        points = self.point_cache.get(id(dap), [])
        deadline = time.monotonic() + 10
        while True:
            for event in list(dap.events):
                if event.get("event") != "breakpoint":
                    continue
                update = event.get("body", {}).get("breakpoint", {})
                for index, point in enumerate(points):
                    if point.get("id") == update.get("id"):
                        points[index] = dict(point, **update)
                        if event["body"].get("reason") == "removed":
                            points[index]["verified"] = False
                dap.events.remove(event)
            if all(p.get("verified") for p in points):
                return points
            dap.pump(deadline)

    def js_child(self, arguments):
        pending = arguments.get("configuration", {})
        # This is an adapter-originated child of this private server, never an
        # arbitrary model process/port or attach-to-host operation.
        if "__pendingTargetId" not in pending or set(pending) - {"type", "name", "__pendingTargetId"}:
            raise DebugError("invalid_protocol", "unbound JS child debug target")
        config = dict(self.js_launch)
        config.update(pending)
        connection = socket.create_connection(("127.0.0.1", self.server_port), timeout=10)
        connection.settimeout(None)
        stream = connection.makefile("rwb", buffering=0)
        child = Dap(stream, stream, on_child=self.js_child)
        child.initialize("pwa-node")
        seq = child.send({"type": "request", "command": arguments.get("request", "attach"), "arguments": config})
        child.event({"initialized"})
        self.breakpoints_for(child)
        child.response(seq)
        self.dap = child

    def build(self):
        language = P["language"]
        entry = ROOT / P["entry"]
        self.check_file(P["entry"])
        if language == "rust":
            command = ["/usr/local/cargo/bin/cargo", "build", "--locked", "--offline", "--target-dir", str(TARGET), "--message-format=json"]
            compiled = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True)
            (PRIVATE / "build.stdout").write_bytes(compiled.stdout)
            (PRIVATE / "build.stderr").write_bytes(compiled.stderr)
            if compiled.returncode:
                raise DebugError("build_failed", "debug build failed; raw logs retained")
            binaries = []
            for line in compiled.stdout.splitlines():
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("reason") == "compiler-artifact" and msg.get("executable") and msg.get("target", {}).get("src_path") == str(entry):
                    binaries.append(msg["executable"])
            if len(binaries) != 1 or not Path(binaries[0]).resolve().is_relative_to(TARGET):
                raise DebugError("artifact_mismatch", "one source-bound debug executable required")
            entry = Path(binaries[0])
        elif language == "typescript":
            config = {"compilerOptions": {"target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext",
                "sourceMap": True, "inlineSources": True, "strict": True, "rootDir": str(ROOT), "outDir": str(TARGET),
                "skipLibCheck": True, "typeRoots": ["/opt/melissa-tools/node_modules/@types"], "types": ["node"]},
                "files": [str(ROOT / p) for p in P["sources"] if p.endswith((".ts", ".tsx"))]}
            config["compilerOptions"].update(P["compiler_options"])
            config["compilerOptions"].update(sourceMap=True, inlineSources=True, noEmit=False,
                                              rootDir=str(ROOT), outDir=str(TARGET))
            (PRIVATE / "tsconfig.json").write_text(json.dumps(config))
            compiled = subprocess.run([NODE, "/opt/melissa-tools/node_modules/typescript/bin/tsc", "-p", str(PRIVATE / "tsconfig.json")], capture_output=True)
            (PRIVATE / "build.stdout").write_bytes(compiled.stdout)
            (PRIVATE / "build.stderr").write_bytes(compiled.stderr)
            if compiled.returncode:
                raise DebugError("build_failed", "TypeScript debug build failed")
            entry = (TARGET / P["entry"]).with_suffix(".js")
        data = entry.read_bytes()
        (PRIVATE / "debug-artifact.bin").write_bytes(data)
        self.binary = {"path": str(entry), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                       "export_path": ".melissa-code06-debug/debug-artifact.bin"}
        if P["expected_binary_sha256"] and self.binary["sha256"] != P["expected_binary_sha256"]:
            raise DebugError("artifact_mismatch", "debug executable differs from expected host identity")
        return entry

    def start(self):
        if self.state != "new":
            raise DebugError("invalid_input", "debug session already started")
        entry = self.build()
        language = P["language"]
        if language == "python":
            child = process([PY, "-Xfrozen_modules=off", "-I", "-m", "debugpy.adapter"])
            self.dap = Dap(child.stdout, child.stdin, child)
            adapter = "python"
            launch = {"name": "owned Python", "type": "python", "request": "launch", "program": str(entry),
                      "python": [PY, "-Xfrozen_modules=off"], "cwd": str(ROOT), "console": "internalConsole",
                      "justMyCode": False, "subProcess": False}
        elif language == "rust":
            child = process(["/usr/bin/lldb-dap-19"])
            self.dap = Dap(child.stdout, child.stdin, child)
            adapter = "lldb"
            launch = {"program": str(entry), "cwd": str(ROOT), "stopOnEntry": False, "disableASLR": False,
                      "initCommands": ["settings set target.disable-aslr false"]}
        else:
            server = process([NODE, "/opt/js-debug/src/dapDebugServer.js", "0", "127.0.0.1"], stdin=subprocess.DEVNULL)
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(server.stdout.readline(8193)), daemon=True).start()
            try:
                line = lines.get(timeout=10).decode()
            except queue.Empty:
                raise DebugError("adapter_crash", "JS DAP server startup timeout")
            (PRIVATE / "server.stdout").write_text(line)
            match = re.search(r":([0-9]+)\s*$", line)
            if not match:
                raise DebugError("adapter_crash", "JS private DAP endpoint missing")
            self.server_port = int(match[1])
            connection = socket.create_connection(("127.0.0.1", self.server_port), timeout=10)
            connection.settimeout(None)
            stream = connection.makefile("rwb", buffering=0)
            self.dap = Dap(stream, stream, server, self.js_child)
            adapter = "pwa-node"
            launch = {"name": "owned Node", "type": "pwa-node", "request": "launch", "program": str(entry),
                "runtimeExecutable": NODE, "cwd": str(ROOT), "console": "internalConsole", "stopOnEntry": True,
                "sourceMaps": True, "outFiles": [str(TARGET / "**/*.js")], "resolveSourceMapLocations": [str(TARGET / "**"), "!**/node_modules/**"],
                "autoAttachChildProcesses": False, "skipFiles": ["<node_internals>/**"]}
            self.js_launch = launch
        self.root_dap = self.dap
        self.dap.initialize(adapter)
        sequence = self.dap.send({"type": "request", "command": "launch", "arguments": launch})
        self.dap.event({"initialized"})
        points = self.breakpoints_for(self.dap)
        self.root_dap.response(sequence)
        if language in ("javascript", "typescript"):
            deadline = time.monotonic() + 20
            while self.dap is self.root_dap:
                self.root_dap.pump(deadline)
        event = self.dap.event({"stopped", "terminated", "exited"})
        self.stopped(event)
        if language in ("javascript", "typescript") and event.get("body", {}).get("reason") == "entry":
            points = self.verified_points(self.dap)
            frames = self.stack()["stackFrames"]
            hits = event["body"].get("hitBreakpointIds", [])
            actual = any(p.get("id") in hits and any(f.get("source", {}).get("path") == p.get("source", {}).get("path")
                and f.get("line") == p.get("line") for f in frames) for p in points)
            if not actual:
                self.dap.request("continue", {"threadId": self.thread})
                event = self.dap.event({"stopped", "terminated", "exited"})
                self.stopped(event)
        if self.state != "stopped":
            raise DebugError("symbol_mismatch", "debuggee exited without reaching source breakpoint")
        points = self.verified_points(self.dap)
        frames = self.stack()["stackFrames"]
        if not any(f.get("source", {}).get("path") == p.get("source", {}).get("path")
                   and f.get("line") == p.get("line") for f in frames for p in points):
            raise DebugError("symbol_mismatch", "stopped frame does not match expected source/build")
        return {"breakpoints": points, "stop": event, "binary": self.binary,
                "capabilities": self.dap.capabilities, "source_digest": P["source_digest"]}

    def stopped(self, event):
        self.clear()
        if event["event"] == "stopped":
            self.state = "stopped"
            self.thread = event["body"].get("threadId")
            if not self.thread:
                threads = self.dap.request("threads").get("threads", [])
                if not threads:
                    raise DebugError("invalid_protocol", "stopped without thread")
                self.thread = threads[0]["id"]
        else:
            self.state = "exited"

    def stack(self):
        self.require_stopped()
        body = self.dap.request("stackTrace", {"threadId": self.thread, "startFrame": 0, "levels": 20})
        self.frames.update(frame["id"] for frame in body.get("stackFrames", []))
        return body

    def require_stopped(self):
        if self.state != "stopped":
            raise DebugError("invalid_input", "frame/variable operation requires stopped session")

    def command(self, request):
        command = request["command"]
        if command == "start":
            return self.start()
        if command == "close":
            if self.dap and self.state not in ("closed", "crashed"):
                try:
                    self.dap.request("disconnect", {"terminateDebuggee": True})
                except Exception:
                    if self.state != "exited":
                        raise
            self.clear()
            self.state = "closed"
            return {"closed": True}
        if command == "stack":
            return self.stack()
        if command == "scopes":
            self.require_stopped()
            if request["frame"] not in self.frames:
                raise DebugError("invalid_input", "unissued/stale frame reference")
            body = self.dap.request("scopes", {"frameId": request["frame"]})
            self.references.update(s["variablesReference"] for s in body.get("scopes", []) if s.get("variablesReference"))
            return body
        if command == "variables":
            self.require_stopped()
            reference = request["reference"]
            if reference not in self.references:
                raise DebugError("invalid_input", "unissued/stale variable reference")
            start, count = request["start"], request["count"]
            body = self.dap.request("variables", {"variablesReference": reference, "start": start, "count": count})
            values = body.get("variables", [])
            self.references.update(v["variablesReference"] for v in values if v.get("variablesReference"))
            body["paging"] = {"requested_start": start, "requested_count": count, "returned": len(values)}
            return body
        if command == "inspect":
            frames = self.stack()
            own = next((f for f in frames.get("stackFrames", []) if f.get("source", {}).get("path", "").startswith(str(ROOT) + "/")), None)
            if own is None:
                raise DebugError("symbol_mismatch", "no source-owned stopped frame")
            scopes = self.command({"command": "scopes", "frame": own["id"]})
            selected = next((s for s in scopes.get("scopes", []) if s.get("name", "").lower() in ("locals", "local")), None)
            selected = selected or next((s for s in scopes.get("scopes", []) if not s.get("expensive")), None)
            values = self.command({"command": "variables", "reference": selected["variablesReference"], "start": 0, "count": request["count"]}) if selected else {"variables": []}
            return {"frame": own, "scopes": scopes, "values": values}
        if command in ("next", "step_in", "step_out", "continue"):
            self.require_stopped()
            self.clear()
            self.state = "running"
            native = {"next": "next", "step_in": "stepIn", "step_out": "stepOut", "continue": "continue"}[command]
            body = self.dap.request(native, {"threadId": self.thread})
            if command != "continue":
                event = self.dap.event({"stopped", "terminated", "exited"})
                self.stopped(event)
                return {"response": body, "stop": event}
            return body
        if command == "pause":
            if self.state != "running":
                raise DebugError("invalid_input", "pause requires running state")
            self.dap.request("pause", {"threadId": self.thread})
            event = self.dap.event({"stopped", "terminated", "exited"})
            self.stopped(event)
            return event
        if command == "wait":
            if self.state != "running":
                raise DebugError("invalid_input", "wait requires running state")
            event = self.dap.event({"stopped", "terminated", "exited"}, timeout=request["timeout_ms"] / 1000)
            self.stopped(event)
            return event
        if command == "breakpoints":
            self.breakpoints = request["breakpoints"]
            return {"breakpoints": self.breakpoints_for(self.dap, configure=False)}
        raise DebugError("invalid_input", "unregistered debug operation")


session = Session()
try:
    for line in sys.stdin.buffer:
        request = json.loads(line)
        reply = {"seq": request["seq"], "ok": False, "body": None, "error": None,
                 "source_digest": P["source_digest"]}
        try:
            if not same_source():
                raise DebugError("source_changed", "worker input source bytes changed")
            if request["epoch"] != session.epoch:
                raise DebugError("invalid_input", "stale debug stop epoch")
            reply["body"] = session.command(request["operation"])
            reply["ok"] = True
        except Exception as exc:
            kind = exc.kind if isinstance(exc, DebugError) else "adapter_crash"
            reply["error"] = {"kind": kind, "message": str(exc)}
            if kind != "invalid_input":
                session.state = "crashed"
        reply.update({"state": session.state, "epoch": session.epoch})
        raw = json.dumps(reply, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(raw) > 64 * 1024:
            raise DebugError("resource_limit", "debug reply needs a smaller explicit page")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        if session.state in ("closed", "crashed"):
            break
finally:
    for child in reversed(owned):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for child in owned:
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    trace.close()
    if TARGET.is_dir() and not TARGET.is_symlink():
        shutil.rmtree(TARGET)
