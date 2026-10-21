"""Fixed semantic servers; source text/config cannot select a server or command."""
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlparse

ROOT = Path.cwd().resolve()
PRIVATE = ROOT / ".melissa-code06-semantic"
P = json.loads((PRIVATE / "program.json").read_bytes())
TRACE = (PRIVATE / "lsp-transcript.ndjson").open("wb")
trace_lock = threading.Lock()
trace_size = 0
messages = queue.Queue(maxsize=1024)
failure = None
responses = {}
notifications = []
sequence = 0
result = {"schema_version": "melissa.semantic-result/v1", "source_digest": P["source_digest"],
          "result": None, "locations": [], "source_unchanged": False,
          "build_scripts_enabled": P["build_scripts"], "error": None, "sdk": P["sdk"],
          "execution_markers": {}}


def record(direction, message):
    global trace_size
    raw = (json.dumps({"direction": direction, "message": message}, ensure_ascii=True) + "\n").encode()
    with trace_lock:
        trace_size += len(raw)
        if trace_size > P["trace_limit"]:
            raise ValueError("semantic transcript quota")
        TRACE.write(raw)
        TRACE.flush()


def same_source():
    return all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
               and (ROOT / name).read_bytes().hex() == raw for name, raw in P["sources"].items())


language = P["language"]
settings = {}
if language == "rust":
    args = ["/usr/local/cargo/bin/rust-analyzer"]
    settings = {"cargo": {"buildScripts": {"enable": P["build_scripts"]}, "extraArgs": ["--offline", "--locked"]},
                "procMacro": {"enable": P["build_scripts"]}, "checkOnSave": False}
elif language == "python":
    args = ["/opt/node/bin/node", "/opt/melissa-tools/node_modules/pyright/langserver.index.js", "--stdio"]
    config = {"include": [p for p in P["sources"] if p.endswith(".py")],
              "exclude": [".melissa-code06-semantic"], "extraPaths": ["/work/src"], "typeCheckingMode": "strict"}
    (ROOT / "pyrightconfig.json").write_text(json.dumps(config))
    settings = {"python": {"pythonPath": "/opt/melissa-python/bin/python", "analysis": config},
                "python.analysis": config}
else:
    args = ["/opt/node/bin/node", "/opt/melissa-tools/node_modules/typescript-language-server/lib/cli.mjs",
            "--stdio"]
    options = {"target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext",
               "strict": True, "allowJs": language == "javascript", "checkJs": language == "javascript",
               "skipLibCheck": True, "types": ["node"], "typeRoots": ["/opt/melissa-tools/node_modules/@types"]}
    options.update(P["compiler_options"])
    if "tsconfig.json" not in P["sources"]:
        (ROOT / "tsconfig.json").write_text(json.dumps({"compilerOptions": options,
            "files": [p for p in P["sources"] if p.endswith((".ts", ".tsx", ".js", ".mjs", ".cjs"))]}))
    settings = {"typescript": {"disableAutomaticTypeAcquisition": True}, "javascript": {"validate": {"enable": True}}}

environment = dict(os.environ, CARGO_NET_OFFLINE="true")
child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=(PRIVATE / "server.stderr").open("wb"), env=environment, start_new_session=True)


def send(message):
    record("client", message)
    raw = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode()
    child.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    child.stdin.flush()


def reader():
    global failure
    try:
        while True:
            headers = {}
            total = 0
            while True:
                line = child.stdout.readline(8193)
                total += len(line)
                if not line or total > 8192:
                    raise ValueError("LSP closed/incomplete header")
                if line == b"\r\n":
                    break
                key, value = line.decode("ascii").strip().split(":", 1)
                if key.lower() in headers or key.lower() not in ("content-length", "content-type"):
                    raise ValueError("invalid LSP headers")
                headers[key.lower()] = value.strip()
            length = int(headers["content-length"])
            if length <= 0 or length > 4 * 1024 * 1024:
                raise ValueError("LSP frame quota")
            data = bytearray()
            while len(data) < length:
                block = child.stdout.read(length - len(data))
                if not block:
                    raise ValueError("incomplete LSP body")
                data.extend(block)
            message = json.loads(data)
            record("server", message)
            messages.put(message, timeout=1)
    except Exception as exc:
        failure = exc


threading.Thread(target=reader, daemon=True).start()


def pump(deadline):
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("semantic operation deadline")
        try:
            message = messages.get(timeout=0.05)
            break
        except queue.Empty:
            if failure:
                raise failure
    if "method" in message and "id" in message:
        method = message["method"]
        if method == "workspace/configuration":
            values = []
            for item in message.get("params", {}).get("items", []):
                section = item.get("section", "")
                values.append(settings if language == "rust" else settings.get(section, {}))
            send({"jsonrpc": "2.0", "id": message["id"], "result": values})
        elif method == "workspace/workspaceFolders":
            send({"jsonrpc": "2.0", "id": message["id"], "result": [{"uri": ROOT.as_uri(), "name": "owned"}]})
        elif method in ("client/registerCapability", "window/workDoneProgress/create", "workspace/semanticTokens/refresh"):
            send({"jsonrpc": "2.0", "id": message["id"], "result": None})
        else:
            send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "source/server requests cannot grant edit/command authority"}})
    elif "id" in message:
        responses[message["id"]] = message
    else:
        notifications.append(message)


def request(method, params):
    global sequence
    sequence += 1
    identity = sequence
    send({"jsonrpc": "2.0", "id": identity, "method": method, "params": params})
    deadline = time.monotonic() + 45
    while identity not in responses:
        pump(deadline)
    response = responses.pop(identity)
    if "error" in response:
        raise ValueError("semantic server error: " + str(response["error"]))
    return response.get("result")


def notification(method, params):
    send({"jsonrpc": "2.0", "method": method, "params": params})


try:
    if not same_source():
        raise ValueError("semantic source changed before initialize")
    request("initialize", {"processId": None, "rootUri": ROOT.as_uri(),
        "workspaceFolders": [{"uri": ROOT.as_uri(), "name": "owned"}],
        "capabilities": {"workspace": {"configuration": True}, "experimental": {"serverStatusNotification": True},
                         "textDocument": {"publishDiagnostics": {"versionSupport": True}}},
        "initializationOptions": settings if language == "rust" else {"tsserver": {
            "path": "/opt/melissa-tools/node_modules/typescript/lib/tsserver.js", "useSyntaxServer": "never"},
            "disableAutomaticTypingAcquisition": True} if language in ("javascript", "typescript") else {}})
    notification("initialized", {})
    notification("workspace/didChangeConfiguration", {"settings": settings})
    path = P["query"]["path"]
    uri = (ROOT / path).as_uri()
    language_id = "python" if language == "python" else "rust" if language == "rust" else "typescript" if path.endswith((".ts", ".tsx")) else "javascript"
    notification("textDocument/didOpen", {"textDocument": {"uri": uri, "languageId": language_id,
                 "version": 1, "text": bytes.fromhex(P["sources"][path]).decode("utf-8", "strict")}})
    if language == "rust":
        deadline = time.monotonic() + 35
        while not any(n.get("method") == "experimental/serverStatus" and n.get("params", {}).get("quiescent") for n in notifications):
            pump(deadline)
    method = P["query"]["method"]
    params = {"textDocument": {"uri": uri}}
    if method in ("definition", "references", "hover"):
        params["position"] = {"line": P["query"]["line"], "character": P["query"]["character"]}
    if method == "references":
        params["context"] = {"includeDeclaration": True}
    if method == "diagnostics":
        deadline = time.monotonic() + 30
        while True:
            found = [n for n in notifications if n.get("method") == "textDocument/publishDiagnostics"
                     and n.get("params", {}).get("uri") == uri and n["params"].get("version", 1) == 1]
            if found:
                result["result"] = found[-1]["params"]
                break
            pump(deadline)
    else:
        native = {"definition": "textDocument/definition", "references": "textDocument/references",
                  "symbols": "textDocument/documentSymbol", "hover": "textDocument/hover"}[method]
        deadline = time.monotonic() + 30
        while True:
            value = request(native, params)
            if value or method not in ("definition", "references") or time.monotonic() > deadline:
                result["result"] = value
                break
            time.sleep(0.1)
    uris = set()
    def locations(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("uri", "targetUri") and isinstance(item, str):
                    uris.add(item)
                else:
                    locations(item)
        elif isinstance(value, list):
            for item in value:
                locations(item)
    locations(result["result"])
    sdk_prefixes = ("/usr/local/rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/",
                    "/opt/melissa-tools/node_modules/typescript/lib/", "/opt/melissa-tools/node_modules/@types/",
                    "/opt/melissa-tools/node_modules/pyright/dist/typeshed-fallback/", "/usr/lib/python3.13/")
    for i, uri in enumerate(sorted(uris)):
        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.netloc:
            raise ValueError("unbound semantic location scheme/authority")
        path = Path(unquote(parsed.path)).resolve()
        relative = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else None
        scope = "workspace" if relative in P["sources"] else "sdk" if str(path).startswith(sdk_prefixes) else None
        if scope is None or not path.is_file() or path.is_symlink():
            raise ValueError("semantic result outside captured workspace/immutable SDK")
        data = path.read_bytes()
        if len(data) > P["trace_limit"]:
            raise ValueError("semantic source artifact quota")
        exported = f".melissa-code06-semantic/location-{i}.bin"
        (ROOT / exported).write_bytes(data)
        result["locations"].append({"uri": uri, "scope": scope, "export_path": exported,
                                   "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    request("shutdown", None)
    notification("exit", None)
except Exception as exc:
    result["error"] = {"kind": type(exc).__name__, "message": str(exc)}
finally:
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    result["source_unchanged"] = same_source()
    result["execution_markers"] = {name: (ROOT / name).is_file()
        for name in ("CODE06_BUILD_SCRIPT_RAN", "CODE06_PROC_MACRO_RAN")}
    for name in (".melissa-code06-target", "target"):
        path = ROOT / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    TRACE.close()
sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
