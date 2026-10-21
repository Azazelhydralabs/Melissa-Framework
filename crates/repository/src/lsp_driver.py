"""Transport-only helper inside an exact CODE-03 Linux worker; no host grants.
The Rust host supplies validated relative paths/query and validates all results.
"""
import json
import os
import select
import subprocess
import time

request = json.load(open(".melissa-analysis/request.json", encoding="utf-8"))
deadline = time.monotonic() + 50
stderr = open(".melissa-analysis/server.stderr", "wb")
server = subprocess.Popen(["/usr/local/cargo/bin/rust-analyzer"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=stderr, env={
    "PATH": "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/work",
    "CARGO_NET_OFFLINE": "true", "RAYON_NUM_THREADS": "2", "RA_LOG": "error",
    "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/usr/local/cargo",
    "RUSTUP_TOOLCHAIN": "1.98.1",
})
trace = []
buffer = bytearray()
quiescent = False


def send(value):
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    server.stdin.write(b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    server.stdin.flush()


def receive():
    while True:
        end = buffer.find(b"\r\n\r\n")
        if end >= 0:
            headers = buffer[:end].decode("ascii").split("\r\n")
            lengths = [h.split(":", 1)[1].strip() for h in headers
                       if h.lower().startswith("content-length:")]
            if len(lengths) != 1:
                raise RuntimeError("LSP length cardinality")
            size = int(lengths[0])
            if size < 0 or size > 8 * 1024 * 1024:
                raise RuntimeError("LSP message bound")
            if len(buffer) >= end + 4 + size:
                value = json.loads(buffer[end+4:end+4+size])
                del buffer[:end+4+size]
                return value
        elif len(buffer) > 8192:
            raise RuntimeError("LSP header bound")
        wait = deadline - time.monotonic()
        if wait <= 0 or not select.select([server.stdout], [], [], wait)[0]:
            raise RuntimeError("LSP deadline")
        chunk = os.read(server.stdout.fileno(), 65536)
        if not chunk:
            raise RuntimeError("LSP server closed before result")
        buffer.extend(chunk)


def response(identifier):
    global quiescent
    while True:
        value = receive()
        if value.get("jsonrpc") != "2.0":
            raise RuntimeError("LSP JSON-RPC version")
        if "method" in value:
            trace.append(value["method"])
            if value["method"] == "experimental/serverStatus":
                quiescent = value.get("params", {}).get("quiescent", False)
                if identifier is None and quiescent:
                    return value
            if len(trace) > 10000:
                raise RuntimeError("LSP event bound")
            if "id" in value:
                method = value["method"]
                if method == "workspace/configuration":
                    result = [None for _ in value.get("params", {}).get("items", [])]
                elif method == "workspace/applyEdit":
                    result = {"applied": False, "failureReason": "analysis only"}
                elif method == "workspace/workspaceFolders":
                    result = [{"uri": "file:///work", "name": "owned-source"}]
                else:
                    result = None
                send({"jsonrpc": "2.0", "id": value["id"], "result": result})
            continue
        if value.get("id") == identifier:
            return value
        raise RuntimeError("unexpected LSP response identity")


try:
    crates = [{"root_module": "/work/" + path, "edition": "2021", "deps": [],
               "cfg": [], "env": {}, "is_workspace_member": True}
              for path in request["root_modules"]]
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "processId": None, "rootUri": "file:///work", "capabilities": {
            "textDocument": {"definition": {"linkSupport": False}},
            "experimental": {"serverStatusNotification": True},
            "general": {"positionEncodings": ["utf-16"]}},
        "initializationOptions": {"linkedProjects": [{"crates": crates}],
            "cargo": {"buildScripts": {"enable": False}, "sysroot": None,
                      "autoreload": True, "noDeps": True},
            "procMacro": {"enable": False}, "checkOnSave": False,
            "cachePriming": {"enable": False}}
    }})
    initialized = response(1)
    if "error" in initialized:
        raise RuntimeError("LSP initialization rejected")
    send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    for path in request["documents"]:
        from urllib.parse import quote
        text = open(path, encoding="utf-8", newline="").read()
        send({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": "file:///work/" + quote(path, safe="/"),
                             "languageId": "rust", "version": 1, "text": text}}})
    ready = response(None)
    query = request["query"]
    from urllib.parse import quote
    params = {"textDocument": {"uri": "file:///work/" + quote(query["path"], safe="/")}}
    if query["method"] != "textDocument/documentSymbol":
        params["position"] = {"line": query["line"], "character": query["character"]}
    if query["method"] == "textDocument/references":
        params["context"] = {"includeDeclaration": query["include_declaration"]}
    # A server may return ContentModified while loading source. Only these
    # effect-free reads are retried in the same isolated server session.
    result = None
    for identifier in range(2, 12):
        send({"jsonrpc": "2.0", "id": identifier, "method": query["method"], "params": params})
        result = response(identifier)
        if "error" not in result:
            break
        if result["error"].get("code") not in (-32801, -32802):
            raise RuntimeError("LSP query rejected: " + str(result["error"].get("code")))
        time.sleep(0.1)
    if result is None or "error" in result:
        raise RuntimeError("LSP content never became current")
    print(json.dumps({"schema_version": "melissa.lsp-worker-result/v1",
                      "server_info": initialized.get("result", {}).get("serverInfo"),
                      "position_encoding": initialized.get("result", {}).get("capabilities", {}).get("positionEncoding", "utf-16"),
                      "query": query, "result": result["result"], "trace": trace,
                      "ready_status": ready.get("params"),
                      "query_attempts": identifier - 1}, ensure_ascii=False))
except Exception:
    import sys
    stderr.flush()
    with open(".melissa-analysis/server.stderr", "rb") as source:
        sys.stderr.buffer.write(source.read(8192))
    raise
finally:
    server.kill()
    server.wait(timeout=3)
    stderr.close()
