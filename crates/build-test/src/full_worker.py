"""CODE-06 fixed SDK procedures. No model command, environment or image input.

All project build scripts/tests and their reports are untrusted developer
observations. The Rust host controls authority and final result admission.
"""
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tomllib

ROOT = Path.cwd().resolve()
PRIVATE = ROOT / ".melissa-code06-v2"
TARGET = ROOT / ".melissa-code06-target"
P = json.loads((PRIVATE / "program.json").read_bytes())
R = {"schema_version": "melissa.sdk-procedure/v1", "source_digest": P["source_digest"],
     "steps": [], "attachments": [], "discovered": [], "runs": [],
     "diagnostics": [], "sdk": {}, "source_unchanged": False,
     "truncated": False, "error": None}
remaining = P["raw_limit"]
PY = "/opt/melissa-python/bin/python"
NODE = "/opt/node/bin/node"
TOOLS = "/opt/melissa-tools/node_modules"
CARGO = "/usr/local/cargo/bin/cargo"


class ProcedureError(Exception):
    def __init__(self, kind, message):
        self.kind = kind
        super().__init__(message)


def same_source():
    return all((ROOT / p).is_file() and not (ROOT / p).is_symlink()
               and (ROOT / p).read_bytes().hex() == data for p, data in P["sources"].items())


def run(stage, argv, env=None):
    global remaining
    item = {"stage": stage, "executable": argv[0], "argv": argv[1:],
            "exit_code": None, "stdout_hex": "", "stderr_hex": ""}
    R["steps"].append(item)
    controlled = dict(os.environ)
    controlled.update({"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1",
                       "NO_COLOR": "1", "FORCE_COLOR": "0"})
    if env:
        controlled.update(env)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=controlled, start_new_session=True)
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    while selector.get_map():
        for key, _ in selector.select():
            block = os.read(key.fd, 65536)
            if not block:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            kept = block[:remaining]
            outputs[key.data].extend(kept)
            remaining -= len(kept)
            if len(kept) != len(block):
                R["truncated"] = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    selector.close()
    item["exit_code"] = process.wait()
    for stream, data in outputs.items():
        item[stream + "_hex"] = data.hex()
    if R["truncated"]:
        raise ProcedureError("incomplete", "raw tool output exceeded the declared envelope")
    return item, bytes(outputs["stdout"]), bytes(outputs["stderr"])


def checked(stage, argv, allowed=(0,)):
    item, stdout, stderr = run(stage, argv)
    if item["exit_code"] not in allowed:
        message = stderr.decode("utf-8", "replace")
        kind = "missing_sdk" if "not installed" in message or "not found" in message else "failed"
        if "no matching package" in message or "failed to download" in message:
            kind = "missing_dependency"
        raise ProcedureError(kind, stage + " failed; inspect raw logs")
    return item, stdout, stderr


def attach(name, path):
    global remaining
    data = Path(path).read_bytes()
    if len(data) > remaining:
        R["truncated"] = True
        raise ProcedureError("incomplete", "raw report exceeds declared envelope")
    remaining -= len(data)
    R["attachments"].append({"name": name, "bytes_hex": data.hex()})
    return json.loads(data)


def probe(name, argv, expected):
    _, stdout, _ = checked("sdk:" + name, argv)
    actual = stdout.decode("utf-8", "strict").strip()
    R["sdk"][name] = actual
    if actual != expected:
        raise ProcedureError("missing_sdk", "pinned " + name + " version mismatch")


def add_test(group, identity, path):
    record = {"group": group, "id": identity, "file": path}
    if record in R["discovered"]:
        raise ProcedureError("invalid_output", "duplicate discovered test identity")
    R["discovered"].append(record)


def parse_libtest(group, stdout, names, code, repetition):
    text = stdout.decode("utf-8", "strict")
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s$", text, re.M)
    if len(summaries) != 1 or not text.endswith("\n"):
        raise ProcedureError("incomplete", "libtest terminal result absent or ambiguous")
    status, passed, failed, ignored, measured, filtered = summaries[0]
    if int(measured) or int(filtered) or sum(map(int, (passed, failed, ignored))) != len(names):
        raise ProcedureError("invalid_output", "libtest discovery/count mismatch")
    if (code == 0) != (int(failed) == 0 and status == "ok"):
        raise ProcedureError("invalid_output", "libtest exit/result mismatch")
    actual = {}
    for line in text.splitlines():
        match = re.fullmatch(r"test (.+) \.\.\. (ok|FAILED|ignored(?:, .*)?)", line)
        if match:
            name, state = match.groups()
            if name not in names or name in actual:
                raise ProcedureError("invalid_output", "unexpected executed test")
            actual[name] = "passed" if state == "ok" else "failed" if state == "FAILED" else "skipped"
    if set(actual) != set(names):
        raise ProcedureError("invalid_output", "discovered test missing from terminal results")
    R["runs"].extend({"group": group, "id": name, "repetition": repetition, "status": state}
                     for name, state in actual.items())


def cargo_messages(data):
    for line in data.splitlines():
        try:
            msg = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if msg.get("reason") == "compiler-message":
            message = msg["message"]
            spans = message.get("spans", [])
            primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
            R["diagnostics"].append({"stage": "compiler", "level": message["level"],
                "code": (message.get("code") or {}).get("code"), "message": message["message"],
                "file": primary.get("file_name"), "line": primary.get("line_start"),
                "column": primary.get("column_start")})
        yield msg


def rust():
    probe("rustc", ["/usr/local/cargo/bin/rustc", "--version"], P["expected_sdk"]["rustc"])
    probe("cargo", [CARGO, "--version"], P["expected_sdk"]["cargo"])
    _, meta, _ = checked("metadata", [CARGO, "metadata", "--format-version=1", "--locked", "--offline"])
    metadata = json.loads(meta)
    operation = P["operation"]["operation"]
    fixed = ["--workspace", "--locked", "--offline", "--target-dir", str(TARGET), "--message-format=json"]
    if operation in ("build", "check", "lint", "format_check"):
        if operation == "format_check":
            checked("format", [CARGO, "fmt", "--all", "--", "--check"])
        else:
            sub = {"build": "build", "check": "check", "lint": "clippy"}[operation]
            extra = ["--", "-D", "warnings"] if operation == "lint" else []
            item, stdout, _ = run(sub, [CARGO, sub, *fixed, *extra])
            messages = list(cargo_messages(stdout))
            if item["exit_code"]:
                raise ProcedureError("failed", "Rust compiler/lint failed")
            finishes = [m.get("success") for m in messages if m.get("reason") == "build-finished"]
            if finishes != [True]:
                raise ProcedureError("incomplete", "compiler completion missing")
        return
    suite = P["operation"]["suite"]
    repeats = P["operation"]["repetitions"]
    if suite != "custom":
        for path, data in P["sources"].items():
            if path.endswith("Cargo.toml"):
                manifest = tomllib.loads(bytes.fromhex(data).decode())
                if manifest.get("lib", {}).get("harness") is False or any(t.get("harness") is False for t in manifest.get("test", [])):
                    raise ProcedureError("unsupported", "custom harness requires explicit host registration")
    if suite in ("unit_integration", "all", "end_to_end", "custom"):
        args = [CARGO, "test", "--no-run", *fixed]
        if suite == "end_to_end":
            if "tests/e2e.rs" not in P["sources"]:
                return
            args.extend(["--test", "e2e"])
        elif suite == "custom":
            args.extend(["--test", P["harness"]["target"]])
        else:
            args.extend(["--tests"])
        item, compiled, _ = run("test-build", args)
        messages = list(cargo_messages(compiled))
        if item["exit_code"]:
            raise ProcedureError("failed", "test compile failed")
        if [m.get("success") for m in messages if m.get("reason") == "build-finished"] != [True]:
            raise ProcedureError("incomplete", "test build completion missing")
        binaries = sorted({m["executable"] for m in messages if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable")})
        for index, binary in enumerate(binaries):
            if not Path(binary).resolve().is_relative_to(TARGET) or Path(binary).is_symlink():
                raise ProcedureError("artifact_mismatch", "test binary outside private target")
            group = "rust:" + str(index)
            flag = "--melissa-list" if suite == "custom" else "--list"
            _, found, _ = checked("discover:" + group, [binary, flag] if suite == "custom" else [binary, flag, "--format", "terse"])
            if suite == "custom":
                listing = json.loads(found)
                if listing.get("schema_version") != "melissa.harness-list/v1":
                    raise ProcedureError("unsupported", "unregistered harness protocol")
                names = listing["tests"]
            else:
                names = [l[:-6] for l in found.decode().splitlines() if l.endswith(": test")]
                if any(l and not l.endswith(": test") for l in found.decode().splitlines()):
                    raise ProcedureError("unsupported", "non-libtest discovery format")
            if len(set(names)) != len(names):
                raise ProcedureError("invalid_output", "duplicate harness identities")
            for name in names:
                add_test(group, name, None)
            for repetition in range(repeats):
                item, result, _ = run(f"run:{group}:{repetition}", [binary, "--melissa-run"] if suite == "custom" else [binary, "--format", "pretty", "--color", "never", "--test-threads=1"])
                if suite == "custom":
                    reported = json.loads(result)
                    states = reported.get("results", [])
                    if reported.get("schema_version") != "melissa.harness-results/v1" or sorted(x["id"] for x in states) != sorted(names):
                        raise ProcedureError("invalid_output", "custom harness discovery/result mismatch")
                    failures = any(x["status"] == "failed" for x in states)
                    if (item["exit_code"] == 0) == failures:
                        raise ProcedureError("invalid_output", "custom harness exit mismatch")
                    R["runs"].extend(dict(x, group=group, repetition=repetition) for x in states)
                else:
                    parse_libtest(group, result, names, item["exit_code"], repetition)
    if suite in ("doctest", "all"):
        for package in metadata["workspace_members"]:
            args = [CARGO, "test", "--doc", "-p", package, "--locked", "--offline", "--target-dir", str(TARGET), "--message-format=json", "--"]
            _, found, _ = checked("discover:doc:" + package, [*args, "--list", "--format", "terse"])
            names = [l[:-6] for l in found.decode().splitlines() if l.endswith(": test")]
            group = "rust-doc:" + package
            for name in names:
                add_test(group, name, None)
            for repetition in range(repeats):
                item, result, _ = run(f"run:{group}:{repetition}", [*args, "--format", "pretty", "--color", "never", "--test-threads=1"])
                parse_libtest(group, result, names, item["exit_code"], repetition)


def typescript_config(emit):
    paths = [str(ROOT / p) for p in P["sources"] if p.endswith((".ts", ".tsx", ".js", ".mjs", ".cjs"))]
    config = {"compilerOptions": {"target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext",
        "strict": True, "skipLibCheck": True, "allowJs": P["language"] == "javascript",
        "checkJs": P["language"] == "javascript", "rootDir": str(ROOT), "outDir": str(TARGET),
        "noEmit": not emit, "sourceMap": True, "inlineSources": True,
        "typeRoots": [TOOLS + "/@types"], "types": ["node"]}, "files": paths}
    config["compilerOptions"].update(P["compiler_options"])
    (PRIVATE / "tsconfig.json").write_text(json.dumps(config))
    return paths


def python():
    probe("python", [PY, "--version"], P["expected_sdk"]["python"])
    operation = P["operation"]["operation"]
    paths = [p for p in P["sources"] if p.endswith(".py")]
    if operation == "build":
        script = "import pathlib,sys,json\nfor name in sys.argv[1:]:\n try: compile(pathlib.Path(name).read_bytes(),name,'exec')\n except SyntaxError as e:\n  print(json.dumps({'file':name,'line':e.lineno,'column':e.offset,'message':e.msg}));raise SystemExit(1)\n"
        item, stdout, _ = run("compile", [PY, "-I", "-c", script, *paths])
        if item["exit_code"]:
            diagnostic = json.loads(stdout)
            R["diagnostics"].append(dict(diagnostic, level="error", code="SyntaxError", stage="compile"))
            raise ProcedureError("failed", "Python syntax compile failed")
        return
    if operation in ("check", "lint", "format_check"):
        if operation == "check":
            config = {"include": [os.path.relpath(ROOT / p, PRIVATE) for p in paths], "extraPaths": [str(ROOT / "src")],
                      "exclude": [str(PRIVATE)], "typeCheckingMode": "strict", "pythonVersion": "3.13"}
            (PRIVATE / "pyrightconfig.json").write_text(json.dumps(config))
            item, stdout, _ = run("typecheck", [NODE, TOOLS + "/pyright/index.js", "--project", str(PRIVATE / "pyrightconfig.json"), "--outputjson"])
            result = json.loads(stdout)
            for diagnostic in result.get("generalDiagnostics", []):
                start = diagnostic["range"]["start"]
                R["diagnostics"].append({"file": diagnostic["file"], "line": start["line"] + 1,
                    "column": start["character"] + 1, "message": diagnostic["message"],
                    "level": diagnostic["severity"], "code": diagnostic.get("rule"), "stage": "typecheck"})
        elif operation == "lint":
            item, stdout, _ = run("lint", ["/opt/melissa-python/bin/ruff", "check", "--isolated", "--no-cache", "--output-format=json", *paths])
            for diagnostic in json.loads(stdout):
                R["diagnostics"].append({"file": diagnostic["filename"], "line": diagnostic["location"]["row"],
                    "column": diagnostic["location"]["column"], "message": diagnostic["message"], "level": "error",
                    "code": diagnostic["code"], "stage": "lint"})
        else:
            item, _, _ = run("format", ["/opt/melissa-python/bin/ruff", "format", "--isolated", "--check", *paths])
        if item["exit_code"]:
            raise ProcedureError("failed", "Python check failed")
        return
    suite = P["operation"]["suite"]
    if suite == "custom":
        raise ProcedureError("unsupported", "Python supports registered pytest and doctest, not the Rust custom protocol")
    selected = [p for p in paths if (p.startswith("e2e/") if suite == "end_to_end" else p.startswith("tests/") or Path(p).name.startswith("test_"))]
    if suite == "doctest":
        selected = [p for p in paths if p.startswith("src/")]
    elif suite == "all":
        selected = paths
    if not selected:
        return
    request = {"paths": selected, "doctest": suite in ("doctest", "all")}
    (PRIVATE / "pytest-request.json").write_text(json.dumps(request))
    base = [PY, "-I", str(PRIVATE / "pytest_runner.py"), str(PRIVATE / "pytest-request.json")]
    discovery_path = PRIVATE / "pytest-collection.json"
    item, _, _ = checked("pytest-discover", [*base, str(discovery_path), "collect"], allowed=(0, 5))
    listing = attach("pytest-discover", discovery_path)
    if listing["collection_errors"]:
        raise ProcedureError("failed", "pytest collection error")
    names = [x["id"] for x in listing["collected"]]
    for identity in listing["collected"]:
        add_test("pytest", identity["id"], identity["file"])
    for repetition in range(P["operation"]["repetitions"]):
        path = PRIVATE / f"pytest-run-{repetition}.json"
        item, _, _ = run(f"pytest-run:{repetition}", [*base, str(path), "run"])
        results = attach(f"pytest-run:{repetition}", path)
        if sorted(results["results"]) != sorted(names) or results["exit_code"] != item["exit_code"]:
            raise ProcedureError("incomplete", "pytest discovery/result/exit mismatch")
        if item["exit_code"] not in (0, 1, 5) or results["collection_errors"]:
            raise ProcedureError("failed", "pytest collection/setup interrupted")
        R["runs"].extend({"group": "pytest", "id": identity, "status": status, "repetition": repetition}
                         for identity, status in results["results"].items())


def javascript():
    probe("node", [NODE, "--version"], P["expected_sdk"]["node"])
    probe("typescript", [NODE, TOOLS + "/typescript/bin/tsc", "--version"], "Version " + P["expected_sdk"]["typescript"])
    operation = P["operation"]["operation"]
    typed = P["language"] == "typescript"
    paths = typescript_config(typed and operation in ("build", "test"))
    if operation == "format_check":
        (PRIVATE / "prettier.json").write_text("{}")
        checked("format", [NODE, TOOLS + "/prettier/bin/prettier.cjs", "--config", str(PRIVATE / "prettier.json"), "--check", *paths])
        return
    if operation in ("check", "build") or (operation == "test" and typed):
        if typed or operation == "check":
            item, stdout, _ = run("tsc", [NODE, TOOLS + "/typescript/bin/tsc", "--project", str(PRIVATE / "tsconfig.json"), "--pretty", "false"])
            for line in stdout.decode("utf-8", "replace").splitlines():
                match = re.match(r"(.+)\((\d+),(\d+)\): (error|warning) (TS\d+): (.+)", line)
                if match:
                    file, row, column, level, code, message = match.groups()
                    R["diagnostics"].append(dict(file=file, line=int(row), column=int(column), level=level, code=code, message=message, stage="tsc"))
            if item["exit_code"]:
                raise ProcedureError("failed", "TypeScript/JS typecheck failed")
        else:
            for path in paths:
                checked("node-syntax:" + path, [NODE, "--check", path])
        if operation != "test":
            return
    if operation == "lint":
        config = "import ts from '" + TOOLS + "/typescript-eslint/dist/index.js';\nexport default [{files:['**/*.js','**/*.mjs','**/*.cjs','**/*.ts','**/*.tsx'],languageOptions:{parser:ts.parser,ecmaVersion:'latest',sourceType:'module',globals:{console:'readonly',process:'readonly',Buffer:'readonly',setTimeout:'readonly',clearTimeout:'readonly',URL:'readonly',module:'readonly',exports:'readonly',require:'readonly',__dirname:'readonly',__filename:'readonly'}},plugins:{'@typescript-eslint':ts.plugin},rules:{'no-undef':'error','no-unreachable':'error','@typescript-eslint/no-unused-vars':['error',{argsIgnorePattern:'^_'}]}}];\n"
        (PRIVATE / "eslint.config.mjs").write_text(config)
        item, stdout, _ = run("eslint", [NODE, TOOLS + "/eslint/bin/eslint.js", "--no-config-lookup", "--config", str(PRIVATE / "eslint.config.mjs"), "--format", "json", *paths])
        for file in json.loads(stdout):
            for diagnostic in file["messages"]:
                R["diagnostics"].append(dict(file=file["filePath"], line=diagnostic.get("line"), column=diagnostic.get("column"), level="error" if diagnostic["severity"] == 2 else "warning", code=diagnostic.get("ruleId"), message=diagnostic["message"], stage="eslint"))
        if item["exit_code"]:
            raise ProcedureError("failed", "ESLint failed")
        return
    suite = P["operation"]["suite"]
    if suite in ("doctest", "custom"):
        raise ProcedureError("unsupported", "Node matrix uses actual node:test discovery; requested harness unsupported")
    candidates = [p for p in P["sources"] if p.endswith((".test.ts", ".test.js", ".test.mjs", ".test.cjs"))]
    if suite == "end_to_end":
        candidates = [p for p in candidates if p.startswith("e2e/")]
    elif suite != "all":
        candidates = [p for p in candidates if not p.startswith("e2e/")]
    if not candidates:
        return
    testpaths = [str((TARGET / p).with_suffix(".js")) if typed else str(ROOT / p) for p in candidates]
    known = None
    for repetition in range(P["operation"]["repetitions"]):
        item, stdout, _ = run(f"node-test:{repetition}", [NODE, "--test", "--test-concurrency=1", "--test-reporter=" + str(PRIVATE / "node_reporter.cjs"), *testpaths])
        states = {}
        files = {}
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                raise ProcedureError("invalid_output", "Node reporter emitted malformed output")
            if event.get("type") not in ("test:pass", "test:fail"):
                continue
            data = event["data"]
            if data.get("details", {}).get("type") == "suite":
                continue
            name = data["name"]
            # An empty test file is a Node file wrapper, not a behavioral test.
            if name in testpaths or str((ROOT / name).resolve()) in testpaths:
                continue
            file = data.get("file", "")
            identity = json.dumps([file, data.get("line"), data.get("column"), data.get("nesting"), data.get("testNumber"), name], ensure_ascii=True)
            if identity in states:
                raise ProcedureError("invalid_output", "duplicate Node test identity")
            states[identity] = "skipped" if data.get("skip") or data.get("todo") else "failed" if event["type"] == "test:fail" else "passed"
            files[identity] = file
        if known is None:
            known = set(states)
            for identity in states:
                add_test("node:test", identity, files[identity])
        if set(states) != known:
            raise ProcedureError("incomplete", "Node runtime discovery changed between explicit repetitions")
        if item["exit_code"] and not any(s == "failed" for s in states.values()):
            raise ProcedureError("failed", "Node process failed without a complete behavioral result")
        R["runs"].extend({"group": "node:test", "id": identity, "status": state, "repetition": repetition} for identity, state in states.items())


try:
    if TARGET.exists() or not same_source():
        raise ProcedureError("source_changed", "fresh target/exact source bytes required")
    {"rust": rust, "python": python, "javascript": javascript, "typescript": javascript}[P["language"]]()
except ProcedureError as exc:
    R["error"] = {"kind": exc.kind, "message": str(exc)}
except Exception as exc:
    R["error"] = {"kind": "invalid_output", "message": type(exc).__name__ + ": " + str(exc)}
finally:
    R["source_unchanged"] = same_source()
    if TARGET.is_dir() and not TARGET.is_symlink():
        shutil.rmtree(TARGET)
sys.stdout.write(json.dumps(R, ensure_ascii=True, separators=(",", ":")))
