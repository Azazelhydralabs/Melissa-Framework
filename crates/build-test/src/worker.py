"""Fixed isolated tool adapter. No host authority, networking, or model argv.

All output, including binary identities and counts, remains developer evidence.
The Rust host checks this protocol and retains the broker's original raw bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tomllib

ROOT = Path.cwd().resolve()
TARGET = ROOT / ".melissa-code06-target"
program = json.loads((ROOT / ".melissa-code06/program.json").read_bytes())
result = {"schema_version": "melissa.rust-build-test/v1", "steps": [],
          "source_unchanged": False, "output_truncated": False,
          "worker_error": None, "artifacts": []}
remaining = program["raw_limit"]


def source_matches():
    return all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
               and (ROOT / name).read_bytes().hex() == value
               for name, value in program["sources"].items())


def run(spec):
    global remaining
    item = dict(spec, exit_code=None, stdout_hex="", stderr_hex="")
    result["steps"].append(item)
    child = subprocess.Popen([spec["executable"], *spec["argv"]],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    sel = selectors.DefaultSelector()
    sel.register(child.stdout, selectors.EVENT_READ, "stdout")
    sel.register(child.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    while sel.get_map():
        for key, _ in sel.select():
            block = os.read(key.fd, 65536)
            if not block:
                sel.unregister(key.fileobj)
                key.fileobj.close()
                continue
            kept = block[:remaining]
            captured[key.data].extend(kept)
            remaining -= len(kept)
            if len(kept) != len(block):
                result["output_truncated"] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    sel.close()
    item["exit_code"] = child.wait()
    for name, data in captured.items():
        item[name + "_hex"] = data.hex()
    return item


try:
    if TARGET.exists() or not source_matches():
        raise ValueError("fresh target and exact source bytes required")
    # A custom harness is outside this stable libtest adapter's support matrix.
    for name in program["sources"]:
        if name.endswith("Cargo.toml"):
            manifest = tomllib.loads((ROOT / name).read_text())
            targets = [manifest.get("lib", {})]
            for kind in ("test", "bin", "example", "bench"):
                targets.extend(manifest.get(kind, []))
            if any(t.get("harness") is False for t in targets):
                raise ValueError("custom test harness unsupported")
    for spec in program["commands"]:
        step = run(spec)
        if step["exit_code"] != 0 or result["output_truncated"]:
            break
        actual = bytes.fromhex(step["stdout_hex"]).decode("utf-8", "strict")
        if spec["stage"] == "rustc-version" and actual.splitlines()[0] != program["expected_rustc"]:
            raise ValueError("pinned rustc mismatch")
        if spec["stage"] == "cargo-version" and actual.strip() != program["expected_cargo"]:
            raise ValueError("pinned cargo mismatch")
    if len(result["steps"]) == 4 and result["steps"][-1]["exit_code"] == 0 and program["repetitions"]:
        # Only actual compiler artifacts in this new target directory are run.
        binaries = set()
        for line in bytes.fromhex(result["steps"][-1]["stdout_hex"]).splitlines():
            try:
                msg = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test") and msg.get("executable"):
                binary = Path(msg["executable"])
                if binary.is_symlink() or not binary.resolve().is_relative_to(TARGET):
                    raise ValueError("test artifact outside fresh target")
                binaries.add(str(binary.resolve()))
        for index, binary in enumerate(sorted(binaries)):
            data = Path(binary).read_bytes()
            identity = {"executable": binary, "worker_reported_sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data)}
            result["artifacts"].append(identity)
            discovery = run({"stage": "discover:" + str(index), "executable": binary,
                             "argv": ["--list", "--format", "terse"]})
            if discovery["exit_code"] != 0 or result["output_truncated"]:
                break
            for repetition in range(program["repetitions"]):
                if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != identity["worker_reported_sha256"]:
                    raise ValueError("binary changed after discovery")
                run({"stage": f"test:{index}:{repetition}", "executable": binary,
                     "argv": ["--format", "pretty", "--color", "never", "--test-threads=1"]})
                if result["output_truncated"]:
                    break
            if result["output_truncated"]:
                break
    result["source_unchanged"] = source_matches()
except Exception as exc:
    # Exception details are tool data, never prompts or permission decisions.
    result["worker_error"] = type(exc).__name__ + ": " + str(exc)
finally:
    # Only this new worker's reserved target is removed, never a host directory.
    # Compiled binaries are not exported as host-trusted installable artifacts.
    if TARGET.is_dir() and not TARGET.is_symlink():
        shutil.rmtree(TARGET)
sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
