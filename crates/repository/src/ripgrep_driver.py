"""Read-only transport adapter in the owned immutable worker."""
import json
import subprocess

query = json.load(open(".melissa-analysis/request.json", encoding="utf-8"))
result = subprocess.run(["/usr/local/cargo/bin/rg", "--json", "--no-config", "--no-ignore",
                         "--hidden", "--text", "--fixed-strings", "--glob", "!.melissa-analysis/**",
                         "--", query["needle"], "."], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env={"PATH": "/usr/bin:/bin", "HOME": "/work"}, timeout=45)
if result.returncode not in (0, 1):
    raise RuntimeError("ripgrep failed: " + str(result.returncode))
events = [json.loads(line) for line in result.stdout.splitlines()]
print(json.dumps({"schema_version": "melissa.ripgrep-worker-result/v1",
                  "exit_code": result.returncode, "events": events}, ensure_ascii=False))
