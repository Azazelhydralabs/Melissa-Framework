"""Private fixed pytest reporter; project tests remain untrusted code."""
import json
from pathlib import Path
import sys
import pytest

request = json.loads(Path(sys.argv[1]).read_bytes())
destination = Path(sys.argv[2])
collect = sys.argv[3] == "collect"
report = {"schema_version": "melissa.pytest-results/v1", "collected": [],
          "results": {}, "collection_errors": [], "exit_code": None}


class Reporter:
    def pytest_collection_finish(self, session):
        report["collected"] = [{"id": item.nodeid, "file": str(item.path)} for item in session.items]

    def pytest_collectreport(self, report):
        if report.failed:
            globals()["report"]["collection_errors"].append(str(report.longrepr))

    def pytest_runtest_logreport(self, report):
        # Setup/teardown errors and xfail/skip can never be overwritten by a
        # later successful phase. Pytest reports these phases independently.
        item = report
        output = globals()["report"]
        previous = output["results"].get(item.nodeid)
        state = "failed" if item.failed else "skipped" if item.skipped else "passed"
        if state == "failed" or (state == "skipped" and previous != "failed"):
            output["results"][item.nodeid] = state
        elif item.when == "call" and previous not in ("failed", "skipped"):
            output["results"][item.nodeid] = state


args = ["-c", "/dev/null", "--rootdir=/work", "--color=no", "-q",
        "-o", "cache_dir=/work/.melissa-code06-v2/pytest-cache",
        "-o", "pythonpath=/work/src"]
if collect:
    args.append("--collect-only")
if request["doctest"]:
    args.append("--doctest-modules")
args.extend(request["paths"])
try:
    code = int(pytest.main(args, plugins=[Reporter()]))
    report["exit_code"] = code
finally:
    destination.write_text(json.dumps(report, ensure_ascii=True), encoding="utf-8")
raise SystemExit(code)
