//! Loss-aware normalization of UNTRUSTED compiler/libtest output. Exit status,
//! discovered tests, source identity and complete worker evidence all matter.
use crate::{CONTRACT, CommandSpec, RustOperation, RustPlan, unhex};
use melissa_container_executor::TerminationReason;
use melissa_execution_broker::container_broker::ContainerExecution;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
    NoTests,
    Skipped,
    Flaky,
    MissingComponent,
    MissingDependency,
    ToolchainMismatch,
    SourceChanged,
    ArtifactMismatch,
    InvalidOutput,
    Incomplete,
    Cancelled,
    TimedOut,
    ResourceLimit,
    RequiresReconciliation,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DiagnosticSpan {
    pub file: String,
    pub line: u64,
    pub column: u64,
    pub end_line: u64,
    pub end_column: u64,
    pub primary: bool,
    pub source_bound: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Diagnostic {
    pub package_id: String,
    pub target: String,
    pub level: String,
    pub code: Option<String>,
    pub message: String,
    pub spans: Vec<DiagnosticSpan>,
    pub occurrences: u64,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TestCounts {
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
    pub measured: u64,
    pub filtered: u64,
}
#[derive(Debug, Serialize)]
pub struct RawLog {
    pub stage: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout_digest: String,
    pub stderr_digest: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_artifact_id: Option<String>,
    pub stderr_artifact_id: Option<String>,
    #[serde(skip)]
    pub stdout: Vec<u8>,
    #[serde(skip)]
    pub stderr: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct TestRun {
    pub binary: String,
    pub repetition: u16,
    pub counts: TestCounts,
    pub tests: BTreeMap<String, String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerArtifact {
    pub executable: String,
    pub worker_reported_sha256: String,
    pub bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct RustReport {
    pub schema_version: String,
    pub operation: RustOperation,
    pub outcome: Outcome,
    pub source_snapshot_digest: String,
    pub worker_input_digest: String,
    pub worker_image_id: String,
    pub adapter_digest: String,
    pub broker_result_artifact_id: String,
    pub host_source_current: bool,
    pub worker_source_unchanged: bool,
    pub atomic_tree_snapshot: bool,
    pub cache_mode: String,
    pub rustc_version: Option<String>,
    pub cargo_version: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub first_error: Option<Diagnostic>,
    pub discovered_tests: u64,
    pub counts: TestCounts,
    pub test_runs: Vec<TestRun>,
    pub worker_reported_artifacts: Vec<WorkerArtifact>,
    pub raw_logs: Vec<RawLog>,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub protocol_error: Option<String>,
    pub tests_scope: String,
    pub protected_acceptance: bool,
    pub task_completed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: String,
    steps: Vec<Step>,
    source_unchanged: bool,
    output_truncated: bool,
    worker_error: Option<String>,
    artifacts: Vec<WorkerArtifact>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    stage: String,
    executable: String,
    argv: Vec<String>,
    exit_code: i32,
    stdout_hex: String,
    stderr_hex: String,
}

pub(crate) fn analyze(
    plan: &RustPlan,
    execution: &ContainerExecution,
    current: bool,
) -> RustReport {
    let mut r = RustReport {
        schema_version: CONTRACT.into(), operation: plan.operation,
        outcome: Outcome::InvalidOutput, source_snapshot_digest: plan.source.digest.clone(),
        worker_input_digest: plan.snapshot.digest().unwrap_or_default(), worker_image_id: plan.request.image_id.clone(),
        adapter_digest: format!("blake3:{}", blake3::hash(crate::DRIVER.as_bytes()).to_hex()),
        broker_result_artifact_id: execution.result_artifact_id.clone(), host_source_current: current,
        worker_source_unchanged: false, atomic_tree_snapshot: false,
        cache_mode: "fresh worker and fresh private target; offline locked resolution".into(),
        rustc_version: None, cargo_version: None, diagnostics: vec![], first_error: None,
        discovered_tests: 0, counts: TestCounts::default(), test_runs: vec![],
        worker_reported_artifacts: vec![], raw_logs: vec![], truncated: false,
        warnings: vec!["Developer tool output is untrusted; this is not protected acceptance or task completion.".into(),
            "Test scope is stable libtest unit/integration only; doctest/e2e/custom harness remain open.".into()],
        protocol_error: None, tests_scope: "rust.stable-libtest.unit-integration/v1".into(),
        protected_acceptance: false, task_completed: false,
    };
    if execution.requires_reconciliation {
        r.outcome = Outcome::RequiresReconciliation;
        return r;
    }
    let Some(worker) = &execution.report else {
        return invalid(r, "no actual worker report");
    };
    r.truncated = worker.output_truncated || worker.export_truncated;
    if worker.input_digest != r.worker_input_digest || worker.image_id != r.worker_image_id {
        r.outcome = Outcome::ArtifactMismatch;
        return r;
    }
    if !worker.cleanup_confirmed || !worker.tree_confirmed_stopped || !worker.policy_verified {
        r.outcome = Outcome::RequiresReconciliation;
        return r;
    }
    r.outcome = match worker.termination {
        TerminationReason::Exited if worker.exit_code == Some(0) && !r.truncated => {
            Outcome::InvalidOutput
        }
        TerminationReason::Cancelled => Outcome::Cancelled,
        TerminationReason::Timeout => Outcome::TimedOut,
        TerminationReason::CpuLimit
        | TerminationReason::OutputLimit
        | TerminationReason::ExportLimit => Outcome::ResourceLimit,
        _ => Outcome::Incomplete,
    };
    if r.outcome != Outcome::InvalidOutput {
        return r;
    }
    let env: Envelope = match serde_json::from_slice(&worker.stdout) {
        Ok(v) => v,
        Err(_) => return invalid(r, "worker envelope missing, malformed or incomplete"),
    };
    if env.schema_version != CONTRACT {
        return invalid(r, "worker contract version");
    }
    r.worker_source_unchanged = env.source_unchanged;
    r.truncated |= env.output_truncated;
    for step in env.steps {
        let (Some(stdout), Some(stderr)) = (unhex(&step.stdout_hex), unhex(&step.stderr_hex))
        else {
            return invalid(r, "raw tool bytes have invalid encoding");
        };
        r.raw_logs.push(RawLog {
            stage: step.stage,
            executable: step.executable,
            argv: step.argv,
            exit_code: step.exit_code,
            stdout_digest: digest(&stdout),
            stderr_digest: digest(&stderr),
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            stdout,
            stderr,
        });
    }
    r.worker_reported_artifacts = env.artifacts;
    if let Some(error) = env.worker_error {
        r.outcome =
            if error.contains("pinned rustc mismatch") || error.contains("pinned cargo mismatch") {
                Outcome::ToolchainMismatch
            } else {
                Outcome::InvalidOutput
            };
        r.protocol_error = Some(error);
        return r;
    }
    if r.truncated {
        r.outcome = Outcome::Incomplete;
        return r;
    }
    if !current || !r.worker_source_unchanged {
        r.outcome = Outcome::SourceChanged;
        return r;
    }
    if let Err(error) = analyze_tools(plan, &mut r) {
        return invalid(r, error);
    }
    r
}
fn invalid(mut r: RustReport, message: &str) -> RustReport {
    r.outcome = Outcome::InvalidOutput;
    r.protocol_error = Some(message.into());
    r
}
fn digest(b: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(b).to_hex())
}
fn matching(log: &RawLog, spec: &CommandSpec) -> bool {
    log.stage == spec.stage && log.executable == spec.executable && log.argv == spec.argv
}

fn analyze_tools(plan: &RustPlan, r: &mut RustReport) -> std::result::Result<(), &'static str> {
    for (i, spec) in plan.commands.iter().enumerate() {
        let log = r.raw_logs.get(i).ok_or("expected tool stage missing")?;
        if !matching(log, spec) {
            return Err("tool stage/command binding mismatch");
        }
        if i == 0 {
            r.rustc_version = String::from_utf8(log.stdout.clone()).ok();
        }
        if i == 1 {
            r.cargo_version = String::from_utf8(log.stdout.clone()).ok();
        }
        if log.exit_code != 0 {
            if r.raw_logs.len() != i + 1 {
                return Err("unexpected execution after failed prerequisite");
            }
            let error = String::from_utf8_lossy(&log.stderr);
            r.outcome = if error.contains("is not installed") || error.contains("no such command") {
                Outcome::MissingComponent
            } else if error.contains("no matching package") || error.contains("failed to download")
            {
                Outcome::MissingDependency
            } else {
                Outcome::Failed
            };
            if i == 3 && plan.operation != RustOperation::FormatCheck {
                r.diagnostics = diagnostics(
                    &log.stdout,
                    &plan.source.files.iter().map(|f| f.path.as_str()).collect(),
                );
                r.first_error = r.diagnostics.iter().find(|d| d.level == "error").cloned();
            }
            return Ok(());
        }
    }
    if !r
        .rustc_version
        .as_deref()
        .is_some_and(|s| s.lines().next() == Some("rustc 1.98.1 (48a229cea 2026-09-01)"))
        || r.cargo_version.as_deref().map(str::trim) != Some("cargo 1.98.1 (797e8a9bc 2026-08-05)")
    {
        r.outcome = Outcome::ToolchainMismatch;
        return Ok(());
    }
    let metadata: Value =
        serde_json::from_slice(&r.raw_logs[2].stdout).map_err(|_| "invalid metadata JSON")?;
    let packages: BTreeSet<&str> = metadata["packages"]
        .as_array()
        .ok_or("metadata packages missing")?
        .iter()
        .map(|p| p["id"].as_str().ok_or("metadata package identity missing"))
        .collect::<std::result::Result<_, _>>()?;
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("workspace identities missing")?
        .iter()
        .map(|v| v.as_str().ok_or("invalid workspace identity"))
        .collect::<std::result::Result<_, _>>()?;
    if members.is_empty() || !members.is_subset(&packages) {
        return Err("workspace metadata mismatch");
    }
    let source_files: BTreeSet<_> = plan.source.files.iter().map(|f| f.path.as_str()).collect();
    for package in metadata["packages"].as_array().unwrap() {
        if members.contains(package["id"].as_str().unwrap_or_default()) {
            let path = package["manifest_path"]
                .as_str()
                .ok_or("manifest identity missing")?;
            if !source_files.contains(
                path.strip_prefix("/work/")
                    .ok_or("manifest outside source")?,
            ) {
                return Err("manifest absent from captured source");
            }
        }
    }
    if plan.operation == RustOperation::FormatCheck {
        if r.raw_logs.len() != 4 {
            return Err("unexpected format stages");
        }
        r.outcome = Outcome::Passed;
        return Ok(());
    }
    let primary = &r.raw_logs[3];
    r.diagnostics = diagnostics(&primary.stdout, &source_files);
    r.first_error = r.diagnostics.iter().find(|d| d.level == "error").cloned();
    let mut finished = vec![];
    let mut binaries = BTreeSet::new();
    for line in primary.stdout.split(|b| *b == b'\n') {
        let Ok(msg) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        match msg["reason"].as_str() {
            Some("build-finished") => finished.push(msg["success"].as_bool()),
            Some("compiler-artifact") => {
                let package = msg["package_id"]
                    .as_str()
                    .ok_or("compiler artifact package missing")?;
                if !packages.contains(package) || msg["fresh"].as_bool() != Some(false) {
                    return Err("unknown package or unexpected cached compiler artifact");
                }
                if msg["profile"]["test"].as_bool() == Some(true)
                    && let Some(executable) = msg["executable"].as_str()
                {
                    if !members.contains(package) || !target_binary(executable) {
                        return Err("test artifact outside workspace or private target");
                    }
                    binaries.insert(executable.to_string());
                }
            }
            _ => (),
        }
    }
    if finished != [Some(true)] || r.first_error.is_some() {
        return Err("successful command lacks one successful compiler completion");
    }
    let RustOperation::Test { repetitions } = plan.operation else {
        if r.raw_logs.len() != 4 {
            return Err("unexpected build stages");
        }
        r.outcome = Outcome::Passed;
        return Ok(());
    };
    if r.worker_reported_artifacts.len() != binaries.len() {
        return Err("artifact identity count mismatch");
    }
    let mut cursor = 4;
    let mut flaky = false;
    for (index, binary) in binaries.iter().enumerate() {
        let artifact = &r.worker_reported_artifacts[index];
        if &artifact.executable != binary
            || artifact.bytes == 0
            || artifact.worker_reported_sha256.len() != 64
            || !artifact
                .worker_reported_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("binary identity missing or mismatched");
        }
        let discovery = r.raw_logs.get(cursor).ok_or("test discovery missing")?;
        cursor += 1;
        if discovery.stage != format!("discover:{index}")
            || &discovery.executable != binary
            || discovery.argv != ["--list", "--format", "terse"]
            || discovery.exit_code != 0
        {
            return Err("test discovery command failed or mismatched");
        }
        let names = discover(&discovery.stdout)?;
        r.discovered_tests += names.len() as u64;
        let mut previous = None;
        for repetition in 0..repetitions {
            let log = r.raw_logs.get(cursor).ok_or("test repetition missing")?;
            cursor += 1;
            if log.stage != format!("test:{index}:{repetition}")
                || &log.executable != binary
                || log.argv != ["--format", "pretty", "--color", "never", "--test-threads=1"]
            {
                return Err("test binary/stage/argument identity mismatch");
            }
            let (counts, tests) = libtest(&log.stdout, log.exit_code, &names)?;
            if let Some(prev) = &previous {
                flaky |= prev != &tests;
            }
            previous = Some(tests.clone());
            r.counts.passed += counts.passed;
            r.counts.failed += counts.failed;
            r.counts.ignored += counts.ignored;
            r.counts.filtered += counts.filtered;
            r.counts.measured += counts.measured;
            r.test_runs.push(TestRun {
                binary: binary.clone(),
                repetition,
                counts,
                tests,
            });
        }
    }
    if cursor != r.raw_logs.len() {
        return Err("unexpected extra worker execution");
    }
    r.outcome = if flaky {
        Outcome::Flaky
    } else if r.counts.failed != 0 {
        Outcome::Failed
    } else if r.counts.ignored != 0 {
        Outcome::Skipped
    } else if r.discovered_tests == 0 {
        Outcome::NoTests
    } else {
        Outcome::Passed
    };
    Ok(())
}
fn target_binary(path: &str) -> bool {
    path.starts_with("/work/.melissa-code06-target/")
        && !path.split('/').any(|p| matches!(p, "." | ".."))
        && !path.contains(['\\', '\0'])
}

fn discover(bytes: &[u8]) -> std::result::Result<BTreeSet<String>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "discovery encoding")?;
    let mut names = BTreeSet::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let name = line
            .strip_suffix(": test")
            .ok_or("unsupported discovery/harness format")?;
        if name.is_empty() || name.chars().any(char::is_control) || !names.insert(name.into()) {
            return Err("invalid or duplicate discovered test identity");
        }
    }
    Ok(names)
}
fn libtest(
    bytes: &[u8],
    code: i32,
    names: &BTreeSet<String>,
) -> std::result::Result<(TestCounts, BTreeMap<String, String>), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "libtest encoding")?;
    if !text.ends_with('\n') {
        return Err("libtest terminal line is incomplete");
    }
    let summaries: Vec<_> = text
        .lines()
        .filter_map(|l| l.strip_prefix("test result: "))
        .collect();
    if summaries.len() != 1 {
        return Err("missing or ambiguous libtest completion");
    }
    let (status, rest) = summaries[0]
        .split_once(". ")
        .ok_or("invalid libtest completion")?;
    let parts: Vec<_> = rest.split(';').collect();
    let duration = parts
        .last()
        .and_then(|s| s.trim().strip_prefix("finished in "))
        .and_then(|s| s.strip_suffix('s'))
        .and_then(|s| s.parse::<f64>().ok());
    if parts.len() != 6 || !duration.is_some_and(|v| v.is_finite() && v >= 0.0) {
        return Err("libtest terminal summary is incomplete");
    }
    let mut values = Vec::new();
    for (part, suffix) in rest.split(';').take(5).zip([
        " passed",
        " failed",
        " ignored",
        " measured",
        " filtered out",
    ]) {
        let value = part
            .trim()
            .strip_suffix(suffix)
            .ok_or("invalid libtest counters")?;
        values.push(value.parse::<u64>().map_err(|_| "invalid libtest count")?);
    }
    if values.len() != 5 {
        return Err("incomplete libtest counters");
    }
    let counts = TestCounts {
        passed: values[0],
        failed: values[1],
        ignored: values[2],
        measured: values[3],
        filtered: values[4],
    };
    if counts.measured != 0
        || counts.filtered != 0
        || counts
            .passed
            .checked_add(counts.failed)
            .and_then(|v| v.checked_add(counts.ignored))
            != Some(names.len() as u64)
        || ((code == 0 && status == "ok") != (counts.failed == 0))
        || (code != 0 && (status != "FAILED" || counts.failed == 0))
    {
        return Err("exit/counters/discovery disagree or tests were filtered");
    }
    let mut tests = BTreeMap::new();
    for line in text.lines().filter_map(|l| l.strip_prefix("test ")) {
        let Some((name, state)) = line.rsplit_once(" ... ") else {
            continue;
        };
        let state = match state {
            "ok" => "passed",
            "FAILED" => "failed",
            s if s == "ignored" || s.starts_with("ignored, ") => "ignored",
            _ => return Err("unsupported test state"),
        };
        if !names.contains(name) || tests.insert(name.into(), state.into()).is_some() {
            return Err("unknown or duplicate executed test");
        }
    }
    for (state, count) in [
        ("passed", counts.passed),
        ("failed", counts.failed),
        ("ignored", counts.ignored),
    ] {
        if tests
            .values()
            .filter(|v: &&String| v.as_str() == state)
            .count() as u64
            != count
        {
            return Err("test identities and counters disagree");
        }
    }
    if tests.len() != names.len() {
        return Err("a discovered test was not reported");
    }
    Ok((counts, tests))
}

fn diagnostics(bytes: &[u8], sources: &BTreeSet<&str>) -> Vec<Diagnostic> {
    let mut result: Vec<Diagnostic> = vec![];
    let mut exact_index: BTreeMap<Diagnostic, usize> = BTreeMap::new();
    for line in bytes.split(|b| *b == b'\n') {
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if value["reason"] != "compiler-message" {
            continue;
        }
        let msg = &value["message"];
        let mut diagnostic = Diagnostic {
            package_id: value["package_id"].as_str().unwrap_or_default().into(),
            target: value["target"]["name"].as_str().unwrap_or_default().into(),
            level: msg["level"].as_str().unwrap_or("unknown").into(),
            code: msg["code"]["code"].as_str().map(str::to_string),
            message: msg["message"].as_str().unwrap_or_default().into(),
            spans: vec![],
            occurrences: 1,
        };
        if let Some(spans) = msg["spans"].as_array() {
            for span in spans {
                let file = span["file_name"].as_str().unwrap_or_default();
                let relative = file.strip_prefix("/work/").unwrap_or(file);
                diagnostic.spans.push(DiagnosticSpan {
                    file: file.into(),
                    line: span["line_start"].as_u64().unwrap_or(0),
                    column: span["column_start"].as_u64().unwrap_or(0),
                    end_line: span["line_end"].as_u64().unwrap_or(0),
                    end_column: span["column_end"].as_u64().unwrap_or(0),
                    primary: span["is_primary"].as_bool().unwrap_or(false),
                    source_bound: sources.contains(relative),
                });
            }
        }
        if let Some(index) = exact_index.get(&diagnostic) {
            result[*index].occurrences += 1;
        } else {
            exact_index.insert(diagnostic.clone(), result.len());
            result.push(diagnostic);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_and_execution_require_exact_names_counts_exit_and_single_completion() {
        let names = discover(b"math::ok: test\n").unwrap();
        let output = b"\nrunning 1 test\ntest math::ok ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n";
        assert_eq!(libtest(output, 0, &names).unwrap().0.passed, 1);
        assert!(libtest(output, 1, &names).is_err());
        assert!(libtest(&output[..output.len() / 2], 0, &names).is_err());
        assert!(libtest(&output[..output.len() - 2], 0, &names).is_err());
        assert!(libtest(b"test math::ok ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",0,&names).is_err());
        assert!(libtest(&[output.as_slice(), output.as_slice()].concat(), 0, &names).is_err());
        assert!(libtest(output, 0, &BTreeSet::from(["another::ok".into()])).is_err());
        assert!(discover(b"a: test\na: test\n").is_err());
        assert!(discover(b"a: benchmark\n").is_err());
    }
    #[test]
    fn zero_tests_and_ignored_are_visible_but_filtered_or_spoofed_counts_are_rejected() {
        let zero = b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(libtest(zero, 0, &BTreeSet::new()).unwrap().0.passed, 0);
        assert!(libtest(zero, 0, &BTreeSet::from(["a".into()])).is_err());
        let skipped = b"test a ... ignored, reason\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(
            libtest(skipped, 0, &BTreeSet::from(["a".into()]))
                .unwrap()
                .0
                .ignored,
            1
        );
        assert!(libtest(b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n", 0, &BTreeSet::new()).is_err());
        assert!(libtest(b"test result: ok. 18446744073709551615 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 0, &BTreeSet::new()).is_err());
    }
    #[test]
    fn diagnostics_group_only_identical_package_target_and_source_locations() {
        let value = serde_json::json!({"reason":"compiler-message","package_id":"pkg:a","target":{"name":"lib"},"message":{"level":"error","code":{"code":"E0308"},"message":"mismatched types α","spans":[{"file_name":"src/lib.rs","line_start":2,"column_start":3,"line_end":2,"column_end":4,"is_primary":true}]}});
        let mut other = value.clone();
        other["message"]["spans"][0]["line_start"] = 8.into();
        let mut foreign = value.clone();
        foreign["message"]["spans"][0]["file_name"] = "/host/secret.rs".into();
        let lines = [value.clone(), value, other, foreign]
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let result = diagnostics(lines.as_bytes(), &BTreeSet::from(["src/lib.rs"]));
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].occurrences, 2);
        assert!(result[0].spans[0].source_bound);
        assert!(!result[2].spans[0].source_bound);
        assert!(!target_binary("/work/.melissa-code06-target/../evil"));
    }
}
