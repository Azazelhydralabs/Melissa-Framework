//! Deterministic common-script library. IO/native operations require an explicit
//! host backend; parsing observations never authenticates their semantic truth.
use crate::{Error, Result, digest, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, Read},
};
pub const IDS: [&str; 21] = [
    "inspect_environment",
    "summarize_logs",
    "extract_stacktraces",
    "find_duplicate_errors",
    "parse_compiler_diagnostics",
    "build_symbol_index",
    "dependency_graph",
    "generate_patch_preview",
    "run_targeted_tests",
    "compare_artifacts",
    "detect_environment_drift",
    "normalize_tool_output",
    "redact_secrets",
    "compact_context",
    "extract_structured_data",
    "validate_json_schema",
    "benchmark_runner",
    "trace_analyzer",
    "cost_report",
    "evidence_manifest",
    "artifact_cleanup",
];
pub fn native(id: &str) -> bool {
    matches!(
        id,
        "inspect_environment"
            | "build_symbol_index"
            | "dependency_graph"
            | "run_targeted_tests"
            | "generate_patch_preview"
            | "artifact_cleanup"
    )
}
fn field<'a>(x: &'a Value, k: &str) -> Result<&'a Value> {
    x.get(k)
        .ok_or_else(|| Error(format!("missing script input {k}")))
}
fn text<'a>(x: &'a Value, k: &str) -> Result<&'a str> {
    field(x, k)?
        .as_str()
        .ok_or_else(|| Error(format!("script {k} must be text")))
}
fn array<'a>(x: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    field(x, k)?
        .as_array()
        .ok_or_else(|| Error(format!("script {k} must be array")))
}
pub fn summarize<R: BufRead>(mut reader: R) -> Result<Value> {
    let mut total = 0u64;
    let mut errors = 0u64;
    let mut groups: BTreeMap<String, u64> = BTreeMap::new();
    let mut traces = Vec::new();
    let mut current = Vec::new();
    loop {
        let mut line = String::new();
        let n = Read::by_ref(&mut reader)
            .take(8 * 1024 * 1024 + 1)
            .read_line(&mut line)
            .map_err(|_| Error("log read failed".into()))?;
        if n == 0 {
            break;
        }
        require(
            n <= 8 * 1024 * 1024,
            "log line exceeds declared parser resource bound",
        )?;
        total += 1;
        let lower = line.to_lowercase();
        if lower.contains("error") || lower.contains("exception") || lower.contains("fatal") {
            errors += 1;
            *groups
                .entry(line.trim_end_matches(['\r', '\n']).into())
                .or_default() += 1;
        }
        if lower.contains("traceback")
            || lower.contains("exception")
            || line.trim_start().starts_with("at ")
            || line.trim_start().starts_with("File ")
        {
            current.push(line.trim_end().to_string());
        } else if !current.is_empty() {
            traces.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        traces.push(current);
    }
    Ok(
        json!({"total_lines":total,"error_lines":errors,"groups":groups,"stacktraces":traces,"parse_coverage":"error_candidates_only_not_a_build_oracle","truncated":false}),
    )
}

/// Versioned wire schema for each common purpose. Native registrations may narrow this to {}.
pub fn input_schema(id: &str) -> Result<Value> {
    require(IDS.contains(&id), "unknown script schema")?;
    let fields: Vec<(&str, Value)> = match id {
        "summarize_logs"
        | "extract_stacktraces"
        | "find_duplicate_errors"
        | "parse_compiler_diagnostics" => vec![("text", json!({"type":"string"}))],
        "compare_artifacts" => vec![
            (
                "left",
                json!({"type":"object","properties":{"digest":{"type":"string"},"bytes":{"type":"integer","minimum":0},"metadata":{"type":"object"}},"required":["digest","bytes","metadata"],"additionalProperties":false}),
            ),
            (
                "right",
                json!({"type":"object","properties":{"digest":{"type":"string"},"bytes":{"type":"integer","minimum":0},"metadata":{"type":"object"}},"required":["digest","bytes","metadata"],"additionalProperties":false}),
            ),
        ],
        "detect_environment_drift" => vec![
            ("baseline", json!({"type":"object"})),
            ("current", json!({"type":"object"})),
        ],
        "normalize_tool_output" => vec![
            ("status", json!({"type":"string"})),
            ("exit_code", json!({"type":["integer","null"]})),
            ("truncated", json!({"type":"boolean"})),
            ("raw_ref", json!({"type":"string"})),
            ("metrics", json!({"type":"object"})),
            ("warnings", json!({"type":"array"})),
        ],
        "redact_secrets" => vec![
            ("text", json!({"type":"string"})),
            (
                "secrets",
                json!({"type":"array","items":{"type":"string","minLength":1}}),
            ),
        ],
        "compact_context" => vec![
            ("required", json!({"type":"array"})),
            ("rejected_hypotheses", json!({"type":"array"})),
            ("open_issues", json!({"type":"array"})),
            ("authorization_ref", json!({"type":"string"})),
            ("remaining_budget", json!({})),
            ("raw_refs", json!({"type":"array"})),
        ],
        "extract_structured_data" => vec![
            ("rows", json!({"type":"array"})),
            ("columns", json!({"type":"array","minItems":1})),
            ("source_region", json!({})),
            ("units", json!({})),
        ],
        "validate_json_schema" => vec![("schema", json!({"type":"object"})), ("value", json!({}))],
        "benchmark_runner" => vec![
            ("task_set_digest", json!({"type":"string"})),
            ("runs", json!({"type":"array","minItems":1})),
        ],
        "trace_analyzer" => vec![
            ("steps", json!({"type":"array"})),
            ("raw_trace_ref", json!({"type":"string"})),
        ],
        "cost_report" => vec![("entries", json!({"type":"array"}))],
        "evidence_manifest" => vec![
            ("artifacts", json!({"type":"array"})),
            ("final_source_digest", json!({"type":"string"})),
        ],
        _ => vec![],
    };
    let required = fields.iter().map(|(k, _)| *k).collect::<Vec<_>>();
    let mut properties = fields
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect::<serde_json::Map<_, _>>();
    if id == "compact_context" {
        properties.insert("optional_summary".into(), json!({}));
    }
    Ok(
        json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
    )
}
pub fn template_schema(category: &str) -> Result<Value> {
    require(
        TEMPLATE_CATEGORIES.contains(&category),
        "unknown template schema",
    )?;
    let fields: &[&str] = match category {
        "task_plan" => &["goal", "acceptance", "steps", "risks"],
        "code_review" => &["source_digest", "findings", "counterexamples", "evidence"],
        "bugfix" => &["reproducer", "root_cause", "patch_scope", "regression"],
        "pull_request" => &["problem", "behavior", "changes", "validation"],
        "research" => &["question", "sources", "findings", "uncertainties"],
        "report" => &["task", "observations", "evidence", "open_issues"],
        _ => &[
            "dataset",
            "source_regions",
            "units",
            "method",
            "results",
            "limitations",
        ],
    };
    let props = fields
        .iter()
        .map(|k| (k.to_string(), json!({})))
        .collect::<serde_json::Map<_, _>>();
    Ok(json!({"type":"object","properties":props,"required":fields,"additionalProperties":false}))
}
pub fn execute(id: &str, input: &Value) -> Result<Value> {
    require(
        input.is_object() && IDS.contains(&id),
        "unknown script or non-object input",
    )?;
    require(
        !native(id),
        "script requires its registered native host backend",
    )?;
    melissa_model_gateway::schema::validate_output(
        &input_schema(id)?,
        &serde_json::to_string(input)?,
    )
    .map_err(|e| Error(e.to_string()))?;
    let data = match id {
        "summarize_logs" | "extract_stacktraces" | "find_duplicate_errors" => {
            summarize(std::io::Cursor::new(text(input, "text")?.as_bytes()))?
        }
        "parse_compiler_diagnostics" => {
            let raw = text(input, "text")?;
            let mut parsed = Vec::new();
            let mut unknown = Vec::new();
            for (line_no, line) in raw.lines().enumerate() {
                match crate::json::<Value>(line.as_bytes()) {
                    Ok(v) if v["reason"] == "compiler-message" || v.get("message").is_some() => {
                        parsed.push(json!({"line":line_no+1,"diagnostic":v}))
                    }
                    _ => unknown.push(json!({"line":line_no+1,"text":line})),
                }
            }
            json!({"diagnostics":parsed,"unparsed":unknown,"complete":unknown.is_empty(),"status":"unverified"})
        }
        "compare_artifacts" => {
            let a = field(input, "left")?;
            let b = field(input, "right")?;
            json!({"bytes_equal":a["digest"]==b["digest"]&&a["bytes"]==b["bytes"],"metadata_equal":a["metadata"]==b["metadata"],"left":a,"right":b})
        }
        "detect_environment_drift" => {
            let a = field(input, "baseline")?
                .as_object()
                .ok_or_else(|| Error("baseline object".into()))?;
            let b = field(input, "current")?
                .as_object()
                .ok_or_else(|| Error("current object".into()))?;
            let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
            let changes = keys
                .into_iter()
                .filter(|k| a.get(*k) != b.get(*k))
                .map(|k| json!({"key":k,"before":a.get(k),"after":b.get(k)}))
                .collect::<Vec<_>>();
            json!({"changed":!changes.is_empty(),"changes":changes})
        }
        "normalize_tool_output" => {
            for k in [
                "status",
                "exit_code",
                "truncated",
                "raw_ref",
                "metrics",
                "warnings",
            ] {
                field(input, k)?;
            }
            require(
                input["truncated"].is_boolean()
                    && input["metrics"].is_object()
                    && input["warnings"].is_array(),
                "malformed observation flags",
            )?;
            json!({"status":input["status"],"exit_code":input["exit_code"],"truncated":input["truncated"],"raw_ref":input["raw_ref"],"metrics":input["metrics"],"warnings":input["warnings"],"verified":false})
        }
        "redact_secrets" => {
            let mut s = text(input, "text")?.to_string();
            let secrets = array(input, "secrets")?;
            let mut replaced = 0;
            for value in secrets {
                let secret = value
                    .as_str()
                    .ok_or_else(|| Error("secret must be text".into()))?;
                require(!secret.is_empty(), "empty redaction secret")?;
                replaced += s.matches(secret).count();
                s = s.replace(secret, "[REDACTED]");
            }
            // Also cover common labelled lines without returning secret values.
            let lines = s
                .lines()
                .map(|line| {
                    if let Some((key, _)) = line.split_once('=')
                        && ["api_key", "password", "secret", "access_token"]
                            .contains(&key.trim().to_ascii_lowercase().as_str())
                    {
                        replaced += 1;
                        format!("{key}=[REDACTED]")
                    } else {
                        line.into()
                    }
                })
                .collect::<Vec<_>>();
            json!({"text":lines.join("\n"),"replacements":replaced,"coverage":"explicit_secrets_and_labelled_values","unknown_secret_patterns":"not_claimed"})
        }
        "compact_context" => {
            let required = array(input, "required")?;
            for item in required {
                for k in ["id", "source_ref", "digest", "outcome"] {
                    field(item, k)?;
                }
            }
            json!({"required":required,"rejected_hypotheses":array(input,"rejected_hypotheses")?,"open_issues":array(input,"open_issues")?,"authorization_ref":text(input,"authorization_ref")?,"remaining_budget":field(input,"remaining_budget")?,"raw_refs":array(input,"raw_refs")?,"optional_summary":input.get("optional_summary"),"required_items_truncated":false})
        }
        "extract_structured_data" => {
            let rows = array(input, "rows")?;
            let columns = array(input, "columns")?;
            let width = columns.len();
            require(
                width > 0
                    && rows
                        .iter()
                        .all(|r| r.as_array().is_some_and(|r| r.len() == width)),
                "ragged structured table",
            )?;
            json!({"columns":columns,"rows":rows,"source_region":field(input,"source_region")?,"units":field(input,"units")?,"lossy":false})
        }
        "validate_json_schema" => {
            let schema = field(input, "schema")?;
            let value = field(input, "value")?;
            melissa_model_gateway::schema::validate_schema(schema)
                .map_err(|e| Error(e.to_string()))?;
            let valid = melissa_model_gateway::schema::validate_output(
                schema,
                &serde_json::to_string(value)?,
            )
            .is_ok();
            json!({"shape_valid":valid,"semantic_truth_verified":false})
        }
        "benchmark_runner" => {
            let runs = array(input, "runs")?;
            require(!runs.is_empty(), "empty benchmark")?;
            let reference = text(input, "task_set_digest")?;
            for r in runs {
                for k in [
                    "model",
                    "tool_version",
                    "environment_digest",
                    "repeat",
                    "outcome",
                    "elapsed_ms",
                    "input_digest",
                ] {
                    field(r, k)?;
                }
                require(
                    r["task_set_digest"] == reference,
                    "unmatched benchmark task set",
                )?;
            }
            json!({"task_set_digest":reference,"runs":runs,"count":runs.len(),"status":"unverified_measurements","comparison_requires_matched_budget":true})
        }
        "trace_analyzer" => {
            let trace = array(input, "steps")?;
            let findings=trace.iter().enumerate().filter(|(_,s)|s["status"]!="success").map(|(i,s)|json!({"step":i,"status":s["status"],"raw_ref":s["raw_ref"],"hypothesis":s.get("hypothesis"),"hypothesis_is_fact":false})).collect::<Vec<_>>();
            json!({"findings":findings,"raw_trace_ref":text(input,"raw_trace_ref")?})
        }
        "cost_report" => {
            let entries = array(input, "entries")?;
            let mut known = 0u64;
            let mut unknown = Vec::new();
            for e in entries {
                if let Some(n) = e["cost_micro_usd"].as_u64() {
                    known = known
                        .checked_add(n)
                        .ok_or_else(|| Error("cost overflow".into()))?;
                } else {
                    unknown.push(e["id"].clone());
                }
            }
            json!({"known_micro_usd":known,"unknown_ids":unknown,"complete":unknown.is_empty(),"entries":entries})
        }
        "evidence_manifest" => {
            let artifacts = array(input, "artifacts")?;
            let mut ids = BTreeSet::new();
            for a in artifacts {
                require(ids.insert(text(a, "id")?), "duplicate evidence identity")?;
                for k in [
                    "input_digest",
                    "output_digest",
                    "verifier_digest",
                    "source_ref",
                ] {
                    text(a, k)?;
                }
            }
            json!({"artifacts":artifacts,"final_source_digest":text(input,"final_source_digest")?,"accepted":false})
        }
        _ => return Err(Error("script implementation unavailable".into())),
    };
    Ok(
        json!({"schema_version":"melissa.common-script-observation/v1","script":id,"input_digest":digest(&serde_json::to_vec(input)?),"data":data,"authority":"untrusted_observation","protected_acceptance":false}),
    )
}

pub const TEMPLATE_CATEGORIES: [&str; 7] = [
    "task_plan",
    "code_review",
    "bugfix",
    "pull_request",
    "research",
    "report",
    "data_analysis",
];
/// Versioned, single-pass structured template factory. No filesystem write.
pub fn template(category: &str, input: &Value) -> Result<Value> {
    require(
        TEMPLATE_CATEGORIES.contains(&category) && input.is_object(),
        "unknown template category",
    )?;
    let required: &[&str] = match category {
        "task_plan" => &["goal", "acceptance", "steps", "risks"],
        "code_review" => &["source_digest", "findings", "counterexamples", "evidence"],
        "bugfix" => &["reproducer", "root_cause", "patch_scope", "regression"],
        "pull_request" => &["problem", "behavior", "changes", "validation"],
        "research" => &["question", "sources", "findings", "uncertainties"],
        "report" => &["task", "observations", "evidence", "open_issues"],
        _ => &[
            "dataset",
            "source_regions",
            "units",
            "method",
            "results",
            "limitations",
        ],
    };
    let map = input.as_object().expect("checked");
    require(
        map.len() == required.len() && required.iter().all(|k| map.contains_key(*k)),
        "missing or undeclared template input",
    )?;
    Ok(
        json!({"schema_version":"melissa.template-output/v1","template_id":format!("melissa.code.{category}"),"template_version":"1.0.0","input_digest":digest(&serde_json::to_vec(input)?),"fields":input,"verified":false}),
    )
}

/// Strategy is an implementation choice, never a permission grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    InlineData,
    ReviewedPackageHelper,
    NativeService,
}
pub fn strategy(id: &str, repeated: bool) -> Result<Strategy> {
    require(IDS.contains(&id), "unknown purpose")?;
    Ok(if native(id) {
        Strategy::NativeService
    } else if repeated {
        Strategy::ReviewedPackageHelper
    } else {
        Strategy::InlineData
    })
}

/// Blueprint's nine first-choice execution strategies. Dispatch still requires native host grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskClass {
    JsonValidation,
    LogParsing,
    LargeFileSearch,
    MathematicalCalculation,
    UnknownCodingProblem,
    StandardDataTransformation,
    NewAlgorithm,
    SecurityFindingGrouping,
    GameBuild,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredRoute {
    Validator,
    Parser,
    IndexedSearch,
    DeterministicSolver,
    CodingAgent,
    RegisteredScript,
    ModelAndRealTests,
    ParserRulesAndAgent,
    NativeEngineTools,
}
pub fn preferred_route(class: TaskClass) -> PreferredRoute {
    use PreferredRoute::*;
    use TaskClass::*;
    match class {
        JsonValidation => Validator,
        LogParsing => Parser,
        LargeFileSearch => IndexedSearch,
        MathematicalCalculation => DeterministicSolver,
        UnknownCodingProblem => CodingAgent,
        StandardDataTransformation => RegisteredScript,
        NewAlgorithm => ModelAndRealTests,
        SecurityFindingGrouping => ParserRulesAndAgent,
        GameBuild => NativeEngineTools,
    }
}
