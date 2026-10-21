#![cfg(windows)]
mod support;
use melissa_build_test::{
    RustOperation,
    full::{
        HarnessRegistration, Language, Operation, ProcedurePlan, ProcedureReport, Status,
        TestSuite, digest,
    },
};
use std::sync::atomic::AtomicBool;
fn execute(
    language: Language,
    operation: Operation,
    files: &[(&str, &str)],
    harness: Option<&HarnessRegistration>,
) -> ProcedureReport {
    let mut f = support::Fixture::new(
        "pub fn sum(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        RustOperation::Build,
        files,
        support::limits(),
    );
    let source = f.repo.snapshot(&support::no()).unwrap();
    let p = ProcedurePlan::prepare(
        &f.repo,
        &source,
        language,
        operation,
        harness,
        support::limits(),
        &support::no(),
    )
    .unwrap();
    let permit = support::permit_for(&mut f, p.request(), p.snapshot());
    let r = p
        .execute(
            &f.repo,
            &mut f.broker,
            &f.task.task_id,
            &permit,
            &support::identity(),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(!r.execution.requires_reconciliation, "{:?}", r.report);
    assert!(!r.report.task_completed && !r.report.protected_acceptance);
    if let Some(d) = &r.report.details {
        for step in &d.steps {
            if step.exit_code != 0 {
                eprintln!(
                    "{} stdout={} stderr={}",
                    step.stage,
                    String::from_utf8_lossy(&decode(&step.stdout_hex)),
                    String::from_utf8_lossy(&decode(&step.stderr_hex))
                );
            }
        }
    }
    r.report
}
fn decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn passed(r: ProcedureReport) {
    assert_eq!(
        r.status,
        Status::Passed,
        "{}",
        serde_json::to_string_pretty(&r).unwrap()
    );
}
#[test]
fn actual_complete_image_runs_clippy_rustfmt_and_final_source_compile() {
    for operation in [
        Operation::Build {},
        Operation::Check {},
        Operation::Lint {},
        Operation::FormatCheck {},
    ] {
        passed(execute(Language::Rust, operation, &[], None));
    }
}
#[test]
fn actual_python_compiler_pyright_ruff_and_repeated_pytest_are_source_bound() {
    let files = [
        (
            "src/calc.py",
            "def add(a: int, b: int) -> int:\n    return a + b\n",
        ),
        (
            "tests/test_calc.py",
            "from calc import add\n\n\ndef test_add() -> None:\n    assert add(2, 3) == 5\n",
        ),
    ];
    for operation in [
        Operation::Build {},
        Operation::Check {},
        Operation::Lint {},
        Operation::FormatCheck {},
        Operation::Test {
            suite: TestSuite::UnitIntegration,
            repetitions: 2,
        },
    ] {
        passed(execute(Language::Python, operation, &files, None));
    }
}
#[test]
fn actual_javascript_and_typescript_compile_check_lint_format_and_node_tests() {
    for (language, extension, body) in [
        (
            Language::JavaScript,
            "js",
            "export function add(a, b) {\n  return a + b;\n}\n",
        ),
        (
            Language::TypeScript,
            "ts",
            "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
        ),
    ] {
        let source = format!("src/calc.{extension}");
        let test = format!("tests/calc.test.{extension}");
        let source_body = if language == Language::JavaScript {
            "/** @param {number} a @param {number} b */\nexport function add(a, b) {\n  return a + b;\n}\n"
        } else {
            body
        };
        let test_body = "import { test } from \"node:test\";\nimport { strict as assert } from \"node:assert\";\nimport { add } from \"../src/calc.js\";\n\ntest(\"actual public behavior\", () => {\n  assert.equal(add(2, 3), 5);\n});\n";
        let files = [
            ("package.json", "{\"type\":\"module\"}\n"),
            (source.as_str(), source_body),
            (test.as_str(), test_body),
        ];
        for operation in [
            Operation::Build {},
            Operation::Check {},
            Operation::Lint {},
            Operation::FormatCheck {},
            Operation::Test {
                suite: TestSuite::UnitIntegration,
                repetitions: 2,
            },
        ] {
            passed(execute(language, operation, &files, None));
        }
    }
}
#[test]
fn actual_rust_and_python_doctests_are_discovered_and_executed() {
    let rust = "/// Addition.\n///\n/// ```\n/// assert_eq!(code06_fixture::sum(2, 3), 5);\n/// ```\npub fn sum(a: i32, b: i32) -> i32 { a + b }\n";
    passed(execute(
        Language::Rust,
        Operation::Test {
            suite: TestSuite::Doctest,
            repetitions: 2,
        },
        &[("src/lib.rs", rust)],
        None,
    ));
    let py = "def add(a: int, b: int) -> int:\n    \"\"\"Add numbers.\n\n    >>> add(2, 3)\n    5\n    \"\"\"\n    return a + b\n";
    passed(execute(
        Language::Python,
        Operation::Test {
            suite: TestSuite::Doctest,
            repetitions: 2,
        },
        &[("src/calc.py", py)],
        None,
    ));
}
#[test]
fn actual_python_and_node_zero_skip_and_flaky_results_never_pass() {
    for (language, files, expected) in [
        (
            Language::Python,
            vec![("tests/test_empty.py", "def helper():\n    return 1\n")],
            Status::NoTests,
        ),
        (
            Language::Python,
            vec![(
                "tests/test_skip.py",
                "import pytest\n@pytest.mark.skip(reason='offline fixture')\ndef test_skip():\n    assert False\n",
            )],
            Status::Skipped,
        ),
        (
            Language::Python,
            vec![(
                "tests/test_flake.py",
                "from pathlib import Path\ndef test_flake():\n    p = Path('/work/.flake')\n    if not p.exists():\n        p.write_text('first')\n        assert False\n",
            )],
            Status::Flaky,
        ),
        (
            Language::JavaScript,
            vec![("tests/empty.test.js", "// no tests\n")],
            Status::NoTests,
        ),
        (
            Language::JavaScript,
            vec![(
                "tests/skip.test.js",
                "const {test}=require('node:test');test.skip('skipped',()=>{});\n",
            )],
            Status::Skipped,
        ),
        (
            Language::JavaScript,
            vec![(
                "tests/flake.test.js",
                "const{test}=require('node:test');const fs=require('node:fs');test('flaky',()=>{if(!fs.existsSync('/work/.flake')){fs.writeFileSync('/work/.flake','first');throw Error('first');}});\n",
            )],
            Status::Flaky,
        ),
    ] {
        let r = execute(
            language,
            Operation::Test {
                suite: TestSuite::UnitIntegration,
                repetitions: 2,
            },
            &files,
            None,
        );
        assert_eq!(r.status, expected, "{:?}", r);
    }
}
#[test]
fn real_compiler_and_type_failures_keep_raw_diagnostics() {
    for (language, files, operation) in [
        (
            Language::Python,
            vec![("src/bad.py", "def broken(:\n")],
            Operation::Build {},
        ),
        (
            Language::Python,
            vec![("src/bad.py", "def answer() -> int:\n    return 'wrong'\n")],
            Operation::Check {},
        ),
        (
            Language::TypeScript,
            vec![("src/bad.ts", "export const answer: number = 'wrong';\n")],
            Operation::Check {},
        ),
        (
            Language::JavaScript,
            vec![
                ("src/bad.js", "export function broken( {\n"),
                ("package.json", "{\"type\":\"module\"}"),
            ],
            Operation::Build {},
        ),
    ] {
        let r = execute(language, operation, &files, None);
        assert_eq!(r.status, Status::Failed, "{:?}", r);
        assert!(!r.raw_artifact_ids.is_empty());
    }
}
#[test]
fn host_registered_rust_custom_harness_is_version_and_source_bound() {
    let custom = "fn main(){let arg=std::env::args().nth(1).unwrap();if arg==\"--melissa-list\"{println!(\"{}\",r#\"{\"schema_version\":\"melissa.harness-list/v1\",\"tests\":[\"real_arithmetic\"]}\"#);}else{let passed=6*7==42;let status=if passed{\"passed\"}else{\"failed\"};println!(\"{{\\\"schema_version\\\":\\\"melissa.harness-results/v1\\\",\\\"results\\\":[{{\\\"id\\\":\\\"real_arithmetic\\\",\\\"status\\\":\\\"{}\\\"}}]}}\",status);if !passed{std::process::exit(1);}}}\n";
    let manifest = "[package]\nname=\"code06_fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[[test]]\nname=\"custom\"\npath=\"tests/custom.rs\"\nharness=false\n";
    let h = HarnessRegistration {
        id: "harness:owned".into(),
        version: "1.0.0".into(),
        target: "custom".into(),
        source_path: "tests/custom.rs".into(),
        source_digest: digest(custom.as_bytes()),
    };
    passed(execute(
        Language::Rust,
        Operation::Test {
            suite: TestSuite::Custom,
            repetitions: 2,
        },
        &[("Cargo.toml", manifest), ("tests/custom.rs", custom)],
        Some(&h),
    ));
}
