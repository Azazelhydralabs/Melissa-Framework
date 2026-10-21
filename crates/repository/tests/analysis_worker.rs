#![cfg(windows)]
mod support;
use melissa_execution_broker::{InvocationIdentity, policy::PermitRequest, unix_ms};
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use melissa_repository::{
    Limits, Repository,
    analysis::{AnalysisPlan, AnalysisQuery, LspMethod, TOOLING_IMAGE, byte_position},
    archive,
    discovery::DiscoveryOptions,
    tools::{AnalysisDispatcher, GitDispatcherConfig, ReviewedAnalysisTool},
};
use std::{
    fs,
    sync::{Arc, Mutex, atomic::AtomicBool},
};
fn no() -> AtomicBool {
    AtomicBool::new(false)
}
fn fixture() -> (tempfile::TempDir, Repository) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("repo");
    fs::create_dir_all(root.join("src")).unwrap();
    for (p, c) in [
        (
            "Cargo.toml",
            "[package]\nname=\"owned_analysis\"\nversion=\"0.0.0\"\nedition=\"2021\"\nbuild=\"build.rs\"\n",
        ),
        (
            "build.rs",
            "fn main(){std::fs::write(\"BUILD_SCRIPT_RAN\",b\"wrong\").unwrap();}",
        ),
        (
            "src/lib.rs",
            "mod alpha;\nmod beta;\npub fn run()->i32 { alpha::same()+beta::same() }\n",
        ),
        ("src/alpha.rs", "pub fn same()->i32 {1}\n"),
        ("src/beta.rs", "pub fn same()->i32 {2}\n"),
        (".gitignore", "secret.txt\n"),
        ("secret.txt", "same private needle"),
    ] {
        fs::write(root.join(p), c).unwrap();
    }
    (
        d,
        Repository::open_for_git(&root, Limits::default()).unwrap(),
    )
}
fn query(method: LspMethod, path: &str, line: u32, character: u32) -> AnalysisQuery {
    AnalysisQuery::Lsp {
        method,
        path: path.into(),
        line,
        character,
        include_declaration: false,
        root_modules: vec!["src/lib.rs".into()],
    }
}
fn run_plan(
    d: &std::path::Path,
    r: &Repository,
    q: AnalysisQuery,
) -> (AnalysisPlan, melissa_container_executor::ContainerReport) {
    let source = r.snapshot(&no()).unwrap();
    let plan =
        AnalysisPlan::prepare(r, &source, q, TOOLING_IMAGE, support::limits(), &no()).unwrap();
    let (store, t) = support::task_store(&d.join("store"), Some(plan.snapshot.digest().unwrap()));
    let mut b = support::container(store, &t, &plan.request, &plan.snapshot);
    let n = unix_ms().unwrap();
    let permit = b
        .issue_permit(
            &t.task_id,
            plan.request.clone(),
            &plan.snapshot,
            PermitRequest {
                permit_id: "permit:analysis-fixture".into(),
                nonce: "nonce:analysis-fixture".into(),
                principal_id: "principal:closeout".into(),
                profile_id: t.selected_profile_ids[0].clone(),
                resource_id: t.workspace_ref.clone(),
                authorization_ref: "auth:closeout".into(),
                not_before_unix_ms: n,
                expires_at_unix_ms: n + 90_000,
            },
        )
        .unwrap();
    let r = plan
        .execute(
            r,
            &mut b,
            &t.task_id,
            &permit,
            &InvocationIdentity {
                invocation_id: "inv:analysis-fixture".into(),
                attempt_id: "attempt:analysis-fixture".into(),
                generation: 1,
                idempotency_key: None,
            },
            &no(),
        )
        .unwrap();
    let report = r.report.unwrap();
    assert_eq!(
        report.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    assert!(report.cleanup_confirmed);
    assert!(report.tree_confirmed_stopped);
    (plan, report)
}
#[test]
fn real_rust_lsp_references_resolve_module_identity_and_never_execute_build_scripts() {
    let (d, r) = fixture();
    let before = r.snapshot(&no()).unwrap();
    let (plan, report) = run_plan(
        d.path(),
        &r,
        query(LspMethod::References, "src/alpha.rs", 0, 8),
    );
    let result = plan
        .decode(&r, &report, &no())
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&report.stdout)));
    assert_eq!(
        result.locations.len(),
        1,
        "{}",
        String::from_utf8_lossy(&report.stdout)
    );
    let location = &result.locations[0];
    assert_eq!(location.version.path, "src/lib.rs");
    let bytes = r.read("src/lib.rs").unwrap().1;
    assert_eq!(&bytes[location.start_byte..location.end_byte], b"same");
    let pos = std::str::from_utf8(&bytes[..location.start_byte]).unwrap();
    assert!(pos.ends_with("alpha::"));
    let imported = archive::inspect_ustar(&report.archive, r.limits()).unwrap();
    assert!(!imported.iter().any(|f| f.path.contains("BUILD_SCRIPT_RAN")));
    assert_eq!(r.snapshot(&no()).unwrap(), before);
    let mut forged = report.clone();
    let mut raw: serde_json::Value = serde_json::from_slice(&forged.stdout).unwrap();
    raw["result"][0]["uri"] = "file:///etc/passwd".into();
    forged.stdout = serde_json::to_vec(&raw).unwrap();
    assert!(plan.decode(&r, &forged, &no()).is_err());
}
#[test]
fn real_rust_lsp_definition_and_symbols_are_source_bound() {
    for (idx, q) in [
        query(LspMethod::Definition, "src/lib.rs", 2, 30),
        query(LspMethod::DocumentSymbol, "src/alpha.rs", 0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let (d, r) = fixture();
        let case = d.path().join(format!("case{idx}"));
        fs::create_dir(&case).unwrap();
        let (plan, report) = run_plan(&case, &r, q);
        let result = plan.decode(&r, &report, &no()).unwrap();
        assert!(
            !result.locations.is_empty(),
            "{}",
            String::from_utf8_lossy(&report.stdout)
        );
        assert!(
            result
                .locations
                .iter()
                .all(|l| l.version.path == "src/alpha.rs")
        );
        fs::write(r.root_path().join("src/alpha.rs"), b"pub fn changed(){}\n").unwrap();
        assert!(plan.decode(&r, &report, &no()).is_err());
    }
}
#[test]
fn real_ripgrep_uses_discovered_sources_and_authenticates_match_bytes() {
    let (d, r) = fixture();
    let q = AnalysisQuery::Ripgrep {
        needle: "same".into(),
        discovery: DiscoveryOptions::default(),
    };
    let (plan, report) = run_plan(d.path(), &r, q);
    let result = plan.decode(&r, &report, &no()).unwrap();
    assert_eq!(result.locations.len(), 4);
    assert!(
        result
            .locations
            .iter()
            .all(|l| l.version.path != "secret.txt")
    );
    for l in &result.locations {
        let (_, bytes) = r.read(&l.version.path).unwrap();
        assert_eq!(&bytes[l.start_byte..l.end_byte], b"same");
    }
}
#[test]
fn lsp_utf16_validation_rejects_surrogate_midpoints_and_outside_lines() {
    let b = "😀name\r\nnext\n".as_bytes();
    assert_eq!(byte_position(b, 0, 2).unwrap(), 4);
    assert!(byte_position(b, 0, 1).is_err());
    assert!(byte_position(b, 4, 0).is_err());
    assert!(byte_position(b, 0, 99).is_err());
    assert_eq!(byte_position(b, 1, 0).unwrap(), 10);
}

#[test]
fn real_analysis_ignores_source_owned_python_startup_and_lsp_configuration() {
    for lsp in [false, true] {
        let (d, r) = fixture();
        fs::create_dir_all(r.root_path().join(".local/lib/python3.13/site-packages")).unwrap();
        fs::write(
            r.root_path()
                .join(".local/lib/python3.13/site-packages/attack.pth"),
            b"import os; os._exit(77)\n",
        )
        .unwrap();
        fs::write(
            r.root_path().join("json.py"),
            b"raise RuntimeError('source startup executed')\n",
        )
        .unwrap();
        fs::write(
            r.root_path().join("rust-analyzer.toml"),
            b"[cargo.buildScripts]\nenable = true\n",
        )
        .unwrap();
        let q = if lsp {
            query(LspMethod::References, "src/alpha.rs", 0, 8)
        } else {
            AnalysisQuery::Ripgrep {
                needle: "same".into(),
                discovery: DiscoveryOptions::default(),
            }
        };
        let (plan, report) = run_plan(d.path(), &r, q);
        let result = plan.decode(&r, &report, &no()).unwrap();
        assert!(!result.locations.is_empty());
    }
}
#[tokio::test]
async fn actual_analysis_gateway_dispatcher_binds_query_context_and_worker_evidence() {
    let (d, r) = fixture();
    let source = r.snapshot(&no()).unwrap();
    let q = query(LspMethod::References, "src/alpha.rs", 0, 8);
    let plan = AnalysisPlan::prepare(
        &r,
        &source,
        q.clone(),
        TOOLING_IMAGE,
        support::limits(),
        &no(),
    )
    .unwrap();
    let (store, t) = support::task_store(
        &d.path().join("store"),
        Some(plan.snapshot.digest().unwrap()),
    );
    let peer = store.connect().unwrap();
    let b = support::container(store, &t, &plan.request, &plan.snapshot);
    let config = GitDispatcherConfig {
        task_id: t.task_id.clone(),
        profile_id: t.selected_profile_ids[0].clone(),
        principal_id: "principal:closeout".into(),
        resource_id: t.workspace_ref.clone(),
        expires_at_ms: unix_ms().unwrap() + 120_000,
    };
    let mut dispatcher = AnalysisDispatcher::new(
        r,
        Arc::new(Mutex::new(b)),
        config,
        vec![ReviewedAnalysisTool {
            plan,
            authorization_ref: "auth:closeout".into(),
        }],
    )
    .unwrap();
    let defs = dispatcher.definitions();
    assert_eq!(defs.len(), 1);
    melissa_model_gateway::schema::validate_schema(&defs[0].definition.parameters).unwrap();
    let c = ToolCall {
        id: "call:semantic".into(),
        name: "code_lsp_references".into(),
        arguments: serde_json::to_string(&q).unwrap(),
    };
    dispatcher.validate_call(&c).unwrap();
    let mut injected = c.clone();
    injected.arguments = r#"{"tool":"lsp","principal_id":"forged"}"#.into();
    assert!(dispatcher.validate_call(&injected).is_err());
    let ctx = ToolContext {
        task_id: t.task_id.clone(),
        profile_id: t.selected_profile_ids[0].clone(),
        run_id: "run:semantic".into(),
        request_id: "request:semantic".into(),
        invocation_id: "inv:semantic".into(),
        attempt_id: "attempt:semantic".into(),
        generation: 1,
    };
    let result = dispatcher.execute(c, ctx, Arc::new(no())).await.unwrap();
    assert!(result.success, "{}", result.content);
    let v: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(v["locations"].as_array().unwrap().len(), 1);
    assert!(!result.artifact_refs.is_empty());
    assert!(
        peer.get_artifact(&t.task_id, "inv:semantic:analysis-result")
            .is_ok()
    );
    peer.integrity_check().unwrap();
}
