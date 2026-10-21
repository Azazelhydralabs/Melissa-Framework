use super::*;
use melissa_model_gateway::schema::{validate_output, validate_schema};

#[test]
fn explicit_reviewed_schema_preserves_old_const_and_rejects_observed_live_wrappers() {
    let operations = vec![
        RepositoryRead::Git(GitOperation::Status),
        RepositoryRead::Git(GitOperation::Diff { staged: false }),
        RepositoryRead::Git(GitOperation::Log { max_entries: 1 }),
        RepositoryRead::Git(GitOperation::WorktreeList),
        RepositoryRead::Git(GitOperation::WorktreeCreate {
            name: "review".into(),
            commit: "HEAD".into(),
        }),
        RepositoryRead::Analysis(AnalysisQuery::Ripgrep {
            needle: "needle".into(),
            discovery: crate::discovery::DiscoveryOptions::default(),
        }),
    ];
    for operation in operations {
        let exact = serde_json::to_value(operation).unwrap();
        let old = json!({"type":"object","const":exact});
        let current = exact_argument_schema(&exact);
        validate_schema(&current).unwrap();
        assert_eq!(current["properties"]["service"]["type"], "string");
        assert_eq!(current["properties"]["operation"]["type"], "object");
        assert!(current.get("const").is_none());
        let mut extra = exact.clone();
        extra["authorization_ref"] = json!("model-injection");
        let mut wrong = exact.clone();
        wrong["operation"]["operation"] = json!("unreviewed");
        for candidate in [
            exact.clone(),
            json!({"const":exact}),
            json!({"const":exact.to_string()}),
            json!({}),
            extra,
            wrong,
            json!({"service":"git","operation":exact["operation"].to_string()}),
        ] {
            let bytes = candidate.to_string();
            let before = validate_output(&old, &bytes).is_ok();
            let after = validate_output(&current, &bytes).is_ok();
            assert_eq!(before, after, "schema authority changed for {candidate}");
        }
        validate_output(&current, &exact.to_string()).unwrap();
    }
}

#[test]
fn lsp_argument_fields_are_visible_but_query_roots_order_and_positions_stay_exact() {
    for method in [
        LspMethod::References,
        LspMethod::Definition,
        LspMethod::DocumentSymbol,
    ] {
        let operation = RepositoryRead::Analysis(AnalysisQuery::Lsp {
            method,
            path: "lib.rs".into(),
            line: 1,
            character: 4,
            include_declaration: false,
            root_modules: vec!["lib.rs".into(), "other.rs".into()],
        });
        let exact = serde_json::to_value(operation).unwrap();
        let current = exact_argument_schema(&exact);
        validate_schema(&current).unwrap();
        validate_output(&current, &exact.to_string()).unwrap();
        let props = &current["properties"]["operation"]["properties"];
        for field in [
            "tool",
            "method",
            "path",
            "line",
            "character",
            "include_declaration",
            "root_modules",
        ] {
            assert!(
                props.get(field).is_some(),
                "missing visible argument {field}"
            );
        }
        let mut wrong_path = exact.clone();
        wrong_path["operation"]["path"] = json!("outside.rs");
        let mut wrong_roots = exact.clone();
        wrong_roots["operation"]["root_modules"] = json!(["other.rs", "lib.rs"]);
        let mut wrong_position = exact.clone();
        wrong_position["operation"]["character"] = json!(5);
        let mut missing = exact.clone();
        missing["operation"].as_object_mut().unwrap().remove("line");
        for candidate in [wrong_path, wrong_roots, wrong_position, missing] {
            assert!(validate_output(&current, &candidate.to_string()).is_err());
        }
    }
}
