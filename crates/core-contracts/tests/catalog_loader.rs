use melissa_core_contracts::Module;
use melissa_core_contracts::catalog::{Catalog, CatalogLimits, safe_relative_path};
use melissa_core_contracts::catalog_models::*;
use melissa_core_contracts::json::parse_contract;
use melissa_core_contracts::validation::Validate;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn catalog() -> Catalog {
    Catalog::load(&root()).expect("the checked-in definition catalog must load")
}
fn profile_json() -> Value {
    serde_json::to_value(catalog().profiles["melissa.code.implementer"].clone()).unwrap()
}
fn reject_profile(value: Value) {
    assert!(
        parse_contract::<AgentProfile>(&serde_json::to_vec(&value).unwrap(), 2 * 1024 * 1024)
            .is_err()
    );
}

#[test]
fn complete_actual_catalog_loads_without_promoting_runtime() {
    let c = catalog();
    assert_eq!(c.profiles.len(), 62);
    assert_eq!(c.workers.len(), 12);
    assert_eq!(c.tools.tools.len(), 150);
    assert_eq!(c.aliases.aliases.len(), 3);
    assert_eq!(c.modules.modules.len(), 8);
    assert_eq!(c.backlog.items.len(), 67);
    assert_eq!(
        c.profiles
            .values()
            .map(|p| p.evaluation_cases.len())
            .sum::<usize>(),
        186
    );
    let r = c.readiness();
    assert!(!r.executable);
    assert_eq!(r.evidence_level, "definition_catalog_only");
    assert_eq!(r.missing_runtime_bindings.len(), 62);
    assert_eq!(r.missing_skill_packages.len(), 62);
    assert_eq!(r.missing_exact_tool_routes.len(), 150);
    assert_eq!(r.pending_input_schemas.len(), 150);
    assert_eq!(r.missing_worker_executors.len(), 12);
    assert_eq!(
        r.source_interface_mappings_pending,
        vec![
            "memory.search",
            "memory.propose",
            "science.cad.inspect",
            "game.physics.simulate"
        ]
    );
}
#[test]
fn aliases_resolve_only_registered_targets_without_granting_routes() {
    let c = catalog();
    assert_eq!(
        c.resolve_tool_alias("artifact.get").unwrap(),
        "artifact.read"
    );
    assert_eq!(
        c.resolve_tool_alias("artifact.read").unwrap(),
        "artifact.read"
    );
    assert!(c.resolve_tool_alias("memory.search").is_err());
    assert!(
        c.readiness()
            .missing_exact_tool_routes
            .contains(&"artifact.read".into())
    );
}
#[test]
fn alias_cycles_shadows_and_unknown_targets_fail() {
    let mut c = catalog();
    c.aliases
        .aliases
        .insert("artifact.get".into(), "artifact.put".into());
    c.aliases
        .aliases
        .insert("artifact.put".into(), "artifact.get".into());
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.aliases
        .aliases
        .insert("artifact.read".into(), "artifact.write".into());
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.aliases
        .aliases
        .insert("artifact.get".into(), "missing.tool".into());
    assert!(c.validate().is_err());
}
#[test]
fn profile_unknown_fields_future_versions_and_enums_fail() {
    let mut value = profile_json();
    value["authority"]["override_runtime"] = json!(true);
    reject_profile(value);
    let mut value = profile_json();
    value["schema_version"] = json!("melissa.agent-profile/v2");
    reject_profile(value);
    let mut value = profile_json();
    value["module"] = json!("unknown");
    reject_profile(value);
    let mut value = profile_json();
    value["model_policy"]["class"] = json!("omniscient");
    reject_profile(value);
}

#[test]
fn nullable_predecessor_must_be_explicit_even_for_first_module() {
    let mut value = serde_json::to_value(catalog().modules).unwrap();
    value["modules"][0]
        .as_object_mut()
        .unwrap()
        .remove("implementation_order_predecessor");
    assert!(
        parse_contract::<ModuleCatalog>(&serde_json::to_vec(&value).unwrap(), 2 * 1024 * 1024)
            .is_err()
    );
}
#[test]
fn profile_cannot_self_authorize_or_hide_required_boundaries() {
    let mut value = profile_json();
    value["authority"]["capability_ceiling"] = json!(["authority.expand"]);
    reject_profile(value);
    let mut value = profile_json();
    value["authority"]["capability_ceiling"] = json!(["fs.*"]);
    reject_profile(value);
    let mut value = profile_json();
    value["authority"]["forbidden_effects"] = json!(["authority.expand"]);
    reject_profile(value);
}
#[test]
fn duplicate_profile_fields_and_nested_keys_fail() {
    let value = serde_json::to_string(&profile_json()).unwrap();
    let duplicate = value.replacen(
        "\"class\":\"coding\"",
        "\"class\":\"coding\",\"class\":\"reasoning\"",
        1,
    );
    assert_ne!(value, duplicate);
    assert!(parse_contract::<AgentProfile>(duplicate.as_bytes(), 2 * 1024 * 1024).is_err());
}
#[test]
fn definition_metadata_cannot_claim_implemented_adapters() {
    let mut value = profile_json();
    value["implementation"]["runtime"] = json!("implemented");
    reject_profile(value);
    let mut c = serde_json::to_value(catalog().tools).unwrap();
    c["tools"][0]["adapter_status"] = json!("implemented");
    assert!(
        parse_contract::<ToolCatalog>(&serde_json::to_vec(&c).unwrap(), 2 * 1024 * 1024).is_err()
    );
}
#[test]
fn mismatched_profile_module_inputs_and_capabilities_fail() {
    let mut value = profile_json();
    value["module"] = json!("core");
    reject_profile(value);
    let mut value = profile_json();
    value["inputs"]["required"] = json!(["workspace_ref"]);
    reject_profile(value);
    let mut value = profile_json();
    value["model_policy"]["required_capabilities"] = json!(["structured_output"]);
    reject_profile(value);
}
#[test]
fn dangling_handoffs_workers_tools_and_stale_reverse_references_fail() {
    let mut c = catalog();
    c.profiles
        .get_mut("melissa.code.implementer")
        .unwrap()
        .handoffs[0]
        .profile_id = "melissa.code.absent".into();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.profiles
        .get_mut("melissa.code.implementer")
        .unwrap()
        .worker_types = vec!["absent-worker".into()];
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.profiles
        .get_mut("melissa.code.implementer")
        .unwrap()
        .tool_ids
        .push("absent.tool".into());
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.tools.tools[0].referenced_by.clear();
    assert!(c.validate().is_err());
}
#[test]
fn protected_verifier_cannot_gain_source_patch_tool() {
    let mut c = catalog();
    c.profiles
        .get_mut("melissa.core.independent-qa")
        .unwrap()
        .tool_ids
        .push("fs.patch".into());
    assert!(c.validate().is_err());
}
#[test]
fn index_module_counts_and_duplicate_entries_fail() {
    let mut c = catalog();
    c.index.profiles[0].path = "catalog/agents/code/backend.json".into();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.modules.modules[1].profile_count += 1;
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.tools.tools.push(c.tools.tools[0].clone());
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.backlog.items.push(c.backlog.items[0].clone());
    assert!(c.validate().is_err());
}
#[test]
fn missing_modules_and_implementation_order_cycles_fail() {
    let mut c = catalog();
    c.modules.modules.pop();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.modules.modules[0]
        .implementation_dependencies
        .push(Module::Code);
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.modules.modules[1].implementation_order_predecessor = Some(Module::Fit);
    assert!(c.validate().is_err());
}
#[test]
fn accepted_work_requires_evidence_and_gate_requires_complete_work() {
    let mut c = catalog();
    let accepted = c.backlog.items.first_mut().unwrap();
    accepted.status = BacklogStatus::Accepted;
    accepted.evidence_refs.clear();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.modules.modules[1].gate.status = GateStatus::Passed;
    c.modules.modules[1].gate.evidence_refs = vec!["reports/local-acceptance.json".into()];
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.modules.modules[1].status.product_acceptance = AcceptanceStatus::Passed;
    assert!(c.validate().is_err());
}
#[test]
fn policy_authority_budget_and_usage_invariants_fail_closed() {
    let mut c = catalog();
    c.policy.authority.model_can_authorize = true;
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.policy.authority.effective_grant = "union(task_grant,profile_ceiling)".into();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.policy.budget.scope = "per_agent".into();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.policy.budget.unknown_usage = "zero".into();
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.policy.budget.reservation = "after_dispatch".into();
    assert!(c.validate().is_err());
}
#[test]
fn worker_unbounded_jobs_or_incomplete_job_identity_fail() {
    let mut c = catalog();
    c.workers
        .get_mut("generic")
        .unwrap()
        .resource_policy
        .unbounded_jobs = true;
    assert!(c.validate().is_err());
    let mut c = catalog();
    c.workers
        .get_mut("generic")
        .unwrap()
        .job_contract
        .required
        .retain(|v| v != "lease_generation");
    assert!(c.validate().is_err());
}
#[test]
fn catalog_can_grow_without_static_profile_upper_bound() {
    let mut c = catalog();
    let mut profile = c.profiles["melissa.code.implementer"].clone();
    profile.id = "melissa.code.future-specialist".into();
    profile.name_tr = "Future specialist".into();
    for case in &mut profile.evaluation_cases {
        case.id = case.id.replace("implementer", "future-specialist");
    }
    for tool in &mut c.tools.tools {
        if profile.tool_ids.contains(&tool.id) {
            tool.referenced_by.push(profile.id.clone());
        }
    }
    let module = c
        .modules
        .modules
        .iter_mut()
        .find(|m| m.id == Module::Code)
        .unwrap();
    module.profile_count += 1;
    module.profile_ids.push(profile.id.clone());
    c.index.profiles.push(AgentIndexEntry {
        id: profile.id.clone(),
        module: Module::Code,
        name_tr: profile.name_tr.clone(),
        path: "catalog/agents/code/future-specialist.json".into(),
    });
    c.profiles.insert(profile.id.clone(), profile);
    c.validate().unwrap();
    assert_eq!(c.profiles.len(), 63);
}
#[test]
fn portable_path_rejects_traversal_ads_reserved_names_and_ambiguities() {
    for path in [
        "../secret",
        "catalog/../secret",
        "/absolute",
        "C:/secret",
        "catalog\\tools.json",
        "catalog//tools.json",
        "catalog/CON.json",
        "catalog/tools.json:stream",
        "catalog/a. /x",
        "catalog/./tools.json",
        "catalog/*",
    ] {
        assert!(safe_relative_path(path).is_err(), "accepted {path}");
    }
    safe_relative_path("catalog/agents/code/implementer.json").unwrap();
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "melissa-code01-catalog-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        // Exclusive ownership; never remove/reuse an existing computed target.
        fs::create_dir(&path).expect("unique test fixture directory");
        let source = root().join("catalog");
        copy_dir(&source, &path.join("catalog"));
        let backlog_file = path.join("catalog/backlog.json");
        let mut synthetic: Value =
            serde_json::from_slice(&fs::read(&backlog_file).unwrap()).unwrap();
        for item in synthetic["items"].as_array_mut().unwrap() {
            item["status"] = json!("accepted");
            item["evidence_refs"] = json!(["reports/catalog-validation.json"]);
        }
        fs::write(&backlog_file, serde_json::to_vec(&synthetic).unwrap()).unwrap();
        fs::create_dir(path.join("reports")).unwrap();
        fs::write(
            path.join("reports/catalog-validation.json"),
            b"synthetic existence fixture, not acceptance",
        )
        .unwrap();
        for reference in catalog()
            .backlog
            .items
            .iter()
            .filter(|item| item.status == BacklogStatus::Accepted)
            .flat_map(|item| item.evidence_refs.iter())
        {
            let target = path.join(reference);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(
                target,
                b"fixture reference existence, not verifier authentication",
            )
            .unwrap();
        }
        Self { path }
    }
    fn edit(&self, relative: &str, mutator: impl FnOnce(&mut Value)) {
        let file = self.path.join(relative);
        let mut value: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        mutator(&mut value);
        fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let base = fs::canonicalize(std::env::temp_dir()).expect("temp directory");
        let actual = fs::canonicalize(&self.path).expect("owned fixture directory");
        assert_eq!(actual.parent(), Some(base.as_path()));
        assert!(
            actual
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("melissa-code01-catalog-")
        );
        fs::remove_dir_all(actual).expect("remove only this fixture");
    }
}
fn copy_dir(source: &Path, target: &Path) {
    fs::create_dir(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let next = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &next);
        } else {
            fs::copy(entry.path(), next).unwrap();
        }
    }
}
#[test]
fn loader_rejects_filename_mismatch_and_unindexed_extra_profile() {
    let f = Fixture::new();
    fs::rename(
        f.path.join("catalog/agents/code/implementer.json"),
        f.path.join("catalog/agents/code/wrong-name.json"),
    )
    .unwrap();
    assert!(Catalog::load(&f.path).is_err());
    let f = Fixture::new();
    let mut profile = profile_json();
    profile["id"] = json!("melissa.code.unindexed");
    fs::write(
        f.path.join("catalog/agents/code/unindexed.json"),
        serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    assert!(Catalog::load(&f.path).is_err());
}
#[test]
fn loader_rejects_missing_evidence_and_evidence_path_escape() {
    let f = Fixture::new();
    fs::remove_file(f.path.join("reports/catalog-validation.json")).unwrap();
    assert!(Catalog::load(&f.path).is_err());
    let f = Fixture::new();
    f.edit("catalog/backlog.json", |v| {
        v["items"][11]["evidence_refs"] = json!(["../external-proof.json"])
    });
    assert!(Catalog::load(&f.path).is_err());
}
#[test]
fn loader_enforces_file_entry_and_total_byte_limits() {
    let limits = CatalogLimits {
        max_file_bytes: 32,
        ..Default::default()
    };
    assert!(Catalog::load_with_limits(&root(), limits).is_err());
    let limits = CatalogLimits {
        max_total_bytes: 32,
        ..Default::default()
    };
    assert!(Catalog::load_with_limits(&root(), limits).is_err());
    let limits = CatalogLimits {
        max_files: 8,
        ..Default::default()
    };
    assert!(Catalog::load_with_limits(&root(), limits).is_err());
    let limits = CatalogLimits {
        max_entries: 10,
        ..Default::default()
    };
    assert!(Catalog::load_with_limits(&root(), limits).is_err());
}
#[test]
fn loader_rejects_duplicate_json_and_unrecognized_policy_fields() {
    let f = Fixture::new();
    let path = f.path.join("catalog/runtime-policy.json");
    let text = fs::read_to_string(&path).unwrap();
    let duplicate = text.replacen(
        "\"model_can_authorize\": false",
        "\"model_can_authorize\": false, \"model_can_authorize\": true",
        1,
    );
    assert_ne!(text, duplicate);
    fs::write(path, duplicate).unwrap();
    assert!(Catalog::load(&f.path).is_err());
    let f = Fixture::new();
    f.edit("catalog/runtime-policy.json", |v| {
        v["budget"]["ignore_limits"] = json!(true)
    });
    assert!(Catalog::load(&f.path).is_err());
}
#[cfg(unix)]
#[test]
fn loader_rejects_symbolic_link_file_and_directory() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let path = f.path.join("catalog/tools.json");
    let original = f.path.join("tools-real.json");
    fs::rename(&path, &original).unwrap();
    symlink(&original, &path).unwrap();
    assert!(Catalog::load(&f.path).is_err());
    let f = Fixture::new();
    let path = f.path.join("catalog/workers");
    let original = f.path.join("workers-real");
    fs::rename(&path, &original).unwrap();
    symlink(&original, &path).unwrap();
    assert!(Catalog::load(&f.path).is_err());
}

#[cfg(windows)]
#[test]
fn windows_loader_rejects_directory_junction() {
    use std::os::windows::process::CommandExt;
    // Junction creation does not require the symbolic-link privilege that is
    // unavailable on this host. PowerShell only creates this owned fixture link;
    // Rust's checked fixture cleanup stays in one filesystem implementation.
    let f = Fixture::new();
    let path = f.path.join("catalog/workers");
    let original = f.path.join("workers-real");
    fs::rename(&path, &original).unwrap();
    let quote = |value: &Path| format!("'{}'", value.to_str().unwrap().replace('\'', "''"));
    let command = format!(
        "New-Item -ItemType Junction -Path {} -Target {} -ErrorAction Stop | Out-Null",
        quote(&path),
        quote(&original)
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Catalog::load(&f.path).is_err());
}
