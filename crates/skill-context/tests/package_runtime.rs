mod common;
use common::*;
use melissa_core_contracts::design::*;
use melissa_skill_context::{digest, package::*};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[test]
fn ten_versioned_packages_load_complete_instructions_and_schemas_without_evaluation_answers() {
    let (reg, p, pins) = setup();
    assert_eq!(pins.len(), 10);
    for pin in pins {
        let package = reg.load(&pin, &p).unwrap();
        let m = package.material().unwrap();
        assert_eq!(
            m.files["SKILL.md"].bytes().unwrap(),
            package.file("SKILL.md").unwrap()
        );
        assert!(m.files.contains_key("schemas/input.json"));
        assert!(m.files.contains_key("schemas/output.json"));
        assert!(m.files.contains_key("references/acceptance.md"));
        assert!(m.files.contains_key("scripts/assess.py"));
        assert!(m.files.contains_key("assets/report.md"));
        assert!(
            !m.files
                .keys()
                .any(|x| x.starts_with("evals/") || x.starts_with("tests/"))
        );
        assert_eq!(m.authority, "untrusted_data_no_execution_grant");
        assert_eq!(package.version().state, SkillReleaseState::Tested);
        assert!(package.version().signature.is_none());
    }
}
#[test]
fn tampered_missing_and_undeclared_files_fail_closed() {
    for mode in 0..3 {
        let (d, v, mut f, p) = raw(0);
        match mode {
            0 => {
                f.get_mut("SKILL.md").unwrap().push(b'!');
            }
            1 => {
                f.remove("schemas/output.json");
            }
            _ => {
                f.insert("hidden.py".into(), vec![]);
            }
        };
        assert!(Package::load(&d, &v, f, &p).is_err());
    }
}
#[test]
fn wrong_pin_wrong_definition_digest_and_wrong_version_are_rejected() {
    for mode in 0..3 {
        let (d, v, f, mut p) = raw(0);
        let mut v: Value = serde_json::from_slice(&v).unwrap();
        match mode {
            0 => p.skill_id = "another-skill".into(),
            1 => v["definition_digest"] = json!(digest(b"different")),
            _ => v["pin"]["semantic_version"] = json!("9.0.0"),
        };
        assert!(Package::load(&d, &serde_json::to_vec(&v).unwrap(), f, &p).is_err());
    }
}
#[test]
fn duplicate_unknown_and_trailing_json_fields_are_rejected_before_loading() {
    for mode in 0..3 {
        let (mut d, v, f, p) = raw(0);
        match mode {
            0 => {
                let mut n=br#"{"schema_version":"x","schema_version":"y","a":{"duplicate":1,"duplicate":2},"rest": "#.to_vec();
                n.extend(d);
                n.push(b'}');
                d = n;
            }
            1 => {
                let mut n: Value = serde_json::from_slice(&d).unwrap();
                n["unknown"] = json!(true);
                d = serde_json::to_vec(&n).unwrap();
            }
            _ => d.extend_from_slice(b" {}"),
        };
        let (v, p2) = repin(&d, &f, &v);
        assert_eq!(p.skill_id, p2.skill_id);
        assert!(Package::load(&d, &v, f, &p2).is_err());
    }
}
#[test]
fn traversal_case_collisions_and_windows_device_paths_are_rejected_even_when_resealed() {
    for path in [
        "../outside.py",
        "C:/outside.py",
        "references/CON.txt",
        "schemas/INPUT.json",
    ] {
        let (d, v, mut f, _) = raw(0);
        let mut d: Value = serde_json::from_slice(&d).unwrap();
        f.insert(path.into(), b"{}".to_vec());
        d["files"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":path,"role":"reference","content_digest":digest(b"{}")}));
        let d = serde_json::to_vec(&d).unwrap();
        let (v, p) = repin(&d, &f, &v);
        assert!(Package::load(&d, &v, f, &p).is_err(), "{path}");
    }
}
#[test]
fn invalid_and_remote_schema_references_cannot_load() {
    for invalid in [
        br#"{"$ref":"https://outside.invalid/schema"}"#.as_slice(),
        br#"{"type":32}"#,
    ] {
        let (d, v, mut f, _) = raw(0);
        let mut d: Value = serde_json::from_slice(&d).unwrap();
        f.insert("schemas/input.json".into(), invalid.to_vec());
        for e in d["files"].as_array_mut().unwrap() {
            if e["path"] == "schemas/input.json" {
                e["content_digest"] = json!(digest(invalid));
            }
        }
        let d = serde_json::to_vec(&d).unwrap();
        let (v, p) = repin(&d, &f, &v);
        assert!(Package::load(&d, &v, f, &p).is_err());
    }
}
#[test]
fn immutable_registration_and_current_policy_prevent_hot_swap_or_authority_escalation() {
    let (mut reg, mut p, pins) = setup();
    assert!(reg.insert(one(0)).is_err());
    p.reviewed.clear();
    assert!(reg.load(&pins[0], &p).is_err());
    let (reg, mut p, pins) = setup();
    p.revoked.insert("melissa-local-development".into());
    assert!(reg.load(&pins[0], &p).is_err());
    p.revoked.clear();
    p.revoked.insert(pins[0].content_digest.clone());
    assert!(reg.load(&pins[0], &p).is_err());
    p.revoked.clear();
    p.tools.clear();
    assert!(reg.load(&pins[0], &p).is_err());
}
#[test]
fn intent_routes_only_eligible_skills_and_capabilities_remain_host_owned() {
    let (reg, mut p, _) = setup();
    let pins = reg.route("runtime_bug", &p);
    assert_eq!(pins.len(), 1);
    assert!(pins[0].skill_id.ends_with("debug-root-cause"));
    assert!(reg.route("invented-purpose", &p).is_empty());
    p.capabilities.clear();
    assert!(reg.route("runtime_bug", &p).is_empty());
}
#[test]
fn draft_is_never_activated_by_first_party_manifest_text() {
    let (d, v, f, _) = raw(0);
    let mut v: SkillVersion = serde_json::from_slice(&v).unwrap();
    v.state = SkillReleaseState::Draft;
    let p = Package::load(&d, &serde_json::to_vec(&v).unwrap(), f, &v.pin).unwrap();
    let (_, policy, _) = setup();
    assert!(policy.check(&p).is_err());
}

#[test]
fn signature_metadata_cannot_impersonate_a_cryptographically_verified_release() {
    let (d, v, f, _) = raw(0);
    let mut v: SkillVersion = serde_json::from_slice(&v).unwrap();
    v.state = SkillReleaseState::SignedRelease;
    v.evaluation_digest = Some(digest(b"claimed evaluation"));
    v.review_artifact_ref = Some("claimed review".into());
    v.signature = Some(SignatureReference {
        algorithm: "ed25519".into(),
        key_id: "claimed-key".into(),
        signature_artifact_ref: "claimed-signature".into(),
    });
    let p = Package::load(&d, &serde_json::to_vec(&v).unwrap(), f, &v.pin).unwrap();
    let (_, policy, _) = setup();
    assert!(policy.check(&p).is_err());
}

#[test]
fn frontmatter_fields_must_be_in_the_header_not_in_untrusted_body_text() {
    for md in [
        "---\nother: value\n---\nname: forged\ndescription: forged\n",
        "---\nname: valid-name\nname: duplicate\ndescription: text\n---\nbody",
        "---\nname: ../escape\ndescription: text\n---\nbody",
    ] {
        let (d, v, mut f, _) = raw(0);
        let mut d: Value = serde_json::from_slice(&d).unwrap();
        f.insert("SKILL.md".into(), md.as_bytes().to_vec());
        for e in d["files"].as_array_mut().unwrap() {
            if e["path"] == "SKILL.md" {
                e["content_digest"] = json!(digest(md.as_bytes()));
            }
        }
        let d = serde_json::to_vec(&d).unwrap();
        let (v, p) = repin(&d, &f, &v);
        assert!(Package::load(&d, &v, f, &p).is_err());
    }
}
#[test]
fn template_binding_is_single_pass_and_cannot_inject_new_placeholder_execution() {
    let p = one(0);
    let mut fields = BTreeMap::new();
    for k in [
        "task",
        "sources",
        "observations",
        "open_issues",
        "acceptance",
    ] {
        fields.insert(k.into(), json!("{{secret}} $(anything) `command`"));
    }
    let out = String::from_utf8(p.render("assets/report.md", &fields).unwrap()).unwrap();
    assert!(out.contains("{{secret}} $(anything) `command`"));
    fields.remove("task");
    assert!(p.render("assets/report.md", &fields).is_err());
    fields.insert("unregistered".into(), json!(1));
    assert!(p.render("assets/report.md", &fields).is_err());
}
#[test]
fn helper_input_and_plan_are_hash_bound_and_do_not_grant_execution() {
    let p = one(0);
    let (_, mut policy, _) = setup();
    let cases = std::str::from_utf8(p.file("evals/cases.jsonl").unwrap()).unwrap();
    let c: Value = serde_json::from_str(cases.lines().next().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&c["input"]).unwrap();
    let input = p
        .validate_script_input("scripts/assess.py", &bytes)
        .unwrap();
    let plan = p.script_plan("scripts/assess.py", &policy, &input).unwrap();
    assert!(plan.requires_broker_admission);
    assert_eq!(plan.input_digest, digest(&bytes));
    assert_eq!(
        plan.script_digest,
        digest(p.file("scripts/assess.py").unwrap())
    );
    policy.allow_helpers = false;
    assert!(p.script_plan("scripts/assess.py", &policy, &input).is_err());
    assert!(p.validate_script_input("scripts/assess.py", b"{}").is_err());
    assert!(
        p.script_plan("scripts/undeclared.py", &policy, &input)
            .is_err()
    );
}
#[test]
fn rollback_requires_an_explicit_compatible_reviewed_target_and_rechecks_revocation() {
    let (mut reg, mut policy, pins) = setup();
    let (d, v, f, old) = raw(0);
    let mut v: SkillVersion = serde_json::from_slice(&v).unwrap();
    let mut d: Value = serde_json::from_slice(&d).unwrap();
    d["description_tr"] = json!("new version");
    let d = serde_json::to_vec(&d).unwrap();
    v.pin.semantic_version = "2.0.0".into();
    v.definition_digest = digest(&d);
    v.pin.content_digest = package_digest(&d, &f).unwrap();
    v.rollback_to = Some(old.clone());
    let new = v.pin.clone();
    let p = Package::load(&d, &serde_json::to_vec(&v).unwrap(), f, &new).unwrap();
    reg.insert(p).unwrap();
    assert_eq!(reg.rollback(&new, &policy).unwrap(), pins[0]);
    policy.revoked.insert(old.content_digest);
    assert!(reg.rollback(&new, &policy).is_err());
}
