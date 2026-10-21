mod common;
use melissa_core_contracts::design::SkillVersion;
use melissa_skill_context::package::Package;
#[test]
fn same_content_distinct_versions_never_replace_an_existing_task_pin() {
    let (mut registry, policy, _) = common::setup();
    let (definition, version, files, old) = common::raw(0);
    let mut version: SkillVersion = serde_json::from_slice(&version).unwrap();
    version.pin.semantic_version = "1.0.1".into();
    let newer = version.pin.clone();
    assert_eq!(old.content_digest, newer.content_digest);
    let p = Package::load(
        &definition,
        &serde_json::to_vec(&version).unwrap(),
        files,
        &newer,
    )
    .unwrap();
    registry.insert(p).unwrap();
    assert_eq!(registry.load(&old, &policy).unwrap().version().pin, old);
    assert_eq!(registry.load(&newer, &policy).unwrap().version().pin, newer);
}
