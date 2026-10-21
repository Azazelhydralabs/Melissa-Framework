#![allow(dead_code)]
use melissa_core_contracts::design::{SkillPin, SkillVersion};
use melissa_skill_context::{
    Namespace, digest,
    package::{Package, Registry, SkillPolicy, package_digest},
    retrieval::*,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
pub fn namespace() -> Namespace {
    Namespace {
        user: "user:a".into(),
        project: "project:a".into(),
        engagement: None,
    }
}
pub fn raw(index: usize) -> (Vec<u8>, Vec<u8>, BTreeMap<String, Vec<u8>>, SkillPin) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills/code");
    let pins: Vec<SkillPin> =
        serde_json::from_slice(&fs::read(root.join("index.json")).unwrap()).unwrap();
    let pin = pins[index].clone();
    let slug = pin.skill_id.strip_prefix("melissa.code.skill.").unwrap();
    let p = root.join(slug).join(&pin.semantic_version);
    let d = fs::read(p.join("definition.json")).unwrap();
    let v = fs::read(p.join("version.json")).unwrap();
    let parsed: melissa_core_contracts::design::SkillDefinition =
        serde_json::from_slice(&d).unwrap();
    let files = parsed
        .files
        .iter()
        .map(|f| (f.path.clone(), fs::read(p.join(&f.path)).unwrap()))
        .collect();
    (d, v, files, pin)
}
pub fn one(index: usize) -> Package {
    let (d, v, f, p) = raw(index);
    Package::load(&d, &v, f, &p).unwrap()
}
pub fn repin(d: &[u8], files: &BTreeMap<String, Vec<u8>>, v: &[u8]) -> (Vec<u8>, SkillPin) {
    let mut version: SkillVersion = serde_json::from_slice(v).unwrap();
    version.definition_digest = digest(d);
    version.pin.content_digest = package_digest(d, files).unwrap();
    (serde_json::to_vec(&version).unwrap(), version.pin)
}
pub fn setup() -> (Registry, SkillPolicy, Vec<SkillPin>) {
    let mut reg = Registry::default();
    let mut policy = SkillPolicy {
        epoch: "policy:1".into(),
        reviewed: BTreeSet::new(),
        publishers: BTreeSet::from(["melissa-local-development".into()]),
        revoked: BTreeSet::new(),
        tools: BTreeSet::new(),
        capabilities: BTreeSet::new(),
        allow_helpers: true,
    };
    let mut pins = vec![];
    for i in 0..10 {
        let p = one(i);
        pins.push(p.version().pin.clone());
        policy
            .reviewed
            .insert(p.version().pin.content_digest.clone());
        policy
            .tools
            .extend(p.definition().manifest.required_tools.clone());
        policy
            .capabilities
            .extend(p.definition().manifest.required_capabilities.clone());
        reg.insert(p).unwrap();
    }
    (reg, policy, pins)
}
pub fn source(id: &str, text: &str) -> Source {
    Source {
        id: id.into(),
        version: "v1".into(),
        namespace: namespace(),
        domain: Domain::Code,
        content: text.into(),
        digest: digest(text.as_bytes()),
        observed_at_ms: 1,
        valid_until_ms: 100,
        symbols: vec![],
        links: vec![],
    }
}
pub fn scope(sources: &[Source]) -> SearchScope {
    SearchScope {
        namespace: namespace(),
        domain: Domain::Code,
        now_ms: 10,
        current: sources
            .iter()
            .map(|s| (s.id.clone(), (s.version.clone(), s.digest.clone())))
            .collect(),
    }
}
