#![cfg(windows)]
mod common;
// Reuse the already accepted CODE-06 fixture unchanged. It opens a new owned
// store and obtains the same CODE-03 policy/permit/container isolation.
#[path = "../../build-test/tests/support/mod.rs"]
mod support;
use melissa_build_test::{
    RustOperation,
    toolchain::{COMPLETE_IMAGE, PYTHON},
};
use melissa_container_executor::{ContainerRequest, Snapshot};
use std::collections::BTreeMap;

#[test]
fn all_ten_development_helpers_distinguish_positive_and_negative_fixtures_in_an_admitted_worker() {
    let (reg, policy, pins) = common::setup();
    let mut files = BTreeMap::new();
    for (i, pin) in pins.iter().enumerate() {
        let p = reg.load(pin, &policy).unwrap();
        let cases = std::str::from_utf8(p.file("evals/cases.jsonl").unwrap()).unwrap();
        for line in cases.lines() {
            let c: serde_json::Value = serde_json::from_str(line).unwrap();
            let bytes = serde_json::to_vec(&c["input"]).unwrap();
            let digest = p
                .validate_script_input("scripts/assess.py", &bytes)
                .unwrap();
            let plan = p
                .script_plan("scripts/assess.py", &policy, &digest)
                .unwrap();
            assert!(plan.requires_broker_admission);
        }
        files.insert(
            format!("skill-{i}.py"),
            p.file("scripts/assess.py").unwrap().to_vec(),
        );
        files.insert(
            format!("skill-{i}.jsonl"),
            p.file("evals/cases.jsonl").unwrap().to_vec(),
        );
        files.insert(
            format!("skill-{i}.schema.json"),
            p.file("schemas/output.json").unwrap().to_vec(),
        );
    }
    let script = r#"import subprocess,json,pathlib,sys
results=[]
for i in range(10):
 for line in pathlib.Path(f'skill-{i}.jsonl').read_text(encoding='utf-8').splitlines():
  c=json.loads(line)
  r=subprocess.run([sys.executable,'-I','-S',f'skill-{i}.py'],input=json.dumps(c['input']),text=True,capture_output=True,timeout=10)
  assert r.returncode==0,(i,c,r.stderr)
  out=json.loads(r.stdout)
  assert out['authority']=='untrusted_observation' and out['protected_acceptance'] is False
  if 'expected_status' in c: assert out['status']==c['expected_status'],(i,c,out)
  if 'expected_not_status' in c: assert out['status']!=c['expected_not_status'],(i,c,out)
  results.append({'skill_index':i,'case':c['id'],'observation':out})
print(json.dumps({'cases':results,'count':len(results),'held_out':False,'real_ai':False}))
"#;
    let request = ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: COMPLETE_IMAGE.into(),
        executable: PYTHON.into(),
        argv: vec!["-I".into(), "-S".into(), "-c".into(), script.into()],
        cwd: ".".into(),
        env: BTreeMap::new(),
        limits: support::limits(),
    };
    let snapshot = Snapshot { files };
    let mut f = support::Fixture::new(
        "pub fn fixture(){}\n",
        RustOperation::Build,
        &[],
        support::limits(),
    );
    let permit = support::permit_for(&mut f, &request, &snapshot);
    let r = f
        .broker
        .execute(
            &f.task.task_id,
            &permit,
            &snapshot,
            &support::identity(),
            &support::no(),
        )
        .unwrap();
    assert!(!r.requires_reconciliation);
    let report = r.report.unwrap();
    assert_eq!(report.exit_code, Some(0), "{report:?}");
    assert!(
        report.cleanup_confirmed
            && report.tree_confirmed_stopped
            && report.policy_verified
            && !report.output_truncated
            && !report.export_truncated
    );
    let bytes = report.stdout;
    let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["count"], 20);
    for c in out["cases"].as_array().unwrap() {
        let i = c["skill_index"].as_u64().unwrap() as usize;
        let p = reg.load(&pins[i], &policy).unwrap();
        let schema = serde_json::from_slice(p.file("schemas/output.json").unwrap()).unwrap();
        melissa_model_gateway::schema::validate_output(
            &schema,
            &serde_json::to_string(&c["observation"]).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
        std::fs::read(f._dir.path().join("repo/dirty.txt")).unwrap(),
        b"preserve this user's work\r\n"
    );
}
