//! Native Cargo fingerprint/build artifacts travel only as encrypted, owned host evidence.
//! Cache reuse never skips the real compiler, C03 admission or independent tests.
use crate::{Error, Namespace, Result, digest, require, runtime::put};
use melissa_container_executor::{ContainerLimits, ContainerRequest, Snapshot, TerminationReason};
use melissa_execution_broker::{
    InvocationIdentity, container_broker::ContainerBroker, container_policy::SignedContainerPermit,
};
use melissa_local_store::LocalStore;
use melissa_repository::{Repository, RepositorySnapshot, archive};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};
const PRIVATE: &str = "c07-cache";
const DRIVER: &str = r#"import subprocess,json,pathlib,hashlib,os,shutil,stat
c=['/usr/local/cargo/bin/cargo','build','--locked','--offline','--config','build.incremental=false','--target-dir','c07-cache','--message-format=json']
r=subprocess.run(c,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
messages=[]
for line in r.stdout.decode('utf-8').splitlines():
 try: messages.append(json.loads(line))
 except ValueError: raise RuntimeError('invalid cargo JSON')
artifacts=[m for m in messages if m.get('reason')=='compiler-artifact']
for p in pathlib.Path('c07-cache').rglob('*'):
 if p.is_symlink(): raise RuntimeError('native cache symlink refused')
 if p.is_file() and p.stat().st_nlink>1:
  temp=p.with_name(p.name+'.cache-copy');shutil.copy2(p,temp);os.replace(temp,p)
print(json.dumps({'exit_code':r.returncode,'artifacts':artifacts,'stderr':r.stderr.decode('utf-8'),'command':c,'fresh_artifacts':sum(a['fresh'] for a in artifacts)}))
raise SystemExit(r.returncode)
"#;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    key: String,
    namespace: Namespace,
    expires: u64,
    files: BTreeMap<String, Vec<u8>>,
}
pub struct BuildSeed(Bundle);
pub struct NativeBuildPlan {
    request: ContainerRequest,
    snapshot: Snapshot,
    source: RepositorySnapshot,
    key: String,
    namespace: Namespace,
    expires: u64,
    reused: bool,
}
pub struct NativeBuildResult {
    pub observation: Value,
    pub seed: BuildSeed,
    pub artifact_id: String,
}
impl BuildSeed {
    pub fn restore(
        store: &LocalStore,
        task: &str,
        id: &str,
        expected_digest: &str,
    ) -> Result<Self> {
        let b = store.get_artifact(task, id)?;
        require(digest(&b) == expected_digest, "build seed receipt mismatch")?;
        Ok(Self(crate::json(&b)?))
    }
}
impl NativeBuildPlan {
    pub fn prepare(
        repo: &Repository,
        namespace: Namespace,
        policy: &str,
        expires: u64,
        limits: ContainerLimits,
        seed: Option<&BuildSeed>,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        namespace.validate()?;
        let now = melissa_execution_broker::unix_ms().map_err(|_| Error("clock".into()))?;
        require(
            now < expires && !policy.is_empty(),
            "build cache expired or missing policy",
        )?;
        let source = repo.snapshot(cancel).map_err(|e| Error(e.to_string()))?;
        let mut snapshot = repo
            .worker_input(&source, cancel)
            .map_err(|e| Error(e.to_string()))?
            .snapshot;
        require(
            snapshot.files.contains_key("Cargo.toml")
                && snapshot.files.contains_key("Cargo.lock")
                && !snapshot.files.keys().any(|p| {
                    p.starts_with(PRIVATE)
                        || p.split('/').any(|c| {
                            matches!(c, ".cargo" | "rust-toolchain" | "rust-toolchain.toml")
                        })
                }),
            "reviewed Rust root and private target required",
        )?;
        let key = digest(&serde_json::to_vec(
            &json!({"namespace":namespace,"source":source.digest,"policy":policy,"sdk":melissa_build_test::toolchain::COMPLETE_IMAGE,"driver":digest(DRIVER.as_bytes()),"limits":limits}),
        )?);
        if let Some(seed) = seed {
            require(
                seed.0.key == key && seed.0.namespace == namespace && now < seed.0.expires,
                "native build cache source/SDK/config/policy/scope changed",
            )?;
            for (p, b) in &seed.0.files {
                require(
                    p.starts_with(&format!("{PRIVATE}/")) && !snapshot.files.contains_key(p),
                    "build seed path collision",
                )?;
                snapshot.files.insert(p.clone(), b.clone());
            }
        }
        let request = ContainerRequest {
            schema_version: "melissa.container-exec/v1".into(),
            image_id: melissa_build_test::toolchain::COMPLETE_IMAGE.into(),
            executable: melissa_build_test::toolchain::PYTHON.into(),
            argv: vec![
                "-I".into(),
                "-S".into(),
                "-u".into(),
                "-c".into(),
                DRIVER.into(),
            ],
            cwd: ".".into(),
            env: BTreeMap::new(),
            limits,
        };
        request.validate().map_err(|e| Error(e.to_string()))?;
        snapshot
            .validate(request.limits.disk_bytes)
            .map_err(|e| Error(e.to_string()))?;
        Ok(Self {
            request,
            snapshot,
            source,
            key,
            namespace,
            expires,
            reused: seed.is_some(),
        })
    }
    pub fn request(&self) -> &ContainerRequest {
        &self.request
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn execute(
        &self,
        repo: &Repository,
        broker: &mut ContainerBroker,
        task: &str,
        permit: &SignedContainerPermit,
        identity: &InvocationIdentity,
        cancel: &AtomicBool,
    ) -> Result<NativeBuildResult> {
        require(
            melissa_execution_broker::unix_ms().map_err(|_| Error("clock".into()))? < self.expires,
            "native build seed/plan expired",
        )?;
        repo.validate_snapshot(&self.source, cancel)
            .map_err(|e| Error(e.to_string()))?;
        let execution = broker
            .execute(task, permit, &self.snapshot, identity, cancel)
            .map_err(|e| Error(e.to_string()))?;
        require(
            !execution.requires_reconciliation,
            "native cache worker needs reconciliation",
        )?;
        let report = execution
            .report
            .ok_or_else(|| Error("missing native cache worker report".into()))?;
        let raw_id = format!("{}:native-build-raw", identity.attempt_id);
        put(
            broker.store_mut(),
            task,
            &raw_id,
            "native-build.raw",
            &serde_json::to_vec(&report)?,
        )?;
        require(
            report.image_id == self.request.image_id
                && report.input_digest
                    == self.snapshot.digest().map_err(|e| Error(e.to_string()))?
                && report.termination == TerminationReason::Exited
                && report.exit_code == Some(0)
                && report.cleanup_confirmed
                && report.tree_confirmed_stopped
                && report.policy_verified
                && !report.export_truncated
                && !report.output_truncated
                && report.monitor_error.is_none(),
            "native build/cache worker failure",
        )?;
        repo.validate_snapshot(&self.source, cancel)
            .map_err(|e| Error(e.to_string()))?;
        let observed: Value = crate::json(&report.stdout)?;
        require(
            observed["exit_code"] == 0
                && observed["artifacts"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
            "no native compiler artifacts",
        )?;
        let files = archive::inspect_ustar(&report.archive, repo.limits())
            .map_err(|e| Error(e.to_string()))?;
        let mut output = BTreeMap::new();
        for f in files {
            if f.path.starts_with(&format!("{PRIVATE}/")) {
                output.insert(f.path, f.bytes);
            }
        }
        require(!output.is_empty(), "missing native cache export")?;
        let seed = BuildSeed(Bundle {
            key: self.key.clone(),
            namespace: self.namespace.clone(),
            expires: self.expires,
            files: output,
        });
        let id = format!("{}:native-build-seed", identity.attempt_id);
        let bytes = serde_json::to_vec(&seed.0)?;
        put(broker.store_mut(), task, &id, "native-build.seed", &bytes)?;
        Ok(NativeBuildResult {
            observation: json!({"native":observed,"cache_seed_reused":self.reused,"cache_key":self.key,"seed_digest":digest(&bytes),"source_digest":self.source.digest,"raw_artifact":raw_id,"fresh_compiler_executed":true,"protected_acceptance":false}),
            seed,
            artifact_id: id,
        })
    }
}
