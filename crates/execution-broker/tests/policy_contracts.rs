use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use melissa_container_executor::{ContainerLimits, ContainerRequest};
use melissa_core_contracts::Module;
use melissa_core_contracts::catalog::Catalog;
use melissa_core_contracts::json::parse_contract;
use melissa_core_contracts::validation::Validate;
use melissa_core_contracts::wire::{TaskContractV1, TaskLimitsV1};
use melissa_execution_broker::container_policy::*;
use melissa_execution_broker::control_policy::*;
use melissa_execution_broker::policy::*;
use serde_json::{Value, json};

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
    })
}
fn task() -> TaskContractV1 {
    TaskContractV1 {
        schema_version: "melissa.task-contract/v1".into(),
        task_id: "task:policy".into(),
        module: Module::Code,
        goal: "Inspect an isolated test fixture".into(),
        workspace_ref: "workspace:policy".into(),
        input_snapshot_digest: "blake3:fixture".into(),
        acceptance_contract_digest: "blake3:protected".into(),
        acceptance_criteria: vec!["independent evidence".into()],
        selected_profile_ids: vec!["melissa.code.implementer".into()],
        allowed_resource_ids: vec!["workspace:policy".into()],
        allowed_effects: vec![
            "process.execute_scoped".into(),
            "workspace.apply_patch_scoped".into(),
            "workspace.read".into(),
        ],
        authorization_refs: vec!["authorization:host-review".into()],
        authority_source: "user_task_and_rust_policy".into(),
        limits: TaskLimitsV1 {
            max_wall_time_ms: 60_000,
            max_cost_micro_usd: 0,
            max_input_tokens: 0,
            max_output_tokens: 0,
            max_parallel_jobs: 1,
            max_disk_bytes: 10_000,
            max_output_bytes: 10_000,
        },
    }
}
fn limits() -> ProcessLimits {
    ProcessLimits {
        wall_time_ms: 5_000,
        cpu_time_ms: 3_000,
        cpu_rate_basis_points: 5_000,
        cpu_mode: CpuLimitMode::StrictTotal,
        memory_bytes: 1_000_000,
        disk_bytes: 1_000,
        disk_mode: DiskLimitMode::Strict,
        output_bytes: 1_000,
        max_processes: 4,
        network: NetworkPolicy::Deny,
    }
}
fn resolved() -> ResolvedProcess {
    #[cfg(windows)]
    let (executable, cwd) = ("C:\\verified\\worker.exe", "C:\\workspace\\fixture");
    #[cfg(not(windows))]
    let (executable, cwd) = ("/verified/worker", "/workspace/fixture");
    ResolvedProcess {
        spec: ProcessSpec {
            schema_version: "melissa.process-exec/v2".into(),
            executable: executable.into(),
            argv: vec![
                "literal argument with spaces".into(),
                "; echo injected | more & $(x)".into(),
            ],
            cwd: "fixture".into(),
            env: BTreeMap::from([("LANG".into(), "tr_TR.UTF-8".into())]),
            limits: limits(),
            effects: vec![
                "process.execute_scoped".into(),
                "workspace.apply_patch_scoped".into(),
            ],
            worker_type: "generic".into(),
        },
        canonical_executable: executable.into(),
        executable_digest: format!("blake3:{}", "a".repeat(64)),
        executable_identity: "volume:1/file:42".into(),
        canonical_cwd: cwd.into(),
        cwd_identity: "volume:1/file:100".into(),
        workspace_identity: "volume:1/file:99".into(),
    }
}
fn request() -> PermitRequest {
    PermitRequest {
        permit_id: "permit:policy".into(),
        nonce: "nonce:host-random".into(),
        principal_id: "principal:host".into(),
        profile_id: "melissa.code.implementer".into(),
        resource_id: "workspace:policy".into(),
        authorization_ref: "authorization:host-review".into(),
        not_before_unix_ms: 1_000,
        expires_at_unix_ms: 5_000,
    }
}
fn authority() -> PermitAuthority {
    PermitAuthority::new(PermitMacKey::from_bytes([23; 32]))
}
fn host_policy(task: &TaskContractV1, process: &ResolvedProcess) -> HostPolicy {
    let grant = AuthorityGrant {
        authorization_ref: "authorization:host-review".into(),
        task_id: task.task_id.clone(),
        task_digest: authenticated_digest(task).unwrap(),
        principal_id: "principal:host".into(),
        profile_id: "melissa.code.implementer".into(),
        resource_id: "workspace:policy".into(),
        process_digest: process.resolved_digest().unwrap(),
        allow_monitored_disk: false,
        allow_monitored_cpu: false,
        allowed_effects: task.allowed_effects.iter().cloned().collect(),
        not_before_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
    };
    HostPolicy {
        revision: "policy:1".into(),
        revocation_epoch: 7,
        issuer: "host:broker".into(),
        audience: "executor:generic".into(),
        key_id: "key:current-session".into(),
        max_permit_lifetime_ms: 5_000,
        ceiling: limits(),
        enforcement: EnforcementCapabilities {
            filesystem_isolation: true,
            network_isolation: true,
            cpu_time: true,
            memory: true,
            disk_quota: true,
            process_tree: true,
            output_limit: true,
        },
        allow_monitored_disk: false,
        allow_monitored_cpu: false,
        allowed_env_names: BTreeSet::from(["LANG".into()]),
        grants: BTreeMap::from([(grant.authorization_ref.clone(), grant)]),
        control_grants: BTreeMap::new(),
        revoked_authorization_refs: BTreeSet::new(),
        revoked_permit_ids: BTreeSet::new(),
        revoked_nonces: BTreeSet::new(),
    }
}
fn signed() -> (TaskContractV1, ResolvedProcess, HostPolicy, SignedPermit) {
    let task = task();
    let process = resolved();
    let policy = host_policy(&task, &process);
    let permit = authority()
        .issue(catalog(), &task, process.clone(), request(), &policy, 2_000)
        .unwrap();
    (task, process, policy, permit)
}

#[test]
fn exact_host_grant_admits_literal_argv_without_shell_interpretation() {
    let (task, process, policy, permit) = signed();
    authority()
        .verify(catalog(), &task, &permit, &process, &policy, 2_000)
        .unwrap();
    assert_eq!(permit.permit.max_invocations, 1);
    assert_eq!(
        permit.permit.arguments_digest,
        process.spec.arguments_digest().unwrap()
    );
    assert_eq!(
        permit.binding.resolved_digest,
        process.resolved_digest().unwrap()
    );
    assert_eq!(permit.permit.arguments_digest.len(), 64);
    assert!(!format!("{:?}", PermitMacKey::from_bytes([23; 32])).contains("23"));
}

#[test]
fn canonical_argument_digest_matches_journal_json_value_bytes() {
    let process = resolved();
    let value = serde_json::to_value(&process.spec).unwrap();
    assert_eq!(
        process.arguments_digest().unwrap(),
        blake3::hash(&serde_json::to_vec(&value).unwrap())
            .to_hex()
            .to_string()
    );
    let object_a = json!({"z":[{"a":1,"b":2}],"a":4});
    let object_b: Value = serde_json::from_str("{\"a\":4,\"z\":[{\"b\":2,\"a\":1}]}").unwrap();
    assert_eq!(
        authenticated_digest(&object_a).unwrap(),
        authenticated_digest(&object_b).unwrap()
    );
}

#[test]
fn every_permit_and_binding_field_is_mac_protected() {
    let (task, process, policy, permit) = signed();
    let original = serde_json::to_value(&permit).unwrap();
    for path in [
        "/permit/permit_id",
        "/permit/task_id",
        "/permit/principal_id",
        "/permit/tool_id",
        "/permit/resource_id",
        "/permit/arguments_digest",
        "/permit/issuer",
        "/permit/audience",
        "/permit/nonce",
        "/permit/policy_version",
        "/permit/authorization_ref",
        "/binding/key_id",
        "/binding/profile_id",
        "/binding/process/executable_identity",
        "/binding/process/cwd_identity",
        "/binding/process/workspace_identity",
        "/binding/process/canonical_executable",
        "/binding/process/canonical_cwd",
        "/binding/process/spec/executable",
        "/binding/process/spec/cwd",
        "/binding/process/spec/worker_type",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = json!("changed");
        let candidate: SignedPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify(catalog(), &task, &candidate, &process, &policy, 2_000)
                .is_err(),
            "tamper accepted: {path}"
        );
    }
    for path in [
        "/permit/not_before_unix_ms",
        "/permit/expires_at_unix_ms",
        "/permit/max_invocations",
        "/permit/max_duration_ms",
        "/binding/revocation_epoch",
        "/binding/process/spec/limits/wall_time_ms",
        "/binding/process/spec/limits/cpu_time_ms",
        "/binding/process/spec/limits/memory_bytes",
        "/binding/process/spec/limits/disk_bytes",
        "/binding/process/spec/limits/output_bytes",
        "/binding/process/spec/limits/max_processes",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = json!(9);
        let candidate: SignedPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify(catalog(), &task, &candidate, &process, &policy, 2_000)
                .is_err(),
            "tamper accepted: {path}"
        );
    }
    for path in [
        "/binding/policy_digest",
        "/binding/task_digest",
        "/binding/profile_digest",
        "/binding/resolved_digest",
        "/binding/process/executable_digest",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = json!(format!("blake3:{}", "b".repeat(64)));
        let candidate: SignedPermit = serde_json::from_value(changed).unwrap();
        assert!(
            matches!(
                authority().verify(catalog(), &task, &candidate, &process, &policy, 2_000),
                Err(PolicyError::Authentication)
            ),
            "digest tamper accepted: {path}"
        );
    }
    for (path, replacement) in [
        ("/binding/process/spec/argv", json!(["different"])),
        ("/binding/process/spec/env", json!({"LANG":"different"})),
        ("/binding/process/spec/effects", json!(["workspace.read"])),
        ("/permit/allowed_effects", json!(["workspace.read"])),
        ("/binding/process/spec/limits/disk_mode", json!("monitored")),
        (
            "/binding/process/spec/limits/cpu_mode",
            json!("monitored_total"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        let candidate: SignedPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify(catalog(), &task, &candidate, &process, &policy, 2_000)
                .is_err(),
            "tamper accepted: {path}"
        );
    }
}

#[test]
fn wrong_key_or_fake_signature_never_authenticates() {
    let (task, process, policy, permit) = signed();
    assert!(matches!(
        PermitAuthority::new(PermitMacKey::from_bytes([24; 32])).verify(
            catalog(),
            &task,
            &permit,
            &process,
            &policy,
            2_000
        ),
        Err(PolicyError::Authentication)
    ));
    for signature in [
        "".to_string(),
        "0".repeat(64),
        "f".repeat(64),
        "F".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
    ] {
        let mut candidate = permit.clone();
        candidate.permit.signature_or_mac = signature;
        assert!(
            authority()
                .verify(catalog(), &task, &candidate, &process, &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn declarative_authorization_string_without_host_grant_has_no_authority() {
    let task = task();
    let process = resolved();
    let mut policy = host_policy(&task, &process);
    policy.grants.clear();
    assert!(
        authority()
            .issue(catalog(), &task, process, request(), &policy, 2_000)
            .is_err()
    );
    let mut task = task;
    task.authorization_refs.clear();
    let process = resolved();
    let policy = host_policy(&task, &process);
    assert!(
        authority()
            .issue(catalog(), &task, process, request(), &policy, 2_000)
            .is_err()
    );
}

#[test]
fn reviewed_grant_binds_all_identity_and_exact_process_scope() {
    let task = task();
    let process = resolved();
    let original = host_policy(&task, &process);
    let mutations: [fn(&mut AuthorityGrant); 8] = [
        |g| g.authorization_ref = "another".into(),
        |g| g.task_id = "another".into(),
        |g| g.task_digest = format!("blake3:{}", "f".repeat(64)),
        |g| g.principal_id = "another".into(),
        |g| g.profile_id = "another".into(),
        |g| g.resource_id = "another".into(),
        |g| g.process_digest = format!("blake3:{}", "f".repeat(64)),
        |g| g.allowed_effects.clear(),
    ];
    for change in mutations {
        let mut policy = original.clone();
        change(policy.grants.values_mut().next().unwrap());
        assert!(
            authority()
                .issue(catalog(), &task, process.clone(), request(), &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn validity_is_half_open_and_bounded_by_host_grant_and_policy() {
    let (task, process, policy, permit) = signed();
    assert!(
        authority()
            .verify(catalog(), &task, &permit, &process, &policy, 999)
            .is_err()
    );
    authority()
        .verify(catalog(), &task, &permit, &process, &policy, 1_000)
        .unwrap();
    authority()
        .verify(catalog(), &task, &permit, &process, &policy, 4_999)
        .unwrap();
    assert!(
        authority()
            .verify(catalog(), &task, &permit, &process, &policy, 5_000)
            .is_err()
    );
    for (start, end) in [
        (999, 5_000),
        (1_000, 10_001),
        (1_000, 7_000),
        (2_000, 2_000),
        (u64::MAX - 10, u64::MAX),
    ] {
        let mut request = request();
        request.not_before_unix_ms = start;
        request.expires_at_unix_ms = end;
        assert!(
            authority()
                .issue(catalog(), &task, process.clone(), request, &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn policy_changes_and_each_revocation_list_are_rechecked() {
    let (task, process, original, permit) = signed();
    let mutations: [fn(&mut HostPolicy); 8] = [
        |p| p.revision = "policy:2".into(),
        |p| p.revocation_epoch += 1,
        |p| p.issuer = "new".into(),
        |p| p.audience = "new".into(),
        |p| p.key_id = "new".into(),
        |p| {
            p.revoked_authorization_refs
                .insert("authorization:host-review".into());
        },
        |p| {
            p.revoked_permit_ids.insert("permit:policy".into());
        },
        |p| {
            p.revoked_nonces.insert("nonce:host-random".into());
        },
    ];
    for change in mutations {
        let mut policy = original.clone();
        change(&mut policy);
        assert!(
            authority()
                .verify(catalog(), &task, &permit, &process, &policy, 2_000)
                .is_err()
        );
    }
    let mut changed = original.clone();
    changed.allowed_env_names.clear();
    assert!(
        authority()
            .verify(catalog(), &task, &permit, &process, &changed, 2_000)
            .is_err()
    );
}

#[test]
fn changed_task_profile_or_canonical_target_is_denied() {
    let (task, process, policy, permit) = signed();
    let mut changed_task = task.clone();
    changed_task.goal.push_str(" changed");
    assert!(
        authority()
            .verify(catalog(), &changed_task, &permit, &process, &policy, 2_000)
            .is_err()
    );
    let mut changed_catalog = catalog().clone();
    changed_catalog
        .profiles
        .get_mut("melissa.code.implementer")
        .unwrap()
        .system_prompt_tr
        .push_str(" changed");
    assert!(
        authority()
            .verify(&changed_catalog, &task, &permit, &process, &policy, 2_000)
            .is_err()
    );
    for change in [
        |p: &mut ResolvedProcess| p.executable_identity.push('x'),
        |p: &mut ResolvedProcess| p.cwd_identity.push('x'),
        |p: &mut ResolvedProcess| p.workspace_identity.push('x'),
    ] {
        let mut changed = process.clone();
        change(&mut changed);
        assert!(
            authority()
                .verify(catalog(), &task, &permit, &changed, &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn catalog_profile_requires_exact_route_capability_worker_and_effect_ceiling() {
    for change in [
        |c: &mut Catalog| {
            c.profiles
                .get_mut("melissa.code.implementer")
                .unwrap()
                .tool_ids
                .retain(|s| s != "process.exec")
        },
        |c: &mut Catalog| {
            c.profiles
                .get_mut("melissa.code.implementer")
                .unwrap()
                .authority
                .capability_ceiling
                .retain(|s| s != "process.execute_scoped")
        },
        |c: &mut Catalog| {
            c.profiles
                .get_mut("melissa.code.implementer")
                .unwrap()
                .worker_types
                .clear()
        },
        |c: &mut Catalog| c.tools.tools.retain(|t| t.id != "process.exec"),
    ] {
        let mut changed = catalog().clone();
        change(&mut changed);
        let task = task();
        let process = resolved();
        let policy = host_policy(&task, &process);
        assert!(
            authority()
                .issue(&changed, &task, process, request(), &policy, 2_000)
                .is_err()
        );
    }
    let mut task = task();
    task.allowed_effects.push("workspace.write".into());
    let mut process = resolved();
    process.spec.effects = vec!["workspace.write".into()];
    let policy = host_policy(&task, &process);
    assert!(
        authority()
            .issue(catalog(), &task, process, request(), &policy, 2_000)
            .is_err()
    );
}

#[test]
fn writable_executor_cannot_be_authorized_as_a_read_only_process() {
    for effects in [
        vec!["workspace.read".to_string()],
        vec!["process.execute_scoped".to_string()],
        vec!["workspace.apply_patch_scoped".to_string()],
    ] {
        let mut task = task();
        task.allowed_effects = effects.clone();
        let mut process = resolved();
        process.spec.effects = effects;
        let policy = host_policy(&task, &process);
        assert!(
            authority()
                .issue(catalog(), &task, process, request(), &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn task_selected_profile_resource_and_module_are_required_even_with_host_grant() {
    for change in [
        |t: &mut TaskContractV1| t.selected_profile_ids = vec!["melissa.code.reviewer".into()],
        |t: &mut TaskContractV1| t.allowed_resource_ids = vec!["workspace:other".into()],
        |t: &mut TaskContractV1| t.module = Module::Cyber,
        |t: &mut TaskContractV1| t.allowed_effects = vec!["workspace.read".into()],
    ] {
        let mut task = task();
        change(&mut task);
        let process = resolved();
        let policy = host_policy(&task, &process);
        assert!(
            authority()
                .issue(catalog(), &task, process, request(), &policy, 2_000)
                .is_err()
        );
    }
    for identifier in ["", "   ", "auth\0injected"] {
        let task = task();
        let process = resolved();
        let policy = host_policy(&task, &process);
        let mut request = request();
        request.authorization_ref = identifier.into();
        assert!(
            authority()
                .issue(catalog(), &task, process, request, &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn task_zero_disk_and_output_are_not_treated_as_unlimited() {
    for zero_disk in [true, false] {
        let mut task = task();
        if zero_disk {
            task.limits.max_disk_bytes = 0;
        } else {
            task.limits.max_output_bytes = 0;
        }
        let process = resolved();
        let policy = host_policy(&task, &process);
        assert!(
            authority()
                .issue(catalog(), &task, process, request(), &policy, 2_000)
                .is_err()
        );
    }
    let mut task = task();
    task.limits.max_output_bytes = 0;
    let mut process = resolved();
    process.spec.limits.output_bytes = 0;
    let policy = host_policy(&task, &process);
    authority()
        .issue(catalog(), &task, process, request(), &policy, 2_000)
        .unwrap();
}

#[test]
fn unsupported_isolation_and_hard_resource_modes_fail_closed() {
    let task = task();
    let process = resolved();
    let original = host_policy(&task, &process);
    for change in [
        |c: &mut EnforcementCapabilities| c.filesystem_isolation = false,
        |c: &mut EnforcementCapabilities| c.network_isolation = false,
        |c: &mut EnforcementCapabilities| c.cpu_time = false,
        |c: &mut EnforcementCapabilities| c.memory = false,
        |c: &mut EnforcementCapabilities| c.disk_quota = false,
        |c: &mut EnforcementCapabilities| c.process_tree = false,
        |c: &mut EnforcementCapabilities| c.output_limit = false,
    ] {
        let mut policy = original.clone();
        change(&mut policy.enforcement);
        assert!(matches!(
            authority().issue(catalog(), &task, process.clone(), request(), &policy, 2_000),
            Err(PolicyError::Unsupported(_))
        ));
    }
}

#[test]
fn monitored_disk_needs_both_reviewed_host_opt_ins_and_positive_allowance() {
    let task = task();
    let mut process = resolved();
    process.spec.limits.disk_mode = DiskLimitMode::Monitored;
    for host in [false, true] {
        for grant in [false, true] {
            let mut policy = host_policy(&task, &process);
            policy.enforcement.disk_quota = false;
            policy.allow_monitored_disk = host;
            policy
                .grants
                .values_mut()
                .next()
                .unwrap()
                .allow_monitored_disk = grant;
            assert_eq!(
                authority()
                    .issue(catalog(), &task, process.clone(), request(), &policy, 2_000)
                    .is_ok(),
                host && grant
            );
        }
    }
    process.spec.limits.disk_bytes = 0;
    let mut policy = host_policy(&task, &process);
    policy.allow_monitored_disk = true;
    policy
        .grants
        .values_mut()
        .next()
        .unwrap()
        .allow_monitored_disk = true;
    assert!(
        authority()
            .issue(catalog(), &task, process, request(), &policy, 2_000)
            .is_err()
    );
}

#[test]
fn monitored_total_cpu_needs_both_reviewed_host_opt_ins() {
    let task = task();
    let mut process = resolved();
    process.spec.limits.cpu_mode = CpuLimitMode::MonitoredTotal;
    for host in [false, true] {
        for grant in [false, true] {
            let mut policy = host_policy(&task, &process);
            policy.enforcement.cpu_time = false;
            policy.allow_monitored_cpu = host;
            policy
                .grants
                .values_mut()
                .next()
                .unwrap()
                .allow_monitored_cpu = grant;
            assert_eq!(
                authority()
                    .issue(catalog(), &task, process.clone(), request(), &policy, 2_000)
                    .is_ok(),
                host && grant
            );
        }
    }
}

#[test]
fn resource_request_cannot_exceed_immutable_host_ceilings() {
    let task = task();
    let original = resolved();
    for change in [
        |l: &mut ProcessLimits| l.wall_time_ms += 1,
        |l: &mut ProcessLimits| l.cpu_time_ms += 1,
        |l: &mut ProcessLimits| l.cpu_rate_basis_points += 1,
        |l: &mut ProcessLimits| l.memory_bytes += 1,
        |l: &mut ProcessLimits| l.disk_bytes += 1,
        |l: &mut ProcessLimits| l.output_bytes += 1,
        |l: &mut ProcessLimits| l.max_processes += 1,
    ] {
        let mut process = original.clone();
        change(&mut process.spec.limits);
        let policy = host_policy(&task, &process);
        assert!(
            authority()
                .issue(catalog(), &task, process, request(), &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn native_unrepresentable_requests_fail_before_permit_signing() {
    let original = resolved().spec;
    for change in [
        |p: &mut ProcessSpec| p.limits.cpu_time_ms = i64::MAX as u64 / 10_000 + 1,
        |p: &mut ProcessSpec| p.limits.output_bytes = 64 * 1024 * 1024 + 1,
        |p: &mut ProcessSpec| {
            p.env.insert("LANG".into(), "a".repeat(30_000));
        },
    ] {
        let mut spec = original.clone();
        change(&mut spec);
        assert!(spec.validate().is_err());
        assert!(
            parse_contract::<ProcessSpec>(&serde_json::to_vec(&spec).unwrap(), MAX_BYTES).is_err()
        );
    }
    let mut largest = original;
    largest.limits.cpu_time_ms = i64::MAX as u64 / 10_000;
    largest.limits.output_bytes = 64 * 1024 * 1024;
    largest.env = BTreeMap::from([("LANG".into(), "a".repeat(29_994))]);
    largest.validate().unwrap();
    largest.env.get_mut("LANG").unwrap().push('a');
    assert!(largest.validate().is_err());
}

#[test]
fn process_v2_requires_explicit_valid_cpu_rate_and_rejects_legacy_v1() {
    let original = resolved().spec;
    for rate in [1, 10_000] {
        let mut spec = original.clone();
        spec.limits.cpu_rate_basis_points = rate;
        spec.validate().unwrap();
    }
    for rate in [0, 10_001, u16::MAX] {
        let mut spec = original.clone();
        spec.limits.cpu_rate_basis_points = rate;
        assert!(spec.validate().is_err());
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["limits"]
        .as_object_mut()
        .unwrap()
        .remove("cpu_rate_basis_points");
    assert!(
        parse_contract::<ProcessSpec>(&serde_json::to_vec(&value).unwrap(), MAX_BYTES).is_err()
    );
    let mut value = serde_json::to_value(&original).unwrap();
    value["schema_version"] = json!("melissa.process-exec/v1");
    assert!(
        parse_contract::<ProcessSpec>(&serde_json::to_vec(&value).unwrap(), MAX_BYTES).is_err()
    );
}

#[test]
fn environment_never_implicitly_inherits_and_requires_host_allowlist() {
    let task = task();
    let mut process = resolved();
    process
        .spec
        .env
        .insert("SECRET".into(), "model asked".into());
    let policy = host_policy(&task, &process);
    assert!(
        authority()
            .issue(catalog(), &task, process, request(), &policy, 2_000)
            .is_err()
    );
    let mut process = resolved();
    process.spec.env.insert("lang".into(), "duplicate".into());
    assert!(process.validate().is_err());
    let mut process = resolved();
    process.spec.env.clear();
    let policy = host_policy(&task, &process);
    authority()
        .issue(catalog(), &task, process, request(), &policy, 2_000)
        .unwrap();
}

#[test]
fn caller_cannot_override_reserved_host_environment_even_if_allowlisted() {
    for name in [
        "SystemRoot",
        "localappdata",
        "TEMP",
        "tmp",
        "Path",
        "PATHEXT",
        "comspec",
        "WINDIR",
        "SYSTEMDRIVE",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "gh_token",
    ] {
        let mut process = resolved();
        process.spec.env.insert(name.into(), "model-value".into());
        assert!(reserved_environment_name(name));
        assert!(
            process.validate().is_err(),
            "reserved environment accepted: {name}"
        );
        assert!(
            parse_contract::<ProcessSpec>(&serde_json::to_vec(&process.spec).unwrap(), MAX_BYTES)
                .is_err()
        );
    }
}

#[test]
fn resolved_scope_authenticates_versioned_host_environment_transform() {
    let process = resolved();
    assert_eq!(
        process.resolved_digest().unwrap(),
        authenticated_digest(
            &json!({"execution_contract":HOST_EXECUTION_CONTRACT_VERSION,"process":process})
        )
        .unwrap()
    );
    assert_ne!(
        process.resolved_digest().unwrap(),
        authenticated_digest(&process).unwrap()
    );
    assert_ne!(process.resolved_digest().unwrap(),authenticated_digest(&json!({"execution_contract":"windows.appcontainer.job.environment/v999","process":process})).unwrap());
}

#[test]
fn strict_parser_rejects_unknown_fields_versions_network_and_duplicate_keys() {
    let original = serde_json::to_value(&resolved().spec).unwrap();
    for (pointer, replacement) in [
        ("/schema_version", json!("melissa.process-exec/v99")),
        ("/limits/network", json!("allow")),
        ("/limits/disk_mode", json!("auto")),
        ("/limits/cpu_mode", json!("auto")),
        ("/worker_type", json!("cyber-lab")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            parse_contract::<ProcessSpec>(&serde_json::to_vec(&changed).unwrap(), MAX_BYTES)
                .is_err()
        );
    }
    let mut changed = original.clone();
    changed["inherit_environment"] = json!(true);
    assert!(
        parse_contract::<ProcessSpec>(&serde_json::to_vec(&changed).unwrap(), MAX_BYTES).is_err()
    );
    let mut changed = original.clone();
    changed["limits"]["gpu_vram_bytes"] = json!(1);
    assert!(
        parse_contract::<ProcessSpec>(&serde_json::to_vec(&changed).unwrap(), MAX_BYTES).is_err()
    );
    let text = serde_json::to_string(&original).unwrap().replacen(
        '{',
        "{\"schema_version\":\"melissa.process-exec/v2\",",
        1,
    );
    assert!(parse_contract::<ProcessSpec>(text.as_bytes(), MAX_BYTES).is_err());
}
const MAX_BYTES: usize = 128 * 1024;

#[test]
fn process_validation_rejects_nul_traversal_shell_wrapper_and_oversize() {
    let mutations: [fn(&mut ProcessSpec); 12] = [
        |p| p.executable = "worker".into(),
        |p| p.executable.push('\0'),
        |p| p.argv.push("bad\0arg".into()),
        |p| p.cwd = "../escape".into(),
        |p| p.cwd = "..\\escape".into(),
        |p| p.cwd = "C:relative".into(),
        |p| {
            p.env
                .insert("BAD=NAME".into(), "x".into())
                .map(drop)
                .unwrap_or(())
        },
        |p| {
            p.env
                .insert("NUL".into(), "a\0b".into())
                .map(drop)
                .unwrap_or(())
        },
        |p| p.argv = vec!["x".repeat(65_536)],
        |p| p.argv = vec!["x".into(); 1025],
        |p| p.limits.wall_time_ms = 0,
        |p| p.effects.clear(),
    ];
    for change in mutations {
        let mut process = resolved().spec;
        change(&mut process);
        assert!(process.validate().is_err());
    }
    let mut process = resolved().spec;
    process.executable = if cfg!(windows) {
        "C:\\Windows\\fake.cmd"
    } else {
        "/fake/script.cmd"
    }
    .into();
    assert!(process.validate().is_err());
}

#[test]
fn wire_round_trip_keeps_modes_and_rejects_extra_binding_authority() {
    let (task, process, policy, permit) = signed();
    let bytes = serde_json::to_vec(&permit).unwrap();
    let decoded: SignedPermit = parse_contract(&bytes, MAX_BYTES).unwrap();
    assert_eq!(decoded, permit);
    authority()
        .verify(catalog(), &task, &decoded, &process, &policy, 2_000)
        .unwrap();
    let mut value = serde_json::to_value(permit).unwrap();
    value["binding"]["model_authorizes"] = json!(true);
    assert!(
        parse_contract::<SignedPermit>(&serde_json::to_vec(&value).unwrap(), MAX_BYTES).is_err()
    );
}

fn control_fixture(
    tool: ControlTool,
) -> (
    TaskContractV1,
    ProcessControlRequest,
    HostPolicy,
    PermitRequest,
) {
    let mut task = task();
    task.selected_profile_ids = vec!["melissa.code.debugger".into()];
    task.allowed_effects.extend([
        "process.inspect_owned".into(),
        "process.cancel_owned".into(),
    ]);
    task.authorization_refs
        .push("authorization:separate-control".into());
    let mut policy = host_policy(&task, &resolved());
    let control = ProcessControlRequest {
        schema_version: "melissa.process-control/v1".into(),
        tool,
        task_id: task.task_id.clone(),
        invocation_id: "invocation:owned".into(),
        generation: 1,
        resource_id: "workspace:policy".into(),
    };
    let mut permit_request = request();
    permit_request.profile_id = "melissa.code.debugger".into();
    permit_request.authorization_ref = "authorization:separate-control".into();
    policy.control_grants.insert(
        permit_request.authorization_ref.clone(),
        ControlGrant {
            authorization_ref: permit_request.authorization_ref.clone(),
            task_id: task.task_id.clone(),
            task_digest: authenticated_digest(&task).unwrap(),
            principal_id: permit_request.principal_id.clone(),
            profile_id: permit_request.profile_id.clone(),
            resource_id: control.resource_id.clone(),
            tool,
            invocation_id: control.invocation_id.clone(),
            generation: control.generation,
            not_before_unix_ms: 1_000,
            expires_at_unix_ms: 10_000,
        },
    );
    (task, control, policy, permit_request)
}

#[test]
fn separately_granted_typed_owned_process_inspect_and_cancel_authenticate() {
    for tool in [ControlTool::Inspect, ControlTool::Cancel] {
        let (task, control, policy, request) = control_fixture(tool);
        let permit = authority()
            .issue_control(catalog(), &task, control.clone(), request, &policy, 2_000)
            .unwrap();
        authority()
            .verify_control(catalog(), &task, &permit, &control, &policy, 2_000)
            .unwrap();
        assert_eq!(permit.permit.tool_id, tool.tool_id());
        assert_eq!(permit.permit.allowed_effects, vec![tool.effect()]);
        assert_eq!(permit.permit.max_invocations, 1);
        assert_eq!(
            permit.permit.arguments_digest,
            blake3::hash(&serde_json::to_vec(&serde_json::to_value(&control).unwrap()).unwrap())
                .to_hex()
                .to_string()
        );
        let bytes = serde_json::to_vec(&permit).unwrap();
        assert_eq!(
            parse_contract::<SignedControlPermit>(&bytes, MAX_BYTES).unwrap(),
            permit
        );
    }
}

#[test]
fn process_execution_authority_never_implies_process_control_authority() {
    let (task, control, mut policy, mut request) = control_fixture(ControlTool::Cancel);
    policy.control_grants.clear();
    request.authorization_ref = "authorization:host-review".into();
    assert!(
        authority()
            .issue_control(catalog(), &task, control, request, &policy, 2_000)
            .is_err()
    );
}

#[test]
fn control_scope_never_transfers_to_another_invocation_generation_or_tool() {
    let (task, control, policy, request) = control_fixture(ControlTool::Inspect);
    for change in [
        |c: &mut ProcessControlRequest| c.invocation_id = "invocation:foreign".into(),
        |c: &mut ProcessControlRequest| c.generation += 1,
        |c: &mut ProcessControlRequest| c.resource_id = "workspace:foreign".into(),
        |c: &mut ProcessControlRequest| c.task_id = "task:foreign".into(),
        |c: &mut ProcessControlRequest| c.tool = ControlTool::Cancel,
    ] {
        let mut changed = control.clone();
        change(&mut changed);
        assert!(
            authority()
                .issue_control(catalog(), &task, changed, request.clone(), &policy, 2_000)
                .is_err()
        );
    }
    let permit = authority()
        .issue_control(catalog(), &task, control.clone(), request, &policy, 2_000)
        .unwrap();
    let mut current = control.clone();
    current.generation += 1;
    assert!(
        authority()
            .verify_control(catalog(), &task, &permit, &current, &policy, 2_000)
            .is_err()
    );
}

#[test]
fn control_mac_protects_every_identity_tool_target_and_limit() {
    let (task, control, policy, request) = control_fixture(ControlTool::Inspect);
    let permit = authority()
        .issue_control(catalog(), &task, control.clone(), request, &policy, 2_000)
        .unwrap();
    let original = serde_json::to_value(&permit).unwrap();
    for pointer in [
        "/permit/permit_id",
        "/permit/task_id",
        "/permit/principal_id",
        "/permit/tool_id",
        "/permit/resource_id",
        "/permit/arguments_digest",
        "/permit/issuer",
        "/permit/audience",
        "/permit/nonce",
        "/permit/policy_version",
        "/permit/authorization_ref",
        "/binding/key_id",
        "/binding/profile_id",
        "/binding/request/task_id",
        "/binding/request/invocation_id",
        "/binding/request/resource_id",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("tampered");
        let decoded: SignedControlPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify_control(catalog(), &task, &decoded, &control, &policy, 2_000)
                .is_err(),
            "control MAC tamper accepted: {pointer}"
        );
    }
    for pointer in [
        "/permit/not_before_unix_ms",
        "/permit/expires_at_unix_ms",
        "/permit/max_invocations",
        "/permit/max_duration_ms",
        "/binding/revocation_epoch",
        "/binding/request/generation",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(9);
        let decoded: SignedControlPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify_control(catalog(), &task, &decoded, &control, &policy, 2_000)
                .is_err()
        );
    }
    for pointer in [
        "/binding/policy_digest",
        "/binding/task_digest",
        "/binding/profile_digest",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(format!("blake3:{}", "e".repeat(64)));
        let decoded: SignedControlPermit = serde_json::from_value(changed).unwrap();
        assert!(matches!(
            authority().verify_control(catalog(), &task, &decoded, &control, &policy, 2_000),
            Err(PolicyError::Authentication)
        ));
    }
    for (pointer, value) in [
        ("/binding/request/tool", json!("process.cancel")),
        ("/permit/allowed_effects", json!(["process.cancel_owned"])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let decoded: SignedControlPermit = serde_json::from_value(changed).unwrap();
        assert!(matches!(
            authority().verify_control(catalog(), &task, &decoded, &control, &policy, 2_000),
            Err(PolicyError::Authentication)
        ));
    }
    let mut wrong_domain = permit;
    wrong_domain.permit.signature_or_mac = signed().3.permit.signature_or_mac;
    assert!(matches!(
        authority().verify_control(catalog(), &task, &wrong_domain, &control, &policy, 2_000),
        Err(PolicyError::Authentication)
    ));
}

#[test]
fn control_requires_selected_profile_exact_tools_and_corresponding_capability() {
    for tool in [ControlTool::Inspect, ControlTool::Cancel] {
        let (task, control, policy, request) = control_fixture(tool);
        let mut changed = catalog().clone();
        changed
            .profiles
            .get_mut("melissa.code.debugger")
            .unwrap()
            .tool_ids
            .retain(|id| id != tool.tool_id());
        assert!(
            authority()
                .issue_control(
                    &changed,
                    &task,
                    control.clone(),
                    request.clone(),
                    &policy,
                    2_000
                )
                .is_err()
        );
        let mut changed = catalog().clone();
        changed
            .profiles
            .get_mut("melissa.code.debugger")
            .unwrap()
            .authority
            .capability_ceiling
            .retain(|id| {
                id != if tool == ControlTool::Inspect {
                    "process.execute_scoped"
                } else {
                    "process.cancel_owned"
                }
            });
        assert!(
            authority()
                .issue_control(
                    &changed,
                    &task,
                    control.clone(),
                    request.clone(),
                    &policy,
                    2_000
                )
                .is_err()
        );
        let mut changed = catalog().clone();
        changed.tools.tools.retain(|t| t.id != tool.tool_id());
        assert!(
            authority()
                .issue_control(&changed, &task, control, request, &policy, 2_000)
                .is_err()
        );
    }
}

#[test]
fn control_policy_revocation_and_task_profile_changes_are_freshly_rechecked() {
    let (task, control, policy, request) = control_fixture(ControlTool::Cancel);
    let permit = authority()
        .issue_control(catalog(), &task, control.clone(), request, &policy, 2_000)
        .unwrap();
    let changes: [fn(&mut HostPolicy); 5] = [
        |p| p.revocation_epoch += 1,
        |p| {
            p.revoked_nonces.insert("nonce:host-random".into());
        },
        |p| {
            p.revoked_permit_ids.insert("permit:policy".into());
        },
        |p| {
            p.revoked_authorization_refs
                .insert("authorization:separate-control".into());
        },
        |p| p.control_grants.clear(),
    ];
    for change in changes {
        let mut changed = policy.clone();
        change(&mut changed);
        assert!(
            authority()
                .verify_control(catalog(), &task, &permit, &control, &changed, 2_000)
                .is_err()
        );
    }
    let mut changed = task.clone();
    changed.goal.push_str(" new");
    assert!(
        authority()
            .verify_control(catalog(), &changed, &permit, &control, &policy, 2_000)
            .is_err()
    );
    let mut changed = catalog().clone();
    changed
        .profiles
        .get_mut("melissa.code.debugger")
        .unwrap()
        .system_prompt_tr
        .push_str(" new");
    assert!(
        authority()
            .verify_control(&changed, &task, &permit, &control, &policy, 2_000)
            .is_err()
    );
    assert!(
        PermitAuthority::new(PermitMacKey::from_bytes([24; 32]))
            .verify_control(catalog(), &task, &permit, &control, &policy, 2_000)
            .is_err()
    );
}

#[test]
fn control_request_rejects_arbitrary_pids_unknown_fields_bad_generation_and_versions() {
    let (_, control, _, _) = control_fixture(ControlTool::Inspect);
    let original = serde_json::to_value(&control).unwrap();
    for (field, value) in [
        ("pid", json!(1234)),
        ("arbitrary_process_handle", json!(42)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            parse_contract::<ProcessControlRequest>(
                &serde_json::to_vec(&changed).unwrap(),
                MAX_BYTES
            )
            .is_err()
        );
    }
    for (field, value) in [
        ("schema_version", json!("melissa.process-control/v999")),
        ("tool", json!("process.exec")),
        ("generation", json!(u64::MAX)),
        ("invocation_id", json!("invocation\nforeign")),
        ("task_id", json!("")),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            parse_contract::<ProcessControlRequest>(
                &serde_json::to_vec(&changed).unwrap(),
                MAX_BYTES
            )
            .is_err()
        );
    }
    let duplicate =
        serde_json::to_string(&original)
            .unwrap()
            .replacen('{', "{\"generation\":1,", 1);
    assert!(parse_contract::<ProcessControlRequest>(duplicate.as_bytes(), MAX_BYTES).is_err());
}

#[test]
fn control_expiry_effects_and_trusted_grant_windows_are_bounded() {
    let (task, control, policy, request) = control_fixture(ControlTool::Inspect);
    let permit = authority()
        .issue_control(
            catalog(),
            &task,
            control.clone(),
            request.clone(),
            &policy,
            2_000,
        )
        .unwrap();
    authority()
        .verify_control(catalog(), &task, &permit, &control, &policy, 1_000)
        .unwrap();
    assert!(
        authority()
            .verify_control(catalog(), &task, &permit, &control, &policy, 999)
            .is_err()
    );
    assert!(
        authority()
            .verify_control(catalog(), &task, &permit, &control, &policy, 5_000)
            .is_err()
    );
    let mut changed = task.clone();
    changed
        .allowed_effects
        .retain(|e| e != "process.inspect_owned");
    let mut changed_policy = policy.clone();
    changed_policy
        .control_grants
        .values_mut()
        .next()
        .unwrap()
        .task_digest = authenticated_digest(&changed).unwrap();
    assert!(
        authority()
            .issue_control(
                catalog(),
                &changed,
                control.clone(),
                request.clone(),
                &changed_policy,
                2_000
            )
            .is_err()
    );
    let mut changed = policy.clone();
    changed
        .control_grants
        .values_mut()
        .next()
        .unwrap()
        .expires_at_unix_ms = 4_000;
    assert!(
        authority()
            .issue_control(
                catalog(),
                &task,
                control.clone(),
                request.clone(),
                &changed,
                2_000
            )
            .is_err()
    );
    let mut changed_request = request;
    changed_request.expires_at_unix_ms = 7_000;
    assert!(
        authority()
            .issue_control(catalog(), &task, control, changed_request, &policy, 2_000)
            .is_err()
    );
}

fn container_fixture() -> (
    TaskContractV1,
    ContainerRequest,
    String,
    HostPolicy,
    PermitRequest,
) {
    let mut task = task();
    task.limits.max_disk_bytes = 8 * 1024 * 1024;
    task.limits.max_output_bytes = 4 * 1024 * 1024;
    let container = ContainerRequest {
        schema_version: "melissa.container-exec/v1".into(),
        image_id: format!("sha256:{}", "a".repeat(64)),
        executable: "/bin/sh".into(),
        argv: vec!["-c".into(), "printf controlled".into()],
        cwd: ".".into(),
        env: BTreeMap::from([("LANG".into(), "C.UTF-8".into())]),
        limits: ContainerLimits {
            wall_time_ms: 5000,
            cpu_time_ms: 3000,
            cpu_rate_basis_points: 5000,
            memory_bytes: 64 * 1024 * 1024,
            disk_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            max_processes: 16,
            export_bytes: 2048,
        },
    };
    let snapshot_digest = format!("blake3:{}", "b".repeat(64));
    let mut policy = host_policy(&task, &resolved());
    policy.allow_monitored_cpu = true;
    policy.enforcement.cpu_time = false;
    policy.ceiling.memory_bytes = container.limits.memory_bytes;
    policy.ceiling.disk_bytes = container.limits.disk_bytes;
    policy.ceiling.output_bytes = task.limits.max_output_bytes;
    policy.ceiling.max_processes = container.limits.max_processes;
    let grant = policy.grants.values_mut().next().unwrap();
    grant.process_digest = container_execution_digest(&container, &snapshot_digest).unwrap();
    grant.allow_monitored_cpu = true;
    (task, container, snapshot_digest, policy, request())
}

#[test]
fn container_permit_binds_immutable_image_snapshot_and_real_backend_contract() {
    let (task, container, snapshot, policy, request) = container_fixture();
    let permit = authority()
        .issue_container(
            catalog(),
            &task,
            container.clone(),
            snapshot.clone(),
            request,
            &policy,
            2000,
        )
        .unwrap();
    authority()
        .verify_container(
            catalog(),
            &task,
            &permit,
            &container,
            &snapshot,
            &policy,
            2000,
        )
        .unwrap();
    assert_eq!(
        permit.permit.arguments_digest,
        container_arguments_digest(&container).unwrap()
    );
    assert_eq!(permit.binding.execution_digest,authenticated_digest(&json!({"request":container,"snapshot_digest":snapshot,"backend_contract":melissa_container_executor::EXECUTION_CONTRACT})).unwrap());
    assert!(
        !serde_json::to_string(&permit)
            .unwrap()
            .contains("executable_identity")
    );
    let bytes = serde_json::to_vec(&permit).unwrap();
    assert_eq!(
        parse_contract::<SignedContainerPermit>(&bytes, MAX_BYTES).unwrap(),
        permit
    );
}

#[test]
fn container_has_separate_mac_domain_and_does_not_reuse_native_grant() {
    let (task, container, snapshot, mut policy, request) = container_fixture();
    let original = policy.clone();
    policy.grants.values_mut().next().unwrap().process_digest =
        resolved().resolved_digest().unwrap();
    assert!(
        authority()
            .issue_container(
                catalog(),
                &task,
                container.clone(),
                snapshot.clone(),
                request.clone(),
                &policy,
                2000
            )
            .is_err()
    );
    let mut permit = authority()
        .issue_container(
            catalog(),
            &task,
            container.clone(),
            snapshot.clone(),
            request,
            &original,
            2000,
        )
        .unwrap();
    permit.permit.signature_or_mac = signed().3.permit.signature_or_mac;
    assert!(matches!(
        authority().verify_container(
            catalog(),
            &task,
            &permit,
            &container,
            &snapshot,
            &original,
            2000
        ),
        Err(PolicyError::Authentication)
    ));
}

#[test]
fn container_mac_covers_image_snapshot_cpu_rate_disk_and_all_argument_fields() {
    let (task, container, snapshot, policy, request) = container_fixture();
    let permit = authority()
        .issue_container(
            catalog(),
            &task,
            container.clone(),
            snapshot.clone(),
            request,
            &policy,
            2000,
        )
        .unwrap();
    let original = serde_json::to_value(&permit).unwrap();
    for (pointer, value) in [
        (
            "/binding/request/image_id",
            json!(format!("sha256:{}", "c".repeat(64))),
        ),
        (
            "/binding/snapshot_digest",
            json!(format!("blake3:{}", "c".repeat(64))),
        ),
        (
            "/binding/execution_digest",
            json!(format!("blake3:{}", "c".repeat(64))),
        ),
        ("/binding/request/executable", json!("/bin/other")),
        ("/binding/request/argv", json!(["different"])),
        ("/binding/request/env", json!({"LANG":"changed"})),
        ("/binding/request/cwd", json!("subdir")),
        ("/binding/request/limits/cpu_rate_basis_points", json!(2500)),
        ("/binding/request/limits/disk_bytes", json!(4096)),
        ("/binding/request/limits/export_bytes", json!(1024)),
        ("/binding/request/limits/wall_time_ms", json!(4000)),
        ("/permit/nonce", json!("other")),
        ("/permit/resource_id", json!("workspace:other")),
        ("/permit/principal_id", json!("principal:other")),
        ("/binding/revocation_epoch", json!(4)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let decoded: SignedContainerPermit = serde_json::from_value(changed).unwrap();
        assert!(
            authority()
                .verify_container(
                    catalog(),
                    &task,
                    &decoded,
                    &container,
                    &snapshot,
                    &policy,
                    2000
                )
                .is_err(),
            "container tamper accepted: {pointer}"
        );
    }
    assert!(
        authority()
            .verify_container(
                catalog(),
                &task,
                &permit,
                &container,
                &format!("blake3:{}", "d".repeat(64)),
                &policy,
                2000
            )
            .is_err()
    );
}

#[test]
fn container_requires_real_strict_disk_capability_and_explicit_total_cpu_opt_ins() {
    let (task, container, snapshot, original, request) = container_fixture();
    for host in [false, true] {
        for grant in [false, true] {
            let mut policy = original.clone();
            policy.allow_monitored_cpu = host;
            policy
                .grants
                .values_mut()
                .next()
                .unwrap()
                .allow_monitored_cpu = grant;
            assert_eq!(
                authority()
                    .issue_container(
                        catalog(),
                        &task,
                        container.clone(),
                        snapshot.clone(),
                        request.clone(),
                        &policy,
                        2000
                    )
                    .is_ok(),
                host && grant
            );
        }
    }
    let mut policy = original;
    policy.enforcement.disk_quota = false;
    assert!(matches!(
        authority().issue_container(
            catalog(),
            &task,
            container,
            snapshot,
            request,
            &policy,
            2000
        ),
        Err(PolicyError::Unsupported(_))
    ));
}

#[test]
fn container_output_and_export_share_task_and_host_budgets_without_overflow() {
    let (mut task, container, snapshot, mut policy, request) = container_fixture();
    task.limits.max_output_bytes =
        container.limits.output_bytes + container.limits.export_bytes - 1;
    policy.grants.values_mut().next().unwrap().task_digest = authenticated_digest(&task).unwrap();
    assert!(
        authority()
            .issue_container(
                catalog(),
                &task,
                container.clone(),
                snapshot.clone(),
                request.clone(),
                &policy,
                2000
            )
            .is_err()
    );
    let (task, container, snapshot, mut policy, request) = container_fixture();
    policy.ceiling.output_bytes = container.limits.output_bytes + container.limits.export_bytes - 1;
    assert!(
        authority()
            .issue_container(
                catalog(),
                &task,
                container,
                snapshot,
                request,
                &policy,
                2000
            )
            .is_err()
    );
}

#[test]
fn container_scope_policy_and_mutable_image_rejections_do_not_expand_authority() {
    let (task, container, snapshot, original, request) = container_fixture();
    for change in [
        |p: &mut HostPolicy| {
            p.revoked_nonces.insert("nonce:host-random".into());
        },
        |p: &mut HostPolicy| p.grants.clear(),
        |p: &mut HostPolicy| p.ceiling.cpu_rate_basis_points = 2500,
        |p: &mut HostPolicy| p.allowed_env_names.clear(),
    ] {
        let mut policy = original.clone();
        change(&mut policy);
        assert!(
            authority()
                .issue_container(
                    catalog(),
                    &task,
                    container.clone(),
                    snapshot.clone(),
                    request.clone(),
                    &policy,
                    2000
                )
                .is_err()
        );
    }
    let signed = authority()
        .issue_container(
            catalog(),
            &task,
            container.clone(),
            snapshot.clone(),
            request.clone(),
            &original,
            2000,
        )
        .unwrap();
    let mut changed_policy = original.clone();
    changed_policy.revocation_epoch += 1;
    assert!(
        authority()
            .verify_container(
                catalog(),
                &task,
                &signed,
                &container,
                &snapshot,
                &changed_policy,
                2000
            )
            .is_err()
    );
    for image in ["python:3.12", "alpine:latest", "sha256:abc"] {
        let mut changed = container.clone();
        changed.image_id = image.into();
        assert!(
            authority()
                .issue_container(
                    catalog(),
                    &task,
                    changed,
                    snapshot.clone(),
                    request.clone(),
                    &original,
                    2000
                )
                .is_err()
        );
    }
    let mut changed = catalog().clone();
    changed
        .profiles
        .get_mut("melissa.code.implementer")
        .unwrap()
        .authority
        .capability_ceiling
        .retain(|s| s != "workspace.apply_patch_scoped");
    assert!(
        authority()
            .issue_container(
                &changed, &task, container, snapshot, request, &original, 2000
            )
            .is_err()
    );
}
