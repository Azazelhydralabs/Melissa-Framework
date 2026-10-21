use super::*;
use crate::{ByteEdit, FilePatch, Limits};
use melissa_core_contracts::{InvocationState, wire::TaskContractV1};
use melissa_local_store::{StoreConfig, StoreKey};
use std::{fs, io::ErrorKind};
use tempfile::TempDir;

fn fixture() -> (TempDir, Repository, LocalStore, PatchPolicy) {
    fixture_with_write(true)
}
fn fixture_with_write(write: bool) -> (TempDir, Repository, LocalStore, PatchPolicy) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a.txt"), b"user-owned\r\nold\r\nkeep\0\xff").unwrap();
    fs::write(root.join("b.txt"), b"other old file\n").unwrap();
    let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
    let mut store = LocalStore::open(
        &temp.path().join("evidence"),
        StoreKey::from_bytes([33; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut contract: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    contract.task_id = "task:repo-fixture".into();
    contract.workspace_ref = "workspace:repo-fixture".into();
    contract.allowed_resource_ids = vec![contract.workspace_ref.clone()];
    contract.allowed_effects = vec![
        "workspace.read".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    if !write {
        contract.allowed_effects = vec!["workspace.read".into()];
    }
    contract.limits.max_disk_bytes = 16 * 1024 * 1024;
    contract.limits.max_wall_time_ms = 60_000;
    store.journal_mut().create_task(&contract).unwrap();
    for next in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = store
            .journal()
            .task(&contract.task_id)
            .unwrap()
            .record
            .version;
        store
            .transition_task(&contract.task_id, v, next, None)
            .unwrap();
    }
    let policy = PatchPolicy {
        principal_id: "principal:repo-fixture".into(),
        task_id: contract.task_id,
        profile_id: contract.selected_profile_ids[0].clone(),
        resource_id: contract.workspace_ref,
        authorization_ref: contract.authorization_refs[0].clone(),
        expires_at_ms: now().unwrap() + 60_000,
        epoch: 0,
        writable_paths: ["a.txt".into(), "b.txt".into()].into(),
        protected_paths: BTreeSet::new(),
    };
    (temp, repo, store, policy)
}
fn proposal(repo: &Repository, paths: &[&str]) -> PatchProposal {
    PatchProposal {
        schema_version: "melissa.repository-patch/v1".into(),
        root_identity: repo.root_identity().into(),
        files: paths
            .iter()
            .map(|p| {
                let (before, bytes) = repo.read(p).unwrap();
                let start = bytes.windows(3).position(|b| b == b"old").unwrap() as u64;
                FilePatch {
                    before,
                    edits: vec![ByteEdit {
                        start,
                        end: start + 3,
                        expected: b"old".to_vec(),
                        replacement: b"new-value".to_vec(),
                    }],
                }
            })
            .collect(),
    }
}

#[test]
fn exact_patch_preserves_dirty_binary_crlf_and_encrypted_preimages() {
    let (temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt", "b.txt"]);
    let before = fs::read(repo.root_path().join("a.txt")).unwrap();
    let result = {
        let mut broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let grant = broker.authorize("inv:patch", "attempt:patch", p).unwrap();
        broker.execute(grant, &AtomicBool::new(false)).unwrap()
    };
    assert_eq!(
        fs::read(repo.root_path().join("a.txt")).unwrap(),
        b"user-owned\r\nnew-value\r\nkeep\0\xff"
    );
    assert_eq!(
        store
            .get_artifact("task:repo-fixture", "inv:patch:preimage:0")
            .unwrap(),
        before
    );
    assert!(!result.task_accepted);
    assert!(!result.multi_file_atomic);
    assert_eq!(
        result.files[0].before.identity,
        result.files[0].after.identity
    );
    assert_eq!(
        store.journal().invocation("inv:patch").unwrap().state,
        InvocationState::Succeeded
    );
    assert_eq!(
        store
            .journal()
            .task("task:repo-fixture")
            .unwrap()
            .record
            .state,
        TaskState::Running
    );
    store.integrity_check().unwrap();
    drop(store);
    for p in fs::read_dir(temp.path().join("evidence/cas/blobs")).unwrap() {
        let b = fs::read(p.unwrap().path()).unwrap();
        assert!(!b.windows(before.len()).any(|s| s == before));
    }
}

#[test]
fn stale_second_file_prevents_every_write_and_dispatch() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt", "b.txt"]);
    let first = fs::read(repo.root_path().join("a.txt")).unwrap();
    let mut broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    let grant = broker.authorize("inv:stale", "attempt:stale", p).unwrap();
    fs::write(repo.root_path().join("b.txt"), b"new user work").unwrap();
    assert!(matches!(
        broker.execute(grant, &AtomicBool::new(false)),
        Err(Error::Stale(_))
    ));
    assert_eq!(fs::read(repo.root_path().join("a.txt")).unwrap(), first);
    assert!(store.journal().invocation("inv:stale").is_err());
}

#[test]
fn changed_identity_with_identical_bytes_is_stale() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let bytes = repo.read("a.txt").unwrap().1;
    fs::rename(
        repo.root_path().join("a.txt"),
        repo.root_path().join("original.txt"),
    )
    .unwrap();
    fs::write(repo.root_path().join("a.txt"), &bytes).unwrap();
    let mut broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    let grant = broker.authorize("inv:id", "attempt:id", p).unwrap();
    assert!(matches!(
        broker.execute(grant, &AtomicBool::new(false)),
        Err(Error::Stale(_))
    ));
    assert_eq!(repo.read("a.txt").unwrap().1, bytes);
}

#[test]
fn revoked_expired_foreign_task_and_scope_grants_never_write() {
    for case in 0..7 {
        let (_temp, repo, mut store, mut policy) = fixture();
        let p = proposal(&repo, &["a.txt"]);
        let before = repo.read("a.txt").unwrap().1;
        match case {
            0 => policy.expires_at_ms = 1,
            1 => policy.writable_paths = ["b.txt".into()].into(),
            2 => policy.protected_paths = ["a.txt".into()].into(),
            3 => policy.authorization_ref = "not:authorized".into(),
            4 => policy.profile_id = "melissa.code.architect".into(),
            _ => (),
        }
        let mut broker = PatchBroker::new(&repo, &mut store, policy.clone()).unwrap();
        if case < 5 {
            assert!(broker.authorize("inv:deny", "attempt:deny", p).is_err());
        } else {
            let grant = broker.authorize("inv:deny", "attempt:deny", p).unwrap();
            if case == 5 {
                broker.revoke().unwrap();
                assert!(broker.execute(grant, &AtomicBool::new(false)).is_err());
            } else {
                drop(broker);
                let mut other = PatchBroker::new(&repo, &mut store, policy).unwrap();
                assert!(other.execute(grant, &AtomicBool::new(false)).is_err());
            }
        }
        assert_eq!(repo.read("a.txt").unwrap().1, before);
        assert!(store.journal().invocation("inv:deny").is_err());
    }
}

#[test]
fn precancel_prevents_patch() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let before = repo.read("a.txt").unwrap().1;
    {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let grant = b.authorize("inv:cancel", "attempt:cancel", p).unwrap();
        assert!(matches!(
            b.execute(grant, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
    }
    assert_eq!(repo.read("a.txt").unwrap().1, before);
    assert!(store.journal().invocation("inv:cancel").is_err());
}
#[test]
fn a_task_without_patch_effect_cannot_gain_it_from_a_host_file_list() {
    let (_temp, repo, mut store, policy) = fixture_with_write(false);
    let p = proposal(&repo, &["a.txt"]);
    let before = repo.read("a.txt").unwrap().1;
    let broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    assert!(
        broker
            .authorize("inv:readonly", "attempt:readonly", p)
            .is_err()
    );
    assert_eq!(repo.read("a.txt").unwrap().1, before);
}
#[test]
fn instruction_files_remain_protected_even_if_in_the_host_write_list() {
    let (_temp, repo, mut store, mut policy) = fixture();
    fs::write(
        repo.root_path().join("AGENTS.md"),
        b"keep old instructions\n",
    )
    .unwrap();
    policy.writable_paths.insert("AGENTS.md".into());
    let p = proposal(&repo, &["AGENTS.md"]);
    let broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    assert!(
        broker
            .authorize("inv:instructions", "attempt:instructions", p)
            .is_err()
    );
    assert_eq!(
        repo.read("AGENTS.md").unwrap().1,
        b"keep old instructions\n"
    );
}

#[test]
fn unicode_case_expansion_cannot_expand_an_exact_host_write_grant() {
    let (_temp, repo, mut store, mut policy) = fixture();
    std::fs::write(repo.root_path().join("ß.txt"), b"owned old content").unwrap();
    std::fs::write(repo.root_path().join("ss.txt"), b"ungranted old content").unwrap();
    policy.writable_paths = ["ß.txt".into()].into();
    let p = proposal(&repo, &["ss.txt"]);
    let before = repo.read("ss.txt").unwrap().1;
    let broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    assert!(
        broker
            .authorize("inv:unicode", "attempt:unicode", p)
            .is_err()
    );
    assert_eq!(repo.read("ss.txt").unwrap().1, before);
}

#[test]
fn a_prepared_peer_attempt_consumes_the_same_task_parallel_allowance() {
    let (_temp, repo, mut store, policy) = fixture();
    let before = repo.read("a.txt").unwrap().1;
    let task = &policy.task_id;
    let v = store.journal().task(task).unwrap().record.version;
    store
        .journal_mut()
        .propose_invocation(
            &InvocationRequest {
                invocation_id: "inv:peer".into(),
                task_id: task.clone(),
                tool_id: "process.exec".into(),
                arguments: serde_json::json!({"peer":"owned fixture"}),
                idempotency_key: None,
                generation: 1,
            },
            v,
        )
        .unwrap();
    let v = store.journal().task(task).unwrap().record.version;
    store
        .journal_mut()
        .authorize_invocation("inv:peer", v, 0)
        .unwrap();
    let v = store.journal().task(task).unwrap().record.version;
    store
        .journal_mut()
        .begin_attempt("inv:peer", "attempt:peer", v, 1, 1)
        .unwrap();
    let p = proposal(&repo, &["a.txt"]);
    let mut broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    let grant = broker
        .authorize("inv:capacity", "attempt:capacity", p)
        .unwrap();
    assert!(broker.execute(grant, &AtomicBool::new(false)).is_err());
    assert_eq!(repo.read("a.txt").unwrap().1, before);
    assert!(store.journal().attempt("attempt:capacity").is_err());
}

#[test]
fn patch_admission_binds_principal_nonce_resource_and_survives_reopen() {
    let (temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let principal = policy.principal_id.clone();
    let resource = policy.resource_id.clone();
    let receipt = {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let permit = b.authorize("inv:admitted", "attempt:admitted", p).unwrap();
        b.execute(permit, &AtomicBool::new(false)).unwrap()
    };
    let admission = store
        .journal()
        .permit_admission(&receipt.permit_id)
        .unwrap();
    assert_eq!(admission.principal_id, principal);
    assert_eq!(admission.resource_id, resource);
    assert_eq!(admission.tool_id, "fs.patch");
    assert!(!admission.nonce.is_empty());
    assert_eq!(
        admission.arguments_digest,
        store
            .journal()
            .invocation("inv:admitted")
            .unwrap()
            .arguments_digest
    );
    store.integrity_check().unwrap();
    drop(store);
    let reopened = LocalStore::open(
        &temp.path().join("evidence"),
        StoreKey::from_bytes([33; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .journal()
            .permit_admission(&receipt.permit_id)
            .unwrap(),
        admission
    );
    reopened.integrity_check().unwrap();
}

#[test]
fn durable_revocation_between_file_writes_stops_remaining_effects_as_unknown() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt", "b.txt"]);
    let before = repo.read("b.txt").unwrap().1;
    let mut peer = store.connect().unwrap();
    let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
    let permit = b.authorize("inv:revoked", "attempt:revoked", p).unwrap();
    let id = permit.permit_id.clone();
    assert!(matches!(
        b.execute_inner(permit, &AtomicBool::new(false), |i| {
            if i == 0 {
                peer.journal_mut().revoke_permit(
                    &id,
                    "owned revocation fixture",
                    now().unwrap(),
                )?;
            }
            Ok(())
        }),
        Err(Error::AfterDispatch(_))
    ));
    assert_eq!(repo.read("b.txt").unwrap().1, before);
    assert_eq!(
        store.journal().invocation("inv:revoked").unwrap().state,
        InvocationState::OutcomeUnknown
    );
}

#[test]
fn partial_write_failure_is_unknown_and_blocks_retry_after_reopen() {
    let (temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt", "b.txt"]);
    let b_before = repo.read("b.txt").unwrap().1;
    {
        let mut broker = PatchBroker::new(&repo, &mut store, policy.clone()).unwrap();
        let grant = broker
            .authorize("inv:partial", "attempt:partial", p)
            .unwrap();
        let result = broker.execute_inner(grant, &AtomicBool::new(false), |i| {
            if i == 0 {
                Err(Error::Io(std::io::Error::from(ErrorKind::WriteZero)))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(Error::AfterDispatch(_))));
    }
    assert_eq!(repo.read("b.txt").unwrap().1, b_before);
    assert_ne!(
        repo.read("a.txt").unwrap().1,
        store
            .get_artifact("task:repo-fixture", "inv:partial:preimage:0")
            .unwrap()
    );
    assert_eq!(
        store.journal().invocation("inv:partial").unwrap().state,
        InvocationState::OutcomeUnknown
    );
    assert_eq!(
        store
            .journal()
            .task("task:repo-fixture")
            .unwrap()
            .record
            .state,
        TaskState::OutcomeUnknown
    );
    store.integrity_check().unwrap();
    drop(store);
    let mut reopened = LocalStore::open(
        &temp.path().join("evidence"),
        StoreKey::from_bytes([33; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let p = proposal(&repo, &["b.txt"]);
    let broker = PatchBroker::new(&repo, &mut reopened, policy).unwrap();
    assert!(broker.authorize("inv:retry", "attempt:retry", p).is_err());
}

#[test]
fn cancellation_between_writes_is_unknown_without_claiming_rollback() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt", "b.txt"]);
    let cancel = AtomicBool::new(false);
    let before = repo.read("b.txt").unwrap().1;
    {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let grant = b
            .authorize("inv:midcancel", "attempt:midcancel", p)
            .unwrap();
        assert!(matches!(
            b.execute_inner(grant, &cancel, |_| {
                cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }),
            Err(Error::AfterDispatch(_))
        ));
    }
    assert_eq!(repo.read("b.txt").unwrap().1, before);
    assert_eq!(
        store.journal().invocation("inv:midcancel").unwrap().state,
        InvocationState::OutcomeUnknown
    );
}

#[test]
fn dispatch_event_and_preimages_exist_before_first_effect() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let mut observer = store.connect().unwrap();
    let mut broker = PatchBroker::new(&repo, &mut store, policy).unwrap();
    let grant = broker
        .authorize("inv:ordered", "attempt:ordered", p)
        .unwrap();
    let receipt = broker.execute_inner(grant, &AtomicBool::new(false), |_| {
        assert_eq!(
            observer.journal().attempt("attempt:ordered").unwrap().state,
            AttemptState::Dispatched
        );
        assert!(
            !observer
                .get_artifact("task:repo-fixture", "inv:ordered:preimage:0")
                .unwrap()
                .is_empty()
        );
        assert!(observer.journal_mut().recover_interrupted().is_ok());
        Ok(())
    });
    // The observer deliberately recovered a live dispatch: evidence finalization
    // must fail closed, even though the file changed. No success is invented.
    assert!(matches!(receipt, Err(Error::AfterDispatch(_))));
}

#[test]
fn encrypted_preimage_can_form_an_explicit_version_checked_reverse_patch() {
    let (_temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let original = repo.read("a.txt").unwrap().1;
    {
        let mut b = PatchBroker::new(&repo, &mut store, policy.clone()).unwrap();
        let g = b.authorize("inv:forward", "attempt:forward", p).unwrap();
        b.execute(g, &AtomicBool::new(false)).unwrap();
    }
    let (before, current) = repo.read("a.txt").unwrap();
    let reverse = PatchProposal {
        schema_version: "melissa.repository-patch/v1".into(),
        root_identity: repo.root_identity().into(),
        files: vec![FilePatch {
            before,
            edits: vec![ByteEdit {
                start: 0,
                end: current.len() as u64,
                expected: current,
                replacement: store
                    .get_artifact("task:repo-fixture", "inv:forward:preimage:0")
                    .unwrap(),
            }],
        }],
    };
    {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let g = b
            .authorize("inv:reverse", "attempt:reverse", reverse)
            .unwrap();
        b.execute(g, &AtomicBool::new(false)).unwrap();
    }
    assert_eq!(repo.read("a.txt").unwrap().1, original);
}

#[test]
fn hardlinks_sharing_conflicts_and_ancestor_rename_are_denied() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    let (temp, repo, mut store, policy) = fixture();
    let p = proposal(&repo, &["a.txt"]);
    let root = repo.root_path().to_owned();
    assert!(fs::rename(&root, temp.path().join("moved")).is_err());
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(root.join("a.txt"))
        .unwrap();
    {
        let mut b = PatchBroker::new(&repo, &mut store, policy).unwrap();
        let g = b.authorize("inv:locked", "attempt:locked", p).unwrap();
        assert!(b.execute(g, &AtomicBool::new(false)).is_err());
    }
    drop(held);
    fs::hard_link(root.join("a.txt"), temp.path().join("outside-link.txt")).unwrap();
    assert!(matches!(repo.read("a.txt"), Err(Error::Denied(_))));
}
