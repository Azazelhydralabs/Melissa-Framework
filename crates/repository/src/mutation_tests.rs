use super::*;
use crate::Limits;
use melissa_core_contracts::{InvocationState, wire::TaskContractV1};
use melissa_local_store::{StoreConfig, StoreKey};
use std::sync::atomic::Ordering;

fn fixture() -> (tempfile::TempDir, Repository, LocalStore, PatchPolicy) {
    let temp = tempfile::tempdir().unwrap();
    let (repo, store, policy) = fixture_at(temp.path());
    (temp, repo, store, policy)
}
fn fixture_at(base: &std::path::Path) -> (Repository, LocalStore, PatchPolicy) {
    let root = base.join("repo");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("old.bin"), b"dirty\r\n\0\xff").unwrap();
    let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
    let mut store = LocalStore::open(
        &base.join("store"),
        StoreKey::from_bytes([65; 32]),
        StoreConfig::default(),
    )
    .unwrap();
    let mut t: TaskContractV1 = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/code01/wire/task-contract-v1.json"
    ))
    .unwrap();
    t.task_id = "task:mutations".into();
    t.workspace_ref = "workspace:mutations".into();
    t.allowed_resource_ids = vec![t.workspace_ref.clone()];
    t.allowed_effects = vec![
        "workspace.read".into(),
        "workspace.apply_patch_scoped".into(),
    ];
    t.limits.max_disk_bytes = 16 * 1024 * 1024;
    t.limits.max_wall_time_ms = 60_000;
    store.journal_mut().create_task(&t).unwrap();
    for state in [
        TaskState::Planned,
        TaskState::Queued,
        TaskState::Leased,
        TaskState::Running,
    ] {
        let v = store.journal().task(&t.task_id).unwrap().record.version;
        store.transition_task(&t.task_id, v, state, None).unwrap();
    }
    let p = PatchPolicy {
        task_id: t.task_id,
        principal_id: "principal:mutations".into(),
        profile_id: t.selected_profile_ids[0].clone(),
        resource_id: t.workspace_ref,
        authorization_ref: t.authorization_refs[0].clone(),
        expires_at_ms: now().unwrap() + 60_000,
        epoch: 0,
        writable_paths: [
            "old.bin",
            "new.bin",
            "nested/moved.bin",
            "nested/new.bin",
            "nested/old.bin",
        ]
        .map(String::from)
        .into(),
        protected_paths: BTreeSet::new(),
    };
    (repo, store, p)
}

#[test]
fn real_process_exit_after_namespace_effect_recovers_unknown_without_retry() {
    const CHILD_ROOT: &str = "MELISSA_CODE05_OWNED_CRASH_TEST_ROOT";
    const CHILD_MODE: &str = "MELISSA_CODE05_OWNED_CRASH_TEST_MODE";
    if let (Some(root), Ok(mode)) = (std::env::var_os(CHILD_ROOT), std::env::var(CHILD_MODE)) {
        let (r, mut s, p) = fixture_at(std::path::Path::new(&root));
        let prop = match mode.as_str() {
            "create" => create(&r, "new.bin"),
            "delete" => delete(&r, "old.bin"),
            "move" => move_file(&r, "old.bin", "new.bin"),
            _ => panic!("unknown owned crash scenario"),
        };
        let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
        let permit = b
            .authorize_mutation("inv:mutation", "attempt:mutation", prop)
            .unwrap();
        let _ = b.mutate_inner(permit, &AtomicBool::new(false), |after| {
            if after {
                std::process::exit(87);
            }
            Ok(())
        });
        panic!("child did not reach namespace effect");
    }
    use std::os::windows::process::CommandExt;
    for mode in ["create", "delete", "move"] {
        let owned = tempfile::tempdir().unwrap();
        let result=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","broker::mutations::tests::real_process_exit_after_namespace_effect_recovers_unknown_without_retry","--nocapture"]).env(CHILD_ROOT,owned.path()).env(CHILD_MODE,mode).creation_flags(0x08000000).output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(87),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut store = LocalStore::open(
            &owned.path().join("store"),
            StoreKey::from_bytes([65; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        assert_eq!(
            store.journal().invocation("inv:mutation").unwrap().state,
            InvocationState::OutcomeUnknown
        );
        assert!(
            store
                .journal()
                .task("task:mutations")
                .unwrap()
                .record
                .unknown_invocation_id
                .is_some()
        );
        let r = Repository::open(&owned.path().join("repo"), Limits::default(), vec![]).unwrap();
        match mode {
            "create" => assert_eq!(fs::read(r.root_path().join("new.bin")).unwrap(), b""),
            "delete" => assert!(!r.root_path().join("old.bin").exists()),
            "move" => {
                assert!(!r.root_path().join("old.bin").exists());
                assert_eq!(r.read("new.bin").unwrap().1, b"dirty\r\n\0\xff");
            }
            _ => unreachable!(),
        }
        let t = store.journal().task("task:mutations").unwrap().contract;
        let p = PatchPolicy {
            task_id: t.task_id,
            profile_id: t.selected_profile_ids[0].clone(),
            principal_id: "principal:mutations".into(),
            resource_id: t.workspace_ref,
            authorization_ref: t.authorization_refs[0].clone(),
            expires_at_ms: now().unwrap() + 60_000,
            epoch: 0,
            writable_paths: ["nested/new.bin".into()].into(),
            protected_paths: BTreeSet::new(),
        };
        assert!(run(&r, &mut store, p, create(&r, "nested/new.bin")).is_err());
        store.integrity_check().unwrap();
    }
}
fn proposal(repo: &Repository, mutation: FileMutation) -> MutationProposal {
    MutationProposal {
        schema_version: "melissa.repository-mutation/v1".into(),
        root_identity: repo.root_identity().into(),
        mutation,
    }
}
fn create(repo: &Repository, p: &str) -> MutationProposal {
    proposal(
        repo,
        FileMutation::Create {
            destination: repo.absent_path(p).unwrap(),
            bytes: b"new\r\n\0\xff".to_vec(),
        },
    )
}
fn delete(repo: &Repository, p: &str) -> MutationProposal {
    proposal(
        repo,
        FileMutation::Delete {
            before: repo.read(p).unwrap().0,
        },
    )
}
fn move_file(repo: &Repository, p: &str, d: &str) -> MutationProposal {
    proposal(
        repo,
        FileMutation::Move {
            before: repo.read(p).unwrap().0,
            destination: repo.absent_path(d).unwrap(),
        },
    )
}
fn run(
    repo: &Repository,
    s: &mut LocalStore,
    policy: PatchPolicy,
    p: MutationProposal,
) -> Result<MutationReceipt> {
    let mut b = PatchBroker::new(repo, s, policy)?;
    let permit = b.authorize_mutation("inv:mutation", "attempt:mutation", p)?;
    b.execute_mutation(permit, &AtomicBool::new(false))
}

#[test]
fn atomic_no_replace_checks_survive_a_destination_race_after_admission() {
    for moving in [false, true] {
        let (_t, r, mut s, p) = fixture();
        let prop = if moving {
            move_file(&r, "old.bin", "new.bin")
        } else {
            create(&r, "new.bin")
        };
        let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
        let permit = b
            .authorize_mutation("inv:mutation", "attempt:mutation", prop)
            .unwrap();
        assert!(matches!(
            b.mutate_inner(permit, &AtomicBool::new(false), |after| {
                if !after {
                    fs::write(r.root_path().join("new.bin"), b"racing writer")?;
                }
                Ok(())
            }),
            Err(Error::AfterDispatch(_))
        ));
        assert_eq!(r.read("new.bin").unwrap().1, b"racing writer");
        assert!(r.read("old.bin").is_ok());
        assert_eq!(
            s.journal().invocation("inv:mutation").unwrap().state,
            InvocationState::OutcomeUnknown
        );
    }
}
#[test]
fn namespace_effects_keep_ancestors_pinned_and_honor_durable_revocation() {
    let (_t, r, mut s, p) = fixture();
    let mut peer = s.connect().unwrap();
    let prop = move_file(&r, "old.bin", "nested/moved.bin");
    let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
    let permit = b
        .authorize_mutation("inv:mutation", "attempt:mutation", prop)
        .unwrap();
    let permit_id = permit.permit.clone();
    assert!(matches!(
        b.mutate_inner(permit, &AtomicBool::new(false), |after| {
            if !after {
                assert!(
                    fs::rename(r.root_path().join("nested"), r.root_path().join("stolen")).is_err()
                );
                peer.journal_mut()
                    .revoke_permit(&permit_id, "host test revoke", now()?)
                    .unwrap();
            }
            Ok(())
        }),
        Err(Error::AfterDispatch(_))
    ));
    assert!(r.read("old.bin").is_ok());
    assert!(!r.root_path().join("nested/moved.bin").exists());
}
#[test]
fn mutations_share_task_wide_active_attempt_quota_with_processes() {
    let (_t, r, mut s, p) = fixture();
    let task = p.task_id.clone();
    let v = s.journal().task(&task).unwrap().record.version;
    s.journal_mut()
        .propose_invocation(
            &InvocationRequest {
                invocation_id: "inv:peer".into(),
                task_id: task.clone(),
                tool_id: "process.exec".into(),
                arguments: serde_json::json!({"peer":true}),
                idempotency_key: None,
                generation: 1,
            },
            v,
        )
        .unwrap();
    let v = s.journal().task(&task).unwrap().record.version;
    s.journal_mut()
        .authorize_invocation("inv:peer", v, 0)
        .unwrap();
    let v = s.journal().task(&task).unwrap().record.version;
    s.journal_mut()
        .begin_attempt("inv:peer", "attempt:peer", v, 1, 1)
        .unwrap();
    assert!(run(&r, &mut s, p, create(&r, "new.bin")).is_err());
    assert!(!r.root_path().join("new.bin").exists());
    assert!(s.journal().attempt("attempt:mutation").is_err());
}

#[test]
fn real_create_preserves_exact_binary_bytes_and_existing_dirty_files() {
    let (_t, r, mut s, p) = fixture();
    let old = r.read("old.bin").unwrap();
    let receipt = run(&r, &mut s, p, create(&r, "nested/new.bin")).unwrap();
    assert_eq!(r.read("nested/new.bin").unwrap().1, b"new\r\n\0\xff");
    assert_eq!(r.read("old.bin").unwrap(), old);
    assert!(receipt.before.is_none());
    assert_eq!(receipt.after.unwrap(), r.read("nested/new.bin").unwrap().0);
    assert!(!receipt.task_accepted);
    assert_eq!(
        s.journal().invocation("inv:mutation").unwrap().state,
        InvocationState::Succeeded
    );
    s.integrity_check().unwrap();
}
#[test]
fn real_delete_retains_encrypted_preimage_and_finalizes_absence() {
    let (_t, r, mut s, p) = fixture();
    let bytes = r.read("old.bin").unwrap().1;
    let receipt = run(&r, &mut s, p, delete(&r, "old.bin")).unwrap();
    assert!(!r.root_path().join("old.bin").exists());
    assert_eq!(
        s.get_artifact(
            "task:mutations",
            receipt.preimage_artifact_id.as_ref().unwrap()
        )
        .unwrap(),
        bytes
    );
    assert!(receipt.after.is_none());
    assert_eq!(receipt.absent_paths, ["old.bin"]);
}

#[test]
fn a_reused_source_name_after_delete_or_move_is_preserved_and_reported_unknown() {
    for moving in [false, true] {
        let (_t, r, mut s, p) = fixture();
        let prop = if moving {
            move_file(&r, "old.bin", "new.bin")
        } else {
            delete(&r, "old.bin")
        };
        let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
        let permit = b
            .authorize_mutation("inv:mutation", "attempt:mutation", prop)
            .unwrap();
        assert!(matches!(
            b.mutate_inner(permit, &AtomicBool::new(false), |after| {
                if after {
                    fs::write(r.root_path().join("old.bin"), b"new user file at old name")?;
                }
                Ok(())
            }),
            Err(Error::AfterDispatch(_))
        ));
        assert_eq!(r.read("old.bin").unwrap().1, b"new user file at old name");
        if moving {
            assert_eq!(r.read("new.bin").unwrap().1, b"dirty\r\n\0\xff");
        }
    }
}
#[test]
fn real_move_to_existing_parent_keeps_file_identity_and_bytes() {
    let (_t, r, mut s, p) = fixture();
    let before = r.read("old.bin").unwrap();
    let receipt = run(&r, &mut s, p, move_file(&r, "old.bin", "nested/moved.bin")).unwrap();
    let after = r.read("nested/moved.bin").unwrap();
    assert_eq!(before.0.identity, after.0.identity);
    assert_eq!(before.1, after.1);
    assert!(!r.root_path().join("old.bin").exists());
    assert_eq!(receipt.after.unwrap(), after.0);
}
#[test]
fn concurrently_appearing_create_or_move_destination_is_never_overwritten() {
    for moving in [false, true] {
        let (_t, r, mut s, p) = fixture();
        let prop = if moving {
            move_file(&r, "old.bin", "new.bin")
        } else {
            create(&r, "new.bin")
        };
        fs::write(r.root_path().join("new.bin"), b"concurrent user bytes").unwrap();
        assert!(run(&r, &mut s, p, prop).is_err());
        assert_eq!(r.read("new.bin").unwrap().1, b"concurrent user bytes");
        assert!(r.read("old.bin").is_ok());
        assert!(s.journal().invocation("inv:mutation").is_err());
    }
}
#[test]
fn replaced_destination_parent_and_stale_source_fail_before_dispatch() {
    let (_t, r, mut s, p) = fixture();
    let prop = create(&r, "nested/new.bin");
    fs::rename(r.root_path().join("nested"), r.root_path().join("former")).unwrap();
    fs::create_dir(r.root_path().join("nested")).unwrap();
    assert!(run(&r, &mut s, p.clone(), prop).is_err());
    let prop = delete(&r, "old.bin");
    fs::write(r.root_path().join("old.bin"), b"changed by user").unwrap();
    assert!(run(&r, &mut s, p, prop).is_err());
    assert!(s.journal().invocation("inv:mutation").is_err());
}
#[test]
fn move_requires_exact_grants_for_both_source_and_destination() {
    let (_t, r, mut s, mut p) = fixture();
    p.writable_paths.remove("nested/moved.bin");
    assert!(run(&r, &mut s, p, move_file(&r, "old.bin", "nested/moved.bin")).is_err());
    assert!(r.read("old.bin").is_ok());
}
#[test]
fn protected_instruction_and_git_paths_cannot_be_created_or_deleted() {
    let (_t, r, mut s, mut p) = fixture();
    p.writable_paths.insert("AGENTS.md".into());
    assert!(run(&r, &mut s, p, create(&r, "AGENTS.md")).is_err());
    assert!(r.absent_path(".git/config").is_err());
}
#[test]
fn directories_links_and_missing_parents_never_gain_file_mutation_authority() {
    let (_t, r, mut s, mut p) = fixture();
    assert!(r.absent_path("missing/new.bin").is_err());
    assert!(r.read("nested").is_err());
    fs::hard_link(
        r.root_path().join("old.bin"),
        r.root_path().join("outside-alias"),
    )
    .unwrap();
    let prop = proposal(
        &r,
        FileMutation::Delete {
            before: FileVersion {
                path: "old.bin".into(),
                identity: "forged".into(),
                digest: digest(b"dirty\r\n\0\xff"),
                bytes: 10,
            },
        },
    );
    p.writable_paths.insert("nested".into());
    assert!(run(&r, &mut s, p, prop).is_err());
    assert!(r.root_path().join("old.bin").exists());
}
#[test]
fn partial_create_and_post_delete_cancellation_are_unknown_after_reopen() {
    for creating in [true, false] {
        let (t, r, mut s, p) = fixture();
        let prop = if creating {
            create(&r, "new.bin")
        } else {
            delete(&r, "old.bin")
        };
        let cancel = AtomicBool::new(false);
        {
            let mut b = PatchBroker::new(&r, &mut s, p.clone()).unwrap();
            let permit = b
                .authorize_mutation("inv:mutation", "attempt:mutation", prop)
                .unwrap();
            assert!(matches!(
                b.mutate_inner(permit, &cancel, |after| {
                    if after {
                        cancel.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                }),
                Err(Error::AfterDispatch(_))
            ));
        }
        assert_eq!(
            s.journal().invocation("inv:mutation").unwrap().state,
            InvocationState::OutcomeUnknown
        );
        drop(s);
        let mut s = LocalStore::open(
            &t.path().join("store"),
            StoreKey::from_bytes([65; 32]),
            StoreConfig::default(),
        )
        .unwrap();
        assert!(run(&r, &mut s, p, create(&r, "nested/new.bin")).is_err());
        if creating {
            assert_eq!(fs::read(r.root_path().join("new.bin")).unwrap(), b"");
        } else {
            assert!(!r.root_path().join("old.bin").exists());
        }
    }
}
#[test]
fn pre_cancel_and_foreign_session_or_revoked_capability_do_not_mutate() {
    let (_t, r, mut s, p) = fixture();
    let prop = create(&r, "new.bin");
    let permit = PatchBroker::new(&r, &mut s, p.clone())
        .unwrap()
        .authorize_mutation("inv:mutation", "attempt:mutation", prop.clone())
        .unwrap();
    let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
    assert!(b.execute_mutation(permit, &AtomicBool::new(false)).is_err());
    let permit = b
        .authorize_mutation("inv:mutation", "attempt:mutation", prop.clone())
        .unwrap();
    b.revoke().unwrap();
    assert!(b.execute_mutation(permit, &AtomicBool::new(false)).is_err());
    let permit = b
        .authorize_mutation("inv:mutation", "attempt:mutation", prop)
        .unwrap();
    assert!(matches!(
        b.execute_mutation(permit, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(!r.root_path().join("new.bin").exists());
}
#[test]
fn mutation_json_rejects_duplicates_authority_injection_and_ambiguous_moves() {
    let (_t, r, _s, _p) = fixture();
    let mut v = serde_json::to_value(create(&r, "new.bin")).unwrap();
    v["principal_id"] = "forged".into();
    assert!(MutationProposal::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(MutationProposal::parse(br#"{"schema_version":"x","schema_version":"y"}"#).is_err());
    let p = proposal(
        &r,
        FileMutation::Move {
            before: r.read("old.bin").unwrap().0,
            destination: AbsentPath {
                path: "OLD.BIN".into(),
                parent_identity: r.root_identity().into(),
            },
        },
    );
    assert!(p.validate(r.limits()).is_err());
}
#[test]
fn delete_and_move_preimages_exist_before_any_namespace_effect() {
    for moving in [true, false] {
        let (_t, r, mut s, p) = fixture();
        let peer = s.connect().unwrap();
        let prop = if moving {
            move_file(&r, "old.bin", "new.bin")
        } else {
            delete(&r, "old.bin")
        };
        let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
        let permit = b
            .authorize_mutation("inv:mutation", "attempt:mutation", prop)
            .unwrap();
        b.mutate_inner(permit, &AtomicBool::new(false), |after| {
            if !after {
                return Ok(());
            }
            assert_eq!(
                peer.journal().invocation("inv:mutation").unwrap().state,
                InvocationState::Dispatched
            );
            assert_eq!(
                peer.get_artifact("task:mutations", "inv:mutation:preimage")
                    .unwrap(),
                b"dirty\r\n\0\xff"
            );
            Ok(())
        })
        .unwrap();
    }
}
