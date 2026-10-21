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
fn directory_post_effect_cancellation_retains_unknown_and_created_objects() {
    for moving in [false, true] {
        let (_t, r, mut s, mut p) = fixture();
        p.writable_paths.insert("nested".into());
        let mutation = if moving {
            FileMutation::MoveDirectory {
                before: r.empty_directory_version("nested").unwrap(),
                destination: r.absent_path("new.bin").unwrap(),
            }
        } else {
            FileMutation::CreateDirectory {
                destination: r.absent_path("new.bin").unwrap(),
            }
        };
        let prop = MutationProposal {
            schema_version: "melissa.repository-mutation/v2".into(),
            root_identity: r.root_identity().into(),
            mutation,
        };
        let cancel = AtomicBool::new(false);
        let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
        let permit = b
            .authorize_mutation("inv:directory", "attempt:directory", prop)
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
        assert!(r.root_path().join("new.bin").is_dir());
        assert_eq!(
            s.journal().invocation("inv:directory").unwrap().state,
            InvocationState::OutcomeUnknown
        );
    }
}
#[test]
fn directory_destination_race_after_admission_never_replaces_a_user_object() {
    let (_t, r, mut s, p) = fixture();
    let prop = MutationProposal {
        schema_version: "melissa.repository-mutation/v2".into(),
        root_identity: r.root_identity().into(),
        mutation: FileMutation::CreateDirectory {
            destination: r.absent_path("new.bin").unwrap(),
        },
    };
    let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
    let permit = b
        .authorize_mutation("inv:directory-race", "attempt:directory-race", prop)
        .unwrap();
    assert!(matches!(
        b.mutate_inner(permit, &AtomicBool::new(false), |after| {
            if !after {
                fs::write(r.root_path().join("new.bin"), b"racing user bytes")?;
            }
            Ok(())
        }),
        Err(Error::AfterDispatch(_))
    ));
    assert_eq!(
        fs::read(r.root_path().join("new.bin")).unwrap(),
        b"racing user bytes"
    );
}
