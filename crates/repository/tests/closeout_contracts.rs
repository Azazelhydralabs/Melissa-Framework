#![cfg(windows)]
mod support;
use melissa_model_gateway::{
    ToolCall,
    tools::{ToolContext, ToolDispatcher},
};
use melissa_repository::tools::{RepositoryDispatcher, RepositoryToolPolicy};
use melissa_repository::{
    FileMutation, MutationProposal, PatchBroker, Repository, discovery::DiscoveryOptions,
    polyglot::PolyglotIndex, unified::ProposedChange,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    sync::{Arc, atomic::AtomicBool},
};
fn no() -> AtomicBool {
    AtomicBool::new(false)
}
fn dir_proposal(r: &Repository, m: FileMutation) -> MutationProposal {
    MutationProposal {
        schema_version: "melissa.repository-mutation/v2".into(),
        root_identity: r.root_identity().into(),
        mutation: m,
    }
}
fn execute(
    r: &Repository,
    s: &mut melissa_local_store::LocalStore,
    p: melissa_repository::PatchPolicy,
    m: MutationProposal,
    id: &str,
) -> melissa_repository::Result<melissa_repository::MutationReceipt> {
    let mut b = PatchBroker::new(r, s, p)?;
    let permit = b.authorize_mutation(&format!("inv:{id}"), &format!("attempt:{id}"), m)?;
    b.execute_mutation(permit, &no())
}

#[test]
fn exact_empty_directory_create_move_and_delete_preserve_identity_and_evidence() {
    let (_d, r, mut s, p) = support::fixture(&["new", "renamed"]);
    let created = execute(
        &r,
        &mut s,
        p.clone(),
        dir_proposal(
            &r,
            FileMutation::CreateDirectory {
                destination: r.absent_path("new").unwrap(),
            },
        ),
        "mkdir",
    )
    .unwrap();
    assert_eq!(created.namespace_kind.as_deref(), Some("empty_directory"));
    let before = r.empty_directory_version("new").unwrap();
    let moved = execute(
        &r,
        &mut s,
        p.clone(),
        dir_proposal(
            &r,
            FileMutation::MoveDirectory {
                before: before.clone(),
                destination: r.absent_path("renamed").unwrap(),
            },
        ),
        "movedir",
    )
    .unwrap();
    assert_eq!(before.identity, moved.after.as_ref().unwrap().identity);
    assert!(!r.root_path().join("new").exists());
    let deleted = execute(
        &r,
        &mut s,
        p,
        dir_proposal(
            &r,
            FileMutation::DeleteDirectory {
                before: r.empty_directory_version("renamed").unwrap(),
            },
        ),
        "rmdir",
    )
    .unwrap();
    assert!(!r.root_path().join("renamed").exists());
    assert!(!deleted.task_accepted);
    assert!(
        s.get_artifact(
            "task:code05-closeout",
            deleted.preimage_artifact_id.as_ref().unwrap()
        )
        .is_ok()
    );
    s.integrity_check().unwrap();
}
#[test]
fn nonempty_directories_and_replaced_parents_are_rejected_before_dispatch() {
    let (_d, r, mut s, p) = support::fixture(&["new", "parent/new"]);
    fs::create_dir(r.root_path().join("new")).unwrap();
    let before = r.empty_directory_version("new").unwrap();
    fs::write(r.root_path().join("new/user.txt"), b"keep user bytes").unwrap();
    assert!(
        execute(
            &r,
            &mut s,
            p.clone(),
            dir_proposal(&r, FileMutation::DeleteDirectory { before }),
            "nonempty"
        )
        .is_err()
    );
    assert_eq!(
        fs::read(r.root_path().join("new/user.txt")).unwrap(),
        b"keep user bytes"
    );
    assert!(s.journal().invocation("inv:nonempty").is_err());
    fs::create_dir(r.root_path().join("parent")).unwrap();
    let prop = dir_proposal(
        &r,
        FileMutation::CreateDirectory {
            destination: r.absent_path("parent/new").unwrap(),
        },
    );
    fs::rename(
        r.root_path().join("parent"),
        r.root_path().join("oldparent"),
    )
    .unwrap();
    fs::create_dir(r.root_path().join("parent")).unwrap();
    assert!(execute(&r, &mut s, p, prop, "stale-parent").is_err());
}
#[test]
fn directory_no_replace_and_task_exact_path_grants_are_enforced() {
    let (_d, r, mut s, p) = support::fixture(&["allowed"]);
    assert!(
        execute(
            &r,
            &mut s,
            p.clone(),
            dir_proposal(
                &r,
                FileMutation::CreateDirectory {
                    destination: r.absent_path("ungranted").unwrap()
                }
            ),
            "denied"
        )
        .is_err()
    );
    let prop = dir_proposal(
        &r,
        FileMutation::CreateDirectory {
            destination: r.absent_path("allowed").unwrap(),
        },
    );
    fs::write(r.root_path().join("allowed"), b"racing file").unwrap();
    assert!(execute(&r, &mut s, p, prop, "race").is_err());
    assert_eq!(
        fs::read(r.root_path().join("allowed")).unwrap(),
        b"racing file"
    );
}

#[test]
fn nonempty_folder_refactor_uses_explicit_versioned_file_moves_and_preserves_unrelated_work() {
    let (_d, r, mut store, p) = support::fixture(&[
        "old",
        "new",
        "old/main.py",
        "old/helper.py",
        "new/main.py",
        "new/helper.py",
    ]);
    fs::create_dir(r.root_path().join("old")).unwrap();
    fs::write(
        r.root_path().join("old/main.py"),
        b"from helper import f\r\n",
    )
    .unwrap();
    fs::write(r.root_path().join("old/helper.py"), b"def f(): return 1\n").unwrap();
    fs::write(r.root_path().join("user-dirty.bin"), b"untouched\0\xff").unwrap();
    let dirty = r.read("user-dirty.bin").unwrap();
    execute(
        &r,
        &mut store,
        p.clone(),
        dir_proposal(
            &r,
            FileMutation::CreateDirectory {
                destination: r.absent_path("new").unwrap(),
            },
        ),
        "folder-create",
    )
    .unwrap();
    for name in ["main.py", "helper.py"] {
        let before = r.read(&format!("old/{name}")).unwrap().0;
        let m = MutationProposal {
            schema_version: "melissa.repository-mutation/v1".into(),
            root_identity: r.root_identity().into(),
            mutation: FileMutation::Move {
                before,
                destination: r.absent_path(&format!("new/{name}")).unwrap(),
            },
        };
        execute(&r, &mut store, p.clone(), m, name).unwrap();
    }
    execute(
        &r,
        &mut store,
        p,
        dir_proposal(
            &r,
            FileMutation::DeleteDirectory {
                before: r.empty_directory_version("old").unwrap(),
            },
        ),
        "folder-remove",
    )
    .unwrap();
    assert!(!r.root_path().join("old").exists());
    assert_eq!(r.read("new/helper.py").unwrap().1, b"def f(): return 1\n");
    assert_eq!(r.read("user-dirty.bin").unwrap(), dirty);
}
#[test]
fn standard_git_unified_patch_preserves_crlf_and_exact_context() {
    let (_d, r, mut s, p) = support::fixture(&["file.txt"]);
    fs::write(
        r.root_path().join("file.txt"),
        b"user dirty\r\nold\r\nkeep\r\n",
    )
    .unwrap();
    let source = r.snapshot(&no()).unwrap();
    let patch=b"diff --git a/file.txt b/file.txt\nindex aaaa..bbbb 100644\n--- a/file.txt\n+++ b/file.txt\n@@ -1,3 +1,3 @@\n user dirty\r\n-old\r\n+new\r\n keep\r\n";
    let proposal = r.propose_unified(&source, patch, &no()).unwrap();
    assert!(!proposal.authorizes_write);
    assert_eq!(
        fs::read(r.root_path().join("file.txt")).unwrap(),
        b"user dirty\r\nold\r\nkeep\r\n"
    );
    let ProposedChange::Patch(typed) = proposal.changes.into_iter().next().unwrap() else {
        panic!()
    };
    let mut b = PatchBroker::new(&r, &mut s, p).unwrap();
    let permit = b
        .authorize("inv:unified", "attempt:unified", typed)
        .unwrap();
    b.execute(permit, &no()).unwrap();
    assert_eq!(
        fs::read(r.root_path().join("file.txt")).unwrap(),
        b"user dirty\r\nnew\r\nkeep\r\n"
    );
    assert!(r.propose_unified(&source, patch, &no()).is_err());
}
#[test]
fn unified_add_delete_rename_and_missing_newline_are_typed_without_authority() {
    let (_d, r, _s, _p) = support::fixture(&["x"]);
    fs::write(r.root_path().join("old.txt"), b"old").unwrap();
    let source = r.snapshot(&no()).unwrap();
    let diff=b"--- a/old.txt\n+++ b/old.txt\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
    let result = r.propose_unified(&source, diff, &no()).unwrap();
    let ProposedChange::Patch(p) = &result.changes[0] else {
        panic!()
    };
    assert_eq!(p.files[0].edits[0].replacement, b"new");
    for patch in [b"--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+created\n".as_slice(),b"--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n\\ No newline at end of file\n",b"diff --git a/old.txt b/moved.txt\nsimilarity index 100%\nrename from old.txt\nrename to moved.txt\n"] {let result=r.propose_unified(&source,patch,&no()).unwrap();assert!(matches!(result.changes[0],ProposedChange::Mutation(_)));}
}
#[test]
fn unified_rejects_fuzz_overlap_traversal_unknown_modes_and_binary_payloads() {
    let (_d, r, _s, _p) = support::fixture(&["x"]);
    fs::write(r.root_path().join("a"), b"actual\n").unwrap();
    let source = r.snapshot(&no()).unwrap();
    for patch in [
        b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-wrong\n+new\n".as_slice(),
        b"--- a/../outside\n+++ b/../outside\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/a b/a\nold mode 100644\nnew mode 100755\n",
        b"GIT binary patch\nliteral 1\na\n",
    ] {
        assert!(r.propose_unified(&source, patch, &no()).is_err());
    }
    assert_eq!(fs::read(r.root_path().join("a")).unwrap(), b"actual\n");
}
#[test]
fn real_ignore_glob_discovery_distinguishes_monorepo_generated_and_ignored_files() {
    let (_d, r, _s, _p) = support::fixture(&["x"]);
    for path in [
        "packages/a/src",
        "packages/b/src",
        "target/debug",
        "ignored",
    ] {
        fs::create_dir_all(r.root_path().join(path)).unwrap();
    }
    for (path, data) in [
        (".gitignore", "ignored/\n*.tmp\n!keep.tmp\n"),
        ("packages/a/Cargo.toml", "[package]\nname=\"a\""),
        ("packages/b/package.json", "{}"),
        ("packages/a/src/lib.rs", "fn same() {}"),
        ("packages/b/src/index.ts", "export function same() {}"),
        ("target/debug/generated.rs", "needle"),
        ("ignored/private.txt", "needle"),
        ("drop.tmp", "drop"),
        ("keep.tmp", "keep"),
    ] {
        fs::write(r.root_path().join(path), data).unwrap();
    }
    let d = r.discover(&DiscoveryOptions::default(), &no()).unwrap();
    let class = |p: &str| {
        d.files
            .iter()
            .find(|f| f.version.path == p)
            .unwrap()
            .classification
            .as_str()
    };
    assert_eq!(class("ignored/private.txt"), "ignored");
    assert_eq!(class("drop.tmp"), "ignored");
    assert_eq!(class("keep.tmp"), "source");
    assert_eq!(class("target/debug/generated.rs"), "generated");
    assert_eq!(d.manifests.len(), 2);
    assert_eq!(d.ignore_inputs.len(), 1);
}
#[test]
fn real_polyglot_grammars_index_three_ecosystems_and_report_invalid_syntax() {
    let (_d, r, _s, _p) = support::fixture(&["x"]);
    for (p, c) in [
        ("lib.rs", "fn rust_name() {}"),
        (
            "main.py",
            "class PythonName:\n    def python_name(self):\n        pass\n",
        ),
        (
            "main.ts",
            "export function ts_name(x:number):number {return x;}",
        ),
        ("component.tsx", "export function View(){return <div/>;}"),
        ("main.js", "function js_name(){return 1;}"),
        ("broken.py", "def ("),
        ("readme.txt", "unsupported"),
    ] {
        fs::write(r.root_path().join(p), c).unwrap();
    }
    let s = r.snapshot(&no()).unwrap();
    let i = PolyglotIndex::build(&r, &s, &no()).unwrap();
    let names: BTreeSet<_> = i.symbols.iter().map(|s| s.name.as_str()).collect();
    for n in [
        "rust_name",
        "PythonName",
        "python_name",
        "ts_name",
        "View",
        "js_name",
    ] {
        assert!(names.contains(n), "{n}");
    }
    assert!(i.syntax_errors.contains(&"broken.py".into()));
    assert!(i.unsupported_files.contains(&"readme.txt".into()));
    fs::write(r.root_path().join("main.ts"), b"changed").unwrap();
    assert!(PolyglotIndex::build(&r, &s, &no()).is_err());
}
fn context(id: &str) -> ToolContext {
    ToolContext {
        task_id: "task:code05-closeout".into(),
        profile_id: "melissa.code.implementer".into(),
        run_id: "run:closeout".into(),
        request_id: format!("request:{id}"),
        invocation_id: format!("inv:{id}"),
        attempt_id: format!("attempt:{id}"),
        generation: 1,
    }
}
async fn call(
    d: &mut RepositoryDispatcher,
    name: &str,
    v: Value,
    id: &str,
) -> melissa_model_gateway::Result<melissa_model_gateway::tools::ToolExecution> {
    let c = ToolCall {
        id: format!("call:{id}"),
        name: name.into(),
        arguments: v.to_string(),
    };
    d.validate_call(&c)?;
    d.execute(c, context(id), Arc::new(no())).await
}
#[tokio::test]
async fn large_file_and_artifact_pages_reassemble_exactly_and_reject_stale_or_foreign_reads() {
    let (_d, r, store, policy) = support::fixture(&["blob.bin"]);
    let bytes: Vec<u8> = (0..300_000).map(|i| (i % 256) as u8).collect();
    fs::write(r.root_path().join("blob.bin"), &bytes).unwrap();
    let version = r.read("blob.bin").unwrap().0;
    let mut d = RepositoryDispatcher::new(
        r,
        store,
        RepositoryToolPolicy {
            files: policy,
            read_repository: true,
            enabled_tools: ["fs_read", "fs_read_page", "fs_artifact_page"]
                .map(String::from)
                .into(),
        },
    )
    .unwrap();
    let full = call(&mut d, "fs_read", json!({"path":"blob.bin"}), "large")
        .await
        .unwrap();
    let meta: Value = serde_json::from_str(&full.content).unwrap();
    assert_eq!(meta["delivery"], "paged_result");
    let mut reconstructed = vec![];
    let mut offset = 0;
    let mut count = 0;
    loop {
        let r=call(&mut d,"fs_artifact_page",json!({"artifact_id":meta["artifact_id"],"digest":meta["digest"],"offset":offset,"max_bytes":32768}),&format!("page{count}")).await.unwrap();
        let v: Value = serde_json::from_str(&r.content).unwrap();
        let page = &v["result"];
        reconstructed.extend(
            page["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8),
        );
        count += 1;
        if page["complete"] == true {
            break;
        }
        offset = page["next_offset"].as_u64().unwrap();
    }
    let whole: Value = serde_json::from_slice(&reconstructed).unwrap();
    let got: Vec<u8> = serde_json::from_value(whole["result"]["bytes"].clone()).unwrap();
    assert_eq!(got, bytes);
    let r = call(
        &mut d,
        "fs_read_page",
        json!({"before":version,"offset":42,"max_bytes":512}),
        "filepage",
    )
    .await
    .unwrap();
    let v: Value = serde_json::from_str(&r.content).unwrap();
    assert_eq!(v["result"]["bytes"], json!(&bytes[42..554]));
    assert!(call(&mut d,"fs_artifact_page",json!({"artifact_id":"other-task:artifact","digest":meta["digest"],"offset":0,"max_bytes":1}),"foreign").await.is_err());
    let mut stale = version;
    stale.digest = "blake3:0000000000000000000000000000000000000000000000000000000000000000".into();
    assert!(
        call(
            &mut d,
            "fs_read_page",
            json!({"before":stale,"offset":0,"max_bytes":1}),
            "stale"
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn directory_discovery_unified_and_polyglot_are_real_model_callable_routes() {
    let (_d, r, store, policy) = support::fixture(&["made"]);
    fs::write(r.root_path().join("lib.rs"), b"fn old() {}\n").unwrap();
    let prop = dir_proposal(
        &r,
        FileMutation::CreateDirectory {
            destination: r.absent_path("made").unwrap(),
        },
    );
    let names = [
        "fs_mkdir",
        "fs_directory",
        "fs_discover",
        "code_unified_propose",
        "code_polyglot_symbols",
    ];
    let mut d = RepositoryDispatcher::new(
        r,
        store,
        RepositoryToolPolicy {
            files: policy,
            read_repository: true,
            enabled_tools: names.map(String::from).into(),
        },
    )
    .unwrap();
    assert!(
        call(&mut d, "fs_mkdir", json!(prop), "mkdirtool")
            .await
            .unwrap()
            .success
    );
    for (name, args) in [
        ("fs_directory", json!({"path":"made"})),
        ("fs_discover", json!(DiscoveryOptions::default())),
        ("code_polyglot_symbols", json!({})),
        (
            "code_unified_propose",
            json!({"patch":"--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-fn old() {}\n+fn new() {}\n"}),
        ),
    ] {
        assert!(call(&mut d, name, args, name).await.unwrap().success);
    }
}
