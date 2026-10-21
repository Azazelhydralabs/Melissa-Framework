#![cfg(windows)]
mod support;
use melissa_execution_broker::{InvocationIdentity, policy::PermitRequest, unix_ms};
use melissa_repository::{
    Limits, PatchBroker, Repository,
    discovery::DiscoveryOptions,
    git::{GitOperation, GitPlan},
    unified::ProposedChange,
};
use std::{fs, path::Path, process::Command, sync::atomic::AtomicBool};
fn no() -> AtomicBool {
    AtomicBool::new(false)
}
fn git(root: &Path, args: &[&str], success: bool) -> Vec<u8> {
    let o = Command::new("C:/Program Files/Git/mingw64/bin/git.exe")
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .args([
            "--no-optional-locks",
            "-c",
            "core.hooksPath=NUL",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.quotePath=true",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        o.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    o.stdout
}
#[test]
fn real_git_unified_roundtrip_handles_dirty_crlf_add_delete_rename_unicode_and_empty_files() {
    let d = tempfile::tempdir().unwrap();
    let original = d.path().join("original");
    let apply = d.path().join("apply");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&apply).unwrap();
    git(&original, &["init", "--quiet"], true);
    for (p, b) in [
        ("old.txt", b"dirty user\r\nold\r\n".as_slice()),
        ("delete.txt", b"delete\n"),
        ("rename.txt", b"move intact\n"),
        ("space name.txt", b"space\n"),
        ("unicode_ç.txt", b"unicode\n"),
    ] {
        fs::write(original.join(p), b).unwrap();
        fs::write(apply.join(p), b).unwrap();
    }
    git(&original, &["add", "--all"], true);
    git(&original, &["commit", "--quiet", "-m", "base"], true);
    fs::write(original.join("old.txt"), b"dirty user\r\nnew\r\n").unwrap();
    fs::remove_file(original.join("delete.txt")).unwrap();
    git(&original, &["mv", "rename.txt", "moved.txt"], true);
    fs::write(original.join("new.txt"), b"new text\n").unwrap();
    fs::write(original.join("empty file.txt"), b"").unwrap();
    fs::write(original.join("unicode_ç.txt"), b"changed unicode\n").unwrap();
    fs::write(original.join("space name.txt"), b"changed space\n").unwrap();
    git(&original, &["add", "--all"], true);
    let patch = git(
        &original,
        &[
            "diff",
            "--cached",
            "--find-renames",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
        ],
        true,
    );
    let r = Repository::open_for_git(&apply, Limits::default()).unwrap();
    let snapshot = r.snapshot(&no()).unwrap();
    let proposal = r
        .propose_unified(&snapshot, &patch, &no())
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&patch)));
    let (mut s, t) = support::task_store(&d.path().join("store"), None);
    let paths = [
        "old.txt",
        "delete.txt",
        "rename.txt",
        "moved.txt",
        "new.txt",
        "empty file.txt",
        "space name.txt",
        "unicode_ç.txt",
    ];
    let p = support::policy(&t, &paths);
    for (i, c) in proposal.changes.into_iter().enumerate() {
        let mut b = PatchBroker::new(&r, &mut s, p.clone()).unwrap();
        let inv = format!("inv:git-unified:{i}");
        let at = format!("attempt:git-unified:{i}");
        match c {
            ProposedChange::Patch(c) => {
                let permit = b.authorize(&inv, &at, c).unwrap();
                b.execute(permit, &no()).unwrap();
            }
            ProposedChange::Mutation(c) => {
                let permit = b.authorize_mutation(&inv, &at, c).unwrap();
                b.execute_mutation(permit, &no()).unwrap();
            }
        }
    }
    for p in paths {
        assert_eq!(
            fs::read(apply.join(p)).ok(),
            fs::read(original.join(p)).ok(),
            "{p}"
        );
    }
    s.integrity_check().unwrap();
}
#[test]
fn real_unmerged_git_state_is_preserved_in_the_private_worker() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--quiet", "--initial-branch=main"], true);
    fs::write(root.join("conflict.txt"), b"base\n").unwrap();
    git(&root, &["add", "--all"], true);
    git(&root, &["commit", "--quiet", "-m", "base"], true);
    git(&root, &["checkout", "--quiet", "-b", "incoming"], true);
    fs::write(root.join("conflict.txt"), b"incoming\n").unwrap();
    git(&root, &["commit", "--quiet", "-am", "incoming"], true);
    git(&root, &["checkout", "--quiet", "main"], true);
    fs::write(root.join("conflict.txt"), b"main\n").unwrap();
    git(&root, &["commit", "--quiet", "-am", "main"], true);
    git(&root, &["merge", "--no-edit", "incoming"], false);
    let expected = git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        true,
    );
    assert!(expected.starts_with(b"UU conflict.txt"));
    let index = fs::read(root.join(".git/index")).unwrap();
    let r = Repository::open_for_git(&root, Limits::default()).unwrap();
    let source = r.snapshot(&no()).unwrap();
    let plan = GitPlan::prepare(
        &r,
        &source,
        &GitOperation::Status,
        "sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4",
        support::limits(),
        &no(),
    )
    .unwrap();
    let (s, t) = support::task_store(
        &d.path().join("store"),
        Some(plan.snapshot.digest().unwrap()),
    );
    let mut b = support::container(s, &t, &plan.request, &plan.snapshot);
    let n = unix_ms().unwrap();
    let permit = b
        .issue_permit(
            &t.task_id,
            plan.request.clone(),
            &plan.snapshot,
            PermitRequest {
                permit_id: "permit:conflict".into(),
                nonce: "nonce:conflict".into(),
                principal_id: "principal:closeout".into(),
                profile_id: t.selected_profile_ids[0].clone(),
                resource_id: t.workspace_ref.clone(),
                authorization_ref: "auth:closeout".into(),
                not_before_unix_ms: n,
                expires_at_unix_ms: n + 90_000,
            },
        )
        .unwrap();
    let result = plan
        .execute(
            &mut b,
            &t.task_id,
            &permit,
            &InvocationIdentity {
                invocation_id: "inv:conflict".into(),
                attempt_id: "attempt:conflict".into(),
                generation: 1,
                idempotency_key: None,
            },
            &no(),
        )
        .unwrap();
    let report = result.report.unwrap();
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.stdout, expected);
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    assert_eq!(r.snapshot(&no()).unwrap(), source);
}
#[test]
fn ignored_parents_cannot_be_reincluded_by_a_nested_ignore_file_and_index_refresh_is_exact() {
    let (_d, r, _s, _p) = support::fixture(&["x"]);
    fs::create_dir(r.root_path().join("hidden")).unwrap();
    fs::write(r.root_path().join(".gitignore"), "hidden/\n*.tmp\n").unwrap();
    fs::write(r.root_path().join("hidden/.gitignore"), "!leak.tmp\n").unwrap();
    fs::write(r.root_path().join("hidden/leak.tmp"), b"must stay ignored").unwrap();
    let first = r.discover(&DiscoveryOptions::default(), &no()).unwrap();
    assert_eq!(
        first
            .files
            .iter()
            .find(|f| f.version.path == "hidden/leak.tmp")
            .unwrap()
            .classification,
        "ignored"
    );
    fs::write(
        r.root_path().join(".gitignore"),
        b"*.tmp\n!hidden/leak.tmp\n",
    )
    .unwrap();
    let next = r.discover(&DiscoveryOptions::default(), &no()).unwrap();
    assert_ne!(first.snapshot.digest, next.snapshot.digest);
    assert_eq!(
        next.files
            .iter()
            .find(|f| f.version.path == "hidden/leak.tmp")
            .unwrap()
            .classification,
        "source"
    );
}
