#![cfg(windows)]
use melissa_repository::{Error, Limits, Repository, symbols::SyntaxIndex};
use std::{fs, sync::atomic::AtomicBool, time::Duration};
#[test]
fn real_rust_ast_distinguishes_same_names_modules_and_comments_from_references() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a.rs"),b"mod first { fn shared() {} fn call() { shared(); } } // shared\nconst LABEL: &str = \"shared\";").unwrap();
    fs::write(root.join("b.rs"), b"mod other { pub fn shared() {} } ").unwrap();
    let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
    let c = AtomicBool::new(false);
    let snapshot = repo.snapshot(&c).unwrap();
    let index = SyntaxIndex::build(&repo, &snapshot, &c, Duration::from_secs(5)).unwrap();
    let symbols = index.lookup(&repo, &snapshot, "shared", &c).unwrap();
    assert_eq!(symbols.len(), 2);
    assert_eq!(symbols[0].scope, "first");
    assert_eq!(symbols[1].scope, "other");
    let occurrences = index.references(&repo, &snapshot, "shared", &c).unwrap();
    assert_eq!(occurrences.len(), 3);
    assert!(
        occurrences
            .iter()
            .all(|o| o.resolution.contains("not_semantically_resolved"))
    );
    fs::write(root.join("a.rs"), b"fn changed() {} ").unwrap();
    assert!(matches!(
        index.lookup(&repo, &snapshot, "shared", &c),
        Err(Error::Stale(_))
    ));
}
#[test]
fn syntax_errors_unsupported_languages_and_cancellation_are_truthful() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("bad.rs"), b"fn broken( {").unwrap();
    fs::write(root.join("a.py"), b"def skipped(): pass").unwrap();
    let repo = Repository::open(&root, Limits::default(), vec![]).unwrap();
    let c = AtomicBool::new(false);
    let snapshot = repo.snapshot(&c).unwrap();
    let index = SyntaxIndex::build(&repo, &snapshot, &c, Duration::from_secs(5)).unwrap();
    assert_eq!(index.files_with_syntax_errors, ["bad.rs"]);
    assert_eq!(index.skipped_non_rust_files, ["a.py"]);
    assert!(matches!(
        SyntaxIndex::build(
            &repo,
            &snapshot,
            &AtomicBool::new(true),
            Duration::from_secs(5)
        ),
        Err(Error::Cancelled)
    ));
}
