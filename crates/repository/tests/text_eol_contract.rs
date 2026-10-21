#![cfg(windows)]
mod support;
use melissa_repository::{
    PatchBroker,
    unified::{ProposedChange, UnifiedLineEndings},
};
use std::{fs, sync::atomic::AtomicBool};
fn no() -> AtomicBool {
    AtomicBool::new(false)
}
const LF_PATCH: &[u8] = b"--- a/file.txt\n+++ b/file.txt\n@@ -1,2 +1,2 @@\n-old\n+new\n keep\n";
#[test]
fn explicit_text_eol_preserves_crlf_and_exact_mode_still_rejects_lf_hunks() {
    let (_t, r, mut s, p) = support::fixture(&["file.txt"]);
    fs::write(r.root_path().join("file.txt"), b"old\r\nkeep\r\n").unwrap();
    let snapshot = r.snapshot(&no()).unwrap();
    assert!(r.propose_unified(&snapshot, LF_PATCH, &no()).is_err());
    let proposal = r
        .propose_unified_with_line_endings(
            &snapshot,
            LF_PATCH,
            UnifiedLineEndings::PreserveSource,
            &no(),
        )
        .unwrap();
    assert_eq!(proposal.line_endings, UnifiedLineEndings::PreserveSource);
    assert!(!proposal.authorizes_write);
    assert_eq!(r.read("file.txt").unwrap().1, b"old\r\nkeep\r\n");
    let ProposedChange::Patch(patch) = proposal.changes[0].clone() else {
        panic!()
    };
    assert_eq!(patch.files[0].before, snapshot.files[0]);
    assert_eq!(patch.files[0].edits[0].replacement, b"new\r\nkeep\r\n");
    let mut broker = PatchBroker::new(&r, &mut s, p).unwrap();
    let permit = broker.authorize("inv:eol", "attempt:eol", patch).unwrap();
    broker.execute(permit, &no()).unwrap();
    assert_eq!(r.read("file.txt").unwrap().1, b"new\r\nkeep\r\n");
    assert!(
        r.propose_unified_with_line_endings(
            &snapshot,
            LF_PATCH,
            UnifiedLineEndings::PreserveSource,
            &no()
        )
        .is_err()
    );
}
#[test]
fn text_eol_rejects_wrong_content_mixed_sources_unknown_modes_and_namespace_changes() {
    let (_t, r, _s, _p) = support::fixture(&["file.txt"]);
    for source in [b"old\r\nkeep\n".as_slice(), b"old\rbroken\nkeep\n", b"old"] {
        fs::write(r.root_path().join("file.txt"), source).unwrap();
        let snapshot = r.snapshot(&no()).unwrap();
        assert!(
            r.propose_unified_with_line_endings(
                &snapshot,
                LF_PATCH,
                UnifiedLineEndings::PreserveSource,
                &no()
            )
            .is_err()
        );
        assert_eq!(r.read("file.txt").unwrap().1, source);
    }
    fs::write(r.root_path().join("file.txt"), b"old\r\nkeep\r\n").unwrap();
    let s = r.snapshot(&no()).unwrap();
    for patch in [
        b"--- a/file.txt\n+++ b/file.txt\n@@ -1,2 +1,2 @@\n-wrong\n+new\n keep\n".as_slice(),
        b"--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n",
        b"--- a/file.txt\n+++ b/moved.txt\n@@ -1,2 +1,2 @@\n-old\n+new\n keep\n",
        b"--- a/../file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-old\n+new\n",
    ] {
        assert!(
            r.propose_unified_with_line_endings(
                &s,
                patch,
                UnifiedLineEndings::PreserveSource,
                &no()
            )
            .is_err()
        );
    }
    assert!(serde_json::from_str::<UnifiedLineEndings>("\"fuzzy\"").is_err());
}
#[test]
fn text_eol_preserves_lf_and_explicit_missing_final_newline_and_rejects_stale_snapshot() {
    let (_t, r, _s, _p) = support::fixture(&["file.txt"]);
    for (source,patch,expected) in [
        (b"old\nkeep\n".as_slice(),LF_PATCH,b"new\nkeep\n".as_slice()),
        (b"old\r\nkeep",b"--- a/file.txt\n+++ b/file.txt\n@@ -1,2 +1,2 @@\n-old\n+new\n keep\n\\ No newline at end of file\n",b"new\r\nkeep"),
    ] {
        fs::write(r.root_path().join("file.txt"),source).unwrap();let s=r.snapshot(&no()).unwrap();
        let proposal=r.propose_unified_with_line_endings(&s,patch,UnifiedLineEndings::PreserveSource,&no()).unwrap();
        let ProposedChange::Patch(p)=&proposal.changes[0] else {panic!()};
        assert_eq!(p.files[0].edits[0].replacement,expected);
        fs::write(r.root_path().join("file.txt"),b"unrelated\r\n").unwrap();
        assert!(r.propose_unified_with_line_endings(&s,patch,UnifiedLineEndings::PreserveSource,&no()).is_err());
    }
}
