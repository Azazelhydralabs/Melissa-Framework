#![cfg(windows)]
use melissa_repository::*;
use std::{fs, sync::atomic::AtomicBool};

fn root() -> (tempfile::TempDir, Repository) {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("source");
    fs::create_dir(&p).unwrap();
    fs::create_dir(p.join("crate-a")).unwrap();
    fs::create_dir(p.join("crate-b")).unwrap();
    fs::write(p.join("crate-a/lib.rs"), b"fn shared() {}\n// needle\n").unwrap();
    fs::write(
        p.join("crate-b/lib.rs"),
        b"fn shared() {}\nfn needle() {}\n",
    )
    .unwrap();
    (t, Repository::open(&p, Limits::default(), vec![]).unwrap())
}
#[test]
fn monorepo_snapshot_search_hashes_and_stale_additions_are_explicit() {
    let (_t, r) = root();
    let c = AtomicBool::new(false);
    let s = r.snapshot(&c).unwrap();
    assert_eq!(s.files.len(), 2);
    assert!(!s.atomic_tree_snapshot);
    let hits = r.search(&s, b"needle", &c).unwrap();
    assert_eq!(hits.hits.len(), 2);
    assert_ne!(hits.hits[0].path, hits.hits[1].path);
    assert!(!hits.truncated);
    for h in &hits.hits {
        assert_eq!(h.digest, r.read(&h.path).unwrap().0.digest);
        assert_eq!(h.line, 2);
    }
    fs::write(r.root_path().join("new.txt"), b"user work").unwrap();
    assert!(r.search(&s, b"needle", &c).is_err());
}
#[test]
fn a_preserved_snapshot_digest_cannot_authenticate_modified_snapshot_fields() {
    let (_t, r) = root();
    let c = AtomicBool::new(false);
    let original = r.snapshot(&c).unwrap();
    for case in 0..5 {
        let mut changed = original.clone();
        match case {
            0 => changed.files.clear(),
            1 => changed.total_bytes = 0,
            2 => changed.schema_version = "fake".into(),
            3 => changed.atomic_tree_snapshot = true,
            _ => changed.excluded_prefixes.clear(),
        }
        assert!(r.validate_snapshot(&changed, &c).is_err());
        assert!(r.search(&changed, b"needle", &c).is_err());
    }
}
#[test]
fn exclusions_and_binary_search_do_not_silently_claim_gitignore() {
    let (_t, r) = root();
    fs::create_dir(r.root_path().join("target")).unwrap();
    fs::write(r.root_path().join("target/generated"), b"ignored").unwrap();
    fs::write(r.root_path().join("binary"), b"zero\0\xffneedle").unwrap();
    let s = r.snapshot(&AtomicBool::new(false)).unwrap();
    assert_eq!(s.files.len(), 3);
    let result = r.search(&s, b"\0\xff", &AtomicBool::new(false)).unwrap();
    assert_eq!(result.hits.len(), 1);
    assert!(r.read(".git/config").is_err());
    assert!(s.excluded_prefixes.contains(&"target".into()));
}
#[test]
fn traversal_ads_devices_ambiguous_paths_and_nested_git_are_rejected() {
    let (_t, r) = root();
    for p in [
        "../outside",
        "/outside",
        "crate-a/../lib.rs",
        "crate-a\\lib.rs",
        "file:stream",
        "CON.txt",
        "COM¹",
        "file.",
        "file ",
        "C:/file",
        "a//b",
        ".git/config",
        "crate-a/.GIT/config",
    ] {
        assert!(r.read(p).is_err(), "{p}");
    }
}
#[test]
fn real_directory_junction_and_file_symlink_cannot_escape() {
    let (t, r) = root();
    let outside = t.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("private.txt"), b"private").unwrap();
    let link = r.root_path().join("junction");
    let ok = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(ok.status.success());
    assert!(r.read("junction/private.txt").is_err());
    assert!(r.snapshot(&AtomicBool::new(false)).is_err());
    // Remove only the owned junction itself; never recurse into its target.
    fs::remove_dir(link).unwrap();
    assert_eq!(fs::read(outside.join("private.txt")).unwrap(), b"private");
}
#[test]
fn resource_quotas_search_truncation_and_cancel_are_observable() {
    let (_t, r) = root();
    let limits = Limits {
        max_file_bytes: 8,
        max_total_bytes: 32,
        ..Limits::default()
    };
    let small = Repository::open(r.root_path(), limits, vec![]).unwrap();
    assert!(matches!(small.read("crate-a/lib.rs"), Err(Error::Quota(_))));
    let limited = Repository::open(
        r.root_path(),
        Limits {
            max_search_hits: 1,
            ..Limits::default()
        },
        vec![],
    )
    .unwrap();
    let c = AtomicBool::new(false);
    let s = limited.snapshot(&c).unwrap();
    assert!(limited.search(&s, b"fn", &c).unwrap().truncated);
    assert!(matches!(
        r.snapshot(&AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}
fn proposal() -> PatchProposal {
    PatchProposal {
        schema_version: "melissa.repository-patch/v1".into(),
        root_identity: "root".into(),
        files: vec![FilePatch {
            before: FileVersion {
                path: "a.rs".into(),
                identity: "1".into(),
                digest: format!("blake3:{}", blake3::hash(b"abc").to_hex()),
                bytes: 3,
            },
            edits: vec![ByteEdit {
                start: 1,
                end: 2,
                expected: b"b".to_vec(),
                replacement: b"new".to_vec(),
            }],
        }],
    }
}
#[test]
fn patch_json_duplicates_unknown_fields_overlap_alias_and_bad_offsets_fail() {
    let p = proposal();
    let raw = serde_json::to_vec(&p).unwrap();
    assert!(PatchProposal::parse(&raw).is_ok());
    let mut v = serde_json::to_value(&p).unwrap();
    v["authority"] = "model".into();
    assert!(PatchProposal::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    let dup = String::from_utf8(raw).unwrap().replacen(
        "\"schema_version\":",
        "\"schema_version\":\"x\",\"schema_version\":",
        1,
    );
    assert!(PatchProposal::parse(dup.as_bytes()).is_err());
    let mut duplicate = p.clone();
    duplicate.files.push(p.files[0].clone());
    assert!(duplicate.validate(&Limits::default()).is_err());
    let mut overlap = p.clone();
    overlap.files[0].edits.push(p.files[0].edits[0].clone());
    assert!(overlap.validate(&Limits::default()).is_err());
    let mut bad = p;
    bad.files[0].edits[0].end = u64::MAX;
    assert!(bad.validate(&Limits::default()).is_err());
}
#[test]
fn parser_build_dependencies_do_not_change_runtime_json_map_canonical_order() {
    // Tree-sitter uses preserve_order only in its build dependency. Resolver 3
    // must keep that separate from the existing runtime's sorted map contract.
    assert_eq!(
        serde_json::json!({"z":1,"a":2}).to_string(),
        "{\"a\":2,\"z\":1}"
    );
}

fn tar_file(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    h[148..156].fill(b' ');
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out.resize(out.len() + 1024, 0);
    out
}
#[test]
fn archive_import_is_bounded_untrusted_memory_and_never_extraction() {
    let raw = tar_file("crate-a/lib.rs", b'0', b"proposal\0\xff");
    let files = archive::inspect_ustar(&raw, &Limits::default()).unwrap();
    assert_eq!(files.len(), 1);
    assert!(!files[0].trusted);
    assert_eq!(files[0].bytes, b"proposal\0\xff");
    let mut bad = raw.clone();
    bad[512] ^= 1;
    assert!(archive::inspect_ustar(&bad, &Limits::default()).is_ok()); // tar has no payload authentication.
    bad[0] ^= 1;
    assert!(archive::inspect_ustar(&bad, &Limits::default()).is_err());
}
#[test]
fn selected_imports_require_exact_outputs_and_unchanged_source() {
    let (_t, r) = root();
    let c = AtomicBool::new(false);
    let snapshot = r.snapshot(&c).unwrap();
    let raw = tar_file("crate-a/lib.rs", b'0', b"fn replacement() {}\n");
    let imported = archive::inspect_ustar(&raw, &Limits::default()).unwrap();
    let selection = r
        .propose_import(&snapshot, &imported, &["crate-a/lib.rs".into()].into(), &c)
        .unwrap();
    assert!(selection.patch.is_some());
    assert_eq!(
        r.read("crate-a/lib.rs").unwrap().1,
        b"fn shared() {}\n// needle\n"
    );
    assert!(
        r.propose_import(&snapshot, &imported, &["CRATE-A/lib.rs".into()].into(), &c)
            .is_err()
    );
    assert!(
        r.propose_import(&snapshot, &imported, &["missing.rs".into()].into(), &c)
            .is_err()
    );
    fs::write(r.root_path().join("crate-a/lib.rs"), b"user updated it").unwrap();
    assert!(
        r.propose_import(&snapshot, &imported, &["crate-a/lib.rs".into()].into(), &c)
            .is_err()
    );
}
#[test]
fn malicious_archive_links_devices_traversal_truncation_and_duplicates_fail() {
    for path in ["../escape", "/absolute", "file:ads", "CON", ".git/config"] {
        assert!(archive::inspect_ustar(&tar_file(path, b'0', b"x"), &Limits::default()).is_err());
    }
    for kind in *b"12346xgS" {
        assert!(archive::inspect_ustar(&tar_file("a", kind, b"x"), &Limits::default()).is_err());
    }
    let mut a = tar_file("A", b'0', b"x");
    a.truncate(a.len() - 1024);
    a.extend(tar_file("a", b'0', b"y"));
    assert!(archive::inspect_ustar(&a, &Limits::default()).is_err());
    let mut a = tar_file("a", b'0', b"x");
    a.truncate(a.len() - 512);
    assert!(archive::inspect_ustar(&a, &Limits::default()).is_err());
    for (first, last) in [("a", "a/b"), ("a/b", "a")] {
        let mut a = tar_file(first, b'0', b"x");
        a.truncate(a.len() - 1024);
        a.extend(tar_file(last, b'0', b"y"));
        assert!(archive::inspect_ustar(&a, &Limits::default()).is_err());
    }
}
