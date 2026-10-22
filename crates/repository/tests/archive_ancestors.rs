//! Portable ustar inspection checks (no Windows filesystem needed).
use melissa_repository::*;

fn header(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
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
    out
}
fn tar(entries: &[(&str, u8)]) -> Vec<u8> {
    let mut out = vec![];
    for (name, kind) in entries {
        let data: &[u8] = if *kind == b'5' { b"" } else { b"x" };
        out.extend(header(name, *kind, data));
    }
    out.resize(out.len() + 1024, 0);
    out
}

#[test]
fn file_after_its_descendants_is_an_ancestor_collision() {
    for entries in [
        &[("a/b", b'0'), ("a", b'0')][..],
        &[("a/b/c", b'0'), ("a/b", b'0')][..],
        &[("A/b", b'0'), ("a", b'0')][..],
        &[("a/b/", b'5'), ("a", b'0')][..],
    ] {
        assert!(
            archive::inspect_ustar(&tar(entries), &Limits::default()).is_err(),
            "{entries:?}"
        );
    }
}

#[test]
fn sibling_names_sharing_a_prefix_are_not_ancestors() {
    for entries in [
        &[("ab/c", b'0'), ("a", b'0')][..],
        &[("a.b/c", b'0'), ("a", b'0')][..],
        &[("a-/c", b'0'), ("a", b'0')][..],
    ] {
        assert_eq!(
            archive::inspect_ustar(&tar(entries), &Limits::default())
                .unwrap()
                .len(),
            2,
            "{entries:?}"
        );
    }
}

#[test]
fn many_flat_entries_are_accepted() {
    let names: Vec<String> = (0..5_000).map(|i| format!("d/f{i:06}")).collect();
    let entries: Vec<(&str, u8)> = names.iter().map(|n| (n.as_str(), b'0')).collect();
    assert_eq!(
        archive::inspect_ustar(&tar(&entries), &Limits::default())
            .unwrap()
            .len(),
        5_000
    );
}
