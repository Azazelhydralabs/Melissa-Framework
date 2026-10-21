use std::{fs, path::Path, sync::Arc, thread};

use melissa_local_store::{
    StoreError,
    cas::{Cas, digest_for, validate_digest},
    crypto::{ENVELOPE_OVERHEAD, StoreKey, stored_len_for_plain},
};

fn key() -> StoreKey {
    StoreKey::from_bytes([0x63; 32])
}

fn blob_file(root: &Path, digest: &str) -> std::path::PathBuf {
    root.join("blobs").join(format!("{}.blob", &digest[7..]))
}

#[test]
fn encryption_authenticates_key_aad_nonce_and_all_ciphertext_bytes() {
    let key = key();
    let envelope = key.seal(b"private contents", b"record:one").unwrap();
    assert_eq!(
        key.open(&envelope, b"record:one").unwrap(),
        b"private contents"
    );
    assert!(key.open(&envelope, b"record:two").is_err());
    assert!(
        StoreKey::from_bytes([0x64; 32])
            .open(&envelope, b"record:one")
            .is_err()
    );
    for index in 0..envelope.len() {
        let mut changed = envelope.clone();
        changed[index] ^= 1;
        assert!(key.open(&changed, b"record:one").is_err(), "byte {index}");
    }
    for length in 0..envelope.len() {
        assert!(key.open(&envelope[..length], b"record:one").is_err());
    }
    let mut appended = envelope.clone();
    appended.push(0);
    assert!(key.open(&appended, b"record:one").is_err());
}

#[test]
fn random_nonce_envelopes_empty_data_and_redacted_keys() {
    let key = StoreKey::generate().unwrap();
    let first = key.seal(b"", b"test").unwrap();
    let second = key.seal(b"", b"test").unwrap();
    assert_ne!(first, second);
    assert_eq!(first.len() as u64, ENVELOPE_OVERHEAD);
    assert!(key.open(&first, b"test").unwrap().is_empty());
    assert_eq!(format!("{key:?}"), "StoreKey([REDACTED])");
    assert_eq!(stored_len_for_plain(19).unwrap(), 19 + ENVELOPE_OVERHEAD);
    assert!(stored_len_for_plain(u64::MAX).is_err());
}

#[test]
fn blake3_vectors_dedup_and_persistent_encrypted_round_trip() {
    assert_eq!(
        digest_for(b""),
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(
        digest_for(b"abc"),
        "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 1024).unwrap();
    let input = b"secret artifact payload never stored in plaintext";
    let first = cas.put(input).unwrap();
    let stored = fs::read(blob_file(directory.path(), &first.digest)).unwrap();
    assert!(!stored.windows(input.len()).any(|window| window == input));
    assert_eq!(first.plain_bytes, input.len() as u64);
    assert_eq!(first.stored_bytes, input.len() as u64 + ENVELOPE_OVERHEAD);
    assert_eq!(cas.put(input).unwrap(), first);
    assert_eq!(
        fs::read(blob_file(directory.path(), &first.digest)).unwrap(),
        stored
    );
    drop(cas);
    let reopened = Cas::open(directory.path(), key(), 1024).unwrap();
    assert_eq!(reopened.get(&first.digest).unwrap(), input);
    assert_eq!(reopened.list().unwrap(), vec![first.clone()]);
    assert_eq!(
        fs::read_dir(directory.path().join("staging"))
            .unwrap()
            .count(),
        0
    );
    reopened.remove(&first.digest).unwrap();
    assert!(matches!(
        reopened.get(&first.digest),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn zero_byte_limit_accepts_only_empty_blobs() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 0).unwrap();
    let empty = cas.put(b"").unwrap();
    assert_eq!(empty.plain_bytes, 0);
    assert_eq!(empty.stored_bytes, ENVELOPE_OVERHEAD);
    assert!(cas.get(&empty.digest).unwrap().is_empty());
    assert!(matches!(cas.put(b"x"), Err(StoreError::Quota(_))));
    assert!(Cas::open(directory.path(), key(), u64::MAX).is_err());
}

#[test]
fn corrupt_existing_blob_does_not_get_replaced_by_dedup() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 1024).unwrap();
    let info = cas.put(b"evidence").unwrap();
    let path = blob_file(directory.path(), &info.digest);
    let mut corrupt = fs::read(&path).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert!(cas.get(&info.digest).is_err());
    assert!(cas.put(b"evidence").is_err());
    assert!(cas.list().is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}

#[test]
fn oversized_and_truncated_files_fail_before_or_during_decryption() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 8).unwrap();
    assert!(matches!(cas.put(b"123456789"), Err(StoreError::Quota(_))));
    let info = cas.put(b"12345678").unwrap();
    let path = blob_file(directory.path(), &info.digest);
    fs::write(&path, vec![0; (ENVELOPE_OVERHEAD + 9) as usize]).unwrap();
    assert!(matches!(
        cas.get(&info.digest),
        Err(StoreError::Integrity(_))
    ));
    fs::write(&path, [0_u8; 2]).unwrap();
    assert!(matches!(
        cas.get(&info.digest),
        Err(StoreError::Integrity(_))
    ));
}

#[test]
fn blob_identity_is_authenticated_and_plaintext_digest_is_rechecked() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 1024).unwrap();
    let first = cas.put(b"first").unwrap();
    let second = cas.put(b"other").unwrap();
    let first_path = blob_file(directory.path(), &first.digest);
    fs::copy(blob_file(directory.path(), &second.digest), &first_path).unwrap();
    assert!(cas.get(&first.digest).is_err());
    let wrong_plaintext = key()
        .seal(
            b"other",
            format!("melissa.cas.blob.v1\0{}", first.digest).as_bytes(),
        )
        .unwrap();
    fs::write(&first_path, wrong_plaintext).unwrap();
    assert!(matches!(
        cas.get(&first.digest),
        Err(StoreError::Integrity(_))
    ));
    let wrong_key = Cas::open(directory.path(), StoreKey::from_bytes([1; 32]), 1024).unwrap();
    assert!(wrong_key.get(&second.digest).is_err());
}

#[test]
fn canonical_digests_prevent_traversal_and_inventory_rejects_unknown_entries() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 1024).unwrap();
    for digest in [
        "../elsewhere",
        "blake3:../elsewhere",
        "sha256:00",
        "blake3:",
        "blake3:AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262",
    ] {
        assert!(validate_digest(digest).is_err());
        assert!(matches!(cas.get(digest), Err(StoreError::Invalid(_))));
        assert!(matches!(cas.remove(digest), Err(StoreError::Invalid(_))));
    }
    fs::write(directory.path().join("blobs").join("unknown.bin"), b"x").unwrap();
    assert!(cas.list().is_err());
    assert!(Cas::open(&directory.path().join("child/../escape"), key(), 1).is_err());
    assert!(!directory.path().join("escape").exists());
    let regular_file = directory.path().join("regular");
    fs::write(&regular_file, b"file").unwrap();
    assert!(Cas::open(&regular_file, key(), 1).is_err());
}

#[test]
fn concurrent_publication_is_no_clobber_and_has_one_verified_blob() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Arc::new(Cas::open(directory.path(), key(), 1024).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(12));
    let writers: Vec<_> = (0..12)
        .map(|_| {
            let cas = Arc::clone(&cas);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                cas.put(b"concurrent identical artifact").unwrap()
            })
        })
        .collect();
    let infos: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().unwrap())
        .collect();
    assert!(infos.iter().all(|info| info == &infos[0]));
    assert_eq!(cas.list().unwrap(), vec![infos[0].clone()]);
    assert_eq!(
        fs::read_dir(directory.path().join("staging"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn staging_cleanup_only_removes_owned_files_older_than_cutoff() {
    let directory = tempfile::tempdir().unwrap();
    let cas = Cas::open(directory.path(), key(), 1024).unwrap();
    let staging = directory.path().join("staging");
    fs::write(staging.join("cas-stage-owned1.tmp"), b"encrypted orphan").unwrap();
    fs::write(staging.join("unrelated.txt"), b"preserve").unwrap();
    fs::write(staging.join("cas-stage-not_owned.tmp"), b"preserve").unwrap();
    assert_eq!(cas.sweep_staging(0).unwrap().removed_files, 0);
    let sweep = cas.sweep_staging(u64::MAX).unwrap();
    assert_eq!(sweep.removed_files, 1);
    assert_eq!(sweep.removed_bytes, b"encrypted orphan".len() as u64);
    assert!(staging.join("unrelated.txt").exists());
    assert!(staging.join("cas-stage-not_owned.tmp").exists());
}

#[cfg(windows)]
#[test]
fn windows_junction_roots_and_replaced_directories_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let outside = directory.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let linked = directory.path().join("linked");
    create_junction(&linked, &outside);
    assert!(Cas::open(&linked, key(), 1024).is_err());
    assert!(Cas::open(&linked.join("child"), key(), 1024).is_err());
    assert!(!outside.join("child").exists());
    fs::remove_dir(&linked).unwrap();

    let cas_root = directory.path().join("safe");
    let cas = Cas::open(&cas_root, key(), 1024).unwrap();
    fs::remove_dir(cas_root.join("blobs")).unwrap();
    create_junction(&cas_root.join("blobs"), &outside);
    assert!(cas.put(b"must not escape").is_err());
    assert!(cas.list().is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    fs::remove_dir(cas_root.join("blobs")).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_device_alternate_stream_and_ambiguous_paths_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    for component in [
        "NUL",
        "con.txt",
        "COM1",
        "LPT³",
        "dir ",
        "dir.",
        "dir:stream",
    ] {
        assert!(
            Cas::open(&directory.path().join(component), key(), 1).is_err(),
            "{component}"
        );
    }
    for path in [
        "C:relative",
        "\\rooted",
        "\\\\server\\share\\cas",
        "\\\\?\\C:\\cas",
    ] {
        assert!(Cas::open(Path::new(path), key(), 1).is_err(), "{path}");
    }
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[cfg(windows)]
fn create_junction(path: &Path, target: &Path) {
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction -Path $env:MELISSA_TEST_LINK -Target $env:MELISSA_TEST_TARGET | Out-Null"])
        .env("MELISSA_TEST_LINK", path)
        .env("MELISSA_TEST_TARGET", target)
        .output().unwrap();
    assert!(
        output.status.success(),
        "junction fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn symlink_roots_blob_entries_and_replaced_directories_are_rejected() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let outside = directory.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let linked = directory.path().join("linked");
    symlink(&outside, &linked).unwrap();
    assert!(Cas::open(&linked, key(), 1024).is_err());
    assert!(Cas::open(&linked.join("child"), key(), 1024).is_err());
    let cas_root = directory.path().join("safe");
    let cas = Cas::open(&cas_root, key(), 1024).unwrap();
    let digest = digest_for(b"example");
    symlink(outside.join("unrelated"), blob_file(&cas_root, &digest)).unwrap();
    assert!(cas.get(&digest).is_err());
    assert!(cas.put(b"example").is_err());
    assert!(cas.list().is_err());
    fs::remove_file(blob_file(&cas_root, &digest)).unwrap();
    fs::remove_dir(cas_root.join("blobs")).unwrap();
    symlink(&outside, cas_root.join("blobs")).unwrap();
    assert!(cas.put(b"must not escape").is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}
