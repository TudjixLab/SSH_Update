use ed25519_dalek::SigningKey;
use std::{fs, path::Path};
use uli4::*;
fn options(id: &str, sequence: u64) -> PackageOptions {
    PackageOptions {
        app_id: "sample".into(),
        release_id: id.into(),
        release_sequence: sequence,
        display_version: "0.1.0".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "node24".into(),
        profile: "nextjs-systemd".into(),
        health_policy: "http".into(),
    }
}
fn trust(key: &SigningKey) -> TrustedProject {
    TrustedProject {
        key: key.verifying_key(),
        app_id: "sample".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "node24".into(),
        allowed_profiles: vec!["nextjs-systemd".into()],
        health_policies: vec!["http".into()],
        agent_version: (0, 1, 0),
        minimum_sequence: 1,
    }
}
fn write(root: &Path, p: &str, bytes: &[u8]) {
    let path = root.join(p);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
#[test]
fn full_roundtrip_excludes_secrets_and_does_not_build() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "package.json", br#"{"scripts":{"build":"exit 99"}}"#);
    write(&root, "app/История.txt", "Привет, мир".as_bytes());
    write(&root, "empty.txt", b"");
    for p in [
        ".env",
        ".env.production",
        "node_modules/x.js",
        ".next/x",
        ".git/config",
        "Secrets/x",
        "private/spec.md",
        "tls.pem",
        "id_ed25519",
    ] {
        write(&root, p, b"DO_NOT_PACKAGE");
    }
    let l = Limits::default();
    let key = SigningKey::from_bytes(&[7; 32]);
    let before = scan(&root, &l).unwrap();
    assert_eq!(before.files.len(), 3);
    assert_eq!(before.excluded.len(), 9);
    let output = t.path().join("sample.uli4");
    pack(&root, &output, options("one", 1), &key, None, &l).unwrap();
    let mut verified = verify(&output, &trust(&key), None, &l).unwrap();
    assert_eq!(verified.base_release().files(), before.files);
    for (index, op) in verified
        .manifest()
        .file_operations
        .clone()
        .iter()
        .enumerate()
    {
        let mut bytes = Vec::new();
        verified.copy_file(index, &mut bytes).unwrap();
        assert_eq!(bytes, fs::read(root.join(&op.file.path)).unwrap());
    }
    assert_eq!(scan(&root, &l).unwrap().files, before.files);
    assert!(!root.join("sample.uli4").exists());
}
#[test]
fn incremental_tracks_add_replace_delete_and_exact_base() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "old", b"old");
    write(&root, "changed", b"before");
    write(&root, "same", b"same");
    let l = Limits::default();
    let key = SigningKey::from_bytes(&[8; 32]);
    let first = t.path().join("one.uli4");
    pack(&root, &first, options("one", 1), &key, None, &l).unwrap();
    let base = verify(&first, &trust(&key), None, &l)
        .unwrap()
        .base_release();
    fs::remove_file(root.join("old")).unwrap();
    write(&root, "changed", b"after");
    write(&root, "new", b"new");
    let second = t.path().join("two.uli4");
    pack(&root, &second, options("two", 2), &key, Some(&base), &l).unwrap();
    assert!(verify(&second, &trust(&key), None, &l).is_err());
    let verified = verify(&second, &trust(&key), Some(&base), &l).unwrap();
    assert_eq!(
        verified
            .manifest()
            .file_operations
            .iter()
            .map(|o| o.kind.clone())
            .collect::<Vec<_>>(),
        [
            OperationKind::Replace,
            OperationKind::Add,
            OperationKind::Delete
        ]
    );
    assert_eq!(
        verified.base_release().files(),
        scan(&root, &l).unwrap().files
    );
}
#[test]
fn corruption_wrong_signer_target_and_replay_floor_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "x", b"payload");
    let l = Limits::default();
    let key = SigningKey::from_bytes(&[9; 32]);
    let output = t.path().join("good.uli4");
    pack(&root, &output, options("one", 1), &key, None, &l).unwrap();
    let bytes = fs::read(&output).unwrap();
    for (n, index) in [0, 128, 160, bytes.len() - 1].into_iter().enumerate() {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        let p = t.path().join(format!("bad{n}.uli4"));
        fs::write(&p, bad).unwrap();
        assert!(verify(&p, &trust(&key), None, &l).is_err());
    }
    let payload_offset = u64::from_le_bytes(bytes[48..56].try_into().unwrap()) as usize;
    let mut bad = bytes.clone();
    bad[payload_offset + 4] ^= 1;
    let p = t.path().join("payload.uli4");
    fs::write(&p, bad).unwrap();
    assert!(verify(&p, &trust(&key), None, &l).is_err());
    let mut bad = bytes.clone();
    bad.push(0);
    let p = t.path().join("trailing.uli4");
    fs::write(&p, bad).unwrap();
    assert!(verify(&p, &trust(&key), None, &l).is_err());
    assert!(
        verify(
            &output,
            &trust(&SigningKey::from_bytes(&[10; 32])),
            None,
            &l
        )
        .is_err()
    );
    let mut wrong = trust(&key);
    wrong.app_id = "other".into();
    assert!(verify(&output, &wrong, None, &l).is_err());
    wrong = trust(&key);
    wrong.minimum_sequence = 2;
    assert!(verify(&output, &wrong, None, &l).is_err());
}
#[test]
fn portable_paths_collisions_and_quotas() {
    for p in [
        "../x",
        "/etc/passwd",
        "a//b",
        "a/./b",
        "C:/x",
        "x\\y",
        "NUL.txt",
        "COM1",
        "tail.",
        "x\0z",
        "e\u{301}.txt",
    ] {
        assert!(validate_path(p).is_err(), "{p:?}");
    }
    let record = |p: &str| FileRecord {
        path: p.into(),
        sha256: "0".repeat(64),
        size: 0,
        mode: 0o644,
    };
    assert!(tree_digest(&[record("A.txt"), record("a.txt")]).is_err());
    assert!(tree_digest(&[record("A/a"), record("a")]).is_err());
    assert!(tree_digest(&[record("ss"), record("ß")]).is_err());
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "x", b"123");
    let limits = Limits {
        file_bytes: 2,
        ..Limits::default()
    };
    assert!(scan(&root, &limits).is_err());
}
#[test]
fn hardlinks_are_rejected_and_output_is_never_overwritten() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "x", b"123");
    fs::hard_link(root.join("x"), root.join("alias")).unwrap();
    assert!(scan(&root, &Limits::default()).is_err());
    fs::remove_file(root.join("alias")).unwrap();
    let output = t.path().join("existing.uli4");
    fs::write(&output, b"keep").unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    assert!(
        pack(
            &root,
            &output,
            options("one", 1),
            &key,
            None,
            &Limits::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(output).unwrap(), b"keep");
    assert!(
        pack(
            &root,
            &root.join("bad.uli4"),
            options("one", 1),
            &key,
            None,
            &Limits::default()
        )
        .is_err()
    );
}
#[test]
fn package_bytes_are_deterministic_for_identical_metadata() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir(&root).unwrap();
    write(&root, "hello.txt", b"Hello ULI4\n");
    let key = SigningKey::from_bytes(&[12; 32]);
    let a = t.path().join("a.uli4");
    let b = t.path().join("b.uli4");
    for output in [&a, &b] {
        pack(
            &root,
            output,
            options("golden", 1),
            &key,
            None,
            &Limits::default(),
        )
        .unwrap();
    }
    let bytes = fs::read(a).unwrap();
    assert_eq!(bytes, fs::read(b).unwrap());
    assert_eq!(
        hex::encode(&bytes[..16]),
        "554c493401000000a000000000000000"
    );
}

#[test]
fn unicode_aliases_devices_and_total_scan_budget() {
    for p in ["COM¹", "LPT².txt", "COM³"] {
        assert!(validate_path(p).is_err());
    }
    for p in ["ſecrets/file", "ſhared/file", ".ENV.local"] {
        assert!(denied_path(p));
    }
    let record = |p: &str| FileRecord {
        path: p.into(),
        sha256: "0".repeat(64),
        size: 0,
        mode: 0o644,
    };
    assert!(tree_digest(&[record("ა"), record("Ა")]).is_err());
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "a", b"12");
    write(t.path(), "b", b"34");
    assert!(
        scan(
            t.path(),
            &Limits {
                plain_bytes: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert_eq!(caseless::UNICODE_VERSION, (16, 0, 0));
    assert_eq!(unicode_normalization::UNICODE_VERSION, (16, 0, 0));
}
#[cfg(unix)]
#[test]
fn source_symlink_and_literal_backslash_rejected() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "real", b"x");
    std::os::unix::fs::symlink(t.path().join("real"), t.path().join("alias")).unwrap();
    assert!(scan(t.path(), &Limits::default()).is_err());
    fs::remove_file(t.path().join("alias")).unwrap();
    write(t.path(), "bad\\path", b"x");
    assert!(scan(t.path(), &Limits::default()).is_err());
}
