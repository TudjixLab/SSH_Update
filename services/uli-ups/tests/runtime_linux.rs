#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::AtomicBool,
};
use uli_ups::runtime::WorkspacePool;
use uli4::{
    linux::{PreparedTree, PrivateRoot},
    *,
};

struct Fixture {
    _temp: tempfile::TempDir,
    prepared: PreparedTree,
    sources: PathBuf,
    runtime: PathBuf,
}
fn fixture(protected: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("app")).unwrap();
    fs::write(input.join("app/page.js"), b"export default 1;").unwrap();
    fs::write(input.join("package.json"), b"{}").unwrap();
    if protected {
        fs::create_dir(input.join("UliUpS")).unwrap();
        fs::write(input.join("UliUpS/agent.json"), b"protected").unwrap();
    }
    let key = SigningKey::from_bytes(&[61; 32]);
    let package = temp.path().join("r1.uli4");
    pack(
        &input,
        &package,
        PackageOptions {
            app_id: "test".into(),
            release_id: "r1".into(),
            release_sequence: 1,
            display_version: "0.1".into(),
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            target_runtime: "static".into(),
            profile: "static-files".into(),
            health_policy: "files".into(),
        },
        &key,
        None,
        &Limits::default(),
    )
    .unwrap();
    let trusted = TrustedProject {
        key: key.verifying_key(),
        app_id: "test".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "static".into(),
        allowed_profiles: vec!["static-files".into()],
        health_policies: vec!["files".into()],
        agent_version: (0, 1, 0),
        minimum_sequence: 1,
    };
    let mut verified = verify(&package, &trusted, None, &Limits::default()).unwrap();
    let sources = temp.path().join("sources");
    fs::create_dir(&sources).unwrap();
    fs::set_permissions(&sources, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&sources).unwrap();
    let prepared = root.prepare(&mut verified, None).unwrap();
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
    Fixture {
        _temp: temp,
        prepared,
        sources,
        runtime,
    }
}
fn gid() -> u32 {
    rustix::process::getegid().as_raw()
}
#[test]
fn signed_prepared_tree_is_copied_without_mutating_original_or_overwriting_previous() {
    let f = fixture(false);
    let pool = WorkspacePool::open(&f.runtime, gid()).unwrap();
    let report = pool
        .export(&f.sources, &f.prepared, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(report.release_id, "r1");
    assert_eq!(report.files, 2);
    assert_eq!(report.source_digest, f.prepared.base_release().digest());
    let leaf = f.runtime.join("releases/r1");
    assert_eq!(
        fs::metadata(&leaf).unwrap().permissions().mode() & 0o7777,
        0o2770
    );
    assert_eq!(
        fs::metadata(leaf.join("app")).unwrap().permissions().mode() & 0o7777,
        0o2770
    );
    let target = leaf.join("app/page.js");
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o660
    );
    assert_eq!(fs::metadata(&target).unwrap().gid(), gid());
    pool.select_build("r1").unwrap();
    assert_eq!(
        fs::read_link(f.runtime.join("build-current")).unwrap(),
        PathBuf::from("releases/r1")
    );
    fs::write(&target, b"build modified this copy").unwrap();
    assert_eq!(
        fs::read(f.sources.join("r1/app/page.js")).unwrap(),
        b"export default 1;"
    );
    assert_eq!(
        pool.export(&f.sources, &f.prepared, &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "RUNTIME_RELEASE_EXISTS"
    );
    assert_eq!(fs::read(&target).unwrap(), b"build modified this copy");
    assert_eq!(
        fs::metadata(f.runtime.join("staging"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
}
#[test]
fn modified_source_is_rejected_and_partial_work_is_kept_private() {
    let f = fixture(false);
    fs::write(f.sources.join("r1/app/page.js"), b"export default 2;").unwrap(); // same length
    let pool = WorkspacePool::open(&f.runtime, gid()).unwrap();
    assert_eq!(
        pool.export(&f.sources, &f.prepared, &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "RUNTIME_SOURCE_MISMATCH"
    );
    assert!(!f.runtime.join("releases/r1").exists());
    let pending: Vec<_> = fs::read_dir(f.runtime.join("staging")).unwrap().collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        fs::metadata(f.runtime.join("staging"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert!(f.sources.join("r1/package.json").is_file());
}
#[test]
fn source_symlinks_protected_agent_and_cancellation_never_publish() {
    let f = fixture(false);
    let source = f.sources.join("r1/package.json");
    fs::remove_file(&source).unwrap();
    symlink(f.sources.join("r1/app/page.js"), &source).unwrap();
    let pool = WorkspacePool::open(&f.runtime, gid()).unwrap();
    assert!(
        pool.export(&f.sources, &f.prepared, &AtomicBool::new(false))
            .is_err()
    );
    assert!(!f.runtime.join("releases/r1").exists());
    let p = fixture(true);
    let protected = WorkspacePool::open(&p.runtime, gid()).unwrap();
    assert_eq!(
        protected
            .export(&p.sources, &p.prepared, &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "RUNTIME_PROTECTED_PATH"
    );
    assert_eq!(fs::read_dir(p.runtime.join("staging")).unwrap().count(), 0);
    assert_eq!(
        protected
            .export(&p.sources, &p.prepared, &AtomicBool::new(true))
            .unwrap_err()
            .0,
        "RUNTIME_CANCELLED"
    );
}
#[test]
fn unsafe_pool_and_non_symlink_selection_are_rejected() {
    let f = fixture(false);
    fs::set_permissions(&f.runtime, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(WorkspacePool::open(&f.runtime, gid()).is_err());
    fs::set_permissions(&f.runtime, fs::Permissions::from_mode(0o750)).unwrap();
    let pool = WorkspacePool::open(&f.runtime, gid()).unwrap();
    pool.export(&f.sources, &f.prepared, &AtomicBool::new(false))
        .unwrap();
    fs::write(f.runtime.join("build-current"), b"keep this file").unwrap();
    assert_eq!(
        pool.select_build("r1").unwrap_err().0,
        "RUNTIME_SELECTION_UNSAFE"
    );
    assert_eq!(
        fs::read(f.runtime.join("build-current")).unwrap(),
        b"keep this file"
    );
    assert!(pool.select_build("../r1").is_err());
}
