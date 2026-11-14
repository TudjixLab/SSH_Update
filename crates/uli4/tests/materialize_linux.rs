#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};
use uli4::{
    linux::{PreparedTree, PrivateRoot},
    *,
};
struct Fixture {
    _temp: tempfile::TempDir,
    source: PathBuf,
    pool: PathBuf,
    root: PrivateRoot,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        let pool = t.path().join("pool");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&pool).unwrap();
        fs::set_permissions(&pool, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&pool).unwrap();
        let f = Self {
            _temp: t,
            source,
            pool,
            root,
            key: SigningKey::from_bytes(&[31; 32]),
        };
        f.write("a.txt", b"before");
        f.write("same/file.txt", b"unchanged");
        f.write("old.txt", b"old");
        f.write("empty", b"");
        f
    }
    fn write(&self, p: &str, b: &[u8]) {
        let p = self.source.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b).unwrap();
    }
    fn package(&self, id: &str, seq: u64, base: Option<&BaseRelease>) -> VerifiedPackage {
        let p = self._temp.path().join(format!("{id}.uli4"));
        pack(
            &self.source,
            &p,
            PackageOptions {
                app_id: "sample".into(),
                release_id: id.into(),
                release_sequence: seq,
                display_version: "0.1.0".into(),
                target_os: "linux".into(),
                target_arch: "x86_64".into(),
                target_runtime: "static".into(),
                profile: "static-files".into(),
                health_policy: "files".into(),
            },
            &self.key,
            base,
            &Limits::default(),
        )
        .unwrap();
        let trust = TrustedProject {
            key: self.key.verifying_key(),
            app_id: "sample".into(),
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            target_runtime: "static".into(),
            allowed_profiles: vec!["static-files".into()],
            health_policies: vec!["files".into()],
            agent_version: (0, 1, 0),
            minimum_sequence: 1,
        };
        verify(&p, &trust, base, &Limits::default()).unwrap()
    }
    fn base(&self) -> PreparedTree {
        self.root
            .prepare(&mut self.package("r1", 1, None), None)
            .unwrap()
    }
}
#[test]
fn full_and_reload_preserve_exact_tree_and_live_pointer() {
    let f = Fixture::new();
    fs::write(f.pool.join("current"), b"live-sentinel").unwrap();
    let b = f.base();
    let expected = scan(&f.source, &Limits::default()).unwrap().files;
    assert_eq!(b.base_release().files(), expected);
    assert_eq!(b.release_id(), "r1");
    let loaded = f.root.load_base("r1", &b.base_release()).unwrap();
    assert_eq!(loaded.base_release().digest(), b.base_release().digest());
    assert_eq!(
        fs::read(f.pool.join("r1/same/file.txt")).unwrap(),
        b"unchanged"
    );
    assert_eq!(fs::read(f.pool.join("current")).unwrap(), b"live-sentinel");
}
#[test]
fn incremental_copies_unchanged_without_hardlinks_and_never_deletes_old_tree() {
    let f = Fixture::new();
    let b = f.base();
    let map = b.base_release();
    f.write("a.txt", b"after");
    f.write("new/file.txt", b"new");
    fs::remove_file(f.source.join("old.txt")).unwrap();
    let p = f
        .root
        .prepare(&mut f.package("r2", 2, Some(&map)), Some(&b))
        .unwrap();
    assert_eq!(
        p.base_release().files(),
        scan(&f.source, &Limits::default()).unwrap().files
    );
    assert!(!f.pool.join("r2/old.txt").exists());
    assert_eq!(fs::read(f.pool.join("r1/old.txt")).unwrap(), b"old");
    assert_ne!(
        fs::metadata(f.pool.join("r1/same/file.txt")).unwrap().ino(),
        fs::metadata(f.pool.join("r2/same/file.txt")).unwrap().ino()
    );
    assert_eq!(
        fs::metadata(f.pool.join("r2/same/file.txt"))
            .unwrap()
            .nlink(),
        1
    );
    assert_eq!(fs::metadata(f.pool.join("r2/empty")).unwrap().len(), 0);
}
#[test]
fn changed_base_after_load_is_rejected() {
    let f = Fixture::new();
    let b = f.base();
    let map = b.base_release();
    let loaded = f.root.load_base("r1", &map).unwrap();
    let mut p = f.package("r2", 2, Some(&map));
    fs::write(f.pool.join("r1/same/file.txt"), b"tampered").unwrap();
    assert!(f.root.prepare(&mut p, Some(&loaded)).is_err());
    assert!(!f.pool.join("r2").exists());
}
#[test]
fn symlink_and_hardlink_base_substitution_rejected() {
    for hard in [false, true] {
        let f = Fixture::new();
        let b = f.base();
        let map = b.base_release();
        let mut p = f.package("r2", 2, Some(&map));
        let target = f.pool.join("r1/same/file.txt");
        let external = f._temp.path().join("external");
        fs::write(&external, b"unchanged").unwrap();
        fs::remove_file(&target).unwrap();
        if hard {
            fs::hard_link(&external, &target).unwrap();
        } else {
            symlink(&external, &target).unwrap();
        }
        assert!(f.root.prepare(&mut p, Some(&b)).is_err());
        assert!(!f.pool.join("r2").exists());
    }
}
#[test]
fn fifo_substitution_fails_without_blocking() {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let f = Fixture::new();
        let b = f.base();
        let mut p = f.package("r2", 2, Some(&b.base_release()));
        let target = f.pool.join("r1/a.txt");
        fs::remove_file(&target).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &target,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        sender
            .send(f.root.prepare(&mut p, Some(&b)).is_err())
            .unwrap();
    });
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("FIFO must not block file opening")
    );
}
#[test]
fn existing_release_and_staging_are_never_overwritten() {
    let f = Fixture::new();
    fs::create_dir(f.pool.join("r1")).unwrap();
    fs::write(f.pool.join("r1/keep"), b"keep").unwrap();
    assert!(f.root.prepare(&mut f.package("r1", 1, None), None).is_err());
    assert_eq!(fs::read(f.pool.join("r1/keep")).unwrap(), b"keep");
    fs::create_dir(f.pool.join(".pending-r2")).unwrap();
    fs::write(f.pool.join(".pending-r2/keep"), b"pending").unwrap();
    assert!(f.root.prepare(&mut f.package("r2", 2, None), None).is_err());
    assert_eq!(
        fs::read(f.pool.join(".pending-r2/keep")).unwrap(),
        b"pending"
    );
    assert!(!f.pool.join("r2").exists());
}
#[test]
fn unsafe_root_and_root_symlink_rejected() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(PrivateRoot::open(&root).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let link = t.path().join("link");
    symlink(&root, &link).unwrap();
    assert!(PrivateRoot::open(&link).is_err());
}
#[test]
fn package_changed_after_verification_cannot_publish_tree() {
    let f = Fixture::new();
    let mut p = f.package("r1", 1, None);
    let path = f._temp.path().join("r1.uli4");
    let mut bytes = fs::read(&path).unwrap();
    let offset = u64::from_le_bytes(bytes[48..56].try_into().unwrap()) as usize;
    bytes[offset + 7] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(f.root.prepare(&mut p, None).is_err());
    assert!(!f.pool.join("r1").exists());
    assert!(f.pool.join(".pending-r1").is_dir());
}
#[test]
fn reload_rejects_changed_files_and_unknown_entries() {
    let f = Fixture::new();
    let b = f.base();
    let map = b.base_release();
    fs::write(f.pool.join("r1/extra"), b"extra").unwrap();
    assert!(f.root.load_base("r1", &map).is_err());
    fs::remove_file(f.pool.join("r1/extra")).unwrap();
    fs::write(f.pool.join("r1/a.txt"), b"wrong").unwrap();
    assert!(f.root.load_base("r1", &map).is_err());
    assert!(f.root.load_base("../r1", &map).is_err());
}
#[test]
fn exclusive_pool_lease_lives_as_long_as_prepared_tree() {
    let f = Fixture::new();
    let b = f.base();
    assert!(PrivateRoot::open(&f.pool).is_err());
    let Fixture {
        _temp, root, pool, ..
    } = f;
    drop(root);
    assert!(PrivateRoot::open(&pool).is_err());
    drop(b);
    assert!(PrivateRoot::open(&pool).is_ok());
    drop(_temp);
}
#[test]
fn restrictive_umask_creates_expected_modes() {
    if std::env::var_os("ULI_TEST_CHILD_UMASK").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "restrictive_umask_creates_expected_modes"])
            .env("ULI_TEST_CHILD_UMASK", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let f = Fixture::new();
    let _b = f.base();
    assert_eq!(
        fs::metadata(f.pool.join("r1"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(f.pool.join("r1/same/file.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}
