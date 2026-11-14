#![cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::{Arc, Barrier},
};
use uliup_protocol::{Command, Request};
use uliup_state::*;
fn instance() -> Instance {
    Instance {
        instance_id: "one".into(),
        app_id: "demo".into(),
        profile_id: "static-files".into(),
    }
}
fn req(id: &str, command: Command) -> Request {
    Request {
        protocol_major: 1,
        request_id: id.into(),
        expected_instance_id: "one".into(),
        command,
    }
}
fn begin(id: &str, data: &[u8]) -> Request {
    req(
        id,
        Command::BeginUpload {
            app_id: "demo".into(),
            size: data.len() as u64,
            package_sha256: hex::encode(Sha256::digest(data)),
        },
    )
}
fn resume(id: &str) -> Request {
    req(
        "resume",
        Command::ResumeUpload {
            upload_id: id.into(),
        },
    )
}
fn finish(id: &str) -> Request {
    req(
        "finish",
        Command::FinalizeUpload {
            upload_id: id.into(),
        },
    )
}
struct Fixture {
    _temp: tempfile::TempDir,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        Self { _temp: t, state }
    }
    fn store(&self) -> Store {
        Store::open(&self.state, instance()).unwrap()
    }
    fn input(&self, id: &str) -> PathBuf {
        self.state.join("uploads").join(id)
    }
    fn artifact(&self, id: &str) -> PathBuf {
        self.state.join("artifacts").join(format!("{id}.uli4"))
    }
}
#[test]
fn durable_offset_resume_discards_only_uncommitted_tail_and_seals_new_inode() {
    let f = Fixture::new();
    let data = b"persistent package";
    let r = begin("begin", data);
    let mut s = f.store();
    let u = s.begin_upload(&r, UploadLimits::default()).unwrap();
    s.append_upload(&u.upload_id, 0, &data[..5]).unwrap();
    // Model a process stopping after write, before offset commit. No reboot is claimed.
    OpenOptions::new()
        .append(true)
        .open(f.input(&u.upload_id))
        .unwrap()
        .write_all(b"uncommitted")
        .unwrap();
    drop(s);
    let mut s = f.store();
    let resumed = s.resume_upload(&resume(&u.upload_id)).unwrap();
    assert_eq!(resumed.committed_offset, 5);
    assert_eq!(fs::metadata(f.input(&u.upload_id)).unwrap().len(), 5);
    s.append_upload(&u.upload_id, 5, &data[5..]).unwrap();
    let sealed = s.finalize_upload(&finish(&u.upload_id)).unwrap();
    assert_eq!(sealed.state, UploadState::Sealed);
    assert_ne!(
        fs::metadata(f.input(&u.upload_id)).unwrap().ino(),
        fs::metadata(f.artifact(&u.upload_id)).unwrap().ino()
    );
    let mut file = s.open_sealed_upload(&u.upload_id).unwrap();
    assert!(file.write_all(b"x").is_err());
    let mut output = Vec::new();
    file.read_to_end(&mut output).unwrap();
    assert_eq!(output, data);
    // A stale ingress writer cannot alter the separate finalized inode.
    fs::write(f.input(&u.upload_id), b"changed ingress").unwrap();
    assert_eq!(s.finalize_upload(&finish(&u.upload_id)).unwrap(), sealed);
    assert_eq!(s.begin_upload(&r, UploadLimits::default()).unwrap(), sealed);
    drop(s);
    let s = f.store();
    assert_eq!(fs::read(f.artifact(&u.upload_id)).unwrap(), data);
    s.open_sealed_upload(&u.upload_id).unwrap();
}
#[test]
fn offset_size_chunk_identity_and_shared_request_conflicts_are_rejected() {
    let f = Fixture::new();
    let mut s = f.store();
    let r = begin("same", b"abcd");
    let u = s.begin_upload(&r, UploadLimits::default()).unwrap();
    let count = s.events(0, 100).unwrap().len();
    assert!(
        s.begin_upload(&begin("same", b"abcde"), UploadLimits::default())
            .is_err()
    );
    assert!(
        s.start_deploy(&req(
            "same",
            Command::StartDeploy {
                release_id: "r1".into()
            }
        ))
        .is_err()
    );
    let mut wrong = begin("wrong", b"a");
    wrong.expected_instance_id = "other".into();
    assert!(s.begin_upload(&wrong, UploadLimits::default()).is_err());
    let mut wrong = begin("wrong", b"a");
    if let Command::BeginUpload { app_id, .. } = &mut wrong.command {
        *app_id = "other".into();
    }
    assert!(s.begin_upload(&wrong, UploadLimits::default()).is_err());
    assert!(s.append_upload("../bad", 0, b"a").is_err());
    assert!(s.append_upload(&u.upload_id, 1, b"a").is_err());
    assert!(s.append_upload(&u.upload_id, 0, b"abcde").is_err());
    assert!(s.append_upload(&u.upload_id, 0, b"").is_err());
    assert!(
        s.append_upload(&u.upload_id, 0, &vec![0; MAX_CHUNK_BYTES + 1])
            .is_err()
    );
    assert!(s.finalize_upload(&finish(&u.upload_id)).is_err());
    assert_eq!(s.events(0, 100).unwrap().len(), count);
    assert_eq!(
        s.resume_upload(&resume(&u.upload_id))
            .unwrap()
            .committed_offset,
        0
    );
}
#[test]
fn wrong_hash_is_durably_rejected_and_exact_retry_has_no_new_event() {
    let f = Fixture::new();
    let mut s = f.store();
    let u = s
        .begin_upload(&begin("begin", b"good"), UploadLimits::default())
        .unwrap();
    s.append_upload(&u.upload_id, 0, b"evil").unwrap();
    let r = finish(&u.upload_id);
    let rejected = s.finalize_upload(&r).unwrap();
    assert_eq!(rejected.state, UploadState::Rejected);
    assert_eq!(rejected.error_code.as_deref(), Some("UPLOAD_HASH_MISMATCH"));
    let n = s.events(0, 100).unwrap().len();
    drop(s);
    let mut s = f.store();
    assert_eq!(s.finalize_upload(&r).unwrap(), rejected);
    assert_eq!(s.events(0, 100).unwrap().len(), n);
    assert!(s.append_upload(&u.upload_id, 0, b"good").is_err());
    assert!(s.open_sealed_upload(&u.upload_id).is_err());
}
#[test]
fn quota_counts_both_copies_and_all_retained_uploads() {
    let f = Fixture::new();
    let mut s = f.store();
    let r = begin("one", b"ten bytes!");
    assert!(
        s.begin_upload(
            &r,
            UploadLimits {
                max_uploads: 1,
                max_reserved_bytes: 19
            }
        )
        .is_err()
    );
    assert!(!f.state.join("uploads").exists());
    let limits = UploadLimits {
        max_uploads: 1,
        max_reserved_bytes: 20,
    };
    let u = s.begin_upload(&r, limits).unwrap();
    assert!(s.begin_upload(&begin("two", b"x"), limits).is_err());
    assert_eq!(s.begin_upload(&r, limits).unwrap(), u);
}
#[test]
fn missing_durable_bytes_are_never_silently_reset() {
    let f = Fixture::new();
    let mut s = f.store();
    let u = s
        .begin_upload(&begin("begin", b"abcd"), UploadLimits::default())
        .unwrap();
    s.append_upload(&u.upload_id, 0, b"abc").unwrap();
    fs::write(f.input(&u.upload_id), b"a").unwrap();
    assert!(s.resume_upload(&resume(&u.upload_id)).is_err());
    assert!(s.append_upload(&u.upload_id, 3, b"d").is_err());
    assert!(s.finalize_upload(&finish(&u.upload_id)).is_err());
}
#[test]
fn pending_seal_retries_and_already_renamed_artifact_are_reconciled() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"sealed bytes";
    let u = s
        .begin_upload(&begin("begin", data), UploadLimits::default())
        .unwrap();
    s.append_upload(&u.upload_id, 0, data).unwrap();
    fs::create_dir(f.state.join("artifacts")).unwrap();
    fs::set_permissions(f.state.join("artifacts"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(f.artifact(&u.upload_id)).unwrap(); // Fails after durable SEALING intent.
    assert!(s.finalize_upload(&finish(&u.upload_id)).is_err());
    drop(s);
    let mut s = f.store();
    assert_eq!(
        s.resume_upload(&resume(&u.upload_id)).unwrap().state,
        UploadState::Sealing
    );
    assert!(s.append_upload(&u.upload_id, 0, b"x").is_err());
    fs::remove_dir(f.artifact(&u.upload_id)).unwrap();
    // Model sync+rename having succeeded before the last database commit.
    fs::copy(f.input(&u.upload_id), f.artifact(&u.upload_id)).unwrap();
    let sealed = s.finalize_upload(&finish(&u.upload_id)).unwrap();
    assert_eq!(sealed.state, UploadState::Sealed);
    s.open_sealed_upload(&u.upload_id).unwrap();
    fs::write(f.artifact(&u.upload_id), b"corruption").unwrap();
    assert!(s.open_sealed_upload(&u.upload_id).is_err());
}
#[test]
fn symlink_hardlink_fifo_and_world_readable_ingress_are_rejected() {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    for kind in 0..4 {
        let f = Fixture::new();
        let mut s = f.store();
        let u = s
            .begin_upload(&begin("begin", b"x"), UploadLimits::default())
            .unwrap();
        let p = f.input(&u.upload_id);
        if kind == 3 {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            fs::remove_file(&p).unwrap();
            let other = f._temp.path().join("other");
            fs::write(&other, b"secret").unwrap();
            fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
            match kind {
                0 => symlink(&other, &p).unwrap(),
                1 => fs::hard_link(&other, &p).unwrap(),
                _ => mknodat(CWD, &p, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap(),
            }
        }
        assert!(s.append_upload(&u.upload_id, 0, b"x").is_err());
    }
}
#[test]
fn concurrent_begin_and_offset_cas_do_not_duplicate_bytes_or_requests() {
    let f = Fixture::new();
    drop(f.store());
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let state = f.state.clone();
        let b = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut s = Store::open(&state, instance()).unwrap();
            b.wait();
            s.begin_upload(&begin("same", b"ab"), UploadLimits::default())
                .unwrap()
                .upload_id
        }));
    }
    let ids: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(ids[0], ids[1]);
    assert_eq!(fs::read_dir(f.state.join("uploads")).unwrap().count(), 1);
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let state = f.state.clone();
        let id = ids[0].clone();
        let b = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut s = Store::open(&state, instance()).unwrap();
            b.wait();
            s.append_upload(&id, 0, b"a").is_ok()
        }));
    }
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(fs::read(f.input(&ids[0])).unwrap(), b"a");
}
#[test]
fn v1_migration_preserves_jobs_and_shared_idempotency() {
    let f = Fixture::new();
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.execute_batch(include_str!("../migrations/001_init.sql"))
        .unwrap();
    db.execute("INSERT INTO instances(singleton,instance_id,app_id,profile_id) VALUES(1,'one','demo','static-files')",[]).unwrap();
    db.execute(
        "INSERT INTO releases VALUES('release','1',1,?1,?1,?1,'{}','VERIFIED',0)",
        ["0".repeat(64)],
    )
    .unwrap();
    db.execute(
        "INSERT INTO jobs VALUES('oldjob','release',NULL,'VERIFIED',0,NULL,0,0)",
        [],
    )
    .unwrap();
    let r = req(
        "old",
        Command::StartDeploy {
            release_id: "release".into(),
        },
    );
    let hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&serde_json::to_value(&r).unwrap()).unwrap(),
    ));
    db.execute("INSERT INTO requests VALUES('old',?1,'oldjob')", [hash])
        .unwrap();
    drop(db);
    fs::set_permissions(
        f.state.join("state.sqlite"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut s = f.store();
    assert_eq!(s.start_deploy(&r).unwrap().job_id, "oldjob");
    assert!(
        s.begin_upload(&begin("old", b"x"), UploadLimits::default())
            .is_err()
    );
    s.begin_upload(&begin("new", b"x"), UploadLimits::default())
        .unwrap();
}
#[test]
fn full_package_upload_seal_signature_verify_register_and_prepare() {
    use ed25519_dalek::SigningKey;
    use uli4::*;
    let f = Fixture::new();
    let source = f._temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("index.html"), b"release content").unwrap();
    let path = f._temp.path().join("release.uli4");
    let key = SigningKey::from_bytes(&[71; 32]);
    pack(
        &source,
        &path,
        PackageOptions {
            app_id: "demo".into(),
            release_id: "release-1".into(),
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
    let data = fs::read(path).unwrap();
    let mut s = f.store();
    let u = s
        .begin_upload(&begin("begin", &data), UploadLimits::default())
        .unwrap();
    for (i, chunk) in data.chunks(100).enumerate() {
        s.append_upload(&u.upload_id, (i * 100) as u64, chunk)
            .unwrap();
    }
    assert_eq!(
        s.finalize_upload(&finish(&u.upload_id)).unwrap().state,
        UploadState::Sealed
    );
    let trust = TrustedProject {
        key: key.verifying_key(),
        app_id: "demo".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "static".into(),
        allowed_profiles: vec!["static-files".into()],
        health_policies: vec!["files".into()],
        agent_version: (0, 1, 0),
        minimum_sequence: 1,
    };
    let mut p = verify_opened(
        s.open_sealed_upload(&u.upload_id).unwrap(),
        &trust,
        None,
        &Limits::default(),
    )
    .unwrap();
    s.register_verified(&p, &u.package_sha256).unwrap();
    let releases = f._temp.path().join("releases");
    fs::create_dir(&releases).unwrap();
    fs::set_permissions(&releases, fs::Permissions::from_mode(0o700)).unwrap();
    let pool = linux::PrivateRoot::open(&releases).unwrap();
    pool.prepare(&mut p, None).unwrap();
    assert_eq!(
        fs::read(releases.join("release-1/index.html")).unwrap(),
        b"release content"
    );
    assert_eq!(s.active_release().unwrap(), None); // Inactive source preparation is not deployment.
}

#[test]
fn resume_request_ids_share_the_global_mutation_ledger() {
    let f = Fixture::new();
    let mut s = f.store();
    let first = s
        .begin_upload(&begin("begin", b"abc"), UploadLimits::default())
        .unwrap();
    let second = s
        .begin_upload(&begin("begin-2", b"xyz"), UploadLimits::default())
        .unwrap();
    let reused = req(
        "begin",
        Command::ResumeUpload {
            upload_id: first.upload_id.clone(),
        },
    );
    assert!(s.resume_upload(&reused).is_err());
    let r = resume(&first.upload_id);
    assert_eq!(s.resume_upload(&r).unwrap().committed_offset, 0);
    s.append_upload(&first.upload_id, 0, b"a").unwrap();
    drop(s);
    let mut s = f.store();
    assert_eq!(s.resume_upload(&r).unwrap().committed_offset, 1);
    assert!(s.resume_upload(&resume(&second.upload_id)).is_err());
    assert!(
        s.start_deploy(&req(
            "resume",
            Command::StartDeploy {
                release_id: "r1".into()
            }
        ))
        .is_err()
    );
}
