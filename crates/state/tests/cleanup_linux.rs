#![cfg(target_os = "linux")]
//! Mandatory cleanup tests for Phase 1 acceptance (R09).
//!
//! These prove the only safe parts of "upload -> verify -> register release":
//! abandoned uploads are reclaimed, active/resumable/released work is protected,
//! orphans are reconciled, and an agent stop mid-cleanup resumes safely.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};
use uliup_protocol::{Command, Request};
use uliup_state::*;
use rusqlite::params;

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
    /// The real (random) upload id for a `begin` request label.
    fn find(&self, label: &str) -> String {
        rusqlite::Connection::open(self.state.join("state.sqlite"))
            .unwrap()
            .query_row(
                "SELECT u.upload_id FROM requests r JOIN uploads u ON r.upload_id=u.upload_id WHERE r.request_id=?1",
                [label],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
    }
    fn path(&self, label: &str) -> PathBuf {
        self.state.join("uploads").join(self.find(label))
    }
    fn artpath(&self, label: &str) -> PathBuf {
        self.state.join("artifacts").join(format!("{}.uli4", self.find(label)))
    }
    fn hash(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }
}

/// Seal a full upload (RECEIVING -> SEALED) with its exact bytes as artifact.
/// The human-readable `id` is only the request label; the real upload id is the
/// random hex value begin_upload returns, and finalize must use that.
fn seal(s: &mut Store, _f: &Fixture, id: &str, data: &[u8]) -> Upload {
    let u = s.begin_upload(&begin(id, data), UploadLimits::default()).unwrap();
    s.append_upload(&u.upload_id, 0, data).unwrap();
    s.finalize_upload(&finish(&u.upload_id)).unwrap()
}

/// Age an upload record past TTL by rewriting created_ms directly in the DB.
fn age_store(db: &rusqlite::Connection, label: &str, created_ms: i64) {
    let id = db
        .query_row(
            "SELECT u.upload_id FROM requests r JOIN uploads u ON r.upload_id=u.upload_id WHERE r.request_id=?1",
            [label],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    db.execute("UPDATE uploads SET created_ms=?1 WHERE upload_id=?2", params![created_ms, id])
        .unwrap();
}

#[test]
fn rejected_upload_is_cleansed_but_row_and_events_are_kept() {
    let f = Fixture::new();
    let mut s = f.store();
    let u = s
        .begin_upload(&begin("bad", b"good payload"), UploadLimits::default())
        .unwrap();
    // Wrong bytes -> finalize rejects. Ingress exists, artifact does not.
    s.append_upload(&u.upload_id, 0, b"evil bytes!!").unwrap();
    let rejected = s.finalize_upload(&finish(&u.upload_id)).unwrap();
    assert_eq!(rejected.state, UploadState::Rejected);
    assert!(f.path("bad").exists());

    let count_before = s.events(0, 100).unwrap().len();
    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 1);

    // Ingress removed; the durable upload row and events survive (FK safety).
    assert!(!f.path("bad").exists());
    let rows = rusqlite::Connection::open(f.state.join("state.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM uploads", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert_eq!(rows, 1, "cleanup must never delete upload rows");
    let events = rusqlite::Connection::open(f.state.join("state.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert!(events >= count_before as i64, "events are preserved by cleanup");
}

#[test]
fn active_receiving_upload_is_never_removed_even_when_old() {
    let f = Fixture::new();
    let mut s = f.store();
    let u = s
        .begin_upload(&begin("keep", b"still uploading"), UploadLimits::default())
        .unwrap();
    s.append_upload(&u.upload_id, 0, b"part").unwrap();
    // Model a stalled receiver: created long ago, still RECEIVING.
    age_store(
        &rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap(),
        "keep",
        1,
    );

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 0, "RECEIVING is protected");
    assert!(f.path("keep").exists());
    assert_eq!(report.cleaned[0].kind, CleanupKind::Keep);
}

#[test]
fn active_sealing_upload_is_never_removed() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"sealing bytes";
    let u = s
        .begin_upload(&begin("seal", data), UploadLimits::default())
        .unwrap();
    s.append_upload(&u.upload_id, 0, data).unwrap();
    // Move into SEALING without completing the artifact rename.
    age_store(
        &rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap(),
        "seal",
        1,
    );
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.execute(
        "UPDATE uploads SET state='SEALING' WHERE upload_id=?1",
        [u.upload_id.as_str()],
    )
    .unwrap();
    drop(db);

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 0, "SEALING is protected");
    assert!(f.path("seal").exists());
}

#[test]
fn sealed_upload_within_ttl_is_retained() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"fresh sealed payload";
    seal(&mut s, &f, "fresh", data);
    // created_ms is recent (just now), so within TTL.

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 0, "within-TTL sealed upload is kept");
    assert!(f.artpath("fresh").exists());
    assert!(f.path("fresh").exists());
}

#[test]
fn abandoned_sealed_upload_past_ttl_is_reclaimed() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"abandoned sealed payload";
    seal(&mut s, &f, "old", data);
    // Old bytes, not published anywhere: abandoned after TTL.
    age_store(
        &rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap(),
        "old",
        1,
    );

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 1);
    assert!(!f.path("old").exists());
    assert!(!f.artpath("old").exists());
    // Row preserved; bytes not a release, so no release integrity harmed.
    let rows = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    assert_eq!(
        rows.query_row("SELECT COUNT(*) FROM uploads", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn published_sealed_artifact_is_protected_past_ttl() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"published sealed payload";
    seal(&mut s, &f, "pub", data);
    let hash = Fixture::hash(data);

    // Register the bytes as a release (VERIFIED). The artifact bytes match it.
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.execute(
        "INSERT INTO releases VALUES('r1','1.0',1,?1,'signer','digest','{}','VERIFIED',999999)",
        params![hash],
    )
    .unwrap();
    age_store(&db, "pub", 1);
    drop(db);

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 0, "released bytes must never be reclaimed");
    assert!(f.artpath("pub").exists());
    assert!(f.path("pub").exists());
    assert_eq!(report.cleaned[0].kind, CleanupKind::Keep);
}

#[test]
fn second_cleanup_run_is_idempotent_and_leaves_no_orphans() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"second run payload";
    seal(&mut s, &f, "again", data);
    age_store(
        &rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap(),
        "again",
        1,
    );

    let first = s.cleanup_abandoned().unwrap();
    assert_eq!(first.succeeded, 1);
    assert!(!f.path("again").exists());
    assert!(!f.artpath("again").exists());

    // A second run reports nothing to do and does not error.
    let second = s.cleanup_abandoned().unwrap();
    assert_eq!(second.succeeded, 0);
    assert_eq!(second.attempted, 0);
    assert!(!second.failed);
    // No stray orphans remain in either directory.
    assert_eq!(fs::read_dir(f.state.join("uploads")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(f.state.join("artifacts")).unwrap().count(), 0);
}

#[test]
fn orphan_file_without_record_is_removed() {
    let f = Fixture::new();
    let mut s = f.store();
    // Simulate a crash that left an ingress file with no DB record.
    let uploads = f.state.join("uploads");
    fs::create_dir(&uploads).unwrap();
    fs::set_permissions(&uploads, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(uploads.join("stray"), b"orphan ingress").unwrap();
    // A stray artifact too.
    let artifacts = f.state.join("artifacts");
    fs::create_dir(&artifacts).unwrap();
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(artifacts.join("stray.uli4"), b"orphan artifact").unwrap();

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.cleaned.len(), 0, "no DB records to classify");
    // Both stray files have no record and no held lock -> removed.
    assert!(!uploads.join("stray").exists());
    assert!(!artifacts.join("stray.uli4").exists());
    let removed = report
        .orphan_outcomes
        .iter()
        .filter(|o| matches!(o, OrphanOutcome::Removed))
        .count();
    assert_eq!(removed, 2, "both orphans removed");
}

#[test]
fn orphan_with_active_lock_is_retained_not_deleted() {
    let f = Fixture::new();
    let mut s = f.store();
    let uploads = f.state.join("uploads");
    fs::create_dir(&uploads).unwrap();
    fs::set_permissions(&uploads, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(uploads.join("busy"), b"being written").unwrap();

    // Hold an exclusive flock on the file from this process: cleanup must not
    // be able to take its lock, so it retains the file.
    let holder = OpenOptions::new()
        .read(true)
        .write(true)
        .open(uploads.join("busy"))
        .unwrap();
    rustix::fs::flock(&holder, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .unwrap();

    let report = s.cleanup_abandoned().unwrap();
    assert!(
        uploads.join("busy").exists(),
        "a held lock must protect the orphan from deletion"
    );
    let has_retained = report
        .orphan_outcomes
        .iter()
        .any(|o| matches!(o, OrphanOutcome::Retained));
    assert!(has_retained, "expected a RETAINED outcome for the locked orphan");
}

#[test]
fn migration_003_applies_to_a_v2_store_on_open() {
    let f = Fixture::new();
    // Seed a v2 database (uploads) with an instance but NO cleanup tables.
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.execute_batch(include_str!("../migrations/001_init.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/002_uploads.sql"))
        .unwrap();
    db.execute(
        "INSERT INTO instances(singleton,instance_id,app_id,profile_id) VALUES(1,'one','demo','static-files')",
        [],
    )
    .unwrap();
    // Store::open requires the sqlite file to be exactly 0600; seed it that way.
    fs::set_permissions(f.state.join("state.sqlite"), fs::Permissions::from_mode(0o600))
        .unwrap();
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, 2, "precondition: seed at v2");
    let has_cleanup: bool = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cleanup'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        != 0;
    assert!(!has_cleanup, "precondition: no cleanup table yet");
    drop(db);

    // Opening the store must run migration 003 and create the cleanup tables.
    let mut s = f.store();
    // A successful cleanup proves the cleanup tables now exist and are usable.
    let report = s.cleanup_abandoned().unwrap();
    assert!(!report.failed, "cleanup tables usable after migration");
    let version: i64 = rusqlite::Connection::open(f.state.join("state.sqlite"))
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3, "store advanced to v3");
    let has_cleanup: bool = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cleanup'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        != 0;
    assert!(has_cleanup, "cleanup table created by migration 003");
}

#[test]
fn interrupt_during_cleanup_resumes_without_repeating_removal() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"interrupted payload";
    seal(&mut s, &f, "int", data);
    age_store(
        &rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap(),
        "int",
        1,
    );

    // First run reclaims the uploads/artifact and commits durable ledger rows.
    let first = s.cleanup_abandoned().unwrap();
    assert_eq!(first.succeeded, 1);

    // Simulate an agent stop mid-cleanup: open a fresh store (new connection) and
    // ensure the ledger is honored, no error, and nothing double-removed.
    let mut s = f.store();
    let second = s.cleanup_abandoned().unwrap();
    assert!(!second.failed, "resume must not report failure");
    assert_eq!(second.succeeded, 0, "completed reclaim is not repeated");
    assert_eq!(second.attempted, 0);
    assert!(!f.path("int").exists());
    assert!(!f.artpath("int").exists());
}

#[test]
fn cleanup_never_removes_a_registered_active_release_even_after_seal_abandoned() {
    let f = Fixture::new();
    let mut s = f.store();
    let data = b"active release payload";
    seal(&mut s, &f, "act", data);
    let hash = Fixture::hash(data);

    // Register as release and mark it ACTIVE + committed via the instance row.
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.execute(
        "INSERT INTO releases VALUES('ra','2.0',2,?1,'signer','digest','{}','ACTIVE',999999)",
        params![hash],
    )
    .unwrap();
    db.execute(
        "UPDATE instances SET active_release_id='ra', committed_sequence=2 WHERE singleton=1",
        [],
    )
    .unwrap();
    age_store(&db, "act", 1);
    drop(db);

    let report = s.cleanup_abandoned().unwrap();
    assert_eq!(report.succeeded, 0, "active release bytes are protected");
    assert!(f.artpath("act").exists());
    assert!(f.path("act").exists());
}
