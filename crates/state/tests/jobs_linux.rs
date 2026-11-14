#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{Arc, Barrier},
};
use uli4::*;
use uliup_protocol::{Command, Request};
use uliup_state::*;
struct Fixture {
    _temp: tempfile::TempDir,
    state: PathBuf,
    source: PathBuf,
    key: SigningKey,
}
fn instance() -> Instance {
    Instance {
        instance_id: "instance-1".into(),
        app_id: "sample".into(),
        profile_id: "static-files".into(),
    }
}
fn request(id: &str, release: &str) -> Request {
    Request {
        protocol_major: 1,
        request_id: id.into(),
        expected_instance_id: "instance-1".into(),
        command: Command::StartDeploy {
            release_id: release.into(),
        },
    }
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state");
        let source = t.path().join("source");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("index.html"), b"sample").unwrap();
        Self {
            _temp: t,
            state,
            source,
            key: SigningKey::from_bytes(&[41; 32]),
        }
    }
    fn store(&self) -> Store {
        Store::open(&self.state, instance()).unwrap()
    }
    fn artifact(&self, id: &str, seq: u64, version: &str) -> (VerifiedPackage, String) {
        let path = self._temp.path().join(format!("{id}.uli4"));
        pack(
            &self.source,
            &path,
            PackageOptions {
                app_id: "sample".into(),
                release_id: id.into(),
                release_sequence: seq,
                display_version: version.into(),
                target_os: "linux".into(),
                target_arch: "x86_64".into(),
                target_runtime: "static".into(),
                profile: "static-files".into(),
                health_policy: "files".into(),
            },
            &self.key,
            None,
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
        let package = verify(&path, &trust, None, &Limits::default()).unwrap();
        (
            package,
            hex::encode(Sha256::digest(fs::read(path).unwrap())),
        )
    }
    fn register(&self, s: &mut Store, id: &str, seq: u64, version: &str) {
        let (p, h) = self.artifact(id, seq, version);
        s.register_verified(&p, &h).unwrap();
    }
}
fn health_phase(s: &mut Store, id: &str) {
    for (a, b) in [
        (Phase::Verified, Phase::Prepared),
        (Phase::Prepared, Phase::StoppingProject),
        (Phase::StoppingProject, Phase::AgentReady),
        (Phase::AgentReady, Phase::MaterializingProject),
        (Phase::MaterializingProject, Phase::StartingProject),
        (Phase::StartingProject, Phase::HealthChecking),
    ] {
        s.advance(id, a, b).unwrap();
    }
}
#[test]
fn persists_phase_and_idempotent_request_across_restart() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "r1", 1, "1.0.0");
    let r = request("req-1", "r1");
    let j = s.start_deploy(&r).unwrap();
    s.advance(&j.job_id, Phase::Verified, Phase::Prepared)
        .unwrap();
    let events = s.events(0, 100).unwrap();
    drop(s);
    let mut s = f.store();
    let pending = s.pending_job().unwrap().unwrap();
    assert_eq!(pending.phase, Phase::Prepared);
    assert_eq!(s.start_deploy(&r).unwrap(), pending);
    assert_eq!(s.events(0, 100).unwrap().len(), events.len());
    let last = events.last().unwrap().event_id;
    assert!(s.events(last, 100).unwrap().is_empty());
    assert!(events.windows(2).all(|e| e[0].event_id < e[1].event_id));
}
#[test]
fn conflicting_request_busy_and_wrong_instance_do_not_create_jobs() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "r1", 1, "1.0.0");
    f.register(&mut s, "r2", 2, "2.0.0");
    let j = s.start_deploy(&request("same", "r1")).unwrap();
    let count = s.events(0, 100).unwrap().len();
    assert!(s.start_deploy(&request("same", "r2")).is_err());
    assert!(s.start_deploy(&request("other", "r2")).is_err());
    let mut wrong = request("new", "r2");
    wrong.expected_instance_id = "other-instance".into();
    assert!(s.start_deploy(&wrong).is_err());
    assert_eq!(s.events(0, 100).unwrap().len(), count);
    assert_eq!(s.pending_job().unwrap().unwrap().job_id, j.job_id);
}
#[test]
fn profile_transitions_and_success_are_explicit() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "r1", 1, "1.0.0");
    let j = s.start_deploy(&request("req", "r1")).unwrap();
    assert!(
        s.advance(&j.job_id, Phase::Verified, Phase::Building)
            .is_err()
    );
    assert!(s.commit_healthy(&j.job_id).is_err());
    health_phase(&mut s, &j.job_id);
    let committed = s.commit_healthy(&j.job_id).unwrap();
    assert!(!committed.terminal);
    assert_eq!(s.active_release().unwrap().as_deref(), Some("r1"));
    assert!(s.finish_cleanup(&j.job_id).unwrap().terminal);
    assert!(s.pending_job().unwrap().is_none());
    let (p, h) = f.artifact("r2", 2, "1.0.0");
    assert!(s.register_verified(&p, &h).is_err());
}
#[test]
fn failed_version_accepts_corrected_new_identity_and_rejects_replay() {
    let f = Fixture::new();
    let mut s = f.store();
    let (p, h) = f.artifact("r1", 1, "1.0.0");
    s.register_verified(&p, &h).unwrap();
    let count = s.events(0, 100).unwrap().len();
    s.register_verified(&p, &h).unwrap();
    assert_eq!(s.events(0, 100).unwrap().len(), count);
    assert!(s.register_verified(&p, &"0".repeat(64)).is_err());
    let r = request("req", "r1");
    let j = s.start_deploy(&r).unwrap();
    let failed = s
        .fail(&j.job_id, Phase::Verified, FailureCode::MaterializeFailed)
        .unwrap();
    assert!(failed.terminal);
    assert_eq!(failed.phase, Phase::Failed);
    assert_eq!(s.start_deploy(&r).unwrap(), failed);
    f.register(&mut s, "r2", 2, "1.0.0");
    assert!(s.start_deploy(&request("corrected", "r2")).is_ok());
    let (p, h) = f.artifact("old", 1, "3.0.0");
    assert!(s.register_verified(&p, &h).is_err());
}
#[test]
fn recovery_failure_is_durable_and_blocks_new_deployments() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "r1", 1, "1.0.0");
    let j = s.start_deploy(&request("req", "r1")).unwrap();
    s.advance(&j.job_id, Phase::Verified, Phase::Prepared)
        .unwrap();
    s.advance(&j.job_id, Phase::Prepared, Phase::StoppingProject)
        .unwrap();
    assert_eq!(
        s.fail(
            &j.job_id,
            Phase::StoppingProject,
            FailureCode::StorageUnavailable
        )
        .unwrap()
        .phase,
        Phase::Recovering
    );
    drop(s);
    let mut s = f.store();
    assert_eq!(s.pending_job().unwrap().unwrap().phase, Phase::Recovering);
    let failed = s.record_rollback(&j.job_id, false).unwrap();
    assert_eq!(failed.phase, Phase::FailedRecovery);
    assert!(failed.terminal);
    f.register(&mut s, "r2", 2, "1.0.0");
    assert!(s.start_deploy(&request("req2", "r2")).is_err());
    assert_eq!(
        s.job(&j.job_id).unwrap().unwrap().error_code.as_deref(),
        Some("RECOVERY_FAILED")
    );
}
#[test]
fn rollback_success_preserves_previous_active_and_accepts_corrected_package() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "r1", 1, "1.0.0");
    let one = s.start_deploy(&request("one", "r1")).unwrap();
    health_phase(&mut s, &one.job_id);
    s.commit_healthy(&one.job_id).unwrap();
    s.finish_cleanup(&one.job_id).unwrap();
    f.register(&mut s, "r2", 2, "2.0.0");
    let two = s.start_deploy(&request("two", "r2")).unwrap();
    assert_eq!(two.previous_release_id.as_deref(), Some("r1"));
    s.advance(&two.job_id, Phase::Verified, Phase::Prepared)
        .unwrap();
    s.advance(&two.job_id, Phase::Prepared, Phase::StoppingProject)
        .unwrap();
    s.fail(
        &two.job_id,
        Phase::StoppingProject,
        FailureCode::HealthFailed,
    )
    .unwrap();
    s.record_rollback(&two.job_id, true).unwrap();
    // Metadata assertion only: the executor must separately verify actual rollback.
    assert_eq!(s.active_release().unwrap().as_deref(), Some("r1"));
    f.register(&mut s, "r3", 3, "2.0.0");
    assert!(s.start_deploy(&request("three", "r3")).is_ok());
}
#[test]
fn staged_older_release_cannot_be_used_as_a_downgrade() {
    let f = Fixture::new();
    let mut s = f.store();
    f.register(&mut s, "old", 1, "1.0.0");
    f.register(&mut s, "new", 2, "2.0.0");
    let j = s.start_deploy(&request("new-request", "new")).unwrap();
    health_phase(&mut s, &j.job_id);
    s.commit_healthy(&j.job_id).unwrap();
    s.finish_cleanup(&j.job_id).unwrap();
    assert!(s.start_deploy(&request("old-request", "old")).is_err());
}
#[test]
fn concurrent_requests_get_one_job_without_duplicate_events() {
    for same in [false, true] {
        let f = Fixture::new();
        let mut s = f.store();
        f.register(&mut s, "r1", 1, "1.0.0");
        f.register(&mut s, "r2", 2, "2.0.0");
        let other = f.store();
        let barrier = Arc::new(Barrier::new(2));
        let b = barrier.clone();
        let a = std::thread::spawn(move || {
            b.wait();
            s.start_deploy(&request("a", "r1"))
        });
        let b = std::thread::spawn(move || {
            barrier.wait();
            let mut other = other;
            other.start_deploy(&request(
                if same { "a" } else { "b" },
                if same { "r1" } else { "r2" },
            ))
        });
        let a = a.join().unwrap();
        let b = b.join().unwrap();
        if same {
            assert_eq!(a.unwrap().job_id, b.unwrap().job_id);
        } else {
            assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        }
        let s = f.store();
        assert_eq!(
            s.events(0, 100)
                .unwrap()
                .iter()
                .filter(|e| e.code == "JOB_STARTED")
                .count(),
            1
        );
    }
}
#[test]
fn storage_symlinks_instance_mismatch_and_future_schema_are_rejected() {
    let f = Fixture::new();
    let s = f.store();
    drop(s);
    let mut wrong = instance();
    wrong.app_id = "other".into();
    assert!(Store::open(&f.state, wrong).is_err());
    let alias = f._temp.path().join("alias");
    symlink(&f.state, &alias).unwrap();
    assert!(Store::open(&alias, instance()).is_err());
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    db.pragma_update(None, "user_version", 999).unwrap();
    drop(db);
    assert!(Store::open(&f.state, instance()).is_err());
    let g = Fixture::new();
    let external = g._temp.path().join("external");
    fs::write(&external, b"keep").unwrap();
    symlink(&external, g.state.join("state.sqlite")).unwrap();
    assert!(Store::open(&g.state, instance()).is_err());
    assert_eq!(fs::read(external).unwrap(), b"keep");
}
