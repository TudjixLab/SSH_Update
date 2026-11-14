#![cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Child, Command},
    time::{Duration, Instant},
};
use uli_ups::journal::{Failure, Journal, RecoveryDecision, Step, inspect};
use uliup_state::{Job, Phase};
struct Fixture {
    temp: tempfile::TempDir,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        Self { temp, state }
    }
    #[track_caller]
    fn journal(&self) -> Journal {
        // Parallel subprocess tests can briefly inherit an OFD lease before exec
        // closes CLOEXEC descriptors. BUSY remains a valid production result.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match Journal::open(&self.state, "instance") {
                Ok(journal) => return journal,
                Err(uli_ups::Error("EXEC_EXECUTOR_BUSY")) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("journal open failed: {error}"),
            }
        }
    }
    fn path(&self) -> PathBuf {
        self.state.join("execution/job.json")
    }
}
fn job(previous: bool) -> Job {
    Job {
        job_id: "job".into(),
        release_id: "new".into(),
        previous_release_id: previous.then(|| "old".into()),
        phase: Phase::Prepared,
        terminal: false,
        error_code: None,
    }
}
fn advance(j: &mut Journal, from: Step, to: Step) -> uli_ups::journal::Record {
    let r = j.get("job").unwrap().unwrap();
    j.advance("job", r.generation, from, to, None).unwrap()
}
#[test]
fn persists_binding_generation_and_intent_without_guessing_completion() {
    let f = Fixture::new();
    let mut j = f.journal();
    let initial = j.begin(&job(true), &"a".repeat(64)).unwrap();
    assert_eq!(initial.recovery_decision(), RecoveryDecision::NotStarted);
    let stop = advance(&mut j, Step::Prepared, Step::StopIntent);
    drop(j);
    let j = f.journal();
    assert_eq!(j.get("job").unwrap().unwrap(), stop);
    assert_eq!(
        stop.recovery_decision(),
        RecoveryDecision::ReconcileExternalState
    );
    assert_eq!(inspect(&f.state, "instance", "job").unwrap().unwrap(), stop);
    assert_eq!(stop.generation, 1);
}
#[test]
fn immutable_binding_and_generation_cas_reject_stale_or_different_actions() {
    let f = Fixture::new();
    let mut j = f.journal();
    let r = j.begin(&job(true), &"b".repeat(64)).unwrap();
    assert_eq!(j.begin(&job(true), &"b".repeat(64)).unwrap(), r);
    assert!(j.begin(&job(true), &"c".repeat(64)).is_err());
    let mut other = job(true);
    other.release_id = "different".into();
    assert!(j.begin(&other, &"b".repeat(64)).is_err());
    assert!(
        j.advance("job", 0, Step::Prepared, Step::Healthy, None)
            .is_err()
    );
    advance(&mut j, Step::Prepared, Step::StopIntent);
    assert!(
        j.advance("job", 0, Step::Prepared, Step::StopIntent, None)
            .is_err()
    );
    assert!(
        j.advance("job", 1, Step::StopIntent, Step::RecoveryIntent, None)
            .is_err()
    );
    assert_eq!(j.get("job").unwrap().unwrap().generation, 1);
}
#[test]
fn complete_build_order_and_rollback_require_separate_confirmation_steps() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.begin(&job(true), &"a".repeat(64)).unwrap();
    let sequence = [
        Step::Prepared,
        Step::StopIntent,
        Step::Stopped,
        Step::AgentReady,
        Step::RuntimeIntent,
        Step::RuntimeReady,
        Step::InstallIntent,
        Step::Installed,
        Step::BuildIntent,
        Step::Built,
        Step::ActivateIntent,
        Step::Activated,
        Step::StartIntent,
        Step::Started,
        Step::HealthIntent,
    ];
    for pair in sequence.windows(2) {
        advance(&mut j, pair[0], pair[1]);
    }
    let r = j.get("job").unwrap().unwrap();
    let r = j
        .advance(
            "job",
            r.generation,
            r.step,
            Step::RecoveryIntent,
            Some(Failure::HealthFailed),
        )
        .unwrap();
    assert_eq!(r.failure, Some(Failure::HealthFailed));
    assert!(
        j.advance("job", r.generation, r.step, Step::RolledBack, None)
            .is_err()
    );
    for pair in [
        Step::RecoveryIntent,
        Step::PreviousSelectionIntent,
        Step::PreviousSelectionRestored,
        Step::PreviousStartIntent,
        Step::PreviousStarted,
        Step::PreviousHealthIntent,
        Step::PreviousHealthy,
        Step::RolledBack,
    ]
    .windows(2)
    {
        advance(&mut j, pair[0], pair[1]);
    }
    let r = j.get("job").unwrap().unwrap();
    assert_eq!(r.recovery_decision(), RecoveryDecision::VerifyRestoredState);
    assert!(
        j.advance("job", r.generation, r.step, Step::StopIntent, None)
            .is_err()
    );
}
#[test]
fn first_install_never_claims_restoration_of_nonexistent_previous_release() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.begin(&job(false), &"a".repeat(64)).unwrap();
    advance(&mut j, Step::Prepared, Step::StopIntent);
    j.advance(
        "job",
        1,
        Step::StopIntent,
        Step::RecoveryIntent,
        Some(Failure::Interrupted),
    )
    .unwrap();
    assert!(
        j.advance(
            "job",
            2,
            Step::RecoveryIntent,
            Step::PreviousSelectionIntent,
            None
        )
        .is_err()
    );
    let r = j
        .advance(
            "job",
            2,
            Step::RecoveryIntent,
            Step::NeedsOperator,
            Some(Failure::StateMismatch),
        )
        .unwrap();
    assert_eq!(r.recovery_decision(), RecoveryDecision::OperatorRequired);
}
#[test]
fn one_executor_lease_survives_independent_read_inspection() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.begin(&job(true), &"a".repeat(64)).unwrap();
    assert!(Journal::open(&f.state, "instance").is_err());
    assert!(inspect(&f.state, "instance", "job").unwrap().is_some());
    assert!(inspect(&f.state, "different-instance", "job").is_err());
    drop(j);
    f.journal();
}
#[test]
fn damaged_future_unknown_and_duplicate_records_do_not_reset() {
    let f = Fixture::new();
    let mut j = f.journal();
    let r = j.begin(&job(true), &"a".repeat(64)).unwrap();
    drop(j);
    let valid = serde_json::to_vec(&r).unwrap();
    for bad in [
        b"{".to_vec(),
        {
            let mut v = serde_json::to_value(&r).unwrap();
            v["schema_version"] = 2.into();
            serde_json::to_vec(&v).unwrap()
        },
        {
            let mut v = serde_json::to_value(&r).unwrap();
            v["shell"] = "secret".into();
            serde_json::to_vec(&v).unwrap()
        },
        {
            let mut v = serde_json::to_value(&r).unwrap();
            v["generation"] = 9.into();
            serde_json::to_vec(&v).unwrap()
        },
        {
            let s = String::from_utf8(valid.clone()).unwrap();
            s.replacen("{", "{\"schema_version\":1,", 1).into_bytes()
        },
    ] {
        fs::write(f.path(), &bad).unwrap();
        let mut j = f.journal();
        assert!(j.get("job").is_err());
        assert!(j.begin(&job(true), &"a".repeat(64)).is_err());
        assert_eq!(fs::read(f.path()).unwrap(), bad);
        drop(j);
    }
    fs::write(f.path(), &valid).unwrap();
    assert_eq!(f.journal().get("job").unwrap().unwrap(), r);
}
#[test]
fn journal_paths_reject_links_modes_and_traversal() {
    for kind in 0..3 {
        let f = Fixture::new();
        let mut j = f.journal();
        j.begin(&job(true), &"a".repeat(64)).unwrap();
        drop(j);
        let other = f.temp.path().join("outside");
        fs::write(&other, b"preserve").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
        match kind {
            0 => {
                fs::remove_file(f.path()).unwrap();
                symlink(&other, f.path()).unwrap();
            }
            1 => {
                fs::remove_file(f.path()).unwrap();
                fs::hard_link(&other, f.path()).unwrap();
            }
            _ => fs::set_permissions(f.path(), fs::Permissions::from_mode(0o644)).unwrap(),
        }
        let j = f.journal();
        assert!(j.get("job").is_err());
        assert!(j.get("../outside").is_err());
        assert_eq!(fs::read(other).unwrap(), b"preserve");
    }
}
#[test]
fn abandoned_temporary_files_are_not_adopted_as_generations() {
    let f = Fixture::new();
    let mut j = f.journal();
    let r = j.begin(&job(true), &"a".repeat(64)).unwrap();
    drop(j);
    fs::write(
        f.state.join("execution/.write-job-orphan"),
        b"partial corrupt bytes",
    )
    .unwrap();
    assert_eq!(f.journal().get("job").unwrap().unwrap(), r);
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "subprocess fixture used only by the SIGKILL test"]
fn journal_process_probe_child() {
    let state = PathBuf::from(std::env::var_os("ULIUPS_JOURNAL_CHILD_STATE").unwrap());
    let mut j = Journal::open(&state, "instance").unwrap();
    j.begin(&job(true), &"a".repeat(64)).unwrap();
    advance(&mut j, Step::Prepared, Step::StopIntent);
    fs::write(state.join("child.ready"), b"intent durable").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}
#[test]
fn process_kill_after_durable_intent_releases_lease_and_keeps_uncertain_action() {
    use std::os::unix::process::ExitStatusExt;
    let f = Fixture::new();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "journal_process_probe_child"])
        .env("ULIUPS_JOURNAL_CHILD_STATE", &f.state)
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let start = Instant::now();
    while !f.state.join("child.ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "probe exited before intent"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    let record = f.journal().get("job").unwrap().unwrap();
    assert_eq!(record.step, Step::StopIntent);
    assert_eq!(record.generation, 1);
    assert_eq!(
        record.recovery_decision(),
        RecoveryDecision::ReconcileExternalState
    );
}
