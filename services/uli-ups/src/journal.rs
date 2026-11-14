//! Durable execution intents for the future Next.js executor.
//! Store remains authoritative for release/job state. This journal runs no command,
//! switches no release and never infers success from a previous completion record.
use crate::{Error, Result, config::directory, identifier, require};
use rustix::fs::{self as fs, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uliup_state::{Job, Phase};

const MAX_BYTES: usize = 64 * 1024;
const MAX_STEPS: usize = 128;
fn flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}
fn millis() -> Result<u64> {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("EXEC_CLOCK_INVALID"))?
        .as_millis();
    let n = u64::try_from(n).map_err(|_| Error("EXEC_CLOCK_INVALID"))?;
    require(n <= 9_007_199_254_740_991, "EXEC_CLOCK_INVALID")?;
    Ok(n)
}
fn sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_directory(parent: &File) -> Result<File> {
    let made = match fs::statat(parent, "execution", fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => false,
        Err(rustix::io::Errno::NOENT) => {
            match fs::mkdirat(parent, "execution", Mode::from_raw_mode(0o700)) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    let file: File = fs::openat2(
        parent,
        "execution",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        flags(),
    )?
    .into();
    if made {
        fs::fchmod(&file, Mode::from_raw_mode(0o700))?;
        file.sync_all()?;
        parent.sync_all()?;
    }
    check_directory(&file, parent)?;
    Ok(file)
}
fn check_directory(file: &File, parent: &File) -> Result<()> {
    let m = file.metadata()?;
    require(
        m.is_dir()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o700
            && m.dev() == parent.metadata()?.dev(),
        "EXEC_DIRECTORY_UNSAFE",
    )
}
fn safe_file(file: &File, parent: &File, unlinked_read: bool) -> Result<()> {
    let m = file.metadata()?;
    require(
        m.is_file()
            && (m.nlink() == 1 || (unlinked_read && m.nlink() == 0))
            && m.mode() & 0o7777 == 0o600
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.dev() == parent.metadata()?.dev(),
        "EXEC_FILE_UNSAFE",
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Step {
    Prepared,
    StopIntent,
    Stopped,
    AgentReady,
    RuntimeIntent,
    RuntimeReady,
    InstallIntent,
    Installed,
    BuildIntent,
    Built,
    ActivateIntent,
    Activated,
    StartIntent,
    Started,
    HealthIntent,
    Healthy,
    CommitIntent,
    Committed,
    RecoveryIntent,
    PreviousSelectionIntent,
    PreviousSelectionRestored,
    PreviousStartIntent,
    PreviousStarted,
    PreviousHealthIntent,
    PreviousHealthy,
    RolledBack,
    FailedBeforeStop,
    NeedsOperator,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Failure {
    BuildFailed,
    StartFailed,
    HealthFailed,
    Interrupted,
    StorageFailure,
    StateMismatch,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub instance_id: String,
    pub job_id: String,
    pub release_id: String,
    pub previous_release_id: Option<String>,
    pub profile_id: String,
    pub profile_sha256: String,
}
impl Binding {
    fn validate(&self, instance: &str) -> Result<()> {
        require(self.instance_id == instance, "EXEC_WRONG_INSTANCE")?;
        require(
            [
                &self.instance_id,
                &self.job_id,
                &self.release_id,
                &self.profile_id,
            ]
            .iter()
            .all(|s| identifier(s)),
            "EXEC_BINDING_INVALID",
        )?;
        require(
            self.previous_release_id
                .as_ref()
                .is_none_or(|s| identifier(s) && s != &self.release_id)
                && self.profile_id == "nextjs-systemd"
                && sha(&self.profile_sha256),
            "EXEC_BINDING_INVALID",
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub generation: u64,
    pub step: Step,
    pub at_ms: u64,
    pub failure: Option<Failure>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u16,
    pub binding: Binding,
    pub generation: u64,
    pub step: Step,
    pub failure: Option<Failure>,
    pub history: Vec<Transition>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryDecision {
    NotStarted,
    ReconcileExternalState,
    VerifyCommittedState,
    VerifyRestoredState,
    NoProjectChange,
    OperatorRequired,
}
impl Record {
    pub fn recovery_decision(&self) -> RecoveryDecision {
        match self.step {
            Step::Prepared => RecoveryDecision::NotStarted,
            Step::Committed => RecoveryDecision::VerifyCommittedState,
            Step::RolledBack => RecoveryDecision::VerifyRestoredState,
            Step::FailedBeforeStop => RecoveryDecision::NoProjectChange,
            Step::NeedsOperator => RecoveryDecision::OperatorRequired,
            _ => RecoveryDecision::ReconcileExternalState,
        }
    }
    fn validate(&self, instance: &str) -> Result<()> {
        require(self.schema_version == 1, "EXEC_SCHEMA_UNSUPPORTED")?;
        self.binding.validate(instance)?;
        require(
            !self.history.is_empty()
                && self.history.len() <= MAX_STEPS
                && self.generation == self.history.len() as u64 - 1,
            "EXEC_JOURNAL_CORRUPT",
        )?;
        let mut previous = Step::Prepared;
        let mut failure = None;
        for (i, item) in self.history.iter().enumerate() {
            require(
                item.generation == i as u64 && item.at_ms <= 9_007_199_254_740_991,
                "EXEC_JOURNAL_CORRUPT",
            )?;
            if i == 0 {
                require(
                    item.step == Step::Prepared && item.failure.is_none(),
                    "EXEC_JOURNAL_CORRUPT",
                )?;
            } else {
                check_transition(
                    previous,
                    item.step,
                    self.binding.previous_release_id.is_some(),
                    item.failure,
                )?;
            }
            if item.failure.is_some() {
                failure = item.failure;
            }
            previous = item.step;
        }
        require(
            self.step == previous && self.failure == failure,
            "EXEC_JOURNAL_CORRUPT",
        )
    }
}
fn check_transition(
    from: Step,
    to: Step,
    has_previous: bool,
    failure: Option<Failure>,
) -> Result<()> {
    use Step::*;
    let terminal = matches!(
        from,
        Committed | RolledBack | FailedBeforeStop | NeedsOperator
    );
    let failure_step = matches!(to, RecoveryIntent | NeedsOperator | FailedBeforeStop);
    require(
        failure_step == failure.is_some(),
        "EXEC_FAILURE_CODE_REQUIRED",
    )?;
    let normal = matches!(
        (from, to),
        (Prepared, StopIntent)
            | (StopIntent, Stopped)
            | (Stopped, AgentReady)
            | (AgentReady, RuntimeIntent)
            | (RuntimeIntent, RuntimeReady)
            | (RuntimeReady, InstallIntent)
            | (InstallIntent, Installed)
            | (Installed, BuildIntent)
            | (BuildIntent, Built)
            | (Built, ActivateIntent)
            | (ActivateIntent, Activated)
            | (Activated, StartIntent)
            | (StartIntent, Started)
            | (Started, HealthIntent)
            | (HealthIntent, Healthy)
            | (Healthy, CommitIntent)
            | (CommitIntent, Committed)
    );
    let restore = has_previous
        && matches!(
            (from, to),
            (RecoveryIntent, PreviousSelectionIntent)
                | (PreviousSelectionIntent, PreviousSelectionRestored)
                | (PreviousSelectionRestored, PreviousStartIntent)
                | (PreviousStartIntent, PreviousStarted)
                | (PreviousStarted, PreviousHealthIntent)
                | (PreviousHealthIntent, PreviousHealthy)
                | (PreviousHealthy, RolledBack)
        );
    let failure_allowed = (!terminal && to == NeedsOperator)
        || (from == Prepared && to == FailedBeforeStop)
        || (!terminal
            && !matches!(
                from,
                Prepared
                    | RecoveryIntent
                    | PreviousSelectionIntent
                    | PreviousSelectionRestored
                    | PreviousStartIntent
                    | PreviousStarted
                    | PreviousHealthIntent
                    | PreviousHealthy
            )
            && to == RecoveryIntent);
    require(
        normal || restore || failure_allowed,
        "EXEC_TRANSITION_FORBIDDEN",
    )
}
fn read_record(dir: &File, id: &str, instance: &str) -> Result<Option<Record>> {
    require(identifier(id), "EXEC_JOB_INVALID")?;
    let name = format!("{id}.json");
    let file: File = match fs::openat2(
        dir,
        name.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        flags(),
    ) {
        Ok(fd) => fd.into(),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    decode_snapshot(file, dir, id, instance).map(Some)
}
fn decode_snapshot(file: File, dir: &File, id: &str, instance: &str) -> Result<Record> {
    // Atomic rename may unlink a valid immutable inode after the reader opened it.
    safe_file(&file, dir, true)?;
    require(
        file.metadata()?.len() <= MAX_BYTES as u64,
        "EXEC_JOURNAL_TOO_LARGE",
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    require(bytes.len() <= MAX_BYTES, "EXEC_JOURNAL_TOO_LARGE")?;
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|_| Error("EXEC_JOURNAL_CORRUPT"))?;
    record.validate(instance)?;
    require(record.binding.job_id == id, "EXEC_BINDING_CONFLICT")?;
    Ok(record)
}
/// Lease guards every read/CAS/write in the single executor. Read-only inspection
/// may observe either complete generation, never a half-written replacement.
pub struct Journal {
    directory: File,
    parent: File,
    instance_id: String,
    #[cfg(test)]
    sync_fault: std::cell::Cell<bool>,
    #[cfg(test)]
    sync_count: std::cell::Cell<usize>,
}
impl Journal {
    pub fn open(state_directory: &Path, instance_id: &str) -> Result<Self> {
        require(identifier(instance_id), "EXEC_BINDING_INVALID")?;
        let parent = directory(state_directory, true)?;
        let directory = private_directory(&parent)?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error("EXEC_EXECUTOR_BUSY"))?;
        let journal = Self {
            directory,
            parent,
            instance_id: instance_id.into(),
            #[cfg(test)]
            sync_fault: std::cell::Cell::new(false),
            #[cfg(test)]
            sync_count: std::cell::Cell::new(0),
        };
        journal.fence()?;
        Ok(journal)
    }
    pub fn get(&self, id: &str) -> Result<Option<Record>> {
        read_record(&self.directory, id, &self.instance_id)
    }
    pub fn begin(&mut self, job: &Job, profile_sha256: &str) -> Result<Record> {
        require(
            job.phase == Phase::Prepared && !job.terminal,
            "EXEC_STORE_PHASE_INVALID",
        )?;
        let binding = Binding {
            instance_id: self.instance_id.clone(),
            job_id: job.job_id.clone(),
            release_id: job.release_id.clone(),
            previous_release_id: job.previous_release_id.clone(),
            profile_id: "nextjs-systemd".into(),
            profile_sha256: profile_sha256.into(),
        };
        binding.validate(&self.instance_id)?;
        if let Some(record) = self.get(&job.job_id)? {
            require(record.binding == binding, "EXEC_BINDING_CONFLICT")?;
            self.fence()?;
            return Ok(record);
        }
        let record = Record {
            schema_version: 1,
            binding,
            generation: 0,
            step: Step::Prepared,
            failure: None,
            history: vec![Transition {
                generation: 0,
                step: Step::Prepared,
                at_ms: millis()?,
                failure: None,
            }],
        };
        self.publish(&record, true)?;
        Ok(record)
    }
    pub fn advance(
        &mut self,
        id: &str,
        expected_generation: u64,
        expected_step: Step,
        next: Step,
        failure: Option<Failure>,
    ) -> Result<Record> {
        let mut record = self.get(id)?.ok_or(Error("EXEC_JOURNAL_MISSING"))?;
        require(
            record.generation == expected_generation && record.step == expected_step,
            "EXEC_GENERATION_CONFLICT",
        )?;
        check_transition(
            expected_step,
            next,
            record.binding.previous_release_id.is_some(),
            failure,
        )?;
        require(record.history.len() < MAX_STEPS, "EXEC_STEP_LIMIT")?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(Error("EXEC_STEP_LIMIT"))?;
        record.step = next;
        if failure.is_some() {
            record.failure = failure;
        }
        record.history.push(Transition {
            generation: record.generation,
            step: next,
            at_ms: millis()?,
            failure,
        });
        self.publish(&record, false)?;
        Ok(record)
    }
    fn fence(&self) -> Result<()> {
        #[cfg(test)]
        {
            self.sync_count.set(self.sync_count.get() + 1);
            if self.sync_fault.replace(false) {
                return Err(Error("EXEC_TEST_SYNC_FAULT"));
            }
        }
        self.directory.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }
    fn publish(&self, record: &Record, first: bool) -> Result<()> {
        record.validate(&self.instance_id)?;
        let bytes = serde_json::to_vec(record).map_err(|_| Error("EXEC_JOURNAL_CORRUPT"))?;
        require(bytes.len() <= MAX_BYTES, "EXEC_JOURNAL_TOO_LARGE")?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error("EXEC_RANDOM_UNAVAILABLE"))?;
        let temporary = format!(".write-{}-{}", record.binding.job_id, hex::encode(random));
        let mut file: File = fs::openat2(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            flags(),
        )?
        .into();
        fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
        safe_file(&file, &self.directory, false)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let destination = format!("{}.json", record.binding.job_id);
        if first {
            fs::renameat_with(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                destination.as_str(),
                RenameFlags::NOREPLACE,
            )?;
        } else {
            fs::renameat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                destination.as_str(),
            )?;
        }
        // No external effect may follow until this succeeds. On error, re-read/reconcile,
        // never roll back the in-memory generation and continue blindly.
        self.fence()?;
        Ok(())
    }
}
/// Non-mutating server view. Does not create a journal, acquire executor ownership,
/// resume any action, or convert an absent/corrupt file into a clean execution.
pub fn inspect(state_directory: &Path, instance_id: &str, job_id: &str) -> Result<Option<Record>> {
    require(
        identifier(instance_id) && identifier(job_id),
        "EXEC_BINDING_INVALID",
    )?;
    let parent = directory(state_directory, true)?;
    let dir: File = match fs::openat2(
        &parent,
        "execution",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        flags(),
    ) {
        Ok(fd) => fd.into(),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    check_directory(&dir, &parent)?;
    read_record(&dir, job_id, instance_id)
}

#[cfg(test)]
mod durability_regressions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn state() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn job() -> Job {
        Job {
            job_id: "job".into(),
            release_id: "new".into(),
            previous_release_id: Some("old".into()),
            phase: Phase::Prepared,
            terminal: false,
            error_code: None,
        }
    }
    #[test]
    fn replay_fences_a_rename_that_was_not_acknowledged_durable() {
        let root = state();
        let mut journal = Journal::open(root.path(), "instance").unwrap();
        journal.begin(&job(), &"a".repeat(64)).unwrap();
        let before = journal.sync_count.get();
        journal.sync_fault.set(true);
        assert!(
            journal
                .advance("job", 0, Step::Prepared, Step::StopIntent, None)
                .is_err()
        );
        assert_eq!(journal.get("job").unwrap().unwrap().generation, 1);
        assert_eq!(journal.sync_count.get(), before + 1);
        let replay = journal.begin(&job(), &"a".repeat(64)).unwrap();
        assert_eq!(replay.generation, 1);
        assert_eq!(journal.sync_count.get(), before + 2);
        drop(journal);
        // Other parallel tests spawn children. A transient inherited flock until
        // exec must remain BUSY in production; only this fixture bounds its retry.
        let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let reopened = loop {
            match Journal::open(root.path(), "instance") {
                Ok(value) => break value,
                Err(Error("EXEC_EXECUTOR_BUSY")) if std::time::Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("journal reopen: {error:?}"),
            }
        };
        assert_eq!(reopened.sync_count.get(), 1);
        assert_eq!(reopened.get("job").unwrap().unwrap().step, Step::StopIntent);
    }
    #[test]
    fn reader_accepts_the_complete_unlinked_snapshot_after_atomic_replacement() {
        let root = state();
        let mut journal = Journal::open(root.path(), "instance").unwrap();
        let original = journal.begin(&job(), &"a".repeat(64)).unwrap();
        let opened: File = fs::openat2(
            &journal.directory,
            "job.json",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            flags(),
        )
        .unwrap()
        .into();
        journal
            .advance("job", 0, Step::Prepared, Step::StopIntent, None)
            .unwrap();
        assert_eq!(opened.metadata().unwrap().nlink(), 0);
        let snapshot = decode_snapshot(opened, &journal.directory, "job", "instance").unwrap();
        assert_eq!(snapshot, original);
        assert_eq!(journal.get("job").unwrap().unwrap().generation, 1);
    }
}
