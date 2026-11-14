use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use rustix::fs::{self as fs, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uli4::{VerifiedPackage, canonical_manifest};
use uliup_protocol::{Command, Request};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Database(rusqlite::Error),
    Io(std::io::Error),
    Rejected(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(_) => f.write_str("STATE_DATABASE_ERROR"),
            Self::Io(_) => f.write_str("STATE_IO_ERROR"),
            Self::Rejected(code) => f.write_str(code),
        }
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
pub(crate) fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Rejected(code))
    }
}
pub(crate) fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or(Error::Rejected("STATE_CLOCK_INVALID"))
}
pub(crate) fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}
fn digest_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub instance_id: String,
    pub app_id: String,
    pub profile_id: String,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Verified,
    Prepared,
    StoppingProject,
    BootstrapSwitching,
    AgentReady,
    MaterializingProject,
    ResolvingRuntime,
    Building,
    StartingProject,
    HealthChecking,
    Committed,
    Cleanup,
    Recovering,
    RolledBack,
    Failed,
    FailedRecovery,
    NeedsOperator,
}
impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Prepared => "PREPARED",
            Self::StoppingProject => "STOPPING_PROJECT",
            Self::BootstrapSwitching => "BOOTSTRAP_SWITCHING",
            Self::AgentReady => "AGENT_READY",
            Self::MaterializingProject => "MATERIALIZING_PROJECT",
            Self::ResolvingRuntime => "RESOLVING_RUNTIME",
            Self::Building => "BUILDING",
            Self::StartingProject => "STARTING_PROJECT",
            Self::HealthChecking => "HEALTH_CHECKING",
            Self::Committed => "COMMITTED",
            Self::Cleanup => "CLEANUP",
            Self::Recovering => "RECOVERING",
            Self::RolledBack => "ROLLED_BACK",
            Self::Failed => "FAILED",
            Self::FailedRecovery => "FAILED_RECOVERY",
            Self::NeedsOperator => "NEEDS_OPERATOR",
        }
    }
    fn parse(s: &str) -> rusqlite::Result<Self> {
        serde_json::from_str(&format!("\"{s}\"")).map_err(|_| rusqlite::Error::InvalidQuery)
    }
}
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCode {
    PackageRejected,
    MaterializeFailed,
    BuildFailed,
    HealthFailed,
    StorageUnavailable,
    RecoveryFailed,
    CleanupFailed,
    Interrupted,
}
impl FailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::PackageRejected => "PACKAGE_REJECTED",
            Self::MaterializeFailed => "MATERIALIZE_FAILED",
            Self::BuildFailed => "BUILD_FAILED",
            Self::HealthFailed => "HEALTH_FAILED",
            Self::StorageUnavailable => "STORAGE_UNAVAILABLE",
            Self::RecoveryFailed => "RECOVERY_FAILED",
            Self::CleanupFailed => "CLEANUP_FAILED",
            Self::Interrupted => "INTERRUPTED",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub job_id: String,
    pub release_id: String,
    pub previous_release_id: Option<String>,
    pub phase: Phase,
    pub terminal: bool,
    pub error_code: Option<String>,
}
#[derive(Debug)]
pub struct Event {
    pub event_id: i64,
    pub job_id: Option<String>,
    pub code: String,
    pub error_code: Option<String>,
}
/// Caller must be the authenticated agent. Store methods are not exposed directly to SSH clients.
/// The connection is dropped before its anchored directory guard.
pub struct Store {
    pub(crate) connection: Connection,
    pub(crate) instance: Instance,
    pub(crate) _directory: File,
}
static OPEN_LOCK: Mutex<()> = Mutex::new(());
fn safe_stat(stat: &fs::Stat) -> Result<()> {
    require(
        fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile
            && stat.st_nlink == 1
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat.st_mode & 0o7777 == 0o600,
        "STATE_PATH_UNSAFE",
    )
}
fn trusted_directory(path: &Path) -> Result<File> {
    let mut directory = File::open("/")?;
    for part in path.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        directory = fs::openat2(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?
        .into();
        let m = directory.metadata()?;
        require(
            (m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
            "STATE_PARENT_UNSAFE",
        )?;
    }
    Ok(directory)
}
impl Store {
    pub fn open(state_directory: &Path, instance: Instance) -> Result<Self> {
        let _guard = OPEN_LOCK
            .lock()
            .map_err(|_| Error::Rejected("STATE_OPEN_UNAVAILABLE"))?;
        require(
            [
                &instance.instance_id,
                &instance.app_id,
                &instance.profile_id,
            ]
            .into_iter()
            .all(|s| id_ok(s)),
            "STATE_INSTANCE_INVALID",
        )?;
        require(
            state_directory.is_absolute()
                && state_directory
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "STATE_PATH_UNSAFE",
        )?;
        let directory = trusted_directory(state_directory)?;
        let m = directory.metadata()?;
        require(
            m.is_dir()
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.mode() & 0o7777 == 0o700,
            "STATE_PATH_UNSAFE",
        )?;
        let resolve = ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV;
        match fs::openat2(
            &directory,
            "state.sqlite",
            OFlags::RDWR
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK
                | OFlags::CREATE
                | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
            resolve,
        ) {
            Ok(fd) => {
                let f: File = fd.into();
                fs::fchmod(&f, Mode::from_raw_mode(0o600))?;
                f.sync_all()?;
                directory.sync_all()?;
                // Close before any SQLite connection is opened: never disturb SQLite POSIX locks.
                drop(f);
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        let before = fs::statat(&directory, "state.sqlite", fs::AtFlags::SYMLINK_NOFOLLOW)?;
        safe_stat(&before)?;
        for name in [
            "state.sqlite-wal",
            "state.sqlite-shm",
            "state.sqlite-journal",
        ] {
            match fs::statat(&directory, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => safe_stat(&stat)?,
                Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // SQLite NOFOLLOW rejects procfd aliases. The pathname chain above is owned by root/euid,
        // non-writable by other users (or sticky), with a private 0700 leaf.
        // Runtime processes must use a separate uid. Privileged/same-uid hostile writers are out of scope.
        let mut connection = Connection::open_with_flags(
            state_directory.join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let after = fs::statat(&directory, "state.sqlite", fs::AtFlags::SYMLINK_NOFOLLOW)?;
        safe_stat(&after)?;
        let current = trusted_directory(state_directory)?.metadata()?;
        require(
            before.st_dev == after.st_dev
                && before.st_ino == after.st_ino
                && m.dev() == current.dev()
                && m.ino() == current.ino(),
            "STATE_PATH_CHANGED",
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let schema: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        require(schema <= 3, "STATE_SCHEMA_UNSUPPORTED")?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                tx.execute_batch(include_str!("../migrations/001_init.sql"))?;
                tx.execute_batch(include_str!("../migrations/002_uploads.sql"))?;
                tx.execute_batch(include_str!("../migrations/003_cleanup.sql"))?;
            }
            1 => {
                tx.execute_batch(include_str!("../migrations/002_uploads.sql"))?;
                tx.execute_batch(include_str!("../migrations/003_cleanup.sql"))?;
            }
            2 => tx.execute_batch(include_str!("../migrations/003_cleanup.sql"))?,
            3 => {}
            _ => return Err(Error::Rejected("STATE_SCHEMA_UNSUPPORTED")),
        }
        tx.execute("INSERT OR IGNORE INTO instances(singleton,instance_id,app_id,profile_id) VALUES(1,?1,?2,?3)",params![instance.instance_id,instance.app_id,instance.profile_id])?;
        let actual = tx.query_row(
            "SELECT instance_id,app_id,profile_id FROM instances WHERE singleton=1",
            [],
            |r| {
                Ok(Instance {
                    instance_id: r.get(0)?,
                    app_id: r.get(1)?,
                    profile_id: r.get(2)?,
                })
            },
        )?;
        require(actual == instance, "STATE_WRONG_INSTANCE")?;
        tx.commit()?;
        directory.sync_all()?;
        Ok(Self {
            connection,
            instance,
            _directory: directory,
        })
    }
    pub fn register_verified(
        &mut self,
        package: &VerifiedPackage,
        package_sha256: &str,
    ) -> Result<()> {
        let m = package.manifest();
        require(
            m.app_id == self.instance.app_id
                && m.deployment_profile_id == self.instance.profile_id
                && m.target_os == "linux"
                && digest_ok(package_sha256),
            "STATE_RELEASE_INCOMPATIBLE",
        )?;
        let json = String::from_utf8(
            canonical_manifest(m).map_err(|_| Error::Rejected("STATE_RELEASE_INVALID"))?,
        )
        .map_err(|_| Error::Rejected("STATE_RELEASE_INVALID"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT package_sha256,manifest_json FROM releases WHERE release_id=?1",
                [&m.release_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((hash, old_json)) = old {
            require(
                hash == package_sha256 && old_json == json,
                "STATE_RELEASE_CONFLICT",
            )?;
            tx.commit()?;
            return Ok(());
        }
        let max: i64 = tx.query_row(
            "SELECT max_seen_sequence FROM instances WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        require(m.release_sequence > max as u64, "STATE_RELEASE_REPLAY")?;
        let same: i64 = tx.query_row(
            "SELECT COUNT(*) FROM releases WHERE display_version=?1 AND state!='FAILED'",
            [&m.display_version],
            |r| r.get(0),
        )?;
        require(same == 0, "STATE_VERSION_ALREADY_RESERVED")?;
        tx.execute(
            "INSERT INTO releases VALUES(?1,?2,?3,?4,?5,?6,?7,'VERIFIED',?8)",
            params![
                m.release_id,
                m.display_version,
                m.release_sequence,
                package_sha256,
                m.signer_key_id,
                m.result_tree_digest,
                json,
                now()?
            ],
        )?;
        tx.execute(
            "UPDATE instances SET max_seen_sequence=?1 WHERE singleton=1",
            [m.release_sequence],
        )?;
        event(&tx, None, "RELEASE_VERIFIED", None)?;
        tx.commit()?;
        Ok(())
    }
    pub fn start_deploy(&mut self, request: &Request) -> Result<Job> {
        request
            .validate_for_instance(&self.instance.instance_id)
            .map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
        let Command::StartDeploy { release_id } = &request.command else {
            return Err(Error::Rejected("STATE_COMMAND_UNSUPPORTED"));
        };
        let json = serde_json::to_vec(
            &serde_json::to_value(request).map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?,
        )
        .map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
        let digest = hex::encode(Sha256::digest(json));
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let upload_request: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM requests WHERE request_id=?1 AND upload_id IS NOT NULL)",
            [&request.request_id],
            |r| r.get(0),
        )?;
        require(!upload_request, "STATE_REQUEST_CONFLICT")?;
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT request_digest,job_id FROM requests WHERE request_id=?1",
                [&request.request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old, id)) = prior {
            require(old == digest, "STATE_REQUEST_CONFLICT")?;
            let job = read_job(&tx, &id)?.ok_or(Error::Rejected("STATE_CORRUPT"))?;
            tx.commit()?;
            return Ok(job);
        }
        let blocked: i64 = tx.query_row(
            "SELECT needs_operator FROM instances WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        require(blocked == 0, "STATE_NEEDS_OPERATOR")?;
        let busy: i64 = tx.query_row("SELECT COUNT(*) FROM jobs WHERE terminal=0", [], |r| {
            r.get(0)
        })?;
        require(busy == 0, "STATE_BUSY")?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM releases WHERE release_id=?1",
                [release_id],
                |r| r.get(0),
            )
            .optional()?;
        require(
            state.as_deref() == Some("VERIFIED"),
            "STATE_RELEASE_NOT_DEPLOYABLE",
        )?;
        let (sequence,floor):(i64,i64)=tx.query_row("SELECT r.sequence,i.committed_sequence FROM releases r CROSS JOIN instances i WHERE r.release_id=?1 AND i.singleton=1",[release_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        require(sequence > floor, "STATE_RELEASE_REPLAY")?;
        let previous: Option<String> = tx.query_row(
            "SELECT active_release_id FROM instances WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Rejected("STATE_RANDOM_UNAVAILABLE"))?;
        let id = hex::encode(random);
        let time = now()?;
        tx.execute(
            "INSERT INTO jobs VALUES(?1,?2,?3,'VERIFIED',0,NULL,?4,?4)",
            params![id, release_id, previous, time],
        )?;
        tx.execute(
            "INSERT INTO requests(request_id,request_digest,job_id) VALUES(?1,?2,?3)",
            params![request.request_id, digest, id],
        )?;
        event(&tx, Some(&id), "JOB_STARTED", None)?;
        let job = read_job(&tx, &id)?.ok_or(Error::Rejected("STATE_CORRUPT"))?;
        tx.commit()?;
        Ok(job)
    }
    /// Records intent/completion reported by the trusted executor; performs no system operation.
    pub fn advance(&mut self, id: &str, expected: Phase, next: Phase) -> Result<Job> {
        let allowed = matches!(
            (expected, next),
            (Phase::Verified, Phase::Prepared)
                | (Phase::Prepared, Phase::StoppingProject)
                | (Phase::StoppingProject, Phase::BootstrapSwitching)
                | (Phase::StoppingProject, Phase::AgentReady)
                | (Phase::BootstrapSwitching, Phase::AgentReady)
                | (Phase::AgentReady, Phase::MaterializingProject)
                | (Phase::ResolvingRuntime, Phase::Building)
                | (Phase::Building, Phase::StartingProject)
                | (Phase::StartingProject, Phase::HealthChecking)
        );
        let profile = (&self.instance.profile_id, expected, next);
        let profile_allowed = matches!(profile,(p,Phase::MaterializingProject,Phase::ResolvingRuntime) if p=="nextjs-systemd")
            || matches!(profile,(p,Phase::MaterializingProject,Phase::StartingProject) if p=="static-files");
        require(allowed || profile_allowed, "STATE_TRANSITION_FORBIDDEN")?;
        self.change(id, expected, next, None, false)
    }
    pub fn fail(&mut self, id: &str, expected: Phase, code: FailureCode) -> Result<Job> {
        let (next, terminal) = match expected {
            Phase::Verified | Phase::Prepared => (Phase::Failed, true),
            Phase::Committed => (Phase::NeedsOperator, true),
            Phase::Cleanup
            | Phase::RolledBack
            | Phase::Failed
            | Phase::FailedRecovery
            | Phase::NeedsOperator => return Err(Error::Rejected("STATE_TRANSITION_FORBIDDEN")),
            _ => (Phase::Recovering, false),
        };
        self.change(id, expected, next, Some(code.as_str()), terminal)
    }
    /// Only the trusted executor may call after actual health success.
    pub fn commit_healthy(&mut self, id: &str) -> Result<Job> {
        self.change(id, Phase::HealthChecking, Phase::Committed, None, false)
    }
    /// Only after actual successful rollback; a failed rollback blocks new jobs.
    pub fn record_rollback(&mut self, id: &str, success: bool) -> Result<Job> {
        self.change(
            id,
            Phase::Recovering,
            if success {
                Phase::RolledBack
            } else {
                Phase::FailedRecovery
            },
            if success {
                None
            } else {
                Some("RECOVERY_FAILED")
            },
            true,
        )
    }
    pub fn finish_cleanup(&mut self, id: &str) -> Result<Job> {
        self.change(id, Phase::Committed, Phase::Cleanup, None, true)
    }
    fn change(
        &mut self,
        id: &str,
        expected: Phase,
        next: Phase,
        error: Option<&str>,
        terminal: bool,
    ) -> Result<Job> {
        require(id_ok(id), "STATE_JOB_INVALID")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = read_job(&tx, id)?.ok_or(Error::Rejected("STATE_JOB_NOT_FOUND"))?;
        require(
            !job.terminal && job.phase == expected,
            "STATE_PHASE_CONFLICT",
        )?;
        if next == Phase::Committed {
            let active: Option<String> = tx.query_row(
                "SELECT active_release_id FROM instances WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            require(active == job.previous_release_id, "STATE_ACTIVE_CONFLICT")?;
            tx.execute(
                "UPDATE releases SET state='RETIRED' WHERE state='ACTIVE'",
                [],
            )?;
            tx.execute(
                "UPDATE releases SET state='ACTIVE' WHERE release_id=?1",
                [&job.release_id],
            )?;
            tx.execute("UPDATE instances SET active_release_id=?1,committed_sequence=(SELECT sequence FROM releases WHERE release_id=?1) WHERE singleton=1",[&job.release_id])?;
        }
        if matches!(
            next,
            Phase::Failed | Phase::RolledBack | Phase::FailedRecovery
        ) {
            tx.execute(
                "UPDATE releases SET state='FAILED' WHERE release_id=?1",
                [&job.release_id],
            )?;
        }
        if matches!(next, Phase::FailedRecovery | Phase::NeedsOperator) {
            tx.execute(
                "UPDATE instances SET needs_operator=1 WHERE singleton=1",
                [],
            )?;
        }
        tx.execute("UPDATE jobs SET phase=?1,terminal=?2,error_code=COALESCE(?3,error_code),updated_ms=?4 WHERE job_id=?5",
            params![next.as_str(),terminal,error,now()?,id])?;
        event(&tx, Some(id), next.as_str(), error)?;
        let result = read_job(&tx, id)?.ok_or(Error::Rejected("STATE_CORRUPT"))?;
        tx.commit()?;
        Ok(result)
    }
    pub fn job(&self, id: &str) -> Result<Option<Job>> {
        require(id_ok(id), "STATE_JOB_INVALID")?;
        Ok(read_job(&self.connection, id)?)
    }
    pub fn pending_job(&self) -> Result<Option<Job>> {
        let id: Option<String> = self
            .connection
            .query_row("SELECT job_id FROM jobs WHERE terminal=0", [], |r| r.get(0))
            .optional()?;
        id.map(|id| self.job(&id)).transpose().map(|o| o.flatten())
    }
    pub fn active_release(&self) -> Result<Option<String>> {
        Ok(self.connection.query_row(
            "SELECT active_release_id FROM instances WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn events(&self, after: i64, limit: u16) -> Result<Vec<Event>> {
        require(
            after >= 0 && limit > 0 && limit <= 1000,
            "STATE_PAGE_INVALID",
        )?;
        let mut statement=self.connection.prepare("SELECT event_id,job_id,code,error_code FROM events WHERE event_id>?1 ORDER BY event_id LIMIT ?2")?;
        let result = statement
            .query_map(params![after, limit], |r| {
                Ok(Event {
                    event_id: r.get(0)?,
                    job_id: r.get(1)?,
                    code: r.get(2)?,
                    error_code: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(result)
    }
}
fn read_job(connection: &Connection, id: &str) -> rusqlite::Result<Option<Job>> {
    connection.query_row("SELECT job_id,release_id,previous_release_id,phase,terminal,error_code FROM jobs WHERE job_id=?1",[id],
        |r|{let phase:String=r.get(3)?;Ok(Job{job_id:r.get(0)?,release_id:r.get(1)?,previous_release_id:r.get(2)?,phase:Phase::parse(&phase)?,terminal:r.get(4)?,error_code:r.get(5)?})}).optional()
}
pub(crate) fn event(
    tx: &Transaction<'_>,
    id: Option<&str>,
    code: &str,
    error: Option<&str>,
) -> Result<()> {
    tx.execute(
        "INSERT INTO events(job_id,code,error_code,created_ms) VALUES(?1,?2,?3,?4)",
        params![id, code, error, now()?],
    )?;
    Ok(())
}
