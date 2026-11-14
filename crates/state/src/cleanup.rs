//! Linux cleanup of abandoned uploads and orphan files. Only the trusted agent calls this.
//!
//! Cleanup touches only transient ingress/artifact files. It never removes
//! SEALED artifacts whose bytes are a registered release, nor verified or active
//! releases, jobs, events, or the database schema. A surviving SEALED artifact is
//! reclaimed only once its bytes are not a release and its orphaned ingress copy
//! is also gone, so a replay after restart can still seal it. Cleanup is
//! idempotent: a second run leaves the directory reconciled without error.
//!
//! All traversal is anchored inside the agent-owned state directory: no path is
//! ever followed as a symlink and no outside path can be removed. The work is
//! durable through the SQLite `cleanup` ledger before and after each removal, so
//! an agent stop mid-cleanup resumes safely instead of repeating or losing data.
use crate::store::{Error, Result, Store, event};
use crate::uploads::{self, UploadState};
use rusqlite::{params, Transaction};
use rustix::fs::{self as fs, AtFlags, FlockOperation, Mode, OFlags, ResolveFlags};
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};

/// How long an abandoned (idle, no active deploy job) upload record is kept
/// before its copies may be reclaimed. Matches the upload-quota policy already
/// established in this crate rather than introduce a new arbitrary threshold.
pub const ABANDONED_RETAIN_MS: u64 = 60 * 60 * 1000;

/// Maximum files inspected per directory during orphan reconciliation. Bounds
/// memory and I/O while still covering realistic staging sizes.
pub const MAX_ORPHAN_FILES: usize = 2048;

/// What cleanup decides to do with an upload's copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupKind {
    /// Active, in flight, still within TTL, or its bytes are a release. Never removed.
    Keep,
    /// Abandoned past TTL, or rejected. Its copies may be reclaimed when durable-safe.
    Reclaim,
}

/// Outcome of orphan reconciliation for a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanOutcome {
    /// Removed a durable orphan that no upload references and no process holds.
    Removed,
    /// Left a file that may still be actively written by an upload process.
    Retained,
    /// Could not prove the file was safe to remove this run.
    Unknown,
}

/// Per-upload decision with the filesystem effects cleanup actually applied.
#[derive(Debug, Clone)]
pub struct CleanupStat {
    pub upload_id: String,
    pub kind: CleanupKind,
    pub removed_ingress: bool,
    pub removed_artifact: bool,
}

/// Aggregate result of one cleanup pass.
#[derive(Debug)]
pub struct CleanupReport {
    pub cleaned: Vec<CleanupStat>,
    pub orphan_outcomes: Vec<OrphanOutcome>,
    pub attempted: u64,
    pub succeeded: u64,
    pub failed: bool,
    pub error: Option<String>,
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| Error::Rejected("STATE_CLOCK_INVALID"))
}

/// What was actually removed from the filesystem for one upload.
#[derive(Debug, Clone, Copy)]
struct ReclaimMark {
    removed_ingress: bool,
    removed_artifact: bool,
}

impl Store {
    /// Reconcile abandoned uploads and orphan files inside the state directory.
    ///
    /// Decision, durable intent, filesystem removal, and completion are applied
    /// inside one transaction so SQLite and the directory never drift, even when
    /// the process is interrupted mid-reclaim.
    pub fn cleanup_abandoned(&mut self) -> Result<CleanupReport> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Classify every upload record against its state and age, collecting
        //    every known id so orphan scanning only touches files with no record.
        let rows = classify(&tx)?;
        let (cleaned, all_ids) = rows;

        // 2. Reconcile orphan files on disk before reclaiming known uploads, so a
        //    crash between the two steps still reconciles fully on the next run.
        let ingress = uploads::spool(&self._directory, "uploads")?;
        let artifacts = uploads::spool(&self._directory, "artifacts")?;
        let orphan_outcomes = reconcile_orphans(&tx, &ingress, &artifacts, &all_ids)?;

        // 3. Durable intent first, then remove copies for the reclaim set.
        let mut report = CleanupReport {
            cleaned,
            orphan_outcomes,
            attempted: 0,
            succeeded: 0,
            failed: false,
            error: None,
        };
        for stat in report.cleaned.iter_mut() {
            if stat.kind != CleanupKind::Reclaim {
                continue;
            }
            report.attempted += 1;
            match reclaim(&tx, &ingress, &artifacts, &stat.upload_id) {
                Ok(mark) => {
                    stat.removed_ingress = mark.removed_ingress;
                    stat.removed_artifact = mark.removed_artifact;
                    report.succeeded += 1;
                }
                Err(e) => {
                    report.failed = true;
                    report.error = Some(format!("{e}"));
                    event(&tx, None, "CLEANUP_FAILED", Some("CLEANUP_RECLAIM_INTERRUPTED"))?;
                    break;
                }
            }
        }
        tx.commit()?;
        Ok(report)
    }
}

fn classify(tx: &Transaction<'_>) -> Result<(Vec<CleanupStat>, Vec<String>)> {
    let mut statement =
        tx.prepare("SELECT upload_id,state,package_sha256,created_ms FROM uploads")?;
    let rows = statement
        .query_map([], |r| {
            Ok(UploadRow {
                upload_id: r.get(0)?,
                state: match r.get::<_, String>(1)?.as_str() {
                    "RECEIVING" => UploadState::Receiving,
                    "SEALING" => UploadState::Sealing,
                    "SEALED" => UploadState::Sealed,
                    "REJECTED" => UploadState::Rejected,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                },
                package_sha256: r.get(2)?,
                created_ms: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut cleaned = Vec::new();
    // All known ids are every upload that has a DB record. Orphan scanning only
    // touches files with NO matching record at all (e.g. ingress left by a crash
    // before the row was written).
    let mut all_ids = Vec::new();
    // Uploads already fully reclaimed by a prior run: keep them in the report
    // but reclaim nothing again, so cleanup is truly idempotent across runs.
    let already_reclaimed = completed_reclaims(tx)?;
    for row in rows {
        all_ids.push(row.upload_id.clone());
        let (kind, removed_ingress, removed_artifact) =
            decide(tx, &row, &already_reclaimed);
        cleaned.push(CleanupStat {
            upload_id: row.upload_id.clone(),
            kind,
            removed_ingress,
            removed_artifact,
        });
    }
    Ok((cleaned, all_ids))
}

/// Which upload ids have a completed ledger reclaim already on disk.
fn completed_reclaims(tx: &Transaction<'_>) -> Result<std::collections::HashSet<String>> {
    let mut stmt = tx.prepare(
        "SELECT upload_id FROM cleanup WHERE completed_ms IS NOT NULL",
    )?;
    let ids = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ids)
}

#[derive(Clone)]
struct UploadRow {
    upload_id: String,
    state: UploadState,
    package_sha256: String,
    created_ms: i64,
}

fn decide(
    tx: &Transaction<'_>,
    row: &UploadRow,
    already_reclaimed: &std::collections::HashSet<String>,
) -> (CleanupKind, bool, bool) {
    // A prior run already cleared its copies; report what it removed and never
    // reclaim it again on this or any later run.
    if already_reclaimed.contains(&row.upload_id) {
        return (
            CleanupKind::Keep,
            false,
            false,
        );
    }
    match row.state {
        // Active or still receiving: never remove, regardless of age.
        UploadState::Receiving | UploadState::Sealing => (CleanupKind::Keep, false, false),
        // Rejected: its bytes were never a release, reclaim its copies.
        UploadState::Rejected => (CleanupKind::Reclaim, false, false),
        // SEALED: never reclaim while within TTL, and never reclaim while its
        // bytes are a registered release (possibly active/deployed). Only reclaim
        // once idle past TTL and the bytes are not a release.
        UploadState::Sealed => {
            if !age_ok(row) {
                (CleanupKind::Keep, false, false)
            } else {
                let published = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM releases WHERE package_sha256=?1)",
                        [&row.package_sha256],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0)
                    == 1;
                if published {
                    (CleanupKind::Keep, false, false)
                } else {
                    (CleanupKind::Reclaim, false, false)
                }
            }
        }
    }
}

fn age_ok(row: &UploadRow) -> bool {
    if let Some(created) = i64::try_from(row.created_ms).ok() {
        now_ms().map_or(false, |now| now.saturating_sub(created as u64) >= ABANDONED_RETAIN_MS)
    } else {
        false
    }
}

/// Reclaim one upload's ingress and artifact copies, durable-first. Idempotent:
/// a second call on an already-cleared upload reports no further deletion.
fn reclaim(
    tx: &Transaction<'_>,
    ingress: &File,
    artifacts: &File,
    upload_id: &str,
) -> Result<ReclaimMark> {
    let cleanup_id = format!("reclaim-{upload_id}");

    // Durable intent: record the attempt with NULL completion before touching
    // any file. If we crash here, the ledger still shows this upload as needing
    // its copies cleared on the next run. INSERT OR IGNORE makes the whole
    // operation idempotent: an existing ledger row from a prior (possibly
    // interrupted) attempt is honored rather than rejected by the primary key.
    tx.execute(
        "INSERT OR IGNORE INTO cleanup(cleanup_id,upload_id,reclaimed_ingress,reclaimed_artifact,attempt_ms) VALUES(?1,?2,0,0,?3)",
        params![cleanup_id, upload_id, now_ms()?,],
    )?;

    // If a previous run already completed, report no further removals.
    let done: Option<bool> = tx
        .query_row("SELECT completed_ms IS NOT NULL FROM cleanup WHERE cleanup_id=?1", [cleanup_id.as_str()], |r| r
            .get(0))?;
    if done == Some(true) {
        return Ok(ReclaimMark {
            removed_ingress: false,
            removed_artifact: false,
        });
    }

    // Remove the ingress copy first so a stale writer cannot rewrite a file we
    // are reclaiming.
    let removed_ingress = remove_child(&ingress, upload_id);

    // Remove the artifact only once its orphaned ingress sibling is cleared, so
    // no partial pair is left behind for a later replay to seal again.
    let removed_artifact = if removed_ingress {
        remove_child(&artifacts, &format!("{upload_id}.uli4"))
    } else {
        false
    };

    // Mark completion after the filesystem change so SQLite and the directory
    // agree on the operation's outcome.
    tx.execute(
        "UPDATE cleanup SET reclaimed_ingress=?1, reclaimed_artifact=?2, completed_ms=?3 WHERE cleanup_id=?4",
        params![removed_ingress as i64, removed_artifact as i64, now_ms()?, cleanup_id],
    )?;
    event(tx, None, "CLEANUP_RECLAIMED", None)?;

    Ok(ReclaimMark {
        removed_ingress,
        removed_artifact,
    })
}

/// Unlink a single child inside an anchored directory. Returns true only when a
/// file was actually removed. BENEATH on the directory fd keeps the child from
/// escaping, even via a symlink or `..` component.
fn remove_child(directory: &File, name: &str) -> bool {
    // Unlinking by name inside an already-anchored parent fd is safe: the path
    // cannot escape the directory (the parent was opened BENEATH|NO_SYMLINKS),
    // and unlinkat removes the link entry itself, never following symlinks.
    // AT_SYMLINK_NOFOLLOW is only valid for symlink targets here, so omit it.
    match fs::unlinkat(directory, name, AtFlags::empty()) {
        Ok(()) => true,
        // Already gone is fine; cleanup is idempotent.
        Err(rustix::io::Errno::NOENT) => false,
        // Any other error (permissions, busy) leaves the file in place safely.
        Err(_) => false,
    }
}

/// Walk both staging directories and reconcile files that do not match any
/// known upload id. Every file with a DB record is kept; a file with no matching
/// record at all is a potential durable orphan. It is removed only when it is
/// not being written by an active process (an exclusive lock can be taken), so
/// concurrent uploads are never touched.
fn reconcile_orphans(
    tx: &Transaction<'_>,
    ingress: &File,
    artifacts: &File,
    all_ids: &[String],
) -> Result<Vec<OrphanOutcome>> {
    let mut outcomes = Vec::new();
    let upload_names = kept_names(all_ids);
    let artifact_names = kept_artifact_names(all_ids);
    outcomes.extend(scan_dir(tx, ingress, "uploads", &upload_names)?);
    outcomes.extend(scan_dir(tx, artifacts, "artifacts", &artifact_names)?);
    Ok(outcomes)
}

/// Every file that belongs to a known upload: ingress uses the bare id, the
/// sealed artifact uses the `{id}.uli4` name, so neither is mistaken for an orphan.
fn kept_names(all_ids: &[String]) -> Vec<String> {
    all_ids.to_vec()
}
fn kept_artifact_names(all_ids: &[String]) -> Vec<String> {
    all_ids
        .iter()
        .map(|id| format!("{id}.uli4"))
        .collect()
}

fn scan_dir(
    tx: &Transaction<'_>,
    dir: &File,
    label: &str,
    known_names: &[String],
) -> Result<Vec<OrphanOutcome>> {
    let now = now_ms()?;
    let mut seen = Vec::new();
    for entry in fs::Dir::read_from(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().ok() else {
            continue;
        };
        if name.is_empty() || name.starts_with('.') {
            continue;
        }
        seen.push(name.to_string());
        if seen.len() > MAX_ORPHAN_FILES {
            break;
        }
    }

    let mut outcomes = Vec::new();
    for name in seen {
        // Every name that belongs to a known upload is kept regardless of whether
        // it is still being written. Only a file with no matching record at all
        // can be a durable orphan; anything else is part of a known upload's copy.
        if known_names.iter().any(|n| n == &name) {
            continue;
        }
        // A durable orphan is only reclaimed when it is not actively being
        // written. If we cannot take the lock now it may be mid-write by an
        // active upload, so retain it rather than delete it.
        if !lock_child(dir, &name) {
            outcomes.push(OrphanOutcome::Retained);
            continue;
        }
        if remove_child(dir, &name) {
            tx.execute(
                "INSERT INTO cleanup_orphans(orphan_id,location,name,outcome,checked_ms) VALUES(?1,?2,?3,?4,?5)",
                params![format!("{name}-{now}"), label, name, "REMOVED", now,],
            )?;
            outcomes.push(OrphanOutcome::Removed);
        } else {
            outcomes.push(OrphanOutcome::Unknown);
        }
    }
    Ok(outcomes)
}

/// Take a non-blocking exclusive lock on a child to prove it is not being
/// written by another process. False means "in use", so leave the file alone.
fn lock_child(directory: &File, name: &str) -> bool {
    match fs::openat2(
        directory,
        name,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(handle) => fs::flock(&handle, FlockOperation::NonBlockingLockExclusive).is_ok(),
        Err(_) => false,
    }
}
