//! Private durable upload storage. Only the trusted agent calls this API.
//! SSH/SFTP must route bounded writes here, never expose these directories.
//! SHA-256 sealing is not ULI4 signature verification or release registration.
use crate::store::{Error, Result, Store, event, id_ok, now, require};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use rustix::fs::{self as fs, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
};
use uliup_protocol::{Command, MAX_UPLOAD_BYTES, Request};

pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const FREE_RESERVE: u64 = 16 * 1024 * 1024;
#[derive(Clone, Copy, Debug)]
pub struct UploadLimits {
    pub max_uploads: u32,
    /// Reserves space for ingress AND its independent sealed copy; includes rejected artifacts.
    pub max_reserved_bytes: u64,
}
impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            max_uploads: 64,
            max_reserved_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    Receiving,
    Sealing,
    Sealed,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upload {
    pub upload_id: String,
    pub size: u64,
    pub package_sha256: String,
    pub committed_offset: u64,
    pub state: UploadState,
    pub error_code: Option<String>,
}
fn read_upload(db: &Connection, id: &str) -> Result<Upload> {
    db.query_row(
        "SELECT upload_id,size,package_sha256,committed_offset,state,error_code FROM uploads WHERE upload_id=?1",
        [id], |r| {
            let state: String = r.get(4)?;
            let state = match state.as_str() {
                "RECEIVING" => UploadState::Receiving, "SEALING" => UploadState::Sealing,
                "SEALED" => UploadState::Sealed, "REJECTED" => UploadState::Rejected,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(Upload { upload_id:r.get(0)?,size:r.get(1)?,package_sha256:r.get(2)?,
                committed_offset:r.get(3)?,state,error_code:r.get(5)? })
        }
    ).optional()?.ok_or(Error::Rejected("UPLOAD_NOT_FOUND"))
}
fn request_digest(request: &Request) -> Result<String> {
    let value =
        serde_json::to_value(request).map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn prior_upload(tx: &Transaction<'_>, request: &Request, digest: &str) -> Result<Option<Upload>> {
    let prior: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT request_digest,upload_id FROM requests WHERE request_id=?1",
            [&request.request_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((old, id)) = prior {
        require(old == digest, "STATE_REQUEST_CONFLICT")?;
        let id = id.ok_or(Error::Rejected("STATE_REQUEST_CONFLICT"))?;
        Ok(Some(read_upload(tx, &id)?))
    } else {
        Ok(None)
    }
}
fn reserve(tx: &Transaction<'_>, request: &Request, digest: &str, upload: &Upload) -> Result<()> {
    tx.execute(
        "INSERT INTO requests(request_id,request_digest,upload_id) VALUES(?1,?2,?3)",
        params![request.request_id, digest, upload.upload_id],
    )?;
    Ok(())
}
fn resolve() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}
pub(crate) fn spool(root: &File, name: &str) -> Result<File> {
    let made = match fs::mkdirat(root, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.into()),
    };
    let directory: File = fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        resolve(),
    )?
    .into();
    if made {
        fs::fchmod(&directory, Mode::from_raw_mode(0o700))?;
        directory.sync_all()?;
        root.sync_all()?;
    }
    let m = directory.metadata()?;
    require(
        m.is_dir()
            && m.mode() & 0o7777 == 0o700
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.dev() == root.metadata()?.dev(),
        "UPLOAD_PATH_UNSAFE",
    )?;
    Ok(directory)
}
fn open_file(root: &File, name: &str, write: bool, create: bool) -> Result<File> {
    let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
    let creation = if create {
        OFlags::CREATE | OFlags::EXCL
    } else {
        OFlags::empty()
    };
    let file: File = fs::openat2(
        root,
        name,
        access | creation | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(if create { 0o600 } else { 0 }),
        resolve(),
    )?
    .into();
    if create {
        fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
    }
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.dev() == root.metadata()?.dev(),
        "UPLOAD_PATH_UNSAFE",
    )?;
    Ok(file)
}
fn lock(file: &File) -> Result<()> {
    fs::flock(file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::Rejected("UPLOAD_BUSY"))
}
fn space(directory: &File, needed: u64) -> Result<()> {
    let stat = fs::fstatvfs(directory)?;
    let bytes = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or(Error::Rejected("UPLOAD_QUOTA_EXCEEDED"))?;
    require(
        bytes >= needed.saturating_add(FREE_RESERVE) && (stat.f_files == 0 || stat.f_favail > 1),
        "UPLOAD_STORAGE_FULL",
    )
}
fn reconcile(file: &File, upload: &Upload) -> Result<()> {
    let len = file.metadata()?.len();
    require(len >= upload.committed_offset, "UPLOAD_STATE_DAMAGED")?;
    if len > upload.committed_offset {
        file.set_len(upload.committed_offset)?;
        file.sync_all()?;
    }
    Ok(())
}
fn digest(file: &mut File, size: u64) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(Error::Rejected("UPLOAD_SIZE_MISMATCH"))?;
        require(count <= size, "UPLOAD_SIZE_MISMATCH")?;
        hash.update(&buffer[..n]);
    }
    require(count == size, "UPLOAD_SIZE_MISMATCH")?;
    file.seek(SeekFrom::Start(0))?;
    Ok(hex::encode(hash.finalize()))
}
impl Store {
    /// Reserve one upload per accepted request ID, never a client-provided path.
    pub fn begin_upload(&mut self, request: &Request, limits: UploadLimits) -> Result<Upload> {
        request
            .validate_for_instance(&self.instance.instance_id)
            .map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
        let Command::BeginUpload {
            app_id,
            size,
            package_sha256,
        } = &request.command
        else {
            return Err(Error::Rejected("STATE_COMMAND_UNSUPPORTED"));
        };
        require(app_id == &self.instance.app_id, "STATE_WRONG_INSTANCE")?;
        require(
            limits.max_uploads > 0
                && limits.max_uploads <= 1024
                && limits.max_reserved_bytes > 0
                && limits.max_reserved_bytes <= 128 * 1024 * 1024 * 1024,
            "UPLOAD_LIMITS_INVALID",
        )?;
        let hash = request_digest(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(upload) = prior_upload(&tx, request, &hash)? {
            tx.commit()?;
            return Ok(upload);
        }
        let (count, total): (u32, u64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(size),0) FROM uploads",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let reserved = total
            .checked_add(*size)
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error::Rejected("UPLOAD_QUOTA_EXCEEDED"))?;
        require(
            count < limits.max_uploads && reserved <= limits.max_reserved_bytes,
            "UPLOAD_QUOTA_EXCEEDED",
        )?;
        let directory = spool(&self._directory, "uploads")?;
        space(
            &directory,
            size.checked_mul(2)
                .ok_or(Error::Rejected("UPLOAD_QUOTA_EXCEEDED"))?,
        )?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Rejected("STATE_RANDOM_UNAVAILABLE"))?;
        let id = hex::encode(random);
        let file = open_file(&directory, &id, true, true)?;
        file.sync_all()?;
        directory.sync_all()?;
        let time = now()?;
        tx.execute(
            "INSERT INTO uploads VALUES(?1,?2,?3,0,'RECEIVING',NULL,?4,?4)",
            params![id, size, package_sha256, time],
        )?;
        let upload = read_upload(&tx, &id)?;
        reserve(&tx, request, &hash, &upload)?;
        event(&tx, None, "UPLOAD_RECEIVING", None)?;
        tx.commit()?;
        Ok(upload)
    }
    /// Chunk retries use resume's durable offset. No raw writable handle escapes this API.
    pub fn append_upload(&mut self, id: &str, offset: u64, bytes: &[u8]) -> Result<Upload> {
        require(id_ok(id), "UPLOAD_ID_INVALID")?;
        require(
            !bytes.is_empty() && bytes.len() <= MAX_CHUNK_BYTES,
            "UPLOAD_CHUNK_INVALID",
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let upload = read_upload(&tx, id)?;
        require(upload.state == UploadState::Receiving, "UPLOAD_CLOSED")?;
        require(offset == upload.committed_offset, "UPLOAD_OFFSET_CONFLICT")?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Rejected("UPLOAD_SIZE_MISMATCH"))?;
        require(end <= upload.size, "UPLOAD_SIZE_MISMATCH")?;
        let directory = spool(&self._directory, "uploads")?;
        space(&directory, bytes.len() as u64)?;
        let mut file = open_file(&directory, id, true, false)?;
        lock(&file)?;
        reconcile(&file, &upload)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        tx.execute(
            "UPDATE uploads SET committed_offset=?1,updated_ms=?2 WHERE upload_id=?3",
            params![end, now()?, id],
        )?;
        let result = read_upload(&tx, id)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn resume_upload(&mut self, request: &Request) -> Result<Upload> {
        request
            .validate_for_instance(&self.instance.instance_id)
            .map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
        let Command::ResumeUpload { upload_id } = &request.command else {
            return Err(Error::Rejected("STATE_COMMAND_UNSUPPORTED"));
        };
        let hash = request_digest(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = prior_upload(&tx, request, &hash)?;
        let upload = read_upload(&tx, upload_id)?;
        if upload.state == UploadState::Receiving {
            let directory = spool(&self._directory, "uploads")?;
            let file = open_file(&directory, upload_id, true, false)?;
            lock(&file)?;
            reconcile(&file, &upload)?;
        }
        if old.is_none() {
            reserve(&tx, request, &hash, &upload)?;
        }
        tx.commit()?;
        Ok(upload)
    }
    /// Persist intent before copying into a NEW private inode. Retry reconciles an existing
    /// sealed copy by its complete hash. Copying/hashing never holds the SQLite writer lock.
    pub fn finalize_upload(&mut self, request: &Request) -> Result<Upload> {
        request
            .validate_for_instance(&self.instance.instance_id)
            .map_err(|_| Error::Rejected("STATE_REQUEST_INVALID"))?;
        let Command::FinalizeUpload { upload_id } = &request.command else {
            return Err(Error::Rejected("STATE_COMMAND_UNSUPPORTED"));
        };
        let hash = request_digest(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = prior_upload(&tx, request, &hash)?;
        let upload = read_upload(&tx, upload_id)?;
        if matches!(upload.state, UploadState::Sealed | UploadState::Rejected) {
            if old.is_none() {
                reserve(&tx, request, &hash, &upload)?;
            }
            tx.commit()?;
            return Ok(upload);
        }
        require(upload.committed_offset == upload.size, "UPLOAD_INCOMPLETE")?;
        let ingress = spool(&self._directory, "uploads")?;
        let mut input = open_file(&ingress, upload_id, false, false)?;
        lock(&input)?;
        require(
            input.metadata()?.len() == upload.size,
            "UPLOAD_SIZE_MISMATCH",
        )?;
        if old.is_none() {
            reserve(&tx, request, &hash, &upload)?;
        }
        tx.execute(
            "UPDATE uploads SET state='SEALING',updated_ms=?1 WHERE upload_id=?2",
            params![now()?, upload_id],
        )?;
        if upload.state == UploadState::Receiving {
            event(&tx, None, "UPLOAD_SEALING", None)?;
        }
        tx.commit()?;
        let directory = spool(&self._directory, "artifacts")?;
        let final_name = format!("{upload_id}.uli4");
        let existing = match fs::statat(
            &directory,
            final_name.as_str(),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(e) => return Err(e.into()),
        };
        let actual = if existing {
            let mut artifact = open_file(&directory, &final_name, false, false)?;
            let actual = digest(&mut artifact, upload.size)?;
            artifact.sync_all()?;
            actual
        } else {
            space(&directory, upload.size)?;
            let temporary = format!(".pending-{upload_id}");
            let mut output = match open_file(&directory, &temporary, true, true) {
                Ok(f) => f,
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    open_file(&directory, &temporary, true, false)?
                }
                Err(e) => return Err(e),
            };
            lock(&output)?;
            output.set_len(0)?;
            let mut buffer = [0u8; 65536];
            let mut sha = Sha256::new();
            let mut copied = 0u64;
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                copied = copied
                    .checked_add(n as u64)
                    .ok_or(Error::Rejected("UPLOAD_SIZE_MISMATCH"))?;
                require(copied <= upload.size, "UPLOAD_SIZE_MISMATCH")?;
                output.write_all(&buffer[..n])?;
                sha.update(&buffer[..n]);
            }
            require(copied == upload.size, "UPLOAD_SIZE_MISMATCH")?;
            output.sync_all()?;
            let actual = hex::encode(sha.finalize());
            if actual == upload.package_sha256 {
                fs::renameat_with(
                    &directory,
                    temporary.as_str(),
                    &directory,
                    final_name.as_str(),
                    RenameFlags::NOREPLACE,
                )?;
                directory.sync_all()?;
            }
            actual
        };
        let success = actual == upload.package_sha256;
        // A prior attempt may have renamed before failing at directory fsync.
        if success {
            directory.sync_all()?;
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_upload(&tx, upload_id)?;
        require(
            current.state == UploadState::Sealing,
            "UPLOAD_STATE_CONFLICT",
        )?;
        tx.execute(
            "UPDATE uploads SET state=?1,error_code=?2,updated_ms=?3 WHERE upload_id=?4",
            params![
                if success { "SEALED" } else { "REJECTED" },
                if success {
                    None
                } else {
                    Some("UPLOAD_HASH_MISMATCH")
                },
                now()?,
                upload_id
            ],
        )?;
        event(
            &tx,
            None,
            if success {
                "UPLOAD_SEALED"
            } else {
                "UPLOAD_REJECTED"
            },
            if success {
                None
            } else {
                Some("UPLOAD_HASH_MISMATCH")
            },
        )?;
        let result = read_upload(&tx, upload_id)?;
        tx.commit()?;
        Ok(result)
    }
    /// Read-only handle from agent-owned artifact storage, freshly rehashed on access.
    /// This proves transport integrity only; the caller MUST still verify ULI4 trust.
    pub fn open_sealed_upload(&self, id: &str) -> Result<File> {
        require(id_ok(id), "UPLOAD_ID_INVALID")?;
        let upload = read_upload(&self.connection, id)?;
        require(
            upload.state == UploadState::Sealed && upload.size <= MAX_UPLOAD_BYTES,
            "UPLOAD_NOT_SEALED",
        )?;
        let directory = spool(&self._directory, "artifacts")?;
        let mut file = open_file(&directory, &format!("{id}.uli4"), false, false)?;
        require(
            digest(&mut file, upload.size)? == upload.package_sha256,
            "UPLOAD_HASH_MISMATCH",
        )?;
        Ok(file)
    }
}
