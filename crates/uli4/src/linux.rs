//! Linux-only preparation of inactive release trees. No service or current-pointer changes.
//! Requires a dedicated 0700 agent-owned release pool on a Linux filesystem.
use crate::{
    BaseRelease, Error, FileRecord, OperationKind, PackageKind, Result, VerifiedPackage, ensure,
    tree::hash_copy,
};
use rustix::fs::{
    self as fs, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Component, Path},
};

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
const MAX_DIRECTORIES: usize = 100_000;
const RESERVED_FREE_BYTES: u64 = 16 * 1024 * 1024;
fn resolve() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}
fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}
fn storage_name(s: &str) -> Result<()> {
    ensure(
        !s.is_empty()
            && s.len() <= 128
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)),
        "ULI4_STORAGE_NAME_INVALID",
    )
}
fn open_dir(parent: &File, name: &str) -> Result<File> {
    Ok(fs::openat2(parent, name, dir_flags(), Mode::empty(), resolve())?.into())
}
fn private_dir(file: &File, device: Option<u64>) -> Result<()> {
    let m = file.metadata()?;
    ensure(
        m.is_dir()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o700
            && device.is_none_or(|d| m.dev() == d),
        "ULI4_STORAGE_NOT_PRIVATE",
    )
}
fn source_file(parent: &File, name: &str, device: u64) -> Result<File> {
    let file: File = fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        resolve(),
    )?
    .into();
    let m = file.metadata()?;
    ensure(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o644
            && m.dev() == device,
        "ULI4_SOURCE_UNSAFE",
    )?;
    Ok(file)
}
fn directories(files: &[FileRecord]) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for f in files {
        for (i, _) in f.path.match_indices('/') {
            set.insert(f.path[..i].to_owned());
            ensure(set.len() <= MAX_DIRECTORIES, "ULI4_QUOTA_EXCEEDED")?;
        }
    }
    ensure(set.len() <= MAX_DIRECTORIES, "ULI4_QUOTA_EXCEEDED")?;
    Ok(set)
}
/// Holds an exclusive advisory lease for this release pool. No global server access.
pub struct PrivateRoot {
    directory: File,
    device: u64,
    inode: u64,
}
/// Verified, synced inactive source tree. This is not a successful deployment.
pub struct PreparedTree {
    directory: File,
    release: BaseRelease,
    root_device: u64,
    root_inode: u64,
    _lease: File,
}
impl PreparedTree {
    pub fn release_id(&self) -> &str {
        self.release.release_id()
    }
    pub fn base_release(&self) -> BaseRelease {
        self.release.clone()
    }
}
impl PrivateRoot {
    pub fn open(path: &Path) -> Result<Self> {
        ensure(
            path.is_absolute()
                && path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "ULI4_STORAGE_PATH_INVALID",
        )?;
        let slash = File::open("/")?;
        let relative = path
            .strip_prefix("/")
            .map_err(|_| Error::Rejected("ULI4_STORAGE_PATH_INVALID"))?;
        ensure(
            !relative.as_os_str().is_empty(),
            "ULI4_STORAGE_PATH_INVALID",
        )?;
        // Root itself may be a mount; nested mounts beneath it are forbidden.
        let directory: File = fs::openat2(
            &slash,
            relative,
            dir_flags(),
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?
        .into();
        private_dir(&directory, None)?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error::Rejected("ULI4_STORAGE_BUSY"))?;
        let m = directory.metadata()?;
        Ok(Self {
            directory,
            device: m.dev(),
            inode: m.ino(),
        })
    }
    pub fn load_base(&self, name: &str, expected: &BaseRelease) -> Result<PreparedTree> {
        storage_name(name)?;
        ensure(name == expected.release_id(), "ULI4_BASE_MISMATCH")?;
        let directory = open_dir(&self.directory, name)?;
        verify_tree(&directory, expected, self.device)?;
        self.prepared(directory, expected.clone())
    }
    fn prepared(&self, directory: File, release: BaseRelease) -> Result<PreparedTree> {
        Ok(PreparedTree {
            directory,
            release,
            root_device: self.device,
            root_inode: self.inode,
            _lease: self.directory.try_clone()?,
        })
    }
    pub fn prepare(
        &self,
        package: &mut VerifiedPackage,
        base: Option<&PreparedTree>,
    ) -> Result<PreparedTree> {
        private_dir(&self.directory, Some(self.device))?;
        let manifest = package.manifest().clone();
        storage_name(&manifest.release_id)?;
        if manifest.kind == PackageKind::Incremental {
            let b = base.ok_or(Error::Rejected("ULI4_BASE_MISMATCH"))?;
            ensure(
                b.release.app_id() == manifest.app_id
                    && b.root_device == self.device
                    && b.root_inode == self.inode
                    && Some(b.release.release_id()) == manifest.base_release_id.as_deref()
                    && Some(b.release.digest()) == manifest.base_state_digest.as_deref(),
                "ULI4_BASE_MISMATCH",
            )?;
            verify_tree(&b.directory, &b.release, self.device)?;
        } else {
            ensure(base.is_none(), "ULI4_BASE_MISMATCH")?;
        }
        match fs::statat(
            &self.directory,
            manifest.release_id.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(Error::Rejected("ULI4_DESTINATION_EXISTS")),
        }
        let result = package.base_release();
        let dirs = directories(result.files())?;
        let total = result
            .files()
            .iter()
            .try_fold(0u64, |s, f| s.checked_add(f.size))
            .ok_or(Error::Rejected("ULI4_QUOTA_EXCEEDED"))?;
        let space = fs::fstatvfs(&self.directory)?;
        let free = space.f_bavail.saturating_mul(space.f_frsize);
        ensure(
            free >= total.saturating_add(RESERVED_FREE_BYTES)
                && (space.f_files == 0
                    || space.f_favail > result.files().len() as u64 + dirs.len() as u64),
            "ULI4_INSUFFICIENT_SPACE",
        )?;
        let staging_name = format!(".pending-{}", manifest.release_id);
        // Never reuse or clean an existing tree: recovery/cleanup belongs to the job engine.
        fs::mkdirat(
            &self.directory,
            staging_name.as_str(),
            Mode::from_raw_mode(0o700),
        )?;
        let staging = open_dir(&self.directory, &staging_name)?;
        fs::fchmod(&staging, Mode::from_raw_mode(0o700))?;
        private_dir(&staging, Some(self.device))?;
        self.directory.sync_all()?;
        for dir in &dirs {
            let (parent, name) = split(dir);
            let parent = if parent.is_empty() {
                staging.try_clone()?
            } else {
                open_dir(&staging, parent)?
            };
            fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700))?;
            let created = open_dir(&parent, name)?;
            fs::fchmod(&created, Mode::from_raw_mode(0o700))?;
            private_dir(&created, Some(self.device))?;
        }
        let changed: BTreeMap<_, _> = manifest
            .file_operations
            .iter()
            .enumerate()
            .filter(|(_, o)| o.kind != OperationKind::Delete)
            .map(|(i, o)| (o.file.path.as_str(), i))
            .collect();
        for record in result.files() {
            let (parent, name) = split(&record.path);
            let parent = if parent.is_empty() {
                staging.try_clone()?
            } else {
                open_dir(&staging, parent)?
            };
            let mut output: File = fs::openat2(
                &parent,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
                resolve(),
            )?
            .into();
            if let Some(index) = changed.get(record.path.as_str()) {
                package.copy_file(*index, &mut output)?;
            } else {
                let base = base.ok_or(Error::Rejected("ULI4_BASE_MISMATCH"))?;
                let source = source_file(&base.directory, &record.path, self.device)?;
                let (size, hash) = hash_copy(&source, &mut output, record.size)?;
                ensure(
                    size == record.size && hash == record.sha256,
                    "ULI4_BASE_MISMATCH",
                )?;
                let m = source.metadata()?;
                ensure(
                    m.nlink() == 1 && m.is_file() && m.len() == record.size,
                    "ULI4_SOURCE_CHANGED",
                )?;
            }
            fs::fchmod(&output, Mode::from_raw_mode(0o644))?;
            let m = output.metadata()?;
            ensure(
                m.is_file()
                    && m.nlink() == 1
                    && m.len() == record.size
                    && m.mode() & 0o7777 == 0o644
                    && m.dev() == self.device,
                "ULI4_OUTPUT_UNSAFE",
            )?;
            output.sync_all()?;
        }
        verify_tree(&staging, &result, self.device)?;
        // Sync children before their parents. No writable file handles escape this function.
        for name in dirs.iter().rev() {
            open_dir(&staging, name)?.sync_all()?;
        }
        staging.sync_all()?;
        let before = staging.metadata()?;
        let linked = open_dir(&self.directory, &staging_name)?.metadata()?;
        ensure(
            before.dev() == linked.dev() && before.ino() == linked.ino(),
            "ULI4_STORAGE_CHANGED",
        )?;
        fs::renameat_with(
            &self.directory,
            staging_name.as_str(),
            &self.directory,
            manifest.release_id.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        let published = open_dir(&self.directory, &manifest.release_id)?.metadata()?;
        ensure(
            before.dev() == published.dev() && before.ino() == published.ino(),
            "ULI4_STORAGE_CHANGED",
        )?;
        self.directory.sync_all()?;
        self.prepared(staging, result)
    }
}
fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}
fn verify_tree(directory: &File, expected: &BaseRelease, device: u64) -> Result<()> {
    private_dir(directory, Some(device))?;
    let dirs = directories(expected.files())?;
    let files: BTreeMap<_, _> = expected
        .files()
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    let mut seen = BTreeSet::new();
    let mut seen_dirs = BTreeSet::new();
    fn walk(
        directory: &File,
        prefix: &str,
        device: u64,
        files: &BTreeMap<&str, &FileRecord>,
        dirs: &BTreeSet<String>,
        seen: &mut BTreeSet<String>,
        seen_dirs: &mut BTreeSet<String>,
    ) -> Result<()> {
        for entry in fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| Error::Rejected("ULI4_PATH_REJECTED"))?;
            if matches!(name, "." | "..") {
                continue;
            }
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            crate::validate_path(&path)?;
            let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    ensure(
                        dirs.contains(&path) && seen_dirs.insert(path.clone()),
                        "ULI4_TREE_MISMATCH",
                    )?;
                    let child = open_dir(directory, name)?;
                    private_dir(&child, Some(device))?;
                    walk(&child, &path, device, files, dirs, seen, seen_dirs)?;
                }
                FileType::RegularFile => {
                    let record = files
                        .get(path.as_str())
                        .ok_or(Error::Rejected("ULI4_TREE_MISMATCH"))?;
                    ensure(seen.insert(path), "ULI4_TREE_MISMATCH")?;
                    let source = source_file(directory, name, device)?;
                    let (size, hash) = hash_copy(&source, std::io::sink(), record.size)?;
                    ensure(
                        size == record.size
                            && hash == record.sha256
                            && source.metadata()?.nlink() == 1,
                        "ULI4_TREE_MISMATCH",
                    )?;
                }
                _ => return Err(Error::Rejected("ULI4_SOURCE_UNSAFE")),
            }
        }
        Ok(())
    }
    walk(
        directory,
        "",
        device,
        &files,
        &dirs,
        &mut seen,
        &mut seen_dirs,
    )?;
    ensure(
        seen.len() == files.len() && seen_dirs.len() == dirs.len(),
        "ULI4_TREE_MISMATCH",
    )
}
