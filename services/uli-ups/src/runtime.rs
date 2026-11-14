//! Export a verified immutable source snapshot into a separate build workspace.
//! This is preparation only: no activation, Store transition or arbitrary commands.
use crate::{Error, Result, identifier, require};
use rustix::fs::{
    self as fs, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};
use uli4::linux::PreparedTree as LinuxPreparedTree;

fn flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}
fn directory(parent: &File, name: &str) -> Result<File> {
    Ok(fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        flags(),
    )?
    .into())
}
fn anchor(path: &Path, mode: u32, gid: Option<u32>) -> Result<File> {
    require(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "RUNTIME_PATH_INVALID",
    )?;
    let mut dir = File::open("/")?;
    for part in path.components() {
        if let Component::Normal(name) = part {
            // A configured root may be a mount; no symlinks in its ancestors.
            dir = fs::openat2(
                &dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?
            .into();
            let m = dir.metadata()?;
            require(
                (m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                    && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
                "RUNTIME_PARENT_UNSAFE",
            )?;
        }
    }
    let m = dir.metadata()?;
    require(
        m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == mode
            && gid.is_none_or(|g| m.gid() == g),
        "RUNTIME_ROOT_UNSAFE",
    )?;
    Ok(dir)
}
fn child_root(parent: &File, name: &str, mode: u32, gid: u32) -> Result<File> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {
            let dir = directory(parent, name)?;
            fs::fchown(&dir, None, Some(rustix::process::Gid::from_raw(gid)))?;
            fs::fchmod(&dir, Mode::from_raw_mode(mode))?;
            dir.sync_all()?;
            parent.sync_all()?;
        }
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    let dir = directory(parent, name)?;
    let m = dir.metadata()?;
    require(
        m.uid() == rustix::process::geteuid().as_raw()
            && m.gid() == gid
            && m.mode() & 0o7777 == mode
            && m.dev() == parent.metadata()?.dev(),
        "RUNTIME_ROOT_UNSAFE",
    )?;
    Ok(dir)
}
#[derive(Debug, serde::Serialize)]
pub struct ExportedWorkspace {
    pub release_id: String,
    pub source_digest: String,
    pub files: usize,
    pub bytes: u64,
}
pub struct WorkspacePool {
    root: File,
    releases: File,
    staging: File,
    runtime_gid: u32,
    #[cfg(test)]
    fence_fault: std::cell::Cell<bool>,
}
impl WorkspacePool {
    // Re-establish cross-directory publication durability after an interrupted
    // export as well as on normal publication. Visibility alone is insufficient.
    fn fence(&self) -> Result<()> {
        #[cfg(test)]
        require(!self.fence_fault.get(), "RUNTIME_SYNC_FAULT")?;
        self.releases.sync_all()?;
        self.staging.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    /// Paths/GID must come from trusted host policy, never from a package.
    /// root: agent-owned 0750, group runtime_gid. Group cannot rename children.
    pub fn open(root: &Path, runtime_gid: u32) -> Result<Self> {
        require(
            rustix::process::geteuid().as_raw() != 0 && runtime_gid != 0,
            "RUNTIME_NONROOT_REQUIRED",
        )?;
        let root = anchor(root, 0o750, Some(runtime_gid))?;
        fs::flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error("RUNTIME_POOL_BUSY"))?;
        let releases = child_root(&root, "releases", 0o750, runtime_gid)?;
        let staging = child_root(&root, "staging", 0o700, runtime_gid)?;
        let pool = Self {
            root,
            releases,
            staging,
            runtime_gid,
            #[cfg(test)]
            fence_fault: std::cell::Cell::new(false),
        };
        pool.fence()?;
        Ok(pool)
    }
    /// Requires the existing SDK PreparedTree token; copies only its signed file list
    /// and rehashes every byte. Failed staging is retained privately, never published.
    pub fn export(
        &self,
        source_pool: &Path,
        prepared: &LinuxPreparedTree,
        cancel: &AtomicBool,
    ) -> Result<ExportedWorkspace> {
        let base = prepared.base_release();
        let id = prepared.release_id();
        require(identifier(id), "RUNTIME_RELEASE_INVALID")?;
        require(!cancel.load(Ordering::Relaxed), "RUNTIME_CANCELLED")?;
        // Validate the entire list before creating output.
        for record in base.files() {
            uli4::validate_path(&record.path)?;
            let first = record.path.split('/').next().unwrap_or("");
            let folded = caseless::default_case_fold_str(first);
            require(
                !uli4::denied_path(&record.path)
                    && !matches!(folded.as_str(), "uliups" | "uli-ups"),
                "RUNTIME_PROTECTED_PATH",
            )?;
        }
        match fs::statat(&self.releases, id, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(Error("RUNTIME_RELEASE_EXISTS")),
            Err(e) => return Err(e.into()),
        }
        let sources = anchor(source_pool, 0o700, None)?;
        let source = directory(&sources, id)?;
        let sm = source.metadata()?;
        require(
            sm.uid() == rustix::process::geteuid().as_raw()
                && sm.mode() & 0o7777 == 0o700
                && sm.dev() == sources.metadata()?.dev(),
            "RUNTIME_SOURCE_UNSAFE",
        )?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error("RUNTIME_RANDOM_UNAVAILABLE"))?;
        let temporary = format!(".prepare-{}", hex::encode(random));
        fs::mkdirat(
            &self.staging,
            temporary.as_str(),
            Mode::from_raw_mode(0o700),
        )?;
        let work = directory(&self.staging, &temporary)?;
        let mut dirs = BTreeSet::new();
        let mut bytes = 0u64;
        for record in base.files() {
            require(!cancel.load(Ordering::Relaxed), "RUNTIME_CANCELLED")?;
            let mut parent = work.try_clone()?;
            let parts: Vec<_> = record.path.split('/').collect();
            let mut relative = String::new();
            for part in &parts[..parts.len() - 1] {
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(part);
                match fs::mkdirat(&parent, *part, Mode::from_raw_mode(0o700)) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                parent = directory(&parent, part)?;
                dirs.insert(relative.clone());
            }
            let mut input: File = fs::openat2(
                &source,
                record.path.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                flags(),
            )?
            .into();
            let before = input.metadata()?;
            require(
                before.is_file()
                    && before.uid() == rustix::process::geteuid().as_raw()
                    && before.nlink() == 1
                    && before.mode() & 0o7777 == 0o644
                    && before.len() == record.size
                    && before.dev() == sm.dev(),
                "RUNTIME_SOURCE_UNSAFE",
            )?;
            let mut output: File = fs::openat2(
                &parent,
                *parts.last().ok_or(Error("RUNTIME_PATH_INVALID"))?,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
                flags(),
            )?
            .into();
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                require(!cancel.load(Ordering::Relaxed), "RUNTIME_CANCELLED")?;
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                count = count
                    .checked_add(n as u64)
                    .ok_or(Error("RUNTIME_SOURCE_MISMATCH"))?;
                require(count <= record.size, "RUNTIME_SOURCE_MISMATCH")?;
                output.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
            }
            require(
                count == record.size && hex::encode(hash.finalize()) == record.sha256,
                "RUNTIME_SOURCE_MISMATCH",
            )?;
            fs::fchown(
                &output,
                None,
                Some(rustix::process::Gid::from_raw(self.runtime_gid)),
            )?;
            fs::fchmod(&output, Mode::from_raw_mode(0o660))?;
            output.sync_all()?;
            bytes = bytes
                .checked_add(count)
                .ok_or(Error("RUNTIME_SOURCE_MISMATCH"))?;
        }
        // All permission changes happen below inaccessible staging/ (0700).
        // Bottom-up sync makes children durable before their parents and publication.
        for relative in dirs.iter().rev() {
            let dir = directory(&work, relative)?;
            fs::fchown(
                &dir,
                None,
                Some(rustix::process::Gid::from_raw(self.runtime_gid)),
            )?;
            fs::fchmod(&dir, Mode::from_raw_mode(0o2770))?;
            dir.sync_all()?;
        }
        fs::fchown(
            &work,
            None,
            Some(rustix::process::Gid::from_raw(self.runtime_gid)),
        )?;
        fs::fchmod(&work, Mode::from_raw_mode(0o2770))?;
        work.sync_all()?;
        self.staging.sync_all()?;
        require(!cancel.load(Ordering::Relaxed), "RUNTIME_CANCELLED")?;
        // Never overwrite a previous workspace (including a partially built one).
        fs::renameat_with(
            &self.staging,
            temporary.as_str(),
            &self.releases,
            id,
            RenameFlags::NOREPLACE,
        )?;
        self.fence()?;
        Ok(ExportedWorkspace {
            release_id: id.into(),
            source_digest: base.digest().into(),
            files: base.files().len(),
            bytes,
        })
    }
    /// Only selects an existing, correctly owned exported leaf. The controller must
    /// record intent and prove its build unit is stopped before invoking this.
    pub fn select_build(&self, release_id: &str) -> Result<()> {
        require(identifier(release_id), "RUNTIME_RELEASE_INVALID")?;
        let leaf = directory(&self.releases, release_id)?;
        let m = leaf.metadata()?;
        require(
            m.uid() == rustix::process::geteuid().as_raw()
                && m.gid() == self.runtime_gid
                && m.mode() & 0o7777 == 0o2770,
            "RUNTIME_WORKSPACE_UNSAFE",
        )?;
        self.fence()?;
        match fs::statat(&self.root, "build-current", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(m) => require(
                FileType::from_raw_mode(m.st_mode) == FileType::Symlink
                    && m.st_uid == rustix::process::geteuid().as_raw(),
                "RUNTIME_SELECTION_UNSAFE",
            )?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error("RUNTIME_RANDOM_UNAVAILABLE"))?;
        let temporary = format!(".selection-{}", hex::encode(random));
        fs::symlinkat(
            format!("releases/{release_id}"),
            &self.root,
            temporary.as_str(),
        )?;
        self.root.sync_all()?;
        fs::renameat(&self.root, temporary.as_str(), &self.root, "build-current")?;
        self.root.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod durability_regression {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn visible_target_cannot_be_selected_before_its_publication_is_fenced() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
        let gid = rustix::process::getegid().as_raw();
        let pool = WorkspacePool::open(&root, gid).unwrap();
        // Simulate rename having succeeded while its acknowledgement fence failed.
        fs::mkdirat(&pool.staging, "pending", Mode::from_raw_mode(0o700)).unwrap();
        let leaf = directory(&pool.staging, "pending").unwrap();
        fs::fchown(&leaf, None, Some(rustix::process::Gid::from_raw(gid))).unwrap();
        fs::fchmod(&leaf, Mode::from_raw_mode(0o2770)).unwrap();
        leaf.sync_all().unwrap();
        fs::renameat(&pool.staging, "pending", &pool.releases, "r1").unwrap();
        pool.fence_fault.set(true);
        assert_eq!(pool.select_build("r1").unwrap_err().0, "RUNTIME_SYNC_FAULT");
        assert!(std::fs::symlink_metadata(root.join("build-current")).is_err());
        pool.fence_fault.set(false);
        pool.select_build("r1").unwrap();
        assert_eq!(
            std::fs::read_link(root.join("build-current")).unwrap(),
            Path::new("releases/r1")
        );
        drop(pool);
        let reopened = WorkspacePool::open(&root, gid).unwrap();
        reopened.select_build("r1").unwrap();
    }
}
