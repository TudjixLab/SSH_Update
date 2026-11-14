use crate::{FileRecord, Limits, Result, ensure, model::validate_files};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[derive(Debug)]
pub struct Preview {
    pub files: Vec<FileRecord>,
    pub excluded: Vec<String>,
}
pub(crate) fn plain_file(path: &Path) -> Result<File> {
    let m = fs::symlink_metadata(path)?;
    ensure(
        m.is_file() && !m.file_type().is_symlink(),
        "ULI4_PATH_REJECTED",
    )?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        ensure(m.file_attributes() & 0x400 == 0, "ULI4_PATH_REJECTED")?;
        options.custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        ensure(m.nlink() == 1, "ULI4_PATH_REJECTED")?;
        // O_NOFOLLOW on the initial Linux target. Other Unix targets are not supported.
        #[cfg(target_os = "linux")]
        options.custom_flags(0x20000);
    }
    let f = options.open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: open handle remains alive; Win32 initializes info on success.
        let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, info.as_mut_ptr()) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let info = unsafe { info.assume_init() };
        ensure(
            info.nNumberOfLinks == 1 && info.dwFileAttributes & 0x400 == 0,
            "ULI4_PATH_REJECTED",
        )?;
    }
    ensure(f.metadata()?.is_file(), "ULI4_PATH_REJECTED")?;
    Ok(f)
}
pub(crate) fn hash_copy(
    mut input: impl Read,
    mut output: impl Write,
    limit: u64,
) -> Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or(crate::Error::Rejected("ULI4_QUOTA_EXCEEDED"))?;
        ensure(size <= limit, "ULI4_QUOTA_EXCEEDED")?;
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    Ok((size, hex::encode(hash.finalize())))
}
pub fn scan(root: &Path, limits: &Limits) -> Result<Preview> {
    let root_meta = fs::symlink_metadata(root)?;
    ensure(
        root_meta.is_dir() && !root_meta.file_type().is_symlink(),
        "ULI4_PATH_REJECTED",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            root_meta.file_attributes() & 0x400 == 0,
            "ULI4_PATH_REJECTED",
        )?;
    }
    let mut result = Preview {
        files: vec![],
        excluded: vec![],
    };
    fn walk(
        root: &Path,
        relative: &Path,
        r: &mut Preview,
        l: &Limits,
        used: &mut u64,
    ) -> Result<()> {
        for entry in fs::read_dir(root.join(relative))? {
            let entry = entry?;
            let rel: PathBuf = relative.join(entry.file_name());
            let raw = rel
                .to_str()
                .ok_or(crate::Error::Rejected("ULI4_PATH_REJECTED"))?;
            #[cfg(windows)]
            let name = raw.replace('\\', "/");
            #[cfg(not(windows))]
            let name = raw.to_owned();
            crate::validate_path(&name)?;
            if crate::denied_path(&name) {
                r.excluded.push(name);
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            ensure(!meta.file_type().is_symlink(), "ULI4_PATH_REJECTED")?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                ensure(meta.file_attributes() & 0x400 == 0, "ULI4_PATH_REJECTED")?;
            }
            if meta.is_dir() {
                walk(root, &rel, r, l, used)?;
            } else {
                let remaining = l.plain_bytes.saturating_sub(*used).min(l.file_bytes);
                ensure(meta.len() <= remaining, "ULI4_QUOTA_EXCEEDED")?;
                let (size, sha256) =
                    hash_copy(plain_file(&entry.path())?, std::io::sink(), remaining)?;
                *used += size;
                r.files.push(FileRecord {
                    path: name,
                    sha256,
                    size,
                    mode: 0o644,
                });
                ensure(r.files.len() as u64 <= l.max_files, "ULI4_QUOTA_EXCEEDED")?;
            }
        }
        Ok(())
    }
    let mut total = 0u64;
    walk(root, Path::new(""), &mut result, limits, &mut total)?;
    result.files.sort_by(|a, b| a.path.cmp(&b.path));
    result.excluded.sort();
    validate_files(&result.files, limits)?;
    Ok(result)
}
pub fn tree_digest(files: &[FileRecord]) -> Result<String> {
    validate_files(files, &Limits::default())?;
    let mut h = Sha256::new();
    h.update(b"ULI4-TREE-V1\0");
    h.update((files.len() as u64).to_le_bytes());
    for f in files {
        h.update((f.path.len() as u32).to_le_bytes());
        h.update(f.path.as_bytes());
        h.update(f.size.to_le_bytes());
        h.update(f.mode.to_le_bytes());
        h.update(hex::decode(&f.sha256).map_err(|_| crate::Error::Rejected("ULI4_FILE_INVALID"))?);
    }
    Ok(hex::encode(h.finalize()))
}
