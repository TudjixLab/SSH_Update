//! Fixed npm build worker. Must run as the configured runtime user inside its
//! root-configured systemd sandbox; it never elevates privileges or activates a site.
use crate::{
    Error, Result, identifier,
    process::{ChildGuard, drain, nonblock},
    require,
};
use rustix::fs::{self as fs, FlockOperation, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    policy_version: u16,
    instance_id: String,
    agent_uid: u32,
    runtime_uid: u32,
    runtime_gid: u32,
    runtime_root: PathBuf,
    cache_directory: PathBuf,
    node_executable: PathBuf,
    npm_entrypoint: PathBuf,
    node_major: u16,
    build_unit: String,
    install_deadline_ms: u32,
    build_deadline_ms: u32,
    max_memory_bytes: u64,
    max_tasks: u16,
    max_cpu_percent: u16,
}
fn small(path: &Path, limit: usize) -> Result<String> {
    let file: File = fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    require(bytes.len() <= limit, "BUILD_CONTEXT_TOO_LARGE")?;
    String::from_utf8(bytes).map_err(|_| Error("BUILD_CONTEXT_INVALID"))
}
fn plain_path(path: &Path) -> Result<()> {
    require(
        path.is_absolute()
            && path
                .components()
                .all(|p| matches!(p, Component::RootDir | Component::Normal(_))),
        "BUILD_PATH_INVALID",
    )
}
fn open_directory(path: &Path, agent_uid: u32, leaf_runtime: Option<u32>) -> Result<File> {
    plain_path(path)?;
    let mut directory = File::open("/")?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|p| {
            if let Component::Normal(n) = p {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    for (i, name) in parts.iter().enumerate() {
        directory = fs::openat2(
            &directory,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?
        .into();
        let m = directory.metadata()?;
        let leaf = i + 1 == parts.len();
        require(
            (m.uid() == 0 || m.uid() == agent_uid || (leaf && leaf_runtime == Some(m.uid())))
                && m.mode() & 0o022 == 0,
            "BUILD_PARENT_UNSAFE",
        )?;
    }
    Ok(directory)
}
fn program(path: &Path, script: bool) -> Result<()> {
    plain_path(path)?;
    let parent = path.parent().ok_or(Error("BUILD_PATH_INVALID"))?;
    let dir = open_directory(parent, 0, None)?;
    let file: File = fs::openat2(
        &dir,
        path.file_name().ok_or(Error("BUILD_PATH_INVALID"))?,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?
    .into();
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o7022 == 0
            && (script || m.mode() & 0o111 != 0),
        "BUILD_LAUNCHER_UNSAFE",
    )
}
fn context(policy: &Policy) -> Result<PathBuf> {
    let status = small(Path::new("/proc/self/status"), 65536)?;
    for (key, expected) in [
        ("NoNewPrivs", "1"),
        ("CapEff", "0000000000000000"),
        ("CapPrm", "0000000000000000"),
        ("CapAmb", "0000000000000000"),
    ] {
        require(
            status.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, value)| name == key && value.trim() == expected)
            }),
            "BUILD_SANDBOX_REQUIRED",
        )?;
    }
    let groups = status
        .lines()
        .find_map(|s| s.strip_prefix("Groups:"))
        .ok_or(Error("BUILD_GROUPS_INVALID"))?;
    require(
        groups
            .split_whitespace()
            .all(|g| g.parse::<u32>().ok() == Some(policy.runtime_gid)),
        "BUILD_GROUPS_INVALID",
    )?;
    let cg = small(Path::new("/proc/self/cgroup"), 65536)?;
    let expected = format!("0::/system.slice/{}", policy.build_unit);
    require(
        cg.lines().count() == 1 && cg.trim() == expected,
        "BUILD_CGROUP_MISMATCH",
    )?;
    let root = PathBuf::from("/sys/fs/cgroup/system.slice").join(&policy.build_unit);
    let m = std::fs::metadata(&root)?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "BUILD_DELEGATED_CGROUP_FORBIDDEN",
    )?;
    let memory = small(&root.join("memory.max"), 64)?
        .trim()
        .parse::<u64>()
        .map_err(|_| Error("BUILD_RESOURCE_LIMIT_REQUIRED"))?;
    let tasks = small(&root.join("pids.max"), 64)?
        .trim()
        .parse::<u64>()
        .map_err(|_| Error("BUILD_RESOURCE_LIMIT_REQUIRED"))?;
    require(
        memory <= policy.max_memory_bytes && tasks <= u64::from(policy.max_tasks),
        "BUILD_RESOURCE_LIMIT_REQUIRED",
    )?;
    let cpu = small(&root.join("cpu.max"), 128)?;
    let fields: Vec<_> = cpu.split_whitespace().collect();
    require(fields.len() == 2, "BUILD_RESOURCE_LIMIT_REQUIRED")?;
    let quota = fields[0]
        .parse::<u64>()
        .map_err(|_| Error("BUILD_RESOURCE_LIMIT_REQUIRED"))?;
    let period = fields[1]
        .parse::<u64>()
        .map_err(|_| Error("BUILD_RESOURCE_LIMIT_REQUIRED"))?;
    require(
        quota > 0
            && period > 0
            && quota
                .checked_mul(100)
                .zip(period.checked_mul(u64::from(policy.max_cpu_percent)))
                .is_some_and(|(a, b)| a <= b),
        "BUILD_RESOURCE_LIMIT_REQUIRED",
    )?;
    let mounts = small(Path::new("/proc/self/mountinfo"), 1024 * 1024)?;
    require(
        mounts.lines().any(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            f.len() > 6 && f[4] == "/" && f[5].split(',').any(|v| v == "ro")
        }),
        "BUILD_READONLY_ROOT_REQUIRED",
    )?;
    Ok(root)
}
fn only_worker(cgroup: &Path, cancel: &AtomicBool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let own = std::process::id();
    let mut quiet = None;
    loop {
        require(!cancel.load(Ordering::Relaxed), "BUILD_CANCELLED")?;
        let text = small(&cgroup.join("cgroup.procs"), 65536)?;
        let ids: Vec<u32> = text
            .lines()
            .map(|s| s.parse().map_err(|_| Error("BUILD_CGROUP_INVALID")))
            .collect::<Result<_>>()?;
        require(ids.len() <= 256, "BUILD_CGROUP_INVALID")?;
        if ids.iter().all(|pid| *pid == own) {
            let since = quiet.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(50) {
                return Ok(());
            }
        } else {
            quiet = None;
        }
        require(Instant::now() < deadline, "BUILD_DESCENDANTS_REMAIN")?;
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn workspace(policy: &Policy) -> Result<(File, String)> {
    let root = open_directory(&policy.runtime_root, policy.agent_uid, None)?;
    let link = fs::statat(&root, "build-current", fs::AtFlags::SYMLINK_NOFOLLOW)?;
    require(
        fs::FileType::from_raw_mode(link.st_mode) == fs::FileType::Symlink
            && (link.st_uid == 0 || link.st_uid == policy.agent_uid),
        "BUILD_SELECTION_UNSAFE",
    )?;
    let target = fs::readlinkat(&root, "build-current", Vec::new())?;
    let target = target
        .to_str()
        .map_err(|_| Error("BUILD_SELECTION_UNSAFE"))?;
    let id = target
        .strip_prefix("releases/")
        .ok_or(Error("BUILD_SELECTION_UNSAFE"))?;
    require(identifier(id), "BUILD_SELECTION_UNSAFE")?;
    // The selection and its parent cannot be renamed by the untrusted build UID.
    let releases: File = fs::openat2(
        &root,
        "releases",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    let parent = releases.metadata()?;
    require(
        parent.dev() == root.metadata()?.dev()
            && (parent.uid() == 0 || parent.uid() == policy.agent_uid)
            && parent.mode() & 0o022 == 0,
        "BUILD_RELEASES_UNSAFE",
    )?;
    // The selected leaf is an explicit root-configured ReadWritePaths anchor.
    let file: File = fs::openat2(
        &releases,
        id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?
    .into();
    let m = file.metadata()?;
    require(
        m.dev() == root.metadata()?.dev()
            && m.uid() == policy.agent_uid
            && m.gid() == policy.runtime_gid
            && m.mode() & 0o7777 == 0o2770,
        "BUILD_WORKSPACE_UNSAFE",
    )?;
    let cwd = File::open(".")?.metadata()?;
    require(
        cwd.dev() == m.dev() && cwd.ino() == m.ino(),
        "BUILD_CWD_MISMATCH",
    )?;
    fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error("BUILD_WORKSPACE_BUSY"))?;
    Ok((file, id.into()))
}
fn safe_required_file(workspace: &File, path: &str, policy: &Policy) -> Result<()> {
    let file: File = fs::openat2(
        workspace,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.nlink() == 1
            && (m.uid() == policy.agent_uid || m.uid() == policy.runtime_uid)
            && m.len() <= 16 * 1024 * 1024,
        "BUILD_FILE_UNSAFE",
    )
}
fn capture(
    policy: &Policy,
    args: &[&str],
    timeout_ms: u32,
    production: bool,
    cancel: &AtomicBool,
) -> Result<(bool, Vec<u8>)> {
    let mut command = Command::new(&policy.node_executable);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &policy.cache_directory)
        .env("NPM_CONFIG_CACHE", policy.cache_directory.join("npm"))
        .env(
            "NPM_CONFIG_USERCONFIG",
            "/nonexistent/uliups-build-user.npmrc",
        )
        .env(
            "NPM_CONFIG_GLOBALCONFIG",
            "/nonexistent/uliups-build-global.npmrc",
        )
        .env("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")
        .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
        .env("NEXT_TELEMETRY_DISABLED", "1")
        .env(
            "NODE_ENV",
            if production {
                "production"
            } else {
                "development"
            },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Inherit the kernel-pinned CWD. Never resolve build-current again at spawn.
    let mut child = ChildGuard::spawn(&mut command)?;
    let mut stdout = child
        .process()
        .stdout
        .take()
        .ok_or(Error("BUILD_PIPE_MISSING"))?;
    let mut stderr = child
        .process()
        .stderr
        .take()
        .ok_or(Error("BUILD_PIPE_MISSING"))?;
    nonblock(&stdout)?;
    nonblock(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.into());
    loop {
        require(!cancel.load(Ordering::Relaxed), "BUILD_CANCELLED")?;
        require(Instant::now() < deadline, "BUILD_DEADLINE")?;
        drain(&mut stdout, &mut out, 1024 * 1024)?;
        drain(&mut stderr, &mut err, 1024 * 1024)?;
        if let Some(status) = child.process().try_wait()? {
            child.mark_reaped();
            drain(&mut stdout, &mut out, 1024 * 1024)?;
            drain(&mut stderr, &mut err, 1024 * 1024)?;
            require(!cancel.load(Ordering::Relaxed), "BUILD_CANCELLED")?;
            require(Instant::now() < deadline, "BUILD_DEADLINE")?;
            out.push(b'\n');
            out.extend(err);
            return Ok((status.success(), out));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn redacted(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "authorization",
                "password",
                "passwd",
                "secret",
                "token",
                "database_url",
                "private key",
                "credential",
                "cookie",
            ]
            .iter()
            .any(|word| lower.contains(word))
                || (lower.contains("://") && lower.contains('@'))
            {
                return "[redacted]".to_string();
            }
            line.chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .collect()
        })
        .collect::<Vec<String>>()
        .join("\n")
}
pub fn run(path: &Path) -> Result<serde_json::Value> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    require(
        rustix::process::geteuid().as_raw() != 0,
        "BUILD_NONROOT_REQUIRED",
    )?;
    let bytes = crate::systemd::root_policy_bytes(path)?;
    let policy: Policy =
        serde_json::from_slice(&bytes).map_err(|_| Error("BUILD_POLICY_INVALID"))?;
    require(
        policy.policy_version == 1
            && identifier(&policy.instance_id)
            && policy.agent_uid != 0
            && policy.runtime_uid != 0
            && policy.runtime_gid != 0
            && policy.agent_uid != policy.runtime_uid
            && rustix::process::geteuid().as_raw() == policy.runtime_uid
            && rustix::process::getuid().as_raw() == policy.runtime_uid
            && rustix::process::getegid().as_raw() == policy.runtime_gid,
        "BUILD_IDENTITY_MISMATCH",
    )?;
    require(
        policy.build_unit.ends_with(".service")
            && policy.build_unit.len() <= 255
            && policy
                .build_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            && (100..=1800000).contains(&policy.install_deadline_ms)
            && (100..=1800000).contains(&policy.build_deadline_ms)
            && (128 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&policy.max_memory_bytes)
            && (16..=256).contains(&policy.max_tasks)
            && (1..=800).contains(&policy.max_cpu_percent)
            && matches!(policy.node_major, 22 | 24),
        "BUILD_POLICY_INVALID",
    )?;
    let cg = context(&policy)?;
    program(&policy.node_executable, false)?;
    program(&policy.npm_entrypoint, true)?;
    let cache = open_directory(
        &policy.cache_directory,
        policy.agent_uid,
        Some(policy.runtime_uid),
    )?;
    let m = cache.metadata()?;
    require(
        m.uid() == policy.runtime_uid && m.mode() & 0o7777 == 0o700,
        "BUILD_CACHE_UNSAFE",
    )?;
    let (workspace, id) = workspace(&policy)?;
    safe_required_file(&workspace, "package.json", &policy)?;
    safe_required_file(&workspace, "package-lock.json", &policy)?;
    let cancel = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::signal::SIGTERM, cancel.clone())?;
    signal_hook::flag::register(signal_hook::consts::signal::SIGINT, cancel.clone())?;
    only_worker(&cg, &cancel)?;
    let (ok, version) = capture(&policy, &["--version"], 5000, false, &cancel)?;
    let version = std::str::from_utf8(&version)
        .map_err(|_| Error("BUILD_NODE_VERSION_MISMATCH"))?
        .trim();
    require(
        ok && version.starts_with(&format!("v{}.", policy.node_major)),
        "BUILD_NODE_VERSION_MISMATCH",
    )?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| Error("BUILD_RANDOM_UNAVAILABLE"))?;
    let name = format!(".uliups-build-{}.log", hex::encode(random));
    let mut log: File = fs::openat2(
        &workspace,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o660),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    fs::fchmod(&log, Mode::from_raw_mode(0o660))?;
    let npm = policy
        .npm_entrypoint
        .to_str()
        .ok_or(Error("BUILD_PATH_INVALID"))?;
    for (phase, args, timeout, prod) in [
        (
            "install",
            vec![npm, "ci", "--include=dev", "--no-audit", "--no-fund"],
            policy.install_deadline_ms,
            false,
        ),
        (
            "build",
            vec![npm, "run", "build"],
            policy.build_deadline_ms,
            true,
        ),
    ] {
        let (ok, output) = capture(&policy, &args, timeout, prod, &cancel)?;
        log.write_all(format!("=== {phase} ===\n{}\n", redacted(&output)).as_bytes())?;
        log.sync_all()?;
        only_worker(&cg, &cancel)?;
        require(
            ok,
            if phase == "install" {
                "BUILD_INSTALL_FAILED"
            } else {
                "BUILD_COMPILATION_FAILED"
            },
        )?;
    }
    safe_required_file(&workspace, ".next/BUILD_ID", &policy)?;
    workspace.sync_all()?;
    Ok(
        serde_json::json!({"code":"BUILD_READY","release_id":id,"log":name,"policy_sha256":hex::encode(Sha256::digest(bytes)),
  "activated":false,"healthy":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_mask_credentials_and_terminal_control() {
        let value=redacted(b"normal\x1b[31m\nAuthorization: bearer value\nDATABASE_URL=postgres://user:pass@host/db\nplain");
        assert!(!value.contains("bearer"));
        assert!(!value.contains("user:pass"));
        assert!(!value.contains('\x1b'));
        assert!(value.contains("plain"));
    }
}
