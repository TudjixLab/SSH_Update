//! Root-owned, per-project systemd command gate. No package supplies unit names,
//! commands, shell fragments or policy contents. Privilege delegation is external;
//! this component never elevates uid and never invokes sudo.
use crate::process::{ChildGuard, drain, nonblock};
use crate::{Error, Result, identifier, require};
use rustix::fs::{self as fs, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    policy_version: u16,
    instance_id: String,
    agent_uid: u32,
    runtime_uid: u32,
    application_unit: String,
    operation_timeout_ms: u16,
}
pub struct SystemdControl {
    policy: Policy,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnitObservation {
    pub unit: String,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: u32,
    pub invocation_id: String,
    pub start_monotonic: u64,
    pub control_group: String,
    pub working_directory: String,
    pub configured_user: String,
}
impl UnitObservation {
    pub fn is_active(&self) -> bool {
        self.active_state == "active"
            && self.main_pid > 0
            && self.start_monotonic > 0
            && self.invocation_id.len() == 32
            && self.invocation_id.bytes().all(|b| b.is_ascii_hexdigit())
            && self.control_group.starts_with('/')
    }
    /// A consistency observation, NOT proof that the probed TCP listener belongs
    /// to this cgroup. A privileged socket-owner check remains mandatory.
    pub fn same_invocation(&self, other: &Self) -> bool {
        self.is_active()
            && other.is_active()
            && self.unit == other.unit
            && self.main_pid == other.main_pid
            && self.invocation_id == other.invocation_id
            && self.start_monotonic == other.start_monotonic
            && self.control_group == other.control_group
            && self.working_directory == other.working_directory
            && self.configured_user == other.configured_user
    }
}
pub(crate) fn root_policy_bytes(path: &Path) -> Result<Vec<u8>> {
    require(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "SYSTEMD_POLICY_PATH_INVALID",
    )?;
    let mut fd = File::open("/")?;
    let parent = path.parent().ok_or(Error("SYSTEMD_POLICY_PATH_INVALID"))?;
    for part in parent.components() {
        if let Component::Normal(name) = part {
            fd = fs::openat2(
                &fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?
            .into();
            let m = fd.metadata()?;
            require(
                m.uid() == 0 && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
                "SYSTEMD_POLICY_PARENT_UNSAFE",
            )?;
        }
    }
    let file: File = fs::openat2(
        &fd,
        path.file_name()
            .ok_or(Error("SYSTEMD_POLICY_PATH_INVALID"))?,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?
    .into();
    let m = file.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o7022 == 0 && m.len() <= 8192,
        "SYSTEMD_POLICY_UNSAFE",
    )?;
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    require(bytes.len() <= 8192, "SYSTEMD_POLICY_TOO_LARGE")?;
    Ok(bytes)
}
fn read_policy(path: &Path) -> Result<Policy> {
    serde_json::from_slice(&root_policy_bytes(path)?).map_err(|_| Error("SYSTEMD_POLICY_INVALID"))
}
fn execute(args: &[&str], until: Instant, cancel: &AtomicBool) -> Result<Vec<u8>> {
    require(!cancel.load(Ordering::Relaxed), "SYSTEMD_CANCELLED")?;
    let meta = std::fs::symlink_metadata(SYSTEMCTL)?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "SYSTEMD_EXECUTABLE_UNSAFE",
    )?;
    let mut command = Command::new(SYSTEMCTL);
    command
        .args(["--system", "--no-pager", "--no-ask-password"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = ChildGuard::spawn(&mut command)?;
    let mut stdout = child
        .process()
        .stdout
        .take()
        .ok_or(Error("SYSTEMD_PIPE_MISSING"))?;
    let mut stderr = child
        .process()
        .stderr
        .take()
        .ok_or(Error("SYSTEMD_PIPE_MISSING"))?;
    nonblock(&stdout)?;
    nonblock(&stderr)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        require(!cancel.load(Ordering::Relaxed), "SYSTEMD_CANCELLED")?;
        require(Instant::now() < until, "SYSTEMD_DEADLINE")?;
        drain(&mut stdout, &mut out, 65536)?;
        drain(&mut stderr, &mut err, 8192)?;
        if let Some(status) = child.process().try_wait()? {
            child.mark_reaped();
            drain(&mut stdout, &mut out, 65536)?;
            require(status.success(), "SYSTEMD_COMMAND_FAILED")?;
            require(!cancel.load(Ordering::Relaxed), "SYSTEMD_CANCELLED")?;
            require(Instant::now() < until, "SYSTEMD_DEADLINE")?;
            return Ok(out);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
impl SystemdControl {
    pub fn load(path: &Path, expected_instance: &str) -> Result<Self> {
        let policy = read_policy(path)?;
        require(
            policy.policy_version == 1
                && identifier(&policy.instance_id)
                && policy.instance_id.len() <= 96
                && policy.instance_id == expected_instance,
            "SYSTEMD_POLICY_INVALID",
        )?;
        require(
            policy.agent_uid != 0
                && policy.runtime_uid != 0
                && policy.agent_uid != policy.runtime_uid
                && (100..=30000).contains(&policy.operation_timeout_ms),
            "SYSTEMD_IDENTITY_INVALID",
        )?;
        require(
            policy.application_unit.ends_with(".service")
                && policy.application_unit.len() <= 255
                && policy
                    .application_unit
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && policy
                    .application_unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
            "SYSTEMD_UNIT_FORBIDDEN",
        )?;
        let actual = rustix::process::geteuid().as_raw();
        require(
            actual == 0 || actual == policy.agent_uid,
            "SYSTEMD_CALLER_FORBIDDEN",
        )?;
        Ok(Self { policy })
    }
    pub fn status(&self, cancel: &AtomicBool) -> Result<UnitObservation> {
        let args = [
            "show",
            self.policy.application_unit.as_str(),
            "--property=ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic,ControlGroup,WorkingDirectory,User",
        ];
        let bytes = execute(
            &args,
            Instant::now() + Duration::from_millis(self.policy.operation_timeout_ms.into()),
            cancel,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Error("SYSTEMD_RESPONSE_INVALID"))?;
        let observation = parse_observation(&self.policy.application_unit, text)?;
        require(
            configured_uid(&observation.configured_user)? == self.policy.runtime_uid,
            "SYSTEMD_RUNTIME_IDENTITY_MISMATCH",
        )?;
        Ok(observation)
    }
    /// These request a manager operation. Callers must observe the resulting state;
    /// manager acknowledgement is never reported as application health success.
    pub fn request_start(&self, cancel: &AtomicBool) -> Result<()> {
        let before = self.status(cancel)?;
        require(
            matches!(before.active_state.as_str(), "inactive" | "failed"),
            "SYSTEMD_START_REQUIRES_STOPPED",
        )?;
        // RestartUnit also starts a stopped static unit. Deliberately do NOT grant
        // polkit verb=start: StartTransientUnit uses that same authorization verb.
        self.request("restart", cancel)
    }
    pub fn request_stop(&self, cancel: &AtomicBool) -> Result<()> {
        self.request("stop", cancel)
    }
    pub fn request_restart(&self, cancel: &AtomicBool) -> Result<()> {
        self.request("restart", cancel)
    }
    fn request(&self, verb: &str, cancel: &AtomicBool) -> Result<()> {
        if matches!(verb, "start" | "restart") {
            self.status(cancel)?;
        }
        execute(
            &["--no-block", verb, &self.policy.application_unit],
            Instant::now() + Duration::from_millis(self.policy.operation_timeout_ms.into()),
            cancel,
        )?;
        Ok(())
    }
}
fn configured_uid(user: &str) -> Result<u32> {
    if user.is_empty() {
        return Ok(0);
    }
    if user.bytes().all(|b| b.is_ascii_digit()) {
        return user
            .parse()
            .map_err(|_| Error("SYSTEMD_RUNTIME_IDENTITY_INVALID"));
    }
    require(identifier(user), "SYSTEMD_RUNTIME_IDENTITY_INVALID")?;
    // Per-project service accounts are local. Remote/dynamic account resolution
    // is deliberately unsupported rather than executing an uncontrolled helper.
    let file: File = fs::open(
        "/etc/passwd",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 1024 * 1024,
        "SYSTEMD_ACCOUNT_DATABASE_UNSAFE",
    )?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= 1024 * 1024,
        "SYSTEMD_ACCOUNT_DATABASE_UNSAFE",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error("SYSTEMD_ACCOUNT_DATABASE_UNSAFE"))?;
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&user) {
            require(fields.len() == 7, "SYSTEMD_ACCOUNT_DATABASE_UNSAFE")?;
            return fields[2]
                .parse()
                .map_err(|_| Error("SYSTEMD_ACCOUNT_DATABASE_UNSAFE"));
        }
    }
    Err(Error("SYSTEMD_RUNTIME_IDENTITY_INVALID"))
}

fn parse_observation(unit: &str, text: &str) -> Result<UnitObservation> {
    let allowed = [
        "ActiveState",
        "SubState",
        "MainPID",
        "InvocationID",
        "ExecMainStartTimestampMonotonic",
        "ControlGroup",
        "WorkingDirectory",
        "User",
    ];
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or(Error("SYSTEMD_RESPONSE_INVALID"))?;
        require(
            allowed.contains(&name)
                && !fields.contains_key(name)
                && value.len() <= 4096
                && value.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "SYSTEMD_RESPONSE_INVALID",
        )?;
        fields.insert(name, value);
    }
    require(fields.len() == allowed.len(), "SYSTEMD_RESPONSE_INVALID")?;
    let state = fields["ActiveState"];
    require(
        matches!(
            state,
            "active"
                | "inactive"
                | "activating"
                | "deactivating"
                | "failed"
                | "reloading"
                | "maintenance"
                | "refreshing"
        ),
        "SYSTEMD_RESPONSE_INVALID",
    )?;
    Ok(UnitObservation {
        unit: unit.into(),
        active_state: state.into(),
        sub_state: fields["SubState"].into(),
        main_pid: fields["MainPID"]
            .parse()
            .map_err(|_| Error("SYSTEMD_RESPONSE_INVALID"))?,
        invocation_id: fields["InvocationID"].into(),
        start_monotonic: fields["ExecMainStartTimestampMonotonic"]
            .parse()
            .map_err(|_| Error("SYSTEMD_RESPONSE_INVALID"))?,
        control_group: fields["ControlGroup"].into(),
        working_directory: fields["WorkingDirectory"].into(),
        configured_user: fields["User"].into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn text() -> String {
        "ActiveState=active\nSubState=running\nMainPID=123\nInvocationID=1234567890abcdef1234567890abcdef\nExecMainStartTimestampMonotonic=99\nControlGroup=/system.slice/demo\nWorkingDirectory=/run/fixture\nUser=65534\n".into()
    }
    #[test]
    fn invocation_consistency_rejects_restarts_and_incomplete_fields() {
        let old = parse_observation("unit", &text()).unwrap();
        assert!(old.is_active());
        assert!(old.same_invocation(&old));
        let changed =
            parse_observation("unit", &text().replace("MainPID=123", "MainPID=124")).unwrap();
        assert!(!old.same_invocation(&changed));
        let changed = parse_observation(
            "unit",
            &text().replace(
                "1234567890abcdef1234567890abcdef",
                "abcdef1234567890abcdef1234567890",
            ),
        )
        .unwrap();
        assert!(!old.same_invocation(&changed));
        assert!(parse_observation("unit", &text().replace("MainPID=123\n", "")).is_err());
        assert!(parse_observation("unit", &(text() + "MainPID=456\n")).is_err());
    }
    #[test]
    fn policy_does_not_accept_runtime_editable_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("policy.json");
        std::fs::write(&path, b"{}").unwrap();
        assert!(SystemdControl::load(&path, "instance").is_err());
    }
}
