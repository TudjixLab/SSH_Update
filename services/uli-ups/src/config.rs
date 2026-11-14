use crate::{Error, Result, identifier, require};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{self as fs, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use uli4::TrustedProject;
use uliup_state::Instance;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub public_key_hex: String,
    pub target_runtime: String,
    pub health_policy_id: String,
    pub minimum_sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u16,
    pub instance_id: String,
    pub app_id: String,
    pub profile_id: String,
    pub agent_home: PathBuf,
    pub trust: TrustConfig,
}
pub(crate) fn directory(path: &Path, private: bool) -> Result<File> {
    require(
        path.is_absolute()
            && path
                .components()
                .all(|p| matches!(p, Component::RootDir | Component::Normal(_))),
        "AGENT_PATH_INVALID",
    )?;
    let mut fd = File::open("/")?;
    for part in path.components() {
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
                (m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                    && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
                "AGENT_PARENT_UNSAFE",
            )?;
        }
    }
    if private {
        let m = fd.metadata()?;
        require(
            m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o7777 == 0o700,
            "AGENT_DIRECTORY_NOT_PRIVATE",
        )?;
    }
    Ok(fd)
}
pub(crate) fn child_directory(parent: &File, name: &str) -> Result<File> {
    // Existing configured anchors may be systemd ReadWritePaths bind mounts.
    // Do not mkdir through a read-only parent when the private anchor already exists.
    let created = match fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => false,
        Err(rustix::io::Errno::NOENT) => {
            match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    let file: File = fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?
    .into();
    if created {
        fs::fchmod(&file, Mode::from_raw_mode(0o700))?;
        file.sync_all()?;
        parent.sync_all()?;
    }
    let m = file.metadata()?;
    require(
        m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o700
            && m.dev() == parent.metadata()?.dev(),
        "AGENT_DIRECTORY_NOT_PRIVATE",
    )?;
    Ok(file)
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or(Error("AGENT_CONFIG_PATH_INVALID"))?;
        let name = path.file_name().ok_or(Error("AGENT_CONFIG_PATH_INVALID"))?;
        let dir = directory(parent, false)?;
        let file: File = fs::openat2(
            &dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?
        .into();
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.mode() & 0o7777 == 0o600
                && m.len() <= 65536,
            "AGENT_CONFIG_UNSAFE",
        )?;
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        require(bytes.len() <= 65536, "AGENT_CONFIG_TOO_LARGE")?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error("AGENT_CONFIG_INVALID"))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        require(self.config_version == 1, "AGENT_CONFIG_VERSION_UNSUPPORTED")?;
        require(
            [
                &self.instance_id,
                &self.app_id,
                &self.profile_id,
                &self.trust.target_runtime,
                &self.trust.health_policy_id,
            ]
            .iter()
            .all(|s| identifier(s)),
            "AGENT_CONFIG_INVALID",
        )?;
        require(
            matches!(self.profile_id.as_str(), "static-files" | "nextjs-systemd"),
            "AGENT_PROFILE_UNSUPPORTED",
        )?;
        require(
            self.trust.minimum_sequence > 0 && self.trust.minimum_sequence <= 9_007_199_254_740_991,
            "AGENT_CONFIG_INVALID",
        )?;
        self.verifying_key()?;
        directory(&self.agent_home, true)?;
        require(
            self.socket_path().as_os_str().len() < 104,
            "AGENT_SOCKET_PATH_TOO_LONG",
        )?;
        Ok(())
    }
    fn verifying_key(&self) -> Result<VerifyingKey> {
        require(
            self.trust.public_key_hex.len() == 64
                && self
                    .trust
                    .public_key_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "AGENT_PUBLIC_KEY_INVALID",
        )?;
        let key: [u8; 32] = hex::decode(&self.trust.public_key_hex)
            .map_err(|_| Error("AGENT_PUBLIC_KEY_INVALID"))?
            .try_into()
            .map_err(|_| Error("AGENT_PUBLIC_KEY_INVALID"))?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| Error("AGENT_PUBLIC_KEY_INVALID"))?;
        require(!key.is_weak(), "AGENT_PUBLIC_KEY_WEAK")?;
        Ok(key)
    }
    pub fn instance(&self) -> Instance {
        Instance {
            instance_id: self.instance_id.clone(),
            app_id: self.app_id.clone(),
            profile_id: self.profile_id.clone(),
        }
    }
    pub fn trusted_project(&self) -> Result<TrustedProject> {
        Ok(TrustedProject {
            key: self.verifying_key()?,
            app_id: self.app_id.clone(),
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            target_runtime: self.trust.target_runtime.clone(),
            allowed_profiles: vec![self.profile_id.clone()],
            health_policies: vec![self.trust.health_policy_id.clone()],
            agent_version: (0, 1, 0),
            minimum_sequence: self.trust.minimum_sequence,
        })
    }
    pub fn state_path(&self) -> PathBuf {
        self.agent_home.join("state")
    }
    pub fn source_path(&self) -> PathBuf {
        self.agent_home.join("sources")
    }
    pub fn socket_path(&self) -> PathBuf {
        self.state_path().join("control.sock")
    }
    pub(crate) fn initialize_directories(&self) -> Result<()> {
        let root = directory(&self.agent_home, true)?;
        child_directory(&root, "state")?;
        child_directory(&root, "sources")?;
        Ok(())
    }
}
