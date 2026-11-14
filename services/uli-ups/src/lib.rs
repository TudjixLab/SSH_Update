//! Per-project Linux agent. The shared format/state/transport crates remain unchanged.
#![cfg(target_os = "linux")]
pub mod agent;
pub mod config;
pub mod control;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("AGENT_IO_ERROR")
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(_: rustix::io::Errno) -> Self {
        Self("AGENT_IO_ERROR")
    }
}
impl From<uliup_state::Error> for Error {
    fn from(error: uliup_state::Error) -> Self {
        match error {
            uliup_state::Error::Rejected(code) => Self(code),
            _ => Self("AGENT_STATE_ERROR"),
        }
    }
}
impl From<uli4::Error> for Error {
    fn from(error: uli4::Error) -> Self {
        match error {
            uli4::Error::Rejected(code) => Self(code),
            _ => Self("AGENT_PACKAGE_ERROR"),
        }
    }
}
pub(crate) fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(Error(code)) }
}
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

pub mod journal;

pub mod health;

pub mod systemd;

pub mod build_worker;
pub(crate) mod process;

pub mod runtime;
