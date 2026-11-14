//! Experimental ULI4 v1 core. No server activation or shell execution.
mod format;
#[cfg(target_os = "linux")]
pub mod linux;
mod model;
mod package;
mod tree;
pub use model::*;
pub use package::{BaseRelease, PackageOptions, TrustedProject, VerifiedPackage, pack, verify};
pub use tree::{Preview, scan, tree_digest};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Rejected(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(_) => f.write_str("ULI4_IO_ERROR"),
            Self::Json(_) => f.write_str("ULI4_MANIFEST_INVALID"),
            Self::Rejected(code) => f.write_str(code),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
pub(crate) fn ensure(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Rejected(code))
    }
}

#[cfg(target_os = "linux")]
pub use package::verify_opened;
