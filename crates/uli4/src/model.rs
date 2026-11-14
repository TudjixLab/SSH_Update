use crate::{Result, ensure};
use caseless::Caseless;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

pub const MAX_JSON_INTEGER: u64 = (1u64 << 53) - 1;
#[derive(Clone, Debug)]
pub struct Limits {
    pub manifest_bytes: u64,
    pub max_files: u64,
    pub package_bytes: u64,
    pub plain_bytes: u64,
    pub file_bytes: u64,
    pub max_ratio: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            manifest_bytes: 8 << 20,
            max_files: 100_000,
            package_bytes: 16 << 30,
            plain_bytes: 32 << 30,
            file_bytes: 8 << 30,
            max_ratio: 1000,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Add,
    Replace,
    Delete,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub kind: OperationKind,
    pub file: FileRecord,
    pub old_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    Full,
    Incremental,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub id: String,
    pub kind: String,
    pub version: String,
    pub profile: String,
    pub files: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub app_id: String,
    pub release_id: String,
    pub release_sequence: u64,
    pub display_version: String,
    pub kind: PackageKind,
    pub base_release_id: Option<String>,
    pub base_state_digest: Option<String>,
    pub target_os: String,
    pub target_arch: String,
    pub target_runtime: String,
    pub min_agent_version: String,
    pub max_supported_protocol_major: u32,
    pub required_capabilities: Vec<String>,
    pub components: Vec<Component>,
    pub file_operations: Vec<Operation>,
    pub result_tree_digest: String,
    pub health_policy_id: String,
    pub deployment_profile_id: String,
    pub signer_key_id: String,
    pub signature_scope: String,
}
pub fn canonical_manifest(value: &Manifest) -> Result<Vec<u8>> {
    // Fixed ASCII object keys and unsigned safe integers form a JCS-compatible subset.
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
pub fn validate_path(path: &str) -> Result<String> {
    ensure(
        !path.is_empty()
            && path.len() <= 1024
            && path.nfc().eq(path.chars())
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path
                .chars()
                .any(|c| c.is_control() || ":*?\"<>|".contains(c)),
        "ULI4_PATH_REJECTED",
    )?;
    ensure(path.split('/').count() <= 64, "ULI4_PATH_REJECTED")?;
    for part in path.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        let device = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|n| {
                n.chars().count() == 1 && n.chars().all(|c| c.is_ascii_digit() || "¹²³".contains(c))
            });
        ensure(
            !part.is_empty()
                && !matches!(part, "." | "..")
                && !part.ends_with(['.', ' '])
                && !device,
            "ULI4_PATH_REJECTED",
        )?;
    }
    Ok(path.chars().default_case_fold().nfc().collect())
}
pub fn denied_path(path: &str) -> bool {
    let folded: String = path.chars().default_case_fold().nfc().collect();
    folded.split('/').any(|p| {
        let p = p.to_ascii_lowercase();
        matches!(
            p.as_str(),
            ".git"
                | ".next"
                | "node_modules"
                | ".tooling"
                | ".uliup"
                | "shared"
                | "secrets"
                | "private"
                | "target"
                | "coverage"
                | ".cache"
        ) || p.starts_with(".env")
            || p.starts_with("id_rsa")
            || p.starts_with("id_ed25519")
            || p.ends_with(".pem")
            || p.ends_with(".key")
            || p.ends_with(".pfx")
            || p.ends_with(".p12")
            || p.ends_with(".log")
            || p.ends_with(".uli4")
    })
}
pub(crate) fn digest_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn validate_files(files: &[FileRecord], limits: &Limits) -> Result<()> {
    ensure(
        files.len() as u64 <= limits.max_files,
        "ULI4_QUOTA_EXCEEDED",
    )?;
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut previous: Option<&str> = None;
    for f in files {
        let folded = validate_path(&f.path)?;
        ensure(
            !denied_path(&f.path) && names.insert(folded.clone()),
            "ULI4_PATH_REJECTED",
        )?;
        for (i, _) in folded.match_indices('/') {
            ensure(!names.contains(&folded[..i]), "ULI4_PATH_REJECTED")?;
        }
        if let Some(p) = previous {
            ensure(p < f.path.as_str(), "ULI4_PATH_REJECTED")?;
        }
        previous = Some(&f.path);
        ensure(
            digest_ok(&f.sha256)
                && f.size <= limits.file_bytes
                && f.size <= MAX_JSON_INTEGER
                && f.mode == 0o644,
            "ULI4_FILE_INVALID",
        )?;
        total = total
            .checked_add(f.size)
            .ok_or(crate::Error::Rejected("ULI4_QUOTA_EXCEEDED"))?;
    }
    // Check both directions: UTF-8 order need not equal casefold order.
    for name in &names {
        for (i, _) in name.match_indices('/') {
            ensure(!names.contains(&name[..i]), "ULI4_PATH_REJECTED")?;
        }
    }
    ensure(total <= limits.plain_bytes, "ULI4_QUOTA_EXCEEDED")
}
