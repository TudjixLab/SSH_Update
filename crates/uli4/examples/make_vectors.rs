//! Internal deterministic fixture generator; never a user-facing third product.
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uli4::*;
fn options(id: &str, n: u64) -> PackageOptions {
    PackageOptions {
        app_id: "golden-app".into(),
        release_id: id.into(),
        release_sequence: n,
        display_version: "0.1.0".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "static".into(),
        profile: "static-files".into(),
        health_policy: "files".into(),
    }
}
fn main() -> Result<()> {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    fs::create_dir_all(&out)?;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("change.txt"), b"before\n")?;
    fs::write(source.join("same.txt"), b"unchanged\n")?;
    fs::write(source.join("old.txt"), b"remove me\n")?;
    // Public deterministic TEST key only. Never use for actual project releases.
    let key = SigningKey::from_bytes(&[21; 32]);
    let trust = TrustedProject {
        key: key.verifying_key(),
        app_id: "golden-app".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "static".into(),
        allowed_profiles: vec!["static-files".into()],
        health_policies: vec!["files".into()],
        agent_version: (0, 1, 0),
        minimum_sequence: 1,
    };
    let full = out.join("full-v1.bin");
    pack(
        &source,
        &full,
        options("golden-full", 1),
        &key,
        None,
        &Limits::default(),
    )?;
    let base = verify(&full, &trust, None, &Limits::default())?.base_release();
    fs::remove_file(source.join("old.txt"))?;
    fs::write(source.join("change.txt"), b"after\n")?;
    fs::write(source.join("История.txt"), "Пакет\n".as_bytes())?;
    let delta = out.join("incremental-v1.bin");
    pack(
        &source,
        &delta,
        options("golden-delta", 2),
        &key,
        Some(&base),
        &Limits::default(),
    )?;
    for p in [&full, &delta] {
        let hash = hex::encode(Sha256::digest(fs::read(p)?));
        let name = p.file_name().unwrap().to_string_lossy();
        fs::write(
            Path::new(&format!("{}.sha256", p.display())),
            format!("{hash}  {name}\n"),
        )?;
        println!("{name} {hash}");
    }
    Ok(())
}
