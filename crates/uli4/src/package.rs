use crate::{
    ensure,
    format::*,
    model::{digest_ok, validate_files},
    tree::{hash_copy, plain_file},
    *,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub struct PackageOptions {
    pub app_id: String,
    pub release_id: String,
    pub release_sequence: u64,
    pub display_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub target_runtime: String,
    pub profile: String,
    pub health_policy: String,
}
pub struct TrustedProject {
    pub key: VerifyingKey,
    pub app_id: String,
    pub target_os: String,
    pub target_arch: String,
    pub target_runtime: String,
    pub allowed_profiles: Vec<String>,
    pub health_policies: Vec<String>,
    pub agent_version: (u64, u64, u64),
    pub minimum_sequence: u64,
}
/// An authenticated source file map, never an activation or persistent replay policy.
#[derive(Clone, Debug)]
pub struct BaseRelease {
    app_id: String,
    release_id: String,
    files: Vec<FileRecord>,
    digest: String,
}
impl BaseRelease {
    pub fn app_id(&self) -> &str {
        &self.app_id
    }
    pub fn files(&self) -> &[FileRecord] {
        &self.files
    }
    pub fn release_id(&self) -> &str {
        &self.release_id
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
/// Constructor is private. Do not activate output from copy_file until the call succeeds.
pub struct VerifiedPackage {
    file: File,
    header: Header,
    manifest: Manifest,
    entries: Vec<Entry>,
    result: BaseRelease,
    limits: Limits,
}
impl VerifiedPackage {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn base_release(&self) -> BaseRelease {
        self.result.clone()
    }
    pub fn copy_file(&mut self, operation_index: usize, output: impl Write) -> Result<()> {
        let e = self
            .entries
            .iter()
            .find(|e| e.operation as usize == operation_index)
            .ok_or(Error::Rejected("ULI4_OPERATION_INVALID"))?;
        self.file
            .seek(SeekFrom::Start(self.header.payload_offset() + e.offset))?;
        let mut magic = [0; 4];
        self.file.read_exact(&mut magic)?;
        ensure(magic == [0x28, 0xb5, 0x2f, 0xfd], "ULI4_FRAME_INVALID")?;
        self.file.seek(SeekFrom::Current(-4))?;
        let compressed = (&mut self.file).take(e.compressed);
        let mut decoder =
            zstd::stream::read::Decoder::with_buffer(BufReader::new(compressed))?.single_frame();
        decoder.window_log_max(23)?;
        let (size, hash) = hash_copy(&mut decoder, output, e.plain.min(self.limits.file_bytes))?;
        let tail = decoder.finish();
        ensure(
            tail.buffer().is_empty()
                && tail.get_ref().limit() == 0
                && size == e.plain
                && hash == hex::encode(e.hash),
            "ULI4_FILE_HASH_MISMATCH",
        )
    }
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}
fn version(s: &str) -> Option<(u64, u64, u64)> {
    let v: Vec<_> = s.split('.').collect();
    if v.len() != 3 {
        return None;
    }
    Some((v[0].parse().ok()?, v[1].parse().ok()?, v[2].parse().ok()?))
}
fn validate_manifest(m: &Manifest, l: &Limits) -> Result<()> {
    ensure(
        m.format_version == 1
            && m.max_supported_protocol_major == 1
            && m.signature_scope == "project"
            && [
                &m.app_id,
                &m.release_id,
                &m.display_version,
                &m.target_os,
                &m.target_arch,
                &m.target_runtime,
                &m.deployment_profile_id,
                &m.health_policy_id,
            ]
            .into_iter()
            .all(|s| token(s))
            && m.release_sequence > 0
            && m.release_sequence <= MAX_JSON_INTEGER
            && version(&m.min_agent_version).is_some()
            && digest_ok(&m.signer_key_id)
            && digest_ok(&m.result_tree_digest)
            && m.required_capabilities == ["uli4.file-v1"]
            && m.components.len() == 1,
        "ULI4_MANIFEST_INVALID",
    )?;
    ensure(
        m.file_operations.len() as u64 <= l.max_files,
        "ULI4_QUOTA_EXCEEDED",
    )?;
    let records: Vec<_> = m.file_operations.iter().map(|o| o.file.clone()).collect();
    validate_files(&records, l)?;
    let c = &m.components[0];
    ensure(
        c.id == "application"
            && c.kind == "source"
            && c.version == m.display_version
            && c.profile == m.deployment_profile_id,
        "ULI4_COMPONENT_REJECTED",
    )?;
    for o in &m.file_operations {
        ensure(
            match o.kind {
                OperationKind::Add => o.old_sha256.is_none(),
                _ => o.old_sha256.as_deref().is_some_and(digest_ok),
            },
            "ULI4_OPERATION_INVALID",
        )?;
    }
    match m.kind {
        PackageKind::Full => ensure(
            m.base_release_id.is_none()
                && m.base_state_digest.is_none()
                && m.file_operations
                    .iter()
                    .all(|o| o.kind == OperationKind::Add),
            "ULI4_BASE_MISMATCH",
        ),
        PackageKind::Incremental => ensure(
            m.base_release_id.as_deref().is_some_and(token)
                && m.base_state_digest.as_deref().is_some_and(digest_ok),
            "ULI4_BASE_MISMATCH",
        ),
    }
}
fn result_map(m: &Manifest, base: Option<&BaseRelease>, l: &Limits) -> Result<BaseRelease> {
    let mut map = BTreeMap::new();
    if m.kind == PackageKind::Incremental {
        let b = base.ok_or(Error::Rejected("ULI4_BASE_MISMATCH"))?;
        ensure(
            b.app_id == m.app_id
                && Some(&b.release_id) == m.base_release_id.as_ref()
                && Some(&b.digest) == m.base_state_digest.as_ref(),
            "ULI4_BASE_MISMATCH",
        )?;
        for f in &b.files {
            map.insert(f.path.clone(), f.clone());
        }
    }
    for o in &m.file_operations {
        match o.kind {
            OperationKind::Add => {
                ensure(!map.contains_key(&o.file.path), "ULI4_BASE_MISMATCH")?;
                map.insert(o.file.path.clone(), o.file.clone());
            }
            OperationKind::Replace | OperationKind::Delete => {
                let old = map
                    .get(&o.file.path)
                    .ok_or(Error::Rejected("ULI4_BASE_MISMATCH"))?;
                ensure(
                    Some(&old.sha256) == o.old_sha256.as_ref(),
                    "ULI4_BASE_MISMATCH",
                )?;
                if o.kind == OperationKind::Delete {
                    ensure(old == &o.file, "ULI4_BASE_MISMATCH")?;
                    map.remove(&o.file.path);
                } else {
                    map.insert(o.file.path.clone(), o.file.clone());
                }
            }
        }
    }
    let files: Vec<_> = map.into_values().collect();
    validate_files(&files, l)?;
    ensure(
        tree_digest(&files)? == m.result_tree_digest
            && m.components[0].files == files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
        "ULI4_TREE_MISMATCH",
    )?;
    Ok(BaseRelease {
        app_id: m.app_id.clone(),
        release_id: m.release_id.clone(),
        digest: m.result_tree_digest.clone(),
        files,
    })
}
/// Does not run any process, npm command, network call, or project build.
pub fn pack(
    source: &Path,
    destination: &Path,
    options: PackageOptions,
    key: &SigningKey,
    base: Option<&BaseRelease>,
    l: &Limits,
) -> Result<Manifest> {
    let parent = destination
        .parent()
        .ok_or(Error::Rejected("ULI4_OUTPUT_INVALID"))?;
    let root = source.canonicalize()?;
    let out = parent.canonicalize()?;
    ensure(!out.starts_with(&root), "ULI4_OUTPUT_INSIDE_SOURCE")?;
    let preview = scan(source, l)?;
    let new: BTreeMap<_, _> = preview
        .files
        .iter()
        .map(|f| (f.path.clone(), f.clone()))
        .collect();
    let old: BTreeMap<_, _> = base
        .map(|b| {
            b.files
                .iter()
                .map(|f| (f.path.clone(), f.clone()))
                .collect()
        })
        .unwrap_or_default();
    if let Some(b) = base {
        ensure(b.app_id == options.app_id, "ULI4_BASE_MISMATCH")?;
    }
    let mut operations = Vec::new();
    for (p, f) in &new {
        match old.get(p) {
            Some(o) if o == f => {}
            Some(o) => operations.push(Operation {
                kind: OperationKind::Replace,
                file: f.clone(),
                old_sha256: Some(o.sha256.clone()),
            }),
            None => operations.push(Operation {
                kind: OperationKind::Add,
                file: f.clone(),
                old_sha256: None,
            }),
        }
    }
    for (p, f) in &old {
        if !new.contains_key(p) {
            operations.push(Operation {
                kind: OperationKind::Delete,
                file: f.clone(),
                old_sha256: Some(f.sha256.clone()),
            });
        }
    }
    operations.sort_by(|a, b| a.file.path.cmp(&b.file.path));
    let manifest = Manifest {
        format_version: 1,
        app_id: options.app_id,
        release_id: options.release_id,
        release_sequence: options.release_sequence,
        display_version: options.display_version,
        kind: if base.is_some() {
            PackageKind::Incremental
        } else {
            PackageKind::Full
        },
        base_release_id: base.map(|b| b.release_id.clone()),
        base_state_digest: base.map(|b| b.digest.clone()),
        target_os: options.target_os,
        target_arch: options.target_arch,
        target_runtime: options.target_runtime,
        min_agent_version: "0.1.0".into(),
        max_supported_protocol_major: 1,
        required_capabilities: vec!["uli4.file-v1".into()],
        components: vec![Component {
            id: "application".into(),
            kind: "source".into(),
            version: "".into(),
            profile: options.profile.clone(),
            files: preview.files.iter().map(|f| f.path.clone()).collect(),
        }],
        file_operations: operations,
        result_tree_digest: tree_digest(&preview.files)?,
        health_policy_id: options.health_policy,
        deployment_profile_id: options.profile,
        signer_key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
        signature_scope: "project".into(),
    };
    let mut manifest = manifest;
    manifest.components[0].version = manifest.display_version.clone();
    validate_manifest(&manifest, l)?;
    result_map(&manifest, base, l)?;
    let mut payload = tempfile::tempfile_in(&out)?;
    let mut entries = Vec::new();
    let mut total_plain = 0u64;
    for (i, o) in manifest.file_operations.iter().enumerate() {
        if o.kind == OperationKind::Delete {
            continue;
        }
        let offset = payload.stream_position()?;
        let mut encoder = zstd::stream::write::Encoder::new(&mut payload, 3)?;
        encoder.window_log(23)?;
        encoder.include_contentsize(true)?;
        encoder.set_pledged_src_size(Some(o.file.size))?;
        let (size, hash) = hash_copy(
            plain_file(&root.join(&o.file.path))?,
            &mut encoder,
            l.file_bytes,
        )?;
        encoder.finish()?;
        ensure(
            size == o.file.size && hash == o.file.sha256,
            "ULI4_SOURCE_CHANGED",
        )?;
        let compressed = payload.stream_position()? - offset;
        ensure(
            compressed > 0 && size <= compressed.saturating_mul(l.max_ratio),
            "ULI4_QUOTA_EXCEEDED",
        )?;
        ensure(
            payload.stream_position()? <= l.package_bytes,
            "ULI4_QUOTA_EXCEEDED",
        )?;
        total_plain = total_plain
            .checked_add(size)
            .ok_or(Error::Rejected("ULI4_QUOTA_EXCEEDED"))?;
        entries.push(Entry {
            operation: i as u32,
            offset,
            compressed,
            plain: size,
            hash: hex::decode(hash).unwrap().try_into().unwrap(),
        });
    }
    let mb = canonical_manifest(&manifest)?;
    ensure(mb.len() as u64 <= l.manifest_bytes, "ULI4_QUOTA_EXCEEDED")?;
    let ib = encode_index(&entries);
    let payload_len = payload.stream_position()?;
    payload.rewind()?;
    let (_, hash) = hash_copy(&mut payload, std::io::sink(), l.package_bytes)?;
    let header = Header {
        manifest_len: mb.len() as u64,
        index_len: ib.len() as u64,
        payload_len,
        total_plain,
        payload_hash: hex::decode(hash).unwrap().try_into().unwrap(),
    };
    ensure(header.total() <= l.package_bytes, "ULI4_QUOTA_EXCEEDED")?;
    let hb = header.encode();
    let signature = key.sign(&signing_message(&hb, &mb, &ib));
    let mut output = tempfile::NamedTempFile::new_in(&out)?;
    output.write_all(&hb)?;
    output.write_all(&mb)?;
    output.write_all(&ib)?;
    payload.rewind()?;
    std::io::copy(&mut payload, &mut output)?;
    output.write_all(&hex::decode(&manifest.signer_key_id).unwrap())?;
    output.write_all(&signature.to_bytes())?;
    output.as_file().sync_all()?;
    output
        .persist_noclobber(destination)
        .map_err(|e| Error::Io(e.error))?;
    #[cfg(unix)]
    File::open(&out)?.sync_all()?;
    Ok(manifest)
}
pub fn verify(
    path: &Path,
    trust: &TrustedProject,
    base: Option<&BaseRelease>,
    l: &Limits,
) -> Result<VerifiedPackage> {
    verify_file(plain_file(path)?, trust, base, l)
}
/// Verify the same private descriptor obtained from the Linux upload spool.
/// Caller must keep its directory private from runtime/transport writers.
#[cfg(target_os = "linux")]
pub fn verify_opened(
    file: File,
    trust: &TrustedProject,
    base: Option<&BaseRelease>,
    l: &Limits,
) -> Result<VerifiedPackage> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    ensure(m.is_file() && m.nlink() == 1, "ULI4_PATH_REJECTED")?;
    verify_file(file, trust, base, l)
}
fn verify_file(
    mut file: File,
    trust: &TrustedProject,
    base: Option<&BaseRelease>,
    l: &Limits,
) -> Result<VerifiedPackage> {
    file.seek(SeekFrom::Start(0))?;
    let actual = file.metadata()?.len();
    let mut hb = [0u8; HEADER];
    file.read_exact(&mut hb)?;
    let header = Header::decode(&hb, actual, l)?;
    let mut mb = vec![0; header.manifest_len as usize];
    file.read_exact(&mut mb)?;
    // Struct deserialization rejects duplicate and unknown keys; no arbitrary JSON object keys.
    let manifest: Manifest = serde_json::from_slice(&mb)?;
    validate_manifest(&manifest, l)?;
    ensure(
        canonical_manifest(&manifest)? == mb,
        "ULI4_MANIFEST_NONCANONICAL",
    )?;
    let mut ib = vec![0; header.index_len as usize];
    file.read_exact(&mut ib)?;
    let entries = decode_index(&ib, l)?;
    file.seek(SeekFrom::Start(header.signature_offset()))?;
    let mut envelope = [0u8; 96];
    file.read_exact(&mut envelope)?;
    let key_id = Sha256::digest(trust.key.as_bytes());
    ensure(
        envelope[..32] == key_id[..] && manifest.signer_key_id == hex::encode(key_id),
        "ULI4_SIGNER_UNTRUSTED",
    )?;
    trust
        .key
        .verify_strict(
            &signing_message(&hb, &mb, &ib),
            &Signature::from_bytes(envelope[32..].try_into().unwrap()),
        )
        .map_err(|_| Error::Rejected("ULI4_BAD_SIGNATURE"))?;
    ensure(
        manifest.app_id == trust.app_id
            && manifest.target_os == trust.target_os
            && manifest.target_arch == trust.target_arch
            && manifest.target_runtime == trust.target_runtime
            && trust
                .allowed_profiles
                .contains(&manifest.deployment_profile_id)
            && trust.health_policies.contains(&manifest.health_policy_id)
            && version(&manifest.min_agent_version).is_some_and(|v| v <= trust.agent_version)
            && manifest.release_sequence >= trust.minimum_sequence,
        "ULI4_INCOMPATIBLE",
    )?;
    let result = result_map(&manifest, base, l)?;
    let expected: Vec<_> = manifest
        .file_operations
        .iter()
        .enumerate()
        .filter(|(_, o)| o.kind != OperationKind::Delete)
        .collect();
    ensure(entries.len() == expected.len(), "ULI4_INDEX_INVALID")?;
    let (mut offset, mut plain) = (0u64, 0u64);
    for (e, (i, o)) in entries.iter().zip(expected) {
        ensure(
            e.operation as usize == i
                && e.offset == offset
                && e.plain == o.file.size
                && e.hash[..] == hex::decode(&o.file.sha256).unwrap()
                && e.compressed >= 4
                && e.plain <= e.compressed.saturating_mul(l.max_ratio),
            "ULI4_INDEX_INVALID",
        )?;
        offset = offset
            .checked_add(e.compressed)
            .ok_or(Error::Rejected("ULI4_INDEX_INVALID"))?;
        plain = plain
            .checked_add(e.plain)
            .ok_or(Error::Rejected("ULI4_INDEX_INVALID"))?;
    }
    ensure(
        offset == header.payload_len && plain == header.total_plain,
        "ULI4_INDEX_INVALID",
    )?;
    file.seek(SeekFrom::Start(header.payload_offset()))?;
    let (_, hash) = hash_copy(
        (&mut file).take(header.payload_len),
        std::io::sink(),
        l.package_bytes,
    )?;
    ensure(
        hash == hex::encode(header.payload_hash),
        "ULI4_PAYLOAD_HASH_MISMATCH",
    )?;
    let indices: Vec<_> = entries.iter().map(|e| e.operation as usize).collect();
    let mut package = VerifiedPackage {
        file,
        header,
        manifest,
        entries,
        result,
        limits: l.clone(),
    };
    for i in indices {
        package.copy_file(i, std::io::sink())?;
    }
    Ok(package)
}
