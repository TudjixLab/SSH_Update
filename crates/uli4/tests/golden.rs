use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use uli4::*;
const FULL: &[u8] = include_bytes!("fixtures/full-v1.bin");
const DELTA: &[u8] = include_bytes!("fixtures/incremental-v1.bin");
fn trust() -> TrustedProject {
    TrustedProject {
        key: SigningKey::from_bytes(&[21; 32]).verifying_key(),
        app_id: "golden-app".into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
        target_runtime: "static".into(),
        allowed_profiles: vec!["static-files".into()],
        health_policies: vec!["files".into()],
        agent_version: (0, 1, 0),
        minimum_sequence: 1,
    }
}
fn value(b: &[u8], i: usize) -> usize {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) as usize
}
fn manifest() -> serde_json::Value {
    serde_json::from_slice(&FULL[160..value(FULL, 32)]).unwrap()
}
fn resign(mb: Vec<u8>) -> Vec<u8> {
    let mut h = FULL[..160].to_vec();
    let old_index = value(FULL, 32);
    let old_payload = value(FULL, 48);
    let old_sig = value(FULL, 64);
    let index = &FULL[old_index..old_payload];
    let payload = &FULL[old_payload..old_sig];
    let index_offset = 160 + mb.len();
    let payload_offset = index_offset + index.len();
    let sig_offset = payload_offset + payload.len();
    for (i, n) in [
        (24, mb.len()),
        (32, index_offset),
        (48, payload_offset),
        (64, sig_offset),
        (80, sig_offset + 96),
    ] {
        h[i..i + 8].copy_from_slice(&(n as u64).to_le_bytes());
    }
    let message = [b"ULI4-SIGN-V1\0".as_slice(), &h, &mb, index].concat();
    let signature = SigningKey::from_bytes(&[21; 32]).sign(&message);
    [
        h.as_slice(),
        &mb,
        index,
        payload,
        &FULL[old_sig..old_sig + 32],
        &signature.to_bytes(),
    ]
    .concat()
}
#[test]
fn fixed_full_and_incremental_vectors() {
    let t = tempfile::tempdir().unwrap();
    let a = t.path().join("full");
    let b = t.path().join("delta");
    fs::write(&a, FULL).unwrap();
    fs::write(&b, DELTA).unwrap();
    let base = verify(&a, &trust(), None, &Limits::default())
        .unwrap()
        .base_release();
    let delta = verify(&b, &trust(), Some(&base), &Limits::default()).unwrap();
    assert_eq!(base.release_id(), "golden-full");
    assert_eq!(delta.base_release().release_id(), "golden-delta");
    assert_eq!(
        delta
            .base_release()
            .files()
            .iter()
            .map(|f| f.path.as_str())
            .collect::<Vec<_>>(),
        ["change.txt", "same.txt", "История.txt"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(FULL)),
        include_str!("fixtures/full-v1.bin.sha256")
            .split_whitespace()
            .next()
            .unwrap()
    );
    assert_eq!(
        hex::encode(Sha256::digest(DELTA)),
        include_str!("fixtures/incremental-v1.bin.sha256")
            .split_whitespace()
            .next()
            .unwrap()
    );
}
#[test]
fn correctly_signed_but_forbidden_manifests_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("bad");
    let mut cases = Vec::new();
    let mut m = manifest();
    m["postinstall"] = serde_json::json!("run-shell");
    cases.push(serde_json::to_vec(&m).unwrap());
    let mut m = manifest();
    m["release_sequence"] = serde_json::json!(9007199254740992u64);
    cases.push(serde_json::to_vec(&m).unwrap());
    let mut m = manifest();
    m["file_operations"][0]["file"]["path"] = serde_json::json!("../../escape");
    cases.push(serde_json::to_vec(&m).unwrap());
    let mut m = manifest();
    m["file_operations"][0]["file"]["path"] = serde_json::json!("ſecrets/file");
    cases.push(serde_json::to_vec(&m).unwrap());
    let mut m = manifest();
    m["required_capabilities"] = serde_json::json!(["arbitrary-shell"]);
    cases.push(serde_json::to_vec(&m).unwrap());
    let original = &FULL[160..value(FULL, 32)];
    cases.push([b"{\"app_id\":\"golden-app\",".as_slice(), &original[1..]].concat());
    cases.push([b" ".as_slice(), original].concat());
    for bytes in cases {
        fs::write(&p, resign(bytes)).unwrap();
        assert!(verify(&p, &trust(), None, &Limits::default()).is_err());
    }
}
#[test]
fn deterministic_bounded_mutation_corpus_does_not_panic_or_accept_damage() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("mutated");
    let mut state = 0x554c4934u64;
    for n in 0..256 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = FULL.to_vec();
        if n % 4 == 0 {
            bytes.truncate(state as usize % bytes.len());
        } else {
            let i = state as usize % bytes.len();
            bytes[i] ^= 1u8 << (n % 8);
        }
        fs::write(&p, bytes).unwrap();
        assert!(verify(&p, &trust(), None, &Limits::default()).is_err());
    }
}
