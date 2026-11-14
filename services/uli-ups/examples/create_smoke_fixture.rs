//! Isolated test fixture only, never production enrollment or alternate upload ingress.
use ed25519_dalek::SigningKey;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use uli_ups::{
    agent::Agent,
    config::{Config, TrustConfig},
};
fn main() {
    let home = PathBuf::from(std::env::args().nth(1).expect("NEW absolute fixture home"));
    assert!(home.is_absolute() && !home.exists());
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::from_bytes(&[93; 32]).verifying_key();
    let config = Config {
        config_version: 1,
        instance_id: "systemd-smoke".into(),
        app_id: "test-app".into(),
        profile_id: "static-files".into(),
        agent_home: home.clone(),
        trust: TrustConfig {
            public_key_hex: hex::encode(key.as_bytes()),
            target_runtime: "static".into(),
            health_policy_id: "files".into(),
            minimum_sequence: 1,
        },
    };
    let path = home.join("agent.json");
    fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    Agent::open(config).unwrap();
    println!("{}", path.display());
}
