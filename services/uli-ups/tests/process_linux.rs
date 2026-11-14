#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uli_ups::{
    agent::Agent,
    config::{Config, TrustConfig},
    control,
};
use uli4::*;
use uliup_protocol::{Command as WireCommand, Request};
use uliup_state::{Phase, Store, UploadLimits, UploadState};

struct Fixture {
    temp: tempfile::TempDir,
    config: Config,
    path: PathBuf,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("UliUpS");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::from_bytes(&[93; 32]);
        let config = Config {
            config_version: 1,
            instance_id: "test-instance".into(),
            app_id: "test-app".into(),
            profile_id: "static-files".into(),
            agent_home: home.clone(),
            trust: TrustConfig {
                public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                target_runtime: "static".into(),
                health_policy_id: "files".into(),
                minimum_sequence: 1,
            },
        };
        let path = home.join("agent.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            temp,
            config,
            path,
            key,
        }
    }
    fn agent(&self) -> Agent {
        Agent::open(self.config.clone()).unwrap()
    }
    fn package(&self, protected: bool) -> PathBuf {
        let source = self.temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("index.html"), b"test release").unwrap();
        if protected {
            fs::create_dir(source.join("UliUpS")).unwrap();
            fs::write(source.join("UliUpS/agent.json"), b"forbidden").unwrap();
        }
        let path = self.temp.path().join("release.uli4");
        pack(
            &source,
            &path,
            PackageOptions {
                app_id: "test-app".into(),
                release_id: "release-1".into(),
                release_sequence: 1,
                display_version: "0.1".into(),
                target_os: "linux".into(),
                target_arch: "x86_64".into(),
                target_runtime: self.config.trust.target_runtime.clone(),
                profile: self.config.profile_id.clone(),
                health_policy: self.config.trust.health_policy_id.clone(),
            },
            &self.key,
            None,
            &Limits::default(),
        )
        .unwrap();
        path
    }
    fn upload(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut agent = self.agent();
        let req = Request {
            protocol_major: 1,
            request_id: "begin".into(),
            expected_instance_id: self.config.instance_id.clone(),
            command: WireCommand::BeginUpload {
                app_id: self.config.app_id.clone(),
                size: data.len() as u64,
                package_sha256: hex::encode(Sha256::digest(data)),
            },
        };
        let u = agent
            .store
            .begin_upload(&req, UploadLimits::default())
            .unwrap();
        agent.store.append_upload(&u.upload_id, 0, data).unwrap();
        let req = Request {
            protocol_major: 1,
            request_id: "finish".into(),
            expected_instance_id: self.config.instance_id.clone(),
            command: WireCommand::FinalizeUpload {
                upload_id: u.upload_id.clone(),
            },
        };
        assert_eq!(
            agent.store.finalize_upload(&req).unwrap().state,
            UploadState::Sealed
        );
        u.upload_id
    }
    fn command(&self, cmd: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_uli-ups"));
        c.args([cmd, "--config", self.path.to_str().unwrap()]);
        c
    }
    fn spawn(&self) -> Process {
        let log = fs::File::create(self.temp.path().join("agent.log")).unwrap();
        let child = self
            .command("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut p = Process(child);
        let start = Instant::now();
        loop {
            if let Ok(value) = self.request(WireCommand::Health {}) {
                assert_eq!(value["body"]["type"], "instance_info");
                break;
            }
            if let Some(exit) = p.0.try_wait().unwrap() {
                panic!(
                    "agent exited {exit}; {}",
                    fs::read_to_string(self.temp.path().join("agent.log")).unwrap()
                );
            }
            assert!(
                start.elapsed() < Duration::from_secs(8),
                "agent did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        p
    }
    fn request(&self, command: WireCommand) -> uli_ups::Result<Value> {
        let req = Request {
            protocol_major: 1,
            request_id: "query".into(),
            expected_instance_id: self.config.instance_id.clone(),
            command,
        };
        control::request(&self.config, &serde_json::to_vec(&req).unwrap())
    }
}
struct Process(Child);
impl Process {
    fn signal(&mut self, signal: &str) {
        assert!(
            Command::new("/bin/kill")
                .args([signal, &self.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    fn stopped(&mut self) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "agent failed to stop"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn binary_starts_store_answers_existing_hello_and_stops_sigterm() {
    let f = Fixture::new();
    let mut p = f.spawn();
    let hello = f.request(WireCommand::Hello {}).unwrap();
    assert_eq!(hello["body"]["agent_version"], "0.1.0");
    // Hello remains compatible with the shared strict response schema.
    serde_json::from_value::<uliup_protocol::Response>(hello).unwrap();
    assert!(f.config.state_path().join("state.sqlite").exists());
    assert_eq!(
        f.request(WireCommand::Health {}).unwrap()["body"]["status"],
        "READY"
    );
    p.signal("-TERM");
    assert!(p.stopped().success());
    assert!(!f.config.socket_path().exists());
    Store::open(&f.config.state_path(), f.config.instance()).unwrap();
}
#[test]
fn sigint_interrupts_a_partial_control_request_with_bounded_shutdown() {
    let f = Fixture::new();
    let mut p = f.spawn();
    let mut stream = UnixStream::connect(f.config.socket_path()).unwrap();
    stream.write_all(b"{").unwrap();
    std::thread::sleep(Duration::from_millis(80));
    p.signal("-INT");
    assert!(p.stopped().success());
    assert!(!f.config.socket_path().exists());
}
#[test]
fn second_daemon_is_refused_and_first_remains_available() {
    let f = Fixture::new();
    let _p = f.spawn();
    let second = f.command("serve").output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("AGENT_ALREADY_RUNNING"));
    assert_eq!(
        f.request(WireCommand::AgentVersion {}).unwrap()["body"]["agent_version"],
        "0.1.0"
    );
}
#[test]
fn registered_signed_upload_stages_through_cli_and_survives_process_kill() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    let package = f.package(false);
    let data = fs::read(&package).unwrap();
    let upload = f.upload(&data);
    // The package is already registered by the shared API before server staging.
    let verified = verify(
        &package,
        &f.config.trusted_project().unwrap(),
        None,
        &Limits::default(),
    )
    .unwrap();
    f.agent()
        .store
        .register_verified(&verified, &hex::encode(Sha256::digest(&data)))
        .unwrap();
    let output = f
        .command("stage-upload")
        .args(["--upload-id", &upload, "--request-id", "stage-1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let staged: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(staged["activated"], false);
    assert_eq!(staged["job"]["phase"], "PREPARED");
    let job_id = staged["job"]["job_id"].as_str().unwrap().to_owned();
    assert_eq!(
        fs::read(f.config.source_path().join("release-1/index.html")).unwrap(),
        b"test release"
    );
    let mut p = f.spawn();
    assert_eq!(
        f.request(WireCommand::Health {}).unwrap()["body"]["status"],
        "RECOVERY_BLOCKED_INTERFACE"
    );
    p.signal("-KILL");
    assert!(!p.stopped().success());
    let mut p = f.spawn(); // Recovers stale socket and reads the same durable job.
    assert_eq!(
        f.request(WireCommand::GetJob {
            job_id: job_id.clone()
        })
        .unwrap()["body"]["job"]["phase"],
        "PREPARED"
    );
    assert_eq!(
        f.agent().store.job(&job_id).unwrap().unwrap().phase,
        Phase::Prepared
    );
    p.signal("-TERM");
    assert!(p.stopped().success());
    let repeated = f
        .command("stage-upload")
        .args(["--upload-id", &upload, "--request-id", "stage-1"])
        .output()
        .unwrap();
    assert!(repeated.status.success());
    let repeated: Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(repeated["job"]["job_id"], job_id);
    assert_eq!(f.agent().store.active_release().unwrap(), None);
}
#[test]
fn bad_signature_and_protected_agent_files_never_create_deploy_job() {
    for protected in [false, true] {
        let f = Fixture::new();
        let package = f.package(protected);
        let mut data = fs::read(package).unwrap();
        if !protected {
            let last = data.len() - 1;
            data[last] ^= 1;
        }
        let upload = f.upload(&data);
        let result = f
            .command("stage-upload")
            .args(["--upload-id", &upload, "--request-id", "stage-1"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        let log = String::from_utf8_lossy(&result.stderr);
        assert!(log.contains(if protected {
            "AGENT_PROTECTED_PATH"
        } else {
            "ULI4_BAD_SIGNATURE"
        }));
        assert!(f.agent().store.pending_job().unwrap().is_none());
        assert!(!f.config.source_path().join("release-1").exists());
    }
}
#[test]
fn materialization_failure_is_persisted_and_returned_as_an_error_event() {
    let f = Fixture::new();
    let data = fs::read(f.package(false)).unwrap();
    let upload = f.upload(&data);
    let invalid = f.config.source_path().join("release-1");
    fs::create_dir(&invalid).unwrap();
    fs::set_permissions(&invalid, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(invalid.join("index.html"), b"wrong bytes").unwrap();
    let result = f
        .command("stage-upload")
        .args(["--upload-id", &upload, "--request-id", "stage-1"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let _p = f.spawn();
    let events = f
        .request(WireCommand::ListErrors {
            after_event_id: 0,
            limit: 100,
        })
        .unwrap();
    assert!(
        events["body"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["error_code"] == "MATERIALIZE_FAILED")
    );
    assert_eq!(f.agent().store.active_release().unwrap(), None);
}
#[test]
fn malformed_wrong_instance_and_unavailable_deployment_fail_closed() {
    let f = Fixture::new();
    let _p = f.spawn();
    let blocked = f
        .request(WireCommand::StartDeploy {
            release_id: "anything".into(),
        })
        .unwrap();
    assert_eq!(blocked["body"]["code"], "AGENT_DEPLOY_API_REQUIRED");
    assert!(f.agent().store.pending_job().unwrap().is_none());
    let mut stream = UnixStream::connect(f.config.socket_path()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"{\"shell\":\"secret-canary\"}\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["body"]["code"],
        "BAD_REQUEST"
    );
    assert!(
        !fs::read_to_string(f.temp.path().join("agent.log"))
            .unwrap()
            .contains("secret-canary")
    );
    let req = Request {
        protocol_major: 1,
        request_id: "wrong".into(),
        expected_instance_id: "different".into(),
        command: WireCommand::Health {},
    };
    let mut stream = UnixStream::connect(f.config.socket_path()).unwrap();
    let mut bytes = serde_json::to_vec(&req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    let mut bytes = String::new();
    stream.read_to_string(&mut bytes).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&bytes).unwrap()["body"]["code"],
        "WRONG_INSTANCE"
    );
}
#[test]
fn unsafe_unknown_or_symlink_configuration_is_rejected_without_leaking_values() {
    let f = Fixture::new();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(Config::load(&f.path).unwrap_err().0, "AGENT_CONFIG_UNSAFE");
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = f.config.agent_home.join("alias.json");
    symlink(&f.path, &alias).unwrap();
    assert!(Config::load(&alias).is_err());
    let mut value = serde_json::to_value(&f.config).unwrap();
    value["secret"] = json!("must-not-leak");
    fs::write(&f.path, serde_json::to_vec(&value).unwrap()).unwrap();
    let result = f.command("serve").output().unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("must-not-leak"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("AGENT_CONFIG_INVALID"));
}

#[test]
fn event_pages_obey_wire_budget_without_losing_cursor_entries() {
    let f = Fixture::new();
    {
        let mut agent = f.agent();
        for i in 0..1000 {
            let request = Request {
                protocol_major: 1,
                request_id: format!("reserve-{i}"),
                expected_instance_id: f.config.instance_id.clone(),
                command: WireCommand::BeginUpload {
                    app_id: f.config.app_id.clone(),
                    size: 1,
                    package_sha256: "0".repeat(64),
                },
            };
            agent
                .store
                .begin_upload(
                    &request,
                    UploadLimits {
                        max_uploads: 1024,
                        max_reserved_bytes: 64 * 1024 * 1024,
                    },
                )
                .unwrap();
        }
    }
    let _p = f.spawn();
    let mut cursor = 0u64;
    let mut ids = Vec::new();
    let mut pages = 0;
    loop {
        let response = f
            .request(WireCommand::ListEvents {
                after_event_id: cursor,
                limit: 1000,
            })
            .unwrap();
        assert!(serde_json::to_vec(&response).unwrap().len() < uliup_protocol::MAX_MESSAGE_BYTES);
        let events = response["body"]["events"].as_array().unwrap();
        if events.is_empty() {
            break;
        }
        pages += 1;
        for event in events {
            ids.push(event["event_id"].as_u64().unwrap());
        }
        let next = response["body"]["next_after_event_id"].as_u64().unwrap();
        assert!(next > cursor);
        cursor = next;
    }
    assert!(pages > 1);
    assert_eq!(ids, (1..=1000).collect::<Vec<_>>());
}

#[test]
fn configured_anchor_symlinks_are_not_adopted() {
    for name in ["state", "sources"] {
        let f = Fixture::new();
        let outside = f.temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(outside.join("sentinel"), b"preserve").unwrap();
        symlink(&outside, f.config.agent_home.join(name)).unwrap();
        assert!(Agent::open(f.config.clone()).is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"preserve");
        assert!(!outside.join("state.sqlite").exists());
    }
}

#[test]
fn execution_intent_is_visible_without_advancing_store_or_running_project_actions() {
    use uli_ups::journal::{Journal, Step};
    let mut f = Fixture::new();
    f.config.profile_id = "nextjs-systemd".into();
    f.config.trust.target_runtime = "node-24".into();
    fs::write(&f.path, serde_json::to_vec(&f.config).unwrap()).unwrap();
    let package = f.package(false);
    let upload = f.upload(&fs::read(package).unwrap());
    let mut agent = f.agent();
    let staged = agent.stage_upload(&upload, "stage-journal").unwrap();
    let id = staged["job"]["job_id"].as_str().unwrap().to_owned();
    let job = agent.store.job(&id).unwrap().unwrap();
    let mut journal = Journal::open(&f.config.state_path(), &f.config.instance_id).unwrap();
    journal.begin(&job, &"a".repeat(64)).unwrap();
    journal
        .advance(&id, 0, Step::Prepared, Step::StopIntent, None)
        .unwrap();
    drop(journal);
    drop(agent);
    let _p = f.spawn();
    let response = f
        .request(WireCommand::GetJob { job_id: id.clone() })
        .unwrap();
    assert_eq!(response["body"]["execution"]["step"], "STOP_INTENT");
    assert_eq!(
        response["body"]["execution"]["recovery"],
        "RECONCILE_EXTERNAL_STATE"
    );
    assert_eq!(
        f.agent().store.job(&id).unwrap().unwrap().phase,
        Phase::Prepared
    );
    fs::write(
        f.config
            .state_path()
            .join("execution")
            .join(format!("{id}.json")),
        b"{broken",
    )
    .unwrap();
    let response = f
        .request(WireCommand::GetJob { job_id: id.clone() })
        .unwrap();
    assert_eq!(response["body"]["code"], "EXEC_JOURNAL_CORRUPT");
    assert_eq!(
        f.agent().store.job(&id).unwrap().unwrap().phase,
        Phase::Prepared
    );
}
