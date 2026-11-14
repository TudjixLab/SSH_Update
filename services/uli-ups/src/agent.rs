use crate::{Error, Result, VERSION, config::Config, identifier, require};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use uli4::{Limits, linux::PrivateRoot, verify_opened};
use uliup_protocol::{Command, Request};
use uliup_state::{FailureCode, Job, Phase, Store};

pub struct Agent {
    pub config: Config,
    pub store: Store,
}
pub fn job_json(job: &Job) -> Value {
    json!({"job_id":job.job_id,"release_id":job.release_id,"previous_release_id":job.previous_release_id,
        "phase":job.phase,"terminal":job.terminal,"error_code":job.error_code})
}
impl Agent {
    pub fn open(config: Config) -> Result<Self> {
        config.validate()?;
        config.initialize_directories()?;
        let store = Store::open(&config.state_path(), config.instance())?;
        Ok(Self { config, store })
    }
    /// Offline owner command using the EXISTING sealed-upload, verifier and Store.
    /// Prepares immutable sources only; never claims activation/build/health success.
    pub fn stage_upload(&mut self, upload_id: &str, request_id: &str) -> Result<Value> {
        require(
            identifier(upload_id) && identifier(request_id),
            "AGENT_IDENTIFIER_INVALID",
        )?;
        let mut file = self.store.open_sealed_upload(upload_id)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        let hash = hex::encode(hash.finalize());
        file.seek(SeekFrom::Start(0))?;
        let mut package = verify_opened(
            file,
            &self.config.trusted_project()?,
            None,
            &Limits::default(),
        )?;
        // Protect the stable agent home even when ordinary project releases are signed.
        for op in &package.manifest().file_operations {
            let first = op
                .file
                .path
                .split('/')
                .next()
                .ok_or(Error("AGENT_PATH_INVALID"))?;
            let folded = caseless::default_case_fold_str(first);
            require(
                !matches!(folded.as_str(), "uliups" | "uli-ups"),
                "AGENT_PROTECTED_PATH",
            )?;
        }
        let release = package.base_release();
        self.store.register_verified(&package, &hash)?;
        let request = Request {
            protocol_major: 1,
            request_id: request_id.into(),
            expected_instance_id: self.config.instance_id.clone(),
            command: Command::StartDeploy {
                release_id: release.release_id().into(),
            },
        };
        let job = self.store.start_deploy(&request)?;
        require(
            matches!(job.phase, Phase::Verified | Phase::Prepared),
            "AGENT_JOB_PHASE_BLOCKED",
        )?;
        let pool = PrivateRoot::open(&self.config.source_path())?;
        let result =
            if std::fs::symlink_metadata(self.config.source_path().join(release.release_id()))
                .is_ok()
            {
                pool.load_base(release.release_id(), &release)
            } else {
                pool.prepare(&mut package, None)
            };
        if let Err(error) = result {
            if job.phase == Phase::Verified {
                self.store
                    .fail(&job.job_id, Phase::Verified, FailureCode::MaterializeFailed)?;
            }
            return Err(error.into());
        }
        let job = if job.phase == Phase::Verified {
            self.store
                .advance(&job.job_id, Phase::Verified, Phase::Prepared)?
        } else {
            job
        };
        Ok(
            json!({"type":"staged","activated":false,"job":job_json(&job),"code":"STAGED_NOT_ACTIVATED"}),
        )
    }
    pub fn dispatch(&mut self, request: &Request) -> Value {
        if request
            .validate_for_instance(&self.config.instance_id)
            .is_err()
        {
            return self.reply(
                &request.request_id,
                json!({"type":"error","code":"WRONG_INSTANCE"}),
            );
        }
        let body = match self.read_command(&request.command) {
            Ok(body) => body,
            Err(error) => json!({"type":"error","code":error.0}),
        };
        self.reply(&request.request_id, body)
    }
    fn reply(&self, id: &str, body: Value) -> Value {
        json!({"protocol_major":1,"request_id":id,"instance_id":self.config.instance_id,"body":body})
    }
    fn execution_view(&self, job: &Job) -> Result<Value> {
        let record = crate::journal::inspect(
            &self.config.state_path(),
            &self.config.instance_id,
            &job.job_id,
        )?;
        if let Some(record) = record {
            require(
                record.binding.release_id == job.release_id
                    && record.binding.previous_release_id == job.previous_release_id
                    && record.binding.profile_id == self.config.profile_id,
                "EXEC_BINDING_CONFLICT",
            )?;
            Ok(
                json!({"step":record.step,"generation":record.generation,"failure":record.failure,
                "recovery":record.recovery_decision(),"profile_sha256":record.binding.profile_sha256}),
            )
        } else {
            Ok(Value::Null)
        }
    }
    fn read_command(&self, command: &Command) -> Result<Value> {
        Ok(match command {
            Command::Hello {} => {
                json!({"type":"hello","agent_version":VERSION,"supported_uli4_major":[1],
                "supported_profiles":[],"capabilities":["durable_jobs","job_events"]})
            }
            Command::Capabilities {} => {
                json!({"type":"capabilities","capabilities":["durable_jobs","job_events"]})
            }
            Command::AgentVersion {} => json!({"type":"agent_version","agent_version":VERSION}),
            Command::InstanceInfo {} | Command::Health {} => {
                let pending = self.store.pending_job()?;
                let execution = pending
                    .as_ref()
                    .map(|job| self.execution_view(job))
                    .transpose()?;
                json!({"type":"instance_info","agent_version":VERSION,"instance_id":self.config.instance_id,
                    "app_id":self.config.app_id,"profile_id":self.config.profile_id,
                    "active_release_id":self.store.active_release()?,
                    "pending_job":pending.as_ref().map(job_json),"execution":execution,
                    "status":if pending.is_some() {"RECOVERY_BLOCKED_INTERFACE"}else{"READY"},
                    "deployment_enabled":false})
            }
            Command::GetJob { job_id } => {
                let job = self.store.job(job_id)?;
                let execution = job.as_ref().map(|j| self.execution_view(j)).transpose()?;
                json!({"type":"job","job":job.as_ref().map(job_json),"execution":execution})
            }
            Command::ListEvents {
                after_event_id,
                limit,
            }
            | Command::ListErrors {
                after_event_id,
                limit,
            } => {
                let after =
                    i64::try_from(*after_event_id).map_err(|_| Error("AGENT_CURSOR_INVALID"))?;
                let events = self.store.events(after, *limit)?;
                let errors_only = matches!(command, Command::ListErrors { .. });
                let mut cursor = after;
                let mut used = 0usize;
                let mut page = Vec::new();
                // Reserve the bounded ASCII envelope, identifiers, cursor and newline.
                let budget = uliup_protocol::MAX_MESSAGE_BYTES - 2048;
                for event in events {
                    if errors_only && event.error_code.is_none() {
                        cursor = event.event_id;
                        continue;
                    }
                    let value = json!({"event_id":event.event_id,"job_id":event.job_id,"code":event.code,"error_code":event.error_code});
                    let size = serde_json::to_vec(&value)
                        .map_err(|_| Error("AGENT_RESPONSE_INVALID"))?
                        .len()
                        + 1;
                    if used + size > budget {
                        require(!page.is_empty(), "AGENT_EVENT_TOO_LARGE")?;
                        break;
                    }
                    used += size;
                    cursor = event.event_id;
                    page.push(value);
                }
                let events = page;

                json!({"type":"events","events":events,"next_after_event_id":cursor})
            }
            Command::StartDeploy { .. } | Command::RequestRollback { .. } => {
                return Err(Error("AGENT_DEPLOY_API_REQUIRED"));
            }
            Command::ValidateRelease { .. } => return Err(Error("AGENT_VALIDATE_API_REQUIRED")),
            // Qwen owns these endpoints. Do not create an independent upload transport.
            _ => return Err(Error("UNSUPPORTED_COMMAND")),
        })
    }
}
