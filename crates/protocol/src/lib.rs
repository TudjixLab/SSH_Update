//! Bounded wire schemas for an authenticated, restricted deployment endpoint.
//!
//! Decoding does not authenticate, authorize or reserve a request ID. A server
//! must also bind the expected instance, authorize the command and durably map
//! each request ID to its original request/outcome before performing side effects.
//! Retrying an ID with different content must fail; a matching retry reuses the
//! original outcome. No variant accepts a shell command or a filesystem path.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: u16 = 1000;
pub const MAX_UPLOAD_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_major: u16,
    pub request_id: String,
    pub expected_instance_id: String,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Hello {},
    Capabilities {},
    InstanceInfo {},
    ListReleases {
        after_release_id: Option<String>,
        limit: u16,
    },
    BeginUpload {
        app_id: String,
        size: u64,
        package_sha256: String,
    },
    ResumeUpload {
        upload_id: String,
    },
    FinalizeUpload {
        upload_id: String,
    },
    ValidateRelease {
        upload_id: String,
    },
    StartDeploy {
        release_id: String,
    },
    GetJob {
        job_id: String,
    },
    ListEvents {
        after_event_id: u64,
        limit: u16,
    },
    ListErrors {
        after_event_id: u64,
        limit: u16,
    },
    AckReport {
        report_id: String,
    },
    RequestRollback {
        release_id: String,
    },
    Health {},
    AgentVersion {},
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    MessageTooLarge,
    ReadFailed,
    InvalidJson,
    UnsupportedProtocol { found: u16 },
    InvalidField(&'static str),
    WrongInstance,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge => f.write_str("protocol message exceeds 64 KiB"),
            Self::ReadFailed => f.write_str("protocol message could not be read"),
            Self::InvalidJson => f.write_str("invalid or unsupported protocol schema"),
            Self::UnsupportedProtocol { found } => write!(f, "unsupported protocol major: {found}"),
            Self::InvalidField(field) => write!(f, "invalid protocol field: {field}"),
            Self::WrongInstance => f.write_str("request targets a different instance"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Parse one complete JSON message, rejecting unknown/duplicate fields and suffixes.
/// The caller must enforce a transport deadline independently of this byte bound.
pub fn decode_request(bytes: &[u8]) -> Result<Request, DecodeError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DecodeError::MessageTooLarge);
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| DecodeError::InvalidJson)?;
    request.validate()?;
    Ok(request)
}

/// Read no more than the message bound plus one byte, then use the strict decoder.
/// This consumes a single framed message or an EOF-terminated restricted channel;
/// it is not a parser for an unframed persistent stream.
pub fn decode_request_from_reader(reader: impl Read) -> Result<Request, DecodeError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| DecodeError::ReadFailed)?;
    decode_request(&bytes)
}

impl Request {
    /// Validate values even when a request was constructed directly rather than decoded.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.protocol_major != PROTOCOL_MAJOR {
            return Err(DecodeError::UnsupportedProtocol {
                found: self.protocol_major,
            });
        }
        identifier(&self.request_id, "request_id")?;
        identifier(&self.expected_instance_id, "expected_instance_id")?;
        match &self.command {
            Command::ListReleases {
                after_release_id,
                limit,
            } => {
                page_limit(*limit)?;
                if let Some(id) = after_release_id {
                    identifier(id, "after_release_id")?;
                }
            }
            Command::BeginUpload {
                app_id,
                size,
                package_sha256,
            } => {
                identifier(app_id, "app_id")?;
                if *size == 0 || *size > MAX_UPLOAD_BYTES {
                    return Err(DecodeError::InvalidField("size"));
                }
                if package_sha256.len() != 64
                    || !package_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(DecodeError::InvalidField("package_sha256"));
                }
            }
            Command::ResumeUpload { upload_id }
            | Command::FinalizeUpload { upload_id }
            | Command::ValidateRelease { upload_id } => identifier(upload_id, "upload_id")?,
            Command::StartDeploy { release_id } | Command::RequestRollback { release_id } => {
                identifier(release_id, "release_id")?
            }
            Command::GetJob { job_id } => identifier(job_id, "job_id")?,
            Command::ListEvents { limit, .. } | Command::ListErrors { limit, .. } => {
                page_limit(*limit)?
            }
            Command::AckReport { report_id } => identifier(report_id, "report_id")?,
            Command::Hello {}
            | Command::Capabilities {}
            | Command::InstanceInfo {}
            | Command::Health {}
            | Command::AgentVersion {} => {}
        }
        Ok(())
    }

    /// Identity binding is required in addition to transport authentication/authorization.
    pub fn validate_for_instance(&self, actual_instance_id: &str) -> Result<(), DecodeError> {
        self.validate()?;
        if self.expected_instance_id != actual_instance_id {
            return Err(DecodeError::WrongInstance);
        }
        Ok(())
    }
}

fn identifier(value: &str, field: &'static str) -> Result<(), DecodeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(DecodeError::InvalidField(field));
    }
    Ok(())
}

fn page_limit(limit: u16) -> Result<(), DecodeError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(DecodeError::InvalidField("limit"));
    }
    Ok(())
}

/// Capability names are a closed vocabulary, not commands or policy expressions.
/// Advertise only capabilities actually implemented and authorized by the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Uli4FullV1,
    Uli4FileIncrementalV1,
    ResumableUpload,
    DurableJobs,
    JobEvents,
    AuthorizedRollback,
    OfficialAgentUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    BadRequest,
    UnsupportedProtocol,
    WrongInstance,
    Unauthorized,
    Conflict,
    UnsupportedCommand,
    QuotaExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_major: u16,
    pub request_id: String,
    pub instance_id: String,
    pub body: ResponseBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseBody {
    Hello {
        agent_version: String,
        supported_uli4_major: Vec<u16>,
        supported_profiles: Vec<String>,
        capabilities: Vec<Capability>,
    },
    Capabilities {
        capabilities: Vec<Capability>,
    },
    Error {
        code: ErrorCode,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(command: &str) -> Vec<u8> {
        format!("{{\"protocol_major\":1,\"request_id\":\"req-1\",\"expected_instance_id\":\"instance-1\",\"command\":{command}}}").into_bytes()
    }

    #[test]
    fn valid_request_and_hello_response() {
        let request = decode_request(&message(r#"{"type":"hello"}"#)).unwrap();
        assert_eq!(request.command, Command::Hello {});
        request.validate_for_instance("instance-1").unwrap();
        let response = Response {
            protocol_major: PROTOCOL_MAJOR,
            request_id: request.request_id,
            instance_id: "instance-1".into(),
            body: ResponseBody::Hello {
                agent_version: "0.1.0".into(),
                supported_uli4_major: vec![1],
                supported_profiles: vec![],
                capabilities: vec![Capability::Uli4FullV1],
            },
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            serde_json::from_slice::<Response>(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn oversized_message_rejected_before_json_parse() {
        let bytes = vec![b' '; MAX_MESSAGE_BYTES + 1];
        assert_eq!(decode_request(&bytes), Err(DecodeError::MessageTooLarge));
        assert_eq!(
            decode_request_from_reader(bytes.as_slice()),
            Err(DecodeError::MessageTooLarge)
        );
    }

    #[test]
    fn unknown_command_rejected() {
        assert_eq!(
            decode_request(&message(r#"{"type":"shell","command":"whoami"}"#)),
            Err(DecodeError::InvalidJson)
        );
    }

    #[test]
    fn wrong_protocol_major_rejected() {
        let bytes = String::from_utf8(message(r#"{"type":"hello"}"#))
            .unwrap()
            .replace("\"protocol_major\":1", "\"protocol_major\":2");
        assert_eq!(
            decode_request(bytes.as_bytes()),
            Err(DecodeError::UnsupportedProtocol { found: 2 })
        );
    }

    #[test]
    fn empty_request_or_instance_id_rejected() {
        for (original, replacement, field) in [
            (
                "\"request_id\":\"req-1\"",
                "\"request_id\":\"\"",
                "request_id",
            ),
            (
                "\"expected_instance_id\":\"instance-1\"",
                "\"expected_instance_id\":\"\"",
                "expected_instance_id",
            ),
        ] {
            let bytes = String::from_utf8(message(r#"{"type":"hello"}"#))
                .unwrap()
                .replace(original, replacement);
            assert_eq!(
                decode_request(bytes.as_bytes()),
                Err(DecodeError::InvalidField(field))
            );
        }
    }

    #[test]
    fn unknown_and_duplicate_fields_rejected() {
        assert_eq!(
            decode_request(&message(r#"{"type":"hello","shell":"whoami"}"#)),
            Err(DecodeError::InvalidJson)
        );
        let bytes = String::from_utf8(message(r#"{"type":"hello"}"#))
            .unwrap()
            .replacen("{", "{\"extra\":0,", 1);
        assert_eq!(
            decode_request(bytes.as_bytes()),
            Err(DecodeError::InvalidJson)
        );
        let bytes = String::from_utf8(message(r#"{"type":"hello"}"#))
            .unwrap()
            .replace(
                "\"request_id\":\"req-1\"",
                "\"request_id\":\"req-1\",\"request_id\":\"req-2\"",
            );
        assert_eq!(
            decode_request(bytes.as_bytes()),
            Err(DecodeError::InvalidJson)
        );
    }

    #[test]
    fn instance_binding_and_page_limits() {
        let request = decode_request(&message(r#"{"type":"health"}"#)).unwrap();
        assert_eq!(
            request.validate_for_instance("different"),
            Err(DecodeError::WrongInstance)
        );
        assert_eq!(
            decode_request(&message(
                r#"{"type":"list_events","after_event_id":0,"limit":0}"#
            )),
            Err(DecodeError::InvalidField("limit"))
        );
    }
}
