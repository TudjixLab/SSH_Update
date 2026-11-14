//! Bounded local HTTP transport probe. Not proof of process/cgroup identity.
//! The executor must independently confirm the selected release/unit/PID before
//! and after this probe before committing a deployment.
use crate::{Error, Result, identifier, require};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHealth {
    pub address: IpAddr,
    pub port: u16,
    pub path: String,
    pub deadline_ms: u16,
    pub expected_status: u16,
    pub release_header: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpObservation {
    pub status: u16,
    pub release_header_matched: bool,
}
impl HttpHealth {
    pub fn validate(&self) -> Result<()> {
        require(
            matches!(self.address,IpAddr::V4(v) if v==std::net::Ipv4Addr::LOCALHOST)
                || matches!(self.address,IpAddr::V6(v) if v==std::net::Ipv6Addr::LOCALHOST),
            "HEALTH_NOT_LOOPBACK",
        )?;
        require(
            self.port != 0
                && (50..=15000).contains(&self.deadline_ms)
                && (200..=299).contains(&self.expected_status),
            "HEALTH_POLICY_INVALID",
        )?;
        require(
            self.path.starts_with('/')
                && self.path.len() <= 1024
                && self
                    .path
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b'#'),
            "HEALTH_PATH_INVALID",
        )?;
        if let Some(header) = &self.release_header {
            require(
                !header.is_empty()
                    && header.len() <= 64
                    && header
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "HEALTH_HEADER_INVALID",
            )?;
        }
        Ok(())
    }
    pub fn probe(&self, release_id: &str, cancel: &AtomicBool) -> Result<HttpObservation> {
        self.validate()?;
        require(identifier(release_id), "HEALTH_RELEASE_INVALID")?;
        let until = Instant::now() + Duration::from_millis(self.deadline_ms.into());
        check_deadline(until, cancel)?;
        let address = SocketAddr::new(self.address, self.port);
        let mut stream = loop {
            check_deadline(until, cancel)?;
            let remaining = until.saturating_duration_since(Instant::now());
            match TcpStream::connect_timeout(&address, remaining.min(Duration::from_millis(100))) {
                Ok(stream) => break stream,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error("HEALTH_CONNECT_FAILED")),
            }
        };
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: uli-ups/0.1\r\n\r\n",
            self.path, address
        );
        let mut remaining = request.as_bytes();
        while !remaining.is_empty() {
            check_deadline(until, cancel)?;
            stream.set_write_timeout(Some(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50))
                    .max(Duration::from_millis(1)),
            ))?;
            match stream.write(remaining) {
                Ok(0) => return Err(Error("HEALTH_WRITE_FAILED")),
                Ok(n) => remaining = &remaining[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error("HEALTH_WRITE_FAILED")),
            }
        }
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            check_deadline(until, cancel)?;
            stream.set_read_timeout(Some(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50))
                    .max(Duration::from_millis(1)),
            ))?;
            match stream.read(&mut buffer) {
                Ok(0) => return Err(Error("HEALTH_INCOMPLETE_RESPONSE")),
                Ok(n) => {
                    check_deadline(until, cancel)?;
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        require(end + 4 <= MAX_HEADER_BYTES, "HEALTH_HEADERS_TOO_LARGE")?;
                        let observed = parse(&bytes[..end], self, release_id)?;
                        check_deadline(until, cancel)?;
                        return Ok(observed);
                    }
                    require(bytes.len() < MAX_HEADER_BYTES, "HEALTH_HEADERS_TOO_LARGE")?;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error("HEALTH_READ_FAILED")),
            }
        }
    }
}
fn check_deadline(until: Instant, cancel: &AtomicBool) -> Result<()> {
    require(!cancel.load(Ordering::Relaxed), "HEALTH_CANCELLED")?;
    require(Instant::now() < until, "HEALTH_DEADLINE")
}
fn parse(bytes: &[u8], policy: &HttpHealth, release_id: &str) -> Result<HttpObservation> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error("HEALTH_RESPONSE_INVALID"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or(Error("HEALTH_RESPONSE_INVALID"))?;
    let (version, rest) = line
        .split_once(' ')
        .ok_or(Error("HEALTH_RESPONSE_INVALID"))?;
    require(
        matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "HEALTH_RESPONSE_INVALID",
    )?;
    let code = rest
        .split(' ')
        .next()
        .ok_or(Error("HEALTH_RESPONSE_INVALID"))?;
    require(
        code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()),
        "HEALTH_RESPONSE_INVALID",
    )?;
    let status: u16 = code.parse().map_err(|_| Error("HEALTH_RESPONSE_INVALID"))?;
    require(status == policy.expected_status, "HEALTH_STATUS_MISMATCH")?;
    let mut found = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(Error("HEALTH_RESPONSE_INVALID"))?;
        require(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && value
                    .bytes()
                    .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b)),
            "HEALTH_RESPONSE_INVALID",
        )?;
        if policy
            .release_header
            .as_ref()
            .is_some_and(|expected| name.eq_ignore_ascii_case(expected))
        {
            require(found.is_none(), "HEALTH_HEADER_AMBIGUOUS")?;
            found = Some(value.trim_matches([' ', '\t']));
        }
    }
    let matched = if policy.release_header.is_some() {
        require(found == Some(release_id), "HEALTH_RELEASE_MISMATCH")?;
        true
    } else {
        false
    };
    Ok(HttpObservation {
        status,
        release_header_matched: matched,
    })
}
