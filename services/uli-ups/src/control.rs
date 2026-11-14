use crate::{
    Error, Result,
    agent::Agent,
    config::{Config, directory},
    require,
};
use rustix::fs::{self as fs, FlockOperation, Mode, OFlags, ResolveFlags};
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::{
    fs::{File, Permissions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uliup_protocol::{MAX_MESSAGE_BYTES, decode_request};

struct Lease {
    _file: File,
}
impl Lease {
    fn acquire(config: &Config) -> Result<Self> {
        let dir = directory(&config.state_path(), true)?;
        let file: File = fs::openat2(
            &dir,
            "agent.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?
        .into();
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.mode() & 0o7777 == 0o600,
            "AGENT_LOCK_UNSAFE",
        )?;
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error("AGENT_ALREADY_RUNNING"))?;
        Ok(Self { _file: file })
    }
}
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(m) = std::fs::symlink_metadata(&self.path)
            && m.dev() == self.device
            && m.ino() == self.inode
            && m.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn read_frame(stream: &mut UnixStream, stop: &AtomicBool) -> Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        require(!stop.load(Ordering::Relaxed), "AGENT_STOPPING")?;
        require(
            start.elapsed() < Duration::from_secs(2),
            "AGENT_REQUEST_TIMEOUT",
        )?;
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                require(bytes.len() <= MAX_MESSAGE_BYTES, "AGENT_REQUEST_TOO_LARGE")?;
                if bytes.contains(&b'\n') {
                    return Ok(bytes);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
}
fn write_frame(stream: &mut UnixStream, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Error("AGENT_RESPONSE_INVALID"))?;
    require(bytes.len() < MAX_MESSAGE_BYTES, "AGENT_RESPONSE_TOO_LARGE")?;
    bytes.push(b'\n');
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(&bytes)?;
    Ok(())
}
pub fn serve(mut agent: Agent) -> Result<()> {
    let _lease = Lease::acquire(&agent.config)?;
    let stop = Arc::new(AtomicBool::new(false));
    let sigterm = signal_hook::flag::register(SIGTERM, stop.clone())?;
    let sigint = signal_hook::flag::register(SIGINT, stop.clone())?;
    let path = agent.config.socket_path();
    if let Ok(m) = std::fs::symlink_metadata(&path) {
        require(
            m.file_type().is_socket() && m.uid() == rustix::process::geteuid().as_raw(),
            "AGENT_SOCKET_UNSAFE",
        )?;
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let m = std::fs::symlink_metadata(&path)?;
    let _socket = SocketGuard {
        path,
        device: m.dev(),
        inode: m.ino(),
    };
    listener.set_nonblocking(true)?;
    eprintln!(
        "{{\"code\":\"AGENT_READY\",\"version\":\"{}\"}}",
        crate::VERSION
    );
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let creds = rustix::net::sockopt::socket_peercred(&stream)?;
                if creds.uid != rustix::process::geteuid() {
                    continue;
                }
                let response = match read_frame(&mut stream, &stop) {
                    Ok(bytes) => match decode_request(&bytes) {
                        Ok(request) => agent.dispatch(&request),
                        Err(_) => {
                            json!({"protocol_major":1,"body":{"type":"error","code":"BAD_REQUEST"}})
                        }
                    },
                    Err(error) => {
                        json!({"protocol_major":1,"body":{"type":"error","code":error.0}})
                    }
                };
                if let Err(error) = write_frame(&mut stream, &response) {
                    eprintln!("{{\"code\":\"{}\"}}", error.0);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    signal_hook::low_level::unregister(sigterm);
    signal_hook::low_level::unregister(sigint);
    eprintln!("{{\"code\":\"AGENT_STOPPED\"}}");
    Ok(())
}
pub fn request(config: &Config, bytes: &[u8]) -> Result<Value> {
    let req = decode_request(bytes).map_err(|_| Error("AGENT_REQUEST_INVALID"))?;
    req.validate_for_instance(&config.instance_id)
        .map_err(|_| Error("WRONG_INSTANCE"))?;
    directory(&config.state_path(), true)?;
    let m = std::fs::symlink_metadata(config.socket_path())?;
    require(
        m.file_type().is_socket()
            && m.mode() & 0o7777 == 0o600
            && m.uid() == rustix::process::geteuid().as_raw(),
        "AGENT_SOCKET_UNSAFE",
    )?;
    let mut stream = UnixStream::connect(config.socket_path())?;
    require(
        rustix::net::sockopt::socket_peercred(&stream)?.uid == rustix::process::geteuid(),
        "AGENT_PEER_UNAUTHORIZED",
    )?;
    let mut data = serde_json::to_vec(&req).map_err(|_| Error("AGENT_REQUEST_INVALID"))?;
    data.push(b'\n');
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.write_all(&data)?;
    let response = read_frame(&mut stream, &AtomicBool::new(false))?;
    serde_json::from_slice(&response).map_err(|_| Error("AGENT_RESPONSE_INVALID"))
}
