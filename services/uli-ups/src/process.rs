use crate::{Error, Result, require};
use rustix::fs::{self as fs, OFlags};
use std::{
    io::Read,
    process::{Child, Command},
    sync::atomic::Ordering,
    time::Duration,
};
const MAX_CHILDREN: usize = 16;
struct Reaper {
    sender: std::sync::mpsc::Sender<Child>,
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
fn reaper() -> Result<&'static Reaper> {
    static INSTANCE: std::sync::OnceLock<Option<Reaper>> = std::sync::OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::channel::<Child>();
            let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = active.clone();
            std::thread::Builder::new()
                .name("uliups-child-reaper".into())
                .spawn(move || {
                    let mut pending = Vec::<Child>::with_capacity(MAX_CHILDREN);
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(20)) {
                            Ok(child) => pending.push(child),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                                if pending.is_empty() =>
                            {
                                break;
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                        while let Ok(child) = receiver.try_recv() {
                            pending.push(child);
                        }
                        pending.retain_mut(|child| match child.try_wait() {
                            Ok(Some(_)) => {
                                count.fetch_sub(1, Ordering::SeqCst);
                                false
                            }
                            Err(error)
                                if error.raw_os_error()
                                    == Some(rustix::io::Errno::CHILD.raw_os_error()) =>
                            {
                                count.fetch_sub(1, Ordering::SeqCst);
                                false
                            }
                            _ => true,
                        });
                    }
                })
                .ok()?;
            Some(Reaper { sender, active })
        })
        .as_ref()
        .ok_or(Error("SYSTEMD_REAPER_UNAVAILABLE"))
}
pub(crate) struct ChildGuard {
    child: Option<Child>,
    reaper: &'static Reaper,
    finished: bool,
}
impl ChildGuard {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        let reaper = reaper()?;
        reaper
            .active
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_CHILDREN).then_some(n + 1)
            })
            .map_err(|_| Error("SYSTEMD_CHILD_LIMIT"))?;
        match command.spawn() {
            Ok(child) => Ok(Self {
                child: Some(child),
                reaper,
                finished: false,
            }),
            Err(error) => {
                reaper.active.fetch_sub(1, Ordering::SeqCst);
                Err(error.into())
            }
        }
    }
    pub(crate) fn process(&mut self) -> &mut Child {
        self.child.as_mut().expect("owned child")
    }
    pub(crate) fn mark_reaped(&mut self) {
        self.finished = true;
        self.reaper.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.finished
            && let Some(mut child) = self.child.take()
        {
            let _ = child.kill();
            // Reaper initialization precedes spawning; outstanding handles are capped.
            // Losing a handle after an unexpected reaper failure is not recoverable in
            // this process: abort so the OS/systemd can reap and restart safely.
            if self.reaper.sender.send(child).is_err() {
                std::process::abort();
            }
        }
    }
}

pub(crate) fn nonblock(fd: impl std::os::fd::AsFd) -> Result<()> {
    let flags = fs::fcntl_getfl(&fd)?;
    fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}
pub(crate) fn drain(reader: &mut impl Read, output: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                require(output.len() + n <= limit, "SYSTEMD_OUTPUT_TOO_LARGE")?;
                output.extend_from_slice(&buffer[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(());
            }
            Err(_) => return Err(Error("SYSTEMD_READ_FAILED")),
        }
    }
}
#[cfg(test)]
mod reaper_regression {
    use super::*;
    use std::{process::Stdio, time::Instant};
    #[test]
    fn dropped_child_is_killed_and_reaped_without_blocking_the_caller() {
        let mut command = Command::new("/usr/bin/sleep");
        command
            .arg("10")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = ChildGuard::spawn(&mut command).unwrap();
        let count = child.reaper.active.clone();
        let started = Instant::now();
        drop(child);
        assert!(started.elapsed() < Duration::from_millis(250));
        while count.load(Ordering::SeqCst) != 0 {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "reaper retained killed child"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
