#![cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};
use uli_ups::health::HttpHealth;
fn server(response: Vec<u8>, delay: Duration) -> (HttpHealth, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0u8; 4096];
        let count = stream.read(&mut bytes).unwrap();
        assert!(
            std::str::from_utf8(&bytes[..count])
                .unwrap()
                .starts_with("GET /health HTTP/1.1\r\n")
        );
        thread::sleep(delay);
        let _ = stream.write_all(&response);
    });
    (
        HttpHealth {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            path: "/health".into(),
            deadline_ms: 1000,
            expected_status: 200,
            release_header: Some("x-uliups-release".into()),
        },
        handle,
    )
}
#[test]
fn real_loopback_request_checks_status_and_exact_release_without_following_redirects() {
    let (policy, worker) = server(
        b"HTTP/1.1 200 OK\r\nX-Uliups-Release: release-1\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::ZERO,
    );
    let result = policy.probe("release-1", &AtomicBool::new(false)).unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, 200);
    assert!(result.release_header_matched);
    let (policy, worker) = server(
        b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\n\r\n".to_vec(),
        Duration::ZERO,
    );
    assert_eq!(
        policy
            .probe("release-1", &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "HEALTH_STATUS_MISMATCH"
    );
    worker.join().unwrap();
}
#[test]
fn external_targets_and_header_injection_are_rejected_before_connection() {
    let policy = HttpHealth {
        address: "192.168.0.39".parse().unwrap(),
        port: 3000,
        path: "/health".into(),
        deadline_ms: 500,
        expected_status: 200,
        release_header: None,
    };
    assert_eq!(
        policy
            .probe("release-1", &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "HEALTH_NOT_LOOPBACK"
    );
    let mut policy = policy;
    policy.address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    policy.path = "/health\r\nAuthorization: secret".into();
    assert_eq!(policy.validate().unwrap_err().0, "HEALTH_PATH_INVALID");
    policy.path = "/health".into();
    policy.release_header = Some("header\r\n".into());
    assert!(policy.validate().is_err());
}
#[test]
fn wrong_missing_and_duplicate_release_headers_fail_closed() {
    for header in [
        "X-Uliups-Release: other\r\n",
        "",
        "X-Uliups-Release: release-1\r\nX-Uliups-Release: release-1\r\n",
    ] {
        let (policy, worker) = server(
            format!("HTTP/1.1 200 OK\r\n{header}\r\n").into_bytes(),
            Duration::ZERO,
        );
        assert!(policy.probe("release-1", &AtomicBool::new(false)).is_err());
        worker.join().unwrap();
    }
}
#[test]
fn stalled_peer_obeys_deadline_and_cancelled_probe_does_not_connect() {
    let (mut policy, worker) = server(
        b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        Duration::from_millis(300),
    );
    policy.deadline_ms = 100;
    let start = Instant::now();
    assert_eq!(
        policy
            .probe("release-1", &AtomicBool::new(false))
            .unwrap_err()
            .0,
        "HEALTH_DEADLINE"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();
    assert_eq!(
        policy
            .probe("release-1", &AtomicBool::new(true))
            .unwrap_err()
            .0,
        "HEALTH_CANCELLED"
    );
}
#[test]
fn oversized_incomplete_and_malformed_headers_are_bounded() {
    for response in [
        [
            b"HTTP/1.1 200 OK\r\nX: ".as_slice(),
            vec![b'x'; 20 * 1024].as_slice(),
        ]
        .concat(),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nBad-Header\r\n\r\n".to_vec(),
    ] {
        let (policy, worker) = server(response, Duration::ZERO);
        assert!(policy.probe("release-1", &AtomicBool::new(false)).is_err());
        worker.join().unwrap();
    }
}
#[test]
fn no_release_header_never_claims_release_identity() {
    let (mut policy, worker) = server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000\r\n\r\n".to_vec(),
        Duration::ZERO,
    );
    policy.release_header = None;
    assert!(
        !policy
            .probe("release-1", &AtomicBool::new(false))
            .unwrap()
            .release_header_matched
    );
    worker.join().unwrap();
}

#[test]
fn cancellation_during_the_final_read_cannot_report_success() {
    use std::sync::{Arc, atomic::Ordering};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancelled = Arc::new(AtomicBool::new(false));
    let remote = cancelled.clone();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0u8; 4096];
        assert!(stream.read(&mut bytes).unwrap() > 0);
        thread::sleep(Duration::from_millis(20));
        remote.store(true, Ordering::SeqCst);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nX-Uliups-Release: release-1\r\n\r\n");
    });
    let policy = HttpHealth {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        path: "/health".into(),
        deadline_ms: 1000,
        expected_status: 200,
        release_header: Some("x-uliups-release".into()),
    };
    assert_eq!(
        policy.probe("release-1", &cancelled).unwrap_err().0,
        "HEALTH_CANCELLED"
    );
    worker.join().unwrap();
}
