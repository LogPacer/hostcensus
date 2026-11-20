//! Whether a running thing produces output, checked through the built binary.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use hostcensus::bundle::{Bundle, ScannerStatus};

/// A stand-in container engine on a Unix socket with two running containers:
/// one writes to the log file at `log_path`, the other has logging turned off.
fn engine_with_a_logging_and_a_silent_container(log_path: &Path) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let logging = format!(
        r#"{{"Id":"aaa111aaa111aaa111","LogPath":"{}","HostConfig":{{"LogConfig":{{"Type":"json-file"}}}},"Config":{{"Env":[]}}}}"#,
        log_path.display()
    );

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let request = String::from_utf8_lossy(&request);
            let target = request.split_whitespace().nth(1).unwrap_or_default();
            let path = target.split('?').next().unwrap_or_default();
            let body = if path.ends_with("/info") {
                r#"{"DockerRootDir":"/var/lib/docker"}"#
            } else if path.ends_with("/containers/json") {
                r#"[{"Id":"aaa111aaa111aaa111","Names":["/shop-api"],"Image":"shop/api:4","State":"running","Labels":{}},{"Id":"bbb222bbb222bbb222","Names":["/shop-proxy"],"Image":"shop/proxy:2","State":"running","Labels":{}}]"#
            } else if path.ends_with("/containers/aaa111aaa111aaa111/json") {
                logging.as_str()
            } else if path.ends_with("/containers/bbb222bbb222bbb222/json") {
                r#"{"Id":"bbb222bbb222bbb222","LogPath":"","HostConfig":{"LogConfig":{"Type":"none"}},"Config":{"Env":[]}}"#
            } else {
                r#"{"message":"no such route"}"#
            };
            let status = if body.contains("no such route") {
                404
            } else {
                200
            };
            let response = format!(
                "HTTP/1.1 {status} Fake\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    (dir, socket)
}

/// intent: example container_output_known exemplifies a_container_says_where_its_output_goes on cli
#[test]
fn a_running_container_shows_its_logging_driver_and_how_much_it_has_written() {
    let logs = tempfile::tempdir().unwrap();
    let log_path = logs.path().join("aaa111-json.log");
    let line = "a log line nobody should find in a bundle\n";
    std::fs::write(&log_path, line).unwrap();
    let (_dir, socket) = engine_with_a_logging_and_a_silent_container(&log_path);

    let out = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(["--output", "-", "--scan-path"])
        .arg(empty.path())
        .current_dir(out.path())
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env_remove("CONTAINER_HOST")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json = String::from_utf8(run.stdout).unwrap();
    let bundle = Bundle::from_json(&json).unwrap();
    assert_eq!(
        bundle.scan.scanners["docker"].status,
        ScannerStatus::Complete,
        "{:?}",
        bundle.scan.scanners["docker"]
    );

    let container = |name: &str| {
        bundle
            .inventory
            .containers
            .iter()
            .find(|container| container.name == name)
            .unwrap()
    };
    let api = container("shop-api");
    assert_eq!(api.log_driver, "json-file");
    assert_eq!(api.log_size, Some(line.len() as u64));
    assert!(!api.log_modified.is_empty());

    let proxy = container("shop-proxy");
    assert_eq!(proxy.log_driver, "none");
    assert_eq!(proxy.log_size, None);
    assert!(proxy.log_modified.is_empty());

    assert!(!json.contains("nobody should find"), "the log was read");
    let summary = String::from_utf8_lossy(&run.stderr);
    assert!(
        summary.contains("Running container log observations: shop-proxy (runtime logging is off)"),
        "{summary}"
    );
}
