//! Values a census keeps out of the bundle whatever they are called, checked
//! through the built binary.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use hostcensus::bundle::{Bundle, ScannerStatus};

fn census(docker_host: Option<&str>, more: &[&str]) -> (Bundle, String) {
    let out = tempfile::tempdir().unwrap();
    let logs = tempfile::tempdir().unwrap();
    std::fs::write(logs.path().join("app.log"), "a line\n").unwrap();
    std::fs::write(logs.path().join("payroll.log"), "a line\n").unwrap();
    let scan_path = logs.path().to_string_lossy().into_owned();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hostcensus"));
    command
        .args(["--output", "-", "--scan-path", &scan_path])
        .args(more)
        .current_dir(out.path())
        .env_remove("DOCKER_HOST")
        .env_remove("CONTAINER_HOST");
    if let Some(docker_host) = docker_host {
        command.env("DOCKER_HOST", docker_host);
    }
    let run = command.output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json = String::from_utf8(run.stdout).unwrap();
    (Bundle::from_json(&json).unwrap(), json)
}

/// A stand-in container engine on a Unix socket with one running container
/// whose environment holds plain facts next to values nobody should see.
fn engine_with_one_running_container() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();

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
                r#"[{"Id":"abc123abc123abc123","Names":["/shop-web-1"],"Image":"shop/web:4","State":"running","Labels":{}}]"#
            } else if path.ends_with("/containers/abc123abc123abc123/json") {
                r#"{"Id":"abc123abc123abc123","LogPath":"/var/lib/docker/containers/abc/abc-json.log","Config":{"Env":["PG_VERSION=16.4-1.pgdg120+1","NODE_ENV=production","OTEL_LOGS_EXPORTER=otlp","DATABASE_URL=postgres://shop:a-database-password@db/shop","LOGPACER_INGEST_TOKEN=a-token-with-our-own-prefix","OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.example:4318","APP_VERSION=postgres://shop:hidden-under-a-version-name@db/shop","PATH=/usr/bin"]}}"#
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

/// intent: example plain_environment_values_kept exemplifies an_environment_value_is_kept_only_for_a_plain_fact on cli
#[test]
fn a_running_container_keeps_plain_facts_and_lists_every_other_variable_by_name() {
    let (_dir, socket) = engine_with_one_running_container();
    let engine = format!("unix://{}", socket.display());

    let (bundle, json) = census(Some(&engine), &[]);

    assert_eq!(
        bundle.scan.scanners["docker"].status,
        ScannerStatus::Complete,
        "{:?}",
        bundle.scan.scanners["docker"]
    );
    let container = &bundle.inventory.containers[0];
    let kept: Vec<(&str, &str)> = container
        .env
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        kept,
        [
            ("NODE_ENV", "production"),
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("PG_VERSION", "16.4-1.pgdg120+1"),
        ]
    );
    assert_eq!(
        container.env_names_withheld,
        [
            "APP_VERSION",
            "DATABASE_URL",
            "LOGPACER_INGEST_TOKEN",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "PATH"
        ]
    );
    for value in [
        "a-database-password",
        "a-token-with-our-own-prefix",
        "collector.example",
        "hidden-under-a-version-name",
    ] {
        assert!(!json.contains(value), "the bundle holds {value}");
    }
}

/// intent: example exclude_patterns_counted exemplifies exclude_patterns_are_not_recorded on cli
#[test]
fn an_exclude_pattern_is_counted_and_not_written_down() {
    let (bundle, json) = census(None, &["--exclude", "payroll.*"]);

    assert_eq!(bundle.scan.options.exclude_patterns, 1);
    assert_eq!(
        bundle
            .inventory
            .log_files
            .iter()
            .filter(|file| file.path.ends_with(".log"))
            .filter(|file| bundle
                .scan
                .options
                .scan_paths
                .iter()
                .any(|p| file.path.starts_with(p)))
            .count(),
        1
    );
    assert!(
        !json.contains("payroll"),
        "the bundle names what was excluded"
    );
}
