//! What a census keeps out of the bundle, checked through the built binary.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use hostcensus::bundle::{Bundle, ScannerStatus};

/// Takes a census with an empty scan path and the given engine address, and
/// returns the bundle with its text.
fn census(docker_host: Option<&str>, more: &[&str]) -> (Bundle, String) {
    let out = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let scan_path = empty.path().to_string_lossy().into_owned();
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

/// intent: example executable_only exemplifies a_process_is_recorded_without_its_arguments on cli
#[test]
fn a_process_is_recorded_by_its_executable_unless_arguments_are_asked_for() {
    // The census is itself a process on the host, started with this argument.
    let marker = ["--exclude", "an-argument-only-this-run-carries"];

    let (plain, plain_json) = census(None, &marker);
    assert!(!plain.scan.options.process_args);
    assert!(
        plain
            .inventory
            .processes
            .iter()
            .any(|process| process.command.ends_with("hostcensus")),
        "{:?}",
        plain.scan.scanners["processes"]
    );
    assert!(
        plain
            .inventory
            .processes
            .iter()
            .all(|process| !process.command.contains(marker[1])),
        "{plain_json}"
    );

    let mut asked = marker.to_vec();
    asked.push("--process-args");
    let (with_arguments, _) = census(None, &asked);
    assert!(with_arguments.scan.options.process_args);
    assert!(
        with_arguments
            .inventory
            .processes
            .iter()
            .any(|process| process.command.contains(marker[1]))
    );
}

/// intent: example interpreter_names_its_program exemplifies an_interpreter_names_the_program_it_runs on cli
#[test]
fn a_shell_running_a_script_is_listed_with_the_script_and_not_its_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("nightly-export.sh");
    std::fs::write(&script, "while :; do sleep 1; done\n").unwrap();
    let mut worker = Command::new("sh")
        .arg(&script)
        .arg("an-argument-nobody-should-see")
        .spawn()
        .unwrap();
    // Give the shell a moment to be the process the census will see.
    std::thread::sleep(std::time::Duration::from_millis(300));

    let (bundle, json) = census(None, &[]);
    worker.kill().unwrap();
    worker.wait().unwrap();

    let script = script.to_string_lossy();
    let shell = bundle
        .inventory
        .processes
        .iter()
        .find(|process| process.program == script);
    assert!(
        shell.is_some(),
        "no process is listed with the program {script}: {:?}",
        bundle.scan.scanners["processes"]
    );
    assert!(!shell.unwrap().command.contains("nightly-export"));
    assert!(!json.contains("an-argument-nobody-should-see"));
}

/// intent: example remote_engine_refused exemplifies only_a_local_engine_is_asked on cli
#[test]
fn an_engine_that_is_not_a_local_socket_is_refused() {
    let (bundle, _) = census(Some("tcp://engine.example:2375"), &[]);

    let docker = &bundle.scan.scanners["docker"];
    assert_eq!(docker.status, ScannerStatus::Unavailable);
    let reason = docker.reason.as_deref().unwrap();
    assert!(reason.contains("DOCKER_HOST"), "{reason}");
    assert!(!reason.contains("engine.example"), "{reason}");
    assert!(bundle.inventory.containers.is_empty());
}

/// A stand-in container engine on a Unix socket, answering the three
/// requests a census makes.
fn engine_with_one_labelled_container() -> (tempfile::TempDir, PathBuf) {
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
                r#"[{"Id":"abc123abc123abc123","Names":["/shop-web-1"],"Image":"shop/web:4","State":"exited","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","traefik.http.middlewares.auth.basicauth.users":"admin:a-hash-nobody-should-see"}}]"#
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

/// intent: example label_values_withheld exemplifies label_values_are_withheld on cli
#[test]
fn a_label_value_is_kept_only_for_a_well_known_key_unless_all_are_asked_for() {
    let (_dir, socket) = engine_with_one_labelled_container();
    let engine = format!("unix://{}", socket.display());
    let secret_key = "traefik.http.middlewares.auth.basicauth.users";

    let (plain, plain_json) = census(Some(&engine), &[]);
    assert_eq!(
        plain.scan.scanners["docker"].status,
        ScannerStatus::Complete,
        "{:?}",
        plain.scan.scanners["docker"]
    );
    let container = &plain.inventory.containers[0];
    assert_eq!(container.labels["com.docker.compose.project"], "shop");
    assert_eq!(container.labels["com.docker.compose.service"], "web");
    assert!(!container.labels.contains_key(secret_key));
    assert_eq!(container.label_keys_withheld, [secret_key]);
    assert!(!plain_json.contains("a-hash-nobody-should-see"));

    let (asked, _) = census(Some(&engine), &["--all-label-values"]);
    let container = &asked.inventory.containers[0];
    assert_eq!(
        container.labels[secret_key],
        "admin:a-hash-nobody-should-see"
    );
    assert!(container.label_keys_withheld.is_empty());
}
