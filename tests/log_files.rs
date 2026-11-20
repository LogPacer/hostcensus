//! Which files a census lists as log files, checked through the built binary.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use hostcensus::bundle::{Bundle, ScannerStatus};
use hostcensus::inventory::LogFile;

fn log_files_under(scan_path: &Path, more: &[&str]) -> Vec<LogFile> {
    let out = tempfile::tempdir().unwrap();
    let scan_path = scan_path.to_string_lossy().into_owned();
    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(["--output", "-", "--scan-path", &scan_path])
        .args(more)
        .current_dir(out.path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    Bundle::from_json(&String::from_utf8(run.stdout).unwrap())
        .unwrap()
        .inventory
        .log_files
        .into_iter()
        .filter(|file| file.path.starts_with(&scan_path))
        .collect()
}

fn names(files: &[LogFile]) -> Vec<&str> {
    files
        .iter()
        .map(|file| file.path.rsplit('/').next().unwrap())
        .collect()
}

fn write(dir: &Path, name: &str) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "a line\n").unwrap();
}

/// intent: example log_files_by_name exemplifies a_log_file_is_recognised_by_its_name on cli
#[test]
fn a_file_is_listed_when_its_name_marks_it_as_a_log_file() {
    let logs = tempfile::tempdir().unwrap();
    for name in [
        "app.log",
        "syslog",
        "messages",
        "secure",
        "httpd/access_log",
        "mail.err",
        "wtmp",
        "lastlog",
        "README",
        "notes.txt",
    ] {
        write(logs.path(), name);
    }

    let listed = log_files_under(logs.path(), &[]);

    assert_eq!(
        names(&listed),
        [
            "app.log",
            "access_log",
            "mail.err",
            "messages",
            "secure",
            "syslog"
        ]
    );
}

/// intent: example old_and_excluded_left_out exemplifies old_and_excluded_log_files_are_left_out on cli
#[test]
fn a_log_file_that_is_old_or_excluded_is_left_out() {
    let logs = tempfile::tempdir().unwrap();
    for name in ["fresh.log", "old.log", "payroll.log"] {
        write(logs.path(), name);
    }
    let a_month_ago = SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(logs.path().join("old.log"))
        .unwrap()
        .set_modified(a_month_ago)
        .unwrap();

    let listed = log_files_under(
        logs.path(),
        &["--max-age-days", "7", "--exclude", "payroll.*"],
    );

    assert_eq!(names(&listed), ["fresh.log"]);
}

/// intent: example quiet_file_listed exemplifies a_quiet_log_file_is_still_listed on cli
#[test]
fn a_log_file_not_written_to_for_weeks_is_still_listed() {
    let logs = tempfile::tempdir().unwrap();
    let days_ago = |name: &str, days: u64| {
        write(logs.path(), name);
        std::fs::File::options()
            .write(true)
            .open(logs.path().join(name))
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60))
            .unwrap();
    };
    write(logs.path(), "busy.log");
    days_ago("monthly.log", 30);
    days_ago("abandoned.log", 120);

    let listed = log_files_under(logs.path(), &[]);

    assert_eq!(names(&listed), ["busy.log", "monthly.log"]);
    let last_write = std::fs::metadata(logs.path().join("monthly.log"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        listed[1].modified,
        hostcensus::timestamp::rfc3339(last_write)
    );
}

/// intent: example rotated_copies_folded exemplifies rotated_copies_belong_to_their_log_file on cli
#[test]
fn rotated_copies_are_listed_under_their_log_file() {
    let logs = tempfile::tempdir().unwrap();
    for name in [
        "app.log",
        "app.log.1",
        "app.log.2.gz",
        "messages",
        "messages-20260102",
    ] {
        write(logs.path(), name);
    }

    let listed = log_files_under(logs.path(), &[]);

    assert_eq!(names(&listed), ["app.log", "messages"]);
    let copies: Vec<Vec<&str>> = listed
        .iter()
        .map(|file| {
            file.rotated_copies
                .iter()
                .map(|copy| copy.path.rsplit('/').next().unwrap())
                .collect()
        })
        .collect();
    assert_eq!(
        copies,
        [vec!["app.log.1", "app.log.2.gz"], vec!["messages-20260102"]]
    );
}

/// intent: example unreadable_file_still_listed exemplifies log_content_is_never_read on cli
#[test]
fn a_log_file_that_cannot_be_opened_is_still_listed() {
    use std::os::unix::fs::PermissionsExt;

    let logs = tempfile::tempdir().unwrap();
    write(logs.path(), "sealed.log");
    let sealed = logs.path().join("sealed.log");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

    let listed = log_files_under(logs.path(), &[]);

    assert_eq!(names(&listed), ["sealed.log"]);
    assert_eq!(listed[0].size, "a line\n".len() as u64);
    assert_eq!(listed[0].permissions, "100000");
}

/// A stand-in container engine on a Unix socket that runs no container and
/// keeps its data under `data_root`.
fn engine_keeping_its_data_under(data_root: &Path) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let info = serde_json::json!({ "DockerRootDir": data_root }).to_string();

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
            let (status, body) = if path.ends_with("/info") {
                (200, info.as_str())
            } else if path.ends_with("/containers/json") {
                (200, "[]")
            } else {
                (404, r#"{"message":"no such route"}"#)
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

/// intent: example image_layers_not_searched exemplifies image_layers_are_not_searched_for_log_files on cli
#[test]
fn the_image_layers_of_a_container_runtime_are_not_searched() {
    use std::os::unix::fs::PermissionsExt;

    let host = tempfile::tempdir().unwrap();
    let data_root = host.path().join("docker-data");
    let layers = data_root.join("overlay2");
    let layers_of_its_containerd =
        data_root.join("containerd/daemon/io.containerd.snapshotter.v1.overlayfs");
    for name in [
        "docker-data/panic.log",
        "docker-data/volumes/shop/_data/orders.log",
        "docker-data/overlay2/3f9a/diff/var/log/dpkg.log",
        "docker-data/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/var/log/apt.log",
        "srv/shop/shop.log",
    ] {
        write(host.path(), name);
    }
    // Reading this directory would fail and show in the report.
    let sealed = layers.join("3f9a/diff/root");
    std::fs::create_dir(&sealed).unwrap();
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_engine, socket) = engine_keeping_its_data_under(&data_root);

    let out = tempfile::tempdir().unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(["--output", "-", "--scan-path"])
        .arg(host.path())
        .current_dir(out.path())
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env_remove("CONTAINER_HOST")
        .output()
        .unwrap();
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let bundle = Bundle::from_json(&String::from_utf8(run.stdout).unwrap()).unwrap();

    let listed: Vec<&str> = bundle
        .inventory
        .log_files
        .iter()
        .filter_map(|file| file.path.strip_prefix(host.path().to_str().unwrap()))
        .collect();
    assert_eq!(
        listed,
        [
            "/docker-data/panic.log",
            "/docker-data/volumes/shop/_data/orders.log",
            "/srv/shop/shop.log"
        ]
    );
    let files = &bundle.scan.scanners["files"];
    assert_eq!(files.status, ScannerStatus::Partial, "{files:?}");
    assert_eq!(
        files.reason.as_deref(),
        Some(
            format!(
                "not searched, because a container runtime keeps image layers there: {}, {}",
                layers_of_its_containerd.display(),
                layers.display()
            )
            .as_str()
        )
    );
    let summary = String::from_utf8_lossy(&run.stderr);
    assert!(
        summary.contains(&format!("{}", layers.display())),
        "{summary}"
    );
}
