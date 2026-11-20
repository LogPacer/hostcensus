//! Marks coverage in a copy of the committed bundle, through the built binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hostcensus::bundle::{Bundle, Collected, NotedBy};

fn bundle_in(dir: &Path) -> PathBuf {
    let path = dir.join("census.json");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bundle.v1.json"),
        &path,
    )
    .unwrap();
    path
}

fn mark(bundle: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .arg("mark")
        .arg("--bundle")
        .arg(bundle)
        .args(args)
        .output()
        .unwrap()
}

fn read(path: &Path) -> Bundle {
    Bundle::from_json(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// intent: example mark_leaves_observations exemplifies a_mark_leaves_the_observations_alone on cli
#[test]
fn a_mark_is_written_into_the_bundle_and_the_observations_stay_as_they_were() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    let before = read(&path);

    let run = mark(
        &path,
        &[
            "--source",
            "log_file:/var/log/nginx/error.log",
            "--collected",
            "yes",
            "--collector",
            "vector",
            "--destination",
            "loki",
            "--evidence",
            "/etc/vector/vector.yaml:8",
            "--by",
            "agent",
        ],
    );

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stderr)
            .contains("Marked /var/log/nginx/error.log as collected")
    );

    let after = read(&path);
    assert_eq!(after.inventory, before.inventory);
    assert_eq!(after.inventory_sha256, before.inventory_sha256);
    assert!(after.inventory_is_intact().unwrap());

    let recorded = after
        .coverage
        .marks
        .iter()
        .find(|m| m.source.identifier == "/var/log/nginx/error.log")
        .unwrap();
    assert_eq!(recorded.collected, Collected::Yes);
    assert_eq!(recorded.collector.as_deref(), Some("vector"));
    assert_eq!(recorded.destination.as_deref(), Some("loki"));
    assert_eq!(
        recorded.evidence.as_deref(),
        Some("/etc/vector/vector.yaml:8")
    );
    assert_eq!(recorded.noted_by, NotedBy::Agent);
    // The mark the fixture already carried for another source is still there.
    assert_eq!(after.coverage.marks.len(), before.coverage.marks.len() + 1);
}

#[cfg(unix)]
#[test]
fn a_marked_bundle_stays_with_the_user_who_ran_sudo() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    // As root the bundle is first given to that user, in a directory that
    // stays with root. Anyone else already owns the copy, and the variables
    // count for nothing.
    let me = std::fs::metadata(dir.path()).unwrap().uid();
    let owner = if me == 0 {
        std::os::unix::fs::chown(&path, Some(4242), Some(4243)).unwrap();
        4242
    } else {
        me
    };

    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .arg("mark")
        .arg("--bundle")
        .arg(&path)
        .args(["--source", "log_file:/var/log/nginx/error.log"])
        .args(["--collected", "yes"])
        .env("SUDO_UID", "4242")
        .env("SUDO_GID", "4243")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(after.uid(), owner);
    assert_eq!(after.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        stderr.contains("The file belongs to user 4242 (group 4243), who ran sudo."),
        me == 0,
        "{stderr}"
    );
    assert!(
        read(&path)
            .coverage
            .marks
            .iter()
            .any(|mark| mark.source.identifier == "/var/log/nginx/error.log")
    );
}

/// intent: example pattern_marks_every_match exemplifies a_pattern_marks_every_source_it_matches on cli
#[test]
fn a_pattern_marks_every_matching_source_and_reports_each() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());

    let run = mark(
        &path,
        &[
            "--source",
            "log_file:/var/log/nginx/*.log",
            "--collected",
            "yes",
            "--collector",
            "vector",
        ],
    );

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("Marked /var/log/nginx/access.log as collected"));
    assert!(stderr.contains("Marked /var/log/nginx/error.log as collected"));

    let after = read(&path);
    let collectors: Vec<_> = after
        .coverage
        .marks
        .iter()
        .map(|m| (m.source.identifier.as_str(), m.collector.as_deref()))
        .collect();
    assert_eq!(
        collectors,
        [
            ("/var/log/nginx/access.log", Some("vector")),
            ("/var/log/nginx/error.log", Some("vector")),
        ]
    );
    assert!(after.inventory_is_intact().unwrap());
}

/// intent: example coverage_lists_sources exemplifies coverage_lists_every_source_with_its_mark on cli
#[test]
fn coverage_lists_every_source_and_counts_the_answers() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    let before = std::fs::read(&path).unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .arg("coverage")
        .arg("--bundle")
        .arg(&path)
        .output()
        .unwrap();

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8(run.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "yes\tlog_file:/var/log/nginx/access.log\tfluent-bit",
            "-\tlog_file:/var/log/nginx/error.log\t",
            "-\tcontainer:shop/api\t",
            "-\tsystemd_service:nginx.service\t",
            "-\twindows_service:W3SVC\t",
            "-\tevent_log_channel:Security\t",
        ]
    );
    assert!(
        String::from_utf8_lossy(&run.stderr)
            .contains("6 sources: 1 collected, 0 not collected, 0 unknown, 5 without a mark")
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn container_replicas_share_one_coverage_mark_and_listing() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    let mut before = read(&path);
    let mut replica = before.inventory.containers[0].clone();
    replica.id = "abcdef012345".into();
    replica.container_id =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
    replica.name = "shop-api-2".into();
    replica.stable_instance_id = "shop/api/2".into();
    before.inventory.containers.push(replica);
    let before = Bundle::seal(
        before.tool,
        before.generated_at,
        before.host,
        before.scan,
        before.inventory,
    )
    .unwrap();
    std::fs::write(&path, before.to_json().unwrap()).unwrap();

    for source in ["container:shop/*", "container:shop/api"] {
        let run = mark(&path, &["--source", source, "--collected", "unknown"]);
        assert!(run.status.success(), "{:?}", run.stderr);

        let after = read(&path);
        assert_eq!(after.coverage.marks.len(), 1);
        assert_eq!(after.coverage.marks[0].source.identifier, "shop/api");
        assert_eq!(after.coverage.marks[0].collected, Collected::Unknown);
        assert_eq!(after.inventory, before.inventory);
        assert_eq!(after.inventory_sha256, before.inventory_sha256);
        assert!(after.inventory_is_intact().unwrap());
    }

    let run = Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(["coverage", "--bundle"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(run.status.success(), "{:?}", run.stderr);
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 6);
    assert_eq!(
        stdout
            .lines()
            .filter(|line| *line == "unknown\tcontainer:shop/api\t")
            .count(),
        1
    );
    assert!(
        String::from_utf8_lossy(&run.stderr)
            .contains("6 sources: 0 collected, 0 not collected, 1 unknown, 5 without a mark")
    );
}

#[test]
fn a_person_is_assumed_to_be_marking_unless_told_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());

    let run = mark(
        &path,
        &[
            "--source",
            "systemd_service:nginx.service",
            "--collected",
            "no",
        ],
    );

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let recorded = read(&path)
        .coverage
        .marks
        .into_iter()
        .find(|m| m.source.identifier == "nginx.service")
        .unwrap();
    assert_eq!(recorded.collected, Collected::No);
    assert_eq!(recorded.noted_by, NotedBy::Human);
}

/// intent: example unknown_source_refused exemplifies only_a_source_in_the_census_can_be_marked on cli
#[test]
fn a_source_the_census_did_not_see_leaves_the_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    let before = std::fs::read(&path).unwrap();

    let run = mark(
        &path,
        &[
            "--source",
            "log_file:/var/log/missing.log",
            "--collected",
            "yes",
        ],
    );

    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("no log file named"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// intent: example edited_inventory_refused exemplifies an_edited_inventory_is_refused on cli
#[test]
fn a_bundle_with_an_edited_inventory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());
    let edited = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"version\": \"1.26.3-3\"", "\"version\": \"0.0.0\"");
    std::fs::write(&path, &edited).unwrap();

    let run = mark(
        &path,
        &[
            "--source",
            "log_file:/var/log/nginx/error.log",
            "--collected",
            "yes",
        ],
    );

    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("changed after the census"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
}

#[test]
fn no_temporary_file_is_left_beside_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let path = bundle_in(dir.path());

    let run = mark(
        &path,
        &[
            "--source",
            "event_log_channel:Security",
            "--collected",
            "unknown",
        ],
    );

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["census.json"]);
}
