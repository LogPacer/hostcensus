//! Runs the built binary the way a person would.

use std::process::{Command, Output};

use hostcensus::bundle::{Bundle, FORMAT};

fn hostcensus(args: &[&str], dir: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

/// intent: example bare_run_names_the_bundle exemplifies a_census_writes_one_bundle on cli
#[test]
fn a_bare_run_writes_one_named_bundle_and_says_so() {
    let dir = tempfile::tempdir().unwrap();

    let run = hostcensus(&[], dir.path());

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty());
    let written: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(written.len(), 1, "{written:?}");
    let name = written[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        name.starts_with("hostcensus-") && name.ends_with(".json"),
        "{name}"
    );

    let bundle = Bundle::from_json(&std::fs::read_to_string(&written[0]).unwrap()).unwrap();
    assert_eq!(bundle.format, FORMAT);
    assert!(!bundle.host.hostname.is_empty());
    assert!(bundle.inventory_is_intact().unwrap());
    assert!(bundle.coverage.marks.is_empty());

    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains(&name), "{stderr}");
    assert!(stderr.contains("Nothing was sent anywhere."), "{stderr}");
}

#[test]
fn the_scan_command_is_the_same_as_a_bare_run() {
    let dir = tempfile::tempdir().unwrap();

    let run = hostcensus(&["scan", "--output", "census.json"], dir.path());

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json = std::fs::read_to_string(dir.path().join("census.json")).unwrap();
    assert_eq!(Bundle::from_json(&json).unwrap().format, FORMAT);
}

/// intent: example existing_file_left_alone exemplifies a_census_never_replaces_a_file on cli
#[test]
fn an_existing_file_is_left_alone_and_the_run_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("census.json");
    std::fs::write(&path, "keep me").unwrap();

    let run = hostcensus(&["--output", "census.json"], dir.path());

    assert!(!run.status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
    assert!(String::from_utf8_lossy(&run.stderr).contains("cannot create census.json"));
}

/// intent: example dash_writes_to_standard_output exemplifies a_census_writes_one_bundle on cli
#[test]
fn a_dash_writes_the_bundle_to_standard_output_and_no_file() {
    let dir = tempfile::tempdir().unwrap();

    let run = hostcensus(&["--output", "-"], dir.path());

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let bundle = Bundle::from_json(&String::from_utf8(run.stdout).unwrap()).unwrap();
    assert_eq!(bundle.format, FORMAT);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// A census of nothing but the host, written to `census.json` in `dir`, with
/// the variables `sudo` would set.
#[cfg(unix)]
fn census_under_sudo(dir: &std::path::Path, sudo: &[(&str, &str)]) -> Output {
    let empty = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_hostcensus"))
        .args(["--output", "census.json", "--scan-path"])
        .arg(empty.path())
        .env_remove("SUDO_UID")
        .env_remove("SUDO_GID")
        .envs(sudo.iter().copied())
        .current_dir(dir)
        .output()
        .unwrap()
}

/// The tests run as root in some places and not in others. The rule under
/// test says what happens in each, so the expected owner follows from who
/// runs the test.
#[cfg(unix)]
fn user_running_the_tests(dir: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).unwrap().uid()
}

/// intent: example sudo_user_owns_the_bundle exemplifies a_census_taken_through_sudo_belongs_to_whoever_ran_it on cli
#[cfg(unix)]
#[test]
fn a_census_taken_as_root_through_sudo_belongs_to_whoever_ran_sudo() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let me = user_running_the_tests(dir.path());
    // A directory the user sudo names could have written to, as /tmp is.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    let run = census_under_sudo(dir.path(), &[("SUDO_UID", "4242"), ("SUDO_GID", "4243")]);

    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    let written = std::fs::metadata(dir.path().join("census.json")).unwrap();
    assert_eq!(written.permissions().mode() & 0o777, 0o600);
    if me == 0 {
        assert_eq!((written.uid(), written.gid()), (4242, 4243));
        assert!(
            stderr.contains("The file belongs to user 4242 (group 4243), who ran sudo."),
            "{stderr}"
        );
    } else {
        assert_eq!(written.uid(), me);
        assert!(!stderr.contains("who ran sudo"), "{stderr}");
    }
}

#[cfg(unix)]
#[test]
fn sudo_variables_that_do_not_both_hold_a_plain_id_change_nothing() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for sudo in [
        &[("SUDO_UID", "-1"), ("SUDO_GID", "4243")][..],
        &[("SUDO_UID", "morten"), ("SUDO_GID", "4243")],
        &[("SUDO_UID", "4242"), ("SUDO_GID", "")],
        &[("SUDO_UID", "4242")],
        &[("SUDO_GID", "4243")],
        &[],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let me = user_running_the_tests(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let run = census_under_sudo(dir.path(), sudo);

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "{sudo:?}: {stderr}");
        let written = std::fs::metadata(dir.path().join("census.json")).unwrap();
        assert_eq!(written.uid(), me, "{sudo:?}");
        assert_eq!(written.permissions().mode() & 0o777, 0o600, "{sudo:?}");
        assert!(!stderr.contains("who ran sudo"), "{sudo:?}: {stderr}");
    }
}

#[cfg(unix)]
#[test]
fn a_census_in_a_directory_the_sudo_user_does_not_own_stays_with_root() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let me = user_running_the_tests(dir.path());

    let run = census_under_sudo(dir.path(), &[("SUDO_UID", "4242"), ("SUDO_GID", "4243")]);

    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    let written = std::fs::metadata(dir.path().join("census.json")).unwrap();
    assert_eq!(written.uid(), me);
    assert_eq!(
        stderr.contains("The file belongs to root, because user 4242 (group 4243)"),
        me == 0,
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn log_files_under_a_scan_path_are_listed_without_the_excluded_ones() {
    let logs = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    std::fs::write(logs.path().join("app.log"), "one line\n").unwrap();
    std::fs::write(logs.path().join("app.log.1"), "rotated\n").unwrap();
    std::fs::write(logs.path().join("payroll.log"), "private\n").unwrap();
    std::fs::write(logs.path().join("notes.txt"), "not a log\n").unwrap();
    let scan_path = logs.path().to_string_lossy().into_owned();

    let run = hostcensus(
        &[
            "--output",
            "-",
            "--scan-path",
            &scan_path,
            "--exclude",
            "payroll.*",
            "--max-age-days",
            "3",
        ],
        out.path(),
    );

    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json = String::from_utf8(run.stdout).unwrap();
    let bundle = Bundle::from_json(&json).unwrap();
    let names: Vec<_> = bundle
        .inventory
        .log_files
        .iter()
        .filter(|file| file.path.starts_with(&scan_path))
        .map(|file| file.path.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(names, ["app.log"]);
    let copies: Vec<_> = bundle
        .inventory
        .log_files
        .iter()
        .filter(|file| file.path.starts_with(&scan_path))
        .flat_map(|file| &file.rotated_copies)
        .map(|copy| copy.path.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(copies, ["app.log.1"]);
    assert_eq!(bundle.scan.options.scan_paths, [scan_path]);
    assert_eq!(bundle.scan.options.exclude_patterns, 1);
    assert!(
        !json.contains("payroll"),
        "an exclude pattern names what was to be left out, so it is not recorded"
    );
    assert_eq!(bundle.scan.options.max_age_days, 3);
    assert!(bundle.inventory_is_intact().unwrap());
}

/// intent: example every_scanner_reports exemplifies every_scanner_reports_how_it_went on cli
#[cfg(unix)]
#[test]
fn every_scanner_says_how_it_went_and_this_run_is_among_the_processes() {
    let out = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let scan_path = empty.path().to_string_lossy().into_owned();

    let run = hostcensus(&["--output", "-", "--scan-path", &scan_path], out.path());

    let bundle = Bundle::from_json(&String::from_utf8(run.stdout).unwrap()).unwrap();
    for scanner in ["docker", "files", "packages", "ports", "processes"] {
        assert!(bundle.scan.scanners.contains_key(scanner), "{scanner}");
    }
    assert!(!bundle.scan.options.process_args);
    assert!(
        bundle
            .inventory
            .processes
            .iter()
            .any(|process| process.command.ends_with("hostcensus")),
        "{:?}",
        bundle.scan.scanners["processes"]
    );
    assert!(
        bundle
            .inventory
            .processes
            .iter()
            .all(|process| !process.command.contains("--scan-path")),
        "arguments must not be recorded by default"
    );
}

#[cfg(unix)]
#[test]
fn process_arguments_are_recorded_only_on_request() {
    let out = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let scan_path = empty.path().to_string_lossy().into_owned();

    let run = hostcensus(
        &["--output", "-", "--process-args", "--scan-path", &scan_path],
        out.path(),
    );

    let bundle = Bundle::from_json(&String::from_utf8(run.stdout).unwrap()).unwrap();
    assert!(bundle.scan.options.process_args);
    assert!(
        bundle
            .inventory
            .processes
            .iter()
            .any(|process| process.command.contains("--process-args")),
        "{:?}",
        bundle.scan.scanners["processes"]
    );
}
