//! Writing a bundle to disk and telling the person what was written.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::bundle::{Bundle, ScannerStatus};
use crate::handover::{Handover, SudoUser};
use crate::inventory::{Inventory, SystemdService};
use crate::timestamp;

/// `hostcensus-<hostname>-<UTC timestamp>.json`, with anything in the host
/// name that is awkward in a file name replaced.
pub fn default_file_name(bundle: &Bundle) -> PathBuf {
    let hostname: String = bundle
        .host
        .hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let hostname = if hostname.is_empty() {
        "host".to_string()
    } else {
        hostname
    };
    let timestamp: String = bundle
        .generated_at
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    PathBuf::from(format!("hostcensus-{hostname}-{timestamp}.json"))
}

/// Writes the bundle to a new file readable only by its owner. An existing
/// file is never replaced. Under `sudo` the file is handed to the user who
/// ran it, before anything is written to it.
pub fn write_new(path: &Path, bundle: &Bundle, sudo_user: Option<SudoUser>) -> Result<Handover> {
    let json = bundle.to_json()?;
    let (mut file, handover) = match sudo_user {
        Some(user) => user
            .create(path)
            .with_context(|| format!("cannot create {}", path.display()))?,
        None => (create_private(path)?, Handover::NotNeeded),
    };
    file.write_all(json.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(handover)
}

/// What a bundle that is being replaced is called while it is written.
pub(crate) const BESIDE_SUFFIX: &str = ".hostcensus-tmp";

/// Replaces a bundle file with a changed bundle. The new content is written
/// next to the file and moved into place, so the file is never left half
/// written. Under `sudo` the new file is handed to the user who ran it.
pub fn replace(path: &Path, bundle: &Bundle, sudo_user: Option<SudoUser>) -> Result<Handover> {
    let json = bundle.to_json()?;
    let cannot_update = || format!("cannot update {}", path.display());
    if let Some(user) = sudo_user {
        return user
            .replace(path, json.as_bytes())
            .with_context(cannot_update);
    }
    let mut beside = path.as_os_str().to_owned();
    beside.push(BESIDE_SUFFIX);
    let beside = PathBuf::from(beside);

    let mut file = create_private(&beside)?;
    let written = file
        .write_all(json.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&beside, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&beside);
    }
    written.with_context(cannot_update)?;
    Ok(Handover::NotNeeded)
}

fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

/// What the person sees on standard error after a census.
pub fn summary(bundle: &Bundle, destination: &str, handover: &Handover) -> String {
    let inventory = &bundle.inventory;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "Census of {} ({}, {}) written to {destination}",
        bundle.host.hostname, bundle.host.os_version, bundle.host.architecture
    );
    for (label, count) in [
        ("log files", inventory.log_files.len()),
        ("containers", inventory.containers.len()),
        ("systemd services", inventory.systemd_services.len()),
        ("Windows services", inventory.windows_services.len()),
        ("event log channels", inventory.event_log_channels.len()),
        ("processes", inventory.processes.len()),
        ("listening ports", inventory.listening_ports.len()),
        ("installed packages", inventory.installed_packages.len()),
    ] {
        let _ = writeln!(text, "  {count:>6}  {label}");
    }
    let rotated_copies: usize = inventory
        .log_files
        .iter()
        .map(|file| file.rotated_copies.len())
        .sum();
    if rotated_copies > 0 {
        let _ = writeln!(
            text,
            "Rotated copies ({rotated_copies}) are listed under the log file they belong to."
        );
    }
    let _ = writeln!(text, "{}", log_file_rule(bundle));
    for line in activity(bundle) {
        let _ = writeln!(text, "{line}");
    }
    for (scanner, report) in &bundle.scan.scanners {
        let status = match report.status {
            ScannerStatus::Complete => continue,
            ScannerStatus::Partial => "partial",
            ScannerStatus::Unavailable => "unavailable",
        };
        let reason = report.reason.as_deref().unwrap_or("no reason given");
        let _ = writeln!(text, "  {scanner}: {status} ({reason})");
    }
    if !bundle.scan.privileged {
        let _ = writeln!(
            text,
            "Taken without root or administrator rights. Other users' processes, the journal \
             and container logs are hidden from such a census, so it cannot show what runs \
             without producing logs. For the full census run it with sudo, or from an elevated \
             prompt on Windows."
        );
    }
    if let Some(note) = handover.note() {
        let _ = writeln!(text, "{note}");
    }
    let _ = writeln!(
        text,
        "Nothing was sent anywhere. Read the file before you share it."
    );
    text
}

/// What the census can say about output, as opposed to existence: how many
/// log files are being written to, and which running containers show no
/// output at all.
fn activity(bundle: &Bundle) -> Vec<String> {
    let mut lines = Vec::new();
    let inventory = &bundle.inventory;

    if let Some(taken) = timestamp::seconds_since_1970(&bundle.generated_at) {
        let written_within = |hours: i64| {
            inventory
                .log_files
                .iter()
                .filter(|file| {
                    timestamp::seconds_since_1970(&file.modified)
                        .is_some_and(|modified| taken - modified <= hours * 3_600)
                })
                .count()
        };
        let all = inventory.log_files.len();
        if all > 0 {
            lines.push(format!(
                "Of {all} log files, {} were written to in the last 24 hours and {} not in the \
                 last 7 days.",
                written_within(24),
                all - written_within(7 * 24)
            ));
        }
    }

    let running_services = || {
        inventory
            .systemd_services
            .iter()
            .filter(|service| service.active_state == "active" && service.sub_state == "running")
    };
    let journal_read = running_services()
        .filter(|service| service.journal_entries_24h.is_some())
        .count();
    if journal_read > 0 {
        lines.push(format!(
            "Of {journal_read} running services, {} had no journal entries observed in the last \
             24 hours.",
            running_services()
                .filter(|service| service.journal_entries_24h == Some(0))
                .count()
        ));
    }

    let silent_services: Vec<String> = running_services()
        .filter(|service| shows_no_sign_of_output(service, inventory))
        .map(|service| service.name.clone())
        .collect();
    if !silent_services.is_empty() {
        lines.push(format!(
            "Running services with no sign of output: {}",
            listed(&silent_services)
        ));
    }

    let runtime_log_notes: Vec<String> = inventory
        .containers
        .iter()
        .filter(|container| container.state == "running")
        .filter_map(|container| {
            if container.log_driver == "none" {
                Some(format!("{} (runtime logging is off)", container.name))
            } else if container.log_size == Some(0) {
                Some(format!("{} (current log is empty)", container.name))
            } else {
                None
            }
        })
        .collect();
    if !runtime_log_notes.is_empty() {
        lines.push(format!(
            "Running container log observations: {}",
            listed(&runtime_log_notes)
        ));
    }
    lines
}

/// Whether a running service produces no log output as far as the census
/// can see: nothing in the journal for 24 hours, no file held open for
/// writing, and no output going to a file or to another program. It is only
/// said when all of that could be seen: the journal was read, the service's
/// processes are known, and what they have open was readable.
fn shows_no_sign_of_output(service: &SystemdService, inventory: &Inventory) -> bool {
    if service.journal_entries_24h != Some(0) {
        return false;
    }
    let processes: Vec<_> = inventory
        .processes
        .iter()
        .filter(|process| process.unit == service.name)
        .collect();
    if processes.is_empty() || processes.iter().any(|process| process.stdout.is_empty()) {
        return false;
    }
    let writes_somewhere = processes.iter().any(|process| {
        [&process.stdout, &process.stderr]
            .iter()
            .any(|output| matches!(output.as_str(), "file" | "pipe"))
            || inventory
                .log_files
                .iter()
                .any(|file| file.open_in.contains(&process.pid))
    });
    !writes_somewhere
}

/// The first ten names, and how many more there are.
fn listed(names: &[String]) -> String {
    let shown = names
        .iter()
        .take(10)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match names.len().saturating_sub(10) {
        0 => shown,
        more => format!("{shown} and {more} more"),
    }
}

/// Which files the census took for log files, from the options it ran with.
/// The names without an extension are Unix conventions and are not applied
/// on Windows.
fn log_file_rule(bundle: &Bundle) -> String {
    let options = &bundle.scan.options;
    let mut names = options
        .extensions
        .iter()
        .map(|extension| format!("*.{extension}"))
        .collect::<Vec<_>>()
        .join(", ");
    if bundle.host.os != "windows" {
        names.push_str(", *_log or like a system log (syslog, messages, secure)");
    }
    format!(
        "Log files are looked for under {}: files named {names}, written to in the last {} days.",
        options.scan_paths.join(", "),
        options.max_age_days
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bundle::{Host, Scan, ScanOptions, ScannerReport, Tool};
    use crate::inventory::Inventory;

    fn bundle(hostname: &str, privileged: bool) -> Bundle {
        Bundle::seal(
            Tool::this_build(),
            "2026-01-02T03:04:05Z".into(),
            Host {
                hostname: hostname.into(),
                os: "linux".into(),
                os_version: "Debian GNU/Linux 13".into(),
                architecture: "x86_64".into(),
                in_container: false,
            },
            Scan {
                options: ScanOptions::default(),
                privileged,
                scanners: BTreeMap::from([
                    (
                        "ports".to_string(),
                        ScannerReport {
                            status: ScannerStatus::Partial,
                            reason: Some("owning processes hidden without root".into()),
                        },
                    ),
                    (
                        "packages".to_string(),
                        ScannerReport {
                            status: ScannerStatus::Complete,
                            reason: None,
                        },
                    ),
                ]),
                duration_ms: 3,
            },
            Inventory::default(),
        )
        .unwrap()
    }

    fn options(scan_paths: &[&str]) -> ScanOptions {
        ScanOptions {
            scan_paths: scan_paths.iter().map(|path| path.to_string()).collect(),
            extensions: vec!["log".into()],
            max_age_days: 7,
            exclude_patterns: 0,
            process_args: false,
            all_label_values: false,
        }
    }

    #[test]
    fn the_summary_states_which_files_count_as_log_files() {
        let mut census = bundle("web-1", true);
        census.scan.options = options(&["/var/log"]);

        assert_eq!(
            log_file_rule(&census),
            "Log files are looked for under /var/log: files named *.log, *_log or like a system \
             log (syslog, messages, secure), written to in the last 7 days."
        );
        assert!(
            summary(&census, "census.json", &Handover::NotNeeded).contains(&log_file_rule(&census))
        );
    }

    #[test]
    fn on_windows_the_rule_names_the_three_default_paths_and_only_the_extension() {
        let mut census = bundle("WEB-1", true);
        census.host.os = "windows".into();
        census.scan.options = options(&[
            r"C:\inetpub\logs\LogFiles",
            r"C:\Windows\Logs",
            r"C:\ProgramData",
        ]);

        assert_eq!(
            log_file_rule(&census),
            r"Log files are looked for under C:\inetpub\logs\LogFiles, C:\Windows\Logs, C:\ProgramData: files named *.log, written to in the last 7 days."
        );
    }

    #[test]
    fn the_file_name_carries_host_and_time() {
        assert_eq!(
            default_file_name(&bundle("web-1.example.net", true)),
            PathBuf::from("hostcensus-web-1.example.net-20260102T030405Z.json")
        );
    }

    #[test]
    fn awkward_host_names_cannot_escape_the_directory() {
        assert_eq!(
            default_file_name(&bundle("../etc/x y", true)),
            PathBuf::from("hostcensus-.._etc_x_y-20260102T030405Z.json")
        );
        assert_eq!(
            default_file_name(&bundle("", true)),
            PathBuf::from("hostcensus-host-20260102T030405Z.json")
        );
    }

    #[test]
    fn an_existing_file_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("census.json");
        std::fs::write(&path, "keep me").unwrap();

        let error = write_new(&path, &bundle("web-1", true), None).unwrap_err();

        assert!(error.to_string().contains("cannot create"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
    }

    #[cfg(unix)]
    #[test]
    fn the_bundle_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("census.json");
        write_new(&path, &bundle("web-1", true), None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_summary_describes_file_activity_and_container_runtime_logs() {
        use crate::inventory::{Container, LogFile};

        let log_file = |path: &str, modified: &str| LogFile {
            path: path.into(),
            size: 1,
            modified: modified.into(),
            permissions: "100640".into(),
            source_format: "file".into(),
            rotated_copies: vec![],
            open_in: vec![],
        };
        let container = |name: &str, state: &str, driver: &str, size: Option<u64>| Container {
            name: name.into(),
            state: state.into(),
            log_driver: driver.into(),
            log_size: size,
            ..Container::default()
        };
        let mut census = bundle("web-1", true);
        census.inventory.log_files = vec![
            log_file("/var/log/busy.log", "2026-01-02T03:00:00Z"),
            log_file("/var/log/yesterday.log", "2026-01-01T03:04:05Z"),
            log_file("/var/log/last-week.log", "2025-12-28T00:00:00Z"),
            log_file("/var/log/quiet.log", "2025-11-20T00:00:00Z"),
        ];
        census.inventory.containers = vec![
            container("proxy", "running", "none", None),
            container("worker", "running", "json-file", Some(0)),
            container("api", "running", "json-file", Some(4096)),
            container("unseen", "running", "json-file", None),
            container("stopped", "exited", "none", None),
        ];

        let text = summary(&census, "census.json", &Handover::NotNeeded);

        assert!(
            text.contains(
                "Of 4 log files, 2 were written to in the last 24 hours and 1 not in the last 7 days."
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "Running container log observations: proxy (runtime logging is off), worker (current log is empty)"
            ),
            "{text}"
        );
    }

    fn file_activity(taken: &str, last_writes: &[&str]) -> Option<String> {
        let mut census = bundle("web-1", true);
        census.generated_at = taken.into();
        census.inventory.log_files = last_writes
            .iter()
            .map(|modified| crate::inventory::LogFile {
                path: "/var/log/app.log".into(),
                size: 1,
                modified: (*modified).into(),
                permissions: "100640".into(),
                source_format: "file".into(),
                rotated_copies: vec![],
                open_in: vec![],
            })
            .collect();
        summary(&census, "census.json", &Handover::NotNeeded)
            .lines()
            .find(|line| line.contains(" log files, "))
            .map(str::to_string)
    }

    #[test]
    fn a_file_written_exactly_a_day_or_a_week_before_the_census_still_counts() {
        assert_eq!(
            file_activity(
                "2024-03-01T00:00:00Z",
                &[
                    "2024-03-01T00:00:01Z",
                    "2024-02-29T00:00:00Z",
                    "2024-02-28T23:59:59Z",
                    "2024-02-23T00:00:00Z",
                    "2024-02-22T23:59:59Z",
                ]
            )
            .as_deref(),
            Some(
                "Of 5 log files, 2 were written to in the last 24 hours and 1 not in the last 7 \
                 days."
            )
        );
        assert_eq!(
            file_activity(
                "2023-03-01T00:00:00Z",
                &[
                    "2023-02-28T00:00:00Z",
                    "2023-02-27T23:59:59Z",
                    "2023-02-22T00:00:00Z",
                    "2023-02-21T23:59:59Z",
                ]
            )
            .as_deref(),
            Some(
                "Of 4 log files, 1 were written to in the last 24 hours and 1 not in the last 7 \
                 days."
            )
        );
        assert_eq!(
            file_activity(
                "2025-01-01T00:00:00Z",
                &[
                    "2024-12-31T00:00:00Z",
                    "2024-12-30T23:59:59Z",
                    "2024-12-25T00:00:00Z",
                    "2024-12-24T23:59:59Z",
                ]
            )
            .as_deref(),
            Some(
                "Of 4 log files, 1 were written to in the last 24 hours and 1 not in the last 7 \
                 days."
            )
        );
    }

    #[test]
    fn a_file_without_a_readable_time_counts_as_not_written_to() {
        assert_eq!(
            file_activity(
                "2026-01-02T03:04:05Z",
                &["", "+10000-01-01T00:00:00Z", "2026-01-02T03:04:05Z"]
            )
            .as_deref(),
            Some(
                "Of 3 log files, 1 were written to in the last 24 hours and 2 not in the last 7 \
                 days."
            )
        );
    }

    #[test]
    fn a_census_without_a_readable_time_says_nothing_of_file_activity() {
        for taken in ["", "+10000-01-01T00:00:00Z"] {
            assert_eq!(file_activity(taken, &["2026-01-02T03:04:05Z"]), None);
        }
    }

    #[test]
    fn a_running_service_with_no_sign_of_output_is_named() {
        use crate::inventory::{LogFile, Process, SystemdService};

        let service = |name: &str, entries: Option<u64>| SystemdService {
            name: name.into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: String::new(),
            journal_entries_24h: entries,
            last_journal_entry: String::new(),
        };
        let process = |pid: u32, unit: &str, stdout: &str| Process {
            pid,
            user: "0".into(),
            command: "/usr/bin/thing".into(),
            program: String::new(),
            cwd: String::new(),
            unit: unit.into(),
            container_id: String::new(),
            stdout: stdout.into(),
            stderr: stdout.into(),
        };
        let mut census = bundle("web-1", true);
        census.inventory.systemd_services = vec![
            // Output thrown away, nothing in the journal, no file: silent.
            service("proxy.service", Some(0)),
            // Nothing in the journal, but it writes to a file.
            service("nginx.service", Some(0)),
            // Nothing in the journal, but its output goes to another program.
            service("piped.service", Some(0)),
            // It logs to the journal.
            service("chatty.service", Some(5)),
            // The journal could not be read for it.
            service("unknown.service", None),
            // What its process has open could not be read.
            service("hidden.service", Some(0)),
            // No process of it was seen.
            service("ghost.service", Some(0)),
        ];
        census.inventory.processes = vec![
            process(10, "proxy.service", "null"),
            process(20, "nginx.service", "null"),
            process(30, "piped.service", "pipe"),
            process(40, "chatty.service", "socket"),
            process(50, "unknown.service", "null"),
            process(60, "hidden.service", ""),
        ];
        census.inventory.log_files = vec![LogFile {
            path: "/var/log/nginx/access.log".into(),
            size: 1,
            modified: "2026-01-02T03:00:00Z".into(),
            permissions: "100640".into(),
            source_format: "file".into(),
            rotated_copies: vec![],
            open_in: vec![20],
        }];

        let text = summary(&census, "census.json", &Handover::NotNeeded);

        assert!(
            text.contains("Running services with no sign of output: proxy.service\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "Of 6 running services, 5 had no journal entries observed in the last 24 hours."
            ),
            "{text}"
        );
    }

    #[test]
    fn a_long_list_is_cut_short_and_counted() {
        let names: Vec<String> = (1..=12).map(|n| format!("c{n}")).collect();
        assert_eq!(
            listed(&names),
            "c1, c2, c3, c4, c5, c6, c7, c8, c9, c10 and 2 more"
        );
    }

    #[test]
    fn the_summary_names_what_could_not_be_seen() {
        let text = summary(&bundle("web-1", false), "census.json", &Handover::NotNeeded);

        assert!(text.contains("Census of web-1"));
        assert!(text.contains("ports: partial (owning processes hidden without root)"));
        assert!(!text.contains("packages:"));
        assert!(text.contains("without root or administrator rights"));
        assert!(text.contains("Nothing was sent anywhere."));
    }

    #[test]
    fn the_summary_says_whose_the_file_is_when_sudo_was_involved() {
        let user = SudoUser::who_ran(true, Some("1000"), Some("1000")).unwrap();

        let text = summary(&bundle("web-1", true), "census.json", &Handover::Done(user));

        assert!(
            text.ends_with(
                "The file belongs to user 1000 (group 1000), who ran sudo.\n\
                 Nothing was sent anywhere. Read the file before you share it.\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_summary_does_not_mention_sudo_when_nobody_ran_it() {
        let text = summary(&bundle("web-1", true), "census.json", &Handover::NotNeeded);
        assert!(!text.contains("sudo"), "{text}");
    }

    #[test]
    fn a_privileged_census_does_not_warn_about_visibility() {
        let text = summary(&bundle("web-1", true), "census.json", &Handover::NotNeeded);
        assert!(!text.contains("Taken without root"));
    }
}
