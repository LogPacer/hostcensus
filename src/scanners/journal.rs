//! How much each systemd service wrote to the journal in the last 24 hours.
//!
//! `journalctl` is asked for the unit name of each entry and nothing else, so
//! no log message reaches hostcensus. The entries are read newest first: if
//! the time limit cuts the reading short, the time of each service's last
//! entry is still right and only the counts are too low.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use super::command::TIME_LIMIT;
use crate::bundle::ScannerReport;
use crate::inventory::SystemdService;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Activity {
    entries: u64,
    /// Microseconds since the Unix epoch, as the journal counts time.
    last_entry: u64,
}

pub(crate) struct JournalScan {
    by_unit: BTreeMap<String, Activity>,
    /// Whether the entries of every service were visible. When they were
    /// not, a service without entries may still have written some.
    saw_every_service: bool,
    pub report: ScannerReport,
}

/// `None` on a host without systemd, where there is no journal to ask.
pub(crate) async fn scan() -> Option<JournalScan> {
    if !Path::new("/run/systemd/system").exists() {
        return None;
    }

    let mut child = match tokio::process::Command::new("journalctl")
        .args([
            "--since=-24h",
            "--reverse",
            "--no-pager",
            "--output=json",
            "--output-fields=_SYSTEMD_UNIT",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let reason = if error.kind() == std::io::ErrorKind::NotFound {
                "journalctl is not installed".to_string()
            } else {
                format!("journalctl could not be started: {}", error.kind())
            };
            return Some(JournalScan {
                by_unit: BTreeMap::new(),
                saw_every_service: false,
                report: ScannerReport::unavailable(reason),
            });
        }
    };

    let mut by_unit = BTreeMap::new();
    let mut cut_short = false;
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        let deadline = tokio::time::Instant::now() + TIME_LIMIT;
        loop {
            match tokio::time::timeout_at(deadline, lines.next_line()).await {
                Ok(Ok(Some(line))) => count(&mut by_unit, &line),
                Ok(_) => break,
                Err(_) => {
                    cut_short = true;
                    let _ = child.start_kill();
                    break;
                }
            }
        }
    }

    let mut complaints = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = tokio::time::timeout(TIME_LIMIT, stderr.read_to_string(&mut complaints)).await;
    }
    let _ = child.wait().await;

    let (report, saw_every_service) = judge(&complaints, cut_short, by_unit.is_empty());
    Some(JournalScan {
        by_unit,
        saw_every_service,
        report,
    })
}

/// One line of `journalctl --output=json --output-fields=_SYSTEMD_UNIT`. An
/// entry that no service wrote, such as a kernel message, has no unit.
#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: Option<String>,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    written_at: Option<String>,
}

fn count(by_unit: &mut BTreeMap<String, Activity>, line: &str) {
    let Ok(Entry {
        unit: Some(unit),
        written_at,
    }) = serde_json::from_str::<Entry>(line)
    else {
        return;
    };
    let activity = by_unit.entry(unit).or_default();
    activity.entries += 1;
    if let Some(written_at) = written_at.and_then(|microseconds| microseconds.parse().ok()) {
        activity.last_entry = activity.last_entry.max(written_at);
    }
}

/// What the reading amounts to, and whether every service's entries were
/// visible. `journalctl` exits successfully and complains on standard error
/// when it may not read the journal, so the complaint decides.
fn judge(complaints: &str, cut_short: bool, nothing_read: bool) -> (ScannerReport, bool) {
    if complaints.contains("No journal files were opened") {
        return (
            ScannerReport::unavailable(
                "the journal can only be read by root or a member of the systemd-journal group",
            ),
            false,
        );
    }
    if complaints.contains("not seeing messages from other users") {
        return (
            ScannerReport::partial(
                "only this user's journal entries are visible without root or the \
                 systemd-journal group",
            ),
            false,
        );
    }
    if cut_short {
        return (
            ScannerReport::partial(format!(
                "the journal of the last 24 hours was not read to the end within {} seconds, so \
                 the entry counts are too low",
                TIME_LIMIT.as_secs()
            )),
            true,
        );
    }
    let first_complaint = complaints
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty());
    match first_complaint {
        Some(complaint) if nothing_read => (
            ScannerReport::unavailable(format!(
                "journalctl failed: {}",
                complaint.chars().take(120).collect::<String>()
            )),
            false,
        ),
        _ => (ScannerReport::complete(), true),
    }
}

impl JournalScan {
    /// Says of each service how much it wrote. Where the entries of every
    /// service were visible, a service without entries wrote nothing, and is
    /// given a count of zero. Otherwise it is left without a count.
    pub(crate) fn describe(&self, services: &mut [SystemdService]) {
        if !self.saw_every_service {
            return;
        }
        for service in services {
            let activity = self.by_unit.get(&service.name).copied().unwrap_or_default();
            service.journal_entries_24h = Some(activity.entries);
            if activity.last_entry > 0 {
                service.last_journal_entry = super::rfc3339(
                    std::time::UNIX_EPOCH + std::time::Duration::from_micros(activity.last_entry),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ScannerStatus;

    // The shape systemd 255 prints with `--output-fields=_SYSTEMD_UNIT`.
    fn entry(unit: &str, microseconds: u64) -> String {
        format!(
            r#"{{"__REALTIME_TIMESTAMP":"{microseconds}","_BOOT_ID":"8d69f756dd5c43418cecce848b8d4af4","__CURSOR":"s=c65f;i=843","__SEQNUM":"2115","_SYSTEMD_UNIT":"{unit}","__MONOTONIC_TIMESTAMP":"261206955763"}}"#
        )
    }

    fn service(name: &str) -> SystemdService {
        SystemdService {
            name: name.into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: String::new(),
            journal_entries_24h: None,
            last_journal_entry: String::new(),
        }
    }

    fn counted(lines: &[String]) -> BTreeMap<String, Activity> {
        let mut by_unit = BTreeMap::new();
        for line in lines {
            count(&mut by_unit, line);
        }
        by_unit
    }

    #[test]
    fn entries_are_counted_per_unit_and_the_latest_is_kept() {
        let by_unit = counted(&[
            entry("shop.service", 1_767_323_045_000_000),
            entry("nginx.service", 1_767_323_040_000_000),
            entry("shop.service", 1_767_323_000_000_000),
            entry("shop.service", 1_767_322_000_000_000),
        ]);

        assert_eq!(
            by_unit["shop.service"],
            Activity {
                entries: 3,
                last_entry: 1_767_323_045_000_000
            }
        );
        assert_eq!(by_unit["nginx.service"].entries, 1);
    }

    #[test]
    fn lines_that_no_service_wrote_are_passed_over() {
        let by_unit = counted(&[
            r#"{"__REALTIME_TIMESTAMP":"1767323045000000","_BOOT_ID":"8d69"}"#.to_string(),
            "not json".to_string(),
            String::new(),
            r#"{"_SYSTEMD_UNIT":["a.service","b.service"]}"#.to_string(),
        ]);

        assert!(by_unit.is_empty());
    }

    #[test]
    fn a_service_without_entries_wrote_nothing_when_every_entry_was_visible() {
        let scan = JournalScan {
            by_unit: counted(&[entry("shop.service", 1_767_323_045_000_000)]),
            saw_every_service: true,
            report: ScannerReport::complete(),
        };
        let mut services = [service("shop.service"), service("proxy.service")];

        scan.describe(&mut services);

        assert_eq!(services[0].journal_entries_24h, Some(1));
        assert_eq!(services[0].last_journal_entry, "2026-01-02T03:04:05Z");
        assert_eq!(services[1].journal_entries_24h, Some(0));
        assert_eq!(services[1].last_journal_entry, "");
    }

    #[test]
    fn no_count_is_given_when_other_entries_may_be_hidden() {
        let scan = JournalScan {
            by_unit: counted(&[entry("shop.service", 1_767_323_045_000_000)]),
            saw_every_service: false,
            report: ScannerReport::partial("hidden"),
        };
        let mut services = [service("shop.service"), service("proxy.service")];

        scan.describe(&mut services);

        assert_eq!(services[0].journal_entries_24h, None);
        assert_eq!(services[1].journal_entries_24h, None);
    }

    #[test]
    fn the_reading_is_judged_by_what_journalctl_complained_about() {
        let (report, saw_all) = judge(
            "No journal files were opened due to insufficient permissions.\n",
            false,
            true,
        );
        assert_eq!(report.status, ScannerStatus::Unavailable);
        assert!(!saw_all);

        let (report, saw_all) = judge(
            "Hint: You are currently not seeing messages from other users and the system.\n",
            false,
            false,
        );
        assert_eq!(report.status, ScannerStatus::Partial);
        assert!(!saw_all);

        let (report, saw_all) = judge("", true, false);
        assert_eq!(report.status, ScannerStatus::Partial);
        assert!(report.reason.unwrap().contains("counts are too low"));
        assert!(saw_all);

        let (report, saw_all) = judge("Failed to open journal: Protocol error\n", false, true);
        assert_eq!(report.status, ScannerStatus::Unavailable);
        assert!(!saw_all);

        // A quiet host: nothing was written, and nothing was complained about.
        let (report, saw_all) = judge("", false, true);
        assert_eq!(report.status, ScannerStatus::Complete);
        assert!(saw_all);
    }
}
