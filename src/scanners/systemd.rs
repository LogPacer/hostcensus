//! systemd services, as `systemctl` lists them.

use std::path::Path;

use super::Scanned;
use super::command;
use crate::bundle::ScannerReport;
use crate::inventory::SystemdService;

pub(crate) async fn scan() -> Scanned<Vec<SystemdService>> {
    if !Path::new("/run/systemd/system").exists() {
        // The host does not run systemd, so there is nothing to list.
        return Scanned::complete(Vec::new());
    }

    // `--plain` matters: without it systemctl puts a status mark in front of
    // failed and not-found units, which shifts every column.
    match command::stdout_of(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--plain",
            "--no-pager",
            "--no-legend",
        ],
    )
    .await
    {
        Ok(listing) => Scanned::complete(services_in(&listing)),
        Err(error) => Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string())),
    }
}

fn services_in(listing: &str) -> Vec<SystemdService> {
    listing
        .lines()
        .filter_map(parse_systemctl_line)
        .filter(produces_logs)
        .collect()
}

/// Inactive and dead units write nothing, so they are left out. Failed units
/// stay: they usually wrote diagnostics on the way down.
fn produces_logs(service: &SystemdService) -> bool {
    !matches!(service.active_state.as_str(), "inactive" | "dead")
}

/// One line of `systemctl list-units --plain --no-legend`:
/// `unit.service  loaded  active  running  Description text`.
fn parse_systemctl_line(line: &str) -> Option<SystemdService> {
    let mut tokens = line.split_whitespace();

    let mut name = tokens.next()?;
    if !name.ends_with(".service") {
        // A status mark from a systemctl that ignores `--plain`.
        name = tokens.next()?;
        if !name.ends_with(".service") {
            return None;
        }
    }

    let load_state = tokens.next().unwrap_or_default();
    let active_state = tokens.next().unwrap_or_default();
    let sub_state = tokens.next().unwrap_or_default();
    let description = tokens.collect::<Vec<&str>>().join(" ");

    Some(SystemdService {
        name: name.to_string(),
        load_state: load_state.to_string(),
        active_state: active_state.to_string(),
        sub_state: sub_state.to_string(),
        description,
        journal_entries_24h: None,
        last_journal_entry: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_service_line() {
        let line =
            "  nginx.service                loaded active running  A high performance web server";
        let svc = parse_systemctl_line(line).unwrap();
        assert_eq!(svc.name, "nginx.service");
        assert_eq!(svc.load_state, "loaded");
        assert_eq!(svc.active_state, "active");
        assert_eq!(svc.sub_state, "running");
        assert_eq!(svc.description, "A high performance web server");
    }

    #[test]
    fn parse_inactive_service() {
        let line = "  bluetooth.service            loaded inactive dead    Bluetooth service";
        let svc = parse_systemctl_line(line).unwrap();
        assert_eq!(svc.name, "bluetooth.service");
        assert_eq!(svc.active_state, "inactive");
        assert_eq!(svc.sub_state, "dead");
    }

    /// systemd 255 without `--plain`, as seen on Ubuntu 24.04: failed and
    /// not-found units carry a status mark in front of their name.
    #[test]
    fn a_status_mark_in_front_of_the_unit_is_passed_over() {
        let line = "\u{25cf} always-fails.service                     loaded    failed   failed  A unit that always fails";
        let svc = parse_systemctl_line(line).unwrap();
        assert_eq!(svc.name, "always-fails.service");
        assert_eq!(svc.load_state, "loaded");
        assert_eq!(svc.active_state, "failed");
        assert_eq!(svc.sub_state, "failed");
        assert_eq!(svc.description, "A unit that always fails");
    }

    /// The same listing with `--plain`, which is what the scanner asks for.
    #[test]
    fn a_plain_listing_keeps_failed_units_and_drops_units_that_do_not_exist() {
        let listing = "\
always-fails.service                     loaded    failed   failed  A unit that always fails
auditd.service                           not-found inactive dead    auditd.service
nginx.service                            loaded    active   running A high performance web server and a reverse proxy server
";
        let names: Vec<String> = services_in(listing)
            .into_iter()
            .map(|service| service.name)
            .collect();

        assert_eq!(names, ["always-fails.service", "nginx.service"]);
    }

    #[test]
    fn skip_non_service_units() {
        let line = "  basic.target                 loaded active active   Basic System";
        assert!(parse_systemctl_line(line).is_none());
    }

    #[test]
    fn skip_empty_lines() {
        assert!(parse_systemctl_line("").is_none());
        assert!(parse_systemctl_line("   ").is_none());
    }

    #[test]
    fn inactive_and_dead_units_are_left_out_and_failed_ones_kept() {
        let listing = "\
nginx.service      loaded    active   running A high performance web server
backup.service     loaded    failed   failed  Nightly backup
bluetooth.service  loaded    inactive dead    Bluetooth service
starting.service   loaded    activating start Something starting
";
        let names: Vec<String> = services_in(listing)
            .into_iter()
            .map(|service| service.name)
            .collect();

        assert_eq!(
            names,
            ["nginx.service", "backup.service", "starting.service"]
        );
    }
}
