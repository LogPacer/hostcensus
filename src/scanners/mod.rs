//! The scanners: each observes one aspect of the host and says how completely
//! it could.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::bundle::{ScanOptions, ScannerReport};
use crate::inventory::{Inventory, LogFile};
pub(crate) use crate::timestamp::rfc3339;

mod command;
mod container;
#[cfg(unix)]
mod cri;
mod docker;
#[cfg(any(windows, test))]
mod event_log;
#[cfg(windows)]
mod event_log_api;
mod exclude_paths;
mod files;
#[cfg(unix)]
mod journal;
mod layer_stores;
#[cfg(unix)]
mod packages;
mod ports;
mod processes;
#[cfg(any(unix, test))]
mod program;
#[cfg(unix)]
mod systemd;
#[cfg(any(windows, test))]
mod windows_services;

/// What a scanner found, and how completely it could look.
pub(crate) struct Scanned<T> {
    pub found: T,
    pub report: ScannerReport,
}

impl<T> Scanned<T> {
    pub fn new(found: T, report: ScannerReport) -> Self {
        Self { found, report }
    }

    pub fn complete(found: T) -> Self {
        Self::new(found, ScannerReport::complete())
    }
}

/// Runs every scanner that applies to this operating system.
pub fn scan(
    options: &ScanOptions,
    exclude: &[String],
    privileged: bool,
) -> anyhow::Result<(Inventory, BTreeMap<String, ScannerReport>)> {
    use anyhow::Context;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the scanners")?;
    Ok(runtime.block_on(scan_host(options, exclude, privileged)))
}

async fn scan_host(
    options: &ScanOptions,
    exclude: &[String],
    privileged: bool,
) -> (Inventory, BTreeMap<String, ScannerReport>) {
    let (containers_and_files, (processes, held_open), ports, only_here) = tokio::join!(
        containers_and_files(options, exclude),
        processes::scan(options.process_args, privileged),
        ports::scan(privileged),
        scanners_of_this_system_only(),
    );
    let (mut inventory, mut reports) = only_here;

    inventory.log_files = containers_and_files.files.found;
    files::note_files_held_open(
        &mut inventory.log_files,
        &held_open,
        &options.extensions,
        &exclude_paths::ExcludePaths::new(exclude),
        &containers_and_files.runtime_owned,
    );
    inventory.containers = containers_and_files
        .containers
        .into_iter()
        .map(|container| {
            container
                .with_log_seen_from_outside()
                .into_census_entry(options.all_label_values)
        })
        .collect();
    inventory.processes = processes.found;
    inventory.listening_ports = ports.found;

    reports.extend([
        ("docker".to_string(), containers_and_files.docker),
        ("files".to_string(), containers_and_files.files.report),
        ("ports".to_string(), ports.report),
        ("processes".to_string(), processes.report),
    ]);
    if let Some(cri) = containers_and_files.cri {
        reports.insert("cri".to_string(), cri);
    }
    (inventory, reports)
}

/// systemd and packages. systemd exists on Linux only; macOS has neither it
/// nor a Container Runtime Interface.
#[cfg(unix)]
async fn scanners_of_this_system_only() -> (Inventory, BTreeMap<String, ScannerReport>) {
    let (mut systemd, packages, journal) =
        tokio::join!(systemd::scan(), packages::scan(), journal::scan());

    let mut reports = BTreeMap::from([("packages".to_string(), packages.report)]);
    if cfg!(target_os = "linux") {
        reports.insert("systemd".to_string(), systemd.report);
    }
    if let Some(journal) = journal {
        journal.describe(&mut systemd.found);
        reports.insert("journal".to_string(), journal.report);
    }
    let inventory = Inventory {
        systemd_services: systemd.found,
        installed_packages: packages.found,
        ..Inventory::default()
    };
    (inventory, reports)
}

/// Windows services and event-log channels.
#[cfg(windows)]
async fn scanners_of_this_system_only() -> (Inventory, BTreeMap<String, ScannerReport>) {
    let (services, channels) = tokio::join!(windows_services::scan(), event_log::scan());

    let reports = BTreeMap::from([
        ("event_log".to_string(), channels.report),
        ("windows_services".to_string(), services.report),
    ]);
    let inventory = Inventory {
        windows_services: services.found,
        event_log_channels: channels.found,
        ..Inventory::default()
    };
    (inventory, reports)
}

struct ContainersAndFiles {
    containers: Vec<container::ObservedContainer>,
    files: Scanned<Vec<LogFile>>,
    /// Paths a container runtime accounts for, which the files scanner
    /// leaves to it.
    runtime_owned: Vec<std::path::PathBuf>,
    docker: ScannerReport,
    /// Present on Linux only, where the Container Runtime Interface exists.
    cri: Option<ScannerReport>,
}

/// The container runtimes are asked first, because what they answer decides
/// which directories the file walk leaves to them.
async fn containers_and_files(options: &ScanOptions, exclude: &[String]) -> ContainersAndFiles {
    #[cfg(unix)]
    let (docker, cri) = tokio::join!(docker::scan(), cri::scan());
    #[cfg(not(unix))]
    let docker = docker::scan().await;

    #[cfg(unix)]
    let pod_logs_accounted_for = cri.runtime_answered;
    #[cfg(not(unix))]
    let pod_logs_accounted_for = false;

    let division = divide_log_directories(
        &docker,
        pod_logs_accounted_for,
        docker::default_json_log_root(),
    );
    let scan_paths = options.scan_paths.clone();
    let extensions = options.extensions.clone();
    let max_age_days = options.max_age_days;
    let exclude = exclude_paths::ExcludePaths::new(exclude);
    let runtime_owned = division.runtime_owned.clone();
    let layer_stores = layer_stores::on_this_host(docker.data_root.as_deref());

    let files = tokio::task::spawn_blocking(move || {
        files::walk(
            &files::Walk {
                scan_paths: &scan_paths,
                extensions: &extensions,
                max_age_days,
                exclude: &exclude,
                runtime_owned: &division.runtime_owned,
                layer_stores: &layer_stores,
                also_walk: &division.also_walk,
            },
            &mut files::Progress::on_standard_error(),
        )
    })
    .await;
    let files = match files {
        Ok(found) => {
            let report = found.report();
            Scanned::new(found.files, report)
        }
        Err(_) => Scanned::new(
            Vec::new(),
            ScannerReport::unavailable("the file walk stopped unexpectedly"),
        ),
    };

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut containers = docker.containers;
    #[cfg(unix)]
    containers.extend(cri.containers);
    #[cfg(unix)]
    let cri = cfg!(target_os = "linux").then_some(cri.report);
    #[cfg(not(unix))]
    let cri = None;

    ContainersAndFiles {
        containers,
        files,
        runtime_owned,
        docker: docker.report,
        cri,
    }
}

struct LogDirectories {
    /// Left out of the file walk: the containers listed account for them.
    runtime_owned: Vec<PathBuf>,
    /// Walked even when no scan path covers them.
    also_walk: Vec<PathBuf>,
}

/// A runtime that answered accounts for its own log files, so the file walk
/// skips them. When Docker did not answer, its default log directory is
/// walked instead, so its containers' logs are at least listed as files.
fn divide_log_directories(
    docker: &docker::DockerScan,
    pod_logs_accounted_for: bool,
    default_docker_json_log_root: PathBuf,
) -> LogDirectories {
    let mut runtime_owned = Vec::new();
    let mut also_walk = Vec::new();

    if docker.engine_answered {
        runtime_owned.extend(docker.owned_paths.iter().cloned());
        if docker.data_root.is_none() {
            runtime_owned.push(default_docker_json_log_root);
        }
    } else {
        also_walk.push(default_docker_json_log_root);
    }
    if pod_logs_accounted_for {
        runtime_owned.push(files::POD_LOGS_DIR.into());
    }

    LogDirectories {
        runtime_owned,
        also_walk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker_scan(engine_answered: bool, data_root_known: bool) -> docker::DockerScan {
        let data_root = data_root_known.then(|| PathBuf::from("/var/lib/docker"));
        docker::DockerScan {
            containers: Vec::new(),
            owned_paths: if engine_answered {
                vec![PathBuf::from("/custom/running-container.log")]
            } else {
                Vec::new()
            },
            engine_answered,
            data_root,
            report: ScannerReport::complete(),
        }
    }

    #[test]
    fn a_docker_listing_without_a_data_root_still_leaves_the_default_log_directory_out() {
        let division = divide_log_directories(
            &docker_scan(true, false),
            false,
            "/var/lib/docker/containers".into(),
        );

        assert_eq!(
            division.runtime_owned,
            [
                PathBuf::from("/custom/running-container.log"),
                PathBuf::from("/var/lib/docker/containers"),
            ]
        );
        assert!(division.also_walk.is_empty());
    }

    #[test]
    fn a_docker_listing_with_a_data_root_owns_only_what_it_named() {
        let division = divide_log_directories(
            &docker_scan(true, true),
            false,
            "/var/lib/docker/containers".into(),
        );

        assert_eq!(
            division.runtime_owned,
            [PathBuf::from("/custom/running-container.log")]
        );
    }

    #[test]
    fn without_docker_its_default_log_directory_is_walked_as_files() {
        let division = divide_log_directories(
            &docker_scan(false, false),
            false,
            "/var/lib/docker/containers".into(),
        );

        assert!(division.runtime_owned.is_empty());
        assert_eq!(
            division.also_walk,
            [PathBuf::from("/var/lib/docker/containers")]
        );
    }

    #[test]
    fn a_runtime_that_answered_accounts_for_the_pod_logs() {
        let division = divide_log_directories(
            &docker_scan(false, false),
            true,
            "/var/lib/docker/containers".into(),
        );

        assert_eq!(division.runtime_owned, [PathBuf::from("/var/log/pods")]);
    }

    #[test]
    fn every_scanner_for_this_system_reports_and_no_other() {
        let options = ScanOptions {
            scan_paths: vec![],
            ..ScanOptions::default()
        };

        let (_, reports) = scan(&options, &[], false).unwrap();

        let has_a_journal = std::path::Path::new("/run/systemd/system").exists();
        let expected: &[&str] = if cfg!(target_os = "linux") && has_a_journal {
            &[
                "cri",
                "docker",
                "files",
                "journal",
                "packages",
                "ports",
                "processes",
                "systemd",
            ]
        } else if cfg!(target_os = "linux") {
            &[
                "cri",
                "docker",
                "files",
                "packages",
                "ports",
                "processes",
                "systemd",
            ]
        } else if cfg!(windows) {
            &[
                "docker",
                "event_log",
                "files",
                "ports",
                "processes",
                "windows_services",
            ]
        } else {
            &["docker", "files", "packages", "ports", "processes"]
        };
        assert_eq!(reports.keys().collect::<Vec<_>>(), expected);
    }
}
