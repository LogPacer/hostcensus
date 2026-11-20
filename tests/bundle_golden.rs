//! Pins the bundle format: a fixed census must serialize to the committed
//! fixture byte for byte, and the fixture must read back as the same census.
//!
//! After a deliberate format change, regenerate with
//! `REGENERATE_BUNDLE_FIXTURE=1 cargo test --test bundle_golden` and review
//! the diff. A change to this fixture is a change to the format.

use std::collections::BTreeMap;
use std::path::PathBuf;

use hostcensus::bundle::{
    Bundle, Collected, Host, Mark, NotedBy, Scan, ScanOptions, ScannerReport, ScannerStatus,
    SourceKind, SourceRef, Tool,
};
use hostcensus::inventory::{
    Container, EventLogChannel, Inventory, ListeningPort, LogFile, Package, Process, RotatedCopy,
    SystemdService, WindowsService,
};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bundle.v1.json")
}

fn census() -> Bundle {
    let inventory = Inventory {
        log_files: vec![
            LogFile {
                path: "/var/log/nginx/error.log".into(),
                size: 2048,
                modified: "2026-01-02T03:00:00Z".into(),
                permissions: "100640".into(),
                source_format: "file".into(),
                rotated_copies: vec![],
                open_in: vec![],
            },
            LogFile {
                path: "/var/log/nginx/access.log".into(),
                size: 1_048_576,
                modified: "2026-01-02T03:04:00Z".into(),
                permissions: "100640".into(),
                source_format: "file".into(),
                rotated_copies: vec![
                    RotatedCopy {
                        path: "/var/log/nginx/access.log.1".into(),
                        size: 8_388_608,
                        modified: "2026-01-02T00:00:01Z".into(),
                    },
                    RotatedCopy {
                        path: "/var/log/nginx/access.log.2.gz".into(),
                        size: 524_288,
                        modified: "2026-01-01T00:00:01Z".into(),
                    },
                ],
                open_in: vec![812],
            },
        ],
        containers: vec![Container {
            id: "0123456789ab".into(),
            name: "shop-api-1".into(),
            image: "registry.example.net/shop/api:4.2".into(),
            state: "running".into(),
            runtime: "docker".into(),
            service_name: "api".into(),
            service_name_explicit: false,
            stable_identifier: "shop/api".into(),
            stable_instance_id: "shop/api/1".into(),
            identifiers: BTreeMap::from([
                ("compose.project".to_string(), "shop".to_string()),
                ("compose.service".to_string(), "api".to_string()),
                ("container.name".to_string(), "shop-api-1".to_string()),
                (
                    "image.repo".to_string(),
                    "registry.example.net/shop/api".to_string(),
                ),
            ]),
            labels: BTreeMap::from([
                ("com.docker.compose.project".to_string(), "shop".to_string()),
                ("com.docker.compose.service".to_string(), "api".to_string()),
            ]),
            label_keys_withheld: vec!["traefik.http.middlewares.auth.basicauth.users".into()],
            env: BTreeMap::from([
                ("NODE_ENV".to_string(), "production".to_string()),
                ("NODE_VERSION".to_string(), "22.11.0".to_string()),
            ]),
            env_names_withheld: vec!["DATABASE_URL".into(), "PATH".into()],
            log_path: "/var/lib/docker/containers/0123456789ab/0123456789ab-json.log".into(),
            log_driver: "json-file".into(),
            log_size: Some(52_428_800),
            log_modified: "2026-01-02T03:04:01Z".into(),
            container_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ..Container::default()
        }],
        systemd_services: vec![SystemdService {
            name: "nginx.service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: "A high performance web server".into(),
            journal_entries_24h: Some(12),
            last_journal_entry: "2026-01-02T02:58:41Z".into(),
        }],
        windows_services: vec![WindowsService {
            name: "W3SVC".into(),
            display_name: "World Wide Web Publishing Service".into(),
            state: "running".into(),
            service_type: "WIN32_SHARE_PROCESS".into(),
            pid: 2100,
        }],
        event_log_channels: vec![EventLogChannel {
            channel: "Security".into(),
            record_count: 31_337,
        }],
        processes: vec![
            Process {
                pid: 812,
                user: "33".into(),
                command: "/usr/sbin/nginx".into(),
                program: String::new(),
                cwd: "/".into(),
                unit: "nginx.service".into(),
                container_id: String::new(),
                stdout: String::new(),
                stderr: String::new(),
            },
            Process {
                pid: 1490,
                user: "1001".into(),
                command: "/usr/bin/java".into(),
                program: "/opt/shop/shop.jar".into(),
                cwd: "/opt/shop".into(),
                unit: String::new(),
                container_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                stdout: "pipe".into(),
                stderr: "pipe".into(),
            },
        ],
        listening_ports: vec![ListeningPort {
            port: 443,
            protocol: "tcp".into(),
            process: "nginx".into(),
            pid: 812,
        }],
        installed_packages: vec![Package {
            name: "nginx".into(),
            version: "1.26.3-3".into(),
            manager: "apt".into(),
        }],
    };

    let mut bundle = Bundle::seal(
        Tool {
            name: "hostcensus".into(),
            version: "0.1.0".into(),
            commit: Some("0000000000000000000000000000000000000000".into()),
        },
        "2026-01-02T03:04:05Z".into(),
        Host {
            hostname: "web-1.example.net".into(),
            os: "linux".into(),
            os_version: "Debian GNU/Linux 13 (trixie)".into(),
            architecture: "x86_64".into(),
            in_container: false,
        },
        Scan {
            options: ScanOptions {
                scan_paths: vec!["/var/log".into()],
                extensions: vec!["log".into()],
                max_age_days: 7,
                exclude_patterns: 1,
                process_args: false,
                all_label_values: false,
            },
            privileged: false,
            scanners: BTreeMap::from([
                (
                    "packages".to_string(),
                    ScannerReport {
                        status: ScannerStatus::Complete,
                        reason: None,
                    },
                ),
                (
                    "ports".to_string(),
                    ScannerReport {
                        status: ScannerStatus::Partial,
                        reason: Some(
                            "without root, 1 listening socket has no visible owner and \
                             listeners inside containers may be missing"
                                .into(),
                        ),
                    },
                ),
                (
                    "cri".to_string(),
                    ScannerReport {
                        status: ScannerStatus::Unavailable,
                        reason: Some(
                            "crictl is not installed, so the containers of the pods under \
                             /var/log/pods are not listed"
                                .into(),
                        ),
                    },
                ),
            ]),
            duration_ms: 412,
        },
        inventory,
    )
    .unwrap();

    bundle.coverage.marks.push(Mark {
        source: SourceRef {
            kind: SourceKind::LogFile,
            identifier: "/var/log/nginx/access.log".into(),
        },
        collected: Collected::Yes,
        collector: Some("fluent-bit".into()),
        destination: Some("elasticsearch".into()),
        evidence: Some("/etc/fluent-bit/fluent-bit.conf:14".into()),
        noted_by: NotedBy::Agent,
        noted_at: "2026-01-02T03:10:00Z".into(),
    });
    bundle
}

/// intent: example fixed_census_matches_fixture exemplifies the_bundle_format_is_pinned on cli
#[test]
fn a_fixed_census_matches_the_committed_bundle() {
    let json = census().to_json().unwrap();

    if std::env::var_os("REGENERATE_BUNDLE_FIXTURE").is_some() {
        std::fs::write(fixture_path(), &json).unwrap();
    }

    let fixture = std::fs::read_to_string(fixture_path()).unwrap();
    assert_eq!(
        json, fixture,
        "the bundle format changed; see the header of this test"
    );
}

#[test]
fn the_committed_bundle_reads_back_as_the_same_census() {
    let fixture = std::fs::read_to_string(fixture_path()).unwrap();
    let bundle = Bundle::from_json(&fixture).unwrap();

    assert_eq!(bundle, census());
    assert!(bundle.inventory_is_intact().unwrap());
}

#[test]
fn the_committed_bundle_lists_sources_in_a_stable_order() {
    let fixture = std::fs::read_to_string(fixture_path()).unwrap();
    let bundle = Bundle::from_json(&fixture).unwrap();
    let paths: Vec<_> = bundle
        .inventory
        .log_files
        .iter()
        .map(|file| file.path.as_str())
        .collect();

    assert_eq!(
        paths,
        ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]
    );
}
