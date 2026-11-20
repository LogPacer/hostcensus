//! The bundle: one census of one host, as written to disk.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::inventory::Inventory;

pub const FORMAT: &str = "hostcensus.bundle/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub tool: Tool,
    /// When the census was taken, RFC 3339 in UTC.
    pub generated_at: String,
    pub host: Host,
    pub scan: Scan,
    pub inventory: Inventory,
    /// SHA-256 of `inventory`, so a later edit to the observations shows.
    pub inventory_sha256: String,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

impl Tool {
    pub fn this_build() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("HOSTCENSUS_COMMIT").map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub architecture: String,
    /// True when the census was taken from inside a container, where it sees
    /// the container and not the machine.
    pub in_container: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scan {
    pub options: ScanOptions,
    /// Whether the census ran as root or an elevated administrator.
    pub privileged: bool,
    /// One entry per scanner that applies to this operating system.
    pub scanners: BTreeMap<String, ScannerReport>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    pub scan_paths: Vec<String>,
    pub extensions: Vec<String>,
    pub max_age_days: u64,
    /// How many `--exclude` patterns were given. The patterns are not
    /// recorded: they name what the person wanted left out.
    pub exclude_patterns: usize,
    pub process_args: bool,
    pub all_label_values: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerReport {
    pub status: ScannerStatus,
    /// Why the result is partial or unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ScannerReport {
    pub fn complete() -> Self {
        Self {
            status: ScannerStatus::Complete,
            reason: None,
        }
    }

    pub fn partial(reason: impl Into<String>) -> Self {
        Self {
            status: ScannerStatus::Partial,
            reason: Some(reason.into()),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: ScannerStatus::Unavailable,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerStatus {
    /// The scanner saw everything it looks for.
    Complete,
    /// The scanner ran but could not see everything, usually for lack of
    /// privileges.
    Partial,
    /// The scanner could not run.
    Unavailable,
}

/// What is already collected, as stated by a person or an agent. The census
/// itself never writes here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub marks: Vec<Mark>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    pub source: SourceRef,
    pub collected: Collected,
    /// What collects it, such as the name of a log shipper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
    /// Where the collector sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Where this was read from, such as a configuration file and line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    pub noted_by: NotedBy,
    pub noted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub identifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LogFile,
    Container,
    SystemdService,
    WindowsService,
    EventLogChannel,
}

impl SourceKind {
    pub const ALL: [Self; 5] = [
        Self::LogFile,
        Self::Container,
        Self::SystemdService,
        Self::WindowsService,
        Self::EventLogChannel,
    ];

    /// The name of the kind as it is written in a bundle and on the command
    /// line.
    pub fn name(self) -> &'static str {
        match self {
            Self::LogFile => "log_file",
            Self::Container => "container",
            Self::SystemdService => "systemd_service",
            Self::WindowsService => "windows_service",
            Self::EventLogChannel => "event_log_channel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Collected {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotedBy {
    Human,
    Agent,
}

impl Bundle {
    /// Seals a census: orders the inventory, fingerprints it, and starts with
    /// no coverage marks.
    pub fn seal(
        tool: Tool,
        generated_at: String,
        host: Host,
        scan: Scan,
        mut inventory: Inventory,
    ) -> Result<Self> {
        inventory.sort();
        let inventory_sha256 = inventory_digest(&inventory)?;
        Ok(Self {
            format: FORMAT.to_string(),
            tool,
            generated_at,
            host,
            scan,
            inventory,
            inventory_sha256,
            coverage: Coverage::default(),
        })
    }

    /// False when the inventory no longer matches the fingerprint taken when
    /// the census was sealed.
    pub fn inventory_is_intact(&self) -> Result<bool> {
        Ok(inventory_digest(&self.inventory)? == self.inventory_sha256)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json).context("not a hostcensus bundle")?;
        anyhow::ensure!(
            bundle.format == FORMAT,
            "unsupported bundle format {:?}, this build reads {FORMAT:?}",
            bundle.format
        );
        Ok(bundle)
    }

    /// The bundle as it is written to disk: indented JSON ending in a newline.
    pub fn to_json(&self) -> Result<String> {
        let mut json = serde_json::to_string_pretty(self).context("serializing the bundle")?;
        json.push('\n');
        Ok(json)
    }
}

/// SHA-256, in lowercase hex, of the inventory serialized as compact JSON
/// with keys in the order the bundle writes them.
fn inventory_digest(inventory: &Inventory) -> Result<String> {
    let bytes = serde_json::to_vec(inventory).context("serializing the inventory")?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Package;

    fn sealed(inventory: Inventory) -> Bundle {
        Bundle::seal(
            Tool {
                name: "hostcensus".into(),
                version: "0.0.0".into(),
                commit: None,
            },
            "2026-01-02T03:04:05Z".into(),
            Host {
                hostname: "web-1".into(),
                os: "linux".into(),
                os_version: "Debian GNU/Linux 13".into(),
                architecture: "x86_64".into(),
                in_container: false,
            },
            Scan {
                options: ScanOptions {
                    scan_paths: vec!["/var/log".into()],
                    extensions: vec!["log".into()],
                    max_age_days: 7,
                    exclude_patterns: 0,
                    process_args: false,
                    all_label_values: false,
                },
                privileged: false,
                scanners: BTreeMap::new(),
                duration_ms: 1,
            },
            inventory,
        )
        .unwrap()
    }

    fn package(name: &str) -> Package {
        Package {
            name: name.into(),
            version: "1.0".into(),
            manager: "apt".into(),
        }
    }

    #[test]
    fn a_sealed_bundle_is_intact_and_has_no_marks() {
        let bundle = sealed(Inventory::default());
        assert!(bundle.inventory_is_intact().unwrap());
        assert!(bundle.coverage.marks.is_empty());
        assert_eq!(bundle.format, FORMAT);
    }

    #[test]
    fn editing_the_inventory_breaks_the_fingerprint() {
        let mut bundle = sealed(Inventory {
            installed_packages: vec![package("nginx")],
            ..Inventory::default()
        });
        bundle.inventory.installed_packages[0].version = "9.9".into();
        assert!(!bundle.inventory_is_intact().unwrap());
    }

    #[test]
    fn marking_coverage_leaves_the_fingerprint_alone() {
        let mut bundle = sealed(Inventory::default());
        bundle.coverage.marks.push(Mark {
            source: SourceRef {
                kind: SourceKind::LogFile,
                identifier: "/var/log/nginx/access.log".into(),
            },
            collected: Collected::Yes,
            collector: Some("fluent-bit".into()),
            destination: None,
            evidence: None,
            noted_by: NotedBy::Human,
            noted_at: "2026-01-02T03:04:05Z".into(),
        });
        assert!(bundle.inventory_is_intact().unwrap());
    }

    #[test]
    fn sealing_orders_the_inventory() {
        let ordered = sealed(Inventory {
            installed_packages: vec![package("zsh"), package("bash")],
            ..Inventory::default()
        });
        let names: Vec<_> = ordered
            .inventory
            .installed_packages
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["bash", "zsh"]);
    }

    #[test]
    fn a_bundle_survives_a_round_trip_through_json() {
        let bundle = sealed(Inventory {
            installed_packages: vec![package("nginx")],
            ..Inventory::default()
        });
        assert_eq!(
            Bundle::from_json(&bundle.to_json().unwrap()).unwrap(),
            bundle
        );
    }

    #[test]
    fn another_format_version_is_refused() {
        let mut bundle = sealed(Inventory::default());
        bundle.format = "hostcensus.bundle/2".into();
        let error = Bundle::from_json(&bundle.to_json().unwrap()).unwrap_err();
        assert!(error.to_string().contains("unsupported bundle format"));
    }
}
