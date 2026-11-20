//! What a census observes on a host.
//!
//! Every list is always present in a bundle, empty when nothing was found or
//! the scanner does not apply to the operating system.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bundle::SourceKind;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub log_files: Vec<LogFile>,
    pub containers: Vec<Container>,
    pub systemd_services: Vec<SystemdService>,
    pub windows_services: Vec<WindowsService>,
    pub event_log_channels: Vec<EventLogChannel>,
    pub processes: Vec<Process>,
    pub listening_ports: Vec<ListeningPort>,
    pub installed_packages: Vec<Package>,
}

impl Inventory {
    /// The identifiers of every source of one kind, as coverage marks name
    /// them.
    pub fn identifiers(&self, kind: SourceKind) -> Vec<&str> {
        match kind {
            SourceKind::LogFile => self.log_files.iter().map(|f| f.path.as_str()).collect(),
            SourceKind::Container => self
                .containers
                .iter()
                .map(|c| c.stable_identifier.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            SourceKind::SystemdService => self
                .systemd_services
                .iter()
                .map(|s| s.name.as_str())
                .collect(),
            SourceKind::WindowsService => self
                .windows_services
                .iter()
                .map(|s| s.name.as_str())
                .collect(),
            SourceKind::EventLogChannel => self
                .event_log_channels
                .iter()
                .map(|c| c.channel.as_str())
                .collect(),
        }
    }

    /// Orders every list by its identity so two censuses of an unchanged host
    /// produce the same bundle.
    pub fn sort(&mut self) {
        self.log_files.sort_by(|a, b| a.path.cmp(&b.path));
        self.containers.sort_by(|a, b| {
            (&a.stable_identifier, &a.stable_instance_id, &a.id).cmp(&(
                &b.stable_identifier,
                &b.stable_instance_id,
                &b.id,
            ))
        });
        self.systemd_services.sort_by(|a, b| a.name.cmp(&b.name));
        self.windows_services.sort_by(|a, b| a.name.cmp(&b.name));
        self.event_log_channels
            .sort_by(|a, b| a.channel.cmp(&b.channel));
        self.processes
            .sort_by(|a, b| (a.pid, &a.command).cmp(&(b.pid, &b.command)));
        self.listening_ports.sort_by(|a, b| {
            (a.port, &a.protocol, a.pid, &a.process).cmp(&(b.port, &b.protocol, b.pid, &b.process))
        });
        self.installed_packages.sort_by(|a, b| {
            (&a.manager, &a.name, &a.version).cmp(&(&b.manager, &b.name, &b.version))
        });
    }
}

/// A log file, described from directory metadata only. Its content is never
/// read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFile {
    pub path: String,
    pub size: u64,
    /// Last modification time, RFC 3339 in UTC.
    pub modified: String,
    /// Octal mode on Unix (`100640`), `readonly` or `readwrite` on Windows.
    pub permissions: String,
    /// How the file is framed, judged from where it lives: `file`,
    /// `docker-json` or `k8s-cri`.
    pub source_format: String,
    /// Earlier parts of this file that log rotation set aside, such as
    /// `app.log.1` and `app.log.2.gz`. They are the same source, not sources
    /// of their own.
    pub rotated_copies: Vec<RotatedCopy>,
    /// The processes that hold the file open for writing, by pid: the ones
    /// that write to it. Read on Linux, and for other users' processes only
    /// as root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_in: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedCopy {
    pub path: String,
    /// Size on disk, which for a compressed copy is the compressed size.
    pub size: u64,
    pub modified: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    /// Short runtime id.
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    /// `docker`, `containerd` or `cri-o`.
    pub runtime: String,
    pub service_name: String,
    /// True only when the service name was set on purpose through the
    /// `LOGPACER_SERVICE_NAME` variable or the `logpacer.com/service-name`
    /// label, not derived from a compose or workload name.
    pub service_name_explicit: bool,
    /// Identity of the workload this container belongs to. Stable across
    /// restarts and redeploys.
    pub stable_identifier: String,
    /// Identity of this one instance of the workload.
    pub stable_instance_id: String,
    /// The facts the two identities were derived from.
    pub identifiers: BTreeMap<String, String>,
    /// Labels whose values are kept. See `label_keys_withheld`.
    pub labels: BTreeMap<String, String>,
    /// Keys of labels that exist on the container but whose values were left
    /// out, because label values can carry secrets.
    pub label_keys_withheld: Vec<String>,
    /// Environment variables of a running container whose values are kept:
    /// versions, the deployment environment, log and telemetry settings. See
    /// `env_names_withheld`.
    pub env: BTreeMap<String, String>,
    /// Names of the variables that exist in the container but whose values
    /// were left out, because a value can be a secret whatever its variable
    /// is called.
    pub env_names_withheld: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub log_path: String,
    /// The logging driver of a running container. `none` means its output is
    /// thrown away.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub log_driver: String,
    /// The size of the container's log, where it can be read. Zero means the
    /// container has written nothing since the log was started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_size: Option<u64>,
    /// When the container's log was last written to, RFC 3339 in UTC.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub log_modified: String,
    /// Full runtime id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod_uid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deployment: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workload_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdService {
    pub name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
    /// How many entries the service wrote to the journal in the 24 hours
    /// before the census. Zero means it wrote none. Absent where the journal
    /// could not be read for every service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_entries_24h: Option<u64>,
    /// When the service last wrote to the journal within those 24 hours,
    /// RFC 3339 in UTC.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_journal_entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsService {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub service_type: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLogChannel {
    pub channel: String,
    pub record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    /// Numeric uid on Linux, user name on macOS, SID on Windows.
    pub user: String,
    /// The executable. The full command line only when the census was taken
    /// with `--process-args`.
    pub command: String,
    /// What an interpreter or language runtime is running: a script, a jar,
    /// a module or a class. Picked out of the command line; no other
    /// argument is recorded.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub program: String,
    /// The working directory, where it could be read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    /// The systemd unit the process belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
    /// The full runtime id of the container the process runs in, which is
    /// `container_id` of an entry in `containers`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container_id: String,
    /// Where standard output goes: `null`, `file`, `pipe`, `socket`,
    /// `terminal` or `other`. `null` means it is thrown away.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    /// Where standard error goes, with the same values.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    /// Empty when the owning process could not be seen without more
    /// privileges.
    pub process: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `apt`, `yum` or `brew`.
    pub manager: String,
}
