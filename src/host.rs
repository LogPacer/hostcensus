//! Facts about the host the census is taken on.

use crate::bundle::Host;

pub fn describe() -> Host {
    Host {
        hostname: gethostname::gethostname().to_string_lossy().into_owned(),
        os: std::env::consts::OS.to_string(),
        os_version: os_version(),
        architecture: std::env::consts::ARCH.to_string(),
        in_container: in_container(),
    }
}

/// Whether the census runs as root. It never raises its own privileges; this
/// only records what it was given.
#[cfg(unix)]
pub fn privileged() -> bool {
    rustix::process::geteuid().is_root()
}

/// Whether the census runs elevated. `whoami /groups` lists the groups of
/// the process token with their identifiers, and the identifiers are the same
/// in every language.
#[cfg(windows)]
pub fn privileged() -> bool {
    output_within_limit("whoami", &["/groups"]).is_some_and(|groups| token_is_elevated(&groups))
}

/// An elevated token carries a mandatory integrity level of high or above:
/// `S-1-16-12288` for an elevated administrator, `S-1-16-16384` for the
/// system account. An ordinary token carries `S-1-16-8192`.
#[cfg(any(windows, test))]
fn token_is_elevated(whoami_groups: &str) -> bool {
    const HIGH: u32 = 12288;
    whoami_groups
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("S-1-16-"))
        .filter_map(|level| level.parse::<u32>().ok())
        .any(|level| level >= HIGH)
}

/// Standard output of a command that succeeds within ten seconds.
#[cfg(windows)]
fn output_within_limit(program: &str, args: &[&str]) -> Option<String> {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(command.output());
    });
    let output = receiver.recv_timeout(Duration::from_secs(10)).ok()?.ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The edition and the build, as Windows records them in its registry.
#[cfg(windows)]
fn os_version() -> String {
    windows_version(
        sysinfo::System::long_os_version().ok(),
        sysinfo::System::kernel_version().ok(),
    )
}

#[cfg(any(windows, test))]
fn windows_version(edition: Option<String>, build: Option<String>) -> String {
    let edition = edition.filter(|edition| !edition.trim().is_empty());
    let build = build.filter(|build| !build.trim().is_empty());
    match (edition, build) {
        (Some(edition), Some(build)) => format!("{} (build {})", edition.trim(), build.trim()),
        (Some(edition), None) => edition.trim().to_string(),
        (None, Some(build)) => format!("Windows (build {})", build.trim()),
        (None, None) => "unknown".to_string(),
    }
}

#[cfg(not(windows))]
fn os_version() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release")
        && let Some(name) = pretty_name(&content)
    {
        return name;
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            return format!("macOS {version}");
        }
    }

    "unknown".to_string()
}

#[cfg(any(not(windows), test))]
fn pretty_name(os_release: &str) -> Option<String> {
    os_release
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|name| name.trim_matches('"').to_string())
}

fn in_container() -> bool {
    use std::path::Path;

    Path::new("/.dockerenv").exists()
        || Path::new("/var/run/secrets/kubernetes.io").exists()
        || std::fs::read_to_string("/proc/1/cgroup").is_ok_and(|cgroup| {
            ["docker", "containerd", "kubepods"]
                .iter()
                .any(|runtime| cgroup.contains(runtime))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pretty_name_is_read_without_its_quotes() {
        let os_release =
            "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n";
        assert_eq!(
            pretty_name(os_release).as_deref(),
            Some("Debian GNU/Linux 13 (trixie)")
        );
    }

    #[test]
    fn a_release_file_without_a_pretty_name_gives_nothing() {
        assert_eq!(pretty_name("ID=alpine\n"), None);
    }

    /// `whoami /groups` on an English Windows, shortened. The account and
    /// group names are invented.
    const ELEVATED: &str = "\r
GROUP INFORMATION\r
-----------------\r
\r
Group Name                             Type             SID          Attributes\r
====================================== ================ ============ ===============================================================\r
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group\r
BUILTIN\\Administrators                 Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner\r
BUILTIN\\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group\r
Mandatory Label\\High Mandatory Level   Label            S-1-16-12288\r
";

    /// The same account without elevation, as a German Windows prints it:
    /// other headings and names, the same identifiers.
    const NOT_ELEVATED: &str = "\r
GRUPPENINFORMATIONEN\r
--------------------\r
\r
Gruppenname                                Typ             SID          Attribute\r
========================================== =============== ============ ==================================================\r
Jeder                                      Bekannte Gruppe S-1-1-0      Verbindliche Gruppe, Standardm\u{e4}\u{df}ig aktiviert\r
VORDEFINIERT\\Administratoren               Alias           S-1-5-32-544 Gruppe, die nur zum Ablehnen verwendet wird\r
VORDEFINIERT\\Benutzer                      Alias           S-1-5-32-545 Verbindliche Gruppe, Standardm\u{e4}\u{df}ig aktiviert\r
Verbindliche Beschriftung\\Mittlere Verbindlichkeitsstufe Bezeichnung S-1-16-8192\r
";

    #[test]
    fn a_token_is_elevated_when_its_integrity_level_is_high_or_above() {
        assert!(token_is_elevated(ELEVATED));
        assert!(!token_is_elevated(NOT_ELEVATED));
        assert!(token_is_elevated("NT AUTHORITY\\SYSTEM Label S-1-16-16384"));
        assert!(!token_is_elevated("Mandatory Label Label S-1-16-8448"));
        assert!(!token_is_elevated(""));
    }

    #[test]
    fn membership_of_the_administrators_group_alone_is_not_elevation() {
        // S-1-5-32-544 is in both listings; only the integrity level differs.
        assert!(NOT_ELEVATED.contains("S-1-5-32-544"));
        assert!(!token_is_elevated(NOT_ELEVATED));
    }

    #[test]
    fn a_windows_version_names_the_edition_and_the_build() {
        assert_eq!(
            windows_version(
                Some("Windows Server 2022 Standard".into()),
                Some("20348".into())
            ),
            "Windows Server 2022 Standard (build 20348)"
        );
        assert_eq!(
            windows_version(Some("Windows 11 Pro".into()), None),
            "Windows 11 Pro"
        );
        assert_eq!(
            windows_version(None, Some("26100".into())),
            "Windows (build 26100)"
        );
        assert_eq!(windows_version(Some("  ".into()), None), "unknown");
    }

    #[test]
    fn this_host_has_a_name_and_an_operating_system() {
        let host = describe();
        assert!(!host.hostname.is_empty());
        assert!(!host.os.is_empty());
        assert!(!host.architecture.is_empty());
    }
}
