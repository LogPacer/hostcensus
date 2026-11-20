//! Installed packages: dpkg or rpm on Linux, Homebrew on macOS.

use super::Scanned;
#[cfg(target_os = "linux")]
use super::command;
#[cfg(target_os = "linux")]
use crate::bundle::ScannerReport;
use crate::inventory::Package;

#[cfg(target_os = "linux")]
const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";

#[cfg(target_os = "linux")]
pub(crate) async fn scan() -> Scanned<Vec<Package>> {
    match std::fs::read_to_string(DPKG_STATUS_PATH) {
        Ok(status) => return Scanned::complete(parse_dpkg_status(&status)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Scanned::new(
                Vec::new(),
                ScannerReport::unavailable(format!(
                    "{DPKG_STATUS_PATH} could not be read: {}",
                    error.kind()
                )),
            );
        }
    }

    match command::stdout_of("rpm", &["-qa", "--queryformat", "%{NAME}|%{VERSION}\n"]).await {
        Ok(listing) => Scanned::complete(parse_rpm_listing(&listing)),
        Err(command::CommandError {
            failure: command::Failure::NotInstalled,
            ..
        }) => Scanned::new(
            Vec::new(),
            ScannerReport::unavailable("neither dpkg nor rpm manages packages on this host"),
        ),
        Err(error) => Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string())),
    }
}

#[cfg(target_os = "macos")]
pub(crate) async fn scan() -> Scanned<Vec<Package>> {
    // Without a Cellar there is no Homebrew, and so nothing to list.
    let packages = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
        .iter()
        .find(|cellar| std::path::Path::new(cellar).is_dir())
        .map(|cellar| read_brew_cellar(std::path::Path::new(cellar)))
        .unwrap_or_default();
    Scanned::complete(packages)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn scan() -> Scanned<Vec<Package>> {
    Scanned::complete(Vec::new())
}

/// The dpkg status file holds one record per package, separated by blank
/// lines. A package counts when it is wanted (`install` or `hold`) and its
/// state is `installed`:
///
/// ```text
/// Package: nginx
/// Status: install ok installed
/// Version: 1.18.0-6ubuntu2
/// ```
#[cfg(any(target_os = "linux", test))]
fn parse_dpkg_status(content: &str) -> Vec<Package> {
    let mut packages = Vec::new();

    for record in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut status = None;

        for line in record.lines() {
            if let Some(val) = line.strip_prefix("Package: ") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version: ") {
                version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Status: ") {
                status = Some(val.trim().to_string());
            }
        }

        if let (Some(name), Some(version), Some(status)) = (name, version, status) {
            let status_parts: Vec<&str> = status.split_whitespace().collect();
            let is_installed = status_parts.last().is_some_and(|s| *s == "installed");
            let is_wanted = status_parts
                .first()
                .is_some_and(|s| *s == "install" || *s == "hold");
            if is_installed && is_wanted {
                packages.push(Package {
                    name,
                    version,
                    manager: "apt".to_string(),
                });
            }
        }
    }

    packages
}

/// Lines of `rpm -qa --queryformat '%{NAME}|%{VERSION}\n'`.
#[cfg(any(target_os = "linux", test))]
fn parse_rpm_listing(listing: &str) -> Vec<Package> {
    listing
        .lines()
        .filter_map(|line| {
            let (name, version) = line.split_once('|')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some(Package {
                name: name.to_string(),
                version: version.trim().to_string(),
                manager: "yum".to_string(),
            })
        })
        .collect()
}

/// A Homebrew Cellar has one directory per package, holding one directory per
/// installed version. The highest version name is reported.
#[cfg(any(target_os = "macos", test))]
fn read_brew_cellar(cellar: &std::path::Path) -> Vec<Package> {
    let Ok(entries) = std::fs::read_dir(cellar) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let version = std::fs::read_dir(entry.path())
                .ok()?
                .flatten()
                .filter(|version| version.path().is_dir())
                .map(|version| version.file_name().to_string_lossy().into_owned())
                .max()
                .unwrap_or_default();
            Some(Package {
                name: entry.file_name().to_string_lossy().into_owned(),
                version,
                manager: "brew".to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DPKG_STATUS: &str = r#"Package: nginx
Status: install ok installed
Priority: optional
Section: httpd
Installed-Size: 1234
Version: 1.18.0-6ubuntu2
Description: high-performance web server

Package: libssl3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 5678
Version: 3.0.2-0ubuntu1
Description: Secure Sockets Layer toolkit

Package: old-removed-pkg
Status: deinstall ok config-files
Priority: optional
Section: misc
Version: 0.1.0-1
Description: a package that was removed

Package: not-installed
Status: purge ok not-installed
Priority: optional
Section: misc
Version: 2.0.0
Description: never fully installed
"#;

    #[test]
    fn parse_dpkg_installed_packages() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert_eq!(packages.len(), 2);

        assert_eq!(packages[0].name, "nginx");
        assert_eq!(packages[0].version, "1.18.0-6ubuntu2");
        assert_eq!(packages[0].manager, "apt");

        assert_eq!(packages[1].name, "libssl3");
        assert_eq!(packages[1].version, "3.0.2-0ubuntu1");
    }

    #[test]
    fn parse_dpkg_excludes_deinstalled() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert!(!packages.iter().any(|p| p.name == "old-removed-pkg"));
    }

    #[test]
    fn parse_dpkg_excludes_not_installed() {
        let packages = parse_dpkg_status(SAMPLE_DPKG_STATUS);
        assert!(!packages.iter().any(|p| p.name == "not-installed"));
    }

    #[test]
    fn parse_dpkg_empty_input() {
        assert!(parse_dpkg_status("").is_empty());
    }

    #[test]
    fn rpm_lines_split_into_name_and_version() {
        let packages = parse_rpm_listing("bash|5.2.26\nopenssl-libs|3.2.2\n|orphan\nnoversion\n");

        assert_eq!(
            packages,
            [
                Package {
                    name: "bash".into(),
                    version: "5.2.26".into(),
                    manager: "yum".into()
                },
                Package {
                    name: "openssl-libs".into(),
                    version: "3.2.2".into(),
                    manager: "yum".into()
                },
            ]
        );
    }

    #[test]
    fn a_cellar_lists_each_package_with_its_highest_version() {
        let cellar = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cellar.path().join("git/2.43.0")).unwrap();
        std::fs::create_dir_all(cellar.path().join("git/2.44.1")).unwrap();
        std::fs::create_dir_all(cellar.path().join("openssl@3/3.2.0")).unwrap();
        std::fs::write(cellar.path().join("stray-file"), "").unwrap();

        let mut packages = read_brew_cellar(cellar.path());
        packages.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(packages.len(), 2);
        assert_eq!(
            (packages[0].name.as_str(), packages[0].version.as_str()),
            ("git", "2.44.1")
        );
        assert_eq!(packages[1].name, "openssl@3");
        assert!(packages.iter().all(|p| p.manager == "brew"));
    }
}
