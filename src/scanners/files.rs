//! Log files, found by walking the scan paths and described from directory
//! metadata only. No log file is ever opened.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::exclude_paths::ExcludePaths;
use super::processes::HeldOpen;
use crate::bundle::ScannerReport;
use crate::inventory::{LogFile, RotatedCopy};

/// Where the kubelet keeps pod logs.
pub(crate) const POD_LOGS_DIR: &str = "/var/log/pods";

const SOURCE_FORMAT_FILE: &str = "file";
const SOURCE_FORMAT_DOCKER_JSON: &str = "docker-json";
const SOURCE_FORMAT_K8S_CRI: &str = "k8s-cri";

pub(crate) struct Walk<'a> {
    pub scan_paths: &'a [String],
    pub extensions: &'a [String],
    pub max_age_days: u64,
    pub exclude: &'a ExcludePaths,
    /// Paths a container runtime already accounts for. Their files are listed
    /// with the container, not here.
    pub runtime_owned: &'a [PathBuf],
    /// Where a container runtime may keep the layers of its images. A
    /// directory among them is not read, and the report names it.
    pub layer_stores: &'a [PathBuf],
    /// Walked in addition to the scan paths unless one of them contains it.
    pub also_walk: &'a [PathBuf],
}

#[derive(Debug, Default)]
pub(crate) struct Found {
    pub files: Vec<LogFile>,
    unreadable_directories: usize,
    missing_scan_paths: Vec<String>,
    layer_stores_left_alone: Vec<String>,
}

impl Found {
    pub fn report(&self) -> ScannerReport {
        let mut gaps = Vec::new();
        match self.unreadable_directories {
            0 => {}
            1 => gaps.push("1 directory could not be read".to_string()),
            count => gaps.push(format!("{count} directories could not be read")),
        }
        if !self.missing_scan_paths.is_empty() {
            gaps.push(format!(
                "scan path does not exist: {}",
                self.missing_scan_paths.join(", ")
            ));
        }
        if !self.layer_stores_left_alone.is_empty() {
            let mut stores = self.layer_stores_left_alone.clone();
            stores.sort();
            stores.dedup();
            gaps.push(format!(
                "not searched, because a container runtime keeps image layers there: {}",
                stores.join(", ")
            ));
        }
        if gaps.is_empty() {
            ScannerReport::complete()
        } else {
            ScannerReport::partial(gaps.join("; "))
        }
    }
}

/// Says how far a walk has come once it has gone on for a while, so that a
/// census of a large tree is not silent. A walk that ends sooner says nothing.
pub(crate) struct Progress<'a> {
    pause: Duration,
    last_said: Instant,
    under: String,
    directories: u64,
    say: Box<dyn FnMut(String) + 'a>,
}

impl<'a> Progress<'a> {
    /// Long enough that most walks end before the first line, and short
    /// enough that a person does not take a long one for a hang.
    const PAUSE: Duration = Duration::from_secs(5);

    pub fn on_standard_error() -> Self {
        Self::every(Self::PAUSE, |line| eprintln!("{line}"))
    }

    fn every(pause: Duration, say: impl FnMut(String) + 'a) -> Self {
        Self {
            pause,
            last_said: Instant::now(),
            under: String::new(),
            directories: 0,
            say: Box::new(say),
        }
    }

    fn starts_under(&mut self, root: &Path) {
        self.under = root.display().to_string();
        self.directories = 0;
    }

    fn has_read_a_directory(&mut self) {
        self.directories += 1;
        if self.last_said.elapsed() < self.pause {
            return;
        }
        let read = match self.directories {
            1 => "1 directory".to_string(),
            count => format!("{count} directories"),
        };
        (self.say)(format!(
            "Looking for log files under {}: {read} read so far.",
            self.under
        ));
        self.last_said = Instant::now();
    }
}

pub(crate) fn walk(plan: &Walk<'_>, progress: &mut Progress<'_>) -> Found {
    let mut found = Found::default();
    let runtime_owned = resolved(plan.runtime_owned);
    let layer_stores = existing(plan.layer_stores);
    let stale_before = stale_cutoff(plan.max_age_days, SystemTime::now());

    for scan_path in plan.scan_paths {
        let base = Path::new(scan_path);
        if !base.exists() {
            found.missing_scan_paths.push(scan_path.clone());
            continue;
        }
        progress.starts_under(base);
        let owned = RuntimeOwned::seen_from(base, &runtime_owned, &layer_stores);
        walk_directory(base, plan, &owned, stale_before, &mut found, progress);
    }

    for extra in plan.also_walk {
        let already_walked = plan
            .scan_paths
            .iter()
            .any(|scan_path| extra.starts_with(scan_path));
        if !already_walked && extra.exists() {
            progress.starts_under(extra);
            let owned = RuntimeOwned::seen_from(extra, &runtime_owned, &layer_stores);
            walk_directory(extra, plan, &owned, stale_before, &mut found, progress);
        }
    }

    found.files = with_rotated_copies_folded(std::mem::take(&mut found.files));
    found
}

/// Says which processes write to each log file, and lists the files that
/// were found only because a process writes to them: a regular file held
/// open for appending is a log wherever it lies and whatever it is called.
/// The same exclusions apply as to the walk.
pub(crate) fn note_files_held_open(
    files: &mut Vec<LogFile>,
    held_open: &[HeldOpen],
    extensions: &[String],
    exclude: &ExcludePaths,
    runtime_owned: &[PathBuf],
) {
    let runtime_owned = resolved(runtime_owned);
    for held in held_open {
        let path = held.path.to_string_lossy();
        if exclude.is_excluded(&held.path) || belongs_to(&held.path, &runtime_owned) {
            continue;
        }
        if let Some(file) = files.iter_mut().find(|file| file.path == path) {
            file.open_in.push(held.pid);
            continue;
        }
        if !(held.appending || is_log_file(&held.path, extensions)) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(&held.path) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        files.push(LogFile {
            path: path.into_owned(),
            size: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .map(super::rfc3339)
                .unwrap_or_default(),
            permissions: permissions_string(&metadata),
            source_format: source_format(&held.path).to_string(),
            rotated_copies: Vec::new(),
            open_in: vec![held.pid],
        });
    }
    for file in files {
        file.open_in.sort_unstable();
        file.open_in.dedup();
    }
}

/// Lists every rotated copy under the file it was rotated from, so that a
/// log file and its copies are one source. A copy whose file is not in the
/// census stays an entry of its own.
fn with_rotated_copies_folded(files: Vec<LogFile>) -> Vec<LogFile> {
    let (mut sources, copies): (Vec<LogFile>, Vec<LogFile>) = files
        .into_iter()
        .partition(|file| written_to_path(&file.path) == file.path);

    for copy in copies {
        let written_to = written_to_path(&copy.path);
        match sources.iter_mut().find(|file| file.path == written_to) {
            Some(source) => source.rotated_copies.push(RotatedCopy {
                path: copy.path,
                size: copy.size,
                modified: copy.modified,
            }),
            None => sources.push(copy),
        }
    }
    for source in &mut sources {
        source.rotated_copies.sort_by(|a, b| a.path.cmp(&b.path));
    }
    sources
}

/// The path a file had while it was being written to: its own path, unless
/// its name carries a rotation suffix (`app.log.1`) or a rotation number
/// before its extension (`app.1.log`).
fn written_to_path(path: &str) -> String {
    let name_starts = path.rfind(['/', '\\']).map_or(0, |separator| separator + 1);
    let (directory, name) = path.split_at(name_starts);

    let without_suffix = without_rotation_suffix(name);
    if without_suffix != name {
        return format!("{directory}{without_suffix}");
    }
    if let Some((stem, extension)) = name.rsplit_once('.')
        && let Some((base, number)) = stem.rsplit_once('.')
        && !base.is_empty()
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
    {
        return format!("{directory}{base}.{extension}");
    }
    path.to_string()
}

fn walk_directory(
    dir: &Path,
    plan: &Walk<'_>,
    runtime_owned: &RuntimeOwned<'_>,
    stale_before: Option<SystemTime>,
    found: &mut Found,
    progress: &mut Progress<'_>,
) {
    if runtime_owned.owns(dir) {
        return;
    }
    if runtime_owned.keeps_image_layers_in(dir) {
        found
            .layer_stores_left_alone
            .push(dir.display().to_string());
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            found.unreadable_directories += 1;
            return;
        }
    };
    progress.has_read_a_directory();

    for entry in entries.flatten() {
        let path = entry.path();
        // `DirEntry::metadata` does not follow symbolic links, so a link is
        // neither a directory nor a file here and is passed over.
        let Ok(metadata) = entry.metadata() else {
            continue;
        };

        if metadata.is_dir() {
            walk_directory(&path, plan, runtime_owned, stale_before, found, progress);
        } else if metadata.is_file()
            && is_log_file(&path, plan.extensions)
            && !plan.exclude.is_excluded(&path)
            && !runtime_owned.owns(&path)
        {
            let modified = metadata.modified().ok();
            if is_stale(modified, stale_before) {
                continue;
            }
            found.files.push(LogFile {
                path: path.to_string_lossy().into_owned(),
                size: metadata.len(),
                modified: modified.map(super::rfc3339).unwrap_or_default(),
                permissions: permissions_string(&metadata),
                source_format: source_format(&path).to_string(),
                rotated_copies: Vec::new(),
                open_in: Vec::new(),
            });
        }
    }
}

/// How a file is framed, judged from where it lives and never from what is
/// in it.
fn source_format(path: &Path) -> &'static str {
    if is_docker_json_log_path(path) {
        SOURCE_FORMAT_DOCKER_JSON
    } else if path.starts_with(POD_LOGS_DIR) {
        SOURCE_FORMAT_K8S_CRI
    } else {
        SOURCE_FORMAT_FILE
    }
}

fn resolved(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
        .collect()
}

/// The paths among `paths` that exist on this host, resolved. A host has
/// few of the places a layer store can be, and most hosts have none, so the
/// walk compares each directory with few paths or with none.
fn existing(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect()
}

/// The paths a container runtime owns, seen from one scan path.
///
/// Those paths are resolved, so a path under the scan path is compared in
/// its resolved form too. The walk follows no link below the scan path, so
/// the scan path is resolved once and the rest of each path is kept as the
/// walk found it. The file system is not asked again for every directory.
struct RuntimeOwned<'a> {
    roots: &'a [PathBuf],
    layer_stores: &'a [PathBuf],
    scan_path: &'a Path,
    resolved_scan_path: PathBuf,
}

impl<'a> RuntimeOwned<'a> {
    fn seen_from(scan_path: &'a Path, roots: &'a [PathBuf], layer_stores: &'a [PathBuf]) -> Self {
        Self {
            roots,
            layer_stores,
            scan_path,
            resolved_scan_path: std::fs::canonicalize(scan_path)
                .unwrap_or_else(|_| scan_path.to_path_buf()),
        }
    }

    /// Whether the walk leaves `path`, which lies under the scan path, to
    /// the runtime because the containers it lists account for it.
    fn owns(&self, path: &Path) -> bool {
        self.lies_under(path, self.roots)
    }

    /// Whether `directory`, which lies under the scan path, is where a
    /// runtime keeps the layers of its images.
    fn keeps_image_layers_in(&self, directory: &Path) -> bool {
        self.lies_under(directory, self.layer_stores)
    }

    fn lies_under(&self, path: &Path, roots: &[PathBuf]) -> bool {
        if roots.is_empty() {
            return false;
        }
        let resolved = path
            .strip_prefix(self.scan_path)
            .map(|below| self.resolved_scan_path.join(below));
        roots.iter().any(|root| {
            path.starts_with(root)
                || resolved
                    .as_ref()
                    .is_ok_and(|resolved| resolved.starts_with(root))
        })
    }
}

/// Whether a path that did not come from the walk lies under one of `roots`.
/// Such a path may hold a link anywhere, so the file system resolves it.
fn belongs_to(path: &Path, roots: &[PathBuf]) -> bool {
    if roots.is_empty() {
        return false;
    }
    roots.iter().any(|root| path.starts_with(root))
        || std::fs::canonicalize(path)
            .ok()
            .is_some_and(|path| roots.iter().any(|root| path.starts_with(root)))
}

/// `<container id>/<container id>-json.log`, the layout of the Docker
/// json-file log driver.
fn is_docker_json_log_path(path: &Path) -> bool {
    let Some(container_id) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
    else {
        return false;
    };
    container_id.len() == 64
        && container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix("-json.log"))
            == Some(container_id)
}

/// The names syslog daemons and distributions give system logs that carry no
/// extension: `/var/log/syslog` on Debian, `/var/log/messages` and
/// `/var/log/secure` on Red Hat, and the per-facility files next to them.
const SYSTEM_LOG_NAMES: &[&str] = &[
    "auth", "boot", "cron", "daemon", "debug", "dmesg", "kern", "mail", "maillog", "messages",
    "secure", "spooler", "syslog", "user",
];

/// Whether a file is a log file, judged from its name alone:
///
/// - its extension is an allowed one (`app.log`),
/// - its name ends in `_log`, as web servers on Red Hat name theirs
///   (`access_log`),
/// - it is a system log without an extension (`syslog`, `messages`, `secure`)
///   or a per-severity mail log (`mail.err`),
/// - or it is a rotated copy of any of these (`app.log.1`, `syslog.2.gz`,
///   `messages-20260102`).
fn is_log_file(path: &Path, allowed: &[String]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| named_like_a_log(name, allowed, cfg!(windows)))
}

/// On Windows only the extension counts, compared without regard to case as
/// Windows file names are. The names without an extension are Unix
/// conventions: a file called `user` or `debug` under `C:\ProgramData` is not
/// a system log.
fn named_like_a_log(name: &str, allowed: &[String], on_windows: bool) -> bool {
    let name = without_rotation_suffix(name);

    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            if on_windows {
                allowed.iter().any(|a| a.eq_ignore_ascii_case(ext))
            } else {
                allowed.iter().any(|a| a == ext)
                    || (stem == "mail" && matches!(ext, "info" | "warn" | "err"))
            }
        }
        _ => !on_windows && (name.ends_with("_log") || SYSTEM_LOG_NAMES.contains(&name)),
    }
}

/// The name a rotated copy had while it was being written to: without a
/// compression extension, and without the number or date logrotate appended.
fn without_rotation_suffix(name: &str) -> &str {
    let name = ["gz", "xz", "zst", "bz2"]
        .iter()
        .find_map(|compression| {
            name.strip_suffix(compression)
                .and_then(|rest| rest.strip_suffix('.'))
        })
        .unwrap_or(name);

    let all_digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if let Some((rest, number)) = name.rsplit_once('.')
        && !rest.is_empty()
        && all_digits(number)
    {
        return rest;
    }
    if let Some((rest, date)) = name.rsplit_once('-')
        && !rest.is_empty()
        && date.len() == 8
        && all_digits(date)
    {
        return rest;
    }
    name
}

fn stale_cutoff(max_age_days: u64, now: SystemTime) -> Option<SystemTime> {
    max_age_days
        .checked_mul(24 * 60 * 60)
        .and_then(|seconds| now.checked_sub(Duration::from_secs(seconds)))
}

fn is_stale(modified: Option<SystemTime>, cutoff: Option<SystemTime>) -> bool {
    matches!((modified, cutoff), (Some(modified), Some(cutoff)) if modified < cutoff)
}

#[cfg(unix)]
fn permissions_string(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;

    format!("{:o}", metadata.permissions().mode())
}

/// Windows has no mode bits. The read-only attribute is the one permission a
/// directory entry carries; access control lists are not read.
#[cfg(not(unix))]
fn permissions_string(metadata: &std::fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "readonly".to_string()
    } else {
        "readwrite".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn walk_of(dir: &Path) -> Found {
        walk_with(dir, &ExcludePaths::default(), &[], &[], 7)
    }

    fn walk_with(
        dir: &Path,
        exclude: &ExcludePaths,
        runtime_owned: &[PathBuf],
        also_walk: &[PathBuf],
        max_age_days: u64,
    ) -> Found {
        walk(
            &Walk {
                scan_paths: &[dir.to_string_lossy().into_owned()],
                extensions: &ext(&["log"]),
                max_age_days,
                exclude,
                runtime_owned,
                layer_stores: &[],
                also_walk,
            },
            &mut Progress::every(Duration::MAX, |_| {}),
        )
    }

    /// The files a walk of `dir` finds, and what it says on the way when it
    /// lets `pause` go by between two lines.
    fn walk_pausing(dir: &Path, pause: Duration) -> (Found, Vec<String>) {
        let mut said = Vec::new();
        let found = walk(
            &Walk {
                scan_paths: &[dir.to_string_lossy().into_owned()],
                extensions: &ext(&["log"]),
                max_age_days: 7,
                exclude: &ExcludePaths::default(),
                runtime_owned: &[],
                layer_stores: &[],
                also_walk: &[],
            },
            &mut Progress::every(pause, |line| said.push(line)),
        );
        (found, said)
    }

    /// The files a walk of `dir` finds when it leaves `layer_stores` alone,
    /// and how many directories it read.
    fn walk_around(dir: &Path, layer_stores: &[PathBuf]) -> (Found, usize) {
        let mut directories_read = 0;
        let found = walk(
            &Walk {
                scan_paths: &[dir.to_string_lossy().into_owned()],
                extensions: &ext(&["log"]),
                max_age_days: 7,
                exclude: &ExcludePaths::default(),
                runtime_owned: &[],
                layer_stores,
                also_walk: &[],
            },
            &mut Progress::every(Duration::ZERO, |_| directories_read += 1),
        );
        (found, directories_read)
    }

    fn not_searched(store: &Path) -> ScannerReport {
        ScannerReport::partial(format!(
            "not searched, because a container runtime keeps image layers there: {}",
            store.display()
        ))
    }

    fn names(found: &Found) -> Vec<String> {
        let mut names: Vec<String> = found
            .files
            .iter()
            .map(|file| {
                Path::new(&file.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn set_file_age(path: &Path, days: u64) {
        let modified = SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    #[test]
    fn detects_log_files() {
        let allowed = ext(&["log"]);
        assert!(is_log_file(Path::new("/var/log/syslog.log"), &allowed));
        assert!(is_log_file(Path::new("/var/log/app.log.gz"), &allowed));
        assert!(!is_log_file(Path::new("/var/log/data.csv"), &allowed));
    }

    #[test]
    fn system_logs_without_an_extension_are_log_files() {
        let allowed = ext(&["log"]);
        for path in [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/maillog",
            "/var/log/cron",
            "/var/log/mail.err",
            "/var/log/httpd/access_log",
            "/var/log/httpd/ssl_error_log",
        ] {
            assert!(is_log_file(Path::new(path), &allowed), "{path}");
        }
    }

    #[test]
    fn rotated_system_logs_are_log_files() {
        let allowed = ext(&["log"]);
        for path in [
            "/var/log/syslog.1",
            "/var/log/syslog.2.gz",
            "/var/log/messages-20260102",
            "/var/log/secure-20260102.gz",
            "/var/log/httpd/access_log.1",
            "/var/log/app.log.3.xz",
            "/var/log/app.log-20260102",
        ] {
            assert!(is_log_file(Path::new(path), &allowed), "{path}");
        }
    }

    #[test]
    fn other_files_in_a_log_directory_are_not_log_files() {
        let allowed = ext(&["log"]);
        for path in [
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/lastlog",
            "/var/log/faillog",
            "/var/log/README",
            "/var/log/journal/abc/system.journal",
            "/var/log/sa/sa12",
            "/var/log/.log",
            "/var/log/messages.txt",
            "/var/log/mail.cf",
            "/var/log/data-20260102",
        ] {
            assert!(!is_log_file(Path::new(path), &allowed), "{path}");
        }
    }

    #[test]
    fn on_windows_the_extension_decides_and_its_case_does_not_matter() {
        let allowed = ext(&["log"]);
        for name in [
            "app.log",
            "APP.LOG",
            "u_ex260102.log",
            "App.Log.1",
            "setupact.log.gz",
        ] {
            assert!(named_like_a_log(name, &allowed, true), "{name}");
        }
        for name in [
            "user",
            "debug",
            "messages",
            "access_log",
            "mail.err",
            "APP.TXT",
        ] {
            assert!(!named_like_a_log(name, &allowed, true), "{name}");
        }
    }

    #[test]
    fn elsewhere_the_case_of_an_extension_matters() {
        let allowed = ext(&["log"]);
        assert!(named_like_a_log("app.log", &allowed, false));
        assert!(!named_like_a_log("APP.LOG", &allowed, false));
    }

    #[test]
    fn default_allowlist_matches_log_only() {
        let allowed = ext(&["log"]);
        assert!(is_log_file(Path::new("/var/log/app.log"), &allowed));
        assert!(!is_log_file(Path::new("/var/log/app.txt"), &allowed));
    }

    #[test]
    fn txt_matches_when_opted_in() {
        let allowed = ext(&["log", "txt"]);
        assert!(is_log_file(Path::new("/var/log/app.txt"), &allowed));
        assert!(is_log_file(Path::new("/var/log/app.log"), &allowed));
    }

    #[test]
    fn rotated_logs_match_under_default_allowlist() {
        let allowed = ext(&["log"]);
        assert!(is_log_file(Path::new("/var/log/app.log.gz"), &allowed));
        assert!(is_log_file(Path::new("/var/log/app.log.1"), &allowed));
        assert!(!is_log_file(Path::new("/var/log/app.csv.1"), &allowed));
    }

    #[test]
    fn discovers_files_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.log"), "line1\nline2\n").unwrap();
        std::fs::write(dir.path().join("other.txt"), "not a log").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("nested.log"), "nested\n").unwrap();

        let found = walk_of(dir.path());

        assert_eq!(names(&found), ["app.log", "nested.log"]);
        assert_eq!(found.report(), ScannerReport::complete());
    }

    #[test]
    fn a_walk_that_goes_on_says_how_far_it_has_come() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("app/archive")).unwrap();
        std::fs::write(dir.path().join("app/app.log"), "line\n").unwrap();

        let (found, said) = walk_pausing(dir.path(), Duration::ZERO);

        let under = dir.path().display().to_string();
        assert_eq!(said.len(), 3, "{said:?}");
        for (line, read) in said
            .iter()
            .zip(["1 directory", "2 directories", "3 directories"])
        {
            assert!(line.contains(&under) && line.contains(read), "{line}");
        }
        assert_eq!(names(&found), ["app.log"]);
    }

    #[test]
    fn a_walk_that_ends_within_the_pause_says_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("app/archive")).unwrap();
        std::fs::write(dir.path().join("app/app.log"), "line\n").unwrap();

        let (found, said) = walk_pausing(dir.path(), Duration::from_secs(60 * 60));

        assert!(said.is_empty(), "{said:?}");
        assert_eq!(names(&found), ["app.log"]);
    }

    #[test]
    fn a_file_is_described_from_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, "twelve bytes").unwrap();

        let found = walk_of(dir.path());

        let file = &found.files[0];
        assert_eq!(file.path, path.to_string_lossy());
        assert_eq!(file.size, 12);
        assert_eq!(file.source_format, "file");
        if cfg!(unix) {
            assert!(file.permissions.starts_with("100"), "{}", file.permissions);
        } else {
            assert_eq!(file.permissions, "readwrite");
        }
        assert!(file.modified.ends_with('Z'), "{}", file.modified);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_nobody_may_read_is_still_listed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.log");
        std::fs::write(&path, "never read").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let found = walk_of(dir.path());

        assert_eq!(names(&found), ["secret.log"]);
        assert_eq!(found.files[0].permissions, "100000");
        assert_eq!(found.files[0].size, 10);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_read_makes_the_walk_partial() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.log"), "kept\n").unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("hidden.log"), "unseen\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&locked).is_err();

        let found = walk_of(dir.path());

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if unreadable {
            assert_eq!(names(&found), ["app.log"]);
            assert_eq!(
                found.report(),
                ScannerReport::partial("1 directory could not be read")
            );
        } else {
            // Root reads the directory regardless of its mode.
            assert_eq!(names(&found), ["app.log", "hidden.log"]);
            assert_eq!(found.report(), ScannerReport::complete());
        }
    }

    #[test]
    fn a_scan_path_that_does_not_exist_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");

        let found = walk_of(&missing);

        assert!(found.files.is_empty());
        assert_eq!(
            found.report(),
            ScannerReport::partial(format!("scan path does not exist: {}", missing.display()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("elsewhere.log"), "x\n").unwrap();
        std::fs::write(dir.path().join("real.log"), "x\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("elsewhere.log"),
            dir.path().join("linked.log"),
        )
        .unwrap();

        assert_eq!(names(&walk_of(dir.path())), ["real.log"]);
    }

    #[test]
    fn a_file_held_open_is_marked_and_one_found_only_that_way_is_listed() {
        let dir = tempfile::tempdir().unwrap();
        let found_by_name = dir.path().join("app.log");
        let odd_name = dir.path().join("production.out");
        let data_file = dir.path().join("state.db");
        let private = dir.path().join("payroll.out");
        let container_log = dir.path().join("containers/abc-json.log");
        std::fs::create_dir(dir.path().join("containers")).unwrap();
        for path in [
            &found_by_name,
            &odd_name,
            &data_file,
            &private,
            &container_log,
        ] {
            std::fs::write(path, "a line\n").unwrap();
        }
        let mut files = walk_with(
            dir.path(),
            &ExcludePaths::default(),
            &[dir.path().join("containers")],
            &[],
            7,
        )
        .files;
        assert_eq!(files.len(), 1);

        let held = |pid: u32, path: &Path, appending: bool| HeldOpen {
            pid,
            path: path.to_path_buf(),
            appending,
        };
        note_files_held_open(
            &mut files,
            &[
                held(20, &found_by_name, true),
                held(10, &found_by_name, true),
                held(20, &found_by_name, true),
                held(30, &odd_name, true),
                // Open for writing, but not appended to and not named like a log.
                held(40, &data_file, false),
                held(50, &private, true),
                held(60, &container_log, true),
                held(70, &dir.path().join("gone.out"), true),
            ],
            &ext(&["log"]),
            &ExcludePaths::new(["payroll.*".to_string()]),
            &[dir.path().join("containers")],
        );

        let mut listed: Vec<(String, Vec<u32>)> = files
            .iter()
            .map(|file| {
                (
                    file.path.rsplit('/').next().unwrap().to_string(),
                    file.open_in.clone(),
                )
            })
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            [
                ("app.log".to_string(), vec![10, 20]),
                ("production.out".to_string(), vec![30]),
            ]
        );
    }

    #[test]
    fn rotated_copies_are_listed_under_the_file_they_belong_to() {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in [
            ("app.log", "now\n"),
            ("app.log.1", "yesterday\n"),
            ("app.log.2.gz", "the day before\n"),
            ("app.log-20260102", "dated\n"),
            ("app.1.log", "numbered before the extension\n"),
            ("other.log", "unrelated\n"),
        ] {
            std::fs::write(dir.path().join(name), content).unwrap();
        }

        let found = walk_with(dir.path(), &ExcludePaths::default(), &[], &[], 7);

        assert_eq!(names(&found), ["app.log", "other.log"]);
        let app = found
            .files
            .iter()
            .find(|file| file.path.ends_with("app.log"))
            .unwrap();
        let copies: Vec<_> = app
            .rotated_copies
            .iter()
            .map(|copy| copy.path.rsplit('/').next().unwrap().to_string())
            .collect();
        assert_eq!(
            copies,
            ["app.1.log", "app.log-20260102", "app.log.1", "app.log.2.gz"]
        );
        assert_eq!(app.rotated_copies[2].size, "yesterday\n".len() as u64);
        assert!(!app.rotated_copies[2].modified.is_empty());

        let other = found
            .files
            .iter()
            .find(|file| file.path.ends_with("other.log"))
            .unwrap();
        assert!(other.rotated_copies.is_empty());
    }

    #[test]
    fn a_copy_folds_only_into_a_file_in_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(dir.path().join("app.log"), "here\n").unwrap();
        std::fs::write(nested.join("app.log.1"), "elsewhere\n").unwrap();

        let found = walk_with(dir.path(), &ExcludePaths::default(), &[], &[], 7);

        assert_eq!(names(&found), ["app.log", "app.log.1"]);
        assert!(
            found
                .files
                .iter()
                .all(|file| file.rotated_copies.is_empty())
        );
    }

    #[test]
    fn a_copy_whose_file_is_gone_stays_an_entry_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("messages-20260102"), "only the copy\n").unwrap();

        let found = walk_with(dir.path(), &ExcludePaths::default(), &[], &[], 7);

        assert_eq!(names(&found), ["messages-20260102"]);
    }

    #[test]
    fn the_written_to_path_drops_only_a_rotation_suffix() {
        for (path, written_to) in [
            ("/var/log/app.log", "/var/log/app.log"),
            ("/var/log/app.log.1", "/var/log/app.log"),
            ("/var/log/syslog.2.gz", "/var/log/syslog"),
            ("/var/log/messages-20260102", "/var/log/messages"),
            (
                "/var/log/postgresql-2026-01-02.log",
                "/var/log/postgresql-2026-01-02.log",
            ),
            ("C:\\inetpub\\logs\\app.log.1", "C:\\inetpub\\logs\\app.log"),
            ("app.log.3", "app.log"),
            ("/var/log/app/service.1.log", "/var/log/app/service.log"),
            ("/var/log/app/v1.2.log", "/var/log/app/v1.log"),
            ("/var/log/app/1.log", "/var/log/app/1.log"),
        ] {
            assert_eq!(written_to_path(path), written_to, "{path}");
        }
    }

    #[test]
    fn excluded_files_are_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::write(dir.path().join("app.log"), "kept\n").unwrap();
        std::fs::write(dir.path().join("payroll.log"), "excluded by name\n").unwrap();
        std::fs::write(private.join("notes.log"), "excluded by path\n").unwrap();
        let exclude =
            ExcludePaths::new(["payroll.*".to_string(), format!("{}/**", private.display())]);

        let found = walk_with(dir.path(), &exclude, &[], &[], 7);

        assert_eq!(names(&found), ["app.log"]);
    }

    #[test]
    fn excludes_files_older_than_max_age() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fresh.log"), "line\n").unwrap();
        let stale = dir.path().join("stale.log");
        std::fs::write(&stale, "line\n").unwrap();
        set_file_age(&stale, 8);

        assert_eq!(names(&walk_of(dir.path())), ["fresh.log"]);
    }

    #[test]
    fn max_file_age_is_tunable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, "line\n").unwrap();
        set_file_age(&path, 8);

        assert!(names(&walk_of(dir.path())).is_empty());
        assert_eq!(
            names(&walk_with(
                dir.path(),
                &ExcludePaths::default(),
                &[],
                &[],
                30
            )),
            ["app.log"]
        );
    }

    #[test]
    fn staleness_boundary_is_exclusive() {
        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        assert!(!is_stale(Some(cutoff), Some(cutoff)));
        assert!(is_stale(
            Some(cutoff - Duration::from_secs(1)),
            Some(cutoff)
        ));
    }

    #[test]
    fn paths_a_container_runtime_owns_are_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_root = dir.path().join("docker/containers");
        std::fs::create_dir_all(&runtime_root).unwrap();
        std::fs::write(runtime_root.join("container-json.log"), "runtime log\n").unwrap();
        std::fs::write(dir.path().join("application.log"), "application log\n").unwrap();

        let found = walk_with(
            dir.path(),
            &ExcludePaths::default(),
            std::slice::from_ref(&runtime_root),
            &[],
            7,
        );

        assert_eq!(names(&found), ["application.log"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_owns_its_paths_under_a_scan_path_reached_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_root = dir.path().join("data/docker/containers");
        std::fs::create_dir_all(&runtime_root).unwrap();
        std::fs::write(runtime_root.join("container-json.log"), "runtime log\n").unwrap();
        let owned_file = dir.path().join("data/custom/running-container.log");
        std::fs::create_dir_all(owned_file.parent().unwrap()).unwrap();
        std::fs::write(&owned_file, "runtime log\n").unwrap();
        std::fs::write(dir.path().join("data/application.log"), "application log\n").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("data"), &link).unwrap();

        let found = walk_with(
            &link,
            &ExcludePaths::default(),
            &[runtime_root, owned_file],
            &[],
            7,
        );

        assert_eq!(names(&found), ["application.log"]);
        assert_eq!(found.report(), ScannerReport::complete());
    }

    #[test]
    fn a_single_runtime_owned_file_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let owned = dir.path().join("custom/running-container.log");
        std::fs::create_dir_all(owned.parent().unwrap()).unwrap();
        std::fs::write(&owned, "runtime\n").unwrap();
        std::fs::write(dir.path().join("application.log"), "application\n").unwrap();

        let found = walk_with(
            dir.path(),
            &ExcludePaths::default(),
            std::slice::from_ref(&owned),
            &[],
            7,
        );

        assert_eq!(names(&found), ["application.log"]);
    }

    #[test]
    fn a_layer_store_is_not_read_and_the_report_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("docker/overlay2");
        std::fs::create_dir_all(store.join("3f9a/diff/var/log")).unwrap();
        std::fs::write(store.join("3f9a/diff/var/log/dpkg.log"), "in an image\n").unwrap();
        std::fs::write(dir.path().join("docker/panic.log"), "from the daemon\n").unwrap();

        let (found, directories_read) = walk_around(dir.path(), std::slice::from_ref(&store));

        assert_eq!(names(&found), ["panic.log"]);
        assert_eq!(directories_read, 2, "the scan path and docker under it");
        assert_eq!(found.report(), not_searched(&store));
    }

    #[test]
    fn a_layer_store_this_host_does_not_have_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let same_name_elsewhere = dir.path().join("shop/overlay2");
        std::fs::create_dir_all(&same_name_elsewhere).unwrap();
        std::fs::write(same_name_elsewhere.join("shop.log"), "from the shop\n").unwrap();

        let (found, directories_read) =
            walk_around(dir.path(), &[dir.path().join("docker/overlay2")]);

        assert_eq!(names(&found), ["shop.log"]);
        assert_eq!(directories_read, 3);
        assert_eq!(found.report(), ScannerReport::complete());
    }

    #[cfg(unix)]
    #[test]
    fn a_layer_store_is_left_alone_under_a_scan_path_reached_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("data/docker/overlay2");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("dpkg.log"), "in an image\n").unwrap();
        std::fs::write(dir.path().join("data/application.log"), "application log\n").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("data"), &link).unwrap();

        let (found, _) = walk_around(&link, &[store]);

        assert_eq!(names(&found), ["application.log"]);
        assert_eq!(found.report(), not_searched(&link.join("docker/overlay2")));
    }

    #[test]
    fn a_scan_path_inside_a_layer_store_is_not_searched() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("docker/overlay2");
        let layer = store.join("3f9a");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::write(layer.join("dpkg.log"), "in an image\n").unwrap();

        let (found, directories_read) = walk_around(&layer, &[store]);

        assert!(found.files.is_empty());
        assert_eq!(directories_read, 0);
        assert_eq!(found.report(), not_searched(&layer));
    }

    #[test]
    fn docker_json_logs_are_recognised_by_their_location() {
        let dir = tempfile::tempdir().unwrap();
        let container_id = "a".repeat(64);
        let container_dir = dir.path().join("containers").join(&container_id);
        std::fs::create_dir_all(&container_dir).unwrap();
        std::fs::write(
            container_dir.join(format!("{container_id}-json.log")),
            "not looked at",
        )
        .unwrap();
        std::fs::write(dir.path().join("application.log"), "application\n").unwrap();

        let found = walk_of(dir.path());

        let formats: Vec<(String, String)> = found
            .files
            .iter()
            .map(|file| {
                (
                    Path::new(&file.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    file.source_format.clone(),
                )
            })
            .collect();
        assert!(formats.contains(&(format!("{container_id}-json.log"), "docker-json".into())));
        assert!(formats.contains(&("application.log".into(), "file".into())));
    }

    #[test]
    fn pod_logs_are_recognised_by_their_location() {
        assert_eq!(
            source_format(Path::new("/var/log/pods/default_web-0_uid/web/0.log")),
            "k8s-cri"
        );
        assert_eq!(source_format(Path::new("/var/log/podsync.log")), "file");
    }

    #[test]
    fn an_extra_root_is_walked_once() {
        let dir = tempfile::tempdir().unwrap();
        let extra = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.log"), "x\n").unwrap();
        std::fs::write(extra.path().join("extra.log"), "x\n").unwrap();
        let inside = dir.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::write(inside.join("inner.log"), "x\n").unwrap();

        let found = walk_with(
            dir.path(),
            &ExcludePaths::default(),
            &[],
            &[extra.path().to_path_buf(), inside.clone()],
            7,
        );

        assert_eq!(names(&found), ["app.log", "extra.log", "inner.log"]);
    }
}
