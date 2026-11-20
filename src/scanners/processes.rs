//! Running processes.
//!
//! Linux reads `/proc`. Other Unix systems, and Linux when `/proc` cannot be
//! read, ask `ps`. Windows asks the system for its process list.
//!
//! A command line is read to find the one argument that says what an
//! interpreter runs (`program`). Nothing else of it reaches the bundle unless
//! the census is taken with `--process-args`.

use super::Scanned;
#[cfg(unix)]
use super::command;
#[cfg(unix)]
use super::program;
use crate::bundle::ScannerReport;
use crate::inventory::Process;

/// A file a process holds open for writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldOpen {
    pub pid: u32,
    pub path: std::path::PathBuf,
    /// Opened for appending, which is how logs are written.
    pub appending: bool,
}

/// The processes, and the files they hold open for writing where that could
/// be read.
pub(crate) type ProcessScan = (Scanned<Vec<Process>>, Vec<HeldOpen>);

#[cfg(unix)]
pub(crate) async fn scan(with_arguments: bool, privileged: bool) -> ProcessScan {
    #[cfg(target_os = "linux")]
    {
        let from_proc =
            tokio::task::spawn_blocking(move || linux::read_proc(with_arguments, privileged)).await;
        if let Ok(Some(scanned)) = from_proc {
            return scanned;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = privileged;
    (ask_ps(with_arguments).await, Vec::new())
}

/// Where a process's standard output or error goes, judged from what the
/// descriptor points at when that is a path.
#[cfg(any(target_os = "linux", test))]
fn output_to_path(path: &str) -> &'static str {
    if path == "/dev/null" {
        "null"
    } else if path.starts_with("/dev/pts/")
        || path.starts_with("/dev/tty")
        || path == "/dev/console"
    {
        "terminal"
    } else if path.starts_with("/dev/") {
        "other"
    } else {
        "file"
    }
}

/// Whether a descriptor was opened for appending. `fdinfo` is the content of
/// `/proc/<pid>/fdinfo/<fd>`, whose `flags:` line holds the open flags in
/// octal.
#[cfg(any(target_os = "linux", test))]
fn opened_for_appending(fdinfo: &str) -> bool {
    const O_APPEND: u32 = 0o2000;
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
        .is_some_and(|flags| flags & O_APPEND != 0)
}

/// Whether a path a process has open could be a log file at all: a file on
/// disk, not a device, not a kernel interface, and still there.
#[cfg(any(target_os = "linux", test))]
fn could_be_a_log(path: &str) -> bool {
    path.starts_with('/')
        && !path.ends_with(" (deleted)")
        && !["/dev/", "/proc/", "/sys/"]
            .iter()
            .any(|kernel| path.starts_with(kernel))
}

#[cfg(windows)]
pub(crate) async fn scan(with_arguments: bool, privileged: bool) -> ProcessScan {
    let processes = tokio::task::spawn_blocking(move || windows::list(with_arguments, privileged))
        .await
        .unwrap_or_else(|_| {
            Scanned::new(
                Vec::new(),
                ScannerReport::unavailable("the process listing stopped unexpectedly"),
            )
        });
    (processes, Vec::new())
}

#[cfg(unix)]
async fn ask_ps(with_arguments: bool) -> Scanned<Vec<Process>> {
    // The trailing `=` suppresses the header. The command column comes last
    // so it is never truncated; `comm` is the executable, `args` the full
    // command line.
    let user_column = if cfg!(target_os = "linux") {
        "uid="
    } else {
        "user="
    };
    let command_column = if with_arguments { "args=" } else { "comm=" };
    let columns = format!("pid=,{user_column},{command_column}");

    let mut processes: Vec<Process> = match command::stdout_of("ps", &["-A", "-o", &columns]).await
    {
        Ok(listing) => listing.lines().filter_map(parse_ps_line).collect(),
        Err(error) => {
            return Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string()));
        }
    };

    // A second listing gives each executable next to its arguments, to find
    // what an interpreter runs. `ps` does not say where a process was
    // started, so only an absolute path can be checked for a file.
    let (Ok(executables), Ok(command_lines)) = tokio::join!(
        command::stdout_of("ps", &["-A", "-o", "pid=,comm="]),
        command::stdout_of("ps", &["-A", "-o", "pid=,args="]),
    ) else {
        return Scanned::complete(processes);
    };
    let executables: std::collections::HashMap<u32, &str> =
        executables.lines().filter_map(pid_and_rest).collect();
    let command_lines: std::collections::HashMap<u32, &str> =
        command_lines.lines().filter_map(pid_and_rest).collect();
    for process in &mut processes {
        let (Some(executable), Some(command_line)) = (
            executables.get(&process.pid),
            command_lines.get(&process.pid),
        ) else {
            continue;
        };
        let arguments: Vec<String> = command_line.split_whitespace().map(String::from).collect();
        process.program = program::of(executable, &arguments, &|path| {
            std::path::Path::new(path).is_absolute() && std::path::Path::new(path).is_file()
        })
        .unwrap_or_default();
    }
    Scanned::complete(processes)
}

/// One line of `ps -A -o pid=,<column>=`: a pid and the rest.
#[cfg(any(unix, test))]
fn pid_and_rest(line: &str) -> Option<(u32, &str)> {
    let (pid, rest) = line.trim_start().split_once(char::is_whitespace)?;
    Some((pid.parse().ok()?, rest.trim()))
}

/// The systemd unit and the container a process belongs to, read from the
/// path of its control group: `/system.slice/nginx.service`,
/// `/system.slice/docker-<id>.scope`, `/kubepods/burstable/pod<uid>/<id>`.
#[cfg(any(target_os = "linux", test))]
fn unit_and_container(cgroup_path: &str) -> (Option<String>, Option<String>) {
    let segments = || cgroup_path.split('/').filter(|segment| !segment.is_empty());

    let unit = segments()
        .rfind(|segment| segment.ends_with(".service"))
        .map(str::to_string);

    let container = segments().find_map(|segment| {
        let id = segment.strip_suffix(".scope").unwrap_or(segment);
        let id = ["docker-", "cri-containerd-", "crio-", "libpod-"]
            .iter()
            .find_map(|prefix| id.strip_prefix(prefix))
            .unwrap_or(id);
        (id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| id.to_string())
    });

    (unit, container)
}

/// One line of `ps -A -o pid=,user=,comm=`: a pid, a user, and the rest.
#[cfg(any(unix, test))]
fn parse_ps_line(line: &str) -> Option<Process> {
    let (pid, rest) = line.trim_start().split_once(char::is_whitespace)?;
    let (user, command) = rest.trim_start().split_once(char::is_whitespace)?;
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    Some(Process {
        pid: pid.parse().ok()?,
        user: user.to_string(),
        command: command.to_string(),
        program: String::new(),
        cwd: String::new(),
        unit: String::new(),
        container_id: String::new(),
        stdout: String::new(),
        stderr: String::new(),
    })
}

/// What a process is, without its arguments.
///
/// The executable path is the best answer, but only root may read it for
/// other users' processes. The first argument is next, unless it holds
/// whitespace: servers such as nginx, PostgreSQL and sshd overwrite it with a
/// status line that names users, databases and client addresses. The kernel's
/// short name for the process is always available.
#[cfg(any(target_os = "linux", test))]
fn executable(exe: Option<&str>, arguments: &[String], kernel_name: &str) -> String {
    if let Some(exe) = exe {
        return exe.strip_suffix(" (deleted)").unwrap_or(exe).to_string();
    }
    match arguments.first() {
        Some(first) if !first.is_empty() && !first.contains(char::is_whitespace) => first.clone(),
        _ => format!("[{kernel_name}]"),
    }
}

#[cfg(any(target_os = "linux", test))]
fn command_line(arguments: &[String], kernel_name: &str) -> String {
    if arguments.is_empty() {
        format!("[{kernel_name}]")
    } else {
        arguments.join(" ")
    }
}

/// Whether `/proc` is mounted so that a process only sees its own user's
/// processes. `mounts` is the content of `/proc/self/mounts`.
#[cfg(any(target_os = "linux", test))]
fn proc_hides_other_users(mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (_device, _mount_point, filesystem, options) =
            (fields.next(), fields.next(), fields.next(), fields.next());
        filesystem == Some("proc")
            && options.is_some_and(|options| {
                options.split(',').any(|option| {
                    option
                        .strip_prefix("hidepid=")
                        .is_some_and(|mode| mode != "0" && mode != "off")
                })
            })
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use procfs::ProcError;
    use procfs::process::{FDPermissions, FDTarget, all_processes};

    use super::{
        HeldOpen, Process, ProcessScan, Scanned, ScannerReport, command_line, could_be_a_log,
        executable, opened_for_appending, output_to_path, proc_hides_other_users, program,
        unit_and_container,
    };

    fn output_kind(target: &FDTarget) -> &'static str {
        match target {
            FDTarget::Path(path) => output_to_path(&path.to_string_lossy()),
            FDTarget::Pipe(_) => "pipe",
            FDTarget::Socket(_) => "socket",
            _ => "other",
        }
    }

    /// `None` when `/proc` cannot be listed at all.
    pub(super) fn read_proc(with_arguments: bool, privileged: bool) -> Option<ProcessScan> {
        let mut processes = Vec::new();
        let mut held_open = Vec::new();
        let mut unreadable = 0usize;
        let mut descriptors_hidden = 0usize;

        for entry in all_processes().ok()? {
            let process = match entry {
                Ok(process) => process,
                Err(ProcError::PermissionDenied(_)) => {
                    unreadable += 1;
                    continue;
                }
                // The process ended between the listing and the read.
                Err(_) => continue,
            };
            let stat = match process.stat() {
                Ok(stat) => stat,
                Err(ProcError::PermissionDenied(_)) => {
                    unreadable += 1;
                    continue;
                }
                Err(_) => continue,
            };
            let Ok(pid) = u32::try_from(stat.pid) else {
                continue;
            };
            let user = match process.uid() {
                Ok(uid) => uid.to_string(),
                Err(ProcError::PermissionDenied(_)) => {
                    unreadable += 1;
                    continue;
                }
                Err(_) => continue,
            };

            let arguments = process.cmdline().unwrap_or_default();
            let exe = process.exe().ok();
            let executable = executable(
                exe.as_ref().map(|exe| exe.to_string_lossy()).as_deref(),
                &arguments,
                &stat.comm,
            );
            // Only root may read where another user's process was started.
            let cwd = process.cwd().ok();
            let program = program::of(&executable, &arguments, &|path| match &cwd {
                Some(cwd) => cwd.join(path).is_file(),
                None => {
                    std::path::Path::new(path).is_absolute() && std::path::Path::new(path).is_file()
                }
            })
            .unwrap_or_default();
            let (unit, container_id) = process
                .cgroups()
                .ok()
                .and_then(|cgroups| {
                    cgroups
                        .into_iter()
                        .map(|cgroup| unit_and_container(&cgroup.pathname))
                        .find(|(unit, container)| unit.is_some() || container.is_some())
                })
                .unwrap_or_default();
            let command = if with_arguments {
                command_line(&arguments, &stat.comm)
            } else {
                executable
            };

            // What the process has open says where its output goes and
            // which files it writes to. Only root may read this for another
            // user's process.
            let (mut stdout, mut stderr) = (String::new(), String::new());
            match process.fd() {
                Ok(descriptors) => {
                    for descriptor in descriptors.flatten() {
                        match descriptor.fd {
                            1 => stdout = output_kind(&descriptor.target).to_string(),
                            2 => stderr = output_kind(&descriptor.target).to_string(),
                            _ => {}
                        }
                        let FDTarget::Path(path) = &descriptor.target else {
                            continue;
                        };
                        if descriptor.mode().contains(FDPermissions::WRITE)
                            && could_be_a_log(&path.to_string_lossy())
                        {
                            let appending = std::fs::read_to_string(format!(
                                "/proc/{pid}/fdinfo/{}",
                                descriptor.fd
                            ))
                            .is_ok_and(|fdinfo| opened_for_appending(&fdinfo));
                            held_open.push(HeldOpen {
                                pid,
                                path: path.clone(),
                                appending,
                            });
                        }
                    }
                }
                Err(ProcError::PermissionDenied(_)) => descriptors_hidden += 1,
                Err(_) => {}
            }

            processes.push(Process {
                pid,
                user,
                command,
                program,
                cwd: cwd
                    .map(|cwd| cwd.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                unit: unit.unwrap_or_default(),
                container_id: container_id.unwrap_or_default(),
                stdout,
                stderr,
            });
        }

        let hidden = !privileged
            && std::fs::read_to_string("/proc/self/mounts")
                .is_ok_and(|mounts| proc_hides_other_users(&mounts));

        let mut gaps = Vec::new();
        if hidden {
            gaps.push("/proc hides the processes of other users (hidepid)".to_string());
        }
        match unreadable {
            0 => {}
            1 => gaps.push("1 process could not be read".to_string()),
            count => gaps.push(format!("{count} processes could not be read")),
        }
        match descriptors_hidden {
            0 => {}
            1 => gaps.push("what 1 process has open could not be read".to_string()),
            count => gaps.push(format!(
                "what {count} processes have open could not be read, so where they write is \
                 not known"
            )),
        }
        let report = if gaps.is_empty() {
            ScannerReport::complete()
        } else {
            ScannerReport::partial(gaps.join("; "))
        };
        Some((Scanned::new(processes, report), held_open))
    }
}

/// What a Windows process is: the path of its image where that can be read,
/// otherwise the name of its image. Its command line only on request.
#[cfg(any(windows, test))]
fn windows_command(
    image_path: Option<&str>,
    image_name: &str,
    arguments: &[String],
    with_arguments: bool,
) -> String {
    if with_arguments && !arguments.is_empty() {
        return arguments.join(" ");
    }
    match image_path {
        Some(path) if !path.is_empty() => path.to_string(),
        _ => image_name.to_string(),
    }
}

/// An elevated census still cannot read the image path of a few protected
/// system processes; that is all there is to see of them. Without elevation
/// the same happens to the processes of every other account.
#[cfg(any(windows, test))]
fn windows_report(listed: usize, name_only: usize, privileged: bool) -> ScannerReport {
    if listed == 0 {
        return ScannerReport::unavailable("Windows listed no processes");
    }
    if privileged || name_only == 0 {
        return ScannerReport::complete();
    }
    ScannerReport::partial(if name_only == 1 {
        "without elevation, 1 process shows only its name and no owner".to_string()
    } else {
        format!("without elevation, {name_only} processes show only their name and no owner")
    })
}

#[cfg(windows)]
mod windows {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    use super::{Process, Scanned, windows_command, windows_report};

    pub(super) fn list(with_arguments: bool, privileged: bool) -> Scanned<Vec<Process>> {
        // Only what the census records is asked for. Without
        // `--process-args` the command lines are not read at all.
        let mut wanted = ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet);
        if with_arguments {
            wanted = wanted.with_cmd(UpdateKind::OnlyIfNotSet);
        }
        let Ok(mut system) = System::new() else {
            return Scanned::new(Vec::new(), windows_report(0, 0, privileged));
        };
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, wanted);

        let mut name_only = 0usize;
        let processes: Vec<Process> = system
            .processes()
            .values()
            .map(|process| {
                let image_path = process
                    .exe()
                    .map(|path| path.to_string_lossy().into_owned())
                    .filter(|path| !path.is_empty());
                if image_path.is_none() {
                    name_only += 1;
                }
                let arguments: Vec<String> = process
                    .cmd()
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect();
                Process {
                    pid: process.pid().as_u32(),
                    user: process
                        .user_id()
                        // A user id wraps the security identifier, which is
                        // what prints as `S-1-5-…`.
                        .map(|user| (**user).to_string())
                        .unwrap_or_default(),
                    command: windows_command(
                        image_path.as_deref(),
                        &process.name().to_string_lossy(),
                        &arguments,
                        with_arguments,
                    ),
                    // Not read on Windows yet: finding the program would
                    // mean reading every command line.
                    program: String::new(),
                    cwd: String::new(),
                    unit: String::new(),
                    container_id: String::new(),
                    stdout: String::new(),
                    stderr: String::new(),
                }
            })
            .collect();

        let report = windows_report(processes.len(), name_only, privileged);
        Scanned::new(processes, report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ps_lines_split_into_pid_user_and_command() {
        let listing = "\
    1 root             /sbin/launchd
  312 _windowserver    /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer
 1042 morten           /Applications/Some App.app/Contents/MacOS/Some App
";
        let processes: Vec<Process> = listing.lines().filter_map(parse_ps_line).collect();

        assert_eq!(processes.len(), 3);
        assert_eq!(processes[0].pid, 1);
        assert_eq!(processes[0].user, "root");
        assert_eq!(processes[0].command, "/sbin/launchd");
        assert_eq!(processes[1].user, "_windowserver");
        assert_eq!(
            processes[2].command,
            "/Applications/Some App.app/Contents/MacOS/Some App"
        );
    }

    #[test]
    fn a_control_group_names_the_unit_and_the_container() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (cgroup_path, unit, container) in [
            ("/system.slice/nginx.service", Some("nginx.service"), None),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/shop.service",
                Some("shop.service"),
                None,
            ),
            (
                &format!("/system.slice/docker-{id}.scope") as &str,
                None,
                Some(id),
            ),
            (&format!("/docker/{id}"), None, Some(id)),
            (
                &format!(
                    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-{id}.scope"
                ),
                None,
                Some(id),
            ),
            (&format!("/kubepods/burstable/pod1234/{id}"), None, Some(id)),
            (&format!("/machine.slice/libpod-{id}.scope"), None, Some(id)),
            // A container started by a unit belongs to both.
            (
                &format!("/system.slice/shop.service/docker-{id}.scope"),
                Some("shop.service"),
                Some(id),
            ),
            ("/user.slice/user-1000.slice/session-3.scope", None, None),
            ("/", None, None),
            ("/system.slice/docker-tooshort.scope", None, None),
        ] {
            let (found_unit, found_container) = unit_and_container(cgroup_path);
            assert_eq!(found_unit.as_deref(), unit, "{cgroup_path}");
            assert_eq!(found_container.as_deref(), container, "{cgroup_path}");
        }
    }

    #[test]
    fn a_ps_line_splits_into_a_pid_and_the_rest() {
        assert_eq!(
            pid_and_rest("  812 /usr/bin/python3 /srv/app/manage.py runserver"),
            Some((812, "/usr/bin/python3 /srv/app/manage.py runserver"))
        );
        assert_eq!(pid_and_rest("not-a-pid sleep"), None);
        assert_eq!(pid_and_rest("812"), None);
    }

    #[test]
    fn ps_lines_that_are_not_processes_are_skipped() {
        assert_eq!(parse_ps_line(""), None);
        assert_eq!(parse_ps_line("  PID USER COMMAND"), None);
        assert_eq!(parse_ps_line("  12 root   "), None);
    }

    #[test]
    fn the_executable_path_names_a_process() {
        assert_eq!(
            executable(
                Some("/usr/sbin/nginx"),
                &arguments(&["nginx: master process /usr/sbin/nginx -g daemon on;"]),
                "nginx"
            ),
            "/usr/sbin/nginx"
        );
        assert_eq!(
            executable(Some("/usr/bin/old (deleted)"), &[], "old"),
            "/usr/bin/old"
        );
    }

    #[test]
    fn arguments_never_leak_into_the_executable() {
        assert_eq!(
            executable(
                None,
                &arguments(&["/usr/bin/psql", "--password=hunter2"]),
                "psql"
            ),
            "/usr/bin/psql"
        );
    }

    #[test]
    fn a_rewritten_process_title_is_not_taken_for_the_executable() {
        assert_eq!(
            executable(
                None,
                &arguments(&["postgres: alice shop 10.0.0.7(52114) idle"]),
                "postgres"
            ),
            "[postgres]"
        );
        assert_eq!(executable(None, &[], "kthreadd"), "[kthreadd]");
    }

    #[test]
    fn the_full_command_line_is_kept_only_on_request() {
        assert_eq!(
            command_line(&arguments(&["/usr/bin/psql", "--password=hunter2"]), "psql"),
            "/usr/bin/psql --password=hunter2"
        );
        assert_eq!(command_line(&[], "kthreadd"), "[kthreadd]");
    }

    #[test]
    fn a_proc_mount_with_hidepid_hides_other_users() {
        assert!(proc_hides_other_users(
            "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n"
        ));
        assert!(proc_hides_other_users(
            "proc /proc proc rw,relatime,hidepid=invisible 0 0\n"
        ));
        assert!(!proc_hides_other_users(
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        ));
        assert!(!proc_hides_other_users(
            "proc /proc proc rw,hidepid=off 0 0\ntmpfs /run tmpfs rw,hidepid=2 0 0\n"
        ));
    }

    #[test]
    fn a_windows_process_is_its_image_path_or_else_its_image_name() {
        let arguments = arguments(&[r"C:\Shop\api.exe", "--token=hunter2"]);

        assert_eq!(
            windows_command(Some(r"C:\Shop\api.exe"), "api.exe", &arguments, false),
            r"C:\Shop\api.exe"
        );
        assert_eq!(
            windows_command(None, "MsMpEng.exe", &arguments, false),
            "MsMpEng.exe"
        );
        assert_eq!(windows_command(Some(""), "System", &[], false), "System");
    }

    #[test]
    fn a_windows_command_line_is_recorded_only_on_request() {
        let arguments = arguments(&[r"C:\Shop\api.exe", "--token=hunter2"]);

        assert_eq!(
            windows_command(Some(r"C:\Shop\api.exe"), "api.exe", &arguments, true),
            r"C:\Shop\api.exe --token=hunter2"
        );
        // A process whose command line cannot be read keeps its image path.
        assert_eq!(
            windows_command(Some(r"C:\Shop\api.exe"), "api.exe", &[], true),
            r"C:\Shop\api.exe"
        );
    }

    #[test]
    fn a_windows_listing_without_elevation_says_how_much_it_could_not_see() {
        assert_eq!(windows_report(120, 5, true), ScannerReport::complete());
        assert_eq!(windows_report(120, 0, false), ScannerReport::complete());
        assert_eq!(
            windows_report(120, 37, false),
            ScannerReport::partial(
                "without elevation, 37 processes show only their name and no owner"
            )
        );
        assert_eq!(
            windows_report(120, 1, false),
            ScannerReport::partial("without elevation, 1 process shows only its name and no owner")
        );
        assert_eq!(
            windows_report(0, 0, true),
            ScannerReport::unavailable("Windows listed no processes")
        );
    }

    #[test]
    fn where_output_goes_is_read_from_what_the_descriptor_points_at() {
        for (path, kind) in [
            ("/dev/null", "null"),
            ("/dev/pts/3", "terminal"),
            ("/dev/tty1", "terminal"),
            ("/dev/console", "terminal"),
            ("/dev/zero", "other"),
            ("/var/log/shop/out.log", "file"),
            ("/srv/shop/shared/production.out", "file"),
        ] {
            assert_eq!(output_to_path(path), kind, "{path}");
        }
    }

    #[test]
    fn the_open_flags_say_whether_a_file_is_appended_to() {
        // O_WRONLY | O_APPEND | O_LARGEFILE, as a log is usually opened.
        assert!(opened_for_appending(
            "pos:\t1024\nflags:\t0102001\nmnt_id:\t27\n"
        ));
        // O_RDWR | O_LARGEFILE: a data file.
        assert!(!opened_for_appending(
            "pos:\t0\nflags:\t0100002\nmnt_id:\t27\n"
        ));
        assert!(!opened_for_appending("pos:\t0\nmnt_id:\t27\n"));
        assert!(!opened_for_appending("flags:\tnot-octal\n"));
    }

    #[test]
    fn devices_kernel_interfaces_and_deleted_files_are_not_logs() {
        for path in ["/var/log/app.log", "/srv/shop/shared/production.out"] {
            assert!(could_be_a_log(path), "{path}");
        }
        for path in [
            "/dev/null",
            "/proc/1/status",
            "/sys/kernel/debug/tracing/trace",
            "/var/log/app.log (deleted)",
            "anon_inode:[eventpoll]",
        ] {
            assert!(!could_be_a_log(path), "{path}");
        }
    }

    #[tokio::test]
    async fn this_test_process_is_in_the_scan() {
        let (scanned, _) = scan(false, false).await;

        assert!(
            scanned
                .found
                .iter()
                .any(|process| process.pid == std::process::id()),
            "{:?}",
            scanned.report
        );
        assert!(scanned.found.iter().all(|process| process.pid > 0));
    }
}
