# What hostcensus touches

This file lists everything hostcensus reads, runs and writes. It is kept in
step with the code: a change to one is a change to the other.

## What it never does

- It opens no network connection. It contains no HTTP client, TLS stack or
  Kubernetes API client, and its code may not use TCP or UDP sockets. Both are
  enforced in CI (`deny.toml`, `clippy.toml`). It talks to a container engine
  only through a Unix socket on the same host, and refuses an engine that is
  configured with a network address.
- It reads no log message. Log files are listed from directory metadata and
  are never opened. The journal is asked only for the unit name and the time
  of each entry, never for its text.
- It writes nothing except the bundle. It keeps no state on the host.
- It does not raise its own privileges. What it cannot see, it reports as
  partial or unavailable, per scanner, with the reason.

## What it keeps out of the bundle

Values that can be secrets are left out, whatever they are called:

- **Environment variables.** Every variable of a running container is
  listed by name. Its value is kept only when the name says the value is a
  plain fact about what runs and how it logs, and the value is a short plain
  token (letters, digits and `. _ + ~ , / -`, at most 64 of them). The names
  are: any ending in `_VERSION` or `_MAJOR`; the deployment environment
  (`NODE_ENV`, `RAILS_ENV`, `RACK_ENV`, `APP_ENV`, `ENVIRONMENT`,
  `ASPNETCORE_ENVIRONMENT`, `DOTNET_ENVIRONMENT`, `SPRING_PROFILES_ACTIVE`);
  log settings (`LOG_LEVEL`, `LOGLEVEL`, `LOG_FORMAT`); telemetry settings
  (`OTEL_SERVICE_NAME`, `OTEL_LOGS_EXPORTER`, `OTEL_TRACES_EXPORTER`,
  `OTEL_METRICS_EXPORTER`, `OTEL_EXPORTER_OTLP_PROTOCOL`);
  `LOGPACER_SERVICE_NAME`; and `TZ`. Every other variable is listed by name
  alone, and there is no option to include its value. An address, a URL or a
  connection string is never a plain token, so it is left out even under one
  of these names.
- **Container label values.** Kept only for keys starting with
  `com.docker.compose.`, `io.kubernetes.` or `org.opencontainers.image.`, and
  for `logpacer.com/service-name` and `log.format`. Every other label is
  listed by key alone. `--all-label-values` includes them all.
- **Process arguments.** A process is listed by its executable, and an
  interpreter also by the one argument that names what it runs. Every other
  argument is left out. `--process-args` includes the full command line.
- **Exclude patterns.** A pattern names what was to be left out, so the
  bundle records how many patterns were given and not the patterns.
- **Engine addresses.** A refused engine address is named by its scheme only.

## What a bundle still tells its reader

A bundle holds no secret values, but it describes the host in detail, and
that is sensitive in its own right. It is written readable by its owner only
for that reason, also when it is handed to the user who ran `sudo`. Read it before it goes anywhere. It contains:

- the host name, operating system and architecture;
- paths of log files, which can hold user, customer and product names;
- container names, images with their registry and tag, the names of their
  environment variables, which show which systems a container talks to, and
  the kept values: versions, the deployment environment, log and telemetry
  settings;
- the kept label values, which include compose working directories and image
  metadata such as authors and source URLs;
- names and descriptions of services, paths of running executables, the
  scripts and jars interpreters run, and working directories;
- every installed package with its version, and every listening port: together
  these show what an attacker would look for;
- whatever a person or an agent wrote into coverage marks.

## The host

| What | Why |
|---|---|
| The host name, from the operating system | `host.hostname` |
| `/etc/os-release` | `host.os_version` on Linux |
| `sw_vers -productVersion` (command, macOS) | `host.os_version` on macOS |
| The registry values `ProductName` and `CurrentBuildNumber` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `host.os_version` on Windows |
| Whether `/.dockerenv` and `/var/run/secrets/kubernetes.io` exist, and `/proc/1/cgroup` | `host.in_container` |
| Its own effective user id | `scan.privileged` on Linux and macOS, and whether a bundle is handed to the user who ran `sudo` |
| The environment variables `SUDO_UID` and `SUDO_GID` (Linux, macOS) | Who a bundle written as root is handed to; see "Who the file belongs to" |
| `whoami /groups` (command, Windows), for the integrity level of its own token | `scan.privileged` on Windows |

On Windows `host.in_container` is always false: a census taken inside a
Windows container is not recognised as such.

## The scanners

Every command below is stopped after 10 seconds. A scanner whose command is
missing, fails or is stopped reports `unavailable` with the reason; the census
goes on without it.

### files (Linux, macOS, Windows)

- Walks each scan path and reads directory entries and their metadata: path,
  size, modification time, permissions. Symbolic links are not followed, and
  on Windows neither are junctions. The default scan path is `/var/log`; on
  Windows the defaults are `C:\inetpub\logs\LogFiles`, `C:\Windows\Logs` and
  `C:\ProgramData`.
- Keeps a file when its name says it is a log file: an allowed extension
  (default `log`), a name ending in `_log` (`access_log`), or the name of a
  system log that has no extension (`syslog`, `messages`, `secure`, `maillog`,
  `cron`, `kern`, `daemon`, `debug`, `user`, `auth`, `mail`, `spooler`,
  `dmesg`, `boot`, and `mail.info`, `mail.warn`, `mail.err`). Rotated copies
  of these are kept too (`app.log.1`, `syslog.2.gz`, `messages-20260102`).
- On Windows only the extension counts, compared without regard to case. The
  names without an extension are Unix conventions and are not applied there.
- Leaves out files not modified within the last 90 days by default, and
  files matched by an `--exclude` pattern. A file that is quiet but younger
  than that is listed, with the time of its last write.
- Lists a rotated copy under the file it was rotated from, when that file is
  in the same directory and in the census. The copy is recognised by its
  name: the file name followed by a number, a date (`-YYYYMMDD`), a
  compression extension, or a number and a compression extension, or with a
  number before the extension (`app.1.log`). On Windows a pattern may use `\` or `/`
  and matches without regard to case.
- A log file with any other name is not listed. Give its extension with
  `--ext`, and its directory with `--scan-path` when it is outside the default.
  The scanner still reports `complete`: it saw everything it looks for.
- On Windows the only permission read is the read-only attribute. Access
  control lists are not read.
- When no Docker engine answered, it also walks `/var/lib/docker/containers`
  (`C:\ProgramData\docker\containers` on Windows).
- Does not read a directory where a container runtime keeps the layers of
  its images, nor anything under it. A file inside an image is not a log this
  host writes, and what a container writes to its output is listed with the
  container. See "Image layers" below for the directories.
- It never opens a file it lists. `source_format` is judged from the path.
- On Linux it adds the files that running processes hold open for writing:
  to a file it already lists it adds the pids that write to it, and a
  regular file held open for appending is listed as a log file wherever it
  lies and whatever it is called. Exclude patterns apply to these too.
- To see everything: read access to the directories under the scan paths,
  which usually means root or an elevated administrator. Directories it may
  not read are counted in the scanner's reason.

#### Image layers

The search for log files leaves these directories alone. It does not list
them and reads nothing under them.

| Under | Directories | Why it is a layer store |
|---|---|---|
| A Docker data root, Linux | `overlay2`, `overlay`, `fuse-overlayfs`, `aufs`, `btrfs`, `devicemapper`, `vfs`, `zfs` | A Docker engine gives each storage driver one directory under its data root, named after the driver. The driver keeps layers there and nothing else. |
| A Docker data root, Windows | `windowsfilter` | The same rule. `windowsfilter` is the storage driver for Windows containers. |
| A containerd root, Linux | `io.containerd.snapshotter.v1.` followed by `overlayfs`, `native`, `btrfs`, `zfs`, `devmapper`, `blockfile` or `erofs` | containerd gives each snapshotter one directory under its root, named after the kind of plugin and the snapshotter. A snapshotter keeps layers there and nothing else. |
| A containerd root, Windows | `io.containerd.snapshotter.v1.windows`, `io.containerd.snapshotter.v1.windows-lcow` | The same rule. |

- The Docker data roots are the default one, `/var/lib/docker`
  (`C:\ProgramData\docker` on Windows), and the one a Docker engine names
  when it answers.
- The containerd roots are the default one, `/var/lib/containerd`
  (`C:\ProgramData\containerd\root` on Windows), and `containerd/daemon` under
  each Docker data root, where an engine that starts a containerd of its own
  keeps that one's data.
- hostcensus asks the file system whether each of these directories exists,
  and where a link to it leads. It asks nothing else about them.
- Everything else under a data root is searched: the engine's own log files,
  such as `C:\ProgramData\docker\panic.log`, and volumes. Container logs are
  found as before.
- When a scan path covers one of these directories, the `files` scanner
  reports `partial`, and its reason names each directory that was not
  searched. The summary on standard error prints the same reason.
- A layer store holds more than images. On Linux it also holds the writable
  layer of every container, so a log file that a container writes inside its
  own file system, not to its output, lies in there and is not listed there.
  Where Docker keeps its images in containerd, it mounts the file system of
  each running container under `rootfs` in its data root. That directory is
  not a layer store and is searched, so such a file is listed from there.
  With the older storage drivers the mount lies inside the driver's
  directory, and the file is not listed.
- The default scan path on Linux, `/var/log`, covers none of these
  directories. The default scan path `C:\ProgramData` on Windows covers both
  default roots.
- A data root that was moved is known only when a Docker engine answers and
  names it. hostcensus does not ask containerd for its root, so a moved
  containerd root is not known. Neither are the stores of other runtimes
  (CRI-O and Podman keep theirs under `/var/lib/containers/storage`), of a
  Kubernetes distribution that brings a containerd of its own, or of a
  snapshotter that runs outside containerd. Such a store is searched like any
  other directory when a scan path covers it. An `--exclude` pattern keeps
  its files out of the bundle, but the search still reads its directories.

### docker (Linux, macOS, Windows)

- Reads the environment variables `DOCKER_HOST` and `CONTAINER_HOST`.
- Does not read the Docker CLI configuration (`~/.docker/config.json`), which
  can hold registry credentials. An engine that listens somewhere other than
  the default socket is found only through `DOCKER_HOST`, for example
  `DOCKER_HOST=unix:///run/user/1000/docker.sock`.
- Connects to one Unix socket: the configured one, or `/var/run/docker.sock`
  when it exists. An address that is not a local socket (`tcp://`, `http://`,
  `ssh://`, …) is refused and nothing is contacted.
- On Windows it connects to one named pipe instead: the configured one
  (`DOCKER_HOST=npipe:////./pipe/<name>`), or `\\.\pipe\docker_engine`. To
  learn whether the pipe exists it opens and closes it once. A pipe on
  another machine (`\\server\pipe\…`) is reached over the network, so it is
  refused like any network address. No pipe means no engine, and the scanner
  reports `complete` with no containers.
- Asks the engine for its info (only the data directory is used), the list of
  all containers, and the details of each running container (only the log
  path, the logging driver and the environment are used).
- Asks the file system for the size and last-write time of each running
  container's log file. The log is not opened. This usually needs root.
- Of a running container's environment, every variable is listed by name.
  A value is written to the bundle only for the variables named under "What
  it keeps out of the bundle", and only when the value is a short plain
  token.
- Label values are kept only for well-known keys; see
  `docs/bundle-format.md`.
- To see everything: root, or membership of the group that owns the socket.
  On Windows: an elevated administrator, or an account the engine lets open
  its pipe.

### cri (Linux)

- Reads the environment variable `CONTAINER_RUNTIME_ENDPOINT`.
- Looks for a Unix socket at `/run/containerd/containerd.sock`,
  `/run/crio/crio.sock` or `/var/run/cri-dockerd.sock`. A configured endpoint
  that is not an existing local socket is not used and nothing else is tried.
- Runs `crictl --runtime-endpoint unix://<socket> ps -a -o json` and
  `crictl --runtime-endpoint unix://<socket> pods -o json`.
- Checks whether `/var/log/pods` exists when `crictl` is not installed.
- A pod container's `log_path` is built from its namespace, pod and container
  names. The directory is not looked at.
- To see everything: root, and `crictl` installed.

### systemd (Linux)

- Checks whether `/run/systemd/system` exists.
- Runs `systemctl list-units --type=service --all --plain --no-pager --no-legend`.
- To see everything: no special privileges on a host with a system bus.

### journal (Linux)

- Checks whether `/run/systemd/system` exists.
- Runs `journalctl --since=-24h --reverse --no-pager --output=json
  --output-fields=_SYSTEMD_UNIT`. With that field list `journalctl` prints,
  for each entry of the last 24 hours, the unit that wrote it and when, and
  not the message. hostcensus counts the entries of each unit and keeps the
  time of its latest one.
- Reading stops after 10 seconds. The scanner then reports `partial`: the
  time of each service's last entry is right, and the counts are too low.
- To see everything: root, or membership of the `systemd-journal` group.
  Without it no count is given for any service, because a service without
  visible entries may still have written some.

### processes (Linux, macOS, Windows)

- Linux: for every process, reads `/proc/<pid>/stat`, the owner of
  `/proc/<pid>`, `/proc/<pid>/cmdline`, `/proc/<pid>/cgroup`, and the
  `/proc/<pid>/exe` and `/proc/<pid>/cwd` links. Reads `/proc/self/mounts` to
  see whether `/proc` hides other users' processes.
- macOS, and Linux when `/proc` cannot be read: runs `ps -A -o pid=,user=,comm=`
  (`uid=` in place of `user=` on Linux), then `ps -A -o pid=,comm=` and
  `ps -A -o pid=,args=`. With `--process-args` the last column of the first
  listing is `args=`.
- The command line is read to find one thing: what an interpreter or a
  language runtime (`java`, `python`, `node`, `deno`, `bun`, `ruby`, `php`,
  `perl`, `dotnet`, a shell) is running. That script, jar, module or class is
  recorded as `program`. It is taken only when it has the shape of one: a
  plain path that names an existing file or ends in one of the interpreter's
  extensions, or a module or class name. To check that a path names a file,
  hostcensus asks the file system whether it exists; it does not open it.
- Without `--process-args` no other argument is recorded. Where the
  executable path cannot be read and the first argument holds whitespace (a
  rewritten process title), the kernel's short process name is recorded in
  brackets instead.
- Linux also records the working directory, where it may be read, and the
  systemd unit and the container the process belongs to, both taken from the
  path of its control group.
- Linux reads what each process has open: the links in `/proc/<pid>/fd`, and
  for a file open for writing the open flags in `/proc/<pid>/fdinfo/<fd>`.
  From that it records where standard output and standard error go, and
  which files the process writes to. No file is opened and nothing is read
  from one. Only root may read this for another user's process; without it
  the scanner reports `partial`.
- Windows: asks the system for its process list and, for each process, the
  path of its image and the security identifier of its owner. The command
  line of a process is read only with `--process-args`. No command is run.
- To see everything: root. Without it, Linux shows other users' processes by
  name only, and a `/proc` mounted with `hidepid` hides them altogether. On
  Windows without elevation, processes of other accounts show their image
  name only and no owner; a few protected system processes do so even to an
  elevated census.

### ports (Linux, macOS, Windows)

- Linux: reads `/proc/net/tcp`, `tcp6`, `udp` and `udp6`; for every process
  the `/proc/<pid>/comm` name, the `/proc/<pid>/ns/net` link and the links in
  `/proc/<pid>/fd`; and `/proc/<pid>/net/tcp` and `tcp6` of one process per
  other network namespace.
- macOS, and Linux when `/proc` cannot be read: runs `lsof -i -P -n`. The
  flags stop `lsof` from looking up host and service names.
- Windows: runs `netstat -ano`, where `-n` stops it from looking up names, and
  asks the system for the image name of each owning process. Neither the
  column headings nor the state column is read, because both are translated
  on a non-English Windows.
- To see everything: root. Without it, sockets of other users' processes have
  no owner and listeners inside containers are not seen. On Windows no
  elevation is needed.

### windows_services (Windows)

- Runs `sc queryex type= service state= all`.
- Records each service's name, display name, state, type and process id. The
  output is read by its shape and the state by its number, not by the field
  labels, which a translated Windows may print differently.
- `sc` writes in the console code page. When that is not UTF-8, display names
  with characters outside ASCII come out garbled and the scanner says so.
- No elevation is needed.

### event_log (Windows)

- Calls the Windows Event Log API in process (`EvtOpenChannelEnum`,
  `EvtNextChannelPath`, `EvtOpenLog`, `EvtGetLogInfo`) to list the channels
  of this host and count the records in each. No event is read.
- Lists the classic channels (`Application`, `System`, `Security`, `Setup`,
  `ForwardedEvents`), every other channel that holds records, and every
  channel that refused access. Debug and analytic channels are left out.
- To see everything: an elevated administrator. Without elevation `Security`
  and some other channels refuse access; they are listed with 0 records and
  the scanner reports `partial`, naming how many.

### packages (Linux, macOS)

- Linux: reads `/var/lib/dpkg/status`. When that file does not exist, runs
  `rpm -qa --queryformat '%{NAME}|%{VERSION}\n'`.
- macOS: reads the directory names under `/opt/homebrew/Cellar` or
  `/usr/local/Cellar`.
- No special privileges are needed.
- Windows has no package scanner, and a census taken there has no `packages`
  entry under `scan.scanners`.

## What it writes

One file: the bundle, at the path given with `--output`, or
`hostcensus-<hostname>-<time>.json` in the current directory. The file is
created readable by its owner only, and an existing file is never replaced.
With `--output -` the bundle goes to standard output and no file is written.

A short summary is printed to standard error. While the search for log files
goes on, a line on standard error says every five seconds which scan path it
is under and how many directories it has read. A search that ends within five
seconds prints no such line.

`hostcensus coverage` reads one bundle and prints its sources and marks. It
writes nothing.

`hostcensus mark` reads one bundle and rewrites it with a coverage mark added.
It writes the new content to `<bundle>.hostcensus-tmp` beside the file and
moves it into place. Apart from what the next section lists, it reads nothing
else on the host and runs no command.

### Who the file belongs to

A census has to run as root to see everything, and a file that root creates
belongs to root. The person who ran `sudo hostcensus` could then not open
their own census. So on Linux and macOS hostcensus reads the environment
variables `SUDO_UID` and `SUDO_GID`, which `sudo` sets to the ids of the user
who ran it.

A bundle written as root into a directory that user owns, or one that everyone
may write to, such as `/tmp`, is made that user's and group's. Anywhere else
it stays root's, and the summary says why and how to get a file that user can
read. Either way the file is readable by its owner only.

- The variables count only when hostcensus runs as root and both hold a plain
  number. Otherwise the file belongs to whoever ran hostcensus, as with any
  program. `doas`, `pkexec` and `su` are not recognised.
- Without `--output` the bundle goes into the current directory, so
  `cd ~ && sudo hostcensus` hands it over.
- `hostcensus mark` also hands over a bundle that already belonged to that
  user, whatever directory it is in.
- The limit is there because a file of one's own in a directory that only
  root may write to is a way to become root. A person whose `sudo` rights
  cover hostcensus alone must not gain that from it.
- To decide this, hostcensus opens the directory the file goes into and reads
  the owner and permissions of that directory. For `mark` it also reads the
  owner of the bundle. It creates the file inside the open directory, changes
  the owner through the open file, and for `mark` moves the new file into
  place inside the same open directory. It never changes an owner by path, so
  a link put into the path cannot turn the change onto another file.
- It looks up no user name. The summary names the user and group by number.
- When the file system refuses the change, a new census stays root's and the
  summary says why. `hostcensus mark` fails instead and leaves the bundle as
  it was.

## What ends up in the bundle

See `docs/bundle-format.md`. What deserves a look before a bundle is shared:

- Paths of log files, which can contain user names.
- Container names, images and label keys.
- Host name, process names and package names.
- With `--process-args`, full command lines. With `--all-label-values`, every
  label value. Both can hold secrets, which is why neither is the default.
