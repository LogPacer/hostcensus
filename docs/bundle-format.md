# Bundle format, version 1

A bundle is one census of one host: a single UTF-8 JSON file, indented so a
person can read it. `tests/fixtures/bundle.v1.json` is a complete example and
is checked byte for byte by `tests/bundle_golden.rs`. A change to that fixture
is a change to this format.

## Top level

| Key | Meaning |
|---|---|
| `format` | Always `hostcensus.bundle/1`. A reader must refuse any other value. |
| `tool` | `name`, `version`, and `commit` when the build recorded one. |
| `generated_at` | When the census was taken, RFC 3339 in UTC. |
| `host` | `hostname`, `os`, `os_version`, `architecture`, `in_container`. |
| `scan` | How the census was taken. See below. |
| `inventory` | What was observed. See below. |
| `inventory_sha256` | Fingerprint of `inventory`. See below. |
| `coverage` | What is already collected, as stated by a person or an agent. |

`host.in_container` is true when the census was taken from inside a container.
Such a census describes the container, not the machine.

## scan

| Key | Meaning |
|---|---|
| `options` | The options in effect: `scan_paths`, `extensions`, `max_age_days`, `exclude_patterns`, `process_args`, `all_label_values`. `exclude_patterns` is how many `--exclude` patterns were given; the patterns name what was to be left out and are not recorded. |
| `privileged` | Whether the census ran as root or an elevated administrator. |
| `scanners` | One entry per scanner that applies to the operating system. |
| `duration_ms` | How long the census took. |

Each scanner entry has a `status` and, unless the status is `complete`, a
`reason`:

- `complete`: the scanner saw everything it looks for.
- `partial`: it ran but could not see everything, usually for lack of
  privileges.
- `unavailable`: it could not run.

A report built on a bundle must not treat a `partial` or `unavailable` scanner
as proof that nothing is there.

Which scanners report depends on the operating system. A scanner that does
not apply has no entry at all:

| Operating system | Scanners |
|---|---|
| Linux | `files`, `docker`, `cri`, `systemd`, `journal`, `processes`, `ports`, `packages` |
| macOS | `files`, `docker`, `processes`, `ports`, `packages` |
| Windows | `files`, `docker`, `windows_services`, `event_log`, `processes`, `ports` |

A scanner whose subject is absent from the host, such as `docker` on a host
without a Docker engine, reports `complete` with nothing found.

## inventory

Every list is always present, and empty when nothing was found or the scanner
does not apply. Each list is ordered by its identity, so two censuses of an
unchanged host are identical apart from times and process ids.

| List | Entry | Identity |
|---|---|---|
| `log_files` | `path`, `size`, `modified`, `permissions`, `source_format`, `rotated_copies`, and where known `open_in` | `path` |
| `containers` | See below | `stable_identifier` |
| `systemd_services` | `name`, `load_state`, `active_state`, `sub_state`, `description`, and where the journal could be read `journal_entries_24h`, `last_journal_entry` | `name` |
| `windows_services` | `name`, `display_name`, `state`, `service_type`, `pid` | `name` |
| `event_log_channels` | `channel`, `record_count` | `channel` |
| `processes` | `pid`, `user`, `command`, and where known `program`, `cwd`, `unit`, `container_id`, `stdout`, `stderr` | none |
| `listening_ports` | `port`, `protocol`, `process`, `pid` | none |
| `installed_packages` | `name`, `version`, `manager` | `manager` and `name` |

`log_files` holds the files under `scan.options.scan_paths` whose name marks
them as log files and that were written to within `max_age_days`, 90 unless
another limit was given. `modified` says how quiet a file is. `DATA.md`
gives the naming rule. A log file with an unusual name is absent, and its
absence is not evidence that the host does not write it.

A directory where a container runtime keeps the layers of its images is not
searched, and no file under it is in `log_files`. When a scan path covers
such a directory, the `files` scanner is `partial` and its `reason` names the
directory after the words `not searched`. `DATA.md` lists the directories.

A log file and the copies log rotation set aside are one source.
`rotated_copies` lists those copies under the file they were rotated from,
each with its `path`, `size` and `modified`: `app.log.1`, `app.log.2.gz`,
`app.1.log`, `messages-20260102`. A compressed copy is listed with its compressed size. A
copy whose file is not in the census (it no longer exists, or it is older
than `max_age_days`) is an entry of its own.

Files that carry a date in their name because the application starts a new
one each day (`catalina.2026-01-02.log`, `u_ex260102.log`) are not rotated
copies. Each is an entry of its own.

Log files are described from directory metadata. Their content is never read,
so a bundle holds no log lines. `source_format` is judged from where a file
lives: `file`, `docker-json` or `k8s-cri`.

`log_files[].open_in` lists the pids of the processes that hold the file open
for writing: the ones that write to it. A file can be in `log_files` for that
reason alone, outside the scan paths and with a name no rule recognises,
because a regular file held open for appending is a log. `processes[].stdout`
and `stderr` say where a process's output goes: `null` (thrown away), `file`,
`pipe` (to another program), `socket` (on a systemd host usually the journal),
`terminal` or `other`. All three are read on Linux only, and for other users'
processes only by root.

### What activity shows

The bundle states facts and leaves the verdict to its reader. The summary's
"no sign of output" for a running service means its `journal_entries_24h` is
0; none of its observed processes (those whose `unit` is the service) has a
pid in any `open_in`; and none has `stdout` or `stderr` of `file` or `pipe`.
This describes the paths visible during the census, not proof that the
service never logs. Read the scanner statuses too: even root cannot make a
partial scan complete. Missing facts are not zero.

A container's `log_driver` of `none` disables runtime capture of stdout and
stderr. A `log_size` of 0 means its current runtime log is empty; rotation or
pruning can reset it. Neither rules out application log files, direct
telemetry or earlier output, nor establishes collection or retention.

`systemd_services[].journal_entries_24h` is the number of entries observed for
the service in the journal's 24-hour query, and
`last_journal_entry` the time of the latest. A count of zero means the
query found no entries for that service. It may still write to a file, and
older journal entries may already have been removed. When the `journal`
scanner is `partial` because its reading timed out, counts are lower bounds,
including zero. Both fields are absent where other services' entries were
hidden by permissions, which the scanner's status says.

`processes[].program` says what an interpreter or a language runtime is
running: the script, jar, module or class, as it was given on the command
line. `cwd` is the working directory. `unit` is the systemd unit the process
belongs to, and `container_id` the full runtime id of its container, which is
the `container_id` of an entry in `containers`. Each is left out where it is
not known: `cwd` needs root for another user's process, `unit` and
`container_id` are read on Linux only, and nothing but `command` is read on
Windows.

`processes[].command` is the executable only: its path where that can be read,
otherwise the name the process was started as, otherwise the short name the
kernel keeps for it, in brackets (`[nginx]`). It holds the full command line
only when `scan.options.process_args` is true. On Windows it is the path of
the image, or the image name where the path cannot be read.

What differs by operating system:

| Field | Linux | macOS | Windows |
|---|---|---|---|
| `log_files[].permissions` | octal mode, `100640` | octal mode | `readonly` or `readwrite` |
| `log_files[].path` | `/var/log/…` | `/var/log/…` | `C:\ProgramData\…`, with backslashes |
| `processes[].user` | numeric user id | user name | security identifier (`S-1-5-…`), empty where it cannot be read |

An event-log channel that refused access is listed with `record_count` 0, and
the `event_log` scanner is `partial`. A count of 0 on a partial scanner is not
a statement that the channel is empty.

### containers

`id`, `name`, `image`, `state`, `runtime`, `service_name`,
`service_name_explicit`, `stable_identifier`, `stable_instance_id`,
`identifiers`, `labels`, `label_keys_withheld`, `env`, `env_names_withheld`, and, when they apply,
`log_driver`, `log_size`, `log_modified`,
`log_path`, `container_id`, `container_name`, `namespace`, `pod_name`,
`pod_uid`, `deployment`, `workload_kind`.

- `runtime` is `docker`, `containerd` or `cri-o`.
- `stable_identifier` names the workload and stays the same across restarts and
  redeploys. `stable_instance_id` names one instance of it. `identifiers` holds
  the facts both were derived from.
  Several container observations can share either identity. CRI containers
  without workload-owner metadata can also share them across unrelated pods
  or namespaces. Preserve the individual rows and runtime ids. A matching
  stable identifier does not prove that two rows are the same workload.
- `labels` holds only labels whose values are safe to keep by default. The keys
  of all other labels are listed in `label_keys_withheld`, without their
  values. When `scan.options.all_label_values` is true, every value is kept.
- `log_driver` is the logging driver of a running container, as the engine
  reports it. `none` means the container's output is thrown away. `log_size`
  and `log_modified` are the size of its log and the time of the last write,
  seen from the outside; they are absent where the log cannot be seen, which
  without root is the usual case, and for drivers that keep no file on the
  host. These describe runtime logging only, with the limits above.
- `env` holds the environment variables of a running container whose values
  are kept: versions (`NODE_VERSION`, `PG_MAJOR`), the deployment environment
  (`NODE_ENV`), log and telemetry settings (`LOG_LEVEL`, `OTEL_SERVICE_NAME`),
  the service name and the time zone, and only when the value is a short
  plain token. `DATA.md` gives the full rule. Every other variable is listed
  by name in `env_names_withheld`, without its value. Both are empty for a
  container that is not running, and for containers found through a CRI
  runtime, which is not asked for the environment.

## inventory_sha256

The SHA-256, in lowercase hex, of `inventory` serialized as compact JSON with
keys in the order shown in a bundle. hostcensus computes it when the census is
sealed and checks it before it adds coverage marks. It shows whether the
observations were edited afterwards. It is not a signature and proves nothing
about who wrote the file.

## coverage

`marks` is empty when the census is written. Each mark states whether one
source is already collected:

| Key | Meaning |
|---|---|
| `source` | `kind` (`log_file`, `container`, `systemd_service`, `windows_service`, `event_log_channel`) and the `identifier` of an inventory entry of that kind. |
| `collected` | `yes`, `no` or `unknown`. |
| `collector` | Optional. What collects it. |
| `destination` | Optional. Where the collector sends it. |
| `evidence` | Optional. Where this was read from, such as a file and line. |
| `noted_by` | `human` or `agent`. |
| `noted_at` | RFC 3339 in UTC. |

Marks are statements, not observations. The census never writes them. They
are added with `hostcensus mark`, which refuses a bundle whose inventory no
longer matches `inventory_sha256` and a source the inventory does not contain.

`hostcensus mark` accepts a pattern in place of an identifier and records one
mark per matching source; a bundle never contains a pattern.

A source has at most one mark: a later statement about the same source
replaces the earlier one. Marks are ordered by kind, then identifier.

Containers sharing a `stable_identifier` share a coverage reference and one
mark, even though every container remains in the inventory. Coverage cannot
express different answers for those rows individually.

The identifier of a source is the identity of its inventory entry: the `path`
of a log file, the `stable_identifier` of a container, the `name` of a systemd
or Windows service, the `channel` of an event log channel.
