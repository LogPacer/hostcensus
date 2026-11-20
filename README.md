# hostcensus

Takes a census of one host: what runs on it and which logs it produces.
It runs once, opens no network connection, and writes a single file.

## Install

A [release](https://github.com/LogPacer/hostcensus/releases) carries one
binary for each platform and a `SHA256SUMS` file. The binary is the whole
tool. There is no installer and no other file to fetch.

| Host | File |
|---|---|
| Linux, x86-64 | `hostcensus-linux-amd64` |
| Linux, 64-bit ARM | `hostcensus-linux-arm64` |
| macOS, Apple silicon | `hostcensus-darwin-arm64` |
| macOS, Intel | `hostcensus-darwin-amd64` |
| Windows, x86-64 | `hostcensus-windows-amd64.exe` |

The Linux binaries are statically linked. They use nothing from the
distribution, so the same file runs on CentOS 7 and on Alpine.

Download the binary and the checksums, check the binary, and run it. On
Linux:

```bash
curl -fsSLO https://github.com/LogPacer/hostcensus/releases/latest/download/hostcensus-linux-amd64
curl -fsSLO https://github.com/LogPacer/hostcensus/releases/latest/download/SHA256SUMS
grep hostcensus-linux-amd64 SHA256SUMS | sha256sum -c -
chmod +x hostcensus-linux-amd64
sudo ./hostcensus-linux-amd64 --output inventory.json
```

Run with `sudo`, the file belongs to you and only you can read it, as long as
you write it into a directory of your own or into `/tmp`. In any other
directory it belongs to root, and the summary says so.

On macOS the steps are the same with the `darwin` file, and the check is
`shasum -a 256 -c -`. On Windows, in an elevated PowerShell:

```powershell
$release = "https://github.com/LogPacer/hostcensus/releases/latest/download"
Invoke-WebRequest "$release/hostcensus-windows-amd64.exe" -OutFile hostcensus-windows-amd64.exe
Invoke-WebRequest "$release/SHA256SUMS" -OutFile SHA256SUMS
(Get-FileHash hostcensus-windows-amd64.exe).Hash -eq (Select-String hostcensus-windows-amd64.exe SHA256SUMS).Line.Split()[0]
.\hostcensus-windows-amd64.exe --output inventory.json
```

The check prints `OK` on Linux and macOS and `True` on Windows. Do not run a
file that fails the check.

The host itself needs no internet access. Download the two files on another
machine and copy them over.

## Take a census

The examples call the binary `hostcensus`. Rename the file, or put it on your
`PATH`, to do the same.

```bash
sudo hostcensus                 # writes hostcensus-<hostname>-<time>.json
sudo hostcensus --output census.json
hostcensus --output -           # to standard output
```

Run it as root, or from an elevated prompt on Windows. Root adds other users'
processes and the files they write to, the process that owns each listening
port, journal activity, log directories that only root can read, and
containers and their logs where the runtime socket belongs to root.

hostcensus never raises its own privileges, and it works without them. A
census taken without them lists what exists and cannot show what runs without
producing logs. Each scanner says in the bundle whether it saw everything.

The file is plain JSON, written so a person can read it before they hand it to
anyone. Nothing is sent anywhere.

A census reads every directory under the scan paths. Where they hold tens of
thousands of directories it takes minutes, and every five seconds it says on
standard error which scan path it is under and how many directories it has
read.

One kind of directory is not read: where a container runtime keeps the layers
of its images, such as `C:\ProgramData\docker\windowsfilter` or
`/var/lib/docker/overlay2`. A file inside an image is not a log the host
writes, and what a container logs is listed with the container. The census
names each such directory it left alone, in the summary and under the `files`
scanner in the bundle. `DATA.md` lists them all, and says which stores it does
not recognise.

It lists log files, containers, systemd services, processes, listening ports
and installed packages, and says for each of these how completely it could
look. Run it as root to see the whole host; without root it reports what it
could not see.

```bash
hostcensus --scan-path /var/log --scan-path /srv/app/log   # where to look for log files
hostcensus --ext log --ext txt                             # what counts as a log file
hostcensus --max-age-days 30                               # how recently it was written
hostcensus --exclude '*.gz' --exclude '/var/log/journal/**'
```

By default a census records the executable of each process, not its
arguments, and the values of well-known container labels only.
`--process-args` and `--all-label-values` record everything, which can include
secrets.

The census shows what a host produces, not what is already collected. That is
recorded separately, one source at a time:

```bash
hostcensus mark --bundle census.json \
  --source log_file:/var/log/nginx/access.log \
  --collected yes --collector fluent-bit \
  --evidence /etc/fluent-bit/fluent-bit.conf:14
```

`hostcensus coverage --bundle census.json` lists every source with what has
been said about it, one per line, and the totals.

An identifier with `*` or `?` marks every source it matches:
`--source 'log_file:/var/log/nginx/*.log'`.

- `docs/bundle-format.md`: what the file contains.
- `DATA.md`: everything the tool reads, runs and writes.
- `skills/`: two skills for a coding agent working on the host.
  `hostcensus-run` takes a census with a person and goes through the result.
  `hostcensus-mark-coverage` finds what already collects logs, checks that it
  runs, and records what is collected.

Linux, macOS and Windows are supported. On Windows a census lists services
and event-log channels in place of systemd services and packages. Every
release binary takes a census on a hosted CI runner of its own platform before
it is published. For Windows that runner, a Windows Server 2022, is the only
host the build has run on so far.

## License

[HostCensus Source-Available License 1.0](LICENSE). Run it free of charge on
computers you own or operate, keep the bundles it writes, and use them with
LogPacer. Using it or its output with a competing product or service, offering
it to others as a service, building it into other software, or distributing
modified copies needs written permission from LogPacer. This is
source-available software, not an open-source license. Third-party crates keep
their own licenses; see [LICENSE-3rdparty.csv](LICENSE-3rdparty.csv).
