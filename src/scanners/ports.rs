//! Listening ports and the processes that own them.
//!
//! Linux reads the socket tables in `/proc`, including those of other network
//! namespaces so listeners inside containers show up with their real process.
//! Other Unix systems, and Linux when `/proc` cannot be read, ask `lsof`.
//! Windows asks `netstat`.

use super::Scanned;
use super::command;
use crate::bundle::ScannerReport;
use crate::inventory::ListeningPort;

/// `netstat -ano` names the owning process of every socket by its id, to any
/// user, so the result does not depend on elevation.
#[cfg(windows)]
pub(crate) async fn scan(_privileged: bool) -> Scanned<Vec<ListeningPort>> {
    let listing = match command::stdout_of("netstat", &["-ano"]).await {
        Ok(listing) => listing,
        Err(error) => {
            return Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string()));
        }
    };
    let ports = parse_netstat(&listing);
    let unnamed = ports.clone();
    match tokio::task::spawn_blocking(move || windows::with_owner_names(ports)).await {
        Ok(Some(named)) => Scanned::complete(named),
        Ok(None) | Err(_) => Scanned::new(
            unnamed,
            ScannerReport::partial(
                "the processes that own the ports could not be named; each port has the id of \
                 its owner",
            ),
        ),
    }
}

/// Listening TCP sockets and bound UDP sockets in `netstat -ano` output:
///
/// ```text
///   Proto  Local Address          Foreign Address        State           PID
///   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
///   UDP    0.0.0.0:5353           *:*                                    777
/// ```
///
/// The headings and the state are translated on a non-English Windows, so
/// neither is read. A TCP row is a listener when its foreign address has port
/// 0, which is what a socket without a peer shows in any language. The owner
/// is the last column.
#[cfg(any(windows, test))]
fn parse_netstat(output: &str) -> Vec<ListeningPort> {
    let mut ports: Vec<ListeningPort> = output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (protocol, local, foreign) = match parts.as_slice() {
                [protocol, local, foreign, _, ..] => {
                    (protocol.to_ascii_lowercase(), local, foreign)
                }
                _ => return None,
            };
            let listening = match protocol.as_str() {
                "tcp" => foreign.ends_with(":0"),
                "udp" => true,
                _ => false,
            };
            if !listening {
                return None;
            }
            Some(ListeningPort {
                port: local.rsplit(':').next()?.parse().ok()?,
                protocol,
                process: String::new(),
                pid: parts.last()?.parse().ok()?,
            })
        })
        .collect();

    ports.sort_by_key(|p| (p.port, p.protocol.clone(), p.pid));
    ports.dedup_by_key(|p| (p.port, p.protocol.clone(), p.pid));
    ports
}

#[cfg(windows)]
mod windows {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    use super::ListeningPort;

    /// Only the image name of each owner is read, nothing else about it.
    /// `None` when Windows would not list processes at all.
    pub(super) fn with_owner_names(mut ports: Vec<ListeningPort>) -> Option<Vec<ListeningPort>> {
        let mut owners: Vec<Pid> = ports.iter().map(|port| Pid::from_u32(port.pid)).collect();
        owners.sort_unstable();
        owners.dedup();

        let mut system = System::new().ok()?;
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&owners),
            true,
            ProcessRefreshKind::nothing(),
        );
        for port in &mut ports {
            if let Some(owner) = system.process(Pid::from_u32(port.pid)) {
                port.process = owner.name().to_string_lossy().into_owned();
            }
        }
        Some(ports)
    }
}

#[cfg(unix)]
pub(crate) async fn scan(privileged: bool) -> Scanned<Vec<ListeningPort>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(Some(ports)) = tokio::task::spawn_blocking(linux::read_proc).await {
            return Scanned::new(ports.clone(), linux_report(&ports, privileged));
        }
    }
    ask_lsof(privileged).await
}

#[cfg(any(target_os = "linux", test))]
fn linux_report(ports: &[ListeningPort], privileged: bool) -> ScannerReport {
    if privileged {
        return ScannerReport::complete();
    }
    let caveat = "listeners inside containers may be missing";
    ScannerReport::partial(match ports.iter().filter(|port| port.pid == 0).count() {
        0 => format!("without root, {caveat}"),
        1 => format!("without root, 1 listening socket has no visible owner and {caveat}"),
        ownerless => format!(
            "without root, {ownerless} listening sockets have no visible owner and {caveat}"
        ),
    })
}

#[cfg(unix)]
async fn ask_lsof(privileged: bool) -> Scanned<Vec<ListeningPort>> {
    // `-n` and `-P` keep lsof from looking up host and service names. It
    // exits with a failure status when it cannot see every process, which is
    // the normal case without root, so the status is not checked.
    match command::run_within("lsof", &["-i", "-P", "-n"], command::TIME_LIMIT).await {
        Ok(output) => {
            let ports = parse_lsof_output(&String::from_utf8_lossy(&output.stdout));
            let report = if privileged {
                ScannerReport::complete()
            } else {
                ScannerReport::partial(
                    "without root, lsof only shows the sockets of your own processes",
                )
            };
            Scanned::new(ports, report)
        }
        Err(error) => Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string())),
    }
}

/// Listening TCP sockets and bound UDP sockets in `lsof -i -P -n` output:
///
/// ```text
/// COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
/// sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)
/// dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53
/// ```
#[cfg(any(unix, test))]
fn parse_lsof_output(output: &str) -> Vec<ListeningPort> {
    let mut ports: Vec<ListeningPort> = output
        .lines()
        .skip(1)
        .filter(|line| line.contains("(LISTEN)") || line.contains(" UDP "))
        .filter_map(parse_lsof_line)
        .collect();

    ports.sort_by_key(|p| (p.port, p.protocol.clone(), p.pid));
    ports.dedup_by_key(|p| (p.port, p.protocol.clone(), p.pid));
    ports
}

#[cfg(any(unix, test))]
fn parse_lsof_line(line: &str) -> Option<ListeningPort> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        return None;
    }

    let protocol = parts[7].to_lowercase();
    if protocol != "tcp" && protocol != "udp" {
        return None;
    }

    // NAME is `*:22`, `[::1]:5432` or `127.0.0.1:8080`.
    let port = parts[8].rsplit(':').next()?.parse().ok()?;

    Some(ListeningPort {
        port,
        protocol,
        process: parts[0].to_string(),
        pid: parts[1].parse().ok()?,
    })
}

/// `(local port, socket inode)` for each row in LISTEN state of a
/// `/proc/<pid>/net/tcp` or `tcp6` table. Columns: 1 is the local address
/// (hex `ip:port`), 3 the state (`0A` is LISTEN), 9 the inode.
#[cfg(any(target_os = "linux", test))]
fn listen_ports_from_proc_net_tcp(table: &str) -> Vec<(u16, u64)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if *cols.get(3)? != "0A" {
                return None;
            }
            let port = u16::from_str_radix(cols.get(1)?.rsplit(':').next()?, 16).ok()?;
            let inode: u64 = cols.get(9)?.parse().ok()?;
            Some((port, inode))
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::fs;

    use procfs::net::{TcpState, tcp, tcp6, udp, udp6};

    use super::{ListeningPort, listen_ports_from_proc_net_tcp};

    /// `None` when the host socket tables cannot be read.
    pub(super) fn read_proc() -> Option<Vec<ListeningPort>> {
        // Which process holds which socket, and one process per network
        // namespace through which that namespace's tables can be read.
        let mut socket_owner: HashMap<u64, (u32, String)> = HashMap::new();
        let mut namespace_member: HashMap<u64, u32> = HashMap::new();

        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };

            if let Some(namespace) = netns_inode(&format!("/proc/{pid}/ns/net")) {
                namespace_member.entry(namespace).or_insert(pid);
            }

            let name = fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default()
                .trim()
                .to_string();

            let Ok(descriptors) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for descriptor in descriptors.flatten() {
                if let Ok(link) = fs::read_link(descriptor.path())
                    && let Some(inode) = link
                        .to_string_lossy()
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|inode| inode.parse::<u64>().ok())
                {
                    socket_owner.insert(inode, (pid, name.clone()));
                }
            }
        }

        let owner_of = |inode: u64| socket_owner.get(&inode).cloned();
        let mut ports = Vec::new();

        let tcp_v4 = tcp();
        let tcp_v6 = tcp6();
        if tcp_v4.is_err() && tcp_v6.is_err() {
            return None;
        }
        for socket in tcp_v4
            .unwrap_or_default()
            .into_iter()
            .chain(tcp_v6.unwrap_or_default())
        {
            if socket.state != TcpState::Listen {
                continue;
            }
            let (pid, process) = owner_of(socket.inode).unwrap_or_default();
            ports.push(ListeningPort {
                port: socket.local_address.port(),
                protocol: "tcp".to_string(),
                process,
                pid,
            });
        }

        // UDP has no LISTEN state: every bound socket counts.
        for socket in udp()
            .unwrap_or_default()
            .into_iter()
            .chain(udp6().unwrap_or_default())
        {
            let port = socket.local_address.port();
            if port == 0 {
                continue;
            }
            let (pid, process) = owner_of(socket.inode).unwrap_or_default();
            ports.push(ListeningPort {
                port,
                protocol: "udp".to_string(),
                process,
                pid,
            });
        }

        // A listener inside a container lives in its own network namespace
        // and is absent from the host tables, which show only the proxy on
        // the published port. Read each other namespace through one of its
        // processes. A row whose owner cannot be resolved adds nothing here.
        let own_namespace = netns_inode("/proc/self/ns/net");
        for (namespace, pid) in namespace_member {
            if Some(namespace) == own_namespace {
                continue;
            }
            for table in ["tcp", "tcp6"] {
                let Ok(content) = fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
                    continue;
                };
                for (port, inode) in listen_ports_from_proc_net_tcp(&content) {
                    if let Some((pid, process)) = owner_of(inode) {
                        ports.push(ListeningPort {
                            port,
                            protocol: "tcp".to_string(),
                            process,
                            pid,
                        });
                    }
                }
            }
        }

        // IPv4 and IPv6 report the same listener twice. The pid stays in the
        // key so distinct owners of one port survive.
        ports.sort_by_key(|p| (p.port, p.protocol.clone(), p.pid));
        ports.dedup_by_key(|p| (p.port, p.protocol.clone(), p.pid));
        Some(ports)
    }

    /// The inode in a `/proc/<pid>/ns/net` link, which reads `net:[4026531840]`.
    fn netns_inode(path: &str) -> Option<u64> {
        let link = fs::read_link(path).ok()?;
        let link = link.to_string_lossy();
        link.strip_prefix("net:[")?.strip_suffix(']')?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Header and one row per socket. 0100007F:1F90 is 127.0.0.1:8080 in
    // LISTEN (0A); the second row is an established connection (01); the
    // third listens on 0.0.0.0:80.
    const SAMPLE_PROC_NET_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 424242 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 424243 1 0000000000000000 20 4 30 10 -1\n   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 424244 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn listen_rows_parse_port_and_inode() {
        let rows = listen_ports_from_proc_net_tcp(SAMPLE_PROC_NET_TCP);
        assert_eq!(vec![(8080, 424242), (80, 424244)], rows);
    }

    #[test]
    fn non_listen_states_are_skipped() {
        let rows = listen_ports_from_proc_net_tcp(SAMPLE_PROC_NET_TCP);
        assert!(!rows.iter().any(|(_, inode)| *inode == 424243));
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let rows = listen_ports_from_proc_net_tcp("header\ngarbage line\n   0: nonsense\n");
        assert!(rows.is_empty());
    }

    const SAMPLE_LSOF: &str = r#"COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)
sshd        843   root    4u  IPv6 0x12346      0t0  TCP [::]:22 (LISTEN)
postgres   1234   morten  5u  IPv6 0x67890      0t0  TCP [::1]:5432 (LISTEN)
node       5678   morten  18u IPv4 0xabc12      0t0  TCP 127.0.0.1:3000 (LISTEN)
dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53
chrome     9999   morten  42u IPv4 0xdeadb      0t0  TCP 192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
"#;

    #[test]
    fn parse_lsof_listen_ports() {
        let ports = parse_lsof_output(SAMPLE_LSOF);
        assert!(ports.iter().any(|p| p.port == 22 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 5432 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 3000 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 53 && p.protocol == "udp"));
        assert!(!ports.iter().any(|p| p.port == 54321));
        assert_eq!(ports.iter().filter(|p| p.port == 22).count(), 1);
    }

    #[test]
    fn parse_lsof_line_tcp_listen() {
        let line = "sshd        843   root    3u  IPv4 0x12345      0t0  TCP *:22 (LISTEN)";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 22);
        assert_eq!(port.protocol, "tcp");
        assert_eq!(port.process, "sshd");
        assert_eq!(port.pid, 843);
    }

    #[test]
    fn parse_lsof_line_udp() {
        let line = "dnsmasq     567   nobody  4u  IPv4 0xabcde      0t0  UDP *:53";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 53);
        assert_eq!(port.protocol, "udp");
        assert_eq!(port.process, "dnsmasq");
        assert_eq!(port.pid, 567);
    }

    #[test]
    fn parse_lsof_ipv6_brackets() {
        let line = "postgres   1234   morten  5u  IPv6 0x67890      0t0  TCP [::1]:5432 (LISTEN)";
        let port = parse_lsof_line(line).unwrap();
        assert_eq!(port.port, 5432);
        assert_eq!(port.protocol, "tcp");
    }

    #[test]
    fn an_unprivileged_linux_scan_says_how_many_owners_it_could_not_see() {
        let port = |pid| ListeningPort {
            port: 80,
            protocol: "tcp".into(),
            process: String::new(),
            pid,
        };
        let ports = [port(0), port(0), port(812)];

        assert_eq!(linux_report(&ports, true), ScannerReport::complete());
        let report = linux_report(&ports, false);
        assert_eq!(report.status, crate::bundle::ScannerStatus::Partial);
        assert!(report.reason.unwrap().contains("2 listening sockets have"));
        assert!(
            linux_report(&ports[1..], false)
                .reason
                .unwrap()
                .contains("1 listening socket has")
        );
        assert_eq!(
            linux_report(&ports[2..], false).reason.unwrap(),
            "without root, listeners inside containers may be missing"
        );
    }

    /// English Windows.
    const NETSTAT_ENGLISH: &str = "\r
Active Connections\r
\r
  Proto  Local Address          Foreign Address        State           PID\r
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\r
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r
  TCP    127.0.0.1:51000        127.0.0.1:443          ESTABLISHED     5000\r
  TCP    10.0.0.12:52311        203.0.113.9:443        TIME_WAIT       0\r
  TCP    [::]:135               [::]:0                 LISTENING       1234\r
  TCP    [::]:8443              [::]:0                 LISTENING       6120\r
  UDP    0.0.0.0:5353           *:*                                    777\r
  UDP    [::1]:1900             *:*                                    3320\r
";

    /// The same sockets as a German Windows prints them: other headings and
    /// another word for the listening state.
    const NETSTAT_GERMAN: &str = "\r
Aktive Verbindungen\r
\r
  Proto  Lokale Adresse         Remoteadresse          Status           PID\r
  TCP    0.0.0.0:135            0.0.0.0:0              ABH\u{d6}REN         1234\r
  TCP    0.0.0.0:445            0.0.0.0:0              ABH\u{d6}REN         4\r
  TCP    127.0.0.1:51000        127.0.0.1:443          HERGESTELLT     5000\r
  TCP    10.0.0.12:52311        203.0.113.9:443        WARTEND         0\r
  TCP    [::]:135               [::]:0                 ABH\u{d6}REN         1234\r
  TCP    [::]:8443              [::]:0                 ABH\u{d6}REN         6120\r
  UDP    0.0.0.0:5353           *:*                                    777\r
  UDP    [::1]:1900             *:*                                    3320\r
";

    fn listeners(output: &str) -> Vec<(u16, String, u32)> {
        parse_netstat(output)
            .into_iter()
            .map(|port| (port.port, port.protocol, port.pid))
            .collect()
    }

    #[test]
    fn netstat_rows_that_listen_are_kept_with_their_owner() {
        assert_eq!(
            listeners(NETSTAT_ENGLISH),
            [
                (135, "tcp".to_string(), 1234),
                (445, "tcp".to_string(), 4),
                (1900, "udp".to_string(), 3320),
                (5353, "udp".to_string(), 777),
                (8443, "tcp".to_string(), 6120),
            ]
        );
    }

    #[test]
    fn netstat_is_read_the_same_in_another_language() {
        assert_eq!(listeners(NETSTAT_GERMAN), listeners(NETSTAT_ENGLISH));
    }

    #[test]
    fn netstat_lines_that_are_not_sockets_are_skipped() {
        assert!(parse_netstat("").is_empty());
        assert!(
            parse_netstat("Active Connections\r\n\r\n  Proto  Local Address  PID\r\n").is_empty()
        );
        assert!(
            parse_netstat("  TCP    0.0.0.0:notaport   0.0.0.0:0   LISTENING   12\r\n").is_empty()
        );
        assert!(
            parse_netstat("  TCP    0.0.0.0:80   0.0.0.0:0   LISTENING   notapid\r\n").is_empty()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_scan_always_reports_how_it_went() {
        let scanned = scan(false).await;

        assert!(scanned.report.reason.is_some(), "{:?}", scanned.report);
    }
}
