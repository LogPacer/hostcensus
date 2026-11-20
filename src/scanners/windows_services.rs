//! Windows services, as `sc queryex` lists them.
//!
//! `sc` prints for people, in the language and the code page of the console.
//! So nothing here reads a field label: a record is read by its shape, and
//! the state of a service by its number, both of which are the same in every
//! language.

use crate::bundle::ScannerReport;
use crate::inventory::WindowsService;

#[cfg(windows)]
pub(crate) async fn scan() -> super::Scanned<Vec<WindowsService>> {
    use super::{Scanned, command};

    let output = match command::run_within(
        "sc",
        &["queryex", "type=", "service", "state=", "all"],
        command::TIME_LIMIT,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            return Scanned::new(Vec::new(), ScannerReport::unavailable(error.to_string()));
        }
    };
    if !output.status.success() {
        return Scanned::new(
            Vec::new(),
            ScannerReport::unavailable("sc could not list the services"),
        );
    }

    // `sc` writes in the console code page, not UTF-8.
    let (listing, readable_text) = match String::from_utf8(output.stdout) {
        Ok(listing) => (listing, true),
        Err(not_utf8) => (
            String::from_utf8_lossy(not_utf8.as_bytes()).into_owned(),
            false,
        ),
    };
    let listed = parse_sc_queryex(&listing);
    let report = report(&listed, readable_text);
    Scanned::new(listed.services, report)
}

#[derive(Debug, Default)]
struct Listed {
    services: Vec<WindowsService>,
    /// Services whose state was not the number `sc` always prints.
    states_not_read: usize,
}

fn report(listed: &Listed, readable_text: bool) -> ScannerReport {
    if listed.services.is_empty() {
        return ScannerReport::unavailable("sc listed no service in a form hostcensus can read");
    }
    let mut gaps = Vec::new();
    match listed.states_not_read {
        0 => {}
        1 => gaps.push("the state of 1 service could not be read".to_string()),
        count => gaps.push(format!("the state of {count} services could not be read")),
    }
    if !readable_text {
        gaps.push(
            "sc wrote in the console code page, so display names with characters outside ASCII \
             are garbled"
                .to_string(),
        );
    }
    if gaps.is_empty() {
        ScannerReport::complete()
    } else {
        ScannerReport::partial(gaps.join("; "))
    }
}

/// Reads `sc queryex` output by its shape:
///
/// ```text
/// SERVICE_NAME: EventLog
/// DISPLAY_NAME: Windows Event Log
///         TYPE               : 30  WIN32
///         STATE              : 4  RUNNING
///                                 (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
///         WIN32_EXIT_CODE    : 0  (0x0)
///         SERVICE_EXIT_CODE  : 0  (0x0)
///         CHECKPOINT         : 0x0
///         WAIT_HINT          : 0x0
///         PID                : 2112
///         FLAGS              :
/// ```
///
/// A record is two lines at the left margin, the name and the display name,
/// followed by indented `label : value` lines. The first indented value is
/// the type, the second the state, the seventh the process id. The labels
/// themselves are not looked at, because a translated `sc` prints others.
fn parse_sc_queryex(output: &str) -> Listed {
    let mut listed = Listed::default();
    let mut record = Record::default();

    for line in output.lines() {
        if line.trim().is_empty() {
            record.finish_into(&mut listed);
            continue;
        }
        let indented = line.starts_with(char::is_whitespace);
        let Some((label, value)) = line.split_once(':') else {
            // The second line of a state, which lists what the service accepts.
            continue;
        };
        if indented {
            record.fields.push((label.trim(), value.trim()));
        } else {
            if !record.fields.is_empty() {
                record.finish_into(&mut listed);
            }
            record.headings.push(value.trim());
        }
    }
    record.finish_into(&mut listed);
    listed
}

#[derive(Default)]
struct Record<'a> {
    headings: Vec<&'a str>,
    fields: Vec<(&'a str, &'a str)>,
}

impl Record<'_> {
    /// Adds the record to `listed` if it has the shape of a service, and
    /// starts a new one either way. Anything else `sc` prints, such as an
    /// error line, has no indented lines and is dropped here.
    fn finish_into(&mut self, listed: &mut Listed) {
        let record = std::mem::take(self);
        let (Some(name), [(_, kind), (_, state), ..]) =
            (record.headings.first(), record.fields.as_slice())
        else {
            return;
        };
        if name.is_empty() {
            return;
        }

        let state = match state_name(state) {
            Some(state) => state.to_string(),
            None => {
                listed.states_not_read += 1;
                "unknown".to_string()
            }
        };
        let pid = record
            .fields
            .iter()
            .find(|(label, _)| *label == "PID")
            .or_else(|| record.fields.get(6))
            .and_then(|(_, pid)| pid.parse().ok())
            .unwrap_or(0);

        listed.services.push(WindowsService {
            name: name.to_string(),
            display_name: record
                .headings
                .get(1)
                .filter(|display_name| !display_name.is_empty())
                .unwrap_or(name)
                .to_string(),
            state,
            service_type: text_after_code(kind).to_ascii_lowercase(),
            pid,
        });
    }
}

/// The state of a service from the number `sc` prints in front of its name
/// for it, as in `4  RUNNING`. The number is the service-control constant and
/// does not change with the language.
fn state_name(value: &str) -> Option<&'static str> {
    match value.split_whitespace().next()?.parse::<u32>().ok()? {
        1 => Some("stopped"),
        2 => Some("start_pending"),
        3 => Some("stop_pending"),
        4 => Some("running"),
        5 => Some("continue_pending"),
        6 => Some("pause_pending"),
        7 => Some("paused"),
        _ => None,
    }
}

/// `WIN32_SHARE_PROCESS` from `20  WIN32_SHARE_PROCESS`; the code itself when
/// nothing follows it.
fn text_after_code(value: &str) -> String {
    let mut parts = value.split_whitespace();
    let code = parts.next().unwrap_or_default();
    let text = parts.collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        code.to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape an English Windows Server prints. The services are invented
    /// except for the ones every Windows has.
    const ENGLISH: &str = "\r
SERVICE_NAME: EventLog\r
DISPLAY_NAME: Windows Event Log\r
        TYPE               : 30  WIN32\r
        STATE              : 4  RUNNING\r
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r
        WIN32_EXIT_CODE    : 0  (0x0)\r
        SERVICE_EXIT_CODE  : 0  (0x0)\r
        CHECKPOINT         : 0x0\r
        WAIT_HINT          : 0x0\r
        PID                : 2112\r
        FLAGS              :\r
\r
SERVICE_NAME: ALG\r
DISPLAY_NAME: Application Layer Gateway Service\r
        TYPE               : 10  WIN32_OWN_PROCESS\r
        STATE              : 1  STOPPED\r
        WIN32_EXIT_CODE    : 1077  (0x435)\r
        SERVICE_EXIT_CODE  : 0  (0x0)\r
        CHECKPOINT         : 0x0\r
        WAIT_HINT          : 0x0\r
        PID                : 0\r
        FLAGS              :\r
\r
SERVICE_NAME: ShopApi\r
DISPLAY_NAME: Shop: API\r
        TYPE               : 10  WIN32_OWN_PROCESS\r
        STATE              : 2  START_PENDING\r
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\r
        WIN32_EXIT_CODE    : 0  (0x0)\r
        SERVICE_EXIT_CODE  : 0  (0x0)\r
        CHECKPOINT         : 0x1\r
        WAIT_HINT          : 0x7d0\r
        PID                : 6120\r
        FLAGS              :\r
\r
SERVICE_NAME: cbdhsvc_4f1a2\r
DISPLAY_NAME: Clipboard User Service_4f1a2\r
        TYPE               : e0  USER_SHARE_PROCESS INSTANCE\r
        STATE              : 4  RUNNING\r
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r
        WIN32_EXIT_CODE    : 0  (0x0)\r
        SERVICE_EXIT_CODE  : 0  (0x0)\r
        CHECKPOINT         : 0x0\r
        WAIT_HINT          : 0x0\r
        PID                : 9044\r
        FLAGS              :\r
";

    /// The same shape with every label replaced. The labels are made up: what
    /// a translated `sc` really prints was not available, and the point is
    /// that the parser does not care.
    const OTHER_LABELS: &str = "\r
DIENSTNAME: EventLog\r
ANZEIGENAME: Windows-Ereignisprotokoll\r
        TYP                : 30  WIN32\r
        STATUS             : 4  RUNNING\r
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r
        WIN32_EXITCODE     : 0  (0x0)\r
        DIENST_EXITCODE    : 0  (0x0)\r
        PRUEFPUNKT         : 0x0\r
        WARTEHINWEIS       : 0x0\r
        PROZESS            : 2112\r
        KENNZEICHEN        :\r
\r
DIENSTNAME: ALG\r
ANZEIGENAME: Gatewaydienst auf Anwendungsebene\r
        TYP                : 10  WIN32_OWN_PROCESS\r
        STATUS             : 1  BEENDET\r
        WIN32_EXITCODE     : 1077  (0x435)\r
        DIENST_EXITCODE    : 0  (0x0)\r
        PRUEFPUNKT         : 0x0\r
        WARTEHINWEIS       : 0x0\r
        PROZESS            : 0\r
        KENNZEICHEN        :\r
";

    fn service<'a>(listed: &'a Listed, name: &str) -> &'a WindowsService {
        listed
            .services
            .iter()
            .find(|service| service.name == name)
            .unwrap()
    }

    #[test]
    fn parses_sc_queryex_services() {
        let listed = parse_sc_queryex(ENGLISH);

        assert_eq!(listed.services.len(), 4);
        assert_eq!(listed.states_not_read, 0);

        let event_log = service(&listed, "EventLog");
        assert_eq!(event_log.display_name, "Windows Event Log");
        assert_eq!(event_log.state, "running");
        assert_eq!(event_log.service_type, "win32");
        assert_eq!(event_log.pid, 2112);

        let alg = service(&listed, "ALG");
        assert_eq!(alg.state, "stopped");
        assert_eq!(alg.service_type, "win32_own_process");
        assert_eq!(alg.pid, 0);
    }

    #[test]
    fn a_display_name_may_hold_a_colon_and_a_state_may_be_pending() {
        let listed = parse_sc_queryex(ENGLISH);

        let api = service(&listed, "ShopApi");
        assert_eq!(api.display_name, "Shop: API");
        assert_eq!(api.state, "start_pending");
        assert_eq!(api.pid, 6120);
    }

    #[test]
    fn a_type_of_several_words_is_kept_whole() {
        let listed = parse_sc_queryex(ENGLISH);

        assert_eq!(
            service(&listed, "cbdhsvc_4f1a2").service_type,
            "user_share_process instance"
        );
        assert_eq!(service(&listed, "cbdhsvc_4f1a2").pid, 9044);
    }

    #[test]
    fn the_labels_are_not_read_so_another_language_parses_the_same() {
        let listed = parse_sc_queryex(OTHER_LABELS);

        assert_eq!(listed.services.len(), 2);
        assert_eq!(listed.states_not_read, 0);

        let event_log = service(&listed, "EventLog");
        assert_eq!(event_log.display_name, "Windows-Ereignisprotokoll");
        assert_eq!(event_log.state, "running");
        assert_eq!(event_log.service_type, "win32");
        assert_eq!(event_log.pid, 2112);

        // The state comes from its number, not from the word after it.
        assert_eq!(service(&listed, "ALG").state, "stopped");
    }

    #[test]
    fn display_name_falls_back_to_service_name() {
        let listed = parse_sc_queryex(
            "SERVICE_NAME: EventLog\r
        TYPE               : 30  WIN32\r
        STATE              : 4  RUNNING\r
        PID                : 2112\r
",
        );

        assert_eq!(listed.services.len(), 1);
        assert_eq!(listed.services[0].display_name, "EventLog");
        assert_eq!(listed.services[0].pid, 2112);
    }

    #[test]
    fn records_need_no_blank_line_between_them() {
        let listed = parse_sc_queryex(
            "SERVICE_NAME: A\r
DISPLAY_NAME: First\r
        TYPE               : 10  WIN32_OWN_PROCESS\r
        STATE              : 4  RUNNING\r
SERVICE_NAME: B\r
DISPLAY_NAME: Second\r
        TYPE               : 20  WIN32_SHARE_PROCESS\r
        STATE              : 7  PAUSED\r
",
        );

        let names: Vec<_> = listed
            .services
            .iter()
            .map(|service| (service.name.as_str(), service.state.as_str()))
            .collect();
        assert_eq!(names, [("A", "running"), ("B", "paused")]);
    }

    #[test]
    fn what_is_not_a_service_record_is_dropped() {
        let listed = parse_sc_queryex(
            "[SC] EnumServicesStatus:OpenSCManager FAILED 5:\r
\r
Access is denied.\r
\r
",
        );

        assert!(listed.services.is_empty());
        assert_eq!(
            report(&listed, true),
            ScannerReport::unavailable("sc listed no service in a form hostcensus can read")
        );
    }

    #[test]
    fn a_state_that_is_not_a_known_number_is_counted() {
        let listed = parse_sc_queryex(
            "SERVICE_NAME: Odd\r
DISPLAY_NAME: Odd\r
        TYPE               : 10  WIN32_OWN_PROCESS\r
        STATE              : RUNNING\r
",
        );

        assert_eq!(listed.services[0].state, "unknown");
        assert_eq!(
            report(&listed, true),
            ScannerReport::partial("the state of 1 service could not be read")
        );
    }

    #[test]
    fn output_that_is_not_utf8_makes_the_scan_partial() {
        let listed = parse_sc_queryex(ENGLISH);

        assert_eq!(report(&listed, true), ScannerReport::complete());
        assert_eq!(
            report(&listed, false),
            ScannerReport::partial(
                "sc wrote in the console code page, so display names with characters outside \
                 ASCII are garbled"
            )
        );
    }
}
