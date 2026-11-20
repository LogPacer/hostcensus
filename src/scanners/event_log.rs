//! Windows Event Log channels.
//!
//! Windows defines around a thousand channels and most are empty. The census
//! lists the classic ones, every other channel that holds records, and every
//! channel that refused to say.

use super::Scanned;
use crate::bundle::ScannerReport;
use crate::inventory::EventLogChannel;

/// Listed even when empty: the channels a person expects to see.
const CLASSIC_CHANNELS: &[&str] = &[
    "Application",
    "System",
    "Security",
    "Setup",
    "ForwardedEvents",
];

/// What asking one channel for its record count gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    Records(u64),
    /// Windows refused access. `Security` does this without elevation.
    Denied,
    /// The channel could not be opened for another reason.
    Unreadable,
}

#[cfg(windows)]
pub(crate) async fn scan() -> Scanned<Vec<EventLogChannel>> {
    match tokio::task::spawn_blocking(probe).await {
        Ok(Ok(probed)) => select(&probed),
        Ok(Err(reason)) => Scanned::new(Vec::new(), ScannerReport::unavailable(reason)),
        Err(_) => Scanned::new(
            Vec::new(),
            ScannerReport::unavailable("listing the event-log channels stopped unexpectedly"),
        ),
    }
}

/// Every channel that is not a trace channel, with its record count.
#[cfg(windows)]
fn probe() -> Result<Vec<(String, Count)>, String> {
    use super::event_log_api;

    let channels = event_log_api::channel_names().map_err(|error| error.to_string())?;
    Ok(channels
        .into_iter()
        .filter(|channel| !is_trace_channel(channel))
        .map(|channel| {
            let count = match event_log_api::record_count(&channel) {
                Ok(records) => Count::Records(records),
                Err(error) if error.is_access_denied() => Count::Denied,
                Err(_) => Count::Unreadable,
            };
            (channel, count)
        })
        .collect())
}

/// Keeps the classic channels, the channels with records, and the channels
/// that refused access: a channel nobody may read is not an empty one.
fn select(probed: &[(String, Count)]) -> Scanned<Vec<EventLogChannel>> {
    let mut channels: Vec<EventLogChannel> = probed
        .iter()
        .filter_map(|(channel, count)| {
            let record_count = match count {
                Count::Records(records) => *records,
                Count::Denied | Count::Unreadable => 0,
            };
            let keep = is_classic(channel) || record_count > 0 || *count == Count::Denied;
            keep.then(|| EventLogChannel {
                channel: channel.clone(),
                record_count,
            })
        })
        .collect();
    channels.sort_by(|a, b| a.channel.cmp(&b.channel));

    let mut denied: Vec<&str> = probed
        .iter()
        .filter(|(_, count)| *count == Count::Denied)
        .map(|(channel, _)| channel.as_str())
        .collect();
    denied.sort_by_key(|channel| (!is_classic(channel), *channel));
    let unreadable = probed
        .iter()
        .filter(|(_, count)| *count == Count::Unreadable)
        .count();

    Scanned::new(channels, report(&denied, unreadable))
}

fn report(denied: &[&str], unreadable: usize) -> ScannerReport {
    const NAMED: usize = 3;

    let mut gaps = Vec::new();
    if !denied.is_empty() {
        let mut names = denied
            .iter()
            .take(NAMED)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if denied.len() > NAMED {
            names = format!("{names} and {} more", denied.len() - NAMED);
        }
        gaps.push(format!(
            "{} refused access, so {} listed with 0 records: {names}; run elevated to count them",
            plural(denied.len(), "channel"),
            if denied.len() == 1 {
                "it is"
            } else {
                "they are"
            },
        ));
    }
    if unreadable > 0 {
        gaps.push(format!(
            "{} could not be opened",
            plural(unreadable, "channel")
        ));
    }
    if gaps.is_empty() {
        ScannerReport::complete()
    } else {
        ScannerReport::partial(gaps.join("; "))
    }
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Debug and analytic channels are high-volume traces, usually disabled.
#[cfg(any(windows, test))]
fn is_trace_channel(channel: &str) -> bool {
    channel.ends_with("/Debug") || channel.ends_with("/Analytic")
}

fn is_classic(channel: &str) -> bool {
    CLASSIC_CHANNELS
        .iter()
        .any(|classic| classic.eq_ignore_ascii_case(channel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ScannerStatus;

    fn probed(channels: &[(&str, Count)]) -> Vec<(String, Count)> {
        channels
            .iter()
            .map(|(channel, count)| (channel.to_string(), *count))
            .collect()
    }

    fn names(scanned: &Scanned<Vec<EventLogChannel>>) -> Vec<(&str, u64)> {
        scanned
            .found
            .iter()
            .map(|channel| (channel.channel.as_str(), channel.record_count))
            .collect()
    }

    #[test]
    fn drops_debug_and_analytic_trace_channels() {
        assert!(is_trace_channel("Microsoft-Windows-WinRM/Debug"));
        assert!(is_trace_channel("Microsoft-Windows-Kernel-WHEA/Analytic"));
        assert!(!is_trace_channel("Microsoft-Windows-WinRM/Operational"));
        assert!(!is_trace_channel("Application"));
    }

    #[test]
    fn classics_are_recognized_case_insensitively() {
        assert!(is_classic("Application"));
        assert!(is_classic("security"));
        assert!(!is_classic("Microsoft-Windows-WinRM/Operational"));
    }

    #[test]
    fn select_keeps_classics_always_and_others_only_with_records() {
        let scanned = select(&probed(&[
            ("Microsoft-Windows-WinRM/Operational", Count::Records(42)),
            ("Application", Count::Records(0)),
            ("Microsoft-Windows-Idle/Operational", Count::Records(0)),
        ]));

        assert_eq!(
            names(&scanned),
            [
                ("Application", 0),
                ("Microsoft-Windows-WinRM/Operational", 42)
            ]
        );
        assert_eq!(scanned.report, ScannerReport::complete());
    }

    #[test]
    fn a_channel_that_refuses_access_is_listed_and_makes_the_scan_partial() {
        let scanned = select(&probed(&[
            ("Application", Count::Records(1200)),
            ("Microsoft-Windows-Sysmon/Operational", Count::Denied),
            ("Security", Count::Denied),
        ]));

        assert_eq!(
            names(&scanned),
            [
                ("Application", 1200),
                ("Microsoft-Windows-Sysmon/Operational", 0),
                ("Security", 0),
            ]
        );
        assert_eq!(
            scanned.report,
            ScannerReport::partial(
                "2 channels refused access, so they are listed with 0 records: Security, \
                 Microsoft-Windows-Sysmon/Operational; run elevated to count them"
            )
        );
    }

    #[test]
    fn one_refusal_reads_as_one() {
        let scanned = select(&probed(&[("Security", Count::Denied)]));

        assert_eq!(
            scanned.report.reason.as_deref(),
            Some(
                "1 channel refused access, so it is listed with 0 records: Security; run \
                 elevated to count them"
            )
        );
    }

    #[test]
    fn many_refusals_are_counted_and_only_a_few_named() {
        let scanned = select(&probed(&[
            ("B/Operational", Count::Denied),
            ("A/Operational", Count::Denied),
            ("Security", Count::Denied),
            ("D/Operational", Count::Denied),
            ("C/Operational", Count::Denied),
        ]));

        let reason = scanned.report.reason.unwrap();
        assert!(reason.starts_with("5 channels refused access"), "{reason}");
        assert!(
            reason.contains(": Security, A/Operational, B/Operational and 2 more;"),
            "{reason}"
        );
    }

    #[test]
    fn a_channel_that_cannot_be_opened_is_counted_and_listed_only_if_classic() {
        let scanned = select(&probed(&[
            ("Application", Count::Records(7)),
            ("Vendor-Broken/Operational", Count::Unreadable),
            ("ForwardedEvents", Count::Unreadable),
        ]));

        assert_eq!(
            names(&scanned),
            [("Application", 7), ("ForwardedEvents", 0)]
        );
        assert_eq!(scanned.report.status, ScannerStatus::Partial);
        assert_eq!(
            scanned.report.reason.as_deref(),
            Some("2 channels could not be opened")
        );
    }
}
