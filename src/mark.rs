//! Recording what is already collected.
//!
//! A mark is a statement by a person or an agent about one source in the
//! inventory. Marking never changes the inventory itself.

use std::str::FromStr;

use anyhow::{Result, bail, ensure};

use crate::bundle::{Bundle, Collected, Mark, NotedBy, SourceKind, SourceRef};
use crate::glob;

/// Which sources a statement is about: one kind, and either the identifier of
/// one source or a pattern that several identifiers match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSelector {
    pub kind: SourceKind,
    pub identifier: String,
}

impl FromStr for SourceSelector {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let Some((kind, identifier)) = text.split_once(':') else {
            bail!("expected <kind>:<identifier>, such as log_file:/var/log/syslog");
        };
        let Some(kind) = SourceKind::ALL.into_iter().find(|k| k.name() == kind) else {
            bail!(
                "unknown kind {kind:?}; use log_file, container, systemd_service, \
                 windows_service or event_log_channel"
            );
        };
        ensure!(
            !identifier.is_empty(),
            "the identifier after the kind is empty"
        );
        Ok(Self {
            kind,
            identifier: identifier.to_string(),
        })
    }
}

/// What is being said about the selected sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub collected: Collected,
    pub collector: Option<String>,
    pub destination: Option<String>,
    pub evidence: Option<String>,
    pub noted_by: NotedBy,
    pub noted_at: String,
}

/// Records the statement for every selected source and returns the sources it
/// was recorded for. A source has one mark: a later statement about the same
/// source replaces the earlier one.
///
/// An identifier that names a source exactly selects that source. Otherwise,
/// an identifier with `*` or `?` in it is a pattern: for log files it matches
/// paths as `--exclude` does, for every other kind it matches the whole name.
/// In a census of a Windows host, log file patterns match with either path
/// separator and without regard to case, as Windows paths do.
pub fn mark(
    bundle: &mut Bundle,
    selector: &SourceSelector,
    statement: &Statement,
) -> Result<Vec<SourceRef>> {
    ensure!(
        bundle.inventory_is_intact()?,
        "the inventory was changed after the census was taken; \
         marks are only added to a bundle as hostcensus wrote it"
    );

    let identifiers = bundle.inventory.identifiers(selector.kind);
    let wanted = &selector.identifier;
    let is_pattern = wanted.contains(['*', '?']);
    let matching: Vec<&str> = if identifiers.contains(&wanted.as_str()) {
        vec![wanted.as_str()]
    } else if is_pattern {
        identifiers
            .into_iter()
            .filter(|identifier| match selector.kind {
                SourceKind::LogFile if bundle.host.os == "windows" => glob::matches(
                    &glob::windows_path_form(wanted),
                    &glob::windows_path_form(identifier),
                ),
                SourceKind::LogFile => glob::matches(wanted, identifier),
                _ => glob::segment_matches(wanted, identifier),
            })
            .collect()
    } else {
        Vec::new()
    };
    ensure!(
        !matching.is_empty(),
        "the census has no {} {} {wanted:?}",
        kind_in_words(selector.kind),
        if is_pattern { "matching" } else { "named" },
    );
    let selected: Vec<SourceRef> = matching
        .into_iter()
        .map(|identifier| SourceRef {
            kind: selector.kind,
            identifier: identifier.to_string(),
        })
        .collect();

    let marks = &mut bundle.coverage.marks;
    marks.retain(|existing| !selected.contains(&existing.source));
    marks.extend(selected.iter().cloned().map(|source| Mark {
        source,
        collected: statement.collected,
        collector: statement.collector.clone(),
        destination: statement.destination.clone(),
        evidence: statement.evidence.clone(),
        noted_by: statement.noted_by,
        noted_at: statement.noted_at.clone(),
    }));
    marks.sort_by(|a, b| a.source.cmp(&b.source));

    Ok(selected)
}

/// Every source the census found, in bundle order, with the mark it carries
/// if anyone has made a statement about it.
pub fn coverage(bundle: &Bundle) -> Vec<(SourceRef, Option<&Mark>)> {
    SourceKind::ALL
        .into_iter()
        .flat_map(|kind| {
            bundle
                .inventory
                .identifiers(kind)
                .into_iter()
                .map(move |identifier| SourceRef {
                    kind,
                    identifier: identifier.to_string(),
                })
        })
        .map(|source| {
            let mark = bundle
                .coverage
                .marks
                .iter()
                .find(|mark| mark.source == source);
            (source, mark)
        })
        .collect()
}

fn kind_in_words(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::LogFile => "log file",
        SourceKind::Container => "container",
        SourceKind::SystemdService => "systemd service",
        SourceKind::WindowsService => "Windows service",
        SourceKind::EventLogChannel => "event log channel",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bundle::{Host, Scan, ScanOptions, Tool};
    use crate::inventory::{Inventory, LogFile, SystemdService};

    fn log_file(path: &str) -> LogFile {
        LogFile {
            path: path.into(),
            size: 1,
            modified: "2026-01-02T03:04:05Z".into(),
            permissions: "100640".into(),
            source_format: "file".into(),
            rotated_copies: vec![],
            open_in: vec![],
        }
    }

    fn census() -> Bundle {
        Bundle::seal(
            Tool::this_build(),
            "2026-01-02T03:04:05Z".into(),
            Host {
                hostname: "web-1".into(),
                os: "linux".into(),
                os_version: "Debian GNU/Linux 13".into(),
                architecture: "x86_64".into(),
                in_container: false,
            },
            Scan {
                options: ScanOptions::default(),
                privileged: true,
                scanners: BTreeMap::new(),
                duration_ms: 1,
            },
            Inventory {
                log_files: vec![
                    log_file("/var/log/nginx/access.log"),
                    log_file("/var/log/nginx/error.log"),
                ],
                systemd_services: vec![SystemdService {
                    name: "nginx.service".into(),
                    load_state: "loaded".into(),
                    active_state: "active".into(),
                    sub_state: "running".into(),
                    description: "web server".into(),
                    journal_entries_24h: None,
                    last_journal_entry: String::new(),
                }],
                ..Inventory::default()
            },
        )
        .unwrap()
    }

    fn statement(collected: Collected, collector: Option<&str>) -> Statement {
        Statement {
            collected,
            collector: collector.map(str::to_string),
            destination: None,
            evidence: None,
            noted_by: NotedBy::Agent,
            noted_at: "2026-01-02T04:00:00Z".into(),
        }
    }

    fn selector(text: &str) -> SourceSelector {
        text.parse().unwrap()
    }

    #[test]
    fn a_selector_is_a_kind_and_an_identifier() {
        assert_eq!(
            selector("log_file:/var/log/syslog"),
            SourceSelector {
                kind: SourceKind::LogFile,
                identifier: "/var/log/syslog".into()
            }
        );
        // Identifiers may contain colons themselves.
        assert_eq!(
            selector("event_log_channel:Vendor:App/Operational").identifier,
            "Vendor:App/Operational"
        );
    }

    #[test]
    fn a_selector_without_a_known_kind_is_refused() {
        for text in ["/var/log/syslog", "file:/var/log/syslog", "log_file:"] {
            assert!(text.parse::<SourceSelector>().is_err(), "{text}");
        }
    }

    #[test]
    fn a_mark_names_the_source_and_carries_the_statement() {
        let mut bundle = census();

        let marked = mark(
            &mut bundle,
            &selector("log_file:/var/log/nginx/access.log"),
            &statement(Collected::Yes, Some("vector")),
        )
        .unwrap();

        assert_eq!(marked.len(), 1);
        let recorded = &bundle.coverage.marks[0];
        assert_eq!(recorded.source.identifier, "/var/log/nginx/access.log");
        assert_eq!(recorded.collected, Collected::Yes);
        assert_eq!(recorded.collector.as_deref(), Some("vector"));
        assert_eq!(recorded.noted_by, NotedBy::Agent);
    }

    #[test]
    fn marking_never_changes_the_inventory() {
        let mut bundle = census();
        let before = (bundle.inventory.clone(), bundle.inventory_sha256.clone());

        mark(
            &mut bundle,
            &selector("systemd_service:nginx.service"),
            &statement(Collected::No, None),
        )
        .unwrap();

        assert_eq!(
            (bundle.inventory.clone(), bundle.inventory_sha256.clone()),
            before
        );
        assert!(bundle.inventory_is_intact().unwrap());
    }

    #[test]
    fn a_later_statement_about_the_same_source_replaces_the_earlier_one() {
        let mut bundle = census();
        let source = selector("log_file:/var/log/nginx/access.log");

        mark(&mut bundle, &source, &statement(Collected::Unknown, None)).unwrap();
        mark(
            &mut bundle,
            &source,
            &statement(Collected::Yes, Some("vector")),
        )
        .unwrap();

        assert_eq!(bundle.coverage.marks.len(), 1);
        assert_eq!(bundle.coverage.marks[0].collected, Collected::Yes);
    }

    #[test]
    fn marks_are_kept_in_source_order() {
        let mut bundle = census();
        for source in [
            "systemd_service:nginx.service",
            "log_file:/var/log/nginx/error.log",
            "log_file:/var/log/nginx/access.log",
        ] {
            mark(
                &mut bundle,
                &selector(source),
                &statement(Collected::Yes, None),
            )
            .unwrap();
        }

        let order: Vec<_> = bundle
            .coverage
            .marks
            .iter()
            .map(|m| m.source.identifier.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "/var/log/nginx/access.log",
                "/var/log/nginx/error.log",
                "nginx.service"
            ]
        );
    }

    #[test]
    fn a_source_the_census_did_not_see_cannot_be_marked() {
        let mut bundle = census();

        let error = mark(
            &mut bundle,
            &selector("log_file:/var/log/missing.log"),
            &statement(Collected::Yes, None),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no log file named \"/var/log/missing.log\"")
        );
        assert!(bundle.coverage.marks.is_empty());
    }

    #[test]
    fn a_pattern_marks_every_log_file_it_matches() {
        let mut bundle = census();

        let marked = mark(
            &mut bundle,
            &selector("log_file:/var/log/nginx/*.log"),
            &statement(Collected::Yes, Some("vector")),
        )
        .unwrap();

        let paths: Vec<_> = marked.iter().map(|s| s.identifier.as_str()).collect();
        assert_eq!(
            paths,
            ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]
        );
        assert_eq!(bundle.coverage.marks.len(), 2);
    }

    #[test]
    fn a_file_name_pattern_matches_in_any_directory() {
        let mut bundle = census();

        let marked = mark(
            &mut bundle,
            &selector("log_file:access.*"),
            &statement(Collected::Yes, None),
        )
        .unwrap();

        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0].identifier, "/var/log/nginx/access.log");
    }

    #[test]
    fn a_pattern_on_a_name_matches_the_whole_name() {
        let mut bundle = census();

        let marked = mark(
            &mut bundle,
            &selector("systemd_service:nginx*"),
            &statement(Collected::Yes, None),
        )
        .unwrap();
        assert_eq!(marked[0].identifier, "nginx.service");

        let error = mark(
            &mut bundle,
            &selector("systemd_service:gin*"),
            &statement(Collected::Yes, None),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no systemd service matching \"gin*\"")
        );
    }

    #[test]
    fn a_pattern_that_matches_nothing_marks_nothing() {
        let mut bundle = census();

        let error = mark(
            &mut bundle,
            &selector("log_file:/var/log/apache2/*.log"),
            &statement(Collected::Yes, None),
        )
        .unwrap_err();

        assert!(error.to_string().contains("no log file matching"));
        assert!(bundle.coverage.marks.is_empty());
    }

    #[test]
    fn a_source_whose_name_holds_a_wildcard_is_named_exactly() {
        let mut bundle = census();
        bundle
            .inventory
            .log_files
            .push(log_file("/var/log/odd*name.log"));
        bundle
            .inventory
            .log_files
            .push(log_file("/var/log/oddXname.log"));
        let mut bundle = Bundle::seal(
            bundle.tool,
            bundle.generated_at,
            bundle.host,
            bundle.scan,
            bundle.inventory,
        )
        .unwrap();

        let marked = mark(
            &mut bundle,
            &selector("log_file:/var/log/odd*name.log"),
            &statement(Collected::Yes, None),
        )
        .unwrap();

        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0].identifier, "/var/log/odd*name.log");
    }

    #[test]
    fn coverage_lists_every_source_with_its_mark_or_none() {
        let mut bundle = census();
        mark(
            &mut bundle,
            &selector("log_file:/var/log/nginx/error.log"),
            &statement(Collected::No, None),
        )
        .unwrap();

        let listed: Vec<_> = coverage(&bundle)
            .into_iter()
            .map(|(source, mark)| {
                (
                    source.kind.name(),
                    source.identifier,
                    mark.map(|m| m.collected),
                )
            })
            .collect();

        assert_eq!(
            listed,
            [
                ("log_file", "/var/log/nginx/access.log".to_string(), None),
                (
                    "log_file",
                    "/var/log/nginx/error.log".to_string(),
                    Some(Collected::No)
                ),
                ("systemd_service", "nginx.service".to_string(), None),
            ]
        );
    }

    #[test]
    fn a_pattern_matches_windows_paths_with_either_separator_and_any_case() {
        let mut bundle = census();
        bundle.host.os = "windows".into();
        bundle.inventory.log_files = vec![
            log_file(r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex260102.log"),
            log_file(r"C:\ProgramData\Vendor\app.log"),
        ];
        let mut bundle = Bundle::seal(
            bundle.tool,
            bundle.generated_at,
            bundle.host,
            bundle.scan,
            bundle.inventory,
        )
        .unwrap();

        for pattern in [
            r"log_file:C:\inetpub\logs\**\*.log",
            "log_file:c:/inetpub/logs/**/*.LOG",
        ] {
            let marked = mark(
                &mut bundle,
                &selector(pattern),
                &statement(Collected::Yes, None),
            )
            .unwrap();
            let paths: Vec<_> = marked.iter().map(|s| s.identifier.as_str()).collect();
            assert_eq!(
                paths,
                [r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex260102.log"],
                "{pattern}"
            );
        }
    }

    #[test]
    fn the_kind_must_match_as_well_as_the_name() {
        let mut bundle = census();

        let error = mark(
            &mut bundle,
            &selector("container:nginx.service"),
            &statement(Collected::Yes, None),
        )
        .unwrap_err();

        assert!(error.to_string().contains("no container named"));
    }

    #[test]
    fn an_edited_inventory_is_not_marked() {
        let mut bundle = census();
        bundle.inventory.log_files.pop();

        let error = mark(
            &mut bundle,
            &selector("log_file:/var/log/nginx/access.log"),
            &statement(Collected::Yes, None),
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed after the census"));
        assert!(bundle.coverage.marks.is_empty());
    }
}
