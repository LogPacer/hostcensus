use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use hostcensus::bundle::{Bundle, Collected, NotedBy, ScanOptions};
use hostcensus::handover::{Handover, SudoUser};
use hostcensus::mark::{SourceSelector, Statement};
use hostcensus::{census, mark, output, timestamp};

/// Take a census of this host: what runs on it and which logs it produces.
///
/// Runs once, opens no network connection, and writes one file.
#[derive(Parser)]
#[command(name = "hostcensus", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Take the census and write it to a file. This is what runs when no
    /// command is given.
    Scan(ScanArgs),
    /// Record in a bundle whether a source is already collected.
    ///
    /// The census observes what a host produces, not what is collected. A
    /// mark is a statement about one source the census found. It is kept
    /// apart from the observations, which are never changed.
    Mark(MarkArgs),
    /// List every source in a bundle with what has been said about it.
    ///
    /// One line per source: yes, no, unknown or - (no mark), then
    /// <kind>:<identifier>, then the collector if one was named. The columns
    /// are separated by tabs. Totals go to standard error.
    Coverage(CoverageArgs),
}

#[derive(Args)]
struct CoverageArgs {
    /// The bundle to read.
    #[arg(long, value_name = "PATH")]
    bundle: PathBuf,
}

#[derive(Args)]
struct ScanArgs {
    /// Where to write the bundle. `-` writes it to standard output.
    /// Defaults to hostcensus-<hostname>-<time>.json in the current directory.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// A directory to search for log files. Repeat for several. Replaces the
    /// default: /var/log, or on Windows the IIS, Windows and ProgramData log
    /// directories.
    #[arg(long = "scan-path", value_name = "DIR")]
    scan_paths: Vec<String>,

    /// A file extension that marks a log file, without the dot. Repeat for
    /// several. Replaces the default, which is `log`.
    #[arg(long = "ext", value_name = "EXTENSION")]
    extensions: Vec<String>,

    /// Leave out log files that were not written to for this many days.
    #[arg(long, value_name = "DAYS")]
    max_age_days: Option<u64>,

    /// Leave out log files matching this pattern. Repeat for several.
    /// `*.gz` matches a file name anywhere, `/var/log/journal/**` a whole
    /// directory tree.
    #[arg(long, value_name = "PATTERN")]
    exclude: Vec<String>,

    /// Record the full command line of every process. Command lines can hold
    /// passwords and tokens; by default only the executable is recorded.
    #[arg(long)]
    process_args: bool,

    /// Record the value of every container label. Label values can hold
    /// secrets; by default only well-known ones are recorded.
    #[arg(long)]
    all_label_values: bool,
}

impl ScanArgs {
    fn options(&self) -> ScanOptions {
        let defaults = ScanOptions::default();
        ScanOptions {
            scan_paths: if self.scan_paths.is_empty() {
                defaults.scan_paths
            } else {
                self.scan_paths.clone()
            },
            extensions: if self.extensions.is_empty() {
                defaults.extensions
            } else {
                self.extensions.clone()
            },
            max_age_days: self.max_age_days.unwrap_or(defaults.max_age_days),
            exclude_patterns: self.exclude.len(),
            process_args: self.process_args,
            all_label_values: self.all_label_values,
        }
    }
}

#[derive(Args)]
struct MarkArgs {
    /// The bundle to record the mark in.
    #[arg(long, value_name = "PATH")]
    bundle: PathBuf,
    /// The source, as <kind>:<identifier>. Kinds: log_file, container,
    /// systemd_service, windows_service, event_log_channel. An identifier
    /// with `*` or `?` marks every source of that kind it matches, such as
    /// log_file:/var/log/nginx/*.log. In a log file pattern `**` also
    /// matches any number of directories.
    #[arg(long, value_name = "KIND:IDENTIFIER")]
    source: SourceSelector,
    /// Whether the source is already collected.
    #[arg(long, value_enum)]
    collected: CollectedArg,
    /// What collects it, such as the name of a log shipper.
    #[arg(long, value_name = "NAME")]
    collector: Option<String>,
    /// Where the collector sends it.
    #[arg(long, value_name = "TEXT")]
    destination: Option<String>,
    /// Where this was read from, such as a configuration file and line.
    #[arg(long, value_name = "TEXT")]
    evidence: Option<String>,
    /// Who is making the statement.
    #[arg(long, value_enum, default_value = "human")]
    by: NotedByArg,
}

#[derive(Clone, Copy, ValueEnum)]
enum CollectedArg {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Copy, ValueEnum)]
enum NotedByArg {
    Human,
    Agent,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Scan(args)) => scan(args),
        Some(Command::Mark(args)) => record_mark(args),
        Some(Command::Coverage(args)) => list_coverage(args),
        None => scan(cli.scan),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hostcensus: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn scan(args: ScanArgs) -> Result<()> {
    let bundle = census::take(args.options(), &args.exclude)?;

    let (destination, handover) = match args.output {
        Some(path) if path.as_os_str() == "-" => {
            std::io::stdout()
                .write_all(bundle.to_json()?.as_bytes())
                .context("cannot write to standard output")?;
            ("standard output".to_string(), Handover::NotNeeded)
        }
        chosen => {
            let path = chosen.unwrap_or_else(|| output::default_file_name(&bundle));
            let handover = output::write_new(&path, &bundle, SudoUser::of_this_process())?;
            (path.display().to_string(), handover)
        }
    };

    eprint!("{}", output::summary(&bundle, &destination, &handover));
    Ok(())
}

fn read_bundle(path: &Path) -> Result<Bundle> {
    let json =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Bundle::from_json(&json).with_context(|| format!("cannot use {}", path.display()))
}

fn list_coverage(args: CoverageArgs) -> Result<()> {
    let bundle = read_bundle(&args.bundle)?;
    let sources = mark::coverage(&bundle);

    let mut listing = String::new();
    let (mut yes, mut no, mut unknown, mut unmarked) = (0, 0, 0, 0);
    for (source, mark) in &sources {
        let answer = match mark.map(|mark| mark.collected) {
            Some(Collected::Yes) => {
                yes += 1;
                "yes"
            }
            Some(Collected::No) => {
                no += 1;
                "no"
            }
            Some(Collected::Unknown) => {
                unknown += 1;
                "unknown"
            }
            None => {
                unmarked += 1;
                "-"
            }
        };
        let collector = mark
            .and_then(|mark| mark.collector.as_deref())
            .unwrap_or("");
        listing.push_str(&format!(
            "{answer}\t{}:{}\t{collector}\n",
            source.kind.name(),
            source.identifier
        ));
    }
    std::io::stdout()
        .write_all(listing.as_bytes())
        .context("cannot write to standard output")?;

    eprintln!(
        "{} sources: {yes} collected, {no} not collected, {unknown} unknown, {unmarked} without a mark",
        sources.len()
    );
    Ok(())
}

fn record_mark(args: MarkArgs) -> Result<()> {
    let mut bundle = read_bundle(&args.bundle)?;

    let collected = match args.collected {
        CollectedArg::Yes => Collected::Yes,
        CollectedArg::No => Collected::No,
        CollectedArg::Unknown => Collected::Unknown,
    };
    let statement = Statement {
        collected,
        collector: args.collector,
        destination: args.destination,
        evidence: args.evidence,
        noted_by: match args.by {
            NotedByArg::Human => NotedBy::Human,
            NotedByArg::Agent => NotedBy::Agent,
        },
        noted_at: timestamp::now(),
    };

    let marked = mark::mark(&mut bundle, &args.source, &statement)?;
    let handover = output::replace(&args.bundle, &bundle, SudoUser::of_this_process())?;

    let answer = match collected {
        Collected::Yes => "collected",
        Collected::No => "not collected",
        Collected::Unknown => "unknown",
    };
    for source in marked {
        eprintln!("Marked {} as {answer}", source.identifier);
    }
    if let Some(note) = handover.note() {
        eprintln!("{note}");
    }
    Ok(())
}
