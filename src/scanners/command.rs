//! Running the few system commands the scanners rely on, each with a time
//! limit so a census can never hang on one.

use std::fmt;
use std::process::{Output, Stdio};
use std::time::Duration;

pub(crate) const TIME_LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommandError {
    pub program: &'static str,
    pub failure: Failure,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    NotInstalled,
    TimedOut(Duration),
    /// The command ran and reported failure. Holds the first line it wrote to
    /// standard error, shortened.
    Failed(String),
    NotStarted(std::io::ErrorKind),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let program = self.program;
        match &self.failure {
            Failure::NotInstalled => write!(f, "{program} is not installed"),
            Failure::TimedOut(limit) => write!(
                f,
                "{program} did not finish within {} seconds",
                limit.as_secs()
            ),
            Failure::Failed(first_line) if first_line.is_empty() => write!(f, "{program} failed"),
            Failure::Failed(first_line) => write!(f, "{program} failed: {first_line}"),
            Failure::NotStarted(kind) => write!(f, "{program} could not be started: {kind}"),
        }
    }
}

/// Runs a command to completion within `limit`. A command that exits with a
/// failure status is still returned: some report partial results that way.
pub(crate) async fn run_within(
    program: &'static str,
    args: &[&str],
    limit: Duration,
) -> Result<Output, CommandError> {
    let error = |failure| CommandError { program, failure };

    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    match tokio::time::timeout(limit, command.output()).await {
        Err(_) => Err(error(Failure::TimedOut(limit))),
        Ok(Err(io)) if io.kind() == std::io::ErrorKind::NotFound => {
            Err(error(Failure::NotInstalled))
        }
        Ok(Err(io)) => Err(error(Failure::NotStarted(io.kind()))),
        Ok(Ok(output)) => Ok(output),
    }
}

/// Standard output of a command that must succeed.
pub(crate) async fn stdout_of(
    program: &'static str,
    args: &[&str],
) -> Result<String, CommandError> {
    let output = run_within(program, args, TIME_LIMIT).await?;
    if !output.status.success() {
        return Err(CommandError {
            program,
            failure: Failure::Failed(first_line(&output.stderr)),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The first line of a command's error output, shortened. Scanner reasons end
/// up in the bundle, so they never carry a whole error dump.
fn first_line(stderr: &[u8]) -> String {
    const LONGEST: usize = 160;
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().map(str::trim).find(|line| !line.is_empty());
    line.map(|line| line.chars().take(LONGEST).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_that_outlives_its_limit_is_stopped() {
        let started = std::time::Instant::now();

        let error = run_within("sleep", &["30"], Duration::from_millis(100))
            .await
            .unwrap_err();

        assert_eq!(error.failure, Failure::TimedOut(Duration::from_millis(100)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_missing_command_is_reported_as_not_installed() {
        let error = stdout_of("hostcensus-no-such-command", &[])
            .await
            .unwrap_err();

        assert_eq!(error.failure, Failure::NotInstalled);
        assert_eq!(
            error.to_string(),
            "hostcensus-no-such-command is not installed"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failing_command_reports_only_its_first_error_line() {
        let error = stdout_of("sh", &["-c", "echo first >&2; echo second >&2; exit 3"])
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "sh failed: first");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_successful_command_returns_its_output() {
        assert_eq!(stdout_of("sh", &["-c", "echo ok"]).await.unwrap(), "ok\n");
    }

    #[test]
    fn long_error_lines_are_shortened() {
        let long = "x".repeat(500);
        assert_eq!(first_line(long.as_bytes()).len(), 160);
        assert_eq!(first_line(b"\n\n  spaced  \nnext"), "spaced");
        assert_eq!(first_line(b""), "");
    }
}
