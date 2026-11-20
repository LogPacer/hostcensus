//! Taking a census: describe the host, run the scanners, seal the bundle.

use std::time::Instant;

use anyhow::Result;

use crate::bundle::{Bundle, Scan, ScanOptions, Tool};
use crate::{host, scanners, timestamp};

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_paths: default_scan_paths(),
            extensions: vec!["log".to_string()],
            // Long enough that a log written to once a month is listed as
            // quiet, and short enough that leftovers of software long gone
            // are not.
            max_age_days: 90,
            exclude_patterns: 0,
            process_args: false,
            all_label_values: false,
        }
    }
}

fn default_scan_paths() -> Vec<String> {
    if cfg!(windows) {
        vec![
            r"C:\inetpub\logs\LogFiles".to_string(),
            r"C:\Windows\Logs".to_string(),
            r"C:\ProgramData".to_string(),
        ]
    } else {
        vec!["/var/log".to_string()]
    }
}

/// Takes a census. `exclude` holds the patterns for files to leave out; the
/// bundle records only how many there were.
pub fn take(mut options: ScanOptions, exclude: &[String]) -> Result<Bundle> {
    options.exclude_patterns = exclude.len();
    let started = Instant::now();
    let generated_at = timestamp::now();
    let host = host::describe();

    let privileged = host::privileged();
    let (inventory, scanners) = scanners::scan(&options, exclude, privileged)?;

    let scan = Scan {
        options,
        privileged,
        scanners,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    };

    Bundle::seal(Tool::this_build(), generated_at, host, scan, inventory)
}
