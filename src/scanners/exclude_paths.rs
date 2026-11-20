//! `--exclude` patterns: files a person does not want listed in the census.
//!
//! Patterns follow `crate::glob`. In addition, a pattern ending in a
//! separator excludes everything under that directory.
//!
//! On Windows a pattern may be written with `\` or `/`, and it matches
//! without regard to case, as Windows file names do.

use std::path::Path;

use crate::glob;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExcludePaths {
    patterns: Vec<String>,
    windows_paths: bool,
}

impl ExcludePaths {
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::for_paths_of(patterns, cfg!(windows))
    }

    fn for_paths_of<I, S>(patterns: I, windows_paths: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = patterns
            .into_iter()
            .map(|pattern| comparable(pattern.as_ref().trim(), windows_paths))
            .filter(|pattern| !pattern.is_empty())
            .map(|pattern| {
                if pattern.ends_with('/') {
                    format!("{pattern}**")
                } else {
                    pattern
                }
            })
            .collect();
        Self {
            patterns,
            windows_paths,
        }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let path = comparable(&path.to_string_lossy(), self.windows_paths);
        self.patterns
            .iter()
            .any(|pattern| glob::matches(pattern, &path))
    }
}

fn comparable(text: &str, windows_paths: bool) -> String {
    if windows_paths {
        glob::windows_path_form(text)
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excluded(patterns: &[&str], path: &str) -> bool {
        ExcludePaths::new(patterns).is_excluded(Path::new(path))
    }

    #[test]
    fn a_pattern_without_a_slash_matches_the_file_name_anywhere() {
        assert!(excluded(&["*.gz"], "/var/log/nginx/access.log.2.gz"));
        assert!(excluded(&["*.gz"], "/srv/app/old.gz"));
        assert!(!excluded(&["*.gz"], "/var/log/nginx/access.log"));
        assert!(!excluded(&["*.gz"], "/var/log/archive.gz/app.log"));
    }

    #[test]
    fn a_pattern_with_a_slash_matches_the_whole_path() {
        let patterns = ["/var/log/journal/**"];
        assert!(excluded(&patterns, "/var/log/journal/abc/system.log"));
        assert!(!excluded(&patterns, "/var/log/journald.log"));
        assert!(!excluded(&["nginx/*.log"], "/var/log/nginx/access.log"));
    }

    #[test]
    fn a_trailing_slash_excludes_the_whole_directory() {
        assert!(excluded(&["/home/alice/"], "/home/alice/notes/app.log"));
        assert!(!excluded(&["/home/alice/"], "/home/alicia/app.log"));
    }

    #[test]
    fn blank_patterns_exclude_nothing() {
        assert!(!excluded(&["", "  "], "/var/log/app.log"));
        assert_eq!(ExcludePaths::new(["", " "]), ExcludePaths::default());
    }

    fn excluded_on_windows(patterns: &[&str], path: &str) -> bool {
        ExcludePaths::for_paths_of(patterns, true).is_excluded(Path::new(path))
    }

    #[test]
    fn on_windows_a_pattern_may_use_either_separator() {
        let path = r"C:\ProgramData\Shop\logs\app.log";

        assert!(excluded_on_windows(&[r"C:\ProgramData\Shop\**"], path));
        assert!(excluded_on_windows(&["C:/ProgramData/Shop/**"], path));
        assert!(excluded_on_windows(&[r"C:\ProgramData\Shop\"], path));
        assert!(excluded_on_windows(&[r"C:\ProgramData\*\logs\*.log"], path));
        assert!(excluded_on_windows(&["*.log"], path));
        assert!(!excluded_on_windows(&[r"C:\ProgramData\Other\**"], path));
        assert!(!excluded_on_windows(&[r"C:\ProgramData\*.log"], path));
    }

    #[test]
    fn on_windows_case_does_not_matter() {
        let path = r"C:\ProgramData\Shop\logs\APP.LOG";

        assert!(excluded_on_windows(&[r"c:\programdata\shop\**"], path));
        assert!(excluded_on_windows(&["*.log"], path));
        assert!(excluded_on_windows(&["App.*"], path));
    }

    #[test]
    fn elsewhere_a_backslash_is_an_ordinary_character_and_case_matters() {
        let unix = |patterns: &[&str], path: &str| {
            ExcludePaths::for_paths_of(patterns, false).is_excluded(Path::new(path))
        };

        assert!(!unix(&["*.log"], "/var/log/APP.LOG"));
        assert!(!unix(&[r"\var\log\**"], "/var/log/app.log"));
        assert!(unix(&["/var/log/**"], "/var/log/app.log"));
    }

    #[test]
    fn any_one_matching_pattern_excludes_the_path() {
        let excludes = ExcludePaths::new(["*.tmp", " *.gz "]);
        assert!(excludes.is_excluded(Path::new("/var/log/app.log.1.gz")));
        assert!(!excludes.is_excluded(Path::new("/var/log/app.log")));
    }
}
