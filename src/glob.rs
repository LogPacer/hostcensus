//! The one pattern matcher in hostcensus.
//!
//! `*` matches any run of characters within a `/`-separated segment, `?`
//! exactly one character, and `**` any number of whole segments, including
//! none.

/// Whether `pattern` matches `text`.
///
/// A pattern without `/` is matched against the last segment of `text` only,
/// so `*.gz` matches `/var/log/app.log.gz`. A pattern with `/` must match the
/// whole of `text`, segment by segment.
pub fn matches(pattern: &str, text: &str) -> bool {
    if pattern.contains('/') {
        segments_match(
            &pattern.split('/').collect::<Vec<_>>(),
            &text.split('/').collect::<Vec<_>>(),
        )
    } else {
        segment_matches(pattern, text.rsplit('/').next().unwrap_or(text))
    }
}

/// A Windows path, or a pattern for one, in the form in which the two are
/// compared: with `/` between segments and in lower case, because Windows
/// accepts either separator and does not distinguish case in file names.
/// `matches` itself knows only `/` and compares exactly.
pub fn windows_path_form(text: &str) -> String {
    text.replace('\\', "/").to_lowercase()
}

fn segments_match(pattern: &[&str], text: &[&str]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((&"**", rest)) => (0..=text.len()).any(|skip| segments_match(rest, &text[skip..])),
        Some((segment, rest)) => text.split_first().is_some_and(|(name, text)| {
            segment_matches(segment, name) && segments_match(rest, text)
        }),
    }
}

/// Whether `pattern` matches the single segment `name`. `/` has no special
/// meaning here.
pub fn segment_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut last_star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            last_star = Some((p, n));
            p += 1;
        } else if let Some((star, matched)) = last_star {
            p = star + 1;
            n = matched + 1;
            last_star = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_without_a_slash_matches_the_last_segment() {
        assert!(matches("*.gz", "/var/log/nginx/access.log.2.gz"));
        assert!(matches("*.gz", "old.gz"));
        assert!(!matches("*.gz", "/var/log/nginx/access.log"));
        assert!(!matches("*.gz", "/var/log/archive.gz/app.log"));
        assert!(matches("secret?.log", "/opt/app/secret1.log"));
        assert!(!matches("secret?.log", "/opt/app/secret12.log"));
        assert!(matches("nginx.service", "nginx.service"));
    }

    #[test]
    fn a_pattern_with_a_slash_matches_the_whole_text() {
        assert!(matches(
            "/var/log/journal/**",
            "/var/log/journal/abc/system.log"
        ));
        assert!(matches("/var/log/journal/**", "/var/log/journal/user.log"));
        assert!(!matches("/var/log/journal/**", "/var/log/journald.log"));
        assert!(!matches(
            "/var/log/journal/**",
            "/srv/var/log/journal/user.log"
        ));
        assert!(matches("/var/log/*/secret.log", "/var/log/app/secret.log"));
        assert!(!matches("/var/log/*/secret.log", "/var/log/a/b/secret.log"));
        assert!(matches("/var/log/**/secret.log", "/var/log/a/b/secret.log"));
        assert!(matches("/var/log/**/secret.log", "/var/log/secret.log"));
        assert!(!matches("nginx/*.log", "/var/log/nginx/access.log"));
        assert!(matches("shop/*", "shop/web"));
    }

    #[test]
    fn a_windows_path_and_its_pattern_meet_in_one_form() {
        let path = windows_path_form(r"C:\ProgramData\Shop\logs\APP.LOG");
        assert_eq!(path, "c:/programdata/shop/logs/app.log");

        assert!(matches(&windows_path_form(r"C:\ProgramData\**"), &path));
        assert!(matches(
            &windows_path_form("c:/programdata/*/logs/*.log"),
            &path
        ));
        assert!(matches(&windows_path_form("*.Log"), &path));
        assert!(!matches(&windows_path_form(r"C:\ProgramData\*.log"), &path));
    }

    #[test]
    fn without_that_form_a_backslash_is_an_ordinary_character() {
        // The whole path is one segment, so `*` runs across the backslashes.
        assert!(matches(
            r"C:\ProgramData\*.log",
            r"C:\ProgramData\Shop\app.log"
        ));
        assert!(!matches(
            "C:/ProgramData/**",
            r"C:\ProgramData\Shop\app.log"
        ));
    }

    #[test]
    fn a_segment_pattern_treats_a_slash_as_any_other_character() {
        assert!(segment_matches("shop/*", "shop/web"));
        assert!(segment_matches("*", ""));
        assert!(!segment_matches("a?c", "ac"));
    }
}
