//! Times as bundles write them: RFC 3339 in UTC, to the second.

use std::ops::Range;
use std::time::SystemTime;

// A file can carry a time far past any real one. The end of the year 262142
// is the last time a bundle has ever held, and a later one is left empty.
const LAST_SECOND: i64 = 8_210_266_876_799;

/// The time now.
pub fn now() -> String {
    rfc3339(SystemTime::now())
}

/// A time before 1970 is written as nothing.
pub fn rfc3339(time: SystemTime) -> String {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|since_1970| i64::try_from(since_1970.as_secs()).ok())
        .filter(|seconds| *seconds <= LAST_SECOND)
        .map(written)
        .unwrap_or_default()
}

/// Reads back a time in the form `rfc3339` writes, as seconds since 1970.
/// Text in any other form is not a time.
pub(crate) fn seconds_since_1970(text: &str) -> Option<i64> {
    let number = |digits: Range<usize>| text.get(digits)?.parse::<u32>().ok().map(i64::from);
    let days = days_since_1970(number(0..4)?, number(5..7)?, number(8..10)?);
    let seconds = days * 86_400 + number(11..13)? * 3_600 + number(14..16)? * 60 + number(17..19)?;
    (written(seconds) == text).then_some(seconds)
}

fn written(seconds_since_1970: i64) -> String {
    let (year, month, day_of_month) = date(seconds_since_1970.div_euclid(86_400));
    let second = seconds_since_1970.rem_euclid(86_400);
    let sign = if year > 9999 { "+" } else { "" };
    format!(
        "{sign}{year:04}-{month:02}-{day_of_month:02}T{:02}:{:02}:{:02}Z",
        second / 3_600,
        second / 60 % 60,
        second % 60
    )
}

// Both ways between a date and its day number follow Howard Hinnant's
// `civil_from_days` and `days_from_civil`. They count in eras of 400 years
// that start on 1 March, so that a leap day is the last day of its year.
const DAYS_IN_ERA: i64 = 146_097;
const DAYS_FROM_FIRST_ERA_TO_1970: i64 = 719_468;

fn date(days_since_1970: i64) -> (i64, i64, i64) {
    let day = days_since_1970 + DAYS_FROM_FIRST_ERA_TO_1970;
    let era = day.div_euclid(DAYS_IN_ERA);
    let day_of_era = day.rem_euclid(DAYS_IN_ERA);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day_of_month = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = (month_from_march + 2) % 12 + 1;
    let year = era * 400 + year_of_era + i64::from(month <= 2);
    (year, month, day_of_month)
}

fn days_since_1970(year: i64, month: i64, day_of_month: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day_of_month - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_IN_ERA + day_of_era - DAYS_FROM_FIRST_ERA_TO_1970
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn written(seconds_since_1970: u64) -> String {
        rfc3339(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds_since_1970))
    }

    /// One second of every day from 1970 to 9999, with the text a calendar
    /// counted month by month gives it.
    fn calendar() -> impl Iterator<Item = (u64, String)> {
        (1970..=9999)
            .flat_map(|year| {
                let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                let february = if leap { 29 } else { 28 };
                let months = [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                (1..).zip(months).flat_map(move |(month, days)| {
                    (1..=days).map(move |day_of_month| (year, month, day_of_month))
                })
            })
            .zip(0..)
            .map(|((year, month, day_of_month), day)| {
                let second = day * 7_919 % 86_400;
                let text = format!(
                    "{year:04}-{month:02}-{day_of_month:02}T{:02}:{:02}:{:02}Z",
                    second / 3_600,
                    second / 60 % 60,
                    second % 60
                );
                (day * 86_400 + second, text)
            })
    }

    #[test]
    fn a_time_is_written_in_utc_to_the_second() {
        for (seconds_since_1970, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (59, "1970-01-01T00:00:59Z"),
            (86_399, "1970-01-01T23:59:59Z"),
            (86_400, "1970-01-02T00:00:00Z"),
            (68_169_599, "1972-02-28T23:59:59Z"),
            (68_256_000, "1972-03-01T00:00:00Z"),
            (946_684_799, "1999-12-31T23:59:59Z"),
            (946_684_800, "2000-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (951_868_799, "2000-02-29T23:59:59Z"),
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_709_251_200, "2024-03-01T00:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (1_735_689_600, "2025-01-01T00:00:00Z"),
            (1_767_323_045, "2026-01-02T03:04:05Z"),
            (2_147_483_647, "2038-01-19T03:14:07Z"),
            (2_147_483_648, "2038-01-19T03:14:08Z"),
            (4_102_444_799, "2099-12-31T23:59:59Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(written(seconds_since_1970), text);
        }
    }

    #[test]
    fn every_day_from_1970_to_9999_is_written_as_the_calendar_has_it() {
        for (seconds_since_1970, text) in calendar() {
            assert_eq!(written(seconds_since_1970), text);
        }
    }

    #[test]
    fn a_part_of_a_second_is_dropped() {
        let time = SystemTime::UNIX_EPOCH + Duration::new(1_767_323_045, 999_999_999);

        assert_eq!(rfc3339(time), "2026-01-02T03:04:05Z");
    }

    #[test]
    fn a_time_before_1970_is_written_as_nothing() {
        assert_eq!(
            rfc3339(SystemTime::UNIX_EPOCH - Duration::from_nanos(1)),
            ""
        );
        assert_eq!(
            rfc3339(SystemTime::UNIX_EPOCH - Duration::from_secs(86_400)),
            ""
        );
    }

    // The clock of Windows ends before these years.
    #[cfg(unix)]
    #[test]
    fn a_year_past_9999_is_written_with_a_sign_up_to_the_year_262142() {
        assert_eq!(written(253_402_300_800), "+10000-01-01T00:00:00Z");
        assert_eq!(written(8_210_266_876_799), "+262142-12-31T23:59:59Z");
        assert_eq!(written(8_210_266_876_800), "");
    }

    #[test]
    fn a_written_time_is_read_back() {
        for (seconds, text) in calendar() {
            assert_eq!(
                seconds_since_1970(&text),
                i64::try_from(seconds).ok(),
                "{text}"
            );
        }
        for (text, seconds) in [
            ("0000-01-01T00:00:00Z", -62_167_219_200),
            ("0000-12-31T23:59:59Z", -62_135_596_801),
            ("1600-02-29T12:00:00Z", -11_670_955_200),
            ("1900-03-01T00:00:00Z", -2_203_891_200),
            ("1969-12-31T23:59:59Z", -1),
        ] {
            assert_eq!(seconds_since_1970(text), Some(seconds), "{text}");
        }
    }

    #[test]
    fn text_in_another_form_is_not_a_time() {
        for text in [
            "",
            "2026-01-02",
            "2026-01-02T03:04:05",
            "2026-01-02T03:04:05Z ",
            "2026-01-02t03:04:05z",
            "2026-01-02 03:04:05Z",
            "2026-01-02T03:04:05.5Z",
            "2026-01-02T03:04:05+00:00",
            "2026-01-02T04:04:05+01:00",
            "2026-01-02T03:04:60Z",
            "2026-01-02T03:60:05Z",
            "2026-01-02T24:04:05Z",
            "2026-02-29T03:04:05Z",
            "2026-13-02T03:04:05Z",
            "2026-00-02T03:04:05Z",
            "2026-01-00T03:04:05Z",
            "2026/01/02T03:04:05Z",
            "+026-01-02T03:04:05Z",
            "-026-01-02T03:04:05Z",
            "2026-+1-02T03:04:05Z",
            "+10000-01-01T00:00:00Z",
            "２026-01-02T03:04:05Z",
        ] {
            assert_eq!(seconds_since_1970(text), None, "{text}");
        }
    }

    #[test]
    fn now_is_the_clock_written_the_same_way() {
        let before = rfc3339(SystemTime::now());
        let now = now();
        let after = rfc3339(SystemTime::now());

        assert!(before <= now && now <= after, "{before} {now} {after}");
    }
}
