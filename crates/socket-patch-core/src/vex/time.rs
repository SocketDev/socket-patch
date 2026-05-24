//! Minimal RFC 3339 timestamp formatter from `SystemTime`.
//!
//! We only need UTC output with a trailing `Z` (no timezone offsets, no
//! sub-second precision) — vexctl accepts both forms. Doing this by hand
//! avoids a chrono/jiff dependency for ~30 lines of arithmetic.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format the current time as RFC 3339 in UTC, e.g. `2024-05-24T12:34:56Z`.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_secs_rfc3339(secs)
}

/// Format an absolute UNIX-epoch second count as RFC 3339 UTC.
///
/// Pulled out as its own function so the formatting can be unit-tested
/// against fixed timestamps without mocking the system clock.
pub fn format_unix_secs_rfc3339(secs: u64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a UNIX-epoch second count into a (Y, M, D, h, m, s) tuple in UTC.
///
/// Uses the civil_from_days algorithm by Howard Hinnant (public domain):
/// <http://howardhinnant.github.io/date_algorithms.html#civil_from_days>.
/// Adapted to operate on a non-negative second count — socket-patch only
/// ever stamps "now", so pre-1970 inputs are out of scope.
fn unix_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // civil_from_days: days since 1970-01-01 → (Y, M, D)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (y + if m <= 2 { 1 } else { 0 }) as i32;

    (year, m, d, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_renders_as_1970_01_01() {
        assert_eq!(format_unix_secs_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_2024_01_01() {
        // 1704067200 = 2024-01-01T00:00:00Z (verified via `date -u -d ...`).
        assert_eq!(
            format_unix_secs_rfc3339(1_704_067_200),
            "2024-01-01T00:00:00Z"
        );
    }

    #[test]
    fn known_timestamp_with_time_of_day() {
        // 1716552896 = 2024-05-24T12:14:56Z
        assert_eq!(
            format_unix_secs_rfc3339(1_716_552_896),
            "2024-05-24T12:14:56Z"
        );
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(
            format_unix_secs_rfc3339(1_709_164_800),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn now_has_z_suffix_and_t_separator() {
        // Sanity check the live function — it must always have the
        // `YYYY-MM-DDTHH:MM:SSZ` shape regardless of the actual clock.
        let s = now_rfc3339();
        assert_eq!(s.len(), 20);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
        assert!(s.ends_with('Z'));
    }
}
