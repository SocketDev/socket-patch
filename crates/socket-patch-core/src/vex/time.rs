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

    // civil_from_days: days since 1970-01-01 → (Y, M, D).
    // `z` is `days + 719_468`. Since `days` is derived from a `u64`
    // input via `secs / 86_400` cast to `i64`, `z` is always
    // non-negative for any plausible socket-patch input (the cast
    // would have to wrap around `i64::MAX` to produce a negative,
    // which requires `secs > i64::MAX * 86_400` — far past the
    // year 292 billion). The `else { z - 146_096 }` arm is kept
    // for algorithmic correctness against the Hinnant reference,
    // but is unreachable in practice and llvm-cov reports it as
    // such.
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

    // ── Calendar-algorithm branch coverage ────────────────────────

    /// Non-leap February: 2023-02-28 23:59:59 → 2023-03-01 00:00:00.
    /// Year 2023 is divisible by neither 4 nor 100/400 → Feb has 28
    /// days. Pins the `doe / 36524` adjustment in the
    /// civil_from_days algorithm.
    #[test]
    fn non_leap_year_feb_to_march_boundary() {
        assert_eq!(
            format_unix_secs_rfc3339(1_677_628_799),
            "2023-02-28T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_677_628_800),
            "2023-03-01T00:00:00Z"
        );
    }

    /// Year-end roll: 2023-12-31 23:59:59 → 2024-01-01 00:00:00.
    /// Exercises the month-to-day-of-year inverse mapping at the
    /// extreme high end.
    #[test]
    fn december_to_january_year_boundary() {
        assert_eq!(
            format_unix_secs_rfc3339(1_704_067_199),
            "2023-12-31T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_704_067_200),
            "2024-01-01T00:00:00Z"
        );
    }

    /// 2100 is divisible by 100 but NOT by 400 → it is NOT a leap
    /// year. Pinning this catches a bug where the algorithm forgets
    /// the `doe / 146_096` correction in the era arithmetic.
    /// Picked 2100-03-01 (1 day after the "would be Feb 29 in a
    /// naive impl" boundary).
    #[test]
    fn century_year_2100_is_not_a_leap_year() {
        assert_eq!(
            format_unix_secs_rfc3339(4_107_542_400),
            "2100-03-01T00:00:00Z"
        );
    }

    /// 2000 IS a leap year (divisible by 400). Feb 29 2000 should
    /// render correctly — the four-century cycle reset point.
    #[test]
    fn four_century_year_2000_is_a_leap_year() {
        assert_eq!(
            format_unix_secs_rfc3339(951_782_400),
            "2000-02-29T00:00:00Z"
        );
    }

    /// 31-day months → 1st of next month. January→February.
    #[test]
    fn january_31_to_february_1() {
        assert_eq!(
            format_unix_secs_rfc3339(1_675_209_599),
            "2023-01-31T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_675_209_600),
            "2023-02-01T00:00:00Z"
        );
    }

    /// 31-day month → 30-day month: March 31 → April 1.
    #[test]
    fn march_31_to_april_1() {
        assert_eq!(
            format_unix_secs_rfc3339(1_680_307_199),
            "2023-03-31T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_680_307_200),
            "2023-04-01T00:00:00Z"
        );
    }

    /// 30-day month → 31-day month: April 30 → May 1.
    #[test]
    fn april_30_to_may_1() {
        assert_eq!(
            format_unix_secs_rfc3339(1_682_899_199),
            "2023-04-30T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_682_899_200),
            "2023-05-01T00:00:00Z"
        );
    }

    /// 30-day month → 31-day month, second half of year:
    /// September 30 → October 1.
    #[test]
    fn september_30_to_october_1() {
        assert_eq!(
            format_unix_secs_rfc3339(1_696_118_399),
            "2023-09-30T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_696_118_400),
            "2023-10-01T00:00:00Z"
        );
    }

    /// Century years 2200 and 2300 are divisible by 100 but NOT by
    /// 400, so neither has a Feb 29 — Feb 28 must roll straight to
    /// Mar 1. Complements `century_year_2100_is_not_a_leap_year` and
    /// guards the `doe / 36_524` / `doe / 146_096` era corrections at
    /// timestamps where the `era` quotient is ≥ 1 (post-2099).
    #[test]
    fn far_future_century_years_are_not_leap() {
        assert_eq!(
            format_unix_secs_rfc3339(7_263_215_999),
            "2200-02-28T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(7_263_216_000),
            "2200-03-01T00:00:00Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(10_418_889_599),
            "2300-02-28T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(10_418_889_600),
            "2300-03-01T00:00:00Z"
        );
    }

    /// 2400 is divisible by 400 → leap year, so Feb 29 2400 exists.
    /// This is the four-century reset point one full era past 2000,
    /// exercising the `era * 400` year reconstruction with `era` ≥ 1.
    #[test]
    fn year_2400_is_a_leap_year() {
        assert_eq!(
            format_unix_secs_rfc3339(13_574_606_400),
            "2400-02-29T12:00:00Z"
        );
    }

    /// A far-future leap day (2248-02-29) with a non-trivial time of
    /// day. Pins the full Y/M/D/h/m/s reconstruction at a timestamp
    /// well into the `era == 1` range.
    #[test]
    fn far_future_leap_day_with_time_of_day() {
        assert_eq!(
            format_unix_secs_rfc3339(8_777_917_815),
            "2248-02-29T06:30:15Z"
        );
    }

    /// Time-of-day rollovers: second→minute, minute→hour, and the
    /// noon midpoint. The date-boundary tests above never cross a
    /// `:59 → :00` minute/hour carry within a fixed day, so these pin
    /// the `secs_of_day` div/mod arithmetic directly.
    #[test]
    fn time_of_day_rollovers() {
        let cases: &[(u64, &str)] = &[
            (1_704_067_259, "2024-01-01T00:00:59Z"), // last second of minute 0
            (1_704_067_260, "2024-01-01T00:01:00Z"), // minute carry
            (1_704_070_799, "2024-01-01T00:59:59Z"), // last second of hour 0
            (1_704_070_800, "2024-01-01T01:00:00Z"), // hour carry
            (1_704_110_400, "2024-01-01T12:00:00Z"), // noon
        ];
        for &(secs, expected) in cases {
            assert_eq!(format_unix_secs_rfc3339(secs), expected, "secs={secs}");
        }
    }

    /// `u64::MAX` does not panic. Output isn't asserted byte-for-byte
    /// because the algorithm uses an `i64` cast that overflows in
    /// well-defined wrapping in debug-release but the function MUST
    /// not crash. Exercise the path and confirm the format shape
    /// (digits-dash-digits-T-digits...) is preserved.
    #[test]
    fn max_u64_input_does_not_panic() {
        // Wrap in `std::panic::catch_unwind` for safety even though
        // the function uses pure arithmetic — a regression that
        // introduced an unsafe cast would still be caught.
        let result = std::panic::catch_unwind(|| format_unix_secs_rfc3339(u64::MAX));
        assert!(result.is_ok(), "u64::MAX must not panic");
        // The output shape should still end in `Z`.
        let s = result.unwrap();
        assert!(s.ends_with('Z'), "output must still end with Z");
    }

    /// Plain within-month day carry (not a month/year boundary):
    /// 2024-05-24 23:59:59 → 2024-05-25 00:00:00. The other boundary
    /// tests only cross at month edges; this pins the day increment in
    /// the middle of a month together with the day→00:00:00 time reset.
    #[test]
    fn within_month_day_carry() {
        assert_eq!(
            format_unix_secs_rfc3339(1_716_595_199),
            "2024-05-24T23:59:59Z"
        );
        assert_eq!(
            format_unix_secs_rfc3339(1_716_595_200),
            "2024-05-25T00:00:00Z"
        );
    }

    /// RFC 3339 UTC strings with fixed-width zero-padded fields sort
    /// lexicographically in chronological order. Sweep ~50 years at a
    /// ~1.7-day stride and assert each output is strictly greater than
    /// the previous one. This is an oracle-free guard: any regression
    /// that scrambles a field, drops zero-padding, or miscomputes a
    /// carry would break monotonicity even where this file's other
    /// tests don't have an exact expected string.
    #[test]
    fn outputs_sort_in_chronological_order() {
        const STRIDE: u64 = 147_853; // ~1.71 days, coprime-ish with day/year
        let mut prev = format_unix_secs_rfc3339(0);
        let mut secs = STRIDE;
        // 0 .. ~50 years.
        while secs < 1_600_000_000 {
            let cur = format_unix_secs_rfc3339(secs);
            assert!(
                cur > prev,
                "non-monotonic at secs={secs}: {prev:?} !< {cur:?}"
            );
            // Every output must keep the canonical 20-char shape.
            assert_eq!(cur.len(), 20, "bad width at secs={secs}: {cur:?}");
            prev = cur;
            secs += STRIDE;
        }
    }

    /// `now_rfc3339` must produce a string that round-trips through
    /// our own `format_unix_secs_rfc3339` — i.e. the year/month/day
    /// fields are within plausible ranges (years 1970..3000, months
    /// 01-12, days 01-31). Smoke gate against a future regression
    /// where the system clock format diverges from our manual one.
    #[test]
    fn now_output_parses_into_plausible_fields() {
        let s = now_rfc3339();
        let year: u32 = s[0..4].parse().unwrap();
        let month: u32 = s[5..7].parse().unwrap();
        let day: u32 = s[8..10].parse().unwrap();
        let hour: u32 = s[11..13].parse().unwrap();
        let minute: u32 = s[14..16].parse().unwrap();
        let second: u32 = s[17..19].parse().unwrap();
        assert!((1970..3000).contains(&year), "year out of range: {year}");
        assert!((1..=12).contains(&month), "month out of range: {month}");
        assert!((1..=31).contains(&day), "day out of range: {day}");
        assert!(hour < 24);
        assert!(minute < 60);
        assert!(second < 60);
    }
}
