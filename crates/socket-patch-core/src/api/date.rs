//! Minimal timestamp parser for the `publishedAt` field on patch records.
//!
//! The Socket patch API serves `publishedAt` as an **RFC 2822 / HTTP-date**
//! string — `Fri, 27 Mar 2026 19:12:42 GMT` — verified live across npm,
//! PyPI, cargo and gem. Test fixtures throughout this repo use RFC 3339
//! (`2026-03-27T19:12:42Z`) instead, so both spellings must parse.
//!
//! This matters because these strings are *ordered*: patch selection ranks
//! by publish date, and comparing the RFC 2822 form as a raw string sorts
//! by day-of-week name (`Fri` < `Mon` < `Sat` < `Sun` < `Thu` < `Tue` <
//! `Wed`), not chronologically. Converting to epoch seconds first is the
//! only way to get a correct order.
//!
//! Doing this by hand avoids a chrono/jiff dependency, matching the
//! existing hand-rolled formatter in [`crate::vex::time`].

/// Parse a patch `publishedAt` timestamp into UNIX epoch seconds (UTC).
///
/// Accepts, in the order tried:
///
/// - RFC 2822 / HTTP-date: `Fri, 27 Mar 2026 19:12:42 GMT` (the format
///   production actually emits). The leading day-of-week is optional and
///   never validated — it is redundant with the date and servers get it
///   wrong often enough that rejecting on it would be worse than ignoring
///   it. A trailing zone of `GMT` / `UTC` / `Z` / `+0000` / `-0000` is
///   accepted; any other numeric offset is applied.
/// - RFC 3339 / ISO 8601: `2026-03-27T19:12:42Z`, with optional fractional
///   seconds and an optional `±HH:MM` offset.
/// - A bare civil date: `2026-03-27` (midnight UTC).
///
/// Returns `None` for anything else, including pre-1970 instants — callers
/// rank `None` last, which is the right treatment for a timestamp we cannot
/// trust. Never panics on malformed input.
pub fn parse_timestamp_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    parse_rfc2822(s).or_else(|| parse_rfc3339(s))
}

/// Days since 1970-01-01 for a civil (proleptic Gregorian) date.
///
/// Howard Hinnant's `days_from_civil` (public domain):
/// <http://howardhinnant.github.io/date_algorithms.html#days_from_civil>.
/// This is the exact inverse of the `civil_from_days` half of
/// [`crate::vex::time::unix_to_ymdhms`]; the round-trip is pinned by
/// `days_from_civil_inverts_unix_to_ymdhms` below.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64; // Mar = 0
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Assemble a UTC (Y, M, D, h, m, s) tuple into epoch seconds, rejecting
/// out-of-range fields and pre-1970 instants.
fn to_epoch_secs(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Leap seconds arrive as `:60`; clamping beats rejecting the record.
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add((hour * 3600 + min * 60 + sec.min(59)) as i64)?;
    u64::try_from(secs).ok()
}

/// Month index (1-12) for an RFC 2822 three-letter month abbreviation.
fn month_from_abbrev(abbrev: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = abbrev.to_ascii_lowercase();
    MONTHS
        .iter()
        .position(|m| *m == lower)
        .map(|i| i as u32 + 1)
}

/// Parse `[Day, ]DD Mon YYYY HH:MM[:SS] [zone]`.
///
/// The zone is optional (absent means UTC, matching HTTP-date practice for
/// the malformed-but-common no-zone spelling).
fn parse_rfc2822(s: &str) -> Option<u64> {
    // Drop the optional `Fri,` day-of-week prefix.
    let rest = match s.split_once(',') {
        Some((_dow, rest)) => rest,
        None => s,
    };
    let mut parts = rest.split_ascii_whitespace();

    let day: u32 = parts.next()?.parse().ok()?;
    let month = month_from_abbrev(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;

    let (hour, min, sec) = match parts.next() {
        Some(time) => parse_hms(time)?,
        // A bare `27 Mar 2026` is a legal enough date; treat it as midnight.
        None => (0, 0, 0),
    };

    let base = to_epoch_secs(year, month, day, hour, min, sec)?;
    match parts.next() {
        None => Some(base),
        Some(zone) => apply_zone(base, zone),
    }
}

/// Shift `base` (which was parsed as if UTC) by an RFC 2822 zone token.
///
/// Named zones other than the UTC aliases are the obsolete RFC 822 forms;
/// per RFC 2822 §4.3 they are to be treated as `-0000`, i.e. UTC.
fn apply_zone(base: u64, zone: &str) -> Option<u64> {
    let offset_secs = match zone {
        "GMT" | "UTC" | "UT" | "Z" | "+0000" | "-0000" => 0,
        // An unrecognized token is an obsolete RFC 822 named zone, which
        // RFC 2822 §4.3 says to read as `-0000` — i.e. no shift.
        _ => parse_numeric_offset(zone).unwrap_or_default(),
    };
    // The parsed fields were wall-clock in `zone`; UTC is that minus the
    // offset.
    let shifted = (base as i64).checked_sub(offset_secs)?;
    u64::try_from(shifted).ok()
}

/// Parse `±HHMM` or `±HH:MM` into signed seconds.
fn parse_numeric_offset(zone: &str) -> Option<i64> {
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1i64, &zone[1..]),
        b'-' => (-1i64, &zone[1..]),
        _ => return None,
    };
    let digits: String = digits.chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let mins: i64 = digits[2..].parse().ok()?;
    Some(sign * (hours * 3600 + mins * 60))
}

/// Parse `HH:MM[:SS]`.
fn parse_hms(time: &str) -> Option<(u32, u32, u32)> {
    let mut it = time.split(':');
    let hour: u32 = it.next()?.parse().ok()?;
    let min: u32 = it.next()?.parse().ok()?;
    let sec: u32 = match it.next() {
        Some(s) => s.parse().ok()?,
        None => 0,
    };
    if it.next().is_some() {
        return None;
    }
    Some((hour, min, sec))
}

/// Parse `YYYY-MM-DD[(T| )HH:MM[:SS][.fff]][Z|±HH:MM]`.
fn parse_rfc3339(s: &str) -> Option<u64> {
    let (date, time) = match s.find(['T', 't', ' ']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    if d.next().is_some() {
        return None;
    }

    let Some(time) = time else {
        return to_epoch_secs(year, month, day, 0, 0, 0);
    };

    // Split the zone suffix off the clock time.
    let (clock, zone) = match time.rfind(['Z', 'z', '+']) {
        Some(i) => (&time[..i], Some(&time[i..])),
        // A `-` can only be a zone sign here — the date half is already gone.
        None => match time.rfind('-') {
            Some(i) => (&time[..i], Some(&time[i..])),
            None => (time, None),
        },
    };
    // Fractional seconds carry no ranking signal at this granularity.
    let clock = clock.split('.').next()?;
    let (hour, min, sec) = parse_hms(clock)?;

    let base = to_epoch_secs(year, month, day, hour, min, sec)?;
    match zone {
        None | Some("Z") | Some("z") => Some(base),
        Some(z) => {
            let offset = parse_numeric_offset(z)?;
            u64::try_from((base as i64).checked_sub(offset)?).ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vex::time::unix_to_ymdhms;

    // ── RFC 2822 / HTTP-date: the format production actually emits ──

    /// Verbatim payloads captured from
    /// `GET https://patches-api.socket.dev/patch/by-package/<purl>` on
    /// 2026-08-04. If this shape ever stops parsing, patch ranking
    /// silently degrades to "unknown date, sorts last" for every patch.
    #[test]
    fn parses_live_production_published_at_strings() {
        let cases = [
            ("Fri, 27 Mar 2026 19:12:42 GMT", (2026, 3, 27, 19, 12, 42)),
            ("Mon, 03 Aug 2026 20:23:06 GMT", (2026, 8, 3, 20, 23, 6)),
            ("Wed, 29 Jul 2026 19:39:44 GMT", (2026, 7, 29, 19, 39, 44)),
            ("Thu, 19 Mar 2026 14:53:13 GMT", (2026, 3, 19, 14, 53, 13)),
        ];
        for (input, expected) in cases {
            let secs = parse_timestamp_secs(input).unwrap_or_else(|| panic!("failed: {input}"));
            assert_eq!(unix_to_ymdhms(secs), expected, "input={input}");
        }
    }

    /// The whole reason this module exists: lexicographic comparison of
    /// RFC 2822 strings orders by weekday name, so an older `Wed` sorts
    /// ahead of a newer `Fri`. Parsed epoch seconds must not.
    #[test]
    fn weekday_prefix_does_not_dominate_ordering() {
        let older = "Wed, 01 Jan 2025 00:00:00 GMT";
        let newer = "Fri, 01 Aug 2026 00:00:00 GMT";
        assert!(older > newer, "precondition: raw strings sort backwards");
        assert!(
            parse_timestamp_secs(older).unwrap() < parse_timestamp_secs(newer).unwrap(),
            "parsed order must be chronological"
        );
    }

    #[test]
    fn parses_every_month_abbreviation() {
        for (i, mon) in [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        .iter()
        .enumerate()
        {
            let s = format!("Mon, 15 {mon} 2026 00:00:00 GMT");
            let secs = parse_timestamp_secs(&s).unwrap_or_else(|| panic!("failed: {s}"));
            let (y, m, d, ..) = unix_to_ymdhms(secs);
            assert_eq!((y, m, d), (2026, i as u32 + 1, 15), "input={s}");
        }
    }

    #[test]
    fn month_abbreviation_is_case_insensitive() {
        let a = parse_timestamp_secs("Fri, 27 MAR 2026 19:12:42 GMT").unwrap();
        let b = parse_timestamp_secs("Fri, 27 mar 2026 19:12:42 GMT").unwrap();
        let c = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn utc_zone_aliases_are_equivalent() {
        let base = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        for zone in ["GMT", "UTC", "UT", "Z", "+0000", "-0000"] {
            assert_eq!(
                parse_timestamp_secs(&format!("Fri, 27 Mar 2026 19:12:42 {zone}")).unwrap(),
                base,
                "zone={zone}"
            );
        }
    }

    #[test]
    fn numeric_offsets_shift_to_utc() {
        let utc = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        // 19:12:42 +0200 is 17:12:42 UTC — two hours EARLIER in absolute time.
        assert_eq!(
            parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 +0200").unwrap(),
            utc - 7200
        );
        assert_eq!(
            parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 -0530").unwrap(),
            utc + 5 * 3600 + 1800
        );
    }

    #[test]
    fn day_of_week_prefix_is_optional_and_unvalidated() {
        let with = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        assert_eq!(parse_timestamp_secs("27 Mar 2026 19:12:42 GMT"), Some(with));
        // A wrong weekday is ignored, not rejected — servers get it wrong.
        assert_eq!(
            parse_timestamp_secs("Tue, 27 Mar 2026 19:12:42 GMT"),
            Some(with)
        );
    }

    #[test]
    fn rfc2822_seconds_are_optional() {
        let secs = parse_timestamp_secs("Fri, 27 Mar 2026 19:12 GMT").unwrap();
        assert_eq!(unix_to_ymdhms(secs), (2026, 3, 27, 19, 12, 0));
    }

    /// A bare `27 Mar 2026` (no time token) is legal enough and reads as
    /// midnight UTC, matching the bare-civil-date arm of the RFC 3339 path.
    #[test]
    fn bare_rfc2822_date_parses_as_midnight_utc() {
        let secs = parse_timestamp_secs("27 Mar 2026").unwrap();
        assert_eq!(unix_to_ymdhms(secs), (2026, 3, 27, 0, 0, 0));
        // Same instant as the ISO spelling of the same day...
        assert_eq!(parse_timestamp_secs("2026-03-27"), Some(secs));
        // ...and the day-of-week prefix stays optional without a time.
        assert_eq!(parse_timestamp_secs("Fri, 27 Mar 2026"), Some(secs));
        // Asymmetry pin: a zone without a time is rejected — the fourth
        // token is always read as a clock time, so `GMT` fails parse_hms.
        assert_eq!(parse_timestamp_secs("27 Mar 2026 GMT"), None);
    }

    /// A missing zone token means UTC (HTTP-date practice for the
    /// malformed-but-common no-zone spelling) — the RFC 2822 twin of the
    /// zoneless `2024-05-24T12:14:56` variant tested below.
    #[test]
    fn rfc2822_missing_zone_is_utc() {
        let with_zone = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        assert_eq!(
            parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42"),
            Some(with_zone)
        );
        assert_eq!(
            parse_timestamp_secs("27 Mar 2026 19:12:42"),
            Some(with_zone)
        );
    }

    /// Named zones other than the UTC aliases are the obsolete RFC 822
    /// forms; per RFC 2822 §4.3 they read as `-0000`, i.e. no shift. An
    /// unrecognized token (even a non-zone like `XYZZY`) never rejects the
    /// record — a wrong-but-rankable date beats sorting last.
    #[test]
    fn named_obsolete_zones_are_read_as_utc() {
        let base = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        for zone in ["EST", "PDT", "JST", "XYZZY"] {
            assert_eq!(
                parse_timestamp_secs(&format!("Fri, 27 Mar 2026 19:12:42 {zone}")),
                Some(base),
                "zone={zone}"
            );
        }
    }

    /// In the RFC 2822 path a sign-prefixed zone that fails to parse as
    /// `±HHMM`/`±HH:MM` degrades to UTC instead of rejecting: the
    /// `unwrap_or_default` fallback in `apply_zone` treats it like an
    /// unknown named zone. Pins current (lenient) behavior — production
    /// only ever emits `GMT`, and keeping the record rankable beats
    /// dropping it. Contrast `rejects_malformed_rfc3339_offsets`, where
    /// the same offsets reject the whole string.
    #[test]
    fn rfc2822_malformed_numeric_offsets_degrade_to_utc() {
        let base = parse_timestamp_secs("Fri, 27 Mar 2026 19:12:42 GMT").unwrap();
        for zone in ["+530", "+02:0"] {
            assert_eq!(
                parse_timestamp_secs(&format!("Fri, 27 Mar 2026 19:12:42 {zone}")),
                Some(base),
                "zone={zone}"
            );
        }
    }

    // ── RFC 3339 / ISO 8601: the format every in-repo fixture uses ──

    #[test]
    fn parses_rfc3339_fixture_format() {
        let secs = parse_timestamp_secs("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(unix_to_ymdhms(secs), (2024, 1, 1, 0, 0, 0));
        assert_eq!(secs, 1_704_067_200);
    }

    #[test]
    fn parses_rfc3339_variants() {
        let base = parse_timestamp_secs("2024-05-24T12:14:56Z").unwrap();
        assert_eq!(base, 1_716_552_896);
        // Lowercase separators, space separator, missing zone, fractional
        // seconds — all the same instant.
        for s in [
            "2024-05-24t12:14:56z",
            "2024-05-24 12:14:56Z",
            "2024-05-24T12:14:56",
            "2024-05-24T12:14:56.123Z",
        ] {
            assert_eq!(parse_timestamp_secs(s), Some(base), "input={s}");
        }
        // Offsets shift to UTC.
        assert_eq!(
            parse_timestamp_secs("2024-05-24T14:14:56+02:00"),
            Some(base)
        );
        assert_eq!(
            parse_timestamp_secs("2024-05-24T10:14:56-02:00"),
            Some(base)
        );
    }

    #[test]
    fn parses_bare_civil_date_as_midnight() {
        assert_eq!(parse_timestamp_secs("2024-01-01"), Some(1_704_067_200));
    }

    #[test]
    fn parses_leap_day() {
        let secs = parse_timestamp_secs("2024-02-29T00:00:00Z").unwrap();
        assert_eq!(unix_to_ymdhms(secs), (2024, 2, 29, 0, 0, 0));
    }

    // ── Rejection ─────────────────────────────────────────────────────

    #[test]
    fn rejects_unparseable_input() {
        for s in [
            "",
            "   ",
            "not a date",
            "Fri, 27 Xyz 2026 19:12:42 GMT", // bad month
            "Fri, 99 Mar 2026 19:12:42 GMT", // day out of range
            "2024-13-01T00:00:00Z",          // month out of range
            "2024-01-01T25:00:00Z",          // hour out of range
            "2024-01-01T00:99:00Z",          // minute out of range
            "1969-12-31T23:59:59Z",          // pre-epoch
            "2024-01-01T00:00:00:00Z",       // too many clock fields
            "2024-01-01-01",                 // too many date fields
        ] {
            assert_eq!(parse_timestamp_secs(s), None, "should reject: {s:?}");
        }
    }

    /// RFC 3339 zone suffixes must be exactly `Z` or `±HHMM`/`±HH:MM`: a
    /// short, digitless, or trailing-junk suffix rejects the whole string
    /// rather than silently mis-shifting the instant.
    #[test]
    fn rejects_malformed_rfc3339_offsets() {
        for s in [
            "2026-03-27T19:12:42+2:00",  // one-digit hour
            "2026-03-27T19:12:42+02",    // missing minutes
            "2026-03-27T19:12:42+ab:cd", // non-digits after sign
            "2026-03-27T19:12:42Zjunk",  // trailing junk after Z
        ] {
            assert_eq!(parse_timestamp_secs(s), None, "should reject: {s:?}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            parse_timestamp_secs("  2024-01-01T00:00:00Z  "),
            Some(1_704_067_200)
        );
    }

    #[test]
    fn does_not_panic_on_adversarial_input() {
        // Multi-byte codepoints at every index the parsers slice on: a
        // byte-index slice landing mid-codepoint would panic.
        for s in [
            "日本語",
            "Fri,日 27 Mar 2026",
            "2024-01-01T日",
            "2024-01-01日00:00:00Z",
            "+",
            "-",
            "T",
            ":::::",
            "2024--01-01",
        ] {
            let _ = parse_timestamp_secs(s);
        }
    }

    // ── Cross-checks against the existing formatter ───────────────────

    /// `days_from_civil` must invert the `civil_from_days` half of
    /// `vex::time::unix_to_ymdhms` exactly. Swept across ~1265 years so
    /// every leap rule and century boundary is covered.
    #[test]
    fn days_from_civil_inverts_unix_to_ymdhms() {
        for days in 0..462_000i64 {
            let (y, m, d, ..) = unix_to_ymdhms(days as u64 * 86_400);
            assert_eq!(
                days_from_civil(y as i64, m, d),
                days,
                "mismatch at day {days} ({y}-{m}-{d})"
            );
        }
    }

    /// Parsing must be monotonic: a later instant always yields a larger
    /// epoch value, in both wire formats. Oracle-free guard against a
    /// scrambled field or a dropped carry.
    #[test]
    fn parsed_order_is_chronological_in_both_formats() {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        const STRIDE: u64 = 147_853; // ~1.71 days
        let mut secs = 0u64;
        let mut prev_2822 = 0u64;
        while secs < 1_900_000_000 {
            let (y, m, d, h, mi, s) = unix_to_ymdhms(secs);
            let iso = format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z");
            let rfc = format!(
                "Mon, {d:02} {} {y:04} {h:02}:{mi:02}:{s:02} GMT",
                MONTHS[m as usize - 1]
            );
            assert_eq!(parse_timestamp_secs(&iso), Some(secs), "iso={iso}");
            assert_eq!(parse_timestamp_secs(&rfc), Some(secs), "rfc={rfc}");
            assert!(secs > prev_2822 || secs == 0);
            prev_2822 = secs;
            secs += STRIDE;
        }
    }
}
