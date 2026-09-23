//! Pure text helpers for human output: counted nouns and one-line
//! truncation. No I/O, no terminal state.

/// `plural(1, "package", "packages")` → `"1 package"`,
/// `plural(2, "package", "packages")` → `"2 packages"` (and `0 packages`).
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

const ELLIPSIS: &str = "...";

/// How far back from the cut point a word boundary is still preferred
/// over a hard mid-word cut.
const WORD_BOUNDARY_WINDOW: usize = 15;

/// Fit `s` on one line of at most `max` characters.
///
/// - Every whitespace run (including embedded newlines and tabs from API
///   free text) collapses to a single space, and the ends are trimmed.
/// - Counts `char`s, never bytes, so multi-byte text never panics.
/// - When it has to cut, it prefers the last space within the final
///   ~15 characters, trims the trailing space, and appends `...`.
/// - The result never exceeds `max` characters (for `max <= 3` there is
///   no room for an ellipsis, so it is a plain hard cut).
pub fn truncate(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    if max <= ELLIPSIS.len() {
        return flat.chars().take(max).collect();
    }
    let budget = max - ELLIPSIS.len();
    let chars: Vec<char> = flat.chars().collect();
    let mut cut = budget;
    // The char right after the cut being a space means the cut already
    // lands on a word boundary; otherwise look back for one.
    if chars[budget] != ' ' {
        if let Some(space) = chars[..budget].iter().rposition(|&c| c == ' ') {
            if space > 0 && space + WORD_BOUNDARY_WINDOW >= budget {
                cut = space;
            }
        }
    }
    let head: String = chars[..cut].iter().collect();
    format!("{}{ELLIPSIS}", head.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plural_counts() {
        assert_eq!(plural(0, "package", "packages"), "0 packages");
        assert_eq!(plural(1, "package", "packages"), "1 package");
        assert_eq!(plural(2, "package", "packages"), "2 packages");
        assert_eq!(plural(1, "patch", "patches"), "1 patch");
        assert_eq!(plural(7, "patch", "patches"), "7 patches");
    }

    #[test]
    fn truncate_short_input_is_untouched() {
        assert_eq!(truncate("hello", 60), "hello");
        assert_eq!(truncate("", 5), "");
        let exact = "a".repeat(10);
        assert_eq!(truncate(&exact, 10), exact);
    }

    #[test]
    fn truncate_ascii_hard_cut_without_nearby_space() {
        let s = "a".repeat(50);
        let out = truncate(&s, 20);
        assert_eq!(out, format!("{}...", "a".repeat(17)));
        assert_eq!(out.chars().count(), 20);
    }

    #[test]
    fn truncate_prefers_word_boundary() {
        let s = "Nuxt route rules silently dropped for mixed-case paths, bypassing appMiddleware";
        let out = truncate(s, 76);
        assert_eq!(
            out,
            "Nuxt route rules silently dropped for mixed-case paths, bypassing..."
        );
        assert!(out.chars().count() <= 76);
    }

    #[test]
    fn truncate_trims_space_before_ellipsis() {
        // The cut lands right after a space: no "word ..." gap.
        let out = truncate("abcdefgh ijklmnopqrstuvwxyz", 12);
        assert_eq!(out, "abcdefgh...");
    }

    #[test]
    fn truncate_far_boundary_falls_back_to_hard_cut() {
        // The only space is further back than the window: cut mid-word.
        let s = format!("ab {}", "c".repeat(40));
        let out = truncate(&s, 30);
        assert_eq!(out, format!("ab {}...", "c".repeat(24)));
        assert_eq!(out.chars().count(), 30);
    }

    #[test]
    fn truncate_multibyte_is_char_safe() {
        let s = "é".repeat(100);
        let out = truncate(&s, 10);
        assert_eq!(out, format!("{}...", "é".repeat(7)));
        let cjk = "漏洞修复".repeat(10);
        assert_eq!(truncate(&cjk, 5).chars().count(), 5);
        // 90 bytes but 30 chars: fits under 80 and is returned untouched
        // (a byte-length check would cut it, a byte slice would panic).
        let fits = "日".repeat(30);
        assert_eq!(truncate(&fits, 80), fits);
    }

    #[test]
    fn truncate_collapses_newlines_and_tabs() {
        assert_eq!(
            truncate("line one\nline\ttwo  \r\n three", 80),
            "line one line two three"
        );
        let out = truncate("first\nsecond third fourth", 16);
        assert!(!out.contains('\n'), "{out:?}");
        assert_eq!(out, "first second...");
    }

    #[test]
    fn truncate_tiny_max_never_exceeds() {
        let s = "abcdefgh";
        assert_eq!(truncate(s, 0), "");
        assert_eq!(truncate(s, 1), "a");
        assert_eq!(truncate(s, 3), "abc");
        assert_eq!(truncate(s, 4), "a...");
        for max in 0..12 {
            assert!(truncate("some words here ok", max).chars().count() <= max);
        }
    }
}
