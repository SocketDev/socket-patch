//! Pure text helpers for human output: counted nouns, one-line
//! truncation, sentence casing and the "Next steps:" block. No I/O, no
//! terminal state.

/// `plural(1, "package", "packages")` → `"1 package"`,
/// `plural(2, "package", "packages")` → `"2 packages"` (and `0 packages`).
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

const ELLIPSIS: &str = "...";

/// How far back from the cut point a word boundary is still preferred
/// over a hard mid-word cut.
const WORD_BOUNDARY_WINDOW: usize = 15;

/// The "Next steps:" block printed after a hosted or vendored run that
/// changed the project: commit `commit`, then `reinstall` and verify with
/// `vex`, then any `extra` steps. Shared so the two modes read alike.
pub(crate) fn next_steps(commit: &str, reinstall: &str, extra: &[String]) -> Vec<String> {
    let mut steps = vec![
        format!("Commit {commit}."),
        format!("{reinstall}, then run `socket-patch vex` to verify the installed patches."),
    ];
    steps.extend(extra.iter().cloned());
    let mut out = vec!["Next steps:".to_string()];
    out.extend(
        steps
            .iter()
            .enumerate()
            .map(|(i, step)| format!("  {}. {step}", i + 1)),
    );
    out
}

/// Short, display-only prefix of a UUID for log lines. Returns
/// the first 8 bytes when they fall on a char boundary, otherwise the
/// whole string. A naive `&uuid[..8]` panics on a malformed/short UUID in
/// the manifest (out-of-bounds or mid-codepoint); this never does. Pure
/// so the no-panic guarantee is unit-testable.
pub(crate) fn short_uuid(uuid: &str) -> &str {
    uuid.get(..8).unwrap_or(uuid)
}

/// The `cleanup_failed` detail for one sweep pass labelled `label`: the
/// directory-level error that stopped the pass, or — after a pass that
/// kept sweeping past unlink failures — the files it could not remove
/// (their counts of what WAS reclaimed still stand). `None` for a clean
/// pass. Every consumer renders it as `<label> cleanup failed: …`.
pub(crate) fn sweep_failure(
    label: &str,
    pass: &std::io::Result<socket_patch_core::manifest::cleanup_blobs::CleanupResult>,
) -> Option<String> {
    match pass {
        Err(e) => Some(format!("{label} cleanup failed: {e}")),
        Ok(r) if !r.failed.is_empty() => {
            Some(format!("{label} cleanup failed: {}", r.failed.join("; ")))
        }
        Ok(_) => None,
    }
}

/// The message for a manifest that exists but could not be read, naming
/// the file (the bare io/serde text — "Permission denied (os error 13)",
/// "EOF while parsing ..." — doesn't say which file). Shared by `list` and `repair`.
pub(crate) fn manifest_error_message(path: &std::path::Path, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::InvalidData {
        let detail = e.to_string();
        let detail = detail
            .strip_prefix("Failed to parse manifest JSON: ")
            .map(|d| format!("not valid JSON: {d}"))
            .or_else(|| {
                detail
                    .strip_prefix("Invalid manifest: ")
                    .map(str::to_string)
            })
            .unwrap_or(detail);
        format!("Invalid manifest at {}: {detail}", path.display())
    } else {
        format!("Could not read manifest at {}: {e}", path.display())
    }
}

/// Lowercase tool names that keep their spelling at the start of a
/// sentence (`pnpm >=11 rejects…` must not become `Pnpm`).
const LOWERCASE_TOOLS: &[&str] = &[
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "cargo",
    "pip",
    "pipenv",
    "uv",
    "poetry",
    "pdm",
    "hatch",
    "go",
    "gem",
    "bundler",
    "bundle",
    "composer",
    "mvn",
    "gradle",
    "dotnet",
    "deno",
    "rush",
    "vlt",
    "vlx",
    "vlr",
    "sbt",
    "mill",
    "scala-cli",
    "socket-patch",
];

/// `msg` with its first letter uppercased, for a human `Error:` /
/// `Warning:` line: the message is shared with the JSON envelope, which
/// keeps it verbatim. A message that opens with a value rather than an
/// English word — a purl, a patch UUID, a path, a file name, a flag, a
/// code span, or a lowercase tool name — is returned unchanged, since
/// capitalizing it would corrupt text the user may copy and paste. The
/// one capitalizer every command's human error and warning lines use.
pub(crate) fn sentence_case(msg: &str) -> String {
    let first_word = msg
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches([',', '.', ';', ':']);
    let is_plain_word = first_word.chars().next().is_some_and(char::is_lowercase)
        && first_word
            .chars()
            .all(|c| c.is_alphabetic() || c == '\'' || c == '-')
        && !LOWERCASE_TOOLS.contains(&first_word);
    if !is_plain_word {
        return msg.to_string();
    }
    let mut chars = msg.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

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

/// `word` as one argument a user can paste into their shell: bare when it
/// holds only characters no shell treats specially, otherwise quoted (POSIX
/// single quotes; double quotes on Windows, which cmd and PowerShell both
/// read as one argument). A trailing run of backslashes is doubled inside
/// the Windows quotes: the argv parser would otherwise read the last one as
/// escaping the closing quote.
pub(crate) fn shell_word(word: &str) -> String {
    let plain = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '/' | '.' | '_' | '-' | ':' | '+' | '=' | ',' | '@')
            || (cfg!(windows) && c == '\\')
    };
    if !word.is_empty() && word.chars().all(plain) {
        word.to_string()
    } else if cfg!(windows) {
        let trailing = word.len() - word.trim_end_matches('\\').len();
        format!("\"{word}{}\"", "\\".repeat(trailing))
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
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

    #[test]
    fn sentence_case_skips_identifiers_and_tool_names() {
        assert_eq!(sentence_case(""), "");
        assert_eq!(
            sentence_case("failed to write x: y"),
            "Failed to write x: y"
        );
        assert_eq!(sentence_case("path pattern x"), "Path pattern x");
        assert_eq!(sentence_case("cannot read x: y"), "Cannot read x: y");
        assert_eq!(sentence_case("can't, really"), "Can't, really");
        assert_eq!(sentence_case("abcdef matches"), "Abcdef matches");
        assert_eq!(sentence_case("Already upper"), "Already upper");
        // Char-safe on non-ASCII first letters.
        assert_eq!(sentence_case("ülk"), "Ülk");
        assert_eq!(sentence_case("éclair"), "Éclair");
        // Values the user may copy back are never altered.
        assert_eq!(sentence_case("--preserve-state"), "--preserve-state");
        assert_eq!(
            sentence_case("pkg:npm/a@1 matches only hosted records"),
            "pkg:npm/a@1 matches only hosted records"
        );
        assert_eq!(
            sentence_case("a1b2c3d4-0000-4000-8000-000000000000 matches nothing"),
            "a1b2c3d4-0000-4000-8000-000000000000 matches nothing"
        );
        assert_eq!(sentence_case(".socket/x is bad"), ".socket/x is bad");
        assert_eq!(
            sentence_case("pnpm-lock.yaml was repointed"),
            "pnpm-lock.yaml was repointed"
        );
        assert_eq!(sentence_case("`vendor` refused"), "`vendor` refused");
        // Tool names keep their lowercase spelling.
        assert_eq!(sentence_case("pnpm >=11 rejects"), "pnpm >=11 rejects");
        for tool in ["vlt", "vlx", "vlr", "npm,", "socket-patch"] {
            let msg = format!("{tool} ci fails");
            assert_eq!(sentence_case(&msg), msg);
        }
    }

    // The `[update]` log line prints the first 8 chars of the manifest's
    // existing UUID. A naive `&uuid[..8]` panics on a short or non-ASCII
    // value; `short_uuid` must never panic.

    #[test]
    fn short_uuid_truncates_normal_uuid() {
        assert_eq!(
            short_uuid("80630680-4da6-45f9-bba8-b888e0ffd58c"),
            "80630680"
        );
    }

    #[test]
    fn short_uuid_returns_whole_string_when_shorter_than_eight() {
        // `&"abc"[..8]` would panic; the helper falls back to the whole value.
        assert_eq!(short_uuid("abc"), "abc");
        assert_eq!(short_uuid(""), "");
    }

    #[test]
    fn short_uuid_does_not_panic_on_multibyte_boundary() {
        // Byte 8 lands mid-codepoint (each "é" is 2 bytes, so byte 8 is a
        // char boundary here — but byte 7 would not be). Use a value whose
        // 8th byte splits a char to exercise the None fallback.
        let s = "ab€cd"; // '€' is 3 bytes: bytes are a b € c d -> len 7
                         // get(..8) is out of range -> None -> whole string, no panic.
        assert_eq!(short_uuid(s), s);
        // A value where byte 8 splits the trailing multibyte char.
        let s2 = "abcdef€"; // 6 ascii + 3-byte '€' = 9 bytes; byte 8 mid-char
        assert_eq!(short_uuid(s2), s2);
    }

    #[test]
    fn sweep_failure_names_the_pass_or_its_unremoved_files() {
        use socket_patch_core::manifest::cleanup_blobs::CleanupResult;
        let err: std::io::Result<CleanupResult> = Err(std::io::Error::other("denied"));
        assert_eq!(
            sweep_failure("blob", &err).as_deref(),
            Some("blob cleanup failed: denied")
        );
        let clean: std::io::Result<CleanupResult> = Ok(CleanupResult::default());
        assert_eq!(sweep_failure("blob", &clean), None);
        let partial: std::io::Result<CleanupResult> = Ok(CleanupResult {
            failed: vec!["a".into(), "b".into()],
            ..CleanupResult::default()
        });
        assert_eq!(
            sweep_failure("diff", &partial).as_deref(),
            Some("diff cleanup failed: a; b")
        );
    }

    #[test]
    fn manifest_error_message_names_the_file() {
        let path = std::path::Path::new("proj/.socket/manifest.json");
        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(manifest_error_message(path, &io)
            .starts_with("Could not read manifest at proj/.socket/manifest.json: "),);
        let bad_json = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse manifest JSON: EOF while parsing an object at line 2 column 0",
        );
        assert_eq!(
            manifest_error_message(path, &bad_json),
            "Invalid manifest at proj/.socket/manifest.json: not valid JSON: EOF while \
             parsing an object at line 2 column 0"
        );
        let schema = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid manifest: missing field `exportedAt`",
        );
        assert_eq!(
            manifest_error_message(path, &schema),
            "Invalid manifest at proj/.socket/manifest.json: missing field `exportedAt`"
        );
        let other = std::io::Error::new(std::io::ErrorKind::InvalidData, "odd");
        assert_eq!(
            manifest_error_message(path, &other),
            "Invalid manifest at proj/.socket/manifest.json: odd"
        );
    }

    #[test]
    fn next_steps_numbers_commit_reinstall_then_extras() {
        assert_eq!(
            next_steps("a and b", "Run `npm ci`", &["vlt: x".to_string()]),
            vec![
                "Next steps:",
                "  1. Commit a and b.",
                "  2. Run `npm ci`, then run `socket-patch vex` to verify the installed patches.",
                "  3. vlt: x",
            ]
        );
    }
}
