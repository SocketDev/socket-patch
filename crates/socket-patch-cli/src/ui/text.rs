//! Pure text helpers for human output: counted nouns, one-line
//! truncation, word wrap, sentence casing and the "Next steps:" block. No
//! I/O, no terminal state.

/// `plural(1, "package", "packages")` → `"1 package"`,
/// `plural(2, "package", "packages")` → `"2 packages"` (and `0 packages`).
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

const ELLIPSIS: &str = "...";

/// Split `text` into wrap tokens at whitespace, except that a
/// backtick-delimited code span (`` `pnpm install --trust-lockfile` ``)
/// stays one token so a command the user copies is never broken across
/// lines. An unclosed span falls back to plain whitespace splitting.
pub(crate) fn wrap_tokens(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut span: Vec<&str> = Vec::new();
    for word in text.split_whitespace() {
        span.push(word);
        let open = span.iter().map(|w| w.matches('`').count()).sum::<usize>() % 2 == 1;
        if !open {
            tokens.push(span.join(" "));
            span.clear();
        }
    }
    tokens.extend(span.into_iter().map(str::to_string));
    tokens
}

/// Greedy word wrap to `width` columns (characters, not bytes). The first
/// line starts with `first_prefix`, later lines with `indent`. A word
/// longer than the line (a URL) gets a line of its own, never split; a
/// backtick code span counts as one word (see [`wrap_tokens`]).
pub(crate) fn wrap_words(
    text: &str,
    width: usize,
    first_prefix: &str,
    indent: &str,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = first_prefix.to_string();
    let mut line_len = first_prefix.chars().count();
    let mut empty = true;
    for word in wrap_tokens(text) {
        let word = word.as_str();
        let wlen = word.chars().count();
        if !empty && line_len + 1 + wlen > width {
            lines.push(std::mem::replace(&mut line, indent.to_string()));
            line_len = indent.chars().count();
            empty = true;
        }
        if !empty {
            line.push(' ');
            line_len += 1;
        }
        line.push_str(word);
        line_len += wlen;
        empty = false;
    }
    lines.push(line);
    lines
}

/// `line` as it prints for a person. With `width` (its stream is a
/// terminal with a person at it) a line that does not fit breaks after a
/// clause (`; `) under a two-space hanging indent, so no clause is cut in
/// two unless it is itself wider than the terminal: such a clause wraps at
/// a word from where the row stands, and the clause after it goes on from
/// there. Without `width` the line is as it is, so a pipe or a log keeps
/// one line.
pub(crate) fn wrap_line(line: &str, width: Option<usize>) -> String {
    const INDENT: &str = "  ";
    let Some(width) = width else {
        return line.to_string();
    };
    let len = |text: &str| text.chars().count();
    // What a row holds beside its indent: every row but the first has one.
    let later = width.saturating_sub(INDENT.len());
    let room = |rows: &[String]| if rows.len() > 1 { later } else { width };
    // Put `text` on the row being filled, or on a new one when it is full.
    fn place(rows: &mut Vec<String>, text: &str, room: usize) {
        let row = rows.last_mut().expect("one row at least");
        if row.is_empty() {
            row.push_str(text);
        } else if row.chars().count() + 1 + text.chars().count() <= room {
            row.push(' ');
            row.push_str(text);
        } else {
            rows.push(text.to_string());
        }
    }
    let mut rows: Vec<String> = vec![String::new()];
    for clause in line.split_inclusive("; ") {
        let clause = clause.trim_end();
        let row = rows.last().expect("one row at least");
        let here = if row.is_empty() {
            len(clause) <= room(&rows)
        } else {
            len(row) + 1 + len(clause) <= room(&rows)
        };
        if here || len(clause) <= later {
            let room = room(&rows);
            place(&mut rows, clause, room);
            continue;
        }
        // Wider than a row: at a word, a code span kept whole.
        for word in wrap_tokens(clause) {
            let room = room(&rows);
            place(&mut rows, &word, room);
        }
    }
    rows.iter()
        .enumerate()
        .map(|(at, row)| match at {
            0 => row.clone(),
            _ => format!("{INDENT}{row}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `text` as it may be printed: without its control characters. For
/// text that came from a service or a project's files, which is shown
/// for reading and must never move the cursor, retitle the terminal or
/// write to its clipboard. One-line fields only: a tab or a newline is a
/// control character too.
pub fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// The worst severity (upper-cased; empty when none is named) and the
/// ids to show for a set of advisories, each given as its id, its
/// severity and its CVEs: an advisory is named by its CVEs, or by its own
/// id when it has none. The ids are sorted, each once.
pub fn worst_and_ids<'a>(
    advisories: impl Iterator<Item = (&'a str, &'a str, &'a [String])>,
) -> (String, Vec<String>) {
    use socket_patch_core::api::ranking::severity_order;
    let mut worst: Option<&str> = None;
    let mut ids = Vec::new();
    for (id, severity, cves) in advisories {
        let severity = severity.trim();
        if !severity.is_empty()
            && worst.is_none_or(|w| severity_order(Some(severity)) < severity_order(Some(w)))
        {
            worst = Some(severity);
        }
        if cves.is_empty() {
            ids.push(id.to_string());
        } else {
            ids.extend(cves.iter().cloned());
        }
    }
    ids.sort();
    ids.dedup();
    (worst.map(str::to_uppercase).unwrap_or_default(), ids)
}

/// How a listing names the packages `purls` name: `name@version` when
/// they are all of one ecosystem (the lines around them say which), the
/// purl otherwise, where a bare name could be either's. The purl is in
/// its display spelling (`canonical_purl`: no qualifiers, percent-decoded).
/// One rule for `scan`, `list` and `vex`, so a package reads the same in
/// each.
pub fn package_names(purls: &[&str]) -> Vec<String> {
    use socket_patch_core::utils::purl::{canonical_purl, purl_parts};
    let parts: Vec<_> = purls.iter().map(|purl| purl_parts(purl)).collect();
    let first = parts.first().and_then(|p| p.as_ref().map(|(ty, _, _)| ty));
    let one_type = first.is_some()
        && parts
            .iter()
            .all(|p| p.as_ref().map(|(ty, _, _)| ty) == first);
    purls
        .iter()
        .zip(&parts)
        .map(|(purl, parts)| match parts {
            Some((_, name, version)) if one_type => format!("{name}@{version}"),
            _ => canonical_purl(purl),
        })
        .collect()
}

/// `items` for a sentence, the first `shown` of them named: `a, b, c and
/// 5 more`.
pub fn folded(items: &[String], shown: usize) -> String {
    if items.len() <= shown {
        return items.join(", ");
    }
    format!(
        "{} and {} more",
        items[..shown].join(", "),
        items.len() - shown
    )
}

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
    numbered_next_steps(&steps)
}

/// [`next_steps`] for a run that already brought the installed packages in
/// line itself (`installed` says so in a few words): there is nothing to
/// reinstall, so the second step is the verification alone.
pub(crate) fn next_steps_installed(commit: &str, installed: &str, extra: &[String]) -> Vec<String> {
    let mut steps = vec![
        format!("Commit {commit}."),
        format!("Run `socket-patch vex` to verify the installed patches ({installed})."),
    ];
    steps.extend(extra.iter().cloned());
    numbered_next_steps(&steps)
}

/// `Next steps:` over `steps`, numbered from 1.
fn numbered_next_steps(steps: &[String]) -> Vec<String> {
    let mut out = vec!["Next steps:".to_string()];
    out.extend(
        steps
            .iter()
            .enumerate()
            .map(|(i, step)| format!("  {}. {step}", i + 1)),
    );
    out
}

/// The "Next steps:" block after an agent-mode run that recorded a patch.
/// Agent mode patches the installed files, so its two steps are to commit
/// `commit` (`.socket/`, and what else the run wired) and to run
/// `socket-patch apply` after every install: `installs` are the install
/// commands of the patched ecosystems (`bundle install`), none when the
/// project's package manager is not known. `apply_now` is a `--save-only`
/// run, whose patches are recorded but not applied yet. `reapply` is false
/// when no install can remove the patches (Go builds from the committed
/// copies), which leaves the commit step alone.
pub(crate) fn agent_next_steps(
    commit: &str,
    installs: &[&str],
    apply_now: bool,
    reapply: bool,
) -> Vec<String> {
    let mut steps = vec![format!("Commit {commit} to keep the patches.")];
    if reapply {
        let every = match installs {
            [] => "every dependency install".to_string(),
            [one] => format!("every `{one}`"),
            [head @ .., last] => format!(
                "every {} and `{last}`",
                head.iter()
                    .map(|c| format!("`{c}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let when = if apply_now { "now, and after" } else { "after" };
        steps.push(format!(
            "Run `socket-patch apply` {when} {every}, locally and in CI. A fresh install \
             removes the patches."
        ));
    } else if apply_now {
        steps.push("Run `socket-patch apply` to apply the patches.".to_string());
    }
    numbered_next_steps(&steps)
}

/// What a command says in a project that holds no patch of any mode (no
/// manifest, no vendored patch, no hosted patch in its lockfiles), in place
/// of "Manifest not found": hosted mode, the default, never has a manifest,
/// so the word tells its users nothing. `nothing_to` is what the command
/// would have done (`roll back`). `moved_manifest` is the manifest path a
/// `--manifest-path` moved it to: it is named, so a mistyped one shows.
pub(crate) fn no_patches_message(
    nothing_to: &str,
    moved_manifest: Option<&std::path::Path>,
) -> String {
    let base = format!("No patches in this project; nothing to {nothing_to}");
    match moved_manifest {
        None => format!("{base}."),
        Some(path) => format!("{base} (no manifest at {}).", path.display()),
    }
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

    /// A line breaks after a clause, a clause is cut only when it is
    /// wider than the terminal, and the clause after one that wrapped goes
    /// on from where it left the row. A pipe keeps one line.
    #[test]
    fn wrap_line_breaks_after_clauses_and_goes_on_after_one_that_wrapped() {
        let kept =
            "nokogiri 1.19.3: patched for aarch64-linux-gnu, x86_64-linux-gnu; upstream gem \
                    kept for arm64-darwin (no patched build yet)";
        assert_eq!(wrap_line(kept, None), kept);
        assert_eq!(wrap_line(kept, Some(200)), kept);
        assert_eq!(
            wrap_line(kept, Some(80)),
            "nokogiri 1.19.3: patched for aarch64-linux-gnu, x86_64-linux-gnu;\n  upstream gem kept \
             for arm64-darwin (no patched build yet)"
        );
        let waiting = "nokogiri 1.19.3: no patched build yet for aarch64-linux-gnu, arm64-darwin, \
                       x86_64-linux-gnu; left on its upstream registry";
        assert_eq!(
            wrap_line(waiting, Some(80)),
            "nokogiri 1.19.3: no patched build yet for aarch64-linux-gnu, arm64-darwin,\n  \
             x86_64-linux-gnu; left on its upstream registry"
        );
        let vendored = "nokogiri@1.19.3 is not vendored: no patched build yet for arm64-darwin \
                        (aarch64-linux-gnu and x86_64-linux-gnu have one). Vendored mode needs \
                        every locked platform; `scan --mode hosted` can patch the others now.";
        assert_eq!(
            wrap_line(vendored, Some(80)),
            "nokogiri@1.19.3 is not vendored: no patched build yet for arm64-darwin\n  \
             (aarch64-linux-gnu and x86_64-linux-gnu have one). Vendored mode needs every\n  \
             locked platform; `scan --mode hosted` can patch the others now."
        );
        for width in [80, 100, 120] {
            for line in [kept, waiting, vendored] {
                let wrapped = wrap_line(line, Some(width));
                assert!(
                    wrapped.lines().all(|row| row.chars().count() <= width),
                    "{width}: {wrapped}"
                );
                assert_eq!(wrapped.replace("\n  ", " "), line, "nothing is lost");
            }
        }
    }

    #[test]
    fn wrap_words_respects_width_prefix_and_long_words() {
        assert_eq!(
            wrap_words("alpha beta gamma delta", 16, "W: ", "  "),
            vec!["W: alpha beta", "  gamma delta"]
        );
        // A word wider than the line sits alone, unsplit.
        let url = "https://patch.socket.dev/very/long/path/that/does/not/fit";
        assert_eq!(
            wrap_words(&format!("see {url} now"), 20, "", "  "),
            vec!["see".to_string(), format!("  {url}"), "  now".to_string()]
        );
        assert_eq!(wrap_words("", 10, "W: ", "  "), vec!["W: "]);
        // Counts characters, not bytes.
        let lines = wrap_words("ééé ééé ééé", 8, "", "");
        assert_eq!(lines, vec!["ééé ééé", "ééé"]);
        for line in wrap_words(&"word ".repeat(50), 30, "Warning: ", "  ") {
            assert!(line.chars().count() <= 30, "{line}");
        }
    }

    #[test]
    fn wrap_words_keeps_code_spans_whole() {
        // The span crosses the wrap column: it moves to the next line whole.
        assert_eq!(
            wrap_words(
                "never rebuild it (`pnpm clean --lockfile`), ever",
                30,
                "",
                "  "
            ),
            vec!["never rebuild it", "  (`pnpm clean --lockfile`),", "  ever"]
        );
        // A span wider than the line gets a line of its own, unsplit.
        assert_eq!(
            wrap_words(
                "use `pnpm install --frozen-lockfile --store-dir <dir>` now",
                20,
                "",
                "  "
            ),
            vec![
                "use",
                "  `pnpm install --frozen-lockfile --store-dir <dir>`",
                "  now"
            ]
        );
        // Two spans in one word, and a word with a closed span, split normally.
        assert_eq!(
            wrap_tokens("a `b` c `d e`f g"),
            vec!["a", "`b`", "c", "`d e`f", "g"]
        );
        // An unclosed span never swallows the rest of the text.
        assert_eq!(wrap_tokens("a `b c d"), vec!["a", "`b", "c", "d"]);
    }

    #[test]
    fn packages_of_one_ecosystem_are_named_without_it() {
        assert_eq!(
            package_names(&["pkg:npm/%40scope/a@1.0.0", "pkg:npm/b@2.0.0?x=1"]),
            ["@scope/a@1.0.0", "b@2.0.0"]
        );
        assert_eq!(
            package_names(&["pkg:npm/%40scope/a@1.0.0", "pkg:pypi/b@2.0.0"]),
            ["pkg:npm/@scope/a@1.0.0", "pkg:pypi/b@2.0.0"]
        );
        assert_eq!(package_names(&["not a purl"]), ["not a purl"]);
        assert!(package_names(&[]).is_empty());
    }

    /// One rule for the severity and the ids of a set of advisories,
    /// wherever a patch is named in a line: the `list` row, `show`'s
    /// title and the patch menu.
    #[test]
    fn worst_and_ids_names_advisories_by_cve_and_skips_blank_severities() {
        let cves = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
        let (two, none, shared) = (cves(&["CVE-2", "CVE-1"]), cves(&[]), cves(&["CVE-1"]));
        let advisories = [
            ("GHSA-b", "moderate", two.as_slice()),
            ("GHSA-a", " High ", none.as_slice()),
            ("GHSA-c", "", shared.as_slice()),
        ];
        assert_eq!(
            worst_and_ids(advisories.into_iter()),
            (
                "HIGH".to_string(),
                vec![
                    "CVE-1".to_string(),
                    "CVE-2".to_string(),
                    "GHSA-a".to_string()
                ]
            )
        );
        // No severity named at all: none is shown, not an empty one.
        assert_eq!(
            worst_and_ids([("GHSA-c", "  ", none.as_slice())].into_iter()),
            (String::new(), vec!["GHSA-c".to_string()])
        );
        assert_eq!(
            worst_and_ids(std::iter::empty()),
            (String::new(), Vec::new())
        );
    }

    #[test]
    fn printable_drops_every_control_character() {
        assert_eq!(printable("lib/a.js"), "lib/a.js");
        assert_eq!(
            printable("a\u{1b}]0;title\u{7}b\u{1b}[2Jc\r\n\td"),
            "a]0;titleb[2Jcd"
        );
        assert_eq!(printable("é 漢字 \u{9b}31m"), "é 漢字 31m");
    }

    #[test]
    fn folded_names_the_first_few_and_counts_the_rest() {
        let items: Vec<String> = ["a", "b", "c", "d", "e"].map(String::from).to_vec();
        assert_eq!(folded(&items, 3), "a, b, c and 2 more");
        assert_eq!(folded(&items[..3], 3), "a, b, c");
        assert_eq!(folded(&items[..1], 3), "a");
        assert_eq!(folded(&[], 3), "");
    }

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

    #[test]
    fn agent_next_steps_name_the_commit_and_the_reapply_after_each_install() {
        assert_eq!(
            agent_next_steps(".socket/", &["bundle install"], false, true),
            vec![
                "Next steps:",
                "  1. Commit .socket/ to keep the patches.",
                "  2. Run `socket-patch apply` after every `bundle install`, locally and in CI. \
                 A fresh install removes the patches.",
            ]
        );
        let two = agent_next_steps(".socket/", &["npm install", "pip install"], false, true);
        assert!(
            two[2].contains("after every `npm install` and `pip install`, locally"),
            "{two:?}"
        );
        let three = agent_next_steps(".socket/", &["a", "b", "c"], false, true);
        assert!(
            three[2].contains("after every `a`, `b` and `c`,"),
            "{three:?}"
        );
        // No known package manager: still say when to re-apply.
        let unknown = agent_next_steps(".socket/", &[], false, true);
        assert!(
            unknown[2].contains("after every dependency install, locally"),
            "{unknown:?}"
        );
        // `--save-only` recorded the patch without applying it.
        let saved = agent_next_steps(".socket/", &["npm install"], true, true);
        assert!(
            saved[2]
                .starts_with("  2. Run `socket-patch apply` now, and after every `npm install`,"),
            "{saved:?}"
        );
        // Nothing an install could undo: the commit is the only step.
        assert_eq!(
            agent_next_steps(".socket/ and go.mod", &[], false, false),
            vec![
                "Next steps:",
                "  1. Commit .socket/ and go.mod to keep the patches."
            ]
        );
        assert_eq!(
            agent_next_steps(".socket/ and go.mod", &[], true, false)[2],
            "  2. Run `socket-patch apply` to apply the patches."
        );
        // No sentence runs past 25 words.
        for line in agent_next_steps(".socket/", &["bundle install"], true, true) {
            for sentence in line.split(". ") {
                assert!(sentence.split_whitespace().count() <= 25, "{sentence}");
            }
        }
    }

    #[test]
    fn no_patches_message_names_only_a_manifest_path_of_the_users_own() {
        assert_eq!(
            no_patches_message("roll back", None),
            "No patches in this project; nothing to roll back."
        );
        assert_eq!(
            no_patches_message("remove", Some(std::path::Path::new("ops/patches.json"))),
            "No patches in this project; nothing to remove (no manifest at ops/patches.json)."
        );
    }

    #[test]
    fn shell_word_quotes_only_what_the_shell_would_split() {
        assert_eq!(shell_word("tools/x"), "tools/x");
        assert_eq!(shell_word("/repo/@scope/x-1.0"), "/repo/@scope/x-1.0");
        if cfg!(windows) {
            assert_eq!(shell_word(r"C:\repo\x"), r"C:\repo\x");
            assert_eq!(shell_word("tools/my x"), "\"tools/my x\"");
            assert_eq!(shell_word("100%"), "\"100%\"");
            assert_eq!(shell_word(r"my dir\"), r#""my dir\\""#);
            assert_eq!(shell_word(""), "\"\"");
        } else {
            assert_eq!(shell_word("tools/my x"), "'tools/my x'");
            assert_eq!(shell_word("100%"), "'100%'");
            assert_eq!(shell_word("it's"), r"'it'\''s'");
            assert_eq!(shell_word("$HOME"), "'$HOME'");
            assert_eq!(shell_word(""), "''");
        }
    }
}
