//! A line diff and its unified rendering, for showing what a patch changes
//! in a file. Pure: bytes in, lines of text out.
//!
//! The diff is Myers' shortest edit script over lines, bounded: a file
//! that changes beyond [`MAX_EDIT_DISTANCE`] lines is shown as replaced
//! whole rather than diffed for as long as it takes. What is rendered is
//! for reading, not for `patch(1)`: control characters in a line are
//! spelled out (file contents come from the network and must not drive the
//! terminal) and a very long line is cut.

use super::{paint, Style};

/// Lines of context around a change.
const CONTEXT: usize = 3;
/// The longest edit script searched for. Past it (a file rewritten
/// wholesale) the two sides are shown as one removal and one addition.
const MAX_EDIT_DISTANCE: usize = 1000;
/// Characters of one line shown before it is cut (a minified bundle is one
/// line of megabytes).
const MAX_LINE_CHARS: usize = 400;

/// One step of an edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Remove,
    Add,
}

/// The shortest edit script turning `a` into `b` (Myers), or `None` when
/// it is longer than `limit`.
fn shortest_edit<T: PartialEq>(a: &[T], b: &[T], limit: usize) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let limit = limit.min(a.len() + b.len()) as isize;
    // `v[k + offset]`: the furthest x reached on diagonal k = x - y. A
    // round d reads diagonals -d-1..=d+1.
    let offset = limit + 1;
    let mut v = vec![0isize; (2 * limit + 3) as usize];
    // Per round, the diagonals it read, as they were before it.
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = false;
    'rounds: for d in 0..=limit {
        trace.push(v[(offset - d - 1) as usize..=(offset + d + 1) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let down =
                k == -d || (k != d && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize]);
            let mut x = if down {
                v[(k + 1 + offset) as usize]
            } else {
                v[(k - 1 + offset) as usize] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[(k + offset) as usize] = x;
            if x >= n && y >= m {
                found = true;
                break 'rounds;
            }
            k += 2;
        }
    }
    if !found {
        return None;
    }
    // Walk the rounds back from the end, emitting the script in reverse.
    let mut ops = Vec::new();
    let (mut x, mut y) = (n, m);
    for (d, seen) in trace.iter().enumerate().rev() {
        let d = d as isize;
        // `seen[k + d + 1]` is the round's view of diagonal k.
        let at = |k: isize| seen[(k + d + 1) as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Keep);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            ops.push(if x == prev_x { Op::Add } else { Op::Remove });
        }
        x = prev_x;
        y = prev_y;
    }
    ops.reverse();
    Some(ops)
}

/// The edit script turning `a` into `b`: the shortest one, or (past
/// [`MAX_EDIT_DISTANCE`]) every line between their common head and tail
/// removed, then added.
fn edit_script<T: PartialEq>(a: &[T], b: &[T]) -> Vec<Op> {
    let head = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (mid_a, mid_b) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let middle = shortest_edit(mid_a, mid_b, MAX_EDIT_DISTANCE).unwrap_or_else(|| {
        std::iter::repeat_n(Op::Remove, mid_a.len())
            .chain(std::iter::repeat_n(Op::Add, mid_b.len()))
            .collect()
    });
    std::iter::repeat_n(Op::Keep, head)
        .chain(middle)
        .chain(std::iter::repeat_n(Op::Keep, tail))
        .collect()
}

/// What a patch does to one file, ready to print.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FileDiff {
    /// Lines the patch adds, and lines it removes.
    pub(crate) added: usize,
    pub(crate) removed: usize,
    /// Either side is not text: no line diff, one line saying so.
    pub(crate) binary: bool,
    /// The unified diff: its two header lines, then the hunks.
    pub(crate) lines: Vec<String>,
}

/// Whether `bytes` are text a line diff makes sense of: valid UTF-8 with
/// no NUL.
fn as_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.contains('\0')).then_some(text)
}

/// One line of file content as it is shown: without its line ending, tabs
/// kept, every other control character spelled in caret notation (`^[` for
/// ESC), and cut at [`MAX_LINE_CHARS`] with the count of what was left
/// out.
fn shown(line: &str) -> String {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let mut out = String::with_capacity(line.len().min(MAX_LINE_CHARS * 4));
    let mut chars = line.chars();
    for c in chars.by_ref().take(MAX_LINE_CHARS) {
        match c {
            '\t' => out.push('\t'),
            '\x7f' => out.push_str("^?"),
            c if (c as u32) < 0x20 => {
                out.push('^');
                out.push((c as u8 + 0x40) as char);
            }
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    let rest = chars.count();
    if rest > 0 {
        out.push_str(&format!(" ...[+{rest} characters]"));
    }
    out
}

/// The unified diff of one file: `before` (absent for a file the patch
/// adds) against `after`, with [`CONTEXT`] lines around each change.
/// `style` colors it: removals red, additions green, hunk headers cyan,
/// the file headers bold.
pub(crate) fn file_diff(path: &str, before: Option<&[u8]>, after: &[u8], style: Style) -> FileDiff {
    let color = style.color;
    let old_name = match before {
        Some(_) => format!("a/{path}"),
        None => "/dev/null".to_string(),
    };
    let mut lines = vec![
        paint(&format!("--- {old_name}"), "1", color),
        paint(&format!("+++ b/{path}"), "1", color),
    ];
    let before_bytes = before.unwrap_or_default();
    let (Some(old), Some(new)) = (as_text(before_bytes), as_text(after)) else {
        lines.push(format!(
            "Binary file changed ({} -> {} bytes)",
            before_bytes.len(),
            after.len()
        ));
        return FileDiff {
            binary: true,
            lines,
            ..FileDiff::default()
        };
    };
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = edit_script(&a, &b);
    let (added, removed) = ops.iter().fold((0, 0), |(add, rem), op| match op {
        Op::Add => (add + 1, rem),
        Op::Remove => (add, rem + 1),
        Op::Keep => (add, rem),
    });

    // The script's steps that belong to a hunk: each change with its
    // context, hunks closer than two contexts merged.
    let changed: Vec<usize> = (0..ops.len()).filter(|&i| ops[i] != Op::Keep).collect();
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for &i in &changed {
        let (start, end) = (i.saturating_sub(CONTEXT), (i + CONTEXT + 1).min(ops.len()));
        match hunks.last_mut() {
            Some(last) if start <= last.1 => last.1 = end,
            _ => hunks.push((start, end)),
        }
    }
    // Line numbers (0-based) of each step on either side.
    let mut position = Vec::with_capacity(ops.len());
    let (mut x, mut y) = (0usize, 0usize);
    for op in &ops {
        position.push((x, y));
        match op {
            Op::Keep => {
                x += 1;
                y += 1;
            }
            Op::Remove => x += 1,
            Op::Add => y += 1,
        }
    }
    for (start, end) in hunks {
        let steps = &ops[start..end];
        let old_len = steps.iter().filter(|op| **op != Op::Add).count();
        let new_len = steps.iter().filter(|op| **op != Op::Remove).count();
        let (old_at, new_at) = position[start];
        // A side with no lines names the line before it, as `diff -u` does.
        let from = |at: usize, len: usize| if len == 0 { at } else { at + 1 };
        lines.push(paint(
            &format!(
                "@@ -{},{old_len} +{},{new_len} @@",
                from(old_at, old_len),
                from(new_at, new_len)
            ),
            "36",
            color,
        ));
        for (i, op) in steps.iter().enumerate() {
            let (x, y) = position[start + i];
            let (mark, text, code) = match op {
                Op::Keep => (' ', a[x], ""),
                Op::Remove => ('-', a[x], "31"),
                Op::Add => ('+', b[y], "32"),
            };
            let line = format!("{mark}{}", shown(text));
            lines.push(if code.is_empty() {
                line
            } else {
                paint(&line, code, color)
            });
            if !text.ends_with('\n') {
                lines.push("\\ No newline at end of file".to_string());
            }
        }
    }
    FileDiff {
        added,
        removed,
        binary: false,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Style = Style::PLAIN;

    /// Apply a script to `a`: what it produces must be `b`.
    fn apply<'a>(ops: &[Op], a: &[&'a str], b: &[&'a str]) -> Vec<&'a str> {
        let (mut x, mut y) = (0, 0);
        let mut out = Vec::new();
        for op in ops {
            match op {
                Op::Keep => {
                    assert_eq!(a[x], b[y], "a kept line is the same on both sides");
                    out.push(a[x]);
                    x += 1;
                    y += 1;
                }
                Op::Remove => x += 1,
                Op::Add => {
                    out.push(b[y]);
                    y += 1;
                }
            }
        }
        assert_eq!((x, y), (a.len(), b.len()), "the script covers both sides");
        out
    }

    fn edits(ops: &[Op]) -> usize {
        ops.iter().filter(|op| **op != Op::Keep).count()
    }

    #[test]
    fn edit_script_is_shortest_and_reproduces_the_target() {
        // Myers' own example: ABCABBA -> CBABAC is five edits.
        let a: Vec<&str> = "ABCABBA".split("").filter(|s| !s.is_empty()).collect();
        let b: Vec<&str> = "CBABAC".split("").filter(|s| !s.is_empty()).collect();
        let ops = edit_script(&a, &b);
        assert_eq!(apply(&ops, &a, &b), b);
        assert_eq!(edits(&ops), 5);

        let cases: &[(&[&str], &[&str], usize)] = &[
            (&[], &[], 0),
            (&[], &["x"], 1),
            (&["x"], &[], 1),
            (&["a", "b", "c"], &["a", "b", "c"], 0),
            (&["a", "b", "c"], &["a", "x", "c"], 2),
            (&["a", "b", "c"], &["a", "c"], 1),
            (&["a", "c"], &["a", "b", "c"], 1),
            (&["a", "b"], &["c", "d"], 4),
            (&["a", "a", "a"], &["a", "a"], 1),
        ];
        for (a, b, want) in cases {
            let ops = edit_script(a, b);
            assert_eq!(apply(&ops, a, b), *b, "{a:?} -> {b:?}");
            assert_eq!(edits(&ops), *want, "{a:?} -> {b:?}");
        }
    }

    /// A rewrite past the search bound is still a correct script: the
    /// common head and tail kept, the middle replaced.
    #[test]
    fn a_wholesale_rewrite_falls_back_to_replacing_the_middle() {
        let old: Vec<String> = (0..MAX_EDIT_DISTANCE + 50)
            .map(|i| format!("old {i}"))
            .collect();
        let new: Vec<String> = (0..MAX_EDIT_DISTANCE + 50)
            .map(|i| format!("new {i}"))
            .collect();
        let mut a: Vec<&str> = vec!["head"];
        a.extend(old.iter().map(String::as_str));
        a.push("tail");
        let mut b: Vec<&str> = vec!["head"];
        b.extend(new.iter().map(String::as_str));
        b.push("tail");
        let ops = edit_script(&a, &b);
        assert_eq!(apply(&ops, &a, &b), b);
        assert_eq!(ops[0], Op::Keep);
        assert_eq!(ops[ops.len() - 1], Op::Keep);
        assert_eq!(edits(&ops), old.len() + new.len());
    }

    #[test]
    fn file_diff_is_unified_with_context_and_counts() {
        let before = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
        let after = "one\ntwo\nthree\nfour\nFIVE\nsix\nseven\neight\nnine\nten\neleven\n";
        let diff = file_diff("lib/a.js", Some(before.as_bytes()), after.as_bytes(), PLAIN);
        assert_eq!((diff.added, diff.removed, diff.binary), (2, 1, false));
        assert_eq!(
            diff.lines,
            vec![
                "--- a/lib/a.js",
                "+++ b/lib/a.js",
                "@@ -2,9 +2,10 @@",
                " two",
                " three",
                " four",
                "-five",
                "+FIVE",
                " six",
                " seven",
                " eight",
                " nine",
                " ten",
                "+eleven",
            ]
        );
        // Changes further apart than their contexts get hunks of their own.
        let lines: Vec<String> = (1..=30).map(|i| format!("l{i}\n")).collect();
        let old = lines.concat();
        let mut changed = lines.clone();
        changed[1] = "L2\n".to_string();
        changed[27] = "L28\n".to_string();
        let diff = file_diff(
            "a",
            Some(old.as_bytes()),
            changed.concat().as_bytes(),
            PLAIN,
        );
        let headers: Vec<&String> = diff.lines.iter().filter(|l| l.starts_with("@@")).collect();
        assert_eq!(headers, ["@@ -1,5 +1,5 @@", "@@ -25,6 +25,6 @@"]);
        // Nothing changed: the headers alone.
        let same = file_diff("a", Some(b"x\n"), b"x\n", PLAIN);
        assert_eq!((same.added, same.removed, same.lines.len()), (0, 0, 2));
    }

    #[test]
    fn file_diff_of_an_added_file_and_a_missing_final_newline() {
        let diff = file_diff("new.txt", None, b"a\nb", PLAIN);
        assert_eq!((diff.added, diff.removed), (2, 0));
        assert_eq!(
            diff.lines,
            vec![
                "--- /dev/null",
                "+++ b/new.txt",
                "@@ -0,0 +1,2 @@",
                "+a",
                "+b",
                "\\ No newline at end of file",
            ]
        );
        // The patch adds the missing newline: the old last line says so.
        let diff = file_diff("f", Some(b"a\nb"), b"a\nb\n", PLAIN);
        assert_eq!(
            diff.lines[2..],
            [
                "@@ -1,2 +1,2 @@",
                " a",
                "-b",
                "\\ No newline at end of file",
                "+b"
            ]
        );
    }

    #[test]
    fn file_diff_of_binary_content_says_so() {
        let diff = file_diff("lib.so", Some(&[0u8, 1, 2]), &[0u8, 1, 2, 3], PLAIN);
        assert!(diff.binary);
        assert_eq!(
            diff.lines,
            vec![
                "--- a/lib.so",
                "+++ b/lib.so",
                "Binary file changed (3 -> 4 bytes)"
            ]
        );
        // Invalid UTF-8 is binary too.
        assert!(file_diff("x", Some(b"ok\n"), &[0xff, 0xfe], PLAIN).binary);
    }

    /// File content never drives the terminal: an escape sequence is
    /// spelled out, and a line of megabytes is cut.
    #[test]
    fn shown_lines_spell_out_control_characters_and_cut_long_lines() {
        assert_eq!(shown("a\tb\r\n"), "a\tb");
        assert_eq!(shown("x\x1b[2Jy\x07\x7f\n"), "x^[[2Jy^G^?");
        assert_eq!(shown("caf\u{e9} \u{6f22}"), "caf\u{e9} \u{6f22}");
        assert_eq!(shown("a\u{9b}b"), "a?b");
        let long = "x".repeat(MAX_LINE_CHARS + 25);
        assert_eq!(
            shown(&long),
            format!("{} ...[+25 characters]", "x".repeat(MAX_LINE_CHARS))
        );
        let diff = file_diff("f", Some(b"a\n"), b"a\x1b[31m\n", PLAIN);
        assert_eq!(diff.lines[3..], ["-a", "+a^[[31m"]);
    }

    #[test]
    fn file_diff_colors_by_kind_of_line() {
        let color = Style {
            color: true,
            glyphs: false,
        };
        let diff = file_diff("f", Some(b"a\nb\n"), b"a\nc\n", color);
        assert_eq!(
            diff.lines,
            vec![
                "\x1b[1m--- a/f\x1b[0m",
                "\x1b[1m+++ b/f\x1b[0m",
                "\x1b[36m@@ -1,2 +1,2 @@\x1b[0m",
                " a",
                "\x1b[31m-b\x1b[0m",
                "\x1b[32m+c\x1b[0m",
            ]
        );
    }
}
