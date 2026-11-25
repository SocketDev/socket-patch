//! The text of a block that socket-patch keeps in the root `MODULE.bazel`.
//!
//! A block is the lines from a first line of its kind (`# >>> socket-patch:
//! Maven patches for Bazel (...) >>>`) to [`END`]. It is appended to the
//! file and taken out byte for byte, and it is known by its text alone:
//! [`super::maven`] and [`super::nuget`] each render what they keep there,
//! and a block that is not, byte for byte, what its owner renders for what
//! it names was changed by hand. This module holds what the two share:
//! where a block is, how one is put into a file and taken out of it, and
//! the file as it reads without one.

use std::ops::Range;

use crate::utils::line_endings::terminator;

/// The last line of a block.
pub(super) const END: &str = "# <<< socket-patch <<<";

/// What a `MODULE.bazel` holds of the block whose first line is `begin`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Found {
    None,
    /// From the first byte of its first line to the last of [`END`], and
    /// the number of its first line.
    At(Range<usize>, usize),
    /// A second first line, one that is not as it is written, or no
    /// [`END`]: the line of the first one.
    Edited(usize),
}

/// Whether `line` is the first line of the block of `begin`, as it is
/// written or touched (a blank after it, another end): `begin` up to its
/// bracket. A file without such a line holds no such block.
pub(super) fn begins(line: &str, begin: &str) -> bool {
    let mark = begin.split(" (").next().unwrap_or(begin);
    line.trim_start().starts_with(mark)
}

pub(super) fn find(text: &str, begin: &str) -> Found {
    let (mut at, mut first, mut end) = (0, None, None);
    for (line, whole) in text.split_inclusive('\n').enumerate() {
        let bare = whole.strip_suffix('\n').unwrap_or(whole);
        let bare = bare.strip_suffix('\r').unwrap_or(bare);
        match (first, end) {
            (None, _) if bare == begin => first = Some((at, line + 1)),
            // A second first line, or one that is not as it is written.
            _ if begins(bare, begin) => {
                return Found::Edited(first.map_or(line + 1, |(_, first)| first));
            }
            (Some(_), None) if bare == END => end = Some(at + bare.len()),
            _ => {}
        }
        at += whole.len();
    }
    match (first, end) {
        (None, _) => Found::None,
        (Some((start, line)), Some(end)) => Found::At(start..end, line),
        (Some((_, line)), None) => Found::Edited(line),
    }
}

/// Whether the block at `at` is `rendered`, whose lines a line feed ends,
/// in the line break of its own lines, whatever the rest of a file with
/// both has.
pub(super) fn is(text: &str, at: &Range<usize>, rendered: &str) -> bool {
    let block = &text[at.clone()];
    rendered.replace('\n', terminator(block)) == block
}

/// `module` with the block `rendered` in the place of the one at `at`, in
/// the line break of that one's lines, or as a new one at the end of the
/// file, after one blank line, in the line break of the file
/// ([`terminator`]: the more frequent one of a file with both). A file
/// whose last line has no line break gets a block without one, so that
/// [`cut`] can tell.
pub(super) fn put(module: &str, at: Option<Range<usize>>, rendered: &str) -> String {
    let ended = module.is_empty() || module.ends_with('\n');
    let eol = terminator(at.as_ref().map_or(module, |at| &module[at.clone()]));
    let block = rendered.replace('\n', eol);
    match at {
        Some(at) => format!("{}{block}{}", &module[..at.start], &module[at.end..]),
        None if ended => format!("{module}{eol}{block}{eol}"),
        None => format!("{module}{eol}{eol}{block}"),
    }
}

/// `module` without the block at `at` and what [`put`] put before it: the
/// file is then byte for byte what it was before the block.
pub(super) fn cut(module: &str, at: Range<usize>) -> String {
    let (head, tail) = (&module[..at.start], &module[at.end..]);
    // The line break before the block and, when it ends a blank line, that
    // line; then the block's own line break or, for a block that ends the
    // file without one, the one that was added to the last line. A line
    // break is one of either kind: a file can have both.
    let cut =
        |text: &str| text.len() - text.ends_with('\n') as usize - text.ends_with("\r\n") as usize;
    let blank = |head: &str| cut(head) == 0 || head[..cut(head)].ends_with('\n');
    let after = tail.strip_prefix('\r').unwrap_or(tail).strip_prefix('\n');
    let (head, tail) = match after {
        Some(tail) if blank(head) => (&head[..cut(head)], tail),
        None if tail.is_empty() && blank(head) => (&head[..cut(&head[..cut(head)])], tail),
        Some(tail) => (head, tail),
        None => (head, tail),
    };
    format!("{head}{tail}")
}

/// `module` as the user wrote it: without the block at `at`, and with
/// every line where it was.
pub(super) fn hidden(module: &str, at: Range<usize>) -> String {
    let lines = "\n".repeat(module[at.clone()].matches('\n').count());
    format!("{}{lines}{}", &module[..at.start], &module[at.end..])
}
