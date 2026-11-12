//! The one Starlark edit, `replace_string_inner`: a byte-span splice of a
//! string's contents (design 5.1).
//!
//! Nothing is re-serialized. The bytes outside the replaced span are the
//! file's own, so its line endings, quotes, comments and layout cannot
//! change, and replacing the new text with the old one gives the original
//! file back byte for byte. The result is read again before it is
//! returned: it must be the same token stream with that one string
//! changed.

use super::lexer::{Eol, Span, Tok, Token};
use super::stmt::{read, BindingKind, File};

/// Why an edit is refused. Nothing is returned to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// The file has both LF and CRLF line ends. Bazel reads it, but the
    /// tools that normalise one kind would turn a one-string change into a
    /// whole-file diff, so it is never edited.
    MixedLineEndings,
    /// The span is not the inside of a plain string literal of this file
    /// (`Tok::Str`): only a string whose value is its source bytes on
    /// every Bazel line is edited.
    NotPlainString,
    /// The string is a name a `load` binds: changing it changes what
    /// every later use of the name means.
    BindsName,
    /// The string does not hold the text the caller expects: the file
    /// changed since it was read.
    Stale,
    /// The new text has the literal's own quote, a backslash or a byte
    /// outside printable ASCII, any of which would need escaping.
    UnsafeText,
    /// The edited file does not read back as the old one with this string
    /// changed.
    RereadMismatch,
}

/// Replace the contents of one plain string literal: `inner` is the range
/// between its quotes ([`super::ValueKind::Str`]), `expect_old` the text
/// it must hold now. Returns the bytes of the edited file.
///
/// The quotes stay as they are, so `new` may not hold the literal's own
/// quote. The other kind is allowed: every text a plain string can hold
/// can be written back, which is what makes the inverse edit total.
pub fn replace_string_inner(
    file: &File<'_>,
    inner: Span,
    expect_old: &str,
    new: &str,
) -> Result<Vec<u8>, EditError> {
    if file.eol == Eol::Mixed {
        return Err(EditError::MixedLineEndings);
    }
    let plain = Tok::Str { inner, plain: true };
    let Some(edited) = file.tokens.iter().position(|t| t.tok == plain) else {
        return Err(EditError::NotPlainString);
    };
    let binds = |kind: BindingKind, span: Span| kind == BindingKind::Load && span == inner;
    if file.bindings.iter().any(|b| binds(b.kind, b.span)) {
        return Err(EditError::BindsName);
    }
    if file.bytes(inner) != expect_old.as_bytes() {
        return Err(EditError::Stale);
    }
    let quote = file.src[inner.0 - 1];
    let safe = |b: u8| (0x20..=0x7E).contains(&b) && b != quote && b != b'\\';
    if !new.bytes().all(safe) {
        return Err(EditError::UnsafeText);
    }
    let out = [&file.src[..inner.0], new.as_bytes(), &file.src[inner.1..]].concat();
    // A file the edit grows past the size cap does not read back.
    let reread = read(&out, file.dialect).map_err(|_| EditError::RereadMismatch)?;
    let same = reads_as_edited(file, &reread, edited, inner, new.len());
    same.then_some(out).ok_or(EditError::RereadMismatch)
}

/// Whether `reread` is `file` with one string changed and nothing else:
/// the string at token `edited`, whose contents `inner` are now `new_len`
/// bytes long. That is the same kind of line end, as many comments and
/// statements, and the same tokens, each one past the string moved by the
/// change in length.
fn reads_as_edited(
    file: &File<'_>,
    reread: &File<'_>,
    edited: usize,
    inner: Span,
    new_len: usize,
) -> bool {
    // Every offset at or past the end of the old text moves by the change
    // in length; the edited token is the only one that straddles it.
    let moved = |at: usize| match at >= inner.1 {
        true => at - (inner.1 - inner.0) + new_len,
        false => at,
    };
    let expected = |(i, t): (usize, &Token)| Token {
        tok: match t.tok {
            Tok::Str { plain, .. } if i == edited => Tok::Str {
                inner: (inner.0, inner.0 + new_len),
                plain,
            },
            Tok::Str { inner, plain } => Tok::Str {
                inner: (moved(inner.0), moved(inner.1)),
                plain,
            },
            other => other,
        },
        start: moved(t.start),
        end: moved(t.end),
        depth: t.depth,
    };
    let tokens = file.tokens.iter().enumerate().map(expected);
    reread.eol == file.eol
        && reread.comments.len() == file.comments.len()
        && reread.stmts.len() == file.stmts.len()
        && reread.tokens.iter().copied().eq(tokens)
}

#[cfg(test)]
mod tests {
    use super::super::stmt::{Dialect, Lookup, StmtKind, ValueKind};
    use super::super::MAX_FILE_BYTES;
    use super::*;

    const MODULE: &str = "module(name = \"m\")\n\n# The pin.\nbazel_dep(\n    name = 'rules_go',  # keep\n    version = \"0.50.1\",\n)\nruby.bundle_fetch(gem_checksums = {\"rack-3.0.8\": \"sha256-old\"})";

    /// The inner span of `bazel_dep(version = ...)` in `MODULE`.
    fn version_of(file: &File<'_>) -> Span {
        let StmtKind::Call(call) = &file.stmts[1].kind else {
            panic!("not a call")
        };
        let Lookup::Found(value) = call.arg("version") else {
            panic!("no version")
        };
        match value.kind {
            ValueKind::Str { inner, .. } => inner.expect("one literal"),
            _ => panic!("not a string"),
        }
    }

    /// Design 5.1: an edit is a splice, so the file's line endings stay,
    /// and the inverse edit restores the file byte for byte.
    #[test]
    fn an_edit_and_its_inverse_are_the_identity_on_lf_and_crlf() {
        for eol in ["\n", "\r\n"] {
            for tail in ["", eol] {
                let src = MODULE.replace('\n', eol) + tail;
                let file = read(src.as_bytes(), Dialect::Module).unwrap();
                let inner = version_of(&file);
                let new = "0.50.1-socket.0a1b2c3d";
                let edited = replace_string_inner(&file, inner, "0.50.1", new).unwrap();
                assert_eq!(edited, src.replace("0.50.1", new).into_bytes());

                let again = read(&edited, Dialect::Module).unwrap();
                assert_eq!(again.eol, file.eol);
                let inner = version_of(&again);
                assert_eq!(again.bytes(inner), new.as_bytes());
                let back = replace_string_inner(&again, inner, new, "0.50.1").unwrap();
                assert_eq!(back, src.as_bytes(), "eol {eol:?} tail {tail:?}");
            }
        }
    }

    #[test]
    fn an_edit_changes_one_string_and_shifts_the_rest() {
        let file = read(MODULE.as_bytes(), Dialect::Module).unwrap();
        let edited = replace_string_inner(&file, version_of(&file), "0.50.1", "1").unwrap();
        let again = read(&edited, Dialect::Module).unwrap();
        // The statement after the edit reads the same, five bytes earlier.
        let (was, now) = (&file.stmts[2], &again.stmts[2]);
        assert_eq!((now.span.0 + 5, now.span.1 + 5), was.span);
        assert_eq!(file.bytes(was.span), again.bytes(now.span));
        assert_eq!(again.stmts[1].leading.len(), 1);
        // A single-quoted string keeps its quotes; an empty string is fine.
        let name = file.tokens.iter().find_map(|t| match t.tok {
            Tok::Str { inner, .. } if file.bytes(inner) == b"rules_go" => Some(inner),
            _ => None,
        });
        let edited = replace_string_inner(&file, name.unwrap(), "rules_go", "").unwrap();
        assert!(String::from_utf8(edited)
            .unwrap()
            .contains("name = '',  # keep"));
    }

    #[test]
    fn what_cannot_be_spliced_safely_is_refused() {
        let file = read(MODULE.as_bytes(), Dialect::Module).unwrap();
        let inner = version_of(&file);
        let edit = |inner, old, new| replace_string_inner(&file, inner, old, new);
        assert_eq!(edit(inner, "0.50.0", "1"), Err(EditError::Stale));
        for new in ["a\"b", "a\\b", "a\nb", "a\tb", "caf\u{e9}", "a\u{7f}"] {
            assert_eq!(
                edit(inner, "0.50.1", new),
                Err(EditError::UnsafeText),
                "{new:?}"
            );
        }
        // The other kind of quote needs no escape, and is what lets an
        // original such as "it's" be restored.
        let quoted = edit(inner, "0.50.1", "it's").unwrap();
        let again = read(&quoted, Dialect::Module).unwrap();
        let inner_again = version_of(&again);
        let restored = replace_string_inner(&again, inner_again, "it's", "0.50.1");
        assert_eq!(restored.as_deref(), Ok(MODULE.as_bytes()));
        let name = (
            MODULE.find("rules_go").unwrap(),
            MODULE.find("rules_go").unwrap() + 8,
        );
        assert_eq!(edit(name, "rules_go", "it's"), Err(EditError::UnsafeText));
        assert!(edit(name, "rules_go", "say \"hi\"").is_ok());
        // Only the exact inside of a string token is a target.
        for span in [
            (inner.0 - 1, inner.1),
            (inner.0, inner.1 + 1),
            (inner.0 + 1, inner.1),
            (0, 6),
        ] {
            assert_eq!(
                edit(span, "0.50.1", "1"),
                Err(EditError::NotPlainString),
                "{span:?}"
            );
        }

        let mixed = MODULE.replacen('\n', "\r\n", 1);
        let file = read(mixed.as_bytes(), Dialect::Module).unwrap();
        let refused = replace_string_inner(&file, version_of(&file), "0.50.1", "1");
        assert_eq!(refused, Err(EditError::MixedLineEndings));

        // A string that is not plain is never edited, whatever it holds.
        for literal in ["\"a\\n\"", "r\"a\"", "\"\"\"a\"\"\"", "\"caf\u{e9}\""] {
            let src = format!("x = {literal}\n");
            let file = read(src.as_bytes(), Dialect::Module).unwrap();
            let inner = file.tokens.iter().find_map(|t| match t.tok {
                Tok::Str { inner, .. } => Some(inner),
                _ => None,
            });
            let old = &src[inner.unwrap().0..inner.unwrap().1];
            let refused = replace_string_inner(&file, inner.unwrap(), old, "b");
            assert_eq!(refused, Err(EditError::NotPlainString), "{literal}");
        }

        // An edit that grows a file past the size the reader takes is
        // refused: its result would not read back. One that keeps the size
        // of the same file is made.
        let mut full = String::from("x = \"a\"\n# ");
        full.push_str(&"c".repeat(MAX_FILE_BYTES - full.len() - 1));
        full.push('\n');
        assert_eq!(full.len(), MAX_FILE_BYTES);
        let at_cap = read(full.as_bytes(), Dialect::Module).unwrap();
        let grow = replace_string_inner(&at_cap, (5, 6), "a", "ab");
        assert_eq!(grow, Err(EditError::RereadMismatch));
        let keep = replace_string_inner(&at_cap, (5, 6), "a", "b").unwrap();
        assert_eq!(keep, full.replacen("\"a\"", "\"b\"", 1).into_bytes());
    }

    /// The re-read guard of design 5.1, on its own. No edit that passes
    /// the checks before it reads back as anything but the file with that
    /// string changed, so the guard is given re-reads that are something
    /// else: each differs from the file in one of the things it compares.
    #[test]
    fn a_reread_is_the_file_with_one_string_changed_or_a_mismatch() {
        const OLD: &str = "V = \"old\" \na()\nb()  # c\n";
        let file = read(OLD.as_bytes(), Dialect::Module).unwrap();
        let (edited, inner) = (2, (5, 8));
        assert_eq!(file.tokens[edited].tok, Tok::Str { inner, plain: true });
        let same = |text: &str, new_len: usize| {
            let reread = read(text.as_bytes(), Dialect::Module).unwrap();
            reads_as_edited(&file, &reread, edited, inner, new_len)
        };
        let new = OLD.replace("old", "new");
        assert!(same(&new, 3));
        // Each replacement keeps every byte offset, so nothing else moves.
        for (what, from, to) in [
            ("the kind of line end", "\" \n", "\"\r\n"),
            ("a comment", "# c", "   "),
            ("a statement", "a()\nb()", "a() b()"),
            ("the kind of a token", "a()", "1()"),
            ("a token", "b()  #", "b(); #"),
        ] {
            assert!(new.contains(from), "{what}");
            assert!(!same(&new.replace(from, to), 3), "{what}");
        }
        // A string of another length moves every token after it by the
        // difference, and by nothing else.
        let longer = OLD.replace("old", "longer");
        assert!(same(&longer, 6));
        assert!(!same(&longer, 3) && !same(&longer, 7) && !same(&new, 6));

        // An empty string starts where it ends, and still does not move.
        let empty = read(b"V = ''\nf()\n", Dialect::Module).unwrap();
        let filled = replace_string_inner(&empty, (5, 5), "", "ab").unwrap();
        assert_eq!(filled, b"V = 'ab'\nf()\n");
        let again = read(&filled, Dialect::Module).unwrap();
        assert!(reads_as_edited(&empty, &again, 2, (5, 5), 2));
        let back = replace_string_inner(&again, (5, 7), "ab", "");
        assert_eq!(back.as_deref(), Ok(&b"V = ''\nf()\n"[..]));
    }

    /// Renaming what a `load` binds would change the meaning of every use
    /// of the name while the token stream stays the same.
    #[test]
    fn a_name_bound_by_load_is_not_a_string_to_edit() {
        let src = "load(\"//:defs.bzl\", \"macro\", alias = \"other\")\nmacro()\n";
        let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
        let inner_of = |text: &str| {
            let at = src.find(text).unwrap();
            (at, at + text.len())
        };
        let edit = |text: &str| replace_string_inner(&file, inner_of(text), text, "x");
        assert_eq!(edit("macro"), Err(EditError::BindsName));
        // The module label and the loaded name behind an alias bind nothing.
        assert!(edit("//:defs.bzl").is_ok());
        assert!(edit("other").is_ok());
    }
}
