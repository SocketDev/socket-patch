//! pip requirements-file grammar shared by its readers: the vendored
//! requirements planner (`vendor::pypi_requirements`), the lockfile
//! inventory (`vendor::lock_inventory`) and lockfile discovery
//! (`vex::discover::pypi_other`) all lex through [`logical_lines`], so the
//! file that is rewired and the file that is read back agree on what a line
//! is and where its comment starts. The hosted requirements rewriter
//! (`patch::redirect`'s requirements module) shares the artifact-filename
//! grammar ([`archive_filename_coords`]) and keeps its own line splitter,
//! which carries each line's ending for byte-exact rewrites.
//!
//! Logical-line model (pip's `join_lines` + `ignore_comments`): physical
//! lines join on a trailing `\` — never on a comment line — and a comment
//! starts at a `#` in column 0 or after whitespace, so `…whl#sha256=…` and
//! `--hash=sha256:ab#cd` are data. Exactly one leading BOM is encoding, not
//! data (pip decodes with utf-8-sig; uv strips it too).

/// One logical requirements line.
pub(crate) struct LogicalLine {
    /// 0-based index of the first physical line.
    pub(crate) start: usize,
    /// The raw physical lines (no newlines, no `\r`).
    pub(crate) physical: Vec<String>,
    /// Continuation-joined text (comments NOT yet stripped).
    pub(crate) text: String,
}

/// Split `content` into pip's logical lines (see the module docs).
pub(crate) fn logical_lines(content: &str) -> Vec<LogicalLine> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let mut physical = vec![lines[i].to_string()];
        // pip's join_lines never continues a comment line: `# ...\` is a
        // complete comment, not a continuation of the next line. The file's
        // BOM is not part of the first line's text (below), so it cannot
        // hide that line's comment either.
        let comment = |i: usize| {
            let line = if i == 0 {
                lines[0].strip_prefix('\u{feff}').unwrap_or(lines[0])
            } else {
                lines[i]
            };
            line.trim_start().starts_with('#')
        };
        while lines[i].trim_end().ends_with('\\') && !comment(i) && i + 1 < lines.len() {
            i += 1;
            physical.push(lines[i].to_string());
        }
        let mut text = String::new();
        for (k, pl) in physical.iter().enumerate() {
            if k + 1 < physical.len() {
                // pip's join: the backslash and the newline vanish.
                text.push_str(pl.trim_end().strip_suffix('\\').unwrap_or(pl));
            } else {
                text.push_str(pl);
            }
        }
        // Only `text` (the parse substrate) drops the BOM — `physical`
        // stays raw, so a rewrite records (and a revert restores) the
        // original bytes.
        if start == 0 {
            if let Some(stripped) = text.strip_prefix('\u{feff}') {
                text = stripped.to_string();
            }
        }
        out.push(LogicalLine {
            start,
            physical,
            text,
        });
        i += 1;
    }
    out
}

/// `(code, comment)` of one logical line: the comment starts at a `#` in
/// column 0 or preceded by whitespace (`--hash=sha256:ab#cd` and a url's
/// `#sha256=` fragment are data, not comments).
pub(crate) fn split_comment(text: &str) -> (&str, Option<&str>) {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return (&text[..i], Some(&text[i + 1..]));
        }
    }
    (text, None)
}

/// [`split_comment`]'s code part.
pub(crate) fn strip_comment(text: &str) -> &str {
    split_comment(text).0
}

/// pip's `expand_env_variables`: each `${NAME}` whose `NAME` is
/// `[A-Z0-9_]+` is replaced by `lookup(NAME)`; an unset or empty variable
/// leaves the reference as written. pip expands after stripping comments
/// and before it splits the options, so a variable can carry quotes or
/// spaces that the split then reads.
pub(crate) fn expand_env_vars(code: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let name_len = after
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(after.len());
        let value = (name_len > 0 && after[name_len..].starts_with('}'))
            .then(|| lookup(&after[..name_len]))
            .flatten()
            .filter(|v| !v.is_empty());
        match value {
            Some(v) => {
                out.push_str(&v);
                rest = &after[name_len + 1..];
            }
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Python's `shlex.split` (POSIX mode), which pip runs over a line's
/// options: whitespace separates words; `'…'` is literal; inside `"…"` a
/// backslash escapes only `"` and `\`; elsewhere a backslash escapes any
/// character; adjacent quoted and bare parts join into one word, and `""`
/// is an empty word. `None` for an unclosed quote or a trailing lone
/// backslash, which pip refuses ("Could not split options").
pub(crate) fn shlex_split(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\\' => {
                word.push(chars.next()?);
                in_word = true;
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        ch => word.push(ch),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => {
                            let next = chars.next()?;
                            if next != '"' && next != '\\' {
                                word.push('\\');
                            }
                            word.push(next);
                        }
                        ch => word.push(ch),
                    }
                }
            }
            _ => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Some(words)
}

/// The `(name as spelled, version)` of an exact `name[extras]==X` registry
/// requirement (a logical line's code part; an optional `; marker` and
/// options may follow), `None` for anything else — ranges, `===`, wildcards
/// (`==1.*`), a version not starting with a digit. Spelled as pip reads it:
/// whitespace may surround the extras and the `==` (`six == 1.0`,
/// `six[x] ==1.0`), and the legacy parenthesised form `six (==1.0)` is the
/// same pin. The ONE exact-pin rule the lock inventory and lockfile
/// discovery read requirements with.
pub(crate) fn exact_pin(code: &str) -> Option<(&str, &str)> {
    let spec = code.split(';').next()?.trim_start();
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(spec.len());
    let (name, mut rest) = spec.split_at(name_end);
    rest = rest.trim_start();
    if rest.starts_with('[') {
        rest = rest[rest.find(']')? + 1..].trim_start();
    }
    let parenthesised = rest.starts_with('(');
    if parenthesised {
        rest = rest[1..].trim_start();
    }
    rest = rest.strip_prefix("==")?.trim_start();
    let version_end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, ')' | ','))
        .unwrap_or(rest.len());
    let (version, mut rest) = rest.split_at(version_end);
    rest = rest.trim_start();
    if parenthesised {
        rest = rest.strip_prefix(')')?.trim_start();
    }
    // Only options (`--hash=…`) may follow the specifier; anything else
    // (`,<2`, a stray `)`, a second token) is not one exact pin.
    if name.is_empty()
        || !(rest.is_empty() || rest.starts_with("--"))
        || version.starts_with('=')
        || version.contains('*')
        || !version.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    Some((name, version))
}

/// The `(name as spelled, reference)` of a PEP 508 direct reference
/// (`name[extras] @ <url-or-path>`) — the shape the HOSTED redirect
/// rewrites an exact pin INTO. The VENDORED requirements writer emits a
/// bare path line tagged with [`vendor_tag`] instead, which this does NOT
/// match: it has no `name @`. `None` for anything else, [`exact_pin`]s
/// included (a pin has no `@` before its specifier). Like `exact_pin` this
/// reads a logical line's code part and stops at an optional `; marker`;
/// the name cannot contain an `@`, so the first one is always the separator
/// and a url's own `user@host` stays inside the reference.
pub(crate) fn direct_reference(code: &str) -> Option<(&str, &str)> {
    let (name, rest) = code.split(';').next()?.split_once('@')?;
    let name = name.split('[').next()?.trim();
    let reference = rest.split_whitespace().next()?;
    (!name.is_empty() && !reference.is_empty()).then_some((name, reference))
}

/// The `(name, version)` of a `socket-patch vendor: <name>==<ver>[ (transitive)]`
/// comment tag (a logical line's comment part) — the tag the vendored
/// requirements writer appends to its wheel-path line.
pub(crate) fn vendor_tag(comment: &str) -> Option<(&str, &str)> {
    let (_, tag) = comment.split_once("socket-patch vendor:")?;
    let pin = tag.split_whitespace().next()?;
    let (name, version) = pin.split_once("==")?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

/// Every `--hash=sha256:<hex>` / `--hash sha256:<hex>` value of a logical
/// line's code part, in order (unvalidated).
pub(crate) fn hash_options(code: &str) -> Vec<String> {
    let mut hashes = Vec::new();
    let mut tokens = code.split_whitespace();
    while let Some(token) = tokens.next() {
        let value = if token == "--hash" {
            tokens.next()
        } else {
            token.strip_prefix("--hash=")
        };
        if let Some(hex) = value.and_then(|v| v.strip_prefix("sha256:")) {
            hashes.push(hex.to_string());
        }
    }
    hashes
}

/// Whether a requirements file puts pip into hash-checking mode for the whole
/// install: pip turns it on as soon as ANY requirement carries a `--hash`
/// option (of any algorithm), or the file sets `--require-hashes`. The mode
/// is all or nothing: once on, every requirement — and every transitive
/// dependency — must be `==`-pinned and hashed, so a writer must match it
/// rather than add the first `--hash` (#376) or an unhashed line (#378).
///
/// Every line counts, socket-patch's own included: a line this writer
/// emitted keeps the mode it was written for, so a re-scan is a no-op. A
/// url's `#sha256=` fragment is not a hash option: pip verifies it without
/// turning the mode on.
pub(crate) fn requires_hashes(content: &str) -> bool {
    logical_lines(content).iter().any(|line| {
        strip_comment(&line.text).split_whitespace().any(|token| {
            token == "--hash" || token.starts_with("--hash=") || token == "--require-hashes"
        })
    })
}

/// `(distribution, version)` a Python artifact filename names: a PEP 427
/// wheel (`dist-version-…-tags.whl`) or an sdist (`dist-version.tar.gz` /
/// `.zip` / `.tar.bz2` / `.tar.xz`). Names are returned as spelled (callers
/// canonicalize); `None` for anything else.
pub(crate) fn archive_filename_coords(filename: &str) -> Option<(&str, &str)> {
    let (dist, version) = if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.splitn(3, '-');
        let dist = parts.next()?;
        let version = parts.next()?;
        parts.next()?;
        (dist, version)
    } else {
        let stem = [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"]
            .into_iter()
            .find_map(|suffix| filename.strip_suffix(suffix))?;
        stem.rsplit_once('-')?
    };
    (!dist.is_empty() && !version.is_empty()).then_some((dist, version))
}

/// The pin in an artifact location's `#sha256=<hex>` fragment (pip's
/// `<url>#sha256=…`, Poetry lock 1.0's `<url>#sha256=<hex>&`): the FIRST
/// `sha256=` parameter after the first `#`, when it is 64 hex (lowercased).
/// A malformed first parameter is no pin, even if a later one is valid.
pub(crate) fn url_sha256_fragment(location: &str) -> Option<String> {
    let (_, fragment) = location.split_once('#')?;
    fragment
        .split('&')
        .find_map(|param| param.strip_prefix("sha256="))
        .and_then(crate::utils::digest::sha256_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_hashes_reads_pip_hash_checking_mode() {
        for hashed in [
            "six==1.16.0 --hash=sha256:aa\nidna==3.7\n",
            "six==1.16.0 \\\n    --hash sha256:aa\n",
            "six==1.16.0 --hash=sha512:aa\n",
            "--require-hashes\nsix==1.16.0\n",
            "\u{feff}--require-hashes\r\nsix==1.16.0\r\n",
        ] {
            assert!(requires_hashes(hashed), "{hashed:?}");
        }
        for unhashed in [
            "",
            "six==1.16.0\nidna==3.7\n",
            // Comments and url fragments are not hash options.
            "six==1.16.0  # --hash=sha256:aa\n# --require-hashes\n",
            "six @ https://example.test/six-1.16.0-py2.py3-none-any.whl#sha256=aa\n",
        ] {
            assert!(!requires_hashes(unhashed), "{unhashed:?}");
        }
    }

    #[test]
    fn lexer_joins_continuations_and_strips_comments_correctly() {
        let lines = logical_lines("six==1.16.0 \\\n    --hash=sha256:abc\nrequests\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].start, 0);
        assert_eq!(lines[0].physical.len(), 2);
        assert_eq!(lines[0].text, "six==1.16.0     --hash=sha256:abc");
        assert_eq!(lines[1].start, 2);

        // Comment rules: whitespace-preceded `#` (or column 0) only.
        assert_eq!(strip_comment("six==1.0  # pinned"), "six==1.0  ");
        assert_eq!(strip_comment("# whole line"), "");
        assert_eq!(
            strip_comment("x --hash=sha256:ab#cd"),
            "x --hash=sha256:ab#cd",
            "a # without preceding whitespace is data, not a comment"
        );
        assert_eq!(
            split_comment("./w.whl  # socket-patch vendor: a==1"),
            ("./w.whl  ", Some(" socket-patch vendor: a==1"))
        );
    }

    /// The ONE exact-pin rule the lock inventory and lockfile discovery
    /// share: wildcards (`==1.*`) and arbitrary equality (`===`) are not
    /// exact pins (the inventory must never emit `pkg:pypi/six@1.*`).
    #[test]
    fn exact_pin_is_the_shared_registry_pin_rule() {
        assert_eq!(exact_pin("six==1.16.0"), Some(("six", "1.16.0")));
        assert_eq!(
            exact_pin("requests[socks]==2.31.0; python_version < \"3.12\" --hash=sha256:ab"),
            Some(("requests", "2.31.0"))
        );
        // #523: pip's whitespace around `==` and the legacy parenthesised
        // form are the same exact pin.
        for code in [
            "six == 1.16.0",
            "six ==1.16.0",
            "six== 1.16.0",
            "six\t==\t1.16.0",
            "six (==1.16.0)",
            "six ( == 1.16.0 )",
            "six(==1.16.0)",
            "six [x] == 1.16.0",
            "six[x] == 1.16.0 ; python_version >= \"3.8\"",
            "six == 1.16.0 --hash=sha256:ab",
            "six (==1.16.0) --hash sha256:ab",
        ] {
            assert_eq!(exact_pin(code), Some(("six", "1.16.0")), "{code}");
        }
        for code in [
            "six==1.*",
            "six==1.16.*",
            "six===1.16.0",
            "six==v1",
            "six>=1.0",
            "six",
            "==1.0",
            "six == 1.*",
            "six (==1.0",
            "six ==1.0)",
            "six==1.0,<2",
            "six == 1.0, <2",
            "six==1.0 extra",
            "six @ https://h/six-1.0-py3-none-any.whl",
        ] {
            assert_eq!(exact_pin(code), None, "{code}");
        }
        assert_eq!(
            vendor_tag(" socket-patch vendor: six==1.16.0 (transitive)"),
            Some(("six", "1.16.0"))
        );
        assert_eq!(vendor_tag(" pinned"), None);
        assert_eq!(
            hash_options("x --hash=sha256:aa --hash sha256:bb --hash=md5:cc"),
            vec!["aa".to_string(), "bb".to_string()]
        );
    }

    #[test]
    fn lexer_never_continues_a_comment_and_drops_one_leading_bom() {
        let lines = logical_lines("\u{feff}# note \\\nsix==1.0\n");
        assert_eq!(lines.len(), 2, "a comment line never continues");
        assert_eq!(lines[0].text, "# note \\");
        assert_eq!(
            lines[0].physical[0], "\u{feff}# note \\",
            "physical stays raw"
        );
        assert_eq!(lines[1].text, "six==1.0");
    }

    #[test]
    fn archive_filename_coords_reads_wheels_and_sdists() {
        assert_eq!(
            archive_filename_coords("six-1.16.0-py2.py3-none-any.whl"),
            Some(("six", "1.16.0"))
        );
        assert_eq!(
            archive_filename_coords("Foo_Bar-2.0.tar.gz"),
            Some(("Foo_Bar", "2.0"))
        );
        assert_eq!(archive_filename_coords("pkg-1.0.zip"), Some(("pkg", "1.0")));
        assert_eq!(archive_filename_coords("six-1.16.0.whl"), None, "no tags");
        assert_eq!(archive_filename_coords("six.tar.gz"), None, "no version");
        assert_eq!(archive_filename_coords("six-1.0.egg"), None);
    }

    #[test]
    fn expand_env_vars_follows_pips_name_grammar() {
        let lookup = |name: &str| match name {
            "REQDIR" => Some("sub".to_string()),
            "SPACED" => Some("\"dev reqs.txt\"".to_string()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            expand_env_vars("-r ${REQDIR}/dev.txt", lookup),
            "-r sub/dev.txt"
        );
        assert_eq!(
            expand_env_vars("-r ${SPACED}", lookup),
            "-r \"dev reqs.txt\""
        );
        assert_eq!(
            expand_env_vars("${REQDIR}/${REQDIR}", lookup),
            "sub/sub",
            "every reference is expanded"
        );
        for kept in [
            "-r ${UNSET}/dev.txt",
            "-r ${EMPTY}/dev.txt",
            "-r ${reqdir}/dev.txt",
            "-r $REQDIR/dev.txt",
            "-r ${}/dev.txt",
            "-r ${REQDIR",
            "-r ${REQ-DIR}/dev.txt",
        ] {
            assert_eq!(expand_env_vars(kept, lookup), kept, "{kept:?}");
        }
    }

    #[test]
    fn shlex_split_matches_python_posix_mode() {
        let split = |s: &str| shlex_split(s).map(|w| w.join("|"));
        assert_eq!(split("-r dev.txt").as_deref(), Some("-r|dev.txt"));
        assert_eq!(split("-r\t dev.txt ").as_deref(), Some("-r|dev.txt"));
        assert_eq!(
            split("-r \"dev reqs.txt\"").as_deref(),
            Some("-r|dev reqs.txt")
        );
        assert_eq!(
            split("-r 'dev reqs.txt'").as_deref(),
            Some("-r|dev reqs.txt")
        );
        assert_eq!(
            split("-r dev\\ reqs.txt").as_deref(),
            Some("-r|dev reqs.txt")
        );
        assert_eq!(
            split("--requirement=\"dev.txt\"").as_deref(),
            Some("--requirement=dev.txt")
        );
        assert_eq!(split("a\"b c\"'d e'f").as_deref(), Some("ab cd ef"));
        assert_eq!(
            split("'a\\b'").as_deref(),
            Some("a\\b"),
            "no escapes in '…'"
        );
        assert_eq!(
            split("\"a\\\"b\\\\c\\d\"").as_deref(),
            Some("a\"b\\c\\d"),
            "in \"…\" only \\\" and \\\\ are escapes"
        );
        assert_eq!(split("sub\\dev.txt").as_deref(), Some("subdev.txt"));
        assert_eq!(shlex_split("-r \"\"").unwrap(), vec!["-r", ""]);
        assert_eq!(shlex_split("").unwrap(), Vec::<String>::new());
        for unbalanced in ["-r \"dev.txt", "-r 'dev.txt", "-r dev.txt\\"] {
            assert_eq!(shlex_split(unbalanced), None, "{unbalanced:?}");
        }
    }
}
