//! The argument tail of a Gemfile `gem "name", …` line: the ONE reader of
//! its options, shared by the hosted redirect (`patch::redirect`) and the
//! vendored rewrite (`vendor::gem`).
//!
//! A tail is the text after the gem name: optional quoted version
//! constraints (`, "7.0.0"`, `, ">= 1", "< 2"`) followed by options. Ruby
//! spells an option key four ways — `key: v`, `"key": v`, `:key => v` and
//! `"key" => v` — and both rewrites must see every spelling, or a
//! source-selecting option slips past the refusal (and a string-keyed option
//! gets mistaken for a version constraint and dropped).

/// The `gem` options that do NOT pick where bundler fetches the gem from
/// (bundler's `Dsl::VALID_KEYS` minus `git`, `path`, `source` and
/// `gemfile`). `branch` / `ref` / `tag` / `submodules` / `glob` / `name`
/// only qualify a git or path source, which carries its own key.
///
/// Anything else selects a source: the built-in `git:` / `path:` /
/// `source:`, the built-in git sources (`github:`, `gist:`, `bitbucket:`,
/// `gitlab:`) and any `git_source(:name) { … }` the Gemfile declares —
/// bundler rejects every other unknown key, so an unknown key here can only
/// be a git source.
const NON_SOURCE_KEYS: [&str; 14] = [
    "group",
    "groups",
    "require",
    "platform",
    "platforms",
    "type",
    "install_if",
    "force_ruby_platform",
    "branch",
    "ref",
    "tag",
    "submodules",
    "glob",
    "name",
];

/// One top-level argument of a tail.
#[derive(Debug, PartialEq, Eq)]
enum Arg<'t> {
    /// A bare quoted string: a version constraint.
    Version,
    /// `key => v` / `key: v` in any spelling; `spelling` is the key as
    /// written (`gitlab:`, `:git`, `"git" =>`).
    Option { key: &'t str, spelling: &'t str },
    /// A `**opts` double splat or a `{ … }` hash literal: options whose
    /// keys cannot be read statically. Its text.
    Dynamic(&'t str),
    /// Any other argument (`*V`, `VERSION`, `ENV.fetch(…)`, `Rack::VERSION`,
    /// a trailing `if` modifier): a positional version constraint, which
    /// never selects a source.
    Positional,
}

/// The code of a tail: everything before a `#` comment that sits outside a
/// string. `None` on an unbalanced quote. Throughout, a backslash escapes
/// the next character in either quote style (Ruby's single-quoted strings
/// honor `\'` and `\\` too).
fn code_of(tail: &str) -> Option<&str> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in tail.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => return Some(&tail[..i]),
                _ => {}
            },
        }
    }
    quote.is_none().then_some(tail)
}

/// Split `code` at its top-level commas (outside strings and brackets).
/// Each piece keeps its byte offset into `code`. `None` on unbalanced
/// brackets.
fn split_args(code: &str) -> Option<Vec<(usize, &str)>> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth: usize = 0;
    let mut start = 0;
    for (i, c) in code.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                out.push((start, &code[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() || depth != 0 {
        return None;
    }
    out.push((start, &code[start..]));
    Some(out)
}

/// A leading quoted literal of `s`: `(content, rest after the closing
/// quote)`.
fn leading_quoted(s: &str) -> Option<(&str, &str)> {
    let q = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let body = &s[1..];
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == q {
            return Some((&body[..i], &body[i + 1..]));
        }
    }
    None
}

/// The length of a leading Ruby identifier (`[A-Za-z_][A-Za-z0-9_]*`).
fn ident_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    if !bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return 0;
    }
    bytes
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(bytes.len())
}

fn classify(arg: &str) -> Arg<'_> {
    let a = arg.trim();
    if let Some((content, rest)) = leading_quoted(a) {
        let rest = rest.trim_start();
        if rest.is_empty() {
            return Arg::Version;
        }
        // `"key" => v` or `"key": v` (Ruby 2.2+ quoted-symbol key).
        if rest.starts_with("=>") || (rest.starts_with(':') && !rest.starts_with("::")) {
            let end = a.len() - rest.len() + if rest.starts_with("=>") { 2 } else { 1 };
            return Arg::Option {
                key: content,
                spelling: &a[..end],
            };
        }
        return Arg::Positional;
    }
    // `:key => v`
    if let Some(sym) = a.strip_prefix(':') {
        let n = ident_len(sym);
        if n > 0 && sym[n..].trim_start().starts_with("=>") {
            return Arg::Option {
                key: &sym[..n],
                spelling: &a[..1 + n],
            };
        }
        return Arg::Positional;
    }
    // `key: v`
    let n = ident_len(a);
    if n > 0 && a[n..].starts_with(':') && !a[n..].starts_with("::") {
        return Arg::Option {
            key: &a[..n],
            spelling: &a[..n + 1],
        };
    }
    if a.starts_with("**") || a.starts_with('{') {
        return Arg::Dynamic(a);
    }
    Arg::Positional
}

/// The arguments of a tail, or `None` when it cannot be read (unbalanced
/// quote or bracket, or text before the first comma).
fn args(tail: &str) -> Option<Vec<(usize, Arg<'_>)>> {
    let code = code_of(tail)?;
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    let lead = code.len() - code.trim_start().len();
    let body = trimmed.strip_prefix(',')?;
    let base = lead + 1;
    let mut out = Vec::new();
    for (off, raw) in split_args(body)? {
        if raw.trim().is_empty() {
            continue;
        }
        let ws = raw.len() - raw.trim_start().len();
        out.push((base + off + ws, classify(raw)));
    }
    Some(out)
}

/// A source-selecting option found on a `gem` line, as written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SourceOption {
    /// The option key (`git`, `gitlab`, a custom git source name), or the
    /// whole argument when it could not be read as `key => value`.
    pub(crate) key: String,
    /// The key as the Gemfile spells it (`gitlab:`, `:git`, `"git" =>`), or
    /// the unreadable argument.
    pub(crate) spelling: String,
    /// True for a `**opts` splat or `{ … }` hash whose keys cannot be read:
    /// it MAY pick a source. The hosted redirect refuses it (a hidden source
    /// would make the redirect a silent, attested no-op); the vendored
    /// rewrite keeps it after `path:`, where a hidden source makes bundler
    /// refuse the Gemfile loudly instead.
    pub(crate) dynamic: bool,
}

/// The first option on a `gem` line's argument tail that picks the gem's
/// source, if any. Bundler allows ONE source per gem, so such an option
/// moved into the Socket source block overrides the block (hosted: the
/// redirect becomes a silent no-op that still gets attested), and kept next
/// to a vendored `path:` makes bundler refuse the Gemfile. Fails closed:
/// an unreadable tail counts as source-selecting, and so (flagged
/// [`SourceOption::dynamic`]) does a `**opts` splat or hash literal, since
/// it may carry one. Positional arguments (`*V`, constants, method calls)
/// are version constraints and never do.
pub(crate) fn source_option(tail: &str) -> Option<SourceOption> {
    let tail = &without_statement_end(tail);
    let Some(args) = args(tail) else {
        return Some(SourceOption {
            key: tail.trim().to_string(),
            spelling: tail.trim().to_string(),
            dynamic: false,
        });
    };
    args.into_iter().find_map(|(_, arg)| match arg {
        Arg::Version | Arg::Positional => None,
        Arg::Option { key, .. } if NON_SOURCE_KEYS.contains(&key) => None,
        Arg::Option { key, spelling } => Some(SourceOption {
            key: key.to_string(),
            spelling: spelling.to_string(),
            dynamic: false,
        }),
        Arg::Dynamic(text) => Some(SourceOption {
            key: text.to_string(),
            spelling: text.to_string(),
            dynamic: true,
        }),
    })
}

/// The argument tail of a `gem "name", …` line minus any leading quoted
/// version-constraint args (`"7.0.0"`, `'~> 7.0'`, `">= 1", "< 2"`) — i.e. the
/// options (`require: false`, `group: :test`, `"require" => false`, …) that
/// must survive the move into the source block or next to a vendored
/// `path:`. Empty when the line carries none; bails to empty on an
/// unparseable tail (unbalanced quote or bracket).
pub(crate) fn trailing_options(tail: &str) -> String {
    let tail = &without_statement_end(tail);
    let Some(args) = args(tail) else {
        return String::new();
    };
    // Options run from the first non-version argument to the end of the
    // tail (a trailing comment rides along with them).
    args.into_iter()
        .find(|(_, arg)| *arg != Arg::Version)
        .map(|(off, _)| tail[off..].trim_end().to_string())
        .unwrap_or_default()
}

/// `opts` minus a top-level `;` statement terminator (and any extra `;`s),
/// keeping a trailing `#` comment. Both rewriters first refuse a tail where
/// another statement follows the `;` (`gem_line_tail_blocks_edit`), so only
/// `;`s, whitespace and a comment can follow it here (#826).
fn without_statement_end(opts: &str) -> String {
    let mut quote: Option<char> = None;
    let mut depth: i64 = 0;
    let mut chars = opts.char_indices();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                chars.next();
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '#' => break,
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => {
                let code = opts[..i].trim_end();
                let rest = opts[i..].trim_start_matches(|c: char| c == ';' || c.is_whitespace());
                return if rest.is_empty() {
                    code.to_string()
                } else {
                    format!("{code} {rest}")
                };
            }
            _ => {}
        }
    }
    opts.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tail: &str) -> Option<String> {
        source_option(tail).map(|o| o.spelling)
    }

    #[test]
    fn plain_versions_and_non_source_options_pass() {
        assert_eq!(key(""), None);
        assert_eq!(key(", \"7.0.0\""), None);
        assert_eq!(key(", '>= 1', '< 2'"), None);
        assert_eq!(key(", \"7.0\", require: false"), None);
        assert_eq!(key(", group: [:test, :development]"), None);
        assert_eq!(key(", platforms: %i[mri windows]"), None);
        assert_eq!(
            key(", require: \"x/y\", install_if: -> { RUBY_VERSION > \"3\" }"),
            None
        );
        assert_eq!(key(", :require => false"), None);
        assert_eq!(key(", \"require\" => false"), None);
        assert_eq!(key(", \"1.0\" # git: in a comment is not code"), None);
    }

    #[test]
    fn builtin_sources_are_refused_in_every_spelling() {
        assert_eq!(key(", git: \"https://x\""), Some("git:".into()));
        assert_eq!(key(", \"7.0\", path: \"../x\""), Some("path:".into()));
        assert_eq!(key(", :github => \"r/r\""), Some(":github".into()));
        assert_eq!(
            key(", source: \"https://gems.example\""),
            Some("source:".into())
        );
        assert_eq!(key(", gist: \"abc\""), Some("gist:".into()));
        assert_eq!(key(", bitbucket: \"a/b\""), Some("bitbucket:".into()));
    }

    /// #652: `gitlab:` (built in since bundler 2.x) and any custom
    /// `git_source(:name)` key pick a git source too.
    #[test]
    fn gitlab_and_custom_git_sources_are_refused() {
        assert_eq!(key(", gitlab: \"vuln-gem\""), Some("gitlab:".into()));
        assert_eq!(key(", local: \"vuln-gem\""), Some("local:".into()));
        assert_eq!(
            key(", \"1.0\", require: false, internal: \"x\""),
            Some("internal:".into())
        );
        assert_eq!(key(", :gitlab => \"x\""), Some(":gitlab".into()));
    }

    /// #652: string-keyed hash rockets and quoted-symbol keys are options,
    /// not version constraints.
    #[test]
    fn string_keyed_source_options_are_refused() {
        assert_eq!(key(", \"git\" => \"/repos/x\""), Some("\"git\" =>".into()));
        assert_eq!(key(", 'path' => '../x'"), Some("'path' =>".into()));
        assert_eq!(key(", \"git\": \"/repos/x\""), Some("\"git\":".into()));
    }

    #[test]
    fn unreadable_arguments_fail_closed() {
        let dynamic = |t: &str| source_option(t).map(|o| o.dynamic);
        assert_eq!(dynamic(", **opts"), Some(true));
        assert_eq!(dynamic(", { git: \"x\" }"), Some(true));
        assert_eq!(dynamic(", \"7.0"), Some(false));
        assert_eq!(dynamic(", require: (\"x\""), Some(false));
    }

    /// #847: positional arguments are version constraints, never sources.
    #[test]
    fn positional_constraints_are_not_sources() {
        for tail in [
            ", *RV",
            ", RACK_VERSION, require: false",
            ", ENV.fetch(\"RV\", \"~> 3.1\")",
            ", Rack::VERSION, group: :web",
            ", \"~> 3.1\", *RV, :require => false # web",
        ] {
            assert_eq!(key(tail), None, "{tail}");
        }
        assert_eq!(key(", RV, gitlab: \"x\""), Some("gitlab:".into()));
    }

    #[test]
    fn escaped_quotes_and_hashes_inside_strings_stay_in_the_string() {
        assert_eq!(key(", require: 'it\\'s', gitlab: \"x\""), Some("gitlab:".into()));
        assert_eq!(key(", require: \"a\\\"b\", git: \"x\""), Some("git:".into()));
        assert_eq!(key(", local: \"#{name}\""), Some("local:".into()));
    }

    #[test]
    fn trailing_options_keep_every_spelling() {
        assert_eq!(trailing_options(","), "");
        assert_eq!(trailing_options(", \"7.0"), "");
        assert_eq!(trailing_options(", \"7.0\""), "");
        assert_eq!(
            trailing_options(", \"7.0\", require: false"),
            "require: false"
        );
        assert_eq!(
            trailing_options(", \"7.0\", \"require\" => false"),
            "\"require\" => false"
        );
        assert_eq!(
            trailing_options(", '>= 1', '< 2', :group => :test # why"),
            ":group => :test # why"
        );
        assert_eq!(
            trailing_options(", require: \"a,b\", group: [:x, :y]"),
            "require: \"a,b\", group: [:x, :y]"
        );
    }

    /// #826: a bare `;` ending the statement is not part of the options
    /// (it would otherwise read as a positional `"7.0";` and be kept).
    #[test]
    fn trailing_options_drop_the_statement_terminator() {
        // Nor is it an unreadable tail, which would fail closed as a
        // source-selecting option.
        for tail in [";", "; # c", ", \"0.8.1\";", ", require: false; # c"] {
            assert_eq!(key(tail), None, "{tail:?}");
        }
        assert_eq!(key(", git: \"x\";"), Some("git:".into()));
        for (tail, opts) in [
            (", \"0.8.1\";", ""),
            (", \"0.8.1\"; # c", ""),
            (", require: false;", "require: false"),
            (
                ", require: false ;; # lazy; ok",
                "require: false # lazy; ok",
            ),
            (", require: \"a;b\";", "require: \"a;b\""),
            (", require: \"a;b\"", "require: \"a;b\""),
            (", require: false # x;", "require: false # x;"),
        ] {
            assert_eq!(trailing_options(tail), opts, "{tail:?}");
        }
    }
}
