//! The `DEPENDENCIES` requirement bundler locks for a gem a Gemfile pins
//! exactly, once the Gemfile's `gemspec` directive is taken into account.
//!
//! `gemspec` adds the gemspec's development dependencies to the Gemfile.
//! Bundler 2.7+ merges such a development dependency with a `gem` line for
//! the same gem that FOLLOWS the directive (`Dsl#add_dependency`): the
//! Gemfile dependency carries both requirement lists, and the lock writes
//! the union, sorted the way `Gem::Dependency#to_lock` sorts it
//! (`vuln-gem (>= 0, = 1.0.0)!`). A `gem` line BEFORE the directive keeps
//! its own requirement (the later development dependency is dropped), and
//! bundler < 2.7 never merges. Both pin writers (hosted
//! [`super::hosted::converge_gem_lock_source`], vendored `edit_lock`) lock
//! what bundler derives here, or every frozen install of the pair fails
//! (#985).
//!
//! The gemspec is Ruby; only literal `add_development_dependency` calls
//! are read. A call naming the gem that cannot be read, or a directive
//! whose gemspec cannot be found or read, is reported as an error: the
//! caller cannot know what bundler would lock.

use super::gemfile::{code_of, leading_quoted, split_args};

/// The `gemspec` files of one directory: `(file name, text)`, the text
/// `None` when the file exists but could not be read. `Err` when the
/// directory itself could not be listed.
pub(crate) type GemspecListing = Result<Vec<(String, Option<String>)>, String>;

/// The synthetic candidate key the hosted planner reads the `gemspec`
/// directives' files from (`hosted::engine::read_candidate_files`): a JSON
/// object mapping each directive's root-relative directory to either its
/// `*.gemspec` files (`{"name.gemspec": text | null}`, `null` when
/// unreadable) or why it could not be listed. Never a path.
pub(crate) const GEMSPECS_KEY: &str = "<socket-patch:gem-gemspecs>";

/// [`GemspecListing`] of `dir` from the candidate files' [`GEMSPECS_KEY`].
pub(crate) fn candidate_listing(
    files: &std::collections::BTreeMap<String, String>,
    dir: &str,
) -> GemspecListing {
    let raw = files
        .get(GEMSPECS_KEY)
        .ok_or_else(|| "the project's gemspecs were not read".to_string())?;
    let listing: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    match listing.get(dir) {
        Some(serde_json::Value::Object(entries)) => Ok(entries
            .iter()
            .map(|(file, text)| (file.clone(), text.as_str().map(str::to_string)))
            .collect()),
        Some(serde_json::Value::String(why)) => Err(why.clone()),
        _ => Err("the directory was not listed".to_string()),
    }
}

/// Whether a directory entry is a gemspec bundler's `gemspec` directive
/// finds (`{,*}.gemspec`: a dotfile only when it is `.gemspec` itself).
pub(crate) fn is_gemspec_file(name: &str) -> bool {
    name == ".gemspec" || (!name.starts_with('.') && name.ends_with(".gemspec"))
}

/// Whether the bundler that wrote `lock` (its `BUNDLED WITH` version) merges
/// a `gemspec` development dependency into a later `gem` line: 2.7+. A lock
/// without the section (bundler < 1.10) or with an unreadable version does
/// not.
pub(crate) fn bundler_merges_dev_dependencies(lock: &str) -> bool {
    let mut lines = lock.lines().map(|l| l.trim_end_matches('\r'));
    let Some(version) = lines
        .by_ref()
        .find(|l| *l == "BUNDLED WITH")
        .and_then(|_| lines.next())
        .map(str::trim)
    else {
        return false;
    };
    let mut parts = version.split('.').map(|p| p.parse::<u32>());
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= (2, 7),
        _ => false,
    }
}

/// One `gemspec` directive of a Gemfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GemspecDirective {
    /// 0-based line index.
    pub(crate) line: usize,
    /// The `path:` option, root-relative with `/` separators (`""` for the
    /// Gemfile's own directory).
    pub(crate) dir: String,
    /// The `name:` option.
    pub(crate) name: Option<String>,
}

/// The `gemspec` directives of `gemfile`, in file order. `Err` names the
/// first one whose options cannot be read statically (a non-literal
/// `path:` / `name:`, a `glob:`, an absolute or escaping path).
pub(crate) fn gemspec_directives(gemfile: &str) -> Result<Vec<GemspecDirective>, String> {
    let mut out = Vec::new();
    for (line, text) in gemfile.split('\n').enumerate() {
        let trimmed = text.trim_start();
        let Some(rest) = trimmed.strip_prefix("gemspec") else {
            continue;
        };
        // `gemspec`, `gemspec path: "x"`, `gemspec(path: "x")`; never
        // `gemspec_foo` or `gemspecs`.
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let unreadable = || format!("line {}: `{}`", line + 1, text.trim());
        let code = code_of(rest).ok_or_else(unreadable)?.trim();
        let code = code.trim_end_matches(';').trim_end();
        let code = match code.strip_prefix('(') {
            Some(inner) => inner.strip_suffix(')').ok_or_else(unreadable)?,
            None => code,
        };
        let mut directive = GemspecDirective {
            line,
            dir: String::new(),
            name: None,
        };
        if !code.trim().is_empty() {
            for (_, arg) in split_args(code).ok_or_else(unreadable)? {
                let (key, value) = option(arg).ok_or_else(unreadable)?;
                match key {
                    "path" => {
                        let lit = literal(value).ok_or_else(unreadable)?;
                        directive.dir = relative_dir(&lit).ok_or_else(unreadable)?;
                    }
                    "name" => directive.name = Some(literal(value).ok_or_else(unreadable)?),
                    // Only picks the group the dependencies join.
                    "development_group" => {}
                    // `glob:` changes which gemspec files bundler finds.
                    _ => return Err(unreadable()),
                }
            }
        }
        out.push(directive);
    }
    Ok(out)
}

/// `key: value` / `:key => value` / `"key" => value`: `(key, value text)`.
fn option(arg: &str) -> Option<(&str, &str)> {
    let a = arg.trim();
    if let Some((key, rest)) = leading_quoted(a) {
        let value = rest.trim_start().strip_prefix("=>")?;
        return Some((key, value));
    }
    if let Some(sym) = a.strip_prefix(':') {
        let (key, value) = sym.split_once("=>")?;
        return Some((key.trim(), value));
    }
    let (key, value) = a.split_once(':')?;
    let key = key.trim();
    (!key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .then_some((key, value))
}

/// A Ruby string literal (`"x"`, `'x'`, `%q<x>`, each optionally
/// `.freeze`d) with no escapes or interpolation: its content.
fn literal(value: &str) -> Option<String> {
    let v = value.trim();
    let v = v.strip_suffix(".freeze").unwrap_or(v).trim_end();
    let content = if let Some((content, rest)) = leading_quoted(v) {
        if !rest.trim().is_empty() || (v.starts_with('"') && content.contains("#{")) {
            return None;
        }
        content
    } else {
        let body = v.strip_prefix("%q").or_else(|| v.strip_prefix("%Q"))?;
        let open = body.chars().next()?;
        let close = match open {
            '<' => '>',
            '{' => '}',
            '(' => ')',
            '[' => ']',
            _ => return None,
        };
        let inner = body[1..].strip_suffix(close)?;
        if inner.contains([open, close]) || inner.contains("#{") {
            return None;
        }
        inner
    };
    (!content.contains('\\')).then(|| content.to_string())
}

/// `path` as a normalized root-relative directory: `""` for `.`, `None`
/// for an absolute path or one that leaves the root.
fn relative_dir(path: &str) -> Option<String> {
    if path.starts_with('/') || path.starts_with('~') || path.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

/// A requirement in the spelling `Gem::Requirement#as_list` gives it:
/// `op version`, the operator defaulting to `=`. `None` when it is not a
/// requirement rubygems parses.
fn normalize_requirement(req: &str) -> Option<String> {
    let r = req.trim();
    let (op, version) = ["~>", ">=", "<=", "!=", "=", ">", "<"]
        .iter()
        .find_map(|op| r.strip_prefix(op).map(|v| (*op, v.trim())))
        .unwrap_or(("=", r));
    let valid = !version.is_empty()
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    valid.then(|| format!("{op} {version}"))
}

/// The requirements the gemspec's `add_development_dependency` call on
/// `gem` declares, as `Gem::Requirement#as_list` spells them (`[">= 0"]`
/// for none). `Ok(None)` when no such call names it. `Err` when a call
/// names it but cannot be read (non-literal arguments, a call spanning
/// lines), or when several calls disagree.
pub(crate) fn dev_dependency_requirements(
    gemspec: &str,
    gem: &str,
) -> Result<Option<Vec<String>>, String> {
    let mut found: Option<Vec<String>> = None;
    for (i, text) in gemspec.split('\n').enumerate() {
        let trimmed = text.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(at) = trimmed.find("add_development_dependency") else {
            continue;
        };
        let after = &trimmed[at + "add_development_dependency".len()..];
        let mentions = after.contains(&format!("\"{gem}\""))
            || after.contains(&format!("'{gem}'"))
            || after.contains(&format!("<{gem}>"))
            || after.contains(&format!("{{{gem}}}"));
        let unreadable = || format!("line {}: `{trimmed}`", i + 1);
        let Some(reqs) = read_dev_call(after) else {
            if mentions {
                return Err(unreadable());
            }
            continue;
        };
        let (name, reqs) = reqs;
        if name != gem {
            continue;
        }
        let reqs = if reqs.is_empty() {
            vec![">= 0".to_string()]
        } else {
            reqs
        };
        match &found {
            Some(prev) if *prev != reqs => return Err(unreadable()),
            _ => found = Some(reqs),
        }
    }
    Ok(found)
}

/// The arguments of one `add_development_dependency` call written on one
/// line (`"x", "~> 1"`, `("x", [">= 1", "< 2"])`, `(%q<x>.freeze, [">= 0"])`):
/// `(gem name, normalized requirements)`.
fn read_dev_call(after: &str) -> Option<(String, Vec<String>)> {
    let code = code_of(after)?.trim();
    let code = code.trim_end_matches(';').trim_end();
    let code = match code.strip_prefix('(') {
        Some(inner) => inner.strip_suffix(')')?,
        None => code,
    };
    let args = split_args(code)?;
    let mut args = args.into_iter().map(|(_, a)| a.trim());
    let name = literal(args.next()?)?;
    let mut reqs = Vec::new();
    for arg in args {
        if arg.is_empty() {
            // A trailing comma: the call continues on the next line.
            return None;
        }
        match arg.strip_prefix('[') {
            Some(list) => {
                let list = list.strip_suffix(']')?;
                for (_, item) in split_args(list)? {
                    if item.trim().is_empty() {
                        continue;
                    }
                    reqs.push(normalize_requirement(&literal(item)?)?);
                }
            }
            None => reqs.push(normalize_requirement(&literal(arg)?)?),
        }
    }
    Some((name, reqs))
}

/// The requirement list bundler locks, inside the parentheses, for `name`
/// once the Gemfile (as the pin writer leaves it) declares it pinned to
/// exactly `version`: `= 1.0.0`, or `>= 0, = 1.0.0` when bundler 2.7+
/// merges a gemspec development dependency into it. `gemspecs` lists a
/// root-relative directory's `*.gemspec` files. `Err` says why the merge
/// cannot be decided (the caller cannot know what bundler would lock).
pub(crate) fn locked_exact_requirement(
    gemfile: &str,
    lock: &str,
    name: &str,
    version: &str,
    gemspecs: &mut dyn FnMut(&str) -> GemspecListing,
) -> Result<String, String> {
    let exact = format!("= {version}");
    if !bundler_merges_dev_dependencies(lock) {
        return Ok(exact);
    }
    let Some(decl) = gemfile.split('\n').position(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#')
            && crate::vendor::gem::gem_declaration_any(trimmed).is_some_and(|d| d.name == name)
    }) else {
        return Ok(exact);
    };
    let directives = gemspec_directives(gemfile)
        .map_err(|why| format!("cannot read the Gemfile's `gemspec` directive ({why})"))?;
    let mut merged: Option<Vec<String>> = None;
    for directive in directives.iter().filter(|d| d.line < decl) {
        let shown = if directive.dir.is_empty() {
            ".".to_string()
        } else {
            directive.dir.clone()
        };
        let files = gemspecs(&directive.dir)
            .map_err(|why| format!("cannot list the gemspecs in {shown} ({why})"))?;
        let file = match &directive.name {
            Some(n) => {
                let want = format!("{n}.gemspec");
                files.iter().find(|(f, _)| *f == want)
            }
            None if files.len() == 1 => files.first(),
            None => None,
        }
        .ok_or_else(|| {
            format!(
                "the Gemfile's `gemspec` directive does not name exactly one gemspec in {shown}"
            )
        })?;
        let text = file
            .1
            .as_deref()
            .ok_or_else(|| format!("cannot read {shown}/{}", file.0))?;
        let reqs = dev_dependency_requirements(text, name).map_err(|why| {
            format!(
                "cannot read the development dependency on {name} in {shown}/{} ({why})",
                file.0
            )
        })?;
        if let Some(reqs) = reqs {
            if merged.is_some() {
                return Err(format!(
                    "more than one gemspec declares a development dependency on {name}"
                ));
            }
            merged = Some(reqs);
        }
    }
    let Some(mut reqs) = merged else {
        return Ok(exact);
    };
    // `Dependency.new(name, gemspec.as_list + gemfile.as_list)`: duplicates
    // dropped, then `to_lock` sorts the spellings and reverses them.
    reqs.push(exact);
    reqs.sort();
    reqs.dedup();
    reqs.reverse();
    Ok(reqs.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK_27: &str = "DEPENDENCIES\n  mylib!\n  vuln-gem\n\nBUNDLED WITH\n   2.7.2\n";

    fn one(text: &'static str) -> impl FnMut(&str) -> GemspecListing {
        move |dir: &str| {
            assert_eq!(dir, "");
            Ok(vec![("mylib.gemspec".to_string(), Some(text.to_string()))])
        }
    }

    const GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"mylib\"\n  \
                           s.add_development_dependency \"vuln-gem\"\n  \
                           s.add_development_dependency \"rack\", \">= 3\"\nend\n";

    #[test]
    fn bundler_2_7_and_later_merge() {
        for (version, want) in [
            ("2.6.9", false),
            ("2.7.0", true),
            ("2.7.2", true),
            ("4.0.22", true),
            ("1.17.3", false),
            ("garbage", false),
        ] {
            let lock = format!("DEPENDENCIES\n  rails\n\nBUNDLED WITH\n   {version}\n");
            assert_eq!(bundler_merges_dev_dependencies(&lock), want, "{version}");
            assert_eq!(
                bundler_merges_dev_dependencies(&lock.replace('\n', "\r\n")),
                want,
                "{version} CRLF"
            );
        }
        assert!(!bundler_merges_dev_dependencies("DEPENDENCIES\n  rails\n"));
    }

    /// #985: a gemspec development dependency merges into a later `gem`
    /// line, sorted as bundler's `to_lock` writes it.
    #[test]
    fn merges_a_dev_dependency_declared_before_the_gem_line() {
        let gemfile = "source \"https://rubygems.org\"\n\ngemspec\n\ngroup :development do\n  \
                       source \"https://patch.example/x/\" do\n    gem \"vuln-gem\", \"1.0.0\"\n  \
                       end\nend\n";
        let got =
            locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut one(GEMSPEC));
        assert_eq!(got.as_deref(), Ok(">= 0, = 1.0.0"));
        let gemfile =
            "source \"https://rubygems.org\"\ngemspec\ngem \"rack\", \"3.2.7\", path: \"v\"\n";
        let got = locked_exact_requirement(gemfile, LOCK_27, "rack", "3.2.7", &mut one(GEMSPEC));
        assert_eq!(got.as_deref(), Ok(">= 3, = 3.2.7"));
    }

    #[test]
    fn keeps_the_exact_pin_when_bundler_does_not_merge() {
        let mut never = |_: &str| -> GemspecListing { panic!("not listed") };
        // Bundler < 2.7.
        let gemfile = "gemspec\ngem \"vuln-gem\", \"1.0.0\"\n";
        let lock = LOCK_27.replace("2.7.2", "2.6.9");
        assert_eq!(
            locked_exact_requirement(gemfile, &lock, "vuln-gem", "1.0.0", &mut never).as_deref(),
            Ok("= 1.0.0")
        );
        // The `gem` line comes first: bundler keeps it unmerged.
        let gemfile = "gem \"vuln-gem\", \"1.0.0\"\ngemspec\n";
        assert_eq!(
            locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut never).as_deref(),
            Ok("= 1.0.0")
        );
        // No `gemspec` directive at all.
        let gemfile = "gem \"vuln-gem\", \"1.0.0\"\n# gemspec\n";
        assert_eq!(
            locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut never).as_deref(),
            Ok("= 1.0.0")
        );
        // The gemspec has no development dependency on it (a runtime one is
        // never merged).
        let gemfile = "gemspec\ngem \"puma\", \"6.0.0\"\n";
        let runtime = "Gem::Specification.new do |s|\n  s.add_dependency \"puma\"\nend\n";
        assert_eq!(
            locked_exact_requirement(gemfile, LOCK_27, "puma", "6.0.0", &mut one(runtime))
                .as_deref(),
            Ok("= 6.0.0")
        );
    }

    #[test]
    fn a_dev_dependency_pinned_to_the_same_version_is_not_repeated() {
        let gemfile = "gemspec\ngem \"vuln-gem\", \"1.0.0\"\n";
        let spec = "s.add_development_dependency(\"vuln-gem\", \"1.0.0\")\n";
        assert_eq!(
            locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut one(spec))
                .as_deref(),
            Ok("= 1.0.0")
        );
    }

    #[test]
    fn reads_the_directive_options() {
        let gemfile = "gemspec path: \"gems/core\", name: \"core\"\ngem \"vuln-gem\", \"1.0.0\"\n";
        let mut listing = |dir: &str| -> GemspecListing {
            assert_eq!(dir, "gems/core");
            Ok(vec![
                ("other.gemspec".to_string(), Some(String::new())),
                (
                    "core.gemspec".to_string(),
                    Some("spec.add_development_dependency 'vuln-gem', '~> 1.0', '< 2'\n".into()),
                ),
            ])
        };
        assert_eq!(
            locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut listing)
                .as_deref(),
            Ok("~> 1.0, = 1.0.0, < 2")
        );
        assert_eq!(
            gemspec_directives(
                "gemspec(:path => './x/../y', \"name\" => 'n', development_group: :dev)\n"
            ),
            Ok(vec![GemspecDirective {
                line: 0,
                dir: "y".into(),
                name: Some("n".into())
            }])
        );
        assert_eq!(gemspec_directives("gemspec_helper\ngemspecs\n"), Ok(vec![]));
        for bad in [
            "gemspec path: ROOT\n",
            "gemspec path: \"../up\"\n",
            "gemspec path: \"/abs\"\n",
            "gemspec glob: \"*.spec\"\n",
            "gemspec path: \"#{x}\"\n",
        ] {
            assert!(gemspec_directives(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reads_generated_and_bracketed_dev_dependencies() {
        let spec = "s.add_development_dependency(%q<vuln-gem>.freeze, [\">= 0.5\", \"< 2\"])\n";
        assert_eq!(
            dev_dependency_requirements(spec, "vuln-gem"),
            Ok(Some(vec![">= 0.5".into(), "< 2".into()]))
        );
        // `if respond_to?` branches repeat the same call.
        let spec = "if x\n  s.add_development_dependency(%q<v>, [\"1.0\"])\nelse\n  \
                    s.add_development_dependency(%q<v>, [\"= 1.0\"])\nend\n";
        assert_eq!(
            dev_dependency_requirements(spec, "v"),
            Ok(Some(vec!["= 1.0".into()]))
        );
        assert_eq!(dev_dependency_requirements(spec, "other"), Ok(None));
        // Commented out.
        assert_eq!(
            dev_dependency_requirements("# s.add_development_dependency \"v\", \"x\"\n", "v"),
            Ok(None)
        );
    }

    #[test]
    fn an_unreadable_dev_dependency_or_gemspec_is_an_error() {
        let gemfile = "gemspec\ngem \"vuln-gem\", \"1.0.0\"\n";
        for spec in [
            "s.add_development_dependency \"vuln-gem\", VERSION\n",
            "s.add_development_dependency \"vuln-gem\",\n  \"~> 1.0\"\n",
            "s.add_development_dependency \"vuln-gem\", \"~> 1\"\ns.add_development_dependency \"vuln-gem\", \"~> 2\"\n",
        ] {
            let text: &'static str = Box::leak(spec.to_string().into_boxed_str());
            assert!(
                locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut one(text))
                    .is_err(),
                "{spec}"
            );
        }
        for listing in [
            Ok(vec![]),
            Ok(vec![
                ("a.gemspec".to_string(), Some(String::new())),
                ("b.gemspec".to_string(), Some(String::new())),
            ]),
            Ok(vec![("a.gemspec".to_string(), None)]),
            Err("denied".to_string()),
        ] {
            let mut f = |_: &str| listing.clone();
            assert!(
                locked_exact_requirement(gemfile, LOCK_27, "vuln-gem", "1.0.0", &mut f).is_err(),
                "{listing:?}"
            );
        }
    }
}
