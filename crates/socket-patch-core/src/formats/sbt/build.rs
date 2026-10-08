//! The sbt build definition, read by regex: never compiled, never run.
//!
//! - [`sbt_version`] / [`sbt_line`] / [`sbt_support`]: `sbt.version` from
//!   `project/build.properties`, the generated file's syntax line, and the
//!   supported range (0.13.18 up; 2.1 and later untested).
//! - [`is_sbt_build`] / [`sbt_build_present`] / [`is_sbt_build_root`]: what
//!   a directory is, over a [`ReadText`].
//! - [`declared_projects`]: the projects the build defines, or `None` when
//!   a definition is seen that cannot be read statically (fail-closed: the
//!   gate then cannot tell whether every project left evidence).
//! - [`deps_digest`]: a short digest of every dependency literal plus the
//!   sbt version, recorded with a pin so a later dependency edit shows.
//! - [`dependency_literals`] / [`declared_newer`]: the library build's
//!   `"g" % "a" % "v"` literals, and those declaring a pinned GA newer than
//!   the pin's base (which the build-wide override would force back down).
//! - [`scan_build_sources`]: the build edits that defeat a generated
//!   override or resolver (`dependencyOverrides :=`, `resolvers :=`,
//!   `sbt.override.build.repos=true`) and a `build.sbt.lock`.
//!
//! Sources are `(root-relative path, text)` pairs the caller read
//! (FIFO-safe, at the IO layer); [`source_kind`] says which ones each
//! question reads. The generated files ([`HOSTED_FILE`], [`VENDORED_FILE`])
//! are never build sources: their own override lines must not count.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest as _, Sha256};

use super::owned_file::{HOSTED_FILE, VENDORED_FILE};

/// The file naming the sbt version (and making a directory a build root).
pub const BUILD_PROPERTIES: &str = "project/build.properties";
/// The conventional root build file.
pub const BUILD_SBT: &str = "build.sbt";
/// sbt-dependency-lock's per-project lock basename.
pub const DEPENDENCY_LOCK: &str = "build.sbt.lock";
/// `.sbtopts` / `.jvmopts`: launcher options checked in at the root.
pub const OPTS_FILES: &[&str] = &[".sbtopts", ".jvmopts"];
/// The oldest supported sbt: earlier lines lack the `inThisBuild` /
/// `dependencyOverrides` behaviour the generated file relies on.
pub const MIN_SUPPORTED: (u32, u32, u32) = (0, 13, 18);
/// The first release line not yet probed (warned, still wired).
pub const FIRST_UNTESTED: (u32, u32) = (2, 1);
/// The id [`declared_projects`] gives sbt's synthesized root project when
/// no definition names base directory `.`.
pub const IMPLICIT_ROOT_ID: &str = "<root>";

/// The syntax line of the generated file, from the sbt version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SbtLine {
    /// 0.13.x: `key in scope`, Scala 2.10.
    Sbt013,
    /// 1.x.
    Sbt1,
    /// 2.x: Scala 3, cached tasks (`Def.uncached`), no `in`.
    Sbt2,
}

/// Whether socket-patch wires a build of a given sbt version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbtSupport {
    /// Below [`MIN_SUPPORTED`], an unknown major, or no parseable version.
    Unsupported,
    Supported(SbtLine),
    /// [`FIRST_UNTESTED`] or later on a known line: wired with a warning.
    Untested(SbtLine),
}

/// Reads a root-relative, `/`-separated path as text; `None` = absent or
/// unreadable.
pub type ReadText<'a> = &'a dyn Fn(&str) -> Option<String>;

/// A [`ReadText`] over a hosted planner's candidate-file map.
pub fn files_reader(files: &BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    move |rel| files.get(rel).cloned()
}

/// `sbt.version` from the text of `project/build.properties` (a Java
/// properties file: `=` or `:` separators, `#`/`!` comments).
pub fn sbt_version(build_properties: &str) -> Option<String> {
    build_properties.lines().find_map(|line| {
        let line = line.trim_start_matches('\u{feff}').trim();
        if line.starts_with('#') || line.starts_with('!') {
            return None;
        }
        let rest = line.strip_prefix("sbt.version")?;
        let value = rest.trim_start().strip_prefix(['=', ':'])?.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// `major.minor.patch` of an sbt version (a pre-release suffix such as
/// `-M3` / `-RC1` is ignored; a missing patch reads as 0).
pub fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$").expect("regex"));
    let caps = RE.captures(version.trim())?;
    Some((
        caps[1].parse().ok()?,
        caps[2].parse().ok()?,
        caps.get(3).map_or(Some(0), |m| m.as_str().parse().ok())?,
    ))
}

/// The syntax line of `version`: 0.13.x, 1.x or 2.x; `None` otherwise.
pub fn sbt_line(version: &str) -> Option<SbtLine> {
    match parse_version(version)? {
        (0, 13, _) => Some(SbtLine::Sbt013),
        (1, _, _) => Some(SbtLine::Sbt1),
        (2, _, _) => Some(SbtLine::Sbt2),
        _ => None,
    }
}

/// Whether `version` is wired, warned or refused.
pub fn sbt_support(version: &str) -> SbtSupport {
    let (Some(parsed), Some(line)) = (parse_version(version), sbt_line(version)) else {
        return SbtSupport::Unsupported;
    };
    if parsed < MIN_SUPPORTED {
        SbtSupport::Unsupported
    } else if (parsed.0, parsed.1) >= FIRST_UNTESTED {
        SbtSupport::Untested(line)
    } else {
        SbtSupport::Supported(line)
    }
}

/// The directory holds an sbt marker: `build.sbt` or
/// `project/build.properties` (subproject `build.sbt` files included).
pub fn is_sbt_build(read: ReadText<'_>) -> bool {
    read(BUILD_SBT).is_some() || read(BUILD_PROPERTIES).is_some()
}

/// An sbt build, or socket-patch's own generated files, are present: the
/// sbt planners have something to wire or to clean up.
pub fn sbt_build_present(read: ReadText<'_>) -> bool {
    is_sbt_build(read) || read(HOSTED_FILE).is_some() || read(VENDORED_FILE).is_some()
}

/// The directory is an sbt build root: `project/build.properties` names an
/// `sbt.version`. A subproject has no `project/`; a root without the
/// version is not wired (the launcher would pick one we cannot see).
pub fn is_sbt_build_root(read: ReadText<'_>) -> bool {
    read(BUILD_PROPERTIES).is_some_and(|text| sbt_version(&text).is_some())
}

/// What a build source is, by its root-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A root `*.sbt` or a `project/**/*.scala`: defines projects and
    /// build-wide settings.
    Definition,
    /// `<P>/*.sbt`: one subproject's settings.
    Subproject,
    /// `project/*.sbt` or anything under `project/project/`: the
    /// meta-build (plugins).
    Meta,
    /// `project/build.properties`.
    Properties,
    /// `.sbtopts` / `.jvmopts`.
    Opts,
    /// A `build.sbt.lock` (root or subproject).
    Lock,
}

/// The [`SourceKind`] of `rel`, `None` for anything that is not an sbt
/// build source (including the generated files and `target/` trees).
pub fn source_kind(rel: &str) -> Option<SourceKind> {
    let segments: Vec<&str> = rel.split('/').collect();
    let leaf = *segments.last()?;
    if segments.len() == 1 && (leaf == HOSTED_FILE || leaf == VENDORED_FILE) {
        return None;
    }
    if segments
        .iter()
        .any(|s| s.is_empty() || *s == "target" || *s == "." || *s == "..")
    {
        return None;
    }
    if leaf == DEPENDENCY_LOCK {
        return Some(SourceKind::Lock);
    }
    match segments.as_slice() {
        [name] if OPTS_FILES.contains(name) => Some(SourceKind::Opts),
        [name] if name.ends_with(".sbt") => Some(SourceKind::Definition),
        ["project", "build.properties"] => Some(SourceKind::Properties),
        ["project", "project", ..] => Some(SourceKind::Meta),
        ["project", name] if name.ends_with(".sbt") => Some(SourceKind::Meta),
        ["project", .., name] if name.ends_with(".scala") => Some(SourceKind::Definition),
        [first, .., name] if *first != "project" && name.ends_with(".sbt") => {
            Some(SourceKind::Subproject)
        }
        _ => None,
    }
}

/// Scala source with comments blanked (`code`) and, in `skeleton`, string
/// literal contents blanked too. Both keep every byte offset and newline of
/// the input, so a match in one is a position in the other and in the
/// source.
struct Lexed {
    code: String,
    skeleton: String,
}

fn lex(src: &str) -> Lexed {
    let bytes = src.as_bytes();
    let mut code = bytes.to_vec();
    let mut skel = bytes.to_vec();
    let blank = |buf: &mut Vec<u8>, at: usize| {
        if buf[at] != b'\n' {
            buf[at] = b' ';
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                blank(&mut code, i);
                blank(&mut skel, i);
                i += 1;
            }
        } else if bytes[i..].starts_with(b"/*") {
            // Scala block comments nest.
            let mut depth = 0usize;
            while i < bytes.len() {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    for k in i..i + 2 {
                        blank(&mut code, k);
                        blank(&mut skel, k);
                    }
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    for k in i..i + 2 {
                        blank(&mut code, k);
                        blank(&mut skel, k);
                    }
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut code, i);
                    blank(&mut skel, i);
                    i += 1;
                }
            }
        } else if bytes[i..].starts_with(b"\"\"\"") {
            i += 3;
            while i < bytes.len() && !bytes[i..].starts_with(b"\"\"\"") {
                blank(&mut skel, i);
                i += 1;
            }
            i = (i + 3).min(bytes.len());
        } else if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    blank(&mut skel, i);
                    i += 1;
                }
                blank(&mut skel, i);
                i += 1;
            }
            i += 1;
        } else if bytes[i] == b'\'' && i + 2 < bytes.len() && bytes[i + 2] == b'\'' {
            // A char literal such as '"' must not open a string.
            blank(&mut skel, i + 1);
            i += 3;
        } else {
            i += 1;
        }
    }
    // Blanking replaces whole UTF-8 sequences byte by byte with ASCII
    // spaces (comments and string contents only), so both stay UTF-8.
    Lexed {
        code: String::from_utf8(code).unwrap_or_default(),
        skeleton: String::from_utf8(skel).unwrap_or_default(),
    }
}

/// `file("d")` as a root-relative base directory (`.` for the root);
/// `None` for an absolute, parent-escaping or backslashed path.
fn normalize_dir(raw: &str) -> Option<String> {
    if raw.starts_with('/') || raw.contains('\\') || raw.contains(':') {
        return None;
    }
    if raw.split('/').any(|s| s == "..") {
        return None;
    }
    let dir = crate::utils::relpath::resolve_rel("", raw, 0)?;
    Some(if dir.is_empty() { ".".to_string() } else { dir })
}

/// The projects the build defines, id → root-relative base directory (`.`
/// for the root project), from the [`SourceKind::Definition`] sources:
///
/// - `lazy val x = project` (base `x`),
/// - `lazy val x = project.in(file("d"))` / `(project in file("d"))`,
/// - `Project("id", file("d"))` (0.13's `Project(id = …, base = …)` too).
///
/// sbt synthesizes a root project when none has base `.`; it is added as
/// [`IMPLICIT_ROOT_ID`]. `None` when a definition cannot be read
/// statically: a `project` not bound by a plain `val`, a non-literal
/// `file(…)` or `Project(…)` argument, `projectMatrix` / `crossProject`, or
/// two definitions of one id.
pub fn declared_projects(sources: &[(String, String)]) -> Option<BTreeMap<String, String>> {
    static VAL_PROJECT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*Project\s*)?=\s*\(?\s*(project)\b")
            .expect("regex")
    });
    // `.in(file("d"))`, closed right after the literal.
    static IN_DOT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"^\s*\.\s*in\s*\(\s*file\s*\(\s*"([^"\\\n]*)"\s*\)\s*\)"#).expect("regex")
    });
    // ` in file("d")`, not continued by a `/ "sub"` path expression.
    static IN_INFIX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"^\s+in\s+file\s*\(\s*"([^"\\\n]*)"\s*\)\s*(?:[).\n]|$)"#).expect("regex")
    });
    static IN_ANY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*(?:\.\s*in\s*\(|in\b)").expect("regex"));
    static PROJECT_TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\bproject\b").expect("regex"));
    static PROJECT_CTOR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\bProject\s*\(").expect("regex"));
    static PROJECT_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"^Project\s*\(\s*(?:id\s*=\s*)?"([^"\\\n]+)"\s*,\s*(?:base\s*=\s*)?file\s*\(\s*"([^"\\\n]*)"\s*\)\s*[,)]"#,
        )
        .expect("regex")
    });
    static UNREADABLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:projectMatrix|crossProject)\b").expect("regex"));

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    // A second definition of one id is ambiguous.
    let insert = |out: &mut BTreeMap<String, String>, id: &str, dir: String| -> Option<()> {
        out.insert(id.to_string(), dir).is_none().then_some(())
    };
    for (rel, text) in sources {
        if source_kind(rel) != Some(SourceKind::Definition) {
            continue;
        }
        let Lexed { code, skeleton } = lex(text);
        if UNREADABLE.is_match(&skeleton) {
            return None;
        }
        // Every `project` token must be the one a plain `val` binds.
        let mut bound: BTreeSet<usize> = BTreeSet::new();
        for caps in VAL_PROJECT.captures_iter(&code) {
            let token = caps.get(2).expect("group 2");
            if skeleton.as_bytes()[token.start()] == b' ' {
                continue; // inside a string literal
            }
            bound.insert(token.start());
            let id = &caps[1];
            let rest = &code[token.end()..];
            let dir = if let Some(m) = IN_DOT.captures(rest).or_else(|| IN_INFIX.captures(rest)) {
                normalize_dir(&m[1])?
            } else if IN_ANY.is_match(rest) {
                return None;
            } else {
                id.to_string()
            };
            insert(&mut out, id, dir)?;
        }
        if PROJECT_TOKEN
            .find_iter(&skeleton)
            .any(|m| !bound.contains(&m.start()))
        {
            return None;
        }
        for m in PROJECT_CTOR.find_iter(&skeleton) {
            let caps = PROJECT_LITERAL.captures(&code[m.start()..])?;
            insert(&mut out, &caps[1], normalize_dir(&caps[2])?)?;
        }
    }
    if !out.values().any(|dir| dir == ".") {
        insert(&mut out, IMPLICIT_ROOT_ID, ".".to_string())?;
    }
    Some(out)
}

/// One `"g" % "a" % "v"` dependency literal of the build (`op` is `%`,
/// `%%` or `%%%`; values trimmed).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DepLiteral {
    pub group: String,
    pub op: String,
    pub artifact: String,
    pub version: String,
}

impl DepLiteral {
    /// Whether this literal declares the Maven artifact `g:a`: a `%%` /
    /// `%%%` literal names `a` without its `_<scala binary>` suffix.
    pub fn declares(&self, g: &str, a: &str) -> bool {
        self.group == g
            && if self.op == "%" {
                self.artifact == a
            } else {
                a.strip_prefix(self.artifact.as_str())
                    .is_some_and(|rest| rest.starts_with('_'))
            }
    }
}

/// The literals of the sources of `kinds`.
fn literals_of(sources: &[(String, String)], meta: bool) -> BTreeSet<DepLiteral> {
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#""([^"\\\n]+)"\s*(%{1,3})\s*"([^"\\\n]+)"\s*%\s*"([^"\\\n]+)""#)
            .expect("regex")
    });
    let mut out = BTreeSet::new();
    for (rel, text) in sources {
        let wanted = match source_kind(rel) {
            Some(SourceKind::Definition | SourceKind::Subproject) => true,
            Some(SourceKind::Meta) => meta,
            _ => false,
        };
        if !wanted {
            continue;
        }
        for caps in DEP.captures_iter(&lex(text).code) {
            out.insert(DepLiteral {
                group: caps[1].trim().to_string(),
                op: caps[2].to_string(),
                artifact: caps[3].trim().to_string(),
                version: caps[4].trim().to_string(),
            });
        }
    }
    out
}

/// The library build's dependency literals (root and subproject `*.sbt`,
/// `project/**/*.scala`; never the meta-build's plugins).
pub fn dependency_literals(sources: &[(String, String)]) -> BTreeSet<DepLiteral> {
    literals_of(sources, false)
}

/// The versions `literals` declare for `g:a` that are newer than the pin's
/// `base` (a `-socket.<hex8>` suffix read as its base): the build-wide
/// override would silently force those back down to the patched base. A
/// dynamic version (`1.+`, a range, `latest.*`) is never compared; an older
/// declared version is evicted by the resolved base anyway.
pub fn declared_newer(
    literals: &BTreeSet<DepLiteral>,
    g: &str,
    a: &str,
    base: &str,
) -> Vec<String> {
    let mut out: Vec<String> = literals
        .iter()
        .filter(|l| l.declares(g, a))
        .map(|l| l.version.clone())
        .filter(|v| {
            !v.starts_with("latest.")
                && !v.contains(['+', '[', ']', '(', ')', ','])
                && numeric_newer(super::gate::normalize_version(v), base)
        })
        .collect();
    out.dedup();
    out
}

/// `v` is newer than `base` by their leading numeric `x.y.z` parts (missing
/// parts read as 0; a qualifier such as `-RC1` never makes a version
/// newer). The generated file's load-time check uses the same rule.
pub fn numeric_newer(v: &str, base: &str) -> bool {
    static NUMS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[0-9]+(?:\.[0-9]+)*").expect("regex"));
    let parts = |s: &str| -> Vec<String> {
        NUMS.find(s.trim())
            .map(|m| {
                m.as_str()
                    .split('.')
                    .map(|p| p.trim_start_matches('0').to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (x, y) = (parts(v), parts(base));
    for i in 0..x.len().max(y.len()) {
        let (p, q) = (
            x.get(i).map_or("", String::as_str),
            y.get(i).map_or("", String::as_str),
        );
        // Digit strings without leading zeros: longer is larger.
        match p.len().cmp(&q.len()).then_with(|| p.cmp(q)) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// A short digest (first 8 hex of a sha256) of every `"g" % "a" % "v"`
/// literal in the build, meta-build included (`%%` / `%%%` kept,
/// whitespace dropped, sorted and de-duplicated), with the sbt version. A
/// pin records it; a re-run that computes a different one knows the build's
/// dependencies changed since.
pub fn deps_digest(sources: &[(String, String)]) -> String {
    let literals: BTreeSet<String> = literals_of(sources, true)
        .into_iter()
        .map(|l| format!("{} {} {} % {}", l.group, l.op, l.artifact, l.version))
        .collect();
    let version = sources
        .iter()
        .filter(|(rel, _)| source_kind(rel) == Some(SourceKind::Properties))
        .map(|(_, text)| sbt_version(text).unwrap_or_default())
        .next_back()
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    for literal in &literals {
        hasher.update(literal.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"sbt.version=");
    hasher.update(version.as_bytes());
    hex::encode(hasher.finalize())[..8].to_string()
}

/// What [`scan_build_sources`] found, each as `<rel>:<line>` (`<rel>` alone
/// for a file-level finding).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildFindings {
    /// `dependencyOverrides :=` / `~=` / `--=`, in any scope: replaces the
    /// generated override where it applies.
    pub overrides_assignment: Vec<String>,
    /// `resolvers` / `externalResolvers` / `fullResolvers` `:=` or `~=`:
    /// can drop the generated resolver.
    pub resolvers_assignment: Vec<String>,
    /// `sbt.override.build.repos=true`: the launcher's repositories replace
    /// the build's, the generated resolver among them.
    pub override_build_repos: Vec<String>,
    /// A `build.sbt.lock` (sbt-dependency-lock), which a pin invalidates.
    pub dependency_lock: Vec<String>,
}

/// The build edits that defeat the generated file; see [`BuildFindings`].
/// Comments and string literals are ignored.
pub fn scan_build_sources(sources: &[(String, String)]) -> BuildFindings {
    const SCOPE: &str = r"(?:\s+in\s+\w+|\s*\.\s*in\s*\(\s*\w+\s*\))?\s*\)?\s*";
    static OVERRIDES: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(r"\bdependencyOverrides\b{SCOPE}(?::=|~=|--=)")).expect("regex")
    });
    static RESOLVERS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r"\b(?:resolvers|externalResolvers|fullResolvers)\b{SCOPE}(?::=|~=)"
        ))
        .expect("regex")
    });
    static OVERRIDE_REPOS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?m)^[^#!\n]*sbt\.override\.build\.repos\s*=\s*true\b").expect("regex")
    });
    // 1-based line of byte offset `at`, from the text's newline offsets (a
    // binary search, so many matches in a large file are not quadratic).
    let newlines =
        |text: &str| -> Vec<usize> { text.match_indices('\n').map(|(i, _)| i).collect() };
    let line_of = |nl: &[usize], at: usize| nl.partition_point(|&i| i < at) + 1;
    let mut out = BuildFindings::default();
    for (rel, text) in sources {
        match source_kind(rel) {
            Some(SourceKind::Definition | SourceKind::Subproject) => {
                let skeleton = lex(text).skeleton;
                let nl = newlines(&skeleton);
                for m in OVERRIDES.find_iter(&skeleton) {
                    out.overrides_assignment
                        .push(format!("{rel}:{}", line_of(&nl, m.start())));
                }
                for m in RESOLVERS.find_iter(&skeleton) {
                    out.resolvers_assignment
                        .push(format!("{rel}:{}", line_of(&nl, m.start())));
                }
            }
            Some(SourceKind::Opts | SourceKind::Properties) => {
                let nl = newlines(text);
                for m in OVERRIDE_REPOS.find_iter(text) {
                    out.override_build_repos
                        .push(format!("{rel}:{}", line_of(&nl, m.start())));
                }
            }
            Some(SourceKind::Lock) => out.dependency_lock.push(rel.clone()),
            Some(SourceKind::Meta) | None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(r, t)| (r.to_string(), t.to_string()))
            .collect()
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sbt_version_reads_properties_syntax() {
        assert_eq!(sbt_version("sbt.version=1.9.9\n").as_deref(), Some("1.9.9"));
        assert_eq!(
            sbt_version("# c\n\u{feff}sbt.version = 2.0.9 \n").as_deref(),
            Some("2.0.9")
        );
        assert_eq!(
            sbt_version("sbt.version: 0.13.18").as_deref(),
            Some("0.13.18")
        );
        assert_eq!(sbt_version("#sbt.version=1.0.0\n! x"), None);
        assert_eq!(sbt_version("sbt.versionx=1\nsbt.version="), None);
    }

    #[test]
    fn lines_and_support_range() {
        assert_eq!(sbt_line("0.13.18"), Some(SbtLine::Sbt013));
        assert_eq!(sbt_line("1.2.8"), Some(SbtLine::Sbt1));
        assert_eq!(sbt_line("2.0.9"), Some(SbtLine::Sbt2));
        assert_eq!(sbt_line("0.12.4"), None);
        assert_eq!(sbt_line("3.0.0"), None);
        assert_eq!(sbt_line("x"), None);
        assert_eq!(sbt_support("0.13.17"), SbtSupport::Unsupported);
        assert_eq!(
            sbt_support("0.13.18"),
            SbtSupport::Supported(SbtLine::Sbt013)
        );
        assert_eq!(sbt_support("1.13.0"), SbtSupport::Supported(SbtLine::Sbt1));
        assert_eq!(sbt_support("2.0.9"), SbtSupport::Supported(SbtLine::Sbt2));
        assert_eq!(sbt_support("2.1.0-M3"), SbtSupport::Untested(SbtLine::Sbt2));
        assert_eq!(sbt_support("1.10"), SbtSupport::Supported(SbtLine::Sbt1));
        assert_eq!(sbt_support("0.12.4"), SbtSupport::Unsupported);
        assert_eq!(sbt_support(""), SbtSupport::Unsupported);
        assert_eq!(parse_version("1.9.9-RC1"), Some((1, 9, 9)));
    }

    #[test]
    fn build_markers_and_root() {
        let files = map(&[("build.sbt", "")]);
        let read = files_reader(&files);
        assert!(is_sbt_build(&read) && sbt_build_present(&read));
        assert!(!is_sbt_build_root(&read), "no project/build.properties");
        let files = map(&[(BUILD_PROPERTIES, "sbt.version=1.9.9\n")]);
        assert!(is_sbt_build_root(&files_reader(&files)));
        let files = map(&[(BUILD_PROPERTIES, "# none\n")]);
        let read = files_reader(&files);
        assert!(is_sbt_build(&read) && !is_sbt_build_root(&read));
        let files = map(&[(HOSTED_FILE, "")]);
        let read = files_reader(&files);
        assert!(!is_sbt_build(&read) && sbt_build_present(&read));
        let files = map(&[("pom.xml", "")]);
        assert!(!sbt_build_present(&files_reader(&files)));
    }

    #[test]
    fn source_kinds() {
        for (rel, kind) in [
            ("build.sbt", Some(SourceKind::Definition)),
            ("zz.sbt", Some(SourceKind::Definition)),
            ("project/Build.scala", Some(SourceKind::Definition)),
            ("project/sub/Deps.scala", Some(SourceKind::Definition)),
            ("project/plugins.sbt", Some(SourceKind::Meta)),
            ("project/project/plugins.sbt", Some(SourceKind::Meta)),
            ("project/build.properties", Some(SourceKind::Properties)),
            ("a/build.sbt", Some(SourceKind::Subproject)),
            ("modules/a/extra.sbt", Some(SourceKind::Subproject)),
            (".sbtopts", Some(SourceKind::Opts)),
            (".jvmopts", Some(SourceKind::Opts)),
            ("build.sbt.lock", Some(SourceKind::Lock)),
            ("a/build.sbt.lock", Some(SourceKind::Lock)),
            (HOSTED_FILE, None),
            (VENDORED_FILE, None),
            ("a/target/x.sbt", None),
            ("src/main/scala/A.scala", None),
            ("../x.sbt", None),
        ] {
            assert_eq!(source_kind(rel), kind, "{rel}");
        }
    }

    #[test]
    fn lex_blanks_comments_and_string_contents_in_place() {
        let text = "a // x \"q\"\n/* b /* nested */ c */ \"s//t\" '\"' \"\"\"tri\"ple\"\"\" d";
        let Lexed { code, skeleton } = lex(text);
        assert_eq!(code.len(), text.len());
        assert_eq!(skeleton.len(), text.len());
        assert!(!code.contains('x') && !code.contains("nested") && !code.contains('c'));
        assert!(code.contains("\"s//t\"") && code.contains("tri\"ple"));
        assert!(!skeleton.contains("s//t") && !skeleton.contains("tri"));
        assert!(skeleton.ends_with(" d") && code.contains('\n'));
    }

    #[test]
    fn declared_projects_reads_every_literal_form() {
        let sources = src(&[(
            "build.sbt",
            r#"
lazy val text19 = "org.apache.commons" % "commons-text" % "1.9"
lazy val root = (project in file(".")).aggregate(a, b, c, d, e)
lazy val a = project.settings(libraryDependencies += text19)
lazy val b = project.in(file("modules/b/"))
val c: Project = (project in file("./c"))
lazy val d = Project("dee", file("d"))
lazy val e = Project(id = "e", base = file("e"), settings = Seq())
// lazy val f = project
val name = "project"
"#,
        )]);
        let got = declared_projects(&sources).expect("readable");
        let want = map(&[
            ("root", "."),
            ("a", "a"),
            ("b", "modules/b"),
            ("c", "c"),
            ("dee", "d"),
            ("e", "e"),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn declared_projects_adds_the_implicit_root() {
        let sources = src(&[("build.sbt", "lazy val a = project\n")]);
        assert_eq!(
            declared_projects(&sources),
            Some(map(&[("a", "a"), (IMPLICIT_ROOT_ID, ".")]))
        );
        let single = src(&[(
            "build.sbt",
            "libraryDependencies += \"g\" % \"a\" % \"1\"\n",
        )]);
        assert_eq!(
            declared_projects(&single),
            Some(map(&[(IMPLICIT_ROOT_ID, ".")]))
        );
        // Projects in project/*.scala count; meta-build and subproject
        // sources are not definitions.
        let scala = src(&[
            (
                "project/Build.scala",
                "object B { lazy val core = project }\n",
            ),
            ("project/plugins.sbt", "lazy val nope = project\n"),
            ("a/build.sbt", "lazy val nope = project\n"),
        ]);
        assert_eq!(
            declared_projects(&scala),
            Some(map(&[("core", "core"), (IMPLICIT_ROOT_ID, ".")]))
        );
    }

    #[test]
    fn declared_projects_fails_closed_on_unreadable_definitions() {
        for text in [
            "lazy val a = Project(name, file(\"a\"))",
            "lazy val a = Project(\"a\", file(dir))",
            "lazy val mods = Seq(\"a\", \"b\").map(n => Project(n, file(n)))",
            "def mk(n: String) = project.in(file(n))",
            "lazy val a = project.in(file(\"x\") / \"a\")",
            "lazy val a = project in dir",
            "lazy val core = projectMatrix.in(file(\"core\"))",
            "lazy val x = crossProject(JVMPlatform).in(file(\"x\"))",
            "lazy val a = project\nlazy val a = project.in(file(\"b\"))",
            "lazy val a = project.in(file(\"../a\"))",
            "lazy val a = project.in(file(\"/abs\"))",
            "lazy val a = foo(project)",
        ] {
            assert_eq!(
                declared_projects(&src(&[("build.sbt", text)])),
                None,
                "{text}"
            );
        }
    }

    #[test]
    fn deps_digest_is_stable_across_layout_and_tracks_changes() {
        let a = src(&[
            ("build.sbt", "libraryDependencies ++= Seq(\"g\" %% \"a\" % \"1\", \"h\" % \"b\" % \"2\" % Test)\n"),
            ("project/build.properties", "sbt.version=1.9.9\n"),
        ]);
        let b = src(&[
            ("project/build.properties", "sbt.version = 1.9.9"),
            ("build.sbt", "// reordered\nlibraryDependencies += \"h\"  %   \"b\" % \"2\"\nlibraryDependencies += \"g\" %%\n \"a\" % \"1\"\n"),
            (HOSTED_FILE, "dependencyOverrides += \"g\" % \"x\" % \"9-socket.abcdef12\""),
        ]);
        let d = deps_digest(&a);
        assert_eq!(d.len(), 8);
        assert!(d.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(d, deps_digest(&b));
        let bumped = src(&[
            (
                "build.sbt",
                "libraryDependencies ++= Seq(\"g\" %% \"a\" % \"1.1\", \"h\" % \"b\" % \"2\")\n",
            ),
            ("project/build.properties", "sbt.version=1.9.9\n"),
        ]);
        assert_ne!(d, deps_digest(&bumped));
        let other_sbt = src(&[
            (
                "build.sbt",
                "libraryDependencies ++= Seq(\"g\" %% \"a\" % \"1\", \"h\" % \"b\" % \"2\")\n",
            ),
            ("project/build.properties", "sbt.version=1.10.0\n"),
        ]);
        assert_ne!(d, deps_digest(&other_sbt));
        let commented = src(&[
            ("build.sbt", "libraryDependencies ++= Seq(\"g\" %% \"a\" % \"1\", \"h\" % \"b\" % \"2\")\n// \"x\" % \"y\" % \"3\"\n"),
            ("project/build.properties", "sbt.version=1.9.9\n"),
        ]);
        assert_eq!(d, deps_digest(&commented));
        let plugin = src(&[
            (
                "build.sbt",
                "libraryDependencies ++= Seq(\"g\" %% \"a\" % \"1\", \"h\" % \"b\" % \"2\")\n",
            ),
            ("project/build.properties", "sbt.version=1.9.9\n"),
            (
                "project/plugins.sbt",
                "addSbtPlugin(\"p\" % \"q\" % \"1\")\n",
            ),
        ]);
        assert_ne!(d, deps_digest(&plugin));
    }

    #[test]
    fn declared_newer_reads_direct_literals_of_the_pinned_ga() {
        let sources = src(&[
            (
                "build.sbt",
                "lazy val a = project\nlibraryDependencies ++= Seq(\n  \"org.apache.commons\" % \"commons-lang3\" % \"3.12.0\",\n  \"org.typelevel\" %% \"cats-core\" % \"2.9.0\",\n  \"g\" % \"dyn\" % \"1.+\")\n// \"g\" % \"x\" % \"9\"\n",
            ),
            ("a/build.sbt", "libraryDependencies += \"g\" % \"old\" % \"0.9\"\n"),
            ("project/plugins.sbt", "addSbtPlugin(\"g\" % \"plugin\" % \"9.0\")\n"),
            ("project/Deps.scala", "object Deps { val x = \"g\" % \"deps\" % \"2.0\" }\n"),
        ]);
        let lits = dependency_literals(&sources);
        assert!(!lits
            .iter()
            .any(|l| l.artifact == "plugin" || l.artifact == "x"));
        let lang3 = |base| declared_newer(&lits, "org.apache.commons", "commons-lang3", base);
        assert_eq!(lang3("3.11"), ["3.12.0"]);
        assert!(lang3("3.12.0").is_empty() && lang3("3.12.1").is_empty());
        assert_eq!(
            declared_newer(&lits, "org.typelevel", "cats-core_2.13", "2.8.0"),
            ["2.9.0"]
        );
        assert!(declared_newer(&lits, "org.typelevel", "cats-core", "2.8.0").is_empty());
        assert!(
            declared_newer(&lits, "g", "dyn", "1.0").is_empty(),
            "dynamic"
        );
        assert!(
            declared_newer(&lits, "g", "old", "1.0").is_empty(),
            "older: evicted"
        );
        assert_eq!(declared_newer(&lits, "g", "deps", "1.0"), ["2.0"]);
        assert!(
            declared_newer(&lits, "g", "plugin", "1.0").is_empty(),
            "meta-build"
        );
    }

    #[test]
    fn numeric_newer_compares_leading_numbers_only() {
        assert!(numeric_newer("3.12.0", "3.11"));
        assert!(numeric_newer("3.11.1", "3.11"));
        assert!(numeric_newer("10.0", "9.9.9"));
        assert!(numeric_newer("3.011", "3.9"), "leading zeros");
        assert!(!numeric_newer("3.11.0", "3.11"));
        assert!(!numeric_newer("3.11-RC1", "3.11"));
        assert!(!numeric_newer("3.10", "3.11"));
        assert!(!numeric_newer("x", "3.11"));
        assert!(numeric_newer("3.12", "x"));
    }

    #[test]
    fn scan_finds_assignments_in_every_scope_spelling() {
        let sources = src(&[
            (
                "build.sbt",
                "ThisBuild / dependencyOverrides := Seq()\n\
                 dependencyOverrides in ThisBuild := Set()\n\
                 dependencyOverrides.in(ThisBuild) ~= identity\n\
                 dependencyOverrides --= Seq()\n\
                 dependencyOverrides += x\n\
                 dependencyOverrides ++= Seq(x)\n\
                 // dependencyOverrides := Seq()\n\
                 val s = \"dependencyOverrides := Seq()\"\n\
                 resolvers := Seq(central)\n\
                 externalResolvers in ThisBuild := Nil\n\
                 fullResolvers ~= (_.take(1))\n\
                 resolvers += x\n",
            ),
            ("a/build.sbt", "dependencyOverrides := Seq()\n"),
            ("project/plugins.sbt", "dependencyOverrides := Seq()\n"),
            (".sbtopts", "-J-Xmx2g\n-Dsbt.override.build.repos=true\n"),
            (".jvmopts", "# -Dsbt.override.build.repos=true\n"),
            (
                "project/build.properties",
                "sbt.version=1.9.9\nsbt.override.build.repos = true\n",
            ),
            ("a/build.sbt.lock", "{}"),
            (HOSTED_FILE, "dependencyOverrides := Seq()\n"),
        ]);
        let found = scan_build_sources(&sources);
        assert_eq!(
            found.overrides_assignment,
            [
                "build.sbt:1",
                "build.sbt:2",
                "build.sbt:3",
                "build.sbt:4",
                "a/build.sbt:1"
            ]
        );
        assert_eq!(
            found.resolvers_assignment,
            ["build.sbt:9", "build.sbt:10", "build.sbt:11"]
        );
        assert_eq!(
            found.override_build_repos,
            [".sbtopts:2", "project/build.properties:2"]
        );
        assert_eq!(found.dependency_lock, ["a/build.sbt.lock"]);
        assert_eq!(scan_build_sources(&[]), BuildFindings::default());
    }
}
