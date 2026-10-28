//! Verify the projection of a patch into Go's selected native vendor tree.
//! modules.txt lists copied packages, not every package in the module. Files
//! outside those packages (except embeds/metadata) and dependency tests are
//! legitimately absent. Present files are always checked; a missing file in a
//! selected package needs proof that Go omits it.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::crawlers::go_crawler::{encode_module_path, GoCrawler};
use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{is_safe_relative_subpath, normalize_file_path};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::utils::fs::read_regular_to_string;

use super::go_mod_edit::{self, ReplaceEntry};

/// One patched module's native vendor check.
pub(super) struct Target<'a> {
    /// The project root (the consumer go.mod's directory).
    pub root: &'a Path,
    /// The vendor directory Go selects (the one holding modules.txt).
    pub dir: &'a Path,
    pub module: &'a str,
    pub version: &'a str,
    /// The project go.mod's `replace` directives.
    pub replaces: &'a [ReplaceEntry],
    /// Patched text the caller already holds, by `afterHash`.
    pub known: &'a HashMap<String, String>,
    /// `go mod vendor` or `go work vendor`.
    pub command: &'static str,
}

/// Read expected text from an authenticated blob or replacement copy. Never
/// trust a build constraint or dependency version from unverified content.
async fn expected_text(t: &Target<'_>, name: &str, hash: &str) -> Option<String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if let Some(text) = t
        .known
        .get(hash)
        .filter(|text| compute_git_sha256_from_bytes(text.as_bytes()) == hash)
    {
        return Some(text.clone());
    }
    let mut paths = vec![t.root.join(".socket/blobs").join(hash)];
    for entry in t.replaces.iter().filter(|e| {
        e.module == t.module && (e.version.is_none() || e.version.as_deref() == Some(t.version))
    }) {
        if let Some(path) = &entry.path {
            paths.push(t.root.join(path).join(name));
        } else if let (Some(cache), Some(target), Some(ver)) = (
            GoCrawler::get_gomodcache(),
            &entry.rhs_module,
            &entry.rhs_version,
        ) {
            if crate::patch::redirect::golang_local::are_safe_redirect_coords(target, ver) {
                paths.push(
                    cache
                        .join(format!(
                            "{}@{}",
                            encode_module_path(target),
                            encode_module_path(ver)
                        ))
                        .join(name),
                );
            }
        }
    }
    for path in paths {
        if let Ok(text) = read_regular_to_string(&path).await {
            if compute_git_sha256_from_bytes(text.as_bytes()) == hash {
                return Some(text);
            }
        }
    }
    None
}

pub(super) async fn verify(t: &Target<'_>, record: &PatchRecord) -> Result<(), String> {
    let (module, version) = (t.module, t.version);
    // Advice for drift that regenerating the vendor tree clears.
    let revendor = |detail: String| format!("{detail}; run `{}` and commit vendor/", t.command);
    let text = read_regular_to_string(&t.dir.join("modules.txt"))
        .await
        .map_err(|e| revendor(format!("cannot read {}/modules.txt: {e}", t.dir.display())))?;
    let packages: HashSet<_> = text
        .lines()
        .filter(|s| !s.starts_with('#') && !s.is_empty())
        .collect();
    // Trailing replacement-only headers describe unused versions too. Only
    // a section with metadata or packages records a selected requirement.
    let mut versions = HashMap::new();
    let mut current = None;
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("# ") {
            let mut fields = header.split_whitespace();
            current = fields
                .next()
                .zip(fields.next())
                .filter(|(_, v)| v.starts_with('v'));
        } else if !line.is_empty() {
            if let Some((module, version)) = current {
                versions.insert(module, version);
            }
        }
    }
    // A module in the build list that provides no vendored package (one only
    // a dependency's tests import, say) has no section, just its trailing
    // `# M v => …` replacement line, and `go mod vendor` cannot add one. Go
    // compiles none of its files, so only its patched requirements matter.
    let compiled = match versions.get(module).copied() {
        Some(selected) if selected == version => true,
        Some(other) => {
            return Err(format!(
                "vendor/modules.txt selects {module} {other}, not the patched {version}, so \
                 the vendored build does not use the patch"
            ))
        }
        None => false,
    };
    let mut embeds = EmbedCache::new();
    for (name, info) in &record.files {
        let name = normalize_file_path(name);
        if !is_safe_relative_subpath(name) {
            return Err("invalid Go patch file path".into());
        }
        if name == "go.mod" {
            let patched = expected_text(t, name, &info.after_hash)
                .await
                .ok_or_else(|| {
                    format!(
                        "cannot verify the patched {module}/go.mod requirements: no local \
                         patch blob or patched copy holds the patched go.mod"
                    )
                })?;
            for (dep, required) in
                go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(&patched))
            {
                // A dependency pruned out of the consumer's graph has no
                // vendored packages. A selected dependency must be new enough.
                if versions.get(dep.as_str()).is_some_and(|selected| {
                    super::go_sum_edit::go_semver_cmp(selected, &required).is_lt()
                }) {
                    return Err(format!(
                        "vendor/modules.txt selects {dep} below patched requirement \
                         {required}; run `go mod tidy`, then `{}`, and commit go.mod, go.sum \
                         and vendor/",
                        t.command
                    ));
                }
            }
            continue;
        }
        if !compiled || name == "go.sum" || name.ends_with("_test.go") {
            continue;
        }
        let path = t.dir.join(module).join(name);
        match compute_file_git_sha256(&path).await {
            Ok(hash) if hash == info.after_hash => continue,
            Ok(_) => {
                return Err(revendor(format!(
                    "{} does not match the patched file",
                    path.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(revendor(format!("cannot verify {}: {e}", path.display()))),
        }
        // Empty after hashes denote deletions, not empty files.
        if info.after_hash.is_empty() {
            continue;
        }
        let parent = Path::new(name).parent().unwrap_or(Path::new(""));
        let package = if parent.as_os_str().is_empty() {
            module.to_string()
        } else {
            Path::new(module)
                .join(parent)
                .to_string_lossy()
                .replace('\\', "/")
        };
        if !packages.contains(package.as_str()) {
            if !is_embedded(t.dir, module, name, &packages, &mut embeds)
                .await
                .map_err(revendor)?
            {
                continue;
            }
            return Err(revendor(format!(
                "{} is missing a patched embedded asset",
                path.display()
            )));
        }
        if name.ends_with(".go") {
            if let Some(text) = expected_text(t, name, &info.after_hash).await {
                if omitted_by_build_constraint(&text) {
                    continue;
                }
            }
        }
        return Err(revendor(format!(
            "{} is missing a patched runtime file",
            path.display()
        )));
    }
    Ok(())
}

/// The `(all:, pattern)` embed patterns of each vendored package read so
/// far, so several missing files share one scan of a package's sources.
type EmbedCache = HashMap<String, Vec<(bool, String)>>;

// Embedded files can live below a selected package without being packages
// themselves. Match both explicit files and recursively embedded directories.
async fn is_embedded(
    dir: &Path,
    module: &str,
    name: &str,
    packages: &HashSet<&str>,
    cache: &mut EmbedCache,
) -> Result<bool, String> {
    // A pattern names paths relative to its package's directory, so only the
    // vendored packages at or above the file can embed it.
    let parts: Vec<&str> = name.split('/').collect();
    for depth in 0..parts.len() {
        let package = match parts[..depth].join("/") {
            subdir if subdir.is_empty() => module.to_string(),
            subdir => format!("{module}/{subdir}"),
        };
        if !packages.contains(package.as_str()) {
            continue;
        }
        if !cache.contains_key(&package) {
            let found = package_embeds(dir, &package).await?;
            cache.insert(package.clone(), found);
        }
        let relative = &parts[depth..];
        for (all, pattern) in &cache[&package] {
            for end in 1..=relative.len() {
                // A matched directory embeds its files recursively, except
                // hidden (`.`/`_`) ones below it unless the pattern is `all:`.
                if path_match(pattern, &relative[..end].join("/")) == Ok(true)
                    && (*all || relative[end..].iter().all(|p| !p.starts_with(['.', '_'])))
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// The embed patterns of one vendored package's Go files, as go/build reads
/// them: `_`/`.` files are not part of the package, an `ignore`-constrained
/// file is never vendored, and a malformed directive or an invalid pattern is
/// skipped (the compiler and `go mod vendor` report those themselves).
async fn package_embeds(dir: &Path, package: &str) -> Result<Vec<(bool, String)>, String> {
    let mut out = Vec::new();
    let package_dir = dir.join(package);
    let mut files = match tokio::fs::read_dir(&package_dir).await {
        Ok(files) => files,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("cannot read {}: {e}", package_dir.display())),
    };
    while let Some(file) = files.next_entry().await.map_err(|e| e.to_string())? {
        let filename = file.file_name();
        let filename = filename.to_string_lossy();
        if !filename.ends_with(".go")
            || filename.ends_with("_test.go")
            || filename.starts_with(['.', '_'])
        {
            continue;
        }
        let source = read_regular_to_string(&file.path())
            .await
            .map_err(|e| format!("cannot read {}: {e}", file.path().display()))?;
        if omitted_by_build_constraint(&source) {
            continue;
        }
        for args in embed_directives(&source) {
            let Some(patterns) = embed_patterns(args) else {
                continue;
            };
            for pattern in patterns {
                let (all, glob) = match pattern.strip_prefix("all:") {
                    Some(glob) => (true, glob.to_string()),
                    None => (false, pattern),
                };
                if path_match(&glob, "").is_ok() {
                    out.push((all, glob));
                }
            }
        }
    }
    Ok(out)
}

/// The argument text of each `//go:embed` directive in Go source, found the
/// way go/build finds them: a `//` comment token (never one inside a string,
/// rune, raw string or block comment) whose directive name is exactly
/// `embed`.
fn embed_directives(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = source[i..].find('\n').map_or(bytes.len(), |n| i + n);
                let comment = source[i..end].trim_end_matches('\r');
                if let Some(rest) = comment.strip_prefix("//go:embed") {
                    // ast.ParseDirective: the name runs to the first space.
                    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                        out.push(rest);
                    }
                }
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = source[i + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |n| i + 2 + n + 2);
            }
            b'`' => {
                i = source[i + 1..]
                    .find('`')
                    .map_or(bytes.len(), |n| i + 1 + n + 1);
            }
            quote @ (b'"' | b'\'') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// A `//go:embed` directive's arguments, as ast.Directive.ParseArgs splits
/// them: bare words, or Go string literals that must be followed by a space
/// or the end. `None` for a malformed line.
fn embed_patterns(mut text: &str) -> Option<Vec<String>> {
    let quoted_end = |rest: &str| rest.is_empty() || rest.starts_with(char::is_whitespace);
    let mut patterns = Vec::new();
    while !text.trim_start().is_empty() {
        text = text.trim_start();
        if let Some(rest) = text.strip_prefix('`') {
            let (pattern, rest) = rest.split_once('`')?;
            if !quoted_end(rest) {
                return None;
            }
            patterns.push(pattern.to_string());
            text = rest;
        } else if let Some(rest) = text.strip_prefix('"') {
            let mut chars = rest.char_indices();
            let mut pattern = String::new();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => {
                        end = Some(i + 1);
                        break;
                    }
                    '\\' => {
                        let (_, escaped) = chars.next()?;
                        pattern.push(match escaped {
                            'a' => '\u{7}',
                            'b' => '\u{8}',
                            'f' => '\u{c}',
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            'v' => '\u{b}',
                            '\\' | '"' => escaped,
                            'x' | 'u' | 'U' | '0'..='7' => {
                                let (radix, count, mut value) = match escaped {
                                    'x' => (16, 2, 0),
                                    'u' => (16, 4, 0),
                                    'U' => (16, 8, 0),
                                    c => (8, 2, c.to_digit(8)?),
                                };
                                for _ in 0..count {
                                    value = value
                                        .checked_mul(radix)?
                                        .checked_add(chars.next()?.1.to_digit(radix)?)?;
                                }
                                char::from_u32(value)?
                            }
                            _ => return None,
                        });
                    }
                    c => pattern.push(c),
                }
            }
            text = &rest[end?..];
            if !quoted_end(text) {
                return None;
            }
            patterns.push(pattern);
        } else {
            let end = text.find(char::is_whitespace).unwrap_or(text.len());
            patterns.push(text[..end].to_string());
            text = &text[end..];
        }
    }
    Some(patterns)
}

/// Go's `path.Match` (path/match.go), which `//go:embed` patterns use: `*`
/// and `?` never match `/`, `[^…]` negates a class, `\` escapes, and `**`
/// is just `*`. `Err(())` for a malformed pattern.
fn path_match(pattern: &str, name: &str) -> Result<bool, ()> {
    let mut pattern = pattern.as_bytes();
    let mut name = name.as_bytes();
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // A trailing * matches the rest of the name unless it has a /.
            return Ok(!name.contains(&b'/'));
        }
        // Look for a match at the current position. The last chunk must
        // exhaust the name, or a later star might still match.
        match match_chunk(chunk, name)? {
            Some(t) if t.is_empty() || !pattern.is_empty() => {
                name = t;
                continue;
            }
            _ => {}
        }
        if star {
            // Look for a match skipping i+1 bytes; a star cannot skip a /.
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                if let Some(t) = match_chunk(chunk, &name[i + 1..])? {
                    // The last chunk must exhaust the name.
                    if !pattern.is_empty() || t.is_empty() {
                        name = t;
                        continue 'pattern;
                    }
                }
                i += 1;
            }
        }
        // Before returning false, check that the rest of the pattern is
        // well-formed.
        while !pattern.is_empty() {
            let (_, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            match_chunk(chunk, b"")?;
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

/// path.Match's scanChunk: leading stars, then the chunk up to the next star
/// outside a class.
fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while let [b'*', rest @ ..] = pattern {
        pattern = rest;
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => return (star, &pattern[..i], &pattern[i..]),
            _ => {}
        }
        i += 1;
    }
    (star, pattern, &[])
}

/// path.Match's matchChunk: the rest of `s` after `chunk` matched its start,
/// `None` on no match. Keeps checking the chunk's syntax after a mismatch.
fn match_chunk<'s>(mut chunk: &[u8], mut s: &'s [u8]) -> Result<Option<&'s [u8]>, ()> {
    let mut failed = false;
    while !chunk.is_empty() {
        failed = failed || s.is_empty();
        match chunk[0] {
            b'[' => {
                let mut r = 0;
                if !failed {
                    let (c, n) = decode_rune(s);
                    r = c;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let negated = chunk.first() == Some(&b'^');
                if negated {
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut ranges = 0;
                loop {
                    if chunk.first() == Some(&b']') && ranges > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        let (h, rest) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest;
                    }
                    matched = matched || lo <= r && r <= hi;
                    ranges += 1;
                }
                failed = failed || matched == negated;
            }
            b'?' => {
                if !failed {
                    failed = s[0] == b'/';
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            b'\\' => {
                chunk = &chunk[1..];
                if chunk.is_empty() {
                    return Err(());
                }
                if !failed {
                    failed = chunk[0] != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
            c => {
                if !failed {
                    failed = c != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok((!failed).then_some(s))
}

/// path.Match's getEsc: one possibly escaped class character, which must
/// be followed by more of the class.
fn get_esc(mut chunk: &[u8]) -> Result<(u32, &[u8]), ()> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(());
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(());
        }
    }
    let (r, n) = decode_rune(chunk);
    if (r == 0xFFFD && n == 1) || chunk.len() == n {
        return Err(());
    }
    Ok((r, &chunk[n..]))
}

/// utf8.DecodeRune: the first rune and its length, `(U+FFFD, 1)` for an
/// invalid encoding.
fn decode_rune(s: &[u8]) -> (u32, usize) {
    let len = match s.first() {
        None => return (0xFFFD, 0),
        Some(&b) if b < 0x80 => return (u32::from(b), 1),
        Some(&b) if b >= 0xF0 => 4,
        Some(&b) if b >= 0xE0 => 3,
        Some(&b) if b >= 0xC0 => 2,
        Some(_) => return (0xFFFD, 1),
    };
    s.get(..len)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| text.chars().next())
        .map_or((0xFFFD, 1), |c| (u32::from(c), len))
}

// Go vendors files for every platform/tag except constraints that require
// `ignore`. Each ordinary tag can be true OR false in this mode. The pair is
// Go's AnyTags evaluation for prefer=true and prefer=false respectively.
fn constraint(expr: &str) -> Option<bool> {
    fn atom(input: &mut &str, depth: usize) -> Option<(bool, bool)> {
        if depth > 100 {
            return None;
        }
        *input = input.trim_start();
        if let Some(rest) = input.strip_prefix('!') {
            *input = rest;
            let (a, b) = atom(input, depth + 1)?;
            return Some((!b, !a));
        }
        if let Some(rest) = input.strip_prefix('(') {
            *input = rest;
            let value = or(input, depth + 1)?;
            *input = input.trim_start().strip_prefix(')')?;
            return Some(value);
        }
        let end = input
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(input.len());
        if end == 0 {
            return None;
        }
        let tag = &input[..end];
        *input = &input[end..];
        Some((tag != "ignore", false))
    }
    fn and(input: &mut &str, depth: usize) -> Option<(bool, bool)> {
        let mut value = atom(input, depth)?;
        while let Some(rest) = input.trim_start().strip_prefix("&&") {
            *input = rest;
            let rhs = atom(input, depth)?;
            value = (value.0 && rhs.0, value.1 && rhs.1);
        }
        Some(value)
    }
    fn or(input: &mut &str, depth: usize) -> Option<(bool, bool)> {
        let mut value = and(input, depth)?;
        while let Some(rest) = input.trim_start().strip_prefix("||") {
            *input = rest;
            let rhs = and(input, depth)?;
            value = (value.0 || rhs.0, value.1 || rhs.1);
        }
        Some(value)
    }
    let mut input = expr;
    let value = or(&mut input, 0)?;
    input.trim().is_empty().then_some(value.0)
}

/// The expression of a `//go:build` line (imports.isGoBuildComment): the
/// prefix followed by whitespace or nothing.
fn go_build_expr(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("//go:build")?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim())
}

/// The expression of a `// +build` line (constraint.splitPlusBuild): `//`,
/// optional whitespace, `+build`, then whitespace or nothing.
fn plus_build_expr(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("//")?
        .trim_start()
        .strip_prefix("+build")?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim())
}

/// Whether a `// +build` line excludes the file when every tag but `ignore`
/// is both true and false (Go's AnyTags), following
/// constraint.parsePlusBuildExpr: space-separated clauses OR, comma-separated
/// literals AND, and `!!x`, a lone `!`, an invalid tag and an empty line all
/// read as `ignore`. `!x` holds for any `x`.
fn plus_build_excludes(expr: &str) -> bool {
    let valid_tag = |tag: &str| {
        !tag.is_empty()
            && tag
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    };
    let excludes = |lit: &str| {
        if lit.starts_with("!!") || lit == "!" {
            return true;
        }
        !lit.starts_with('!') && (lit == "ignore" || !valid_tag(lit))
    };
    let mut clauses = expr.split_whitespace().peekable();
    clauses.peek().is_none() || clauses.all(|clause| clause.split(',').any(excludes))
}

fn omitted_by_build_constraint(text: &str) -> bool {
    let mut modern = None;
    let mut legacy = Vec::new();
    let mut legacy_end = 0;
    let mut block = false;
    let mut legacy_allowed = true;
    for line in text.lines() {
        let mut line = line.trim();
        if line.is_empty() && legacy_allowed {
            legacy_end = legacy.len();
        }
        if !block {
            if let Some(expr) = go_build_expr(line) {
                if modern.replace(expr).is_some() {
                    return false;
                }
            } else if legacy_allowed {
                if let Some(expr) = plus_build_expr(line) {
                    legacy.push(expr);
                }
            }
        }
        loop {
            if block {
                let Some((_, rest)) = line.split_once("*/") else {
                    break;
                };
                line = rest.trim();
                block = false;
            } else if let Some(rest) = line.strip_prefix("/*") {
                block = true;
                legacy_allowed = false;
                line = rest;
            } else {
                break;
            }
        }
        if block {
            continue;
        }
        if !line.is_empty() && !line.starts_with("//") {
            break;
        }
    }
    if let Some(expr) = modern {
        return constraint(expr) == Some(false);
    }
    legacy[..legacy_end]
        .iter()
        .any(|expr| plus_build_excludes(expr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_patterns_decode_go_literals() {
        assert_eq!(
            embed_patterns(r#"data/* "space dir/*.txt" `all:assets` "data/\x66ix.txt""#),
            Some(vec![
                "data/*".into(),
                "space dir/*.txt".into(),
                "all:assets".into(),
                "data/fix.txt".into()
            ])
        );
        assert_eq!(embed_patterns("\"unterminated"), None);
        // A quoted argument must end at a space (ast.Directive.ParseArgs).
        assert_eq!(embed_patterns(r#""a"b"#), None);
        assert_eq!(embed_patterns("`a`b"), None);
    }

    #[test]
    fn embed_directives_are_line_comments_outside_literals() {
        let source = "package p\n\nimport \"embed\"\n\n\
            //go:embed static/*\n\
            var a embed.FS\n\
            //go:embed\ttabbed\r\n\
            var b embed.FS\n\
            //go:embedded not-a-directive\n\
            const tmpl = `\n//go:embed in-raw-string\n`\n\
            const s = \"//go:embed in-string\"\n\
            /*\n//go:embed in-block-comment\n*/\n";
        let found: Vec<_> = embed_directives(source)
            .into_iter()
            .map(str::trim)
            .collect();
        assert_eq!(found, vec!["static/*", "tabbed"]);
    }

    #[test]
    fn path_match_follows_go() {
        // Cases from Go's path/match_test.go plus embed patterns the glob
        // crate read differently.
        for (pattern, name, want) in [
            ("abc", "abc", Ok(true)),
            ("*", "abc", Ok(true)),
            ("*c", "abc", Ok(true)),
            ("a*", "a", Ok(true)),
            ("a*", "abc", Ok(true)),
            ("a*", "ab/c", Ok(false)),
            ("a*/b", "abc/b", Ok(true)),
            ("a*/b", "a/c/b", Ok(false)),
            ("a*b*c*d*e*/f", "axbxcxdxe/f", Ok(true)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/f", Ok(true)),
            ("a*b*c*d*e*/f", "axbxcxdxe/xxx/f", Ok(false)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/fff", Ok(false)),
            ("a*b?c*x", "abxbbxdbxebxczzx", Ok(true)),
            ("a*b?c*x", "abxbbxdbxebxczzy", Ok(false)),
            ("ab[c]", "abc", Ok(true)),
            ("ab[b-d]", "abc", Ok(true)),
            ("ab[e-g]", "abc", Ok(false)),
            ("ab[^c]", "abc", Ok(false)),
            ("ab[^b-d]", "abc", Ok(false)),
            ("ab[^e-g]", "abc", Ok(true)),
            ("a\\*b", "a*b", Ok(true)),
            ("a\\*b", "ab", Ok(false)),
            ("a?b", "a\u{263a}b", Ok(true)),
            ("a[^a]b", "a\u{263a}b", Ok(true)),
            ("a???b", "a\u{263a}b", Ok(false)),
            ("a[^a][^a][^a]b", "a\u{263a}b", Ok(false)),
            ("[a-\u{3b6}]*", "\u{3b1}", Ok(true)),
            ("*[a-\u{3b6}]", "A", Ok(false)),
            ("a?b", "a/b", Ok(false)),
            ("a*b", "a/b", Ok(false)),
            ("[\\]a]", "]", Ok(true)),
            ("[\\-]", "-", Ok(true)),
            ("[x\\-]", "x", Ok(true)),
            ("[x\\-]", "-", Ok(true)),
            ("[x\\-]", "z", Ok(false)),
            ("[\\-x]", "x", Ok(true)),
            ("[\\-x]", "-", Ok(true)),
            ("[\\-x]", "a", Ok(false)),
            ("[]a]", "]", Err(())),
            ("[-]", "-", Err(())),
            ("[x-]", "x", Err(())),
            ("[x-]", "-", Err(())),
            ("[x-]", "z", Err(())),
            ("[-x]", "x", Err(())),
            ("[-x]", "-", Err(())),
            ("[-x]", "a", Err(())),
            ("\\", "a", Err(())),
            ("[a-b-c]", "a", Err(())),
            ("[", "a", Err(())),
            ("[^", "a", Err(())),
            ("[^bc", "a", Err(())),
            ("a[", "a", Err(())),
            ("a[", "ab", Err(())),
            ("a[", "x", Err(())),
            ("a/b[", "x", Err(())),
            ("*x", "xxx", Ok(true)),
            ("static/a**", "static/abc", Ok(true)),
            ("static/**.css", "static/x.css", Ok(true)),
            (
                "templates/**/*.html",
                "templates/admin/index.html",
                Ok(true),
            ),
            ("templates/**/*.html", "templates/a/b/c.html", Ok(false)),
            ("templates/**/*.html", "templates/top.html", Ok(false)),
            ("static/[!.]*", "static/app.js", Ok(false)),
            ("static/[!.]*", "static/!x", Ok(true)),
            ("static/[^.]*", "static/app.js", Ok(true)),
            ("static/[^.]*", "static/.env", Ok(false)),
            ("pages/\\[id\\].html", "pages/[id].html", Ok(true)),
        ] {
            assert_eq!(path_match(pattern, name), want, "{pattern} vs {name}");
        }
    }

    #[test]
    fn vendor_build_constraints_match_any_platform_except_ignore() {
        for expr in [
            "ignore",
            "linux && ignore",
            "(windows || linux) && ignore",
            "!!ignore",
        ] {
            assert!(
                omitted_by_build_constraint(&format!("//go:build {expr}\n\npackage main\n")),
                "{expr}"
            );
        }
        for expr in [
            "linux",
            "!linux",
            "linux && !linux",
            "ignore || windows",
            "!ignore",
            "!(ignore && linux)",
        ] {
            assert!(
                !omitted_by_build_constraint(&format!("//go:build {expr}\n\npackage main\n")),
                "{expr}"
            );
        }
        assert!(omitted_by_build_constraint(
            "// +build ignore,linux\n\npackage main\n"
        ));
        assert!(!omitted_by_build_constraint(
            "// +build ignore linux\n\npackage main\n"
        ));
        assert!(!omitted_by_build_constraint(
            "// +build ignore\npackage main\n"
        ));
        assert!(!omitted_by_build_constraint(
            "/* //go:build ignore */\npackage main\n"
        ));
        assert!(!omitted_by_build_constraint(
            "package main\n//go:build ignore\n"
        ));
    }

    #[test]
    fn build_constraint_headers_and_plus_build_literals_follow_go() {
        // Spellings go mod vendor treats as excluding the file.
        for header in [
            "//go:build\tignore",
            "//+build ignore",
            "//  +build ignore",
            "// +build\tignore",
            "// +build",
            "// +build !!linux",
            "// +build !",
            "// +build integration-test",
            "// +build linux,!!amd64 darwin-x",
        ] {
            assert!(
                omitted_by_build_constraint(&format!("{header}\n\npackage main\n")),
                "{header:?}"
            );
        }
        // And ones it keeps: negations hold for any tag, and a longer word
        // is not the directive.
        for header in [
            "// +build !ignore",
            "// +build !integration-test",
            "// +buildfoo ignore",
            "//go:buildx ignore",
        ] {
            assert!(
                !omitted_by_build_constraint(&format!("{header}\n\npackage main\n")),
                "{header:?}"
            );
        }
    }

    fn record(files: &[(&str, &str)]) -> PatchRecord {
        PatchRecord {
            uuid: "u".into(),
            exported_at: "t".into(),
            files: files
                .iter()
                .map(|(name, after)| {
                    (
                        name.to_string(),
                        crate::manifest::schema::PatchFileInfo {
                            before_hash: String::new(),
                            after_hash: after.to_string(),
                        },
                    )
                })
                .collect(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    #[tokio::test]
    async fn module_without_vendored_packages_is_not_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join("vendor");
        std::fs::create_dir_all(&dir).unwrap();
        // example.com/testonly is in the build list (a dependency's tests
        // import it), so go mod vendor writes only its replacement line.
        std::fs::write(
            dir.join("modules.txt"),
            "# example.com/dep v1.0.0\n## explicit; go 1.21\nexample.com/dep\n\
             # example.com/testonly v1.0.0 => ./.socket/go-patches/example.com/testonly@v1.0.0\n",
        )
        .unwrap();
        let hash = compute_git_sha256_from_bytes(b"package testonly\n");
        let known = HashMap::new();
        let target = |module| Target {
            root,
            dir: &dir,
            module,
            version: "v1.0.0",
            replaces: &[],
            known: &known,
            command: "go mod vendor",
        };
        let rec = record(&[("lib.go", &hash)]);
        assert_eq!(verify(&target("example.com/testonly"), &rec).await, Ok(()));
        // A selected module's missing file is still drift.
        let err = verify(&target("example.com/dep"), &rec).await.unwrap_err();
        assert!(err.contains("missing a patched runtime file"), "{err}");
        // So is another selected version, without re-vendoring advice.
        std::fs::write(
            dir.join("modules.txt"),
            "# example.com/testonly v1.1.0\n## explicit; go 1.21\nexample.com/testonly\n",
        )
        .unwrap();
        let err = verify(&target("example.com/testonly"), &rec)
            .await
            .unwrap_err();
        assert!(err.contains("selects example.com/testonly v1.1.0"), "{err}");
        assert!(!err.contains("go mod vendor"), "{err}");
    }

    #[tokio::test]
    async fn embeds_use_go_pattern_rules_and_skip_unbuilt_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vendor");
        let pkg = dir.join("example.com/m");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("assets.go"),
            "package m\n\nimport \"embed\"\n\n//go:embed templates/**/*.html static/a** css/[^_]*\n\
             var fs embed.FS\nconst t = `\n//go:embed raw/*\n`\n",
        )
        .unwrap();
        std::fs::write(
            pkg.join("_old.go"),
            "package m\n\nimport \"embed\"\n\n//go:embed old/*\nvar o embed.FS\n",
        )
        .unwrap();
        std::fs::write(
            pkg.join("gen.go"),
            "//go:build ignore\n\npackage main\n\nimport \"embed\"\n\n//go:embed gen/*\nvar g embed.FS\n",
        )
        .unwrap();
        let packages: HashSet<&str> = ["example.com/m"].into_iter().collect();
        let mut cache = EmbedCache::new();
        for (name, want) in [
            ("templates/admin/index.html", true),
            ("templates/admin/deep/x.html", false),
            ("templates/top.html", false),
            ("static/abc.txt", true),
            ("css/site.css", true),
            ("css/_partial.css", false),
            ("raw/x.txt", false),
            ("old/x.txt", false),
            ("gen/x.txt", false),
        ] {
            assert_eq!(
                is_embedded(&dir, "example.com/m", name, &packages, &mut cache).await,
                Ok(want),
                "{name}"
            );
        }
    }
}
