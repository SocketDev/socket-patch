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

/// Read expected text from an authenticated blob or replacement copy. Never
/// trust a build constraint or dependency version from unverified content.
async fn expected_text(
    root: &Path,
    replaces: &[ReplaceEntry],
    module: &str,
    version: &str,
    name: &str,
    hash: &str,
) -> Option<String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut paths = vec![root.join(".socket/blobs").join(hash)];
    for entry in replaces.iter().filter(|e| {
        e.module == module && (e.version.is_none() || e.version.as_deref() == Some(version))
    }) {
        if let Some(path) = &entry.path {
            paths.push(root.join(path).join(name));
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

pub(super) async fn verify(
    root: &Path,
    dir: &Path,
    module: &str,
    version: &str,
    record: &PatchRecord,
    replaces: &[ReplaceEntry],
) -> Result<(), String> {
    let text = read_regular_to_string(&dir.join("modules.txt"))
        .await
        .map_err(|e| format!("cannot read {}/modules.txt: {e}", dir.display()))?;
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
    if versions.get(module).copied() != Some(version) {
        return Err(format!(
            "vendor/modules.txt does not select {module} {version}"
        ));
    }
    for (name, info) in &record.files {
        let name = normalize_file_path(name);
        if !is_safe_relative_subpath(name) {
            return Err("invalid Go patch file path".into());
        }
        if name == "go.mod" {
            let patched = expected_text(root, replaces, module, version, name, &info.after_hash)
                .await
                .ok_or_else(|| format!("cannot verify the patched {module}/go.mod requirements"))?;
            for (dep, required) in
                go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(&patched))
            {
                // A dependency pruned out of the consumer's graph has no
                // vendored packages. A selected dependency must be new enough.
                if versions.get(dep.as_str()).is_some_and(|selected| {
                    super::go_sum_edit::go_semver_cmp(selected, &required).is_lt()
                }) {
                    return Err(format!(
                        "vendor/modules.txt selects {dep} below patched requirement {required}"
                    ));
                }
            }
            continue;
        }
        if name == "go.sum" || name.ends_with("_test.go") {
            continue;
        }
        let path = dir.join(module).join(name);
        match compute_file_git_sha256(&path).await {
            Ok(hash) if hash == info.after_hash => continue,
            Ok(_) => {
                return Err(format!(
                    "{} does not match the patched file",
                    path.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot verify {}: {e}", path.display())),
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
            if !is_embedded(dir, module, name, &packages).await? {
                continue;
            }
            return Err(format!(
                "{} is missing a patched embedded asset",
                path.display()
            ));
        }
        if name.ends_with(".go") {
            if let Some(text) =
                expected_text(root, replaces, module, version, name, &info.after_hash).await
            {
                if omitted_by_build_constraint(&text) {
                    continue;
                }
            }
        }
        return Err(format!(
            "{} is missing a patched runtime file",
            path.display()
        ));
    }
    Ok(())
}

// Embedded files can live below a selected package without being packages
// themselves. Match both explicit files and recursively embedded directories.
async fn is_embedded(
    dir: &Path,
    module: &str,
    name: &str,
    packages: &HashSet<&str>,
) -> Result<bool, String> {
    for package in packages {
        let relative = if *package == module {
            name
        } else if let Some(subdir) = package.strip_prefix(&format!("{module}/")) {
            let Some(relative) = name.strip_prefix(&format!("{subdir}/")) else {
                continue;
            };
            relative
        } else {
            continue;
        };
        let mut files = tokio::fs::read_dir(dir.join(package))
            .await
            .map_err(|e| e.to_string())?;
        while let Some(file) = files.next_entry().await.map_err(|e| e.to_string())? {
            let filename = file.file_name();
            let filename = filename.to_string_lossy();
            if !filename.ends_with(".go") || filename.ends_with("_test.go") {
                continue;
            }
            let source = read_regular_to_string(&file.path())
                .await
                .map_err(|e| e.to_string())?;
            if omitted_by_build_constraint(&source) {
                continue;
            }
            for line in source.lines() {
                let Some(patterns) = line
                    .trim()
                    .strip_prefix("//go:embed")
                    .filter(|tail| tail.starts_with(char::is_whitespace))
                else {
                    continue;
                };
                let patterns = embed_patterns(patterns).ok_or_else(|| {
                    format!("cannot parse embed patterns in {}", file.path().display())
                })?;
                for pattern in patterns {
                    let (all, pattern) = pattern
                        .strip_prefix("all:")
                        .map_or((false, pattern.as_str()), |p| (true, p));
                    let pattern = glob::Pattern::new(pattern).map_err(|e| e.to_string())?;
                    let parts: Vec<_> = relative.split('/').collect();
                    for end in 1..=parts.len() {
                        if pattern.matches_with(
                            &parts[..end].join("/"),
                            glob::MatchOptions {
                                case_sensitive: true,
                                require_literal_separator: true,
                                require_literal_leading_dot: false,
                            },
                        ) && (all || parts[end..].iter().all(|p| !p.starts_with(['.', '_'])))
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

fn embed_patterns(mut text: &str) -> Option<Vec<String>> {
    let mut patterns = Vec::new();
    while !text.trim_start().is_empty() {
        text = text.trim_start();
        if let Some(rest) = text.strip_prefix('`') {
            let (pattern, rest) = rest.split_once('`')?;
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
            patterns.push(pattern);
        } else {
            let end = text.find(char::is_whitespace).unwrap_or(text.len());
            patterns.push(text[..end].to_string());
            text = &text[end..];
        }
    }
    Some(patterns)
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
        if let Some(expr) = line.strip_prefix("//go:build ") {
            if modern.replace(expr).is_some() {
                return false;
            }
        } else if legacy_allowed {
            if let Some(expr) = line.strip_prefix("// +build ") {
                legacy.push(expr);
            }
        }
        if !line.is_empty() && !line.starts_with("//") {
            break;
        }
    }
    if let Some(expr) = modern {
        return constraint(expr) == Some(false);
    }
    legacy[..legacy_end].iter().any(|line| {
        // Legacy constraints: whitespace OR, commas AND.
        !line
            .split_whitespace()
            .any(|term| term.split(',').all(|tag| tag != "ignore"))
    })
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
}
