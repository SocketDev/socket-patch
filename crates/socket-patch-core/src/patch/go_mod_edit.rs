//! Read / write `<project_root>/go.mod` for the project-local Go
//! `replace`-redirect backend.
//!
//! Mirrors the contract of [`crate::patch::cargo_config`] (the cargo
//! `[patch.crates-io]` analog), but `go.mod` is **not** TOML, so there is no
//! `toml_edit` to lean on. This is a small, line/block-aware editor that
//! preserves the rest of the file (comments, `require`/`exclude`/`retract`
//! directives, the user's own `replace`s) and only touches socket-owned
//! `replace` directives.
//!
//! ## Ownership model (no sidecar manifest)
//! A `replace` directive is *socket-owned* iff its right-hand side is a
//! filesystem path under `.socket/go-patches/`. A module-to-module replacement
//! (`=> example.com/fork v1.2.3`) or a path pointing anywhere else is
//! user-authored and is never modified or removed. This is the entire
//! ownership signal; there is no `managed.json`.
//!
//! ## Why `replace` (validated empirically — see project memory)
//! A local-path `replace` target is **not** `go.sum` content-verified, so
//! patched bytes build cleanly under the default `-mod=readonly`. The directive
//! is keyed by *module + version*: a stale pin (the graph resolved a different
//! version) is silently ignored and the build links the UNPATCHED module —
//! hence the version cross-check in [`crate::patch::go_redirect`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::fs;

/// Project-relative directory holding patched module copies. A `replace` whose
/// target path is under this prefix is how socket ownership is recognised.
pub const GO_PATCHES_DIR: &str = ".socket/go-patches";

/// The expected (project-root-relative) `replace` target path for a module
/// copy. Always `./`-prefixed and forward-slashed: Go treats a replacement
/// target as a *filesystem path* only when it begins with `./`, `../`, or `/`
/// (otherwise it is parsed as a module path), and accepts forward slashes on
/// every platform.
pub fn expected_replace_path(module: &str, version: &str) -> String {
    format!("./{GO_PATCHES_DIR}/{module}@{version}")
}

/// One parsed `replace` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceEntry {
    /// Left-hand-side module path.
    pub module: String,
    /// Left-hand-side version, or `None` for a version-less `replace M => ...`.
    pub version: Option<String>,
    /// Right-hand-side path, iff the replacement is a filesystem path
    /// (`None` for a module-to-module `=> mod ver` replacement).
    pub path: Option<String>,
    /// True iff `path` is under `.socket/go-patches/`.
    pub socket_owned: bool,
}

// ── public async API ─────────────────────────────────────────────────────────

/// Read all `replace` directives. Read-only; a missing/unreadable `go.mod`
/// yields an empty vec (callers treat that as "no managed entries").
pub async fn read_replace_entries(project_root: &Path) -> Vec<ReplaceEntry> {
    match fs::read_to_string(go_mod_path(project_root)).await {
        Ok(content) => parse_replace_entries(&content),
        Err(_) => Vec::new(),
    }
}

/// Resolved versions from the `require` directives, keyed by module path. Used
/// for the version cross-check (a socket `replace` pinned to a version the
/// module graph no longer selects is silently unused). `None` ⇒ no/unreadable
/// `go.mod` ⇒ skip the check (mirrors cargo's `read_locked_versions`).
pub async fn read_required_versions(project_root: &Path) -> Option<HashMap<String, String>> {
    let content = fs::read_to_string(go_mod_path(project_root)).await.ok()?;
    Some(parse_required_versions(&content))
}

/// Upsert a socket-owned `replace <module> <version> => ./.socket/go-patches/<module>@<version>`.
/// Idempotent. Returns whether the file changed. Errors (without writing) if a
/// `go.mod` is absent, or if a *user-authored* `replace` already pins the same
/// `module`+`version` (a duplicate would make `go.mod` invalid).
pub async fn ensure_replace_entry(
    project_root: &Path,
    module: &str,
    version: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_go_mod(project_root, dry_run, |c| {
        upsert_replace_entry(c, module, version)
    })
    .await
}

/// Remove the *socket-owned* `replace` directive(s) for `module` (pruning an
/// emptied `replace ( … )` block). A user-authored or absent entry is a no-op.
/// Returns whether the file changed.
pub async fn drop_replace_entry(
    project_root: &Path,
    module: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_go_mod(project_root, dry_run, |c| remove_replace_entry(c, module)).await
}

// ── file resolution + read/write ──────────────────────────────────────────────

fn go_mod_path(project_root: &Path) -> PathBuf {
    project_root.join("go.mod")
}

/// Apply a pure transform to `go.mod`, writing only if it changed and
/// `!dry_run`. Unlike `.cargo/config.toml`, a `go.mod` is **required** to exist
/// (it defines the module): a missing file is an error, not an empty start.
async fn edit_go_mod(
    project_root: &Path,
    dry_run: bool,
    transform: impl FnOnce(&str) -> Result<Option<String>, String>,
) -> Result<bool, String> {
    let path = go_mod_path(project_root);
    let content = fs::read_to_string(&path)
        .await
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    match transform(&content)? {
        None => Ok(false),
        Some(new) => {
            if !dry_run {
                fs::write(&path, new)
                    .await
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
            }
            Ok(true)
        }
    }
}

// ── parsing ────────────────────────────────────────────────────────────────

/// Strip a trailing `// …` line comment. Module paths and our `./…` targets
/// never contain `//`, so the first occurrence is the comment.
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// True if a replacement RHS token is a filesystem path (vs a module path).
/// Go's rule: a path begins with `./`, `../`, `/`, or a Windows drive/`\`.
fn rhs_is_path(tok: &str) -> bool {
    tok.starts_with("./")
        || tok.starts_with("../")
        || tok.starts_with('/')
        || tok.starts_with(".\\")
        || tok.starts_with("..\\")
        || (tok.len() >= 2 && tok.as_bytes()[1] == b':') // C:\…
}

/// True if a `replace` target path lies under `.socket/go-patches/`.
fn path_is_socket_owned(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    let norm = norm.strip_prefix("./").unwrap_or(&norm);
    let prefix = format!("{GO_PATCHES_DIR}/");
    norm.starts_with(&prefix) || norm.contains(&format!("/{prefix}"))
}

/// Parse the `module path => target [version]` body of a replace directive
/// (the part after the `replace` keyword, or a line inside a `replace ( … )`
/// block). Returns `None` if there is no `=>` (not a replace body).
fn parse_replace_body(body: &str) -> Option<ReplaceEntry> {
    let (lhs, rhs) = body.split_once("=>")?;
    let lhs: Vec<&str> = lhs.split_whitespace().collect();
    let rhs: Vec<&str> = rhs.split_whitespace().collect();
    let module = (*lhs.first()?).to_string();
    let version = lhs.get(1).map(|s| s.to_string());
    let first_rhs = rhs.first()?;
    let (path, socket_owned) = if rhs_is_path(first_rhs) {
        let p = (*first_rhs).to_string();
        let owned = path_is_socket_owned(&p);
        (Some(p), owned)
    } else {
        (None, false) // module-to-module replacement
    };
    Some(ReplaceEntry {
        module,
        version,
        path,
        socket_owned,
    })
}

/// Parse every `replace` directive (single-line and block forms).
pub fn parse_replace_entries(content: &str) -> Vec<ReplaceEntry> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            if let Some(e) = parse_replace_body(line) {
                out.push(e);
            }
            continue;
        }
        if let Some(rest) = directive_block_open(line, "replace") {
            if rest {
                in_block = true;
            }
            continue;
        }
        if let Some(body) = line.strip_prefix("replace ") {
            if let Some(e) = parse_replace_body(body) {
                out.push(e);
            }
        }
    }
    out
}

/// Parse `require` directives into `module -> version` (last wins; the module
/// graph selects one version per module path).
pub fn parse_required_versions(content: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut in_block = false;
    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            insert_require(&mut out, line);
            continue;
        }
        if let Some(rest) = directive_block_open(line, "require") {
            if rest {
                in_block = true;
            }
            continue;
        }
        if let Some(body) = line.strip_prefix("require ") {
            insert_require(&mut out, body);
        }
    }
    out
}

fn insert_require(out: &mut HashMap<String, String>, body: &str) {
    let toks: Vec<&str> = body.split_whitespace().collect();
    if let (Some(m), Some(v)) = (toks.first(), toks.get(1)) {
        out.insert((*m).to_string(), (*v).to_string());
    }
}

/// For a directive keyword (`replace`/`require`), classify a line:
/// * `Some(true)`  — opens a `keyword (` block,
/// * `Some(false)` — a bare `keyword (` … `)` is not this (e.g. `keyword (` only
///   matches the open form); returns `Some(false)` for `keyword ()` empties,
/// * `None`        — the line is not a block opener for this keyword.
fn directive_block_open(line: &str, keyword: &str) -> Option<bool> {
    // `replace (`  /  `replace(`
    let rest = line.strip_prefix(keyword)?;
    let rest = rest.trim_start();
    if rest == "(" {
        return Some(true);
    }
    if rest == "()" {
        return Some(false); // empty inline block — nothing inside
    }
    None
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// Upsert a socket-owned `replace module version => ./…@version`.
fn upsert_replace_entry(
    content: &str,
    module: &str,
    version: &str,
) -> Result<Option<String>, String> {
    let want_path = expected_replace_path(module, version);
    let want_line = format!("replace {module} {version} => {want_path}");

    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();

    // Locate an existing socket-owned replace line for `module`, and detect a
    // conflicting user-authored replace pinning the same module+version.
    let mut socket_line: Option<usize> = None;
    let mut in_block = false;
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            inspect_existing(line, module, version, &want_path, i, &mut socket_line)?;
            continue;
        }
        if let Some(opened) = directive_block_open(line, "replace") {
            in_block = opened;
            continue;
        }
        if let Some(body) = line.strip_prefix("replace ") {
            inspect_existing(body, module, version, &want_path, i, &mut socket_line)?;
        }
    }

    if let Some(idx) = socket_line {
        // Rewrite the existing socket-owned line in place, preserving whether it
        // was a block member (`\tmodule … => …`) or a single-line `replace …`.
        let raw = &lines[idx];
        let indent: String = raw.chars().take_while(|c| c.is_whitespace()).collect();
        let is_block_member = !strip_comment(raw).trim_start().starts_with("replace ");
        let new = if is_block_member {
            format!("{indent}{module} {version} => {want_path}")
        } else {
            format!("{indent}{want_line}")
        };
        if lines[idx] == new {
            return Ok(None);
        }
        lines[idx] = new;
        return Ok(Some(join_preserving_trailing_newline(&lines, content)));
    }

    // No socket-owned entry yet → append a single-line directive.
    let mut body = content.to_string();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&want_line);
    body.push('\n');
    Ok(Some(body))
}

/// Inspect an existing replace `body` (after `replace `, or a block line) for
/// the target `module`: record a socket-owned match (to refresh) or reject a
/// user-authored same-version pin (a duplicate would be invalid go.mod).
fn inspect_existing(
    body: &str,
    module: &str,
    version: &str,
    want_path: &str,
    line_idx: usize,
    socket_line: &mut Option<usize>,
) -> Result<(), String> {
    let Some(e) = parse_replace_body(body) else {
        return Ok(());
    };
    if e.module != module {
        return Ok(());
    }
    if e.socket_owned {
        // Our entry (any version): refresh it. Prefer the first one found.
        if socket_line.is_none() {
            *socket_line = Some(line_idx);
        }
        return Ok(());
    }
    // A user-authored replace for the same module. Only the *same version*
    // (or a version-less catch-all) collides with the directive we want to add.
    let same_version = e.version.as_deref() == Some(version) || e.version.is_none();
    if same_version && e.path.as_deref() != Some(want_path) {
        return Err(format!(
            "go.mod already has a user-authored `replace {module}{}` => {}; \
             refusing to overwrite",
            e.version
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default(),
            e.path.as_deref().unwrap_or("<module>")
        ));
    }
    Ok(())
}

/// Remove socket-owned `replace` directive(s) for `module`, pruning an emptied
/// `replace ( … )` block.
fn remove_replace_entry(content: &str, module: &str) -> Result<Option<String>, String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut keep = vec![true; lines.len()];

    // Track block extents so we can prune a block that becomes empty.
    let mut i = 0;
    let mut changed = false;
    while i < lines.len() {
        let line = strip_comment(lines[i]).trim();
        if directive_block_open(line, "replace") == Some(true) {
            // Block spans [i, close]; mark socket-owned members for removal.
            let open = i;
            let mut close = i;
            let mut members_total = 0usize;
            let mut members_removed = 0usize;
            let mut j = i + 1;
            while j < lines.len() {
                let inner = strip_comment(lines[j]).trim();
                if inner == ")" {
                    close = j;
                    break;
                }
                if !inner.is_empty() {
                    members_total += 1;
                    if let Some(e) = parse_replace_body(inner) {
                        if e.module == module && e.socket_owned {
                            keep[j] = false;
                            members_removed += 1;
                            changed = true;
                        }
                    }
                }
                close = j;
                j += 1;
            }
            // If every member was removed, drop the whole block (open + close).
            if members_total > 0 && members_removed == members_total {
                keep[open] = false;
                if close < lines.len() {
                    keep[close] = false;
                }
            }
            i = close + 1;
            continue;
        }
        if let Some(body) = line.strip_prefix("replace ") {
            if let Some(e) = parse_replace_body(body) {
                if e.module == module && e.socket_owned {
                    keep[i] = false;
                    changed = true;
                }
            }
        }
        i += 1;
    }

    if !changed {
        return Ok(None);
    }

    let kept: Vec<String> = lines
        .iter()
        .zip(keep)
        .filter(|(_, k)| *k)
        .map(|(l, _)| l.to_string())
        .collect();
    Ok(Some(join_preserving_trailing_newline(&kept, content)))
}

/// Re-join lines, restoring a trailing newline iff the original had one.
fn join_preserving_trailing_newline(lines: &[String], original: &str) -> String {
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── path ownership ───────────────────────────────────────────────
    #[test]
    fn test_is_socket_owned() {
        assert!(path_is_socket_owned("./.socket/go-patches/github.com/x/y@v1.0.0"));
        assert!(path_is_socket_owned(".socket/go-patches/x@v1.0.0"));
        assert!(path_is_socket_owned("sub/.socket/go-patches/x@v1.0.0"));
        assert!(!path_is_socket_owned("../fork"));
        assert!(!path_is_socket_owned("./vendor/x"));
        assert!(!path_is_socket_owned("/abs/.socketX/go-patches/x"));
    }

    #[test]
    fn test_rhs_is_path() {
        assert!(rhs_is_path("./local"));
        assert!(rhs_is_path("../local"));
        assert!(rhs_is_path("/abs"));
        assert!(!rhs_is_path("example.com/mod"));
        assert!(!rhs_is_path("github.com/x/y"));
    }

    #[test]
    fn test_expected_path() {
        assert_eq!(
            expected_replace_path("github.com/foo/bar", "v1.4.2"),
            "./.socket/go-patches/github.com/foo/bar@v1.4.2"
        );
    }

    // ── parse ────────────────────────────────────────────────────────
    #[test]
    fn test_parse_single_and_block() {
        let gomod = "\
module example.com/app

go 1.21

require (
\tgithub.com/foo/bar v1.4.2
\texample.com/baz v2.0.0 // indirect
)

replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2

replace (
\texample.com/baz v2.0.0 => ../local-baz
\texample.com/qux => example.com/qux-fork v1.1.0
)
";
        let entries = parse_replace_entries(gomod);
        assert_eq!(entries.len(), 3);
        let bar = entries.iter().find(|e| e.module == "github.com/foo/bar").unwrap();
        assert!(bar.socket_owned);
        assert_eq!(bar.version.as_deref(), Some("v1.4.2"));
        let baz = entries.iter().find(|e| e.module == "example.com/baz").unwrap();
        assert!(!baz.socket_owned);
        assert_eq!(baz.path.as_deref(), Some("../local-baz"));
        let qux = entries.iter().find(|e| e.module == "example.com/qux").unwrap();
        assert!(!qux.socket_owned);
        assert_eq!(qux.path, None, "module-to-module replacement has no path");

        let req = parse_required_versions(gomod);
        assert_eq!(req.get("github.com/foo/bar").map(String::as_str), Some("v1.4.2"));
        assert_eq!(req.get("example.com/baz").map(String::as_str), Some("v2.0.0"));
    }

    #[test]
    fn test_parse_require_single() {
        let gomod = "module m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n";
        let req = parse_required_versions(gomod);
        assert_eq!(req.get("github.com/x/y").map(String::as_str), Some("v1.0.0"));
    }

    // ── upsert ───────────────────────────────────────────────────────
    #[test]
    fn test_upsert_appends_single_line() {
        let gomod = "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2")
            .unwrap()
            .unwrap();
        assert!(out.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
        // Original content preserved.
        assert!(out.contains("require github.com/foo/bar v1.4.2"));
        assert!(out.ends_with('\n'));
        // Idempotent.
        assert!(upsert_replace_entry(&out, "github.com/foo/bar", "v1.4.2")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_version_bump_single_line() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.5.0")
            .unwrap()
            .unwrap();
        assert!(out.contains(
            "replace github.com/foo/bar v1.5.0 => ./.socket/go-patches/github.com/foo/bar@v1.5.0"
        ));
        assert!(!out.contains("bar@v1.4.2"), "old version line gone");
        // Exactly one replace for the module.
        assert_eq!(parse_replace_entries(&out).iter().filter(|e| e.module == "github.com/foo/bar").count(), 1);
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_inside_block() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n)\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.5.0")
            .unwrap()
            .unwrap();
        // Still a block member (indented, no `replace ` keyword), version bumped.
        assert!(out.contains("\tgithub.com/foo/bar v1.5.0 => ./.socket/go-patches/github.com/foo/bar@v1.5.0"));
        assert!(out.contains("replace ("));
    }

    #[test]
    fn test_upsert_refuses_user_authored_same_version() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ../fork\n";
        assert!(upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2").is_err());
    }

    #[test]
    fn test_upsert_allows_user_replace_at_different_version() {
        // User pins a DIFFERENT version → no conflict; ours is added alongside.
        let gomod = "module m\n\nreplace github.com/foo/bar v1.0.0 => ../fork\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2")
            .unwrap()
            .unwrap();
        assert!(out.contains("replace github.com/foo/bar v1.0.0 => ../fork"));
        assert!(out.contains("replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"));
    }

    #[test]
    fn test_upsert_refuses_versionless_user_catchall() {
        let gomod = "module m\n\nreplace github.com/foo/bar => ../fork\n";
        assert!(upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2").is_err());
    }

    #[test]
    fn test_upsert_allows_versionless_catchall_for_different_module() {
        // A user's version-less catch-all for a DIFFERENT module must not block
        // (or be touched by) our replace for github.com/foo/bar.
        let gomod = "module m\n\nreplace example.com/other => ../other-fork\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2")
            .unwrap()
            .unwrap();
        assert!(out.contains("replace example.com/other => ../other-fork"), "user catch-all preserved");
        assert!(out.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
        let entries = parse_replace_entries(&out);
        assert!(entries.iter().any(|e| e.module == "example.com/other" && !e.socket_owned));
        assert!(entries.iter().any(|e| e.module == "github.com/foo/bar" && e.socket_owned));
    }

    // ── remove ───────────────────────────────────────────────────────
    #[test]
    fn test_remove_single_line() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar")
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(out.contains("module m"));
    }

    #[test]
    fn test_remove_block_member_prunes_empty_block() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n)\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar")
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(!out.contains("replace ("), "emptied block pruned");
    }

    #[test]
    fn test_remove_block_keeps_other_members() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n\texample.com/baz v2.0.0 => ../local-baz\n)\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar")
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(out.contains("replace ("), "block kept (still has a member)");
        assert!(out.contains("example.com/baz v2.0.0 => ../local-baz"));
    }

    #[test]
    fn test_remove_leaves_user_replace() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ../fork\n";
        assert!(remove_replace_entry(gomod, "github.com/foo/bar").unwrap().is_none());
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(remove_replace_entry("module m\n\ngo 1.21\n", "github.com/foo/bar")
            .unwrap()
            .is_none());
    }

    // ── async round-trip ─────────────────────────────────────────────
    #[tokio::test]
    async fn test_ensure_then_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();

        assert!(ensure_replace_entry(dir.path(), "github.com/foo/bar", "v1.4.2", false)
            .await
            .unwrap());
        let entries = read_replace_entries(dir.path()).await;
        let bar = entries.iter().find(|e| e.module == "github.com/foo/bar").unwrap();
        assert!(bar.socket_owned);
        assert_eq!(
            bar.path.as_deref(),
            Some("./.socket/go-patches/github.com/foo/bar@v1.4.2")
        );
        // Required-version cross-check source.
        let req = read_required_versions(dir.path()).await.unwrap();
        assert_eq!(req.get("github.com/foo/bar").map(String::as_str), Some("v1.4.2"));

        // Idempotent on disk.
        assert!(!ensure_replace_entry(dir.path(), "github.com/foo/bar", "v1.4.2", false)
            .await
            .unwrap());
        // Drop.
        assert!(drop_replace_entry(dir.path(), "github.com/foo/bar", false)
            .await
            .unwrap());
        assert!(read_replace_entries(dir.path()).await.is_empty());
    }

    #[tokio::test]
    async fn test_ensure_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let body = "module m\n\ngo 1.21\n";
        fs::write(dir.path().join("go.mod"), body).await.unwrap();
        let changed = ensure_replace_entry(dir.path(), "github.com/foo/bar", "v1.4.2", true)
            .await
            .unwrap();
        assert!(changed, "dry-run reports the change it would make");
        assert_eq!(
            fs::read_to_string(dir.path().join("go.mod")).await.unwrap(),
            body,
            "dry-run must not write"
        );
    }

    #[tokio::test]
    async fn test_ensure_missing_go_mod_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_replace_entry(dir.path(), "github.com/foo/bar", "v1.4.2", false)
            .await
            .is_err());
    }
}
