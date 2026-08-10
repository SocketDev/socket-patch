//! Read / write `<project_root>/go.mod` for the project-local Go
//! `replace`-redirect backend.
//!
//! `go.mod` is **not** TOML, so there is no `toml_edit` to lean on. This is a
//! small, line/block-aware editor that
//! preserves the rest of the file (comments, `require`/`exclude`/`retract`
//! directives, the user's own `replace`s) and only touches socket-owned
//! `replace` directives.
//!
//! ## Ownership model (no sidecar manifest)
//! A `replace` directive is *socket-owned* iff its right-hand side is a
//! filesystem path under one of the two socket-managed prefixes:
//! `.socket/go-patches/` (the `apply` redirect backend, [`ReplaceOwner::GoPatches`])
//! or `.socket/vendor/golang/` (the `vendor` backend, [`ReplaceOwner::Vendor`]).
//! A module-to-module replacement (`=> example.com/fork v1.2.3`) or a path
//! pointing anywhere else is user-authored and is never modified or removed.
//! The path prefix is the entire ownership signal; there is no `managed.json`.
//!
//! At most one socket-owned `replace` exists per module: `ensure_replace_entry`
//! rewrites an existing socket-owned line of EITHER owner in place (this
//! cross-owner upsert is how `vendor` takes over an `apply` redirect), while
//! `drop_replace_entry` removes only the requested owner's directives (so
//! `apply`'s reconcile can never prune a vendored module and vice versa).
//! Policy about *when* an owner may take over lives in the callers.
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

/// Project-relative directory holding `apply`'s patched module copies. A
/// `replace` whose target path is under this prefix is owned by
/// [`ReplaceOwner::GoPatches`].
pub const GO_PATCHES_DIR: &str = ".socket/go-patches";

/// Project-relative directory holding `vendor`'s committed module copies
/// (`<GO_VENDOR_DIR>/<patch-uuid>/<module>@<version>`). A `replace` whose
/// target path is under this prefix is owned by [`ReplaceOwner::Vendor`].
const GO_VENDOR_DIR: &str = ".socket/vendor/golang";

/// Which socket-managed backend owns a `replace` directive, classified by the
/// directive's target-path prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOwner {
    /// `apply`'s machine-local redirect copies under `.socket/go-patches/`.
    GoPatches,
    /// `vendor`'s committed copies under `.socket/vendor/golang/<uuid>/`.
    Vendor,
}

/// Classify a `replace` target path: which socket backend owns it, or `None`
/// for a user-authored path. The two prefixes don't overlap, but `Vendor` is
/// tested first to keep the intent explicit (`.socket/vendor/golang/` is more
/// specific than a hypothetical future `.socket/` catch-all).
pub(crate) fn detect_owner(path: &str) -> Option<ReplaceOwner> {
    let norm = path.replace('\\', "/");
    let norm = norm.strip_prefix("./").unwrap_or(&norm);
    for (owner, dir) in [
        (ReplaceOwner::Vendor, GO_VENDOR_DIR),
        (ReplaceOwner::GoPatches, GO_PATCHES_DIR),
    ] {
        let prefix = format!("{dir}/");
        if norm.starts_with(&prefix) || norm.contains(&format!("/{prefix}")) {
            return Some(owner);
        }
    }
    None
}

/// The (project-root-relative) `replace` target path for a copy that lives at
/// `<base_rel>/<module>@<version>`. Always `./`-prefixed and forward-slashed:
/// Go treats a replacement target as a *filesystem path* only when it begins
/// with `./`, `../`, or `/` (otherwise it is parsed as a module path), and
/// accepts forward slashes on every platform.
pub fn replace_target_path(base_rel: &str, module: &str, version: &str) -> String {
    format!("./{base_rel}/{module}@{version}")
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
    /// Which socket backend owns this directive (`None` = user-authored).
    pub owner: Option<ReplaceOwner>,
}

impl ReplaceEntry {
    /// True iff the directive is socket-owned (either backend).
    pub fn socket_owned(&self) -> bool {
        self.owner.is_some()
    }
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

/// Upsert a socket-owned `replace <module> <version> => ./<base_rel>/<module>@<version>`,
/// where `base_rel` is the project-relative copy base (e.g. [`GO_PATCHES_DIR`],
/// or `<GO_VENDOR_DIR>/<uuid>` for vendor). Idempotent. An existing
/// socket-owned line for `module` — of EITHER owner — is rewritten in place
/// (the cross-owner case is `vendor` taking over an `apply` redirect). Returns
/// whether the file changed. Errors (without writing) if `go.mod` is absent,
/// or if a *user-authored* `replace` already pins the same `module`+`version`
/// (a duplicate would make `go.mod` invalid).
pub async fn ensure_replace_entry(
    project_root: &Path,
    module: &str,
    version: &str,
    base_rel: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_go_mod(project_root, dry_run, |c| {
        upsert_replace_entry(c, module, version, base_rel)
    })
    .await
}

/// Remove the `replace` directive(s) for `module` owned by `owner` (pruning an
/// emptied `replace ( … )` block). A user-authored entry, the OTHER owner's
/// entry, or an absent entry is a no-op — so `apply`'s reconcile can never
/// drop a vendored module's directive and vice versa. Returns whether the file
/// changed.
pub async fn drop_replace_entry(
    project_root: &Path,
    module: &str,
    owner: ReplaceOwner,
    dry_run: bool,
) -> Result<bool, String> {
    edit_go_mod(project_root, dry_run, |c| {
        remove_replace_entry(c, module, owner)
    })
    .await
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
                // go.mod is user-owned (their own require/replace directives and
                // comments live alongside our socket `replace`) — a torn write
                // would corrupt a manifest that no longer builds, and the swap
                // must keep the file's permission bits.
                crate::utils::fs::atomic_write_bytes_preserving_mode(&path, new.as_bytes())
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

/// Walk every directive body for `keyword` — the single-line form
/// (`keyword <body>`) and the members of a `keyword ( … )` block — calling
/// `f(line_index, body)` with the comment stripped and whitespace trimmed.
fn for_each_directive_body(
    content: &str,
    keyword: &str,
    mut f: impl FnMut(usize, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut in_block = false;
    for (i, raw) in content.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
            } else {
                f(i, line)?;
            }
        } else if let Some(after) = line.strip_prefix(keyword) {
            let rest = after.trim_start();
            match rest {
                "(" => in_block = true,
                "()" => {} // empty inline block — nothing inside
                _ => {
                    // Go's lexer separates tokens on ANY whitespace, so
                    // `replace\tmod …` is as valid as `replace mod …` (and
                    // `replaceX` is a different word entirely).
                    if after.starts_with(char::is_whitespace) && !rest.is_empty() {
                        f(i, rest)?;
                    }
                }
            }
        }
    }
    Ok(())
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
    let (path, owner) = if rhs_is_path(first_rhs) {
        let p = (*first_rhs).to_string();
        let owner = detect_owner(&p);
        (Some(p), owner)
    } else {
        (None, None) // module-to-module replacement
    };
    Some(ReplaceEntry {
        module,
        version,
        path,
        owner,
    })
}

/// Parse every `replace` directive (single-line and block forms).
fn parse_replace_entries(content: &str) -> Vec<ReplaceEntry> {
    let mut out = Vec::new();
    let _ = for_each_directive_body(content, "replace", |_, body| {
        out.extend(parse_replace_body(body));
        Ok(())
    });
    out
}

/// Parse `require` directives into `module -> version` (last wins; the module
/// graph selects one version per module path).
fn parse_required_versions(content: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let _ = for_each_directive_body(content, "require", |_, body| {
        let mut toks = body.split_whitespace();
        if let (Some(m), Some(v)) = (toks.next(), toks.next()) {
            out.insert(m.to_string(), v.to_string());
        }
        Ok(())
    });
    out
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// Upsert a socket-owned `replace module version => ./<base_rel>/…@version`.
fn upsert_replace_entry(
    content: &str,
    module: &str,
    version: &str,
    base_rel: &str,
) -> Result<Option<String>, String> {
    let want_path = replace_target_path(base_rel, module, version);
    let want_line = format!("replace {module} {version} => {want_path}");

    // Locate an existing socket-owned replace line for `module`, and detect a
    // conflicting user-authored replace pinning the same module+version.
    let mut socket_line: Option<usize> = None;
    for_each_directive_body(content, "replace", |i, body| {
        inspect_existing(body, module, version, &want_path, i, &mut socket_line)
    })?;

    if let Some(idx) = socket_line {
        // Rewrite the existing socket-owned line in place, preserving whether it
        // was a block member (`\tmodule … => …`) or a single-line `replace …`.
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let raw = &lines[idx];
        let indent: String = raw.chars().take_while(|c| c.is_whitespace()).collect();
        let is_block_member = !strip_comment(raw)
            .trim_start()
            .strip_prefix("replace")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace));
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
    if e.socket_owned() {
        // A socket-owned entry (any version, EITHER owner): refresh it in
        // place. The cross-owner rewrite is the takeover mechanism — a single
        // atomic go.mod write repoints e.g. a go-patches redirect at the
        // vendor copy with no remove+add window.
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

/// Remove `owner`'s `replace` directive(s) for `module`, pruning an emptied
/// `replace ( … )` block. The other owner's directives are left untouched.
fn remove_replace_entry(
    content: &str,
    module: &str,
    owner: ReplaceOwner,
) -> Result<Option<String>, String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut keep = vec![true; lines.len()];

    // Track block extents so we can prune a block that becomes empty.
    let mut i = 0;
    let mut changed = false;
    while i < lines.len() {
        let line = strip_comment(lines[i]).trim();
        if line.strip_prefix("replace").map(str::trim_start) == Some("(") {
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
                        if e.module == module && e.owner == Some(owner) {
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
        if let Some(after) = line.strip_prefix("replace") {
            if after.starts_with(char::is_whitespace) {
                if let Some(e) = parse_replace_body(after) {
                    if e.module == module && e.owner == Some(owner) {
                        keep[i] = false;
                        changed = true;
                    }
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
    fn test_detect_owner() {
        use ReplaceOwner::*;
        assert_eq!(
            detect_owner("./.socket/go-patches/github.com/x/y@v1.0.0"),
            Some(GoPatches)
        );
        assert_eq!(detect_owner(".socket/go-patches/x@v1.0.0"), Some(GoPatches));
        assert_eq!(
            detect_owner("sub/.socket/go-patches/x@v1.0.0"),
            Some(GoPatches)
        );
        assert_eq!(
            detect_owner("./.socket/vendor/golang/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/github.com/x/y@v1.0.0"),
            Some(Vendor)
        );
        assert_eq!(
            detect_owner(".socket/vendor/golang/u/x@v1.0.0"),
            Some(Vendor)
        );
        assert_eq!(detect_owner("../fork"), None);
        assert_eq!(detect_owner("./vendor/x"), None);
        assert_eq!(detect_owner("/abs/.socketX/go-patches/x"), None);
        // The npm/composer vendor dirs are NOT golang-owned replace targets.
        assert_eq!(detect_owner(".socket/vendor/npm/u/x.tgz"), None);
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
    fn test_replace_target_path() {
        assert_eq!(
            replace_target_path(GO_PATCHES_DIR, "github.com/foo/bar", "v1.4.2"),
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
        let bar = entries
            .iter()
            .find(|e| e.module == "github.com/foo/bar")
            .unwrap();
        assert!(bar.socket_owned());
        assert_eq!(bar.version.as_deref(), Some("v1.4.2"));
        let baz = entries
            .iter()
            .find(|e| e.module == "example.com/baz")
            .unwrap();
        assert!(!baz.socket_owned());
        assert_eq!(baz.path.as_deref(), Some("../local-baz"));
        let qux = entries
            .iter()
            .find(|e| e.module == "example.com/qux")
            .unwrap();
        assert!(!qux.socket_owned());
        assert_eq!(qux.path, None, "module-to-module replacement has no path");

        let req = parse_required_versions(gomod);
        assert_eq!(
            req.get("github.com/foo/bar").map(String::as_str),
            Some("v1.4.2")
        );
        assert_eq!(
            req.get("example.com/baz").map(String::as_str),
            Some("v2.0.0")
        );
    }

    #[test]
    fn test_parse_require_single() {
        let gomod = "module m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n";
        let req = parse_required_versions(gomod);
        assert_eq!(
            req.get("github.com/x/y").map(String::as_str),
            Some("v1.0.0")
        );
    }

    // ── upsert ───────────────────────────────────────────────────────
    #[test]
    fn test_upsert_appends_single_line() {
        let gomod = "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR)
            .unwrap()
            .unwrap();
        assert!(out.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
        // Original content preserved.
        assert!(out.contains("require github.com/foo/bar v1.4.2"));
        assert!(out.ends_with('\n'));
        // Idempotent.
        assert!(
            upsert_replace_entry(&out, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_version_bump_single_line() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.5.0", GO_PATCHES_DIR)
            .unwrap()
            .unwrap();
        assert!(out.contains(
            "replace github.com/foo/bar v1.5.0 => ./.socket/go-patches/github.com/foo/bar@v1.5.0"
        ));
        assert!(!out.contains("bar@v1.4.2"), "old version line gone");
        // Exactly one replace for the module.
        assert_eq!(
            parse_replace_entries(&out)
                .iter()
                .filter(|e| e.module == "github.com/foo/bar")
                .count(),
            1
        );
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_inside_block() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n)\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.5.0", GO_PATCHES_DIR)
            .unwrap()
            .unwrap();
        // Still a block member (indented, no `replace ` keyword), version bumped.
        assert!(out.contains(
            "\tgithub.com/foo/bar v1.5.0 => ./.socket/go-patches/github.com/foo/bar@v1.5.0"
        ));
        assert!(out.contains("replace ("));
    }

    #[test]
    fn test_upsert_refuses_user_authored_same_version() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ../fork\n";
        assert!(
            upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR).is_err()
        );
    }

    #[test]
    fn test_upsert_allows_user_replace_at_different_version() {
        // User pins a DIFFERENT version → no conflict; ours is added alongside.
        let gomod = "module m\n\nreplace github.com/foo/bar v1.0.0 => ../fork\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR)
            .unwrap()
            .unwrap();
        assert!(out.contains("replace github.com/foo/bar v1.0.0 => ../fork"));
        assert!(out.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
    }

    #[test]
    fn test_upsert_refuses_versionless_user_catchall() {
        let gomod = "module m\n\nreplace github.com/foo/bar => ../fork\n";
        assert!(
            upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR).is_err()
        );
    }

    #[test]
    fn test_upsert_allows_versionless_catchall_for_different_module() {
        // A user's version-less catch-all for a DIFFERENT module must not block
        // (or be touched by) our replace for github.com/foo/bar.
        let gomod = "module m\n\nreplace example.com/other => ../other-fork\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR)
            .unwrap()
            .unwrap();
        assert!(
            out.contains("replace example.com/other => ../other-fork"),
            "user catch-all preserved"
        );
        assert!(out.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
        let entries = parse_replace_entries(&out);
        assert!(entries
            .iter()
            .any(|e| e.module == "example.com/other" && !e.socket_owned()));
        assert!(entries
            .iter()
            .any(|e| e.module == "github.com/foo/bar" && e.socket_owned()));
    }

    // ── cross-owner takeover + owner filtering ───────────────────────
    const VENDOR_BASE: &str = ".socket/vendor/golang/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    /// Vendor takes over an apply (go-patches) redirect: the SAME socket-owned
    /// line is rewritten in place to the vendor path — never a remove+add pair,
    /// and never a second directive for the module.
    #[test]
    fn test_upsert_cross_owner_takeover() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", VENDOR_BASE)
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"), "old owner's path gone");
        assert!(out.contains(&format!(
            "replace github.com/foo/bar v1.4.2 => ./{VENDOR_BASE}/github.com/foo/bar@v1.4.2"
        )));
        let entries = parse_replace_entries(&out);
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.module == "github.com/foo/bar")
                .count(),
            1,
            "exactly one directive for the module"
        );
        assert_eq!(entries[0].owner, Some(ReplaceOwner::Vendor));
    }

    /// Dropping one owner's directive leaves the other owner's (and the
    /// user's) directives untouched — reconcile non-interference.
    #[test]
    fn test_remove_is_owner_filtered() {
        let gomod = format!(
            "module m\n\n\
             replace github.com/a/a v1.0.0 => ./.socket/go-patches/github.com/a/a@v1.0.0\n\
             replace github.com/b/b v2.0.0 => ./{VENDOR_BASE}/github.com/b/b@v2.0.0\n\
             replace github.com/c/c v3.0.0 => ../fork\n"
        );
        // GoPatches drop must not touch the vendor directive…
        assert!(
            remove_replace_entry(&gomod, "github.com/b/b", ReplaceOwner::GoPatches)
                .unwrap()
                .is_none(),
            "go-patches drop of a vendor-owned module is a no-op"
        );
        // …and the vendor drop must not touch the go-patches directive.
        assert!(
            remove_replace_entry(&gomod, "github.com/a/a", ReplaceOwner::Vendor)
                .unwrap()
                .is_none(),
            "vendor drop of a go-patches-owned module is a no-op"
        );
        // Matching owner removes exactly its own line.
        let out = remove_replace_entry(&gomod, "github.com/b/b", ReplaceOwner::Vendor)
            .unwrap()
            .unwrap();
        assert!(!out.contains("github.com/b/b"));
        assert!(out.contains("go-patches/github.com/a/a@v1.0.0"));
        assert!(out.contains("replace github.com/c/c v3.0.0 => ../fork"));
    }

    // ── remove ───────────────────────────────────────────────────────
    #[test]
    fn test_remove_single_line() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar", ReplaceOwner::GoPatches)
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(out.contains("module m"));
    }

    #[test]
    fn test_remove_block_member_prunes_empty_block() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n)\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar", ReplaceOwner::GoPatches)
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(!out.contains("replace ("), "emptied block pruned");
    }

    #[test]
    fn test_remove_block_keeps_other_members() {
        let gomod = "module m\n\nreplace (\n\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n\texample.com/baz v2.0.0 => ../local-baz\n)\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar", ReplaceOwner::GoPatches)
            .unwrap()
            .unwrap();
        assert!(!out.contains("go-patches"));
        assert!(out.contains("replace ("), "block kept (still has a member)");
        assert!(out.contains("example.com/baz v2.0.0 => ../local-baz"));
    }

    #[test]
    fn test_remove_leaves_user_replace() {
        let gomod = "module m\n\nreplace github.com/foo/bar v1.4.2 => ../fork\n";
        assert!(
            remove_replace_entry(gomod, "github.com/foo/bar", ReplaceOwner::GoPatches)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(remove_replace_entry(
            "module m\n\ngo 1.21\n",
            "github.com/foo/bar",
            ReplaceOwner::GoPatches
        )
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

        assert!(ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .unwrap());
        let entries = read_replace_entries(dir.path()).await;
        let bar = entries
            .iter()
            .find(|e| e.module == "github.com/foo/bar")
            .unwrap();
        assert!(bar.socket_owned());
        assert_eq!(
            bar.path.as_deref(),
            Some("./.socket/go-patches/github.com/foo/bar@v1.4.2")
        );
        // Required-version cross-check source.
        let req = read_required_versions(dir.path()).await.unwrap();
        assert_eq!(
            req.get("github.com/foo/bar").map(String::as_str),
            Some("v1.4.2")
        );

        // Idempotent on disk.
        assert!(!ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .unwrap());
        // Drop.
        assert!(drop_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            ReplaceOwner::GoPatches,
            false
        )
        .await
        .unwrap());
        assert!(read_replace_entries(dir.path()).await.is_empty());
    }

    #[tokio::test]
    async fn test_ensure_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let body = "module m\n\ngo 1.21\n";
        fs::write(dir.path().join("go.mod"), body).await.unwrap();
        let changed = ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            true,
        )
        .await
        .unwrap();
        assert!(changed, "dry-run reports the change it would make");
        assert_eq!(
            fs::read_to_string(dir.path().join("go.mod")).await.unwrap(),
            body,
            "dry-run must not write"
        );
    }

    // ── atomic commit: stage+rename leaves no litter, never truncates ────────
    /// A real write must rename its `.socket-stage-*` sibling over `go.mod` and
    /// leave nothing behind — a leftover stage file (or, worse, a half-written
    /// truncated `go.mod`) is exactly the corruption the atomic writer exists to
    /// prevent. Mirrors the litter guard in `package_json/update.rs`.
    #[tokio::test]
    async fn test_ensure_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();

        assert!(ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .unwrap());

        // Only go.mod should remain in the project root.
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["go.mod".to_string()], "no stage-file litter");
        assert!(
            !names.iter().any(|n| n.starts_with(".socket-stage-")),
            "stage file must be renamed away, not left behind"
        );
    }

    /// An overwrite must replace the whole file in one atomic step while
    /// preserving every unrelated byte (module line, `go` line, `require`s, the
    /// user's own `replace`, and comments) — the writer stages full new content
    /// and renames, never truncates-in-place.
    #[tokio::test]
    async fn test_ensure_overwrite_preserves_unrelated_content_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let original = "module example.com/app\n\ngo 1.21\n\n// keep me\nrequire github.com/foo/bar v1.4.2\n\nreplace example.com/other v2.0.0 => ../other-fork\n";
        fs::write(dir.path().join("go.mod"), original)
            .await
            .unwrap();

        assert!(ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .unwrap());

        let on_disk = fs::read_to_string(dir.path().join("go.mod")).await.unwrap();
        // Our directive landed…
        assert!(on_disk.contains(
            "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
        ));
        // …and nothing the user authored was lost.
        assert!(on_disk.contains("module example.com/app"));
        assert!(on_disk.contains("// keep me"));
        assert!(on_disk.contains("require github.com/foo/bar v1.4.2"));
        assert!(on_disk.contains("replace example.com/other v2.0.0 => ../other-fork"));
        assert!(
            on_disk.starts_with(original),
            "original content kept verbatim as a prefix"
        );
    }

    /// `go.mod` is user-owned: editing it must not reset its permission bits
    /// (a 0600 private go.mod silently becoming umask-default 0644 is the
    /// `package_json/update.rs` mode-reset bug, same class).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_ensure_preserves_go_mod_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("go.mod");
        fs::write(&path, "module m\n\ngo 1.21\n").await.unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();

        assert!(ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .unwrap());

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "edit must preserve go.mod permission bits");
    }

    // ── tab-separated directives (Go's lexer: any whitespace separates) ──────
    /// A hand-formatted `replace\tmodule … => …` (tab after the keyword) is
    /// valid go.mod. Upsert must recognize it as the existing socket-owned
    /// entry — appending a second directive for the same module+version makes
    /// go.mod invalid ("duplicate replacement").
    #[test]
    fn test_upsert_recognizes_tab_separated_socket_replace() {
        let gomod = "module m\n\nreplace\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out =
            upsert_replace_entry(gomod, "github.com/foo/bar", "v1.4.2", GO_PATCHES_DIR).unwrap();
        // Either a no-op or an in-place normalization is fine; a duplicate is not.
        // Count raw text occurrences — parse_replace_entries can't be the
        // oracle for a form the parser itself might be blind to.
        let content = out.as_deref().unwrap_or(gomod);
        assert_eq!(
            content.matches("github.com/foo/bar v1.4.2 =>").count(),
            1,
            "must not append a duplicate replace for the module: {content:?}"
        );
        // Still a well-formed single-line directive (keyword kept).
        assert!(
            content.contains("replace")
                && content.contains(
                    "github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2"
                ),
        );
    }

    /// Same input: drop must remove the tab-separated socket-owned directive —
    /// leaving it behind strands a `replace` pointing at a copy dir the caller
    /// is about to delete.
    #[test]
    fn test_remove_tab_separated_socket_replace() {
        let gomod = "module m\n\nreplace\tgithub.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n";
        let out = remove_replace_entry(gomod, "github.com/foo/bar", ReplaceOwner::GoPatches)
            .unwrap()
            .expect("tab-separated socket replace must be removable");
        assert!(!out.contains("go-patches"));
        assert!(out.contains("module m"));
    }

    #[tokio::test]
    async fn test_ensure_missing_go_mod_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_replace_entry(
            dir.path(),
            "github.com/foo/bar",
            "v1.4.2",
            GO_PATCHES_DIR,
            false
        )
        .await
        .is_err());
    }
}
