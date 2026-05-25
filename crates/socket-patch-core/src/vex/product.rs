//! Top-level product PURL auto-detection.
//!
//! Detection chain (first match wins):
//!   1. `.git/config` `[remote "origin"]` URL — the canonical
//!      identifier when the repo IS the product. GitHub/GitLab/
//!      Bitbucket URLs are normalized to
//!      `pkg:<github|gitlab|bitbucket>/<owner>/<name>`; anything else
//!      is returned as the raw URL.
//!   2. `package.json` (npm)        → `pkg:npm/<name>@<version>`
//!   3. `pyproject.toml` (PyPI)     → `pkg:pypi/<name>@<version>`
//!   4. `Cargo.toml` (Cargo)        → `pkg:cargo/<name>@<version>`
//!
//! Returns `None` only when none of these sources yield a usable
//! identifier. Multiple-package-manifest case: we pick the highest
//! package-manifest priority and surface a warning via
//! [`DetectResult::warnings`] so the CLI can echo it to stderr. Git
//! remote presence does NOT trigger that warning even when alongside
//! a package manifest — the priority is documented and stable.

use std::path::Path;

/// Outcome of [`detect_product`].
#[derive(Debug, Clone, Default)]
pub struct DetectResult {
    /// Detected product PURL, or `None` if nothing matched.
    pub purl: Option<String>,
    /// Non-fatal observations the CLI should print to stderr — e.g.
    /// "found Cargo.toml AND package.json; using package.json".
    pub warnings: Vec<String>,
}

pub async fn detect_product(cwd: &Path) -> DetectResult {
    let mut result = DetectResult::default();

    // 1. git remote origin (highest priority — canonical when present).
    if let Some(purl) = detect_git_remote(cwd).await {
        result.purl = Some(purl);
        return result;
    }

    let pkg_json = cwd.join("package.json");
    let pyproject = cwd.join("pyproject.toml");
    let cargo = cwd.join("Cargo.toml");

    let pkg_json_exists = tokio::fs::metadata(&pkg_json).await.is_ok();
    let pyproject_exists = tokio::fs::metadata(&pyproject).await.is_ok();
    let cargo_exists = tokio::fs::metadata(&cargo).await.is_ok();

    // Collect a warning if more than one manifest is present.
    let present_count = [pkg_json_exists, pyproject_exists, cargo_exists]
        .iter()
        .filter(|b| **b)
        .count();
    if present_count > 1 {
        let mut found = Vec::new();
        if pkg_json_exists {
            found.push("package.json");
        }
        if pyproject_exists {
            found.push("pyproject.toml");
        }
        if cargo_exists {
            found.push("Cargo.toml");
        }
        result.warnings.push(format!(
            "Multiple project manifests detected ({}); using {} for the top-level product",
            found.join(", "),
            found[0]
        ));
    }

    if pkg_json_exists {
        if let Some(purl) = read_package_json(&pkg_json).await {
            result.purl = Some(purl);
            return result;
        }
    }
    if pyproject_exists {
        if let Some(purl) = read_pyproject(&pyproject).await {
            result.purl = Some(purl);
            return result;
        }
    }
    if cargo_exists {
        if let Some(purl) = read_cargo_toml(&cargo).await {
            result.purl = Some(purl);
            return result;
        }
    }

    result
}

async fn read_package_json(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    let name = v.get("name")?.as_str()?;
    let version = v.get("version")?.as_str()?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // npm scoped packages keep their `@scope/name` form in the PURL —
    // matches how socket-patch's manifest already stores them.
    Some(format!("pkg:npm/{name}@{version}"))
}

async fn read_pyproject(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    // PEP 621 `[project]` takes precedence (newer projects favor it),
    // then fall back to Poetry's `[tool.poetry]` for legacy layouts.
    let (name, version) = scan_toml_section(&content, "project")
        .or_else(|| scan_toml_section(&content, "tool.poetry"))?;
    Some(format!("pkg:pypi/{name}@{version}"))
}

async fn read_cargo_toml(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let (name, version) = scan_toml_section(&content, "package")?;
    Some(format!("pkg:cargo/{name}@{version}"))
}

/// Minimal line-based TOML scanner for `[<section>]` blocks. Reads
/// `name = "..."` and `version = "..."` from the named section and
/// stops at the next `[` header. Robust enough for the well-formed
/// `pyproject.toml` / `Cargo.toml` files we expect at the top level —
/// no full TOML parser dependency.
///
/// Returns `None` if either key is missing, both keys appear outside
/// the section, the value is empty, or the value is `version.workspace
/// = true` (matches the cargo crawler's behavior of skipping workspace
/// inheritance).
fn scan_toml_section(content: &str, section: &str) -> Option<(String, String)> {
    let mut in_section = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let header = format!("[{section}]");

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == header;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(v) = parse_toml_string_kv(line, "name") {
            name = Some(v);
        } else if let Some(v) = parse_toml_string_kv(line, "version") {
            version = Some(v);
        }
    }

    let name = name?;
    let version = version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Walk up from `start` looking for a `.git/config` (the working tree
/// or any of its ancestors). When found, parse the
/// `[remote "origin"] url = ...` line and convert that URL to a PURL.
///
/// Returns `None` when:
/// * `cwd` is not inside a git working tree,
/// * `.git/config` has no `[remote "origin"]` section, or
/// * the URL is empty / parsing failed catastrophically. (Otherwise
///   even unrecognized hosts fall through to the raw-URL case.)
///
/// Worktrees (`.git` as a file pointing at a real git dir elsewhere)
/// are deliberately NOT followed — they're rare and the package-
/// manifest fallback handles them correctly. Submodules likewise:
/// only the outermost `.git/config` wins.
async fn detect_git_remote(start: &Path) -> Option<String> {
    let git_config_path = find_git_config(start).await?;
    let content = tokio::fs::read_to_string(&git_config_path).await.ok()?;
    let url = scan_remote_origin_url(&content)?;
    Some(remote_url_to_purl(&url))
}

/// Walk ancestors looking for `<dir>/.git/config` as a regular file.
/// Returns the path to it, or `None` if we exhaust the chain.
async fn find_git_config(start: &Path) -> Option<std::path::PathBuf> {
    let mut cursor = match tokio::fs::canonicalize(start).await {
        Ok(p) => p,
        Err(_) => start.to_path_buf(),
    };
    loop {
        let candidate = cursor.join(".git").join("config");
        if tokio::fs::metadata(&candidate)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return Some(candidate);
        }
        match cursor.parent() {
            Some(p) => cursor = p.to_path_buf(),
            None => return None,
        }
    }
}

/// Read the `url = ...` line out of the `[remote "origin"]` section of
/// a git config file. Returns the trimmed URL, or `None`.
fn scan_remote_origin_url(content: &str) -> Option<String> {
    let mut in_section = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line == "[remote \"origin\"]";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(rest) = line.strip_prefix("url") {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            if rest.is_empty() {
                return None;
            }
            return Some(rest.to_string());
        }
    }
    None
}

/// Convert a git remote URL to a PURL when possible, else return the
/// URL itself (OpenVEX `@id` accepts any URI).
///
/// Handled forms:
/// * `git@github.com:owner/repo.git`     → `pkg:github/owner/repo`
/// * `https://github.com/owner/repo.git` → `pkg:github/owner/repo`
/// * `https://github.com/owner/repo`     → `pkg:github/owner/repo`
/// * Same shapes for `gitlab.com` (→ `pkg:gitlab`) and `bitbucket.org`
///   (→ `pkg:bitbucket`).
/// * Anything else (self-hosted gitea, generic SSH, etc.) → URL as-is.
fn remote_url_to_purl(url: &str) -> String {
    if let Some((host, path)) = split_remote_host_path(url) {
        let cleaned = path.strip_suffix(".git").unwrap_or(path);
        let cleaned = cleaned.trim_matches('/');
        let parts: Vec<&str> = cleaned.split('/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            let ecosystem = match host {
                "github.com" => Some("github"),
                "gitlab.com" => Some("gitlab"),
                "bitbucket.org" => Some("bitbucket"),
                _ => None,
            };
            if let Some(eco) = ecosystem {
                return format!("pkg:{eco}/{}/{}", parts[0], parts[1]);
            }
        }
    }
    url.to_string()
}

/// Pull `(host, path)` out of a git remote URL. Returns `None` for
/// shapes we don't recognize — the caller falls back to raw-URL mode.
fn split_remote_host_path(url: &str) -> Option<(&str, &str)> {
    // SSH form: `git@<host>:<path>`. The `:` is a path separator, NOT
    // a port — git's URL parser treats this as scp-style.
    if let Some(rest) = url.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        return Some((host, path));
    }
    // ssh:// or git+ssh:// form: strip both then drop the user.
    let stripped = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("git+ssh://"))
        .or_else(|| url.strip_prefix("git://"))
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("http://"));
    if let Some(rest) = stripped {
        // Drop optional `user@` prefix.
        let rest = match rest.split_once('@') {
            Some((_, after)) => after,
            None => rest,
        };
        let (host_with_port, path) = rest.split_once('/')?;
        // Strip a `:port` if present.
        let host = host_with_port
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_with_port);
        return Some((host, path));
    }
    None
}

/// Parse `<key> = "<value>"`. Returns `None` if the key doesn't match,
/// the value isn't a double-quoted string literal, or the value is
/// empty. Inline-table forms like `version = { workspace = true }`
/// fail this check and are skipped by the caller.
fn parse_toml_string_kv(line: &str, key: &str) -> Option<String> {
    let eq = line.find('=')?;
    let (lhs, rhs) = line.split_at(eq);
    if lhs.trim() != key {
        return None;
    }
    let rhs = rhs[1..].trim(); // drop the leading '=' and surrounding ws
    let stripped = rhs.strip_prefix('"')?;
    let end = stripped.find('"')?;
    let value = &stripped[..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detect_package_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"my-app","version":"1.2.3"}"#,
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/my-app@1.2.3"));
        assert!(r.warnings.is_empty());
    }

    #[tokio::test]
    async fn detect_scoped_npm_package() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"@socket/foo","version":"0.1.0"}"#,
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/@socket/foo@0.1.0"));
    }

    #[tokio::test]
    async fn detect_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[project]\nname = \"my-pylib\"\nversion = \"0.4.0\"\n";
        tokio::fs::write(dir.path().join("pyproject.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/my-pylib@0.4.0"));
    }

    #[tokio::test]
    async fn detect_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[package]\nname = \"my-rust\"\nversion = \"2.0.0\"\nedition = \"2021\"\n";
        tokio::fs::write(dir.path().join("Cargo.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:cargo/my-rust@2.0.0"));
    }

    #[tokio::test]
    async fn cargo_workspace_inheritance_is_unsupported() {
        // `version.workspace = true` is not a quoted string literal,
        // so detection should report None rather than emit garbage.
        let dir = tempfile::tempdir().unwrap();
        let content = "[package]\nname = \"my-rust\"\nversion.workspace = true\n";
        tokio::fs::write(dir.path().join("Cargo.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    #[tokio::test]
    async fn multiple_manifests_warns_and_picks_package_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"my-app","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"alt\"\nversion = \"9.9.9\"\n",
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/my-app@1.0.0"));
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("Multiple"));
    }

    #[tokio::test]
    async fn empty_dir_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn scan_toml_skips_other_sections() {
        let toml = "[other]\nname = \"wrong\"\nversion = \"0.0.0\"\n\n[package]\nname = \"right\"\nversion = \"1.0.0\"\n";
        let (n, v) = scan_toml_section(toml, "package").unwrap();
        assert_eq!(n, "right");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn scan_toml_ignores_comments_and_blank_lines() {
        let toml = "[package]\n# a comment\n\nname = \"x\"\nversion = \"1.0\"\n";
        let (n, v) = scan_toml_section(toml, "package").unwrap();
        assert_eq!(n, "x");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn scan_toml_missing_version_returns_none() {
        let toml = "[package]\nname = \"only-name\"\n";
        assert!(scan_toml_section(toml, "package").is_none());
    }

    // ─────────────────── git-remote detection ───────────────────

    #[test]
    fn remote_url_github_ssh_becomes_pkg_github() {
        assert_eq!(
            remote_url_to_purl("git@github.com:SocketDev/socket-patch.git"),
            "pkg:github/SocketDev/socket-patch"
        );
    }

    #[test]
    fn remote_url_github_https_becomes_pkg_github() {
        assert_eq!(
            remote_url_to_purl("https://github.com/SocketDev/socket-patch.git"),
            "pkg:github/SocketDev/socket-patch"
        );
    }

    #[test]
    fn remote_url_github_https_no_dot_git() {
        assert_eq!(
            remote_url_to_purl("https://github.com/SocketDev/socket-patch"),
            "pkg:github/SocketDev/socket-patch"
        );
    }

    #[test]
    fn remote_url_gitlab_and_bitbucket() {
        assert_eq!(
            remote_url_to_purl("git@gitlab.com:foo/bar.git"),
            "pkg:gitlab/foo/bar"
        );
        assert_eq!(
            remote_url_to_purl("https://bitbucket.org/foo/bar"),
            "pkg:bitbucket/foo/bar"
        );
    }

    #[test]
    fn remote_url_unknown_host_returns_url_as_is() {
        // Self-hosted gitea / unknown forge — VEX `@id` accepts any URI.
        let raw = "https://git.example.com/team/repo.git";
        assert_eq!(remote_url_to_purl(raw), raw);
    }

    #[test]
    fn remote_url_ssh_protocol_form() {
        assert_eq!(
            remote_url_to_purl("ssh://git@github.com/foo/bar.git"),
            "pkg:github/foo/bar"
        );
    }

    #[test]
    fn scan_origin_url_picks_url_in_section() {
        let cfg = "[core]\nbare = false\n[remote \"origin\"]\nurl = git@github.com:foo/bar.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n";
        assert_eq!(
            scan_remote_origin_url(cfg).as_deref(),
            Some("git@github.com:foo/bar.git")
        );
    }

    #[test]
    fn scan_origin_url_ignores_other_remotes() {
        // `[remote "upstream"]` must not be confused for origin.
        let cfg = "[remote \"upstream\"]\nurl = git@github.com:other/repo.git\n[remote \"origin\"]\nurl = git@github.com:me/repo.git\n";
        assert_eq!(
            scan_remote_origin_url(cfg).as_deref(),
            Some("git@github.com:me/repo.git")
        );
    }

    #[test]
    fn scan_origin_url_returns_none_when_missing() {
        assert!(scan_remote_origin_url("[core]\nbare = false\n").is_none());
    }

    #[tokio::test]
    async fn detect_prefers_git_remote_over_package_manifest() {
        let dir = tempfile::tempdir().unwrap();
        // package.json says "from-pkg"; git remote says "from-git".
        // Git remote must win.
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"from-pkg","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let git_dir = dir.path().join(".git");
        tokio::fs::create_dir_all(&git_dir).await.unwrap();
        tokio::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = git@github.com:owner/from-git.git\n",
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:github/owner/from-git"));
    }

    #[tokio::test]
    async fn detect_falls_back_to_package_manifest_when_no_git_remote() {
        // Empty .git/config (no remote) → fall through to package.json.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"pkg-only","version":"2.0.0"}"#,
        )
        .await
        .unwrap();
        let git_dir = dir.path().join(".git");
        tokio::fs::create_dir_all(&git_dir).await.unwrap();
        tokio::fs::write(git_dir.join("config"), "[core]\nbare = false\n")
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/pkg-only@2.0.0"));
    }

    #[tokio::test]
    async fn detect_finds_git_config_in_parent_directory() {
        // Common case: socket-patch is invoked from a subdir of the repo.
        let root = tempfile::tempdir().unwrap();
        let git_dir = root.path().join(".git");
        tokio::fs::create_dir_all(&git_dir).await.unwrap();
        tokio::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = git@github.com:org/proj.git\n",
        )
        .await
        .unwrap();

        let nested = root.path().join("packages").join("inner");
        tokio::fs::create_dir_all(&nested).await.unwrap();

        let r = detect_product(&nested).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:github/org/proj"));
    }

    // ── Edge-case + branch coverage ───────────────────────────────

    /// `.git/config` exists but lists only non-origin remotes →
    /// detection must fall through to package-manifest discovery
    /// (otherwise the repo would surface no identifier at all).
    #[tokio::test]
    async fn git_config_with_only_non_origin_remote_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"fallback-app","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let git_dir = dir.path().join(".git");
        tokio::fs::create_dir_all(&git_dir).await.unwrap();
        tokio::fs::write(
            git_dir.join("config"),
            "[remote \"upstream\"]\n\turl = git@github.com:other/proj.git\n",
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/fallback-app@1.0.0"));
    }

    /// `url =` with no value after the `=` is a malformed git config.
    /// Detection must treat it as "no remote" and fall through.
    #[tokio::test]
    async fn git_config_with_empty_url_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"fallback-app","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let git_dir = dir.path().join(".git");
        tokio::fs::create_dir_all(&git_dir).await.unwrap();
        tokio::fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n\turl = \n",
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/fallback-app@1.0.0"));
    }

    /// CRLF line endings — Rust's `str::lines()` already handles
    /// `\r\n`, but pin this so a future switch to `split('\n')`
    /// would surface the regression.
    #[test]
    fn scan_origin_url_handles_crlf_line_endings() {
        let cfg =
            "[remote \"origin\"]\r\n\turl = git@github.com:foo/bar.git\r\n";
        assert_eq!(
            scan_remote_origin_url(cfg).as_deref(),
            Some("git@github.com:foo/bar.git")
        );
    }

    /// `git+ssh://` URL form → `split_remote_host_path` branch.
    #[test]
    fn remote_url_git_plus_ssh_form() {
        assert_eq!(
            remote_url_to_purl("git+ssh://git@github.com/owner/repo.git"),
            "pkg:github/owner/repo"
        );
    }

    /// `git://` URL form (legacy unauthenticated) — separate branch
    /// from `ssh://` and `https://`.
    #[test]
    fn remote_url_git_protocol_form() {
        assert_eq!(
            remote_url_to_purl("git://github.com/owner/repo.git"),
            "pkg:github/owner/repo"
        );
    }

    /// `http://` (plain, not https) — exercises the
    /// `strip_prefix("http://")` arm in `split_remote_host_path`.
    #[test]
    fn remote_url_http_form() {
        assert_eq!(
            remote_url_to_purl("http://github.com/owner/repo.git"),
            "pkg:github/owner/repo"
        );
    }

    /// `ssh://git@host:22/path` — port suffix on host must be
    /// stripped so the ecosystem lookup still matches `github.com`.
    #[test]
    fn remote_url_ssh_with_port_strips_port() {
        assert_eq!(
            remote_url_to_purl("ssh://git@github.com:22/owner/repo.git"),
            "pkg:github/owner/repo"
        );
    }

    /// Pre-`split_remote_host_path` SSH form WITH NO user prefix:
    /// `ssh://github.com/foo/bar.git`. Branch where the `@` split
    /// doesn't fire and the whole rest is treated as `host/path`.
    #[test]
    fn remote_url_ssh_no_user_prefix() {
        assert_eq!(
            remote_url_to_purl("ssh://github.com/foo/bar.git"),
            "pkg:github/foo/bar"
        );
    }

    /// Truly unrecognized URL form (no recognized scheme prefix and
    /// no scp-style `git@host:path`) → returned as-is.
    #[test]
    fn remote_url_unknown_shape_returned_verbatim() {
        let weird = "file:///srv/repos/proj.git";
        assert_eq!(remote_url_to_purl(weird), weird);
    }

    /// `pyproject.toml` with `[tool.poetry]` (Poetry layout) is now
    /// supported as a fallback when `[project]` is absent.
    #[tokio::test]
    async fn detect_pyproject_tool_poetry_layout() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[tool.poetry]\nname = \"poetry-app\"\nversion = \"0.9.0\"\n";
        tokio::fs::write(dir.path().join("pyproject.toml"), content)
            .await
            .unwrap();
        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/poetry-app@0.9.0"));
    }

    /// When `[project]` and `[tool.poetry]` are both present, the
    /// PEP-621 section wins (modern projects prefer it).
    #[tokio::test]
    async fn detect_pyproject_project_section_wins_over_tool_poetry() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[project]\nname = \"pep621-app\"\nversion = \"1.0.0\"\n\n[tool.poetry]\nname = \"poetry-app\"\nversion = \"0.9.0\"\n";
        tokio::fs::write(dir.path().join("pyproject.toml"), content)
            .await
            .unwrap();
        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/pep621-app@1.0.0"));
    }

    /// Multi-manifest combo: pyproject + Cargo.toml present, no
    /// package.json. pyproject wins per the priority list.
    #[tokio::test]
    async fn detect_pyproject_over_cargo_when_no_package_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"py-app\"\nversion = \"1.0.0\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"rust-app\"\nversion = \"2.0.0\"\n",
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/py-app@1.0.0"));
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("pyproject.toml"));
        assert!(r.warnings[0].contains("Cargo.toml"));
    }

    /// `package.json` with only `version` (no `name`) → None.
    /// Currently the early `is_empty()` branch in `read_package_json`.
    #[tokio::test]
    async fn package_json_missing_name_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `package.json` with empty `name` string → None (is_empty check).
    #[tokio::test]
    async fn package_json_empty_name_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `package.json` with invalid JSON → None (parse-error branch).
    #[tokio::test]
    async fn package_json_invalid_json_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("package.json"), "{ not json").await.unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `parse_toml_string_kv`: line without `=` → None.
    #[test]
    fn parse_toml_kv_returns_none_when_no_equals() {
        assert!(parse_toml_string_kv("name without equals", "name").is_none());
    }

    /// `parse_toml_string_kv`: key mismatch → None even if value is fine.
    #[test]
    fn parse_toml_kv_returns_none_when_key_mismatch() {
        assert!(parse_toml_string_kv(r#"other = "value""#, "name").is_none());
    }

    /// `parse_toml_string_kv`: missing closing quote → None.
    #[test]
    fn parse_toml_kv_returns_none_when_unterminated_string() {
        assert!(parse_toml_string_kv(r#"name = "no-close"#, "name").is_none());
    }

    /// `parse_toml_string_kv`: empty quoted value → None (we reject
    /// `name = ""`).
    #[test]
    fn parse_toml_kv_returns_none_when_value_empty() {
        assert!(parse_toml_string_kv(r#"name = """#, "name").is_none());
    }

    /// `parse_toml_string_kv`: non-string value (e.g. `key = 42`) →
    /// None (we only accept quoted strings).
    #[test]
    fn parse_toml_kv_returns_none_when_value_not_quoted() {
        assert!(parse_toml_string_kv(r#"name = 42"#, "name").is_none());
    }

    /// `split_remote_host_path`: SSH URL with no `:` separator →
    /// None. Defensive — `git@` prefix without scp-style path.
    #[test]
    fn split_host_path_rejects_ssh_without_colon() {
        assert!(split_remote_host_path("git@github.com").is_none());
    }

    /// `split_remote_host_path`: stripped scheme but no `/` →
    /// host-without-path, the inner `split_once('/')` returns None.
    #[test]
    fn split_host_path_rejects_scheme_url_without_path() {
        assert!(split_remote_host_path("https://github.com").is_none());
    }

    /// `remote_url_to_purl`: GitHub URL with 3 path segments
    /// (`owner/repo/extra`) falls into the "not exactly 2 parts"
    /// branch and returns the raw URL.
    #[test]
    fn remote_url_three_path_segments_returns_url_as_is() {
        let raw = "https://github.com/owner/repo/extra";
        assert_eq!(remote_url_to_purl(raw), raw);
    }

    /// `remote_url_to_purl`: trailing slash on the path is trimmed
    /// before splitting, so `https://github.com/owner/repo/` still
    /// resolves to `pkg:github/owner/repo`.
    #[test]
    fn remote_url_trailing_slash_is_normalized() {
        assert_eq!(
            remote_url_to_purl("https://github.com/owner/repo/"),
            "pkg:github/owner/repo"
        );
    }

    /// `Cargo.toml` with `name` only (no `version`) → None. Exercises
    /// the `version?` early-return path inside `scan_toml_section`.
    #[tokio::test]
    async fn cargo_toml_missing_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"only-name\"\n",
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// Pyproject without `[project]` AND without `[tool.poetry]` →
    /// None.
    #[tokio::test]
    async fn pyproject_with_no_recognized_section_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("pyproject.toml"),
            "[build-system]\nrequires = [\"setuptools\"]\n",
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `DetectResult::default()` is empty (purl=None, warnings=[]).
    #[test]
    fn detect_result_default_is_empty() {
        let r = DetectResult::default();
        assert!(r.purl.is_none());
        assert!(r.warnings.is_empty());
    }

    /// `find_git_config` returns None for a path that genuinely has
    /// no `.git/config` on any ancestor. Tempdir on `/var/folders` (macOS)
    /// or `/tmp` (linux) gives us a tree that escapes the user's home.
    #[tokio::test]
    async fn find_git_config_returns_none_when_no_repo_ancestor() {
        // Walk up from the tempdir — none of its ancestors should
        // contain `.git/config`. This depends on the test runner's
        // tempdir living outside any git repo; both macOS
        // /var/folders and Linux /tmp satisfy that.
        let dir = tempfile::tempdir().unwrap();
        let r = find_git_config(dir.path()).await;
        assert!(r.is_none(), "unexpected .git/config above {dir:?}: {r:?}");
    }

    /// `find_git_config` handles a non-existent start path via the
    /// `canonicalize → Err` arm and still walks ancestors of the
    /// raw input. Returns None when no config is found.
    #[tokio::test]
    async fn find_git_config_handles_non_existent_start_path() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does/not/exist");
        // No I/O panic; the fallback `start.to_path_buf()` arm of
        // the `canonicalize` match runs.
        let r = find_git_config(&nonexistent).await;
        assert!(r.is_none());
    }

    /// `package.json` where `name` is a number, not a string → None.
    /// Exercises the `.as_str()?` branch on the JSON value.
    #[tokio::test]
    async fn package_json_with_non_string_name_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":42,"version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `package.json` where `version` is a number → None.
    #[tokio::test]
    async fn package_json_with_non_string_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"x","version":42}"#,
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    /// `[remote "origin"]` block has a line that starts with `url`
    /// but has no `=` (e.g. `url ` then EOL). The `strip_prefix('=')?`
    /// inside `scan_remote_origin_url` returns None and the scanner
    /// continues — eventually exhausting the section with no url.
    #[test]
    fn scan_origin_url_skips_url_line_without_equals_sign() {
        let cfg = "[remote \"origin\"]\n\turl no-equals-here\n";
        // The `url` line has no `=`, so the scanner returns None
        // from the inner `strip_prefix('=')?` — but per the code
        // shape (line 224 with `?` on an Option), that propagates
        // out of `scan_remote_origin_url` as None.
        assert!(scan_remote_origin_url(cfg).is_none());
    }

    /// `package.json` missing the `version` key entirely. Exercises
    /// the `v.get("version")?` early-return path (distinct from the
    /// `.as_str()?` branch — `get` returns None, not Some(non-string)).
    #[tokio::test]
    async fn package_json_missing_version_key_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"x"}"#,
        )
        .await
        .unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }
}
