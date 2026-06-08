//! Read / write `<project_root>/.cargo/config.toml` for the project-local
//! cargo `[patch]`-redirect backend.
//!
//! Mirrors the contract style of [`crate::pth_hook::edit`]: pure
//! `fn(&str) -> Result<Option<String>, String>` transforms (`Some(new)` =
//! changed, `None` = already in the desired state) wrapped by async
//! read-or-create / write helpers that honour `dry_run` and preserve the
//! user's existing formatting + comments via `toml_edit`.
//!
//! ## Ownership model (no sidecar manifest)
//! A `[patch.crates-io]` entry is *socket-owned* iff its `path` value lies
//! under `.socket/cargo-patches/`. Anything else — a `git`/`registry` source,
//! or a `path` pointing elsewhere — is user-authored and is never modified or
//! removed. This is the entire ownership signal; there is no `managed.json`.
//!
//! ## Relative-path semantics
//! A relative `path` in a config-file `[patch]` entry is resolved by cargo
//! relative to the **parent of the `.cargo/` directory** (i.e. the project
//! root), so the committed `<root>/.socket/cargo-patches/<name>-<version>`
//! copy is found on any clone. `[env] SOCKET_PATCH_ROOT` is orthogonal: cargo
//! does not expand env vars inside `[patch]` paths. It is written
//! `{ value = ".", relative = true }`, which cargo resolves (same base — the
//! project root) to the absolute project root and exports for build scripts.
//! The build-time guard reads it to locate `Cargo.lock` + `.socket/` and to
//! pass `apply --cwd <root>`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::fs;
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

/// Project-relative directory holding patched crate copies. An entry whose
/// `path` is under this prefix is how socket ownership is recognised.
pub const CARGO_PATCHES_DIR: &str = ".socket/cargo-patches";

/// The `[env]` key carrying the project root for the build-time guard.
const ENV_ROOT_KEY: &str = "SOCKET_PATCH_ROOT";

/// Info about one `[patch.crates-io]` entry, for reconcile / verify.
#[derive(Debug, Clone)]
pub struct PatchEntryInfo {
    /// The `path` value as written (verbatim), or `None` for a non-path
    /// source (e.g. `git`/`registry`).
    pub path: Option<String>,
    /// True iff `path` is under `.socket/cargo-patches/`.
    pub socket_owned: bool,
}

/// The expected (project-root-relative) `[patch]` path for a crate copy.
/// Always forward-slashed — cargo accepts that on every platform.
pub fn expected_patch_path(name: &str, version: &str) -> String {
    format!("{CARGO_PATCHES_DIR}/{name}-{version}")
}

// ── public async API ─────────────────────────────────────────────────────────

/// Upsert `[patch.crates-io].<name> = { path = "<.socket/cargo-patches/...>" }`.
/// Idempotent. Returns whether the file changed. Errors (without writing) if a
/// same-name entry exists but is user-authored.
pub async fn ensure_patch_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_config(project_root, dry_run, |c| {
        upsert_patch_entry(c, name, version)
    })
    .await
}

/// Remove a *socket-owned* `[patch.crates-io].<name>` entry, cleaning up empty
/// `[patch.crates-io]` / `[patch]` tables. A user-authored or absent entry is a
/// no-op. Returns whether the file changed.
pub async fn drop_patch_entry(
    project_root: &Path,
    name: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_config(project_root, dry_run, |c| remove_patch_entry(c, name)).await
}

/// Upsert `[env] SOCKET_PATCH_ROOT = { value = ".", relative = true }`.
/// Idempotent. Returns whether the file changed.
pub async fn ensure_env_root(project_root: &Path, dry_run: bool) -> Result<bool, String> {
    edit_config(project_root, dry_run, upsert_env_root).await
}

/// Remove the `[env] SOCKET_PATCH_ROOT` key (leaving any other `[env]` keys).
/// Returns whether the file changed.
pub async fn drop_env_root(project_root: &Path, dry_run: bool) -> Result<bool, String> {
    edit_config(project_root, dry_run, remove_env_root).await
}

/// Read all `[patch.crates-io]` entries. Read-only; a missing or malformed
/// config yields an empty map (callers treat that as "no managed entries").
pub async fn read_patch_entries(project_root: &Path) -> HashMap<String, PatchEntryInfo> {
    let path = config_path(project_root).await;
    match fs::read_to_string(&path).await {
        Ok(content) => parse_patch_entries(&content),
        Err(_) => HashMap::new(),
    }
}

/// Whether `.cargo/config.toml` declares `[env] SOCKET_PATCH_ROOT`. Read-only;
/// powers `setup --check` and the GitHub-App audit. A missing/malformed config
/// reads as `false`.
pub async fn env_root_present(project_root: &Path) -> bool {
    let path = config_path(project_root).await;
    match fs::read_to_string(&path).await {
        Ok(content) => parse_has_env_root(&content),
        Err(_) => false,
    }
}

fn parse_has_env_root(content: &str) -> bool {
    content
        .parse::<DocumentMut>()
        .ok()
        .and_then(|doc| {
            doc.get("env")
                .and_then(Item::as_table_like)
                .map(|env| env.contains_key(ENV_ROOT_KEY))
        })
        .unwrap_or(false)
}

// ── config-file resolution + read-or-create write ────────────────────────────

/// Resolve the config file under `<project_root>/.cargo/`. Prefers an existing
/// `config.toml`, then an existing legacy `config`, else `config.toml` (created
/// on first write).
async fn config_path(project_root: &Path) -> PathBuf {
    let dir = project_root.join(".cargo");
    let toml = dir.join("config.toml");
    if fs::metadata(&toml).await.is_ok() {
        return toml;
    }
    let legacy = dir.join("config");
    if fs::metadata(&legacy).await.is_ok() {
        return legacy;
    }
    toml
}

/// Apply a pure transform to the config file, writing only if it changed and
/// `!dry_run`. A missing file is treated as empty (and created on write).
async fn edit_config(
    project_root: &Path,
    dry_run: bool,
    transform: impl FnOnce(&str) -> Result<Option<String>, String>,
) -> Result<bool, String> {
    let path = config_path(project_root).await;
    let content = match fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    match transform(&content)? {
        None => Ok(false),
        Some(new) => {
            if !dry_run {
                if new.trim().is_empty() {
                    // The edit emptied the file (all socket-owned content removed
                    // and no user content — comments / other tables — remained).
                    // Delete it, and prune the now-empty `.cargo/` dir, so
                    // `setup --remove` restores the exact pre-setup tree rather
                    // than leaving an empty `.cargo/config.toml` behind
                    // (CLI_CONTRACT.md → "Setup command contract", property 8).
                    // A file with surviving user content never trims to empty, so
                    // this only fires for a config that was entirely socket's.
                    match fs::remove_file(&path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("remove {}: {e}", path.display())),
                    }
                    if let Some(parent) = path.parent() {
                        // Best-effort: `remove_dir` only succeeds when the dir is
                        // empty, so a `.cargo/` holding other files is left intact.
                        let _ = fs::remove_dir(parent).await;
                    }
                } else {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)
                            .await
                            .map_err(|e| format!("create {}: {e}", parent.display()))?;
                    }
                    atomic_write(&path, new.as_bytes())
                        .await
                        .map_err(|e| format!("write {}: {e}", path.display()))?;
                }
            }
            Ok(true)
        }
    }
}

/// Atomically commit `content` to `path` via stage + fsync + rename.
///
/// `.cargo/config.toml` is a *user-owned* file — it can hold `[build]`,
/// `[net]`, credentials-adjacent settings, and comments alongside our
/// `[patch]` / `[env]` entries. A bare `fs::write` truncates the target before
/// writing, so a crash, power loss, or `ENOSPC` mid-write would leave the
/// user's config truncated or empty, destroying content we only meant to add
/// two lines to. Instead we write a sibling stage file, fsync it, then rename
/// over the target (atomic on the same filesystem), so a reader/recovering
/// process only ever sees the complete old or the complete new bytes. Mirrors
/// the hardened writers in `patch/apply.rs` and `package_json/update.rs`.
async fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    let stage = parent.join(format!(".socket-stage-{}-{}", stem, uuid::Uuid::new_v4()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .await?;

    use tokio::io::AsyncWriteExt;
    if let Err(e) = file.write_all(content).await {
        let _ = fs::remove_file(&stage).await;
        return Err(e);
    }
    if let Err(e) = file.sync_all().await {
        let _ = fs::remove_file(&stage).await;
        return Err(e);
    }
    drop(file);

    if let Err(e) = fs::rename(&stage, path).await {
        let _ = fs::remove_file(&stage).await;
        return Err(e);
    }

    // The rename only updated the parent directory entry; fsync the directory
    // so the rename itself survives a crash. Best-effort, Unix only.
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(parent).await {
            let _ = dir.sync_all().await;
        }
    }

    Ok(())
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// True if a `[patch]` `path` value lies under `.socket/cargo-patches/`.
fn path_is_socket_owned(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    let prefix = format!("{CARGO_PATCHES_DIR}/");
    norm.starts_with(&prefix) || norm.contains(&format!("/{prefix}"))
}

/// The `path` string of a `[patch]` entry (inline table or sub-table), if any.
fn entry_path(item: &Item) -> Option<&str> {
    item.as_table_like()
        .and_then(|t| t.get("path"))
        .and_then(Item::as_str)
}

/// Ensure `parent[key]` is a table, creating it if absent. Errors if present
/// but a non-table. Mirrors `pth_hook::edit::ensure_table`.
fn ensure_table<'a>(
    parent: &'a mut Table,
    key: &str,
    implicit: bool,
) -> Result<&'a mut Table, String> {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(implicit);
        parent.insert(key, Item::Table(t));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn upsert_patch_entry(content: &str, name: &str, version: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;
    let want = expected_patch_path(name, version);

    let root = doc.as_table_mut();
    // `[patch]` is a parent table that only ever holds `[patch.crates-io]`, so
    // keep it implicit; `[patch.crates-io]` is the explicit one we write into.
    let patch = ensure_table(root, "patch", true)?;
    let crates_io = ensure_table(patch, "crates-io", false)?;

    if let Some(existing) = crates_io.get(name) {
        match entry_path(existing) {
            Some(p) if p == want => return Ok(None), // already correct
            Some(p) if path_is_socket_owned(p) => {} // socket-owned, refresh
            _ => {
                return Err(format!(
                    "`patch.crates-io.{name}` is user-authored; refusing to overwrite"
                ));
            }
        }
    }

    let mut it = InlineTable::new();
    it.insert("path", Value::from(want));
    crates_io.insert(name, Item::Value(Value::InlineTable(it)));
    Ok(Some(doc.to_string()))
}

fn remove_patch_entry(content: &str, name: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;

    let mut removed = false;
    if let Some(patch) = doc.get_mut("patch").and_then(Item::as_table_mut) {
        let mut crates_io_empty = false;
        if let Some(crates_io) = patch.get_mut("crates-io").and_then(Item::as_table_mut) {
            if matches!(crates_io.get(name).and_then(entry_path), Some(p) if path_is_socket_owned(p))
            {
                crates_io.remove(name);
                removed = true;
                crates_io_empty = crates_io.is_empty();
            }
        }
        if crates_io_empty {
            patch.remove("crates-io");
        }
    }
    if !removed {
        return Ok(None);
    }
    if doc
        .get("patch")
        .and_then(Item::as_table)
        .map(Table::is_empty)
        .unwrap_or(false)
    {
        doc.as_table_mut().remove("patch");
    }
    Ok(Some(doc.to_string()))
}

fn upsert_env_root(content: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;
    let root = doc.as_table_mut();
    let env = ensure_table(root, "env", false)?;

    let already = env
        .get(ENV_ROOT_KEY)
        .and_then(Item::as_table_like)
        .map(|t| {
            t.get("value").and_then(Item::as_str) == Some(".")
                && t.get("relative").and_then(Item::as_bool) == Some(true)
        })
        .unwrap_or(false);
    if already {
        return Ok(None);
    }

    let mut it = InlineTable::new();
    it.insert("value", Value::from("."));
    it.insert("relative", Value::from(true));
    env.insert(ENV_ROOT_KEY, Item::Value(Value::InlineTable(it)));
    Ok(Some(doc.to_string()))
}

fn remove_env_root(content: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;
    let mut changed = false;
    if let Some(env) = doc.get_mut("env").and_then(Item::as_table_mut) {
        if env.remove(ENV_ROOT_KEY).is_some() {
            changed = true;
        }
    }
    if !changed {
        return Ok(None);
    }
    if doc
        .get("env")
        .and_then(Item::as_table)
        .map(Table::is_empty)
        .unwrap_or(false)
    {
        doc.as_table_mut().remove("env");
    }
    Ok(Some(doc.to_string()))
}

fn parse_patch_entries(content: &str) -> HashMap<String, PatchEntryInfo> {
    let mut out = HashMap::new();
    let doc = match content.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(_) => return out,
    };
    let crates_io = doc
        .get("patch")
        .and_then(Item::as_table)
        .and_then(|t| t.get("crates-io"))
        .and_then(Item::as_table);
    if let Some(tbl) = crates_io {
        for (name, item) in tbl.iter() {
            let path = entry_path(item).map(str::to_string);
            let socket_owned = path.as_deref().map(path_is_socket_owned).unwrap_or(false);
            out.insert(name.to_string(), PatchEntryInfo { path, socket_owned });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> DocumentMut {
        s.parse::<DocumentMut>().unwrap()
    }

    // ── path ownership ───────────────────────────────────────────────
    #[test]
    fn test_is_socket_owned() {
        assert!(path_is_socket_owned(".socket/cargo-patches/cfg-if-1.0.0"));
        assert!(path_is_socket_owned("./.socket/cargo-patches/x-1.0.0")); // contains "/.socket/.."
        assert!(path_is_socket_owned("sub/.socket/cargo-patches/x-1.0.0"));
        assert!(path_is_socket_owned(r".socket\cargo-patches\x-1.0.0")); // backslash normalised
        assert!(!path_is_socket_owned("vendor/cfg-if"));
        assert!(!path_is_socket_owned("../cfg-if"));
        assert!(!path_is_socket_owned("/abs/.socketX/cargo-patches/x"));
    }

    // ── upsert ───────────────────────────────────────────────────────
    #[test]
    fn test_upsert_into_empty_creates_entry() {
        let out = upsert_patch_entry("", "cfg-if", "1.0.0").unwrap().unwrap();
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(".socket/cargo-patches/cfg-if-1.0.0")
        );
        // Idempotent: a second upsert is a no-op.
        assert!(upsert_patch_entry(&out, "cfg-if", "1.0.0")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_upsert_preserves_user_content() {
        let toml = "# my config\n[build]\njobs = 4\n\n[patch.crates-io]\nother = { git = \"https://example.com/o.git\" }\n";
        let out = upsert_patch_entry(toml, "cfg-if", "1.0.0")
            .unwrap()
            .unwrap();
        assert!(out.contains("# my config"));
        assert!(out.contains("jobs = 4"));
        let doc = parse(&out);
        // The user's git entry survives alongside ours.
        assert_eq!(
            doc["patch"]["crates-io"]["other"]
                .as_table_like()
                .and_then(|t| t.get("git"))
                .and_then(Item::as_str),
            Some("https://example.com/o.git")
        );
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(".socket/cargo-patches/cfg-if-1.0.0")
        );
    }

    #[test]
    fn test_upsert_refuses_user_authored_same_name() {
        let toml = "[patch.crates-io]\ncfg-if = { git = \"https://example.com/c.git\" }\n";
        assert!(upsert_patch_entry(toml, "cfg-if", "1.0.0").is_err());
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_version_bump() {
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.0\" }\n";
        let out = upsert_patch_entry(toml, "cfg-if", "1.0.1")
            .unwrap()
            .unwrap();
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(".socket/cargo-patches/cfg-if-1.0.1")
        );
    }

    // ── remove ───────────────────────────────────────────────────────
    #[test]
    fn test_remove_socket_owned_cleans_empty_tables() {
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.0\" }\n";
        let out = remove_patch_entry(toml, "cfg-if").unwrap().unwrap();
        assert!(!out.contains("cfg-if"));
        // Empty [patch.crates-io] and [patch] are pruned.
        assert!(!out.contains("[patch"));
    }

    #[test]
    fn test_remove_leaves_user_entry_and_table() {
        let toml = "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.0\" }\nother = { git = \"https://example.com/o.git\" }\n";
        let out = remove_patch_entry(toml, "cfg-if").unwrap().unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_none());
        assert!(doc["patch"]["crates-io"].get("other").is_some());
    }

    #[test]
    fn test_remove_user_authored_same_name_is_noop() {
        let toml = "[patch.crates-io]\ncfg-if = { git = \"https://example.com/c.git\" }\n";
        assert!(remove_patch_entry(toml, "cfg-if").unwrap().is_none());
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(remove_patch_entry("[build]\njobs = 2\n", "cfg-if")
            .unwrap()
            .is_none());
    }

    // ── env root ─────────────────────────────────────────────────────
    #[test]
    fn test_env_root_upsert_relative() {
        let out = upsert_env_root("").unwrap().unwrap();
        let doc = parse(&out);
        let env = doc["env"][ENV_ROOT_KEY].as_table_like().unwrap();
        assert_eq!(env.get("value").and_then(Item::as_str), Some("."));
        assert_eq!(env.get("relative").and_then(Item::as_bool), Some(true));
        // Idempotent.
        assert!(upsert_env_root(&out).unwrap().is_none());
    }

    #[test]
    fn test_env_root_remove_leaves_other_keys() {
        let toml =
            "[env]\nMY_VAR = \"x\"\nSOCKET_PATCH_ROOT = { value = \".socket\", relative = true }\n";
        let out = remove_env_root(toml).unwrap().unwrap();
        let doc = parse(&out);
        assert!(doc["env"].get(ENV_ROOT_KEY).is_none());
        assert_eq!(doc["env"]["MY_VAR"].as_str(), Some("x"));
    }

    #[test]
    fn test_env_root_remove_prunes_empty_table() {
        let toml = "[env]\nSOCKET_PATCH_ROOT = { value = \".socket\", relative = true }\n";
        let out = remove_env_root(toml).unwrap().unwrap();
        assert!(!out.contains("[env]"));
    }

    // ── read_patch_entries / parse ───────────────────────────────────
    #[test]
    fn test_parse_entries_classifies_ownership() {
        let toml = "[patch.crates-io]\nmine = { path = \".socket/cargo-patches/mine-1.0.0\" }\nyours = { git = \"https://example.com/y.git\" }\ntheirs = { path = \"vendor/theirs\" }\n";
        let entries = parse_patch_entries(toml);
        assert!(entries["mine"].socket_owned);
        assert!(!entries["yours"].socket_owned);
        assert_eq!(entries["yours"].path, None);
        assert!(!entries["theirs"].socket_owned);
        assert_eq!(entries["theirs"].path.as_deref(), Some("vendor/theirs"));
    }

    #[test]
    fn test_parse_entries_handles_subtable_form() {
        let toml = "[patch.crates-io.mine]\npath = \".socket/cargo-patches/mine-1.0.0\"\n";
        let entries = parse_patch_entries(toml);
        assert!(entries["mine"].socket_owned);
    }

    #[test]
    fn test_parse_malformed_is_empty() {
        assert!(parse_patch_entries("this is = = not toml [[[").is_empty());
    }

    // ── formatting preservation ──────────────────────────────────────
    #[test]
    fn test_comments_and_indentation_preserved() {
        // `.cargo/config.toml` is a managed file; toml_edit faithfully keeps
        // comments and unrelated tables (it does NOT promise CRLF round-trips,
        // which is harmless for a generated config).
        let toml = "# socket-managed config\n[net]\nretry = 3   # keep retries\n";
        let out = upsert_patch_entry(toml, "cfg-if", "1.0.0")
            .unwrap()
            .unwrap();
        assert!(out.contains("# socket-managed config"));
        assert!(out.contains("retry = 3   # keep retries"));
        assert!(parse(&out)["patch"]["crates-io"].get("cfg-if").is_some());
    }

    // ── async wrappers ───────────────────────────────────────────────
    #[tokio::test]
    async fn test_ensure_dry_run_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let changed = ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", true)
            .await
            .unwrap();
        assert!(changed, "dry-run reports the change it would make");
        assert!(
            !dir.path().join(".cargo/config.toml").exists(),
            "dry-run must not create the file"
        );
    }

    #[tokio::test]
    async fn test_ensure_then_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", false)
            .await
            .unwrap());
        assert!(ensure_env_root(dir.path(), false).await.unwrap());
        let entries = read_patch_entries(dir.path()).await;
        assert!(entries["cfg-if"].socket_owned);
        assert_eq!(
            entries["cfg-if"].path.as_deref(),
            Some(".socket/cargo-patches/cfg-if-1.0.0")
        );
        // Re-running is a no-op (idempotent on disk).
        assert!(!ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", false)
            .await
            .unwrap());
        // Drop everything.
        assert!(drop_patch_entry(dir.path(), "cfg-if", false).await.unwrap());
        assert!(drop_env_root(dir.path(), false).await.unwrap());
        assert!(read_patch_entries(dir.path()).await.is_empty());
    }

    #[tokio::test]
    async fn test_prefers_existing_legacy_config() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        // Only a legacy `config` (no extension) exists.
        fs::write(cargo_dir.join("config"), "[build]\njobs = 2\n")
            .await
            .unwrap();
        assert!(ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", false)
            .await
            .unwrap());
        // We wrote into the legacy file, not a fresh config.toml.
        assert!(!cargo_dir.join("config.toml").exists());
        let body = fs::read_to_string(cargo_dir.join("config")).await.unwrap();
        assert!(body.contains("cfg-if"));
        assert!(body.contains("jobs = 2"));
    }

    // ── exact-restore: emptied socket-created config is deleted (property 8) ──
    #[tokio::test]
    async fn test_drop_env_root_deletes_socket_created_config_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        // No `.cargo/` before setup.
        assert!(!dir.path().join(".cargo").exists());
        // setup creates `.cargo/config.toml` holding only [env] SOCKET_PATCH_ROOT.
        assert!(ensure_env_root(dir.path(), false).await.unwrap());
        assert!(dir.path().join(".cargo/config.toml").exists());
        // remove empties it → both the file and the now-empty `.cargo/` are gone.
        assert!(drop_env_root(dir.path(), false).await.unwrap());
        assert!(
            !dir.path().join(".cargo/config.toml").exists(),
            "an emptied socket-created config must be deleted, not left empty"
        );
        assert!(
            !dir.path().join(".cargo").exists(),
            "the now-empty .cargo/ dir must be pruned"
        );
    }

    #[tokio::test]
    async fn test_drop_env_root_keeps_config_with_user_content() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        // A user config carrying a [build] table alongside our env entry.
        fs::write(
            cargo_dir.join("config.toml"),
            "[build]\njobs = 4\n\n[env]\nSOCKET_PATCH_ROOT = { value = \".\", relative = true }\n",
        )
        .await
        .unwrap();
        assert!(drop_env_root(dir.path(), false).await.unwrap());
        // The file survives (user content remains); only our key is gone.
        let body = fs::read_to_string(cargo_dir.join("config.toml")).await.unwrap();
        assert!(body.contains("jobs = 4"), "user [build] table must be preserved");
        assert!(!body.contains("SOCKET_PATCH_ROOT"));
    }

    // ── atomic-commit: stage+rename leaves no litter, never truncates ────────
    /// List the non-hidden-temp entries left under `.cargo/` after a commit. The
    /// atomic writer stages a `.socket-stage-*` sibling and renames it over the
    /// target; if any stage file survives, the commit aborted mid-flight (or the
    /// rename was actually a copy) — both are litter the user would have to clean.
    async fn stage_litter(cargo_dir: &Path) -> Vec<String> {
        let mut names = Vec::new();
        let mut rd = fs::read_dir(cargo_dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.contains("socket-stage") {
                names.push(n);
            }
        }
        names
    }

    #[tokio::test]
    async fn test_commit_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", false)
            .await
            .unwrap());
        let cargo_dir = dir.path().join(".cargo");
        assert!(
            stage_litter(&cargo_dir).await.is_empty(),
            "create-path commit must rename the stage file away, not leave it"
        );
        // A second, mutating upsert (version bump) must also clean up after itself.
        assert!(ensure_patch_entry(dir.path(), "cfg-if", "1.0.1", false)
            .await
            .unwrap());
        assert!(
            stage_litter(&cargo_dir).await.is_empty(),
            "overwrite-path commit must rename the stage file away, not leave it"
        );
    }

    #[tokio::test]
    async fn test_commit_overwrites_existing_user_config_in_place() {
        // The dangerous case the atomic writer protects: an existing user config
        // we must edit in place. A non-atomic truncate-then-write would risk
        // leaving this empty on a crash; here we assert the user content survives
        // and the new entry lands, with no stage file left behind.
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "# user comment\n[build]\njobs = 7\n\n[net]\nretry = 5\n",
        )
        .await
        .unwrap();

        assert!(ensure_patch_entry(dir.path(), "cfg-if", "1.0.0", false)
            .await
            .unwrap());

        let body = fs::read_to_string(cargo_dir.join("config.toml"))
            .await
            .unwrap();
        assert!(body.contains("# user comment"), "comment preserved");
        assert!(body.contains("jobs = 7"), "[build] preserved");
        assert!(body.contains("retry = 5"), "[net] preserved");
        assert!(body.contains("cfg-if"), "our entry was added");
        assert!(
            stage_litter(&cargo_dir).await.is_empty(),
            "in-place overwrite must not leave a stage file"
        );
    }

    #[tokio::test]
    async fn test_drop_env_root_keeps_nonempty_cargo_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        // A sibling file (e.g. credentials) means `.cargo/` must survive even
        // though our config is emptied + deleted.
        fs::write(cargo_dir.join("credentials.toml"), "[registry]\ntoken = \"x\"\n")
            .await
            .unwrap();
        assert!(ensure_env_root(dir.path(), false).await.unwrap());
        assert!(drop_env_root(dir.path(), false).await.unwrap());
        assert!(
            !cargo_dir.join("config.toml").exists(),
            "emptied config is deleted"
        );
        assert!(
            cargo_dir.exists() && cargo_dir.join("credentials.toml").exists(),
            ".cargo/ is kept because it still holds the user's credentials file"
        );
    }
}
