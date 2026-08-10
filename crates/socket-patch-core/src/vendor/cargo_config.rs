//! Read / write `<project_root>/.cargo/config.toml` for the cargo vendor
//! backend's `[patch.crates-io]` wiring.
//!
//! Mirrors the contract style of [`crate::pth_hook::edit`]: pure
//! `fn(&str) -> Result<Option<String>, String>` transforms (`Some(new)` =
//! changed, `None` = already in the desired state) wrapped by async
//! read-or-create / write helpers that honour `dry_run` and preserve the
//! user's existing formatting + comments via `toml_edit`.
//!
//! ## Ownership model (no sidecar manifest)
//! A `[patch.crates-io]` entry is *socket-owned* iff its `path` value lies
//! under `.socket/vendor/cargo/` (this backend's committed copies) **or** the
//! legacy `.socket/cargo-patches/` (the retired `[patch]`-redirect backend) —
//! recognising the legacy prefix lets vendor take over / clean up entries left
//! by old releases instead of refusing them as user-authored. Anything else —
//! a `git`/`registry` source, or a `path` pointing elsewhere — is
//! user-authored and is never modified or removed. The path prefix is the
//! entire ownership signal; there is no `managed.json`.
//!
//! ## Relative-path semantics
//! A relative `path` in a config-file `[patch]` entry is resolved by cargo
//! relative to the **parent of the `.cargo/` directory** (i.e. the project
//! root), so the committed `<root>/.socket/vendor/cargo/<uuid>/<name>-<ver>`
//! copy is found on any clone (spike-verified, including builds invoked from a
//! subdirectory — see `spikes/PHASE0-FINDINGS.txt` cargo claim 7).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::fs;
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

use crate::pth_hook::edit::ensure_table;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

/// Project-relative root of the vendor backend's committed crate copies. An
/// entry whose `path` is under this prefix is socket-owned.
const CARGO_VENDOR_DIR: &str = ".socket/vendor/cargo";

/// Project-relative root of the retired `[patch]`-redirect backend's copies.
/// Entries under this prefix are still recognised as socket-owned so vendor
/// can rewrite (take over) or drop residue from old releases rather than
/// refusing it as user-authored.
pub const LEGACY_CARGO_PATCHES_DIR: &str = ".socket/cargo-patches";

/// Info about one `[patch.crates-io]` entry, for vendor pre-flight / verify.
#[derive(Debug, Clone)]
pub struct PatchEntryInfo {
    /// The `path` value as written (verbatim), or `None` for a non-path
    /// source (e.g. `git`/`registry`).
    pub path: Option<String>,
    /// True iff `path` is under `CARGO_VENDOR_DIR` or
    /// [`LEGACY_CARGO_PATCHES_DIR`].
    pub socket_owned: bool,
}

// ── public async API ─────────────────────────────────────────────────────────

/// Upsert `[patch.crates-io].<name> = { path = "<rel_path>" }`, where
/// `rel_path` is the project-relative copy path
/// (`.socket/vendor/cargo/<uuid>/<name>-<version>`). Idempotent. A
/// socket-owned same-name entry (either prefix) is refreshed in place — the
/// legacy-prefix rewrite is how vendor takes over an old redirect entry.
/// Returns whether the file changed. Errors (without writing) if a same-name
/// entry exists but is user-authored.
pub async fn ensure_patch_entry(
    project_root: &Path,
    name: &str,
    rel_path: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_config(project_root, dry_run, |c| {
        upsert_patch_entry(c, name, rel_path)
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

/// Read all `[patch.crates-io]` entries. Read-only; a missing or malformed
/// config yields an empty map (callers treat that as "no managed entries").
pub async fn read_patch_entries(project_root: &Path) -> HashMap<String, PatchEntryInfo> {
    let path = config_path(project_root).await;
    match fs::read_to_string(&path).await {
        Ok(content) => parse_patch_entries(&content),
        Err(_) => HashMap::new(),
    }
}

// ── config-file resolution + read-or-create write ────────────────────────────

/// Resolve the config file under `<project_root>/.cargo/`. Prefers an existing
/// legacy `config`: when both files exist cargo reads the one WITHOUT the
/// extension (and warns) — writing into `config.toml` there would leave the
/// `[patch]` entry silently inert. Falls back to an existing `config.toml`,
/// else `config.toml` (created on first write).
async fn config_path(project_root: &Path) -> PathBuf {
    let dir = project_root.join(".cargo");
    let legacy = dir.join("config");
    if fs::metadata(&legacy).await.is_ok() {
        return legacy;
    }
    dir.join("config.toml")
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
                    // The edit emptied the file (all socket-owned content
                    // removed and no user content — comments / other tables —
                    // remained). Delete it, and prune the now-empty `.cargo/`
                    // dir, so a full revert restores the exact pre-vendor tree
                    // rather than leaving an empty `.cargo/config.toml`
                    // behind. A file with surviving user content never trims
                    // to empty, so this only fires for a config that was
                    // entirely socket's.
                    match fs::remove_file(&path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("remove {}: {e}", path.display())),
                    }
                    if let Some(parent) = path.parent() {
                        // Best-effort: `remove_dir` only succeeds when the dir
                        // is empty, so a `.cargo/` holding other files (e.g.
                        // credentials) is left intact.
                        let _ = fs::remove_dir(parent).await;
                    }
                } else {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)
                            .await
                            .map_err(|e| format!("create {}: {e}", parent.display()))?;
                    }
                    // `.cargo/config.toml` is a *user-owned* file — it can hold
                    // `[build]`, `[net]`, credentials-adjacent settings, and
                    // comments alongside our `[patch]` entries. Commit
                    // atomically (stage + fsync + rename) so a crash mid-write
                    // can never truncate content we only meant to add one
                    // entry to — and keep the destination's permission bits
                    // (the rename would otherwise reset them to the fresh
                    // stage inode's default).
                    atomic_write_bytes_preserving_mode(&path, new.as_bytes())
                        .await
                        .map_err(|e| format!("write {}: {e}", path.display()))?;
                }
            }
            Ok(true)
        }
    }
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// True if a `[patch]` `path` value lies under a socket-owned prefix
/// ([`CARGO_VENDOR_DIR`] or the legacy [`LEGACY_CARGO_PATCHES_DIR`]).
fn path_is_socket_owned(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    for dir in [CARGO_VENDOR_DIR, LEGACY_CARGO_PATCHES_DIR] {
        let prefix = format!("{dir}/");
        if norm.starts_with(&prefix) || norm.contains(&format!("/{prefix}")) {
            return true;
        }
    }
    false
}

/// The `path` string of a `[patch]` entry (inline table or sub-table), if any.
fn entry_path(item: &Item) -> Option<&str> {
    item.as_table_like()
        .and_then(|t| t.get("path"))
        .and_then(Item::as_str)
}

fn upsert_patch_entry(content: &str, name: &str, rel_path: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;

    let root = doc.as_table_mut();
    // `[patch]` is a parent table that only ever holds `[patch.crates-io]`, so
    // keep it implicit; `[patch.crates-io]` is the explicit one we write into.
    let patch = ensure_table(root, "patch", true)?;
    let crates_io = ensure_table(patch, "crates-io", false)?;

    if let Some(existing) = crates_io.get(name) {
        match entry_path(existing) {
            Some(p) if p == rel_path => return Ok(None), // already correct
            Some(p) if path_is_socket_owned(p) => {}     // socket-owned, refresh
            _ => {
                return Err(format!(
                    "`patch.crates-io.{name}` is user-authored; refusing to overwrite"
                ));
            }
        }
    }

    let mut it = InlineTable::new();
    it.insert("path", Value::from(rel_path));
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

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn vendor_path(name: &str, version: &str) -> String {
        format!("{CARGO_VENDOR_DIR}/{UUID}/{name}-{version}")
    }

    fn parse(s: &str) -> DocumentMut {
        s.parse::<DocumentMut>().unwrap()
    }

    // ── path ownership ───────────────────────────────────────────────
    #[test]
    fn test_is_socket_owned() {
        assert!(path_is_socket_owned(&vendor_path("cfg-if", "1.0.4")));
        assert!(path_is_socket_owned("./.socket/vendor/cargo/u/x-1.0.0")); // contains "/.socket/…"
        assert!(path_is_socket_owned("sub/.socket/vendor/cargo/u/x-1.0.0"));
        assert!(path_is_socket_owned(r".socket\vendor\cargo\u\x-1.0.0")); // backslash normalised
                                                                          // Legacy redirect copies are recognised as ours (takeover / cleanup).
        assert!(path_is_socket_owned(".socket/cargo-patches/cfg-if-1.0.0"));
        assert!(path_is_socket_owned("./.socket/cargo-patches/x-1.0.0"));
        // User paths are not.
        assert!(!path_is_socket_owned("vendor/cfg-if"));
        assert!(!path_is_socket_owned("../cfg-if"));
        assert!(!path_is_socket_owned("/abs/.socketX/vendor/cargo/x"));
        // Other ecosystems' vendor dirs are not cargo-owned entries.
        assert!(!path_is_socket_owned(".socket/vendor/npm/u/x.tgz"));
    }

    // ── upsert ───────────────────────────────────────────────────────
    #[test]
    fn test_upsert_into_empty_creates_entry() {
        let want = vendor_path("cfg-if", "1.0.4");
        let out = upsert_patch_entry("", "cfg-if", &want).unwrap().unwrap();
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(want.as_str())
        );
        // Idempotent: a second upsert is a no-op.
        assert!(upsert_patch_entry(&out, "cfg-if", &want).unwrap().is_none());
    }

    #[test]
    fn test_upsert_preserves_user_content() {
        let toml = "# my config\n[build]\njobs = 4\n\n[patch.crates-io]\nother = { git = \"https://example.com/o.git\" }\n";
        let want = vendor_path("cfg-if", "1.0.4");
        let out = upsert_patch_entry(toml, "cfg-if", &want).unwrap().unwrap();
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
            Some(want.as_str())
        );
    }

    #[test]
    fn test_upsert_refuses_user_authored_same_name() {
        let toml = "[patch.crates-io]\ncfg-if = { git = \"https://example.com/c.git\" }\n";
        assert!(upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4")).is_err());
        // A user path entry (not under a socket prefix) is equally protected.
        let toml = "[patch.crates-io]\ncfg-if = { path = \"../my-fork\" }\n";
        assert!(upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4")).is_err());
    }

    #[test]
    fn test_upsert_refreshes_socket_owned_uuid_bump() {
        // A patch update changes the uuid level of the path; the entry is
        // refreshed in place.
        let old = format!("{CARGO_VENDOR_DIR}/11111111-2222-3333-4444-555555555555/cfg-if-1.0.4");
        let toml = format!("[patch.crates-io]\ncfg-if = {{ path = \"{old}\" }}\n");
        let want = vendor_path("cfg-if", "1.0.4");
        let out = upsert_patch_entry(&toml, "cfg-if", &want).unwrap().unwrap();
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(want.as_str())
        );
    }

    #[test]
    fn test_upsert_takes_over_legacy_redirect_entry() {
        // An entry left by the retired redirect backend is socket-owned →
        // rewritten to the vendor copy, never refused.
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n";
        let want = vendor_path("cfg-if", "1.0.4");
        let out = upsert_patch_entry(toml, "cfg-if", &want).unwrap().unwrap();
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(want.as_str())
        );
        assert!(!out.contains("cargo-patches"), "legacy path gone");
    }

    // ── remove ───────────────────────────────────────────────────────
    #[test]
    fn test_remove_socket_owned_cleans_empty_tables() {
        let toml = format!(
            "[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entry(&toml, "cfg-if").unwrap().unwrap();
        assert!(!out.contains("cfg-if"));
        // Empty [patch.crates-io] and [patch] are pruned.
        assert!(!out.contains("[patch"));
    }

    #[test]
    fn test_remove_legacy_entry_is_socket_owned() {
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n";
        let out = remove_patch_entry(toml, "cfg-if").unwrap().unwrap();
        assert!(!out.contains("cfg-if"), "legacy entry removable: {out}");
    }

    #[test]
    fn test_remove_leaves_user_entry_and_table() {
        let toml = format!(
            "[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\nother = {{ git = \"https://example.com/o.git\" }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entry(&toml, "cfg-if").unwrap().unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_none());
        assert!(doc["patch"]["crates-io"].get("other").is_some());
    }

    #[test]
    fn test_remove_user_authored_same_name_is_noop() {
        let toml = "[patch.crates-io]\ncfg-if = { git = \"https://example.com/c.git\" }\n";
        assert!(remove_patch_entry(toml, "cfg-if").unwrap().is_none());
        let toml = "[patch.crates-io]\ncfg-if = { path = \"../my-fork\" }\n";
        assert!(remove_patch_entry(toml, "cfg-if").unwrap().is_none());
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(remove_patch_entry("[build]\njobs = 2\n", "cfg-if")
            .unwrap()
            .is_none());
    }

    // ── read_patch_entries / parse ───────────────────────────────────
    #[test]
    fn test_parse_entries_classifies_ownership() {
        let toml = format!(
            "[patch.crates-io]\nmine = {{ path = \"{}\" }}\nlegacy = {{ path = \".socket/cargo-patches/legacy-1.0.0\" }}\nyours = {{ git = \"https://example.com/y.git\" }}\ntheirs = {{ path = \"vendor/theirs\" }}\n",
            vendor_path("mine", "1.0.0")
        );
        let entries = parse_patch_entries(&toml);
        assert!(entries["mine"].socket_owned);
        assert!(entries["legacy"].socket_owned, "legacy prefix is ours");
        assert!(!entries["yours"].socket_owned);
        assert_eq!(entries["yours"].path, None);
        assert!(!entries["theirs"].socket_owned);
        assert_eq!(entries["theirs"].path.as_deref(), Some("vendor/theirs"));
    }

    #[test]
    fn test_parse_entries_handles_subtable_form() {
        let toml = format!(
            "[patch.crates-io.mine]\npath = \"{}\"\n",
            vendor_path("mine", "1.0.0")
        );
        let entries = parse_patch_entries(&toml);
        assert!(entries["mine"].socket_owned);
    }

    #[test]
    fn test_parse_malformed_is_empty() {
        assert!(parse_patch_entries("this is = = not toml [[[").is_empty());
    }

    // ── formatting preservation ──────────────────────────────────────
    #[test]
    fn test_comments_and_indentation_preserved() {
        let toml = "# socket-managed config\n[net]\nretry = 3   # keep retries\n";
        let out = upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4"))
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
        let changed =
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), true)
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
        let want = vendor_path("cfg-if", "1.0.4");
        assert!(ensure_patch_entry(dir.path(), "cfg-if", &want, false)
            .await
            .unwrap());
        let entries = read_patch_entries(dir.path()).await;
        assert!(entries["cfg-if"].socket_owned);
        assert_eq!(entries["cfg-if"].path.as_deref(), Some(want.as_str()));
        // Re-running is a no-op (idempotent on disk).
        assert!(!ensure_patch_entry(dir.path(), "cfg-if", &want, false)
            .await
            .unwrap());
        // Drop it.
        assert!(drop_patch_entry(dir.path(), "cfg-if", false).await.unwrap());
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
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        // We wrote into the legacy file, not a fresh config.toml.
        assert!(!cargo_dir.join("config.toml").exists());
        let body = fs::read_to_string(cargo_dir.join("config")).await.unwrap();
        assert!(body.contains("cfg-if"));
        assert!(body.contains("jobs = 2"));
    }

    #[tokio::test]
    async fn test_prefers_legacy_config_when_both_exist() {
        // cargo warns "both `.cargo/config` and `.cargo/config.toml` exist.
        // Using `.cargo/config`" — when both are present the entry must land
        // in the file cargo actually reads, or the patch is silently inert.
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        fs::write(cargo_dir.join("config"), "[build]\njobs = 2\n")
            .await
            .unwrap();
        fs::write(cargo_dir.join("config.toml"), "[net]\nretry = 3\n")
            .await
            .unwrap();
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        let legacy = fs::read_to_string(cargo_dir.join("config")).await.unwrap();
        assert!(
            legacy.contains("cfg-if"),
            "entry must go into the file cargo uses: {legacy}"
        );
        let toml = fs::read_to_string(cargo_dir.join("config.toml"))
            .await
            .unwrap();
        assert!(
            !toml.contains("cfg-if"),
            "config.toml is ignored by cargo while `config` exists; must stay untouched"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_edit_preserves_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        let cfg = cargo_dir.join("config.toml");
        fs::write(&cfg, "[build]\njobs = 4\n").await.unwrap();
        // 0o640 never matches a fresh-inode default (0666 & !umask is one of
        // 600/644/664/666), so a writer that drops the destination's bits is
        // caught under any umask.
        fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        let mode = fs::metadata(&cfg).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "editing a user-owned config must not reset its permission bits"
        );
    }

    // ── exact-restore: emptied socket-created config is deleted ──────
    #[tokio::test]
    async fn test_drop_deletes_socket_created_config_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        // No `.cargo/` before vendoring.
        assert!(!dir.path().join(".cargo").exists());
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        assert!(dir.path().join(".cargo/config.toml").exists());
        // Revert empties it → both the file and the now-empty `.cargo/` go.
        assert!(drop_patch_entry(dir.path(), "cfg-if", false).await.unwrap());
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
    async fn test_drop_keeps_config_with_user_content() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            format!(
                "[build]\njobs = 4\n\n[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\n",
                vendor_path("cfg-if", "1.0.4")
            ),
        )
        .await
        .unwrap();
        assert!(drop_patch_entry(dir.path(), "cfg-if", false).await.unwrap());
        // The file survives (user content remains); only our entry is gone.
        let body = fs::read_to_string(cargo_dir.join("config.toml"))
            .await
            .unwrap();
        assert!(body.contains("jobs = 4"), "user [build] table preserved");
        assert!(!body.contains("cfg-if"));
    }

    #[tokio::test]
    async fn test_drop_keeps_nonempty_cargo_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        // A sibling file (e.g. credentials) means `.cargo/` must survive even
        // though our config is emptied + deleted.
        fs::write(
            cargo_dir.join("credentials.toml"),
            "[registry]\ntoken = \"x\"\n",
        )
        .await
        .unwrap();
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        assert!(drop_patch_entry(dir.path(), "cfg-if", false).await.unwrap());
        assert!(
            !cargo_dir.join("config.toml").exists(),
            "emptied config is deleted"
        );
        assert!(
            cargo_dir.exists() && cargo_dir.join("credentials.toml").exists(),
            ".cargo/ is kept because it still holds the user's credentials file"
        );
    }

    // ── atomic-commit: stage+rename leaves no litter, never truncates ─
    /// List socket stage-file litter left under `.cargo/` after a commit. The
    /// atomic writer stages a sibling and renames it over the target; if any
    /// stage file survives, the commit aborted mid-flight (or the rename was
    /// actually a copy) — both are litter the user would have to clean.
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
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        let cargo_dir = dir.path().join(".cargo");
        assert!(
            stage_litter(&cargo_dir).await.is_empty(),
            "create-path commit must rename the stage file away, not leave it"
        );
        // A second, mutating upsert (uuid bump) must also clean up.
        let bumped =
            format!("{CARGO_VENDOR_DIR}/11111111-2222-3333-4444-555555555555/cfg-if-1.0.4");
        assert!(ensure_patch_entry(dir.path(), "cfg-if", &bumped, false)
            .await
            .unwrap());
        assert!(
            stage_litter(&cargo_dir).await.is_empty(),
            "overwrite-path commit must rename the stage file away, not leave it"
        );
    }

    #[tokio::test]
    async fn test_commit_overwrites_existing_user_config_in_place() {
        // The dangerous case the atomic writer protects: an existing user
        // config we must edit in place. A non-atomic truncate-then-write would
        // risk leaving this empty on a crash; here we assert the user content
        // survives and the new entry lands, with no stage file left behind.
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "# user comment\n[build]\njobs = 7\n\n[net]\nretry = 5\n",
        )
        .await
        .unwrap();

        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );

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
}
