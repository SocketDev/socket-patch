//! Read / write `<project_root>/.cargo/config.toml` for the cargo vendor
//! backend's `[patch.crates-io]` wiring.
//!
//! Mirrors the contract style of [`crate::setup::pypi::edit`]: pure
//! `fn(&str) -> Result<Option<String>, String>` transforms (`Some(new)` =
//! changed, `None` = already in the desired state) wrapped by async
//! read-or-create / write helpers that honour `dry_run` and preserve the
//! user's existing formatting + comments via `toml_edit`.
//!
//! ## Ownership model (no sidecar manifest)
//! A `[patch.crates-io]` entry is *socket-owned* iff its `path` value is a
//! root-anchored relative path (not absolute, no `..`) under THIS project's
//! `.socket/vendor/cargo/` (this backend's committed copies) **or** the
//! legacy `.socket/cargo-patches/` (the retired `[patch]`-redirect backend) —
//! recognising the legacy prefix lets vendor take over / clean up entries left
//! by old releases instead of refusing them as user-authored. Anything else —
//! a `git`/`registry` source, or a `path` pointing elsewhere (including one
//! that merely traverses a *foreign* checkout's `.socket/vendor/cargo/`) — is
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
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

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

/// Guarded read shared in shape with the vendor/cargo.rs + setup twins:
/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular files,
/// so a FIFO planted as `.cargo/config(.toml)` fails fast instead of wedging
/// scan / vendor apply forever in an `open(2)` that waits for a writer.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// Read all `[patch.crates-io]` entries. Read-only; a missing or malformed
/// config yields an empty map (callers treat that as "no managed entries").
pub async fn read_patch_entries(project_root: &Path) -> HashMap<String, PatchEntryInfo> {
    let path = config_path(project_root).await;
    match read_regular_to_string(&path).await {
        Ok(content) => parse_patch_entries(&content),
        Err(_) => HashMap::new(),
    }
}

/// The hosted-mode `[registries.socket-patch-<uuid>]` sparse-index URLs
/// declared in the project's cargo config, as `(registry_name, index_url)`
/// pairs. Reads BOTH `.cargo/config` and `.cargo/config.toml` (a mixed /
/// legacy state may hold blocks in either file). Read-only; missing or
/// malformed files contribute nothing. This is how takeover logic proves a
/// `Cargo.lock` `source` points at Socket's hosted patch registry without
/// depending on the index URL's host (test registries are localhost).
pub async fn socket_registry_indexes(project_root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for file in [".cargo/config", ".cargo/config.toml"] {
        let Ok(content) = read_regular_to_string(&project_root.join(file)).await else {
            continue;
        };
        let Ok(doc) = content.parse::<DocumentMut>() else {
            continue;
        };
        let Some(registries) = doc.get("registries").and_then(Item::as_table_like) else {
            continue;
        };
        for (name, item) in registries.iter() {
            if !name.starts_with("socket-patch-") {
                continue;
            }
            let index = item
                .as_table_like()
                .and_then(|t| t.get("index"))
                .and_then(Item::as_str);
            if let Some(index) = index {
                out.push((name.to_string(), index.to_string()));
            }
        }
    }
    out
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
    // Guarded read: a FIFO/device/directory squatting the config path errors
    // here (`InvalidInput`) rather than blocking, and is never mistaken for
    // an empty config to rename a fresh file over.
    let content = match read_regular_to_string(&path).await {
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

/// True if a `[patch]` `path` value denotes one of THIS project's
/// socket-owned copies: a relative path that escapes nothing (not absolute,
/// no `..` segment) and sits under [`CARGO_VENDOR_DIR`] or the legacy
/// [`LEGACY_CARGO_PATCHES_DIR`]. Cargo resolves relative `[patch]` paths
/// against the project root, so only a root-anchored relative prefix can be a
/// copy this backend wrote — a path that merely *traverses* some other
/// checkout's `.socket/vendor/cargo/` (`../shared/.socket/vendor/cargo/…`,
/// `/abs/.socket/vendor/cargo/…`, `sub/.socket/vendor/cargo/…`) is
/// user-authored and must never be rewritten or removed.
fn path_is_socket_owned(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    if norm.starts_with('/') {
        return false; // absolute (also covers //unc-style prefixes)
    }
    if norm.as_bytes().get(1) == Some(&b':') {
        return false; // Windows drive-letter absolute (C:/…)
    }
    let segments: Vec<&str> = norm
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if segments.contains(&"..") {
        return false;
    }
    [CARGO_VENDOR_DIR, LEGACY_CARGO_PATCHES_DIR]
        .iter()
        .any(|dir| {
            let prefix: Vec<&str> = dir.split('/').collect();
            segments.len() > prefix.len() && segments[..prefix.len()] == prefix[..]
        })
}

/// The `path` string of a `[patch]` entry (inline table or sub-table), if any.
fn entry_path(item: &Item) -> Option<&str> {
    item.as_table_like()
        .and_then(|t| t.get("path"))
        .and_then(Item::as_str)
}

/// `parent[key]` as a mutable table-like view, creating a (header) table if
/// absent. Like `toml_edit_ext::ensure_table` but tolerant of an existing
/// inline-table value — `[patch]` + `crates-io = { … }` is valid TOML that
/// cargo honors identically to `[patch.crates-io]` (a hand edit or another
/// tool re-serializing this user-owned file produces it), and refusing it
/// would strand the socket-owned entries inside. Errors on a non-table item.
fn ensure_table_like<'a>(
    parent: &'a mut dyn TableLike,
    key: &str,
    implicit: bool,
) -> Result<&'a mut dyn TableLike, String> {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(implicit);
        // An inline-table parent converts this to an inline value on insert,
        // preserving the user's inline style.
        parent.insert(key, Item::Table(t));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn upsert_patch_entry(content: &str, name: &str, rel_path: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?;

    let root = doc.as_table_mut();
    // `[patch]` is a parent table that only ever holds `[patch.crates-io]`, so
    // keep it implicit; `[patch.crates-io]` is the explicit one we write into.
    let patch = ensure_table_like(root, "patch", true)?;
    let crates_io = ensure_table_like(patch, "crates-io", false)?;

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
    // Table-like views (as in `entry_path`): the inline `crates-io = { … }`
    // form is honored by cargo, and a remove blind to it would leave the
    // entry dangling after the vendor copy it points at is deleted.
    if let Some(patch) = doc.get_mut("patch").and_then(Item::as_table_like_mut) {
        let mut crates_io_empty = false;
        if let Some(crates_io) = patch.get_mut("crates-io").and_then(Item::as_table_like_mut) {
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
        .and_then(Item::as_table_like)
        .map(|t| t.is_empty())
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
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("crates-io"))
        .and_then(Item::as_table_like);
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
        assert!(path_is_socket_owned("./.socket/vendor/cargo/u/x-1.0.0")); // "." segment normalised
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

    /// AUDIT B4: only a root-anchored relative path can be a copy this
    /// backend wrote (cargo resolves relative `[patch]` paths against the
    /// project root). A path that merely TRAVERSES some other checkout's
    /// `.socket/vendor/cargo/` — via `..`, an absolute prefix, or a nested
    /// sub-checkout — is user-authored and must never be classified ours.
    #[test]
    fn test_foreign_socket_paths_are_user_authored() {
        // Sibling checkout, reached with `..`.
        assert!(!path_is_socket_owned(
            "../other-checkout/.socket/vendor/cargo/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/x-1.0.0"
        ));
        // Absolute paths (unix, and Windows drive-letter form).
        assert!(!path_is_socket_owned(
            "/home/u/shared/.socket/vendor/cargo/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/x-1.0.0"
        ));
        assert!(!path_is_socket_owned(
            r"C:\shared\.socket\vendor\cargo\u\x-1.0.0"
        ));
        // A `..` INSIDE the owned prefix escapes it.
        assert!(!path_is_socket_owned(".socket/vendor/cargo/../../../etc"));
        assert!(!path_is_socket_owned(".socket/cargo-patches/../../secrets"));
        // A nested sub-checkout's socket dir is not THIS project's.
        assert!(!path_is_socket_owned("sub/.socket/vendor/cargo/u/x-1.0.0"));
        // The bare owned dir itself (no copy segment) is not an entry we write.
        assert!(!path_is_socket_owned(".socket/vendor/cargo"));
    }

    /// AUDIT B4: a user-authored entry pointing through a foreign checkout's
    /// socket dir must be a remove no-op — never deleted on revert.
    #[test]
    fn test_remove_foreign_socket_path_entry_is_noop() {
        let toml = "[patch.crates-io]\ncfg-if = { path = \"../other-checkout/.socket/vendor/cargo/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/cfg-if-1.0.4\" }\n";
        let out = remove_patch_entry(toml, "cfg-if").unwrap();
        assert!(
            out.is_none(),
            "user entry must be a no-op, but it was removed: {out:?}"
        );
    }

    /// AUDIT B4: ...and an upsert over it must refuse, never overwrite.
    #[test]
    fn test_upsert_refuses_foreign_socket_path_entry() {
        let toml = "[patch.crates-io]\ncfg-if = { path = \"../shared-fork/.socket/vendor/cargo/99999999-9999-9999-9999-999999999999/cfg-if-1.0.4\" }\n";
        assert!(
            upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4")).is_err(),
            "foreign-checkout entry must refuse the overwrite"
        );
        let toml = "[patch.crates-io]\ncfg-if = { path = \"/abs/.socket/vendor/cargo/99999999-9999-9999-9999-999999999999/cfg-if-1.0.4\" }\n";
        assert!(
            upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4")).is_err(),
            "absolute-path entry must refuse the overwrite"
        );
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

    /// COVERAGE 2026-09: `crates-io` written as an INLINE table —
    /// `[patch]` + `crates-io = { cfg-if = { path = "…" } }` — is valid TOML
    /// that cargo honors identically to `[patch.crates-io]` (a hand edit or
    /// another tool re-serializing this user-owned file produces it). The
    /// path prefix is the entire ownership signal, so a socket-owned entry
    /// in this form must refresh in place, not error via `ensure_table`.
    #[test]
    fn test_upsert_refreshes_inline_crates_io_form() {
        let old = format!("{CARGO_VENDOR_DIR}/11111111-2222-3333-4444-555555555555/cfg-if-1.0.4");
        let toml = format!("[patch]\ncrates-io = {{ cfg-if = {{ path = \"{old}\" }} }}\n");
        let want = vendor_path("cfg-if", "1.0.4");
        let out = upsert_patch_entry(&toml, "cfg-if", &want)
            .expect("inline-form owned entry must refresh, not error")
            .expect("stale path means the file changes");
        let doc = parse(&out);
        assert_eq!(
            entry_path(&doc["patch"]["crates-io"]["cfg-if"]),
            Some(want.as_str())
        );
        // Idempotent thereafter.
        assert!(upsert_patch_entry(&out, "cfg-if", &want).unwrap().is_none());
    }

    /// COVERAGE 2026-09: …and a USER-authored entry in the inline form is
    /// still refused, never silently overwritten.
    #[test]
    fn test_upsert_refuses_user_authored_inline_form() {
        let toml = "[patch]\ncrates-io = { cfg-if = { path = \"../my-fork\" } }\n";
        assert!(upsert_patch_entry(toml, "cfg-if", &vendor_path("cfg-if", "1.0.4")).is_err());
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

    /// COVERAGE 2026-09: removal twin of the inline-form blindness. A
    /// socket-owned entry inside `crates-io = { … }` must be removed on
    /// rollback — a silent no-op here means revert_cargo_vendor_opts still
    /// deletes the `.socket/vendor/cargo/<uuid>/` copy, leaving a dangling
    /// `[patch]` entry that breaks the next `cargo build`.
    #[test]
    fn test_remove_inline_crates_io_form_socket_entry() {
        let toml = format!(
            "[patch]\ncrates-io = {{ cfg-if = {{ path = \"{}\" }} }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entry(&toml, "cfg-if")
            .unwrap()
            .expect("socket-owned inline-form entry must be removed, not no-op'd");
        assert!(!out.contains("cfg-if"));
        assert!(!out.contains("[patch"), "emptied [patch] pruned: {out}");

        // The fully-inline `patch = { crates-io = { … } }` form as well.
        let toml = format!(
            "patch = {{ crates-io = {{ cfg-if = {{ path = \"{}\" }} }} }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entry(&toml, "cfg-if")
            .unwrap()
            .expect("fully-inline patch form entry must be removed");
        assert!(!out.contains("cfg-if"));
        assert!(!out.contains("patch"), "emptied inline patch pruned: {out}");
    }

    /// COVERAGE 2026-09: sibling user entries sharing the inline table
    /// survive the removal.
    #[test]
    fn test_remove_inline_crates_io_form_keeps_user_entry() {
        let toml = format!(
            "[patch]\ncrates-io = {{ cfg-if = {{ path = \"{}\" }}, other = {{ git = \"https://example.com/o.git\" }} }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entry(&toml, "cfg-if").unwrap().unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_none());
        assert!(doc["patch"]["crates-io"].get("other").is_some());
    }

    /// COVERAGE 2026-09: the ownership guard holds through the inline form —
    /// a user-authored same-name entry stays a no-op.
    #[test]
    fn test_remove_inline_form_user_entry_is_noop() {
        let toml = "[patch]\ncrates-io = { cfg-if = { path = \"../my-fork\" } }\n";
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

    /// COVERAGE 2026-09: read twin of the inline-form blindness — an unread
    /// entry makes verify / pre-flight report the vendor copy unwired (so
    /// GC-reclaimable) while cargo still resolves through it.
    #[test]
    fn test_parse_entries_handles_inline_crates_io_form() {
        let toml = format!(
            "[patch]\ncrates-io = {{ mine = {{ path = \"{}\" }}, yours = {{ git = \"https://example.com/y.git\" }} }}\n",
            vendor_path("mine", "1.0.0")
        );
        let entries = parse_patch_entries(&toml);
        assert!(
            entries.get("mine").is_some_and(|e| e.socket_owned),
            "inline-table crates-io form must be readable: {entries:?}"
        );
        assert!(entries.get("yours").is_some_and(|e| !e.socket_owned));

        // The fully-inline `patch = { crates-io = { … } }` form as well.
        let toml = format!(
            "patch = {{ crates-io = {{ mine = {{ path = \"{}\" }} }} }}\n",
            vendor_path("mine", "1.0.0")
        );
        let entries = parse_patch_entries(&toml);
        assert!(
            entries.get("mine").is_some_and(|e| e.socket_owned),
            "fully-inline patch form must be readable: {entries:?}"
        );
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

    // ── FIFO / special-file guard: reads must fail fast, not wedge ───
    /// mkfifo(2) directly rather than shelling out to the `mkfifo` binary —
    /// same helper as the setup/pypi + crawler FIFO tests: fork/exec flakes
    /// under heavy parallel load and the syscall needs no process at all.
    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// Connect (and immediately drop) a writer to a FIFO whose reader is
    /// wedged in `open(2)`, releasing the leaked `spawn_blocking` thread the
    /// runtime would otherwise wait for on shutdown — so a regressed test
    /// FAILS instead of hanging the whole suite. `O_NONBLOCK` so a FIFO with
    /// no pending reader errors (`ENXIO`) instead of blocking us in turn.
    #[cfg(unix)]
    fn release_fifo_reader(path: &Path) {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path);
    }

    /// A FIFO planted as `.cargo/config.toml` must not wedge the read path:
    /// a plain `read_to_string` `open(2)` of a FIFO waits for a writer that
    /// never comes, hanging `scan` and every vendor pre-flight that consults
    /// the patch table. Same class as the `open_regular_file` guards in the
    /// redirect-ledger / vendor `Cargo.toml` twins; the non-regular file must
    /// instead read as "no entries" (the malformed-config contract).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_read_patch_entries_fifo_config_does_not_wedge() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        let cfg = cargo_dir.join("config.toml");
        mkfifo(&cfg);

        let deadline = std::time::Duration::from_secs(5);
        let Ok(entries) = tokio::time::timeout(deadline, read_patch_entries(dir.path())).await
        else {
            release_fifo_reader(&cfg);
            panic!("read_patch_entries must complete promptly with a FIFO config");
        };
        assert!(
            entries.is_empty(),
            "a FIFO config holds no readable entries"
        );
    }

    /// The edit path: `config_path` picks a legacy `.cargo/config` whose
    /// metadata probes fine, but the plain read then blocks forever in
    /// `open(2)`, wedging wet vendor apply/remove. It must fail fast with an
    /// error instead — and never treat the squatted path as an empty config
    /// to rename a fresh file over.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_ensure_patch_entry_fifo_legacy_config_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        let legacy = cargo_dir.join("config");
        mkfifo(&legacy);

        let deadline = std::time::Duration::from_secs(5);
        let Ok(res) = tokio::time::timeout(
            deadline,
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false),
        )
        .await
        else {
            release_fifo_reader(&legacy);
            panic!("ensure_patch_entry must complete promptly with a FIFO config");
        };
        assert!(
            res.is_err(),
            "a FIFO config must fail loudly, not be edited"
        );
        use std::os::unix::fs::FileTypeExt;
        let ft = std::fs::symlink_metadata(&legacy).unwrap().file_type();
        assert!(ft.is_fifo(), "squatted path must not be replaced");
    }

    /// The registry-index read sweeps both config files; a FIFO squatting
    /// either one must contribute nothing rather than wedge `scan`. Only the
    /// first file (`config`) has a pending reader when the timeout fires —
    /// the dropped future never reaches `config.toml` — so only it needs
    /// releasing.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_socket_registry_indexes_fifo_configs_do_not_wedge() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        let legacy = cargo_dir.join("config");
        mkfifo(&legacy);
        mkfifo(&cargo_dir.join("config.toml"));

        let deadline = std::time::Duration::from_secs(5);
        let Ok(out) = tokio::time::timeout(deadline, socket_registry_indexes(dir.path())).await
        else {
            release_fifo_reader(&legacy);
            panic!("socket_registry_indexes must complete promptly with FIFO configs");
        };
        assert!(out.is_empty(), "FIFO configs contribute no registries");
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
