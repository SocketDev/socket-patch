//! The project cargo config (`.cargo/config.toml`, or the legacy
//! extensionless `.cargo/config` cargo prefers): the shared `[patch.*]` /
//! `[registries.*]` readers, and the LEGACY vendored wiring.
//!
//! Before v5 the cargo vendor backend wrote its `[patch.crates-io]` path
//! entry here; v5 writes it to the workspace-root `Cargo.toml` instead
//! ([`super::cargo_manifest`]). This module still reads the legacy entries
//! (liveness probes, takeover guards, lockfile discovery) and removes them
//! on migration and revert ([`drop_legacy_patch_entries`]) — it never writes
//! a new one. Transforms are pure `fn(&str) -> Result<Option<String>,
//! String>` (`Some(new)` = changed) wrapped by an async edit helper that
//! honours `dry_run` and preserves the user's formatting via `toml_edit`.
//!
//! ## Ownership model (no sidecar manifest)
//! A `[patch.crates-io]` entry is *socket-owned* iff its `path` value is a
//! root-anchored relative path (not absolute, no `..`) under THIS project's
//! `.socket/vendor/cargo/` (this backend's committed copies). Anything else —
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
use std::sync::Arc;

use tokio::fs;
use toml_edit::{DocumentMut, Item, Table, TableLike};

use super::parse_memo::ParseMemo;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};

/// The run's cargo-config parse. A wet vendor run probes the `[patch]`
/// entries and then edits them once per patched crate, against a file that
/// grows by an entry per crate; see [`ParseMemo`]. One slot per config
/// spelling: [`socket_registry_indexes`] reads BOTH in one pass, so a
/// single slot would make the two evict each other on every call in the
/// mixed/legacy state that loop exists for.
static CONFIG_MEMO: ParseMemo<DocumentMut, 2> = ParseMemo::new();

/// Parse a cargo config, reusing the run's parse while `content` is the
/// text that produced it. Read-only callers take the shared document; the
/// two transforms below clone it before mutating.
fn config_doc(content: &str) -> Result<Arc<DocumentMut>, toml_edit::TomlError> {
    CONFIG_MEMO.parse(content.as_bytes(), || content.parse::<DocumentMut>())
}

/// Project-relative root of the vendor backend's committed crate copies. An
/// entry whose `path` is under this prefix is socket-owned.
const CARGO_VENDOR_DIR: &str = ".socket/vendor/cargo";

/// Cargo's legacy extensionless project config: when it exists cargo reads
/// it INSTEAD of [`CONFIG_TOML`] (and warns that the `.toml` is ignored).
pub(crate) const CONFIG_LEGACY: &str = ".cargo/config";
/// The project config cargo reads when [`CONFIG_LEGACY`] does not exist.
pub(crate) const CONFIG_TOML: &str = ".cargo/config.toml";
/// The prefix every Socket-owned registry name carries
/// (`socket-patch-<uuid>`, as the hosted rewriter defines and pins it).
pub(crate) const SOCKET_REGISTRY_PREFIX: &str = "socket-patch-";

/// Info about one `[patch.crates-io]` entry, for vendor pre-flight / verify.
#[derive(Debug, Clone)]
pub struct PatchEntryInfo {
    /// The `path` value as written (verbatim), or `None` for a non-path
    /// source (e.g. `git`/`registry`).
    pub path: Option<String>,
    /// True iff `path` is under `CARGO_VENDOR_DIR`.
    pub socket_owned: bool,
}

// ── public async API ─────────────────────────────────────────────────────────

/// Upsert `[patch.crates-io].<name> = { path = "<rel_path>" }` — the pre-v5
/// vendored wiring, kept only to seed legacy projects in migration tests.
#[cfg(test)]
pub(crate) async fn ensure_patch_entry(
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

/// Remove every *socket-owned* legacy `[patch.crates-io]` entry wiring
/// `name@version` (key-agnostic: effective crate name + a
/// `.socket/vendor/cargo/<uuid>/<name>-<version>` path) from the config
/// cargo reads, cleaning up emptied `[patch.crates-io]` / `[patch]` tables
/// and deleting a config file (and `.cargo/`) the removal emptied. A
/// user-authored or absent entry is a no-op. Returns whether the file
/// changed.
pub async fn drop_legacy_patch_entries(
    project_root: &Path,
    name: &str,
    version: &str,
    dry_run: bool,
) -> Result<bool, String> {
    edit_config(project_root, dry_run, |c| {
        remove_patch_entries(c, name, version)
    })
    .await
}

/// The legacy config's socket-owned `[patch.crates-io]` entries for crate
/// `name` (any version), as `(key, path)`, from the config cargo reads.
/// Read-only; a missing or malformed config yields none.
pub async fn legacy_socket_entries(project_root: &Path, name: &str) -> Vec<(String, String)> {
    let path = config_path(project_root).await;
    let Ok(content) = read_regular_to_string(&path).await else {
        return Vec::new();
    };
    let Ok(doc) = content.parse::<DocumentMut>() else {
        return Vec::new();
    };
    patch_entries(&doc)
        .into_iter()
        .filter(|e| e.source == "crates-io" && e.name == name)
        .filter_map(|e| {
            let p = e.path.filter(|p| path_is_socket_owned(p))?;
            Some((e.key.to_string(), p.to_string()))
        })
        .collect()
}

/// One config file of the chain cargo merges `[patch]` tables from.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// For messages: root-relative for the project config, else absolute.
    pub file: String,
    /// The directory relative `[patch]` paths in this file resolve against
    /// (the parent of the directory holding the file).
    pub base: PathBuf,
    /// The project's own config — the only file whose Socket-shaped paths
    /// are this project's copies (legacy wiring). Every entry of any other
    /// file is reported as user-authored.
    pub project: bool,
    /// Its crates.io `[patch]` items (`crates-io` and URL spellings).
    pub entries: Vec<super::cargo_manifest::ManifestPatchEntry>,
}

/// Every cargo config file whose `[patch]` items cargo merges over the root
/// manifest's when building this project: the project's own `.cargo/config*`,
/// every ancestor directory's, and `$CARGO_HOME`'s (default `~/.cargo`), in
/// that order (cargo lets a config item replace the manifest item with the
/// same key, whatever its version). Read-only and fail-soft: missing /
/// unreadable / malformed files contribute nothing.
pub async fn read_config_chain(project_root: &Path) -> Vec<ChainConfig> {
    let cargo_home = match std::env::var("CARGO_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => crate::utils::fs::home_dir().join(".cargo"),
    };
    read_config_chain_with(project_root, &cargo_home).await
}

/// [`read_config_chain`] with an explicit `$CARGO_HOME`.
pub async fn read_config_chain_with(project_root: &Path, cargo_home: &Path) -> Vec<ChainConfig> {
    let root = fs::canonicalize(project_root)
        .await
        .unwrap_or_else(|_| project_root.to_path_buf());
    let mut dirs: Vec<(PathBuf, PathBuf, bool)> = root
        .ancestors()
        .map(|dir| (dir.join(".cargo"), dir.to_path_buf(), dir == root))
        .collect();
    let home_base = cargo_home
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cargo_home.to_path_buf());
    dirs.push((cargo_home.to_path_buf(), home_base, false));
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut out = Vec::new();
    for (cargo_dir, base, project) in dirs {
        let legacy = cargo_dir.join("config");
        let file = if fs::metadata(&legacy).await.is_ok() {
            legacy
        } else {
            cargo_dir.join("config.toml")
        };
        let key = fs::canonicalize(&file)
            .await
            .unwrap_or_else(|_| file.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let Ok(content) = read_regular_to_string(&file).await else {
            continue;
        };
        let Ok(doc) = content.parse::<DocumentMut>() else {
            continue;
        };
        let mut entries = super::cargo_manifest::crates_io_patch_entries(&doc);
        if !project {
            for entry in &mut entries {
                entry.socket_owned = false;
            }
        }
        if entries.is_empty() {
            continue;
        }
        let file = if project {
            effective_config_rel(project_root).await.to_string()
        } else {
            file.display().to_string()
        };
        out.push(ChainConfig {
            file,
            base,
            project,
            entries,
        });
    }
    out
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
    for file in [CONFIG_LEGACY, CONFIG_TOML] {
        let Ok(content) = read_regular_to_string(&project_root.join(file)).await else {
            continue;
        };
        let Ok(doc) = config_doc(&content) else {
            continue;
        };
        out.extend(registry_definitions(&doc));
    }
    out
}

// ── pure reader ──────────────────────────────────────────────────────────────
// The read-only walks of a parsed manifest / config that the vendor side
// above and lockfile discovery (`vex::discover::cargo`) share.

/// The `[registries.socket-patch-*]` definitions of a parsed cargo config,
/// as `(registry_name, index)` pairs in document order; a definition with
/// no string `index` is skipped.
pub(crate) fn registry_definitions(doc: &DocumentMut) -> Vec<(String, String)> {
    let Some(registries) = doc.get("registries").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    registries
        .iter()
        .filter(|(name, _)| name.starts_with(SOCKET_REGISTRY_PREFIX))
        .filter_map(|(name, item)| {
            let index = item.as_table_like()?.get("index")?.as_str()?;
            Some((name.to_string(), index.to_string()))
        })
        .collect()
}

/// One item of a `[patch.<source>]` table, as written.
pub(crate) struct CargoPatchEntry<'d> {
    /// The `<source>` key (`crates-io`, or a registry / git URL).
    pub(crate) source: &'d str,
    /// The item's own key.
    pub(crate) key: &'d str,
    /// The crate it patches: `package = "…"` when renamed, else the key.
    pub(crate) name: &'d str,
    /// The `path` / `registry` values (`None` too for a non-table item).
    pub(crate) path: Option<&'d str>,
    pub(crate) registry: Option<&'d str>,
}

/// Every item of every `[patch.<source>]` table of a manifest or config, in
/// document order — header, dotted, and `[patch] crates-io = { … }` inline
/// forms alike (cargo honors all). A `<source>` that is not a table
/// contributes nothing.
pub(crate) fn patch_entries(doc: &DocumentMut) -> Vec<CargoPatchEntry<'_>> {
    let Some(patch) = doc.get("patch").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for (source, table) in patch.iter() {
        let Some(table) = table.as_table_like() else {
            continue;
        };
        for (key, item) in table.iter() {
            let field = move |k: &str| item.as_table_like()?.get(k)?.as_str();
            entries.push(CargoPatchEntry {
                source,
                key,
                name: field("package").unwrap_or(key),
                path: field("path"),
                registry: field("registry"),
            });
        }
    }
    entries
}

// ── config-file resolution + read-or-create write ────────────────────────────

/// The project config cargo reads, root-relative: [`CONFIG_LEGACY`] when it
/// exists — both files present means cargo reads the one WITHOUT the
/// extension (and warns) — else [`CONFIG_TOML`] (which may not exist yet).
/// `metadata`, not lstat: cargo's own existence probe follows symlinks.
pub(crate) async fn effective_config_rel(project_root: &Path) -> &'static str {
    if fs::metadata(project_root.join(".cargo").join("config"))
        .await
        .is_ok()
    {
        CONFIG_LEGACY
    } else {
        CONFIG_TOML
    }
}

/// Resolve the config file under `<project_root>/.cargo/`
/// ([`effective_config_rel`]): writing into `config.toml` while a legacy
/// `config` exists would leave the `[patch]` entry silently inert. A missing
/// `config.toml` is created on first write.
async fn config_path(project_root: &Path) -> PathBuf {
    let rel = effective_config_rel(project_root).await;
    rel.split('/')
        .fold(project_root.to_path_buf(), |path, segment| {
            path.join(segment)
        })
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
                    match crate::utils::fs::remove_file(&path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("remove {}: {e}", path.display())),
                    }
                    CONFIG_MEMO.invalidate();
                    if let Some(parent) = path.parent() {
                        // Best-effort: `remove_dir` only succeeds when the dir
                        // is empty, so a `.cargo/` holding other files (e.g.
                        // credentials) is left intact. Inside a vendored
                        // run's group commit the file's removal is captured,
                        // so the directory goes once the commit is on disk.
                        crate::utils::group_commit::remove_dir_after_commit(parent).await;
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
                    CONFIG_MEMO.invalidate();
                }
            }
            Ok(true)
        }
    }
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// True if a `[patch]` `path` value denotes one of THIS project's
/// socket-owned copies: a relative path that escapes nothing (not absolute,
/// no `..` segment) and sits under [`CARGO_VENDOR_DIR`] (the retired
/// `.socket/cargo-patches/` redirect root never shipped in a tagged release,
/// so an entry there is a user path). Cargo resolves relative `[patch]` paths
/// against the project root, so only a root-anchored relative prefix can be a
/// copy this backend wrote — a path that merely *traverses* some other
/// checkout's `.socket/vendor/cargo/` (`../shared/.socket/vendor/cargo/…`,
/// `/abs/.socket/vendor/cargo/…`, `sub/.socket/vendor/cargo/…`) is
/// user-authored and must never be rewritten or removed.
pub(crate) fn path_is_socket_owned(path: &str) -> bool {
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
    let prefix: Vec<&str> = CARGO_VENDOR_DIR.split('/').collect();
    segments.len() > prefix.len() && segments[..prefix.len()] == prefix[..]
}

/// The `path` string of a `[patch]` entry (inline table or sub-table), if any.
#[cfg(test)]
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
pub(crate) fn ensure_table_like<'a>(
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

#[cfg(test)]
fn upsert_patch_entry(content: &str, name: &str, rel_path: &str) -> Result<Option<String>, String> {
    use toml_edit::{InlineTable, Value};
    let mut doc =
        (*config_doc(content).map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?).clone();

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

fn remove_patch_entries(
    content: &str,
    name: &str,
    version: &str,
) -> Result<Option<String>, String> {
    let mut doc =
        (*config_doc(content).map_err(|e| format!("Invalid .cargo/config.toml: {e}"))?).clone();
    let keys: Vec<String> = patch_entries(&doc)
        .into_iter()
        .filter(|e| {
            e.source == "crates-io"
                && e.name == name
                && e.path
                    .is_some_and(|p| super::cargo_manifest::is_socket_copy_of(p, name, version))
        })
        .map(|e| e.key.to_string())
        .collect();
    if keys.is_empty() {
        return Ok(None);
    }
    // Table-like views: the inline `crates-io = { … }` form is honored by
    // cargo, and a remove blind to it would leave the entry dangling after
    // the vendor copy it points at is deleted.
    if let Some(patch) = doc.get_mut("patch").and_then(Item::as_table_like_mut) {
        let mut crates_io_empty = false;
        if let Some(crates_io) = patch.get_mut("crates-io").and_then(Item::as_table_like_mut) {
            for key in &keys {
                crates_io.remove(key);
            }
            crates_io_empty = crates_io.is_empty();
        }
        if crates_io_empty {
            patch.remove("crates-io");
        }
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

/// Every `[patch.crates-io]` item keyed by its table key ([`patch_entries`]).
fn parse_patch_entries(content: &str) -> HashMap<String, PatchEntryInfo> {
    let Ok(doc) = config_doc(content) else {
        return HashMap::new();
    };
    patch_entries(&doc)
        .into_iter()
        .filter(|entry| entry.source == "crates-io")
        .map(|entry| {
            let path = entry.path.map(str::to_string);
            let socket_owned = path.as_deref().is_some_and(path_is_socket_owned);
            (entry.key.to_string(), PatchEntryInfo { path, socket_owned })
        })
        .collect()
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
                                                                          // The retired redirect backend's `.socket/cargo-patches/` never
                                                                          // shipped in a tagged release: an entry there is a user path.
        assert!(!path_is_socket_owned(".socket/cargo-patches/cfg-if-1.0.0"));
        assert!(!path_is_socket_owned("./.socket/cargo-patches/x-1.0.0"));
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
        let out = remove_patch_entries(toml, "cfg-if", "1.0.4").unwrap();
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
    fn test_upsert_refuses_retired_redirect_path_entry() {
        // `.socket/cargo-patches/` (the retired redirect backend) never
        // shipped: a same-name entry pointing there is user-authored and
        // refused, never rewritten.
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n";
        let want = vendor_path("cfg-if", "1.0.4");
        assert!(upsert_patch_entry(toml, "cfg-if", &want).is_err());
    }

    // ── remove ───────────────────────────────────────────────────────
    #[test]
    fn test_remove_socket_owned_cleans_empty_tables() {
        let toml = format!(
            "[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert!(!out.contains("cfg-if"));
        // Empty [patch.crates-io] and [patch] are pruned.
        assert!(!out.contains("[patch"));
    }

    #[test]
    fn test_remove_leaves_retired_redirect_path_entry() {
        let toml =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n";
        assert!(
            remove_patch_entries(toml, "cfg-if", "1.0.4")
                .unwrap()
                .is_none(),
            "a user-authored entry is never removed"
        );
    }

    #[test]
    fn test_remove_leaves_user_entry_and_table() {
        let toml = format!(
            "[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\nother = {{ git = \"https://example.com/o.git\" }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_none());
        assert!(doc["patch"]["crates-io"].get("other").is_some());
    }

    #[test]
    fn test_remove_user_authored_same_name_is_noop() {
        let toml = "[patch.crates-io]\ncfg-if = { git = \"https://example.com/c.git\" }\n";
        assert!(remove_patch_entries(toml, "cfg-if", "1.0.4")
            .unwrap()
            .is_none());
        let toml = "[patch.crates-io]\ncfg-if = { path = \"../my-fork\" }\n";
        assert!(remove_patch_entries(toml, "cfg-if", "1.0.4")
            .unwrap()
            .is_none());
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
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
            .unwrap()
            .expect("socket-owned inline-form entry must be removed, not no-op'd");
        assert!(!out.contains("cfg-if"));
        assert!(!out.contains("[patch"), "emptied [patch] pruned: {out}");

        // The fully-inline `patch = { crates-io = { … } }` form as well.
        let toml = format!(
            "patch = {{ crates-io = {{ cfg-if = {{ path = \"{}\" }} }} }}\n",
            vendor_path("cfg-if", "1.0.4")
        );
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
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
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_none());
        assert!(doc["patch"]["crates-io"].get("other").is_some());
    }

    /// COVERAGE 2026-09: the ownership guard holds through the inline form —
    /// a user-authored same-name entry stays a no-op.
    #[test]
    fn test_remove_inline_form_user_entry_is_noop() {
        let toml = "[patch]\ncrates-io = { cfg-if = { path = \"../my-fork\" } }\n";
        assert!(remove_patch_entries(toml, "cfg-if", "1.0.4")
            .unwrap()
            .is_none());
    }

    /// Legacy removal is KEY-AGNOSTIC and VERSION-SCOPED: a renamed
    /// socket-owned entry for the crate@version goes; another version's
    /// socket-owned entry stays.
    #[test]
    fn test_remove_is_key_agnostic_and_version_scoped() {
        let toml = format!(
            "[patch.crates-io]\nalias = {{ package = \"cfg-if\", path = \"{}\" }}\ncfg-if = {{ path = \"{}\" }}\n",
            vendor_path("cfg-if", "1.0.4"),
            vendor_path("cfg-if", "0.1.10")
        );
        let out = remove_patch_entries(&toml, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        let doc = parse(&out);
        assert!(doc["patch"]["crates-io"].get("alias").is_none());
        assert!(doc["patch"]["crates-io"].get("cfg-if").is_some());
        assert!(remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(
            remove_patch_entries("[build]\njobs = 2\n", "cfg-if", "1.0.4")
                .unwrap()
                .is_none()
        );
    }

    /// COVERAGE 2026-09: `[patch]` exists but `crates-io` is absent or not a
    /// table. Only `[patch.crates-io]` is managed — an entry under some other
    /// registry's patch table is never ours, even when its `path` value looks
    /// socket-owned; and a scalar `crates-io` (adversarial hand edit) must be
    /// a quiet no-op rather than a panic or a rewrite.
    #[test]
    fn test_remove_with_patch_but_no_crates_io_table_is_noop() {
        // A different registry's patch table; crates-io absent entirely.
        let toml = format!(
            "[patch.my-registry]\nfoo = {{ path = \"{}\" }}\n",
            vendor_path("foo", "1.0.0")
        );
        assert!(
            remove_patch_entries(&toml, "foo", "1.0.0")
                .unwrap()
                .is_none(),
            "entries under a foreign registry's patch table are not managed"
        );
        // `crates-io` present but not table-like.
        let toml = "[patch]\ncrates-io = \"oops\"\n";
        assert!(
            remove_patch_entries(toml, "cfg-if", "1.0.4")
                .unwrap()
                .is_none(),
            "a non-table crates-io value must be left untouched"
        );
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
        assert!(
            !entries["legacy"].socket_owned,
            "the retired redirect prefix is a user path"
        );
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
        assert!(
            drop_legacy_patch_entries(dir.path(), "cfg-if", "1.0.4", false)
                .await
                .unwrap()
        );
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

    /// COVERAGE 2026-09: the skip branches of `socket_registry_indexes` — a
    /// malformed legacy `.cargo/config` alongside a good `config.toml` (a
    /// real mixed/legacy state) contributes nothing, per the doc's
    /// "malformed files contribute nothing" promise; a user-authored
    /// `[registries.*]` entry (mirror / private registry) is never reported
    /// as Socket's; and a socket-named table without an `index` key is
    /// skipped rather than fabricated.
    #[tokio::test]
    async fn test_socket_registry_indexes_skips_malformed_and_foreign_registries() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).await.unwrap();
        fs::write(cargo_dir.join("config"), "not = = toml [[")
            .await
            .unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "[registries.my-mirror]\n\
             index = \"https://example.com/idx\"\n\n\
             [registries.socket-patch-9f6b2c4e]\n\
             index = \"sparse+http://127.0.0.1:8000/idx/\"\n\n\
             [registries.socket-patch-noindex]\n\
             token = \"x\"\n",
        )
        .await
        .unwrap();

        let out = socket_registry_indexes(dir.path()).await;
        assert_eq!(
            out,
            vec![(
                "socket-patch-9f6b2c4e".to_string(),
                "sparse+http://127.0.0.1:8000/idx/".to_string()
            )],
            "only the socket-named registry WITH an index is reported"
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
        assert!(
            drop_legacy_patch_entries(dir.path(), "cfg-if", "1.0.4", false)
                .await
                .unwrap()
        );
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
        assert!(
            drop_legacy_patch_entries(dir.path(), "cfg-if", "1.0.4", false)
                .await
                .unwrap()
        );
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
        assert!(
            drop_legacy_patch_entries(dir.path(), "cfg-if", "1.0.4", false)
                .await
                .unwrap()
        );
        assert!(
            !cargo_dir.join("config.toml").exists(),
            "emptied config is deleted"
        );
        assert!(
            cargo_dir.exists() && cargo_dir.join("credentials.toml").exists(),
            ".cargo/ is kept because it still holds the user's credentials file"
        );
    }

    /// COVERAGE 2026-09: a real `remove_file` failure in the delete branch
    /// must propagate as `Err("remove {path}: …")` — a swallowed unlink error
    /// would make `drop_legacy_patch_entries` report a successful revert while the
    /// stale `[patch]` wiring still sits on disk.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_drop_errors_when_emptied_config_is_undeletable() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root ignores directory permission bits");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(
            ensure_patch_entry(dir.path(), "cfg-if", &vendor_path("cfg-if", "1.0.4"), false)
                .await
                .unwrap()
        );
        let cargo_dir = dir.path().join(".cargo");
        // Read-only dir: the emptied config's unlink gets EACCES.
        fs::set_permissions(&cargo_dir, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let res = drop_legacy_patch_entries(dir.path(), "cfg-if", "1.0.4", false).await;
        // Restore before asserting so the tempdir always cleans up.
        fs::set_permissions(&cargo_dir, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        let err = res.expect_err("undeletable emptied config must fail the revert");
        assert!(
            err.starts_with("remove ") && err.contains("config.toml"),
            "error must name the remove and the path: {err}"
        );
        assert!(
            cargo_dir.join("config.toml").exists(),
            "failed unlink must leave the config in place, not half-deleted"
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
