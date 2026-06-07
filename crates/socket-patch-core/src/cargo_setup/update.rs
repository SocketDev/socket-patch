//! Add / remove the `socket-patch-guard` build-time dependency in a crate's
//! `Cargo.toml`, and statically check whether it is present.
//!
//! Edits go through `toml_edit` so the user's formatting + comments survive,
//! and the user's `build.rs` (if any) is **never** touched — that's the whole
//! reason the guard is a separate crate. Mirrors the contract style of
//! [`crate::package_json::update`] (idempotent, `dry_run`-aware,
//! `Updated`/`AlreadyConfigured`/`Error` status).

use std::path::Path;

use tokio::fs;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

/// The guard crate's package name.
pub const GUARD_CRATE: &str = "socket-patch-guard";

/// Outcome of editing one `Cargo.toml`. Mirrors
/// `package_json::update::UpdateStatus` / `pth_hook::edit::PthStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoSetupStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

#[derive(Debug, Clone)]
pub struct CargoEditResult {
    pub path: String,
    pub status: CargoSetupStatus,
    pub error: Option<String>,
}

impl CargoEditResult {
    fn ok(path: &Path, status: CargoSetupStatus) -> Self {
        Self {
            path: path.display().to_string(),
            status,
            error: None,
        }
    }
    fn err(path: &Path, msg: impl Into<String>) -> Self {
        Self {
            path: path.display().to_string(),
            status: CargoSetupStatus::Error,
            error: Some(msg.into()),
        }
    }
}

/// Add `socket-patch-guard = "<version>"` under `[dependencies]`. Idempotent
/// (an existing entry of any value shape is left untouched → `AlreadyConfigured`).
/// A missing `Cargo.toml` is an error (we don't synthesize one).
pub async fn add_guard_dep(cargo_toml: &Path, version: &str, dry_run: bool) -> CargoEditResult {
    let content = match fs::read_to_string(cargo_toml).await {
        Ok(c) => c,
        Err(e) => return CargoEditResult::err(cargo_toml, e.to_string()),
    };
    match guard_dep_add(&content, version) {
        Ok(None) => CargoEditResult::ok(cargo_toml, CargoSetupStatus::AlreadyConfigured),
        Ok(Some(new)) => {
            if !dry_run {
                if let Err(e) = fs::write(cargo_toml, &new).await {
                    return CargoEditResult::err(cargo_toml, e.to_string());
                }
            }
            CargoEditResult::ok(cargo_toml, CargoSetupStatus::Updated)
        }
        Err(e) => CargoEditResult::err(cargo_toml, e),
    }
}

/// Remove the `socket-patch-guard` dependency. Idempotent (already-absent →
/// `AlreadyConfigured`). A missing `Cargo.toml` is a no-op (`AlreadyConfigured`).
pub async fn remove_guard_dep(cargo_toml: &Path, dry_run: bool) -> CargoEditResult {
    let content = match fs::read_to_string(cargo_toml).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CargoEditResult::ok(cargo_toml, CargoSetupStatus::AlreadyConfigured)
        }
        Err(e) => return CargoEditResult::err(cargo_toml, e.to_string()),
    };
    match guard_dep_remove(&content) {
        Ok(None) => CargoEditResult::ok(cargo_toml, CargoSetupStatus::AlreadyConfigured),
        Ok(Some(new)) => {
            if !dry_run {
                if let Err(e) = fs::write(cargo_toml, &new).await {
                    return CargoEditResult::err(cargo_toml, e.to_string());
                }
            }
            CargoEditResult::ok(cargo_toml, CargoSetupStatus::Updated)
        }
        Err(e) => CargoEditResult::err(cargo_toml, e),
    }
}

/// Static check: is `socket-patch-guard` present under `[dependencies]`?
/// Pure parse — exactly what a GitHub App reads to audit a repo. Returns
/// `false` on malformed TOML.
pub fn is_guard_dep_present(content: &str) -> bool {
    content
        .parse::<DocumentMut>()
        .ok()
        .and_then(|doc| {
            doc.get("dependencies")
                .and_then(Item::as_table_like)
                .map(|deps| deps.contains_key(GUARD_CRATE))
        })
        .unwrap_or(false)
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// Get `parent[key]` as a mutable table, creating an empty `[key]` table if
/// it's absent. Accepts both standard (`[dependencies]`) and inline
/// (`dependencies = { … }`) tables via `as_table_like_mut` so it stays in
/// lockstep with [`is_guard_dep_present`] (which reads via `as_table_like`).
fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut dyn TableLike, String> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn guard_dep_add(content: &str, version: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid Cargo.toml: {e}"))?;
    // A *virtual* workspace manifest (`[workspace]` but no `[package]`) cannot
    // carry a `[dependencies]` section — cargo rejects it with "this virtual
    // manifest specifies a `dependencies` section, which is not allowed". Adding
    // the guard here would corrupt the manifest, and there is no crate to build
    // anyway (the guard belongs in each *member*). Refuse rather than write a
    // file cargo can no longer parse. (Reachable via `discover`'s empty-members
    // fallback, which hands the workspace root to `setup`.)
    if doc.contains_key("workspace") && !doc.contains_key("package") {
        return Err(
            "Cargo.toml is a virtual workspace manifest (no `[package]`); the guard \
             dependency belongs in each member crate, not the workspace root"
                .to_string(),
        );
    }
    let root = doc.as_table_mut();
    let deps = ensure_table(root, "dependencies")?;
    if deps.contains_key(GUARD_CRATE) {
        return Ok(None);
    }
    deps.insert(GUARD_CRATE, Item::Value(Value::from(version)));
    Ok(Some(doc.to_string()))
}

fn guard_dep_remove(content: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid Cargo.toml: {e}"))?;
    let removed = doc
        .get_mut("dependencies")
        .and_then(Item::as_table_like_mut)
        .map(|deps| deps.remove(GUARD_CRATE).is_some())
        .unwrap_or(false);
    if !removed {
        return Ok(None);
    }
    Ok(Some(doc.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_into_existing_deps() {
        let toml = "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        assert!(out.contains("socket-patch-guard = \"3.3\""));
        assert!(out.contains("serde = \"1\""));
        // Idempotent.
        assert!(guard_dep_add(&out, "3.3").unwrap().is_none());
    }

    #[test]
    fn test_add_creates_dependencies_table() {
        let toml = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["dependencies"][GUARD_CRATE].as_str(), Some("3.3"));
    }

    #[test]
    fn test_add_preserves_existing_guard_entry() {
        // A user who pinned a richer spec (path/version table) keeps it.
        let toml = "[dependencies]\nsocket-patch-guard = { version = \"3.3\", optional = true }\n";
        assert!(guard_dep_add(toml, "3.3").unwrap().is_none());
    }

    #[test]
    fn test_add_preserves_comments_and_build_section() {
        let toml = "# my crate\n[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"  # json\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        assert!(out.contains("# my crate"));
        assert!(out.contains("serde = \"1\"  # json"));
    }

    #[test]
    fn test_add_into_inline_dependencies_table() {
        // `dependencies = { … }` is a valid (if uncommon) *root-level* inline
        // table. The reader (`is_guard_dep_present`) sees through it via
        // `as_table_like`, so the writer must insert INTO it too — otherwise add
        // would either error or fork a second `[dependencies]` (a duplicate key,
        // which is invalid TOML). The `dependencies` key must be at the document
        // root, NOT under `[package]` (where it would belong to `package.*` and
        // the writer would never touch it — masking this very regression).
        let toml = "dependencies = { serde = \"1\" }\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        assert!(is_guard_dep_present(&out));
        assert!(out.contains("serde = \"1\""));
        // Round-trips through a parser (proves it is not a duplicate-key file).
        let doc = out.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["dependencies"][GUARD_CRATE].as_str(), Some("3.3"));
        // The guard lives in the SAME (inline) table as serde — there is exactly
        // one `dependencies` key, still inline.
        assert!(doc["dependencies"].is_inline_table());
    }

    #[test]
    fn test_add_inline_dependencies_idempotent() {
        // Guard already present in an inline table → AlreadyConfigured (Ok(None)),
        // NOT an error. Mirrors `is_guard_dep_present` returning true here.
        let toml = "dependencies = { socket-patch-guard = \"3.3\", serde = \"1\" }\n";
        assert!(is_guard_dep_present(toml));
        assert!(guard_dep_add(toml, "3.3").unwrap().is_none());
    }

    #[test]
    fn test_remove_from_inline_dependencies_table() {
        // The dangerous case: a `remove` that silently no-ops while the guard
        // is still present (reports AlreadyConfigured but leaves it behind).
        let toml = "dependencies = { socket-patch-guard = \"3.3\", serde = \"1\" }\n";
        assert!(is_guard_dep_present(toml));
        let out = guard_dep_remove(toml).unwrap().unwrap();
        assert!(!is_guard_dep_present(&out), "guard must actually be removed");
        assert!(out.contains("serde = \"1\""));
    }

    #[test]
    fn test_remove() {
        let toml = "[dependencies]\nserde = \"1\"\nsocket-patch-guard = \"3.3\"\n";
        let out = guard_dep_remove(toml).unwrap().unwrap();
        assert!(!out.contains("socket-patch-guard"));
        assert!(out.contains("serde = \"1\""));
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(guard_dep_remove("[dependencies]\nserde = \"1\"\n")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_is_guard_dep_present() {
        assert!(is_guard_dep_present(
            "[dependencies]\nsocket-patch-guard = \"3.3\"\n"
        ));
        assert!(is_guard_dep_present(
            "[dependencies]\nsocket-patch-guard = { version = \"3.3\" }\n"
        ));
        assert!(!is_guard_dep_present("[dependencies]\nserde = \"1\"\n"));
        assert!(!is_guard_dep_present("not valid toml ["));
    }

    #[test]
    fn test_invalid_toml_errors() {
        assert!(guard_dep_add("not = = toml [[", "3.3").is_err());
    }

    #[tokio::test]
    async fn test_add_missing_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let res = add_guard_dep(&dir.path().join("Cargo.toml"), "3.3", false).await;
        assert_eq!(res.status, CargoSetupStatus::Error);
    }

    #[tokio::test]
    async fn test_remove_missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let res = remove_guard_dep(&dir.path().join("Cargo.toml"), false).await;
        assert_eq!(res.status, CargoSetupStatus::AlreadyConfigured);
    }

    #[test]
    fn test_add_to_virtual_workspace_manifest_is_error() {
        // A virtual manifest (`[workspace]`, no `[package]`) cannot hold a
        // `[dependencies]` section — cargo refuses to parse it. `add` must NOT
        // produce such a file; it errors instead so `setup` surfaces the problem
        // rather than silently corrupting the workspace root.
        let toml = "[workspace]\nmembers = [\"crates/*\"]\n";
        let err = guard_dep_add(toml, "3.3").unwrap_err();
        assert!(
            err.contains("virtual workspace manifest"),
            "expected a virtual-manifest error, got: {err}"
        );
        // The async wrapper reports it as Error, not a (corrupting) Updated.
        // (Covered indirectly; the pure transform is the contract.)
    }

    #[test]
    fn test_add_to_root_package_with_workspace_is_allowed() {
        // A *root package* (`[package]` AND `[workspace]`) is a real crate and
        // CAN carry `[dependencies]` — the virtual-manifest guard must not reject
        // it. This is the common single-repo-with-root-crate layout.
        let toml = "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\n[workspace]\nmembers = [\"crates/*\"]\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        assert!(is_guard_dep_present(&out));
        // The produced manifest still parses (no duplicate/invalid section).
        assert!(out.parse::<DocumentMut>().is_ok());
    }

    #[test]
    fn test_add_into_root_inline_does_not_fork_a_second_table() {
        // Regression guard: inserting into a root-level inline `dependencies`
        // must mutate THAT table, never append a separate `[dependencies]`
        // header (which would be a duplicate key → unparseable).
        let toml = "dependencies = { serde = \"1\" }\n";
        let out = guard_dep_add(toml, "3.3").unwrap().unwrap();
        assert_eq!(
            out.matches("dependencies").count(),
            1,
            "must not fork a second dependencies table: {out}"
        );
        assert!(out.parse::<DocumentMut>().is_ok(), "must stay valid TOML: {out}");
    }

    #[test]
    fn test_add_then_remove_round_trips_byte_for_byte() {
        // add into an existing `[dependencies]`, then remove, must restore the
        // original manifest exactly (formatting + comments preserved).
        let toml = "# top\n[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"  # json\n";
        let added = guard_dep_add(toml, "3.3").unwrap().unwrap();
        let removed = guard_dep_remove(&added).unwrap().unwrap();
        assert_eq!(removed, toml, "add→remove must round-trip byte-for-byte");
    }

    #[test]
    fn test_dotted_guard_header_is_present_and_removable() {
        // The guard pinned via a `[dependencies.socket-patch-guard]` section
        // header (a sub-table) must be detected AND actually removed — not a
        // silent no-op that leaves it behind.
        let toml = "[dependencies.socket-patch-guard]\nversion = \"3.3\"\nfeatures = [\"x\"]\n";
        assert!(is_guard_dep_present(toml));
        // Idempotent add (already configured).
        assert!(guard_dep_add(toml, "3.3").unwrap().is_none());
        let out = guard_dep_remove(toml).unwrap().unwrap();
        assert!(!is_guard_dep_present(&out), "dotted guard must be removed");
    }

    #[tokio::test]
    async fn test_remove_dry_run_does_not_write() {
        // The remove dry-run branch was previously untested.
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        let body = "[dependencies]\nsocket-patch-guard = \"3.3\"\nserde = \"1\"\n";
        tokio::fs::write(&cargo, body).await.unwrap();
        let res = remove_guard_dep(&cargo, true).await;
        assert_eq!(res.status, CargoSetupStatus::Updated);
        let on_disk = tokio::fs::read_to_string(&cargo).await.unwrap();
        assert_eq!(on_disk, body, "dry-run must not modify the file");
    }

    #[tokio::test]
    async fn test_add_to_virtual_manifest_wrapper_reports_error_without_writing() {
        // End-to-end: the async wrapper turns the virtual-manifest refusal into
        // an Error result and leaves the file byte-for-byte unchanged.
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        let body = "[workspace]\nmembers = [\"a\", \"b\"]\n";
        tokio::fs::write(&cargo, body).await.unwrap();
        let res = add_guard_dep(&cargo, "3.3", false).await;
        assert_eq!(res.status, CargoSetupStatus::Error);
        let on_disk = tokio::fs::read_to_string(&cargo).await.unwrap();
        assert_eq!(on_disk, body, "must not corrupt the virtual manifest");
    }

    #[tokio::test]
    async fn test_add_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        tokio::fs::write(&cargo, "[package]\nname=\"x\"\n")
            .await
            .unwrap();
        let res = add_guard_dep(&cargo, "3.3", true).await;
        assert_eq!(res.status, CargoSetupStatus::Updated);
        let body = tokio::fs::read_to_string(&cargo).await.unwrap();
        assert!(
            !body.contains("socket-patch-guard"),
            "dry-run must not write"
        );
    }
}


