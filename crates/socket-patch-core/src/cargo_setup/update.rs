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
use toml_edit::{DocumentMut, Item, Table, Value};

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

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table, String> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn guard_dep_add(content: &str, version: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid Cargo.toml: {e}"))?;
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
        .and_then(Item::as_table_mut)
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
