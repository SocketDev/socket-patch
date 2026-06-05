//! Composer (PHP) `setup` backend: wire the socket-patch re-apply hook into a
//! project's `composer.json` `scripts`.
//!
//! Composer has a native post-install hook — the `post-install-cmd` and
//! `post-update-cmd` script events fire after `composer install` /
//! `composer update` finish populating `vendor/`. `setup` appends
//! `socket-patch apply --offline --silent --ecosystems composer` to both so the
//! committed `.socket/` patches are re-applied on every install/update (the
//! socket-patch CLI must be on `PATH`, the same requirement as the cargo build
//! guard / gem Bundler plugin / Go guard).
//!
//! `composer.json` is JSON, so — like the npm `package_json` backend — edits go
//! through `serde_json` (with the workspace's `preserve_order` feature, so the
//! user's key order survives) and are written back with
//! `to_string_pretty(..) + "\n"`. The contract mirrors the other backends:
//! idempotent, `dry_run`-aware, `Updated`/`AlreadyConfigured`/`Error`, and a
//! `--remove` that strips exactly what `setup` added.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tokio::fs;

/// The command `setup` appends to each composer script event. The socket-patch
/// CLI is invoked from `PATH` (composer has no `npx`-style fetch), offline (the
/// patches are committed under `.socket/`) and silent (so it doesn't clutter
/// composer's own output).
pub const APPLY_COMMAND: &str = "socket-patch apply --offline --silent --ecosystems composer";

/// Composer script events `setup` wires: post-install-cmd fires after
/// `composer install`, post-update-cmd after `composer update`. Covering both
/// re-applies patches whenever the installed set could have changed.
const HOOK_EVENTS: &[&str] = &["post-install-cmd", "post-update-cmd"];

/// Loose marker for "this script line is ours" — used by `--check` detection so
/// a slightly different flag set still reads as configured.
const HOOK_MARKER: &str = "socket-patch apply";

/// Outcome of one setup edit. Mirrors `gem_setup::GemSetupStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposerSetupStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

#[derive(Debug, Clone)]
pub struct ComposerEditResult {
    /// Envelope `files[].kind` — always `composer`.
    pub kind: &'static str,
    pub path: String,
    pub status: ComposerSetupStatus,
    pub error: Option<String>,
}

impl ComposerEditResult {
    fn from_result(path: String, result: Result<bool, String>) -> Self {
        match result {
            Ok(true) => Self {
                kind: "composer",
                path,
                status: ComposerSetupStatus::Updated,
                error: None,
            },
            Ok(false) => Self {
                kind: "composer",
                path,
                status: ComposerSetupStatus::AlreadyConfigured,
                error: None,
            },
            Err(e) => Self {
                kind: "composer",
                path,
                status: ComposerSetupStatus::Error,
                error: Some(e),
            },
        }
    }
}

/// A discovered composer project (the dir holding `composer.json`).
#[derive(Debug, Clone)]
pub struct ComposerProject {
    pub root: PathBuf,
    pub composer_json: PathBuf,
}

/// Find the composer project rooted at `cwd` (a `composer.json` in `cwd`).
/// cwd-only, matching the other single-project backends (gem/pypi/go).
pub async fn discover_composer_project(cwd: &Path) -> Option<ComposerProject> {
    let composer_json = cwd.join("composer.json");
    if fs::metadata(&composer_json).await.is_ok() {
        Some(ComposerProject {
            root: cwd.to_path_buf(),
            composer_json,
        })
    } else {
        None
    }
}

/// Static check: does this `composer.json` already wire our re-apply hook into
/// any of the covered script events? Pure parse + scan — what a repo auditor
/// reads. A user's own unrelated script does not match.
pub fn is_hook_present(content: &str) -> bool {
    let doc: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let scripts = match doc.get("scripts").and_then(Value::as_object) {
        Some(s) => s,
        None => return false,
    };
    HOOK_EVENTS
        .iter()
        .any(|event| event_contains_marker(scripts.get(*event)))
}

/// Whether a script-event value (string | array-of-strings) holds a command
/// carrying our marker.
fn event_contains_marker(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(s)) => s.contains(HOOK_MARKER),
        Some(Value::Array(arr)) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains(HOOK_MARKER))),
        _ => false,
    }
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// Append [`APPLY_COMMAND`] to both hook events, normalising each to an array.
/// `None` if already present in every event (idempotent no-op).
fn composer_add(content: &str) -> Result<Option<String>, String> {
    let mut doc: Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid composer.json: {e}"))?;
    if !doc.is_object() {
        return Err("Invalid composer.json: root is not a JSON object".to_string());
    }
    // Refuse to clobber a present-but-non-object `scripts`.
    if let Some(scripts) = doc.get("scripts") {
        if !scripts.is_null() && !scripts.is_object() {
            return Err("Invalid composer.json: \"scripts\" is not a JSON object".to_string());
        }
    }

    let root = doc.as_object_mut().unwrap();
    let scripts = ensure_scripts_object(root);

    let mut changed = false;
    for event in HOOK_EVENTS {
        changed |= add_command_to_event(scripts, event);
    }
    if !changed {
        // We created an empty `scripts` object above only if it was absent;
        // drop it again so a no-op truly changes nothing.
        if root.get("scripts").and_then(Value::as_object).is_some_and(Map::is_empty) {
            root.remove("scripts");
        }
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&doc).unwrap() + "\n"))
}

/// Strip [`APPLY_COMMAND`] from both hook events, pruning emptied events and an
/// emptied `scripts` object. `None` if our command is absent everywhere.
fn composer_remove(content: &str) -> Result<Option<String>, String> {
    let mut doc: Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid composer.json: {e}"))?;
    let root = match doc.as_object_mut() {
        Some(r) => r,
        None => return Ok(None),
    };
    let scripts = match root.get_mut("scripts").and_then(Value::as_object_mut) {
        Some(s) => s,
        None => return Ok(None),
    };

    let mut changed = false;
    for event in HOOK_EVENTS {
        changed |= remove_command_from_event(scripts, event);
    }
    if !changed {
        return Ok(None);
    }
    if scripts.is_empty() {
        root.remove("scripts");
    }
    Ok(Some(serde_json::to_string_pretty(&doc).unwrap() + "\n"))
}

/// Get-or-create the `scripts` object (replacing a `null`).
fn ensure_scripts_object(root: &mut Map<String, Value>) -> &mut Map<String, Value> {
    let needs_init = !root.get("scripts").map(Value::is_object).unwrap_or(false);
    if needs_init {
        root.insert("scripts".to_string(), Value::Object(Map::new()));
    }
    root.get_mut("scripts").unwrap().as_object_mut().unwrap()
}

/// Add [`APPLY_COMMAND`] to one event, normalising string → array. Returns
/// whether the event changed. Already-present (exact command) is a no-op.
fn add_command_to_event(scripts: &mut Map<String, Value>, event: &str) -> bool {
    let cmd = Value::String(APPLY_COMMAND.to_string());
    match scripts.get_mut(event) {
        None => {
            scripts.insert(event.to_string(), Value::Array(vec![cmd]));
            true
        }
        Some(Value::String(s)) => {
            if s == APPLY_COMMAND {
                false
            } else {
                let existing = Value::String(s.clone());
                scripts.insert(event.to_string(), Value::Array(vec![existing, cmd]));
                true
            }
        }
        Some(Value::Array(arr)) => {
            if arr.iter().any(|v| v.as_str() == Some(APPLY_COMMAND)) {
                false
            } else {
                arr.push(cmd);
                true
            }
        }
        // A non-string/array script value is user data we won't clobber.
        Some(_) => false,
    }
}

/// Remove [`APPLY_COMMAND`] from one event, pruning an emptied event key.
/// Returns whether the event changed.
fn remove_command_from_event(scripts: &mut Map<String, Value>, event: &str) -> bool {
    match scripts.get_mut(event) {
        Some(Value::String(s)) if s == APPLY_COMMAND => {
            scripts.remove(event);
            true
        }
        Some(Value::Array(arr)) => {
            let before = arr.len();
            arr.retain(|v| v.as_str() != Some(APPLY_COMMAND));
            if arr.len() == before {
                return false;
            }
            if arr.is_empty() {
                scripts.remove(event);
            }
            true
        }
        _ => false,
    }
}

// ── async wrappers ───────────────────────────────────────────────────────────

/// Wire the project: append our command to the composer script events.
pub async fn add_hook(project: &ComposerProject, dry_run: bool) -> ComposerEditResult {
    edit(&project.composer_json, dry_run, composer_add).await
}

/// Unwire the project: strip our command, pruning emptied keys.
pub async fn remove_hook(project: &ComposerProject, dry_run: bool) -> ComposerEditResult {
    edit(&project.composer_json, dry_run, composer_remove).await
}

async fn edit(
    composer_json: &Path,
    dry_run: bool,
    transform: impl FnOnce(&str) -> Result<Option<String>, String>,
) -> ComposerEditResult {
    let result = async {
        let content = match fs::read_to_string(composer_json).await {
            Ok(c) => c,
            // A missing composer.json on remove is a no-op, not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        match transform(&content)? {
            None => Ok(false),
            Some(new) => {
                if !dry_run {
                    fs::write(composer_json, &new).await.map_err(|e| e.to_string())?;
                }
                Ok(true)
            }
        }
    }
    .await;
    ComposerEditResult::from_result(composer_json.display().to_string(), result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str = "{\n  \"name\": \"acme/app\",\n  \"require\": {\n    \"php\": \">=8.1\"\n  }\n}\n";

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn test_add_wires_both_events_and_is_idempotent() {
        let out = composer_add(BASIC).unwrap().unwrap();
        let doc = parse(&out);
        for event in HOOK_EVENTS {
            let arr = doc["scripts"][event].as_array().unwrap();
            assert!(arr.iter().any(|v| v == APPLY_COMMAND), "{event} must carry our command");
        }
        assert!(is_hook_present(&out));
        // Idempotent: second add is a no-op.
        assert!(composer_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_add_preserves_key_order_and_require() {
        let out = composer_add(BASIC).unwrap().unwrap();
        // `name` and `require` must precede the appended `scripts`.
        let pos_name = out.find("\"name\"").unwrap();
        let pos_require = out.find("\"require\"").unwrap();
        let pos_scripts = out.find("\"scripts\"").unwrap();
        assert!(pos_name < pos_require && pos_require < pos_scripts, "key order preserved:\n{out}");
        assert_eq!(parse(&out)["require"]["php"], ">=8.1");
    }

    #[test]
    fn test_add_preserves_user_script_as_array_member() {
        let with_user = "{\n  \"scripts\": {\n    \"post-install-cmd\": \"@php artisan\"\n  }\n}\n";
        let out = composer_add(with_user).unwrap().unwrap();
        let arr = parse(&out)["scripts"]["post-install-cmd"]
            .as_array()
            .unwrap()
            .clone();
        assert!(arr.iter().any(|v| v == "@php artisan"), "user command kept");
        assert!(arr.iter().any(|v| v == APPLY_COMMAND), "ours appended");
        // post-update-cmd is freshly created.
        assert!(parse(&out)["scripts"]["post-update-cmd"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == APPLY_COMMAND));
    }

    #[test]
    fn test_remove_restores_user_only_state() {
        let with_user = "{\n  \"scripts\": {\n    \"post-install-cmd\": \"@php artisan\"\n  }\n}\n";
        let added = composer_add(with_user).unwrap().unwrap();
        let removed = composer_remove(&added).unwrap().unwrap();
        let doc = parse(&removed);
        // Our command is gone everywhere.
        assert!(!is_hook_present(&removed));
        // The user's command survives (still present in post-install-cmd).
        let pi = doc["scripts"]["post-install-cmd"].as_array().unwrap();
        assert!(pi.iter().any(|v| v == "@php artisan"));
        // The event we created solely for our command is pruned.
        assert!(doc["scripts"].get("post-update-cmd").is_none());
    }

    #[test]
    fn test_remove_prunes_scripts_object_when_only_ours() {
        let added = composer_add(BASIC).unwrap().unwrap();
        let removed = composer_remove(&added).unwrap().unwrap();
        // We created `scripts` solely for our two events; removing both prunes it.
        assert!(parse(&removed).get("scripts").is_none(), "emptied scripts pruned:\n{removed}");
        assert!(!is_hook_present(&removed));
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(composer_remove(BASIC).unwrap().is_none());
    }

    #[test]
    fn test_round_trip_restores_basic_byte_for_byte() {
        // A composer.json already in 2-space `to_string_pretty` form round-trips
        // byte-for-byte: add then remove yields the input exactly.
        let added = composer_add(BASIC).unwrap().unwrap();
        let removed = composer_remove(&added).unwrap().unwrap();
        assert_eq!(removed, BASIC, "add→remove restores the original bytes");
    }

    #[test]
    fn test_user_string_event_already_ours_is_noop() {
        // An event whose string value is exactly our command counts as present.
        let already = format!(
            "{{\n  \"scripts\": {{\n    \"post-install-cmd\": \"{APPLY_COMMAND}\",\n    \"post-update-cmd\": \"{APPLY_COMMAND}\"\n  }}\n}}\n"
        );
        assert!(is_hook_present(&already));
        assert!(composer_add(&already).unwrap().is_none(), "exact-string command is idempotent");
    }

    #[test]
    fn test_invalid_json_is_error() {
        assert!(composer_add("not json!!!").is_err());
    }

    #[test]
    fn test_non_object_scripts_is_error() {
        assert!(composer_add("{\"scripts\": \"oops\"}").is_err());
    }

    #[test]
    fn test_is_hook_present_false_without_scripts() {
        assert!(!is_hook_present(BASIC));
        assert!(!is_hook_present("{}"));
    }

    #[tokio::test]
    async fn test_async_add_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cj = dir.path().join("composer.json");
        fs::write(&cj, BASIC).await.unwrap();
        let project = discover_composer_project(dir.path()).await.unwrap();

        let added = add_hook(&project, false).await;
        assert_eq!(added.status, ComposerSetupStatus::Updated);
        assert!(is_hook_present(&fs::read_to_string(&cj).await.unwrap()));

        // Idempotent.
        assert_eq!(add_hook(&project, false).await.status, ComposerSetupStatus::AlreadyConfigured);

        let removed = remove_hook(&project, false).await;
        assert_eq!(removed.status, ComposerSetupStatus::Updated);
        assert_eq!(fs::read_to_string(&cj).await.unwrap(), BASIC, "byte-for-byte restore");
    }

    #[tokio::test]
    async fn test_async_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let cj = dir.path().join("composer.json");
        fs::write(&cj, BASIC).await.unwrap();
        let project = discover_composer_project(dir.path()).await.unwrap();
        let res = add_hook(&project, true).await;
        assert_eq!(res.status, ComposerSetupStatus::Updated);
        assert_eq!(fs::read_to_string(&cj).await.unwrap(), BASIC, "dry-run must not write");
    }

    #[tokio::test]
    async fn test_discover_none_without_composer_json() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_composer_project(dir.path()).await.is_none());
    }
}
