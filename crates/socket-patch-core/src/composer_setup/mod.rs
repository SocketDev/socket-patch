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
const APPLY_COMMAND: &str = "socket-patch apply --offline --silent --ecosystems composer";

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

#[derive(Debug)]
pub struct ComposerEditResult {
    /// Envelope `files[].kind` — always `composer`.
    pub kind: &'static str,
    pub path: String,
    pub status: ComposerSetupStatus,
    pub error: Option<String>,
}

/// Find the composer project rooted at `cwd`: the path to a `composer.json`
/// directly in `cwd`. cwd-only, matching the other single-project backends
/// (gem/pypi/go).
pub async fn discover_composer_project(cwd: &Path) -> Option<PathBuf> {
    let composer_json = cwd.join("composer.json");
    fs::metadata(&composer_json)
        .await
        .is_ok()
        .then_some(composer_json)
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

/// Parse `composer.json` for editing, rejecting malformed input: the root must
/// be a JSON object, and a present `scripts` must be an object (or `null`) —
/// add refuses to clobber it, remove refuses to silently swallow it as a
/// "nothing to remove" no-op.
fn parse_checked(content: &str) -> Result<Value, String> {
    let doc: Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid composer.json: {e}"))?;
    if !doc.is_object() {
        return Err("Invalid composer.json: root is not a JSON object".to_string());
    }
    if let Some(scripts) = doc.get("scripts") {
        if !scripts.is_null() && !scripts.is_object() {
            return Err("Invalid composer.json: \"scripts\" is not a JSON object".to_string());
        }
    }
    Ok(doc)
}

/// Append [`APPLY_COMMAND`] to both hook events, normalising each to an array.
/// `None` if already present in every event (idempotent no-op).
fn composer_add(content: &str) -> Result<Option<String>, String> {
    let mut doc = parse_checked(content)?;
    let root = doc.as_object_mut().unwrap();

    // Get-or-create the `scripts` object (replacing a `null`).
    if !root.get("scripts").map(Value::is_object).unwrap_or(false) {
        root.insert("scripts".to_string(), Value::Object(Map::new()));
    }
    let scripts = root.get_mut("scripts").unwrap().as_object_mut().unwrap();

    let mut changed = false;
    for event in HOOK_EVENTS {
        changed |= add_command_to_event(scripts, event)?;
    }
    if !changed {
        // We created an empty `scripts` object above only if it was absent;
        // drop it again so a no-op truly changes nothing.
        if root
            .get("scripts")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        {
            root.remove("scripts");
        }
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&doc).unwrap() + "\n"))
}

/// Strip [`APPLY_COMMAND`] from both hook events, pruning emptied events and an
/// emptied `scripts` object. `None` if our command is absent everywhere.
fn composer_remove(content: &str) -> Result<Option<String>, String> {
    let mut doc = parse_checked(content)?;
    let root = doc.as_object_mut().unwrap();
    // An absent (or `null`) `scripts` is a legitimate no-op: nothing of ours.
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
        // shift_remove: with preserve_order, plain `remove` is swap_remove and
        // would teleport the last root key into this slot.
        root.shift_remove("scripts");
    }
    Ok(Some(serde_json::to_string_pretty(&doc).unwrap() + "\n"))
}

/// Add [`APPLY_COMMAND`] to one event, normalising string → array. Returns
/// whether the event changed; errors on a non-string/array event value it
/// refuses to clobber. Any command already carrying [`HOOK_MARKER`]
/// counts as present — the same predicate as [`is_hook_present`] / `--check`,
/// so a user-customized flag set is left alone rather than duplicated.
fn add_command_to_event(scripts: &mut Map<String, Value>, event: &str) -> Result<bool, String> {
    if event_contains_marker(scripts.get(event)) {
        return Ok(false);
    }
    let cmd = Value::String(APPLY_COMMAND.to_string());
    match scripts.get_mut(event) {
        None => {
            scripts.insert(event.to_string(), Value::Array(vec![cmd]));
            Ok(true)
        }
        Some(Value::String(s)) => {
            let existing = Value::String(s.clone());
            scripts.insert(event.to_string(), Value::Array(vec![existing, cmd]));
            Ok(true)
        }
        Some(Value::Array(arr)) => {
            arr.push(cmd);
            Ok(true)
        }
        // A non-string/array script value is user data we won't clobber — and
        // can't wire into, so treating it as "no change" would surface as
        // AlreadyConfigured while `--check` says not configured. Refuse loudly,
        // like the non-object-`scripts` guard.
        Some(_) => Err(format!(
            "Invalid composer.json: \"{event}\" script is not a string or array"
        )),
    }
}

/// Remove [`APPLY_COMMAND`] from one event, pruning an emptied event key.
/// Returns whether the event changed.
fn remove_command_from_event(scripts: &mut Map<String, Value>, event: &str) -> bool {
    // shift_remove throughout: with preserve_order, plain `remove` is
    // swap_remove and would shuffle the user's other scripts.
    match scripts.get_mut(event) {
        Some(Value::String(s)) if s == APPLY_COMMAND => {
            scripts.shift_remove(event);
            true
        }
        Some(Value::Array(arr)) => {
            let before = arr.len();
            arr.retain(|v| v.as_str() != Some(APPLY_COMMAND));
            if arr.len() == before {
                return false;
            }
            if arr.is_empty() {
                scripts.shift_remove(event);
            }
            true
        }
        _ => false,
    }
}

// ── async wrappers ───────────────────────────────────────────────────────────

/// Wire the project: append our command to the composer script events.
pub async fn add_hook(composer_json: &Path, dry_run: bool) -> ComposerEditResult {
    edit(composer_json, dry_run, composer_add).await
}

/// Unwire the project: strip our command, pruning emptied keys.
pub async fn remove_hook(composer_json: &Path, dry_run: bool) -> ComposerEditResult {
    edit(composer_json, dry_run, composer_remove).await
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
                    // The crate-wide atomic writer (stage+fsync+rename): the
                    // user's committed composer.json must never be left torn
                    // by a crash mid-write.
                    crate::utils::fs::atomic_write_bytes(composer_json, new.as_bytes())
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(true)
            }
        }
    }
    .await;
    let (status, error) = match result {
        Ok(true) => (ComposerSetupStatus::Updated, None),
        Ok(false) => (ComposerSetupStatus::AlreadyConfigured, None),
        Err(e) => (ComposerSetupStatus::Error, Some(e)),
    };
    ComposerEditResult {
        kind: "composer",
        path: composer_json.display().to_string(),
        status,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str =
        "{\n  \"name\": \"acme/app\",\n  \"require\": {\n    \"php\": \">=8.1\"\n  }\n}\n";

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn test_add_wires_both_events_and_is_idempotent() {
        let out = composer_add(BASIC).unwrap().unwrap();
        let doc = parse(&out);
        for event in HOOK_EVENTS {
            let arr = doc["scripts"][event].as_array().unwrap();
            assert!(
                arr.iter().any(|v| v == APPLY_COMMAND),
                "{event} must carry our command"
            );
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
        assert!(
            pos_name < pos_require && pos_require < pos_scripts,
            "key order preserved:\n{out}"
        );
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
        assert!(
            parse(&removed).get("scripts").is_none(),
            "emptied scripts pruned:\n{removed}"
        );
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
        assert!(
            composer_add(&already).unwrap().is_none(),
            "exact-string command is idempotent"
        );
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
        let found = discover_composer_project(dir.path()).await.unwrap();

        let added = add_hook(&found, false).await;
        assert_eq!(added.status, ComposerSetupStatus::Updated);
        assert!(is_hook_present(&fs::read_to_string(&cj).await.unwrap()));

        // Idempotent.
        assert_eq!(
            add_hook(&found, false).await.status,
            ComposerSetupStatus::AlreadyConfigured
        );

        let removed = remove_hook(&found, false).await;
        assert_eq!(removed.status, ComposerSetupStatus::Updated);
        assert_eq!(
            fs::read_to_string(&cj).await.unwrap(),
            BASIC,
            "byte-for-byte restore"
        );
    }

    #[tokio::test]
    async fn test_async_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let cj = dir.path().join("composer.json");
        fs::write(&cj, BASIC).await.unwrap();
        let found = discover_composer_project(dir.path()).await.unwrap();
        let res = add_hook(&found, true).await;
        assert_eq!(res.status, ComposerSetupStatus::Updated);
        assert_eq!(
            fs::read_to_string(&cj).await.unwrap(),
            BASIC,
            "dry-run must not write"
        );
    }

    #[tokio::test]
    async fn test_discover_none_without_composer_json() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_composer_project(dir.path()).await.is_none());
    }

    #[test]
    fn test_remove_round_trip_with_other_user_scripts() {
        // add then remove restores a composer.json that already had unrelated
        // scripts, byte-for-byte (our two events are added and then pruned).
        let inp = "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"test\": \"phpunit\"\n  }\n}\n";
        let added = composer_add(inp).unwrap().unwrap();
        let removed = composer_remove(&added).unwrap().unwrap();
        assert_eq!(removed, inp, "round-trip with user scripts");
    }

    #[test]
    fn test_remove_non_object_root_is_error() {
        // Regression: composer_remove must reject a malformed (non-object) root
        // with an error, not silently report "nothing to remove" — matching
        // composer_add and the npm `remove_package_json_content` contract.
        let err = composer_remove("[1, 2, 3]").unwrap_err();
        assert!(err.contains("root is not a JSON object"), "got: {err}");
        assert!(composer_remove("\"just a string\"").is_err());
        assert!(composer_remove("42").is_err());
    }

    #[test]
    fn test_remove_non_object_scripts_is_error() {
        // Regression: a present-but-non-object `scripts` is malformed. `setup`
        // (composer_add) errors on it; `setup --remove` must too, rather than
        // silently swallowing it as a no-op success.
        let err = composer_remove("{\"scripts\": \"oops\"}").unwrap_err();
        assert!(
            err.contains("\"scripts\" is not a JSON object"),
            "got: {err}"
        );
        assert!(composer_remove("{\"scripts\": 7}").is_err());
        assert!(composer_remove("{\"scripts\": [\"a\"]}").is_err());
        // add and remove agree on what counts as malformed.
        assert!(composer_add("{\"scripts\": \"oops\"}").is_err());
    }

    #[test]
    fn test_remove_absent_or_null_scripts_is_noop_not_error() {
        // A genuinely absent or null `scripts` has nothing of ours: no-op, not
        // an error (the malformed-input guard must not over-trigger).
        assert!(composer_remove("{\"name\": \"x\"}").unwrap().is_none());
        assert!(composer_remove("{\"scripts\": null}").unwrap().is_none());
    }

    #[test]
    fn test_exhaustive_invariants() {
        let event_values = [
            None,
            Some(format!("\"{APPLY_COMMAND}\"")),
            Some("\"@php artisan\"".to_string()),
            Some(format!("[\"{APPLY_COMMAND}\"]")),
            Some("[\"@php artisan\"]".to_string()),
            Some(format!("[\"@php artisan\",\"{APPLY_COMMAND}\"]")),
            Some("[]".to_string()),
        ];
        for a in &event_values {
            for b in &event_values {
                let mut parts = vec![];
                if let Some(v) = a {
                    parts.push(format!("\"post-install-cmd\":{v}"));
                }
                if let Some(v) = b {
                    parts.push(format!("\"post-update-cmd\":{v}"));
                }
                let json = format!("{{\"scripts\":{{{}}}}}", parts.join(","));

                // add is idempotent
                let after_add = match composer_add(&json).unwrap() {
                    Some(out) => {
                        assert!(
                            is_hook_present(&out),
                            "add changed but not present:\n{json}\n{out}"
                        );
                        assert!(
                            composer_add(&out).unwrap().is_none(),
                            "add NOT idempotent:\n{json}\n{out}"
                        );
                        out
                    }
                    None => json.clone(),
                };

                // after a full add, both events must carry our command
                if composer_add(&json).unwrap().is_some() {
                    assert!(is_hook_present(&after_add));
                }

                // remove undoes add, and remove is idempotent
                if let Some(rem) = composer_remove(&after_add).unwrap() {
                    assert!(
                        composer_remove(&rem).unwrap().is_none(),
                        "remove NOT idempotent:\n{after_add}\n{rem}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_add_noops_on_flag_variant_hook() {
        // Regression: `setup --check` (is_hook_present) treats any
        // `socket-patch apply` variant as configured, and `setup` must agree —
        // appending the stock command next to a user-customized flag set would
        // run the hook twice on every install. Mirrors the npm backend's
        // `script_is_configured` contract (loose marker on both sides).
        let customized = "{\"scripts\":{\
            \"post-install-cmd\":[\"socket-patch apply --offline --ecosystems composer\"],\
            \"post-update-cmd\":\"socket-patch apply --offline --ecosystems composer\"}}";
        assert!(is_hook_present(customized), "variant reads as configured");
        assert!(
            composer_add(customized).unwrap().is_none(),
            "add must not duplicate a hook --check already reports as configured"
        );
    }

    // ── atomic-write contract (no truncation / no stage litter) ──────
    //
    // The edit must go through stage+fsync+rename, never a bare truncating
    // write, so a crash can't leave the user's committed composer.json empty.

    #[cfg(unix)]
    #[tokio::test]
    async fn test_add_replaces_readonly_manifest_atomically() {
        use std::os::unix::fs::PermissionsExt;
        // Oracle for the truncating-write bug: rename needs only directory
        // write permission, while a bare `fs::write` must open the target
        // itself for writing — so a read-only composer.json distinguishes the
        // two (EACCES under truncate, clean replace under stage+rename, same
        // as the npm/pypi/cargo/go manifest writers).
        let dir = tempfile::tempdir().unwrap();
        let cj = dir.path().join("composer.json");
        fs::write(&cj, BASIC).await.unwrap();
        std::fs::set_permissions(&cj, std::fs::Permissions::from_mode(0o444)).unwrap();

        let found = discover_composer_project(dir.path()).await.unwrap();
        let res = add_hook(&found, false).await;
        assert_eq!(
            res.status,
            ComposerSetupStatus::Updated,
            "err: {:?}",
            res.error
        );
        assert!(is_hook_present(&fs::read_to_string(&cj).await.unwrap()));
    }

    #[tokio::test]
    async fn test_edit_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let cj = dir.path().join("composer.json");
        fs::write(&cj, BASIC).await.unwrap();
        let found = discover_composer_project(dir.path()).await.unwrap();

        assert_eq!(
            add_hook(&found, false).await.status,
            ComposerSetupStatus::Updated
        );
        assert_eq!(
            remove_hook(&found, false).await.status,
            ComposerSetupStatus::Updated
        );
        assert_eq!(fs::read_to_string(&cj).await.unwrap(), BASIC);

        // No half-written `.socket-stage-*` sibling left behind.
        let mut rd = fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.starts_with(".socket-stage-"), "stage litter: {name}");
        }
    }

    #[test]
    fn test_remove_event_prune_preserves_sibling_script_order() {
        // Regression: with preserve_order, serde_json's `Map::remove` is
        // swap_remove — pruning an emptied event key teleported the *last*
        // script into its slot, shuffling the user's own scripts. Scenario:
        // setup wired the events first, the user appended scripts later.
        let inp = format!(
            "{{\"scripts\":{{\"post-install-cmd\":[\"{APPLY_COMMAND}\"],\"post-update-cmd\":[\"{APPLY_COMMAND}\"],\"test\":\"phpunit\",\"lint\":\"phpcs\"}}}}"
        );
        let removed = composer_remove(&inp).unwrap().unwrap();
        assert!(!is_hook_present(&removed));
        let pos_test = removed.find("\"test\"").unwrap();
        let pos_lint = removed.find("\"lint\"").unwrap();
        assert!(
            pos_test < pos_lint,
            "sibling script order must survive event pruning:\n{removed}"
        );
    }

    #[test]
    fn test_remove_scripts_prune_preserves_root_key_order() {
        // Regression: same swap_remove hazard at the root — pruning an emptied
        // `scripts` object teleported the last root key into its slot.
        let inp = format!(
            "{{\"name\":\"acme/app\",\"scripts\":{{\"post-install-cmd\":[\"{APPLY_COMMAND}\"]}},\"require\":{{\"php\":\">=8.1\"}},\"autoload\":{{}}}}"
        );
        let removed = composer_remove(&inp).unwrap().unwrap();
        assert!(parse(&removed).get("scripts").is_none(), "scripts pruned");
        let pos_name = removed.find("\"name\"").unwrap();
        let pos_require = removed.find("\"require\"").unwrap();
        let pos_autoload = removed.find("\"autoload\"").unwrap();
        assert!(
            pos_name < pos_require && pos_require < pos_autoload,
            "root key order must survive scripts pruning:\n{removed}"
        );
    }

    #[test]
    fn test_add_malformed_event_value_is_error_not_silent_success() {
        // Regression: an event value that is neither string nor array can't be
        // wired (we won't clobber it), but reporting "no change" surfaced as
        // AlreadyConfigured — exit-0 success — while `--check`
        // (is_hook_present) says not configured on the very same file. Refusal
        // must be a loud error, matching the non-object-`scripts` guard.
        let malformed = "{\"scripts\":{\"post-install-cmd\":42,\"post-update-cmd\":{\"a\":\"b\"}}}";
        assert!(!is_hook_present(malformed), "nothing configured here");
        let err = composer_add(malformed).unwrap_err();
        assert!(
            err.contains("not a string or array"),
            "refusal must be an error, got: {err}"
        );
        // remove stays a no-op: a non-string/array value can't hold our
        // command, so there is honestly nothing to strip.
        assert!(composer_remove(malformed).unwrap().is_none());
    }

    #[test]
    fn test_add_then_check_consistency() {
        // For every input where add reports a change, is_hook_present must be true.
        let inputs = [
            BASIC,
            "{\"scripts\":{\"post-install-cmd\":\"@php artisan\"}}",
            "{\"scripts\":{\"post-install-cmd\":[\"a\",\"b\"]}}",
            "{\"scripts\":{}}",
            "{\"scripts\":null}",
            "{}",
        ];
        for inp in inputs {
            if let Some(out) = composer_add(inp).unwrap() {
                assert!(
                    is_hook_present(&out),
                    "add changed but check false for {inp}\n{out}"
                );
                // second add is a no-op
                assert!(
                    composer_add(&out).unwrap().is_none(),
                    "not idempotent for {inp}"
                );
                // remove undoes
                let rem = composer_remove(&out).unwrap().unwrap();
                assert!(!is_hook_present(&rem), "remove left hook for {inp}\n{rem}");
            }
        }
    }
}
