//! Persistent update-check state, shared by the passive notifier and
//! `--update` itself (an explicit update refreshes `latest_seen` so the
//! notifier never nags about a version the user just installed).
//!
//! This is disposable *cache* state, not configuration: it lives under the
//! per-user cache root (the same root the gem/composer launchers use for
//! their binary cache) and every read tolerates absence, corruption, and
//! clock skew by degrading to "never checked". Nothing in here may ever
//! fail a command — callers treat all errors as "skip the check".

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::utils::fs::atomic_write_bytes;

/// Checks are due at most once per this interval.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A `last_check_at` this far in the future is clock skew, not a valid
/// suppression: treat it as never-checked so a wrong clock cannot wedge
/// the notifier until the bogus timestamp passes.
const FORWARD_SKEW_SLACK: Duration = Duration::from_secs(5 * 60);

/// On-disk schema (camelCase JSON, unix seconds). Unknown fields are
/// ignored and missing fields default, so both directions of version drift
/// stay non-fatal.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct UpdateCheckState {
    pub schema_version: u32,
    /// When a check last *ran* (success or failure) — rate-limits attempts.
    pub last_check_at: Option<u64>,
    /// Newest release version observed by any check or explicit update.
    pub latest_seen: Option<String>,
    /// When a notice was last printed — rate-limits the nag itself.
    pub last_notified_at: Option<u64>,
}

pub const STATE_SCHEMA_VERSION: u32 = 1;

/// Seconds since the unix epoch, saturating at 0 on a pre-1970 clock.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Directory holding the state file (and the update lock). Resolution:
/// `SOCKET_UPDATE_STATE_DIR` (internal override so tests never touch the
/// real per-user dir) → `$XDG_CACHE_HOME` → `~/.cache` (all Unix flavors,
/// macOS included — deliberately the launchers' shared cache root, not
/// `~/Library/Caches`) → `%LOCALAPPDATA%` → `%USERPROFILE%\AppData\Local`
/// (Windows). `None` = no resolvable base; callers silently skip.
pub fn state_dir() -> Option<PathBuf> {
    fn env_dir(name: &str) -> Option<PathBuf> {
        std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    if let Some(dir) = env_dir("SOCKET_UPDATE_STATE_DIR") {
        return Some(dir);
    }
    let base = if cfg!(windows) {
        env_dir("LOCALAPPDATA").or_else(|| {
            env_dir("USERPROFILE").map(|p| p.join("AppData").join("Local"))
        })
    } else {
        env_dir("XDG_CACHE_HOME").or_else(|| env_dir("HOME").map(|h| h.join(".cache")))
    };
    base.map(|b| b.join("socket-patch"))
}

fn state_file_path() -> Option<PathBuf> {
    state_dir().map(|d| d.join("update-check.json"))
}

/// Load the state, degrading to `Default` (never-checked) on any missing
/// dir, unreadable file, or unparseable content. Cache, not config: no
/// warning is worth printing.
pub fn load_state() -> UpdateCheckState {
    let Some(path) = state_file_path() else {
        return UpdateCheckState::default();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return UpdateCheckState::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Persist the state atomically (stage + fsync + rename). Errors bubble so
/// callers can debug-log them, but callers must treat them as non-fatal.
pub async fn save_state(state: &UpdateCheckState) -> std::io::Result<()> {
    let Some(path) = state_file_path() else {
        return Ok(()); // nowhere to persist — same as the load side's silence
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut state = state.clone();
    state.schema_version = STATE_SCHEMA_VERSION;
    let bytes = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
    atomic_write_bytes(&path, &bytes).await
}

/// Whether a fresh check is due at `now`, given the recorded
/// `last_check_at`. Pure so the skew rules are table-testable.
pub fn check_is_due(last_check_at: Option<u64>, now: u64) -> bool {
    is_due(last_check_at, now)
}

/// Whether printing a notice is due (same cadence + skew rules as checks).
pub fn notice_is_due(last_notified_at: Option<u64>, now: u64) -> bool {
    is_due(last_notified_at, now)
}

fn is_due(last: Option<u64>, now: u64) -> bool {
    let Some(last) = last else {
        return true;
    };
    // A timestamp more than the slack into the future is clock skew:
    // due now, so a bad clock self-heals instead of wedging the check.
    if last > now + FORWARD_SKEW_SLACK.as_secs() {
        return true;
    }
    now.saturating_sub(last) >= CHECK_INTERVAL.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const NOW: u64 = 1_753_142_400;

    #[test]
    fn due_when_never_checked() {
        assert!(check_is_due(None, NOW));
    }

    #[test]
    fn fresh_check_suppresses_until_interval_elapses() {
        assert!(!check_is_due(Some(NOW - 60 * 60), NOW), "1h ago: fresh");
        assert!(
            !check_is_due(Some(NOW - CHECK_INTERVAL.as_secs() + 1), NOW),
            "one second inside the interval: still fresh"
        );
        assert!(
            check_is_due(Some(NOW - CHECK_INTERVAL.as_secs()), NOW),
            "exactly the interval: due"
        );
        assert!(check_is_due(Some(NOW - 25 * 60 * 60), NOW), "25h ago: due");
    }

    #[test]
    fn future_timestamp_beyond_slack_means_due() {
        // A wrong clock (or a state file written by a machine with one)
        // must never suppress checks until the bogus timestamp passes.
        assert!(check_is_due(Some(NOW + 48 * 60 * 60), NOW));
        // Small forward skew (below the slack) is normal cross-process
        // drift and counts as fresh.
        assert!(!check_is_due(Some(NOW + 60), NOW));
    }

    #[test]
    fn state_round_trips_through_json() {
        let state = UpdateCheckState {
            schema_version: STATE_SCHEMA_VERSION,
            last_check_at: Some(NOW),
            latest_seen: Some("3.4.0".to_string()),
            last_notified_at: Some(NOW - 10),
        };
        let json = serde_json::to_string(&state).unwrap();
        // The wire format is camelCase — pinned because external tooling
        // (and future schema migrations) key off these exact names.
        assert!(json.contains("\"lastCheckAt\""), "{json}");
        assert!(json.contains("\"latestSeen\""), "{json}");
        let back: UpdateCheckState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn unknown_fields_and_missing_fields_tolerated() {
        let forward: UpdateCheckState =
            serde_json::from_str(r#"{"schemaVersion":9,"futureField":true,"lastCheckAt":5}"#)
                .unwrap();
        assert_eq!(forward.last_check_at, Some(5));
        let sparse: UpdateCheckState = serde_json::from_str("{}").unwrap();
        assert_eq!(sparse, UpdateCheckState::default());
    }

    #[test]
    fn corrupt_state_loads_as_default() {
        // load_state's parse path: any non-JSON bytes degrade to Default.
        let garbage: Result<UpdateCheckState, _> = serde_json::from_slice(b"\x00garbage{{{");
        assert!(garbage.is_err());
        // (The full read path is exercised e2e; here we pin that the
        // fallback the code uses — unwrap_or_default — yields never-checked.)
        assert!(check_is_due(UpdateCheckState::default().last_check_at, NOW));
    }

    #[test]
    #[serial(update_state_dir_env)]
    fn state_dir_honors_override_and_empty_env_falls_through() {
        // Env-mutating test: keep it self-contained and restore.
        let prev = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", "/tmp/socket-update-test");
        assert_eq!(
            state_dir(),
            Some(PathBuf::from("/tmp/socket-update-test"))
        );
        // Empty value means unset (env_non_empty convention) — falls through
        // to the platform default rather than yielding "".
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", "");
        assert_ne!(state_dir(), Some(PathBuf::from("")));
        match prev {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
    }

    #[tokio::test]
    #[serial(update_state_dir_env)]
    async fn save_state_writes_atomically_with_no_stage_droppings() {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", tmp.path());
        let state = UpdateCheckState {
            last_check_at: Some(NOW),
            latest_seen: Some("9.9.9".into()),
            ..Default::default()
        };
        save_state(&state).await.unwrap();
        let loaded = load_state();
        assert_eq!(loaded.latest_seen.as_deref(), Some("9.9.9"));
        assert_eq!(loaded.schema_version, STATE_SCHEMA_VERSION);
        // Atomic writer leaves no .socket-stage-* siblings behind.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "update-check.json")
            .collect();
        assert!(leftovers.is_empty(), "unexpected files: {leftovers:?}");
        match prev {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
    }
}
