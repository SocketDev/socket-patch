//! Read-only fallback reader for the JS Socket CLI's persisted config.
//!
//! `socket login` / `socket config set` (the npm `socket` CLI) persist a
//! base64-encoded JSON object at `<data dir>/socket/settings/config.json`:
//!
//! - Linux:   `$XDG_DATA_HOME` or `~/.local/share`
//! - macOS:   `$XDG_DATA_HOME` or `~/Library/Application Support`
//! - Windows: `%LOCALAPPDATA%` or `%USERPROFILE%\AppData\Local`
//!
//! socket-patch reads exactly three keys — `apiToken`, `defaultOrg` (with
//! its socket-cli alias `org`), and `apiBaseUrl` — as the resolution layer
//! *below* env vars and *above* built-in defaults, so a single
//! `socket login` configures every Socket tool. The file is **never
//! written**: socket-cli owns it, and its other keys (`apiProxy`,
//! `enforcedOrgs`, `skipAskToPersistDefaultOrg`) encode socket-cli UX
//! policy with no socket-patch analog and are deliberately ignored.
//!
//! Failure semantics: a missing file (or unresolvable data dir) is silent —
//! that is the normal case. A present-but-unreadable or undecodable file
//! warns once on stderr (even under `--silent`/`--json`, matching the
//! legacy-env deprecation warnings) and is then treated as absent; the
//! fallback layer must never break a working command. Diagnostics go to
//! stderr only, so `--json` stdout stays machine-parseable.
//!
//! `SOCKET_NO_CONFIG` (truthy) disables the layer entirely — the escape
//! hatch for hermetic tests and for users who want pure flag+env behavior.

use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine as _;

/// The subset of socket-cli's `LocalConfig` that socket-patch honors.
/// Values are non-empty strings; empty/missing/non-string JSON values are
/// normalized to `None` at parse time (empty == unset, the repo-wide rule).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketCliConfig {
    pub api_token: Option<String>,
    pub default_org: Option<String>,
    pub api_base_url: Option<String>,
}

/// Read an env var, treating empty (or non-Unicode) as unset. The repo has
/// shipped empty-`HOME` bugs before; an exported-but-blank `XDG_DATA_HOME`
/// must not resolve paths against the filesystem root.
fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Truthy check for the config-layer toggles (`SOCKET_NO_CONFIG`,
/// `SOCKET_NO_API_TOKEN`). Accepts the same affirmative vocabulary as the
/// CLI's `parse_bool_flag` (`1`/`true`/`yes`/`on`, case-insensitive);
/// anything else — including unset and empty — is false.
fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on" | "y" | "t"
    )
}

/// `SOCKET_NO_CONFIG` — disable the socket-cli config fallback layer.
pub fn is_config_disabled() -> bool {
    env_flag("SOCKET_NO_CONFIG")
}

/// `SOCKET_NO_API_TOKEN` — ignore ambient API tokens (env var and
/// socket-cli config); only an explicit `--api-token` flag authenticates.
/// Mirrors socket-cli's `SOCKET_CLI_NO_API_TOKEN` (aliased in the CLI).
pub fn no_api_token_veto() -> bool {
    env_flag("SOCKET_NO_API_TOKEN")
}

/// The platform data dir socket-cli resolves in its `getSocketAppDataPath`
/// (`packages/cli/src/constants/paths.mts`) — mirrored exactly so both
/// tools find the same file.
fn data_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env_non_empty("LOCALAPPDATA").map(PathBuf::from).or_else(|| {
            env_non_empty("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
    }
    #[cfg(target_os = "macos")]
    {
        env_non_empty("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
            env_non_empty("HOME")
                .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
        })
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        env_non_empty("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env_non_empty("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }
}

/// Full path of socket-cli's persisted config, or `None` when no data dir
/// resolves (e.g. `HOME` unset in a stripped container) — silently absent.
pub fn config_json_path() -> Option<PathBuf> {
    data_home().map(|d| d.join("socket").join("settings").join("config.json"))
}

/// Decode the config file body: base64(JSON) per socket-cli, with a plain-JSON
/// fallback for robustness (hand-edited or future-format files). Unknown keys
/// are ignored and known keys with non-string values are treated as unset —
/// the allowlist posture socket-cli itself applies when reading.
fn parse_config_bytes(raw: &[u8]) -> Result<SocketCliConfig, String> {
    let text = std::str::from_utf8(raw).map_err(|e| format!("not UTF-8: {e}"))?;
    let trimmed = text.trim();
    let value: serde_json::Value = match base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .and_then(|decoded| serde_json::from_slice(&decoded).ok())
    {
        Some(v) => v,
        // Lenient fallback: accept the payload as plain JSON.
        None => serde_json::from_str(trimmed)
            .map_err(|e| format!("neither base64-encoded JSON nor plain JSON: {e}"))?,
    };
    let obj = value
        .as_object()
        .ok_or_else(|| "top-level JSON value is not an object".to_string())?;
    let string_key = |key: &str| -> Option<String> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Ok(SocketCliConfig {
        api_token: string_key("apiToken"),
        // socket-cli treats `org` as a convenience alias for `defaultOrg`;
        // prefer the canonical key when both are present.
        default_org: string_key("defaultOrg").or_else(|| string_key("org")),
        api_base_url: string_key("apiBaseUrl"),
    })
}

/// Read the config from disk. `None` covers every failure path; a corrupt
/// or unreadable file warns (callers cache this, so it fires once per
/// process).
fn read_from_disk() -> Option<SocketCliConfig> {
    let path = config_json_path()?;
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "[socket-patch] warning: unreadable socket-cli config at {}: {e}; ignoring it",
                path.display()
            );
            return None;
        }
    };
    match parse_config_bytes(&raw) {
        Ok(config) => Some(config),
        Err(e) => {
            eprintln!(
                "[socket-patch] warning: could not parse socket-cli config at {}: {e}; \
                 ignoring it (re-run `socket login` to rewrite it)",
                path.display()
            );
            None
        }
    }
}

/// The socket-cli config, if present and enabled. The disk read is done at
/// most once per process; the `SOCKET_NO_CONFIG` gate is checked on every
/// call so tests (and wrapper re-execs) can flip it after startup.
pub fn load() -> Option<&'static SocketCliConfig> {
    if is_config_disabled() {
        return None;
    }
    static CACHE: OnceLock<Option<SocketCliConfig>> = OnceLock::new();
    CACHE.get_or_init(read_from_disk).as_ref()
}

/// Resolve the authenticated API base URL through the full fallback chain:
/// `SOCKET_API_URL` env → socket-cli config `apiBaseUrl` →
/// [`DEFAULT_SOCKET_API_URL`](crate::constants::DEFAULT_SOCKET_API_URL).
///
/// Shared by API-client construction and the telemetry endpoint resolver so
/// the two can never disagree about which host is "the API". (An explicit
/// `--api-url` override is applied by the caller *before* this fallback.)
pub fn resolve_api_base_url() -> String {
    env_non_empty("SOCKET_API_URL")
        .or_else(|| load().and_then(|c| c.api_base_url.clone()))
        .unwrap_or_else(|| crate::constants::DEFAULT_SOCKET_API_URL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(json: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .encode(json)
            .into_bytes()
    }

    #[test]
    fn parses_base64_encoded_json() {
        let cfg = parse_config_bytes(&b64(
            r#"{"apiToken":"sktsec_tok","defaultOrg":"acme","apiBaseUrl":"https://api.example"}"#,
        ))
        .unwrap();
        assert_eq!(cfg.api_token.as_deref(), Some("sktsec_tok"));
        assert_eq!(cfg.default_org.as_deref(), Some("acme"));
        assert_eq!(cfg.api_base_url.as_deref(), Some("https://api.example"));
    }

    /// socket-cli writes the file without a trailing newline, but editors
    /// add one; whitespace around the base64 payload must not matter.
    #[test]
    fn tolerates_surrounding_whitespace() {
        let mut raw = b"\n  ".to_vec();
        raw.extend_from_slice(&b64(r#"{"apiToken":"t"}"#));
        raw.extend_from_slice(b"\n");
        let cfg = parse_config_bytes(&raw).unwrap();
        assert_eq!(cfg.api_token.as_deref(), Some("t"));
    }

    /// Lenient fallback: a plain-JSON body (hand-edited file) still parses.
    #[test]
    fn falls_back_to_plain_json() {
        let cfg = parse_config_bytes(br#"{"defaultOrg":"acme"}"#).unwrap();
        assert_eq!(cfg.default_org.as_deref(), Some("acme"));
        assert_eq!(cfg.api_token, None);
    }

    /// `org` is socket-cli's alias for `defaultOrg`; the canonical key wins
    /// when both are present.
    #[test]
    fn default_org_beats_org_alias() {
        let cfg = parse_config_bytes(br#"{"defaultOrg":"canon","org":"alias"}"#).unwrap();
        assert_eq!(cfg.default_org.as_deref(), Some("canon"));
        let cfg = parse_config_bytes(br#"{"org":"alias"}"#).unwrap();
        assert_eq!(cfg.default_org.as_deref(), Some("alias"));
    }

    /// Unknown keys are ignored; known keys with non-string or empty values
    /// are unset — never an error (allowlist posture).
    #[test]
    fn ignores_unknown_keys_and_non_string_values() {
        let cfg = parse_config_bytes(
            br#"{"apiToken":42,"apiBaseUrl":"","enforcedOrgs":["a"],"future":{"x":1}}"#,
        )
        .unwrap();
        assert_eq!(cfg, SocketCliConfig::default());
    }

    #[test]
    fn rejects_garbage_and_non_object_json() {
        assert!(parse_config_bytes(b"!!! not base64 or json").is_err());
        assert!(parse_config_bytes(b"[1,2,3]").is_err());
        assert!(parse_config_bytes(&[0xff, 0xfe]).is_err());
    }

    /// Base64 that decodes to garbage (truncated/double-encoded) must fall
    /// through to the plain-JSON attempt and then error, not panic.
    #[test]
    fn base64_of_non_json_errors() {
        assert!(parse_config_bytes(&b64("definitely not json")).is_err());
    }

    // Env-mutating tests below are serialized: XDG_DATA_HOME / HOME /
    // SOCKET_NO_CONFIG are process-global and shared with other suites.

    fn with_env(pairs: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let saved: Vec<(&str, Option<String>)> = pairs
            .iter()
            .map(|&(k, _)| (k, std::env::var(k).ok()))
            .collect();
        for &(k, v) in pairs {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    #[serial_test::serial]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn path_prefers_xdg_data_home_then_home() {
        with_env(
            &[("XDG_DATA_HOME", Some("/xdg")), ("HOME", Some("/home/u"))],
            || {
                assert_eq!(
                    config_json_path(),
                    Some(PathBuf::from("/xdg/socket/settings/config.json"))
                );
            },
        );
        with_env(
            &[("XDG_DATA_HOME", None), ("HOME", Some("/home/u"))],
            || {
                assert_eq!(
                    config_json_path(),
                    Some(PathBuf::from(
                        "/home/u/.local/share/socket/settings/config.json"
                    ))
                );
            },
        );
    }

    #[test]
    #[serial_test::serial]
    #[cfg(target_os = "macos")]
    fn path_prefers_xdg_data_home_then_home() {
        with_env(
            &[("XDG_DATA_HOME", Some("/xdg")), ("HOME", Some("/Users/u"))],
            || {
                assert_eq!(
                    config_json_path(),
                    Some(PathBuf::from("/xdg/socket/settings/config.json"))
                );
            },
        );
        with_env(
            &[("XDG_DATA_HOME", None), ("HOME", Some("/Users/u"))],
            || {
                assert_eq!(
                    config_json_path(),
                    Some(PathBuf::from(
                        "/Users/u/Library/Application Support/socket/settings/config.json"
                    ))
                );
            },
        );
    }

    /// Empty env values are unset — an exported-but-blank `XDG_DATA_HOME`
    /// (or `HOME`) must not resolve against the filesystem root, and with
    /// no base dir at all the layer is silently absent.
    #[test]
    #[serial_test::serial]
    #[cfg(unix)]
    fn empty_env_is_unset_and_no_base_dir_is_none() {
        with_env(
            &[("XDG_DATA_HOME", Some("")), ("HOME", Some("/home/u"))],
            || {
                let path = config_json_path().expect("HOME fallback");
                assert!(
                    path.starts_with("/home/u"),
                    "blank XDG_DATA_HOME must fall through to HOME: {path:?}"
                );
            },
        );
        with_env(&[("XDG_DATA_HOME", None), ("HOME", Some(""))], || {
            assert_eq!(config_json_path(), None);
        });
        with_env(&[("XDG_DATA_HOME", None), ("HOME", None)], || {
            assert_eq!(config_json_path(), None);
        });
    }

    #[test]
    #[serial_test::serial]
    fn socket_no_config_disables_load() {
        with_env(&[("SOCKET_NO_CONFIG", Some("1"))], || {
            assert!(load().is_none());
        });
        with_env(&[("SOCKET_NO_CONFIG", Some("yes"))], || {
            assert!(is_config_disabled());
        });
        with_env(&[("SOCKET_NO_CONFIG", Some(""))], || {
            assert!(!is_config_disabled());
        });
        with_env(&[("SOCKET_NO_CONFIG", Some("0"))], || {
            assert!(!is_config_disabled());
        });
    }

    #[test]
    #[serial_test::serial]
    fn resolve_api_base_url_layers() {
        // Env wins outright.
        with_env(
            &[
                ("SOCKET_API_URL", Some("https://env.example")),
                ("SOCKET_NO_CONFIG", Some("1")),
            ],
            || {
                assert_eq!(resolve_api_base_url(), "https://env.example");
            },
        );
        // No env, config disabled → built-in default.
        with_env(
            &[
                ("SOCKET_API_URL", None),
                ("SOCKET_NO_CONFIG", Some("1")),
            ],
            || {
                assert_eq!(
                    resolve_api_base_url(),
                    crate::constants::DEFAULT_SOCKET_API_URL
                );
            },
        );
        // Empty env is unset.
        with_env(
            &[
                ("SOCKET_API_URL", Some("")),
                ("SOCKET_NO_CONFIG", Some("1")),
            ],
            || {
                assert_eq!(
                    resolve_api_base_url(),
                    crate::constants::DEFAULT_SOCKET_API_URL
                );
            },
        );
    }
}
