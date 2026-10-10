//! Environment-variable readers shared by the CLI and core, plus the
//! accepted `SOCKET_CLI_*` peer aliases.

/// Check if debug mode is enabled via `SOCKET_DEBUG`.
pub fn is_debug_enabled() -> bool {
    matches!(
        std::env::var("SOCKET_DEBUG").unwrap_or_default().as_str(),
        "1" | "true"
    )
}

/// `message` made safe for a `SOCKET_DEBUG` line (every URL in it through
/// [`redact_urls_in`](crate::utils::redact::redact_urls_in)), or `None`
/// when debug output is off. Debug lines quote grant URLs and `--api-url`s,
/// and debug output is routinely pasted into CI logs and bug reports.
pub fn debug_message(message: &str) -> Option<std::borrow::Cow<'_, str>> {
    is_debug_enabled().then(|| crate::utils::redact::redact_urls_in(message))
}

/// Print a `SOCKET_DEBUG` line as `[socket-patch <channel>] <message>`,
/// URLs redacted. The one debug printer: every core debug line goes
/// through it (or through [`debug_message`] when it is held back first).
pub fn debug_log(channel: &str, message: &str) {
    if let Some(message) = debug_message(message) {
        eprintln!("[socket-patch {channel}] {message}");
    }
}

/// Strict-airgap gate: `SOCKET_OFFLINE` is `"1"` or `"true"`. It lives
/// here as the single definition of the vocabulary shared by every offline
/// gate (telemetry kill-switch, API-client advisory and org-slug
/// auto-resolution). The CLI mirrors `--offline` (whose clap-side
/// bool parse accepts a wider vocabulary) into `SOCKET_OFFLINE=1` before
/// any of those gates run, so the env read alone is authoritative.
pub(crate) fn is_offline_env() -> bool {
    matches!(
        std::env::var("SOCKET_OFFLINE").unwrap_or_default().as_str(),
        "1" | "true"
    )
}

/// The public patch-API proxy base URL: `SOCKET_PROXY_URL`, defaulting to
/// [`DEFAULT_PATCH_API_PROXY_URL`](crate::constants::DEFAULT_PATCH_API_PROXY_URL).
pub(crate) fn proxy_url_from_env() -> String {
    std::env::var("SOCKET_PROXY_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| crate::constants::DEFAULT_PATCH_API_PROXY_URL.to_string())
}

/// Peer env-var aliases accepted from the sibling JS Socket CLI, so an
/// environment configured for `socket` (e.g. a CI job exporting
/// `SOCKET_CLI_API_TOKEN`) works for `socket-patch` unchanged.
///
/// First entry is the canonical `SOCKET_*` name (what clap and core read);
/// second is the accepted `SOCKET_CLI_*` peer name. These are **not**
/// deprecated — promotion is silent and the canonical name simply wins
/// when both are set. The list is deliberately tight: `SOCKET_CLI_CONFIG` (ephemeral JSON override),
/// `SOCKET_CLI_API_PROXY` (an HTTP forward proxy — reqwest already honors
/// `HTTP_PROXY`/`HTTPS_PROXY`), and `SOCKET_CLI_DEBUG` are intentionally
/// not mirrored.
pub const PEER_ENV_ALIASES: &[(&str, &str)] = &[
    ("SOCKET_API_TOKEN", "SOCKET_CLI_API_TOKEN"),
    ("SOCKET_ORG_SLUG", "SOCKET_CLI_ORG_SLUG"),
    ("SOCKET_API_URL", "SOCKET_CLI_API_BASE_URL"),
    ("SOCKET_NO_API_TOKEN", "SOCKET_CLI_NO_API_TOKEN"),
];

/// Silently copy each set-and-non-empty [`PEER_ENV_ALIASES`] value onto its
/// canonical `SOCKET_*` name when the canonical name is unset or empty.
/// Call once, early in `main`, before the empty-var scrub / clap parse.
pub fn promote_peer_env_vars() {
    promote_aliases(PEER_ENV_ALIASES);
}

/// Core of [`promote_peer_env_vars`], parameterized over the alias table so
/// tests can use isolated env-var names.
fn promote_aliases(aliases: &[(&str, &str)]) {
    for &(canonical, alias) in aliases {
        let canonical_set = matches!(std::env::var(canonical).as_deref(), Ok(v) if !v.is_empty());
        if canonical_set {
            continue;
        }
        if let Ok(value) = std::env::var(alias) {
            if !value.is_empty() {
                std::env::set_var(canonical, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every core `SOCKET_DEBUG` line is printed by [`debug_log`] (or, held
    /// back first, by the API client from [`debug_message`]), so every URL
    /// in it is redacted: a module that prints its own `[socket-patch …]`
    /// line again fails here.
    #[test]
    fn debug_lines_have_one_printer() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut printers = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            let production = text
                .find("#[cfg(test)]\nmod tests {")
                .map_or(text.as_str(), |at| &text[..at]);
            let raw = production.matches("\"[socket-patch ").count();
            if raw > 0 {
                printers.push((rel, raw));
            }
        }
        printers.sort();
        assert_eq!(
            printers,
            vec![
                ("api/client.rs".to_string(), 2),
                ("utils/env_compat.rs".to_string(), 1)
            ]
        );
    }

    /// Peer-alias promotion copies a set alias onto the unset canonical
    /// name.
    #[test]
    fn peer_alias_promotes_silently_when_canonical_unset() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_PROMOTE";
        const ALIAS: &str = "SOCKET_TEST_PEER_PROMOTE_CLI";
        std::env::remove_var(CANONICAL);
        std::env::set_var(ALIAS, "from-alias");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(std::env::var(CANONICAL).ok().as_deref(), Some("from-alias"));
        std::env::remove_var(CANONICAL);
        std::env::remove_var(ALIAS);
    }

    /// The canonical name wins when both are set — the alias never clobbers.
    #[test]
    fn peer_alias_does_not_clobber_canonical() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_KEEP";
        const ALIAS: &str = "SOCKET_TEST_PEER_KEEP_CLI";
        std::env::set_var(CANONICAL, "canonical-value");
        std::env::set_var(ALIAS, "alias-value");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(
            std::env::var(CANONICAL).ok().as_deref(),
            Some("canonical-value")
        );
        std::env::remove_var(CANONICAL);
        std::env::remove_var(ALIAS);
    }

    /// Empty == unset on both sides: an empty canonical is filled from the
    /// alias, and an empty alias is never promoted.
    #[test]
    fn peer_alias_treats_empty_as_unset() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_EMPTY";
        const ALIAS: &str = "SOCKET_TEST_PEER_EMPTY_CLI";
        std::env::set_var(CANONICAL, "");
        std::env::set_var(ALIAS, "alias-value");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(
            std::env::var(CANONICAL).ok().as_deref(),
            Some("alias-value")
        );
        std::env::remove_var(CANONICAL);

        std::env::set_var(ALIAS, "");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(std::env::var(CANONICAL).ok(), None);
        std::env::remove_var(ALIAS);
    }
}
