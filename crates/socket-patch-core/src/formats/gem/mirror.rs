//! Whether a Bundler mirror captures a hosted gem's patch-registry source.
//!
//! Bundler selects `mirror.all`, then an exact source URI, then its hostname.
//! App config overrides the environment per encoded setting key, not per tier:
//! an environment `mirror.all` still outranks a local source-specific mirror.
//! This pure model reads the flat keys written by `bundle config`; the crawler
//! owns app-config/environment intake. User-global config is not modeled.
//!
//! Refuse a configured mirror conservatively even if a fallback timeout might
//! let a particular install bypass it. We do not probe mirror reachability.
//! An exact-source timeout without a mirror URL, however, deterministically
//! shadows the host mirror and selects the original source in Bundler.

use std::collections::BTreeMap;

use crate::crawlers::ruby_crawler::unquote_bundle_config_value;

const MIRROR_PREFIX: &str = "BUNDLE_MIRROR__";
const FALLBACK_SUFFIX: &str = ".fallback_timeout";

#[derive(Clone, Copy)]
enum Origin {
    AppConfig,
    Environment,
}

/// Normalize the HTTP(S) URI operations Bundler uses here: add a trailing
/// slash, omit the scheme's default port, and case-fold the whole lookup key.
/// Keep path segments/escapes intact (a web URL parser would normalize more).
fn normalize_source(source: &str) -> String {
    let mut uri = source.to_lowercase();
    if !uri.ends_with('/') {
        uri.push('/');
    }
    let Some((scheme, rest)) = uri.split_once("://") else {
        return uri;
    };
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return uri,
    };
    let authority_start = scheme.len() + 3;
    let authority_end = authority_start + rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &uri[authority_start..authority_end];
    if let Some((host, port)) = authority.rsplit_once(':') {
        // The last colon of an IPv6 address is not a port separator.
        if !port.contains(']') && port.parse::<u64>() == Ok(default_port) {
            let port_start = authority_start + host.len();
            uri.replace_range(port_start..authority_end, "");
        }
    }
    uri
}

fn source_host(source: &str) -> Option<&str> {
    let (_, rest) = source.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if host_port.starts_with('[') {
        Some(&host_port[..=host_port.find(']')?])
    } else {
        host_port.split(':').next()
    }
}

/// `Settings.key_for` normalizes HTTP(S) keys before re-encoding them. A
/// malformed noncanonical environment key is not an alternative valid key.
fn encoded_key(setting: &str) -> String {
    let setting = if setting.starts_with("http:") || setting.starts_with("https:") {
        if let Some(source) = setting.strip_suffix(FALLBACK_SUFFIX) {
            format!("{}{FALLBACK_SUFFIX}", normalize_source(source))
        } else {
            normalize_source(setting)
        }
    } else {
        setting.to_owned()
    };
    format!(
        "{MIRROR_PREFIX}{}",
        setting
            .replace('.', "__")
            .replace('-', "___")
            .to_uppercase()
    )
}

/// A mirror setting that captures a patch source, without either URL in its
/// diagnostic: values and source keys can both contain credentials/tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorCapture {
    pub setting: String,
    pub remedy: String,
}

fn capture(kind: &str, origin: Origin) -> MirrorCapture {
    let (location, remedy) = match (kind, origin) {
        ("mirror.all", Origin::AppConfig) => (
            "the project's Bundler config",
            "scope the existing mirror URL to `mirror.https://rubygems.org` instead, then remove \
             `mirror.all` (including any slash alias) from the project's Bundler config",
        ),
        ("mirror.all", Origin::Environment) => (
            "the environment (BUNDLE_MIRROR__ALL or its slash alias)",
            "unset the BUNDLE_MIRROR__ALL environment setting (including any slash alias) and \
             scope its existing mirror URL to `mirror.https://rubygems.org` instead",
        ),
        (_, Origin::AppConfig) => (
            "the project's Bundler config",
            "remove the applicable patch-source or hostname mirror from the project's Bundler \
             config and scope its existing mirror URL to `mirror.https://rubygems.org` instead",
        ),
        (_, Origin::Environment) => (
            "the environment",
            "unset the applicable patch-source or hostname BUNDLE_MIRROR__ environment setting \
             and scope its existing mirror URL to `mirror.https://rubygems.org` instead",
        ),
    };
    MirrorCapture {
        setting: format!("Bundler's {kind} setting in {location}"),
        remedy: remedy.into(),
    }
}

/// Detect a capturing mirror in the app config and explicit environment
/// settings. `config` is absent when `BUNDLE_IGNORE_CONFIG` is set. Environment
/// keys use Bundler's encoded `BUNDLE_MIRROR__...` spelling.
pub fn capturing_mirror(
    config: Option<&str>,
    environment: &[(&str, &str)],
    sources: &[&str],
) -> Option<MirrorCapture> {
    let mut settings = BTreeMap::new();
    for &(key, value) in environment {
        if key.starts_with(MIRROR_PREFIX) {
            settings.insert(key.to_owned(), (value, Origin::Environment));
        }
    }
    if let Some(config) = config {
        for line in config.lines() {
            // URI keys contain colons, so only a YAML mapping separator ends
            // the key. Preserve empty values so a local key still shadows env.
            if let Some(index) = line.char_indices().find_map(|(index, ch)| {
                (ch == ':'
                    && (line[index + 1..].is_empty() || line[index + 1..].starts_with([' ', '\t'])))
                .then_some(index)
            }) {
                // Settings#load_config also accepts legacy literal dots and
                // dashes, and appends a missing slash to HTTP(S) source keys.
                // Environment keys do not get this file-only normalization.
                let mut key = line[..index].to_owned();
                let lower = key.to_ascii_lowercase();
                if (lower.contains("http:") || lower.contains("https:"))
                    && !key.ends_with('/')
                    && !key.ends_with("__FALLBACK_TIMEOUT")
                {
                    key.push('/');
                }
                let key = key.replace('.', "__").replace('-', "___");
                if !key.starts_with(MIRROR_PREFIX) {
                    continue;
                }
                settings.insert(
                    key,
                    (
                        unquote_bundle_config_value(&line[index + 1..]),
                        Origin::AppConfig,
                    ),
                );
            }
        }
    }
    // Settings#all decodes, downcases and sorts names before Mirrors#parse.
    let mut names: Vec<_> = settings
        .keys()
        .map(|key| {
            key[MIRROR_PREFIX.len()..]
                .replace("___", "-")
                .replace("__", ".")
                .to_lowercase()
        })
        .collect();
    names.sort();
    let mut mirrors = BTreeMap::<String, Option<Origin>>::new();
    for name in names {
        let Some(&(value, origin)) = settings.get(&encoded_key(&name)) else {
            continue;
        };
        // MirrorConfig accepts precisely one optional trailing slash alias.
        let name = name.strip_suffix('/').unwrap_or(&name);
        let (name, timeout_only) = name
            .strip_suffix(FALLBACK_SUFFIX)
            .map_or((name, false), |name| (name, true));
        let name = if name.contains("://") {
            normalize_source(name)
        } else {
            name.to_owned()
        };
        let mirror = mirrors.entry(name).or_default();
        if !timeout_only {
            *mirror = (!value.trim().is_empty()).then_some(origin);
        }
    }
    if let Some(Some(origin)) = mirrors.get("all") {
        return Some(capture("mirror.all", *origin));
    }
    for source in sources {
        let source = normalize_source(source);
        if let Some(mirror) = mirrors.get(&source) {
            if let Some(origin) = mirror {
                return Some(capture("exact patch-source mirror", *origin));
            }
            // A URL-less exact mirror shadows the hostname fallback.
            continue;
        }
        if let Some(Some(origin)) = source_host(&source).and_then(|host| mirrors.get(host)) {
            return Some(capture("patch-registry hostname mirror", *origin));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "https://patch.socket.dev/gem/tok-1/0a1b-2c/";
    const URL: &str = "https://mirror.example/";

    fn config(setting: &str) -> String {
        format!("{}: \"{URL}\"\n", encoded_key(setting))
    }

    #[test]
    fn mirror_all_in_the_app_config_captures_every_source() {
        let cfg = config("all");
        let c = capturing_mirror(Some(&cfg), &[], &[SRC]).unwrap();
        assert!(c.setting.contains("mirror.all"), "{c:?}");
        assert!(c.setting.contains("project's Bundler config"), "{c:?}");
        assert!(capturing_mirror(Some(&cfg), &[], &[]).is_some());
    }

    #[test]
    fn mirror_all_from_the_environment_captures_every_source() {
        let c = capturing_mirror(None, &[("BUNDLE_MIRROR__ALL", URL)], &[SRC]).unwrap();
        assert!(c.setting.contains("BUNDLE_MIRROR__ALL"), "{c:?}");
        assert_eq!(
            capturing_mirror(None, &[("BUNDLE_MIRROR__ALL", "")], &[SRC]),
            None
        );
    }

    #[test]
    fn source_and_hostname_matching_follows_bundler_in_both_tiers() {
        // Native Bundler 2.6.9 and 4.0.17 controls: one slash alias, full
        // case-folding/default ports, exact source vs host (not URL prefixes).
        let cases = [
            ("all", SRC, true),
            ("all/", SRC, true),
            ("all//", SRC, false),
            (SRC, SRC, true),
            ("https://patch.socket.dev/gem/tok-1/0a1b-2c//", SRC, true),
            ("https://patch.socket.dev/gem/tok-1/0a1b-2c///", SRC, false),
            ("https://PATCH.socket.dev/GEM/TOK-1/0A1B-2C/", SRC, true),
            ("https://patch.socket.dev:443/gem/tok-1/0a1b-2c/", SRC, true),
            (SRC, "https://PATCH.socket.dev:443/GEM/TOK-1/0A1B-2C/", true),
            ("http://patch.test:80/gem/", "http://patch.test/gem", true),
            ("http://[::1]:8443/gem/", "http://[::1]:8443/gem/", true),
            (
                "https://patch.socket.dev:8443/gem/tok-1/0a1b-2c/",
                SRC,
                false,
            ),
            ("https://patch.socket.dev/", SRC, false),
            ("https://patch.socket.dev/gem/other/", SRC, false),
            ("patch.socket.dev", SRC, true),
            ("PATCH.socket.dev/", SRC, true),
            ("patch.socket.dev//", SRC, false),
            (
                "patch.socket.dev",
                "http://patch.socket.dev:8443/another/",
                true,
            ),
            (
                "patch.socket.dev:8443",
                "http://patch.socket.dev:8443/another/",
                false,
            ),
            ("other.socket.dev", SRC, false),
            ("https://rubygems.org", SRC, false),
            ("rubygems.org", SRC, false),
        ];
        for (setting, source, captures) in cases {
            let cfg = config(setting);
            let key = encoded_key(setting);
            for actual in [
                capturing_mirror(Some(&cfg), &[], &[source]),
                capturing_mirror(None, &[(&key, URL)], &[source]),
            ] {
                assert_eq!(
                    actual.is_some(),
                    captures,
                    "{setting:?} for {source:?}: {actual:?}"
                );
            }
        }
    }

    #[test]
    fn legacy_app_key_normalization_does_not_apply_to_the_environment() {
        let key = "BUNDLE_MIRROR__HTTPS://PATCH.SOCKET.DEV/GEM/TOK-1/0A1B-2C";
        let cfg = format!("{key}: \"{URL}\"\n");
        assert!(capturing_mirror(Some(&cfg), &[], &[SRC]).is_some());
        assert_eq!(capturing_mirror(None, &[(key, URL)], &[SRC]), None);
        let empty = format!("{key}: \"\"\n");
        // File normalization happens before the per-key local/env overlay.
        let canonical = encoded_key(SRC);
        assert_eq!(
            capturing_mirror(Some(&empty), &[(&canonical, URL)], &[SRC]),
            None
        );
    }

    #[test]
    fn precedence_is_per_key_then_all_exact_host() {
        let exact = encoded_key(SRC);
        let host = encoded_key("patch.socket.dev");
        let local_host = config("patch.socket.dev");
        let local_exact = config(SRC);
        let local_all = config("all");
        let cases = [
            (
                local_all.as_str(),
                exact.as_str(),
                "mirror.all",
                "project's Bundler config",
            ),
            (
                local_exact.as_str(),
                "BUNDLE_MIRROR__ALL",
                "mirror.all",
                "environment",
            ),
            (
                local_host.as_str(),
                exact.as_str(),
                "exact patch-source",
                "environment",
            ),
            (
                local_exact.as_str(),
                exact.as_str(),
                "exact patch-source",
                "project's Bundler config",
            ),
            (
                local_exact.as_str(),
                host.as_str(),
                "exact patch-source",
                "project's Bundler config",
            ),
        ];
        for (cfg, env_key, kind, origin) in cases {
            let c = capturing_mirror(Some(cfg), &[(env_key, URL)], &[SRC]).unwrap();
            assert!(
                c.setting.contains(kind) && c.setting.contains(origin),
                "{c:?}"
            );
        }
        let both = format!("{local_exact}{local_host}");
        assert!(capturing_mirror(Some(&both), &[], &[SRC])
            .unwrap()
            .setting
            .contains("exact patch-source"));
        // Empty values remain present: don't uncover a lower-tier setting.
        assert_eq!(
            capturing_mirror(
                Some("BUNDLE_MIRROR__ALL: \"\"\n"),
                &[("BUNDLE_MIRROR__ALL", URL)],
                &[SRC]
            ),
            None
        );
    }

    #[test]
    fn fallback_only_exact_mirror_shadows_host_but_all_does_not() {
        let exact_timeout = encoded_key(&format!("{SRC}{FALLBACK_SUFFIX}"));
        let host = config("patch.socket.dev");
        let cfg = format!("{host}{exact_timeout}: \"true\"\n");
        assert_eq!(capturing_mirror(Some(&cfg), &[], &[SRC]), None);
        // The exact shadow only applies to that source, not other candidates.
        assert!(capturing_mirror(
            Some(&cfg),
            &[],
            &[SRC, "https://patch.socket.dev/gem/other/"]
        )
        .is_some());
        assert_eq!(
            capturing_mirror(Some(&host), &[(&exact_timeout, "true")], &[SRC]),
            None
        );
        assert!(capturing_mirror(
            Some(&host),
            &[("BUNDLE_MIRROR__ALL__FALLBACK_TIMEOUT", "true")],
            &[SRC]
        )
        .is_some());
        let both = format!("{cfg}{}", config(SRC));
        assert!(capturing_mirror(Some(&both), &[], &[SRC]).is_some());
        assert_eq!(
            capturing_mirror(
                Some("BUNDLE_MIRROR__ALL__FALLBACK_TIMEOUT: \"3\"\n"),
                &[],
                &[SRC]
            ),
            None
        );
    }

    #[test]
    fn each_remedy_converges_without_printing_the_mirror_value() {
        let scoped = config("https://rubygems.org");
        for setting in ["all", SRC, "patch.socket.dev"] {
            let cfg = config(setting);
            let key = encoded_key(setting);
            for c in [
                capturing_mirror(Some(&cfg), &[], &[SRC]).unwrap(),
                capturing_mirror(None, &[(&key, URL)], &[SRC]).unwrap(),
            ] {
                assert!(c.remedy.contains("mirror.https://rubygems.org"), "{c:?}");
                assert!(!c.remedy.contains(URL), "{c:?}");
            }
            assert_eq!(capturing_mirror(Some(&scoped), &[], &[SRC]), None);
            assert_eq!(capturing_mirror(None, &[], &[SRC]), None);
        }
    }

    #[test]
    fn mirror_diagnostics_do_not_disclose_configured_credentials() {
        let mirror = "https://review-user:review-secret@mirror.example/private?token=review-token";
        let source = "https://source-user:source-secret@patch.socket.dev/gem/source-token/";
        for setting in ["all", source, "patch.socket.dev"] {
            let key = encoded_key(setting);
            let cfg = format!("{key}: \"{mirror}\"\n");
            for c in [
                capturing_mirror(Some(&cfg), &[], &[source]).unwrap(),
                capturing_mirror(None, &[(&key, mirror)], &[source]).unwrap(),
            ] {
                let diagnostic = format!("{} {}", c.setting, c.remedy);
                for secret in [
                    "review-user",
                    "review-secret",
                    "review-token",
                    "source-user",
                    "source-secret",
                    "source-token",
                ] {
                    assert!(
                        !diagnostic.contains(secret),
                        "diagnostic disclosed a synthetic credential"
                    );
                }
            }
        }
    }

    #[test]
    fn a_host_mirror_captures_the_patch_registry() {
        let config = "BUNDLE_MIRROR__PATCH__SOCKET__DEV: \"https://mirror.example/\"\n";
        assert!(capturing_mirror(Some(config), &[], &[SRC]).is_some());
    }
}
