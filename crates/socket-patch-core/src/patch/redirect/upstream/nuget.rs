//! NuGet upstream restore: the inverse of `rewrite_nuget` over the root
//! `nuget.config` (the file discovery names) and its `packages.lock.json`.
//!
//! The config loses the `<add key="socket-patch-<uuid>" …/>` source and its
//! exact-id `<packageSource>` mapping. A `<packageSourceMapping>` left with
//! nothing but a `*` fan-out for every remaining source — the shape the
//! rewriter authors around a from-scratch mapping — routes exactly like no
//! mapping at all, so it is dropped too. What stays: a `nuget.org` source
//! the rewriter seeded into a source-less config (indistinguishable from
//! one the user wrote), and a config it created from scratch (identical to
//! a user's default config, so it is kept and a warning says so).
//!
//! Every lock entry of the id gets nuget.org's `contentHash` back (NuGet's
//! signature-excluded content hash of the `.nupkg` nuget.org serves — not
//! the catalog `packageHash`, see [`UpstreamClient::nuget_content_hash`]) — only
//! when the restored config resolves the id from nuget.org alone: another
//! feed (or several) may serve different bytes, and socket-patch cannot
//! tell which one the original lock came from, so such a pin is refused.
//!
//! [`UpstreamClient::nuget_content_hash`]: super::UpstreamClient::nuget_content_hash

use regex::Regex;
use serde_json::Value;

use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::formats::nuget::{parse_config, NugetConfig};
use crate::vendor::nuget_feed::normalize_nuget_version;

const PACKAGES_LOCK: &str = "packages.lock.json";
const NUGET_ORG_INDEX: &str = "https://api.nuget.org/v3/index.json";

fn is_nuget_org(url: &str) -> bool {
    url.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(NUGET_ORG_INDEX)
}

/// The config's first quoted value of `attr` inside the tag text `tag`.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"\s{attr}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
        attr = regex::escape(attr)
    ))
    .expect("escaped attribute regex is valid");
    re.captures(tag)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().to_string())
}

/// Remove one pin's source definition and mapping, each with the line
/// break before it (the rewriter's own insertion).
fn remove_source(config: &str, uuid: &str, id: &str, ctx: &Ctx<'_>) -> Result<String, String> {
    let key = crate::patch::redirect::generation::hosted_pin_name(uuid);
    let quoted = format!(r#"(?:"{k}"|'{k}')"#, k = regex::escape(&key));
    let add_re = Regex::new(&format!(
        r"(?:\r?\n[ \t]*)?<add\s[^>]*?key\s*=\s*{quoted}[^>]*?/>"
    ))
    .expect("escaped add regex is valid");
    let adds: Vec<(usize, usize)> = add_re
        .find_iter(config)
        .filter(|m| {
            attr_value(m.as_str(), "value")
                .and_then(|v| ctx.hosted_uuid(&v))
                .as_deref()
                == Some(uuid)
        })
        .map(|m| (m.start(), m.end()))
        .collect();
    let [(add_start, add_end)] = adds[..] else {
        return Err(format!(
            "the config does not define the Socket source {key} exactly once"
        ));
    };
    let mut out = format!("{}{}", &config[..add_start], &config[add_end..]);

    let map_re = Regex::new(&format!(
        r"(?s)(?:\r?\n[ \t]*)?<packageSource\s+key\s*=\s*{quoted}\s*>(.*?)</packageSource\s*>"
    ))
    .expect("escaped packageSource regex is valid");
    let maps: Vec<regex::Captures<'_>> = map_re.captures_iter(&out).collect();
    let [only] = &maps[..] else {
        return Err(format!("the config does not map {key} exactly once"));
    };
    let pattern_re = Regex::new(r#"<package\s+pattern\s*=\s*(?:"([^"]*)"|'([^']*)')\s*/>"#)
        .expect("static package-pattern regex is valid");
    let patterns: Vec<String> = pattern_re
        .captures_iter(&only[1])
        .filter_map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().trim().to_string())
        })
        .collect();
    if !matches!(&patterns[..], [p] if p.eq_ignore_ascii_case(id)) {
        return Err(format!(
            "the config maps {key} to {patterns:?}, not to the one package {id}"
        ));
    }
    let whole = only.get(0).expect("group 0 always matches");
    out = format!("{}{}", &out[..whole.start()], &out[whole.end()..]);
    if out.contains(&key) {
        return Err(format!("the config still names {key} elsewhere"));
    }
    Ok(out)
}

/// Drop a `<packageSourceMapping>` that no longer routes anything: empty,
/// or a `*` fan-out naming every remaining source of the file (and, as the
/// writers author it on disk, the sources inherited from the user and
/// parent configs, #354).
fn drop_fanout_mapping(config: &str) -> String {
    let Some(cfg) = parse_config(config) else {
        return config.to_string();
    };
    let mut mapped: Vec<&str> = cfg.mappings.iter().map(|(k, _)| k.as_str()).collect();
    let mut sources: Vec<&str> = cfg.sources.iter().map(|(k, _)| k.as_str()).collect();
    mapped.sort_unstable();
    sources.sort_unstable();
    let fanout_only = cfg
        .mappings
        .iter()
        .all(|(_, patterns)| matches!(&patterns[..], [p] if p == "*"));
    let covers_sources = sources.iter().all(|s| mapped.contains(s));
    if !(cfg.mappings.is_empty() || (fanout_only && covers_sources)) {
        return config.to_string();
    }
    let re = Regex::new(r"(?s)<packageSourceMapping\s*>.*?</packageSourceMapping\s*>")
        .expect("static packageSourceMapping regex is valid");
    let found: Vec<(usize, usize)> = re.find_iter(config).map(|m| (m.start(), m.end())).collect();
    let [(start, end)] = found[..] else {
        return config.to_string();
    };
    // The whole lines when the element has them to itself.
    let line_start = config[..start].rfind('\n').map_or(0, |i| i + 1);
    let tail = &config[end..];
    let eol = if tail.starts_with("\r\n") {
        2
    } else if tail.starts_with('\n') {
        1
    } else {
        0
    };
    if config[line_start..start].trim().is_empty() && eol > 0 {
        format!("{}{}", &config[..line_start], &config[end + eol..])
    } else {
        format!("{}{}", &config[..start], tail)
    }
}

/// Does `pattern` route `id`, and how specifically (NuGet: an exact id
/// beats the longest `prefix*`, which beats `*`)?
fn pattern_score(pattern: &str, id: &str) -> Option<usize> {
    match pattern.strip_suffix('*') {
        Some(prefix) => (id.len() >= prefix.len()
            && id[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then_some(prefix.len()),
        None => pattern.eq_ignore_ascii_case(id).then_some(usize::MAX),
    }
}

/// `Ok` when the restored config resolves `id` from nuget.org alone.
fn check_upstream_feed(cfg: &NugetConfig, id: &str, config_rel: &str) -> Result<(), String> {
    let enabled: Vec<&(String, String)> = cfg
        .sources
        .iter()
        .filter(|(k, _)| !cfg.disabled.contains(k))
        .collect();
    let candidates: Vec<&(String, String)> = if cfg.mappings.is_empty() {
        enabled
    } else {
        let scored: Vec<(usize, &str)> = cfg
            .mappings
            .iter()
            .filter_map(|(key, patterns)| {
                patterns
                    .iter()
                    .filter_map(|p| pattern_score(p, id))
                    .max()
                    .map(|s| (s, key.as_str()))
            })
            .collect();
        let Some(best) = scored.iter().map(|(s, _)| *s).max() else {
            return Err(format!("no package source in {config_rel} maps {id}"));
        };
        enabled
            .into_iter()
            .filter(|(k, _)| scored.iter().any(|(s, key)| *s == best && key == k))
            .collect()
    };
    // No source at all: NuGet falls back to the user-level default, nuget.org.
    if candidates.iter().all(|(_, url)| is_nuget_org(url)) {
        return Ok(());
    }
    let names: Vec<String> = candidates
        .iter()
        .map(|(k, url)| format!("{k} ({url})"))
        .collect();
    Err(format!(
        "{id} resolves from {} under {config_rel}, not from nuget.org alone, so the original \
         contentHash cannot be re-derived",
        names.join(", ")
    ))
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let (dir, leaf) = match rel.rsplit_once('/') {
            Some((d, l)) => (format!("{d}/"), l),
            None => (String::new(), rel.as_str()),
        };
        if !crate::patch::redirect::NUGET_CONFIG_FILE_NAMES.contains(&leaf) {
            // A lock is restored together with the config that wires it; a
            // pin no config claims is refused by the driver.
            continue;
        }
        let Some(original) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let wired: Vec<&HostedPin> = pins
            .values()
            .copied()
            .filter(|p| p.files.contains(rel))
            .collect();
        let mut text = original.clone();
        let mut restored: Vec<(&HostedPin, String, String)> = Vec::new();
        for pin in &wired {
            let Some((id, version)) = pin.name_version() else {
                result.refuse(&pin.uuid, format!("{} is not a NuGet purl", pin.purl));
                continue;
            };
            // Put back the patterns the rewriter set aside first: their
            // comments name the Socket source (#462).
            let key = crate::patch::redirect::generation::hosted_pin_name(&pin.uuid);
            let unaside = crate::formats::nuget::restore_set_aside(&text, &key);
            match remove_source(&unaside, &pin.uuid, &id, ctx) {
                Ok(next) => {
                    text = next;
                    restored.push((pin, id, version));
                }
                Err(why) => result.refuse(&pin.uuid, format!("{rel}: {why}")),
            }
        }
        if restored.is_empty() {
            continue;
        }
        text = drop_fanout_mapping(&text);
        let Some(cfg) = parse_config(&text) else {
            refuse_all_in(
                &pins,
                rel,
                &mut result,
                format!("restoring {rel} would not leave well-formed XML"),
            );
            continue;
        };

        // The locks the config governs: at the root, every lock a project
        // under it restores into (#353, #514); a nested config, its own
        // directory's default lock.
        let lock_rels: Vec<String> = if dir.is_empty() {
            match crate::vendor::nuget_config::governed_locks_on_disk(view.root()) {
                Ok(governed) => {
                    if let Some((project, detail)) = governed.unresolved.first() {
                        refuse_all_in(
                            &pins,
                            rel,
                            &mut result,
                            format!("{project}: {detail}; its lock cannot be restored"),
                        );
                        continue;
                    }
                    governed.locks
                }
                Err(why) => {
                    refuse_all_in(&pins, rel, &mut result, why);
                    continue;
                }
            }
        } else {
            vec![format!("{dir}{PACKAGES_LOCK}")]
        };
        let mut locks: Vec<(String, String, Value)> = Vec::new();
        let mut unreadable = false;
        for lock_rel in lock_rels {
            match view.read(&lock_rel).await {
                Ok(None) => {}
                Ok(Some(text)) => match crate::formats::nuget::lock::parse_lock(&text) {
                    Ok(value) => locks.push((lock_rel, text, value)),
                    Err(_) => {
                        refuse_all_in(
                            &pins,
                            rel,
                            &mut result,
                            format!("{lock_rel} is not valid JSON"),
                        );
                        unreadable = true;
                        break;
                    }
                },
                Err(e) => {
                    refuse_all_in(&pins, rel, &mut result, e);
                    unreadable = true;
                    break;
                }
            }
        }
        if unreadable {
            continue;
        }
        for (pin, id, version) in &restored {
            // Only the entries at the pinned version: another version of
            // the id was never re-pinned (#593).
            let norm = normalize_nuget_version(version);
            let pinned = locks.iter().any(|(_, _, lock)| {
                crate::formats::nuget::lock::locked_at(lock, id, &norm)
                    .any(|e| e.content_hash.is_some())
            });
            if !pinned {
                continue;
            }
            if let Err(why) = check_upstream_feed(&cfg, id, rel) {
                result.refuse(&pin.uuid, why);
                continue;
            }
            let hash = match ctx.client.nuget_content_hash(id, &norm).await {
                Ok(h) => h,
                Err(why) => {
                    result.refuse(&pin.uuid, format!("{id} {version}: {why}"));
                    continue;
                }
            };
            for (_, _, lock) in locks.iter_mut() {
                for (_, entry) in crate::formats::nuget::lock::locked_at_mut(lock, id, &norm) {
                    if entry.contains_key("contentHash") {
                        entry.insert("contentHash".into(), Value::String(hash.clone()));
                    }
                }
            }
        }
        // A refusal in this file reruns the pass without that pin; write
        // only a file every wired pin restored in.
        if restored
            .iter()
            .any(|(p, ..)| result.refused.contains_key(&p.uuid))
        {
            continue;
        }
        if text == super::super::default_nuget_config() || text == super::super::EMPTY_NUGET_CONFIG
        {
            result.warnings.push((
                "nuget_default_config_left",
                format!(
                    "{rel} now holds only the nuget.org source; if hosted mode created it, \
                     delete it"
                ),
            ));
        }
        view.write(rel, text);
        for (lock_rel, before, lock) in locks {
            // In the lock's own layout (BOM, indent, line endings).
            if crate::formats::nuget::lock::parse_lock(&before)
                .ok()
                .as_ref()
                != Some(&lock)
            {
                view.write(&lock_rel, super::super::serialize_json_like(&lock, &before));
            }
        }
        result
            .handled
            .extend(restored.iter().map(|(p, ..)| p.uuid.clone()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_scores_follow_nuget_precedence() {
        assert_eq!(pattern_score("*", "Newtonsoft.Json"), Some(0));
        assert_eq!(pattern_score("Newtonsoft.*", "newtonsoft.json"), Some(11));
        assert_eq!(
            pattern_score("newtonsoft.json", "Newtonsoft.Json"),
            Some(usize::MAX)
        );
        assert_eq!(pattern_score("Contoso.*", "Newtonsoft.Json"), None);
        assert_eq!(
            pattern_score("Newtonsoft.Json.Bson", "Newtonsoft.Json"),
            None
        );
    }

    fn cfg(text: &str) -> NugetConfig {
        parse_config(text).unwrap()
    }

    #[test]
    fn upstream_feed_must_be_nuget_org_alone() {
        let only_org = cfg(
            r#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json/" /></packageSources></configuration>"#,
        );
        assert!(check_upstream_feed(&only_org, "A", "nuget.config").is_ok());
        let none = cfg("<configuration></configuration>");
        assert!(check_upstream_feed(&none, "A", "nuget.config").is_ok());
        let two = cfg(
            r#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /><add key="corp" value="https://corp/v3/index.json" /></packageSources></configuration>"#,
        );
        let why = check_upstream_feed(&two, "A", "nuget.config").unwrap_err();
        assert!(why.contains("corp (https://corp/v3/index.json)"), "{why}");
        // A mapping that routes the id to nuget.org only settles it.
        let mapped = cfg(
            r#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /><add key="corp" value="https://corp/v3/index.json" /></packageSources><packageSourceMapping><packageSource key="nuget.org"><package pattern="A" /></packageSource><packageSource key="corp"><package pattern="*" /></packageSource></packageSourceMapping></configuration>"#,
        );
        assert!(check_upstream_feed(&mapped, "a", "nuget.config").is_ok());
        let why = check_upstream_feed(&mapped, "B", "nuget.config").unwrap_err();
        assert!(why.contains("corp"), "{why}");
        // A disabled second source is not a candidate.
        let disabled = cfg(
            r#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /><add key="corp" value="https://corp/v3/index.json" /></packageSources><disabledPackageSources><add key="corp" value="true" /></disabledPackageSources></configuration>"#,
        );
        assert!(check_upstream_feed(&disabled, "A", "nuget.config").is_ok());
        let unmapped = cfg(
            r#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources><packageSourceMapping><packageSource key="nuget.org"><package pattern="Other" /></packageSource></packageSourceMapping></configuration>"#,
        );
        assert!(check_upstream_feed(&unmapped, "A", "nuget.config")
            .unwrap_err()
            .contains("maps"));
    }

    #[test]
    fn fanout_mapping_is_dropped_only_when_it_routes_nothing() {
        let fanout = "<configuration>\n  <packageSources>\n    <add key=\"a\" value=\"https://a/\" />\n  </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"a\">\n      <package pattern=\"*\" />\n    </packageSource>\n  </packageSourceMapping>\n</configuration>\n";
        assert_eq!(
            drop_fanout_mapping(fanout),
            "<configuration>\n  <packageSources>\n    <add key=\"a\" value=\"https://a/\" />\n  </packageSources>\n</configuration>\n"
        );
        // A second source without a fan-out is excluded by the mapping.
        let partial = fanout.replace(
            "  </packageSources>",
            "    <add key=\"b\" value=\"https://b/\" />\n  </packageSources>",
        );
        assert_eq!(drop_fanout_mapping(&partial), partial);
        // A real pattern keeps it.
        let pinned = fanout.replace("pattern=\"*\"", "pattern=\"Foo.*\"");
        assert_eq!(drop_fanout_mapping(&pinned), pinned);
    }

    use super::super::{restore_upstream, HostedPin, PinStatus, RestoreOptions, RestoreOutcome};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "66666666-6666-6666-6666-666666666666";
    const PATCHED: &str = "PATCHEDcontenthashPATCHEDcontenthashAA==";

    fn index_url() -> String {
        format!(
            "https://patch.socket.dev/patch-registry/nuget/11111111-1111-1111-1111-111111111111/{UUID}/index.json"
        )
    }

    /// What `rewrite_nuget` makes of `config` for Newtonsoft.Json.
    fn hosted_config(config: &str) -> String {
        super::super::super::add_nuget_source(
            config,
            &parse_config(config).unwrap(),
            None,
            false,
            &format!("socket-patch-{UUID}"),
            &index_url(),
            "Newtonsoft.Json",
        )
        .unwrap()
    }

    fn lock(hash: &str) -> String {
        format!(
            "{{\n  \"version\": 1,\n  \"dependencies\": {{\n    \"net6.0\": {{\n      \"Newtonsoft.Json\": {{\n        \"type\": \"Direct\",\n        \"requested\": \"[13.0.3, )\",\n        \"resolved\": \"13.0.3\",\n        \"contentHash\": \"{hash}\"\n      }}\n    }},\n    \"net8.0\": {{\n      \"newtonsoft.json\": {{\n        \"type\": \"Transitive\",\n        \"resolved\": \"13.0.3\",\n        \"contentHash\": \"{hash}\"\n      }}\n    }}\n  }}\n}}\n"
        )
    }

    /// A tiny `.nupkg`, with or without a repository signature entry
    /// (appended last, where NuGet's signer puts it).
    fn nupkg(signed: bool) -> Vec<u8> {
        use std::io::Write as _;
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts =
            zip::write::SimpleFileOptions::default().last_modified_time(zip::DateTime::default());
        let mut files: Vec<(&str, &[u8])> = vec![
            ("newtonsoft.json.nuspec", b"<package />"),
            ("LICENSE.md", b"The MIT License (MIT)"),
        ];
        if signed {
            files.push((".signature.p7s", b"repository-signature"));
        }
        for (name, data) in files {
            zw.start_file(name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// The lock's original `contentHash`: NuGet's content hash, which
    /// excludes the signature, i.e. the hash of the unsigned archive.
    fn upstream() -> String {
        crate::utils::digest::sha512_base64_of(&nupkg(false))
    }

    /// nuget.org's flat container serving the SIGNED package.
    async fn nuget_org() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(nupkg(true)))
            .mount(&server)
            .await;
        server
    }

    /// Restore the Newtonsoft.Json pin over `config` + `lock(PATCHED)`.
    async fn run(config: &str, offline: bool) -> (RestoreOutcome, String, String) {
        let server = nuget_org().await;
        std::env::set_var("SOCKET_NUGET_URL", server.uri());
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("nuget.config"), config).unwrap();
        std::fs::write(tmp.path().join(PACKAGES_LOCK), lock(PATCHED)).unwrap();
        let pins = [HostedPin {
            purl: "pkg:nuget/Newtonsoft.Json@13.0.3".into(),
            uuid: UUID.into(),
            files: vec!["nuget.config".into()],
        }];
        let opts = RestoreOptions {
            offline,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), &pins, &opts).await;
        std::env::remove_var("SOCKET_NUGET_URL");
        let read = |rel: &str| std::fs::read_to_string(tmp.path().join(rel)).unwrap();
        (outcome, read("nuget.config"), read(PACKAGES_LOCK))
    }

    const USER_MAPPING: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n    <add key=\"corp\" value=\"https://corp.example/v3/index.json\" />\n  </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>\n    <packageSource key=\"corp\">\n      <package pattern=\"Contoso.*\" />\n    </packageSource>\n  </packageSourceMapping>\n</configuration>\n";

    #[tokio::test]
    #[serial_test::serial]
    async fn an_existing_mapping_keeps_the_users_entries() {
        let (outcome, config, lock_after) = run(&hosted_config(USER_MAPPING), false).await;
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert_eq!(config, USER_MAPPING);
        // #624: the signature-excluded content hash, never the hash of the
        // signed file as served (what the catalog's packageHash records).
        assert_ne!(
            upstream(),
            crate::utils::digest::sha512_base64_of(&nupkg(true))
        );
        assert_eq!(lock_after, lock(&upstream()));
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    }

    /// #462: the pattern the rewriter set aside comes back byte-exact.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_set_aside_pattern_is_restored() {
        let user = USER_MAPPING.replace(
            "      <package pattern=\"*\" />\n",
            "      <package pattern=\"*\" />\n      <package pattern=\"Newtonsoft.Json\" />\n",
        );
        let hosted = hosted_config(&user);
        let key = format!("socket-patch-{UUID}");
        let (aside, moved) = crate::formats::nuget::set_aside_competing_patterns(
            &hosted,
            &parse_config(&hosted).unwrap(),
            &key,
            "Newtonsoft.Json",
        )
        .unwrap();
        assert_eq!(moved, ["nuget.org"]);
        let (outcome, config, _) = run(&aside, false).await;
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert_eq!(config, user);
    }

    /// #353: the root config governs a member project's lock, so the
    /// unwind restores it with the config.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_member_project_lock_is_restored_with_the_root_config() {
        let server = nuget_org().await;
        std::env::set_var("SOCKET_NUGET_URL", server.uri());
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("src/App");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(tmp.path().join("nuget.config"), hosted_config(USER_MAPPING)).unwrap();
        std::fs::write(app.join("App.csproj"), "<Project />").unwrap();
        std::fs::write(app.join(PACKAGES_LOCK), lock(PATCHED)).unwrap();
        let pins = [HostedPin {
            purl: "pkg:nuget/Newtonsoft.Json@13.0.3".into(),
            uuid: UUID.into(),
            files: vec!["nuget.config".into()],
        }];
        let outcome = restore_upstream(tmp.path(), &pins, &RestoreOptions::default()).await;
        std::env::remove_var("SOCKET_NUGET_URL");
        assert_eq!(
            outcome.pins[0].status,
            PinStatus::Restored,
            "{:?}",
            outcome.pins
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("nuget.config")).unwrap(),
            USER_MAPPING
        );
        assert_eq!(
            std::fs::read_to_string(app.join(PACKAGES_LOCK)).unwrap(),
            lock(UPSTREAM)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn a_config_created_from_scratch_is_kept_and_warned() {
        let default = super::super::super::default_nuget_config();
        let (outcome, config, lock_after) = run(&hosted_config(&default), false).await;
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(config, default);
        assert_eq!(lock_after, lock(&upstream()));
        assert!(outcome
            .warnings
            .iter()
            .any(|(code, _)| *code == "nuget_default_config_left"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn refusals_change_nothing() {
        let routed_to_corp = USER_MAPPING.replace("Contoso.*", "Newtonsoft.*");
        let two_patterns = hosted_config(USER_MAPPING).replace(
            "<package pattern=\"Newtonsoft.Json\" />",
            "<package pattern=\"Newtonsoft.Json\" />\n      <package pattern=\"Other\" />",
        );
        let cases = [
            (hosted_config(USER_MAPPING), true, "offline"),
            (
                hosted_config(&routed_to_corp),
                false,
                "corp (https://corp.example/v3/index.json)",
            ),
            (two_patterns, false, "not to the one package"),
            (
                USER_MAPPING.to_string(),
                false,
                "does not define the Socket source",
            ),
        ];
        for (config, offline, needle) in cases {
            let (outcome, after, lock_after) = run(&config, offline).await;
            let PinStatus::Refused(why) = &outcome.pins[0].status else {
                panic!("{needle}: restored");
            };
            assert!(why.contains(needle), "{needle}: {why}");
            assert!(why.contains("git checkout -- nuget.config"), "{why}");
            assert_eq!(after, config, "{needle}");
            assert_eq!(lock_after, lock(PATCHED), "{needle}");
        }
    }
}
