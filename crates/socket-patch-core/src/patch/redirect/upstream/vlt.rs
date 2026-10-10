//! vlt-lock.json upstream restore: the inverse of the hosted node splice
//! (`redirect::vlt`), which rewrites only slot [2] (integrity) and slot [3]
//! (resolved URL) of each default-registry node of `name@version`.
//!
//! Slot [2] comes back from the npm registry's `dist.integrity`. Slot [3]
//! follows the lock's own convention, since vlt versions disagree on it:
//! 0.0.0-x … 1.0.0-rc.32 write no resolved URL for a registry node (a
//! 3-tuple, or `null` when later slots exist), rc.33 and 1.x write the
//! tarball URL on the node's registry. The convention is read from the
//! lock's other default-registry nodes of the same DepID era; with none to
//! read, a legacy-era (`·`) id never carries one, and a tilde-era (`~`)
//! id carries one when the lock records `options.registries` (the rc.33+
//! writer), the node sits on the default alias, and the tarball URL is not
//! under a recorded `options.registry` (vlt's own save rule, unchanged from
//! rc.33 through 1.2.0: slot [3] is written only when no `registry` is
//! configured or the resolved URL does not start with it; real rc.33,
//! 1.0.4, 1.0.10 and 1.2.0 locks of a `config.registry` project are
//! byte-identical 3-tuples — fixture `capture-1.2.0-config-registry`).
//!
//! Every hosted instance of a pin is restored together, and every other
//! byte of the lock (flags, trailing slots, indent, comma, `\r`) is kept.
//! Default-registry admission and sibling conventions use the same raw
//! segment policy as forward rewrite, heal and vendor. Only the shared
//! `registry_base` normalizes a modern empty segment when resolving a URL.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::npm::fetch_dists_on;
use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::vendor::vlt_lock_text::{
    brotli_for_slot3, default_registry_alias, entry_text, is_default_registry, nodes_block,
    parse_node_line, registry_base, render_entry_line, render_tuple_with_slots, sniff_lock,
    split_dep_id, split_lines, DepIdEra, DepIdKind, LockSniff,
};

/// One hosted node line to restore.
struct Hit {
    line: usize,
    uuid: String,
    name: String,
    version: String,
    era: DepIdEra,
    /// The decoded registry segment of the DepID.
    segment: String,
}

/// The conventional tarball URL of `name@version` on `base`.
fn tarball_url(base: &str, name: &str, version: &str) -> String {
    crate::vendor::registry_fetch::npm_tarball_url(base.trim_end_matches('/'), name, version)
}

/// Does the lock record a resolved URL (slot [3]) for a default-registry
/// node of `era` on `segment`? `siblings` are the `(era, has_url)` of the
/// lock's non-hosted default-registry nodes.
fn records_url(
    era: DepIdEra,
    segment: &str,
    name: &str,
    siblings: &[(DepIdEra, bool)],
    options: Option<&Map<String, Value>>,
) -> bool {
    let same_era: Vec<bool> = siblings
        .iter()
        .filter(|(e, _)| *e == era)
        .map(|(_, url)| *url)
        .collect();
    if !same_era.is_empty() {
        let with = same_era.iter().filter(|u| **u).count();
        return with * 2 >= same_era.len();
    }
    era == DepIdEra::Tilde
        && options
            .and_then(|o| o.get("registries"))
            .is_some_and(Value::is_object)
        && (segment.is_empty() || default_registry_alias(options) == Some(segment))
        && !under_configured_registry(era, segment, name, options)
}

/// Would a default-registry node on `segment` resolve under the lock's
/// recorded `options.registry`? vlt omits slot [3] for such a node
/// (`lockfile/save.ts`: `customRegistry = resolved && (!registry ||
/// !resolved.startsWith(registry))`).
fn under_configured_registry(
    era: DepIdEra,
    segment: &str,
    name: &str,
    options: Option<&Map<String, Value>>,
) -> bool {
    let Some(registry) = options
        .and_then(|o| o.get("registry"))
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty())
    else {
        return false;
    };
    registry_base(era, segment, name, options).is_some_and(|base| base.starts_with(registry))
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
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let parsed = match sniff_lock(&text) {
            LockSniff::Readable(parsed) => parsed,
            LockSniff::Bom => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} starts with a UTF-8 BOM"),
                );
                continue;
            }
            LockSniff::NotJsonObject => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} is not a JSON object"),
                );
                continue;
            }
            LockSniff::UnsupportedVersion(raw) => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} has unsupported lockfileVersion {raw}"),
                );
                continue;
            }
        };
        let options = parsed.options();
        let lines = split_lines(&text);
        let Some(span) = nodes_block(&lines) else {
            refuse_all_in(
                &pins,
                rel,
                &mut result,
                format!("{rel} nodes section is not in vlt's canonical layout"),
            );
            continue;
        };

        let mut hits: Vec<Hit> = Vec::new();
        let mut siblings: Vec<(DepIdEra, bool)> = Vec::new();
        let mut seen_keys = std::collections::BTreeSet::new();
        for i in span.entry_lines() {
            let Some(line) = parse_node_line(lines[i]) else {
                // A line outside the node grammar that still names an
                // in-scope patch cannot be restored slot by slot.
                for uuid in crate::vex::discover::hosted_uuids_in_text(lines[i], ctx.origins) {
                    if pins.contains_key(uuid.as_str()) {
                        result.refuse(
                            &uuid,
                            format!("a {rel} node wiring it is outside vlt's node grammar"),
                        );
                    }
                }
                continue;
            };
            let entry = &line.entry;
            let duplicate = !seen_keys.insert(entry.key);
            let slot3: Option<String> = entry
                .slot(3)
                .and_then(|raw| serde_json::from_str::<Option<String>>(raw).ok())
                .flatten();
            let dep_id = split_dep_id(entry.key);
            let hosted = slot3.as_deref().and_then(|u| ctx.hosted_uuid(u));
            let Some(uuid) = hosted else {
                if let Some(dep_id) = dep_id.filter(|d| {
                    d.kind == DepIdKind::Registry && is_default_registry(&d.first, options)
                }) {
                    siblings.push((dep_id.era, slot3.is_some()));
                }
                continue;
            };
            let Some(pin) = pins.get(uuid.as_str()) else {
                continue;
            };
            let Some((name, version)) = pin.name_version() else {
                result.refuse(&uuid, format!("{} is not an npm purl", pin.purl));
                continue;
            };
            if duplicate {
                result.refuse(&uuid, format!("{rel} has {} more than once", entry.key));
                continue;
            }
            let matches = dep_id.as_ref().filter(|d| {
                d.kind == DepIdKind::Registry
                    && d.registry_identity() == Some((name.as_str(), version.as_str()))
                    && entry.name().as_deref() == Some(name.as_str())
            });
            let Some(dep_id) = matches else {
                result.refuse(
                    &uuid,
                    format!(
                        "the {rel} node `{}` wiring it is not {name}@{version}",
                        entry.key
                    ),
                );
                continue;
            };
            if !is_default_registry(&dep_id.first, options) {
                result.refuse(
                    &uuid,
                    format!(
                        "the {rel} node `{}` wiring it is not on vlt's default registry",
                        entry.key
                    ),
                );
                continue;
            }
            hits.push(Hit {
                line: i,
                uuid,
                name,
                version,
                era: dep_id.era,
                segment: dep_id.first.clone(),
            });
        }

        let wanted = hits
            .iter()
            .map(|h| (h.uuid.clone(), h.name.clone(), h.version.clone()))
            .collect();
        // Each version document comes from the registry its node resolves
        // against, whose `dist.tarball` vlt wrote into slot [3] (#521).
        let bases: BTreeMap<&str, String> = hits
            .iter()
            .filter_map(|h| {
                registry_base(h.era, &h.segment, &h.name, options).map(|b| (h.name.as_str(), b))
            })
            .collect();
        let dists =
            fetch_dists_on(&wanted, |name| bases.get(name).cloned(), ctx, &mut result).await;
        let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
        let mut planned: Vec<&str> = Vec::new();
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            let found = dists.get(&(hit.name.clone(), hit.version.clone()));
            let Some(integrity) = found.and_then(|d| d.dist.integrity.clone()) else {
                result.refuse(
                    &hit.uuid,
                    format!(
                        "the registry records no integrity for {}@{}",
                        hit.name, hit.version
                    ),
                );
                continue;
            };
            let line = parse_node_line(lines[hit.line]).expect("the hit line parsed above");
            let json = |s: &str| serde_json::to_string(s).expect("a str serializes to JSON");
            let slot3 = if records_url(hit.era, &hit.segment, &hit.name, &siblings, options) {
                let Some(base) = registry_base(hit.era, &hit.segment, &hit.name, options) else {
                    result.refuse(
                        &hit.uuid,
                        format!("{rel} maps no registry for the `{}` segment", hit.segment),
                    );
                    continue;
                };
                // The node's registry advertised its tarball URL; without
                // that document, the conventional URL on the node's base.
                match found.filter(|d| d.from_project) {
                    Some(d) => Some(json(&d.dist.tarball)),
                    None => Some(json(&tarball_url(&base, &hit.name, &hit.version))),
                }
            } else {
                None
            };
            let tuple = render_tuple_with_slots(
                &line.entry.elems,
                brotli_for_slot3(slot3.as_deref()),
                Some(&json(&integrity)),
                slot3.as_deref(),
            );
            out[hit.line] =
                render_entry_line(&entry_text(line.entry.key, &tuple), line.comma, line.cr);
            planned.push(&hit.uuid);
        }
        // A pin refused after one of its instances was planned (a later
        // instance failed) restores none of them.
        let mut changed = false;
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                out[hit.line] = lines[hit.line].to_string();
            } else if planned.contains(&hit.uuid.as_str()) {
                changed = true;
            }
        }
        if !changed {
            continue;
        }
        let restored = out.join("\n");
        if serde_json::from_str::<Value>(&restored).is_err() {
            refuse_all_in(
                &pins,
                rel,
                &mut result,
                format!("restoring {rel} would not leave valid JSON"),
            );
            continue;
        }
        for uuid in planned {
            if !result.refused.contains_key(uuid) {
                result.handled.insert(uuid.to_string());
            }
        }
        view.write(rel, restored);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn tarball_url_keeps_the_scope_in_the_path() {
        assert_eq!(
            tarball_url("https://mirror.example/npm/", "@a/b", "1.0.0"),
            "https://mirror.example/npm/@a/b/-/b-1.0.0.tgz"
        );
    }

    #[test]
    fn slot3_convention_prefers_same_era_siblings() {
        let with_registries = opts(r#"{"registries":{"npm":"https://registry.npmjs.org/"}}"#);
        // Siblings decide, whatever the options say.
        assert!(!records_url(
            DepIdEra::Tilde,
            "npm",
            "left-pad",
            &[(DepIdEra::Tilde, false)],
            Some(&with_registries)
        ));
        assert!(records_url(
            DepIdEra::Tilde,
            "npm",
            "left-pad",
            &[(DepIdEra::Tilde, true)],
            None
        ));
        // Another era's siblings do not.
        assert!(!records_url(
            DepIdEra::Legacy,
            "npm",
            "left-pad",
            &[(DepIdEra::Tilde, true)],
            Some(&with_registries)
        ));
        // No siblings: the rc.33+ writer records `registries`.
        assert!(records_url(
            DepIdEra::Tilde,
            "npm",
            "left-pad",
            &[],
            Some(&with_registries)
        ));
        assert!(!records_url(DepIdEra::Tilde, "npm", "left-pad", &[], None));
        assert!(!records_url(
            DepIdEra::Tilde,
            "https://registry.example.com/",
            "left-pad",
            &[],
            Some(&with_registries)
        ));
        let alias = opts(r#"{"default-registry-alias":"corp","registries":{"corp":"https://c/"}}"#);
        assert!(records_url(
            DepIdEra::Tilde,
            "corp",
            "left-pad",
            &[],
            Some(&alias)
        ));
        // A recorded `registry` the node resolves under: vlt (rc.33 … 1.2.0
        // with `config.registry`) writes no slot [3].
        let configured = opts(
            r#"{"registry":"http://127.0.0.1:4873/","registries":{"npm":"http://127.0.0.1:4873/"}}"#,
        );
        assert!(!records_url(
            DepIdEra::Tilde,
            "npm",
            "left-pad",
            &[],
            Some(&configured)
        ));
        // ...but a node on another registry than the configured one does.
        let elsewhere = opts(
            r#"{"registry":"https://registry.npmjs.org/","registries":{"npm":"http://127.0.0.1:4873/"}}"#,
        );
        assert!(records_url(
            DepIdEra::Tilde,
            "npm",
            "left-pad",
            &[],
            Some(&elsewhere)
        ));
    }

    use super::super::{restore_upstream, RestoreOptions, RestoreOutcome};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LP_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const FS_UUID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const LP_UPSTREAM: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
    const FS_UPSTREAM: &str = "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==";

    fn hosted(uuid: &str, leaf: &str) -> String {
        format!(
            "https://patch.socket.dev/patch/npm/11111111-1111-1111-1111-111111111111/{uuid}/{leaf}"
        )
    }

    fn pin(purl: &str, uuid: &str) -> HostedPin {
        HostedPin {
            purl: purl.into(),
            uuid: uuid.into(),
            files: vec!["vlt-lock.json".into()],
        }
    }

    async fn run(lock: &str, pins: &[HostedPin], offline: bool) -> (RestoreOutcome, String) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("vlt-lock.json"), lock).unwrap();
        let opts = RestoreOptions {
            offline,
            ..RestoreOptions::default()
        };
        let outcome = restore_upstream(tmp.path(), pins, &opts).await;
        let after = std::fs::read_to_string(tmp.path().join("vlt-lock.json")).unwrap();
        (outcome, after)
    }

    /// An npm registry that knows `(name, version, integrity?)`.
    async fn registry(docs: &[(&str, &str, Option<&str>)]) -> MockServer {
        let server = MockServer::start().await;
        for (name, version, integrity) in docs {
            let mut dist = serde_json::json!({ "tarball": format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz") });
            if let Some(i) = integrity {
                dist["integrity"] = (*i).into();
            }
            Mock::given(method("GET"))
                .and(path(format!("/{}/{version}", name.replace('/', "%2f"))))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "dist": dist })),
                )
                .mount(&server)
                .await;
        }
        server
    }

    fn refused(outcome: &RestoreOutcome) -> Vec<String> {
        outcome.refused().map(|(_, why)| why.to_string()).collect()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn legacy_crlf_lock_restores_3_tuples_and_null_slots() {
        let server = registry(&[
            ("left-pad", "1.3.0", Some(LP_UPSTREAM)),
            ("fsevents", "2.3.3", Some(FS_UPSTREAM)),
        ])
        .await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let lock = |lp: &str, fs: &str| {
            format!(
                "{{\r\n  \"lockfileVersion\": 0,\r\n  \"options\": {{}},\r\n  \"nodes\": {{\r\n    \"··fsevents@2.3.3\": [1,\"fsevents\",{fs},null,null,{{\"os\":[\"darwin\"]}}],\r\n    \"··left-pad@1.3.0\": [0,\"left-pad\",{lp}]\r\n  }},\r\n  \"edges\": {{}}\r\n}}\r\n"
            )
        };
        let hosted_lock = lock(
            &format!(
                "\"sha512-AAAA==\",\"{}\"",
                hosted(LP_UUID, "left-pad-1.3.0.tgz")
            ),
            &format!(
                "\"sha512-BBBB==\",\"{}\"",
                hosted(FS_UUID, "fsevents-2.3.3.tgz")
            ),
        );
        let pins = [
            pin("pkg:npm/left-pad@1.3.0", LP_UUID),
            pin("pkg:npm/fsevents@2.3.3", FS_UUID),
        ];
        let (outcome, after) = run(&hosted_lock, &pins, false).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
        assert_eq!(
            after,
            lock(
                &format!("\"{LP_UPSTREAM}\""),
                &format!("\"{FS_UPSTREAM}\",null")
            )
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn every_instance_of_a_pin_is_restored_with_the_url_convention() {
        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let url = hosted(LP_UUID, "left-pad-1.3.0.tgz");
        let text = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"],\n    \"~npm~left-pad@1.3.0~peer.1\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"],\n    \"~npm~ms@2.1.3\": [0,\"ms\",\"sha512-M==\",\"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz\"]\n  }},\n  \"edges\": {{}}\n}}\n"
        );
        let (outcome, after) = run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
        let upstream = format!(
            "[0,\"left-pad\",\"{LP_UPSTREAM}\",\"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"]"
        );
        assert_eq!(after.matches(&upstream).count(), 2, "{after}");
        assert!(!after.contains("patch.socket.dev"));
    }

    /// Restore rebuilds slot [3] on the base the shared `registry_base`
    /// resolves, for every default-registry row of the table, and refuses
    /// every other row (the lock does not name vlt's default registry).
    #[tokio::test]
    #[serial_test::serial]
    async fn restore_resolves_registries_through_the_shared_registry_base() {
        use crate::vendor::vlt_lock_text::REGISTRY_BASE_CASES;
        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let url = hosted(LP_UUID, "left-pad-1.3.0.tgz");
        for (era, segment, options, want) in REGISTRY_BASE_CASES {
            if segment.starts_with("http") {
                continue;
            }
            // A same-era sibling that records slot [3] makes restore write
            // one for the pin.
            let delimiter = era.delimiter();
            let lock_version = u8::from(*era == DepIdEra::Tilde);
            let text = format!(
                "{{\n  \"lockfileVersion\": {lock_version},\n  \"options\": {options},\n  \"nodes\": {{\n    \"{delimiter}{segment}{delimiter}left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"],\n    \"{delimiter}{segment}{delimiter}ms@2.1.3\": [0,\"ms\",\"sha512-M==\",\"https://x.example/ms/-/ms-2.1.3.tgz\"]\n  }},\n  \"edges\": {{}}\n}}\n"
            );
            let (outcome, after) =
                run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
            let opts = opts(options);
            let admitted = is_default_registry(segment, Some(&opts));
            if let (true, Some(want)) = (admitted, *want) {
                assert!(
                    refused(&outcome).is_empty(),
                    "{segment:?} {options}: {:?}",
                    refused(&outcome)
                );
                let upstream = format!(
                    "[0,\"left-pad\",\"{LP_UPSTREAM}\",\"{want}left-pad/-/left-pad-1.3.0.tgz\"]"
                );
                assert!(after.contains(&upstream), "{segment:?} {options}: {after}");
            } else {
                let why = refused(&outcome);
                let reason = if admitted {
                    "maps no registry"
                } else {
                    "not on vlt's default registry"
                };
                assert!(why[0].contains(reason), "{segment:?} {options}: {why:?}");
                assert_eq!(after, text);
            }
        }
        std::env::remove_var("SOCKET_NPM_REGISTRY");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn restore_empty_tilde_resolution_and_raw_sibling_convention() {
        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let url = hosted(LP_UUID, "left-pad-1.3.0.tgz");
        for (segment, options, sibling, base) in [
            (
                "",
                r#"{"registry":"https://a.example/","registries":{"npm":"https://b.example/"}}"#,
                "",
                Some("https://b.example/"),
            ),
            (
                "npm",
                r#"{"registry":"https://a.example/","registries":{"npm":"https://b.example/"}}"#,
                "",
                Some("https://b.example/"),
            ),
            (
                "corp",
                r#"{"default-registry-alias":"corp","registries":{"npm":"https://b.example/","corp":"https://c.example/"}}"#,
                // Keep forward rewrite's raw-empty admission policy when
                // choosing siblings, so its 3-tuple convention is retained.
                ",\n    \"~~ms@2.1.3\": [0,\"ms\",\"sha512-M==\"]",
                None,
            ),
        ] {
            let key = format!("~{segment}~left-pad@1.3.0");
            let text = format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {options},\n  \"nodes\": {{\n    \"{key}\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]{sibling}\n  }},\n  \"edges\": {{}}\n}}\n"
            );
            let (outcome, after) =
                run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
            assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
            let after: Value = serde_json::from_str(&after).unwrap();
            let expected = match base {
                Some(base) => serde_json::json!([
                    0,
                    "left-pad",
                    LP_UPSTREAM,
                    format!("{base}left-pad/-/left-pad-1.3.0.tgz")
                ]),
                None => serde_json::json!([0, "left-pad", LP_UPSTREAM]),
            };
            assert_eq!(after["nodes"][&key], expected, "{segment:?} {options}");
        }
        std::env::remove_var("SOCKET_NPM_REGISTRY");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rewritten_empty_tilde_under_custom_alias_restores_byte_for_byte() {
        use crate::patch::redirect::{DepOverride, RewriteResult};

        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let url = hosted(LP_UUID, "left-pad-1.3.0.tgz");
        let dep: DepOverride = serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "name": "left-pad",
            "version": "1.3.0",
            "token": "t",
            "patchUuid": LP_UUID,
            "artifactUrl": url,
            "integrity": { "sha512": "sha512-PATCHED==" },
        }))
        .unwrap();
        for sibling in [
            "",
            ",\n    \"~~ms@2.1.3\": [0,\"ms\",\"sha512-M==\",\"https://b.example/ms/-/ms-2.1.3.tgz\"]",
        ] {
            let original = format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"default-registry-alias\":\"corp\",\"registry\":\"https://a.example/\",\"registries\":{{\"corp\":\"https://a.example/\",\"npm\":\"https://b.example/\"}}}},\n  \"nodes\": {{\n    \"~~left-pad@1.3.0\": [0,\"left-pad\",\"{LP_UPSTREAM}\",\"https://b.example/left-pad/-/left-pad-1.3.0.tgz\"]{sibling}\n  }},\n  \"edges\": {{}}\n}}\n"
            );
            let files = [("vlt-lock.json".to_string(), original.clone())]
                .into_iter()
                .collect();
            let mut rewritten = RewriteResult::default();
            crate::patch::redirect::vlt::rewrite_vlt_lock(
                &files,
                std::slice::from_ref(&dep),
                false,
                &mut rewritten,
            );
            let pinned = rewritten.files.get("vlt-lock.json").expect("forward rewrite admits the raw empty segment");
            assert!(pinned.contains(&url), "{pinned}");
            let (outcome, restored) =
                run(pinned, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
            assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
            assert_eq!(restored, original);
        }
        std::env::remove_var("SOCKET_NPM_REGISTRY");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn restore_honors_scope_for_slot3_and_configured_registry_omission() {
        use crate::vendor::vlt_lock_text::SCOPED_REGISTRY_OPTIONS;
        let server = registry(&[("@s/a", "1.0.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let url = hosted(LP_UUID, "a-1.0.0.tgz");
        for records_url in [false, true] {
            let sibling = if records_url {
                ",\n    \"~npm~ms@2.1.3\": [0,\"ms\",\"sha512-M==\",\"https://b.example/ms/-/ms-2.1.3.tgz\"]"
            } else {
                ""
            };
            let text = format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {SCOPED_REGISTRY_OPTIONS},\n  \"nodes\": {{\n    \"~npm~@s+a@1.0.0\": [0,\"@s/a\",\"sha512-AA==\",\"{url}\"]{sibling}\n  }},\n  \"edges\": {{}}\n}}\n"
            );
            let (outcome, after) = run(&text, &[pin("pkg:npm/@s/a@1.0.0", LP_UUID)], false).await;
            assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
            let after: Value = serde_json::from_str(&after).unwrap();
            let expected = if records_url {
                serde_json::json!([
                    0,
                    "@s/a",
                    LP_UPSTREAM,
                    "https://a.example/@s/a/-/a-1.0.0.tgz"
                ])
            } else {
                // The scoped URL is under options.registry, even though
                // registries.npm names a different base: vlt omits slot 3.
                serde_json::json!([0, "@s/a", LP_UPSTREAM])
            };
            assert_eq!(after["nodes"]["~npm~@s+a@1.0.0"], expected);
        }
        std::env::remove_var("SOCKET_NPM_REGISTRY");
    }

    /// #521: slot [3] is the `dist.tarball` the node's own registry
    /// advertises (what vlt writes verbatim), not a conventional
    /// `<registry>/<name>/-/<leaf>-<ver>.tgz` it may never serve. The
    /// version document comes from that registry, not the default one.
    #[tokio::test]
    #[serial_test::serial]
    async fn restore_takes_slot3_from_the_node_registrys_dist_tarball() {
        let server = MockServer::start().await;
        // The default registry (npmjs's stand-in) knows nothing of a CDN.
        Mock::given(method("GET"))
            .and(path("/left-pad/1.3.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dist": {
                    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-WRONG==",
                }
            })))
            .mount(&server)
            .await;
        let cdn = format!("{}/_cdn/files/left-pad-1.3.0.tgz", server.uri());
        Mock::given(method("GET"))
            .and(path("/mirror/left-pad/1.3.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dist": { "tarball": cdn, "integrity": LP_UPSTREAM }
            })))
            .mount(&server)
            .await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let mirror = format!("{}/mirror/", server.uri());
        let original = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"registries\":{{\"npm\":\"{mirror}\"}}}},\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"{LP_UPSTREAM}\",\"{cdn}\"]\n  }},\n  \"edges\": {{}}\n}}\n"
        );
        let hosted_lock = original
            .replace(LP_UPSTREAM, "sha512-AA==")
            .replace(&cdn, &hosted(LP_UUID, "left-pad-1.3.0.tgz"));
        let (outcome, after) = run(
            &hosted_lock,
            &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)],
            false,
        )
        .await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
        assert_eq!(after, original);
    }

    /// A node registry that can't be read (a private mirror wanting
    /// credentials) falls back to the default registry's document and the
    /// conventional URL on the node's base, and says so.
    #[tokio::test]
    #[serial_test::serial]
    async fn unreadable_node_registry_falls_back_with_a_warning() {
        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        // Nothing is mounted under /private/: every lookup there is a 404.
        let mirror = format!("{}/private/", server.uri());
        let text = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"registries\":{{\"npm\":\"{mirror}\"}}}},\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{}\"]\n  }},\n  \"edges\": {{}}\n}}\n",
            hosted(LP_UUID, "left-pad-1.3.0.tgz")
        );
        let (outcome, after) = run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
        let after: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(
            after["nodes"]["~npm~left-pad@1.3.0"],
            serde_json::json!([
                0,
                "left-pad",
                LP_UPSTREAM,
                format!("{mirror}left-pad/-/left-pad-1.3.0.tgz")
            ])
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|(code, detail)| *code == "upstream_registry_fallback"
                    && detail.contains(mirror.trim_end_matches('/'))),
            "{:?}",
            outcome.warnings
        );
    }

    /// A credentialed registry URL (`https://user:token@host/`) that can't
    /// be read never leaks its userinfo into the `upstream_registry_fallback`
    /// detail: rollback and remove print it and persist it in `--json`
    /// output, which lands in CI logs.
    #[tokio::test]
    #[serial_test::serial]
    async fn registry_fallback_warning_drops_url_credentials() {
        let server = registry(&[("left-pad", "1.3.0", Some(LP_UPSTREAM))]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let host = server.uri().replace("http://", "");
        let mirror = format!("http://ci-user:s3cret-token@{host}/private/");
        let text = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"registries\":{{\"npm\":\"{mirror}\"}}}},\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{}\"]\n  }},\n  \"edges\": {{}}\n}}\n",
            hosted(LP_UUID, "left-pad-1.3.0.tgz")
        );
        let (outcome, _) = run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert!(refused(&outcome).is_empty(), "{:?}", refused(&outcome));
        let fallback: Vec<&String> = outcome
            .warnings
            .iter()
            .filter(|(code, _)| *code == "upstream_registry_fallback")
            .map(|(_, detail)| detail)
            .collect();
        assert_eq!(fallback.len(), 1, "{:?}", outcome.warnings);
        assert!(
            fallback[0].contains(&format!("http://{host}/private")),
            "{}",
            fallback[0]
        );
        for secret in ["s3cret-token", "ci-user"] {
            assert!(!fallback[0].contains(secret), "{}", fallback[0]);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn missing_registry_integrity_refuses() {
        let server = registry(&[("left-pad", "1.3.0", None)]).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let text = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{}\"]\n  }}\n}}\n",
            hosted(LP_UUID, "left-pad-1.3.0.tgz")
        );
        let (outcome, after) = run(&text, &[pin("pkg:npm/left-pad@1.3.0", LP_UUID)], false).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        let why = refused(&outcome);
        assert!(why[0].contains("records no integrity"), "{why:?}");
        assert!(why[0].contains("git checkout -- vlt-lock.json"), "{why:?}");
        assert_eq!(after, text);
    }

    #[tokio::test]
    async fn refusals_leave_the_lock_untouched() {
        let url = hosted(LP_UUID, "left-pad-1.3.0.tgz");
        let lp = [pin("pkg:npm/left-pad@1.3.0", LP_UUID)];
        let cases = [
            // Offline: slot [2] must come from the registry.
            (
                format!("{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "offline",
            ),
            // A hosted URL on a non-default registry node.
            (
                format!("{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"registries\": {{\"corp\": \"https://corp/\"}}}},\n  \"nodes\": {{\n    \"~corp~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "not on vlt's default registry",
            ),
            // A node of another package.
            (
                format!("{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"~npm~right-pad@1.3.0\": [0,\"right-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "is not left-pad@1.3.0",
            ),
            // The same DepID twice.
            (
                format!("{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"],\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "more than once",
            ),
            // Not vlt's one-node-per-line layout.
            (
                format!("{{\"lockfileVersion\": 1, \"nodes\": {{\"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]}}}}\n"),
                "canonical layout",
            ),
            (
                format!("\u{feff}{{\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "BOM",
            ),
            (
                format!("{{\n  \"lockfileVersion\": 2,\n  \"nodes\": {{\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-AA==\",\"{url}\"]\n  }}\n}}\n"),
                "lockfileVersion 2",
            ),
        ];
        for (text, needle) in cases {
            let (outcome, after) = run(&text, &lp, true).await;
            let why = refused(&outcome);
            assert!(
                matches!(&why[..], [w] if w.contains(needle)),
                "{needle}: {why:?}"
            );
            assert_eq!(after, text, "{needle}");
            assert!(outcome.reverted_files.is_empty(), "{needle}");
        }
    }
}
