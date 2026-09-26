//! Real vlt locks (`tests/fixtures/vlt-locks/<version>/`, captured from every
//! era) through the hosted rewriter: only the target nodes' slots [2] and [3]
//! change, and the output stays in vlt's own canonical serialization, so
//! vlt's next save leaves it byte-identical.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride};

const TOKEN: &str = "11111111-1111-1111-1111-111111111111";

/// `(version, the DepIDs rewritten in override order, warning codes)`.
const CAPTURES: &[(&str, &[&str], &[&str])] = &[
    (
        "0.0.0-1",
        &[
            "··left-pad@1.3.0",
            "··@isaacs§string-locale-compare@1.1.0",
            "··use-sync-external-store@1.2.0",
            "··semver@7.6.0",
            "··fsevents@2.3.3",
        ],
        &[
            "redirect_vlt_lockfile_version_missing",
            "redirect_vlt_old_lockfile_ignored",
            "redirect_vlt_entry_not_found",
        ],
    ),
    (
        "0.0.0-16",
        &[
            "··left-pad@1.3.0",
            "··@isaacs§string-locale-compare@1.1.0",
            "··use-sync-external-store@1.2.0",
            "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            "··semver@7.6.0",
            "··fsevents@2.3.3",
        ],
        &["redirect_vlt_lockfile_version_missing"],
    ),
    (
        "0.0.0-19",
        &[
            "··left-pad@1.3.0",
            "··@isaacs§string-locale-compare@1.1.0",
            "··use-sync-external-store@1.2.0",
            "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            "··semver@7.6.0",
            "··fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "0.0.0-32",
        &[
            "··left-pad@1.3.0",
            "··@isaacs§string-locale-compare@1.1.0",
            "··use-sync-external-store@1.2.0",
            "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            "··semver@7.6.0",
            "··fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.0-rc.8",
        &[
            "··left-pad@1.3.0",
            "··@isaacs§string-locale-compare@1.1.0",
            "··use-sync-external-store@1.2.0",
            "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            "··semver@7.6.0",
            "··fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.0-rc.14",
        &[
            "·npm·left-pad@1.3.0",
            "·npm·@isaacs§string-locale-compare@1.1.0",
            "·npm·use-sync-external-store@1.2.0",
            "·npm·ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            "·npm·semver@7.6.0",
            "·npm·fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.0-rc.15",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.0-rc.32",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.0-rc.33",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.0.10",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0~peer.0df72515a50372ba",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.1.1",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0~peer.0df72515a50372ba",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
    (
        "1.2.0",
        &[
            "~npm~left-pad@1.3.0",
            "~npm~@isaacs+string-locale-compare@1.1.0",
            "~npm~use-sync-external-store@1.2.0~peer.0df72515a50372ba",
            "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
            "~npm~semver@7.6.0",
            "~npm~fsevents@2.3.3",
        ],
        &[],
    ),
];

/// `(full name, version, patch uuid)` of the override set: a direct, a
/// scoped, a peer, a transitive (modifier) target, a bins and an optional
/// platform node.
const TARGETS: &[(&str, &str, &str)] = &[
    ("left-pad", "1.3.0", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
    (
        "@isaacs/string-locale-compare",
        "1.1.0",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    ),
    (
        "use-sync-external-store",
        "1.2.0",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    ),
    ("ms", "2.1.3", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
    ("semver", "7.6.0", "ffffffff-ffff-4fff-8fff-ffffffffffff"),
    ("fsevents", "2.3.3", "00000000-0000-4000-8000-000000000000"),
];

fn captures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vlt-locks")
}

fn hosted_url(name: &str, version: &str, uuid: &str) -> String {
    let bare = name.rsplit('/').next().unwrap();
    format!("https://patch.socket.dev/patch/npm/{TOKEN}/{uuid}/{bare}-{version}.tgz")
}

fn patched_sha(uuid: &str) -> String {
    let tag = uuid[..1].to_ascii_uppercase();
    format!("sha512-{}==", tag.repeat(86))
}

fn overrides() -> Vec<DepOverride> {
    TARGETS
        .iter()
        .map(|(name, version, uuid)| {
            let (namespace, bare) = match name.split_once('/') {
                Some((scope, bare)) => (Some(scope), bare),
                None => (None, *name),
            };
            serde_json::from_value(serde_json::json!({
                "ecosystem": "npm",
                "name": bare,
                "namespace": namespace,
                "version": version,
                "token": TOKEN,
                "patchUuid": uuid,
                "artifactUrl": hosted_url(name, version, uuid),
                "integrity": { "sha512": patched_sha(uuid) },
            }))
            .unwrap()
        })
        .collect()
}

/// vlt `save.ts` `extraFormat(JSON.stringify(data, null, 2))`.
fn vlt_serialize(text: &str) -> String {
    let value: Value = serde_json::from_str(text).unwrap();
    let pretty = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let marker = "  \"nodes\": {";
    let mut parts = pretty.split(marker);
    let mut out = parts.next().unwrap().to_string();
    for part in parts {
        out.push_str(marker);
        out.push_str(&part.replace("\n      ", "").replace("\n    ]", "]"));
    }
    out
}

fn node_entry(line: &str) -> (String, Vec<Value>) {
    let body = line.trim_start().trim_end_matches(',');
    let (key, tuple) = body.split_once(": ").unwrap();
    let key: String = serde_json::from_str(key).unwrap();
    let tuple: Vec<Value> = serde_json::from_str(tuple).unwrap();
    (key, tuple)
}

fn read_capture(version: &str) -> BTreeMap<String, String> {
    let dir = captures_root().join(version);
    let mut files = BTreeMap::new();
    for name in ["vlt-lock.json", "vlt.json"] {
        if let Ok(text) = fs::read_to_string(dir.join(name)) {
            files.insert(name.to_string(), text);
        }
    }
    files
}

#[test]
fn every_capture_is_listed() {
    let mut on_disk: Vec<String> = fs::read_dir(captures_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = CAPTURES.iter().map(|(v, _, _)| v.to_string()).collect();
    listed.sort();
    assert_eq!(on_disk, listed);
}

#[test]
fn captured_locks_are_in_vlt_canonical_form() {
    for (version, _, _) in CAPTURES {
        let lock = &read_capture(version)["vlt-lock.json"];
        assert_eq!(&vlt_serialize(lock), lock, "{version}");
    }
}

#[test]
fn hosted_rewrite_changes_exactly_the_target_slots() {
    let overrides = overrides();
    for (version, targets, warnings) in CAPTURES {
        let files = read_capture(version);
        let input = &files["vlt-lock.json"];
        let result = rewrite_registry_redirect(&files, &overrides);
        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(&codes, warnings, "{version}");
        let output = &result.files["vlt-lock.json"];
        assert_eq!(result.files.len(), 1, "{version}");
        assert_eq!(&vlt_serialize(output), output, "{version}: canonical");

        let before: Vec<&str> = input.split('\n').collect();
        let after: Vec<&str> = output.split('\n').collect();
        assert_eq!(before.len(), after.len(), "{version}");
        let mut changed = Vec::new();
        for (old, new) in before.iter().zip(&after) {
            if old == new {
                continue;
            }
            let (old_key, old_tuple) = node_entry(old);
            let (new_key, new_tuple) = node_entry(new);
            assert_eq!(old_key, new_key, "{version}");
            let name = old_tuple[1].as_str().unwrap();
            let (_, target_version, uuid) = TARGETS
                .iter()
                .find(|(n, v, _)| *n == name && old_key.contains(&format!("@{v}")))
                .unwrap_or_else(|| panic!("{version}: {old_key} is not a target"));
            assert_eq!(
                new_tuple.len(),
                old_tuple.len().max(4),
                "{version} {old_key}"
            );
            assert_eq!(new_tuple[0], old_tuple[0], "{version} {old_key}");
            assert_eq!(new_tuple[1], old_tuple[1], "{version} {old_key}");
            assert_eq!(new_tuple[2], Value::String(patched_sha(uuid)));
            assert_eq!(
                new_tuple[3],
                Value::String(hosted_url(name, target_version, uuid))
            );
            assert_eq!(
                new_tuple[4..],
                old_tuple[old_tuple.len().min(4)..],
                "{version} {old_key}"
            );
            changed.push(old_key);
        }
        let mut want: Vec<&str> = targets.to_vec();
        want.sort_unstable();
        changed.sort_unstable();
        assert_eq!(changed, want, "{version}");
        let edited: Vec<&str> = result
            .edits
            .iter()
            .map(|e| {
                let original = e.original.as_ref().and_then(Value::as_str).unwrap();
                original[1..].split_once('"').unwrap().0
            })
            .collect();
        assert_eq!(&edited, targets, "{version}: edits in override order");

        let again = rewrite_registry_redirect(&result.files, &overrides);
        assert!(again.files.is_empty(), "{version}: a rerun is a no-op");
        assert!(again.edits.is_empty(), "{version}");
    }
}
